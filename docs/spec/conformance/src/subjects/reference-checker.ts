import { Ajv2020 } from "ajv/dist/2020.js";
import { ed25519 } from "@noble/curves/ed25519";
import { resolveJsonPointer } from "../json-pointer.js";
import type { ConformanceCheckDocument, VectorDocument } from "../types.js";
import coreVerificationContextSchema from "../../schema/core-verification-context-v1.schema.json" with { type: "json" };
import {
  bindNip01Raw,
  computeNip01Digest,
  isNostrSignedEvent,
  verifyNip01Signature,
} from "./nip01.js";
import type {
  CheckerStage,
  CoreVerificationContextV1,
  NostrSignedEvent,
  SubjectResult,
} from "./types.js";

type StageResult = SubjectResult["stages"][number];

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateCoreContext = ajv.compile<CoreVerificationContextV1>(coreVerificationContextSchema);
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function reject(
  stages: StageResult[],
  stage: CheckerStage,
  reasonCode?: string,
): SubjectResult {
  const terminal: StageResult = reasonCode === undefined
    ? { stage, verdict: "reject" }
    : { stage, verdict: "reject", reasonCode };
  if (reasonCode === undefined) {
    return {
      terminalStage: stage,
      verdict: "reject",
      stages: [...stages, terminal],
    };
  }
  return {
    terminalStage: stage,
    verdict: "reject",
    reasonCode,
    stages: [...stages, terminal],
  };
}

function hasValidContextSemantics(
  context: CoreVerificationContextV1,
  event: NostrSignedEvent,
): boolean {
  if (context.pointer.persona !== context.persona || context.signer.pubkey !== event.pubkey) {
    return false;
  }

  const eventIds = new Set<string>();
  for (let index = 0; index < context.kel.length; index += 1) {
    const entry = context.kel[index]!;
    const prior = context.kel[index - 1];
    const next = context.kel[index + 1];
    if (
      entry.sequence !== index
      || eventIds.has(entry.event_id)
      || (index === 0 ? entry.prior_event_id !== null : entry.prior_event_id !== prior!.event_id)
      || (next === undefined
        ? entry.effective_until !== null
        : entry.effective_until !== next.effective_from)
      || (entry.effective_until !== null && entry.effective_until <= entry.effective_from)
    ) {
      return false;
    }
    eventIds.add(entry.event_id);
  }

  const head = context.kel.at(-1)!;
  if (
    context.pointer.kel_head.event_id !== head.event_id
    || context.pointer.kel_head.sequence !== head.sequence
  ) {
    return false;
  }

  if (context.signer.type === "delegated") {
    return context.signer.delegation.persona === context.persona
      && context.signer.delegation.publisher_pubkey === context.signer.pubkey;
  }
  return context.signer.delegation === null;
}

function resolveContext(
  vector: VectorDocument,
  check: ConformanceCheckDocument,
  event: NostrSignedEvent,
): CoreVerificationContextV1 | undefined {
  if (check.context_pointer === undefined) {
    return undefined;
  }
  let resolved;
  try {
    resolved = resolveJsonPointer(vector, check.context_pointer);
  } catch {
    return undefined;
  }
  if (!resolved.found || !validateCoreContext(resolved.value)) {
    return undefined;
  }
  return hasValidContextSemantics(resolved.value, event) ? resolved.value : undefined;
}

function hasValidVersionStamp(
  event: NostrSignedEvent,
  policy: CoreVerificationContextV1["version_policy"],
): boolean {
  const stamps: unknown[] = event.tags
    .filter((tag) => tag[0] === "spec_version")
    .map((tag) => tag.length === 2 ? tag[1] : undefined);

  try {
    const content: unknown = JSON.parse(event.content);
    if (
      content !== null
      && typeof content === "object"
      && !Array.isArray(content)
      && Object.hasOwn(content, "spec_version")
    ) {
      stamps.push((content as Record<string, unknown>).spec_version);
    }
  } catch {
    // A non-JSON content value simply has no content-carried stamp.
  }

  if (policy.mode === "forbidden") {
    return stamps.length === 0;
  }
  if (stamps.some((stamp) => stamp !== policy.value)) {
    return false;
  }
  return policy.mode === "required" ? stamps.length === 1 : stamps.length <= 1;
}

function kelHeadFailure(
  event: NostrSignedEvent,
  context: CoreVerificationContextV1,
): string | undefined {
  const tags = event.tags.filter((tag) => tag[0] === "kel_head");
  const mode = context.kel_head_policy.mode;
  if (mode === "forbidden") {
    return tags.length === 0 ? undefined : "kel_head_forbidden";
  }
  if (tags.length === 0) {
    return mode === "required" ? "kel_head_missing" : undefined;
  }
  if (tags.length !== 1) {
    return "kel_head_missing";
  }

  const tag = tags[0]!;
  if (
    tag.length !== 3
    || !/^[0-9a-f]{64}$/u.test(tag[1]!)
    || !/^(?:0|[1-9][0-9]*)$/u.test(tag[2]!)
  ) {
    return "kel_head_missing";
  }
  const sequence = Number(tag[2]);
  if (!Number.isSafeInteger(sequence)) {
    return "kel_head_missing";
  }
  if (
    tag[1] !== context.pointer.kel_head.event_id
    || sequence !== context.pointer.kel_head.sequence
  ) {
    return "kel_head_mismatch";
  }
  return undefined;
}

function authorityFailure(
  event: NostrSignedEvent,
  context: CoreVerificationContextV1,
): string | undefined {
  const entry = context.kel.find((candidate) =>
    event.created_at >= candidate.effective_from
    && (candidate.effective_until === null || event.created_at < candidate.effective_until));
  if (entry === undefined) {
    return "retired-key-authority-window-invalid";
  }
  if (entry.compromise_since !== null && event.created_at >= entry.compromise_since) {
    return "signing_key_compromised_at_created_at";
  }

  if (context.signer.type === "epoch") {
    return context.signer.pubkey === entry.epoch_pubkey
      ? undefined
      : "retired-key-authority-window-invalid";
  }

  const delegation = context.signer.delegation;
  if (event.created_at < delegation.valid_from) {
    return "delegation_mismatch";
  }
  if (delegation.valid_until !== null && event.created_at >= delegation.valid_until) {
    return "expired_delegation";
  }
  if (delegation.revoked_at !== null && event.created_at >= delegation.revoked_at) {
    return "revoked_key_post_revoked_at";
  }
  return undefined;
}

function singleTag(event: NostrSignedEvent, name: string): string[] | undefined {
  const matches = event.tags.filter((tag) => tag[0] === name);
  return matches.length === 1 ? matches[0] : undefined;
}

function decodeBase58(value: string): Uint8Array | undefined {
  let number = 0n;
  for (const character of value) {
    const digit = BASE58_ALPHABET.indexOf(character);
    if (digit < 0) {
      return undefined;
    }
    number = number * 58n + BigInt(digit);
  }

  const encoded = number === 0n ? "" : number.toString(16).padStart(number.toString(16).length + (number.toString(16).length % 2), "0");
  const body = encoded.length === 0 ? new Uint8Array() : new Uint8Array(Buffer.from(encoded, "hex"));
  let zeroes = 0;
  while (value[zeroes] === "1") {
    zeroes += 1;
  }
  const decoded = new Uint8Array(zeroes + body.length);
  decoded.set(body, zeroes);
  return decoded;
}

function nidMatchesPublicKey(nid: string, publicKey: string): boolean {
  if (!nid.startsWith("did:key:z")) {
    return false;
  }
  const decoded = decodeBase58(nid.slice("did:key:z".length));
  return decoded !== undefined
    && decoded.length === 34
    && decoded[0] === 0xed
    && decoded[1] === 0x01
    && Buffer.from(decoded.subarray(2)).toString("hex") === publicKey;
}

function isUnicodeScalarString(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const lowSurrogate = value.charCodeAt(index + 1);
      if (!(lowSurrogate >= 0xdc00 && lowSurrogate <= 0xdfff)) {
        return false;
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function proofBytes(domain: string, claim: Record<string, string>): Uint8Array | undefined {
  if (!Object.values(claim).every(isUnicodeScalarString)) {
    return undefined;
  }
  const canonicalClaim = `{${Object.keys(claim)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${JSON.stringify(claim[key])}`)
    .join(",")}}`;
  const domainBytes = new TextEncoder().encode(domain);
  const claimBytes = new TextEncoder().encode(canonicalClaim);
  const bytes = new Uint8Array(domainBytes.length + 1 + claimBytes.length);
  bytes.set(domainBytes);
  bytes.set(claimBytes, domainBytes.length + 1);
  return bytes;
}

function verifyEd25519Proof(signature: string, message: Uint8Array, publicKey: string): boolean {
  if (!/^[0-9a-f]{128}$/u.test(signature)) {
    return false;
  }
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

function nidDelegationFailure(
  event: NostrSignedEvent,
  context: CoreVerificationContextV1,
  nidPublicKey: string,
): string | undefined {
  const d = singleTag(event, "d");
  const discriminator = singleTag(event, "heterodyne");
  const nidTag = singleTag(event, "radicle_nid");
  const publisher = singleTag(event, "publishing_key");
  const coldRoot = singleTag(event, "cold_root");
  const proof = singleTag(event, "nid_proof");
  const validUntil = singleTag(event, "valid_until");
  if (
    event.kind !== 31_001
    || event.content !== ""
    || d?.length !== 2
    || discriminator?.length !== 2
    || discriminator[1] !== "delegation"
    || nidTag?.length !== 2
    || publisher?.length !== 2
    || !/^[0-9a-f]{64}$/u.test(publisher[1]!)
    || coldRoot?.length !== 2
    || coldRoot[1] !== context.persona
    || validUntil?.length !== 2
  ) {
    return "nid_binding_missing_signature";
  }
  const nid = nidTag[1]!;
  if (d[1] !== `nid:${nid}` || !nidMatchesPublicKey(nid, nidPublicKey)) {
    return "nid_proof_invalid";
  }
  if (
    validUntil[1] !== ""
    && (!/^(?:0|[1-9][0-9]*)$/u.test(validUntil[1]!)
      || !Number.isSafeInteger(Number(validUntil[1]))
      || Number(validUntil[1]) <= event.created_at)
  ) {
    return "expired_delegation";
  }
  if (proof?.length !== 2) {
    return "nid_binding_missing_signature";
  }
  const message = proofBytes("heterodyne-nid-binding-v1", {
    cold_root: context.persona,
    nid,
  });
  return message !== undefined && verifyEd25519Proof(proof[1]!, message, nidPublicKey)
    ? undefined
    : "nid_proof_invalid";
}

function nodeAdvertisementFailure(
  event: NostrSignedEvent,
  nidPublicKey: string,
): string | undefined {
  const d = singleTag(event, "d");
  const discriminator = singleTag(event, "heterodyne");
  const ridTag = singleTag(event, "rid");
  const nidTag = singleTag(event, "nid");
  const endpointTag = singleTag(event, "endpoint");
  const repoHeadTag = singleTag(event, "repo_head");
  const expiryTag = singleTag(event, "expiry");
  const proof = singleTag(event, "nid_proof");
  if (
    event.kind !== 31_010
    || event.content !== ""
    || d?.length !== 2
    || discriminator?.length !== 2
    || discriminator[1] !== "node_advert"
    || ridTag?.length !== 2
    || d[1] !== ridTag[1]
    || nidTag?.length !== 2
    || endpointTag?.length !== 2
    || endpointTag[1]!.length === 0
    || repoHeadTag?.length !== 2
    || !/^[0-9a-f]{40}$/u.test(repoHeadTag[1]!)
    || expiryTag?.length !== 2
    || proof?.length !== 2
  ) {
    return "nid_proof_invalid";
  }

  const expiryText = expiryTag[1]!;
  if (!/^(?:0|[1-9][0-9]*)$/u.test(expiryText)) {
    return "node-advert-expiry-invalid";
  }
  const expiry = Number(expiryText);
  if (!Number.isSafeInteger(expiry) || expiry <= event.created_at) {
    return "node-advert-expiry-invalid";
  }
  if (expiry - event.created_at > 86_400) {
    return "node-advert-lifetime-exceeded";
  }

  const nid = nidTag[1]!;
  if (!nidMatchesPublicKey(nid, nidPublicKey)) {
    return "nid_proof_invalid";
  }
  const message = proofBytes("heterodyne-node-advert-v1", {
    endpoint: endpointTag[1]!,
    expiry: expiryText,
    nid,
    repo_head: repoHeadTag[1]!,
    rid: ridTag[1]!,
  });
  return message !== undefined && verifyEd25519Proof(proof[1]!, message, nidPublicKey)
    ? undefined
    : "nid_proof_invalid";
}

function subtypeFailure(
  event: NostrSignedEvent,
  context: CoreVerificationContextV1,
): string | undefined {
  if (context.subtype_policy.mode === "generic") {
    return undefined;
  }
  return context.subtype_policy.mode === "nid-delegation"
    ? nidDelegationFailure(event, context, context.subtype_policy.nid_pubkey)
    : nodeAdvertisementFailure(event, context.subtype_policy.nid_pubkey);
}

export function checkCoreSignedEvent(
  vector: VectorDocument,
  check: ConformanceCheckDocument,
): SubjectResult {
  const stages: StageResult[] = [];
  let resolved;
  try {
    resolved = resolveJsonPointer(vector, check.event_pointer);
  } catch {
    return reject(stages, "event_structure");
  }
  if (!resolved.found || !isNostrSignedEvent(resolved.value)) {
    return reject(stages, "event_structure");
  }
  const event = resolved.value;
  stages.push({ stage: "event_structure", verdict: "pass" });

  let rawResolved;
  try {
    rawResolved = resolveJsonPointer(vector, check.nip01_raw_pointer);
  } catch {
    return reject(stages, "nip01_raw", "nip01_raw_mismatch");
  }
  const bound = bindNip01Raw(event, rawResolved.found ? rawResolved.value : undefined);
  if (bound === undefined) {
    return reject(stages, "nip01_raw", "nip01_raw_mismatch");
  }
  stages.push({ stage: "nip01_raw", verdict: "pass" });

  const digest = computeNip01Digest(bound.bytes);
  const identifier = Buffer.from(digest).toString("hex");
  if (identifier !== event.id) {
    return reject(stages, "identifier", "bad_signature");
  }
  stages.push({ stage: "identifier", verdict: "pass" });

  if (!verifyNip01Signature(event, digest)) {
    return reject(stages, "signature", "bad_signature");
  }
  stages.push({ stage: "signature", verdict: "pass" });

  const context = resolveContext(vector, check, event);
  if (context === undefined) {
    return reject(stages, "persona_resolution", "delegation_mismatch");
  }
  stages.push({ stage: "persona_resolution", verdict: "pass" });

  if (!hasValidVersionStamp(event, context.version_policy)) {
    return reject(stages, "version_stamp");
  }
  stages.push({ stage: "version_stamp", verdict: "pass" });

  const headFailure = kelHeadFailure(event, context);
  if (headFailure !== undefined) {
    return reject(stages, "kel_head", headFailure);
  }
  stages.push({ stage: "kel_head", verdict: "pass" });

  const authorityReason = authorityFailure(event, context);
  if (authorityReason !== undefined) {
    return reject(stages, "epoch_authority", authorityReason);
  }
  stages.push({ stage: "epoch_authority", verdict: "pass" });

  const subtypeReason = subtypeFailure(event, context);
  if (subtypeReason !== undefined) {
    return reject(stages, "subtype_nid", subtypeReason);
  }
  stages.push({ stage: "subtype_nid", verdict: "pass" });
  stages.push({ stage: "accept", verdict: "pass" });
  return { terminalStage: "accept", verdict: "accept", stages };
}
