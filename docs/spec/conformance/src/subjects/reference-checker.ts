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
const QUALIFIED_HETERODYNE_VERSION =
  /^heterodyne\/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u;

function reject(
  stages: StageResult[],
  stage: CheckerStage,
  reasonCode: string,
): SubjectResult {
  const terminal: StageResult = { stage, verdict: "reject", reasonCode };
  return {
    terminalStage: stage,
    verdict: "reject",
    reasonCode,
    stages: [...stages, terminal],
  };
}

function equivocation(stages: StageResult[]): SubjectResult {
  return {
    terminalStage: "kel_head",
    verdict: "equivocation_flagged",
    stages: [...stages, { stage: "kel_head", verdict: "equivocation_flagged" }],
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

  const pointerHeadOnKel = context.kel.some((entry) =>
    context.pointer.kel_head.event_id === entry.event_id
    && context.pointer.kel_head.sequence === entry.sequence);
  if (!pointerHeadOnKel) {
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

function topLevelJsonObjectMemberNames(source: string): string[] | undefined {
  const firstToken = source.search(/\S/u);
  if (firstToken < 0 || source[firstToken] !== "{") {
    return [];
  }

  const names: string[] = [];
  let depth = 0;
  for (let index = firstToken; index < source.length; index += 1) {
    const character = source[index]!;
    if (character === "{" || character === "[") {
      depth += 1;
    } else if (character === "}" || character === "]") {
      depth -= 1;
    } else if (character === '"') {
      const start = index;
      index += 1;
      while (index < source.length && source[index] !== '"') {
        if (source[index] === "\\") {
          index += 1;
        }
        index += 1;
      }
      if (index >= source.length) {
        return undefined;
      }
      let next = index + 1;
      while (/\s/u.test(source[next] ?? "")) {
        next += 1;
      }
      if (depth === 1 && source[next] === ":") {
        try {
          names.push(JSON.parse(source.slice(start, index + 1)) as string);
        } catch {
          return undefined;
        }
      }
    }
  }
  return names;
}

function versionStampFailure(
  event: NostrSignedEvent,
  policy: CoreVerificationContextV1["version_policy"],
): { invalid: false } | { invalid: true; reasonCode: string } {
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
      const memberNames = topLevelJsonObjectMemberNames(event.content);
      if (
        memberNames === undefined
        || memberNames.filter((name) => name === "spec_version").length !== 1
      ) {
        return { invalid: true, reasonCode: "version_stamp_invalid" };
      }
      stamps.push((content as Record<string, unknown>).spec_version);
    }
  } catch {
    // A non-JSON content value simply has no content-carried stamp.
  }

  if (policy.mode === "forbidden") {
    return stamps.length === 0
      ? { invalid: false }
      : { invalid: true, reasonCode: "version_stamp_invalid" };
  }
  if (
    (policy.mode === "required" && stamps.length !== 1)
    || (policy.mode === "optional" && stamps.length > 1)
  ) {
    return { invalid: true, reasonCode: "version_stamp_invalid" };
  }
  if (stamps.some((stamp) => stamp !== policy.value)) {
    const hasFutureMajor = stamps.some((stamp) => {
      if (typeof stamp !== "string") return false;
      const match = QUALIFIED_HETERODYNE_VERSION.exec(stamp);
      return match !== null && Number(match[1]) > 0;
    });
    return hasFutureMajor
      ? { invalid: true, reasonCode: "unknown_major_version" }
      : { invalid: true, reasonCode: "version_stamp_invalid" };
  }
  return { invalid: false };
}

type KelHeadResult =
  | { verdict: "pass" | "provisional" }
  | { verdict: "reject"; reasonCode: string }
  | { verdict: "equivocation_flagged" };

function classifyKelHead(
  event: NostrSignedEvent,
  context: CoreVerificationContextV1,
): KelHeadResult {
  const tags = event.tags.filter((tag) => tag[0] === "kel_head");
  const mode = context.kel_head_policy.mode;
  if (mode === "forbidden") {
    return tags.length === 0
      ? { verdict: "pass" }
      : { verdict: "reject", reasonCode: "kel_head_forbidden" };
  }
  if (tags.length === 0) {
    return mode === "required"
      ? { verdict: "reject", reasonCode: "kel_head_missing" }
      : { verdict: "pass" };
  }
  if (tags.length !== 1) {
    return { verdict: "reject", reasonCode: "kel_head_missing" };
  }

  const tag = tags[0]!;
  if (
    tag.length !== 3
    || !/^[0-9a-f]{64}$/u.test(tag[1]!)
    || !/^(?:0|[1-9][0-9]*)$/u.test(tag[2]!)
  ) {
    return { verdict: "reject", reasonCode: "kel_head_missing" };
  }
  const sequence = Number(tag[2]);
  if (!Number.isSafeInteger(sequence)) {
    return { verdict: "reject", reasonCode: "kel_head_missing" };
  }
  const namedEntry = context.kel.find((entry) => entry.event_id === tag[1]);
  if (namedEntry !== undefined && sequence !== namedEntry.sequence) {
    return { verdict: "reject", reasonCode: "kel_head_mismatch" };
  }
  const acceptedHead = context.kel.at(-1)!;
  if (sequence > acceptedHead.sequence) {
    return context.kel_refresh.status === "succeeded"
      ? { verdict: "equivocation_flagged" }
      : { verdict: "provisional" };
  }
  return namedEntry === undefined
    ? { verdict: "equivocation_flagged" }
    : { verdict: "pass" };
}

function effectiveCompromiseCutoff(
  entry: CoreVerificationContextV1["kel"][number],
): number | undefined {
  if (entry.compromise_since === null) return undefined;
  const effectiveCompromiseSince = entry.effective_until === null
    ? entry.compromise_since
    : Math.min(entry.compromise_since, entry.effective_until);
  return effectiveCompromiseSince - 300;
}

function epochEntryAt(
  context: CoreVerificationContextV1,
  at: number,
): { entry?: CoreVerificationContextV1["kel"][number]; reasonCode?: string } {
  const entry = context.kel.find((candidate) =>
    at >= candidate.effective_from
    && (candidate.effective_until === null || at < candidate.effective_until));
  if (entry === undefined) return { reasonCode: "retired-key-authority-window-invalid" };
  const cutoff = effectiveCompromiseCutoff(entry);
  if (cutoff !== undefined && at >= cutoff) {
    return { reasonCode: "signing_key_compromised_at_created_at" };
  }
  return { entry };
}

function authorityFailure(
  event: NostrSignedEvent,
  context: CoreVerificationContextV1,
): string | undefined {
  const atEvent = epochEntryAt(context, event.created_at);
  if (atEvent.reasonCode !== undefined) return atEvent.reasonCode;
  const entry = atEvent.entry!;

  if (context.signer.type === "epoch") {
    if (context.signer.pubkey !== entry.epoch_pubkey) {
      return "retired-key-authority-window-invalid";
    }
    if (event.kind === 31_001) {
      const atEvaluation = epochEntryAt(context, context.evaluation_time);
      if (atEvaluation.entry?.epoch_pubkey !== context.signer.pubkey) {
        return "retired-key-authority-window-invalid";
      }
    }
    return undefined;
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

function encodeBase58(value: Uint8Array): string {
  let number = 0n;
  for (const byte of value) number = number * 256n + BigInt(byte);
  let encoded = "";
  while (number > 0n) {
    encoded = BASE58_ALPHABET[Number(number % 58n)]! + encoded;
    number /= 58n;
  }
  let zeroes = 0;
  while (value[zeroes] === 0) zeroes += 1;
  return "1".repeat(zeroes) + encoded;
}

function isCanonicalRadicleRid(value: string): boolean {
  if (!value.startsWith("rad:z")) return false;
  const body = value.slice("rad:z".length);
  const decoded = decodeBase58(body);
  return decoded !== undefined && decoded.length === 20 && encodeBase58(decoded) === body;
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
  if (context.signer.type !== "epoch") {
    return "delegation_mismatch";
  }
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
      || Number(validUntil[1])
        <= context.evaluation_time - context.nid_clock_skew_allowance)
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
  context: CoreVerificationContextV1,
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
    || !isCanonicalRadicleRid(ridTag[1]!)
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
  if (context.clock_uncertainty > 300) {
    return "node-advert-clock-uncertain";
  }
  if (Math.abs(event.created_at - context.evaluation_time) > 300) {
    return "node-advert-clock-skew";
  }
  if (context.evaluation_time >= expiry) {
    return "node_advert_expired";
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
    : nodeAdvertisementFailure(event, context, context.subtype_policy.nid_pubkey);
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
    return reject(stages, "event_structure", "bad_signature");
  }
  if (!resolved.found || !isNostrSignedEvent(resolved.value)) {
    return reject(stages, "event_structure", "bad_signature");
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

  const versionFailure = versionStampFailure(event, context.version_policy);
  if (versionFailure.invalid) {
    return reject(stages, "version_stamp", versionFailure.reasonCode);
  }
  stages.push({ stage: "version_stamp", verdict: "pass" });

  const head = classifyKelHead(event, context);
  if (head.verdict === "reject") {
    return reject(stages, "kel_head", head.reasonCode);
  }
  if (head.verdict === "equivocation_flagged") {
    return equivocation(stages);
  }
  const provisional = head.verdict === "provisional";
  stages.push({ stage: "kel_head", verdict: provisional ? "provisional" : "pass" });

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
  stages.push({ stage: "accept", verdict: provisional ? "provisional" : "pass" });
  return {
    terminalStage: "accept",
    verdict: provisional ? "accept_provisional" : "accept",
    stages,
  };
}
