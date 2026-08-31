import { createPublicKey, verify as verifyNativeSignature, type JsonWebKey } from "node:crypto";
import { types as utilTypes } from "node:util";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/nist";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { proofBytes } from "./proof-bytes.js";
import {
  canonicalNip01,
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";
import { didKeyFromEd25519 } from "./radicle.js";
import { reasonCodeValues } from "./reason-codes.js";
import {
  validateClaimRevocationSchemaOrThrow,
  validateKeyClaimSchemaOrThrow,
} from "./schema.js";
import {
  evaluateCredentialGeneration,
  type CredentialLedgerBinding,
} from "./credential-generation.js";

export type KeyRef =
  | { type: "nostr-secp256k1"; value: string }
  | { type: "radicle-ed25519-nid"; value: string }
  | { type: "jwk-thumbprint"; value: string };

export type ClaimClass = "descriptive" | "authorization";
export type ClaimVisibility = "public" | "pairwise-private" | "repository-private" | "local-only";
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export const CLAIM_REVOCATION_PROFILE = {
  spec_version: "heterodyne/0.6.0",
  profile_revision: 2,
} as const;

export const CLAIM_REVOCATION_OPERATION_BUDGET = 10_000;

export type DelegationConstraints = {
  namespaces: string[];
  audiences: string[];
  resources: string[];
  remaining_depth: number;
};

export type ClaimSemanticBody = {
  claim_id: string;
  issuer: KeyRef;
  subject: KeyRef;
  claim_class: ClaimClass;
  credential_ledger_persona: string | null;
  credential_ledger_generation: number | null;
  namespace: string;
  name: string;
  value: JsonValue;
  issued_at: number;
  not_before: number;
  expires_at?: number;
  audience?: string[];
  resources?: string[];
  visibility: ClaimVisibility;
  parent_claim_id?: string;
  constraints?: DelegationConstraints;
  revokers?: KeyRef[];
  spec_version: "heterodyne/0.6.0";
  profile_revision: 2;
};

export type KeyProof =
  | { type: "nostr-bip340"; signature: string }
  | { type: "radicle-ed25519"; public_key: string; signature: string }
  | { type: "jwk-jws"; jwk: Record<string, JsonValue>; protected: string; signature: string };

export type ClaimRevocation = {
  claim_id: string;
  revoked_at: number;
  reason_code: string;
  revoker: KeyRef;
  proof?: KeyProof;
  spec_version: "heterodyne/0.6.0";
  profile_revision: 2;
};

export type VerifiedRevocation = ClaimRevocation & {
  signer: KeyRef;
  event_id: string;
  event_created_at: number;
};

declare const verifiedClaimArtifactBrand: unique symbol;
declare const verifiedClaimRevocationArtifactBrand: unique symbol;

export type VerifiedClaimArtifact = Readonly<{
  readonly [verifiedClaimArtifactBrand]: true;
}>;

export type VerifiedClaimRevocationArtifact = Readonly<{
  readonly [verifiedClaimRevocationArtifactBrand]: true;
}>;

export type SubjectProofChallenge = {
  domain: "heterodyne-claim-pop-v1";
  claim_id: string;
  nonce: string;
  audience: string;
  resource: string;
  operation: string;
  issued_at: number;
  expires_at: number;
};

export type ClaimEnvelopeContext = {
  profile_revision: 2;
  credential_ledger: CredentialLedgerBinding;
  existing_semantic_body?: ClaimSemanticBody;
  existing_verified_claim?: VerifiedClaimArtifact;
  readonly [member: string]: unknown;
};

export type ClaimState =
  | "invalid"
  | "untrusted"
  | "provisional"
  | "active"
  | "expired"
  | "revoked"
  | "conflicted";

export type ClaimVerificationContext = {
  now: number;
  audience: string;
  resource: string;
  requested_namespace: string;
  requested_operation: string;
  expected_nonce: string;
  used_nonces: Set<string>;
  trusted_issuers: KeyRef[];
  credential_ledger: CredentialLedgerBinding;
  repository_confirmed: Set<string>;
  repository_conflicted: Set<string>;
  revocations: readonly unknown[];
  subject_proof: { key: KeyRef; challenge: SubjectProofChallenge; proof: KeyProof } | null;
  /** Transitional structural compatibility; unrecognized members never grant authority. */
  readonly [member: string]: any;
};

export type AuthorizationDecision = {
  allowed: boolean;
  state: ClaimState;
  reason_code: string | null;
};

type RevocationProofBody = Pick<
  ClaimRevocation,
  "claim_id" | "revoked_at" | "reason_code" | "spec_version" | "profile_revision"
>;

const CLAIM_KIND = 31013;
const REVOCATION_KIND = 31014;
const CLAIM_ID_PATTERN = /^[0-9a-f]{64}$/;
const LOWER_HEX_32_PATTERN = /^[0-9a-f]{64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const REGISTERED_REASON_CODES = new Set(reasonCodeValues());
const PRIVATE_JWK_MEMBERS = new Set(["d", "k", "p", "q", "dp", "dq", "qi", "oth"]);
const REMOTE_JWK_MEMBERS = new Set(["jku", "x5u"]);
const NIP01_SIGNED_EVENT_FIELDS = ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"];
const CLAIM_VERIFIER_IDENTITY = Object.freeze({});
const MAX_CLAIM_ARTIFACT_MAP_SIZE = 256;
const MAX_CLAIM_CHAIN_LENGTH = 9;
const MAX_REVOCATION_ARTIFACTS = 256;
const MAX_CONTEXT_SET_SIZE = 256;
const MAP_ENTRIES = Map.prototype.entries;
const MAP_SIZE_GETTER = Object.getOwnPropertyDescriptor(Map.prototype, "size")!.get!;
const MAP_ITERATOR_NEXT = Object.getPrototypeOf(new Map().entries()).next as (
  this: MapIterator<unknown>,
) => IteratorResult<unknown>;
const SET_VALUES = Set.prototype.values;
const SET_SIZE_GETTER = Object.getOwnPropertyDescriptor(Set.prototype, "size")!.get!;
const SET_ITERATOR_NEXT = Object.getPrototypeOf(new Set().values()).next as (
  this: SetIterator<unknown>,
) => IteratorResult<unknown>;

type VerifiedClaimRecord = Readonly<{
  verifier: object;
  event: VerifiedNostrEvent;
  nip01_raw: string;
  semantic_bytes: string;
  semantic: ClaimSemanticBody;
  claim_id: string;
  issuer_pubkey: string;
  event_id: string;
  issued_at: number;
  credential_ledger_persona: string | null;
  credential_ledger_generation: number | null;
  chain_binding_digest: string;
}>;

type VerifiedClaimRevocationRecord = Readonly<{
  verifier: object;
  event: VerifiedNostrEvent;
  nip01_raw: string;
  semantic_bytes: string;
  semantic: ClaimRevocation;
  claim_id: string;
  signer: KeyRef;
  event_id: string;
  revoked_at: number;
  chain_binding_digest: string;
}>;

const VERIFIED_CLAIMS = new WeakMap<object, VerifiedClaimRecord>();
const VERIFIED_CLAIM_REVOCATIONS = new WeakMap<object, VerifiedClaimRevocationRecord>();

export function computeClaimId(body: Omit<ClaimSemanticBody, "claim_id">): string {
  const { claim_id: _omitted, ...semantic } = body as Omit<ClaimSemanticBody, "claim_id"> & {
    claim_id?: unknown;
  };
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize(semantic))));
}

export function validateClaimId(body: ClaimSemanticBody): void {
  if (!CLAIM_ID_PATTERN.test(body.claim_id)) {
    throw new Error("claim_id must be lowercase 64-character hexadecimal");
  }
  if (body.claim_id !== computeClaimId(body)) {
    throw new Error("claim-id-mismatch: claim_id does not match the canonical semantic body");
  }
}

export function verifyClaimEnvelope(
  sourceEvent: NostrSignedEvent,
  context: ClaimEnvelopeContext,
): VerifiedClaimArtifact {
  const record = verifyClaimRecord(sourceEvent, context);
  const artifact = Object.freeze({}) as VerifiedClaimArtifact;
  VERIFIED_CLAIMS.set(artifact, record);
  return artifact;
}

export function validateClaimEnvelope(
  sourceEvent: NostrSignedEvent,
  context: ClaimEnvelopeContext,
): VerifiedClaimArtifact {
  return verifyClaimEnvelope(sourceEvent, context);
}

export function inspectVerifiedClaim(artifact: VerifiedClaimArtifact): ClaimSemanticBody {
  return deepFreezeJsonClone(requireVerifiedClaimRecord(artifact).semantic);
}

export function verifyLedgerClaimArtifact(
  value: unknown,
  context: ClaimEnvelopeContext,
): VerifiedClaimArtifact {
  const wire = captureEmbeddedArtifact(value, "claim_artifact");
  const duplicate = deepFreezeJson(
    snapshotJsonNode(wire.semantic, new Set<object>()) as ClaimSemanticBody,
  );
  const artifact = verifyClaimEnvelope(wire.event as NostrSignedEvent, context);
  if (jcsCanonicalize(duplicate) !== jcsCanonicalize(inspectVerifiedClaim(artifact))) {
    throw new Error("claim-id-mismatch: claim artifact semantic does not equal signed event content");
  }
  return artifact;
}

function verifyClaimRecord(
  sourceEvent: NostrSignedEvent,
  context: ClaimEnvelopeContext,
): VerifiedClaimRecord {
  const event = requireVerifiedClaimEvent(sourceEvent);
  const capturedContext = captureClaimEnvelopeContext(context);
  assertAddressedCommsEvent(event, CLAIM_KIND);
  const parsed = parseCanonicalContent(event.content, "claim") as unknown;
  if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) &&
      !Object.prototype.hasOwnProperty.call(parsed, "credential_ledger_generation")) {
    throw new Error("credential_generation_missing");
  }
  validateKeyClaimSchemaOrThrow(parsed);
  const body = parsed as ClaimSemanticBody;
  validateKeyRef(body.issuer);
  validateKeyRef(body.subject);
  for (const revoker of body.revokers ?? []) validateKeyRef(revoker);
  if (body.issuer.type !== "nostr-secp256k1" || body.issuer.value !== event.pubkey) {
    throw new Error("claim-key-reference-invalid: outer Nostr signer must equal the typed claim issuer");
  }
  validateClaimId(body);
  assertSingleAddress(event, body.claim_id);
  if (capturedContext.profile_revision !== 2 || body.profile_revision !== capturedContext.profile_revision) {
    throw new Error("claim-schema-invalid: registry revision does not match the supplied context");
  }
  if (body.claim_class === "authorization") {
    const generation = evaluateCredentialGeneration(body, capturedContext.credential_ledger);
    if (!generation.valid) throw new Error(generation.reason_code);
  } else if (body.credential_ledger_persona !== null || body.credential_ledger_generation !== null) {
    throw new Error("credential_schema_invalid");
  }
  const existing = capturedContext.existing_verified_claim === undefined
    ? capturedContext.existing_semantic_body
    : requireVerifiedClaimRecord(capturedContext.existing_verified_claim).semantic;
  if (
    existing !== undefined &&
    jcsCanonicalize(existing) !== event.content
  ) {
    throw new Error("claim-repository-conflict: semantic body at an existing address must be identical");
  }
  const semantic = deepFreezeJson(body);
  const nip01Raw = canonicalNip01(event);
  return Object.freeze({
    verifier: CLAIM_VERIFIER_IDENTITY,
    event,
    nip01_raw: nip01Raw,
    semantic_bytes: event.content,
    semantic,
    claim_id: semantic.claim_id,
    issuer_pubkey: event.pubkey,
    event_id: event.id,
    issued_at: semantic.issued_at,
    credential_ledger_persona: semantic.credential_ledger_persona,
    credential_ledger_generation: semantic.credential_ledger_generation,
    chain_binding_digest: bindingDigest("heterodyne-verified-claim-artifact-v1", {
      event_id: event.id,
      issuer_pubkey: event.pubkey,
      nip01_raw: nip01Raw,
      semantic_bytes: event.content,
    }),
  });
}

export function revocationProofPayload(body: RevocationProofBody): Uint8Array {
  return proofBytes("heterodyne-claim-revocation-v1", {
    claim_id: body.claim_id,
    profile_revision: body.profile_revision,
    reason_code: body.reason_code,
    revoked_at: body.revoked_at,
    spec_version: body.spec_version,
  });
}

export function verifyClaimRevocationEnvelope(
  sourceEvent: NostrSignedEvent,
): VerifiedClaimRevocationArtifact {
  const record = verifyClaimRevocationRecord(sourceEvent);
  const artifact = Object.freeze({}) as VerifiedClaimRevocationArtifact;
  VERIFIED_CLAIM_REVOCATIONS.set(artifact, record);
  return artifact;
}

export function inspectVerifiedClaimRevocation(
  artifact: VerifiedClaimRevocationArtifact,
): VerifiedRevocation {
  return inspectedRevocation(requireVerifiedClaimRevocationRecord(artifact));
}

export function verifyLedgerClaimRevocationArtifact(
  value: unknown,
): VerifiedClaimRevocationArtifact {
  const wire = captureEmbeddedArtifact(value, "revocation_artifact");
  const duplicate = deepFreezeJson(
    snapshotJsonNode(wire.semantic, new Set<object>()) as ClaimRevocation,
  );
  const artifact = verifyClaimRevocationEnvelope(wire.event as NostrSignedEvent);
  const inspected = inspectVerifiedClaimRevocation(artifact);
  const {
    signer: _signer,
    event_id: _eventId,
    event_created_at: _eventCreatedAt,
    ...semantic
  } = inspected;
  if (jcsCanonicalize(duplicate) !== jcsCanonicalize(semantic)) {
    throw new Error("claim-id-mismatch: revocation artifact semantic does not equal signed event content");
  }
  return artifact;
}

export function validateClaimRevocationEnvelope(
  sourceEvent: NostrSignedEvent,
): VerifiedClaimRevocationArtifact {
  return verifyClaimRevocationEnvelope(sourceEvent);
}

function verifyClaimRevocationRecord(
  sourceEvent: NostrSignedEvent,
): VerifiedClaimRevocationRecord {
  const event = requireVerifiedClaimEvent(sourceEvent);
  assertAddressedCommsEvent(event, REVOCATION_KIND);
  const parsed = parseCanonicalContent(event.content, "revocation") as unknown;
  validateClaimRevocationSchemaOrThrow(parsed);
  const revocation = parsed as ClaimRevocation;
  validateKeyRef(revocation.revoker);
  assertSingleAddress(event, revocation.claim_id);
  if (!REGISTERED_REASON_CODES.has(revocation.reason_code)) {
    throw new Error(`claim-schema-invalid: unregistered reason_code ${revocation.reason_code}`);
  }
  if (revocation.revoked_at !== event.created_at) {
    throw new Error("claim-schema-invalid: revoked_at must equal signed event created_at");
  }
  verifyRevocationProof(event, revocation);
  const semantic = deepFreezeJson(revocation);
  const nip01Raw = canonicalNip01(event);
  return Object.freeze({
    verifier: CLAIM_VERIFIER_IDENTITY,
    event,
    nip01_raw: nip01Raw,
    semantic_bytes: event.content,
    semantic,
    claim_id: semantic.claim_id,
    signer: semantic.revoker,
    event_id: event.id,
    revoked_at: semantic.revoked_at,
    chain_binding_digest: bindingDigest("heterodyne-verified-claim-revocation-v1", {
      event_id: event.id,
      nip01_raw: nip01Raw,
      semantic_bytes: event.content,
    }),
  });
}

export function validateKeyRef(key: KeyRef): void {
  if (key.type === "nostr-secp256k1") {
    if (!LOWER_HEX_32_PATTERN.test(key.value)) {
      throw new Error("claim-key-reference-invalid: Nostr key must be lowercase 32-byte x-only hex");
    }
    try {
      schnorr.utils.lift_x(BigInt(`0x${key.value}`));
    } catch {
      throw new Error("claim-key-reference-invalid: Nostr key is not a secp256k1 x-coordinate");
    }
    return;
  }
  if (key.type === "radicle-ed25519-nid") {
    decodeEd25519Nid(key.value);
    return;
  }
  if (key.type === "jwk-thumbprint") {
    if (!/^[A-Za-z0-9_-]{43}$/.test(key.value)) {
      throw new Error("claim-key-reference-invalid: JWK thumbprint must be a canonical SHA-256 base64url value");
    }
    const decoded = decodeCanonicalBase64url(key.value, "JWK thumbprint");
    if (decoded.length !== 32) {
      throw new Error("claim-key-reference-invalid: JWK thumbprint must decode to exactly 32 bytes");
    }
    return;
  }
  throw new Error("claim-key-reference-invalid: unsupported typed key reference");
}

/**
 * Resolves a claim chain deterministically from its leaf to its root and
 * returns the canonical root-to-leaf order used by every later decision.
 */
export function verifyClaimChain(
  leaf: VerifiedClaimArtifact,
  claimsById: ReadonlyMap<string, VerifiedClaimArtifact>,
): readonly VerifiedClaimArtifact[] {
  const leafRecord = requireVerifiedClaimRecord(leaf);
  const captured = captureClaimArtifactMap(claimsById);
  const mappedLeaf = captured.get(leafRecord.claim_id);
  if (mappedLeaf !== undefined && mappedLeaf.value !== leaf) {
    throw new Error("claim-issuer-authority-invalid: leaf artifact identity differs from artifact map");
  }
  const reversed: VerifiedClaimArtifact[] = [];
  const reversedRecords: VerifiedClaimRecord[] = [];
  const seen = new Set<string>();
  let current = leaf;
  let currentRecord = leafRecord;
  let edges = 0;
  while (true) {
    if (seen.has(currentRecord.claim_id)) {
      throw new Error(`claim-chain-cycle: repeated claim ${currentRecord.claim_id}`);
    }
    seen.add(currentRecord.claim_id);
    reversed.push(current);
    reversedRecords.push(currentRecord);
    if (currentRecord.semantic.parent_claim_id === undefined) break;
    edges += 1;
    if (edges > 8) {
      throw new Error("claim-chain-depth-exceeded: issuance chain exceeds eight edges");
    }
    const parent = captured.get(currentRecord.semantic.parent_claim_id);
    if (parent === undefined) {
      throw new Error(`claim-delegation-not-authorized: missing ancestor ${currentRecord.semantic.parent_claim_id}`);
    }
    current = parent.value;
    currentRecord = parent.record;
  }
  const chain = reversed.reverse();
  const records = reversedRecords.reverse();
  validateResolvedChain(leafRecord.semantic, records.map(({ semantic }) => semantic));
  if (records[records.length - 1] !== leafRecord || chain[chain.length - 1] !== leaf) {
    throw new Error("claim-delegation-not-authorized: chain identity does not terminate at leaf artifact");
  }
  return Object.freeze(chain);
}

export function subjectProofPayload(
  challenge: SubjectProofChallenge,
): Uint8Array {
  const { domain, ...claim } = challenge;
  return proofBytes(domain, claim);
}

export function resolveClaimState(
  leaf: VerifiedClaimArtifact,
  chain: readonly VerifiedClaimArtifact[],
  context: ClaimVerificationContext,
): ClaimState {
  return evaluateClaim(leaf, chain, context).state;
}

export function authorizeWithClaim(
  leaf: VerifiedClaimArtifact,
  chain: readonly VerifiedClaimArtifact[],
  context: ClaimVerificationContext,
): AuthorizationDecision {
  const result = evaluateClaim(leaf, chain, context);
  return {
    // Task 6 owns durable proof acquisition and the authorization effect.
    allowed: false,
    state: result.state,
    reason_code: result.reason_code,
  };
}

export function isClaimRevocationAuthorized(
  target: VerifiedClaimArtifact,
  chain: readonly VerifiedClaimArtifact[],
  candidate: VerifiedClaimRevocationArtifact,
  context: ClaimVerificationContext,
): boolean {
  return inspectClaimRevocationAuthorityEvaluation(target, chain, candidate, context).authorized;
}

export type ClaimRevocationAuthorityEvaluation = Readonly<{
  authorized: boolean;
  rejected: boolean;
  operations: number;
  operation_budget: number;
}>;

export function inspectClaimRevocationAuthorityEvaluation(
  target: VerifiedClaimArtifact,
  chain: readonly VerifiedClaimArtifact[],
  candidate: VerifiedClaimRevocationArtifact,
  context: ClaimVerificationContext,
): ClaimRevocationAuthorityEvaluation {
  const budget = { operations: 0 };
  try {
    const targetRecord = requireVerifiedClaimRecord(target);
    const chainRecords = captureClaimArtifactArray(chain);
    if (chainRecords.length === 0 || chainRecords[chainRecords.length - 1] !== targetRecord) {
      throw new Error("claim-revoker-unauthorized: chain identity mismatch");
    }
    validateResolvedChain(targetRecord.semantic, chainRecords.map(({ semantic }) => semantic));
    const candidateRecord = requireVerifiedClaimRevocationRecord(candidate);
    const capturedContext = captureRevocationAuthorityContext(context);
    const alreadyPresent = capturedContext.revocations.find((record) => record === candidateRecord);
    if (alreadyPresent === undefined &&
        capturedContext.revocations.some((record) => record.event_id === candidateRecord.event_id)) {
      throw new Error("claim-revoker-unauthorized: duplicate revocation event ID");
    }
    const revocations = alreadyPresent === undefined
      ? chronologicalRevocationSnapshot([...capturedContext.revocations, candidateRecord])
      : capturedContext.revocations;
    const result = evaluateRevocationTimeline(
      chainRecords,
      revocations,
      capturedContext,
      capturedContext.now,
      candidateRecord.event_id,
      budget,
    );
    return Object.freeze({
      authorized: result.requested_authorized,
      rejected: false,
      operations: budget.operations,
      operation_budget: CLAIM_REVOCATION_OPERATION_BUDGET,
    });
  } catch {
    return Object.freeze({
      authorized: false,
      rejected: true,
      operations: Math.min(budget.operations, CLAIM_REVOCATION_OPERATION_BUDGET),
      operation_budget: CLAIM_REVOCATION_OPERATION_BUDGET,
    });
  }
}

type ClaimEvaluation = Pick<AuthorizationDecision, "state" | "reason_code">;

/** Implements the approved eight-stage authentication-before-policy order. */
function evaluateClaim(
  leafArtifact: unknown,
  chainArtifacts: readonly unknown[],
  context: ClaimVerificationContext,
): ClaimEvaluation {
  let leafRecord: VerifiedClaimRecord;
  let chainRecords: VerifiedClaimRecord[];
  let capturedContext: RevocationAuthorityContextSnapshot;
  try {
    leafRecord = requireVerifiedClaimRecord(leafArtifact);
    chainRecords = captureClaimArtifactArray(chainArtifacts);
    capturedContext = captureRevocationAuthorityContext(context);
    if (
      chainRecords.length === 0 ||
      chainRecords[chainRecords.length - 1] !== leafRecord
    ) throw new Error("claim-delegation-not-authorized: supplied chain does not terminate at leaf artifact");
  } catch (error) {
    return invalidEvaluation(error, "claim-issuer-authority-invalid");
  }
  const leaf = leafRecord.semantic;
  const chain = chainRecords.map(({ semantic }) => semantic);
  for (const claim of chain) {
    if (!Object.prototype.hasOwnProperty.call(claim, "credential_ledger_generation")) {
      return { state: "invalid", reason_code: "credential_generation_missing" };
    }
    if (claim.claim_class === "authorization") {
      const generation = evaluateCredentialGeneration(claim, capturedContext.credential_ledger);
      if (!generation.valid) return { state: "invalid", reason_code: generation.reason_code };
    } else if (claim.credential_ledger_persona !== null || claim.credential_ledger_generation !== null) {
      return { state: "invalid", reason_code: "credential_schema_invalid" };
    }
  }

  // 1. Canonical semantic content and claim identifiers.
  try {
    for (const claim of chain) {
      validateClaimId(claim);
      validateKeyRef(claim.issuer);
      validateKeyRef(claim.subject);
    }
    if (chain.length === 0 || !sameClaim(chain[chain.length - 1], leaf)) {
      throw new Error("claim-delegation-not-authorized: supplied chain does not terminate at leaf");
    }
  } catch (error) {
    return invalidEvaluation(error);
  }

  // 2. Consume only exact verifier-minted envelope artifacts.
  for (const record of chainRecords) {
    if (
      record.verifier !== CLAIM_VERIFIER_IDENTITY ||
      record.event_id !== record.event.id ||
      record.issuer_pubkey !== record.event.pubkey ||
      record.semantic_bytes !== record.event.content ||
      canonicalNip01(record.event) !== record.nip01_raw ||
      record.semantic.issuer.type !== "nostr-secp256k1" ||
      record.semantic.issuer.value !== record.issuer_pubkey
    ) {
      return { state: "invalid", reason_code: "claim-issuer-authority-invalid" };
    }
  }

  // 3-4. Resolve the issuance chain, then prove attenuation/depth.
  try {
    validateResolvedChain(leaf, chain);
  } catch (error) {
    return invalidEvaluation(error);
  }

  // 5. Time, audience, namespace, resource, and subject type.
  if (chain.some((claim) => capturedContext.now < claim.not_before)) {
    return { state: "invalid", reason_code: "claim-issuer-authority-invalid" };
  }
  if (chain.some((claim) => claim.expires_at !== undefined && capturedContext.now >= claim.expires_at)) {
    return { state: "expired", reason_code: "claim-expired" };
  }
  if (context.requested_namespace !== leaf.namespace) {
    return { state: "invalid", reason_code: "claim-attenuation-violation" };
  }
  if (
    leaf.claim_class === "authorization" &&
    (
      leaf.audience === undefined || leaf.audience.length === 0 ||
      leaf.resources === undefined || leaf.resources.length === 0
    )
  ) {
    return { state: "invalid", reason_code: "claim-attenuation-violation" };
  }
  if (!matchesRestriction(leaf.audience, context.audience) || !matchesRestriction(leaf.resources, context.resource)) {
    return { state: "invalid", reason_code: "claim-attenuation-violation" };
  }
  try {
    validateKeyRef(leaf.subject);
  } catch (error) {
    return invalidEvaluation(error);
  }

  // 6. Authenticated monotonic reductions win before repository confirmation.
  if (isRevoked(chainRecords, capturedContext)) {
    return { state: "revoked", reason_code: "claim-revoked" };
  }
  if (chain.some((claim) => capturedContext.repository_conflicted.includes(claim.claim_id))) {
    return { state: "conflicted", reason_code: "claim-repository-conflict" };
  }
  if (chain.some((claim) =>
    claim.claim_class === "authorization" &&
    !capturedContext.repository_confirmed.includes(claim.claim_id)
  )) {
    return { state: "provisional", reason_code: "claim-repository-unconfirmed" };
  }

  // 7. Authorization requires fresh proof by the exact subject key.
  if (leaf.claim_class === "authorization") {
    if (context.subject_proof === null) {
      return { state: "invalid", reason_code: "claim-subject-proof-required" };
    }
    try {
      verifySubjectProof(leaf, context);
    } catch {
      return { state: "invalid", reason_code: "claim-subject-proof-invalid" };
    }
  }

  // 8. Local trust/release policy is deliberately last.
  const trustAnchor = chain[0].issuer;
  if (!capturedContext.trusted_issuers.some((candidate) => sameKeyRef(candidate, trustAnchor))) {
    return { state: "untrusted", reason_code: "claim-issuer-untrusted" };
  }
  return { state: "active", reason_code: null };
}

function validateResolvedChain(leaf: ClaimSemanticBody, chain: ClaimSemanticBody[]): void {
  if (chain.length === 0 || chain.length > 9) {
    throw new Error("claim-chain-depth-exceeded: issuance chain exceeds eight edges");
  }
  if (!sameClaim(chain[chain.length - 1], leaf)) {
    throw new Error("claim-delegation-not-authorized: supplied chain does not terminate at leaf");
  }
  const ids = new Set<string>();
  for (let index = 0; index < chain.length; index += 1) {
    const claim = chain[index];
    if (ids.has(claim.claim_id)) throw new Error(`claim-chain-cycle: repeated claim ${claim.claim_id}`);
    ids.add(claim.claim_id);
    if (index === 0) {
      if (claim.parent_claim_id !== undefined) {
        throw new Error(`claim-delegation-not-authorized: missing ancestor ${claim.parent_claim_id}`);
      }
      continue;
    }
    const parent = chain[index - 1];
    if (claim.parent_claim_id !== parent.claim_id || !sameKeyRef(claim.issuer, parent.subject)) {
      throw new Error("claim-delegation-not-authorized: parent subject did not authorize the child issuer");
    }
    if (parent.claim_class !== "authorization" || parent.constraints === undefined || parent.constraints.remaining_depth < 1) {
      throw new Error("claim-delegation-not-authorized: parent lacks an explicit claim-issuance capability");
    }
    assertAttenuated(parent, claim);
  }
}

function assertAttenuated(parent: ClaimSemanticBody, child: ClaimSemanticBody): void {
  const constraints = parent.constraints!;
  if (
    (child.claim_class === "authorization" &&
      (child.credential_ledger_persona !== parent.credential_ledger_persona ||
       child.credential_ledger_generation !== parent.credential_ledger_generation)) ||
    child.namespace !== parent.namespace ||
    child.name !== parent.name ||
    jcsCanonicalize(child.value) !== jcsCanonicalize(parent.value) ||
    !constraints.namespaces.includes(child.namespace)
  ) {
    throw new Error("claim-attenuation-violation: child widened namespace, name, or atomic value scope");
  }
  if (child.issued_at < parent.issued_at || child.not_before < parent.not_before) {
    throw new Error("claim-attenuation-violation: child extended the lower validity bound");
  }
  if (
    parent.expires_at !== undefined &&
    (child.expires_at === undefined || child.expires_at > parent.expires_at)
  ) {
    throw new Error("claim-attenuation-violation: child extended the expiry bound");
  }
  if (!isSubset(child.audience, parent.audience) || !isSubset(child.audience, constraints.audiences)) {
    throw new Error("claim-attenuation-violation: child widened audience scope");
  }
  if (!isSubset(child.resources, parent.resources) || !isSubset(child.resources, constraints.resources)) {
    throw new Error("claim-attenuation-violation: child widened resource scope");
  }
  if (child.constraints !== undefined) {
    if (child.constraints.remaining_depth !== constraints.remaining_depth - 1) {
      throw new Error("claim-attenuation-violation: child did not decrement remaining depth exactly once");
    }
    if (
      !isSubset(child.constraints.namespaces, constraints.namespaces) ||
      !isSubset(child.constraints.audiences, constraints.audiences) ||
      !isSubset(child.constraints.resources, constraints.resources)
    ) {
      throw new Error("claim-attenuation-violation: child widened delegation constraints");
    }
  }
}

function verifySubjectProof(leaf: ClaimSemanticBody, context: ClaimVerificationContext): void {
  const presented = context.subject_proof!;
  const challenge = presented.challenge;
  if (
    !sameKeyRef(presented.key, leaf.subject) ||
    challenge.domain !== "heterodyne-claim-pop-v1" ||
    challenge.claim_id !== leaf.claim_id ||
    challenge.audience !== context.audience ||
    challenge.resource !== context.resource ||
    challenge.operation !== context.requested_operation ||
    challenge.nonce !== context.expected_nonce ||
    context.used_nonces.has(context.expected_nonce) ||
    typeof challenge.operation !== "string" || challenge.operation.length === 0 ||
    !/^[0-9a-f]{32,128}$/.test(challenge.nonce) ||
    !Number.isSafeInteger(challenge.issued_at) ||
    !Number.isSafeInteger(challenge.expires_at) ||
    challenge.expires_at <= challenge.issued_at ||
    challenge.expires_at - challenge.issued_at > 60 ||
    context.now < challenge.issued_at ||
    context.now >= challenge.expires_at
  ) {
    throw new Error("claim-subject-proof-invalid: challenge binding or freshness failed");
  }
  const payload = subjectProofPayload(challenge);
  if (leaf.subject.type === "nostr-secp256k1") {
    if (presented.proof.type !== "nostr-bip340") throw new Error("proof suite mismatch");
    const signature = parseLowerHex(presented.proof.signature, 64, "BIP-340 signature");
    let valid = false;
    try {
      valid = schnorr.verify(signature, payload, leaf.subject.value);
    } catch {
      valid = false;
    }
    if (!valid) throw new Error("claim-subject-proof-invalid: BIP-340 proof is invalid");
    return;
  }
  if (leaf.subject.type === "radicle-ed25519-nid") {
    if (presented.proof.type !== "radicle-ed25519") throw new Error("proof suite mismatch");
    const publicKey = parseLowerHex(presented.proof.public_key, 32, "Ed25519 public key");
    if (didKeyFromEd25519(presented.proof.public_key) !== leaf.subject.value) {
      throw new Error("claim-subject-proof-invalid: Ed25519 key does not derive subject NID");
    }
    const signature = parseLowerHex(presented.proof.signature, 64, "Ed25519 signature");
    if (!ed25519.verify(signature, payload, publicKey)) {
      throw new Error("claim-subject-proof-invalid: Ed25519 proof is invalid");
    }
    return;
  }
  if (presented.proof.type !== "jwk-jws") throw new Error("proof suite mismatch");
  if (computeJwkThumbprint(presented.proof.jwk) !== leaf.subject.value) {
    throw new Error("claim-subject-proof-invalid: JWK thumbprint does not match subject");
  }
  verifyDetachedJws(presented.proof, payload);
}

function isRevoked(
  chainRecords: VerifiedClaimRecord[],
  context: RevocationAuthorityContextSnapshot,
): boolean {
  const result = evaluateRevocationTimeline(
    chainRecords,
    context.revocations,
    context,
    context.now,
    null,
    { operations: 0 },
  );
  return result.revoked.some(Boolean);
}

type RevocationWorkBudget = { operations: number };

function consumeRevocationOperation(budget: RevocationWorkBudget): void {
  budget.operations += 1;
  if (budget.operations > CLAIM_REVOCATION_OPERATION_BUDGET) {
    throw new Error("claim-revoker-unauthorized: revocation operation budget exceeded");
  }
}

function evaluateRevocationTimeline(
  chainRecords: VerifiedClaimRecord[],
  revocations: readonly VerifiedClaimRevocationRecord[],
  context: RevocationAuthorityContextSnapshot,
  cutoff: number,
  requestedEventId: string | null,
  budget: RevocationWorkBudget,
): Readonly<{ revoked: readonly boolean[]; requested_authorized: boolean }> {
  const revoked = Array.from({ length: chainRecords.length }, () => false);
  let requestedAuthorized = false;
  const trustAnchor = chainRecords[0].semantic.issuer;
  const trusted = context.trusted_issuers.some((candidate) => sameKeyRef(candidate, trustAnchor));
  for (const candidate of revocations) {
    consumeRevocationOperation(budget);
    const revocation = candidate.semantic;
    if (revocation.revoked_at > cutoff) break;
    let targetIndex = -1;
    for (let index = 0; index < chainRecords.length; index += 1) {
      consumeRevocationOperation(budget);
      if (chainRecords[index].claim_id === revocation.claim_id) {
        targetIndex = index;
        break;
      }
    }
    if (targetIndex < 0) continue;
    const target = chainRecords[targetIndex].semantic;
    if (
      candidate.event.created_at !== revocation.revoked_at ||
      revocation.revoked_at < target.issued_at ||
      !sameKeyRef(revocation.revoker, candidate.signer)
    ) continue;
    const directIssuer = sameKeyRef(target.issuer, candidate.signer);
    const personaAuthorized = target.claim_class === "authorization" &&
      target.credential_ledger_persona !== null &&
      candidate.signer.type === "nostr-secp256k1" &&
      candidate.signer.value === target.credential_ledger_persona &&
      context.credential_ledger.credential_ledger_persona === target.credential_ledger_persona &&
      context.credential_ledger.credential_ledger_generation === target.credential_ledger_generation;
    let authorized = directIssuer || personaAuthorized ||
      target.claim_class === "authorization" && sameKeyRef(candidate.signer, target.subject) ||
      target.claim_class === "descriptive" &&
        (target.revokers ?? []).some((revoker) => sameKeyRef(revoker, candidate.signer));
    if (!authorized) {
      for (let superiorIndex = 0; superiorIndex < targetIndex; superiorIndex += 1) {
        consumeRevocationOperation(budget);
        if (
          sameKeyRef(chainRecords[superiorIndex].semantic.issuer, candidate.signer) &&
          claimWasActiveAtSnapshot(
            superiorIndex,
            revocation.revoked_at,
            chainRecords,
            revoked,
            context,
            trusted,
          )
        ) {
          authorized = true;
          break;
        }
      }
    }
    if (!authorized) continue;
    revoked[targetIndex] = true;
    if (candidate.event_id === requestedEventId) requestedAuthorized = true;
  }
  return Object.freeze({ revoked: Object.freeze(revoked), requested_authorized: requestedAuthorized });
}

function claimWasActiveAtSnapshot(
  claimIndex: number,
  evaluationTime: number,
  chainRecords: VerifiedClaimRecord[],
  revoked: readonly boolean[],
  context: RevocationAuthorityContextSnapshot,
  trusted: boolean,
): boolean {
  const claim = chainRecords[claimIndex].semantic;
  if (
    evaluationTime < claim.not_before ||
    (claim.expires_at !== undefined && evaluationTime >= claim.expires_at) ||
    revoked[claimIndex] ||
    context.repository_conflicted.includes(claim.claim_id) ||
    (claim.claim_class === "authorization" && !context.repository_confirmed.includes(claim.claim_id)) ||
    !trusted
  ) return false;
  if (claim.claim_class === "authorization") {
    const generation = evaluateCredentialGeneration(claim, context.credential_ledger);
    if (!generation.valid) return false;
  }
  return true;
}

function matchesRestriction(restriction: string[] | undefined, value: string): boolean {
  return restriction === undefined || restriction.includes(value);
}

function isSubset(child: string[] | undefined, parent: string[] | undefined): boolean {
  if (parent === undefined) return true;
  if (child === undefined) return false;
  const allowed = new Set(parent);
  return child.every((value) => allowed.has(value));
}

function sameKeyRef(left: KeyRef, right: KeyRef): boolean {
  return left.type === right.type && left.value === right.value;
}

function sameClaim(left: ClaimSemanticBody, right: ClaimSemanticBody): boolean {
  return left.claim_id === right.claim_id && jcsCanonicalize(left) === jcsCanonicalize(right);
}

function invalidEvaluation(error: unknown, fallback = "claim-schema-invalid"): ClaimEvaluation {
  const message = error instanceof Error ? error.message : "";
  const code = message.match(/\b(claim-[a-z-]+)\b/)?.[1] ?? fallback;
  return { state: "invalid", reason_code: code };
}

function requireVerifiedClaimRecord(value: unknown): VerifiedClaimRecord {
  if (value === null || typeof value !== "object") {
    throw new Error("claim-issuer-authority-invalid: verified claim artifact required");
  }
  const record = VERIFIED_CLAIMS.get(value);
  if (record === undefined || record.verifier !== CLAIM_VERIFIER_IDENTITY) {
    throw new Error("claim-issuer-authority-invalid: verified claim artifact required");
  }
  return record;
}

function requireVerifiedClaimRevocationRecord(
  value: unknown,
): VerifiedClaimRevocationRecord {
  if (value === null || typeof value !== "object") {
    throw new Error("claim-revoker-unauthorized: verified claim revocation artifact required");
  }
  const record = VERIFIED_CLAIM_REVOCATIONS.get(value);
  if (record === undefined || record.verifier !== CLAIM_VERIFIER_IDENTITY) {
    throw new Error("claim-revoker-unauthorized: verified claim revocation artifact required");
  }
  return record;
}

function captureClaimArtifactMap(
  value: ReadonlyMap<string, VerifiedClaimArtifact>,
): Map<string, Readonly<{
  value: VerifiedClaimArtifact;
  record: VerifiedClaimRecord;
}>> {
  if (
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Map.prototype ||
    Reflect.ownKeys(value).length !== 0
  ) throw new Error("claim-issuer-authority-invalid: ordinary verified artifact map required");
  const size = MAP_SIZE_GETTER.call(value) as number;
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_CLAIM_ARTIFACT_MAP_SIZE) {
    throw new Error("claim-issuer-authority-invalid: verified artifact map is oversized");
  }
  const captured = new Map<string, Readonly<{
    value: VerifiedClaimArtifact;
    record: VerifiedClaimRecord;
  }>>();
  const iterator = MAP_ENTRIES.call(value);
  for (let index = 0; index < size; index += 1) {
    const step = MAP_ITERATOR_NEXT.call(iterator) as IteratorResult<[unknown, unknown]>;
    if (step.done || !Array.isArray(step.value) || step.value.length !== 2) {
      throw new Error("claim-issuer-authority-invalid: invalid verified artifact map iterator");
    }
    const [claimId, artifact] = step.value;
    if (typeof claimId !== "string" || captured.has(claimId)) {
      throw new Error("claim-issuer-authority-invalid: invalid verified artifact map key");
    }
    const record = requireVerifiedClaimRecord(artifact);
    if (record.claim_id !== claimId) {
      throw new Error("claim-issuer-authority-invalid: artifact map key does not match claim ID");
    }
    captured.set(claimId, Object.freeze({ value: artifact as VerifiedClaimArtifact, record }));
  }
  if (!MAP_ITERATOR_NEXT.call(iterator).done) {
    throw new Error("claim-issuer-authority-invalid: verified artifact map changed during capture");
  }
  return captured;
}

function captureClaimArtifactArray(value: unknown): VerifiedClaimRecord[] {
  return captureOrdinaryDenseArray(
    value,
    MAX_CLAIM_CHAIN_LENGTH,
    "claim-issuer-authority-invalid: ordinary verified claim artifact chain required",
  ).map(requireVerifiedClaimRecord);
}

function captureRevocationArtifactArray(value: unknown): VerifiedClaimRevocationRecord[] {
  const records = captureOrdinaryDenseArray(
    value,
    MAX_REVOCATION_ARTIFACTS,
    "claim-revoker-unauthorized: ordinary verified revocation artifact array required",
  ).map(requireVerifiedClaimRevocationRecord);
  return [...chronologicalRevocationSnapshot(records)];
}

function chronologicalRevocationSnapshot(
  records: VerifiedClaimRevocationRecord[],
): readonly VerifiedClaimRevocationRecord[] {
  const eventIds = new Map<string, VerifiedClaimRevocationRecord>();
  for (const record of records) {
    if (eventIds.has(record.event_id)) {
      throw new Error("claim-revoker-unauthorized: duplicate revocation event ID");
    }
    eventIds.set(record.event_id, record);
  }
  return Object.freeze([...records].sort((left, right) =>
    left.revoked_at - right.revoked_at || left.event_id.localeCompare(right.event_id)));
}

type RevocationAuthorityContextSnapshot = Readonly<{
  now: number;
  credential_ledger: CredentialLedgerBinding;
  repository_confirmed: readonly string[];
  repository_conflicted: readonly string[];
  trusted_issuers: readonly KeyRef[];
  revocations: readonly VerifiedClaimRevocationRecord[];
}>;

function captureRevocationAuthorityContext(value: unknown): RevocationAuthorityContextSnapshot {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
  ) throw new Error("claim-issuer-authority-invalid: ordinary claim verification context required");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const required = [
    "now",
    "audience",
    "resource",
    "requested_namespace",
    "requested_operation",
    "expected_nonce",
    "used_nonces",
    "trusted_issuers",
    "credential_ledger",
    "repository_confirmed",
    "repository_conflicted",
    "revocations",
    "subject_proof",
  ];
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== required.length || keys.some((key) =>
    typeof key !== "string" || !required.includes(key))) {
    throw new Error("claim-issuer-authority-invalid: closed claim verification context required");
  }
  const read = (member: string): unknown => {
    const descriptor = descriptors[member];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error("claim-issuer-authority-invalid: data-only claim verification context required");
    }
    return descriptor.value;
  };
  const now = read("now");
  if (!Number.isSafeInteger(now) || (now as number) < 0) {
    throw new Error("claim-issuer-authority-invalid: invalid verification time");
  }
  const credential = captureCredentialLedgerBinding(read("credential_ledger"));
  const confirmed = captureClosedStringSet(read("repository_confirmed"), "repository_confirmed");
  const conflicted = captureClosedStringSet(read("repository_conflicted"), "repository_conflicted");
  const trusted = captureOrdinaryDenseArray(
    read("trusted_issuers"),
    MAX_CONTEXT_SET_SIZE,
    "claim-issuer-authority-invalid: ordinary trusted issuer array required",
  ).map((entry) => {
    const snapshot = deepFreezeJson(snapshotJsonNode(entry, new Set<object>()) as KeyRef);
    validateKeyRef(snapshot);
    return snapshot;
  });
  const revocations = captureRevocationArtifactArray(read("revocations"));
  return Object.freeze({
    now: now as number,
    credential_ledger: credential,
    repository_confirmed: confirmed,
    repository_conflicted: conflicted,
    trusted_issuers: Object.freeze(trusted),
    revocations: Object.freeze(revocations),
  });
}

function captureClosedStringSet(value: unknown, label: string): readonly string[] {
  if (
    value === null || typeof value !== "object" || utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Set.prototype || Reflect.ownKeys(value).length !== 0
  ) throw new Error(`claim-issuer-authority-invalid: ordinary ${label} set required`);
  const size = SET_SIZE_GETTER.call(value) as number;
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_CONTEXT_SET_SIZE) {
    throw new Error(`claim-issuer-authority-invalid: bounded ${label} set required`);
  }
  const iterator = SET_VALUES.call(value);
  const captured: string[] = [];
  for (let index = 0; index < size; index += 1) {
    const step = SET_ITERATOR_NEXT.call(iterator) as IteratorResult<unknown>;
    if (step.done || typeof step.value !== "string") {
      throw new Error(`claim-issuer-authority-invalid: string ${label} set required`);
    }
    captured.push(step.value);
  }
  if (!SET_ITERATOR_NEXT.call(iterator).done) {
    throw new Error(`claim-issuer-authority-invalid: ${label} set changed during capture`);
  }
  return Object.freeze(captured);
}

function captureOrdinaryDenseArray(
  value: unknown,
  maximumLength: number,
  errorMessage: string,
): unknown[] {
  if (
    value === null || typeof value !== "object" || utilTypes.isProxy(value) ||
    !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
  ) throw new Error(errorMessage);
  const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as PropertyDescriptorMap;
  const keys = Reflect.ownKeys(descriptors);
  const lengthDescriptor = descriptors.length;
  const length = lengthDescriptor !== undefined && "value" in lengthDescriptor
    ? lengthDescriptor.value
    : undefined;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0 ||
      length > maximumLength || keys.length !== length + 1) {
    throw new Error(errorMessage);
  }
  const captured: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(errorMessage);
    }
    captured.push(descriptor.value);
  }
  return captured;
}

function captureClaimEnvelopeContext(
  value: unknown,
): Readonly<{
  profile_revision: 2;
  credential_ledger: CredentialLedgerBinding;
  existing_semantic_body?: ClaimSemanticBody;
  existing_verified_claim?: VerifiedClaimArtifact;
}> {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
  ) throw new Error("claim-issuer-authority-invalid: ordinary verification context required");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  const allowed = new Set([
    "profile_revision",
    "credential_ledger",
    "existing_semantic_body",
    "existing_verified_claim",
  ]);
  if (
    keys.some((key) => typeof key !== "string") ||
    keys.some((key) => !allowed.has(key as string))
  ) throw new Error("claim-issuer-authority-invalid: closed verification context required");
  const read = (member: string): unknown => {
    const descriptor = descriptors[member];
    if (descriptor === undefined) return undefined;
    if (!("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error("claim-issuer-authority-invalid: data-only verification context required");
    }
    return descriptor.value;
  };
  const profileRevision = read("profile_revision");
  if (profileRevision !== 2) {
    throw new Error("claim-schema-invalid: registry revision does not match the supplied context");
  }
  const credentialLedger = captureCredentialLedgerBinding(read("credential_ledger"));
  const existingSemanticValue = read("existing_semantic_body");
  const existingVerifiedValue = read("existing_verified_claim");
  if (existingSemanticValue !== undefined && existingVerifiedValue !== undefined) {
    throw new Error("claim-repository-conflict: duplicate existing claim inputs");
  }
  const existingSemantic = existingSemanticValue === undefined
    ? undefined
    : deepFreezeJson(snapshotJsonNode(existingSemanticValue, new Set<object>()) as ClaimSemanticBody);
  if (existingVerifiedValue !== undefined) {
    requireVerifiedClaimRecord(existingVerifiedValue);
  }
  return Object.freeze({
    profile_revision: 2 as const,
    credential_ledger: credentialLedger,
    ...(existingSemantic === undefined ? {} : { existing_semantic_body: existingSemantic }),
    ...(existingVerifiedValue === undefined
      ? {}
      : { existing_verified_claim: existingVerifiedValue as VerifiedClaimArtifact }),
  });
}

function captureEmbeddedArtifact(
  value: unknown,
  label: string,
): Readonly<{ event: unknown; semantic: unknown }> {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
  ) throw new Error(`claim-schema-invalid: ${label} must be an ordinary object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== 2 ||
    keys.some((key) => typeof key !== "string") ||
    !Object.hasOwn(descriptors, "event") ||
    !Object.hasOwn(descriptors, "semantic")
  ) throw new Error(`claim-schema-invalid: ${label} must contain exactly event and semantic`);
  const read = (member: "event" | "semantic"): unknown => {
    const descriptor = descriptors[member];
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`claim-schema-invalid: ${label} members must be enumerable data properties`);
    }
    return descriptor.value;
  };
  return Object.freeze({ event: read("event"), semantic: read("semantic") });
}

function captureCredentialLedgerBinding(value: unknown): CredentialLedgerBinding {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
  ) throw new Error("credential_schema_invalid");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== 2 ||
    !Object.hasOwn(descriptors, "credential_ledger_persona") ||
    !Object.hasOwn(descriptors, "credential_ledger_generation") ||
    keys.some((key) => typeof key !== "string")
  ) throw new Error("credential_schema_invalid");
  const read = (member: string): unknown => {
    const descriptor = descriptors[member];
    return descriptor !== undefined && "value" in descriptor && descriptor.enumerable
      ? descriptor.value
      : undefined;
  };
  const persona = read("credential_ledger_persona");
  const generation = read("credential_ledger_generation");
  if (
    typeof persona !== "string" || !LOWER_HEX_32_PATTERN.test(persona) ||
    !Number.isSafeInteger(generation) || (generation as number) < 0
  ) throw new Error("credential_schema_invalid");
  return Object.freeze({
    credential_ledger_persona: persona,
    credential_ledger_generation: generation as number,
  });
}

function inspectedRevocation(record: VerifiedClaimRevocationRecord): VerifiedRevocation {
  return deepFreezeJson({
    ...deepFreezeJsonClone(record.semantic),
    signer: deepFreezeJsonClone(record.signer),
    event_id: record.event_id,
    event_created_at: record.event.created_at,
  });
}

function bindingDigest(domain: string, value: unknown): string {
  return bytesToHex(sha256(utf8Bytes(`${domain}\0${jcsCanonicalize(value)}`)));
}

function deepFreezeJsonClone<T>(value: T): T {
  return deepFreezeJson(snapshotJsonNode(value, new Set<object>()) as T);
}

function deepFreezeJson<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreezeJson(member);
    Object.freeze(value);
  }
  return value;
}

function snapshotJsonNode(value: unknown, seen: Set<object>): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("claim-schema-invalid: non-finite JSON number");
    return value;
  }
  if (typeof value !== "object" || utilTypes.isProxy(value) || seen.has(value)) {
    throw new Error("claim-schema-invalid: unsafe JSON data tree");
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw new Error("claim-schema-invalid: unsafe JSON array");
      }
      const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as PropertyDescriptorMap;
      const lengthDescriptor = descriptors.length;
      if (lengthDescriptor === undefined || !("value" in lengthDescriptor)) {
        throw new Error("claim-schema-invalid: unsafe JSON array length");
      }
      const length = lengthDescriptor.value as number;
      if (Reflect.ownKeys(descriptors).length !== length + 1) {
        throw new Error("claim-schema-invalid: sparse JSON array");
      }
      return Array.from({ length }, (_, index) => {
        const descriptor = descriptors[String(index)];
        if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
          throw new Error("claim-schema-invalid: unsafe JSON array member");
        }
        return snapshotJsonNode(descriptor.value, seen);
      });
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new Error("claim-schema-invalid: unsafe JSON object");
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const snapshot: Record<string, unknown> = {};
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== "string") throw new Error("claim-schema-invalid: symbol JSON member");
      const descriptor = descriptors[key];
      if (!("value" in descriptor) || !descriptor.enumerable || descriptor.value === undefined) {
        throw new Error("claim-schema-invalid: unsafe JSON object member");
      }
      snapshot[key] = snapshotJsonNode(descriptor.value, seen);
    }
    return snapshot;
  } finally {
    seen.delete(value);
  }
}

export function computeJwkThumbprint(jwk: Record<string, JsonValue>): string {
  return inspectPublicJwk(jwk).thumbprint;
}

function assertAddressedCommsEvent(event: NostrSignedEvent, expectedKind: number): void {
  if (event.kind !== expectedKind) {
    throw new Error(`claim-schema-invalid: expected kind:${expectedKind}`);
  }
}

function requireVerifiedClaimEvent(value: unknown): VerifiedNostrEvent {
  const event = snapshotAndVerifyNostrEvent(value);
  if (event === null) {
    throw new Error(
      "claim-event-signature-invalid: invalid canonical NIP-01 id or BIP-340 signature",
    );
  }
  return event;
}

function assertSingleAddress(event: NostrSignedEvent, expected: string): void {
  if (
    event.tags.length !== 1 ||
    event.tags[0].length !== 2 ||
    event.tags[0][0] !== "d" ||
    event.tags[0][1] !== expected
  ) {
    throw new Error("claim-schema-invalid: event tags must be exactly [[\"d\",claim_id]]");
  }
}

function parseCanonicalContent(content: string, label: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content) as unknown;
  } catch {
    throw new Error(`claim-schema-invalid: ${label} content is not JSON`);
  }
  let canonical: string;
  try {
    canonical = jcsCanonicalize(parsed);
  } catch (error) {
    throw new Error(`claim-schema-invalid: ${error instanceof Error ? error.message : "invalid JCS content"}`);
  }
  if (content !== canonical) {
    throw new Error(`claim-schema-invalid: ${label} content is not canonical RFC 8785 JCS`);
  }
  return parsed;
}

function verifyRevocationProof(event: VerifiedNostrEvent, revocation: ClaimRevocation): void {
  if (revocation.revoker.type === "nostr-secp256k1") {
    if (revocation.proof !== undefined) {
      throw new Error("claim-key-reference-invalid: Nostr revocation uses only the outer event signature");
    }
    if (revocation.revoker.value !== event.pubkey) {
      throw new Error("claim-key-reference-invalid: Nostr revoker does not match the outer event signer");
    }
    return;
  }

  const payload = revocationProofPayload(revocation);
  if (revocation.revoker.type === "radicle-ed25519-nid") {
    const proof = revocation.proof;
    if (proof?.type !== "radicle-ed25519") {
      throw new Error("claim-key-reference-invalid: Radicle revoker requires a radicle-ed25519 proof");
    }
    const publicKey = parseLowerHex(proof.public_key, 32, "Ed25519 public key");
    if (didKeyFromEd25519(proof.public_key) !== revocation.revoker.value) {
      throw new Error("claim-key-reference-invalid: Ed25519 public key does not derive the named NID");
    }
    const signature = parseLowerHex(proof.signature, 64, "Ed25519 signature");
    let valid = false;
    try {
      valid = ed25519.verify(signature, payload, publicKey);
    } catch {
      valid = false;
    }
    if (!valid) throw new Error("claim-subject-proof-invalid: Ed25519 revocation proof is invalid");
    return;
  }

  const proof = revocation.proof;
  if (proof?.type !== "jwk-jws") {
    throw new Error("claim-key-reference-invalid: JWK revoker requires a jwk-jws proof");
  }
  if (computeJwkThumbprint(proof.jwk) !== revocation.revoker.value) {
    throw new Error("claim-key-reference-invalid: embedded JWK does not match the named thumbprint");
  }
  verifyDetachedJws(proof, payload);
}

function decodeEd25519Nid(value: string): Uint8Array {
  if (!value.startsWith("did:key:z")) {
    throw new Error("claim-key-reference-invalid: Radicle NID must use did:key base58btc");
  }
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(value.slice("did:key:z".length));
  } catch {
    throw new Error("claim-key-reference-invalid: Radicle NID has invalid base58btc");
  }
  if (
    decoded.length !== 34 ||
    decoded[0] !== 0xed ||
    decoded[1] !== 0x01 ||
    `did:key:z${base58.encode(decoded)}` !== value
  ) {
    throw new Error("claim-key-reference-invalid: Radicle NID is not a canonical Ed25519 did:key");
  }
  return decoded.slice(2);
}

function parseLowerHex(value: string, bytes: number, label: string): Uint8Array {
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) {
    throw new Error(`claim-key-reference-invalid: ${label} must be lowercase ${bytes}-byte hex`);
  }
  return hexToBytes(value);
}

function thumbprintMembers(jwk: Record<string, JsonValue>): Record<string, string> {
  const kty = requireJwkString(jwk, "kty");
  if (kty === "RSA") {
    const n = requireBase64urlUInt(jwk, "n");
    const e = requireBase64urlUInt(jwk, "e");
    const modulusBits = (n.bytes.length - 1) * 8 + (32 - Math.clz32(n.bytes[0]));
    if (modulusBits < 2048) {
      throw new Error("claim-key-reference-invalid: RSA modulus must be at least 2048 bits");
    }
    if ((n.bytes[n.bytes.length - 1] & 1) === 0) {
      throw new Error("claim-key-reference-invalid: RSA modulus is not a valid odd public modulus");
    }
    const exponent = bytesToBigInt(e.bytes);
    if (exponent < 3n || (exponent & 1n) === 0n) {
      throw new Error("claim-key-reference-invalid: RSA exponent is not a valid odd public exponent");
    }
    return { e: e.value, kty, n: n.value };
  }
  if (kty === "EC") {
    const crv = requireJwkString(jwk, "crv");
    if (crv !== "P-256") {
      throw new Error(`claim-key-reference-invalid: unsupported EC curve ${crv}`);
    }
    const x = requireExactBase64urlMember(jwk, "x", 32);
    const y = requireExactBase64urlMember(jwk, "y", 32);
    const encoded = new Uint8Array(65);
    encoded[0] = 0x04;
    encoded.set(x.bytes, 1);
    encoded.set(y.bytes, 33);
    try {
      p256.Point.fromBytes(encoded).assertValidity();
    } catch {
      throw new Error("claim-key-reference-invalid: P-256 coordinates do not encode a valid public point");
    }
    return {
      crv,
      kty,
      x: x.value,
      y: y.value,
    };
  }
  if (kty === "OKP") {
    const crv = requireJwkString(jwk, "crv");
    if (crv !== "Ed25519") {
      throw new Error(`claim-key-reference-invalid: unsupported OKP curve ${crv}`);
    }
    const x = requireExactBase64urlMember(jwk, "x", 32);
    try {
      const point = ed25519.Point.fromBytes(x.bytes, false);
      point.assertValidity();
      if (point.isSmallOrder() || !point.isTorsionFree()) throw new Error("invalid subgroup");
    } catch {
      throw new Error("claim-key-reference-invalid: Ed25519 x does not encode a valid prime-order public point");
    }
    return { crv, kty, x: x.value };
  }
  throw new Error(`claim-key-reference-invalid: unsupported public JWK kty ${kty}`);
}

type PublicJwkProfile = {
  algorithm: "EdDSA" | "RS256" | "ES256";
  thumbprint: string;
};

function inspectPublicJwk(jwk: Record<string, JsonValue>): PublicJwkProfile {
  if (jwk === null || Array.isArray(jwk) || typeof jwk !== "object") {
    throw new Error("claim-key-reference-invalid: JWK must be an object");
  }
  for (const member of PRIVATE_JWK_MEMBERS) {
    if (Object.prototype.hasOwnProperty.call(jwk, member)) {
      throw new Error(`claim-key-reference-invalid: embedded JWK contains private key member ${member}`);
    }
  }
  for (const member of REMOTE_JWK_MEMBERS) {
    if (Object.prototype.hasOwnProperty.call(jwk, member)) {
      throw new Error(`claim-key-reference-invalid: embedded JWK contains prohibited remote-key metadata ${member}`);
    }
  }
  const required = thumbprintMembers(jwk);
  const kty = required.kty;
  const algorithm = kty === "OKP" ? "EdDSA" : kty === "EC" ? "ES256" : "RS256";
  const allowed = new Set([...Object.keys(required), "alg", "use", "key_ops", "kid"]);
  for (const member of Object.keys(jwk)) {
    if (!allowed.has(member)) {
      throw new Error(`claim-key-reference-invalid: embedded JWK contains unrecognized member ${member}`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(jwk, "use") && jwk.use !== "sig") {
    throw new Error("claim-key-reference-invalid: JWK use metadata must be the string sig");
  }
  if (Object.prototype.hasOwnProperty.call(jwk, "key_ops")) {
    const operations = jwk.key_ops;
    if (
      !Array.isArray(operations) ||
      operations.some((operation) => typeof operation !== "string") ||
      new Set(operations).size !== operations.length ||
      operations.length !== 1 ||
      operations[0] !== "verify"
    ) {
      throw new Error("claim-key-reference-invalid: JWK key_ops must contain exactly one unique verify operation");
    }
  }
  if (Object.prototype.hasOwnProperty.call(jwk, "alg") && jwk.alg !== algorithm) {
    throw new Error(`claim-key-reference-invalid: JWK alg metadata must be exactly ${algorithm}`);
  }
  const thumbprint = Buffer.from(
    sha256(utf8Bytes(jcsCanonicalize(required))),
  ).toString("base64url");
  if (Object.prototype.hasOwnProperty.call(jwk, "kid") && jwk.kid !== thumbprint) {
    throw new Error("claim-key-reference-invalid: JWK kid must equal its RFC 7638 thumbprint");
  }
  return { algorithm, thumbprint };
}

function requireJwkString(jwk: Record<string, JsonValue>, member: string): string {
  const value = jwk[member];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`claim-key-reference-invalid: JWK ${member} must be a non-empty string`);
  }
  return value;
}

function requireExactBase64urlMember(
  jwk: Record<string, JsonValue>,
  member: string,
  bytes: number,
): { value: string; bytes: Buffer } {
  const value = requireJwkString(jwk, member);
  const decoded = decodeCanonicalBase64url(value, `JWK ${member}`);
  if (decoded.length !== bytes) {
    throw new Error(`claim-key-reference-invalid: JWK ${member} must decode to exactly ${bytes} bytes`);
  }
  return { value, bytes: decoded };
}

function requireBase64urlUInt(
  jwk: Record<string, JsonValue>,
  member: string,
): { value: string; bytes: Buffer } {
  const value = requireJwkString(jwk, member);
  const bytes = decodeCanonicalBase64url(value, `JWK ${member}`);
  if (bytes.length > 1 && bytes[0] === 0) {
    throw new Error(`claim-key-reference-invalid: JWK ${member} Base64urlUInt is not minimal (leading zero)`);
  }
  return { value, bytes };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function decodeCanonicalBase64url(value: string, label: string): Buffer {
  if (!BASE64URL_PATTERN.test(value)) {
    throw new Error(`claim-key-reference-invalid: ${label} is not unpadded base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length === 0 || decoded.toString("base64url") !== value) {
    throw new Error(`claim-key-reference-invalid: ${label} is not canonical base64url`);
  }
  return decoded;
}

function verifyDetachedJws(
  proof: Extract<KeyProof, { type: "jwk-jws" }>,
  payload: Uint8Array,
): void {
  const protectedBytes = decodeCanonicalBase64url(proof.protected, "JWS protected header");
  const signature = decodeCanonicalBase64url(proof.signature, "JWS signature");
  let header: unknown;
  try {
    header = JSON.parse(protectedBytes.toString("utf8")) as unknown;
  } catch {
    throw new Error("claim-subject-proof-invalid: JWS protected header is not JSON");
  }
  if (
    header === null ||
    Array.isArray(header) ||
    typeof header !== "object" ||
    Object.keys(header).length !== 1 ||
    typeof (header as { alg?: unknown }).alg !== "string"
  ) {
    throw new Error("claim-subject-proof-invalid: JWS protected header must contain only alg");
  }
  if (protectedBytes.toString("utf8") !== jcsCanonicalize(header)) {
    throw new Error("claim-subject-proof-invalid: JWS protected header is ambiguous or non-canonical");
  }
  const alg = (header as { alg: string }).alg;
  const expectedAlgorithm = algorithmForJwk(proof.jwk);
  if (alg !== expectedAlgorithm) {
    throw new Error(`claim-subject-proof-invalid: unsupported or mismatched JWS alg ${alg}`);
  }
  if (typeof proof.jwk.alg === "string" && proof.jwk.alg !== alg) {
    throw new Error("claim-subject-proof-invalid: JWK alg does not match protected alg");
  }
  if (Array.isArray(proof.jwk.key_ops) && !proof.jwk.key_ops.includes("verify")) {
    throw new Error("claim-subject-proof-invalid: JWK key_ops does not permit verification");
  }
  const signingInput = utf8Bytes(
    `${proof.protected}.${Buffer.from(payload).toString("base64url")}`,
  );
  let key;
  try {
    key = createPublicKey({ key: proof.jwk as JsonWebKey, format: "jwk" });
  } catch {
    throw new Error("claim-key-reference-invalid: embedded JWK is not a valid public key");
  }
  let valid = false;
  try {
    if (alg === "EdDSA") {
      valid = verifyNativeSignature(null, signingInput, key, signature);
    } else if (alg === "RS256") {
      valid = verifyNativeSignature("RSA-SHA256", signingInput, key, signature);
    } else {
      valid = verifyNativeSignature("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature);
    }
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("claim-subject-proof-invalid: detached JWS revocation proof is invalid");
}

function algorithmForJwk(jwk: Record<string, JsonValue>): "EdDSA" | "RS256" | "ES256" {
  return inspectPublicJwk(jwk).algorithm;
}
