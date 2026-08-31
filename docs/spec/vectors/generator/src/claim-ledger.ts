import { createHmac } from "node:crypto";
import { types as utilTypes } from "node:util";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import {
  authorizeWithClaim,
  computeJwkThumbprint,
  inspectVerifiedClaim,
  inspectVerifiedClaimRevocation,
  isClaimRevocationAuthorized,
  verifyLedgerClaimArtifact,
  verifyLedgerClaimRevocationArtifact,
  verifyClaimChain,
  validateKeyRef,
  type AuthorizationDecision,
  type ClaimSemanticBody,
  type ClaimEnvelopeContext,
  type ClaimVerificationContext,
  type ClaimState,
  type JsonValue,
  type VerifiedClaimArtifact,
  type VerifiedClaimRevocationArtifact,
} from "./claims.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  validateClaimLedgerRecordSchemaOrThrow,
  validateOidcIssuanceRecordSchemaOrThrow,
} from "./schema.js";
import {
  assertCurrentCredentialGeneration,
  evaluateCredentialGeneration,
  isCredentialLedgerBinding,
  type CredentialLedgerBinding,
} from "./credential-generation.js";
import { type NostrSignedEvent } from "./nostr.js";
import {
  captureExactDataObject,
  snapshotClosedDataTree,
} from "./closed-data.js";
import {
  resolveCurrentRepositoryWriterBinding,
  revalidateCurrentRepositoryWriterBinding,
  type CoreRepositoryWriterAuthority,
  type CurrentRepositoryWriterBinding,
  type RepositoryWriterBindingV1,
} from "./core-writer-binding.js";

export type LedgerRecordType =
  | "claim"
  | "revocation"
  | "authority-reduction"
  | "reader-change"
  | "audience-key-epoch"
  | "issuer-authority"
  | "issuance-reservation"
  | "status-invalidation";

export type LedgerRecord = {
  record_id: string;
  record_type: LedgerRecordType;
  persona: string;
  credential_ledger_generation: number;
  writer_nid: string;
  created_at: number;
  parents: string[];
  payload: JsonValue;
  payload_digest: string;
  signature: string;
};

export type LedgerCheckpoint = {
  repository_rid: string;
  branch: "main";
  commit_oid: string;
  observed_at: number;
};

export type MintingEligibility = {
  allowed: boolean;
  reason_code: string | null;
  checkpoint: LedgerCheckpoint;
};

export type StatusReservation = {
  uri: string;
  idx: number;
  expiry_bucket: string;
  writer_nid_fingerprint: string;
  list_sequence: number;
};

export type IssuanceRecord = {
  credential_ledger_generation: number;
  jti: string;
  reservation: StatusReservation;
  checkpoint: LedgerCheckpoint;
  manifest_max_age_seconds: number;
  signing_key_id: string;
  client_id: string;
  authorization_request_digest: string;
  release_digest: string;
  source_claim_ids: string[];
  issued_at: number;
  expires_at: number;
};

export type IssuerKeyEnvelope = {
  object_type: "oidc-signing-jwk-v1";
  persona: string;
  credential_ledger_generation: number;
  repository_rid: string;
  checkpoint_commit_oid: string;
  epoch: number;
  audience_key_id: string;
  previous_key_id: string;
  signing_key_id: string;
  content_digest: string;
  nonce: string;
  ciphertext: string;
  authority_record_ids: string[];
  authority_record_set_digest: string;
  recipient_wraps: Array<{ writer_nid: string; context_digest: string; wrapped_key: string }>;
  removed_issuer_nids: string[];
};

export type LedgerMergeResult = {
  credential_ledger: CredentialLedgerBinding;
  records: LedgerRecord[];
  conflicted_claim_ids: string[];
  checkpoint: LedgerCheckpoint;
  repository_confirmed_record_ids?: string[];
  delivered_record_ids?: string[];
  authenticated_revocations?: VerifiedClaimRevocationArtifact[];
  token_invalidations?: string[];
  canonical_commit_oids?: string[];
};

export type MintingAttemptDecision = MintingEligibility & {
  authority_state: ClaimState;
  active_issuer_nids: string[];
  key_epoch: number;
  pending_rotation: boolean;
};

export type ClaimArtifact = { event: NostrSignedEvent; semantic: ClaimSemanticBody };
export type RevocationArtifact = { event: NostrSignedEvent; semantic: JsonValue };

export type LedgerRecordValidationEvidence = {
  record_id: string;
  payload_digest: string;
  claim_envelope_context?: ClaimEnvelopeContext;
  claims_by_id?: Map<string, unknown>;
  claim_verification_context?: ClaimVerificationContext;
};

export type LedgerRecordLocation = Readonly<{
  record_id: string;
  repository_rid: string;
  writer_ref: string;
  commit: string;
  checkpoint: string;
  revision: number;
  writer_binding: RepositoryWriterBindingV1;
}>;

export type LedgerRepositoryCommit = {
  commit_oid: string;
  tree_oid: string;
  parents: string[];
  record_ids: string[];
  record_set_digest: string;
};

export type LedgerRepositoryEvidence = {
  repository_rid: string;
  branch: "main";
  genesis: boolean;
  prior_checkpoint: LedgerCheckpoint | null;
  canonical_head: string;
  checkpoint: LedgerCheckpoint;
  commits: LedgerRepositoryCommit[];
  repository_confirmed_record_ids: string[];
};

export type ReaderAccessRequest = {
  claim_record_id: string;
  envelope_context: ClaimEnvelopeContext;
  claims_by_id: Map<string, unknown>;
  verification_context: ClaimVerificationContext;
};

export type LedgerValidationContext = {
  credential_ledger: CredentialLedgerBinding;
  record_evidence: Map<string, LedgerRecordValidationEvidence>;
  repository: LedgerRepositoryEvidence;
  reader_requests: Map<string, ReaderAccessRequest>;
  audience_keys_by_epoch: Map<number, Uint8Array>;
  issuer_key_material_by_record_id?: Map<string, { envelope: IssuerKeyEnvelope; audience_key: Uint8Array }>;
  writer_authority: CoreRepositoryWriterAuthority;
  load_record_location: (record: LedgerRecord) => LedgerRecordLocation;
};

export type LedgerLayout = {
  entries: Array<{ path: string; size: 64; ciphertext: string }>;
  commit_metadata: {
    message: "heterodyne private ledger update";
    entry_count: 256;
    entry_size: 64;
    epoch: number;
    commit_oid: string;
    nonce: string;
    snapshot_digest: string;
  };
};

export type AudienceKeyEpochPayload = {
  epoch: number;
  key_id: string;
  key_digest: string;
  previous_epoch: number;
  previous_key_id: string;
  reader_nids: string[];
  removed_reader_nids: string[];
  recipient_wraps: Array<{ reader_nid: string; context_digest: string; wrapped_key: string }>;
  radicle_access_removed: string[];
  checkpoint_commit_oid: string;
  retire_previous_state: true;
  scrub_profile: "comms-encrypted-branch-cooperative-v1";
};

export type IssuerKeyEpochPayload = {
  scope: "oidc-issuer-key";
  epoch: number;
  envelope_digest: string;
  key_digest: string;
  previous_epoch: number;
  previous_envelope_digest: string;
  previous_key_digest: string;
  recipient_nids: string[];
  checkpoint: LedgerCheckpoint;
};

export type LedgerOnboardingBundle = {
  transport: "dr-self-dm";
  authorization: { claim_record_id: string; event_id: string; claim_id: string };
  repository: { rid: string; branch: "main" };
  checkpoint: LedgerCheckpoint;
  key_epoch: { epoch: number; key_id: string; key_digest: string; recipient_wrap: string };
  audience_key: string;
  compact_state: JsonValue;
  compact_state_digest: string;
  radicle_access: { nid: string; role: "fetch-and-seed"; context_digest: string };
  bundle_digest: string;
};

type UnsignedLedgerRecord = Omit<LedgerRecord, "record_id" | "payload_digest" | "signature">;

const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{128}$/;
const JWK_THUMBPRINT = /^[A-Za-z0-9_-]{43}$/;
const PERSONA = HEX_32;
const COMMIT_OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const RID = /^rad:z[1-9A-HJ-NP-Za-km-z]+$/;
const ED25519_PREFIX = Uint8Array.from([0xed, 0x01]);
export const GENESIS_AUDIENCE_KEY_ID = "00".repeat(32);
const MAX_SAFE = 9_007_199_254_740_991;
const RECORD_KEYS = [
  "record_id",
  "record_type",
  "persona",
  "credential_ledger_generation",
  "writer_nid",
  "created_at",
  "parents",
  "payload",
  "payload_digest",
  "signature",
] as const;
const RECORD_TYPES = new Set<LedgerRecordType>([
  "claim",
  "revocation",
  "authority-reduction",
  "reader-change",
  "audience-key-epoch",
  "issuer-authority",
  "issuance-reservation",
  "status-invalidation",
]);
const ARTIFACT_SENSITIVE_RECORD_TYPES = new Set<LedgerRecordType>([
  "claim",
  "revocation",
  "authority-reduction",
  "reader-change",
  "issuer-authority",
  "status-invalidation",
]);
const VALIDATED_LEDGER_STATES = new WeakSet<object>();
const VALIDATED_LEDGER_REPOSITORIES = new WeakMap<object, LedgerRepositoryEvidence>();
const VALIDATED_LEDGER_CONTEXTS = new WeakMap<object, LedgerValidationContext>();
const VALIDATED_LEDGER_SNAPSHOTS = new WeakMap<object, LedgerMergeResult>();
type LedgerWriterAuthorityRecord = Readonly<{
  authority: CoreRepositoryWriterAuthority;
  binding: CurrentRepositoryWriterBinding;
  fingerprint: string;
}>;
const VALIDATED_LEDGER_WRITERS = new WeakMap<
  object,
  readonly LedgerWriterAuthorityRecord[]
>();
type ReplayValidationFingerprint = {
  record: string;
  evidence: string;
  record_context: string;
};
const REPLAY_VALIDATED_RECORDS = new WeakMap<
  LedgerValidationContext,
  Map<LedgerRecord, ReplayValidationFingerprint>
>();

function recordTypeMayCarryAuthorityArtifact(recordType: unknown): boolean {
  return typeof recordType !== "string" ||
    !RECORD_TYPES.has(recordType as LedgerRecordType) ||
    ARTIFACT_SENSITIVE_RECORD_TYPES.has(recordType as LedgerRecordType);
}

function captureLedgerRecordValidationEvidence(
  value: unknown,
  artifactSensitive: boolean,
): LedgerRecordValidationEvidence | undefined {
  if (value === undefined) return undefined;
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
  ) throw new Error("claim-repository-unconfirmed: ordinary record evidence is required");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  const allowed = artifactSensitive
    ? [
      "record_id",
      "payload_digest",
      "claim_envelope_context",
      "claims_by_id",
      "claim_verification_context",
    ]
    : ["record_id", "payload_digest"];
  if (
    keys.some((key) => typeof key !== "string" || !allowed.includes(key)) ||
    !Object.hasOwn(descriptors, "record_id") ||
    !Object.hasOwn(descriptors, "payload_digest")
  ) throw new Error("claim-repository-unconfirmed: closed record evidence is required");
  const captured: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key as string];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new Error("claim-repository-unconfirmed: data-only record evidence is required");
    }
    captured[key as string] = descriptor.value;
  }
  return Object.freeze(captured) as LedgerRecordValidationEvidence;
}

export function prepareLedgerReplayValidationContext(
  context: LedgerValidationContext,
  source?: LedgerValidationContext,
): void {
  if (REPLAY_VALIDATED_RECORDS.has(context)) return;
  REPLAY_VALIDATED_RECORDS.set(
    context,
    source === undefined ? new Map<LedgerRecord, ReplayValidationFingerprint>() :
      (REPLAY_VALIDATED_RECORDS.get(source) ?? new Map<LedgerRecord, ReplayValidationFingerprint>()),
  );
}

export function createSignedLedgerRecord(input: UnsignedLedgerRecord, writerSecretKey: string): LedgerRecord {
  const payload_digest = domainSeparatedDigestJson("heterodyne-claim-ledger-payload-v1", input.payload);
  const signing = recordSigningPayload({ ...input, payload_digest });
  const signature = bytesToHex(ed25519.sign(utf8Bytes(signing), hexToBytes(writerSecretKey)));
  const withoutId = { ...input, payload_digest, signature };
  return {
    record_id: domainSeparatedDigestJson("heterodyne-claim-ledger-record-id-v1", withoutId),
    ...withoutId,
  };
}

export function validateLedgerRecordOrThrow(
  record: LedgerRecord,
  recordsById: ReadonlyMap<string, LedgerRecord>,
  evidence: LedgerRecordValidationEvidence | undefined,
  expectedCredentialLedger: CredentialLedgerBinding,
): void {
  const capturedEvidence = captureLedgerRecordValidationEvidence(
    evidence,
    recordTypeMayCarryAuthorityArtifact(record.record_type),
  );
  validateCapturedLedgerRecordOrThrow(
    record,
    recordsById,
    capturedEvidence,
    expectedCredentialLedger,
  );
}

function validateCapturedLedgerRecordOrThrow(
  record: LedgerRecord,
  recordsById: ReadonlyMap<string, LedgerRecord>,
  evidence: LedgerRecordValidationEvidence | undefined,
  expectedCredentialLedger: CredentialLedgerBinding,
): void {
  assertPlainObject(record, "record");
  if (!Object.prototype.hasOwnProperty.call(record, "credential_ledger_generation")) {
    throw new Error("credential_generation_missing");
  }
  assertExactKeys(record, RECORD_KEYS, "record");
  validateClaimLedgerRecordSchemaOrThrow(record);
  if (!HEX_32.test(record.record_id)) throw new Error("claim-id-mismatch: invalid ledger record_id");
  if (!RECORD_TYPES.has(record.record_type)) throw new Error("claim-schema-invalid: invalid ledger record_type");
  if (!PERSONA.test(record.persona)) throw new Error("claim-schema-invalid: invalid ledger persona");
  if (!Number.isSafeInteger(record.credential_ledger_generation) ||
      record.credential_ledger_generation < 0 ||
      record.credential_ledger_generation > MAX_SAFE) {
    throw new Error("claim-schema-invalid: invalid credential-ledger generation");
  }
  if (!Number.isSafeInteger(record.created_at) || record.created_at < 0 || record.created_at > MAX_SAFE) {
    throw new Error("claim-schema-invalid: invalid ledger created_at");
  }
  const writerPublicKey = ed25519PublicKeyFromNid(record.writer_nid);
  if (!Array.isArray(record.parents) || record.parents.length > 256 || new Set(record.parents).size !== record.parents.length) {
    throw new Error("claim-schema-invalid: parents must be a unique bounded array");
  }
  if (!HEX_32.test(record.payload_digest) ||
      record.payload_digest !== domainSeparatedDigestJson("heterodyne-claim-ledger-payload-v1", record.payload)) {
    throw new Error("claim-id-mismatch: ledger payload_digest mismatch");
  }
  if (!HEX_64.test(record.signature)) throw new Error("claim-schema-invalid: invalid ledger signature encoding");
  validatePayload(record.record_type, record.payload);
  const expectedId = domainSeparatedDigestJson(
    "heterodyne-claim-ledger-record-id-v1",
    withoutRecordId(record),
  );
  if (record.record_id !== expectedId) throw new Error("claim-id-mismatch: ledger record_id mismatch");
  if (!ed25519.verify(
    hexToBytes(record.signature),
    utf8Bytes(recordSigningPayload(record)),
    writerPublicKey,
  )) {
    throw new Error("claim-event-signature-invalid: ledger writer signature is invalid");
  }
  assertCurrentCredentialGeneration({
    credential_ledger_persona: record.persona,
    credential_ledger_generation: record.credential_ledger_generation,
  }, expectedCredentialLedger);
  for (const parentId of record.parents) {
    if (!HEX_32.test(parentId) || parentId === record.record_id) {
      throw new Error("claim-repository-conflict: invalid parent reference");
    }
    const parent = recordsById.get(parentId);
    if (parent === undefined) throw new Error(`claim-repository-conflict: missing parent ${parentId}`);
    if (parent.persona !== record.persona) throw new Error("claim-repository-conflict: cross-persona parent");
    if (parent.created_at > record.created_at) throw new Error("claim-repository-conflict: parent is newer than child");
  }
  if (evidence === undefined || evidence.record_id !== record.record_id || evidence.payload_digest !== record.payload_digest) {
    throw new Error("claim-repository-unconfirmed: record validation evidence is absent or not record-bound");
  }
  validateAuthenticatedArtifact(record, recordsById, evidence);
}

export function mergeClaimLedger(
  left: LedgerRecord[],
  right: LedgerRecord[],
  checkpoint: LedgerCheckpoint,
  context?: LedgerValidationContext,
): LedgerMergeResult {
  if (context === undefined) {
    throw new Error("claim-repository-unconfirmed: explicit validation and canonical repository evidence is required");
  }
  let capturedContext: LedgerValidationContext;
  let capturedLeft: readonly LedgerRecord[];
  let capturedRight: readonly LedgerRecord[];
  let capturedCheckpoint: LedgerCheckpoint;
  try {
    capturedLeft = captureLedgerRecordArray(left, "left claim ledger records");
    capturedRight = captureLedgerRecordArray(right, "right claim ledger records");
    capturedCheckpoint = captureLedgerCheckpoint(checkpoint);
    capturedContext = captureLedgerValidationContext(context);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("claim-ledger-writer-unauthorized:")) {
      throw error;
    }
    throw writerUnauthorized("validation context capture failed");
  }
  if (!isCredentialLedgerBinding(capturedContext.credential_ledger)) {
    throw new Error("credential_schema_invalid");
  }
  const recordsById = new Map<string, LedgerRecord>();
  for (const record of [...capturedLeft, ...capturedRight]) {
    const existing = recordsById.get(record.record_id);
    if (existing !== undefined && jcsCanonicalize(existing) !== jcsCanonicalize(record)) {
      throw new Error("claim-repository-conflict: record ID collision");
    }
    recordsById.set(record.record_id, record);
  }
  const records = [...recordsById.values()];
  validateRepositoryEvidence(capturedCheckpoint, recordsById, capturedContext.repository);
  const writerAuthorities = resolveLedgerWriterAuthorities(
    records,
    capturedCheckpoint,
    capturedContext,
  );
  const replayValidatedRecords = REPLAY_VALIDATED_RECORDS.get(context);
  const recordContextFingerprint = replayValidatedRecords === undefined
    ? null
    : replayValidationFingerprint([...records].sort((left, right) => left.record_id.localeCompare(right.record_id)));
  for (const record of records) {
    const artifactSensitiveRecord = recordTypeMayCarryAuthorityArtifact(record.record_type);
    const evidence = captureLedgerRecordValidationEvidence(
      Map.prototype.get.call(capturedContext.record_evidence, record.record_id) as
        | LedgerRecordValidationEvidence
        | undefined,
      artifactSensitiveRecord,
    );
    if (replayValidatedRecords === undefined) {
      validateCapturedLedgerRecordOrThrow(
        record,
        recordsById,
        evidence,
        {
          credential_ledger_persona: capturedContext.credential_ledger.credential_ledger_persona,
          credential_ledger_generation: record.credential_ledger_generation,
        },
      );
      continue;
    }
    const fingerprint = {
      record: replayValidationFingerprint(record),
      // Opaque artifact identity is intentionally not serializable. Never
      // cache artifact-sensitive evidence by a shaped-data fingerprint.
      evidence: artifactSensitiveRecord
        ? "opaque-artifact-evidence-uncached"
        : replayValidationFingerprint(evidence),
      record_context: recordContextFingerprint!,
    };
    const validated = replayValidatedRecords.get(record);
    if (artifactSensitiveRecord || validated === undefined ||
        validated.record !== fingerprint.record ||
        validated.evidence !== fingerprint.evidence ||
        validated.record_context !== fingerprint.record_context) {
      validateCapturedLedgerRecordOrThrow(
        record,
        recordsById,
        evidence,
        {
          credential_ledger_persona: capturedContext.credential_ledger.credential_ledger_persona,
          credential_ledger_generation: record.credential_ledger_generation,
        },
      );
      if (artifactSensitiveRecord) replayValidatedRecords.delete(record);
      else replayValidatedRecords.set(record, fingerprint);
    }
  }
  if (records.some(({ credential_ledger_generation }) =>
    credential_ledger_generation > capturedContext.credential_ledger.credential_ledger_generation)) {
    throw new Error("credential_generation_stale");
  }
  assertAcyclic(recordsById);
  validateLedgerStateInvariants(recordsById, capturedContext);
  const personas = new Set(records.map(({ persona }) => persona));
  if (personas.size > 1) throw new Error("claim-repository-conflict: one persona is permitted per ledger");
  records.sort((a, b) => a.record_id.localeCompare(b.record_id));
  const confirmed = [...capturedContext.repository.repository_confirmed_record_ids].sort();
  const authenticatedRevocations = records
    .filter((record) => ["revocation", "authority-reduction", "reader-change", "issuer-authority"].includes(record.record_type))
    .filter((record) => isReduction(record))
    .map(revocationArtifactFromRecord)
    .filter((artifact): artifact is RevocationArtifact => artifact !== null)
    .map((artifact) => verifyLedgerClaimRevocationArtifact(artifact));
  const confirmedSet = new Set(confirmed);
  const explicitTokenInvalidations = records
    .filter(({ record_type, record_id }) => record_type === "status-invalidation" && confirmedSet.has(record_id))
    .map((record) => String(payloadObject(record.payload).jti));
  const tokenInvalidations = [...new Set(explicitTokenInvalidations)].sort();
  const canonicalCommits = canonicalAncestorCommits(capturedContext.repository);
  const result: LedgerMergeResult = {
    credential_ledger: { ...capturedContext.credential_ledger },
    records,
    conflicted_claim_ids: findConflictedClaims(records),
    checkpoint: { ...capturedCheckpoint },
    repository_confirmed_record_ids: confirmed,
    delivered_record_ids: records.map(({ record_id }) => record_id).filter((id) => !confirmed.includes(id)).sort(),
    authenticated_revocations: authenticatedRevocations,
    token_invalidations: tokenInvalidations,
    canonical_commit_oids: canonicalCommits.map(({ commit_oid }) => commit_oid),
  };
  VALIDATED_LEDGER_STATES.add(result);
  VALIDATED_LEDGER_REPOSITORIES.set(result, structuredClone(capturedContext.repository));
  VALIDATED_LEDGER_CONTEXTS.set(result, capturedContext);
  VALIDATED_LEDGER_SNAPSHOTS.set(result, structuredClone(result));
  VALIDATED_LEDGER_WRITERS.set(result, writerAuthorities);
  return result;
}

function captureLedgerRecordArray(
  value: unknown,
  label: string,
): readonly LedgerRecord[] {
  if (!Array.isArray(value) || utilTypes.isProxy(value) ||
      Object.getPrototypeOf(value) !== Array.prototype) {
    throw writerUnauthorized(`${label} must be an ordinary array`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const length = Reflect.get(descriptors, "length") as PropertyDescriptor | undefined;
  if (length === undefined || !("value" in length) ||
      !Number.isSafeInteger(length.value) || length.value < 0 || length.value > 4_096) {
    throw writerUnauthorized(`${label} must be a bounded dense array`);
  }
  snapshotBoundedClosedDataTree(value, label);
  return Object.freeze(Array.from(
    { length: length.value as number },
    (_, index) => descriptors[String(index)]!.value as LedgerRecord,
  ));
}

function snapshotBoundedClosedDataTree<T>(value: T, label: string): T {
  const budget = { nodes: 0 };
  const ancestors = new WeakSet<object>();
  const visit = (member: unknown, path: string, depth: number): void => {
    budget.nodes += 1;
    if (budget.nodes > 65_536 || depth > 64) {
      throw writerUnauthorized(`${label} exceeds its closed-data budget`);
    }
    if (member === null || typeof member === "boolean") return;
    if (typeof member === "string") {
      if (member.length > 1_048_576) {
        throw writerUnauthorized(`${label} contains an oversized string`);
      }
      return;
    }
    if (typeof member === "number") {
      if (!Number.isFinite(member)) {
        throw writerUnauthorized(`${label} contains a non-finite number`);
      }
      return;
    }
    if (typeof member !== "object" || utilTypes.isProxy(member)) {
      throw writerUnauthorized(`${path} must be closed ordinary data`);
    }
    if (ancestors.has(member)) throw writerUnauthorized(`${label} contains a cycle`);
    ancestors.add(member);
    try {
      const descriptors = Object.getOwnPropertyDescriptors(member);
      const keys = Reflect.ownKeys(descriptors);
      if (keys.some((key) => typeof key === "symbol")) {
        throw writerUnauthorized(`${path} contains a symbol member`);
      }
      if (Array.isArray(member)) {
        if (Object.getPrototypeOf(member) !== Array.prototype) {
          throw writerUnauthorized(`${path} must be an ordinary array`);
        }
        const length = Reflect.get(descriptors, "length") as PropertyDescriptor | undefined;
        if (length === undefined || !("value" in length) ||
            typeof length.value !== "number" || !Number.isSafeInteger(length.value) ||
            length.value < 0 || length.value > 4_096) {
          throw writerUnauthorized(`${path} must be a bounded dense array`);
        }
        const expected = ["length", ...Array.from({ length: length.value as number }, (_, index) => String(index))]
          .sort();
        if (keys.map(String).sort().join("\0") !== expected.join("\0")) {
          throw writerUnauthorized(`${path} must be a bounded dense array`);
        }
      } else if (Object.getPrototypeOf(member) !== Object.prototype || keys.length > 256) {
        throw writerUnauthorized(`${path} must be a bounded ordinary object`);
      }
      for (const key of keys) {
        if (key === "length" && Array.isArray(member)) continue;
        const descriptor = descriptors[String(key)];
        if (descriptor === undefined || descriptor.enumerable !== true || !("value" in descriptor)) {
          throw writerUnauthorized(`${path} members must be enumerable data properties`);
        }
        visit(descriptor.value, `${path}.${String(key)}`, depth + 1);
      }
    } finally {
      ancestors.delete(member);
    }
  };
  visit(value, label, 0);
  return snapshotClosedDataTree(value, label);
}

function captureLedgerCheckpoint(value: unknown): LedgerCheckpoint {
  const captured = captureExactDataObject(value, [[
    "repository_rid",
    "branch",
    "commit_oid",
    "observed_at",
  ]], "claim ledger checkpoint");
  return Object.freeze({
    repository_rid: captured.repository_rid as string,
    branch: captured.branch as "main",
    commit_oid: captured.commit_oid as string,
    observed_at: captured.observed_at as number,
  });
}

export function revalidateLedgerWriterAuthorities(
  state: LedgerMergeResult,
):
  | { verdict: "accept"; writer_fingerprints: readonly string[] }
  | { verdict: "reject"; reason_code: "claim-ledger-writer-unauthorized" } {
  try {
    assertValidatedLedgerState(state);
    const snapshot = VALIDATED_LEDGER_SNAPSHOTS.get(state);
    const writers = VALIDATED_LEDGER_WRITERS.get(state);
    if (snapshot === undefined || writers === undefined ||
        jcsCanonicalize(state) !== jcsCanonicalize(snapshot)) {
      throw writerUnauthorized("validated ledger writer state is absent or changed");
    }
    for (const writer of writers) {
      revalidateCurrentRepositoryWriterBinding(writer.authority, writer.binding);
    }
    return Object.freeze({
      verdict: "accept" as const,
      writer_fingerprints: Object.freeze(writers.map(({ fingerprint }) => fingerprint)),
    });
  } catch {
    return Object.freeze({
      verdict: "reject" as const,
      reason_code: "claim-ledger-writer-unauthorized" as const,
    });
  }
}

function captureLedgerValidationContext(
  value: LedgerValidationContext,
): LedgerValidationContext {
  const required = [
    "credential_ledger",
    "record_evidence",
    "repository",
    "reader_requests",
    "audience_keys_by_epoch",
    "writer_authority",
    "load_record_location",
  ];
  const captured = captureExactDataObject(value, [
    required,
    [...required, "issuer_key_material_by_record_id"],
  ], "claim ledger validation context");
  if (
    typeof captured.load_record_location !== "function" ||
    utilTypes.isProxy(captured.load_record_location)
  ) throw writerUnauthorized("record-location loader must be a non-proxy callback");
  const credential = snapshotBoundedClosedDataTree(
    captured.credential_ledger,
    "claim ledger credential binding",
  ) as CredentialLedgerBinding;
  const repository = snapshotBoundedClosedDataTree(
    captured.repository,
    "claim ledger repository evidence",
  ) as LedgerRepositoryEvidence;
  return Object.freeze({
    credential_ledger: credential,
    record_evidence: captureOrdinaryMap(
      captured.record_evidence,
      "claim ledger record evidence",
    ) as Map<string, LedgerRecordValidationEvidence>,
    repository,
    reader_requests: captureOrdinaryMap(
      captured.reader_requests,
      "claim ledger reader requests",
    ) as Map<string, ReaderAccessRequest>,
    audience_keys_by_epoch: captureOrdinaryMap(
      captured.audience_keys_by_epoch,
      "claim ledger audience keys",
    ) as Map<number, Uint8Array>,
    ...(captured.issuer_key_material_by_record_id === undefined ? {} : {
      issuer_key_material_by_record_id: captureOrdinaryMap(
        captured.issuer_key_material_by_record_id,
        "claim ledger issuer-key material",
      ) as Map<string, { envelope: IssuerKeyEnvelope; audience_key: Uint8Array }>,
    }),
    writer_authority: captured.writer_authority as CoreRepositoryWriterAuthority,
    load_record_location: captured.load_record_location as LedgerValidationContext["load_record_location"],
  });
}

function captureOrdinaryMap(
  value: unknown,
  label: string,
): Map<unknown, unknown> {
  if (
    value === null || typeof value !== "object" || utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Map.prototype
  ) throw writerUnauthorized(`${label} must be an ordinary Map`);
  let size: number;
  try {
    size = Reflect.getOwnPropertyDescriptor(Map.prototype, "size")!.get!.call(value) as number;
  } catch {
    throw writerUnauthorized(`${label} is not readable as a Map`);
  }
  if (!Number.isSafeInteger(size) || size < 0 || size > 4_096) {
    throw writerUnauthorized(`${label} is oversized`);
  }
  const result = new Map<unknown, unknown>();
  try {
    for (const [key, member] of Map.prototype.entries.call(value) as MapIterator<[unknown, unknown]>) {
      if (result.size >= 4_096) throw writerUnauthorized(`${label} is oversized`);
      result.set(key, member);
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("claim-ledger-writer-unauthorized:")) {
      throw error;
    }
    throw writerUnauthorized(`${label} iteration failed`);
  }
  if (result.size !== size) throw writerUnauthorized(`${label} changed during capture`);
  return result;
}

function captureLedgerRecordLocation(
  value: unknown,
): LedgerRecordLocation & Readonly<{ writer_binding_source: RepositoryWriterBindingV1 }> {
  const captured = captureExactDataObject(value, [[
    "record_id",
    "repository_rid",
    "writer_ref",
    "commit",
    "checkpoint",
    "revision",
    "writer_binding",
  ]], "claim ledger record location");
  if (
    typeof captured.record_id !== "string" || !HEX_32.test(captured.record_id) ||
    typeof captured.repository_rid !== "string" || !RID.test(captured.repository_rid) ||
    typeof captured.writer_ref !== "string" || captured.writer_ref.length === 0 ||
    typeof captured.commit !== "string" || !COMMIT_OID.test(captured.commit) ||
    typeof captured.checkpoint !== "string" || !COMMIT_OID.test(captured.checkpoint) ||
    !Number.isSafeInteger(captured.revision) || (captured.revision as number) < 1
  ) throw writerUnauthorized("record location is invalid");
  const bindingSource = captured.writer_binding as RepositoryWriterBindingV1;
  const binding = snapshotBoundedClosedDataTree(
    bindingSource,
    "claim ledger writer binding",
  ) as RepositoryWriterBindingV1;
  return Object.freeze({
    record_id: captured.record_id,
    repository_rid: captured.repository_rid,
    writer_ref: captured.writer_ref,
    commit: captured.commit,
    checkpoint: captured.checkpoint,
    revision: captured.revision as number,
    writer_binding: binding,
    writer_binding_source: bindingSource,
  });
}

function resolveLedgerWriterAuthorities(
  records: readonly LedgerRecord[],
  checkpoint: LedgerCheckpoint,
  context: LedgerValidationContext,
): readonly LedgerWriterAuthorityRecord[] {
  if (records.length > 4_096) throw writerUnauthorized("too many ledger records");
  const commits = context.repository.commits;
  const writers = new Map<string, LedgerWriterAuthorityRecord>();
  for (const record of records) {
    validateRecordIdentityBeforeWriterResolution(record);
    let loaded: unknown;
    try {
      loaded = context.load_record_location(
        snapshotBoundedClosedDataTree(record, "claim ledger record-location input"),
      );
    } catch {
      throw writerUnauthorized("record-location load failed");
    }
    let location: ReturnType<typeof captureLedgerRecordLocation>;
    try {
      location = captureLedgerRecordLocation(loaded);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("claim-ledger-writer-unauthorized:")) {
        throw error;
      }
      throw writerUnauthorized("record-location capture failed");
    }
    if (
      location.record_id !== record.record_id ||
      location.repository_rid !== checkpoint.repository_rid ||
      location.repository_rid !== context.repository.repository_rid ||
      location.commit !== context.repository.canonical_head ||
      location.checkpoint !== checkpoint.commit_oid ||
      location.checkpoint !== context.repository.canonical_head ||
      location.revision !== commits.length
    ) throw writerUnauthorized("record location does not match canonical repository bytes");
    const binding = location.writer_binding;
    if (
      binding.owner_active_key !== record.persona ||
      binding.repository_rid !== location.repository_rid ||
      binding.writer_nid !== record.writer_nid
    ) throw writerUnauthorized("record and writer binding do not match");
    const fingerprint = domainSeparatedDigestJson(
      "heterodyne-claim-ledger-writer-authority-v1",
      {
        owner_active_key: record.persona,
        repository_rid: location.repository_rid,
        writer_nid: record.writer_nid,
        writer_ref: location.writer_ref,
        operation: "claim-ledger-write",
        writer_binding: location.writer_binding,
      },
    );
    const existing = writers.get(record.writer_nid);
    if (existing !== undefined) {
      if (existing.fingerprint !== fingerprint) {
        throw writerUnauthorized("one writer resolved to conflicting authority");
      }
      continue;
    }
    let opaque: CurrentRepositoryWriterBinding;
    try {
      opaque = resolveCurrentRepositoryWriterBinding(
        context.writer_authority,
        location.writer_binding_source,
        {
          owner_active_key: record.persona,
          repository_rid: location.repository_rid,
          writer_nid: record.writer_nid,
          writer_ref: location.writer_ref,
          operation: "claim-ledger-write",
        },
      );
    } catch {
      throw writerUnauthorized("current Core writer resolution failed");
    }
    writers.set(record.writer_nid, Object.freeze({
      authority: context.writer_authority,
      binding: opaque,
      fingerprint,
    }));
  }
  return Object.freeze(
    [...writers.values()].sort((left, right) =>
      left.fingerprint.localeCompare(right.fingerprint)),
  );
}

function validateRecordIdentityBeforeWriterResolution(record: LedgerRecord): void {
  assertPlainObject(record, "record");
  assertExactKeys(record, RECORD_KEYS, "record");
  validateClaimLedgerRecordSchemaOrThrow(record);
  if (!HEX_32.test(record.record_id) || !HEX_32.test(record.payload_digest) ||
      !HEX_64.test(record.signature)) {
    throw new Error("claim-schema-invalid: invalid ledger byte encoding");
  }
  if (record.payload_digest !==
      domainSeparatedDigestJson("heterodyne-claim-ledger-payload-v1", record.payload) ||
      record.record_id !== domainSeparatedDigestJson(
        "heterodyne-claim-ledger-record-id-v1",
        withoutRecordId(record),
      )) {
    throw new Error("claim-id-mismatch: record_id does not match the record bytes at its location");
  }
  if (!ed25519.verify(
    hexToBytes(record.signature),
    utf8Bytes(recordSigningPayload(record)),
    ed25519PublicKeyFromNid(record.writer_nid),
  )) throw new Error("claim-event-signature-invalid: record self-signature is invalid");
}

function writerUnauthorized(detail: string): Error {
  return new Error(`claim-ledger-writer-unauthorized: ${detail}`);
}

export function canonicalValidatedCheckpoint(state: LedgerMergeResult): LedgerCheckpoint {
  assertValidatedLedgerState(state);
  const snapshot = VALIDATED_LEDGER_SNAPSHOTS.get(state);
  if (snapshot === undefined) throw new Error("claim-repository-unconfirmed: immutable state snapshot is absent");
  if (jcsCanonicalize(state) !== jcsCanonicalize(snapshot)) {
    throw new Error("claim-repository-conflict: validated ledger state was mutated after merge");
  }
  return structuredClone(snapshot.checkpoint);
}

export function currentAuthorizationLedgerView(state: LedgerMergeResult): Readonly<{
  checkpoint: LedgerCheckpoint;
  conflicted: boolean;
  state: LedgerMergeResult;
}> {
  assertValidatedLedgerState(state);
  const snapshot = VALIDATED_LEDGER_SNAPSHOTS.get(state);
  if (snapshot === undefined) {
    throw new Error("claim-repository-unconfirmed: immutable state snapshot is absent");
  }
  const capturedState = snapshotClosedDataTree(state, "current authorization ledger state");
  if (jcsCanonicalize(capturedState) !== jcsCanonicalize(snapshot)) {
    throw new Error("claim-repository-conflict: validated ledger state was mutated after merge");
  }
  const immutableState = snapshotClosedDataTree(snapshot, "current authorization ledger snapshot");
  VALIDATED_LEDGER_STATES.add(immutableState);
  VALIDATED_LEDGER_SNAPSHOTS.set(immutableState, immutableState);
  const writerAuthorities = VALIDATED_LEDGER_WRITERS.get(state);
  if (writerAuthorities === undefined) {
    throw writerUnauthorized("current authorization writer state is absent");
  }
  VALIDATED_LEDGER_WRITERS.set(immutableState, writerAuthorities);
  return Object.freeze({
    checkpoint: immutableState.checkpoint,
    conflicted: snapshot.conflicted_claim_ids.length > 0,
    state: immutableState,
  });
}

export function activeCanonicalClaimSemanticsAt(
  state: LedgerMergeResult,
  evaluationTime = state.checkpoint.observed_at,
): ClaimSemanticBody[] {
  canonicalValidatedCheckpoint(state);
  const snapshot = VALIDATED_LEDGER_SNAPSHOTS.get(state);
  const repository = validatedRepositoryForState(state);
  const canonicalHead = repository.commits.find(({ commit_oid }) => commit_oid === repository.canonical_head);
  if (snapshot === undefined || canonicalHead === undefined) {
    throw new Error("claim-repository-unconfirmed: canonical claim snapshot is absent");
  }
  const confirmed = new Set(repository.repository_confirmed_record_ids);
  const atHead = new Set(canonicalHead.record_ids);
  const active = new Map<string, ClaimSemanticBody>();
  for (const record of snapshot.records) {
    if (record.record_type !== "claim" ||
        record.credential_ledger_generation !== snapshot.credential_ledger.credential_ledger_generation ||
        !confirmed.has(record.record_id) || !atHead.has(record.record_id)) continue;
    const semantic = claimArtifactFromRecord(record)?.semantic;
    if (semantic !== undefined &&
        resolveAuthoritativeClaimState(semantic.claim_id, snapshot, evaluationTime) === "active") {
      active.set(semantic.claim_id, structuredClone(semantic));
    }
  }
  return [...active.values()].sort((left, right) => left.claim_id.localeCompare(right.claim_id));
}

export function activeIssuerWriterNidsAt(state: LedgerMergeResult, now: number): string[] {
  assertValidatedLedgerState(state);
  if (!Number.isSafeInteger(now) || now < state.checkpoint.observed_at) {
    throw new Error("oidc-issuer-authority-invalid: invalid issuer-authority evaluation time");
  }
  return deriveActiveIssuerNids(state, now);
}

export function currentIssuerSigningKeyId(state: LedgerMergeResult): string {
  assertValidatedLedgerState(state);
  canonicalValidatedCheckpoint(state);
  const record = currentIssuerKeyEpochRecord(state);
  if (record === null) throw new Error("oidc-signing-key-unavailable: current issuer-key epoch is absent");
  const keyId = payloadObject(record.payload).key_digest;
  assertCanonicalSigningKeyId(keyId, "current issuer signing-key ID");
  return keyId;
}

export function replayConfirmedClaimForAuthorization(input: {
  state: LedgerMergeResult;
  claim_record_id: string;
  verification_context: ClaimVerificationContext;
}): {
  record: LedgerRecord;
  semantic: ClaimSemanticBody;
  decision: AuthorizationDecision;
  verified_claim: VerifiedClaimArtifact;
  chain: readonly VerifiedClaimArtifact[];
} {
  assertValidatedLedgerState(input.state);
  canonicalValidatedCheckpoint(input.state);
  if (jcsCanonicalize(input.state.checkpoint) !==
      jcsCanonicalize(validatedRepositoryForState(input.state).checkpoint)) {
    throw new Error("claim-ledger-rollback: release checkpoint is not the full canonical checkpoint");
  }
  const snapshot = VALIDATED_LEDGER_SNAPSHOTS.get(input.state);
  if (snapshot === undefined) throw new Error("claim-repository-unconfirmed: immutable state snapshot is absent");
  const record = snapshot.records.find(({ record_id }) => record_id === input.claim_record_id);
  const context = VALIDATED_LEDGER_CONTEXTS.get(input.state);
  const repository = validatedRepositoryForState(input.state);
  const canonicalHead = repository.commits.find(({ commit_oid }) => commit_oid === repository.canonical_head);
  if (record?.record_type !== "claim" ||
      record.credential_ledger_generation !== input.state.credential_ledger.credential_ledger_generation ||
      context === undefined ||
      !repository.repository_confirmed_record_ids.includes(input.claim_record_id) ||
      !canonicalHead?.record_ids.includes(input.claim_record_id)) {
    throw new Error("claim-repository-unconfirmed: release source claim is not canonical");
  }
  const records = new Map(snapshot.records.map((candidate) => [candidate.record_id, candidate]));
  const evidence = context.record_evidence.get(record.record_id);
  validateLedgerRecordOrThrow(record, records, evidence, input.state.credential_ledger);
  const artifact = claimArtifactFromRecord(record);
  if (artifact === null || evidence?.claim_envelope_context === undefined || evidence.claims_by_id === undefined) {
    throw new Error("claim-event-signature-invalid: release source claim evidence is absent");
  }
  const verifiedClaim = verifyLedgerClaimArtifact(artifact, evidence.claim_envelope_context);
  const semantic = inspectVerifiedClaim(verifiedClaim);
  const chain = verifyClaimChain(
    verifiedClaim,
    evidence.claims_by_id as ReadonlyMap<string, VerifiedClaimArtifact>,
  );
  const decision = authorizeWithClaim(verifiedClaim, chain, {
    ...input.verification_context,
    repository_confirmed: confirmedClaimIds(snapshot),
    repository_conflicted: new Set(snapshot.conflicted_claim_ids),
    revocations: authenticatedRevocationsFromRecords(snapshot.records),
  });
  if (resolveAuthoritativeClaimState(semantic.claim_id, snapshot, input.verification_context.now) !== decision.state) {
    throw new Error("claim-repository-conflict: replayed and authoritative claim state disagree");
  }
  return { record, semantic, decision, verified_claim: verifiedClaim, chain };
}

export function currentClaimAuthorizationView(state: LedgerMergeResult): Readonly<{
  credential_ledger: CredentialLedgerBinding;
  checkpoint_digest: string;
  repository_revision: number;
  claims: readonly VerifiedClaimArtifact[];
  revocations: readonly VerifiedClaimRevocationArtifact[];
  conflicted_claim_ids: readonly string[];
  ledger_state: LedgerMergeResult;
}> {
  assertValidatedLedgerState(state);
  canonicalValidatedCheckpoint(state);
  const context = VALIDATED_LEDGER_CONTEXTS.get(state);
  const repository = validatedRepositoryForState(state);
  const confirmed = new Set(repository.repository_confirmed_record_ids);
  const head = repository.commits.find(({ commit_oid }) =>
    commit_oid === repository.canonical_head);
  if (context === undefined || head === undefined) {
    throw new Error("claim-repository-unconfirmed: current claim authorization view is absent");
  }
  const claims: VerifiedClaimArtifact[] = [];
  for (const record of state.records) {
    if (record.record_type !== "claim" || !confirmed.has(record.record_id) ||
        !head.record_ids.includes(record.record_id)) continue;
    const artifact = claimArtifactFromRecord(record);
    const evidence = context.record_evidence.get(record.record_id);
    if (artifact === null || evidence?.claim_envelope_context === undefined) {
      throw new Error("claim-event-signature-invalid: current claim artifact is absent");
    }
    claims.push(verifyLedgerClaimArtifact(artifact, evidence.claim_envelope_context));
  }
  const revocations = authenticatedRevocationsFromRecords(state.records);
  return Object.freeze({
    credential_ledger: Object.freeze({ ...state.credential_ledger }),
    checkpoint_digest: domainSeparatedDigestJson(
      "heterodyne-claim-authorization-checkpoint-v1",
      state.checkpoint,
    ),
    repository_revision: repository.commits.length,
    claims: Object.freeze(claims),
    revocations: Object.freeze(revocations),
    conflicted_claim_ids: Object.freeze([...state.conflicted_claim_ids].sort()),
    ledger_state: state,
  });
}

export function prepareReaderClaimAuthorization(
  readerNid: string | null,
  state: LedgerMergeResult,
  request?: ReaderAccessRequest,
): Readonly<{
  decision: AuthorizationDecision;
  verified_claim?: VerifiedClaimArtifact;
  chain?: readonly VerifiedClaimArtifact[];
}> {
  const decision = evaluateReaderAccess(readerNid, state, request);
  if (decision.state !== "active" || readerNid === null || request === undefined) {
    return Object.freeze({ decision });
  }
  const record = state.records.find(({ record_id }) =>
    record_id === request.claim_record_id);
  const artifact = record === undefined ? null : claimArtifactFromRecord(record);
  if (artifact === null) return Object.freeze({
    decision: readerDenied("invalid", "claim-ledger-reader-unauthorized"),
  });
  try {
    const verifiedClaim = verifyLedgerClaimArtifact(
      artifact,
      request.envelope_context,
    );
    return Object.freeze({
      decision,
      verified_claim: verifiedClaim,
      chain: verifyClaimChain(
        verifiedClaim,
        request.claims_by_id as ReadonlyMap<string, VerifiedClaimArtifact>,
      ),
    });
  } catch {
    return Object.freeze({
      decision: readerDenied("invalid", "claim-event-signature-invalid"),
    });
  }
}

export function deriveLedgerPath(audienceKey: Uint8Array, recordId: string): string {
  if (audienceKey.length !== 32) throw new Error("ledger audience key must be exactly 32 bytes");
  if (!HEX_32.test(recordId)) throw new Error("ledger record ID must be lowercase SHA-256 hex");
  const opaque = createHmac("sha256", audienceKey)
    .update("heterodyne-claim-ledger-path-v1\0", "utf8")
    .update(recordId, "hex")
    .digest("hex");
  // Every ledger generation materializes all 256 bucket files (empty buckets
  // contain authenticated padding). The keyed selector therefore reveals
  // neither a raw record ID nor the number or class of records in the tree.
  return `objects/${opaque.slice(0, 2)}.bin`;
}

export function materializeLedgerLayout(
  audienceKey: Uint8Array,
  epoch: number,
  commitOid: string,
  commitNonce: string,
  records: LedgerRecord[],
): LedgerLayout {
  if (audienceKey.length !== 32) throw new Error("ledger audience key must be exactly 32 bytes");
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error("claim-schema-invalid: invalid ledger key epoch");
  if (!HEX_32.test(commitOid)) throw new Error("claim-schema-invalid: commit OID must be 32-byte lowercase hex");
  if (!HEX_32.test(commitNonce)) throw new Error("claim-schema-invalid: commit nonce must be 32-byte lowercase hex");
  const snapshot_digest = digestJson({
    domain: "heterodyne-claim-ledger-snapshot-v1",
    records: [...records].sort((left, right) => left.record_id.localeCompare(right.record_id)),
  });
  const buckets = Array.from({ length: 256 }, () => [] as string[]);
  for (const record of records) {
    if (!HEX_32.test(record.record_id)) throw new Error("claim-id-mismatch: invalid ledger record ID");
    const bucket = Number.parseInt(deriveLedgerPath(audienceKey, record.record_id).slice(8, 10), 16);
    buckets[bucket].push(record.record_id);
  }
  const entries = buckets.map((recordIds, bucket) => {
    const bucketHex = bucket.toString(16).padStart(2, "0");
    const plaintextDigest = digestJson({
      domain: "heterodyne-claim-ledger-bucket-v1",
      epoch,
      commit_oid: commitOid,
      snapshot_digest,
      bucket: bucketHex,
      record_ids: recordIds.sort(),
    });
    const block = (counter: number) => createHmac("sha256", audienceKey)
      .update("heterodyne-claim-ledger-fixed-layout-v1\0", "utf8")
      .update(commitNonce, "hex")
      .update(commitOid, "hex")
      .update(snapshot_digest, "hex")
      .update(utf8Bytes(`${epoch}|${bucketHex}|${counter}|${plaintextDigest}`))
      .digest("hex");
    return {
      path: `objects/${bucketHex}.bin`,
      size: 64 as const,
      ciphertext: `${block(0)}${block(1)}`,
    };
  });
  return {
    entries,
    commit_metadata: {
      message: "heterodyne private ledger update",
      entry_count: 256,
      entry_size: 64,
      epoch,
      commit_oid: commitOid,
      nonce: commitNonce,
      snapshot_digest,
    },
  };
}

export function validateLedgerLayoutTransition(previous: LedgerLayout, next: LedgerLayout): void {
  if (next.commit_metadata.epoch < previous.commit_metadata.epoch ||
      next.commit_metadata.commit_oid === previous.commit_metadata.commit_oid ||
      next.commit_metadata.nonce === previous.commit_metadata.nonce) {
    throw new Error("claim-repository-conflict: ledger commit, epoch, and nonce transition is not unique");
  }
}

export function createAudienceKeyEpochPayload(input: {
  persona: string;
  repository_rid: string;
  checkpoint_commit_oid: string;
  epoch: number;
  key_id: string;
  audience_key: Uint8Array;
  previous_epoch: number;
  previous_key_id: string;
  reader_nids: string[];
  removed_reader_nids: string[];
}): AudienceKeyEpochPayload {
  const key_digest = bytesToHex(sha256(input.audience_key));
  if (!PERSONA.test(input.persona) || !RID.test(input.repository_rid) || !HEX_32.test(input.checkpoint_commit_oid) ||
      input.audience_key.length !== 32 || !Number.isSafeInteger(input.epoch) || !Number.isSafeInteger(input.previous_epoch) ||
      input.epoch !== input.previous_epoch + 1 || input.epoch < 1) {
    throw new Error("claim-schema-invalid: invalid audience-key rotation context");
  }
  if (input.key_id !== key_digest || !HEX_32.test(input.previous_key_id) ||
      input.key_id === input.previous_key_id ||
      (input.previous_epoch === 0 && input.previous_key_id !== GENESIS_AUDIENCE_KEY_ID)) {
    throw new Error("claim-schema-invalid: audience key ID must be the canonical key-material digest");
  }
  validateNidSet(input.reader_nids);
  validateNidSet(input.removed_reader_nids);
  if (input.removed_reader_nids.some((nid) => input.reader_nids.includes(nid))) {
    throw new Error("claim-ledger-reader-unauthorized: removed reader retained in new key epoch");
  }
  const recipient_wraps = [...input.reader_nids].sort().map((reader_nid) => {
    const context = {
      domain: "heterodyne-claim-ledger-recipient-wrap-v1",
      persona: input.persona,
      repository_rid: input.repository_rid,
      checkpoint_commit_oid: input.checkpoint_commit_oid,
      epoch: input.epoch,
      key_id: input.key_id,
      key_digest,
      reader_nid,
    };
    const context_digest = digestJson(context);
    const wrapBlock = (counter: number) => createHmac("sha256", input.audience_key)
      .update("heterodyne-claim-ledger-key-wrap-v1\0", "utf8")
      .update(context_digest, "hex")
      .update(Uint8Array.of(counter))
      .digest("hex");
    return { reader_nid, context_digest, wrapped_key: `${wrapBlock(0)}${wrapBlock(1)}` };
  });
  return {
    epoch: input.epoch,
    key_id: input.key_id,
    key_digest,
    previous_epoch: input.previous_epoch,
    previous_key_id: input.previous_key_id,
    reader_nids: [...input.reader_nids].sort(),
    removed_reader_nids: [...input.removed_reader_nids].sort(),
    recipient_wraps,
    radicle_access_removed: [...input.removed_reader_nids].sort(),
    checkpoint_commit_oid: input.checkpoint_commit_oid,
    retire_previous_state: true,
    scrub_profile: "comms-encrypted-branch-cooperative-v1",
  };
}

export function createIssuerKeyEpochPayload(input: {
  authority_state: LedgerMergeResult;
  envelope: IssuerKeyEnvelope;
  previous_record: LedgerRecord | null;
}): IssuerKeyEpochPayload {
  assertValidatedLedgerState(input.authority_state);
  if (!Object.prototype.hasOwnProperty.call(input.envelope, "credential_ledger_generation")) {
    throw new Error("credential_generation_missing");
  }
  const recipients = input.envelope.recipient_wraps.map(({ writer_nid }) => writer_nid).sort();
  const activeIssuers = deriveActiveIssuerNids(input.authority_state);
  const expectedAuthorityIds = issuerAuthorityRecordIds(input.authority_state);
  if (input.envelope.persona !== input.authority_state.credential_ledger.credential_ledger_persona ||
      input.envelope.credential_ledger_generation !==
        input.authority_state.credential_ledger.credential_ledger_generation ||
      input.envelope.repository_rid !== input.authority_state.checkpoint.repository_rid ||
      input.envelope.checkpoint_commit_oid !== input.authority_state.checkpoint.commit_oid ||
      !input.authority_state.records.every(({ persona }) => persona === input.envelope.persona) ||
      jcsCanonicalize(recipients) !== jcsCanonicalize(activeIssuers) ||
      jcsCanonicalize(input.envelope.authority_record_ids) !== jcsCanonicalize(expectedAuthorityIds) ||
      input.envelope.authority_record_set_digest !== digestJson(expectedAuthorityIds)) {
    throw new Error("oidc-signing-key-unavailable: issuer envelope is not bound to canonical authority state");
  }
  let previousEpoch = 0;
  let previousEnvelopeDigest = GENESIS_AUDIENCE_KEY_ID;
  let previousKeyDigest = GENESIS_AUDIENCE_KEY_ID;
  if (input.previous_record !== null) {
    if (input.previous_record.record_type !== "audience-key-epoch") {
      throw new Error("claim-repository-conflict: issuer-key predecessor has wrong record type");
    }
    const previous = payloadObject(input.previous_record.payload);
    if (previous.scope !== "oidc-issuer-key") {
      throw new Error("claim-repository-conflict: issuer-key predecessor has wrong scope");
    }
    previousEpoch = Number(previous.epoch);
    previousEnvelopeDigest = String(previous.envelope_digest);
    previousKeyDigest = String(previous.key_digest);
  }
  if (input.envelope.epoch !== previousEpoch + 1 ||
      (previousEpoch === 0 ? input.envelope.previous_key_id !== GENESIS_AUDIENCE_KEY_ID :
        input.envelope.previous_key_id === GENESIS_AUDIENCE_KEY_ID)) {
    throw new Error("claim-repository-conflict: issuer-key epoch does not extend its predecessor");
  }
  return {
    scope: "oidc-issuer-key",
    epoch: input.envelope.epoch,
    envelope_digest: digestJson(input.envelope),
    key_digest: input.envelope.signing_key_id,
    previous_epoch: previousEpoch,
    previous_envelope_digest: previousEnvelopeDigest,
    previous_key_digest: previousKeyDigest,
    recipient_nids: recipients,
    checkpoint: { ...input.authority_state.checkpoint },
  };
}

export function buildLedgerRepositoryEvidence(input: {
  repository_rid: string;
  confirmed_records: LedgerRecord[];
  observed_at: number;
  prior?: LedgerRepositoryEvidence;
}): { checkpoint: LedgerCheckpoint; repository: LedgerRepositoryEvidence } {
  if (!RID.test(input.repository_rid)) throw new Error("claim-schema-invalid: invalid repository RID");
  const recordIds = [...new Set(input.confirmed_records.map(({ record_id }) => record_id))].sort();
  const record_set_digest = digestJson(recordIds);
  const tree_oid = digestJson({
    domain: "heterodyne-claim-ledger-tree-v1",
    record_ids: recordIds,
    record_set_digest,
  });
  const parents = input.prior === undefined ? [] : [input.prior.canonical_head];
  const commitCore = {
    domain: "heterodyne-claim-ledger-commit-v1",
    repository_rid: input.repository_rid,
    branch: "main" as const,
    tree_oid,
    parents,
    record_set_digest,
  };
  const commit_oid = digestJson(commitCore);
  const commit: LedgerRepositoryCommit = { commit_oid, tree_oid, parents, record_ids: recordIds, record_set_digest };
  const checkpoint: LedgerCheckpoint = {
    repository_rid: input.repository_rid,
    branch: "main",
    commit_oid,
    observed_at: input.observed_at,
  };
  return {
    checkpoint,
    repository: {
      repository_rid: input.repository_rid,
      branch: "main",
      genesis: input.prior === undefined,
      prior_checkpoint: input.prior?.checkpoint ?? null,
      canonical_head: commit_oid,
      checkpoint,
      commits: [...(input.prior?.commits ?? []), commit],
      repository_confirmed_record_ids: recordIds,
    },
  };
}

export function evaluateLedgerCheckpointEligibility(
  now: number,
  checkpoint: LedgerCheckpoint,
  manifestMaxAgeSeconds: number,
): AuthorizationDecision {
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(manifestMaxAgeSeconds) ||
      manifestMaxAgeSeconds < 0 || manifestMaxAgeSeconds > 300 || now < checkpoint.observed_at ||
      now - checkpoint.observed_at > manifestMaxAgeSeconds) {
    return { allowed: false, state: "invalid", reason_code: "oidc-checkpoint-stale" };
  }
  return { allowed: true, state: "active", reason_code: null };
}

/**
 * Evaluate a mint against the canonical checkpoint produced by the immediately
 * preceding repository synchronization attempt. The caller derives
 * issuerClaimState from the merged, conflict-aware ledger and hasSigningKey by
 * successfully unwrapping the dedicated issuer-key object.
 */
export function canMint(
  now: number,
  checkpoint: LedgerCheckpoint,
  manifestMaxAgeSeconds: number,
  issuerClaimState: ClaimState,
  hasSigningKey: boolean,
): MintingEligibility {
  const denied = (reason_code: string): MintingEligibility => ({
    allowed: false,
    reason_code,
    checkpoint: { ...checkpoint },
  });
  try {
    validateCheckpoint(checkpoint);
  } catch {
    return denied("oidc-checkpoint-stale");
  }
  if (issuerClaimState !== "active") return denied("oidc-issuer-authority-invalid");
  if (!hasSigningKey) return denied("oidc-signing-key-unavailable");
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(manifestMaxAgeSeconds) ||
      manifestMaxAgeSeconds < 0 || manifestMaxAgeSeconds > 300 || now < checkpoint.observed_at) {
    return denied("oidc-checkpoint-stale");
  }
  if (now - checkpoint.observed_at > manifestMaxAgeSeconds) return denied("oidc-checkpoint-stale");
  return { allowed: true, reason_code: null, checkpoint: { ...checkpoint } };
}

export function reserveStatusIndex(
  writerNid: string,
  expiresAt: number,
  listSequence: number,
  existing: IssuanceRecord[],
): StatusReservation {
  ed25519PublicKeyFromNid(writerNid);
  if (!Number.isSafeInteger(expiresAt) || expiresAt < 0 ||
      !Number.isSafeInteger(listSequence) || listSequence < 0) {
    throw new Error("claim-schema-invalid: invalid status reservation tuple");
  }
  for (const issuance of existing) validateIssuanceRecordOrThrow(issuance);
  const seen = new Set<string>();
  for (const issuance of existing) {
    const tuple = `${issuance.reservation.uri}\0${issuance.reservation.idx}`;
    if (seen.has(tuple)) throw new Error("claim-repository-conflict: duplicate status tuple/index reservation");
    seen.add(tuple);
  }
  const expiry_bucket = String(Math.floor(expiresAt / 86_400));
  const writer_nid_fingerprint = bytesToHex(sha256(utf8Bytes(writerNid))).slice(0, 32);
  const uri = `status-lists/${expiry_bucket}/${writer_nid_fingerprint}/${String(listSequence)}.jwt`;
  const indexes = existing
    .filter(({ reservation }) => reservation.uri === uri)
    .map(({ reservation }) => reservation.idx)
    .sort((left, right) => left - right);
  indexes.forEach((idx, position) => {
    if (idx !== position) throw new Error("claim-repository-conflict: status indexes are not a monotonic allocation prefix");
  });
  return { uri, idx: indexes.length, expiry_bucket, writer_nid_fingerprint, list_sequence: listSequence };
}

export function validateIssuanceRecordOrThrow(
  record: IssuanceRecord,
  expectedCredentialLedger?: CredentialLedgerBinding,
): void {
  if (record === null || typeof record !== "object" ||
      !Object.prototype.hasOwnProperty.call(record, "credential_ledger_generation")) {
    throw new Error("credential_generation_missing");
  }
  validateOidcIssuanceRecordSchemaOrThrow(record);
  if (expectedCredentialLedger !== undefined &&
      record.credential_ledger_generation !== expectedCredentialLedger.credential_ledger_generation) {
    throw new Error("credential_generation_stale");
  }
  assertCanonicalSigningKeyId(record.signing_key_id);
  if (record.expires_at <= record.issued_at ||
      record.issued_at < record.checkpoint.observed_at ||
      record.issued_at - record.checkpoint.observed_at > record.manifest_max_age_seconds ||
      record.reservation.expiry_bucket !== String(Math.floor(record.expires_at / 86_400)) ||
      record.reservation.uri !== `status-lists/${record.reservation.expiry_bucket}/${record.reservation.writer_nid_fingerprint}/${String(record.reservation.list_sequence)}.jwt`) {
    throw new Error("claim-schema-invalid: issuance record freshness or reservation binding is invalid");
  }
  validateCheckpoint(record.checkpoint);
}

function assertCanonicalSigningKeyId(value: unknown, label = "signing_key_id"): asserts value is string {
  if (typeof value !== "string" || !JWK_THUMBPRINT.test(value)) {
    throw new Error(`claim-schema-invalid: ${label} must be a canonical SHA-256 JWK thumbprint`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== value) {
    throw new Error(`claim-schema-invalid: ${label} must decode to exactly 32 bytes`);
  }
}

function validatePrivateIssuerJwk(value: JsonValue): string {
  assertPlainObject(value, "private issuer signing JWK");
  assertExactKeys(value, [
    "kty", "n", "e", "d", "p", "q", "dp", "dq", "qi", "kid", "alg", "use", "key_ops",
  ], "private issuer signing JWK");
  if (value.kty !== "RSA" || value.alg !== "RS256" || value.use !== "sig" ||
      !Array.isArray(value.key_ops) || value.key_ops.length !== 1 || value.key_ops[0] !== "sign") {
    throw new Error("oidc-signing-key-unavailable: issuer signing JWK metadata is invalid");
  }
  for (const member of ["n", "e", "d", "p", "q", "dp", "dq", "qi"] as const) {
    if (typeof value[member] !== "string" || value[member].length === 0) {
      throw new Error(`oidc-signing-key-unavailable: issuer signing JWK ${member} is missing`);
    }
  }
  const thumbprint = computeJwkThumbprint({ kty: "RSA", n: value.n, e: value.e });
  assertCanonicalSigningKeyId(thumbprint);
  if (value.kid !== thumbprint) {
    throw new Error("oidc-signing-key-unavailable: private JWK kid must equal its RFC 7638 public thumbprint");
  }
  return thumbprint;
}

export function createIssuerKeyEnvelope(input: {
  persona: string;
  repository_rid: string;
  epoch: number;
  audience_key: Uint8Array;
  signing_jwk: JsonValue;
  authority_state: LedgerMergeResult;
  recipient_nids: string[];
  previous?: { envelope: IssuerKeyEnvelope; audience_key: Uint8Array };
}): IssuerKeyEnvelope {
  assertValidatedLedgerState(input.authority_state);
  const repository = validatedRepositoryForState(input.authority_state);
  const checkpoint_commit_oid = input.authority_state.checkpoint.commit_oid;
  if (!PERSONA.test(input.persona) || !RID.test(input.repository_rid) ||
      !Number.isSafeInteger(input.epoch) || input.epoch < 1 || input.audience_key.length !== 32) {
    throw new Error("claim-schema-invalid: invalid issuer signing-key envelope context");
  }
  if (input.persona !== input.authority_state.credential_ledger.credential_ledger_persona) {
    throw new Error("credential_ledger_persona_mismatch");
  }
  const credential_ledger_generation =
    input.authority_state.credential_ledger.credential_ledger_generation;
  if (input.authority_state.checkpoint.repository_rid !== input.repository_rid ||
      input.authority_state.records.some((record) =>
        record.record_type === "issuer-authority" && payloadObject(record.payload).action === "remove" &&
        !(input.authority_state.repository_confirmed_record_ids ?? []).includes(record.record_id))) {
    throw new Error("claim-repository-unconfirmed: issuer-key rotation requires canonical authority reductions");
  }
  validateNidSet(input.recipient_nids);
  const activeIssuerNids = deriveActiveIssuerNids(input.authority_state);
  if (jcsCanonicalize([...input.recipient_nids].sort()) !== jcsCanonicalize(activeIssuerNids)) {
    throw new Error("oidc-issuer-authority-invalid: issuer-key recipients must exactly equal active canonical issuers");
  }
  const signing_key_id = validatePrivateIssuerJwk(input.signing_jwk);
  const plaintext = utf8Bytes(jcsCanonicalize(input.signing_jwk));
  const content_digest = bytesToHex(sha256(plaintext));
  const audience_key_id = bytesToHex(sha256(input.audience_key));
  const previous_key_id = input.previous?.envelope.audience_key_id ?? GENESIS_AUDIENCE_KEY_ID;
  const hasCanonicalRemoval = input.authority_state.records.some((record) =>
    record.record_type === "issuer-authority" && payloadObject(record.payload).action === "remove" &&
    (input.authority_state.repository_confirmed_record_ids ?? []).includes(record.record_id));
  let previousRecipients: string[] = [];
  if (input.previous === undefined) {
    if (input.epoch !== 1 || hasCanonicalRemoval) {
      throw new Error("oidc-signing-key-unavailable: issuer genesis cannot follow authority removal or an existing epoch");
    }
  } else {
    previousRecipients = validatePreviousIssuerKeyEnvelope({
      previous: input.previous,
      state: input.authority_state,
      repository,
      persona: input.persona,
      repository_rid: input.repository_rid,
      next_epoch: input.epoch,
      next_audience_key_id: audience_key_id,
      next_signing_key_id: signing_key_id,
      next_content_digest: content_digest,
    });
  }
  if (input.previous !== undefined && (
      input.epoch !== input.previous.envelope.epoch + 1 ||
      bytesToHex(sha256(input.previous.audience_key)) !== input.previous.envelope.audience_key_id ||
      previous_key_id === audience_key_id)) {
    throw new Error("oidc-signing-key-unavailable: issuer audience key was not rotated");
  }
  const removed_issuer_nids = previousRecipients.filter((nid) => !activeIssuerNids.includes(nid)).sort();
  const authority_record_ids = issuerAuthorityRecordIds(input.authority_state);
  const authority_record_set_digest = digestJson(authority_record_ids);
  const context = {
    domain: "heterodyne-oidc-signing-key-object-v1",
    persona: input.persona,
    credential_ledger_generation,
    repository_rid: input.repository_rid,
    checkpoint_commit_oid,
    epoch: input.epoch,
    audience_key_id,
    previous_key_id,
    signing_key_id,
    content_digest,
    authority_record_set_digest,
  };
  const aad = utf8Bytes(jcsCanonicalize(context));
  const nonce = sha256(utf8Bytes(`heterodyne-oidc-signing-key-nonce-v1\0${jcsCanonicalize(context)}`)).slice(0, 24);
  const ciphertext = xchacha20poly1305(input.audience_key, nonce, aad).encrypt(plaintext);
  const recipient_wraps = activeIssuerNids.map((writer_nid) => {
    const context_digest = digestJson({ ...context, writer_nid });
    const wrapBlock = (counter: number) => createHmac("sha256", input.audience_key)
      .update("heterodyne-oidc-issuer-key-wrap-v1\0", "utf8")
      .update(context_digest, "hex")
      .update(Uint8Array.of(counter))
      .digest("hex");
    return { writer_nid, context_digest, wrapped_key: `${wrapBlock(0)}${wrapBlock(1)}` };
  });
  return {
    object_type: "oidc-signing-jwk-v1",
    persona: input.persona,
    credential_ledger_generation,
    repository_rid: input.repository_rid,
    checkpoint_commit_oid,
    epoch: input.epoch,
    audience_key_id,
    previous_key_id,
    signing_key_id,
    content_digest,
    nonce: bytesToHex(nonce),
    ciphertext: bytesToHex(ciphertext),
    authority_record_ids,
    authority_record_set_digest,
    recipient_wraps,
    removed_issuer_nids,
  };
}

export function unwrapIssuerSigningJwk(
  envelope: IssuerKeyEnvelope,
  writerNid: string,
  audienceKey: Uint8Array,
): JsonValue {
  if (!Object.prototype.hasOwnProperty.call(envelope, "credential_ledger_generation")) {
    throw new Error("credential_generation_missing");
  }
  ed25519PublicKeyFromNid(writerNid);
  if (audienceKey.length !== 32 || bytesToHex(sha256(audienceKey)) !== envelope.audience_key_id) {
    throw new Error("oidc-signing-key-unavailable: incorrect dedicated issuer audience key");
  }
  const wrap = envelope.recipient_wraps.find(({ writer_nid }) => writer_nid === writerNid);
  if (wrap === undefined || envelope.removed_issuer_nids.includes(writerNid)) {
    throw new Error("oidc-issuer-authority-invalid: no active issuer recipient wrap");
  }
  const context = {
    domain: "heterodyne-oidc-signing-key-object-v1",
    persona: envelope.persona,
    credential_ledger_generation: envelope.credential_ledger_generation,
    repository_rid: envelope.repository_rid,
    checkpoint_commit_oid: envelope.checkpoint_commit_oid,
    epoch: envelope.epoch,
    audience_key_id: envelope.audience_key_id,
    previous_key_id: envelope.previous_key_id,
    signing_key_id: envelope.signing_key_id,
    content_digest: envelope.content_digest,
    authority_record_set_digest: envelope.authority_record_set_digest,
  };
  if (envelope.authority_record_set_digest !== digestJson(envelope.authority_record_ids)) {
    throw new Error("oidc-issuer-authority-invalid: issuer authority record-set binding mismatch");
  }
  if (wrap.context_digest !== digestJson({ ...context, writer_nid: writerNid })) {
    throw new Error("oidc-signing-key-unavailable: issuer recipient wrap binding mismatch");
  }
  const expectedWrapBlock = (counter: number) => createHmac("sha256", audienceKey)
    .update("heterodyne-oidc-issuer-key-wrap-v1\0", "utf8")
    .update(wrap.context_digest, "hex")
    .update(Uint8Array.of(counter))
    .digest("hex");
  if (wrap.wrapped_key !== `${expectedWrapBlock(0)}${expectedWrapBlock(1)}`) {
    throw new Error("oidc-signing-key-unavailable: issuer recipient key wrap is invalid");
  }
  try {
    const plaintext = xchacha20poly1305(
      audienceKey,
      hexToBytes(envelope.nonce),
      utf8Bytes(jcsCanonicalize(context)),
    ).decrypt(hexToBytes(envelope.ciphertext));
    if (bytesToHex(sha256(plaintext)) !== envelope.content_digest) throw new Error("digest");
    const jwk = JSON.parse(new TextDecoder().decode(plaintext)) as JsonValue;
    if (validatePrivateIssuerJwk(jwk) !== envelope.signing_key_id) throw new Error("thumbprint");
    return jwk;
  } catch {
    throw new Error("oidc-signing-key-unavailable: issuer signing JWK decryption failed");
  }
}

export function invalidationsForCompromisedSigningKey(
  compromisedKeyId: string,
  replacementEnvelope: IssuerKeyEnvelope,
  existing: IssuanceRecord[],
): string[] {
  assertCanonicalSigningKeyId(compromisedKeyId, "compromised signing key id");
  assertCanonicalSigningKeyId(replacementEnvelope.signing_key_id, "replacement signing key id");
  if (replacementEnvelope.signing_key_id === compromisedKeyId ||
      replacementEnvelope.audience_key_id === replacementEnvelope.previous_key_id || replacementEnvelope.epoch < 2) {
    throw new Error("oidc-signing-key-unavailable: compromised key was not rotated before minting resumed");
  }
  for (const issuance of existing) validateIssuanceRecordOrThrow(issuance);
  return [...new Set(existing.filter(({ signing_key_id }) => signing_key_id === compromisedKeyId).map(({ jti }) => jti))].sort();
}

export function createStatusInvalidationRecords(input: {
  state: LedgerMergeResult;
  writer_nid: string;
  writer_secret_key: string;
  created_at: number;
  compromised_signing_key_ids: string[];
}): LedgerRecord[] {
  assertValidatedLedgerState(input.state);
  if (!deriveActiveIssuerNids(input.state, input.created_at).includes(input.writer_nid)) {
    throw new Error("oidc-issuer-authority-invalid: invalidation writer lacks active issuer authority");
  }
  const writerPublicKey = ed25519PublicKeyFromNid(input.writer_nid);
  if (!HEX_32.test(input.writer_secret_key) ||
      bytesToHex(ed25519.getPublicKey(hexToBytes(input.writer_secret_key))) !== bytesToHex(writerPublicKey)) {
    throw new Error("claim-event-signature-invalid: invalidation writer key does not match NID");
  }
  if (!Number.isSafeInteger(input.created_at) || input.created_at < input.state.checkpoint.observed_at) {
    throw new Error("claim-schema-invalid: invalid invalidation creation time");
  }
  const compromised = [...new Set(input.compromised_signing_key_ids)].sort();
  compromised.forEach((keyId) => assertCanonicalSigningKeyId(keyId, "compromised signing-key ID"));
  const authorityClaimId = canonicalIssuerAuthorityClaimId(input.writer_nid, input.state, input.created_at);
  const issuerEpochRecord = currentIssuerKeyEpochRecord(input.state);
  const issuerEpoch = issuerEpochRecord === null
    ? null
    : payloadObject(issuerEpochRecord.payload) as unknown as IssuerKeyEpochPayload;
  const activeIssuers = deriveActiveIssuerNids(input.state, input.created_at);
  if (authorityClaimId === null || issuerEpoch === null ||
      !issuerEpoch.recipient_nids.includes(input.writer_nid) ||
      jcsCanonicalize(issuerEpoch.recipient_nids) !== jcsCanonicalize(activeIssuers)) {
    throw new Error("oidc-signing-key-unavailable: invalidation creation requires the current canonical issuer-key epoch");
  }
  const authorityBinding = {
    writer_authority_claim_id: authorityClaimId,
    authority_checkpoint: { ...input.state.checkpoint },
    issuer_key_epoch: issuerEpoch.epoch,
    issuer_key_digest: issuerEpoch.key_digest,
  };
  const existingCauses = new Set(input.state.records
    .filter(({ record_type }) => record_type === "status-invalidation")
    .map(({ payload }) => invalidationCauseKey(payloadObject(payload))));
  const records: LedgerRecord[] = [];
  const confirmed = new Set(input.state.repository_confirmed_record_ids ?? []);
  const issuances = input.state.records
    .filter(({ record_type, record_id }) => record_type === "issuance-reservation" && confirmed.has(record_id))
    .filter(({ record_id }) => determineHistoricalTokenReturnability(record_id, input.state).allowed)
    .sort((left, right) => left.record_id.localeCompare(right.record_id));
  for (const issuanceRecord of issuances) {
    const issuance = payloadObject(issuanceRecord.payload) as unknown as IssuanceRecord;
    for (const sourceClaimId of [...issuance.source_claim_ids].sort()) {
      if (resolveAuthoritativeClaimState(sourceClaimId, input.state, input.created_at) !== "revoked") continue;
      const reduction = input.state.records
        .filter((record) => isReduction(record) && recordClaimId(record) === sourceClaimId && revocationArtifactFromRecord(record) !== null)
        .sort((left, right) => left.record_id.localeCompare(right.record_id))[0];
      if (reduction === undefined) continue;
      const payload = {
        cause: "source-claim-revoked",
        jti: issuance.jti,
        source_claim_id: sourceClaimId,
        revocation_artifact: revocationArtifactFromRecord(reduction)!,
        ...authorityBinding,
      } as unknown as JsonValue;
      const causeKey = invalidationCauseKey(payloadObject(payload));
      if (!existingCauses.has(causeKey)) {
        records.push(createSignedLedgerRecord({
          record_type: "status-invalidation",
          persona: input.state.credential_ledger.credential_ledger_persona,
          credential_ledger_generation: input.state.credential_ledger.credential_ledger_generation,
          writer_nid: input.writer_nid,
          created_at: input.created_at,
          parents: [issuanceRecord.record_id, reduction.record_id].sort(),
          payload,
        }, input.writer_secret_key));
        existingCauses.add(causeKey);
      }
    }
    if (compromised.includes(issuance.signing_key_id)) {
      const payload = {
        cause: "signing-key-compromised",
        jti: issuance.jti,
        signing_key_id: issuance.signing_key_id,
        compromise_evidence: {
          detected_at: input.created_at,
          evidence_digest: digestJson({
            domain: "heterodyne-oidc-signing-key-compromise-v1",
            signing_key_id: issuance.signing_key_id,
            checkpoint: input.state.checkpoint,
            detected_at: input.created_at,
          }),
        },
        ...authorityBinding,
      } as unknown as JsonValue;
      const causeKey = invalidationCauseKey(payloadObject(payload));
      if (!existingCauses.has(causeKey)) {
        records.push(createSignedLedgerRecord({
          record_type: "status-invalidation",
          persona: input.state.credential_ledger.credential_ledger_persona,
          credential_ledger_generation: input.state.credential_ledger.credential_ledger_generation,
          writer_nid: input.writer_nid,
          created_at: input.created_at,
          parents: [issuanceRecord.record_id],
          payload,
        }, input.writer_secret_key));
        existingCauses.add(causeKey);
      }
    }
  }
  return records.sort((left, right) => {
    const leftPayload = payloadObject(left.payload);
    const rightPayload = payloadObject(right.payload);
    return String(leftPayload.jti).localeCompare(String(rightPayload.jti)) ||
      String(leftPayload.cause).localeCompare(String(rightPayload.cause)) ||
      left.record_id.localeCompare(right.record_id);
  });
}

export function ledgerErrorReason(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  for (const code of [
    "credential_generation_missing",
    "credential_roster_empty",
    "credential_ledger_persona_mismatch",
    "credential_generation_stale",
    "credential_checkpoint_stale_kel",
    "credential_checkpoint_invalid",
    "credential_reset_invalid",
    "claim-ledger-rollback",
    "claim-ledger-writer-unauthorized",
    "claim-repository-conflict",
    "claim-repository-unconfirmed",
    "claim-ledger-reader-unauthorized",
    "claim-revoker-unauthorized",
    "claim-event-signature-invalid",
    "claim-id-mismatch",
    "claim-schema-invalid",
  ]) {
    if (message.includes(code)) return code;
  }
  return "claim-schema-invalid";
}

export function evaluateReaderAccess(
  readerNid: string | null,
  state: LedgerMergeResult,
  request?: ReaderAccessRequest,
): AuthorizationDecision {
  if (readerNid === null) return readerDenied("invalid", "claim-ledger-reader-unauthorized");
  try {
    ed25519PublicKeyFromNid(readerNid);
  } catch {
    return readerDenied("invalid", "claim-ledger-reader-unauthorized");
  }
  if (request === undefined) return readerDenied("invalid", "claim-ledger-reader-unauthorized");
  if (request.verification_context.now < state.checkpoint.observed_at) {
    return readerDenied("invalid", "claim-ledger-reader-unauthorized");
  }
  const record = state.records.find(({ record_id }) => record_id === request.claim_record_id);
  if (record === undefined ||
      record.credential_ledger_generation !== state.credential_ledger.credential_ledger_generation) {
    return readerDenied("provisional", "credential_generation_stale");
  }
  const artifact = claimArtifactFromRecord(record);
  if (artifact === null) return readerDenied("invalid", "claim-ledger-reader-unauthorized");
  let verifiedClaim: VerifiedClaimArtifact;
  let claim: ClaimSemanticBody;
  let chain: readonly VerifiedClaimArtifact[];
  try {
    verifiedClaim = verifyLedgerClaimArtifact(artifact, request.envelope_context);
    claim = inspectVerifiedClaim(verifiedClaim);
    chain = verifyClaimChain(
      verifiedClaim,
      request.claims_by_id as ReadonlyMap<string, VerifiedClaimArtifact>,
    );
  } catch {
    return readerDenied("invalid", "claim-event-signature-invalid");
  }
  if (
    claim.claim_class !== "authorization" ||
    claim.namespace !== "heterodyne.device" ||
    claim.name !== "claim-ledger-reader" ||
    claim.value !== true ||
    claim.visibility !== "repository-private" ||
    claim.subject.type !== "radicle-ed25519-nid" ||
    claim.subject.value !== readerNid ||
    request.verification_context.audience !== record.persona ||
    request.verification_context.resource !== `${state.checkpoint.repository_rid}#claim-ledger` ||
    request.verification_context.requested_namespace !== claim.namespace
  ) return readerDenied("invalid", "claim-ledger-reader-unauthorized");

  const futureApplicableReduction = state.records.some((candidate) =>
    isReduction(candidate) &&
    recordClaimId(candidate) === claim.claim_id &&
    candidate.created_at > request.verification_context.now
  );
  if (futureApplicableReduction) return readerDenied("invalid", "claim-ledger-reader-unauthorized");

  const repositoryConfirmed = confirmedClaimIds(state);
  const verification: ClaimVerificationContext = {
    ...request.verification_context,
    repository_confirmed: repositoryConfirmed,
    repository_conflicted: new Set(state.conflicted_claim_ids),
    revocations: authenticatedRevocationsFromRecords(state.records),
  };
  const decision = authorizeWithClaim(verifiedClaim, chain, verification);
  return {
    ...decision,
    reason_code: decision.state === "active"
      ? null
      : decision.reason_code ?? "claim-ledger-reader-unauthorized",
  };
}

export function resolveAuthoritativeClaimState(
  claimId: string,
  state: LedgerMergeResult,
  evaluationTime = state.checkpoint.observed_at,
): ClaimState {
  if (!HEX_32.test(claimId) || !Number.isSafeInteger(evaluationTime) || evaluationTime < state.checkpoint.observed_at) {
    return "invalid";
  }
  const allRelated = state.records.filter((record) =>
    recordClaimId(record) === claimId);
  const related = allRelated.filter((record) =>
    record.credential_ledger_generation ===
      state.credential_ledger.credential_ledger_generation);
  if (related.length === 0 && allRelated.length !== 0) return "invalid";
  if (related.some((record) => isReduction(record) && record.created_at > evaluationTime)) return "invalid";
  if (related.some(isReduction)) return "revoked";
  if (state.conflicted_claim_ids.includes(claimId)) return "conflicted";
  const claimRecords = related.filter((record) =>
    record.record_type === "claim" && claimArtifactFromRecord(record) !== null
  );
  if (claimRecords.length === 0) return "provisional";
  if (claimRecords.every(({ record_id }) => !(state.repository_confirmed_record_ids ?? []).includes(record_id))) {
    return "provisional";
  }
  const claims = claimRecords.map((record) => claimArtifactFromRecord(record)!.semantic);
  if (claims.some((claim) => evaluationTime < claim.not_before)) return "provisional";
  if (claims.some((claim) => claim.expires_at !== undefined && evaluationTime >= claim.expires_at)) {
    return "expired";
  }
  return "active";
}

export function resolveIssuerAuthorityState(
  writerNid: string,
  state: LedgerMergeResult,
  evaluationTime = state.checkpoint.observed_at,
): ClaimState {
  try {
    ed25519PublicKeyFromNid(writerNid);
  } catch {
    return "invalid";
  }
  const confirmed = new Set(state.repository_confirmed_record_ids ?? []);
  const candidateClaims = state.records.filter((record) => {
    if (record.record_type !== "claim" ||
        record.credential_ledger_generation !== state.credential_ledger.credential_ledger_generation ||
        !confirmed.has(record.record_id)) return false;
    const claim = claimArtifactFromRecord(record)?.semantic;
    return claim?.claim_class === "authorization" &&
      claim.namespace === "heterodyne.device" &&
      claim.name === "oidc-token-issuer" &&
      claim.value === true &&
      claim.visibility === "repository-private" &&
      claim.subject.type === "radicle-ed25519-nid" &&
      claim.subject.value === writerNid &&
      claim.audience?.includes(record.persona) === true &&
      claim.resources?.includes(`${state.checkpoint.repository_rid}#oidc-issuer`) === true;
  });
  const claimIds = [...new Set(candidateClaims.map((record) => claimArtifactFromRecord(record)!.semantic.claim_id))];
  if (claimIds.length !== 1) return claimIds.length === 0 ? "invalid" : "conflicted";
  const hasCanonicalGrant = state.records.some((record) => {
    if (record.record_type !== "issuer-authority" || !confirmed.has(record.record_id)) return false;
    const payload = payloadObject(record.payload);
    return payload.action === "grant" && payload.writer_nid === writerNid &&
      claimArtifactFromRecord(record)?.semantic.claim_id === claimIds[0];
  });
  return hasCanonicalGrant ? resolveAuthoritativeClaimState(claimIds[0], state, evaluationTime) : "invalid";
}

function canonicalIssuerAuthorityClaimId(
  writerNid: string,
  state: LedgerMergeResult,
  evaluationTime: number,
): string | null {
  if (resolveIssuerAuthorityState(writerNid, state, evaluationTime) !== "active") return null;
  const confirmed = new Set(state.repository_confirmed_record_ids ?? []);
  const claimIds = state.records
    .filter((record) =>
      record.record_type === "claim" &&
      record.credential_ledger_generation ===
        state.credential_ledger.credential_ledger_generation &&
      confirmed.has(record.record_id))
    .map(claimArtifactFromRecord)
    .filter((artifact): artifact is ClaimArtifact => artifact !== null)
    .map(({ semantic }) => semantic)
    .filter((claim) => claim.claim_class === "authorization" && claim.namespace === "heterodyne.device" &&
      claim.name === "oidc-token-issuer" && claim.value === true &&
      claim.visibility === "repository-private" && claim.subject.type === "radicle-ed25519-nid" &&
      claim.subject.value === writerNid && claim.audience?.includes(state.records[0]?.persona ?? "") === true &&
      claim.resources?.includes(`${state.checkpoint.repository_rid}#oidc-issuer`) === true)
    .map(({ claim_id }) => claim_id);
  const unique = [...new Set(claimIds)];
  return unique.length === 1 ? unique[0] : null;
}

export function deriveActiveIssuerNids(
  state: LedgerMergeResult,
  evaluationTime = state.checkpoint.observed_at,
): string[] {
  assertValidatedLedgerState(state);
  const candidates = new Set<string>();
  for (const record of state.records) {
    if (record.credential_ledger_generation !== state.credential_ledger.credential_ledger_generation) continue;
    const claim = claimArtifactFromRecord(record)?.semantic;
    if (claim?.claim_class === "authorization" && claim.namespace === "heterodyne.device" &&
        claim.name === "oidc-token-issuer" && claim.value === true &&
        claim.visibility === "repository-private" && claim.subject.type === "radicle-ed25519-nid") {
      candidates.add(claim.subject.value);
    }
  }
  return [...candidates]
    .filter((nid) => resolveIssuerAuthorityState(nid, state, evaluationTime) === "active")
    .sort();
}

export function evaluateMintingAttempt(input: {
  now: number;
  manifest_max_age_seconds: number;
  writer_nid: string;
  state: LedgerMergeResult;
  envelope: IssuerKeyEnvelope;
  audience_key: Uint8Array;
}): MintingAttemptDecision {
  assertValidatedLedgerState(input.state);
  const active_issuer_nids = deriveActiveIssuerNids(input.state, input.now);
  const authority_state = resolveIssuerAuthorityState(input.writer_nid, input.state, input.now);
  const generation = Object.prototype.hasOwnProperty.call(
    input.envelope,
    "credential_ledger_generation",
  )
    ? evaluateCredentialGeneration({
        credential_ledger_persona: input.envelope.persona,
        credential_ledger_generation: input.envelope.credential_ledger_generation,
      }, input.state.credential_ledger)
    : { valid: false as const, reason_code: "credential_generation_missing" as const };
  if (!generation.valid) {
    return {
      allowed: false,
      reason_code: generation.reason_code,
      checkpoint: { ...input.state.checkpoint },
      authority_state,
      active_issuer_nids,
      key_epoch: input.envelope.epoch,
      pending_rotation: true,
    };
  }
  const envelopeAuthorityIds = new Set(input.envelope.authority_record_ids);
  const confirmed = new Set(input.state.repository_confirmed_record_ids ?? []);
  const expectedAuthorityIds = issuerAuthorityRecordIds(input.state);
  const personaMatches = input.state.records.every(({ persona }) => persona === input.envelope.persona);
  const currentIssuerEpoch = currentIssuerKeyEpochRecord(input.state);
  const currentIssuerEpochPayload = currentIssuerEpoch === null
    ? null
    : payloadObject(currentIssuerEpoch.payload) as unknown as IssuerKeyEpochPayload;
  const issuerEpochBindingValid = currentIssuerEpochPayload !== null &&
    currentIssuerEpochPayload.epoch === input.envelope.epoch &&
    currentIssuerEpochPayload.envelope_digest === digestJson(input.envelope) &&
    currentIssuerEpochPayload.key_digest === input.envelope.signing_key_id &&
    jcsCanonicalize(currentIssuerEpochPayload.recipient_nids) ===
      jcsCanonicalize(input.envelope.recipient_wraps.map(({ writer_nid }) => writer_nid).sort());
  const hasIssuerRemoval = input.state.records.some((record) =>
    record.record_type === "issuer-authority" && payloadObject(record.payload).action === "remove");
  const epochChainValid = input.envelope.epoch === 1
    ? input.envelope.previous_key_id === GENESIS_AUDIENCE_KEY_ID && !hasIssuerRemoval
    : input.envelope.epoch > 1 && input.envelope.previous_key_id !== GENESIS_AUDIENCE_KEY_ID &&
      input.envelope.previous_key_id !== input.envelope.audience_key_id;
  const envelopeBindingValid = issuerEpochBindingValid && epochChainValid &&
    personaMatches &&
    input.envelope.persona === input.state.credential_ledger.credential_ledger_persona &&
    input.envelope.credential_ledger_generation ===
      input.state.credential_ledger.credential_ledger_generation &&
    input.envelope.repository_rid === input.state.checkpoint.repository_rid &&
    input.envelope.authority_record_set_digest === digestJson(input.envelope.authority_record_ids) &&
    jcsCanonicalize(input.envelope.authority_record_ids) === jcsCanonicalize(expectedAuthorityIds) &&
    input.envelope.authority_record_ids.every((recordId) => confirmed.has(recordId)) &&
    isCanonicalAncestorForState(input.state, input.envelope.checkpoint_commit_oid);
  const pendingRemoval = input.state.records.some((record) =>
    record.record_type === "issuer-authority" && payloadObject(record.payload).action === "remove" &&
    !envelopeAuthorityIds.has(record.record_id)
  );
  const envelopeRecipients = input.envelope.recipient_wraps.map(({ writer_nid }) => writer_nid).sort();
  const pending_rotation = !envelopeBindingValid || pendingRemoval ||
    jcsCanonicalize(envelopeRecipients) !== jcsCanonicalize(active_issuer_nids);
  let hasSigningKey = false;
  if (!pending_rotation) {
    try {
      unwrapIssuerSigningJwk(input.envelope, input.writer_nid, input.audience_key);
      hasSigningKey = true;
    } catch {
      hasSigningKey = false;
    }
  }
  const primitive = canMint(
    input.now,
    input.state.checkpoint,
    input.manifest_max_age_seconds,
    authority_state,
    hasSigningKey,
  );
  const decision = pending_rotation ? {
    allowed: false,
    reason_code: "oidc-signing-key-unavailable",
    checkpoint: { ...input.state.checkpoint },
  } : primitive;
  return {
    ...decision,
    authority_state,
    active_issuer_nids,
    key_epoch: input.envelope.epoch,
    pending_rotation,
  };
}

export function canReturnToken(
  recordId: string,
  state: LedgerMergeResult,
  envelope: IssuerKeyEnvelope,
  audienceKey: Uint8Array,
): AuthorizationDecision {
  try {
    assertValidatedLedgerState(state);
    const record = state.records.find((candidate) => candidate.record_id === recordId);
    if (record?.record_type !== "issuance-reservation" ||
        !(state.repository_confirmed_record_ids ?? []).includes(recordId)) {
      return { allowed: false, state: "provisional", reason_code: "claim-repository-unconfirmed" };
    }
    const issuance = payloadObject(record.payload) as unknown as IssuanceRecord;
    validateIssuanceRecordOrThrow(issuance, state.credential_ledger);
    if (record.credential_ledger_generation !== state.credential_ledger.credential_ledger_generation ||
        record.credential_ledger_generation !== issuance.credential_ledger_generation) {
      return { allowed: false, state: "invalid", reason_code: "credential_generation_stale" };
    }
    if (!isCanonicalAncestorForState(state, issuance.checkpoint.commit_oid)) {
      return { allowed: false, state: "invalid", reason_code: "claim-ledger-rollback" };
    }
    const confirmed = new Set(state.repository_confirmed_record_ids ?? []);
    for (const claimId of issuance.source_claim_ids) {
      const canonical = state.records.some((candidate) =>
        candidate.record_type === "claim" && confirmed.has(candidate.record_id) &&
        claimArtifactFromRecord(candidate)?.semantic.claim_id === claimId
      );
      if (!canonical) {
        return { allowed: false, state: "provisional", reason_code: "claim-repository-unconfirmed" };
      }
      const sourceState = resolveAuthoritativeClaimState(claimId, state, state.checkpoint.observed_at);
      if (sourceState === "revoked") {
        return { allowed: false, state: "revoked", reason_code: "claim-revoked" };
      }
      if (sourceState !== "active") {
        return { allowed: false, state: "provisional", reason_code: "claim-repository-unconfirmed" };
      }
    }
    if (resolveIssuerAuthorityState(record.writer_nid, state, state.checkpoint.observed_at) !== "active") {
      return { allowed: false, state: "invalid", reason_code: "oidc-issuer-authority-invalid" };
    }
    const mintBinding = evaluateMintingAttempt({
      now: state.checkpoint.observed_at,
      manifest_max_age_seconds: issuance.manifest_max_age_seconds,
      writer_nid: record.writer_nid,
      state,
      envelope,
      audience_key: audienceKey,
    });
    if (!mintBinding.allowed) {
      return { allowed: false, state: "invalid", reason_code: mintBinding.reason_code };
    }
    if (issuance.signing_key_id !== envelope.signing_key_id) {
      return { allowed: false, state: "invalid", reason_code: "oidc-signing-key-unavailable" };
    }
    return { allowed: true, state: "active", reason_code: null };
  } catch {
    return { allowed: false, state: "invalid", reason_code: "claim-repository-conflict" };
  }
}

export function determineHistoricalTokenReturnability(
  recordId: string,
  state: LedgerMergeResult,
): AuthorizationDecision {
  try {
    assertValidatedLedgerState(state);
    const record = state.records.find((candidate) => candidate.record_id === recordId);
    if (record?.record_type !== "issuance-reservation" ||
        !(state.repository_confirmed_record_ids ?? []).includes(recordId)) {
      return { allowed: false, state: "provisional", reason_code: "claim-repository-unconfirmed" };
    }
    const issuance = payloadObject(record.payload) as unknown as IssuanceRecord;
    validateIssuanceRecordOrThrow(issuance);
    const repository = validatedRepositoryForState(state);
    const commits = new Map(repository.commits.map((commit) => [commit.commit_oid, commit]));
    const firstCommit = uniqueCanonicalIntroductionCommit(repository, recordId);
    if (firstCommit === undefined ||
        !isCommitAncestor(issuance.checkpoint.commit_oid, firstCommit.commit_oid, commits)) {
      return { allowed: false, state: "invalid", reason_code: "claim-ledger-rollback" };
    }
    const firstRecordIds = new Set(firstCommit.record_ids);
    const historicalCheckpoint: LedgerCheckpoint = {
      repository_rid: repository.repository_rid,
      branch: "main",
      commit_oid: firstCommit.commit_oid,
      observed_at: issuance.issued_at,
    };
    const historical = ledgerSnapshotForRecordSet(
      state, firstRecordIds, issuance.issued_at, historicalCheckpoint,
    );
    if (resolveIssuerAuthorityState(record.writer_nid, historical, issuance.issued_at) !== "active") {
      return { allowed: false, state: "invalid", reason_code: "oidc-issuer-authority-invalid" };
    }
    const sourcesValid = issuance.source_claim_ids.every((claimId) => historical.records.some((candidate) =>
      candidate.record_type === "claim" &&
      claimArtifactFromRecord(candidate)?.semantic.claim_id === claimId) &&
      resolveAuthoritativeClaimState(claimId, historical, issuance.issued_at) === "active");
    if (!sourcesValid) {
      return { allowed: false, state: "invalid", reason_code: "claim-repository-unconfirmed" };
    }
    const preMintCommit = commits.get(issuance.checkpoint.commit_oid);
    const epochRecords = historical.records
      .filter(isIssuerKeyEpochRecord)
      .sort((left, right) => Number(payloadObject(right.payload).epoch) - Number(payloadObject(left.payload).epoch));
    const epochRecord = epochRecords[0];
    const epoch = epochRecord === undefined ? null : payloadObject(epochRecord.payload) as unknown as IssuerKeyEpochPayload;
    if (preMintCommit === undefined || epochRecord === undefined || epoch === null ||
        !preMintCommit.record_ids.includes(epochRecord.record_id) ||
        epoch.key_digest !== issuance.signing_key_id || !epoch.recipient_nids.includes(record.writer_nid) ||
        !isCommitAncestor(epoch.checkpoint.commit_oid, issuance.checkpoint.commit_oid, commits)) {
      return { allowed: false, state: "invalid", reason_code: "oidc-signing-key-unavailable" };
    }
    return { allowed: true, state: "active", reason_code: null };
  } catch {
    return { allowed: false, state: "invalid", reason_code: "claim-repository-conflict" };
  }
}

export function buildReaderOnboardingBundle(
  input: {
    reader_nid: string;
    request: ReaderAccessRequest;
    audience_key: Uint8Array;
    compact_state: JsonValue;
  },
  state: LedgerMergeResult,
): LedgerOnboardingBundle {
  const decision = evaluateReaderAccess(input.reader_nid, state, input.request);
  if (decision.state !== "active") {
    throw new Error(decision.reason_code ?? "claim-ledger-reader-unauthorized");
  }
  if (input.audience_key.length !== 32) throw new Error("ledger audience key must be exactly 32 bytes");
  const claimRecord = state.records.find(({ record_id }) => record_id === input.request.claim_record_id);
  const artifact = claimRecord === undefined ? null : claimArtifactFromRecord(claimRecord);
  if (artifact === null) throw new Error("claim-ledger-reader-unauthorized: onboarding authorization artifact is absent");
  verifyLedgerClaimArtifact(artifact, input.request.envelope_context);
  const verifiedEventId = artifact.event.id;
  const epochRecord = currentAudienceEpochRecord(state);
  if (epochRecord === null) throw new Error("claim-ledger-reader-unauthorized: current audience-key epoch is absent");
  const epoch = payloadObject(epochRecord.payload) as unknown as AudienceKeyEpochPayload;
  const keyDigest = bytesToHex(sha256(input.audience_key));
  const wrap = epoch.recipient_wraps.find(({ reader_nid }) => reader_nid === input.reader_nid);
  if (keyDigest !== epoch.key_digest || wrap === undefined || epoch.removed_reader_nids.includes(input.reader_nid)) {
    throw new Error("claim-ledger-reader-unauthorized: onboarding key or recipient wrap mismatch");
  }
  const compact_state_digest = digestJson(input.compact_state);
  const accessContext = {
    domain: "heterodyne-claim-ledger-radicle-access-v1",
    persona: claimRecord!.persona,
    reader_nid: input.reader_nid,
    repository_rid: state.checkpoint.repository_rid,
    checkpoint_commit_oid: state.checkpoint.commit_oid,
    epoch: epoch.epoch,
    key_digest: epoch.key_digest,
    compact_state_digest,
  };
  const withoutDigest: Omit<LedgerOnboardingBundle, "bundle_digest"> = {
    transport: "dr-self-dm",
    authorization: {
      claim_record_id: claimRecord!.record_id,
      event_id: verifiedEventId,
      claim_id: artifact.semantic.claim_id,
    },
    repository: { rid: state.checkpoint.repository_rid, branch: "main" },
    checkpoint: { ...state.checkpoint },
    key_epoch: { epoch: epoch.epoch, key_id: epoch.key_id, key_digest: epoch.key_digest, recipient_wrap: wrap.wrapped_key },
    audience_key: bytesToHex(input.audience_key),
    compact_state: structuredClone(input.compact_state),
    compact_state_digest,
    radicle_access: { nid: input.reader_nid, role: "fetch-and-seed", context_digest: digestJson(accessContext) },
  };
  return { ...withoutDigest, bundle_digest: onboardingBundleMac(input.audience_key, withoutDigest) };
}

export function validateReaderOnboardingBundle(
  bundle: LedgerOnboardingBundle,
  state: LedgerMergeResult,
  request?: ReaderAccessRequest,
): void {
  if (request === undefined ||
      evaluateReaderAccess(bundle.radicle_access.nid, state, request).state !== "active") {
    throw new Error("claim-ledger-reader-unauthorized: onboarding authorization failed replay");
  }
  const { bundle_digest, ...withoutDigest } = bundle;
  let audienceKey: Uint8Array;
  try {
    audienceKey = hexToBytes(bundle.audience_key);
  } catch {
    throw new Error("claim-ledger-reader-unauthorized: invalid onboarding audience key encoding");
  }
  const epochRecord = currentAudienceEpochRecord(state);
  const epoch = epochRecord === null ? null : payloadObject(epochRecord.payload) as unknown as AudienceKeyEpochPayload;
  const compactDigest = digestJson(bundle.compact_state);
  const accessContext = epoch === null ? null : {
    domain: "heterodyne-claim-ledger-radicle-access-v1",
    persona: state.records.find(({ record_id }) => record_id === bundle.authorization.claim_record_id)?.persona,
    reader_nid: bundle.radicle_access.nid,
    repository_rid: bundle.repository.rid,
    checkpoint_commit_oid: bundle.checkpoint.commit_oid,
    epoch: bundle.key_epoch.epoch,
    key_digest: bundle.key_epoch.key_digest,
    compact_state_digest: compactDigest,
  };
  const authorizationRecord = state.records.find(({ record_id }) => record_id === bundle.authorization.claim_record_id);
  const authorizationArtifact = authorizationRecord === undefined ? null : claimArtifactFromRecord(authorizationRecord);
  if (bundle.transport !== "dr-self-dm" || bundle.bundle_digest !== onboardingBundleMac(audienceKey, withoutDigest) ||
      bundle.repository.rid !== state.checkpoint.repository_rid || bundle.repository.branch !== "main" ||
      jcsCanonicalize(bundle.checkpoint) !== jcsCanonicalize(state.checkpoint) || epoch === null ||
      bundle.key_epoch.epoch !== epoch.epoch || bundle.key_epoch.key_id !== epoch.key_id ||
      bundle.key_epoch.key_digest !== epoch.key_digest || bytesToHex(sha256(hexToBytes(bundle.audience_key))) !== epoch.key_digest ||
      !epoch.recipient_wraps.some(({ reader_nid, wrapped_key }) => reader_nid === bundle.radicle_access.nid && wrapped_key === bundle.key_epoch.recipient_wrap) ||
      bundle.compact_state_digest !== compactDigest || bundle.radicle_access.role !== "fetch-and-seed" ||
      accessContext === null || bundle.radicle_access.context_digest !== digestJson(accessContext) ||
      bundle.authorization.claim_record_id !== request.claim_record_id || authorizationArtifact === null ||
      bundle.authorization.event_id !== authorizationArtifact.event.id ||
      bundle.authorization.claim_id !== authorizationArtifact.semantic.claim_id ||
      authorizationArtifact.semantic.subject.type !== "radicle-ed25519-nid" ||
      authorizationArtifact.semantic.subject.value !== bundle.radicle_access.nid) {
    throw new Error("claim-ledger-reader-unauthorized: invalid reader onboarding bundle binding");
  }
}

function onboardingBundleMac(
  audienceKey: Uint8Array,
  bundle: Omit<LedgerOnboardingBundle, "bundle_digest">,
): string {
  if (audienceKey.length !== 32) throw new Error("claim-ledger-reader-unauthorized: invalid onboarding audience key");
  return createHmac("sha256", audienceKey)
    .update("heterodyne-claim-ledger-onboarding-mac-v1\0", "utf8")
    .update(utf8Bytes(jcsCanonicalize(bundle)))
    .digest("hex");
}

function recordSigningPayload(record: Pick<
  LedgerRecord,
  "record_type" | "persona" | "credential_ledger_generation" | "writer_nid" | "created_at" | "parents" | "payload" | "payload_digest"
>): string {
  return jcsCanonicalize({
    domain: "heterodyne-claim-ledger-record-v1",
    record_type: record.record_type,
    persona: record.persona,
    credential_ledger_generation: record.credential_ledger_generation,
    writer_nid: record.writer_nid,
    created_at: record.created_at,
    parents: record.parents,
    payload: record.payload,
    payload_digest: record.payload_digest,
  });
}

function withoutRecordId(record: LedgerRecord): Omit<LedgerRecord, "record_id"> {
  const { record_id: _recordId, ...withoutId } = record;
  return withoutId;
}

function digestJson(value: unknown): string {
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize(value))));
}

function domainSeparatedDigestJson(domain: string, value: unknown): string {
  return bytesToHex(sha256(Uint8Array.from([
    ...utf8Bytes(domain),
    0,
    ...utf8Bytes(jcsCanonicalize(value)),
  ])));
}

function replayValidationFingerprint(value: unknown): string {
  return digestJson(replayFingerprintValue(value));
}

function replayFingerprintValue(value: unknown): JsonValue {
  if (value === undefined) return ["undefined"];
  if (value === null) return ["null"];
  if (typeof value === "boolean") return ["boolean", value];
  if (typeof value === "number") return ["number", value];
  if (typeof value === "string") return ["string", value];
  if (value instanceof Uint8Array) return ["bytes", bytesToHex(value)];
  if (Array.isArray(value)) return ["array", ...value.map(replayFingerprintValue)];
  if (value instanceof Map) {
    const entries = [...value.entries()].map(([key, entryValue]) => [
      replayFingerprintValue(key), replayFingerprintValue(entryValue),
    ] as JsonValue[]);
    entries.sort((left, right) => jcsCanonicalize(left[0]).localeCompare(jcsCanonicalize(right[0])));
    return ["map", ...entries];
  }
  if (value instanceof Set) {
    const entries = [...value].map(replayFingerprintValue)
      .sort((left, right) => jcsCanonicalize(left).localeCompare(jcsCanonicalize(right)));
    return ["set", ...entries];
  }
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return ["object", ...Object.keys(object).sort().map((key) => [key, replayFingerprintValue(object[key])])];
  }
  throw new Error("claim-schema-invalid: unsupported replay validation context value");
}

function ed25519PublicKeyFromNid(nid: string): Uint8Array {
  if (!nid.startsWith("did:key:z")) throw new Error("claim-key-reference-invalid: invalid writer NID");
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(nid.slice("did:key:z".length));
  } catch {
    throw new Error("claim-key-reference-invalid: invalid writer NID base58");
  }
  if (decoded.length !== 34 || decoded[0] !== ED25519_PREFIX[0] || decoded[1] !== ED25519_PREFIX[1]) {
    throw new Error("claim-key-reference-invalid: writer NID is not canonical Ed25519 did:key");
  }
  const publicKey = decoded.slice(2);
  if (base58.encode(decoded) !== nid.slice("did:key:z".length)) {
    throw new Error("claim-key-reference-invalid: writer NID is not canonical base58btc");
  }
  validateKeyRef({ type: "radicle-ed25519-nid", value: nid });
  return publicKey;
}

function validateCheckpoint(
  checkpoint: LedgerCheckpoint,
): void {
  assertPlainObject(checkpoint, "checkpoint");
  assertExactKeys(checkpoint, ["repository_rid", "branch", "commit_oid", "observed_at"], "checkpoint");
  if (!RID.test(checkpoint.repository_rid)) throw new Error("claim-schema-invalid: invalid repository RID");
  if (checkpoint.branch !== "main") throw new Error("claim-ledger-rollback: only canonical main is authoritative");
  if (!COMMIT_OID.test(checkpoint.commit_oid)) throw new Error("claim-schema-invalid: invalid canonical commit OID");
  if (!Number.isSafeInteger(checkpoint.observed_at) || checkpoint.observed_at < 0) {
    throw new Error("claim-schema-invalid: invalid checkpoint observation time");
  }
}

function validateRepositoryEvidence(
  checkpoint: LedgerCheckpoint,
  recordsById: ReadonlyMap<string, LedgerRecord>,
  repository: LedgerRepositoryEvidence,
): void {
  validateCheckpoint(checkpoint);
  if (repository.repository_rid !== checkpoint.repository_rid || repository.branch !== "main" ||
      repository.canonical_head !== checkpoint.commit_oid ||
      jcsCanonicalize(repository.checkpoint) !== jcsCanonicalize(checkpoint)) {
    throw new Error("claim-ledger-rollback: checkpoint is not bound to canonical repository evidence");
  }
  const commits = new Map<string, LedgerRepositoryCommit>();
  for (const commit of repository.commits) {
    const recordIds = [...commit.record_ids].sort();
    if (new Set(recordIds).size !== recordIds.length || recordIds.some((id) => !HEX_32.test(id))) {
      throw new Error("claim-ledger-rollback: invalid canonical record set");
    }
    const expectedRecordSetDigest = digestJson(recordIds);
    const expectedTree = digestJson({
      domain: "heterodyne-claim-ledger-tree-v1",
      record_ids: recordIds,
      record_set_digest: expectedRecordSetDigest,
    });
    const expectedCommit = digestJson({
      domain: "heterodyne-claim-ledger-commit-v1",
      repository_rid: repository.repository_rid,
      branch: "main",
      tree_oid: expectedTree,
      parents: commit.parents,
      record_set_digest: expectedRecordSetDigest,
    });
    if (commit.record_set_digest !== expectedRecordSetDigest || commit.tree_oid !== expectedTree ||
        commit.commit_oid !== expectedCommit || commits.has(commit.commit_oid) ||
        commit.parents.some((parent) => !commits.has(parent))) {
      throw new Error("claim-ledger-rollback: canonical commit/tree/record-set digest mismatch");
    }
    for (const parentId of commit.parents) {
      const parent = commits.get(parentId)!;
      if (parent.record_ids.some((id) => !recordIds.includes(id))) {
        throw new Error("claim-ledger-rollback: append-only record disappeared from canonical history");
      }
    }
    commits.set(commit.commit_oid, commit);
  }
  const head = commits.get(repository.canonical_head);
  if (head === undefined ||
      jcsCanonicalize([...repository.repository_confirmed_record_ids].sort()) !== jcsCanonicalize(head.record_ids)) {
    throw new Error("claim-ledger-rollback: canonical head does not bind the confirmed record IDs");
  }
  const newestConfirmedRecord = head.record_ids.reduce(
    (latest, id) => Math.max(latest, recordsById.get(id)?.created_at ?? 0),
    0,
  );
  if (checkpoint.observed_at < newestConfirmedRecord) {
    throw new Error("claim-ledger-rollback: stale checkpoint predates canonical ledger records");
  }
  for (const id of head.record_ids) {
    const record = recordsById.get(id);
    if (record === undefined) throw new Error("claim-repository-unconfirmed: canonical tree names an absent record");
    if (record.parents.some((parent) => !head.record_ids.includes(parent))) {
      throw new Error("claim-repository-unconfirmed: confirmed record parent is not canonically reachable");
    }
  }
  if (repository.genesis) {
    if (repository.prior_checkpoint !== null || head.parents.length !== 0 || repository.commits.length !== 1) {
      throw new Error("claim-ledger-rollback: invalid explicit genesis evidence");
    }
  } else {
    const prior = repository.prior_checkpoint;
    if (prior === null || prior.repository_rid !== checkpoint.repository_rid || prior.branch !== "main" ||
        checkpoint.observed_at < prior.observed_at || !isCommitAncestor(prior.commit_oid, head.commit_oid, commits)) {
      throw new Error("claim-ledger-rollback: prior finalized checkpoint is not an ancestor");
    }
  }
}

function isCommitAncestor(
  ancestor: string,
  descendant: string,
  commits: ReadonlyMap<string, LedgerRepositoryCommit>,
): boolean {
  const pending = [descendant];
  const seen = new Set<string>();
  while (pending.length > 0) {
    const current = pending.pop()!;
    if (current === ancestor) return true;
    if (seen.has(current)) continue;
    seen.add(current);
    pending.push(...(commits.get(current)?.parents ?? []));
  }
  return false;
}

function canonicalAncestorCommits(repository: LedgerRepositoryEvidence): LedgerRepositoryCommit[] {
  const commits = new Map(repository.commits.map((commit) => [commit.commit_oid, commit]));
  return repository.commits.filter((commit) =>
    isCommitAncestor(commit.commit_oid, repository.canonical_head, commits));
}

function uniqueCanonicalIntroductionCommit(
  repository: LedgerRepositoryEvidence,
  recordId: string,
): LedgerRepositoryCommit | undefined {
  const commits = new Map(repository.commits.map((commit) => [commit.commit_oid, commit]));
  const containing = canonicalAncestorCommits(repository)
    .filter((commit) => commit.record_ids.includes(recordId));
  const minimal = containing.filter((candidate) => !containing.some((other) =>
    other.commit_oid !== candidate.commit_oid &&
    isCommitAncestor(other.commit_oid, candidate.commit_oid, commits)
  ));
  if (minimal.length > 1) {
    throw new Error("claim-repository-conflict: record has ambiguous canonical introduction commits");
  }
  return minimal[0];
}

function validatePayload(type: LedgerRecordType, value: JsonValue): void {
  const payload = payloadObject(value);
  switch (type) {
    case "claim":
      assertExactKeys(payload, ["claim_artifact"], "claim payload");
      return;
    case "revocation":
      assertExactKeys(payload, ["revocation_artifact"], "revocation payload");
      return;
    case "authority-reduction":
      assertExactKeys(payload, ["role", "subject_nid", "revocation_artifact"], "authority reduction payload");
      ed25519PublicKeyFromNid(String(payload.subject_nid));
      if (!["claim-ledger-reader", "oidc-token-issuer"].includes(String(payload.role))) {
        throw new Error("claim-schema-invalid: invalid authority reduction payload");
      }
      return;
    case "reader-change": {
      const action = payload.action;
      assertExactKeys(payload, action === "grant" ? ["action", "reader_nid", "claim_artifact"] : ["action", "reader_nid", "revocation_artifact"], "reader change payload");
      ed25519PublicKeyFromNid(String(payload.reader_nid));
      if (action !== "grant" && action !== "remove") throw new Error("claim-schema-invalid: invalid reader action");
      return;
    }
    case "audience-key-epoch":
      if (payload.scope === "oidc-issuer-key") {
        assertExactKeys(payload, [
          "scope", "epoch", "envelope_digest", "key_digest", "previous_epoch",
          "previous_envelope_digest", "previous_key_digest", "recipient_nids", "checkpoint",
        ], "issuer key epoch payload");
        if (!Number.isSafeInteger(payload.epoch) || Number(payload.epoch) < 1 ||
            !Number.isSafeInteger(payload.previous_epoch) || Number(payload.previous_epoch) < 0) {
          throw new Error("claim-schema-invalid: invalid issuer key epoch");
        }
        assertClaimId(payload.envelope_digest);
        assertCanonicalSigningKeyId(payload.key_digest, "issuer key epoch key_digest");
        assertClaimId(payload.previous_envelope_digest);
        if (payload.previous_key_digest !== GENESIS_AUDIENCE_KEY_ID) {
          assertCanonicalSigningKeyId(payload.previous_key_digest, "issuer key epoch previous_key_digest");
        }
        validateNidSet(payload.recipient_nids);
        validateCheckpoint(payload.checkpoint as unknown as LedgerCheckpoint);
        return;
      }
      assertExactKeys(payload, ["epoch", "key_id", "key_digest", "previous_epoch", "previous_key_id", "reader_nids", "removed_reader_nids", "recipient_wraps", "radicle_access_removed", "checkpoint_commit_oid", "retire_previous_state", "scrub_profile"], "audience key epoch payload");
      if (!Number.isSafeInteger(payload.epoch) || !Number.isSafeInteger(payload.previous_epoch) ||
          !/^[A-Za-z0-9._-]{1,128}$/.test(String(payload.key_id)) || payload.retire_previous_state !== true ||
          payload.scrub_profile !== "comms-encrypted-branch-cooperative-v1") {
        throw new Error("claim-schema-invalid: invalid audience key epoch");
      }
      validateNidSet(payload.reader_nids);
      validateNidSet(payload.removed_reader_nids);
      validateNidSet(payload.radicle_access_removed);
      return;
    case "issuer-authority": {
      const action = payload.action;
      assertExactKeys(payload, action === "grant" ? ["action", "writer_nid", "claim_artifact"] : ["action", "writer_nid", "revocation_artifact"], "issuer authority payload");
      ed25519PublicKeyFromNid(String(payload.writer_nid));
      if (action !== "grant" && action !== "remove") throw new Error("claim-schema-invalid: invalid issuer action");
      return;
    }
    case "issuance-reservation":
      validateIssuanceRecordOrThrow(payload as unknown as IssuanceRecord);
      return;
    case "status-invalidation":
      if (!/^[A-Za-z0-9_-]{16,128}$/.test(String(payload.jti))) throw new Error("claim-schema-invalid: invalid jti");
      assertClaimId(payload.writer_authority_claim_id);
      validateCheckpoint(payload.authority_checkpoint as unknown as LedgerCheckpoint);
      if (!Number.isSafeInteger(payload.issuer_key_epoch) || Number(payload.issuer_key_epoch) < 1) {
        throw new Error("claim-schema-invalid: invalid invalidation issuer-key epoch");
      }
      assertCanonicalSigningKeyId(payload.issuer_key_digest, "issuer_key_digest");
      if (payload.cause === "source-claim-revoked") {
        assertExactKeys(payload, [
          "cause", "jti", "source_claim_id", "revocation_artifact", "writer_authority_claim_id",
          "authority_checkpoint", "issuer_key_epoch", "issuer_key_digest",
        ], "source invalidation payload");
        assertClaimId(payload.source_claim_id);
      } else if (payload.cause === "signing-key-compromised") {
        assertExactKeys(payload, [
          "cause", "jti", "signing_key_id", "compromise_evidence", "writer_authority_claim_id",
          "authority_checkpoint", "issuer_key_epoch", "issuer_key_digest",
        ], "key invalidation payload");
        assertCanonicalSigningKeyId(payload.signing_key_id);
        const compromise = payloadObject(payload.compromise_evidence);
        assertExactKeys(compromise, ["detected_at", "evidence_digest"], "key compromise evidence");
        if (!Number.isSafeInteger(compromise.detected_at)) throw new Error("claim-schema-invalid: invalid compromise time");
        assertClaimId(compromise.evidence_digest);
      } else {
        throw new Error("claim-schema-invalid: invalid status-invalidation cause");
      }
      return;
  }
}

function validateAuthenticatedArtifact(
  record: LedgerRecord,
  recordsById: ReadonlyMap<string, LedgerRecord>,
  evidence: LedgerRecordValidationEvidence,
): void {
  const claimArtifact = claimArtifactFromRecord(record);
  if (claimArtifact === null && claimArtifactValueFromRecord(record) !== undefined) {
    throw new Error("claim-event-signature-invalid: invalid signed claim artifact event");
  }
  if (claimArtifact !== null) {
    if (evidence.claim_envelope_context === undefined || evidence.claims_by_id === undefined) {
      throw new Error("claim-issuer-authority-invalid: signed claim validation context is required");
    }
    const verifiedClaim = verifyLedgerClaimArtifact(claimArtifact, evidence.claim_envelope_context);
    const parsed = inspectVerifiedClaim(verifiedClaim);
    if (parsed.claim_class === "authorization" &&
        (parsed.credential_ledger_persona !== record.persona ||
         parsed.credential_ledger_generation !== record.credential_ledger_generation)) {
      throw new Error(parsed.credential_ledger_persona !== record.persona
        ? "credential_ledger_persona_mismatch"
        : "credential_generation_stale");
    }
    const chain = verifyClaimChain(
      verifiedClaim,
      evidence.claims_by_id as ReadonlyMap<string, VerifiedClaimArtifact>,
    );
    if (evidence.claim_verification_context !== undefined) {
      const decision = authorizeWithClaim(verifiedClaim, chain, evidence.claim_verification_context);
      if (decision.state === "invalid") throw new Error(decision.reason_code ?? "claim-issuer-authority-invalid");
    }
  }

  const revocationArtifact = revocationArtifactFromRecord(record);
  if (revocationArtifact === null && revocationArtifactValueFromRecord(record) !== undefined) {
    throw new Error("claim-event-signature-invalid: invalid signed revocation artifact event");
  }
  if (revocationArtifact === null) return;
  if (evidence.claims_by_id === undefined || evidence.claim_verification_context === undefined) {
    throw new Error("claim-revoker-unauthorized: revocation validation context is required");
  }
  const verifiedArtifact = verifyLedgerClaimRevocationArtifact(revocationArtifact);
  const verified = inspectVerifiedClaimRevocation(verifiedArtifact);
  const target = Map.prototype.get.call(evidence.claims_by_id, verified.claim_id) as
    | VerifiedClaimArtifact
    | undefined;
  if (target === undefined) throw new Error("claim-revoker-unauthorized: revocation target claim is absent");
  const chain = verifyClaimChain(
    target,
    evidence.claims_by_id as ReadonlyMap<string, VerifiedClaimArtifact>,
  );
  if (!isClaimRevocationAuthorized(
    target,
    chain,
    verifiedArtifact,
    evidence.claim_verification_context,
  )) {
    throw new Error("claim-revoker-unauthorized: Task 3 did not authenticate this revocation effect");
  }
  const targetSemantic = inspectVerifiedClaim(target);
  const payload = payloadObject(record.payload);
  if (record.record_type === "authority-reduction") {
    if (targetSemantic.subject.type !== "radicle-ed25519-nid" || targetSemantic.subject.value !== payload.subject_nid ||
        targetSemantic.name !== payload.role) {
      throw new Error("claim-revoker-unauthorized: authority reduction target, subject, or role mismatch");
    }
  }
  if (record.record_type === "reader-change" && payload.action === "remove") {
    if (targetSemantic.subject.type !== "radicle-ed25519-nid" || targetSemantic.subject.value !== payload.reader_nid ||
        targetSemantic.name !== "claim-ledger-reader") {
      throw new Error("claim-revoker-unauthorized: reader removal is not bound to the reader claim");
    }
  }
  if (record.record_type === "issuer-authority" && payload.action === "remove") {
    if (targetSemantic.subject.type !== "radicle-ed25519-nid" || targetSemantic.subject.value !== payload.writer_nid ||
        targetSemantic.name !== "oidc-token-issuer") {
      throw new Error("claim-revoker-unauthorized: issuer removal is not bound to the issuer claim");
    }
  }
  if (record.record_type === "status-invalidation" && payload.cause === "source-claim-revoked" && payload.source_claim_id !== verified.claim_id) {
    throw new Error("claim-revoker-unauthorized: token invalidation source claim mismatch");
  }
  // recordsById is intentionally consulted through target artifacts so an
  // external bare semantic body cannot be the sole authority source.
  if (![...recordsById.values()].some((candidate) =>
    claimArtifactFromRecord(candidate)?.semantic.claim_id === verified.claim_id
  )) throw new Error("claim-repository-unconfirmed: revocation target has no signed ledger artifact");
}

function claimArtifactFromRecord(record: LedgerRecord): ClaimArtifact | null {
  const value = claimArtifactValueFromRecord(record);
  if (value === undefined) return null;
  const artifact = payloadObject(value);
  return {
    event: artifact.event as unknown as NostrSignedEvent,
    semantic: artifact.semantic as unknown as ClaimSemanticBody,
  };
}

function claimArtifactValueFromRecord(record: LedgerRecord): JsonValue | undefined {
  const payload = payloadObject(record.payload);
  return record.record_type === "claim" ? payload.claim_artifact :
    ((record.record_type === "reader-change" || record.record_type === "issuer-authority")
      && payload.action === "grant") ? payload.claim_artifact : undefined;
}

function revocationArtifactFromRecord(record: LedgerRecord): RevocationArtifact | null {
  const value = revocationArtifactValueFromRecord(record);
  if (value === undefined) return null;
  const artifact = payloadObject(value);
  return {
    event: artifact.event as unknown as NostrSignedEvent,
    semantic: artifact.semantic as JsonValue,
  };
}

function revocationArtifactValueFromRecord(record: LedgerRecord): JsonValue | undefined {
  const payload = payloadObject(record.payload);
  return record.record_type === "revocation" || record.record_type === "authority-reduction" ||
    (record.record_type === "status-invalidation" && payload.cause === "source-claim-revoked") ||
    ((record.record_type === "reader-change" || record.record_type === "issuer-authority")
      && payload.action === "remove")
    ? payload.revocation_artifact : undefined;
}

function authenticatedRevocationsFromRecords(
  records: readonly LedgerRecord[],
): VerifiedClaimRevocationArtifact[] {
  return records
    .filter((record) => isReduction(record))
    .map(revocationArtifactFromRecord)
    .filter((artifact): artifact is RevocationArtifact => artifact !== null)
    .map((artifact) => verifyLedgerClaimRevocationArtifact(artifact));
}

function findConflictedClaims(records: LedgerRecord[]): string[] {
  const widenings = new Map<string, Map<string, string[]>>();
  for (const record of records) {
    if (isReduction(record)) continue;
    const payload = payloadObject(record.payload);
    const artifact = claimArtifactFromRecord(record);
    if (artifact === null) continue;
    const key = record.record_type === "reader-change" ? `reader:${String(payload.reader_nid)}` :
      record.record_type === "issuer-authority" ? `issuer:${String(payload.writer_nid)}` :
      `claim:${artifact.semantic.claim_id}`;
    const variants = widenings.get(key) ?? new Map<string, string[]>();
    const semantic = jcsCanonicalize(artifact.semantic);
    variants.set(semantic, [...(variants.get(semantic) ?? []), artifact.semantic.claim_id]);
    widenings.set(key, variants);
  }
  return [...new Set(
    [...widenings.values()]
      .filter((variants) => variants.size > 1)
      .flatMap((variants) => [...variants.values()].flat()),
  )].sort();
}

function recordClaimId(record: LedgerRecord): string | null {
  const payload = payloadObject(record.payload);
  const claim = claimArtifactFromRecord(record);
  if (claim !== null) return claim.semantic.claim_id;
  const revocation = revocationArtifactFromRecord(record);
  if (revocation !== null) {
    const semantic = payloadObject(revocation.semantic);
    return typeof semantic.claim_id === "string" ? semantic.claim_id : null;
  }
  return typeof payload.source_claim_id === "string" ? payload.source_claim_id : null;
}

function isReduction(record: LedgerRecord): boolean {
  const payload = payloadObject(record.payload);
  return record.record_type === "revocation" || record.record_type === "authority-reduction" ||
    (record.record_type === "reader-change" && payload.action === "remove") ||
    (record.record_type === "issuer-authority" && payload.action === "remove");
}

function assertAcyclic(recordsById: ReadonlyMap<string, LedgerRecord>): void {
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (id: string): void => {
    if (visiting.has(id)) throw new Error("claim-repository-conflict: ledger parent cycle");
    if (visited.has(id)) return;
    visiting.add(id);
    for (const parent of recordsById.get(id)?.parents ?? []) visit(parent);
    visiting.delete(id);
    visited.add(id);
  };
  for (const id of recordsById.keys()) visit(id);
}

function validateLedgerStateInvariants(
  recordsById: ReadonlyMap<string, LedgerRecord>,
  context: LedgerValidationContext,
): void {
  const records = [...recordsById.values()];
  const issuanceRecords = records
    .filter(({ record_type }) => record_type === "issuance-reservation")
    .map((record) => ({ record, issuance: payloadObject(record.payload) as unknown as IssuanceRecord }));
  const seenJtis = new Set<string>();
  const seenAllocations = new Set<string>();
  const indexesByUri = new Map<string, number[]>();
  for (const { record, issuance } of issuanceRecords) {
    validateIssuanceRecordOrThrow(issuance);
    if (record.credential_ledger_generation !== issuance.credential_ledger_generation) {
      throw new Error("credential_generation_stale: issuance payload does not match its ledger record");
    }
    if (seenJtis.has(issuance.jti)) throw new Error("claim-repository-conflict: duplicate issuance jti");
    seenJtis.add(issuance.jti);
    const allocation = `${issuance.reservation.uri}\0${issuance.reservation.idx}`;
    if (seenAllocations.has(allocation)) throw new Error("claim-repository-conflict: duplicate status tuple/index reservation");
    seenAllocations.add(allocation);
    indexesByUri.set(issuance.reservation.uri, [...(indexesByUri.get(issuance.reservation.uri) ?? []), issuance.reservation.idx]);
    const expectedFingerprint = bytesToHex(sha256(utf8Bytes(record.writer_nid))).slice(0, 32);
    if (issuance.reservation.writer_nid_fingerprint !== expectedFingerprint ||
        !context.repository.commits.some(({ commit_oid }) => commit_oid === issuance.checkpoint.commit_oid) ||
        issuance.checkpoint.repository_rid !== context.repository.repository_rid ||
        issuance.checkpoint.observed_at > issuance.issued_at || record.created_at < issuance.issued_at ||
        issuance.source_claim_ids.some((claimId) => !records.some((candidate) =>
          claimArtifactFromRecord(candidate)?.semantic.claim_id === claimId))) {
      throw new Error("claim-repository-conflict: issuance record is not durably bound to writer, checkpoint, signing key, and sources");
    }
  }
  for (const indexes of indexesByUri.values()) {
    indexes.sort((left, right) => left - right).forEach((idx, position) => {
      if (idx !== position) throw new Error("claim-repository-conflict: status indexes are not a monotonic allocation prefix");
    });
  }
  for (const invalidationRecord of records.filter(({ record_type }) => record_type === "status-invalidation")) {
    const invalidation = payloadObject(invalidationRecord.payload);
    const issuance = issuanceRecords.find(({ issuance: candidate }) => candidate.jti === invalidation.jti)?.issuance;
    const bound = issuance !== undefined && (invalidation.cause === "source-claim-revoked"
      ? issuance.source_claim_ids.includes(String(invalidation.source_claim_id))
      : issuance.signing_key_id === invalidation.signing_key_id);
    if (!bound) {
      throw new Error("claim-repository-conflict: token invalidation is not bound to its durable issuance and cause");
    }
  }
  const stateForReaders: LedgerMergeResult = {
    credential_ledger: { ...context.credential_ledger },
    records,
    conflicted_claim_ids: findConflictedClaims(records),
    checkpoint: context.repository.checkpoint,
    repository_confirmed_record_ids: [...context.repository.repository_confirmed_record_ids],
    delivered_record_ids: records.map(({ record_id }) => record_id)
      .filter((id) => !context.repository.repository_confirmed_record_ids.includes(id)),
    authenticated_revocations: records
      .filter((record) => isReduction(record))
      .map(revocationArtifactFromRecord)
      .filter((artifact): artifact is RevocationArtifact => artifact !== null)
      .map((artifact) => verifyLedgerClaimRevocationArtifact(artifact)),
    token_invalidations: [],
  };
  for (const invalidationRecord of records.filter(({ record_type }) => record_type === "status-invalidation")) {
    validateHistoricalInvalidationAuthority(invalidationRecord, stateForReaders, context.repository);
  }
  const issuerEpochRecords = records
    .filter(isIssuerKeyEpochRecord)
    .sort((left, right) => Number(payloadObject(left.payload).epoch) - Number(payloadObject(right.payload).epoch));
  const issuerEpochs = new Map<number, LedgerRecord>();
  const repositoryCommits = new Map(context.repository.commits.map((commit) => [commit.commit_oid, commit]));
  for (const record of issuerEpochRecords) {
    const payload = payloadObject(record.payload) as unknown as IssuerKeyEpochPayload;
    if (issuerEpochs.has(payload.epoch)) {
      throw new Error("claim-repository-conflict: divergent canonical issuer-key epoch");
    }
    const checkpointCommit = repositoryCommits.get(payload.checkpoint.commit_oid);
    if (checkpointCommit === undefined || payload.checkpoint.repository_rid !== context.repository.repository_rid ||
        payload.checkpoint.branch !== "main" || payload.checkpoint.observed_at > record.created_at ||
        !isCommitAncestor(payload.checkpoint.commit_oid, context.repository.canonical_head, repositoryCommits)) {
      throw new Error("claim-ledger-rollback: issuer-key epoch checkpoint is not canonical history");
    }
    const checkpointRecordIds = new Set(checkpointCommit.record_ids);
    const activeAtCheckpoint = activeIssuerNidsForRecordSet(
      stateForReaders, checkpointRecordIds, payload.checkpoint.observed_at, payload.checkpoint,
    );
    if (jcsCanonicalize(payload.recipient_nids) !== jcsCanonicalize(activeAtCheckpoint) ||
        !activeAtCheckpoint.includes(record.writer_nid)) {
      throw new Error("oidc-issuer-authority-invalid: issuer-key epoch recipients/writer do not match checkpoint authority");
    }
    const material = context.issuer_key_material_by_record_id?.get(record.record_id);
    if (material !== undefined) {
      assertPlainObject(material.envelope, "canonical issuer envelope");
      assertExactKeys(material.envelope, [
        "object_type", "persona", "credential_ledger_generation", "repository_rid", "checkpoint_commit_oid", "epoch",
        "audience_key_id", "previous_key_id", "signing_key_id", "content_digest", "nonce", "ciphertext",
        "authority_record_ids", "authority_record_set_digest", "recipient_wraps", "removed_issuer_nids",
      ], "canonical issuer envelope");
      if (!Array.isArray(material.envelope.recipient_wraps) ||
          !Array.isArray(material.envelope.authority_record_ids) ||
          !Array.isArray(material.envelope.removed_issuer_nids)) {
        throw new Error("claim-schema-invalid: canonical issuer envelope arrays are invalid");
      }
      for (const wrap of material.envelope.recipient_wraps) {
        assertPlainObject(wrap, "canonical issuer recipient wrap");
        assertExactKeys(wrap, ["writer_nid", "context_digest", "wrapped_key"], "canonical issuer recipient wrap");
      }
    }
    const expectedAuthorityIds = issuerAuthorityRecordIds(stateForReaders, checkpointRecordIds);
    if (material === undefined || digestJson(material.envelope) !== payload.envelope_digest ||
        material.envelope.object_type !== "oidc-signing-jwk-v1" ||
        material.envelope.persona !== record.persona ||
        material.envelope.credential_ledger_generation !== record.credential_ledger_generation ||
        material.envelope.repository_rid !== context.repository.repository_rid ||
        material.envelope.signing_key_id !== payload.key_digest || material.envelope.epoch !== payload.epoch ||
        material.envelope.checkpoint_commit_oid !== payload.checkpoint.commit_oid ||
        jcsCanonicalize(material.envelope.authority_record_ids) !== jcsCanonicalize(expectedAuthorityIds) ||
        material.envelope.authority_record_set_digest !== digestJson(expectedAuthorityIds) ||
        jcsCanonicalize(material.envelope.recipient_wraps.map(({ writer_nid }) => writer_nid).sort()) !==
          jcsCanonicalize(payload.recipient_nids) ||
        bytesToHex(sha256(material.audience_key)) !== material.envelope.audience_key_id) {
      throw new Error("oidc-signing-key-unavailable: issuer-key epoch material/envelope binding is absent");
    }
    validateNidSet(material.envelope.removed_issuer_nids);
    for (const recipient of payload.recipient_nids) {
      unwrapIssuerSigningJwk(material.envelope, recipient, material.audience_key);
    }
    if (payload.epoch === 1) {
      if (payload.previous_epoch !== 0 || payload.previous_envelope_digest !== GENESIS_AUDIENCE_KEY_ID ||
          payload.previous_key_digest !== GENESIS_AUDIENCE_KEY_ID ||
          material.envelope.previous_key_id !== GENESIS_AUDIENCE_KEY_ID ||
          material.envelope.removed_issuer_nids.length !== 0) {
        throw new Error("claim-repository-conflict: invalid issuer-key genesis epoch");
      }
    } else {
      const previousRecord = issuerEpochs.get(payload.epoch - 1);
      const previous = previousRecord === undefined ? null : payloadObject(previousRecord.payload) as unknown as IssuerKeyEpochPayload;
      const previousMaterial = previousRecord === undefined
        ? undefined
        : context.issuer_key_material_by_record_id?.get(previousRecord.record_id);
      const expectedRemoved = previous === null
        ? []
        : previous.recipient_nids.filter((nid) => !payload.recipient_nids.includes(nid)).sort();
      if (previousRecord === undefined || previous === null || payload.previous_epoch !== previous.epoch ||
          previousMaterial === undefined ||
          payload.previous_envelope_digest !== previous.envelope_digest ||
          payload.previous_key_digest !== previous.key_digest || !record.parents.includes(previousRecord.record_id) ||
          payload.envelope_digest === previous.envelope_digest || payload.key_digest === previous.key_digest ||
          material.envelope.previous_key_id !== previousMaterial.envelope.audience_key_id ||
          jcsCanonicalize([...material.envelope.removed_issuer_nids].sort()) !== jcsCanonicalize(expectedRemoved)) {
        throw new Error("claim-repository-conflict: issuer-key epoch does not extend the exact canonical predecessor");
      }
    }
    issuerEpochs.set(payload.epoch, record);
  }
  const maximumEpoch = records
    .filter((record) => isReaderAudienceKeyEpochRecord(record) &&
      record.credential_ledger_generation === context.credential_ledger.credential_ledger_generation)
    .reduce((maximum, epochRecord) => Math.max(maximum, Number(payloadObject(epochRecord.payload).epoch)), 0);
  const canonicalReaderClaims = records.filter((record) => {
    if (record.record_type !== "claim" ||
        record.credential_ledger_generation !== context.credential_ledger.credential_ledger_generation ||
        !context.repository.repository_confirmed_record_ids.includes(record.record_id)) {
      return false;
    }
    const claim = claimArtifactFromRecord(record)?.semantic;
    return claim?.claim_class === "authorization" &&
      claim.namespace === "heterodyne.device" &&
      claim.name === "claim-ledger-reader" &&
      claim.value === true &&
      claim.visibility === "repository-private" &&
      claim.subject.type === "radicle-ed25519-nid";
  });
  const activeReaders = new Set<string>();
  for (const candidate of canonicalReaderClaims) {
    const claim = claimArtifactFromRecord(candidate)!.semantic;
    const request = context.reader_requests.get(candidate.record_id);
    if (request === undefined || request.claim_record_id !== candidate.record_id) {
      throw new Error("claim-ledger-reader-unauthorized: validation context is required for every canonical reader candidate");
    }
    if (evaluateReaderAccess(claim.subject.value, stateForReaders, request).state === "active") {
      activeReaders.add(claim.subject.value);
    }
  }
  for (const record of recordsById.values()) {
    if (!isReaderAudienceKeyEpochRecord(record)) continue;
    const payload = payloadObject(record.payload) as unknown as AudienceKeyEpochPayload;
    const readers = payload.reader_nids as string[];
    const removed = payload.removed_reader_nids as string[];
    const accessRemoved = payload.radicle_access_removed as string[];
    if (removed.some((nid) => readers.includes(nid))) {
      throw new Error("claim-repository-conflict: removed reader retained in rotated audience");
    }
    if ([...removed].sort().join("\0") !== [...accessRemoved].sort().join("\0")) {
      throw new Error("claim-ledger-reader-unauthorized: reader removal must remove matching Radicle access");
    }
    if (payload.epoch === maximumEpoch) {
      if (jcsCanonicalize([...activeReaders].sort()) !== jcsCanonicalize([...readers].sort())) {
        throw new Error("claim-ledger-reader-unauthorized: recipient wraps do not equal the active durable reader set");
      }
    }
    const audienceKey = context.audience_keys_by_epoch.get(payload.epoch);
    if (audienceKey === undefined) throw new Error("claim-ledger-reader-unauthorized: audience key epoch material is absent");
    const expected = createAudienceKeyEpochPayload({
      persona: record.persona,
      repository_rid: context.repository.repository_rid,
      checkpoint_commit_oid: payload.checkpoint_commit_oid,
      epoch: payload.epoch,
      key_id: payload.key_id,
      audience_key: audienceKey,
      previous_epoch: payload.previous_epoch,
      previous_key_id: payload.previous_key_id,
      reader_nids: readers,
      removed_reader_nids: removed,
    });
    if (jcsCanonicalize(expected) !== jcsCanonicalize(payload)) {
      throw new Error("claim-ledger-reader-unauthorized: key digest, recipient wrap, or rotation context mismatch");
    }
    if (!context.repository.commits.some(({ commit_oid }) => commit_oid === payload.checkpoint_commit_oid)) {
      throw new Error("claim-ledger-rollback: audience-key epoch is not bound to repository history");
    }
    const previousEpochRecord = [...recordsById.values()].find((candidate) => {
      if (!isReaderAudienceKeyEpochRecord(candidate)) return false;
      const candidatePayload = payloadObject(candidate.payload);
      return candidatePayload.epoch === payload.previous_epoch && candidatePayload.key_id === payload.previous_key_id;
    });
    if (payload.previous_epoch === 0) {
      if (removed.length !== 0 || previousEpochRecord !== undefined) {
        throw new Error("claim-repository-conflict: invalid audience-key genesis epoch");
      }
    } else {
      const previousAudienceKey = context.audience_keys_by_epoch.get(payload.previous_epoch);
      const previousKeyDigest = previousAudienceKey === undefined ? null : bytesToHex(sha256(previousAudienceKey));
      if (previousEpochRecord === undefined || previousAudienceKey === undefined ||
          !record.parents.includes(previousEpochRecord.record_id) ||
          payload.previous_key_id !== previousKeyDigest || payload.key_id !== payload.key_digest ||
          payload.key_id === payload.previous_key_id || payload.key_digest === previousKeyDigest) {
        throw new Error("claim-repository-conflict: audience-key epoch did not rotate monotonically from distinct key material and identifiers");
      }
    }
    for (const removedNid of removed) {
      const orderedReduction = record.parents
        .map((parentId) => recordsById.get(parentId))
        .some((parent) => parent !== undefined && reductionRemovesReader(parent, removedNid));
      if (!orderedReduction) {
        throw new Error("claim-repository-conflict: audience-key rotation must directly follow each authenticated reader reduction");
      }
    }
  }
}

function validateHistoricalInvalidationAuthority(
  record: LedgerRecord,
  state: LedgerMergeResult,
  repository: LedgerRepositoryEvidence,
): void {
  const payload = payloadObject(record.payload);
  const authorityCheckpoint = payload.authority_checkpoint as unknown as LedgerCheckpoint;
  const commits = new Map(repository.commits.map((commit) => [commit.commit_oid, commit]));
  const authorityCommit = commits.get(authorityCheckpoint.commit_oid);
  if (authorityCommit === undefined || authorityCheckpoint.repository_rid !== repository.repository_rid ||
      authorityCheckpoint.branch !== "main" || authorityCheckpoint.observed_at > record.created_at ||
      !isCommitAncestor(authorityCheckpoint.commit_oid, repository.canonical_head, commits)) {
    throw new Error("oidc-issuer-authority-invalid: invalidation authority checkpoint is not canonical history");
  }
  const firstCommit = uniqueCanonicalIntroductionCommit(repository, record.record_id);
  if (firstCommit === undefined
    ? authorityCheckpoint.commit_oid !== repository.canonical_head
    : !firstCommit.parents.includes(authorityCheckpoint.commit_oid)) {
    throw new Error("oidc-issuer-authority-invalid: invalidation was not created from its immediate canonical checkpoint");
  }
  const recordIds = new Set(authorityCommit.record_ids);
  const creationCheckpoint = { ...authorityCheckpoint, observed_at: record.created_at };
  const historical = ledgerSnapshotForRecordSet(
    state, recordIds, record.created_at, creationCheckpoint,
  );
  const authorityClaimId = canonicalIssuerAuthorityClaimId(
    record.writer_nid, historical, record.created_at,
  );
  const epochRecord = currentIssuerKeyEpochRecord(historical);
  const epoch = epochRecord === null ? null : payloadObject(epochRecord.payload) as unknown as IssuerKeyEpochPayload;
  const activeIssuers = activeIssuerNidsForRecordSet(
    state, recordIds, record.created_at, creationCheckpoint,
  );
  if (authorityClaimId === null || authorityClaimId !== payload.writer_authority_claim_id || epoch === null ||
      epoch.epoch !== payload.issuer_key_epoch || epoch.key_digest !== payload.issuer_key_digest ||
      !epoch.recipient_nids.includes(record.writer_nid) ||
      jcsCanonicalize(epoch.recipient_nids) !== jcsCanonicalize(activeIssuers)) {
    throw new Error("oidc-issuer-authority-invalid: invalidation writer/key was not authorized at creation checkpoint");
  }
}

function reductionRemovesReader(record: LedgerRecord, readerNid: string): boolean {
  const payload = payloadObject(record.payload);
  return (
    record.record_type === "authority-reduction" &&
    payload.role === "claim-ledger-reader" &&
    payload.subject_nid === readerNid
  ) || (
    record.record_type === "reader-change" &&
    payload.action === "remove" &&
    payload.reader_nid === readerNid
  );
}

function payloadObject(value: JsonValue | undefined): Record<string, JsonValue> {
  assertPlainObject(value, "payload");
  return value;
}

function isIssuerKeyEpochRecord(record: LedgerRecord): boolean {
  return record.record_type === "audience-key-epoch" &&
    payloadObject(record.payload).scope === "oidc-issuer-key";
}

function isReaderAudienceKeyEpochRecord(record: LedgerRecord): boolean {
  return record.record_type === "audience-key-epoch" &&
    payloadObject(record.payload).scope !== "oidc-issuer-key";
}

function assertPlainObject(value: unknown, label: string): asserts value is Record<string, JsonValue> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`claim-schema-invalid: ${label} must be an object`);
  }
}

function assertValidatedLedgerState(state: LedgerMergeResult): void {
  if (!VALIDATED_LEDGER_STATES.has(state)) {
    throw new Error("claim-repository-unconfirmed: canonical merged ledger state is required");
  }
}

function validatedRepositoryForState(state: LedgerMergeResult): LedgerRepositoryEvidence {
  assertValidatedLedgerState(state);
  const repository = VALIDATED_LEDGER_REPOSITORIES.get(state);
  if (repository === undefined) {
    throw new Error("claim-repository-unconfirmed: canonical repository evidence is required");
  }
  return repository;
}

function isCanonicalAncestorForState(state: LedgerMergeResult, commitOid: string): boolean {
  const repository = validatedRepositoryForState(state);
  const commits = new Map(repository.commits.map((commit) => [commit.commit_oid, commit]));
  return isCommitAncestor(commitOid, repository.canonical_head, commits);
}

function issuerAuthorityRecordIds(
  state: LedgerMergeResult,
  confirmed = new Set(state.repository_confirmed_record_ids ?? []),
): string[] {
  const selectedGenerations = state.records
    .filter(({ record_id }) => confirmed.has(record_id))
    .map(({ credential_ledger_generation }) => credential_ledger_generation);
  const selectedGeneration = selectedGenerations.length === 0
    ? state.credential_ledger.credential_ledger_generation
    : Math.max(...selectedGenerations);
  return state.records.filter((record) => {
    if (!confirmed.has(record.record_id)) return false;
    if (record.record_type === "issuer-authority") {
      return isReduction(record) ||
        record.credential_ledger_generation === selectedGeneration;
    }
    if (record.record_type !== "claim") return false;
    if (record.credential_ledger_generation !== selectedGeneration) return false;
    const claim = claimArtifactFromRecord(record)?.semantic;
    return claim?.claim_class === "authorization" && claim.namespace === "heterodyne.device" &&
      claim.name === "oidc-token-issuer" && claim.value === true &&
      claim.visibility === "repository-private" && claim.subject.type === "radicle-ed25519-nid" &&
      claim.audience?.includes(record.persona) === true &&
      claim.resources?.includes(`${state.checkpoint.repository_rid}#oidc-issuer`) === true;
  }).map(({ record_id }) => record_id).sort();
}

function ledgerSnapshotForRecordSet(
  state: LedgerMergeResult,
  recordIds: Set<string>,
  evaluationTime = state.checkpoint.observed_at,
  checkpoint = state.checkpoint,
): LedgerMergeResult {
  const records = state.records.filter(({ record_id }) => recordIds.has(record_id));
  const selectedGeneration = records.length === 0
    ? state.credential_ledger.credential_ledger_generation
    : Math.max(...records.map(({ credential_ledger_generation }) => credential_ledger_generation));
  return {
    credential_ledger: {
      credential_ledger_persona: state.credential_ledger.credential_ledger_persona,
      credential_ledger_generation: selectedGeneration,
    },
    records,
    conflicted_claim_ids: findConflictedClaims(records),
    checkpoint: { ...checkpoint, observed_at: evaluationTime },
    repository_confirmed_record_ids: [...recordIds],
    delivered_record_ids: [],
    authenticated_revocations: records
      .filter((record) => isReduction(record))
      .map(revocationArtifactFromRecord)
      .filter((artifact): artifact is RevocationArtifact => artifact !== null)
      .map((artifact) => verifyLedgerClaimRevocationArtifact(artifact)),
    token_invalidations: [],
  };
}

function activeIssuerNidsForRecordSet(
  state: LedgerMergeResult,
  recordIds: Set<string>,
  evaluationTime = state.checkpoint.observed_at,
  checkpoint = state.checkpoint,
): string[] {
  const snapshot = ledgerSnapshotForRecordSet(state, recordIds, evaluationTime, checkpoint);
  const records = snapshot.records;
  const candidates = new Set(records
    .filter(({ record_type }) => record_type === "claim")
    .map(claimArtifactFromRecord)
    .filter((artifact): artifact is ClaimArtifact => artifact !== null)
    .filter(({ semantic }) => semantic.claim_class === "authorization" &&
      semantic.namespace === "heterodyne.device" && semantic.name === "oidc-token-issuer" &&
      semantic.value === true && semantic.visibility === "repository-private" &&
      semantic.subject.type === "radicle-ed25519-nid")
    .map(({ semantic }) => semantic.subject.value));
  return [...candidates]
    .filter((nid) => resolveIssuerAuthorityState(nid, snapshot, evaluationTime) === "active")
    .sort();
}

function validatePreviousIssuerKeyEnvelope(input: {
  previous: { envelope: IssuerKeyEnvelope; audience_key: Uint8Array };
  state: LedgerMergeResult;
  repository: LedgerRepositoryEvidence;
  persona: string;
  repository_rid: string;
  next_epoch: number;
  next_audience_key_id: string;
  next_signing_key_id: string;
  next_content_digest: string;
}): string[] {
  try {
    const envelope = input.previous.envelope;
    assertPlainObject(envelope, "previous issuer envelope");
    assertExactKeys(envelope, [
      "object_type", "persona", "credential_ledger_generation", "repository_rid", "checkpoint_commit_oid", "epoch",
      "audience_key_id", "previous_key_id", "signing_key_id", "content_digest", "nonce", "ciphertext",
      "authority_record_ids", "authority_record_set_digest", "recipient_wraps", "removed_issuer_nids",
    ], "previous issuer envelope");
    assertCanonicalSigningKeyId(envelope.signing_key_id, "previous issuer signing_key_id");
    if (envelope.object_type !== "oidc-signing-jwk-v1" || envelope.persona !== input.persona ||
        !Number.isSafeInteger(envelope.credential_ledger_generation) ||
        envelope.credential_ledger_generation < 0 ||
        envelope.credential_ledger_generation >
          input.state.credential_ledger.credential_ledger_generation ||
        input.state.credential_ledger.credential_ledger_generation -
          envelope.credential_ledger_generation > 1 ||
        envelope.repository_rid !== input.repository_rid || !Number.isSafeInteger(envelope.epoch) || envelope.epoch < 1 ||
        input.next_epoch !== envelope.epoch + 1 || !HEX_32.test(envelope.audience_key_id) ||
        !HEX_32.test(envelope.previous_key_id) || !HEX_32.test(envelope.content_digest) ||
        !/^[0-9a-f]{48}$/.test(envelope.nonce) || !/^[0-9a-f]+$/.test(envelope.ciphertext) ||
        envelope.ciphertext.length < 32 || envelope.ciphertext.length % 2 !== 0 ||
        envelope.content_digest === input.next_content_digest || envelope.signing_key_id === input.next_signing_key_id ||
        envelope.audience_key_id === input.next_audience_key_id ||
        bytesToHex(sha256(input.previous.audience_key)) !== envelope.audience_key_id) {
      throw new Error("binding");
    }
    const commits = new Map(input.repository.commits.map((commit) => [commit.commit_oid, commit]));
    const priorCommit = commits.get(envelope.checkpoint_commit_oid);
    if (priorCommit === undefined ||
        !isCommitAncestor(envelope.checkpoint_commit_oid, input.repository.canonical_head, commits)) {
      throw new Error("checkpoint");
    }
    if (!Array.isArray(envelope.authority_record_ids) || !Array.isArray(envelope.recipient_wraps) ||
        !Array.isArray(envelope.removed_issuer_nids)) {
      throw new Error("shape");
    }
    const priorRecordIds = new Set(priorCommit.record_ids);
    const priorGenerations = input.state.records
      .filter(({ record_id }) => priorRecordIds.has(record_id))
      .map(({ credential_ledger_generation }) => credential_ledger_generation);
    if (priorGenerations.length === 0 ||
        envelope.credential_ledger_generation !== Math.max(...priorGenerations)) {
      throw new Error("generation");
    }
    const expectedAuthorityIds = issuerAuthorityRecordIds(input.state, priorRecordIds);
    if (jcsCanonicalize(envelope.authority_record_ids) !== jcsCanonicalize(expectedAuthorityIds) ||
        envelope.authority_record_set_digest !== digestJson(expectedAuthorityIds)) {
      throw new Error("authority");
    }
    const recipients = envelope.recipient_wraps.map((wrap) => {
      assertPlainObject(wrap, "previous issuer recipient wrap");
      assertExactKeys(wrap, ["writer_nid", "context_digest", "wrapped_key"], "previous issuer recipient wrap");
      if (!HEX_32.test(wrap.context_digest) || !/^[0-9a-f]{128}$/.test(wrap.wrapped_key)) throw new Error("wrap");
      return wrap.writer_nid;
    });
    validateNidSet(recipients);
    validateNidSet(envelope.removed_issuer_nids);
    const expectedRecipients = activeIssuerNidsForRecordSet(input.state, priorRecordIds);
    if (jcsCanonicalize([...recipients].sort()) !== jcsCanonicalize(expectedRecipients) ||
        envelope.removed_issuer_nids.some((nid) => recipients.includes(nid))) {
      throw new Error("recipients");
    }
    for (const recipient of recipients) {
      unwrapIssuerSigningJwk(envelope, recipient, input.previous.audience_key);
    }
    return [...recipients].sort();
  } catch {
    throw new Error("oidc-signing-key-unavailable: previous issuer envelope/key binding is invalid or material was not rotated");
  }
}

function invalidationCauseKey(payload: Record<string, JsonValue>): string {
  return payload.cause === "source-claim-revoked"
    ? `${String(payload.jti)}\0source\0${String(payload.source_claim_id)}`
    : `${String(payload.jti)}\0key\0${String(payload.signing_key_id)}`;
}

function assertExactKeys(value: object, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new Error(`claim-schema-invalid: ${label} has missing or unknown members`);
  }
}

function assertClaimId(value: JsonValue): void {
  if (typeof value !== "string" || !HEX_32.test(value)) throw new Error("claim-schema-invalid: invalid claim ID");
}

function validateNidSet(value: JsonValue | undefined): void {
  if (!Array.isArray(value) || value.length > 256 || new Set(value).size !== value.length ||
      value.some((nid) => typeof nid !== "string")) {
    throw new Error("claim-schema-invalid: invalid NID set");
  }
  for (const nid of value) ed25519PublicKeyFromNid(nid as string);
}

function validateClaimIdSet(value: JsonValue | undefined): void {
  if (!Array.isArray(value) || value.length === 0 || value.length > 256 || new Set(value).size !== value.length) {
    throw new Error("claim-schema-invalid: invalid source claim ID set");
  }
  for (const claimId of value) assertClaimId(claimId);
}

function readerDenied(state: ClaimState, reason_code: string): AuthorizationDecision {
  return { allowed: false, state, reason_code };
}

function confirmedClaimIds(state: LedgerMergeResult): Set<string> {
  const confirmedRecords = new Set(state.repository_confirmed_record_ids ?? []);
  return new Set(
    state.records
      .filter(({ record_id, record_type, credential_ledger_generation }) =>
        record_type === "claim" && confirmedRecords.has(record_id) &&
        credential_ledger_generation === state.credential_ledger.credential_ledger_generation)
      .map(recordClaimId)
      .filter((claimId): claimId is string => claimId !== null),
  );
}

function currentAudienceEpochRecord(state: LedgerMergeResult): LedgerRecord | null {
  const confirmed = new Set(state.repository_confirmed_record_ids ?? []);
  return state.records
    .filter((record) => isReaderAudienceKeyEpochRecord(record) && confirmed.has(record.record_id) &&
      record.credential_ledger_generation === state.credential_ledger.credential_ledger_generation)
    .sort((left, right) => Number(payloadObject(right.payload).epoch) - Number(payloadObject(left.payload).epoch))[0] ?? null;
}

function currentIssuerKeyEpochRecord(state: LedgerMergeResult): LedgerRecord | null {
  const confirmed = new Set(state.repository_confirmed_record_ids ?? []);
  return state.records
    .filter((record) => isIssuerKeyEpochRecord(record) && confirmed.has(record.record_id) &&
      record.credential_ledger_generation === state.credential_ledger.credential_ledger_generation)
    .sort((left, right) => Number(payloadObject(right.payload).epoch) - Number(payloadObject(left.payload).epoch))[0] ?? null;
}
