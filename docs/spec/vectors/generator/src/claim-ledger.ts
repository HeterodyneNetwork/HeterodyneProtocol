import { createHmac } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import {
  authorizeWithClaim,
  validateClaimEnvelope,
  validateClaimRevocationEnvelope,
  verifyClaimChain,
  validateKeyRef,
  type AuthorizationDecision,
  type ClaimSemanticBody,
  type ClaimEnvelopeContext,
  type ClaimVerificationContext,
  type ClaimState,
  type JsonValue,
  type VerifiedRevocation,
} from "./claims.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  validateClaimLedgerRecordSchemaOrThrow,
} from "./schema.js";
import type { NostrSignedEvent } from "./nostr.js";

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

export type LedgerMergeResult = {
  records: LedgerRecord[];
  conflicted_claim_ids: string[];
  checkpoint: LedgerCheckpoint;
  repository_confirmed_record_ids?: string[];
  delivered_record_ids?: string[];
  authenticated_revocations?: VerifiedRevocation[];
  token_invalidations?: string[];
};

export type ClaimArtifact = { event: NostrSignedEvent; semantic: ClaimSemanticBody };
export type RevocationArtifact = { event: NostrSignedEvent; semantic: JsonValue };

export type LedgerRecordValidationEvidence = {
  record_id: string;
  payload_digest: string;
  claim_envelope_context?: ClaimEnvelopeContext;
  claims_by_id?: Map<string, ClaimSemanticBody>;
  claim_verification_context?: ClaimVerificationContext;
};

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
  claims_by_id: Map<string, ClaimSemanticBody>;
  verification_context: ClaimVerificationContext;
};

export type LedgerValidationContext = {
  record_evidence: Map<string, LedgerRecordValidationEvidence>;
  repository: LedgerRepositoryEvidence;
  reader_requests: Map<string, ReaderAccessRequest>;
  audience_keys_by_epoch: Map<number, Uint8Array>;
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

export function createSignedLedgerRecord(input: UnsignedLedgerRecord, writerSecretKey: string): LedgerRecord {
  const payload_digest = digestJson(input.payload);
  const signing = recordSigningPayload({ ...input, payload_digest });
  const signature = bytesToHex(ed25519.sign(utf8Bytes(signing), hexToBytes(writerSecretKey)));
  const withoutId = { ...input, payload_digest, signature };
  return { record_id: digestJson(withoutId), ...withoutId };
}

export function validateLedgerRecordOrThrow(
  record: LedgerRecord,
  recordsById: ReadonlyMap<string, LedgerRecord>,
  evidence?: LedgerRecordValidationEvidence,
): void {
  assertPlainObject(record, "record");
  assertExactKeys(record, RECORD_KEYS, "record");
  validateClaimLedgerRecordSchemaOrThrow(record);
  if (!HEX_32.test(record.record_id)) throw new Error("claim-id-mismatch: invalid ledger record_id");
  if (!RECORD_TYPES.has(record.record_type)) throw new Error("claim-schema-invalid: invalid ledger record_type");
  if (!PERSONA.test(record.persona)) throw new Error("claim-schema-invalid: invalid ledger persona");
  if (!Number.isSafeInteger(record.created_at) || record.created_at < 0 || record.created_at > MAX_SAFE) {
    throw new Error("claim-schema-invalid: invalid ledger created_at");
  }
  const writerPublicKey = ed25519PublicKeyFromNid(record.writer_nid);
  if (!Array.isArray(record.parents) || record.parents.length > 256 || new Set(record.parents).size !== record.parents.length) {
    throw new Error("claim-schema-invalid: parents must be a unique bounded array");
  }
  if (!HEX_32.test(record.payload_digest) || record.payload_digest !== digestJson(record.payload)) {
    throw new Error("claim-id-mismatch: ledger payload_digest mismatch");
  }
  if (!HEX_64.test(record.signature)) throw new Error("claim-schema-invalid: invalid ledger signature encoding");
  validatePayload(record.record_type, record.payload);
  const expectedId = digestJson(withoutRecordId(record));
  if (record.record_id !== expectedId) throw new Error("claim-id-mismatch: ledger record_id mismatch");
  if (!ed25519.verify(
    hexToBytes(record.signature),
    utf8Bytes(recordSigningPayload(record)),
    writerPublicKey,
  )) {
    throw new Error("claim-event-signature-invalid: ledger writer signature is invalid");
  }
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
  const recordsById = new Map<string, LedgerRecord>();
  for (const record of [...left, ...right]) {
    const existing = recordsById.get(record.record_id);
    if (existing !== undefined && jcsCanonicalize(existing) !== jcsCanonicalize(record)) {
      throw new Error("claim-repository-conflict: record ID collision");
    }
    recordsById.set(record.record_id, record);
  }
  const records = [...recordsById.values()];
  validateRepositoryEvidence(checkpoint, recordsById, context.repository);
  for (const record of records) {
    validateLedgerRecordOrThrow(record, recordsById, context.record_evidence.get(record.record_id));
  }
  assertAcyclic(recordsById);
  validateLedgerStateInvariants(recordsById, context);
  const personas = new Set(records.map(({ persona }) => persona));
  if (personas.size > 1) throw new Error("claim-repository-conflict: one persona is permitted per ledger");
  records.sort((a, b) => a.record_id.localeCompare(b.record_id));
  const confirmed = [...context.repository.repository_confirmed_record_ids].sort();
  const authenticatedRevocations = records
    .filter((record) => ["revocation", "authority-reduction", "reader-change", "issuer-authority"].includes(record.record_type))
    .filter((record) => isReduction(record))
    .map(revocationArtifactFromRecord)
    .filter((artifact): artifact is RevocationArtifact => artifact !== null)
    .map(({ event }) => validateClaimRevocationEnvelope(event));
  const tokenInvalidations = records
    .filter(({ record_type }) => record_type === "status-invalidation")
    .map((record) => String(payloadObject(record.payload).jti))
    .sort();
  return {
    records,
    conflicted_claim_ids: findConflictedClaims(records),
    checkpoint: { ...checkpoint },
    repository_confirmed_record_ids: confirmed,
    delivered_record_ids: records.map(({ record_id }) => record_id).filter((id) => !confirmed.includes(id)).sort(),
    authenticated_revocations: authenticatedRevocations,
    token_invalidations: tokenInvalidations,
  };
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

export function ledgerErrorReason(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  for (const code of [
    "claim-ledger-rollback",
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
  if (record === undefined) return readerDenied("provisional", "claim-repository-unconfirmed");
  const artifact = claimArtifactFromRecord(record);
  if (artifact === null) return readerDenied("invalid", "claim-ledger-reader-unauthorized");
  let claim: ClaimSemanticBody;
  let chain: ClaimSemanticBody[];
  try {
    claim = validateClaimEnvelope(artifact.event, request.envelope_context);
    if (jcsCanonicalize(claim) !== jcsCanonicalize(artifact.semantic)) throw new Error("artifact mismatch");
    const claimsById = new Map(request.claims_by_id);
    claimsById.set(claim.claim_id, claim);
    chain = verifyClaimChain(claim, claimsById);
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
    revocations: [...(state.authenticated_revocations ?? [])],
  };
  const decision = authorizeWithClaim(claim, chain, verification);
  return decision.allowed ? decision : {
    ...decision,
    reason_code: decision.reason_code ?? "claim-ledger-reader-unauthorized",
  };
}

export function resolveAuthoritativeClaimState(
  claimId: string,
  state: LedgerMergeResult,
  evaluationTime = state.checkpoint.observed_at,
): ClaimState {
  if (!HEX_32.test(claimId)) return "invalid";
  const related = state.records.filter((record) => recordClaimId(record) === claimId);
  if (related.some((record) => isReduction(record) && record.created_at > evaluationTime)) return "invalid";
  if (related.some(isReduction)) return "revoked";
  if (state.conflicted_claim_ids.includes(claimId)) return "conflicted";
  const claimRecords = related.filter((record) => claimArtifactFromRecord(record) !== null);
  if (claimRecords.length === 0) return "provisional";
  if (claimRecords.every(({ record_id }) => !(state.repository_confirmed_record_ids ?? []).includes(record_id))) {
    return "provisional";
  }
  const claims = claimRecords.map((record) => claimArtifactFromRecord(record)!.semantic);
  if (claims.some((claim) => state.checkpoint.observed_at < claim.not_before)) return "provisional";
  if (claims.some((claim) => claim.expires_at !== undefined && state.checkpoint.observed_at >= claim.expires_at)) {
    return "expired";
  }
  return "active";
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
  if (!decision.allowed) throw new Error(decision.reason_code ?? "claim-ledger-reader-unauthorized");
  if (input.audience_key.length !== 32) throw new Error("ledger audience key must be exactly 32 bytes");
  const claimRecord = state.records.find(({ record_id }) => record_id === input.request.claim_record_id);
  const artifact = claimRecord === undefined ? null : claimArtifactFromRecord(claimRecord);
  if (artifact === null) throw new Error("claim-ledger-reader-unauthorized: onboarding authorization artifact is absent");
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
      event_id: artifact.event.id,
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
  if (request === undefined || !evaluateReaderAccess(bundle.radicle_access.nid, state, request).allowed) {
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
  "record_type" | "persona" | "writer_nid" | "created_at" | "parents" | "payload" | "payload_digest"
>): string {
  return jcsCanonicalize({
    domain: "heterodyne-claim-ledger-record-v1",
    record_type: record.record_type,
    persona: record.persona,
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
      assertExactKeys(payload, ["jti", "writer_nid", "source_claim_ids", "allocation_ref"], "issuance reservation payload");
      if (!/^[A-Za-z0-9_-]{16,128}$/.test(String(payload.jti))) throw new Error("claim-schema-invalid: invalid jti");
      ed25519PublicKeyFromNid(String(payload.writer_nid));
      validateClaimIdSet(payload.source_claim_ids);
      if (!/^pending:[A-Za-z0-9._:-]{1,256}$/.test(String(payload.allocation_ref))) {
        throw new Error("claim-schema-invalid: Task 4 requires an opaque pending allocation reference");
      }
      return;
    case "status-invalidation":
      assertExactKeys(payload, ["jti", "source_claim_id", "revocation_artifact"], "status invalidation payload");
      if (!/^[A-Za-z0-9_-]{16,128}$/.test(String(payload.jti))) throw new Error("claim-schema-invalid: invalid jti");
      assertClaimId(payload.source_claim_id);
  }
}

function validateAuthenticatedArtifact(
  record: LedgerRecord,
  recordsById: ReadonlyMap<string, LedgerRecord>,
  evidence: LedgerRecordValidationEvidence,
): void {
  const claimArtifact = claimArtifactFromRecord(record);
  if (claimArtifact !== null) {
    if (evidence.claim_envelope_context === undefined || evidence.claims_by_id === undefined) {
      throw new Error("claim-issuer-authority-invalid: signed claim validation context is required");
    }
    const parsed = validateClaimEnvelope(claimArtifact.event, evidence.claim_envelope_context);
    if (jcsCanonicalize(parsed) !== jcsCanonicalize(claimArtifact.semantic)) {
      throw new Error("claim-id-mismatch: claim artifact semantic does not equal signed event content");
    }
    const claimsById = new Map(evidence.claims_by_id);
    claimsById.set(parsed.claim_id, parsed);
    const chain = verifyClaimChain(parsed, claimsById);
    if (evidence.claim_verification_context !== undefined) {
      const decision = authorizeWithClaim(parsed, chain, evidence.claim_verification_context);
      if (decision.state === "invalid") throw new Error(decision.reason_code ?? "claim-issuer-authority-invalid");
    }
  }

  const revocationArtifact = revocationArtifactFromRecord(record);
  if (revocationArtifact === null) return;
  if (evidence.claims_by_id === undefined || evidence.claim_verification_context === undefined) {
    throw new Error("claim-revoker-unauthorized: revocation validation context is required");
  }
  const verified = validateClaimRevocationEnvelope(revocationArtifact.event);
  if (jcsCanonicalize(verifiedRevocationSemantic(verified)) !== jcsCanonicalize(revocationArtifact.semantic)) {
    throw new Error("claim-id-mismatch: revocation artifact semantic does not equal signed event content");
  }
  const target = evidence.claims_by_id.get(verified.claim_id);
  if (target === undefined) throw new Error("claim-revoker-unauthorized: revocation target claim is absent");
  const chain = verifyClaimChain(target, evidence.claims_by_id);
  const decision = authorizeWithClaim(target, chain, {
    ...evidence.claim_verification_context,
    revocations: [...evidence.claim_verification_context.revocations, verified],
  });
  if (decision.state !== "revoked") {
    throw new Error("claim-revoker-unauthorized: Task 3 did not authenticate this revocation effect");
  }
  const payload = payloadObject(record.payload);
  if (record.record_type === "authority-reduction") {
    if (target.subject.type !== "radicle-ed25519-nid" || target.subject.value !== payload.subject_nid ||
        target.name !== payload.role) {
      throw new Error("claim-revoker-unauthorized: authority reduction target, subject, or role mismatch");
    }
  }
  if (record.record_type === "reader-change" && payload.action === "remove") {
    if (target.subject.type !== "radicle-ed25519-nid" || target.subject.value !== payload.reader_nid ||
        target.name !== "claim-ledger-reader") {
      throw new Error("claim-revoker-unauthorized: reader removal is not bound to the reader claim");
    }
  }
  if (record.record_type === "issuer-authority" && payload.action === "remove") {
    if (target.subject.type !== "radicle-ed25519-nid" || target.subject.value !== payload.writer_nid ||
        target.name !== "oidc-token-issuer") {
      throw new Error("claim-revoker-unauthorized: issuer removal is not bound to the issuer claim");
    }
  }
  if (record.record_type === "status-invalidation" && payload.source_claim_id !== verified.claim_id) {
    throw new Error("claim-revoker-unauthorized: token invalidation source claim mismatch");
  }
  // recordsById is intentionally consulted through target artifacts so an
  // external bare semantic body cannot be the sole authority source.
  if (![...recordsById.values()].some((candidate) =>
    claimArtifactFromRecord(candidate)?.semantic.claim_id === verified.claim_id
  )) throw new Error("claim-repository-unconfirmed: revocation target has no signed ledger artifact");
}

function claimArtifactFromRecord(record: LedgerRecord): ClaimArtifact | null {
  const payload = payloadObject(record.payload);
  const value = record.record_type === "claim" ? payload.claim_artifact :
    ((record.record_type === "reader-change" || record.record_type === "issuer-authority") && payload.action === "grant") ? payload.claim_artifact : undefined;
  if (value === undefined) return null;
  const artifact = payloadObject(value);
  return { event: artifact.event as unknown as NostrSignedEvent, semantic: artifact.semantic as unknown as ClaimSemanticBody };
}

function revocationArtifactFromRecord(record: LedgerRecord): RevocationArtifact | null {
  const payload = payloadObject(record.payload);
  const value = record.record_type === "revocation" || record.record_type === "authority-reduction" ||
    record.record_type === "status-invalidation" ||
    ((record.record_type === "reader-change" || record.record_type === "issuer-authority") && payload.action === "remove")
    ? payload.revocation_artifact : undefined;
  if (value === undefined) return null;
  const artifact = payloadObject(value);
  return { event: artifact.event as unknown as NostrSignedEvent, semantic: artifact.semantic as JsonValue };
}

function verifiedRevocationSemantic(verified: VerifiedRevocation): JsonValue {
  const { signer: _signer, event_id: _eventId, event_created_at: _eventCreatedAt, ...semantic } = verified;
  return semantic as unknown as JsonValue;
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
  const stateForReaders: LedgerMergeResult = {
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
      .map(({ event }) => validateClaimRevocationEnvelope(event)),
    token_invalidations: [],
  };
  const maximumEpoch = records
    .filter(({ record_type }) => record_type === "audience-key-epoch")
    .reduce((maximum, epochRecord) => Math.max(maximum, Number(payloadObject(epochRecord.payload).epoch)), 0);
  const canonicalReaderClaims = records.filter((record) => {
    if (record.record_type !== "claim" || !context.repository.repository_confirmed_record_ids.includes(record.record_id)) {
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
    if (evaluateReaderAccess(claim.subject.value, stateForReaders, request).allowed) {
      activeReaders.add(claim.subject.value);
    }
  }
  for (const record of recordsById.values()) {
    if (record.record_type !== "audience-key-epoch") continue;
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
      if (candidate.record_type !== "audience-key-epoch") return false;
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

function assertPlainObject(value: unknown, label: string): asserts value is Record<string, JsonValue> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`claim-schema-invalid: ${label} must be an object`);
  }
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
      .filter(({ record_id, record_type }) => record_type === "claim" && confirmedRecords.has(record_id))
      .map(recordClaimId)
      .filter((claimId): claimId is string => claimId !== null),
  );
}

function currentAudienceEpochRecord(state: LedgerMergeResult): LedgerRecord | null {
  const confirmed = new Set(state.repository_confirmed_record_ids ?? []);
  return state.records
    .filter((record) => record.record_type === "audience-key-epoch" && confirmed.has(record.record_id))
    .sort((left, right) => Number(payloadObject(right.payload).epoch) - Number(payloadObject(left.payload).epoch))[0] ?? null;
}
