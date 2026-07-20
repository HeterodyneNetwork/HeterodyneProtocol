import { createHmac } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import {
  validateClaimId,
  validateKeyRef,
  type AuthorizationDecision,
  type ClaimSemanticBody,
  type ClaimState,
  type JsonValue,
} from "./claims.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { reasonCodeValues } from "./reason-codes.js";
import {
  validateClaimLedgerRecordSchemaOrThrow,
  validateKeyClaimSchemaOrThrow,
} from "./schema.js";

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
};

export type LedgerCheckpointGuard = {
  previous_checkpoint: LedgerCheckpoint;
  canonical_ancestors: string[];
};

export type LedgerOnboardingBundle = {
  transport: "dr-self-dm";
  authorization: ClaimSemanticBody;
  repository: { rid: string; branch: "main" };
  checkpoint: LedgerCheckpoint;
  audience_key: string;
  compact_state: JsonValue;
  radicle_access: { nid: string; role: "fetch-and-seed" };
};

export type ReductionEvidence = {
  claim_id: string;
  event_id: string;
  authority: "claim-revocation" | "claim-ledger-reader" | "oidc-token-issuer" | "source-claim";
  validated_at: number;
  core_kel_authority_valid: true;
  evidence_digest: string;
};

type UnsignedLedgerRecord = Omit<LedgerRecord, "record_id" | "payload_digest" | "signature">;

const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{128}$/;
const PERSONA = HEX_32;
const COMMIT_OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const RID = /^rad:z[1-9A-HJ-NP-Za-km-z]+$/;
const ED25519_PREFIX = Uint8Array.from([0xed, 0x01]);
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
const REGISTERED_REASON_CODES = new Set(reasonCodeValues());

export function createSignedLedgerRecord(input: UnsignedLedgerRecord, writerSecretKey: string): LedgerRecord {
  const payload_digest = digestJson(input.payload);
  const signing = recordSigningPayload({ ...input, payload_digest });
  const signature = bytesToHex(ed25519.sign(utf8Bytes(signing), hexToBytes(writerSecretKey)));
  const withoutId = { ...input, payload_digest, signature };
  return { record_id: digestJson(withoutId), ...withoutId };
}

export function createReductionEvidence(
  input: Omit<ReductionEvidence, "evidence_digest">,
): ReductionEvidence {
  return { ...input, evidence_digest: digestJson(input) };
}

export function validateLedgerRecordOrThrow(
  record: LedgerRecord,
  recordsById: ReadonlyMap<string, LedgerRecord>,
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
}

export function mergeClaimLedger(
  left: LedgerRecord[],
  right: LedgerRecord[],
  checkpoint: LedgerCheckpoint,
  guard?: LedgerCheckpointGuard,
): LedgerMergeResult {
  // Both inputs are verified candidate sets for canonical main. A delivered
  // grant is deliberately absent until repository reachability is proved;
  // authenticated reductions may be supplied immediately and remain
  // absorbing when their record later becomes repository-final.
  const recordsById = new Map<string, LedgerRecord>();
  for (const record of [...left, ...right]) {
    const existing = recordsById.get(record.record_id);
    if (existing !== undefined && jcsCanonicalize(existing) !== jcsCanonicalize(record)) {
      throw new Error("claim-repository-conflict: record ID collision");
    }
    recordsById.set(record.record_id, record);
  }
  const records = [...recordsById.values()];
  validateCheckpoint(checkpoint, records, guard);
  for (const record of records) validateLedgerRecordOrThrow(record, recordsById);
  assertAcyclic(recordsById);
  validateLedgerStateInvariants(recordsById);
  const personas = new Set(records.map(({ persona }) => persona));
  if (personas.size > 1) throw new Error("claim-repository-conflict: one persona is permitted per ledger");
  records.sort((a, b) => a.record_id.localeCompare(b.record_id));
  return {
    records,
    conflicted_claim_ids: findConflictedClaims(records),
    checkpoint: { ...checkpoint },
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

export function evaluateReaderAccess(
  readerNid: string | null,
  claims: ClaimSemanticBody[],
  state: LedgerMergeResult,
): AuthorizationDecision {
  if (readerNid === null) return readerDenied("invalid", "claim-ledger-reader-unauthorized");
  try {
    ed25519PublicKeyFromNid(readerNid);
  } catch {
    return readerDenied("invalid", "claim-ledger-reader-unauthorized");
  }
  const candidates = claims
    .filter((claim) => validReaderClaimCandidate(claim, readerNid, state))
    .sort((a, b) => a.claim_id.localeCompare(b.claim_id));
  if (candidates.length === 0) return readerDenied("invalid", "claim-ledger-reader-unauthorized");
  for (const claim of candidates) {
    const claimState = resolveAuthoritativeClaimState(claim.claim_id, state);
    if (claimState === "active") return { allowed: true, state: "active", reason_code: null };
    if (claimState === "conflicted") return readerDenied("conflicted", "claim-repository-conflict");
    if (claimState === "revoked") return readerDenied("revoked", "claim-revoked");
    if (claimState === "expired") return readerDenied("expired", "claim-expired");
  }
  return readerDenied("provisional", "claim-repository-unconfirmed");
}

export function resolveAuthoritativeClaimState(claimId: string, state: LedgerMergeResult): ClaimState {
  if (!HEX_32.test(claimId)) return "invalid";
  if (state.conflicted_claim_ids.includes(claimId)) return "conflicted";
  const related = state.records.filter((record) => recordClaimId(record) === claimId);
  if (related.some(isReduction)) return "revoked";
  const claimRecords = related.filter((record) => record.record_type === "claim");
  if (claimRecords.length === 0) return "provisional";
  const claims = claimRecords.map((record) => payloadObject(record.payload).claim as unknown as ClaimSemanticBody);
  if (claims.some((claim) => state.checkpoint.observed_at < claim.not_before)) return "provisional";
  if (claims.some((claim) => claim.expires_at !== undefined && state.checkpoint.observed_at >= claim.expires_at)) {
    return "expired";
  }
  return "active";
}

export function buildReaderOnboardingBundle(
  input: {
    reader_nid: string;
    authorization: ClaimSemanticBody;
    repository_rid: string;
    checkpoint: LedgerCheckpoint;
    audience_key: Uint8Array;
    compact_state: JsonValue;
    radicle_access: { nid: string; role: "fetch-and-seed" };
  },
  state: LedgerMergeResult,
): LedgerOnboardingBundle {
  const decision = evaluateReaderAccess(input.reader_nid, [input.authorization], state);
  if (!decision.allowed) throw new Error(decision.reason_code ?? "claim-ledger-reader-unauthorized");
  if (input.repository_rid !== state.checkpoint.repository_rid ||
      jcsCanonicalize(input.checkpoint) !== jcsCanonicalize(state.checkpoint)) {
    throw new Error("claim-ledger-rollback: onboarding checkpoint is not canonical");
  }
  if (input.radicle_access.nid !== input.reader_nid || input.radicle_access.role !== "fetch-and-seed") {
    throw new Error("claim-ledger-reader-unauthorized: Radicle access is not bound to the reader NID");
  }
  if (input.audience_key.length !== 32) throw new Error("ledger audience key must be exactly 32 bytes");
  return {
    transport: "dr-self-dm",
    authorization: structuredClone(input.authorization),
    repository: { rid: input.repository_rid, branch: "main" },
    checkpoint: { ...input.checkpoint },
    audience_key: bytesToHex(input.audience_key),
    compact_state: structuredClone(input.compact_state),
    radicle_access: { ...input.radicle_access },
  };
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
  records: LedgerRecord[],
  guard?: LedgerCheckpointGuard,
): void {
  assertPlainObject(checkpoint, "checkpoint");
  assertExactKeys(checkpoint, ["repository_rid", "branch", "commit_oid", "observed_at"], "checkpoint");
  if (!RID.test(checkpoint.repository_rid)) throw new Error("claim-schema-invalid: invalid repository RID");
  if (checkpoint.branch !== "main") throw new Error("claim-ledger-rollback: only canonical main is authoritative");
  if (!COMMIT_OID.test(checkpoint.commit_oid)) throw new Error("claim-schema-invalid: invalid canonical commit OID");
  if (!Number.isSafeInteger(checkpoint.observed_at) || checkpoint.observed_at < 0) {
    throw new Error("claim-schema-invalid: invalid checkpoint observation time");
  }
  const newestRecord = records.reduce((latest, record) => Math.max(latest, record.created_at), 0);
  if (checkpoint.observed_at < newestRecord) throw new Error("claim-ledger-rollback: stale checkpoint predates ledger records");
  if (guard !== undefined) {
    const prior = guard.previous_checkpoint;
    if (prior.repository_rid !== checkpoint.repository_rid || prior.branch !== "main" ||
        checkpoint.observed_at < prior.observed_at ||
        (prior.commit_oid !== checkpoint.commit_oid && !guard.canonical_ancestors.includes(prior.commit_oid))) {
      throw new Error("claim-ledger-rollback: checkpoint does not descend from finalized canonical main");
    }
  }
}

function validatePayload(type: LedgerRecordType, value: JsonValue): void {
  const payload = payloadObject(value);
  switch (type) {
    case "claim": {
      assertExactKeys(payload, ["claim"], "claim payload");
      const claim = payloadObject(payload.claim) as unknown as ClaimSemanticBody;
      validateKeyClaimSchemaOrThrow(claim);
      validateClaimId(claim);
      return;
    }
    case "revocation":
      assertExactKeys(payload, ["claim_id", "reason_code", "evidence"], "revocation payload");
      assertClaimId(payload.claim_id);
      if (typeof payload.reason_code !== "string" || payload.reason_code.length === 0) {
        throw new Error("claim-schema-invalid: invalid authenticated revocation payload");
      }
      if (!REGISTERED_REASON_CODES.has(payload.reason_code)) {
        throw new Error("claim-schema-invalid: revocation reason_code is not registered");
      }
      validateReductionEvidence(payload.evidence, payload.claim_id as string, "claim-revocation");
      return;
    case "authority-reduction":
      assertExactKeys(payload, ["claim_id", "subject_nid", "authority", "evidence"], "authority reduction payload");
      assertClaimId(payload.claim_id);
      ed25519PublicKeyFromNid(String(payload.subject_nid));
      if (!["claim-ledger-reader", "oidc-token-issuer"].includes(String(payload.authority))) {
        throw new Error("claim-schema-invalid: invalid authority reduction payload");
      }
      validateReductionEvidence(payload.evidence, payload.claim_id as string, payload.authority as ReductionEvidence["authority"]);
      return;
    case "reader-change":
      assertExactKeys(payload, ["claim_id", "reader_nid", "action"], "reader change payload");
      assertClaimId(payload.claim_id);
      ed25519PublicKeyFromNid(String(payload.reader_nid));
      if (payload.action !== "grant" && payload.action !== "remove") throw new Error("claim-schema-invalid: invalid reader action");
      return;
    case "audience-key-epoch":
      assertAllowedAndRequiredKeys(
        payload,
        ["key_id", "previous_key_id", "reader_nids", "removed_reader_nids", "radicle_access_removed", "retire_previous_state", "scrub_profile"],
        ["key_id", "reader_nids", "removed_reader_nids", "radicle_access_removed", "retire_previous_state", "scrub_profile"],
        "audience key epoch payload",
      );
      if (!/^[A-Za-z0-9._-]{1,128}$/.test(String(payload.key_id)) || payload.retire_previous_state !== true ||
          payload.scrub_profile !== "comms-encrypted-branch-cooperative-v1") {
        throw new Error("claim-schema-invalid: invalid audience key epoch");
      }
      if (payload.previous_key_id !== undefined && !/^[A-Za-z0-9._-]{1,128}$/.test(String(payload.previous_key_id))) {
        throw new Error("claim-schema-invalid: invalid previous audience key ID");
      }
      validateNidSet(payload.reader_nids);
      validateNidSet(payload.removed_reader_nids);
      validateNidSet(payload.radicle_access_removed);
      return;
    case "issuer-authority":
      assertExactKeys(payload, ["claim_id", "writer_nid", "action"], "issuer authority payload");
      assertClaimId(payload.claim_id);
      ed25519PublicKeyFromNid(String(payload.writer_nid));
      if (payload.action !== "grant" && payload.action !== "remove") throw new Error("claim-schema-invalid: invalid issuer action");
      return;
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
      assertExactKeys(payload, ["jti", "source_claim_id", "evidence"], "status invalidation payload");
      if (!/^[A-Za-z0-9_-]{16,128}$/.test(String(payload.jti))) throw new Error("claim-schema-invalid: invalid jti");
      assertClaimId(payload.source_claim_id);
      validateReductionEvidence(payload.evidence, payload.source_claim_id as string, "source-claim");
  }
}

function findConflictedClaims(records: LedgerRecord[]): string[] {
  const widenings = new Map<string, Set<string>>();
  for (const record of records) {
    const claimId = recordClaimId(record);
    if (claimId === null || isReduction(record) || !["claim", "reader-change", "issuer-authority"].includes(record.record_type)) continue;
    const key = `${record.record_type}:${claimId}`;
    const variants = widenings.get(key) ?? new Set<string>();
    variants.add(jcsCanonicalize(record.payload));
    widenings.set(key, variants);
  }
  return [...new Set(
    [...widenings.entries()]
      .filter(([, variants]) => variants.size > 1)
      .map(([key]) => key.slice(key.indexOf(":") + 1)),
  )].sort();
}

function recordClaimId(record: LedgerRecord): string | null {
  const payload = payloadObject(record.payload);
  if (record.record_type === "claim") {
    const claim = payloadObject(payload.claim);
    return typeof claim.claim_id === "string" ? claim.claim_id : null;
  }
  return typeof payload.claim_id === "string" ? payload.claim_id :
    typeof payload.source_claim_id === "string" ? payload.source_claim_id : null;
}

function isReduction(record: LedgerRecord): boolean {
  const payload = payloadObject(record.payload);
  return record.record_type === "revocation" || record.record_type === "authority-reduction" ||
    record.record_type === "status-invalidation" ||
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

function validateLedgerStateInvariants(recordsById: ReadonlyMap<string, LedgerRecord>): void {
  for (const record of recordsById.values()) {
    if (record.record_type !== "audience-key-epoch") continue;
    const payload = payloadObject(record.payload);
    const readers = payload.reader_nids as string[];
    const removed = payload.removed_reader_nids as string[];
    const accessRemoved = payload.radicle_access_removed as string[];
    if (removed.length > 0 && typeof payload.previous_key_id !== "string") {
      throw new Error("claim-repository-conflict: reader-removal rotation must name the previous key epoch");
    }
    if (removed.some((nid) => readers.includes(nid))) {
      throw new Error("claim-repository-conflict: removed reader retained in rotated audience");
    }
    if ([...removed].sort().join("\0") !== [...accessRemoved].sort().join("\0")) {
      throw new Error("claim-ledger-reader-unauthorized: reader removal must remove matching Radicle access");
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
    payload.authority === "claim-ledger-reader" &&
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

function assertAllowedAndRequiredKeys(
  value: object,
  allowed: readonly string[],
  required: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value);
  if (actual.some((key) => !allowed.includes(key)) || required.some((key) => !actual.includes(key))) {
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

function validateReductionEvidence(
  value: JsonValue | undefined,
  claimId: string,
  authority: ReductionEvidence["authority"],
): void {
  const evidence = payloadObject(value);
  assertExactKeys(
    evidence,
    ["claim_id", "event_id", "authority", "validated_at", "core_kel_authority_valid", "evidence_digest"],
    "reduction evidence",
  );
  assertClaimId(evidence.claim_id);
  assertClaimId(evidence.event_id);
  if (evidence.claim_id !== claimId || evidence.authority !== authority ||
      evidence.core_kel_authority_valid !== true || !Number.isSafeInteger(evidence.validated_at) ||
      (evidence.validated_at as number) < 0) {
    throw new Error("claim-revoker-unauthorized: reduction evidence is not bound to the target claim and authority");
  }
  const { evidence_digest: digest, ...unsigned } = evidence;
  if (typeof digest !== "string" || digest !== digestJson(unsigned)) {
    throw new Error("claim-revoker-unauthorized: reduction evidence digest mismatch");
  }
}

function readerDenied(state: ClaimState, reason_code: string): AuthorizationDecision {
  return { allowed: false, state, reason_code };
}

function validReaderClaimCandidate(
  claim: ClaimSemanticBody,
  readerNid: string,
  state: LedgerMergeResult,
): boolean {
  try {
    validateKeyClaimSchemaOrThrow(claim);
    validateClaimId(claim);
  } catch {
    return false;
  }
  if (
    claim.claim_class !== "authorization" ||
    claim.namespace !== "heterodyne.device" ||
    claim.name !== "claim-ledger-reader" ||
    claim.value !== true ||
    claim.visibility !== "repository-private" ||
    claim.subject.type !== "radicle-ed25519-nid" ||
    claim.subject.value !== readerNid ||
    !claim.resources?.includes(`${state.checkpoint.repository_rid}#claim-ledger`)
  ) {
    return false;
  }
  const claimRecords = state.records.filter(
    (record) => record.record_type === "claim" && recordClaimId(record) === claim.claim_id,
  );
  if (claimRecords.length === 0) return true;
  const persona = claimRecords[0].persona;
  if (!claim.audience?.includes(persona)) return false;
  return claimRecords.every((record) =>
    jcsCanonicalize(payloadObject(record.payload).claim) === jcsCanonicalize(claim)
  );
}
