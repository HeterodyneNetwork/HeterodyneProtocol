import { Ajv, type AnySchema, type ValidateFunction } from "ajv";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import acceptanceSchema from "../../../schemas/assurance/active-key-acceptance-v1.schema.json" with { type: "json" };
import associatedKeySchema from "../../../schemas/assurance/associated-key-v1.schema.json" with { type: "json" };
import inceptionSchema from "../../../schemas/assurance/enrollment-inception-v1.schema.json" with { type: "json" };
import successionSchema from "../../../schemas/assurance/succession-v1.schema.json" with { type: "json" };
import { domainSeparatedJcsDigest } from "./credential-continuity.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";

export {
  createAssuranceEnrollmentObservationAuthority,
  evaluateEnrollmentEligibility,
} from "./assurance-observation.js";
export type {
  AssuranceEnrollmentAuthoritativePin,
  AssuranceEnrollmentObservationAuthority,
  EnrollmentEvidenceInput,
  EnrollmentObservationAuthorityConfig,
  EnrollmentObservationJournal,
  EnrollmentObservationJournalEntry,
  EnrollmentWitnessPolicy,
} from "./assurance-observation.js";

export type EpochPolicy = {
  mode: "none" | "pre-rotation";
  current_keys: string[];
  next_key_commitments: string[];
};

export type WitnessPolicy = { key: string; weight: number };
export type ThresholdPolicy = { epoch: number; witness: number };
export type AssociatedKeyGrantCeiling = { role: string; scope: string[] };
export type AssociatedKeyPolicy = {
  active_key: AssociatedKeyGrantCeiling[];
  epoch_threshold: AssociatedKeyGrantCeiling[];
};

export type EnrollmentInception = {
  profile: "heterodyne.assurance.enrollment-inception.v1";
  spec_version: "heterodyne/0.6.0";
  active_key: string;
  created_at: number;
  predecessor: null;
  cold_root: string;
  succession_authority: string | null;
  epoch_policy: EpochPolicy;
  witnesses: WitnessPolicy[];
  thresholds: ThresholdPolicy;
  associated_key_policy: AssociatedKeyPolicy;
};

export type AssuranceHeadState = {
  active_key: string;
  head: string;
  head_created_at: number;
  inception_event_id: string;
  inception_signature: string;
  cold_root: string;
  succession_authority: string | null;
  epoch_policy: EpochPolicy;
  witnesses: WitnessPolicy[];
  thresholds: ThresholdPolicy;
  associated_key_policy: AssociatedKeyPolicy;
  compromise_cutoff: number | null;
};

export type AuthorityProof = { authority_key: string; signature: string };
export type WitnessReceipt = { witness_key: string; signature: string };
export type SubordinateReauthorization = {
  role: string;
  subject_key: string;
  scope: string[];
  expires_at: number | null;
};
export type SuccessionRecord = {
  profile: "heterodyne.assurance.succession.v1";
  spec_version: "heterodyne/0.6.0";
  active_key: string;
  created_at: number;
  predecessor: string;
  previous_active_key: string;
  previous_head: string;
  new_active_key: string;
  authorizing_evidence: {
    authority_class: "succession" | "recovery" | "epoch-threshold";
    authority_proofs: AuthorityProof[];
    witness_receipts: WitnessReceipt[];
  };
  new_key_acceptance: { key: string; signature: string };
  class: "routine" | "compromise";
  compromise_time?: number;
  next_succession_authority: string | null;
  next_epoch_policy: EpochPolicy;
  witnesses: WitnessPolicy[];
  thresholds: ThresholdPolicy;
  next_associated_key_policy: AssociatedKeyPolicy;
  subordinate_reauthorizations: SubordinateReauthorization[];
};

export type SuccessionResult = {
  succession_event_id: string;
  transition_digest: string;
  new_active_key: string;
  compromise_cutoff: number | null;
  record: SuccessionRecord;
};

export type AssociatedKeyRecord = {
  profile: "heterodyne.assurance.associated-key.v1";
  spec_version: "heterodyne/0.6.0";
  active_key: string;
  created_at: number;
  predecessor: string;
  assurance_head: string;
  role: string;
  scope: string[];
  issuer: string;
  issuer_authority: {
    class: "active-key" | "epoch-threshold";
    authority_proofs: AuthorityProof[];
  };
  subject_key: string;
  expires_at?: number;
  visibility: "public" | "private";
  subject_proof?: string;
  state: "active" | "revoked";
  revocation?: {
    revoked_at: number;
    reason: "operator-request" | "expiry" | "compromise" | "superseded";
  };
};

export type AssociatedKeyState = {
  event_id: string;
  state: "active" | "revoked";
  active_key: string;
  assurance_head: string;
  role: string;
  scope: string[];
  issuer: string;
  subject_key: string;
};

export type AssociatedKeyVerdict = AssuranceVerdict<AssociatedKeyState> | {
  verdict: "reject";
  reason_code: "assurance-associated-key-revoked";
  normalized: AssociatedKeyState;
};

type ActiveKeyAcceptance = {
  profile: "heterodyne.assurance.active-key-acceptance.v1";
  spec_version: "heterodyne/0.6.0";
  active_key: string;
  created_at: number;
  predecessor: string;
  inception_event_id: string;
  cold_root: string;
  cold_root_signature: string;
  assurance_head: string;
  state: "assured" | "downgraded";
};

export type AssuranceVerdict<T> =
  | { verdict: "accept"; normalized: T }
  | { verdict: "reject"; reason_code: string };

export type EnrollmentObservationReceipt = {
  profile: "heterodyne.assurance.enrollment-observation-receipt.v1";
  spec_version: "heterodyne/0.6.0";
  inception_event_id: string;
  active_key: string;
  cold_root: string;
  accepted_head: string;
  first_observed_at: number;
  last_observed_at: number;
  conflict_free: true;
  witness_key: string;
  signature: string;
};

export type AssuranceEnrollmentEligibility = {
  state: "pending" | "verified" | "contested";
  reason: "assurance-enrollment-pending-window" |
    "assurance-enrollment-contested" | null;
  warnings: Array<"assurance-enrollment-contested">;
  normalized: AssuranceHeadState;
};

const ajv = new Ajv({ allErrors: true, strict: false });
const validateInception = ajv.compile(inceptionSchema as AnySchema);
const validateAcceptance = ajv.compile(acceptanceSchema as AnySchema);
const validateAssociatedKey = ajv.compile(associatedKeySchema as AnySchema);
const validateSuccession = ajv.compile(successionSchema as AnySchema);

export function evaluateEnrollment(input: {
  inception: NostrSignedEvent;
  acceptance: NostrSignedEvent;
}): AssuranceVerdict<AssuranceHeadState> {
  const candidate = snapshotEnrollmentCandidate(input);
  if (candidate === null) return reciprocalReject();
  return evaluateVerifiedEnrollment(candidate.inception, candidate.acceptance);
}

function snapshotEnrollmentCandidate(input: {
  inception: NostrSignedEvent;
  acceptance: NostrSignedEvent;
}): { inception: VerifiedNostrEvent; acceptance: VerifiedNostrEvent } | null {
  let inceptionInput: NostrSignedEvent;
  let acceptanceInput: NostrSignedEvent;
  try {
    inceptionInput = input.inception;
    acceptanceInput = input.acceptance;
  } catch {
    return null;
  }
  const inception = snapshotAndVerifyNostrEvent(inceptionInput);
  const acceptance = snapshotAndVerifyNostrEvent(acceptanceInput);
  if (inception === null || acceptance === null) return null;
  return Object.freeze({ inception, acceptance });
}

function evaluateVerifiedEnrollment(
  inceptionEvent: VerifiedNostrEvent,
  acceptanceEvent: VerifiedNostrEvent,
): AssuranceVerdict<AssuranceHeadState> {
  const inception = parseRecord<EnrollmentInception>(
    inceptionEvent,
    31002,
    validateInception,
  );
  const acceptance = parseRecord<ActiveKeyAcceptance>(
    acceptanceEvent,
    31000,
    validateAcceptance,
  );
  if (inception === null || acceptance === null) return reciprocalReject();
  if (!hasExactTags(inceptionEvent, [
    ["d", `assurance-inception:${inception.active_key}`],
    ["profile", inception.profile],
    ["p", inception.active_key],
  ]) || !hasExactTags(acceptanceEvent, [
    ["d", "assurance-head"],
    ["profile", acceptance.profile],
  ])) {
    return reciprocalReject();
  }
  if (!validPolicy(inception.epoch_policy, inception.witnesses, inception.thresholds)) {
    return reciprocalReject();
  }
  if (
    inceptionEvent.pubkey !== inception.cold_root ||
    acceptanceEvent.pubkey !== inception.active_key ||
    acceptance.active_key !== inception.active_key ||
    acceptance.predecessor !== inceptionEvent.id ||
    acceptance.inception_event_id !== inceptionEvent.id ||
    acceptance.assurance_head !== inceptionEvent.id ||
    acceptance.cold_root !== inception.cold_root ||
    acceptance.cold_root_signature !== inceptionEvent.sig ||
    acceptance.created_at < inception.created_at ||
    acceptance.state !== "assured"
  ) {
    return reciprocalReject();
  }
  return {
    verdict: "accept",
    normalized: {
      active_key: inception.active_key,
      head: acceptanceEvent.id,
      head_created_at: acceptanceEvent.created_at,
      inception_event_id: inceptionEvent.id,
      inception_signature: inceptionEvent.sig,
      cold_root: inception.cold_root,
      succession_authority: inception.succession_authority,
      epoch_policy: inception.epoch_policy,
      witnesses: inception.witnesses,
      thresholds: inception.thresholds,
      associated_key_policy: inception.associated_key_policy,
      compromise_cutoff: null,
    },
  };
}

export function successionTransitionDigest(record: SuccessionRecord): string {
  const transition = {
    ...record,
    authorizing_evidence: {
      authority_class: record.authorizing_evidence.authority_class,
      authority_proofs: record.authorizing_evidence.authority_proofs.map(
        ({ signature: _signature, ...bound }) => bound,
      ),
      witness_receipts: record.authorizing_evidence.witness_receipts.map(
        ({ signature: _signature, ...bound }) => bound,
      ),
    },
    new_key_acceptance: { key: record.new_key_acceptance.key },
  };
  return domainSeparatedJcsDigest(
    "heterodyne-assurance-succession-transition-v1",
    transition,
  );
}

export function evaluateSuccession(input: {
  current: AssuranceHeadState;
  event: NostrSignedEvent;
}): AssuranceVerdict<SuccessionResult> {
  const event = snapshotAndVerifyNostrEvent(input.event);
  if (event === null) return reject("assurance-schema-invalid");
  const record = parseRecord<SuccessionRecord>(
    event,
    31003,
    validateSuccession,
  );
  if (record === null || !hasExactTags(event, [
    ["d", `assurance-succession:${record?.previous_head ?? ""}`],
    ["profile", record?.profile ?? ""],
    ["p", record?.active_key ?? ""],
    ["p", record?.new_active_key ?? ""],
  ])) return reject("assurance-schema-invalid");

  if (record.predecessor !== input.current.head) {
    return reject("assurance-predecessor-mismatch");
  }
  if (
    record.previous_head !== input.current.head ||
    record.active_key !== input.current.active_key ||
    record.previous_active_key !== input.current.active_key
  ) return reject("assurance-head-mismatch");
  if (record.new_active_key === input.current.active_key) {
    return reject("assurance-new-key-acceptance-invalid");
  }

  if (record.class === "routine") {
    if (
      event.pubkey !== input.current.active_key ||
      record.authorizing_evidence.authority_class === "recovery"
    ) return reject("assurance-authority-invalid");
  } else {
    if (
      event.pubkey !== input.current.cold_root ||
      record.authorizing_evidence.authority_class !== "recovery"
    ) return reject("assurance-authority-invalid");
    if (
      record.compromise_time === undefined ||
      record.compromise_time < input.current.head_created_at ||
      record.compromise_time > record.created_at
    ) return reject("assurance-compromise-cutoff");
    if (record.subordinate_reauthorizations.length !== 0) {
      return reject("assurance-subordinate-continuation-forbidden");
    }
  }

  if (!validPolicy(record.next_epoch_policy, record.witnesses, record.thresholds)) {
    return reject("assurance-authority-invalid");
  }
  if (
    input.current.epoch_policy.mode === "pre-rotation" &&
    record.next_epoch_policy.current_keys.some(
      (key) => !input.current.epoch_policy.next_key_commitments.includes(
        bytesToHex(sha256(hexToBytes(key))),
      ),
    )
  ) return reject("assurance-authority-invalid");

  const digest = successionTransitionDigest(record);
  if (!validSuccessionAuthority(input.current, record, digest)) {
    return reject("assurance-authority-invalid");
  }
  if (
    record.new_key_acceptance.key !== record.new_active_key ||
    !validSchnorr(
      record.new_key_acceptance.signature,
      digest,
      record.new_key_acceptance.key,
    )
  ) return reject("assurance-new-key-acceptance-invalid");
  if (!validWitnessThreshold(input.current, record, digest)) {
    return reject("assurance-witness-threshold-unsatisfied");
  }

  return {
    verdict: "accept",
    normalized: {
      succession_event_id: event.id,
      transition_digest: digest,
      new_active_key: record.new_active_key,
      compromise_cutoff: record.compromise_time ?? null,
      record,
    },
  };
}

export function evaluateAssuranceAuthorityAt(
  createdAt: number,
  compromiseCutoff: number | null,
): AssuranceVerdict<{ created_at: number }> {
  return compromiseCutoff !== null && createdAt >= compromiseCutoff
    ? reject("assurance-compromise-cutoff")
    : { verdict: "accept", normalized: { created_at: createdAt } };
}

export function evaluateSuccessorAcceptance(input: {
  current: AssuranceHeadState;
  succession: NostrSignedEvent;
  acceptance: NostrSignedEvent;
}): AssuranceVerdict<AssuranceHeadState> {
  const succession = evaluateSuccession({
    current: input.current,
    event: input.succession,
  });
  if (succession.verdict === "reject") return succession;
  const pending = succession.normalized;
  const acceptanceEvent = snapshotAndVerifyNostrEvent(input.acceptance);
  if (acceptanceEvent === null) return reciprocalReject();
  const acceptance = parseRecord<ActiveKeyAcceptance>(
    acceptanceEvent,
    31000,
    validateAcceptance,
  );
  if (acceptance === null || !hasExactTags(acceptanceEvent, [
    ["d", "assurance-head"],
    ["profile", acceptance?.profile ?? ""],
  ])) return reciprocalReject();
  if (
    acceptanceEvent.pubkey !== pending.new_active_key ||
    acceptance.active_key !== pending.new_active_key ||
    acceptance.inception_event_id !== input.current.inception_event_id ||
    acceptance.cold_root !== input.current.cold_root ||
    acceptance.cold_root_signature !== input.current.inception_signature ||
    acceptance.state !== "assured"
  ) return reciprocalReject();
  if (
    acceptance.predecessor !== pending.succession_event_id ||
    acceptance.assurance_head !== pending.succession_event_id
  ) return reject("assurance-head-mismatch");
  if (acceptance.created_at < pending.record.created_at) {
    return reject("assurance-head-mismatch");
  }
  return {
    verdict: "accept",
    normalized: {
      active_key: pending.new_active_key,
      head: acceptanceEvent.id,
      head_created_at: acceptanceEvent.created_at,
      inception_event_id: input.current.inception_event_id,
      inception_signature: input.current.inception_signature,
      cold_root: input.current.cold_root,
      succession_authority: pending.record.next_succession_authority,
      epoch_policy: pending.record.next_epoch_policy,
      witnesses: pending.record.witnesses,
      thresholds: pending.record.thresholds,
      associated_key_policy: pending.record.next_associated_key_policy,
      compromise_cutoff: pending.compromise_cutoff,
    },
  };
}

export function associatedKeyRecordDigest(record: AssociatedKeyRecord): string {
  const { subject_proof: _subjectProof, ...withoutSubjectProof } = record;
  const bound = {
    ...withoutSubjectProof,
    issuer_authority: {
      class: record.issuer_authority.class,
      authority_proofs: record.issuer_authority.authority_proofs.map(
        ({ signature: _signature, ...proofKey }) => proofKey,
      ),
    },
  };
  return domainSeparatedJcsDigest(
    "heterodyne-assurance-associated-key-record-v1",
    bound,
  );
}

export function evaluateAssociatedKey(input: {
  current: AssuranceHeadState;
  event: NostrSignedEvent;
  now: number;
  previous: AssociatedKeyState | null;
}): AssociatedKeyVerdict {
  const event = snapshotAndVerifyNostrEvent(input.event);
  if (event === null) return reject("assurance-schema-invalid");
  const record = parseRecord<AssociatedKeyRecord>(
    event,
    31001,
    validateAssociatedKey,
  );
  if (record === null || !hasExactTags(event, [
    ["d", `assurance-associated:${record?.active_key ?? ""}:${record?.role ?? ""}:${record?.subject_key ?? ""}`],
    ["profile", record?.profile ?? ""],
    ["p", record?.active_key ?? ""],
  ])) return reject("assurance-schema-invalid");
  if (record.assurance_head !== input.current.head) {
    return reject("assurance-head-mismatch");
  }
  if (record.active_key !== input.current.active_key) {
    return reject("assurance-head-mismatch");
  }
  const expectedPredecessor = input.previous?.event_id ?? input.current.head;
  if (record.predecessor !== expectedPredecessor) {
    return reject("assurance-predecessor-mismatch");
  }
  if (input.previous !== null && (
    input.previous.active_key !== record.active_key ||
    input.previous.assurance_head !== record.assurance_head ||
    input.previous.role !== record.role ||
    input.previous.issuer !== record.issuer ||
    input.previous.subject_key !== record.subject_key
  )) return reject("assurance-predecessor-mismatch");
  if (input.previous?.state === "revoked") {
    return {
      verdict: "reject",
      reason_code: "assurance-associated-key-revoked",
      normalized: input.previous,
    };
  }
  if (event.pubkey !== record.issuer) {
    return reject("assurance-authority-invalid");
  }

  const digest = associatedKeyRecordDigest(record);
  const ceilings = record.issuer_authority.class === "active-key"
    ? input.current.associated_key_policy.active_key
    : input.current.associated_key_policy.epoch_threshold;
  if (!ceilings.some((ceiling) =>
    ceiling.role === record.role && isSubset(record.scope, ceiling.scope))) {
    return reject("assurance-authority-invalid");
  }
  if (!validAssociatedIssuer(input.current, record, digest)) {
    return reject("assurance-authority-invalid");
  }

  if (
    record.state === "active" &&
    record.role === "agent" &&
    record.visibility === "public"
  ) {
    if (record.subject_proof === undefined) {
      return reject("assurance-associated-key-subject-proof-required");
    }
    if (!validSchnorr(record.subject_proof, digest, record.subject_key)) {
      return reject("assurance-associated-key-subject-proof-invalid");
    }
  }

  if (record.state === "revoked") {
    return {
      verdict: "reject",
      reason_code: "assurance-associated-key-revoked",
      normalized: associatedKeyState(record, event.id),
    };
  }
  if (record.expires_at !== undefined && input.now >= record.expires_at) {
    return reject("assurance-associated-key-expired");
  }
  return {
    verdict: "accept",
    normalized: associatedKeyState(record, event.id),
  };
}

function parseRecord<T>(
  event: VerifiedNostrEvent,
  kind: number,
  validate: ValidateFunction,
): T | null {
  try {
    if (event.kind !== kind) return null;
    const value = JSON.parse(event.content) as unknown;
    if (event.content !== jcsCanonicalize(value) || !validate(value)) return null;
    if (
      typeof value !== "object" || value === null ||
      (value as { created_at?: unknown }).created_at !== event.created_at
    ) return null;
    return deepFreeze(value) as T;
  } catch {
    return null;
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function hasExactTags(event: NostrSignedEvent, expected: string[][]): boolean {
  const canonical = (tags: string[][]) => tags.map((tag) => JSON.stringify(tag)).sort();
  return JSON.stringify(canonical(event.tags)) === JSON.stringify(canonical(expected));
}

function reciprocalReject(): AssuranceVerdict<never> {
  return { verdict: "reject", reason_code: "assurance-reciprocal-proof-invalid" };
}

function reject(reason_code: string): AssuranceVerdict<never> {
  return { verdict: "reject", reason_code };
}

function validPolicy(
  epoch: EpochPolicy,
  witnesses: WitnessPolicy[],
  thresholds: ThresholdPolicy,
): boolean {
  if (new Set(epoch.current_keys).size !== epoch.current_keys.length) return false;
  if (new Set(epoch.next_key_commitments).size !== epoch.next_key_commitments.length) return false;
  if (new Set(witnesses.map(({ key }) => key)).size !== witnesses.length) return false;
  if (epoch.mode === "none") {
    if (
      epoch.current_keys.length !== 0 ||
      epoch.next_key_commitments.length !== 0 ||
      thresholds.epoch !== 0
    ) return false;
  } else if (
    epoch.current_keys.length === 0 ||
    epoch.next_key_commitments.length === 0 ||
    thresholds.epoch < 1 ||
    thresholds.epoch > epoch.current_keys.length
  ) return false;
  const witnessWeight = witnesses.reduce((sum, witness) => sum + witness.weight, 0);
  return witnesses.length === 0
    ? thresholds.witness === 0
    : thresholds.witness >= 1 && thresholds.witness <= witnessWeight;
}

function validSuccessionAuthority(
  current: AssuranceHeadState,
  record: SuccessionRecord,
  digest: string,
): boolean {
  const proofs = record.authorizing_evidence.authority_proofs;
  const keys = proofs.map(({ authority_key }) => authority_key);
  if (new Set(keys).size !== keys.length) return false;
  if (!proofs.every(({ authority_key, signature }) =>
    validSchnorr(signature, digest, authority_key))) return false;

  switch (record.authorizing_evidence.authority_class) {
    case "succession":
      return current.succession_authority !== null &&
        proofs.length === 1 && keys[0] === current.succession_authority;
    case "recovery":
      return proofs.length === 1 && keys[0] === current.cold_root;
    case "epoch-threshold":
      return current.epoch_policy.mode === "pre-rotation" &&
        proofs.length >= current.thresholds.epoch &&
        keys.every((key) => current.epoch_policy.current_keys.includes(key));
  }
}

function validWitnessThreshold(
  current: AssuranceHeadState,
  record: SuccessionRecord,
  digest: string,
): boolean {
  const receipts = record.authorizing_evidence.witness_receipts;
  const keys = receipts.map(({ witness_key }) => witness_key);
  if (new Set(keys).size !== keys.length) return false;
  let weight = 0;
  for (const receipt of receipts) {
    const configured = current.witnesses.find(({ key }) => key === receipt.witness_key);
    if (
      configured === undefined ||
      !validSchnorr(receipt.signature, digest, receipt.witness_key)
    ) return false;
    weight += configured.weight;
  }
  return weight >= current.thresholds.witness;
}

function validSchnorr(signature: string, digest: string, key: string): boolean {
  try {
    return schnorr.verify(signature, digest, key);
  } catch {
    return false;
  }
}

function validAssociatedIssuer(
  current: AssuranceHeadState,
  record: AssociatedKeyRecord,
  digest: string,
): boolean {
  const proofs = record.issuer_authority.authority_proofs;
  if (record.issuer_authority.class === "active-key") {
    return record.issuer === current.active_key && proofs.length === 0;
  }
  const keys = proofs.map(({ authority_key }) => authority_key);
  return current.epoch_policy.mode === "pre-rotation" &&
    current.epoch_policy.current_keys.includes(record.issuer) &&
    new Set(keys).size === keys.length &&
    proofs.length >= current.thresholds.epoch &&
    proofs.every(({ authority_key, signature }) =>
      current.epoch_policy.current_keys.includes(authority_key) &&
      validSchnorr(signature, digest, authority_key));
}

function isSubset(values: string[], ceiling: string[]): boolean {
  const allowed = new Set(ceiling);
  return values.every((value) => allowed.has(value));
}

function associatedKeyState(
  record: AssociatedKeyRecord,
  event_id: string,
): AssociatedKeyState {
  return {
    event_id,
    state: record.state,
    active_key: record.active_key,
    assurance_head: record.assurance_head,
    role: record.role,
    scope: record.scope,
    issuer: record.issuer,
    subject_key: record.subject_key,
  };
}
