import { types as utilTypes } from "node:util";
import { Ajv, type AnySchema } from "ajv";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import contestSchema from "../../../schemas/assurance/enrollment-contest-v1.schema.json" with { type: "json" };
import observationReceiptSchema from "../../../schemas/assurance/enrollment-observation-receipt-v1.schema.json" with { type: "json" };
import {
  evaluateEnrollment,
  type AssuranceEnrollmentEligibility,
  type AssuranceHeadState,
  type AssuranceVerdict,
  type EnrollmentInception,
  type EnrollmentObservationReceipt,
} from "./assurance.js";
import { domainSeparatedJcsDigest } from "./credential-continuity.js";
import { bytesToHex } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";

const ENROLLMENT_WINDOW_SECONDS = 604_800;
const ENROLLMENT_OBSERVATION_DOMAIN =
  "heterodyne-assurance-enrollment-observation-v1";
const ENROLLMENT_PIN_BASIS_DOMAIN =
  "heterodyne-assurance-enrollment-pin-basis-v1";
const MAX_CAS_ATTEMPTS = 16;

export type EnrollmentWitnessPolicy = Readonly<{
  policy_digest: string;
  minimum_weight: number;
  witnesses: ReadonlyMap<string, number>;
}>;

export type EnrollmentObservationWitnessState = Readonly<{
  witness_key: string;
  first_ingested_at: number;
  latest_ingested_at: number;
  first_observed_at: number;
  last_observed_at: number;
  receipt_digests: readonly string[];
}>;

export type EnrollmentObservationConflict = Readonly<{
  digest: string;
  first_ingested_at: number;
  kind: "contest" | "competing-enrollment";
}>;

export type EnrollmentEligibilityBasis = Readonly<{
  authority_id: string;
  active_key: string;
  inception_event_id: string;
  cold_root: string;
  accepted_head: string;
  closing_revision: number;
  start_ingested_at: number;
  closed_at: number;
  mode: "local" | "witness";
  qualifying_receipt_digests: readonly string[];
  witness_policy_digest: string;
  conflict_digests: readonly string[];
}>;

export type AssuranceEnrollmentAuthoritativePin = Readonly<{
  active_key: string;
  inception_event_id: string;
  cold_root: string;
  accepted_head: string;
  state: "verified";
  observed_at: number;
  authority_id: string;
  eligibility_basis: EnrollmentEligibilityBasis;
  eligibility_basis_digest: string;
}>;

export type EnrollmentObservationJournalEntry = Readonly<{
  revision: number;
  authority_id: string;
  active_key: string;
  inception_event_id: string;
  cold_root: string;
  accepted_head: string;
  policy_digest: string;
  first_candidate_ingested_at: number;
  evidence_digests: readonly string[];
  witnesses: Readonly<Record<string, EnrollmentObservationWitnessState>>;
  conflicts: readonly EnrollmentObservationConflict[];
  contested: boolean;
  pin: AssuranceEnrollmentAuthoritativePin | null;
}>;

export type EnrollmentObservationJournal = {
  load(key: string): EnrollmentObservationJournalEntry | null;
  compareAndSwap(
    key: string,
    expectedRevision: number | null,
    next: EnrollmentObservationJournalEntry,
  ): "committed" | "conflict";
};

export type EnrollmentObservationAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  witness_policy: EnrollmentWitnessPolicy;
  journal: EnrollmentObservationJournal;
}>;

export type EnrollmentEvidenceInput = Readonly<{
  witness_receipts: readonly EnrollmentObservationReceipt[];
  contests: readonly NostrSignedEvent[];
  competing_enrollments: readonly Readonly<{
    inception: NostrSignedEvent;
    acceptance: NostrSignedEvent;
  }>[];
}>;

declare const assuranceEnrollmentObservationAuthorityBrand: unique symbol;
export type AssuranceEnrollmentObservationAuthority = Readonly<{
  [assuranceEnrollmentObservationAuthorityBrand]: true;
}>;

type CapturedAuthority = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  policy_digest: string;
  minimum_weight: number;
  witnesses: ReadonlyMap<string, number>;
  load: EnrollmentObservationJournal["load"];
  compare_and_swap: EnrollmentObservationJournal["compareAndSwap"];
  retained_pins: Map<string, string>;
}>;

type Candidate = Readonly<{
  inception: VerifiedNostrEvent;
  acceptance: VerifiedNostrEvent;
  enrollment: AssuranceHeadState;
  inception_body: EnrollmentInception;
}>;

const AUTHORITIES = new WeakMap<object, CapturedAuthority>();
const ajv = new Ajv({ allErrors: true, strict: false });
const validateContest = ajv.compile(contestSchema as AnySchema);
const validateObservationReceipt = ajv.compile(
  observationReceiptSchema as AnySchema,
);

export function createAssuranceEnrollmentObservationAuthority(
  config: EnrollmentObservationAuthorityConfig,
): AssuranceEnrollmentObservationAuthority {
  const captured = exactRecord(config, [
    "authority_id",
    "trusted_now",
    "witness_policy",
    "journal",
  ]);
  if (captured === null) throw observationAuthorityInvalid();
  const policy = exactRecord(captured.witness_policy, [
    "policy_digest",
    "minimum_weight",
    "witnesses",
  ]);
  const journal = captureJournal(captured.journal);
  if (
    typeof captured.authority_id !== "string" || captured.authority_id === "" ||
    typeof captured.trusted_now !== "function" ||
    utilTypes.isProxy(captured.trusted_now) ||
    policy === null ||
    typeof policy.policy_digest !== "string" ||
    !isDigest(policy.policy_digest) ||
    !Number.isSafeInteger(policy.minimum_weight) ||
    (policy.minimum_weight as number) < 0 ||
    !(policy.witnesses instanceof Map) || utilTypes.isProxy(policy.witnesses) ||
    journal === null ||
    typeof journal.load !== "function" || utilTypes.isProxy(journal.load) ||
    typeof journal.compareAndSwap !== "function" ||
    utilTypes.isProxy(journal.compareAndSwap)
  ) throw observationAuthorityInvalid();

  const witnesses = new Map<string, number>();
  try {
    for (const [key, weight] of policy.witnesses as ReadonlyMap<unknown, unknown>) {
      if (
        typeof key !== "string" || !isHex32(key) ||
        !Number.isSafeInteger(weight) || (weight as number) <= 0 ||
        witnesses.has(key)
      ) throw observationAuthorityInvalid();
      witnesses.set(key, weight as number);
    }
  } catch (error) {
    if (error instanceof Error && error.message.includes("observation-authority-invalid")) {
      throw error;
    }
    throw observationAuthorityInvalid();
  }

  const authority = Object.freeze({});
  AUTHORITIES.set(authority, Object.freeze({
    authority_id: captured.authority_id,
    trusted_now: captured.trusted_now as () => number,
    policy_digest: policy.policy_digest,
    minimum_weight: policy.minimum_weight as number,
    witnesses,
    load: (journal.load as EnrollmentObservationJournal["load"]).bind(
      captured.journal,
    ),
    compare_and_swap: (
      journal.compareAndSwap as EnrollmentObservationJournal["compareAndSwap"]
    ).bind(captured.journal),
    retained_pins: new Map<string, string>(),
  }));
  return authority as AssuranceEnrollmentObservationAuthority;
}

export async function evaluateEnrollmentEligibility(
  authority: AssuranceEnrollmentObservationAuthority,
  input: Readonly<{
    inception: NostrSignedEvent;
    acceptance: NostrSignedEvent;
    evidence: EnrollmentEvidenceInput;
  }>,
): Promise<AssuranceEnrollmentEligibility | AssuranceVerdict<never>> {
  const captured = authority !== null && typeof authority === "object"
    ? AUTHORITIES.get(authority)
    : undefined;
  if (captured === undefined) throw observationAuthorityInvalid();

  const candidate = captureCandidate(input);
  if (candidate === null) return reciprocalReject();
  const evidence = captureEvidence(input);
  if (evidence === null) return pending(candidate.enrollment);
  const key = journalKey(candidate.enrollment);
  const retained = captured.retained_pins.get(candidate.enrollment.active_key);
  if (retained !== undefined && retained !== key) return pinConflict();

  let now: number;
  try {
    now = captured.trusted_now();
  } catch {
    throw observationAuthorityInvalid();
  }
  if (!isUnixTime(now)) throw observationAuthorityInvalid();

  for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt += 1) {
    let loaded: unknown;
    try {
      loaded = captured.load(key);
    } catch {
      throw observationAuthorityInvalid();
    }
    let entry = snapshotJournalEntry(loaded);
    const expectedRevision = entry?.revision ?? null;
    if (loaded !== null && entry === null) return pinConflict();
    const created = entry === null;
    if (entry === null) {
      entry = initialEntry(captured, candidate.enrollment, now);
    } else if (!entryMatches(entry, captured, candidate.enrollment)) {
      return pinConflict();
    }
    if (entry.pin !== null && !validRetainedPin(entry.pin, entry)) {
      return pinConflict();
    }

    const ingested = ingestEvidence(entry, candidate, evidence, captured, now);
    if (ingested === null) return pending(candidate.enrollment);
    entry = ingested.entry;
    const changed = created || ingested.changed;

    if (entry.contested) {
      if (changed && !commit(captured, key, expectedRevision, entry)) continue;
      return contested(candidate.enrollment);
    }

    if (entry.pin !== null) {
      if (changed && !commit(captured, key, expectedRevision, entry)) continue;
      captured.retained_pins.set(candidate.enrollment.active_key, key);
      return verified(candidate.enrollment, entry.conflicts.length > 0);
    }

    const witness = qualifyingWitnessReceipts(entry, candidate, captured, now);
    const localMature = elapsed(entry.first_candidate_ingested_at, now);
    if (witness === null && !localMature) {
      if (changed && !commit(captured, key, expectedRevision, entry)) continue;
      return pending(candidate.enrollment);
    }

    const basis: EnrollmentEligibilityBasis = {
      authority_id: captured.authority_id,
      active_key: candidate.enrollment.active_key,
      inception_event_id: candidate.enrollment.inception_event_id,
      cold_root: candidate.enrollment.cold_root,
      accepted_head: candidate.enrollment.head,
      closing_revision: expectedRevision === null ? 0 : expectedRevision + 1,
      start_ingested_at: witness?.start ?? entry.first_candidate_ingested_at,
      closed_at: now,
      mode: witness === null ? "local" : "witness",
      qualifying_receipt_digests: witness?.digests ?? [],
      witness_policy_digest: captured.policy_digest,
      conflict_digests: [],
    };
    const closed = snapshotJournalEntry({
      ...entry,
      revision: basis.closing_revision,
      pin: {
        active_key: candidate.enrollment.active_key,
        inception_event_id: candidate.enrollment.inception_event_id,
        cold_root: candidate.enrollment.cold_root,
        accepted_head: candidate.enrollment.head,
        state: "verified",
        observed_at: now,
        authority_id: captured.authority_id,
        eligibility_basis: basis,
        eligibility_basis_digest: basisDigest(basis),
      },
    });
    if (closed === null) throw observationAuthorityInvalid();
    if (!commit(captured, key, expectedRevision, closed)) continue;
    captured.retained_pins.set(candidate.enrollment.active_key, key);
    return verified(candidate.enrollment, false);
  }
  throw observationAuthorityInvalid();
}

function captureCandidate(input: unknown): Candidate | null {
  const record = exactRecord(input, ["inception", "acceptance", "evidence"]);
  if (record === null) return null;
  const inception = snapshotAndVerifyNostrEvent(record.inception as NostrSignedEvent);
  const acceptance = snapshotAndVerifyNostrEvent(record.acceptance as NostrSignedEvent);
  if (inception === null || acceptance === null) return null;
  const verdict = evaluateEnrollment({ inception, acceptance });
  if (verdict.verdict === "reject") return null;
  let body: unknown;
  try {
    body = JSON.parse(inception.content);
  } catch {
    return null;
  }
  const inceptionBody = snapshotInceptionBody(body);
  if (inceptionBody === null) return null;
  return Object.freeze({
    inception,
    acceptance,
    enrollment: immutableClone(verdict.normalized),
    inception_body: inceptionBody,
  });
}

function captureEvidence(input: unknown): EnrollmentEvidenceInput | null {
  const outer = exactRecord(input, ["inception", "acceptance", "evidence"]);
  if (outer === null) return null;
  const record = exactRecord(outer.evidence, [
    "witness_receipts",
    "contests",
    "competing_enrollments",
  ]);
  if (record === null) return null;
  const receiptValues = denseArray(record.witness_receipts);
  const contestValues = denseArray(record.contests);
  const competitorValues = denseArray(record.competing_enrollments);
  if (receiptValues === null || contestValues === null || competitorValues === null) {
    return null;
  }
  const witnessReceipts: EnrollmentObservationReceipt[] = [];
  for (const value of receiptValues) {
    const receipt = snapshotReceipt(value);
    if (receipt !== null) witnessReceipts.push(receipt);
  }
  const contests: NostrSignedEvent[] = [];
  for (const value of contestValues) {
    const event = snapshotAndVerifyNostrEvent(value as NostrSignedEvent);
    if (event !== null) contests.push(event);
  }
  const competingEnrollments: Array<Readonly<{
    inception: NostrSignedEvent;
    acceptance: NostrSignedEvent;
  }>> = [];
  for (const value of competitorValues) {
    const competitor = exactRecord(value, ["inception", "acceptance"]);
    if (competitor === null) continue;
    const inception = snapshotAndVerifyNostrEvent(
      competitor.inception as NostrSignedEvent,
    );
    const acceptance = snapshotAndVerifyNostrEvent(
      competitor.acceptance as NostrSignedEvent,
    );
    if (inception !== null && acceptance !== null) {
      competingEnrollments.push(Object.freeze({ inception, acceptance }));
    }
  }
  return Object.freeze({
    witness_receipts: Object.freeze(witnessReceipts),
    contests: Object.freeze(contests),
    competing_enrollments: Object.freeze(competingEnrollments),
  });
}

function ingestEvidence(
  entry: EnrollmentObservationJournalEntry,
  candidate: Candidate,
  evidence: EnrollmentEvidenceInput,
  authority: CapturedAuthority,
  now: number,
): { entry: EnrollmentObservationJournalEntry; changed: boolean } | null {
  const next = mutableEntry(entry);
  let changed = false;
  const knownDigests = new Set(next.evidence_digests);

  for (const receipt of evidence.witness_receipts) {
    if (!receiptMatches(receipt, candidate, authority, now)) continue;
    const digest = evidenceDigest(receipt);
    if (knownDigests.has(digest)) continue;
    const current = next.witnesses[receipt.witness_key];
    if (
      current !== undefined &&
      (receipt.first_observed_at !== current.first_observed_at ||
        receipt.last_observed_at < current.last_observed_at)
    ) continue;
    knownDigests.add(digest);
    next.evidence_digests.push(digest);
    if (current === undefined) {
      next.witnesses[receipt.witness_key] = {
        witness_key: receipt.witness_key,
        first_ingested_at: now,
        latest_ingested_at: now,
        first_observed_at: receipt.first_observed_at,
        last_observed_at: receipt.last_observed_at,
        receipt_digests: [digest],
      };
    } else {
      next.witnesses[receipt.witness_key] = {
        ...current,
        latest_ingested_at: now,
        last_observed_at: receipt.last_observed_at,
        receipt_digests: [...current.receipt_digests, digest],
      };
    }
    changed = true;
  }

  for (const event of evidence.contests) {
    if (!validContest(event, candidate)) continue;
    if (knownDigests.has(event.id)) continue;
    knownDigests.add(event.id);
    next.evidence_digests.push(event.id);
    next.conflicts.push({
      digest: event.id,
      first_ingested_at: now,
      kind: "contest",
    });
    if (entry.pin === null) next.contested = true;
    changed = true;
  }

  for (const competitor of evidence.competing_enrollments) {
    const verdict = evaluateEnrollment(competitor);
    if (
      verdict.verdict === "reject" ||
      verdict.normalized.active_key !== candidate.enrollment.active_key ||
      verdict.normalized.inception_event_id === candidate.enrollment.inception_event_id
    ) continue;
    const digest = evidenceDigest({
      inception_event_id: verdict.normalized.inception_event_id,
      accepted_head: verdict.normalized.head,
    });
    if (knownDigests.has(digest)) continue;
    knownDigests.add(digest);
    next.evidence_digests.push(digest);
    next.conflicts.push({ digest, first_ingested_at: now, kind: "competing-enrollment" });
    if (entry.pin === null) next.contested = true;
    changed = true;
  }

  if (!changed) return { entry, changed: false };
  next.revision = entry.revision + 1;
  const snapshot = snapshotJournalEntry(next);
  return snapshot === null ? null : { entry: snapshot, changed: true };
}

function qualifyingWitnessReceipts(
  entry: EnrollmentObservationJournalEntry,
  candidate: Candidate,
  authority: CapturedAuthority,
  now: number,
): { start: number; digests: string[] } | null {
  let weight = 0;
  let start = now;
  const digests: string[] = [];
  for (const configured of candidate.inception_body.witnesses) {
    const localWeight = authority.witnesses.get(configured.key);
    const state = entry.witnesses[configured.key];
    if (
      localWeight === undefined || state === undefined ||
      state.receipt_digests.length < 2 ||
      !elapsed(state.first_ingested_at, state.latest_ingested_at) ||
      state.latest_ingested_at > now ||
      state.last_observed_at - state.first_observed_at < ENROLLMENT_WINDOW_SECONDS
    ) continue;
    weight += Math.min(configured.weight, localWeight);
    start = Math.min(start, state.first_ingested_at);
    digests.push(...state.receipt_digests);
  }
  if (
    candidate.inception_body.thresholds.witness <= 0 ||
    weight < candidate.inception_body.thresholds.witness ||
    weight < authority.minimum_weight
  ) return null;
  return { start, digests: [...new Set(digests)].sort() };
}

function receiptMatches(
  receipt: EnrollmentObservationReceipt,
  candidate: Candidate,
  authority: CapturedAuthority,
  now: number,
): boolean {
  if (
    receipt.inception_event_id !== candidate.enrollment.inception_event_id ||
    receipt.active_key !== candidate.enrollment.active_key ||
    receipt.cold_root !== candidate.enrollment.cold_root ||
    receipt.accepted_head !== candidate.enrollment.head ||
    receipt.first_observed_at > receipt.last_observed_at ||
    receipt.last_observed_at > now ||
    !candidate.inception_body.witnesses.some(({ key }) => key === receipt.witness_key) ||
    !authority.witnesses.has(receipt.witness_key)
  ) return false;
  const { signature, ...bound } = receipt;
  return schnorrVerify(signature, domainSeparatedJcsDigest(
    ENROLLMENT_OBSERVATION_DOMAIN,
    bound,
  ), receipt.witness_key);
}

function validContest(event: NostrSignedEvent, candidate: Candidate): boolean {
  const verified = snapshotAndVerifyNostrEvent(event);
  if (verified === null || verified.kind !== 31006 ||
      verified.pubkey !== candidate.enrollment.active_key) return false;
  let body: unknown;
  try {
    body = JSON.parse(verified.content);
  } catch {
    return false;
  }
  if (!validateContest(body) || jcsCanonicalize(body) !== verified.content) return false;
  const record = body as {
    inception_event_id: string;
    cold_root: string;
  };
  return record.inception_event_id === candidate.enrollment.inception_event_id &&
    record.cold_root === candidate.enrollment.cold_root &&
    exactTags(verified.tags, [
      ["d", record.inception_event_id],
      ["p", record.cold_root],
    ]);
}

function validRetainedPin(
  pin: AssuranceEnrollmentAuthoritativePin,
  entry: EnrollmentObservationJournalEntry,
): boolean {
  const basis = pin.eligibility_basis;
  const evidenceDigests = new Set(entry.evidence_digests);
  const witnessReceiptDigests = new Set(Object.values(entry.witnesses).flatMap(
    ({ receipt_digests }) => receipt_digests,
  ));
  const modeProvenanceValid = basis.mode === "local"
    ? basis.start_ingested_at === entry.first_candidate_ingested_at &&
      basis.qualifying_receipt_digests.length === 0
    : basis.qualifying_receipt_digests.length >= 2 &&
      basis.qualifying_receipt_digests.every((digest) =>
        witnessReceiptDigests.has(digest));
  return pin.active_key === entry.active_key &&
    pin.inception_event_id === entry.inception_event_id &&
    pin.cold_root === entry.cold_root &&
    pin.accepted_head === entry.accepted_head &&
    pin.authority_id === entry.authority_id &&
    basis.authority_id === entry.authority_id &&
    basis.active_key === entry.active_key &&
    basis.inception_event_id === entry.inception_event_id &&
    basis.cold_root === entry.cold_root &&
    basis.accepted_head === entry.accepted_head &&
    basis.witness_policy_digest === entry.policy_digest &&
    basis.closing_revision <= entry.revision &&
    basis.closed_at === pin.observed_at &&
    elapsed(basis.start_ingested_at, basis.closed_at) &&
    basis.qualifying_receipt_digests.every((digest) => evidenceDigests.has(digest)) &&
    modeProvenanceValid &&
    basis.conflict_digests.length === 0 &&
    pin.eligibility_basis_digest === basisDigest(basis);
}

function initialEntry(
  authority: CapturedAuthority,
  enrollment: AssuranceHeadState,
  now: number,
): EnrollmentObservationJournalEntry {
  return {
    revision: 0,
    authority_id: authority.authority_id,
    active_key: enrollment.active_key,
    inception_event_id: enrollment.inception_event_id,
    cold_root: enrollment.cold_root,
    accepted_head: enrollment.head,
    policy_digest: authority.policy_digest,
    first_candidate_ingested_at: now,
    evidence_digests: [],
    witnesses: {},
    conflicts: [],
    contested: false,
    pin: null,
  };
}

function entryMatches(
  entry: EnrollmentObservationJournalEntry,
  authority: CapturedAuthority,
  enrollment: AssuranceHeadState,
): boolean {
  return entry.authority_id === authority.authority_id &&
    entry.policy_digest === authority.policy_digest &&
    entry.active_key === enrollment.active_key &&
    entry.inception_event_id === enrollment.inception_event_id &&
    entry.cold_root === enrollment.cold_root &&
    entry.accepted_head === enrollment.head;
}

function commit(
  authority: CapturedAuthority,
  key: string,
  expectedRevision: number | null,
  entry: EnrollmentObservationJournalEntry,
): boolean {
  let result: unknown;
  try {
    result = authority.compare_and_swap(
      key,
      expectedRevision,
      immutableClone(entry),
    );
  } catch {
    throw observationAuthorityInvalid();
  }
  if (result !== "committed" && result !== "conflict") {
    throw observationAuthorityInvalid();
  }
  return result === "committed";
}

function snapshotReceipt(value: unknown): EnrollmentObservationReceipt | null {
  const receipt = exactRecord(value, [
    "profile",
    "spec_version",
    "inception_event_id",
    "active_key",
    "cold_root",
    "accepted_head",
    "first_observed_at",
    "last_observed_at",
    "conflict_free",
    "witness_key",
    "signature",
  ]);
  if (receipt === null || !validateObservationReceipt(receipt)) return null;
  return immutableClone(receipt) as EnrollmentObservationReceipt;
}

function snapshotInceptionBody(value: unknown): EnrollmentInception | null {
  const record = value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as EnrollmentInception
    : null;
  if (record === null || !Array.isArray(record.witnesses)) return null;
  return immutableClone(record);
}

function snapshotJournalEntry(value: unknown): EnrollmentObservationJournalEntry | null {
  if (value === null) return null;
  const entry = exactRecord(value, [
    "revision", "authority_id", "active_key", "inception_event_id",
    "cold_root", "accepted_head", "policy_digest",
    "first_candidate_ingested_at", "evidence_digests", "witnesses",
    "conflicts", "contested", "pin",
  ]);
  if (
    entry === null || !Number.isSafeInteger(entry.revision) ||
    (entry.revision as number) < 0 || typeof entry.authority_id !== "string" ||
    !isHex32(entry.active_key) || !isHex32(entry.inception_event_id) ||
    !isHex32(entry.cold_root) || !isHex32(entry.accepted_head) ||
    !isDigest(entry.policy_digest) ||
    !isUnixTime(entry.first_candidate_ingested_at) ||
    typeof entry.contested !== "boolean"
  ) return null;
  try {
    const cloned = immutableClone(entry) as EnrollmentObservationJournalEntry;
    if (!Array.isArray(cloned.evidence_digests) ||
        !cloned.evidence_digests.every(isDigest) ||
        new Set(cloned.evidence_digests).size !== cloned.evidence_digests.length ||
        cloned.witnesses === null || typeof cloned.witnesses !== "object" ||
        Array.isArray(cloned.witnesses) ||
        !Array.isArray(cloned.conflicts)) return null;
    for (const [key, witness] of Object.entries(cloned.witnesses)) {
      if (exactRecord(witness, [
        "witness_key", "first_ingested_at", "latest_ingested_at",
        "first_observed_at", "last_observed_at", "receipt_digests",
      ]) === null) return null;
      if (
        !isHex32(key) || witness.witness_key !== key ||
        !isUnixTime(witness.first_ingested_at) ||
        !isUnixTime(witness.latest_ingested_at) ||
        witness.latest_ingested_at < witness.first_ingested_at ||
        !isUnixTime(witness.first_observed_at) ||
        !isUnixTime(witness.last_observed_at) ||
        witness.last_observed_at < witness.first_observed_at ||
        !Array.isArray(witness.receipt_digests) ||
        !witness.receipt_digests.every(isDigest) ||
        new Set(witness.receipt_digests).size !== witness.receipt_digests.length
      ) return null;
    }
    for (const conflict of cloned.conflicts) {
      if (exactRecord(conflict, [
        "digest", "first_ingested_at", "kind",
      ]) === null) return null;
      if (!isDigest(conflict.digest) || !isUnixTime(conflict.first_ingested_at) ||
          !["contest", "competing-enrollment"].includes(conflict.kind)) return null;
    }
    if (new Set(cloned.conflicts.map(({ digest }) => digest)).size !==
        cloned.conflicts.length) return null;
    if (cloned.pin !== null) {
      const pin = cloned.pin;
      const pinRecord = exactRecord(pin, [
        "active_key", "inception_event_id", "cold_root", "accepted_head",
        "state", "observed_at", "authority_id", "eligibility_basis",
        "eligibility_basis_digest",
      ]);
      const basis = exactRecord(pin.eligibility_basis, [
        "authority_id", "active_key", "inception_event_id", "cold_root",
        "accepted_head", "closing_revision", "start_ingested_at", "closed_at",
        "mode", "qualifying_receipt_digests", "witness_policy_digest",
        "conflict_digests",
      ]);
      if (
        pinRecord === null || basis === null ||
        !isHex32(pin.active_key) || !isHex32(pin.inception_event_id) ||
        !isHex32(pin.cold_root) || !isHex32(pin.accepted_head) ||
        pin.state !== "verified" || !isUnixTime(pin.observed_at) ||
        typeof pin.authority_id !== "string" ||
        !isDigest(pin.eligibility_basis_digest) ||
        pin.eligibility_basis === null ||
        typeof pin.eligibility_basis !== "object" ||
        typeof basis.authority_id !== "string" ||
        !isHex32(basis.active_key) || !isHex32(basis.inception_event_id) ||
        !isHex32(basis.cold_root) || !isHex32(basis.accepted_head) ||
        !Number.isSafeInteger(basis.closing_revision) ||
        (basis.closing_revision as number) < 0 ||
        !isUnixTime(basis.start_ingested_at) || !isUnixTime(basis.closed_at) ||
        !["local", "witness"].includes(basis.mode as string) ||
        !Array.isArray(basis.qualifying_receipt_digests) ||
        !basis.qualifying_receipt_digests.every(isDigest) ||
        new Set(basis.qualifying_receipt_digests).size !==
          basis.qualifying_receipt_digests.length ||
        !isDigest(basis.witness_policy_digest) ||
        !Array.isArray(basis.conflict_digests) ||
        !basis.conflict_digests.every(isDigest) ||
        new Set(basis.conflict_digests).size !== basis.conflict_digests.length
      ) return null;
    }
    return cloned;
  } catch {
    return null;
  }
}

function mutableEntry(entry: EnrollmentObservationJournalEntry): {
  -readonly [K in keyof EnrollmentObservationJournalEntry]:
    K extends "evidence_digests" ? string[] :
    K extends "witnesses" ? Record<string, EnrollmentObservationWitnessState> :
    K extends "conflicts" ? EnrollmentObservationConflict[] :
    EnrollmentObservationJournalEntry[K];
} {
  return {
    ...entry,
    evidence_digests: [...entry.evidence_digests],
    witnesses: Object.fromEntries(Object.entries(entry.witnesses).map(
      ([key, value]) => [key, { ...value, receipt_digests: [...value.receipt_digests] }],
    )),
    conflicts: entry.conflicts.map((conflict) => ({ ...conflict })),
    pin: entry.pin,
  };
}

function exactRecord(
  value: unknown,
  members: readonly string[],
): Record<string, unknown> | null {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    utilTypes.isProxy(value)
  ) return null;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype &&
        Object.getPrototypeOf(value) !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.some((key) => typeof key !== "string") ||
      keys.length !== members.length ||
      !members.every((member) => Object.hasOwn(descriptors, member))
    ) return null;
    const snapshot: Record<string, unknown> = {};
    for (const member of members) {
      const descriptor = descriptors[member];
      if (descriptor === undefined || !("value" in descriptor) ||
          descriptor.enumerable !== true) return null;
      snapshot[member] = descriptor.value;
    }
    return snapshot;
  } catch {
    return null;
  }
}

function denseArray(value: unknown): unknown[] | null {
  if (!Array.isArray(value) || utilTypes.isProxy(value)) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (lengthDescriptor === undefined || lengthDescriptor.value !== value.length) {
    return null;
  }
  const result: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined || !("value" in descriptor)) return null;
    result.push(descriptor.value);
  }
  return result;
}

function immutableClone<T>(value: T): T {
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => immutableClone(item))) as T;
  }
  if (value !== null && typeof value === "object") {
    if (utilTypes.isProxy(value)) throw observationAuthorityInvalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const clone: Record<string, unknown> = {};
    for (const key of Reflect.ownKeys(descriptors)) {
      if (typeof key !== "string") throw observationAuthorityInvalid();
      const descriptor = descriptors[key];
      if (descriptor === undefined || !("value" in descriptor)) {
        throw observationAuthorityInvalid();
      }
      clone[key] = immutableClone(descriptor.value);
    }
    return Object.freeze(clone) as T;
  }
  return value;
}

function journalKey(enrollment: AssuranceHeadState): string {
  return [
    enrollment.active_key,
    enrollment.inception_event_id,
    enrollment.cold_root,
    enrollment.head,
  ].join(":");
}

function evidenceDigest(value: unknown): string {
  return bytesToHex(sha256(new TextEncoder().encode(jcsCanonicalize(value))));
}

function basisDigest(basis: EnrollmentEligibilityBasis): string {
  return domainSeparatedJcsDigest(ENROLLMENT_PIN_BASIS_DOMAIN, basis);
}

function exactTags(actual: string[][], expected: string[][]): boolean {
  return actual.length === expected.length && actual.every((tag, index) =>
    tag.length === expected[index]?.length &&
    tag.every((value, member) => value === expected[index]?.[member]));
}

function schnorrVerify(signature: string, digest: string, key: string): boolean {
  try {
    return schnorr.verify(signature, digest, key);
  } catch {
    return false;
  }
}

function captureJournal(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || utilTypes.isProxy(value)) {
    return null;
  }
  const result: Record<string, unknown> = {};
  try {
    for (const member of ["load", "compareAndSwap"] as const) {
      let owner: object | null = value;
      let descriptor: PropertyDescriptor | undefined;
      while (owner !== null && descriptor === undefined) {
        descriptor = Object.getOwnPropertyDescriptor(owner, member);
        owner = Object.getPrototypeOf(owner);
      }
      if (descriptor === undefined || !("value" in descriptor) ||
          typeof descriptor.value !== "function") return null;
      result[member] = descriptor.value;
    }
    return result;
  } catch {
    return null;
  }
}

function elapsed(start: number, end: number): boolean {
  return end >= start && end - start >= ENROLLMENT_WINDOW_SECONDS;
}

function isUnixTime(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isHex32(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isDigest(value: unknown): value is string {
  return isHex32(value);
}

function enrollmentResult(
  state: "pending" | "verified" | "contested",
  normalized: AssuranceHeadState,
  warning: boolean,
): AssuranceEnrollmentEligibility {
  return {
    state,
    reason: state === "pending"
      ? "assurance-enrollment-pending-window"
      : state === "contested"
        ? "assurance-enrollment-contested"
        : null,
    warnings: warning ? ["assurance-enrollment-contested"] : [],
    normalized,
  };
}

function pending(normalized: AssuranceHeadState): AssuranceEnrollmentEligibility {
  return enrollmentResult("pending", normalized, false);
}

function contested(normalized: AssuranceHeadState): AssuranceEnrollmentEligibility {
  return enrollmentResult("contested", normalized, true);
}

function verified(
  normalized: AssuranceHeadState,
  warning: boolean,
): AssuranceEnrollmentEligibility {
  return enrollmentResult("verified", normalized, warning);
}

function reciprocalReject(): AssuranceVerdict<never> {
  return { verdict: "reject", reason_code: "assurance-reciprocal-proof-invalid" };
}

function pinConflict(): AssuranceVerdict<never> {
  return { verdict: "reject", reason_code: "assurance-pin-conflict" };
}

function observationAuthorityInvalid(): Error {
  return new Error("assurance-enrollment-observation-authority-invalid");
}
