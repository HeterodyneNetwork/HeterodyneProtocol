import { types as utilTypes } from "node:util";
import { createHmac, timingSafeEqual } from "node:crypto";
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
const ENROLLMENT_JOURNAL_SEAL_DOMAIN =
  "heterodyne-assurance-enrollment-journal-seal-v1";

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
  receipt_ingestions: readonly EnrollmentObservationReceiptIngestion[];
}>;

export type EnrollmentObservationReceiptIngestion = Readonly<{
  digest: string;
  ingested_at: number;
  ingested_revision: number;
  first_observed_at: number;
  last_observed_at: number;
}>;

export type EnrollmentObservationConflict = Readonly<{
  digest: string;
  first_ingested_at: number;
  ingested_revision: number;
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
  scope: Readonly<{
    active_key: string;
    inception_event_id: string;
  }>;
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
  seal: string;
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
  journal_integrity_key: string;
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
  journal_integrity_key: string;
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

export function assuranceEnrollmentWitnessPolicyDigest(
  value: Readonly<{
    minimum_weight: number;
    witnesses: ReadonlyMap<string, number>;
  }>,
): string {
  const record = exactRecord(value, ["minimum_weight", "witnesses"]);
  if (
    record === null || !Number.isSafeInteger(record.minimum_weight) ||
    (record.minimum_weight as number) < 0
  ) throw observationAuthorityInvalid();
  const witnesses = captureWitnessMap(record.witnesses);
  if (witnesses === null) throw observationAuthorityInvalid();
  return canonicalPolicyDigest(record.minimum_weight as number, witnesses);
}

export function createAssuranceEnrollmentObservationAuthority(
  config: EnrollmentObservationAuthorityConfig,
): AssuranceEnrollmentObservationAuthority {
  const captured = exactRecord(config, [
    "authority_id",
    "trusted_now",
    "witness_policy",
    "journal_integrity_key",
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
    typeof captured.journal_integrity_key !== "string" ||
    !isHex32(captured.journal_integrity_key) ||
    policy === null ||
    typeof policy.policy_digest !== "string" ||
    !isDigest(policy.policy_digest) ||
    !Number.isSafeInteger(policy.minimum_weight) ||
    (policy.minimum_weight as number) < 0 ||
    journal === null ||
    typeof journal.load !== "function" || utilTypes.isProxy(journal.load) ||
    typeof journal.compareAndSwap !== "function" ||
    utilTypes.isProxy(journal.compareAndSwap)
  ) throw observationAuthorityInvalid();

  const witnesses = captureWitnessMap(policy.witnesses);
  if (witnesses === null) throw observationAuthorityInvalid();
  if (policy.policy_digest !== canonicalPolicyDigest(
    policy.minimum_weight as number,
    witnesses,
  )) throw observationAuthorityInvalid();

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
    journal_integrity_key: captured.journal_integrity_key.slice(0),
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
  const key = journalScopeKey(candidate.enrollment);

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
    if (
      loaded !== null &&
      (entry === null || !validJournalSeal(entry, captured.journal_integrity_key))
    ) return pinConflict();
    const created = entry === null;
    if (entry === null) {
      entry = initialEntry(captured, candidate.enrollment, now);
    } else if (!scopeMatches(entry, captured, candidate.enrollment)) {
      return pinConflict();
    }
    if (!candidateMatches(entry, candidate.enrollment)) {
      if (entry.pin !== null) return pinConflict();
      if (!entry.contested) {
        const alternate = contestAlternateCandidate(
          entry,
          candidate.enrollment,
          captured,
          now,
        );
        if (!commit(captured, key, expectedRevision, alternate)) continue;
        entry = alternate;
      }
      return contested(candidate.enrollment);
    }
    if (!validJournalState(entry, candidate, captured, now)) {
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
    const closed = sealJournalEntry({
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
    }, captured.journal_integrity_key);
    if (!validJournalState(closed, candidate, captured, now)) {
      throw observationAuthorityInvalid();
    }
    if (!commit(captured, key, expectedRevision, closed)) continue;
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
        receipt_ingestions: [{
          digest,
          ingested_at: now,
          ingested_revision: entry.revision + 1,
          first_observed_at: receipt.first_observed_at,
          last_observed_at: receipt.last_observed_at,
        }],
      };
    } else {
      next.witnesses[receipt.witness_key] = {
        ...current,
        latest_ingested_at: now,
        last_observed_at: receipt.last_observed_at,
        receipt_digests: [...current.receipt_digests, digest],
        receipt_ingestions: [...current.receipt_ingestions, {
          digest,
          ingested_at: now,
          ingested_revision: entry.revision + 1,
          first_observed_at: receipt.first_observed_at,
          last_observed_at: receipt.last_observed_at,
        }],
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
      ingested_revision: entry.revision + 1,
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
    next.conflicts.push({
      digest,
      first_ingested_at: now,
      ingested_revision: entry.revision + 1,
      kind: "competing-enrollment",
    });
    if (entry.pin === null) next.contested = true;
    changed = true;
  }

  if (!changed) return { entry, changed: false };
  next.revision = entry.revision + 1;
  return {
    entry: sealJournalEntry(next, authority.journal_integrity_key),
    changed: true,
  };
}

function qualifyingWitnessReceipts(
  entry: EnrollmentObservationJournalEntry,
  candidate: Candidate,
  authority: CapturedAuthority,
  now: number,
): { start: number; digests: string[] } | null {
  return qualifyingWitnessReceiptsAt(
    entry,
    candidate,
    authority,
    now,
    entry.revision,
  );
}

function qualifyingWitnessReceiptsAt(
  entry: EnrollmentObservationJournalEntry,
  candidate: Candidate,
  authority: CapturedAuthority,
  closeAt: number,
  closingRevision: number,
): { start: number; digests: string[] } | null {
  let weight = 0;
  let start = closeAt;
  const digests: string[] = [];
  for (const configured of candidate.inception_body.witnesses) {
    const localWeight = authority.witnesses.get(configured.key);
    const state = entry.witnesses[configured.key];
    const receipts = state?.receipt_ingestions.filter(
      ({ ingested_revision }) => ingested_revision <= closingRevision,
    ) ?? [];
    const first = receipts[0];
    const latest = receipts.at(-1);
    if (
      localWeight === undefined || state === undefined ||
      receipts.length < 2 || first === undefined || latest === undefined ||
      !elapsed(first.ingested_at, latest.ingested_at) ||
      latest.last_observed_at - first.first_observed_at < ENROLLMENT_WINDOW_SECONDS
    ) continue;
    weight += Math.min(configured.weight, localWeight);
    start = Math.min(start, first.ingested_at);
    digests.push(...receipts.map(({ digest }) => digest));
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

function validJournalState(
  entry: EnrollmentObservationJournalEntry,
  candidate: Candidate,
  authority: CapturedAuthority,
  now: number,
): boolean {
  if (
    entry.first_candidate_ingested_at > now ||
    entry.scope.active_key !== entry.active_key ||
    entry.scope.inception_event_id !== entry.inception_event_id
  ) return false;
  const reconstructedDigests: string[] = [];
  for (const [key, witness] of Object.entries(entry.witnesses)) {
    const receipts = witness.receipt_ingestions;
    if (receipts.length === 0 || witness.witness_key !== key) return false;
    let priorIngestedAt = -1;
    let priorIngestedRevision = -1;
    let priorLastObservedAt = -1;
    const receiptDigests = new Set<string>();
    for (const receipt of receipts) {
      if (
        receipt.ingested_at < priorIngestedAt || receipt.ingested_at > now ||
        receipt.ingested_at < entry.first_candidate_ingested_at ||
        receipt.ingested_revision < 1 ||
        receipt.ingested_revision < priorIngestedRevision ||
        receipt.ingested_revision > entry.revision ||
        (receipt.ingested_revision === priorIngestedRevision &&
          receipt.ingested_at !== priorIngestedAt) ||
        receiptDigests.has(receipt.digest) ||
        receipt.first_observed_at !== receipts[0]!.first_observed_at ||
        receipt.first_observed_at > receipt.last_observed_at ||
        receipt.last_observed_at < priorLastObservedAt ||
        receipt.last_observed_at > receipt.ingested_at
      ) return false;
      priorIngestedAt = receipt.ingested_at;
      priorIngestedRevision = receipt.ingested_revision;
      priorLastObservedAt = receipt.last_observed_at;
      receiptDigests.add(receipt.digest);
      reconstructedDigests.push(receipt.digest);
    }
    const latest = receipts.at(-1)!;
    if (
      witness.first_ingested_at !== receipts[0]!.ingested_at ||
      witness.latest_ingested_at !== latest.ingested_at ||
      witness.first_observed_at !== receipts[0]!.first_observed_at ||
      witness.last_observed_at !== latest.last_observed_at ||
      !sameStrings(
        witness.receipt_digests,
        receipts.map(({ digest }) => digest),
      )
    ) return false;
  }
  for (const conflict of entry.conflicts) {
    if (
      conflict.first_ingested_at < entry.first_candidate_ingested_at ||
      conflict.first_ingested_at > now ||
      conflict.ingested_revision < 1 ||
      conflict.ingested_revision > entry.revision
    ) return false;
    reconstructedDigests.push(conflict.digest);
  }
  if (!sameStringSets(entry.evidence_digests, reconstructedDigests)) return false;
  if (entry.contested && (entry.pin !== null || entry.conflicts.length === 0)) {
    return false;
  }
  if (entry.pin === null && entry.conflicts.length > 0 && !entry.contested) {
    return false;
  }
  return entry.pin === null || validRetainedPin(
    entry.pin,
    entry,
    candidate,
    authority,
    now,
  );
}

function validRetainedPin(
  pin: AssuranceEnrollmentAuthoritativePin,
  entry: EnrollmentObservationJournalEntry,
  candidate: Candidate,
  authority: CapturedAuthority,
  now: number,
): boolean {
  const basis = pin.eligibility_basis;
  const evidenceDigests = new Set(entry.evidence_digests);
  const qualifying = qualifyingWitnessReceiptsAt(
    entry,
    candidate,
    authority,
    basis.closed_at,
    basis.closing_revision,
  );
  const modeProvenanceValid = basis.mode === "local"
    ? basis.start_ingested_at === entry.first_candidate_ingested_at &&
      basis.qualifying_receipt_digests.length === 0 && qualifying === null &&
      elapsed(entry.first_candidate_ingested_at, basis.closed_at)
    : qualifying !== null && basis.start_ingested_at === qualifying.start &&
      sameStrings(basis.qualifying_receipt_digests, qualifying.digests);
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
    basis.closed_at <= now &&
    elapsed(basis.start_ingested_at, basis.closed_at) &&
    basis.qualifying_receipt_digests.every((digest) => evidenceDigests.has(digest)) &&
    modeProvenanceValid &&
    basis.conflict_digests.length === 0 &&
    entry.conflicts.every(({ ingested_revision }) =>
      ingested_revision > basis.closing_revision) &&
    pin.eligibility_basis_digest === basisDigest(basis);
}

function initialEntry(
  authority: CapturedAuthority,
  enrollment: AssuranceHeadState,
  now: number,
): EnrollmentObservationJournalEntry {
  return sealJournalEntry({
    scope: {
      active_key: enrollment.active_key,
      inception_event_id: enrollment.inception_event_id,
    },
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
    seal: "00".repeat(32),
  }, authority.journal_integrity_key);
}

function scopeMatches(
  entry: EnrollmentObservationJournalEntry,
  authority: CapturedAuthority,
  enrollment: AssuranceHeadState,
): boolean {
  return entry.authority_id === authority.authority_id &&
    entry.policy_digest === authority.policy_digest &&
    entry.scope.active_key === enrollment.active_key &&
    entry.scope.inception_event_id === enrollment.inception_event_id;
}

function candidateMatches(
  entry: EnrollmentObservationJournalEntry,
  enrollment: AssuranceHeadState,
): boolean {
  return entry.active_key === enrollment.active_key &&
    entry.inception_event_id === enrollment.inception_event_id &&
    entry.cold_root === enrollment.cold_root &&
    entry.accepted_head === enrollment.head;
}

function contestAlternateCandidate(
  entry: EnrollmentObservationJournalEntry,
  enrollment: AssuranceHeadState,
  authority: CapturedAuthority,
  now: number,
): EnrollmentObservationJournalEntry {
  const digest = evidenceDigest({
    active_key: enrollment.active_key,
    inception_event_id: enrollment.inception_event_id,
    cold_root: enrollment.cold_root,
    accepted_head: enrollment.head,
  });
  return sealJournalEntry({
    ...entry,
    revision: entry.revision + 1,
    evidence_digests: entry.evidence_digests.includes(digest)
      ? entry.evidence_digests
      : [...entry.evidence_digests, digest],
    conflicts: entry.conflicts.some((conflict) => conflict.digest === digest)
      ? entry.conflicts
      : [...entry.conflicts, {
          digest,
          first_ingested_at: now,
          ingested_revision: entry.revision + 1,
          kind: "competing-enrollment" as const,
        }],
    contested: true,
  }, authority.journal_integrity_key);
}

function commit(
  authority: CapturedAuthority,
  key: string,
  expectedRevision: number | null,
  entry: EnrollmentObservationJournalEntry,
): boolean {
  if (!validJournalSeal(entry, authority.journal_integrity_key)) {
    throw observationAuthorityInvalid();
  }
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
    "scope", "revision", "authority_id", "active_key", "inception_event_id",
    "cold_root", "accepted_head", "policy_digest",
    "first_candidate_ingested_at", "evidence_digests", "witnesses",
    "conflicts", "contested", "pin", "seal",
  ]);
  const scope = entry === null
    ? null
    : exactRecord(entry.scope, ["active_key", "inception_event_id"]);
  if (
    entry === null || scope === null ||
    !isHex32(scope.active_key) || !isHex32(scope.inception_event_id) ||
    !Number.isSafeInteger(entry.revision) ||
    (entry.revision as number) < 0 || typeof entry.authority_id !== "string" ||
    !isHex32(entry.active_key) || !isHex32(entry.inception_event_id) ||
    !isHex32(entry.cold_root) || !isHex32(entry.accepted_head) ||
    !isDigest(entry.policy_digest) ||
    !isDigest(entry.seal) ||
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
        "receipt_ingestions",
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
        new Set(witness.receipt_digests).size !== witness.receipt_digests.length ||
        !Array.isArray(witness.receipt_ingestions)
      ) return null;
      for (const receipt of witness.receipt_ingestions) {
        if (exactRecord(receipt, [
          "digest", "ingested_at", "ingested_revision", "first_observed_at",
          "last_observed_at",
        ]) === null || !isDigest(receipt.digest) ||
            !isUnixTime(receipt.ingested_at) ||
            !Number.isSafeInteger(receipt.ingested_revision) ||
            receipt.ingested_revision < 1 ||
            !isUnixTime(receipt.first_observed_at) ||
            !isUnixTime(receipt.last_observed_at)) return null;
      }
    }
    for (const conflict of cloned.conflicts) {
      if (exactRecord(conflict, [
        "digest", "first_ingested_at", "ingested_revision", "kind",
      ]) === null) return null;
      if (!isDigest(conflict.digest) || !isUnixTime(conflict.first_ingested_at) ||
          !Number.isSafeInteger(conflict.ingested_revision) ||
          conflict.ingested_revision < 0 ||
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
      ([key, value]) => [key, {
        ...value,
        receipt_digests: [...value.receipt_digests],
        receipt_ingestions: value.receipt_ingestions.map((receipt) => ({ ...receipt })),
      }],
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
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && utilTypes.isProxy(prototype)) return null;
    if (prototype !== Object.prototype && prototype !== null) return null;
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
    if (utilTypes.isProxy(value)) throw observationAuthorityInvalid();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && utilTypes.isProxy(prototype)) {
      throw observationAuthorityInvalid();
    }
    if (prototype !== Array.prototype) throw observationAuthorityInvalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    const arrayLength = lengthDescriptor?.value;
    if (
      lengthDescriptor === undefined || !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(arrayLength) || (arrayLength as number) < 0 ||
      keys.some((key) => typeof key !== "string") ||
      keys.length !== (arrayLength as number) + 1
    ) throw observationAuthorityInvalid();
    const clone: unknown[] = [];
    for (let index = 0; index < (arrayLength as number); index += 1) {
      const descriptor = descriptors[String(index)];
      if (
        descriptor === undefined || !("value" in descriptor) ||
        descriptor.enumerable !== true
      ) throw observationAuthorityInvalid();
      clone.push(immutableClone(descriptor.value));
    }
    return Object.freeze(clone) as T;
  }
  if (value !== null && typeof value === "object") {
    if (utilTypes.isProxy(value)) throw observationAuthorityInvalid();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && utilTypes.isProxy(prototype)) {
      throw observationAuthorityInvalid();
    }
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

function journalScopeKey(enrollment: AssuranceHeadState): string {
  return [
    enrollment.active_key,
    enrollment.inception_event_id,
  ].join(":");
}

function evidenceDigest(value: unknown): string {
  return bytesToHex(sha256(new TextEncoder().encode(jcsCanonicalize(value))));
}

function canonicalPolicyDigest(
  minimumWeight: number,
  witnesses: ReadonlyMap<string, number>,
): string {
  return evidenceDigest({
    minimum_weight: minimumWeight,
    witnesses: [...witnesses.entries()]
      .map(([key, weight]) => ({ key, weight }))
      .sort((left, right) => left.key.localeCompare(right.key)),
  });
}

function captureWitnessMap(value: unknown): Map<string, number> | null {
  if (
    value === null || typeof value !== "object" || utilTypes.isProxy(value) ||
    !(value instanceof Map)
  ) return null;
  try {
    let prototype = Object.getPrototypeOf(value);
    while (prototype !== null) {
      if (utilTypes.isProxy(prototype)) return null;
      prototype = Object.getPrototypeOf(prototype);
    }
    const witnesses = new Map<string, number>();
    for (const [key, weight] of Map.prototype.entries.call(value) as
      IterableIterator<[unknown, unknown]>) {
      if (
        typeof key !== "string" || !isHex32(key) ||
        !Number.isSafeInteger(weight) || (weight as number) <= 0 ||
        witnesses.has(key)
      ) return null;
      witnesses.set(key, weight as number);
    }
    return witnesses;
  } catch {
    return null;
  }
}

function journalSealBody(
  value: EnrollmentObservationJournalEntry | Record<string, unknown>,
): Record<string, unknown> {
  const { seal: _seal, ...body } = value;
  return body;
}

function journalSeal(
  value: EnrollmentObservationJournalEntry | Record<string, unknown>,
  integrityKey: string,
): string {
  return createHmac("sha256", Buffer.from(integrityKey, "hex"))
    .update(ENROLLMENT_JOURNAL_SEAL_DOMAIN, "utf8")
    .update("\0", "utf8")
    .update(jcsCanonicalize(journalSealBody(value)), "utf8")
    .digest("hex");
}

function sealJournalEntry(
  value: EnrollmentObservationJournalEntry | Record<string, unknown>,
  integrityKey: string,
): EnrollmentObservationJournalEntry {
  const sealed = {
    ...journalSealBody(value),
    seal: journalSeal(value, integrityKey),
  };
  const snapshot = snapshotJournalEntry(sealed);
  if (snapshot === null) throw observationAuthorityInvalid();
  return snapshot;
}

function validJournalSeal(
  entry: EnrollmentObservationJournalEntry,
  integrityKey: string,
): boolean {
  if (!isDigest(entry.seal)) return false;
  const expected = journalSeal(entry, integrityKey);
  return timingSafeEqual(
    Buffer.from(entry.seal, "hex"),
    Buffer.from(expected, "hex"),
  );
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
        if (utilTypes.isProxy(owner)) return null;
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

function sameStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index]);
}

function sameStringSets(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return sameStrings([...left].sort(), [...right].sort());
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
