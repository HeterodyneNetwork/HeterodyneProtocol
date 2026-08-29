import { describe, expect, it } from "vitest";
import { schnorr } from "@noble/curves/secp256k1";
import { domainSeparatedJcsDigest } from "./credential-continuity.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import {
  createAssuranceEnrollmentObservationAuthority,
  evaluateEnrollmentEligibility,
  type EnrollmentObservationJournal,
  type EnrollmentObservationJournalEntry,
  type EnrollmentWitnessPolicy,
} from "./assurance-observation.js";
import type {
  AssociatedKeyPolicy,
  EnrollmentInception,
  EnrollmentObservationReceipt,
} from "./assurance.js";

// BLUE TEAM VALIDATION: synthetic/local fixtures below are deterministic,
// minimal, non-deployable protocol-quality checks. They use no live target,
// production system, real credential/account, external system, or reusable
// exploit/payload.

const AUX_RAND = "00".repeat(32);
const secret = (value: number): string => value.toString(16).padStart(64, "0");
const COLD_SECRET = secret(101);
const ACTIVE_SECRET = secret(102);
const WITNESS_SECRET = secret(103);
const SECOND_WITNESS_SECRET = secret(104);
const UNTRUSTED_WITNESS_SECRET = secret(105);
const COLD_KEY = getPublicKey(COLD_SECRET);
const ACTIVE_KEY = getPublicKey(ACTIVE_SECRET);
const WITNESS_KEY = getPublicKey(WITNESS_SECRET);
const SECOND_WITNESS_KEY = getPublicKey(SECOND_WITNESS_SECRET);
const WINDOW = 604_800;
const START = 1_800_000_000;

const associatedKeyPolicy: AssociatedKeyPolicy = {
  active_key: [],
  epoch_threshold: [],
};

async function assuranceEvent(
  secretKey: string,
  kind: number,
  d: string,
  profile: string,
  body: Record<string, unknown>,
  publicKeys: string[] = [],
): Promise<NostrSignedEvent> {
  return signEvent({
    secretKey,
    created_at: body.created_at as number,
    kind,
    tags: [
      ["d", d],
      ["profile", profile],
      ...publicKeys.map((key) => ["p", key]),
    ],
    content: jcsCanonicalize(body),
    auxRand: AUX_RAND,
  });
}

async function enrollment(
  witnesses: EnrollmentInception["witnesses"] = [
    { key: WITNESS_KEY, weight: 1 },
  ],
  witnessThreshold = 1,
) {
  const inceptionBody: EnrollmentInception = {
    profile: "heterodyne.assurance.enrollment-inception.v1",
    spec_version: "heterodyne/0.6.0",
    active_key: ACTIVE_KEY,
    created_at: 1,
    predecessor: null,
    cold_root: COLD_KEY,
    succession_authority: null,
    epoch_policy: { mode: "none", current_keys: [], next_key_commitments: [] },
    witnesses,
    thresholds: { epoch: 0, witness: witnessThreshold },
    associated_key_policy: associatedKeyPolicy,
  };
  const inception = await assuranceEvent(
    COLD_SECRET,
    31002,
    `assurance-inception:${ACTIVE_KEY}`,
    inceptionBody.profile,
    inceptionBody,
    [ACTIVE_KEY],
  );
  const acceptanceBody = {
    profile: "heterodyne.assurance.active-key-acceptance.v1" as const,
    spec_version: "heterodyne/0.6.0" as const,
    active_key: ACTIVE_KEY,
    created_at: 2,
    predecessor: inception.id,
    inception_event_id: inception.id,
    cold_root: COLD_KEY,
    cold_root_signature: inception.sig,
    assurance_head: inception.id,
    state: "assured" as const,
  };
  const acceptance = await assuranceEvent(
    ACTIVE_SECRET,
    31000,
    "assurance-head",
    acceptanceBody.profile,
    acceptanceBody,
  );
  return { inception, acceptance };
}

function signedReceipt(
  pair: Awaited<ReturnType<typeof enrollment>>,
  signingSecret = WITNESS_SECRET,
  overrides: Partial<Omit<EnrollmentObservationReceipt, "signature">> = {},
): EnrollmentObservationReceipt {
  const unsigned = {
    profile: "heterodyne.assurance.enrollment-observation-receipt.v1" as const,
    spec_version: "heterodyne/0.6.0" as const,
    inception_event_id: pair.inception.id,
    active_key: ACTIVE_KEY,
    cold_root: COLD_KEY,
    accepted_head: pair.acceptance.id,
    first_observed_at: 1,
    last_observed_at: START,
    conflict_free: true as const,
    witness_key: getPublicKey(signingSecret),
    ...overrides,
  };
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      domainSeparatedJcsDigest(
        "heterodyne-assurance-enrollment-observation-v1",
        unsigned,
      ),
      hexToBytes(signingSecret),
      hexToBytes(AUX_RAND),
    )),
  };
}

async function contest(
  pair: Awaited<ReturnType<typeof enrollment>>,
): Promise<NostrSignedEvent> {
  const body = {
    profile: "heterodyne.assurance.enrollment-contest.v1",
    spec_version: "heterodyne/0.6.0",
    inception_event_id: pair.inception.id,
    cold_root: COLD_KEY,
  };
  return signEvent({
    secretKey: ACTIVE_SECRET,
    created_at: 3,
    kind: 31006,
    tags: [["d", pair.inception.id], ["p", COLD_KEY]],
    content: jcsCanonicalize(body),
    auxRand: AUX_RAND,
  });
}

class MemoryJournal implements EnrollmentObservationJournal {
  readonly entries = new Map<string, EnrollmentObservationJournalEntry>();

  load(key: string): EnrollmentObservationJournalEntry | null {
    return this.entries.get(key) ?? null;
  }

  compareAndSwap(
    key: string,
    expectedRevision: number | null,
    next: EnrollmentObservationJournalEntry,
  ): "committed" | "conflict" {
    const current = this.entries.get(key);
    if ((current?.revision ?? null) !== expectedRevision) return "conflict";
    this.entries.set(key, next);
    return "committed";
  }
}

function trustedPolicy(
  overrides: Partial<EnrollmentWitnessPolicy> = {},
): EnrollmentWitnessPolicy {
  return {
    policy_digest: "11".repeat(32),
    minimum_weight: 1,
    witnesses: new Map([[WITNESS_KEY, 1], [SECOND_WITNESS_KEY, 1]]),
    ...overrides,
  };
}

function authority(
  journal: EnrollmentObservationJournal,
  now: () => number,
  policy: EnrollmentWitnessPolicy = trustedPolicy(),
  authorityId = "local-authority-a",
) {
  return createAssuranceEnrollmentObservationAuthority({
    authority_id: authorityId,
    trusted_now: now,
    witness_policy: policy,
    journal,
  });
}

function emptyEvidence() {
  return {
    witness_receipts: [],
    contests: [],
    competing_enrollments: [],
  };
}

function onlyEntry(journal: MemoryJournal): EnrollmentObservationJournalEntry {
  expect(journal.entries.size).toBe(1);
  return [...journal.entries.values()][0]!;
}

describe("BLUE TEAM VALIDATION: synthetic/local authority-owned chronology", () => {
  it("rejects immediate backdating and starts two receipt replays at each authority's ingestion time", async () => {
    const pair = await enrollment();
    const historical = signedReceipt(pair, WITNESS_SECRET, {
      first_observed_at: 1,
      last_observed_at: START,
    });
    const firstJournal = new MemoryJournal();
    const secondJournal = new MemoryJournal();

    const first = await evaluateEnrollmentEligibility(
      authority(firstJournal, () => START, trustedPolicy(), "authority-a"),
      { ...pair, evidence: { ...emptyEvidence(), witness_receipts: [historical] } },
    );
    const second = await evaluateEnrollmentEligibility(
      authority(secondJournal, () => START + 9, trustedPolicy(), "authority-b"),
      { ...pair, evidence: { ...emptyEvidence(), witness_receipts: [historical] } },
    );

    expect(first).toMatchObject({ state: "pending" });
    expect(second).toMatchObject({ state: "pending" });
    expect(onlyEntry(firstJournal).first_candidate_ingested_at).toBe(START);
    expect(onlyEntry(secondJournal).first_candidate_ingested_at).toBe(START + 9);
  });

  it("does not trust a witness selected only by the candidate", async () => {
    const untrustedKey = getPublicKey(UNTRUSTED_WITNESS_SECRET);
    const pair = await enrollment([{ key: untrustedKey, weight: 100 }], 1);
    const journal = new MemoryJournal();
    const result = await evaluateEnrollmentEligibility(
      authority(journal, () => START, trustedPolicy({
        witnesses: new Map(),
      })),
      {
        ...pair,
        evidence: {
          ...emptyEvidence(),
          witness_receipts: [signedReceipt(pair, UNTRUSTED_WITNESS_SECRET)],
        },
      },
    );
    expect(result).toMatchObject({ state: "pending" });
    expect(Object.keys(onlyEntry(journal).witnesses)).toEqual([]);
  });

  it("rejects a receipt for the wrong accepted head", async () => {
    const pair = await enrollment();
    const journal = new MemoryJournal();
    const wrongHead = signedReceipt(pair, WITNESS_SECRET, {
      accepted_head: "aa".repeat(32),
    });
    const result = await evaluateEnrollmentEligibility(
      authority(journal, () => START),
      { ...pair, evidence: { ...emptyEvidence(), witness_receipts: [wrongHead] } },
    );
    expect(result).toMatchObject({ state: "pending" });
    expect(Object.keys(onlyEntry(journal).witnesses)).toEqual([]);
  });

  it("deduplicates exact receipt replay instead of advancing witness chronology", async () => {
    const pair = await enrollment();
    const journal = new MemoryJournal();
    let now = START;
    const localAuthority = authority(journal, () => now);
    const replay = signedReceipt(pair);
    await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: { ...emptyEvidence(), witness_receipts: [replay] },
    });
    const first = onlyEntry(journal);
    now += WINDOW;
    await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: { ...emptyEvidence(), witness_receipts: [replay, replay] },
    });
    const latest = onlyEntry(journal);
    expect(latest.witnesses[WITNESS_KEY]).toMatchObject({
      first_ingested_at: START,
      latest_ingested_at: START,
      receipt_digests: [first.witnesses[WITNESS_KEY]!.receipt_digests[0]],
    });
    expect(latest.pin?.eligibility_basis.mode).toBe("local");
  });

  it("counts one witness once even when distinct same-witness receipts are supplied", async () => {
    const pair = await enrollment([
      { key: WITNESS_KEY, weight: 1 },
      { key: SECOND_WITNESS_KEY, weight: 1 },
    ], 2);
    const journal = new MemoryJournal();
    const result = await evaluateEnrollmentEligibility(
      authority(journal, () => START, trustedPolicy({ minimum_weight: 2 })),
      {
        ...pair,
        evidence: {
          ...emptyEvidence(),
          witness_receipts: [
            signedReceipt(pair, WITNESS_SECRET, { last_observed_at: START - 1 }),
            signedReceipt(pair, WITNESS_SECRET, { last_observed_at: START }),
          ],
        },
      },
    );
    expect(result).toMatchObject({ state: "pending" });
    expect(Object.keys(onlyEntry(journal).witnesses)).toEqual([WITNESS_KEY]);
  });

  it("does not advance witness chronology with a nonmonotonic signed update", async () => {
    const pair = await enrollment();
    const journal = new MemoryJournal();
    let now = START;
    const localAuthority = authority(journal, () => now);
    const first = signedReceipt(pair, WITNESS_SECRET, {
      first_observed_at: 10,
      last_observed_at: START,
    });
    await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: { ...emptyEvidence(), witness_receipts: [first] },
    });
    now += WINDOW;
    const regressed = signedReceipt(pair, WITNESS_SECRET, {
      first_observed_at: 9,
      last_observed_at: START - 1,
    });
    await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: { ...emptyEvidence(), witness_receipts: [regressed] },
    });
    expect(onlyEntry(journal).witnesses[WITNESS_KEY]).toMatchObject({
      first_ingested_at: START,
      latest_ingested_at: START,
      first_observed_at: 10,
      last_observed_at: START,
    });
  });

  it("captures witness policy once and rejects later config substitution", async () => {
    const pair = await enrollment();
    const journal = new MemoryJournal();
    const policy = trustedPolicy();
    const config = {
      authority_id: "captured-authority",
      trusted_now: () => START,
      witness_policy: policy,
      journal,
    };
    const localAuthority = createAssuranceEnrollmentObservationAuthority(config);
    config.witness_policy = trustedPolicy({
      policy_digest: "22".repeat(32),
      witnesses: new Map(),
    });
    await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: { ...emptyEvidence(), witness_receipts: [signedReceipt(pair)] },
    });
    expect(onlyEntry(journal).policy_digest).toBe("11".repeat(32));
  });
});

describe("BLUE TEAM VALIDATION: synthetic/local absorbing contests and pins", () => {
  it("keeps a pre-pin contest absorbing after later evidence disappears", async () => {
    const pair = await enrollment();
    const journal = new MemoryJournal();
    let now = START;
    const localAuthority = authority(journal, () => now);
    const contested = await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: { ...emptyEvidence(), contests: [await contest(pair)] },
    });
    now += WINDOW * 2;
    const replay = await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: emptyEvidence(),
    });
    expect(contested).toMatchObject({ state: "contested" });
    expect(replay).toMatchObject({ state: "contested" });
    expect(onlyEntry(journal).contested).toBe(true);
  });

  it("retries a pre-pin CAS race and observes the racing contest before verification", async () => {
    const pair = await enrollment();
    const base = new MemoryJournal();
    let now = START;
    const localAuthority = authority(base, () => now);
    await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: emptyEvidence(),
    });
    now += WINDOW;
    const racingContest = await contest(pair);
    let raced = false;
    const racingJournal: EnrollmentObservationJournal = {
      load: (key) => base.load(key),
      compareAndSwap(key, expectedRevision, next) {
        if (!raced && next.pin !== null) {
          raced = true;
          const current = base.load(key)!;
          base.entries.set(key, {
            ...current,
            revision: current.revision + 1,
            contested: true,
            conflicts: [{
              digest: racingContest.id,
              first_ingested_at: now,
              kind: "contest",
            }],
          });
          return "conflict";
        }
        return base.compareAndSwap(key, expectedRevision, next);
      },
    };
    const result = await evaluateEnrollmentEligibility(
      authority(racingJournal, () => now),
      { ...pair, evidence: emptyEvidence() },
    );
    expect(result).toMatchObject({ state: "contested" });
    expect(base.load([...base.entries.keys()][0]!)?.pin).toBeNull();
  });

  it("retains an exact pin while journaling late immature receipts and contests as warnings", async () => {
    const pair = await enrollment();
    const journal = new MemoryJournal();
    let now = START;
    const localAuthority = authority(journal, () => now);
    await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: emptyEvidence(),
    });
    now += WINDOW;
    const pinned = await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: emptyEvidence(),
    });
    const retainedDigest = onlyEntry(journal).pin?.eligibility_basis_digest;
    now += 1;
    const late = await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: {
        ...emptyEvidence(),
        witness_receipts: [signedReceipt(pair, WITNESS_SECRET, {
          last_observed_at: now,
        })],
        contests: [await contest(pair)],
      },
    });
    expect(pinned).toMatchObject({ state: "verified", warnings: [] });
    expect(late).toMatchObject({
      state: "verified",
      warnings: ["assurance-enrollment-contested"],
    });
    expect(onlyEntry(journal).pin?.eligibility_basis_digest).toBe(retainedDigest);
    expect(onlyEntry(journal).first_candidate_ingested_at).toBe(START);
  });

  it("rejects a nonmatching acceptance instead of replacing a retained pin", async () => {
    const pair = await enrollment();
    const journal = new MemoryJournal();
    let now = START;
    const localAuthority = authority(journal, () => now);
    await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: emptyEvidence(),
    });
    now += WINDOW;
    await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: emptyEvidence(),
    });
    const acceptanceBody = JSON.parse(pair.acceptance.content) as Record<string, unknown>;
    const alternate = await assuranceEvent(
      ACTIVE_SECRET,
      31000,
      "assurance-head",
      acceptanceBody.profile as string,
      { ...acceptanceBody, created_at: 4 },
    );
    expect(await evaluateEnrollmentEligibility(localAuthority, {
      inception: pair.inception,
      acceptance: alternate,
      evidence: emptyEvidence(),
    })).toEqual({
      verdict: "reject",
      reason_code: "assurance-pin-conflict",
    });
  });

  it("fails closed when retained pin provenance is mutated", async () => {
    const pair = await enrollment();
    const base = new MemoryJournal();
    let now = START;
    const original = authority(base, () => now);
    await evaluateEnrollmentEligibility(original, { ...pair, evidence: emptyEvidence() });
    now += WINDOW;
    await evaluateEnrollmentEligibility(original, { ...pair, evidence: emptyEvidence() });
    const corrupted: EnrollmentObservationJournal = {
      load(key) {
        const entry = base.load(key);
        if (entry?.pin === null || entry === null) return entry;
        return {
          ...entry,
          pin: {
            ...entry.pin,
            eligibility_basis_digest: "ff".repeat(32),
          },
        };
      },
      compareAndSwap: (...args) => base.compareAndSwap(...args),
    };
    const result = await evaluateEnrollmentEligibility(
      authority(corrupted, () => now),
      { ...pair, evidence: emptyEvidence() },
    );
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "assurance-pin-conflict",
    });
  });
});

describe("BLUE TEAM VALIDATION: synthetic/local callback boundary hardening", () => {
  it("rejects proxy/accessor callbacks without invocation and snapshots journal results", async () => {
    const pair = await enrollment();
    const journal = new MemoryJournal();
    const config = {
      authority_id: "local",
      trusted_now: () => START,
      witness_policy: trustedPolicy(),
      journal,
    };
    expect(() => createAssuranceEnrollmentObservationAuthority(new Proxy(config, {})))
      .toThrow(/observation-authority-invalid/);
    let getterCalls = 0;
    const accessor = { ...config } as Record<string, unknown>;
    Object.defineProperty(accessor, "trusted_now", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return () => START;
      },
    });
    expect(() => createAssuranceEnrollmentObservationAuthority(
      accessor as typeof config,
    )).toThrow(/observation-authority-invalid/);
    expect(getterCalls).toBe(0);

    const localAuthority = authority(journal, () => START);
    const result = await evaluateEnrollmentEligibility(localAuthority, {
      ...pair,
      evidence: emptyEvidence(),
    });
    expect(result).toMatchObject({ state: "pending" });
    const loaded = onlyEntry(journal) as unknown as Record<string, unknown>;
    expect(() => {
      loaded.contested = true;
    }).toThrow(TypeError);
    expect(onlyEntry(journal).contested).toBe(false);
  });
});
