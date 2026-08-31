import { describe, expect, it } from "vitest";
import { schnorr } from "@noble/curves/secp256k1";
import { domainSeparatedJcsDigest } from "./credential-continuity.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import {
  assuranceEnrollmentWitnessPolicyDigest,
  commitAssuranceEnrollmentDowngrade,
  createAssuranceEnrollmentObservationAuthority,
  evaluateEnrollmentEligibility,
  resolveAssuranceEnrollmentPinForDowngrade,
  type AssuranceEnrollmentAuthoritativePin,
  type EnrollmentObservationJournal,
  type EnrollmentObservationJournalEntry,
} from "./assurance-observation.js";
import {
  commitAssuranceDowngrade,
  evaluateAssuranceDowngrade,
  type VerifiedAssuranceDowngrade,
} from "./assurance-downgrade.js";

// BLUE TEAM VALIDATION: synthetic/local fixtures below are deterministic,
// minimal, and non-deployable: no live targets; no production deployments;
// no real credentials/accounts; no external systems; no reusable payloads.

const AUX_RAND = "00".repeat(32);
const secret = (value: number): string => value.toString(16).padStart(64, "0");
const COLD_SECRET = secret(201);
const ACTIVE_SECRET = secret(202);
const WRONG_SECRET = secret(203);
const COLD_KEY = getPublicKey(COLD_SECRET);
const ACTIVE_KEY = getPublicKey(ACTIVE_SECRET);
const START = 1_810_000_000;
const WINDOW = 604_800;
const INTEGRITY_KEY = "d4".repeat(32);
const PIN_INCEPTION_SIGNATURES = new WeakMap<object, string>();

class MemoryJournal implements EnrollmentObservationJournal {
  readonly entries = new Map<string, EnrollmentObservationJournalEntry>();
  conflictNextCommit = false;
  throwNextCommit = false;

  load(key: string): EnrollmentObservationJournalEntry | null {
    return this.entries.get(key) ?? null;
  }

  compareAndSwap(
    key: string,
    expectedRevision: number | null,
    next: EnrollmentObservationJournalEntry,
  ): "committed" | "conflict" {
    if (this.throwNextCommit) {
      this.throwNextCommit = false;
      throw new Error("synthetic local persistence failure");
    }
    if (this.conflictNextCommit) {
      this.conflictNextCommit = false;
      return "conflict";
    }
    const current = this.entries.get(key);
    if ((current?.revision ?? null) !== expectedRevision) return "conflict";
    this.entries.set(key, next);
    return "committed";
  }
}

function observationAuthority(journal: EnrollmentObservationJournal, now: () => number) {
  const policy = { minimum_weight: 0, witnesses: new Map<string, number>() };
  return createAssuranceEnrollmentObservationAuthority({
    authority_id: "downgrade-test-authority",
    trusted_now: now,
    witness_policy: {
      ...policy,
      policy_digest: assuranceEnrollmentWitnessPolicyDigest(policy),
    },
    journal_integrity_key: INTEGRITY_KEY,
    journal,
  });
}

async function assuranceEvent(
  secretKey: string,
  body: Readonly<Record<string, unknown>>,
): Promise<NostrSignedEvent> {
  return signEvent({
    secretKey,
    created_at: body.created_at as number,
    kind: 31000,
    tags: [
      ["d", "assurance-head"],
      ["profile", body.profile as string],
    ],
    content: jcsCanonicalize(body),
    auxRand: AUX_RAND,
  });
}

async function enrollment() {
  const inceptionBody = {
    profile: "heterodyne.assurance.enrollment-inception.v1",
    spec_version: "heterodyne/0.6.0",
    active_key: ACTIVE_KEY,
    created_at: 1,
    predecessor: null,
    cold_root: COLD_KEY,
    succession_authority: null,
    epoch_policy: { mode: "none", current_keys: [], next_key_commitments: [] },
    witnesses: [],
    thresholds: { epoch: 0, witness: 0 },
    associated_key_policy: { active_key: [], epoch_threshold: [] },
  };
  const inception = await signEvent({
    secretKey: COLD_SECRET,
    created_at: inceptionBody.created_at,
    kind: 31002,
    tags: [
      ["d", `assurance-inception:${ACTIVE_KEY}`],
      ["profile", inceptionBody.profile],
      ["p", ACTIVE_KEY],
    ],
    content: jcsCanonicalize(inceptionBody),
    auxRand: AUX_RAND,
  });
  const acceptanceBody = {
    profile: "heterodyne.assurance.active-key-acceptance.v1",
    spec_version: "heterodyne/0.6.0",
    active_key: ACTIVE_KEY,
    created_at: 2,
    predecessor: inception.id,
    inception_event_id: inception.id,
    cold_root: COLD_KEY,
    cold_root_signature: inception.sig,
    assurance_head: inception.id,
    state: "assured",
  };
  return {
    inception,
    acceptance: await assuranceEvent(ACTIVE_SECRET, acceptanceBody),
  };
}

async function genuinePin(options: { journal?: MemoryJournal; restart?: boolean } = {}) {
  const pair = await enrollment();
  const journal = options.journal ?? new MemoryJournal();
  let now = START;
  let authority = observationAuthority(journal, () => now);
  await evaluateEnrollmentEligibility(authority, {
    ...pair,
    evidence: { witness_receipts: [], contests: [], competing_enrollments: [] },
  });
  now += WINDOW;
  const closed = await evaluateEnrollmentEligibility(authority, {
    ...pair,
    evidence: { witness_receipts: [], contests: [], competing_enrollments: [] },
  });
  if (options.restart) {
    authority = observationAuthority(journal, () => now);
  }
  const result = options.restart
    ? await evaluateEnrollmentEligibility(authority, {
      ...pair,
      evidence: { witness_receipts: [], contests: [], competing_enrollments: [] },
    })
    : closed;
  if ("verdict" in result || result.state !== "verified" || result.retained_pin === null) {
    throw new Error("synthetic retained pin was not returned");
  }
  PIN_INCEPTION_SIGNATURES.set(result.retained_pin, pair.inception.sig);
  return { pair, journal, authority, pin: result.retained_pin };
}

function recoveryProofBody(
  pin: AssuranceEnrollmentAuthoritativePin,
  overrides: Readonly<Record<string, unknown>> = {},
) {
  return {
    active_key: pin.active_key,
    assurance_head: pin.accepted_head,
    created_at: START + WINDOW + 1,
    inception_event_id: pin.inception_event_id,
    predecessor: pin.accepted_head,
    ...overrides,
  };
}

async function signedDowngrade(
  pin: AssuranceEnrollmentAuthoritativePin,
  options: Readonly<{
    activeSecret?: string;
    recoverySecret?: string;
    overrides?: Readonly<Record<string, unknown>>;
    omitConsent?: boolean;
  }> = {},
): Promise<NostrSignedEvent> {
  const proofBody = recoveryProofBody(pin, options.overrides);
  const body: Record<string, unknown> = {
    profile: "heterodyne.assurance.active-key-acceptance.v1",
    spec_version: "heterodyne/0.6.0",
    ...proofBody,
    cold_root: pin.cold_root,
    cold_root_signature: PIN_INCEPTION_SIGNATURES.get(pin) ?? "00".repeat(64),
    state: "downgraded",
  };
  if (!options.omitConsent) {
    body.downgrade_consent = {
      recovery_authority: getPublicKey(options.recoverySecret ?? COLD_SECRET),
      signature: bytesToHex(schnorr.sign(
        domainSeparatedJcsDigest(
          "heterodyne-assurance-downgrade-v1",
          proofBody,
        ),
        hexToBytes(options.recoverySecret ?? COLD_SECRET),
        hexToBytes(AUX_RAND),
      )),
    };
  }
  return assuranceEvent(options.activeSecret ?? ACTIVE_SECRET, body);
}

function acceptedArtifact(
  verdict: ReturnType<typeof evaluateAssuranceDowngrade>,
): VerifiedAssuranceDowngrade {
  expect(verdict).toMatchObject({ verdict: "accept" });
  if (verdict.verdict !== "accept") throw new Error("expected accepted artifact");
  return verdict.normalized;
}

describe("BLUE TEAM VALIDATION: synthetic/local dual-signature Assurance downgrade", () => {
  it("BLUE TEAM VALIDATION: synthetic/local commits a real dual-signature event and caches only the exact completed retry", async () => {
    const { pin, journal } = await genuinePin();
    const source = await signedDowngrade(pin);
    const artifact = acceptedArtifact(evaluateAssuranceDowngrade(pin, source));
    const committed = commitAssuranceDowngrade(artifact);

    expect(committed).toMatchObject({
      verdict: "accept",
      normalized: {
        state: "downgraded",
        active_key: pin.active_key,
        inception_event_id: pin.inception_event_id,
        cold_root: pin.cold_root,
        accepted_head: pin.accepted_head,
        downgrade_event_id: source.id,
      },
    });
    expect(commitAssuranceDowngrade(artifact)).toEqual(committed);
    expect([...journal.entries.values()][0]).toMatchObject({
      revision: pin.eligibility_basis.closing_revision + 1,
      terminal: { state: "downgraded", downgrade_event_id: source.id },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects boolean and structural pin lookalikes", async () => {
    const { pin } = await genuinePin();
    const source = await signedDowngrade(pin);
    const booleanLookalike = {
      ...structuredClone(pin),
      active_key_consent: true,
      recovery_authority_proof: true,
    };
    expect(evaluateAssuranceDowngrade(booleanLookalike as never, source))
      .toEqual({ verdict: "reject", reason_code: "assurance-pin-conflict" });
    expect(evaluateAssuranceDowngrade(structuredClone(pin), source))
      .toEqual({ verdict: "reject", reason_code: "assurance-pin-conflict" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects fabricated and foreign transitions at the private terminal bridge", async () => {
    const { pin, journal } = await genuinePin();
    const context = resolveAssuranceEnrollmentPinForDowngrade(pin);
    expect(context).not.toBeNull();
    expect(commitAssuranceEnrollmentDowngrade(context!.capability, {
      active_key: pin.active_key,
      inception_event_id: pin.inception_event_id,
      cold_root: pin.cold_root,
      accepted_head: pin.accepted_head,
      predecessor: pin.accepted_head,
      created_at: START + WINDOW + 1,
      downgrade_event_id: "44".repeat(32),
      downgrade_event_signature: "55".repeat(64),
      transition_digest: "66".repeat(32),
      binding_digest: "77".repeat(32),
    } as never)).toEqual({
      verdict: "reject",
      reason_code: "assurance-pin-conflict",
    });
    expect([...journal.entries.values()][0]?.terminal).toBeNull();

    const foreign = await genuinePin();
    const foreignArtifact = acceptedArtifact(evaluateAssuranceDowngrade(
      foreign.pin,
      await signedDowngrade(foreign.pin),
    ));
    expect(commitAssuranceEnrollmentDowngrade(
      context!.capability,
      foreignArtifact,
    )).toEqual({
      verdict: "reject",
      reason_code: "assurance-pin-conflict",
    });
    expect([...journal.entries.values()][0]?.terminal).toBeNull();
    expect([...foreign.journal.entries.values()][0]?.terminal).toBeNull();
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects missing or wrong recovery consent", async () => {
    const { pin } = await genuinePin();
    expect(evaluateAssuranceDowngrade(pin, await signedDowngrade(pin, {
      omitConsent: true,
    }))).toEqual({
      verdict: "reject",
      reason_code: "assurance-downgrade-consent-required",
    });
    expect(evaluateAssuranceDowngrade(pin, await signedDowngrade(pin, {
      recoverySecret: WRONG_SECRET,
    }))).toEqual({
      verdict: "reject",
      reason_code: "assurance-downgrade-consent-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects the wrong active signer and exact signed-byte mutation", async () => {
    const { pin } = await genuinePin();
    expect(evaluateAssuranceDowngrade(pin, await signedDowngrade(pin, {
      activeSecret: WRONG_SECRET,
    }))).toEqual({
      verdict: "reject",
      reason_code: "assurance-downgrade-consent-required",
    });
    const valid = await signedDowngrade(pin);
    expect(evaluateAssuranceDowngrade(pin, {
      ...valid,
      content: `${valid.content} `,
    })).toEqual({
      verdict: "reject",
      reason_code: "assurance-downgrade-consent-required",
    });
    const { sig: _sig, ...missingOuterSignature } = valid;
    expect(evaluateAssuranceDowngrade(pin, missingOuterSignature)).toEqual({
      verdict: "reject",
      reason_code: "assurance-downgrade-consent-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects wrong inception, head, and predecessor bindings", async () => {
    const { pin } = await genuinePin();
    for (const overrides of [
      { inception_event_id: "11".repeat(32) },
      { assurance_head: "22".repeat(32) },
      { predecessor: "33".repeat(32) },
    ]) {
      expect(evaluateAssuranceDowngrade(
        pin,
        await signedDowngrade(pin, { overrides }),
      ), JSON.stringify(overrides)).toEqual({
        verdict: "reject",
        reason_code: "assurance-head-mismatch",
      });
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned artifacts and source mutation after verification", async () => {
    const { pin } = await genuinePin();
    const source = await signedDowngrade(pin);
    const artifact = acceptedArtifact(evaluateAssuranceDowngrade(pin, source));
    expect(commitAssuranceDowngrade({ ...artifact } as never)).toEqual({
      verdict: "reject",
      reason_code: "assurance-downgrade-consent-required",
    });
    source.content = `${source.content} `;
    expect(commitAssuranceDowngrade(artifact)).toEqual({
      verdict: "reject",
      reason_code: "assurance-downgrade-consent-required",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects terminal CAS conflict without exposing an uncommitted accept", async () => {
    const journal = new MemoryJournal();
    const { pin } = await genuinePin({ journal });
    const artifact = acceptedArtifact(evaluateAssuranceDowngrade(
      pin,
      await signedDowngrade(pin),
    ));
    journal.conflictNextCommit = true;
    expect(commitAssuranceDowngrade(artifact)).toEqual({
      verdict: "reject",
      reason_code: "assurance-pin-conflict",
    });
    expect([...journal.entries.values()][0]?.terminal).toBeNull();
  });

  it("BLUE TEAM VALIDATION: synthetic/local fails closed when terminal persistence throws before commit", async () => {
    const journal = new MemoryJournal();
    const { pin } = await genuinePin({ journal });
    const artifact = acceptedArtifact(evaluateAssuranceDowngrade(
      pin,
      await signedDowngrade(pin),
    ));
    journal.throwNextCommit = true;
    expect(commitAssuranceDowngrade(artifact)).toEqual({
      verdict: "reject",
      reason_code: "assurance-pin-conflict",
    });
    expect([...journal.entries.values()][0]?.terminal).toBeNull();
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects mismatched replay and preserves terminal state across restart", async () => {
    const { pair, pin, journal } = await genuinePin({ restart: true });
    const first = acceptedArtifact(evaluateAssuranceDowngrade(
      pin,
      await signedDowngrade(pin),
    ));
    expect(commitAssuranceDowngrade(first)).toMatchObject({ verdict: "accept" });

    const replaySource = await signedDowngrade(pin, {
      overrides: { created_at: START + WINDOW + 2 },
    });
    const replayArtifact = acceptedArtifact(evaluateAssuranceDowngrade(pin, replaySource));
    expect(commitAssuranceDowngrade(replayArtifact)).toEqual({
      verdict: "reject",
      reason_code: "assurance-pin-conflict",
    });

    const restarted = observationAuthority(journal, () => START + WINDOW + 2);
    const retained = await evaluateEnrollmentEligibility(restarted, {
      ...pair,
      evidence: { witness_receipts: [], contests: [], competing_enrollments: [] },
    });
    expect(retained).toMatchObject({ state: "downgraded", retained_pin: pin });
  });
});
