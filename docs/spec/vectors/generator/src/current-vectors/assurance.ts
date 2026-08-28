import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import {
  createAssuranceEnrollmentObservationAuthority,
  evaluateEnrollmentEligibility,
  type AssuranceEnrollmentObservationEvidence,
  type EnrollmentInception,
  type EnrollmentObservationReceipt,
} from "../assurance.js";
import { domainSeparatedJcsDigest } from "../credential-continuity.js";
import { QUALIFIED_VERSION } from "../family.js";
import { bytesToHex, hexToBytes } from "../hex.js";
import { jcsCanonicalize } from "../jcs.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "../nostr.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const AUX_RAND = "00".repeat(32);
const secret = (value: number): string => value.toString(16).padStart(64, "0");
const COLD_SECRET = secret(1);
const ACTIVE_SECRET = secret(2);
const SUCCESSION_SECRET = secret(3);
const EPOCH_SECRET = secret(4);
const WITNESS_SECRET = secret(5);
const WRONG_SECRET = secret(9);
const SECOND_WITNESS_SECRET = secret(11);
const COLD_KEY = getPublicKey(COLD_SECRET);
const ACTIVE_KEY = getPublicKey(ACTIVE_SECRET);
const SUCCESSION_KEY = getPublicKey(SUCCESSION_SECRET);
const EPOCH_KEY = getPublicKey(EPOCH_SECRET);
const WITNESS_KEY = getPublicKey(WITNESS_SECRET);
const SECOND_WITNESS_KEY = getPublicKey(SECOND_WITNESS_SECRET);
const WRONG_KEY = getPublicKey(WRONG_SECRET);
const CREATED_AT = 1_785_000_000;
const OBSERVATION_NOW = CREATED_AT + 700_000;
const WINDOW = 604_800;

const commitment = (key: string): string => bytesToHex(sha256(hexToBytes(key)));
const proof = (secretKey: string, digest: string): string => bytesToHex(
  schnorr.sign(digest, hexToBytes(secretKey), hexToBytes(AUX_RAND)),
);

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

async function enrolledPersona(options: {
  witnesses?: EnrollmentInception["witnesses"];
  witnessThreshold?: number;
  coldSecret?: string;
} = {}) {
  const coldSecret = options.coldSecret ?? COLD_SECRET;
  const coldRoot = getPublicKey(coldSecret);
  const inceptionBody: EnrollmentInception = {
    profile: "heterodyne.assurance.enrollment-inception.v1",
    spec_version: QUALIFIED_VERSION,
    active_key: ACTIVE_KEY,
    created_at: CREATED_AT,
    predecessor: null,
    cold_root: coldRoot,
    succession_authority: SUCCESSION_KEY,
    epoch_policy: {
      mode: "pre-rotation",
      current_keys: [EPOCH_KEY],
      next_key_commitments: [commitment(getPublicKey(secret(7)))],
    },
    witnesses: options.witnesses ?? [{ key: WITNESS_KEY, weight: 1 }],
    thresholds: { epoch: 1, witness: options.witnessThreshold ?? 1 },
    associated_key_policy: {
      active_key: [{ role: "agent", scope: ["nostr:kind:1"] }],
      epoch_threshold: [{ role: "client", scope: ["repository:read"] }],
    },
  };
  const inception = await assuranceEvent(
    coldSecret,
    31_002,
    `assurance-inception:${ACTIVE_KEY}`,
    inceptionBody.profile,
    inceptionBody,
    [ACTIVE_KEY],
  );
  const acceptanceBody = {
    profile: "heterodyne.assurance.active-key-acceptance.v1" as const,
    spec_version: QUALIFIED_VERSION,
    active_key: ACTIVE_KEY,
    created_at: CREATED_AT + 1,
    predecessor: inception.id,
    inception_event_id: inception.id,
    cold_root: coldRoot,
    cold_root_signature: inception.sig,
    assurance_head: inception.id,
    state: "assured" as const,
  };
  const acceptance = await assuranceEvent(
    ACTIVE_SECRET,
    31_000,
    "assurance-head",
    acceptanceBody.profile,
    acceptanceBody,
  );
  return { inception, acceptance, inceptionBody, acceptanceBody };
}

function baseEvidence(
  overrides: Partial<AssuranceEnrollmentObservationEvidence> = {},
): AssuranceEnrollmentObservationEvidence {
  return {
    local_first_observed_at: OBSERVATION_NOW - WINDOW,
    witness_receipts: [],
    contests: [],
    competing_inceptions: [],
    authoritative_pin: null,
    ...overrides,
  };
}

async function evaluate(
  pair: Awaited<ReturnType<typeof enrolledPersona>>,
  evidence: AssuranceEnrollmentObservationEvidence,
): Promise<Awaited<ReturnType<typeof evaluateEnrollmentEligibility>>> {
  return evaluateEnrollmentEligibility(
    createAssuranceEnrollmentObservationAuthority({
      trusted_now: () => OBSERVATION_NOW,
      load_evidence: async () => evidence,
    }),
    pair,
  );
}

function output(result: Awaited<ReturnType<typeof evaluate>>): Record<string, unknown> {
  if ("verdict" in result) return result;
  return result.reason === null
    ? {
        verdict: "accept",
        state: result.state,
        warnings: result.warnings,
        assurance_head: result.normalized.head,
      }
    : {
        verdict: "reject",
        reason_code: result.reason,
        state: result.state,
        warnings: result.warnings,
        assurance_head: result.normalized.head,
      };
}

async function enrollmentContest(
  pair: Awaited<ReturnType<typeof enrolledPersona>>,
  signingSecret = ACTIVE_SECRET,
): Promise<NostrSignedEvent> {
  const body = {
    profile: "heterodyne.assurance.enrollment-contest.v1",
    spec_version: QUALIFIED_VERSION,
    inception_event_id: pair.inception.id,
    cold_root: COLD_KEY,
  };
  return signEvent({
    secretKey: signingSecret,
    created_at: CREATED_AT + 50,
    kind: 31_006,
    tags: [["d", pair.inception.id], ["p", COLD_KEY]],
    content: jcsCanonicalize(body),
    auxRand: AUX_RAND,
  });
}

async function competingEnrollment() {
  const pair = await enrolledPersona({ coldSecret: WRONG_SECRET });
  return {
    inception: pair.inception,
    acceptance: pair.acceptance,
  };
}

function receipt(
  pair: Awaited<ReturnType<typeof enrolledPersona>>,
  signingSecret: string,
): EnrollmentObservationReceipt {
  const unsigned = {
    profile: "heterodyne.assurance.enrollment-observation-receipt.v1" as const,
    spec_version: QUALIFIED_VERSION as EnrollmentObservationReceipt["spec_version"],
    inception_event_id: pair.inception.id,
    active_key: ACTIVE_KEY,
    cold_root: COLD_KEY,
    first_observed_at: OBSERVATION_NOW - WINDOW,
    last_observed_at: OBSERVATION_NOW,
    conflict_free: true as const,
    witness_key: getPublicKey(signingSecret),
  };
  return {
    ...unsigned,
    signature: proof(
      signingSecret,
      domainSeparatedJcsDigest(
        "heterodyne-assurance-enrollment-observation-v1",
        unsigned,
      ),
    ),
  };
}

export async function buildAssuranceCases(): Promise<CurrentVectorCase[]> {
  const pair = await enrolledPersona();
  const firstObserved = OBSERVATION_NOW - WINDOW;
  const contest = await enrollmentContest(pair);
  const competitor = await competingEnrollment();
  const forgedContest = await enrollmentContest(pair, WRONG_SECRET);

  const pendingEvidence = baseEvidence({ local_first_observed_at: firstObserved + 1 });
  const verifiedEvidence = baseEvidence({ local_first_observed_at: firstObserved });
  const contestEvidence = baseEvidence({
    contests: [{ observed_at: firstObserved + 1, event: contest }],
  });
  const competitorEvidence = baseEvidence({
    competing_inceptions: [{
      observed_at: firstObserved + 1,
      inception: competitor.inception,
      acceptance: competitor.acceptance,
    }],
  });
  const forgedEvidence = baseEvidence({
    contests: [{ observed_at: firstObserved + 1, event: forgedContest }],
  });
  const lateEvidence = baseEvidence({
    local_first_observed_at: firstObserved - WINDOW,
    contests: [{ observed_at: firstObserved + 1, event: contest }],
    authoritative_pin: {
      active_key: ACTIVE_KEY,
      inception_event_id: pair.inception.id,
      cold_root: COLD_KEY,
      accepted_head: pair.acceptance.id,
      state: "verified",
      observed_at: firstObserved,
    },
  });

  const witnessPair = await enrolledPersona({
    witnesses: [
      { key: WITNESS_KEY, weight: 1 },
      { key: SECOND_WITNESS_KEY, weight: 1 },
    ],
    witnessThreshold: 2,
  });
  const witnessPassEvidence = baseEvidence({
    local_first_observed_at: null,
    witness_receipts: [
      receipt(witnessPair, WITNESS_SECRET),
      receipt(witnessPair, SECOND_WITNESS_SECRET),
    ],
  });
  const witnessFailEvidence = baseEvidence({
    local_first_observed_at: null,
    witness_receipts: [receipt(witnessPair, WITNESS_SECRET)],
  });

  const results = await Promise.all([
    evaluate(pair, pendingEvidence),
    evaluate(pair, verifiedEvidence),
    evaluate(pair, contestEvidence),
    evaluate(pair, competitorEvidence),
    evaluate(pair, forgedEvidence),
    evaluate(pair, lateEvidence),
    evaluate(witnessPair, witnessPassEvidence),
    evaluate(witnessPair, witnessFailEvidence),
  ]);
  const ids = [
    "enrollment-pending-w-minus-one",
    "enrollment-verified-at-window",
    "enrollment-timely-contest",
    "enrollment-competing-inception",
    "enrollment-forged-contest-ignored",
    "enrollment-late-warning-no-unpin",
    "witness-threshold-pass",
    "witness-threshold-fail",
  ] as const;
  const evidences = [
    pendingEvidence,
    verifiedEvidence,
    contestEvidence,
    competitorEvidence,
    forgedEvidence,
    lateEvidence,
    witnessPassEvidence,
    witnessFailEvidence,
  ];
  const descriptions = [
    "Enrollment remains pending one second before the local observation window matures.",
    "Enrollment becomes verified at the exact local observation-window boundary.",
    "An authenticated contest observed during the window makes enrollment contested.",
    "A reciprocal competing inception observed during the window makes enrollment contested.",
    "A contest not signed by the candidate active key is ignored.",
    "Late authenticated contest evidence warns without unpinning a verified enrollment.",
    "Distinct configured witness receipts whose weight reaches threshold verify enrollment.",
    "Insufficient configured witness weight leaves enrollment pending.",
  ];

  return ids.map((id, index) => {
    const expected = output(results[index]);
    return {
      relativePath: `assurance/${id}.json`,
      vector_id: `assurance/${id}`,
      owner_document: "assurance" as const,
      ...index === 2
        ? { profile: "heterodyne-assurance-enrollment-contest-profile-v1" }
        : index === 0
        ? { profile: "heterodyne-assurance-enrollment-inception-v1" }
        : {},
      spec_refs: [currentSpecRef(index === 5
        ? "assurance-pinning"
        : "assurance-enrollment-window")],
      invariants: ["ASSURANCE-I-ENROLLMENT-WINDOWED"],
      reason_codes: expected.verdict === "reject" ? [String(expected.reason_code)] : [],
      description: descriptions[index],
      direction: "consume" as const,
      input: {
        inception: index >= 6 ? witnessPair.inception : pair.inception,
        acceptance: index >= 6 ? witnessPair.acceptance : pair.acceptance,
        trusted_now: OBSERVATION_NOW,
        evidence: evidences[index],
      },
      expected_output: expected,
    };
  });
}
