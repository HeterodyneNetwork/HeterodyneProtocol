import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { associatedKeyRecordDigest, evaluateAssuranceAuthorityAt, evaluateAssociatedKey, evaluateEnrollment, evaluateSuccession, successionTransitionDigest, type AssociatedKeyRecord, type AssociatedKeyState, type AssuranceHeadState, type EnrollmentInception, type EnrollmentObservationReceipt, type SuccessionRecord, } from "../assurance.js";
import type { EnrollmentEvidenceInput } from "../assurance-observation.js";
import { evaluateAssuranceAssociatedKeyConsent, evaluateAssuranceCompromiseContinuation, evaluateAssuranceExport, evaluateAssurancePinPolicy, } from "../assurance-policy.js";
import { domainSeparatedJcsDigest } from "../credential-continuity.js";
import { QUALIFIED_VERSION } from "../family.js";
import { classifyRetiredKeyObservation } from "../follow-up-hardening.js";
import { bytesToHex, hexToBytes } from "../hex.js";
import { jcsCanonicalize } from "../jcs.js";
import { canonicalNip01, getPublicKey, signEvent, type NostrSignedEvent } from "../nostr.js";
import { currentSpecRef, type CurrentCaseFixture } from "./types.js";
const AUX_RAND = "00".repeat(32);
const secret = (value: number): string => value.toString(16).padStart(64, "0");
const COLD_SECRET = secret(1);
const ACTIVE_SECRET = secret(2);
const SUCCESSION_SECRET = secret(3);
const EPOCH_SECRET = secret(4);
const WITNESS_SECRET = secret(5);
const WRONG_SECRET = secret(9);
const SECOND_WITNESS_SECRET = secret(11);
const NEXT_ACTIVE_SECRET = secret(6);
const NEXT_EPOCH_SECRET = secret(7);
const FUTURE_EPOCH_SECRET = secret(8);
const SUBJECT_SECRET = secret(10);
const COLD_KEY = getPublicKey(COLD_SECRET);
const ACTIVE_KEY = getPublicKey(ACTIVE_SECRET);
const SUCCESSION_KEY = getPublicKey(SUCCESSION_SECRET);
const EPOCH_KEY = getPublicKey(EPOCH_SECRET);
const WITNESS_KEY = getPublicKey(WITNESS_SECRET);
const SECOND_WITNESS_KEY = getPublicKey(SECOND_WITNESS_SECRET);
const WRONG_KEY = getPublicKey(WRONG_SECRET);
const NEXT_ACTIVE_KEY = getPublicKey(NEXT_ACTIVE_SECRET);
const NEXT_EPOCH_KEY = getPublicKey(NEXT_EPOCH_SECRET);
const FUTURE_EPOCH_KEY = getPublicKey(FUTURE_EPOCH_SECRET);
const SUBJECT_KEY = getPublicKey(SUBJECT_SECRET);
const CREATED_AT = 1785000000;
const OBSERVATION_NOW = CREATED_AT + 700000;
const WINDOW = 604800;
const commitment = (key: string): string => bytesToHex(sha256(hexToBytes(key)));
const proof = (secretKey: string, digest: string): string => bytesToHex(schnorr.sign(digest, hexToBytes(secretKey), hexToBytes(AUX_RAND)));
async function assuranceEvent(secretKey: string, kind: number, d: string, profile: string, body: Record<string, unknown>, publicKeys: string[] = []): Promise<NostrSignedEvent> {
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
    const inception = await assuranceEvent(coldSecret, 31002, `assurance-inception:${ACTIVE_KEY}`, inceptionBody.profile, inceptionBody, [ACTIVE_KEY]);
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
    const acceptance = await assuranceEvent(ACTIVE_SECRET, 31000, "assurance-head", acceptanceBody.profile, acceptanceBody);
    return { inception, acceptance, inceptionBody, acceptanceBody };
}
function baseEvidence(overrides: Partial<EnrollmentEvidenceInput> = {}): EnrollmentEvidenceInput {
    return {
        witness_receipts: [],
        contests: [],
        competing_enrollments: [],
        ...overrides,
    };
}
async function enrollmentContest(pair: Awaited<ReturnType<typeof enrolledPersona>>, signingSecret = ACTIVE_SECRET): Promise<NostrSignedEvent> {
    const body = {
        profile: "heterodyne.assurance.enrollment-contest.v1",
        spec_version: QUALIFIED_VERSION,
        inception_event_id: pair.inception.id,
        cold_root: COLD_KEY,
    };
    return signEvent({
        secretKey: signingSecret,
        created_at: CREATED_AT + 50,
        kind: 31006,
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
function receipt(pair: Awaited<ReturnType<typeof enrolledPersona>>, signingSecret: string, firstObservedAt = 1, lastObservedAt = OBSERVATION_NOW): EnrollmentObservationReceipt {
    const unsigned = {
        profile: "heterodyne.assurance.enrollment-observation-receipt.v1" as const,
        spec_version: QUALIFIED_VERSION as EnrollmentObservationReceipt["spec_version"],
        inception_event_id: pair.inception.id,
        active_key: ACTIVE_KEY,
        cold_root: COLD_KEY,
        accepted_head: pair.acceptance.id,
        first_observed_at: firstObservedAt,
        last_observed_at: lastObservedAt,
        conflict_free: true as const,
        witness_key: getPublicKey(signingSecret),
    };
    return {
        ...unsigned,
        signature: proof(signingSecret, domainSeparatedJcsDigest("heterodyne-assurance-enrollment-observation-v1", unsigned)),
    };
}
function observationInput(
    pair: Awaited<ReturnType<typeof enrolledPersona>>,
    steps: ReadonlyArray<Readonly<{ at: number; evidence: EnrollmentEvidenceInput }>>,
    witnesses: ReadonlyArray<readonly [string, number]> = [[WITNESS_KEY, 1], [SECOND_WITNESS_KEY, 1]],
    minimumWeight = 1,
): Readonly<Record<string, unknown>> {
    return {
        inception: pair.inception,
        acceptance: pair.acceptance,
        authority_id: "current-vector-assurance-observer",
        witness_policy: {
            policy_digest: "11".repeat(32),
            minimum_weight: minimumWeight,
            witnesses,
        },
        steps,
    };
}
function acceptedHead(pair: Awaited<ReturnType<typeof enrolledPersona>>): AssuranceHeadState {
    const decision = evaluateEnrollment(pair);
    if (decision.verdict !== "accept") {
        throw new Error(`current Assurance enrollment fixture rejected: ${decision.reason_code}`);
    }
    return decision.normalized;
}
function successionRecord(current: AssuranceHeadState, overrides: Partial<SuccessionRecord> = {}): SuccessionRecord {
    const base: SuccessionRecord = {
        profile: "heterodyne.assurance.succession.v1",
        spec_version: QUALIFIED_VERSION,
        active_key: current.active_key,
        created_at: current.head_created_at + 10,
        predecessor: current.head,
        previous_active_key: current.active_key,
        previous_head: current.head,
        new_active_key: NEXT_ACTIVE_KEY,
        authorizing_evidence: {
            authority_class: "succession",
            authority_proofs: [{ authority_key: SUCCESSION_KEY, signature: "00".repeat(64) }],
            witness_receipts: [{ witness_key: WITNESS_KEY, signature: "00".repeat(64) }],
        },
        new_key_acceptance: { key: NEXT_ACTIVE_KEY, signature: "00".repeat(64) },
        class: "routine",
        next_succession_authority: SUCCESSION_KEY,
        next_epoch_policy: {
            mode: "pre-rotation",
            current_keys: [NEXT_EPOCH_KEY],
            next_key_commitments: [commitment(FUTURE_EPOCH_KEY)],
        },
        witnesses: [{ key: WITNESS_KEY, weight: 1 }],
        thresholds: { epoch: 1, witness: 1 },
        next_associated_key_policy: current.associated_key_policy,
        subordinate_reauthorizations: [],
    };
    return { ...base, ...overrides };
}
function signSuccession(body: SuccessionRecord, authoritySecret = SUCCESSION_SECRET, newKeySecret = NEXT_ACTIVE_SECRET, witnessSecret = WITNESS_SECRET): SuccessionRecord {
    const digest = successionTransitionDigest(body);
    return {
        ...body,
        authorizing_evidence: {
            ...body.authorizing_evidence,
            authority_proofs: body.authorizing_evidence.authority_proofs.map((entry) => ({
                ...entry,
                signature: proof(authoritySecret, digest),
            })),
            witness_receipts: body.authorizing_evidence.witness_receipts.map((entry) => ({
                ...entry,
                signature: proof(witnessSecret, digest),
            })),
        },
        new_key_acceptance: {
            ...body.new_key_acceptance,
            signature: proof(newKeySecret, digest),
        },
    };
}
async function successionEvent(body: SuccessionRecord, outerSecret = ACTIVE_SECRET): Promise<NostrSignedEvent> {
    return assuranceEvent(outerSecret, 31003, `assurance-succession:${body.previous_head}`, body.profile, body, [body.active_key, body.new_active_key]);
}
function associatedRecord(current: AssuranceHeadState, overrides: Partial<AssociatedKeyRecord> = {}): AssociatedKeyRecord {
    const base: AssociatedKeyRecord = {
        profile: "heterodyne.assurance.associated-key.v1",
        spec_version: QUALIFIED_VERSION,
        active_key: current.active_key,
        created_at: current.head_created_at + 2,
        predecessor: current.head,
        assurance_head: current.head,
        role: "agent",
        scope: ["nostr:kind:1"],
        issuer: current.active_key,
        issuer_authority: { class: "active-key", authority_proofs: [] },
        subject_key: SUBJECT_KEY,
        expires_at: current.head_created_at + 100,
        visibility: "public",
        subject_proof: "00".repeat(64),
        state: "active",
    };
    return { ...base, ...overrides };
}
function signAssociatedSubject(body: AssociatedKeyRecord): AssociatedKeyRecord {
    return {
        ...body,
        subject_proof: proof(SUBJECT_SECRET, associatedKeyRecordDigest(body)),
    };
}
async function associatedEvent(body: AssociatedKeyRecord): Promise<NostrSignedEvent> {
    return assuranceEvent(ACTIVE_SECRET, 31001, `assurance-associated:${body.active_key}:${body.role}:${body.subject_key}`, body.profile, body, [body.active_key]);
}

/**
 * Deterministic boundary-specific inputs used by the fixed profile oracle.
 * No registry data or semantic trace label participates in their construction.
 */
export async function buildAssuranceProfileBoundaryFixtures(): Promise<Readonly<{
    reciprocal: Readonly<Record<string, unknown>>;
    contest: Readonly<Record<string, unknown>>;
    succession: Readonly<Record<string, unknown>>;
    associated: Readonly<Record<string, unknown>>;
}>> {
    const pair = await enrolledPersona();
    const current = acceptedHead(pair);
    const succession = signSuccession(successionRecord(current));
    const associated = signAssociatedSubject(associatedRecord(current));
    const firstObserved = OBSERVATION_NOW - WINDOW;
    const forgedContest = await enrollmentContest(pair, WRONG_SECRET);
    return {
        reciprocal: {
            inception: pair.inception,
            acceptance: pair.acceptance,
        },
        contest: {
            ...observationInput(pair, [
                { at: firstObserved, evidence: baseEvidence() },
                { at: OBSERVATION_NOW, evidence: baseEvidence({ contests: [forgedContest] }) },
            ]),
        },
        succession: {
            current,
            event: await successionEvent(succession),
        },
        associated: {
            current,
            event: await associatedEvent(associated),
            now: associated.created_at,
            previous: null,
        },
    };
}
export async function buildAssuranceCases(): Promise<CurrentCaseFixture[]> {
    const pair = await enrolledPersona();
    const firstObserved = OBSERVATION_NOW - WINDOW;
    const contest = await enrollmentContest(pair);
    const competitor = await competingEnrollment();
    const forgedContest = await enrollmentContest(pair, WRONG_SECRET);
    const witnessPair = await enrolledPersona({
        witnesses: [
            { key: WITNESS_KEY, weight: 1 },
            { key: SECOND_WITNESS_KEY, weight: 1 },
        ],
        witnessThreshold: 2,
    });
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
    const inputs = [
        observationInput(pair, [
            { at: firstObserved + 1, evidence: baseEvidence() },
            { at: OBSERVATION_NOW, evidence: baseEvidence() },
        ]),
        observationInput(pair, [
            { at: firstObserved, evidence: baseEvidence() },
            { at: OBSERVATION_NOW, evidence: baseEvidence() },
        ]),
        observationInput(pair, [
            { at: firstObserved, evidence: baseEvidence() },
            { at: OBSERVATION_NOW, evidence: baseEvidence({ contests: [contest] }) },
        ]),
        observationInput(pair, [
            { at: firstObserved, evidence: baseEvidence() },
            { at: OBSERVATION_NOW, evidence: baseEvidence({
                competing_enrollments: [competitor],
            }) },
        ]),
        observationInput(pair, [
            { at: firstObserved, evidence: baseEvidence() },
            { at: OBSERVATION_NOW, evidence: baseEvidence({ contests: [forgedContest] }) },
        ]),
        observationInput(pair, [
            { at: firstObserved - WINDOW, evidence: baseEvidence() },
            { at: firstObserved, evidence: baseEvidence() },
            { at: OBSERVATION_NOW, evidence: baseEvidence({ contests: [contest] }) },
        ]),
        observationInput(witnessPair, [
            { at: firstObserved, evidence: baseEvidence({
                witness_receipts: [
                    receipt(witnessPair, WITNESS_SECRET, 1, firstObserved),
                    receipt(witnessPair, SECOND_WITNESS_SECRET, 1, firstObserved),
                ],
            }) },
            { at: OBSERVATION_NOW, evidence: baseEvidence({
                witness_receipts: [
                    receipt(witnessPair, WITNESS_SECRET, 1, OBSERVATION_NOW),
                    receipt(witnessPair, SECOND_WITNESS_SECRET, 1, OBSERVATION_NOW),
                ],
            }) },
        ], [[WITNESS_KEY, 1], [SECOND_WITNESS_KEY, 1]], 2),
        observationInput(witnessPair, [
            { at: firstObserved + 1, evidence: baseEvidence({
                witness_receipts: [receipt(witnessPair, WITNESS_SECRET, 1, firstObserved + 1)],
            }) },
            { at: OBSERVATION_NOW, evidence: baseEvidence({
                witness_receipts: [receipt(witnessPair, WITNESS_SECRET, 1, firstObserved + 1)],
            }) },
        ], [[WITNESS_KEY, 1], [SECOND_WITNESS_KEY, 1]], 2),
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
    const enrollmentCases = ids.map((id, index) => {
        return {
            vector_id: `assurance/${id}`,
            description: descriptions[index],
            direction: "consume" as const,
            input: inputs[index]!
        };
    });
    const current = acceptedHead(pair);
    const validSuccessionRecord = signSuccession(successionRecord(current));
    const validSuccessionEvent = await successionEvent(validSuccessionRecord);
    const validSuccessionDecision = evaluateSuccession({
        current,
        event: validSuccessionEvent,
    });
    const malformedSuccessionEvent = {
        ...validSuccessionEvent,
        sig: "00".repeat(64),
    };
    const malformedSuccessionDecision = evaluateSuccession({
        current,
        event: malformedSuccessionEvent,
    });
    const wrongPredecessorRecord = signSuccession(successionRecord(current, {
        predecessor: "dd".repeat(32),
    }));
    const wrongPredecessorEvent = await successionEvent(wrongPredecessorRecord);
    const wrongPredecessorDecision = evaluateSuccession({
        current,
        event: wrongPredecessorEvent,
    });
    const wrongHeadRecord = signSuccession(successionRecord(current, {
        previous_head: "ee".repeat(32),
    }));
    const wrongHeadEvent = await successionEvent(wrongHeadRecord);
    const wrongHeadDecision = evaluateSuccession({ current, event: wrongHeadEvent });
    const wrongOuterEvent = await successionEvent(validSuccessionRecord, SUCCESSION_SECRET);
    const wrongOuterDecision = evaluateSuccession({ current, event: wrongOuterEvent });
    const invalidNewKeyRecord = {
        ...validSuccessionRecord,
        new_key_acceptance: {
            ...validSuccessionRecord.new_key_acceptance,
            signature: "00".repeat(64),
        },
    };
    const invalidNewKeyEvent = await successionEvent(invalidNewKeyRecord);
    const invalidNewKeyDecision = evaluateSuccession({ current, event: invalidNewKeyEvent });
    const insufficientWitnessRecord = {
        ...validSuccessionRecord,
        authorizing_evidence: {
            ...validSuccessionRecord.authorizing_evidence,
            witness_receipts: validSuccessionRecord.authorizing_evidence.witness_receipts.map((entry) => ({ ...entry, signature: "00".repeat(64) })),
        },
    };
    const insufficientWitnessEvent = await successionEvent(insufficientWitnessRecord);
    const insufficientWitnessDecision = evaluateSuccession({
        current,
        event: insufficientWitnessEvent,
    });
    const compromiseBase = successionRecord(current, {
        class: "compromise",
        compromise_time: current.head_created_at + 1,
        authorizing_evidence: {
            authority_class: "recovery",
            authority_proofs: [{ authority_key: COLD_KEY, signature: "00".repeat(64) }],
            witness_receipts: [{ witness_key: WITNESS_KEY, signature: "00".repeat(64) }],
        },
        subordinate_reauthorizations: [{
                role: "agent",
                subject_key: WRONG_KEY,
                scope: ["nostr:kind:1"],
                expires_at: current.head_created_at + 3600,
            }],
    });
    const compromiseWithSubordinate = signSuccession(compromiseBase, COLD_SECRET);
    const compromiseWithSubordinateEvent = await successionEvent(compromiseWithSubordinate, COLD_SECRET);
    const subordinatePolicyInput = {
        transition_class: "compromise" as const,
        subordinate_reauthorization_ids: compromiseWithSubordinate
            .subordinate_reauthorizations.map(({ subject_key }) => subject_key),
    };
    const subordinateDecision = evaluateAssuranceCompromiseContinuation(subordinatePolicyInput);
    const cutoffInput = {
        created_at: current.head_created_at + 1,
        compromise_cutoff: current.head_created_at + 1,
    };
    const cutoffDecision = evaluateAssuranceAuthorityAt(cutoffInput.created_at, cutoffInput.compromise_cutoff);
    const postCompromiseInput = {
        signatureValid: true,
        createdAtInAuthorityWindow: true,
        compromiseSince: CREATED_AT,
        eventCreatedAt: CREATED_AT,
        repoCommitAncestorOfRetirementCheckpoint: false,
        trustedLocalReceiptBeforeRetirement: false,
    };
    const postCompromiseDecision = classifyRetiredKeyObservation(postCompromiseInput);
    const reciprocalInput = {
        inception: pair.inception,
        acceptance: { ...pair.acceptance, sig: "00".repeat(64) },
    };
    const reciprocalDecision = evaluateEnrollment(reciprocalInput);
    const requiredBase = associatedRecord(current);
    const { subject_proof: _subjectProof, ...withoutSubjectProof } = requiredBase;
    const subjectRequiredEvent = await associatedEvent(withoutSubjectProof);
    const subjectRequiredPolicyInput = {
        state: requiredBase.state,
        role: requiredBase.role,
        visibility: requiredBase.visibility,
        subject_proof_present: false,
        subject_proof_valid: false,
    } as const;
    const subjectRequiredDecision = evaluateAssuranceAssociatedKeyConsent(subjectRequiredPolicyInput);
    const subjectInvalidEvent = await associatedEvent(requiredBase);
    const subjectInvalidDecision = evaluateAssociatedKey({
        current,
        event: subjectInvalidEvent,
        now: requiredBase.created_at,
        previous: null,
    });
    const activeAssociatedRecord = signAssociatedSubject(associatedRecord(current));
    const activeAssociatedEvent = await associatedEvent(activeAssociatedRecord);
    const activeAssociatedDecision = evaluateAssociatedKey({
        current,
        event: activeAssociatedEvent,
        now: activeAssociatedRecord.created_at,
        previous: null,
    });
    const expiredAssociatedDecision = evaluateAssociatedKey({
        current,
        event: activeAssociatedEvent,
        now: activeAssociatedRecord.expires_at!,
        previous: null,
    });
    if (activeAssociatedDecision.verdict !== "accept") {
        throw new Error("current associated-key grant fixture rejected");
    }
    const activeAssociatedState: AssociatedKeyState = activeAssociatedDecision.normalized;
    const { subject_proof: _activeProof, ...activeWithoutProof } = activeAssociatedRecord;
    const revocationRecord: AssociatedKeyRecord = {
        ...activeWithoutProof,
        created_at: activeAssociatedRecord.created_at + 1,
        predecessor: activeAssociatedEvent.id,
        state: "revoked",
        revocation: {
            revoked_at: activeAssociatedRecord.created_at + 1,
            reason: "operator-request",
        },
    };
    const revocationEvent = await associatedEvent(revocationRecord);
    const revocationDecision = evaluateAssociatedKey({
        current,
        event: revocationEvent,
        now: revocationRecord.created_at,
        previous: activeAssociatedState,
    });
    const successionCases: CurrentCaseFixture[] = [
        {
            vector_id: "assurance/succession-valid",
            description: "A routine successor remains a distinct active key and advances only the explicitly bound next policy.",
            direction: "consume",
            input: { current, event: validSuccessionEvent }
        },
        {
            vector_id: "assurance/succession-schema-invalid",
            description: "A succession with an invalid outer event signature fails the closed record boundary.",
            direction: "consume",
            input: { current, event: malformedSuccessionEvent }
        },
        {
            vector_id: "assurance/succession-predecessor-mismatch",
            description: "A fully signed succession cannot skip the accepted predecessor event.",
            direction: "consume",
            input: { current, event: wrongPredecessorEvent }
        },
        {
            vector_id: "assurance/succession-head-mismatch",
            description: "A fully signed succession that names a different prior head is rejected.",
            direction: "consume",
            input: { current, event: wrongHeadEvent }
        },
        {
            vector_id: "assurance/succession-authority-invalid",
            description: "A routine succession carried by a non-active outer author is rejected despite valid inner proofs.",
            direction: "consume",
            input: { current, event: wrongOuterEvent }
        },
        {
            vector_id: "assurance/succession-new-key-acceptance-invalid",
            description: "Authority and witness proofs cannot substitute for the new key's proof over the identical transition digest.",
            direction: "consume",
            input: { current, event: invalidNewKeyEvent }
        },
        {
            vector_id: "assurance/succession-witness-threshold-unsatisfied",
            description: "A succession with valid authority and new-key proofs still fails without its configured witness threshold.",
            direction: "consume",
            input: { current, event: insufficientWitnessEvent }
        },
        {
            vector_id: "assurance/compromise-subordinate-continuation-forbidden",
            description: "A compromise recovery transition cannot carry an existing subordinate authorization forward.",
            direction: "consume",
            input: subordinatePolicyInput
        },
        {
            vector_id: "assurance/authority-at-compromise-cutoff",
            description: "Assurance authority is rejected at the exact inclusive compromise cutoff.",
            direction: "consume",
            input: cutoffInput
        },
        {
            vector_id: "assurance/retired-key-post-compromise",
            description: "Retired-key material at the inclusive accepted compromise cutoff is non-authoritative.",
            direction: "consume",
            input: postCompromiseInput
        },
        {
            vector_id: "assurance/reciprocal-proof-invalid",
            description: "A malformed active-key acceptance cannot attach Assurance to an otherwise valid Core persona.",
            direction: "consume",
            input: reciprocalInput
        },
    ];
    const associatedCases: CurrentCaseFixture[] = [
        {
            vector_id: "assurance/associated-key-subject-proof-required",
            description: "A public agent grant requires the subject key's proof of possession and consent.",
            direction: "consume",
            input: { ...subjectRequiredPolicyInput, associated_key_event: subjectRequiredEvent }
        },
        {
            vector_id: "assurance/associated-key-subject-proof-invalid",
            description: "A public agent subject proof must verify over the exact associated-key record digest.",
            direction: "consume",
            input: { current, event: subjectInvalidEvent, now: requiredBase.created_at, previous: null }
        },
        {
            vector_id: "assurance/associated-key-expired",
            description: "An associated key expires at its exact exclusive expiry boundary.",
            direction: "consume",
            input: { current, event: activeAssociatedEvent, now: activeAssociatedRecord.expires_at, previous: null }
        },
        {
            vector_id: "assurance/associated-key-revoked",
            description: "An issuer-authorized revocation is terminal without requiring subject cooperation.",
            direction: "consume",
            input: { current, event: revocationEvent, now: revocationRecord.created_at, previous: activeAssociatedState }
        },
    ];
    const retainedPin = {
        active_key: ACTIVE_KEY,
        assurance_head: pair.acceptance.id,
        recovery_authority: COLD_KEY,
    };
    const pinConflictInput = {
        retained_pin: retainedPin,
        presented_head: "aa".repeat(32),
        downgrade: null,
        authorized_successors: [] as string[],
    };
    const unilateralDowngradeInput = {
        retained_pin: retainedPin,
        presented_head: retainedPin.assurance_head,
        downgrade: { active_key_consent: true, recovery_authority_proof: false },
        authorized_successors: [] as string[],
    };
    const duplicityInput = {
        retained_pin: retainedPin,
        presented_head: retainedPin.assurance_head,
        downgrade: null,
        authorized_successors: ["bb".repeat(32), "cc".repeat(32)],
    };
    const exportInput = {
        active_key: ACTIVE_KEY,
        requested_aid: ACTIVE_KEY,
        requested_suite: "Ed25519",
        supported_suites: ["Ed25519"],
        accepted_features: ["continuity", "associated-keys"],
        mapped_features: ["associated-keys", "continuity"],
        required_members: ["active_key", "head"],
        mapped_members: { active_key: ACTIVE_KEY, head: pair.acceptance.id },
    };
    const exportCases = [
        ["lossless", exportInput],
        ["unsupported-suite", { ...exportInput, requested_suite: "P-256" }],
        ["unmappable-feature", { ...exportInput, mapped_features: ["continuity"] }],
        ["incomplete", { ...exportInput, mapped_members: { active_key: ACTIVE_KEY } }],
        ["aid-substitution", { ...exportInput, requested_aid: WRONG_KEY }],
    ] as const;
    const personaAuthorMismatchInput = {
        event: pair.acceptance,
        nip01_raw: canonicalNip01(pair.acceptance),
        stamp_policy: "optional" as const,
        active_persona_key: WRONG_KEY,
    };
    const keriWireInput = {
        serialized_record: "{\"v\":\"KERI10JSON000000_\"}",
    };
    return [
        ...enrollmentCases,
        ...successionCases,
        ...associatedCases,
        {
            vector_id: "assurance/persona-author-mismatch",
            description: "A valid NIP-01 event from a non-active persona key is rejected before optional Assurance can affect the Core verdict.",
            direction: "consume",
            input: personaAuthorMismatchInput,
        },
        {
            vector_id: "assurance/keri-wire-format-rejected",
            description: "A derived KERI10JSON export is rejected when presented in place of the registered NIP-01 Assurance record.",
            direction: "consume",
            input: keriWireInput,
        },
        {
            vector_id: "assurance/pin-conflict-rejected",
            description: "A presented Assurance head that conflicts with the retained verified pin cannot replace it.",
            direction: "consume",
            input: pinConflictInput
        },
        {
            vector_id: "assurance/unilateral-downgrade-rejected",
            description: "Active-key consent without the current recovery-authority proof cannot downgrade a retained pin.",
            direction: "consume",
            input: unilateralDowngradeInput
        },
        {
            vector_id: "assurance/duplicity-rejected",
            description: "Two distinct authorized successors of the same retained head stall instead of aliasing one persona author.",
            direction: "consume",
            input: duplicityInput
        },
        ...exportCases.map(([id, input]) => {
            const decision = evaluateAssuranceExport(input);
            return {
                vector_id: `assurance/export-${id}`,
                description: `Assurance export ${id.replaceAll("-", " ")} is evaluated against complete accepted semantics.`,
                direction: "consume" as const,
                input
            };
        }),
    ];
}
