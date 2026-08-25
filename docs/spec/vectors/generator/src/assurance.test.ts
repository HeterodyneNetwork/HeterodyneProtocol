import { describe, expect, it } from "vitest";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { jcsCanonicalize } from "./jcs.js";
import {
  associatedKeyRecordDigest,
  evaluateAssuranceAuthorityAt,
  evaluateAssociatedKey,
  evaluateEnrollment,
  evaluateSuccessorAcceptance,
  evaluateSuccession,
  successionTransitionDigest,
  type AssociatedKeyPolicy,
  type AssociatedKeyRecord,
  type AssociatedKeyState,
  type AssuranceHeadState,
  type EnrollmentInception,
  type SuccessionRecord,
} from "./assurance.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";

const AUX_RAND = "00".repeat(32);
const secret = (value: number): string => value.toString(16).padStart(64, "0");
const COLD_SECRET = secret(1);
const ACTIVE_SECRET = secret(2);
const SUCCESSION_SECRET = secret(3);
const EPOCH_SECRET = secret(4);
const WITNESS_SECRET = secret(5);
const NEXT_ACTIVE_SECRET = secret(6);
const NEXT_EPOCH_SECRET = secret(7);
const FUTURE_EPOCH_SECRET = secret(8);
const WRONG_SECRET = secret(9);
const SUBJECT_SECRET = secret(10);
const COLD_KEY = getPublicKey(COLD_SECRET);
const ACTIVE_KEY = getPublicKey(ACTIVE_SECRET);
const SUCCESSION_KEY = getPublicKey(SUCCESSION_SECRET);
const EPOCH_KEY = getPublicKey(EPOCH_SECRET);
const WITNESS_KEY = getPublicKey(WITNESS_SECRET);
const NEXT_ACTIVE_KEY = getPublicKey(NEXT_ACTIVE_SECRET);
const NEXT_EPOCH_KEY = getPublicKey(NEXT_EPOCH_SECRET);
const FUTURE_EPOCH_KEY = getPublicKey(FUTURE_EPOCH_SECRET);
const WRONG_KEY = getPublicKey(WRONG_SECRET);
const SUBJECT_KEY = getPublicKey(SUBJECT_SECRET);
const CREATED_AT = 1_785_000_000;

const associatedKeyPolicy: AssociatedKeyPolicy = {
  active_key: [{ role: "agent", scope: ["nostr:kind:1", "nostr:kind:6"] }],
  epoch_threshold: [{ role: "client", scope: ["repository:read"] }],
};

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

async function enrolledPersona(overrides: Partial<EnrollmentInception> = {}) {
  const inceptionBody: EnrollmentInception = {
    profile: "heterodyne.assurance.enrollment-inception.v1",
    spec_version: "heterodyne/0.5.0",
    active_key: ACTIVE_KEY,
    created_at: CREATED_AT,
    predecessor: null,
    cold_root: COLD_KEY,
    succession_authority: SUCCESSION_KEY,
    epoch_policy: {
      mode: "pre-rotation",
      current_keys: [EPOCH_KEY],
      next_key_commitments: [commitment(NEXT_EPOCH_KEY)],
    },
    witnesses: [{ key: WITNESS_KEY, weight: 1 }],
    thresholds: { epoch: 1, witness: 1 },
    associated_key_policy: associatedKeyPolicy,
  };
  Object.assign(inceptionBody, overrides);
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
    spec_version: "heterodyne/0.5.0" as const,
    active_key: ACTIVE_KEY,
    created_at: CREATED_AT + 1,
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
  return { inception, inceptionBody, acceptance, acceptanceBody };
}

async function acceptedEnrollment(): Promise<{
  state: AssuranceHeadState;
  inception: NostrSignedEvent;
}> {
  const { inception, acceptance } = await enrolledPersona();
  const result = evaluateEnrollment({ inception, acceptance });
  if (result.verdict !== "accept") throw new Error(result.reason_code);
  return { state: result.normalized, inception };
}

function successionBody(
  state: AssuranceHeadState,
  overrides: Partial<SuccessionRecord> = {},
): SuccessionRecord {
  const base: SuccessionRecord = {
    profile: "heterodyne.assurance.succession.v1",
    spec_version: "heterodyne/0.5.0",
    active_key: state.active_key,
    created_at: state.head_created_at + 10,
    predecessor: state.head,
    previous_active_key: state.active_key,
    previous_head: state.head,
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
    next_associated_key_policy: associatedKeyPolicy,
    subordinate_reauthorizations: [{
      role: "agent",
      subject_key: getPublicKey(WRONG_SECRET),
      scope: ["nostr:kind:1"],
      expires_at: state.head_created_at + 3_600,
    }],
  };
  return { ...base, ...overrides };
}

function signSuccessionProofs(
  body: SuccessionRecord,
  authoritySecret = SUCCESSION_SECRET,
  newKeySecret = NEXT_ACTIVE_SECRET,
  witnessSecret = WITNESS_SECRET,
): SuccessionRecord {
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

async function successionEvent(
  body: SuccessionRecord,
  outerSecret = ACTIVE_SECRET,
): Promise<NostrSignedEvent> {
  return assuranceEvent(
    outerSecret,
    31003,
    `assurance-succession:${body.previous_head}`,
    body.profile,
    body,
    [body.active_key, body.new_active_key],
  );
}

function associatedBody(
  state: AssuranceHeadState,
  overrides: Partial<AssociatedKeyRecord> = {},
): AssociatedKeyRecord {
  const base: AssociatedKeyRecord = {
    profile: "heterodyne.assurance.associated-key.v1",
    spec_version: "heterodyne/0.5.0",
    active_key: state.active_key,
    created_at: state.head_created_at + 2,
    predecessor: state.head,
    assurance_head: state.head,
    role: "agent",
    scope: ["nostr:kind:1"],
    issuer: state.active_key,
    issuer_authority: { class: "active-key", authority_proofs: [] },
    subject_key: SUBJECT_KEY,
    expires_at: state.head_created_at + 100,
    visibility: "public",
    subject_proof: "00".repeat(64),
    state: "active",
  };
  return { ...base, ...overrides };
}

function signSubject(body: AssociatedKeyRecord): AssociatedKeyRecord {
  return { ...body, subject_proof: proof(SUBJECT_SECRET, associatedKeyRecordDigest(body)) };
}

function signEpochIssuer(body: AssociatedKeyRecord, issuerSecret = EPOCH_SECRET): AssociatedKeyRecord {
  const digest = associatedKeyRecordDigest(body);
  return {
    ...body,
    issuer_authority: {
      ...body.issuer_authority,
      authority_proofs: [{
        authority_key: getPublicKey(issuerSecret),
        signature: proof(issuerSecret, digest),
      }],
    },
  };
}

async function associatedEvent(
  body: AssociatedKeyRecord,
  issuerSecret = ACTIVE_SECRET,
): Promise<NostrSignedEvent> {
  return assuranceEvent(
    issuerSecret,
    31001,
    `assurance-associated:${body.active_key}:${body.role}:${body.subject_key}`,
    body.profile,
    body,
    [body.active_key],
  );
}

describe("Assurance reciprocal enrollment", () => {
  it("accepts real reciprocal signatures and makes the acceptance event the current head", async () => {
    const { inception, acceptance } = await enrolledPersona();

    expect(evaluateEnrollment({ inception, acceptance })).toMatchObject({
      verdict: "accept",
      normalized: {
        active_key: ACTIVE_KEY,
        head: acceptance.id,
        inception_event_id: inception.id,
        cold_root: COLD_KEY,
      },
    });
  });

  it("rejects mismatched reciprocal equality and invalid outer signatures", async () => {
    const { inception, acceptance, acceptanceBody } = await enrolledPersona();
    const mismatched = await assuranceEvent(
      ACTIVE_SECRET,
      31000,
      "assurance-head",
      acceptanceBody.profile,
      { ...acceptanceBody, cold_root_signature: "00".repeat(64) },
    );

    expect(evaluateEnrollment({ inception, acceptance: mismatched })).toEqual({
      verdict: "reject",
      reason_code: "assurance-reciprocal-proof-invalid",
    });
    expect(evaluateEnrollment({
      inception,
      acceptance: { ...acceptance, sig: "00".repeat(64) },
    })).toEqual({
      verdict: "reject",
      reason_code: "assurance-reciprocal-proof-invalid",
    });
  });

  it("rejects an inception whose thresholds cannot be evaluated against its current policy", async () => {
    const { inception, acceptance } = await enrolledPersona({
      thresholds: { epoch: 2, witness: 2 },
    });

    expect(evaluateEnrollment({ inception, acceptance })).toEqual({
      verdict: "reject",
      reason_code: "assurance-reciprocal-proof-invalid",
    });
  });
});

describe("Assurance succession validation", () => {
  it("accepts a routine transition only with old-active participation and current authority", async () => {
    const { state } = await acceptedEnrollment();
    const body = signSuccessionProofs(successionBody(state));
    const event = await successionEvent(body);

    expect(evaluateSuccession({ current: state, event })).toMatchObject({
      verdict: "accept",
      normalized: {
        succession_event_id: event.id,
        new_active_key: NEXT_ACTIVE_KEY,
        transition_digest: successionTransitionDigest(body),
      },
    });
    expect(evaluateSuccession({
      current: state,
      event: await successionEvent(body, SUCCESSION_SECRET),
    })).toEqual({ verdict: "reject", reason_code: "assurance-authority-invalid" });

    const wrongAuthority = signSuccessionProofs(
      successionBody(state, {
        authorizing_evidence: {
          authority_class: "succession",
          authority_proofs: [{ authority_key: WRONG_KEY, signature: "00".repeat(64) }],
          witness_receipts: [{ witness_key: WITNESS_KEY, signature: "00".repeat(64) }],
        },
      }),
      WRONG_SECRET,
    );
    expect(evaluateSuccession({
      current: state,
      event: await successionEvent(wrongAuthority),
    })).toEqual({ verdict: "reject", reason_code: "assurance-authority-invalid" });
  });

  it("advances successor policy only after the new active key accepts the exact succession head", async () => {
    const { state } = await acceptedEnrollment();
    const body = signSuccessionProofs(successionBody(state));
    const succession = await successionEvent(body);
    const pending = evaluateSuccession({ current: state, event: succession });
    if (pending.verdict !== "accept") throw new Error(pending.reason_code);
    const acceptanceBody = {
      profile: "heterodyne.assurance.active-key-acceptance.v1" as const,
      spec_version: "heterodyne/0.5.0" as const,
      active_key: body.new_active_key,
      created_at: body.created_at + 1,
      predecessor: succession.id,
      inception_event_id: state.inception_event_id,
      cold_root: state.cold_root,
      cold_root_signature: state.inception_signature,
      assurance_head: succession.id,
      state: "assured" as const,
    };
    const acceptance = await assuranceEvent(
      NEXT_ACTIVE_SECRET,
      31000,
      "assurance-head",
      acceptanceBody.profile,
      acceptanceBody,
    );

    expect(evaluateSuccessorAcceptance({ current: state, succession, acceptance }))
      .toMatchObject({
        verdict: "accept",
        normalized: {
          active_key: NEXT_ACTIVE_KEY,
          head: acceptance.id,
          associated_key_policy: body.next_associated_key_policy,
        },
      });
    expect(evaluateSuccessorAcceptance({
      current: state,
      succession: { ...succession, sig: "00".repeat(64) },
      acceptance,
    })).toEqual({ verdict: "reject", reason_code: "assurance-schema-invalid" });
    const wrongHead = await assuranceEvent(
      NEXT_ACTIVE_SECRET,
      31000,
      "assurance-head",
      acceptanceBody.profile,
      { ...acceptanceBody, assurance_head: state.head },
    );
    expect(evaluateSuccessorAcceptance({
      current: state,
      succession,
      acceptance: wrongHead,
    })).toEqual({ verdict: "reject", reason_code: "assurance-head-mismatch" });
  });

  it("rejects proof replay after any next-policy or subordinate mutation", async () => {
    const { state } = await acceptedEnrollment();
    const signed = signSuccessionProofs(successionBody(state));
    expect(evaluateSuccession({
      current: state,
      event: await successionEvent(signed),
    })).toMatchObject({ verdict: "accept" });
    const mutations: SuccessionRecord[] = [
      {
        ...signed,
        next_epoch_policy: {
          ...signed.next_epoch_policy,
          next_key_commitments: [commitment(getPublicKey(secret(10)))],
        },
      },
      { ...signed, witnesses: [{ key: WITNESS_KEY, weight: 2 }] },
      { ...signed, thresholds: { epoch: 1, witness: 2 }, witnesses: [{ key: WITNESS_KEY, weight: 2 }] },
      {
        ...signed,
        next_associated_key_policy: {
          ...signed.next_associated_key_policy,
          active_key: [{ role: "agent", scope: ["nostr:kind:1", "nostr:kind:6", "nostr:kind:7"] }],
        },
      },
      {
        ...signed,
        subordinate_reauthorizations: [{
          ...signed.subordinate_reauthorizations[0]!,
          scope: ["nostr:kind:6"],
        }],
      },
    ];

    for (const mutated of mutations) {
      expect(evaluateSuccession({
        current: state,
        event: await successionEvent(mutated),
      })).toEqual({ verdict: "reject", reason_code: "assurance-authority-invalid" });
    }
  });

  it("makes authority, new-key acceptance, and witnesses bind the identical digest", async () => {
    const { state } = await acceptedEnrollment();
    const original = signSuccessionProofs(successionBody(state));
    const changed = {
      ...original,
      next_associated_key_policy: {
        ...original.next_associated_key_policy,
        active_key: [{ role: "agent", scope: ["nostr:kind:1"] }],
      },
    };
    const digest = successionTransitionDigest(changed);
    const authorityAndWitnessResigned: SuccessionRecord = {
      ...changed,
      authorizing_evidence: {
        ...changed.authorizing_evidence,
        authority_proofs: [{ authority_key: SUCCESSION_KEY, signature: proof(SUCCESSION_SECRET, digest) }],
        witness_receipts: [{ witness_key: WITNESS_KEY, signature: proof(WITNESS_SECRET, digest) }],
      },
    };
    expect(evaluateSuccession({
      current: state,
      event: await successionEvent(authorityAndWitnessResigned),
    })).toEqual({ verdict: "reject", reason_code: "assurance-new-key-acceptance-invalid" });

    const authorityAndNewKeyResigned: SuccessionRecord = {
      ...changed,
      authorizing_evidence: {
        ...changed.authorizing_evidence,
        authority_proofs: [{ authority_key: SUCCESSION_KEY, signature: proof(SUCCESSION_SECRET, digest) }],
      },
      new_key_acceptance: { key: NEXT_ACTIVE_KEY, signature: proof(NEXT_ACTIVE_SECRET, digest) },
    };
    expect(evaluateSuccession({
      current: state,
      event: await successionEvent(authorityAndNewKeyResigned),
    })).toEqual({ verdict: "reject", reason_code: "assurance-witness-threshold-unsatisfied" });
  });

  it("uses compromise recovery when the old active key is unavailable and enforces its cutoff", async () => {
    const { state } = await acceptedEnrollment();
    const recoveryBase = successionBody(state, {
      class: "compromise",
      compromise_time: state.head_created_at + 1,
      authorizing_evidence: {
        authority_class: "recovery",
        authority_proofs: [{ authority_key: COLD_KEY, signature: "00".repeat(64) }],
        witness_receipts: [{ witness_key: WITNESS_KEY, signature: "00".repeat(64) }],
      },
      subordinate_reauthorizations: [],
    });
    const recovery = signSuccessionProofs(recoveryBase, COLD_SECRET);
    expect(evaluateSuccession({
      current: state,
      event: await successionEvent(recovery, COLD_SECRET),
    })).toMatchObject({ verdict: "accept", normalized: { compromise_cutoff: state.head_created_at + 1 } });

    const replayedAtDifferentCutoff = {
      ...recovery,
      compromise_time: recovery.compromise_time! + 1,
    };
    expect(evaluateSuccession({
      current: state,
      event: await successionEvent(replayedAtDifferentCutoff, COLD_SECRET),
    })).toEqual({ verdict: "reject", reason_code: "assurance-authority-invalid" });

    for (const compromise_time of [state.head_created_at - 1, recovery.created_at + 1]) {
      const invalid = signSuccessionProofs({ ...recoveryBase, compromise_time }, COLD_SECRET);
      expect(evaluateSuccession({
        current: state,
        event: await successionEvent(invalid, COLD_SECRET),
      })).toEqual({ verdict: "reject", reason_code: "assurance-compromise-cutoff" });
    }
    expect(evaluateAssuranceAuthorityAt(state.head_created_at, state.head_created_at + 1))
      .toEqual({ verdict: "accept", normalized: { created_at: state.head_created_at } });
    expect(evaluateAssuranceAuthorityAt(state.head_created_at + 1, state.head_created_at + 1))
      .toEqual({ verdict: "reject", reason_code: "assurance-compromise-cutoff" });
  });

  it("rejects a fully re-signed transition that does not continue the current head", async () => {
    const { state } = await acceptedEnrollment();
    const wrongHead = "ff".repeat(32);
    const body = signSuccessionProofs(successionBody(state, {
      predecessor: wrongHead,
      previous_head: wrongHead,
    }));

    expect(evaluateSuccession({
      current: state,
      event: await successionEvent(body),
    })).toEqual({ verdict: "reject", reason_code: "assurance-predecessor-mismatch" });
  });
});

describe("Assurance associated-key evaluation", () => {
  it("accepts an active public-agent grant only with subject proof and a narrowed active-key scope", async () => {
    const { state } = await acceptedEnrollment();
    const body = signSubject(associatedBody(state));
    const event = await associatedEvent(body);

    expect(evaluateAssociatedKey({
      current: state,
      event,
      now: body.created_at,
      previous: null,
    })).toMatchObject({
      verdict: "accept",
      normalized: { event_id: event.id, state: "active", role: "agent" },
    });

    const widened = signSubject(associatedBody(state, {
      scope: ["nostr:kind:1", "nostr:kind:30023"],
    }));
    expect(evaluateAssociatedKey({
      current: state,
      event: await associatedEvent(widened),
      now: widened.created_at,
      previous: null,
    })).toEqual({ verdict: "reject", reason_code: "assurance-authority-invalid" });

    const invalidProof = { ...body, subject_proof: "00".repeat(64) };
    expect(evaluateAssociatedKey({
      current: state,
      event: await associatedEvent(invalidProof),
      now: invalidProof.created_at,
      previous: null,
    })).toEqual({
      verdict: "reject",
      reason_code: "assurance-associated-key-subject-proof-invalid",
    });
  });

  it("requires the exact current epoch threshold and policy ceiling", async () => {
    const { state } = await acceptedEnrollment();
    const { subject_proof: _subjectProof, ...withoutSubjectProof } = associatedBody(state);
    const base: AssociatedKeyRecord = {
      ...withoutSubjectProof,
      role: "client",
      scope: ["repository:read"],
      issuer: EPOCH_KEY,
      issuer_authority: {
        class: "epoch-threshold",
        authority_proofs: [{ authority_key: EPOCH_KEY, signature: "00".repeat(64) }],
      },
      visibility: "private",
    };
    const body = signEpochIssuer(base);
    expect(evaluateAssociatedKey({
      current: state,
      event: await associatedEvent(body, EPOCH_SECRET),
      now: body.created_at,
      previous: null,
    })).toMatchObject({ verdict: "accept" });

    const wrong = signEpochIssuer({
      ...base,
      issuer: WRONG_KEY,
      issuer_authority: {
        class: "epoch-threshold",
        authority_proofs: [{ authority_key: WRONG_KEY, signature: "00".repeat(64) }],
      },
    }, WRONG_SECRET);
    expect(evaluateAssociatedKey({
      current: state,
      event: await associatedEvent(wrong, WRONG_SECRET),
      now: wrong.created_at,
      previous: null,
    })).toEqual({ verdict: "reject", reason_code: "assurance-authority-invalid" });

    const wrongProof = signEpochIssuer(base, WRONG_SECRET);
    expect(evaluateAssociatedKey({
      current: state,
      event: await associatedEvent(wrongProof, EPOCH_SECRET),
      now: wrongProof.created_at,
      previous: null,
    })).toEqual({ verdict: "reject", reason_code: "assurance-authority-invalid" });
  });

  it("expires at the exclusive bound and keeps revocation absorbing without subject cooperation", async () => {
    const { state } = await acceptedEnrollment();
    const grant = signSubject(associatedBody(state));
    const grantEvent = await associatedEvent(grant);
    const activeResult = evaluateAssociatedKey({
      current: state,
      event: grantEvent,
      now: grant.created_at,
      previous: null,
    });
    expect(activeResult).toMatchObject({ verdict: "accept" });
    expect(evaluateAssociatedKey({
      current: state,
      event: grantEvent,
      now: grant.expires_at!,
      previous: null,
    })).toEqual({ verdict: "reject", reason_code: "assurance-associated-key-expired" });

    const { subject_proof: _subjectProof, ...grantWithoutSubjectProof } = grant;
    const revocation: AssociatedKeyRecord = {
      ...grantWithoutSubjectProof,
      created_at: grant.created_at + 1,
      predecessor: grantEvent.id,
      state: "revoked",
      revocation: { revoked_at: grant.created_at + 1, reason: "compromise" },
    };
    const previous = activeResult.verdict === "accept" ? activeResult.normalized : null;
    expect(previous).not.toBeNull();
    const revocationEvent = await associatedEvent(revocation);
    const revocationResult = evaluateAssociatedKey({
      current: state,
      event: revocationEvent,
      now: revocation.created_at,
      previous,
    });
    expect(revocationResult).toMatchObject({
      verdict: "reject",
      reason_code: "assurance-associated-key-revoked",
      normalized: { event_id: revocationEvent.id, state: "revoked" },
    });
    if (!("normalized" in revocationResult)) throw new Error("missing terminal state");
    const revokedState: AssociatedKeyState = revocationResult.normalized;
    const attemptedRegrant = signSubject({
      ...grant,
      created_at: revocation.created_at + 1,
      predecessor: revocationEvent.id,
    });
    expect(evaluateAssociatedKey({
      current: state,
      event: await associatedEvent(attemptedRegrant),
      now: attemptedRegrant.created_at,
      previous: revokedState,
    })).toMatchObject({
      verdict: "reject",
      reason_code: "assurance-associated-key-revoked",
      normalized: revokedState,
    });
  });

  it("rejects an otherwise valid grant against a stale Assurance head", async () => {
    const { state } = await acceptedEnrollment();
    const stale = signSubject(associatedBody(state, { assurance_head: "ff".repeat(32) }));
    expect(evaluateAssociatedKey({
      current: state,
      event: await associatedEvent(stale),
      now: stale.created_at,
      previous: null,
    })).toEqual({ verdict: "reject", reason_code: "assurance-head-mismatch" });
  });
});
