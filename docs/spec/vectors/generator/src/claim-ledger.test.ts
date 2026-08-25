import { beforeAll, describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import {
  activeCanonicalClaimSemanticsAt,
  buildLedgerRepositoryEvidence,
  buildReaderOnboardingBundle,
  canMint,
  canReturnToken,
  createAudienceKeyEpochPayload,
  createIssuerKeyEnvelope,
  createIssuerKeyEpochPayload,
  createSignedLedgerRecord,
  createStatusInvalidationRecords,
  deriveActiveIssuerNids,
  determineHistoricalTokenReturnability,
  evaluateMintingAttempt,
  evaluateReaderAccess,
  materializeLedgerLayout,
  mergeClaimLedger,
  reserveStatusIndex,
  resolveAuthoritativeClaimState,
  resolveIssuerAuthorityState,
  unwrapIssuerSigningJwk,
  validateIssuanceRecordOrThrow,
  validateLedgerRecordOrThrow,
  validateReaderOnboardingBundle,
  type LedgerRecord,
  type LedgerRecordValidationEvidence,
  type LedgerValidationContext,
  type ReaderAccessRequest,
} from "./claim-ledger.js";
import { buildFixtures } from "./fixtures.js";
import {
  buildClaimLedgerScenario,
  type ClaimLedgerScenario,
} from "./claim-ledger-test-support.js";
import { bytesToHex, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE, OIDC_RSA_TWO } from "./oidc-rsa-fixtures.js";

const fixtures = buildFixtures();
let s: ClaimLedgerScenario;

beforeAll(async () => {
  s = await buildClaimLedgerScenario(fixtures);
});

function contextFor(repository: ReturnType<typeof buildLedgerRepositoryEvidence>["repository"]): LedgerValidationContext {
  return s.makeContext(repository);
}

function bindingFor(record: LedgerRecord) {
  return {
    credential_ledger_persona: record.persona,
    credential_ledger_generation: record.credential_ledger_generation,
  };
}

function cloneRequest(request: ReaderAccessRequest): ReaderAccessRequest {
  return structuredClone(request);
}

function resign(record: LedgerRecord, payload: LedgerRecord["payload"], writer = s.writerTwo): LedgerRecord {
  return createSignedLedgerRecord({
    record_type: record.record_type,
    persona: record.persona,
    credential_ledger_generation: record.credential_ledger_generation,
    writer_nid: writer.did_key,
    created_at: record.created_at,
    parents: record.parents,
    payload,
  }, writer.private_key);
}

function boundEvidence(record: LedgerRecord, source?: LedgerRecordValidationEvidence): LedgerRecordValidationEvidence {
  return {
    ...(source ?? {}),
    record_id: record.record_id,
    payload_digest: record.payload_digest,
  };
}

function digestJson(value: unknown): string {
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize(value))));
}

describe("signed ledger artifact validation", () => {
  it("requires record-bound validation evidence even for a valid repository writer", () => {
    const records = new Map([[s.claimRecordOne.record_id, s.claimRecordOne]]);
    const binding = {
      credential_ledger_persona: s.persona,
      credential_ledger_generation: 0,
    };
    expect(() => validateLedgerRecordOrThrow(s.claimRecordOne, records, undefined, binding)).toThrow(/evidence|unconfirmed/);
    expect(() => validateLedgerRecordOrThrow(
      s.claimRecordOne,
      records,
      s.evidence.get(s.claimRecordOne.record_id),
      binding,
    )).not.toThrow();
    expect(() => validateLedgerRecordOrThrow(
      s.claimRecordOne,
      records,
      s.evidence.get(s.claimRecordOne.record_id),
      { ...binding, credential_ledger_generation: 1 },
    )).toThrow(/credential_generation_stale/);
    expect(() => validateLedgerRecordOrThrow(
      s.claimRecordOne,
      records,
      s.evidence.get(s.claimRecordOne.record_id),
      { ...binding, credential_ledger_persona: "ff".repeat(32) },
    )).toThrow(/credential_ledger_persona_mismatch/);
    const missingGeneration = { ...s.claimRecordOne } as Partial<LedgerRecord>;
    delete missingGeneration.credential_ledger_generation;
    expect(() => validateLedgerRecordOrThrow(
      missingGeneration as LedgerRecord,
      records,
      s.evidence.get(s.claimRecordOne.record_id),
      binding,
    )).toThrow(/credential_generation_missing/);
  });

  it("rejects a bare semantic claim and an invalid signed envelope despite a valid Ed25519 writer", () => {
    const bare = resign(s.claimRecordOne, { claim: s.claimOne.artifact.semantic });
    expect(() => validateLedgerRecordOrThrow(
      bare,
      new Map([[bare.record_id, bare]]),
      boundEvidence(bare, s.evidence.get(s.claimRecordOne.record_id)),
      bindingFor(bare),
    )).toThrow(/schema/);

    const artifact = structuredClone(s.claimOne.artifact);
    artifact.event.sig = `${artifact.event.sig[0] === "0" ? "1" : "0"}${artifact.event.sig.slice(1)}`;
    const tampered = resign(s.claimRecordOne, { claim_artifact: artifact });
    expect(() => validateLedgerRecordOrThrow(
      tampered,
      new Map([[tampered.record_id, tampered]]),
      boundEvidence(tampered, s.evidence.get(s.claimRecordOne.record_id)),
      bindingFor(tampered),
    )).toThrow(/signature|event/);
  });

  it("requires an authorization claim's binding to equal its containing ledger record", () => {
    const mismatched = createSignedLedgerRecord({
      record_type: s.claimRecordOne.record_type,
      persona: s.claimRecordOne.persona,
      credential_ledger_generation: 1,
      writer_nid: s.writerOne.did_key,
      created_at: s.claimRecordOne.created_at,
      parents: [],
      payload: s.claimRecordOne.payload,
    }, s.writerOne.private_key);
    expect(() => validateLedgerRecordOrThrow(
      mismatched,
      new Map([[mismatched.record_id, mismatched]]),
      boundEvidence(mismatched, s.evidence.get(s.claimRecordOne.record_id)),
      bindingFor(mismatched),
    )).toThrow(/credential_generation_stale/);
  });

  it("rejects payload/record/signature mutations and cross-writer substitution", () => {
    const evidence = s.evidence.get(s.claimRecordOne.record_id)!;
    for (const mutation of [
      { ...s.claimRecordOne, record_id: "00".repeat(32) },
      { ...s.claimRecordOne, payload_digest: "00".repeat(32) },
      { ...s.claimRecordOne, signature: "00".repeat(64) },
      { ...s.claimRecordOne, writer_nid: s.writerTwo.did_key },
    ]) {
      expect(() => validateLedgerRecordOrThrow(
        mutation,
        new Map([[mutation.record_id, mutation]]),
        evidence,
        bindingFor(mutation),
      )).toThrow();
    }
  });

  it("replays revocation authority and rejects target, signer-role, or subject mismatch", () => {
    const records = new Map([
      [s.claimRecordOne.record_id, s.claimRecordOne],
      [s.reductionRecord.record_id, s.reductionRecord],
    ]);
    expect(() => validateLedgerRecordOrThrow(
      s.reductionRecord,
      records,
      s.evidence.get(s.reductionRecord.record_id),
      bindingFor(s.reductionRecord),
    )).not.toThrow();

    const wrongSubject = resign(s.reductionRecord, {
      ...s.reductionRecord.payload as Record<string, unknown>,
      subject_nid: s.writerTwo.did_key,
    } as LedgerRecord["payload"]);
    const wrongRecords = new Map([
      [s.claimRecordOne.record_id, s.claimRecordOne],
      [wrongSubject.record_id, wrongSubject],
    ]);
    expect(() => validateLedgerRecordOrThrow(
      wrongSubject,
      wrongRecords,
      boundEvidence(wrongSubject, s.evidence.get(s.reductionRecord.record_id)),
      bindingFor(wrongSubject),
    )).toThrow(/target|subject|role/);
  });
});

describe("canonical repository evidence and convergence", () => {
  it("retains prior-generation records for audit without treating their grants as current", () => {
    const context = contextFor(s.baseRepository.repository);
    context.credential_ledger = {
      credential_ledger_persona: s.persona,
      credential_ledger_generation: 1,
    };
    const state = mergeClaimLedger(
      [s.claimRecordOne, s.claimRecordTwo],
      [],
      s.baseRepository.checkpoint,
      context,
    );
    expect(state.records).toHaveLength(2);
    expect(state.credential_ledger).toEqual(context.credential_ledger);
    expect(activeCanonicalClaimSemanticsAt(state)).toEqual([]);
    expect(resolveAuthoritativeClaimState(
      s.claimOne.artifact.semantic.claim_id,
      state,
    )).toBe("invalid");
  });

  it("fails closed without the required validation/repository context", () => {
    expect(() => mergeClaimLedger(
      [s.claimRecordOne, s.claimRecordTwo], [], s.baseRepository.checkpoint,
    )).toThrow(/explicit validation|repository evidence/);
  });

  it("validates explicit genesis and deterministic permutation/idempotence", () => {
    const records = [s.claimRecordOne, s.claimRecordTwo];
    const left = mergeClaimLedger([records[0]], [records[1], records[0]], s.baseRepository.checkpoint, contextFor(s.baseRepository.repository));
    const right = mergeClaimLedger([records[1]], [records[0]], s.baseRepository.checkpoint, contextFor(s.baseRepository.repository));
    expect(left.records.map(({ record_id }) => record_id)).toEqual(right.records.map(({ record_id }) => record_id));
    expect(left.repository_confirmed_record_ids).toEqual(right.repository_confirmed_record_ids);
  });

  it("rejects commit, tree, record-set, ancestry, and reachability mutation", () => {
    const records = [s.claimRecordOne, s.claimRecordTwo, s.epochOneRecord];
    const mutations = [
      (repository: typeof s.epochOneRepository.repository) => { repository.canonical_head = "00".repeat(32); },
      (repository: typeof s.epochOneRepository.repository) => { repository.commits.at(-1)!.tree_oid = "00".repeat(32); },
      (repository: typeof s.epochOneRepository.repository) => { repository.commits.at(-1)!.record_set_digest = "00".repeat(32); },
      (repository: typeof s.epochOneRepository.repository) => { repository.commits.at(-1)!.parents = []; },
      (repository: typeof s.epochOneRepository.repository) => { repository.repository_confirmed_record_ids = [s.epochOneRecord.record_id]; },
    ];
    for (const mutate of mutations) {
      const repository = structuredClone(s.epochOneRepository.repository);
      mutate(repository);
      expect(() => mergeClaimLedger(records, [], s.epochOneRepository.checkpoint, contextFor(repository))).toThrow(/rollback|reachable|confirmed/);
    }
  });

  it("separates canonical confirmation from delivered authenticated effects", () => {
    const emptyRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: [], observed_at: s.now + 50 });
    const deliveredClaim = mergeClaimLedger([s.claimRecordOne], [], emptyRepo.checkpoint, contextFor(emptyRepo.repository));
    expect(resolveAuthoritativeClaimState(s.claimOne.artifact.semantic.claim_id, deliveredClaim)).toBe("provisional");

    const deliveredRevocation = mergeClaimLedger(
      [s.claimRecordOne, s.claimRecordTwo], [s.revocationRecord],
      s.baseRepository.checkpoint, contextFor(s.baseRepository.repository),
    );
    expect(deliveredRevocation.delivered_record_ids).toContain(s.revocationRecord.record_id);
    expect(resolveAuthoritativeClaimState(s.claimOne.artifact.semantic.claim_id, deliveredRevocation)).toBe("revoked");
  });
});

describe("reader authorization and effect precedence", () => {
  it("requires the exact signed reader claim, trust, current state, and fresh subject PoP", () => {
    const records = [s.claimRecordOne, s.claimRecordTwo];
    const state = mergeClaimLedger(records, [], s.baseRepository.checkpoint, contextFor(s.baseRepository.repository));
    const request = s.requestFor(s.claimRecordOne, s.claimOne);
    request.verification_context.now = s.baseRepository.checkpoint.observed_at;
    expect(evaluateReaderAccess(s.writerOne.did_key, state, request).allowed).toBe(true);
    expect(evaluateReaderAccess(null, state, request).reason_code).toBe("claim-ledger-reader-unauthorized");
    expect(evaluateReaderAccess(s.writerTwo.did_key, state, request).allowed).toBe(false);
    expect(evaluateReaderAccess(s.writerOne.did_key, state).allowed).toBe(false);

    const untrusted = cloneRequest(request);
    untrusted.verification_context.trusted_issuers = [];
    expect(evaluateReaderAccess(s.writerOne.did_key, state, untrusted).state).toBe("untrusted");
    const noProof = cloneRequest(request);
    noProof.verification_context.subject_proof = null;
    expect(evaluateReaderAccess(s.writerOne.did_key, state, noProof).reason_code).toBe("claim-subject-proof-required");
    const staleProof = cloneRequest(request);
    staleProof.verification_context.now = staleProof.verification_context.subject_proof!.challenge.expires_at;
    expect(evaluateReaderAccess(s.writerOne.did_key, state, staleProof).reason_code).toBe("claim-subject-proof-invalid");
  });

  it("denies provisional, conflicted, revoked, and expired reader state", () => {
    const emptyRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: [], observed_at: s.now + 50 });
    const provisional = mergeClaimLedger([s.claimRecordOne], [], emptyRepo.checkpoint, contextFor(emptyRepo.repository));
    const request = s.requestFor(s.claimRecordOne, s.claimOne);
    request.verification_context.now = emptyRepo.checkpoint.observed_at;
    expect(evaluateReaderAccess(s.writerOne.did_key, provisional, request).state).toBe("provisional");

    const conflictRecords = [s.claimRecordOne, s.claimRecordTwo, s.grantOne, s.grantDivergent];
    const conflictRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: conflictRecords, observed_at: s.now + 50 });
    const conflicted = mergeClaimLedger(conflictRecords, [], conflictRepo.checkpoint, contextFor(conflictRepo.repository));
    expect(evaluateReaderAccess(s.writerOne.did_key, conflicted, request).state).toBe("conflicted");

    const revoked = mergeClaimLedger(
      [s.claimRecordOne, s.claimRecordTwo], [s.revocationRecord], s.baseRepository.checkpoint, contextFor(s.baseRepository.repository),
    );
    const revokedRequest = cloneRequest(request);
    revokedRequest.verification_context.now = s.baseRepository.checkpoint.observed_at;
    expect(evaluateReaderAccess(s.writerOne.did_key, revoked, revokedRequest).state).toBe("revoked");

    const expiredRequest = cloneRequest(request);
    expiredRequest.verification_context.now = s.claimOne.artifact.semantic.expires_at!;
    expiredRequest.verification_context.claim_authority_evidence.get(
      s.claimOne.artifact.semantic.claim_id,
    )!.valid_until = expiredRequest.verification_context.now + 1;
    expect(evaluateReaderAccess(s.writerOne.did_key, mergeClaimLedger(
      [s.claimRecordOne, s.claimRecordTwo], [], s.baseRepository.checkpoint, contextFor(s.baseRepository.repository),
    ), expiredRequest).state).toBe("expired");
  });

  it("applies authenticated reduction before widening conflict and isolates status invalidation", () => {
    const conflictRecords = [s.claimRecordOne, s.claimRecordTwo, s.grantOne, s.grantDivergent];
    const conflictRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: conflictRecords, observed_at: s.now + 50 });
    const reduced = mergeClaimLedger(conflictRecords, [s.reductionRecord], conflictRepo.checkpoint, contextFor(conflictRepo.repository));
    expect(reduced.conflicted_claim_ids).toContain(s.claimOne.artifact.semantic.claim_id);
    expect(resolveAuthoritativeClaimState(s.claimOne.artifact.semantic.claim_id, reduced)).toBe("revoked");

    const statusRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
      s.reservationOne, s.statusInvalidation,
    ];
    const statusRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: statusRecords, observed_at: s.now + 80, prior: s.issuerKeyEpochOneRepository.repository });
    const status = mergeClaimLedger(statusRecords, [], statusRepo.checkpoint, s.makeTask5Context(statusRepo.repository));
    expect(status.token_invalidations).toEqual(["writer_one_token_0001"]);
    expect(resolveAuthoritativeClaimState(s.claimOne.artifact.semantic.claim_id, status)).toBe("active");
  });
});

describe("reader lifecycle and metadata privacy", () => {
  it("enforces monotonic distinct epochs, removal order, active-reader wraps, and scrub/access state", () => {
    expect(() => createAudienceKeyEpochPayload({
      persona: s.persona, repository_rid: s.rid, checkpoint_commit_oid: s.epochOneRepository.checkpoint.commit_oid,
      epoch: 1, key_id: "bad", audience_key: s.audienceKeyOne,
      previous_epoch: 1, previous_key_id: "same", reader_nids: [s.writerOne.did_key], removed_reader_nids: [],
    })).toThrow(/rotation|epoch|key/);
    expect(() => createAudienceKeyEpochPayload({
      persona: s.persona, repository_rid: s.rid, checkpoint_commit_oid: s.epochOneRepository.checkpoint.commit_oid,
      epoch: 2, key_id: String((s.epochTwoRecord.payload as Record<string, unknown>).key_id), audience_key: s.audienceKeyTwo,
      previous_epoch: 1, previous_key_id: String((s.epochOneRecord.payload as Record<string, unknown>).key_id), reader_nids: [s.writerOne.did_key], removed_reader_nids: [s.writerOne.did_key],
    })).toThrow(/removed reader/);

    const finalRecords = [s.claimRecordOne, s.claimRecordTwo, s.epochOneRecord, s.removalRecord, s.epochTwoRecord];
    const finalRepository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: finalRecords,
      observed_at: s.now + 70,
      prior: s.epochOneRepository.repository,
    });
    expect(() => mergeClaimLedger(
      finalRecords, [], finalRepository.checkpoint, contextFor(finalRepository.repository),
    )).not.toThrow();

    const expectInvalidRotation = (
      replacement: LedgerRecord,
      audienceKey = s.audienceKeyTwo,
    ) => {
      const records = [s.claimRecordOne, s.claimRecordTwo, s.epochOneRecord, s.removalRecord, replacement];
      const repository = buildLedgerRepositoryEvidence({
        repository_rid: s.rid,
        confirmed_records: records,
        observed_at: s.now + 70,
        prior: s.epochOneRepository.repository,
      });
      const context = contextFor(repository.repository);
      context.record_evidence.set(replacement.record_id, boundEvidence(replacement));
      context.audience_keys_by_epoch.set(2, audienceKey);
      expect(() => mergeClaimLedger(records, [], repository.checkpoint, context)).toThrow(/rotation|reader|key|conflict/);
    };

    expect(() => createAudienceKeyEpochPayload({
      persona: s.persona, repository_rid: s.rid,
      checkpoint_commit_oid: s.epochOneRepository.checkpoint.commit_oid,
      epoch: 2, key_id: String((s.epochOneRecord.payload as Record<string, unknown>).key_id), audience_key: s.audienceKeyOne,
      previous_epoch: 1, previous_key_id: String((s.epochOneRecord.payload as Record<string, unknown>).key_id),
      reader_nids: [s.writerTwo.did_key], removed_reader_nids: [s.writerOne.did_key],
    })).toThrow(/key|rotation/);

    expectInvalidRotation(createSignedLedgerRecord({
      record_type: "audience-key-epoch", persona: s.persona, credential_ledger_generation: 0,
      writer_nid: s.writerTwo.did_key,
      created_at: s.epochTwoRecord.created_at, parents: [s.epochOneRecord.record_id],
      payload: s.epochTwoRecord.payload,
    }, s.writerTwo.private_key));

    const staleReadersPayload = createAudienceKeyEpochPayload({
      persona: s.persona, repository_rid: s.rid,
      checkpoint_commit_oid: s.epochOneRepository.checkpoint.commit_oid,
      epoch: 2, key_id: String((s.epochTwoRecord.payload as Record<string, unknown>).key_id), audience_key: s.audienceKeyTwo,
      previous_epoch: 1, previous_key_id: String((s.epochOneRecord.payload as Record<string, unknown>).key_id),
      reader_nids: [s.writerOne.did_key, s.writerTwo.did_key], removed_reader_nids: [],
    });
    expectInvalidRotation(resign(s.epochTwoRecord, staleReadersPayload as never));

    const tamperedWrap = structuredClone(s.epochTwoRecord.payload) as Record<string, unknown>;
    const wraps = tamperedWrap.recipient_wraps as Array<Record<string, unknown>>;
    wraps[0].wrapped_key = "00".repeat(32);
    expectInvalidRotation(resign(s.epochTwoRecord, tamperedWrap as never));
  });

  it("builds and executably validates the exact current-epoch onboarding bundle", () => {
    const records = [s.claimRecordOne, s.claimRecordTwo, s.epochOneRecord];
    const state = mergeClaimLedger(records, [], s.epochOneRepository.checkpoint, contextFor(s.epochOneRepository.repository));
    const request = s.requestFor(s.claimRecordOne, s.claimOne);
    request.verification_context.now = s.now + 60;
    const bundle = buildReaderOnboardingBundle({
      reader_nid: s.writerOne.did_key,
      request,
      audience_key: s.audienceKeyOne,
      compact_state: { confirmed_claim_ids: [s.claimOne.artifact.semantic.claim_id] },
    }, state);
    expect(() => validateReaderOnboardingBundle(bundle, state, request)).not.toThrow();
    for (const mutation of [
      { ...bundle, bundle_digest: "00".repeat(32) },
      { ...bundle, compact_state_digest: "00".repeat(32) },
      { ...bundle, key_epoch: { ...bundle.key_epoch, epoch: 2 } },
      { ...bundle, radicle_access: { ...bundle.radicle_access, nid: s.writerTwo.did_key } },
    ]) {
      expect(() => validateReaderOnboardingBundle(mutation, state, request)).toThrow(/onboarding|binding|authorization/);
    }
  });

  it("materializes all fixed-size opaque buckets and changes every bucket per commit", () => {
    const one = materializeLedgerLayout(s.audienceKeyOne, 1, s.baseRepository.checkpoint.commit_oid, "11".repeat(32), [s.claimRecordOne]);
    const many = materializeLedgerLayout(s.audienceKeyOne, 1, s.baseRepository.checkpoint.commit_oid, "12".repeat(32), [s.claimRecordOne, s.claimRecordTwo, s.epochOneRecord]);
    expect(one.entries).toHaveLength(256);
    expect(many.entries).toHaveLength(256);
    expect(new Set(one.entries.map(({ size }) => size))).toEqual(new Set([64]));
    expect(one.entries.map(({ path }) => path)).toEqual(many.entries.map(({ path }) => path));
    expect(one.entries.every((entry, index) => entry.ciphertext !== many.entries[index].ciphertext)).toBe(true);
    const visible = JSON.stringify({ entries: many.entries.map(({ path, size }) => ({ path, size })), metadata: many.commit_metadata });
    for (const secret of ["claim", "revocation", "reader_nid", s.persona, s.writerOne.did_key, s.claimOne.artifact.semantic.claim_id]) {
      expect(visible).not.toContain(secret);
    }
  });
});

describe("multi-writer OIDC issuer authority", () => {
  it("separates the RFC 7638 signing-key identity from encrypted-content integrity", () => {
    const audienceKey = Uint8Array.from({ length: 32 }, () => 0x70);
    const envelope = createIssuerKeyEnvelope({
      persona: s.persona,
      repository_rid: s.rid,
      epoch: 1,
      audience_key: audienceKey,
      signing_jwk: OIDC_RSA_ONE.private_jwk,
      authority_state: s.authorityState,
      recipient_nids: [s.writerOne.did_key, s.writerTwo.did_key],
    });
    expect(envelope.signing_key_id).toBe(OIDC_RSA_ONE.key_id);
    expect(envelope.content_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(envelope.content_digest).not.toBe(envelope.signing_key_id);
    expect(unwrapIssuerSigningJwk(envelope, s.writerOne.did_key, audienceKey))
      .toEqual(OIDC_RSA_ONE.private_jwk);

    expect(() => createIssuerKeyEnvelope({
      persona: s.persona,
      repository_rid: s.rid,
      epoch: 1,
      audience_key: audienceKey,
      signing_jwk: { ...OIDC_RSA_ONE.private_jwk, kid: OIDC_RSA_TWO.key_id },
      authority_state: s.authorityState,
      recipient_nids: [s.writerOne.did_key, s.writerTwo.did_key],
    })).toThrow(/kid|thumbprint|signing key/);

    expect(() => validateIssuanceRecordOrThrow({
      ...s.issuanceOne,
      signing_key_id: OIDC_RSA_ONE.key_id,
    })).not.toThrow();
    expect(() => validateIssuanceRecordOrThrow({
      ...s.issuanceOne,
      signing_key_id: "11".repeat(32),
    })).toThrow(/signing_key_id|pattern/);
  });

  it("creates a closed issuer-key genesis epoch bound to canonical authority", () => {
    expect(createIssuerKeyEpochPayload({
      authority_state: s.authorityState,
      envelope: s.issuerKeyEnvelopeOne,
      previous_record: null,
    })).toMatchObject({
      scope: "oidc-issuer-key",
      epoch: 1,
      previous_epoch: 0,
      previous_envelope_digest: "00".repeat(32),
      previous_key_digest: "00".repeat(32),
      recipient_nids: [s.writerOne.did_key, s.writerTwo.did_key].sort(),
      checkpoint: s.authorityState.checkpoint,
    });
  });

  it("requires one unique canonical issuer-key genesis before minting", () => {
    const authorityRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
    ];
    const payload = createIssuerKeyEpochPayload({
      authority_state: s.authorityState,
      envelope: s.issuerKeyEnvelopeOne,
      previous_record: null,
    });
    const epochRecord = createSignedLedgerRecord({
      record_type: "audience-key-epoch",
      persona: s.persona,
      credential_ledger_generation: 0,
      writer_nid: s.writerTwo.did_key,
      created_at: s.now + 65,
      parents: [s.issuerAuthorityRecordOne.record_id, s.issuerAuthorityRecordTwo.record_id].sort(),
      payload: payload as never,
    }, s.writerTwo.private_key);
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: [...authorityRecords, epochRecord],
      observed_at: s.now + 66,
      prior: s.authorityRepository.repository,
    });
    const context = s.makeTask5Context(repository.repository);
    context.record_evidence.set(epochRecord.record_id, boundEvidence(epochRecord));
    (context as any).issuer_key_material_by_record_id = new Map([[
      epochRecord.record_id,
      { envelope: s.issuerKeyEnvelopeOne, audience_key: s.issuerAudienceKeyOne },
    ]]);
    const state = mergeClaimLedger([...authorityRecords, epochRecord], [], repository.checkpoint, context);
    expect(evaluateMintingAttempt({
      now: state.checkpoint.observed_at,
      manifest_max_age_seconds: 300,
      writer_nid: s.writerOne.did_key,
      state,
      envelope: s.issuerKeyEnvelopeOne,
      audience_key: s.issuerAudienceKeyOne,
    })).toMatchObject({ allowed: true, key_epoch: 1 });
    expect(evaluateMintingAttempt({
      now: state.checkpoint.observed_at,
      manifest_max_age_seconds: 300,
      writer_nid: s.writerOne.did_key,
      state,
      envelope: {
        ...s.issuerKeyEnvelopeOne,
        credential_ledger_generation: 1,
      },
      audience_key: s.issuerAudienceKeyOne,
    })).toMatchObject({
      allowed: false,
      reason_code: "credential_generation_stale",
      pending_rotation: true,
    });

    const noEpoch = evaluateMintingAttempt({
      now: s.authorityState.checkpoint.observed_at,
      manifest_max_age_seconds: 300,
      writer_nid: s.writerOne.did_key,
      state: s.authorityState,
      envelope: s.issuerKeyEnvelopeOne,
      audience_key: s.issuerAudienceKeyOne,
    });
    expect(noEpoch).toMatchObject({ allowed: false, pending_rotation: true });
  });

  it("rejects canonical issuer envelopes with inconsistent internal context", () => {
    const authorityRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo,
    ];
    const mutations = [
      (envelope: any) => { envelope.object_type = "not-an-issuer-key"; },
      (envelope: any) => { envelope.authority_record_ids.reverse(); },
      (envelope: any) => { envelope.removed_issuer_nids = [fixtures.ed25519_nids.bob_device_1.did_key]; },
      (envelope: any) => { envelope.unknown_member = true; },
      (envelope: any) => { envelope.recipient_wraps[0].unknown_member = true; },
    ];
    for (const mutate of mutations) {
      const envelope = structuredClone(s.issuerKeyEnvelopeOne);
      mutate(envelope);
      expect(() => {
        const payload = createIssuerKeyEpochPayload({
          authority_state: s.authorityState,
          envelope,
          previous_record: null,
        });
        const record = createSignedLedgerRecord({
          record_type: "audience-key-epoch",
          persona: s.persona,
          credential_ledger_generation: 0,
          writer_nid: s.writerTwo.did_key,
          created_at: s.now + 65,
          parents: [s.issuerAuthorityRecordOne.record_id, s.issuerAuthorityRecordTwo.record_id].sort(),
          payload: payload as never,
        }, s.writerTwo.private_key);
        const repository = buildLedgerRepositoryEvidence({
          repository_rid: s.rid,
          confirmed_records: [...authorityRecords, record],
          observed_at: s.now + 66,
          prior: s.authorityRepository.repository,
        });
        const context = s.makeTask5Context(repository.repository);
        context.record_evidence.set(record.record_id, boundEvidence(record));
        context.issuer_key_material_by_record_id!.set(record.record_id, {
          envelope,
          audience_key: s.issuerAudienceKeyOne,
        });
        mergeClaimLedger([...authorityRecords, record], [], repository.checkpoint, context);
      }).toThrow(/issuer|authority|envelope|key/);
    }
  });

  it("blocks concurrent issuer-key genesis and rotation forks", () => {
    const authorityRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo,
    ];
    const alternateGenesisKey = Uint8Array.from({ length: 32 }, () => 0x76);
    const alternateGenesisEnvelope = createIssuerKeyEnvelope({
      persona: s.persona, repository_rid: s.rid, epoch: 1,
      audience_key: alternateGenesisKey,
      signing_jwk: OIDC_RSA_TWO.private_jwk,
      authority_state: s.authorityState,
      recipient_nids: [s.writerOne.did_key, s.writerTwo.did_key],
    });
    const alternateGenesisPayload = createIssuerKeyEpochPayload({
      authority_state: s.authorityState, envelope: alternateGenesisEnvelope, previous_record: null,
    });
    const alternateGenesisRecord = createSignedLedgerRecord({
      record_type: "audience-key-epoch", persona: s.persona, credential_ledger_generation: 0,
      writer_nid: s.writerOne.did_key,
      created_at: s.now + 65,
      parents: [s.issuerAuthorityRecordOne.record_id, s.issuerAuthorityRecordTwo.record_id].sort(),
      payload: alternateGenesisPayload as never,
    }, s.writerOne.private_key);
    const genesisRecords = [...authorityRecords, s.issuerKeyEpochRecordOne, alternateGenesisRecord];
    const genesisRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: genesisRecords, observed_at: s.now + 67,
      prior: s.authorityRepository.repository,
    });
    const genesisContext = s.makeTask5Context(genesisRepo.repository);
    genesisContext.record_evidence.set(alternateGenesisRecord.record_id, boundEvidence(alternateGenesisRecord));
    genesisContext.issuer_key_material_by_record_id!.set(alternateGenesisRecord.record_id, {
      envelope: alternateGenesisEnvelope, audience_key: alternateGenesisKey,
    });
    expect(() => mergeClaimLedger(genesisRecords, [], genesisRepo.checkpoint, genesisContext))
      .toThrow(/divergent|conflict/);

    const alternateRotationKey = Uint8Array.from({ length: 32 }, () => 0x77);
    const alternateRotationEnvelope = createIssuerKeyEnvelope({
      persona: s.persona, repository_rid: s.rid, epoch: 2,
      audience_key: alternateRotationKey,
      signing_jwk: OIDC_RSA_TWO.private_jwk,
      authority_state: s.removedAuthorityState,
      recipient_nids: [s.writerTwo.did_key],
      previous: { envelope: s.issuerKeyEnvelopeOne, audience_key: s.issuerAudienceKeyOne },
    });
    const alternateRotationPayload = createIssuerKeyEpochPayload({
      authority_state: s.removedAuthorityState, envelope: alternateRotationEnvelope,
      previous_record: s.issuerKeyEpochRecordOne,
    });
    const alternateRotationRecord = createSignedLedgerRecord({
      record_type: "audience-key-epoch", persona: s.persona, credential_ledger_generation: 0,
      writer_nid: s.writerTwo.did_key,
      created_at: s.now + 101,
      parents: [s.issuerKeyEpochRecordOne.record_id, s.issuerRemovalRecord.record_id].sort(),
      payload: alternateRotationPayload as never,
    }, s.writerTwo.private_key);
    const rotationRecords = [
      ...authorityRecords, s.issuerKeyEpochRecordOne, s.issuerRemovalRecord,
      s.issuerKeyEpochRecordTwo, alternateRotationRecord,
    ];
    const rotationRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: rotationRecords, observed_at: s.now + 103,
      prior: s.removedAuthorityRepository.repository,
    });
    const rotationContext = s.makeTask5Context(rotationRepo.repository);
    rotationContext.record_evidence.set(alternateRotationRecord.record_id, boundEvidence(alternateRotationRecord));
    rotationContext.issuer_key_material_by_record_id!.set(alternateRotationRecord.record_id, {
      envelope: alternateRotationEnvelope, audience_key: alternateRotationKey,
    });
    expect(() => mergeClaimLedger(rotationRecords, [], rotationRepo.checkpoint, rotationContext))
      .toThrow(/divergent|conflict/);
  });

  it("derives only exact canonical oidc-token-issuer grants as mint authority", () => {
    const readerOnly = mergeClaimLedger(
      [s.claimRecordOne, s.claimRecordTwo], [], s.baseRepository.checkpoint, contextFor(s.baseRepository.repository),
    );
    expect(resolveIssuerAuthorityState(s.writerOne.did_key, readerOnly)).toBe("invalid");
    const records = [
      s.claimRecordOne, s.claimRecordTwo,
      s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo,
    ];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: records,
      observed_at: s.now + 100,
      prior: s.authorityRepository.repository,
    });
    const state = mergeClaimLedger(records, [], repository.checkpoint, s.makeTask5Context(repository.repository));
    expect(resolveIssuerAuthorityState(s.writerOne.did_key, state)).toBe("active");
    expect(resolveIssuerAuthorityState(s.writerTwo.did_key, state)).toBe("active");
  });

  it("enforces active authority, signing-key possession, and the 300-second freshness ceiling", () => {
    const checkpoint = s.baseRepository.checkpoint;
    expect(canMint(checkpoint.observed_at + 300, checkpoint, 300, "active", true)).toMatchObject({
      allowed: true,
      reason_code: null,
      checkpoint,
    });
    expect(canMint(checkpoint.observed_at + 301, checkpoint, 300, "active", true).reason_code)
      .toBe("oidc-checkpoint-stale");
    expect(canMint(checkpoint.observed_at, checkpoint, 301, "active", true).allowed).toBe(false);
    expect(canMint(checkpoint.observed_at, checkpoint, 300, "revoked", true).reason_code)
      .toBe("oidc-issuer-authority-invalid");
    expect(canMint(checkpoint.observed_at, checkpoint, 300, "conflicted", true).reason_code)
      .toBe("oidc-issuer-authority-invalid");
    expect(canMint(checkpoint.observed_at, checkpoint, 300, "active", false).reason_code)
      .toBe("oidc-signing-key-unavailable");
    expect(canMint(checkpoint.observed_at, checkpoint, 0, "active", true).allowed).toBe(true);
    expect(canMint(checkpoint.observed_at, checkpoint, 300.5, "active", true).allowed).toBe(false);
    expect(canMint(checkpoint.observed_at + 121, checkpoint, 120, "active", true).reason_code)
      .toBe("oidc-checkpoint-stale");
    expect(canMint(checkpoint.observed_at - 1, checkpoint, 300, "active", true).allowed).toBe(false);
    expect(canMint(checkpoint.observed_at + 0.5, checkpoint, 300, "active", true).allowed).toBe(false);
    expect(canMint(checkpoint.observed_at, checkpoint, -1, "active", true).allowed).toBe(false);
    expect(canMint(checkpoint.observed_at, { ...checkpoint, branch: "dev" } as never, 300, "active", true).allowed)
      .toBe(false);
    for (const state of ["provisional", "expired", "invalid", "untrusted"] as const) {
      expect(canMint(checkpoint.observed_at, checkpoint, 300, state, true).reason_code)
        .toBe("oidc-issuer-authority-invalid");
    }
  });

  it("persists the exact mint bound and permits zero only at the checkpoint instant", () => {
    const checkpoint = s.baseRepository.checkpoint;
    expect(canMint(checkpoint.observed_at, checkpoint, 0, "active", true)).toMatchObject({ allowed: true });
    expect(canMint(checkpoint.observed_at + 1, checkpoint, 0, "active", true)).toMatchObject({ allowed: false });

    expect(() => validateIssuanceRecordOrThrow({
      ...s.issuanceOne,
      manifest_max_age_seconds: 5,
      checkpoint,
      issued_at: checkpoint.observed_at + 5,
    } as never)).not.toThrow();
    expect(() => validateIssuanceRecordOrThrow({
      ...s.issuanceOne,
      manifest_max_age_seconds: 5,
      checkpoint,
      issued_at: checkpoint.observed_at + 6,
    } as never)).toThrow(/fresh|manifest|checkpoint/);
    expect(() => validateIssuanceRecordOrThrow({
      ...s.issuanceOne,
      manifest_max_age_seconds: 301,
    } as never)).toThrow(/manifest|maximum|schema/);
    expect(() => validateIssuanceRecordOrThrow({
      ...s.issuanceOne,
      manifest_max_age_seconds: 0.5,
    } as never)).toThrow(/manifest|integer|schema/);
  });

  it("derives exhaustive issuer recipients, gates pending rotation, and requires canonical issuance finality", () => {
    const records = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
    ];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: records, observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const state = mergeClaimLedger(records, [], repository.checkpoint, s.makeTask5Context(repository.repository));
    expect(deriveActiveIssuerNids(state)).toEqual([s.writerOne.did_key, s.writerTwo.did_key].sort());
    expect(evaluateMintingAttempt({
      now: state.checkpoint.observed_at, manifest_max_age_seconds: 300,
      writer_nid: s.writerOne.did_key, state,
      envelope: s.issuerKeyEnvelopeOne, audience_key: s.issuerAudienceKeyOne,
    }).allowed).toBe(true);

    const deliveredRemoval = mergeClaimLedger(
      records, [s.issuerRemovalRecord], repository.checkpoint, s.makeTask5Context(repository.repository),
    );
    expect(evaluateMintingAttempt({
      now: deliveredRemoval.checkpoint.observed_at, manifest_max_age_seconds: 300,
      writer_nid: s.writerTwo.did_key, state: deliveredRemoval,
      envelope: s.issuerKeyEnvelopeOne, audience_key: s.issuerAudienceKeyOne,
    })).toMatchObject({ allowed: false, pending_rotation: true });

    const deliveredIssuance = mergeClaimLedger(
      records, [s.reservationOne], repository.checkpoint, s.makeTask5Context(repository.repository),
    );
    expect(canReturnToken(
      s.reservationOne.record_id, deliveredIssuance, s.issuerKeyEnvelopeOne, s.issuerAudienceKeyOne,
    ).allowed).toBe(false);

    expect(() => createIssuerKeyEnvelope({
      persona: s.persona,
      repository_rid: s.rid,
      epoch: 1,
      audience_key: s.issuerAudienceKeyOne,
      signing_jwk: s.signingJwk,
      authority_state: s.removedAuthorityState,
      recipient_nids: [s.writerTwo.did_key],
    })).toThrow(/genesis|rotation|removed/);
  });

  it("rejects a canonical issuance whose checkpoint is only on a side branch", () => {
    const authorityRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo,
    ];
    const side = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: authorityRecords,
      observed_at: s.now + 90,
      prior: s.baseRepository.repository,
    });
    const sideIssuance = createSignedLedgerRecord({
      record_type: "issuance-reservation",
      persona: s.persona,
      credential_ledger_generation: 0,
      writer_nid: s.writerOne.did_key,
      created_at: s.now + 92,
      parents: [s.claimRecordOne.record_id],
      payload: {
        ...s.issuanceOne,
        checkpoint: side.checkpoint,
        issued_at: s.now + 91,
      } as never,
    }, s.writerOne.private_key);
    const canonical = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: [...authorityRecords, sideIssuance],
      observed_at: s.now + 100,
      prior: s.baseRepository.repository,
    });
    canonical.repository.commits.splice(-1, 0, side.repository.commits.at(-1)!);
    const context = s.makeTask5Context(canonical.repository);
    context.record_evidence.set(sideIssuance.record_id, boundEvidence(sideIssuance));
    const state = mergeClaimLedger(
      [...authorityRecords, sideIssuance], [], canonical.checkpoint, context,
    );
    expect(canReturnToken(
      sideIssuance.record_id, state, s.issuerKeyEnvelopeOne, s.issuerAudienceKeyOne,
    )).toMatchObject({
      allowed: false,
      reason_code: "claim-ledger-rollback",
    });
  });

  it("rejects canonical token return from an unauthorized writer or unbound signing key", () => {
    const bob = fixtures.ed25519_nids.bob_device_1;
    const authorityRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
    ];
    const issuance = {
      ...s.issuanceOne,
      jti: "unauthorized_bob_token_0001",
      reservation: reserveStatusIndex(bob.did_key, s.now + 3_600, 0, []),
      checkpoint: s.issuerKeyEpochOneRepository.checkpoint,
      signing_key_id: OIDC_RSA_TWO.key_id,
      issued_at: s.now + 66,
    };
    const record = createSignedLedgerRecord({
      record_type: "issuance-reservation",
      persona: s.persona,
      credential_ledger_generation: 0,
      writer_nid: bob.did_key,
      created_at: s.now + 70,
      parents: [s.claimRecordOne.record_id],
      payload: issuance as never,
    }, bob.private_key);
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: [...authorityRecords, record],
      observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const context = s.makeTask5Context(repository.repository);
    context.record_evidence.set(record.record_id, boundEvidence(record));
    const state = mergeClaimLedger([...authorityRecords, record], [], repository.checkpoint, context);
    expect(canReturnToken(
      record.record_id, state, s.issuerKeyEnvelopeOne, s.issuerAudienceKeyOne,
    )).toMatchObject({ allowed: false, reason_code: "oidc-issuer-authority-invalid" });
    expect(createStatusInvalidationRecords({
      state,
      writer_nid: s.writerTwo.did_key,
      writer_secret_key: s.writerTwo.private_key,
      created_at: repository.checkpoint.observed_at + 1,
      compromised_signing_key_ids: [issuance.signing_key_id],
    })).toEqual([]);
  });

  it("preserves historical returnability after later issuer removal and source revocation", () => {
    const issuedRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
      s.reservationOne, s.reservationTwo,
    ];
    const issuedRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: issuedRecords, observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const removedRecords = [...issuedRecords, s.issuerRemovalRecord];
    const removedRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: removedRecords, observed_at: s.now + 110,
      prior: issuedRepo.repository,
    });
    const removedState = mergeClaimLedger(
      removedRecords, [], removedRepo.checkpoint, s.makeTask5Context(removedRepo.repository),
    );
    expect(canReturnToken(
      s.reservationOne.record_id, removedState, s.issuerKeyEnvelopeOne, s.issuerAudienceKeyOne,
    )).toMatchObject({
      allowed: false,
      state: "invalid",
      reason_code: "oidc-issuer-authority-invalid",
    });
    const revokedRecords = [...removedRecords, s.revocationRecord];
    const revokedRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: revokedRecords, observed_at: s.now + 111,
      prior: removedRepo.repository,
    });
    const state = mergeClaimLedger(
      revokedRecords, [], revokedRepo.checkpoint, s.makeTask5Context(revokedRepo.repository),
    );
    expect(resolveIssuerAuthorityState(s.writerOne.did_key, state)).toBe("revoked");
    expect(resolveAuthoritativeClaimState(s.claimOne.artifact.semantic.claim_id, state)).toBe("revoked");
    expect(determineHistoricalTokenReturnability(s.reservationOne.record_id, state)).toMatchObject({
      allowed: true,
      state: "active",
    });
    expect(canReturnToken(
      s.reservationOne.record_id, state, s.issuerKeyEnvelopeOne, s.issuerAudienceKeyOne,
    )).toMatchObject({ allowed: false, state: "revoked", reason_code: "claim-revoked" });
  });

  it("rejects ambiguous sibling introductions of one canonical issuance", () => {
    const baseRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
    ];
    const leftRecords = [...baseRecords, s.reservationOne];
    const rightRecords = [...baseRecords, s.reservationOne, s.reservationTwo];
    const left = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: leftRecords, observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const right = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: rightRecords, observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const recordIds = rightRecords.map(({ record_id }) => record_id).sort();
    const recordSetDigest = digestJson(recordIds);
    const treeOid = digestJson({
      domain: "heterodyne-claim-ledger-tree-v1",
      record_ids: recordIds,
      record_set_digest: recordSetDigest,
    });
    const parents = [left.repository.canonical_head, right.repository.canonical_head].sort();
    const commitOid = digestJson({
      domain: "heterodyne-claim-ledger-commit-v1",
      repository_rid: s.rid,
      branch: "main",
      tree_oid: treeOid,
      parents,
      record_set_digest: recordSetDigest,
    });
    const checkpoint = {
      repository_rid: s.rid, branch: "main" as const, commit_oid: commitOid, observed_at: s.now + 101,
    };
    const priorCommits = s.issuerKeyEpochOneRepository.repository.commits;
    const repository = {
      repository_rid: s.rid,
      branch: "main" as const,
      genesis: false,
      prior_checkpoint: s.issuerKeyEpochOneRepository.checkpoint,
      canonical_head: commitOid,
      checkpoint,
      commits: [
        ...priorCommits,
        left.repository.commits.at(-1)!,
        right.repository.commits.at(-1)!,
        {
          commit_oid: commitOid,
          tree_oid: treeOid,
          parents,
          record_ids: recordIds,
          record_set_digest: recordSetDigest,
        },
      ],
      repository_confirmed_record_ids: recordIds,
    };
    const state = mergeClaimLedger(
      rightRecords, [], checkpoint, s.makeTask5Context(repository),
    );
    expect(determineHistoricalTokenReturnability(s.reservationOne.record_id, state)).toMatchObject({
      allowed: false,
      reason_code: "claim-repository-conflict",
    });
  });

  it("exposes deterministic signed invalidation record creation", () => {
    const issuedRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
      s.reservationOne, s.reservationTwo,
    ];
    const issuedRepository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: issuedRecords, observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const records = [...issuedRecords, s.revocationRecord];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: records, observed_at: s.now + 110,
      prior: issuedRepository.repository,
    });
    const state = mergeClaimLedger(records, [], repository.checkpoint, s.makeTask5Context(repository.repository));
    const input = {
      state, writer_nid: s.writerTwo.did_key, writer_secret_key: s.writerTwo.private_key,
      created_at: repository.checkpoint.observed_at + 1,
      compromised_signing_key_ids: [s.issuanceOne.signing_key_id],
    };
    const first = createStatusInvalidationRecords(input);
    const second = createStatusInvalidationRecords(input);
    expect(first).toEqual(second);
    expect(first).toHaveLength(4);
    expect(first.map(({ record_type }) => record_type)).toEqual(Array(4).fill("status-invalidation"));
    expect(new Set(first.map(({ payload }) => (payload as any).cause))).toEqual(
      new Set(["source-claim-revoked", "signing-key-compromised"]),
    );
    expect(first.every(({ payload }) => {
      const value = payload as any;
      return value.writer_authority_claim_id === s.issuerClaimTwo.artifact.semantic.claim_id &&
        value.authority_checkpoint.commit_oid === state.checkpoint.commit_oid &&
        value.issuer_key_epoch === 1 &&
        value.issuer_key_digest === s.issuerKeyEnvelopeOne.signing_key_id;
    })).toBe(true);

    const deliveredOnly = mergeClaimLedger(
      [
        s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
        s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
      ],
      [s.reservationOne, s.revocationRecord],
      s.issuerKeyEpochOneRepository.checkpoint,
      s.makeTask5Context(s.issuerKeyEpochOneRepository.repository),
    );
    expect(deliveredOnly.token_invalidations).toEqual([]);
    expect(createStatusInvalidationRecords({
      ...input,
      state: deliveredOnly,
      created_at: deliveredOnly.checkpoint.observed_at + 1,
    })).toEqual([]);
  });

  it("keeps a historically authorized canonical invalidation valid after writer removal", () => {
    const issuedRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
      s.reservationOne, s.reservationTwo,
    ];
    const issuedRepository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: issuedRecords, observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const records = [...issuedRecords, s.revocationRecord];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: records, observed_at: s.now + 110,
      prior: issuedRepository.repository,
    });
    const state = mergeClaimLedger(records, [], repository.checkpoint, s.makeTask5Context(repository.repository));
    const invalidations = createStatusInvalidationRecords({
      state, writer_nid: s.writerOne.did_key, writer_secret_key: s.writerOne.private_key,
      created_at: repository.checkpoint.observed_at + 1,
      compromised_signing_key_ids: [s.issuanceOne.signing_key_id],
    });
    const invalidationRecords = [...records, ...invalidations];
    const invalidationRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: invalidationRecords, observed_at: s.now + 112,
      prior: repository.repository,
    });
    const removedRecords = [...invalidationRecords, s.issuerRemovalRecord];
    const removedRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: removedRecords, observed_at: s.now + 113,
      prior: invalidationRepo.repository,
    });
    const context = s.makeTask5Context(removedRepo.repository);
    const sourceEvidence = context.record_evidence.get(s.statusInvalidation.record_id)!;
    for (const record of invalidations) {
      const payload = record.payload as any;
      context.record_evidence.set(record.record_id, {
        ...(payload.cause === "source-claim-revoked" ? sourceEvidence : {}),
        record_id: record.record_id,
        payload_digest: record.payload_digest,
      });
    }
    expect(() => mergeClaimLedger(removedRecords, [], removedRepo.checkpoint, context)).not.toThrow();
  });

  it("rejects an invalidation authored after the bound writer authority expires", () => {
    const issuedRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
      s.reservationOne,
    ];
    const issuedRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: issuedRecords, observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const createdAt = s.issuerClaimTwo.artifact.semantic.expires_at! + 1;
    const invalidation = createSignedLedgerRecord({
      record_type: "status-invalidation",
      persona: s.persona,
      credential_ledger_generation: 0,
      writer_nid: s.writerTwo.did_key,
      created_at: createdAt,
      parents: [s.reservationOne.record_id],
      payload: {
        ...(s.statusInvalidation.payload as Record<string, unknown>),
        authority_checkpoint: issuedRepo.checkpoint,
        issuer_key_epoch: 1,
        issuer_key_digest: s.issuerKeyEnvelopeOne.signing_key_id,
      } as never,
    }, s.writerTwo.private_key);
    const records = [...issuedRecords, invalidation];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: records, observed_at: createdAt + 1,
      prior: issuedRepo.repository,
    });
    const context = s.makeTask5Context(repository.repository);
    context.record_evidence.set(invalidation.record_id, {
      ...context.record_evidence.get(s.statusInvalidation.record_id)!,
      record_id: invalidation.record_id,
      payload_digest: invalidation.payload_digest,
    });
    expect(() => mergeClaimLedger(records, [], repository.checkpoint, context))
      .toThrow(/authority|expired/);
  });

  it("creates invalidations for historical tokens after issuer removal, rotation, and later compromise", () => {
    const issuedRecords = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
      s.reservationOne, s.reservationTwo,
    ];
    const issuedRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: issuedRecords, observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const removedRecords = [...issuedRecords, s.issuerRemovalRecord];
    const removedRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: removedRecords, observed_at: s.now + 110,
      prior: issuedRepo.repository,
    });
    const removedState = mergeClaimLedger(
      removedRecords, [], removedRepo.checkpoint, s.makeTask5Context(removedRepo.repository),
    );
    const rotatedAudienceKey = Uint8Array.from({ length: 32 }, () => 0x79);
    const rotatedEnvelope = createIssuerKeyEnvelope({
      persona: s.persona,
      repository_rid: s.rid,
      epoch: 2,
      audience_key: rotatedAudienceKey,
      signing_jwk: OIDC_RSA_TWO.private_jwk,
      authority_state: removedState,
      recipient_nids: [s.writerTwo.did_key],
      previous: { envelope: s.issuerKeyEnvelopeOne, audience_key: s.issuerAudienceKeyOne },
    });
    const rotatedPayload = createIssuerKeyEpochPayload({
      authority_state: removedState,
      envelope: rotatedEnvelope,
      previous_record: s.issuerKeyEpochRecordOne,
    });
    const rotatedRecord = createSignedLedgerRecord({
      record_type: "audience-key-epoch",
      persona: s.persona,
      credential_ledger_generation: 0,
      writer_nid: s.writerTwo.did_key,
      created_at: s.now + 111,
      parents: [s.issuerKeyEpochRecordOne.record_id, s.issuerRemovalRecord.record_id].sort(),
      payload: rotatedPayload as never,
    }, s.writerTwo.private_key);
    const rotatedRecords = [...removedRecords, rotatedRecord];
    const rotatedRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: rotatedRecords, observed_at: s.now + 112,
      prior: removedRepo.repository,
    });
    const revokedRecords = [...rotatedRecords, s.revocationRecord];
    const revokedRepo = buildLedgerRepositoryEvidence({
      repository_rid: s.rid, confirmed_records: revokedRecords, observed_at: s.now + 113,
      prior: rotatedRepo.repository,
    });
    const context = s.makeTask5Context(revokedRepo.repository);
    context.record_evidence.set(rotatedRecord.record_id, boundEvidence(rotatedRecord));
    context.issuer_key_material_by_record_id!.set(rotatedRecord.record_id, {
      envelope: rotatedEnvelope,
      audience_key: rotatedAudienceKey,
    });
    const state = mergeClaimLedger(revokedRecords, [], revokedRepo.checkpoint, context);
    const invalidations = createStatusInvalidationRecords({
      state,
      writer_nid: s.writerTwo.did_key,
      writer_secret_key: s.writerTwo.private_key,
      created_at: state.checkpoint.observed_at + 1,
      compromised_signing_key_ids: [s.issuerKeyEnvelopeOne.signing_key_id],
    });
    expect(invalidations).toHaveLength(4);
    expect(new Set(invalidations.map(({ payload }) => (payload as any).jti))).toEqual(
      new Set([s.issuanceOne.jti, s.issuanceTwo.jti]),
    );
    expect(new Set(invalidations.map(({ payload }) => (payload as any).cause))).toEqual(
      new Set(["source-claim-revoked", "signing-key-compromised"]),
    );
    expect(invalidations.every(({ payload }) => (payload as any).issuer_key_epoch === 2)).toBe(true);
  });

  it("confines a separately encrypted signing JWK to active issuer devices", () => {
    const issuerKey = Uint8Array.from({ length: 32 }, () => 0x71);
    const jwk = OIDC_RSA_ONE.private_jwk;
    const envelope = createIssuerKeyEnvelope({
      persona: s.persona,
      repository_rid: s.rid,
      epoch: 1,
      audience_key: issuerKey,
      signing_jwk: jwk,
      authority_state: s.authorityState,
      recipient_nids: [s.writerOne.did_key, s.writerTwo.did_key],
    });
    expect(() => createIssuerKeyEnvelope({
      persona: s.persona, repository_rid: s.rid, epoch: 1, audience_key: issuerKey,
      signing_jwk: jwk, authority_state: s.authorityState, recipient_nids: [s.writerOne.did_key],
    })).toThrow(/exactly equal/);
    expect(() => createIssuerKeyEnvelope({
      persona: s.persona, repository_rid: s.rid, epoch: 1, audience_key: issuerKey,
      signing_jwk: jwk, authority_state: s.authorityState,
      recipient_nids: [s.writerOne.did_key, s.writerTwo.did_key, fixtures.ed25519_nids.bob_device_1.did_key],
    })).toThrow(/exactly equal/);
    expect(unwrapIssuerSigningJwk(envelope, s.writerOne.did_key, issuerKey)).toEqual(jwk);
    expect(unwrapIssuerSigningJwk(envelope, s.writerTwo.did_key, issuerKey)).toEqual(jwk);
    expect(() => unwrapIssuerSigningJwk(envelope, s.writerOne.did_key, s.audienceKeyOne))
      .toThrow(/signing key|audience key/);
    const tamperedEnvelope = structuredClone(envelope);
    tamperedEnvelope.recipient_wraps[0].wrapped_key = "00".repeat(64);
    expect(() => unwrapIssuerSigningJwk(tamperedEnvelope, tamperedEnvelope.recipient_wraps[0].writer_nid, issuerKey))
      .toThrow(/wrap/);

    const rotated = createIssuerKeyEnvelope({
      persona: s.persona,
      repository_rid: s.rid,
      epoch: 2,
      audience_key: Uint8Array.from({ length: 32 }, () => 0x72),
      signing_jwk: OIDC_RSA_TWO.private_jwk,
      authority_state: s.removedAuthorityState,
      recipient_nids: [s.writerTwo.did_key],
      previous: { envelope, audience_key: issuerKey },
    });
    expect(rotated.recipient_wraps.map(({ writer_nid }) => writer_nid)).toEqual([s.writerTwo.did_key]);
    expect(() => createIssuerKeyEnvelope({
      persona: s.persona,
      repository_rid: s.rid,
      epoch: 2,
      audience_key: Uint8Array.from({ length: 32 }, () => 0x75),
      signing_jwk: jwk,
      authority_state: s.removedAuthorityState,
      recipient_nids: [s.writerTwo.did_key],
      previous: { envelope, audience_key: issuerKey },
    })).toThrow(/signing|material|rotated/);
    expect(() => createIssuerKeyEnvelope({
      persona: s.persona,
      repository_rid: s.rid,
      epoch: 2,
      audience_key: Uint8Array.from({ length: 32 }, () => 0x74),
      signing_jwk: OIDC_RSA_TWO.private_jwk,
      authority_state: s.removedAuthorityState,
      recipient_nids: [s.writerTwo.did_key],
      previous: {
        envelope: {
          epoch: envelope.epoch,
          audience_key_id: envelope.audience_key_id,
          recipient_wraps: envelope.recipient_wraps,
        } as never,
        audience_key: issuerKey,
      },
    })).toThrow(/previous|envelope|binding|unavailable/);
    for (const mutation of [
      {
        epoch: 3,
        audience_key: Uint8Array.from({ length: 32 }, () => 0x73),
        previous: { envelope, audience_key: issuerKey },
      },
      {
        epoch: 2,
        audience_key: issuerKey,
        previous: { envelope, audience_key: issuerKey },
      },
      {
        epoch: 2,
        audience_key: Uint8Array.from({ length: 32 }, () => 0x73),
        previous: { envelope, audience_key: s.audienceKeyOne },
      },
    ]) {
      expect(() => createIssuerKeyEnvelope({
        persona: s.persona,
        repository_rid: s.rid,
        signing_jwk: jwk,
        authority_state: s.removedAuthorityState,
        recipient_nids: [s.writerTwo.did_key],
        ...mutation,
      })).toThrow(/rotated/);
    }
    expect(() => unwrapIssuerSigningJwk(rotated, s.writerOne.did_key, Uint8Array.from({ length: 32 }, () => 0x72)))
      .toThrow(/authority|recipient/);
  });

  it("allocates monotonic collision-free indexes in canonical writer/list namespaces", () => {
    const first = reserveStatusIndex(s.writerOne.did_key, s.now + 172_800, 0, []);
    const issuance = {
      credential_ledger_generation: 0,
      jti: "writer_one_token_0001",
      reservation: first,
      checkpoint: s.baseRepository.checkpoint,
      manifest_max_age_seconds: 300,
      signing_key_id: OIDC_RSA_ONE.key_id,
      client_id: "heterodyne-task5-client",
      authorization_request_digest: "21".repeat(32),
      release_digest: "22".repeat(32),
      source_claim_ids: [s.claimOne.artifact.semantic.claim_id],
      issued_at: s.baseRepository.checkpoint.observed_at,
      expires_at: s.now + 172_800,
    };
    expect(first.expiry_bucket).toBe(String(Math.floor((s.now + 172_800) / 86_400)));
    expect(first.writer_nid_fingerprint).toMatch(/^[0-9a-f]{32}$/);
    expect(first.uri).toBe(`status-lists/${first.expiry_bucket}/${first.writer_nid_fingerprint}/0.jwt`);
    expect(reserveStatusIndex(s.writerOne.did_key, s.now + 172_800, 0, [issuance]).idx).toBe(1);
    expect(reserveStatusIndex(s.writerTwo.did_key, s.now + 172_800, 0, [issuance])).toMatchObject({ idx: 0 });
    expect(() => reserveStatusIndex(s.writerOne.did_key, s.now + 172_800, 0, [issuance, issuance]))
      .toThrow(/duplicate/);
    expect(() => reserveStatusIndex("did:key:zbad", s.now, 0, [])).toThrow(/NID|key/);
    expect(() => reserveStatusIndex(s.writerOne.did_key, -1, 0, [])).toThrow(/reservation|schema/);
    expect(() => reserveStatusIndex(s.writerOne.did_key, s.now, -1, [])).toThrow(/reservation|schema/);
    expect(() => reserveStatusIndex(s.writerOne.did_key, s.now, 0.5, [])).toThrow(/reservation|schema/);

    expect(() => validateIssuanceRecordOrThrow({ ...issuance, extra: true } as never)).toThrow(/additional/);
    const missingGeneration = { ...issuance } as Partial<typeof issuance>;
    delete missingGeneration.credential_ledger_generation;
    expect(() => validateIssuanceRecordOrThrow(missingGeneration as typeof issuance))
      .toThrow(/credential_generation_missing/);
    expect(() => validateIssuanceRecordOrThrow({ ...issuance, jti: "short" })).toThrow(/jti|pattern/);
    expect(() => validateIssuanceRecordOrThrow({ ...issuance, signing_key_id: "11" })).toThrow(/signing_key_id|pattern/);
    expect(() => validateIssuanceRecordOrThrow({ ...issuance, source_claim_ids: [] })).toThrow(/source_claim_ids|items/);
    expect(() => validateIssuanceRecordOrThrow({
      ...issuance,
      reservation: { ...issuance.reservation, uri: `${issuance.reservation.uri}0` },
    })).toThrow(/uri|reservation/);
  });

  it("rejects duplicate concurrent durable reservations during canonical merge", () => {
    const duplicate = createSignedLedgerRecord({
      record_type: "issuance-reservation",
      persona: s.persona,
      credential_ledger_generation: 0,
      writer_nid: s.writerOne.did_key,
      created_at: s.now + 71,
      parents: [s.claimRecordOne.record_id],
      payload: s.issuanceOne as never,
    }, s.writerOne.private_key);
    const records = [
      s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
      s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
      s.reservationOne, duplicate,
    ];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: records,
      observed_at: s.now + 100,
      prior: s.issuerKeyEpochOneRepository.repository,
    });
    const context = s.makeTask5Context(repository.repository);
    context.record_evidence.set(duplicate.record_id, boundEvidence(duplicate));
    expect(() => mergeClaimLedger(records, [], repository.checkpoint, context)).toThrow(/duplicate/);
  });
});
