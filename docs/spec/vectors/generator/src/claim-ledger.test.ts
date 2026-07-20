import { beforeAll, describe, expect, it } from "vitest";
import {
  buildLedgerRepositoryEvidence,
  buildReaderOnboardingBundle,
  canMint,
  createAudienceKeyEpochPayload,
  createIssuerKeyEnvelope,
  createSignedLedgerRecord,
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
import { buildClaimLedgerScenario, buildClaimLedgerVectors, type ClaimLedgerScenario } from "./topics-claim-ledger.js";

const fixtures = buildFixtures();
let s: ClaimLedgerScenario;

beforeAll(async () => {
  s = await buildClaimLedgerScenario(fixtures);
});

function contextFor(repository: ReturnType<typeof buildLedgerRepositoryEvidence>["repository"]): LedgerValidationContext {
  return s.makeContext(repository);
}

function cloneRequest(request: ReaderAccessRequest): ReaderAccessRequest {
  return structuredClone(request);
}

function resign(record: LedgerRecord, payload: LedgerRecord["payload"], writer = s.writerTwo): LedgerRecord {
  return createSignedLedgerRecord({
    record_type: record.record_type,
    persona: record.persona,
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

describe("signed ledger artifact validation", () => {
  it("requires record-bound validation evidence even for a valid repository writer", () => {
    const records = new Map([[s.claimRecordOne.record_id, s.claimRecordOne]]);
    expect(() => validateLedgerRecordOrThrow(s.claimRecordOne, records)).toThrow(/evidence|unconfirmed/);
    expect(() => validateLedgerRecordOrThrow(
      s.claimRecordOne,
      records,
      s.evidence.get(s.claimRecordOne.record_id),
    )).not.toThrow();
  });

  it("rejects a bare semantic claim and an invalid signed envelope despite a valid Ed25519 writer", () => {
    const bare = resign(s.claimRecordOne, { claim: s.claimOne.artifact.semantic });
    expect(() => validateLedgerRecordOrThrow(
      bare,
      new Map([[bare.record_id, bare]]),
      boundEvidence(bare, s.evidence.get(s.claimRecordOne.record_id)),
    )).toThrow(/schema/);

    const artifact = structuredClone(s.claimOne.artifact);
    artifact.event.sig = `${artifact.event.sig[0] === "0" ? "1" : "0"}${artifact.event.sig.slice(1)}`;
    const tampered = resign(s.claimRecordOne, { claim_artifact: artifact });
    expect(() => validateLedgerRecordOrThrow(
      tampered,
      new Map([[tampered.record_id, tampered]]),
      boundEvidence(tampered, s.evidence.get(s.claimRecordOne.record_id)),
    )).toThrow(/signature|event/);
  });

  it("rejects payload/record/signature mutations and cross-writer substitution", () => {
    const evidence = s.evidence.get(s.claimRecordOne.record_id)!;
    for (const mutation of [
      { ...s.claimRecordOne, record_id: "00".repeat(32) },
      { ...s.claimRecordOne, payload_digest: "00".repeat(32) },
      { ...s.claimRecordOne, signature: "00".repeat(64) },
      { ...s.claimRecordOne, writer_nid: s.writerTwo.did_key },
    ]) {
      expect(() => validateLedgerRecordOrThrow(mutation, new Map([[mutation.record_id, mutation]]), evidence)).toThrow();
    }
  });

  it("replays revocation authority and rejects target, signer-role, or subject mismatch", () => {
    const records = new Map([
      [s.claimRecordOne.record_id, s.claimRecordOne],
      [s.reductionRecord.record_id, s.reductionRecord],
    ]);
    expect(() => validateLedgerRecordOrThrow(s.reductionRecord, records, s.evidence.get(s.reductionRecord.record_id))).not.toThrow();

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
    )).toThrow(/target|subject|role/);
  });
});

describe("canonical repository evidence and convergence", () => {
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

    const statusRecords = [s.claimRecordOne, s.claimRecordTwo, s.reservationOne, s.statusInvalidation];
    const statusRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: statusRecords, observed_at: s.now + 80, prior: s.baseRepository.repository });
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
      record_type: "audience-key-epoch", persona: s.persona, writer_nid: s.writerTwo.did_key,
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
      prior: s.baseRepository.repository,
    });
    const state = mergeClaimLedger(records, [], repository.checkpoint, s.makeTask5Context(repository.repository));
    expect(resolveIssuerAuthorityState(s.writerOne.did_key, state)).toBe("active");
    expect(resolveIssuerAuthorityState(s.writerTwo.did_key, state)).toBe("active");
  });

  it("enforces active authority, signing-key possession, and the 300-second freshness ceiling", () => {
    const checkpoint = s.baseRepository.checkpoint;
    expect(canMint(checkpoint.observed_at + 300, checkpoint, 600, "active", true)).toMatchObject({
      allowed: true,
      reason_code: null,
      checkpoint,
    });
    expect(canMint(checkpoint.observed_at + 301, checkpoint, 600, "active", true).reason_code)
      .toBe("oidc-checkpoint-stale");
    expect(canMint(checkpoint.observed_at, checkpoint, 300, "revoked", true).reason_code)
      .toBe("oidc-issuer-authority-invalid");
    expect(canMint(checkpoint.observed_at, checkpoint, 300, "conflicted", true).reason_code)
      .toBe("oidc-issuer-authority-invalid");
    expect(canMint(checkpoint.observed_at, checkpoint, 300, "active", false).reason_code)
      .toBe("oidc-signing-key-unavailable");
    expect(canMint(checkpoint.observed_at, checkpoint, 0, "active", true).allowed).toBe(true);
    expect(canMint(checkpoint.observed_at + 1, checkpoint, 0, "active", true).reason_code)
      .toBe("oidc-checkpoint-stale");
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

  it("confines a separately encrypted signing JWK to active issuer devices", () => {
    const issuerKey = Uint8Array.from({ length: 32 }, () => 0x71);
    const jwk = { kty: "RSA", kid: "issuer-key-1", d: "private-material" };
    const envelope = createIssuerKeyEnvelope({
      persona: s.persona,
      repository_rid: s.rid,
      checkpoint_commit_oid: s.baseRepository.checkpoint.commit_oid,
      epoch: 1,
      audience_key: issuerKey,
      signing_jwk: jwk,
      active_issuer_nids: [s.writerOne.did_key, s.writerTwo.did_key],
    });
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
      checkpoint_commit_oid: s.epochOneRepository.checkpoint.commit_oid,
      epoch: 2,
      previous_key_id: envelope.audience_key_id,
      audience_key: Uint8Array.from({ length: 32 }, () => 0x72),
      signing_jwk: jwk,
      active_issuer_nids: [s.writerTwo.did_key],
      removed_issuer_nids: [s.writerOne.did_key],
    });
    expect(rotated.recipient_wraps.map(({ writer_nid }) => writer_nid)).toEqual([s.writerTwo.did_key]);
    expect(() => unwrapIssuerSigningJwk(rotated, s.writerOne.did_key, Uint8Array.from({ length: 32 }, () => 0x72)))
      .toThrow(/authority|recipient/);
  });

  it("allocates monotonic collision-free indexes in canonical writer/list namespaces", () => {
    const first = reserveStatusIndex(s.writerOne.did_key, s.now + 172_800, 0, []);
    const issuance = {
      jti: "writer_one_token_0001",
      reservation: first,
      checkpoint: s.baseRepository.checkpoint,
      signing_key_id: "11".repeat(32),
      source_claim_ids: [s.claimOne.artifact.semantic.claim_id],
      issued_at: s.now,
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
      writer_nid: s.writerOne.did_key,
      created_at: s.now + 71,
      parents: [s.claimRecordOne.record_id],
      payload: s.issuanceOne as never,
    }, s.writerOne.private_key);
    const records = [s.claimRecordOne, s.claimRecordTwo, s.reservationOne, duplicate];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: records,
      observed_at: s.now + 100,
      prior: s.baseRepository.repository,
    });
    const context = s.makeTask5Context(repository.repository);
    context.record_evidence.set(duplicate.record_id, boundEvidence(duplicate));
    expect(() => mergeClaimLedger(records, [], repository.checkpoint, context)).toThrow(/duplicate/);
  });
});

describe("Task 4 vector closure", () => {
  it("authors the exact thirteen vectors from executable decisions", async () => {
    const vectors = await buildClaimLedgerVectors(fixtures);
    expect(vectors).toHaveLength(13);
    expect(vectors.map(({ relativePath }) => relativePath)).toEqual(
      Array.from({ length: 13 }, (_, index) => `claim-ledger/${(index + 1).toString().padStart(3, "0")}-${[
        "reader-nid-authorized", "nidless-reader-denied", "delivered-grant-provisional", "immediate-revocation",
        "multiwriter-revocation-wins", "authority-reduction-wins", "nonmonotonic-conflict-blocks",
        "checkpoint-rollback-rejected", "keyed-path-metadata-private", "reader-removal-key-rotation",
        "multiwriter-status-allocation", "stale-minter-denied", "source-claim-revokes-token",
      ][index]}.json`),
    );
    const rollback = vectors.find(({ vector }) => vector.vector_id.endsWith("checkpoint-rollback-rejected"))!.vector;
    expect(rollback.expected_output).toEqual({ verdict: "reject", reason_code: "claim-ledger-rollback" });
    const privacy = vectors.find(({ vector }) => vector.vector_id.endsWith("keyed-path-metadata-private"))!.vector;
    expect((privacy.expected_output.normalized as { changed_entries: number }).changed_entries).toBe(256);
    const multiwriter = vectors.find(({ vector }) => vector.vector_id.endsWith("multiwriter-status-allocation"))!.vector;
    const multiwriterOutput = multiwriter.expected_output.normalized as any;
    expect(multiwriter.expected_output.verdict).toBe("accept");
    expect(multiwriterOutput.writers.map(({ eligibility }: any) => eligibility.allowed)).toEqual([true, true]);
    expect(new Set(multiwriterOutput.writers.map(({ signing_key_id }: any) => signing_key_id)).size).toBe(1);
    expect(multiwriterOutput.unique_allocation_count).toBe(2);
    expect(multiwriterOutput.durable_before_return).toBe(true);

    const stale = vectors.find(({ vector }) => vector.vector_id.endsWith("stale-minter-denied"))!.vector;
    const staleOutput = stale.expected_output.normalized as any;
    expect(staleOutput.boundary_300.allowed).toBe(true);
    expect(staleOutput.boundary_301.reason_code).toBe("oidc-checkpoint-stale");
    expect(staleOutput.removal.reason_code).toBe("oidc-issuer-authority-invalid");
    expect(staleOutput.removed_recipient_can_unwrap_rotated_key).toBe(false);
    expect(staleOutput.rotated_key.audience_key_id).not.toBe(staleOutput.rotated_key.previous_key_id);

    const invalidation = vectors.find(({ vector }) => vector.vector_id.endsWith("source-claim-revokes-token"))!.vector;
    const invalidationOutput = invalidation.expected_output.normalized as any;
    expect(invalidationOutput.converged).toBe(true);
    expect(invalidationOutput.left_token_invalidations).toEqual(["writer_one_token_0001", "writer_two_token_0001"]);
    expect(invalidationOutput.invalidation_record_jtis).toEqual(invalidationOutput.left_token_invalidations);
    expect(invalidationOutput.signing_key_compromise.invalidated_jtis).toEqual(invalidationOutput.left_token_invalidations);
    expect(invalidationOutput.signing_key_compromise.replacement_signing_key_id)
      .not.toBe(invalidationOutput.signing_key_compromise.compromised_signing_key_id);
  });
});
