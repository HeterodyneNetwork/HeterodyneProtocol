import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import {
  buildLedgerRepositoryEvidence,
  createAudienceKeyEpochPayload,
  createIssuerKeyEnvelope,
  createIssuerKeyEpochPayload,
  createSignedLedgerRecord,
  currentClaimAuthorizationView,
  mergeClaimLedger,
  reserveStatusIndex,
  type ClaimArtifact,
  type LedgerRecord,
  type LedgerRecordValidationEvidence,
  type LedgerRepositoryEvidence,
  type LedgerValidationContext,
  type IssuanceRecord,
  type ReaderAccessRequest,
  type RevocationArtifact,
} from "./claim-ledger.js";
import {
  createClaimAuthorizationAuthority,
  type CurrentClaimAuthorizationView,
  type ClaimEffectRecord,
  type ClaimEffectStore,
} from "./claim-authorization.js";
import {
  createCoreRepositoryWriterAuthority,
  type RepositoryWriterBindingV1,
} from "./core-writer-binding.js";
import type { CurrentRepositoryPolicy } from "./core-policy.js";
import {
  CLAIM_REVOCATION_PROFILE,
  computeClaimId,
  subjectProofPayload,
  verifyClaimEnvelope,
  verifyClaimRevocationEnvelope,
  type ClaimRevocation,
  type ClaimSemanticBody,
  type ClaimVerificationContext,
  type JsonValue,
  type SubjectProofChallenge,
} from "./claims.js";
import type { Fixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { signEvent } from "./nostr.js";
import { AUX_RAND } from "./vector-helpers.js";
import { OIDC_RSA_ONE, OIDC_RSA_TWO } from "./oidc-rsa-fixtures.js";
import { proofBytes } from "./proof-bytes.js";

export type ClaimLedgerScenario = Awaited<ReturnType<typeof buildClaimLedgerScenario>>;

export async function buildClaimLedgerScenario(fixtures: Fixtures) {
  const now = fixtures.test_epoch + 20_000;
  const persona = fixtures.personas.alice.epoch_keys.epoch_1.pubkey;
  const issuer = fixtures.personas.alice.epoch_keys.epoch_1;
  const writerOne = fixtures.ed25519_nids.alice_device_1;
  const writerTwo = fixtures.ed25519_nids.alice_device_2;
  const rid = fixtures.radicle_rids.alice;
  const resource = `${rid}#claim-ledger`;
  const writerRefNamespace = "refs/xyz.heterodyne.claim-ledger/writers/";
  const writerRefs = new Map([
    [writerOne.did_key, `${writerRefNamespace}writer-one`],
    [writerTwo.did_key, `${writerRefNamespace}writer-two`],
  ]);
  const makeWriterBinding = (
    writer: typeof writerOne,
  ): RepositoryWriterBindingV1 => {
    const body = {
      profile: "heterodyne.core.repository-writer-binding.v1" as const,
      spec_version: "heterodyne/0.6.0" as const,
      owner_active_key: persona,
      repository_rid: rid,
      writer_nid: writer.did_key,
      ref_namespace: writerRefNamespace,
      operations: ["claim-ledger-write"],
      issued_at: now - 10,
      expires_at: now + 10_000,
    };
    const payload = proofBytes(
      "heterodyne-core-repository-writer-binding-v1",
      body,
    );
    return {
      ...body,
      owner_signature: bytesToHex(schnorr.sign(
        sha256(payload),
        hexToBytes(issuer.private_key),
        hexToBytes(AUX_RAND),
      )),
      nid_signature: bytesToHex(ed25519.sign(
        payload,
        hexToBytes(writer.private_key),
      )),
    };
  };
  const writerBindings = new Map([
    [writerOne.did_key, makeWriterBinding(writerOne)],
    [writerTwo.did_key, makeWriterBinding(writerTwo)],
  ]);
  const activeWriterPolicy = (): CurrentRepositoryPolicy => ({
    repository_rid: rid,
    owner_active_key: persona,
    revision: 7,
    checkpoint: "a7".repeat(20),
    predecessor: "a6".repeat(20),
    state: "active",
    writers: [writerOne, writerTwo].map((writer) => ({
      writer_nid: writer.did_key,
      ref_namespace: writerRefNamespace,
      operations: ["claim-ledger-write"],
      state: "active" as const,
    })),
  });
  let currentWriterPolicy = activeWriterPolicy();
  const writerAuthority = createCoreRepositoryWriterAuthority({
    authority_id: "synthetic-local-claim-ledger-writer-authority",
    trusted_now: () => now + 50,
    load_current_policy: () => currentWriterPolicy,
  });
  const setCurrentWriterPolicy = (policy: CurrentRepositoryPolicy): void => {
    currentWriterPolicy = policy;
  };
  const resetCurrentWriterPolicy = (): void => {
    currentWriterPolicy = activeWriterPolicy();
  };
  const makeClaimAuthorizationHarness = (options: Readonly<{
    load_state: () => ReturnType<typeof mergeClaimLedger>;
    trusted_now?: () => number;
    transform_view?: (view: CurrentClaimAuthorizationView) => CurrentClaimAuthorizationView;
  }>) => {
    const records = new Map<string, ClaimEffectRecord>();
    const calls = { load: 0, acquire: 0, commit: 0, mark: 0 };
    const store: ClaimEffectStore = {
      load(singleUseKey) {
        calls.load += 1;
        return records.get(singleUseKey) ?? null;
      },
      acquire(singleUseKey, bindingDigest, executionToken) {
        calls.acquire += 1;
        if (records.has(singleUseKey)) return "replay";
        records.set(singleUseKey, {
          state: "executing",
          binding_digest: bindingDigest,
          execution_token: executionToken,
        });
        return "acquired";
      },
      commit(executionToken, resultDigest, cachedResult) {
        calls.commit += 1;
        const entry = [...records.entries()].find(([, value]) =>
          value.execution_token === executionToken);
        if (entry === undefined || entry[1].state !== "executing") return "conflict";
        records.set(entry[0], {
          state: "committed",
          binding_digest: entry[1].binding_digest,
          execution_token: executionToken,
          result_digest: resultDigest,
          cached_result: structuredClone(cachedResult),
        });
        return "committed";
      },
      markIndeterminate(executionToken, reconciliationDigest) {
        calls.mark += 1;
        const entry = [...records.entries()].find(([, value]) =>
          value.execution_token === executionToken);
        if (entry === undefined || entry[1].state !== "executing") return "conflict";
        records.set(entry[0], {
          state: "indeterminate",
          binding_digest: entry[1].binding_digest,
          execution_token: executionToken,
          reconciliation_digest: reconciliationDigest,
        });
        return "indeterminate";
      },
    };
    const authority = createClaimAuthorizationAuthority({
      authority_id: "synthetic-local-claim-ledger-effect-authority",
      trusted_now: options.trusted_now ?? (() => options.load_state().checkpoint.observed_at),
      trusted_issuers: [{ type: "nostr-secp256k1", value: persona }],
      load_current_view: () => {
        const view = currentClaimAuthorizationView(options.load_state());
        return options.transform_view?.(view) ?? view;
      },
      store,
      effect_timeout_ms: 60_000,
      schedule_effect_deadline: { schedule: () => () => {} },
    });
    return { authority, records, calls };
  };
  const audienceKeyOne = Uint8Array.from({ length: 32 }, () => 0x51);
  const audienceKeyTwo = Uint8Array.from({ length: 32 }, () => 0x52);
  const issuerAudienceKeyOne = Uint8Array.from({ length: 32 }, () => 0x71);
  const issuerAudienceKeyTwo = Uint8Array.from({ length: 32 }, () => 0x72);
  const audienceKeyOneId = bytesToHex(sha256(audienceKeyOne));
  const audienceKeyTwoId = bytesToHex(sha256(audienceKeyTwo));

  const makeClaim = async (
    reader: typeof writerOne,
    overrides: Partial<Omit<ClaimSemanticBody, "claim_id">> = {},
  ) => {
    const body: Omit<ClaimSemanticBody, "claim_id"> = {
      issuer: { type: "nostr-secp256k1", value: issuer.pubkey },
      subject: { type: "radicle-ed25519-nid", value: reader.did_key },
      claim_class: "authorization",
      credential_ledger_persona: persona,
      credential_ledger_generation: 0,
      namespace: "heterodyne.device",
      name: "claim-ledger-reader",
      value: true,
      issued_at: now,
      not_before: now,
      expires_at: now + 3_600,
      audience: [persona],
      resources: [resource],
      visibility: "repository-private",
      spec_version: "heterodyne/0.6.0",
      profile_revision: 2,
      ...overrides,
    };
    const semantic: ClaimSemanticBody = { claim_id: computeClaimId(body), ...body };
    const event = await signEvent({
      secretKey: issuer.private_key,
      auxRand: AUX_RAND,
      created_at: semantic.issued_at,
      kind: 31013,
      tags: [["d", semantic.claim_id]],
      content: jcsCanonicalize(semantic),
    });
    const envelopeContext = {
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    } as const;
    const verifiedArtifact = verifyClaimEnvelope(event, envelopeContext);
    return {
      artifact: { event, semantic } satisfies ClaimArtifact,
      verified_artifact: verifiedArtifact,
      reader,
    };
  };

  const claimOne = await makeClaim(writerOne);
  const claimTwo = await makeClaim(writerTwo);
  const issuerClaimOne = await makeClaim(writerOne, { name: "oidc-token-issuer", resources: [`${rid}#oidc-issuer`] });
  const issuerClaimTwo = await makeClaim(writerTwo, { name: "oidc-token-issuer", resources: [`${rid}#oidc-issuer`] });
  const alternateClaimOne = await makeClaim(writerOne, { expires_at: now + 1_800 });
  const temporalClaim = await makeClaim(writerOne, { not_before: now + 55, expires_at: now + 65 });
  const allClaims = new Map<string, unknown>([
    [claimOne.artifact.semantic.claim_id, claimOne.verified_artifact],
    [claimTwo.artifact.semantic.claim_id, claimTwo.verified_artifact],
    [alternateClaimOne.artifact.semantic.claim_id, alternateClaimOne.verified_artifact],
  ]);
  const issuerClaimsById = new Map<string, unknown>([
    ...allClaims,
    [issuerClaimOne.artifact.semantic.claim_id, issuerClaimOne.verified_artifact] as const,
    [issuerClaimTwo.artifact.semantic.claim_id, issuerClaimTwo.verified_artifact] as const,
  ]);

  const makeVerification = (
    claim: typeof claimOne,
    confirmed = new Set<string>([claim.artifact.semantic.claim_id]),
  ): ClaimVerificationContext => {
    const semantic = claim.artifact.semantic;
    const claimResource = semantic.resources?.[0] ?? resource;
    const challenge: SubjectProofChallenge = {
      domain: "heterodyne-claim-pop-v1",
      claim_id: semantic.claim_id,
      nonce: bytesToHex(Uint8Array.from({ length: 16 }, (_, index) => (index + (claim.reader === writerOne ? 1 : 33)) & 0xff)),
      audience: persona,
      resource: claimResource,
      operation: "read",
      issued_at: now + 11,
      expires_at: now + 71,
    };
    const signature = bytesToHex(ed25519.sign(
      subjectProofPayload(challenge),
      hexToBytes(claim.reader.private_key),
    ));
    return {
      now: now + 20,
      audience: persona,
      resource: claimResource,
      requested_namespace: semantic.namespace,
      requested_operation: "read",
      expected_nonce: challenge.nonce,
      used_nonces: new Set(),
      trusted_issuers: [semantic.issuer],
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
      repository_confirmed: confirmed,
      repository_conflicted: new Set(),
      revocations: [],
      subject_proof: {
        key: semantic.subject,
        challenge,
        proof: { type: "radicle-ed25519", public_key: claim.reader.public_key, signature },
      },
    };
  };

  const requestFor = (record: LedgerRecord, claim: typeof claimOne): ReaderAccessRequest => ({
    claim_record_id: record.record_id,
    envelope_context: {
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(),
    verification_context: makeVerification(claim),
  });

  const signRecord = (
    record_type: LedgerRecord["record_type"],
    payload: JsonValue,
    writer = writerOne,
    parents: string[] = [],
    created_at = now + 1,
  ) => createSignedLedgerRecord({
    record_type,
    persona,
    credential_ledger_generation: 0,
    writer_nid: writer.did_key,
    created_at,
    parents,
    payload,
  }, writer.private_key);

  const claimRecordOne = signRecord("claim", { claim_artifact: claimOne.artifact });
  const claimRecordTwo = signRecord("claim", { claim_artifact: claimTwo.artifact }, writerTwo);
  const issuerClaimRecordOne = signRecord("claim", { claim_artifact: issuerClaimOne.artifact });
  const issuerClaimRecordTwo = signRecord("claim", { claim_artifact: issuerClaimTwo.artifact }, writerTwo);
  const issuerAuthorityRecordOne = signRecord("issuer-authority", {
    action: "grant", writer_nid: writerOne.did_key, claim_artifact: issuerClaimOne.artifact,
  }, writerOne, [issuerClaimRecordOne.record_id], now + 2);
  const issuerAuthorityRecordTwo = signRecord("issuer-authority", {
    action: "grant", writer_nid: writerTwo.did_key, claim_artifact: issuerClaimTwo.artifact,
  }, writerTwo, [issuerClaimRecordTwo.record_id], now + 2);
  const temporalClaimRecord = signRecord("claim", { claim_artifact: temporalClaim.artifact });
  const grantOne = signRecord("reader-change", {
    action: "grant", reader_nid: writerOne.did_key, claim_artifact: claimOne.artifact,
  }, writerOne, [claimRecordOne.record_id], now + 2);
  const grantDivergent = signRecord("reader-change", {
    action: "grant", reader_nid: writerOne.did_key, claim_artifact: alternateClaimOne.artifact,
  }, writerTwo, [claimRecordOne.record_id], now + 2);
  const grantOnly = signRecord("reader-change", {
    action: "grant", reader_nid: writerOne.did_key, claim_artifact: claimOne.artifact,
  }, writerOne, [], now + 2);

  const revocationSemantic: ClaimRevocation = {
    ...CLAIM_REVOCATION_PROFILE,
    claim_id: claimOne.artifact.semantic.claim_id,
    revoked_at: now + 30,
    reason_code: "claim-revoked",
    revoker: claimOne.artifact.semantic.issuer,
  };
  const revocationEvent = await signEvent({
    secretKey: issuer.private_key,
    auxRand: AUX_RAND,
    created_at: revocationSemantic.revoked_at,
    kind: 31014,
    tags: [["d", revocationSemantic.claim_id]],
    content: jcsCanonicalize(revocationSemantic),
  });
  const revocationArtifact: RevocationArtifact = { event: revocationEvent, semantic: revocationSemantic as unknown as JsonValue };
  const verifiedRevocationArtifact = verifyClaimRevocationEnvelope(revocationEvent);
  const revocationRecord = signRecord("revocation", { revocation_artifact: revocationArtifact }, writerTwo, [claimRecordOne.record_id], now + 31);
  const reductionRecord = signRecord("authority-reduction", {
    role: "claim-ledger-reader", subject_nid: writerOne.did_key, revocation_artifact: revocationArtifact,
  }, writerTwo, [claimRecordOne.record_id], now + 31);
  const removalRecord = signRecord("reader-change", {
    action: "remove", reader_nid: writerOne.did_key, revocation_artifact: revocationArtifact,
  }, writerTwo, [claimRecordOne.record_id], now + 31);
  const issuerRevocationSemantic: ClaimRevocation = {
    ...CLAIM_REVOCATION_PROFILE,
    claim_id: issuerClaimOne.artifact.semantic.claim_id,
    revoked_at: now + 81,
    reason_code: "claim-revoked",
    revoker: issuerClaimOne.artifact.semantic.issuer,
  };
  const issuerRevocationEvent = await signEvent({
    secretKey: issuer.private_key,
    auxRand: AUX_RAND,
    created_at: issuerRevocationSemantic.revoked_at,
    kind: 31014,
    tags: [["d", issuerRevocationSemantic.claim_id]],
    content: jcsCanonicalize(issuerRevocationSemantic),
  });
  const issuerRevocationArtifact: RevocationArtifact = {
    event: issuerRevocationEvent,
    semantic: issuerRevocationSemantic as unknown as JsonValue,
  };
  const issuerRemovalRecord = signRecord("issuer-authority", {
    action: "remove", writer_nid: writerOne.did_key, revocation_artifact: issuerRevocationArtifact,
  }, writerTwo, [issuerAuthorityRecordOne.record_id], now + 82);

  const evidence = new Map<string, LedgerRecordValidationEvidence>();
  const addClaimEvidence = (record: LedgerRecord, claim: typeof claimOne) => evidence.set(record.record_id, {
    record_id: record.record_id,
    payload_digest: record.payload_digest,
    claim_envelope_context: {
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(),
    claim_verification_context: makeVerification(claim),
  });
  addClaimEvidence(claimRecordOne, claimOne);
  addClaimEvidence(claimRecordTwo, claimTwo);
  addClaimEvidence(grantOne, claimOne);
  addClaimEvidence(grantDivergent, alternateClaimOne);
  const temporalVerification = makeVerification(temporalClaim);
  temporalVerification.now = temporalClaim.artifact.semantic.not_before;
  const temporalRecordEvidence: LedgerRecordValidationEvidence = {
    record_id: temporalClaimRecord.record_id,
    payload_digest: temporalClaimRecord.payload_digest,
    claim_envelope_context: {
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(),
    claim_verification_context: temporalVerification,
  };
  const grantOnlyEvidence: LedgerRecordValidationEvidence = {
    record_id: grantOnly.record_id,
    payload_digest: grantOnly.payload_digest,
    claim_envelope_context: {
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(),
    claim_verification_context: makeVerification(claimOne),
  };
  const revocationVerification = makeVerification(claimOne);
  revocationVerification.now = now + 40;
  for (const record of [revocationRecord, reductionRecord, removalRecord]) evidence.set(record.record_id, {
    record_id: record.record_id,
    payload_digest: record.payload_digest,
    claims_by_id: new Map(allClaims),
    claim_verification_context: revocationVerification,
  });

  const baseRepository = buildLedgerRepositoryEvidence({
    repository_rid: rid,
    confirmed_records: [claimRecordOne, claimRecordTwo],
    observed_at: now + 50,
  });
  const epochOnePayload = createAudienceKeyEpochPayload({
    persona, repository_rid: rid, checkpoint_commit_oid: baseRepository.checkpoint.commit_oid,
    epoch: 1, key_id: audienceKeyOneId, audience_key: audienceKeyOne,
    previous_epoch: 0, previous_key_id: "00".repeat(32), reader_nids: [writerOne.did_key, writerTwo.did_key], removed_reader_nids: [],
  });
  const epochOneRecord = signRecord("audience-key-epoch", epochOnePayload as unknown as JsonValue, writerTwo,
    [claimRecordOne.record_id, claimRecordTwo.record_id], now + 51);
  evidence.set(epochOneRecord.record_id, { record_id: epochOneRecord.record_id, payload_digest: epochOneRecord.payload_digest });
  const epochOneRepository = buildLedgerRepositoryEvidence({
    repository_rid: rid,
    confirmed_records: [claimRecordOne, claimRecordTwo, epochOneRecord],
    observed_at: now + 60,
    prior: baseRepository.repository,
  });
  const epochTwoPayload = createAudienceKeyEpochPayload({
    persona, repository_rid: rid, checkpoint_commit_oid: epochOneRepository.checkpoint.commit_oid,
    epoch: 2, key_id: audienceKeyTwoId, audience_key: audienceKeyTwo,
    previous_epoch: 1, previous_key_id: audienceKeyOneId, reader_nids: [writerTwo.did_key], removed_reader_nids: [writerOne.did_key],
  });
  const epochTwoRecord = signRecord("audience-key-epoch", epochTwoPayload as unknown as JsonValue, writerTwo,
    [epochOneRecord.record_id, removalRecord.record_id], now + 61);
  evidence.set(epochTwoRecord.record_id, { record_id: epochTwoRecord.record_id, payload_digest: epochTwoRecord.payload_digest });

  const signingJwk: JsonValue = OIDC_RSA_ONE.private_jwk;
  const rotatedSigningJwk: JsonValue = OIDC_RSA_TWO.private_jwk;
  const issuerEvidence = new Map<string, LedgerRecordValidationEvidence>();
  const addIssuerEvidence = (record: LedgerRecord, claim: typeof issuerClaimOne) => issuerEvidence.set(record.record_id, {
    record_id: record.record_id,
    payload_digest: record.payload_digest,
    claim_envelope_context: {
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(),
    claim_verification_context: makeVerification(claim),
  });
  addIssuerEvidence(issuerClaimRecordOne, issuerClaimOne);
  addIssuerEvidence(issuerClaimRecordTwo, issuerClaimTwo);
  addIssuerEvidence(issuerAuthorityRecordOne, issuerClaimOne);
  addIssuerEvidence(issuerAuthorityRecordTwo, issuerClaimTwo);
  const issuerRevocationVerification = makeVerification(issuerClaimOne);
  issuerRevocationVerification.now = now + 90;
  issuerEvidence.set(issuerRemovalRecord.record_id, {
    record_id: issuerRemovalRecord.record_id,
    payload_digest: issuerRemovalRecord.payload_digest,
    claims_by_id: new Map(issuerClaimsById),
    claim_verification_context: issuerRevocationVerification,
  });
  const authorityRecords = [
    claimRecordOne, claimRecordTwo, issuerClaimRecordOne, issuerClaimRecordTwo,
    issuerAuthorityRecordOne, issuerAuthorityRecordTwo,
  ];
  const authorityRepository = buildLedgerRepositoryEvidence({
    repository_rid: rid, confirmed_records: authorityRecords, observed_at: now + 64,
    prior: baseRepository.repository,
  });
  const contextForAuthority = (repository: LedgerRepositoryEvidence): LedgerValidationContext => {
    const requestOne = requestFor(claimRecordOne, claimOne);
    const requestTwo = requestFor(claimRecordTwo, claimTwo);
    requestOne.verification_context.now = repository.checkpoint.observed_at;
    requestTwo.verification_context.now = repository.checkpoint.observed_at;
    return {
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
      record_evidence: new Map([...evidence, ...issuerEvidence]),
      repository,
      reader_requests: new Map([[claimRecordOne.record_id, requestOne], [claimRecordTwo.record_id, requestTwo]]),
      audience_keys_by_epoch: new Map([[1, audienceKeyOne], [2, audienceKeyTwo]]),
      writer_authority: writerAuthority,
      load_record_location(record) {
        return {
          record_id: record.record_id,
          repository_rid: repository.repository_rid,
          writer_ref: writerRefs.get(record.writer_nid) ?? `${writerRefNamespace}unknown`,
          commit: repository.canonical_head,
          checkpoint: repository.canonical_head,
          revision: repository.commits.length,
          writer_binding: writerBindings.get(record.writer_nid) ?? writerBindings.get(writerOne.did_key)!,
        };
      },
    };
  };
  const authorityState = mergeClaimLedger(
    authorityRecords, [], authorityRepository.checkpoint, contextForAuthority(authorityRepository.repository),
  );
  const issuerKeyEnvelopeOne = createIssuerKeyEnvelope({
    persona, repository_rid: rid, epoch: 1, audience_key: issuerAudienceKeyOne, signing_jwk: signingJwk,
    authority_state: authorityState, recipient_nids: [writerOne.did_key, writerTwo.did_key],
  });
  const issuerKeyEpochPayloadOne = createIssuerKeyEpochPayload({
    authority_state: authorityState, envelope: issuerKeyEnvelopeOne, previous_record: null,
  });
  const issuerKeyEpochRecordOne = signRecord(
    "audience-key-epoch", issuerKeyEpochPayloadOne as unknown as JsonValue, writerTwo,
    [issuerAuthorityRecordOne.record_id, issuerAuthorityRecordTwo.record_id].sort(), now + 65,
  );
  issuerEvidence.set(issuerKeyEpochRecordOne.record_id, {
    record_id: issuerKeyEpochRecordOne.record_id, payload_digest: issuerKeyEpochRecordOne.payload_digest,
  });
  const issuerKeyEpochOneRecords = [...authorityRecords, issuerKeyEpochRecordOne];
  const issuerKeyEpochOneRepository = buildLedgerRepositoryEvidence({
    repository_rid: rid, confirmed_records: issuerKeyEpochOneRecords, observed_at: now + 66,
    prior: authorityRepository.repository,
  });
  const issuerEpochOneContext = contextForAuthority(issuerKeyEpochOneRepository.repository);
  issuerEpochOneContext.issuer_key_material_by_record_id = new Map([[
    issuerKeyEpochRecordOne.record_id, { envelope: issuerKeyEnvelopeOne, audience_key: issuerAudienceKeyOne },
  ]]);
  const issuerKeyEpochOneState = mergeClaimLedger(
    issuerKeyEpochOneRecords, [], issuerKeyEpochOneRepository.checkpoint, issuerEpochOneContext,
  );
  const removedAuthorityRecords = [...issuerKeyEpochOneRecords, issuerRemovalRecord];
  const removedAuthorityRepository = buildLedgerRepositoryEvidence({
    repository_rid: rid, confirmed_records: removedAuthorityRecords, observed_at: now + 100,
    prior: issuerKeyEpochOneRepository.repository,
  });
  const removedAuthorityState = mergeClaimLedger(
    removedAuthorityRecords, [], removedAuthorityRepository.checkpoint,
    (() => {
      const context = contextForAuthority(removedAuthorityRepository.repository);
      context.issuer_key_material_by_record_id = new Map([[
        issuerKeyEpochRecordOne.record_id, { envelope: issuerKeyEnvelopeOne, audience_key: issuerAudienceKeyOne },
      ]]);
      return context;
    })(),
  );
  const issuerKeyEnvelopeTwo = createIssuerKeyEnvelope({
    persona, repository_rid: rid, epoch: 2, audience_key: issuerAudienceKeyTwo, signing_jwk: rotatedSigningJwk,
    authority_state: removedAuthorityState, recipient_nids: [writerTwo.did_key],
    previous: { envelope: issuerKeyEnvelopeOne, audience_key: issuerAudienceKeyOne },
  });
  const issuerKeyEpochPayloadTwo = createIssuerKeyEpochPayload({
    authority_state: removedAuthorityState, envelope: issuerKeyEnvelopeTwo,
    previous_record: issuerKeyEpochRecordOne,
  });
  const issuerKeyEpochRecordTwo = signRecord(
    "audience-key-epoch", issuerKeyEpochPayloadTwo as unknown as JsonValue, writerTwo,
    [issuerKeyEpochRecordOne.record_id, issuerRemovalRecord.record_id].sort(), now + 101,
  );
  issuerEvidence.set(issuerKeyEpochRecordTwo.record_id, {
    record_id: issuerKeyEpochRecordTwo.record_id, payload_digest: issuerKeyEpochRecordTwo.payload_digest,
  });
  const issuerKeyEpochTwoRecords = [...removedAuthorityRecords, issuerKeyEpochRecordTwo];
  const issuerKeyEpochTwoRepository = buildLedgerRepositoryEvidence({
    repository_rid: rid, confirmed_records: issuerKeyEpochTwoRecords, observed_at: now + 102,
    prior: removedAuthorityRepository.repository,
  });
  const issuerEpochTwoContext = contextForAuthority(issuerKeyEpochTwoRepository.repository);
  issuerEpochTwoContext.issuer_key_material_by_record_id = new Map([
    [issuerKeyEpochRecordOne.record_id, { envelope: issuerKeyEnvelopeOne, audience_key: issuerAudienceKeyOne }],
    [issuerKeyEpochRecordTwo.record_id, { envelope: issuerKeyEnvelopeTwo, audience_key: issuerAudienceKeyTwo }],
  ]);
  const issuerKeyEpochTwoState = mergeClaimLedger(
    issuerKeyEpochTwoRecords, [], issuerKeyEpochTwoRepository.checkpoint, issuerEpochTwoContext,
  );

  const issuanceOne: IssuanceRecord = {
    credential_ledger_generation: 0,
    jti: "writer_one_token_0001",
    reservation: reserveStatusIndex(writerOne.did_key, now + 3_600, 0, []),
    checkpoint: issuerKeyEpochOneRepository.checkpoint,
    manifest_max_age_seconds: 300,
    signing_key_id: issuerKeyEnvelopeOne.signing_key_id,
    client_id: "heterodyne-task5-client",
    authorization_request_digest: bytesToHex(sha256(utf8Bytes("task5-request-writer-one"))),
    release_digest: bytesToHex(sha256(utf8Bytes("task5-release-writer-one"))),
    source_claim_ids: [claimOne.artifact.semantic.claim_id],
    issued_at: now + 66,
    expires_at: now + 3_600,
  };
  const issuanceTwo: IssuanceRecord = {
    credential_ledger_generation: 0,
    jti: "writer_two_token_0001",
    reservation: reserveStatusIndex(writerTwo.did_key, now + 3_600, 0, [issuanceOne]),
    checkpoint: issuerKeyEpochOneRepository.checkpoint,
    manifest_max_age_seconds: 300,
    signing_key_id: issuerKeyEnvelopeOne.signing_key_id,
    client_id: "heterodyne-task5-client",
    authorization_request_digest: bytesToHex(sha256(utf8Bytes("task5-request-writer-two"))),
    release_digest: bytesToHex(sha256(utf8Bytes("task5-release-writer-two"))),
    source_claim_ids: [claimOne.artifact.semantic.claim_id],
    issued_at: now + 66,
    expires_at: now + 3_600,
  };
  const reservationOne = signRecord("issuance-reservation", issuanceOne as unknown as JsonValue,
    writerOne, [claimRecordOne.record_id], now + 70);
  const reservationTwo = signRecord("issuance-reservation", issuanceTwo as unknown as JsonValue,
    writerTwo, [claimRecordOne.record_id], now + 70);
  const statusInvalidation = signRecord("status-invalidation", {
    cause: "source-claim-revoked", jti: "writer_one_token_0001", source_claim_id: claimOne.artifact.semantic.claim_id, revocation_artifact: revocationArtifact,
    writer_authority_claim_id: issuerClaimTwo.artifact.semantic.claim_id,
    authority_checkpoint: issuerKeyEpochOneRepository.checkpoint,
    issuer_key_epoch: 1, issuer_key_digest: issuerKeyEnvelopeOne.signing_key_id,
  }, writerTwo, [reservationOne.record_id], now + 71);
  const statusInvalidationTwo = signRecord("status-invalidation", {
    cause: "source-claim-revoked", jti: "writer_two_token_0001", source_claim_id: claimOne.artifact.semantic.claim_id, revocation_artifact: revocationArtifact,
    writer_authority_claim_id: issuerClaimOne.artifact.semantic.claim_id,
    authority_checkpoint: issuerKeyEpochOneRepository.checkpoint,
    issuer_key_epoch: 1, issuer_key_digest: issuerKeyEnvelopeOne.signing_key_id,
  }, writerOne, [reservationTwo.record_id], now + 71);

  // Preserve Task 4's unused replay-evidence map entries byte-for-byte so
  // replacing vectors 011-013 does not rewrite vectors 001-010.
  const legacyReservationOne = signRecord("issuance-reservation", {
    jti: "writer_one_token_0001", writer_nid: writerOne.did_key,
    source_claim_ids: [claimOne.artifact.semantic.claim_id], allocation_ref: "pending:writer-one:sequence-0",
  }, writerOne, [claimRecordOne.record_id], now + 70);
  const legacyReservationTwo = signRecord("issuance-reservation", {
    jti: "writer_two_token_0001", writer_nid: writerTwo.did_key,
    source_claim_ids: [claimOne.artifact.semantic.claim_id], allocation_ref: "pending:writer-two:sequence-0",
  }, writerTwo, [claimRecordOne.record_id], now + 70);
  const legacyStatusInvalidation = signRecord("status-invalidation", {
    jti: "writer_one_token_0001", source_claim_id: claimOne.artifact.semantic.claim_id, revocation_artifact: revocationArtifact,
  }, writerTwo, [legacyReservationOne.record_id], now + 71);
  for (const record of [legacyReservationOne, legacyReservationTwo]) evidence.set(record.record_id, {
    record_id: record.record_id, payload_digest: record.payload_digest,
  });
  evidence.set(legacyStatusInvalidation.record_id, {
    record_id: legacyStatusInvalidation.record_id, payload_digest: legacyStatusInvalidation.payload_digest,
    claims_by_id: new Map(allClaims), claim_verification_context: revocationVerification,
  });

  const task5Evidence = new Map(evidence);
  for (const [recordId, recordEvidence] of issuerEvidence) task5Evidence.set(recordId, recordEvidence);
  for (const record of [reservationOne, reservationTwo]) task5Evidence.set(record.record_id, {
    record_id: record.record_id, payload_digest: record.payload_digest,
  });
  for (const record of [statusInvalidation, statusInvalidationTwo]) task5Evidence.set(record.record_id, {
    record_id: record.record_id, payload_digest: record.payload_digest,
    claims_by_id: new Map(allClaims), claim_verification_context: revocationVerification,
  });

  const makeContext = (repository: LedgerRepositoryEvidence): LedgerValidationContext => {
    const requestOne = requestFor(claimRecordOne, claimOne);
    const requestTwo = requestFor(claimRecordTwo, claimTwo);
    requestOne.verification_context.now = repository.checkpoint.observed_at;
    requestTwo.verification_context.now = repository.checkpoint.observed_at;
    return {
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
      record_evidence: new Map(evidence),
      repository,
      reader_requests: new Map([
        [claimRecordOne.record_id, requestOne],
        [claimRecordTwo.record_id, requestTwo],
      ]),
      audience_keys_by_epoch: new Map([[1, audienceKeyOne], [2, audienceKeyTwo]]),
      writer_authority: writerAuthority,
      load_record_location(record) {
        return {
          record_id: record.record_id,
          repository_rid: repository.repository_rid,
          writer_ref: writerRefs.get(record.writer_nid) ?? `${writerRefNamespace}unknown`,
          commit: repository.canonical_head,
          checkpoint: repository.canonical_head,
          revision: repository.commits.length,
          writer_binding: writerBindings.get(record.writer_nid) ?? writerBindings.get(writerOne.did_key)!,
        };
      },
    };
  };
  const makeTask5Context = (repository: LedgerRepositoryEvidence): LedgerValidationContext => ({
    ...makeContext(repository),
    record_evidence: new Map(task5Evidence),
    issuer_key_material_by_record_id: new Map([
      [issuerKeyEpochRecordOne.record_id, { envelope: issuerKeyEnvelopeOne, audience_key: issuerAudienceKeyOne }],
      [issuerKeyEpochRecordTwo.record_id, { envelope: issuerKeyEnvelopeTwo, audience_key: issuerAudienceKeyTwo }],
    ]),
  });

  return {
    now, persona, issuer, writerOne, writerTwo, rid, resource, audienceKeyOne, audienceKeyTwo, issuerAudienceKeyOne, issuerAudienceKeyTwo,
    writerRefNamespace, writerRefs, writerBindings, writerAuthority, activeWriterPolicy, setCurrentWriterPolicy, resetCurrentWriterPolicy, makeClaimAuthorizationHarness,
    claimOne, claimTwo, issuerClaimOne, issuerClaimTwo, alternateClaimOne, temporalClaim, allClaims, makeClaim, makeVerification, requestFor, signRecord, evidence, temporalRecordEvidence, grantOnlyEvidence, makeContext, makeTask5Context,
    claimRecordOne, claimRecordTwo, temporalClaimRecord, grantOne, grantDivergent, grantOnly, revocationRecord, verifiedRevocationArtifact, reductionRecord, removalRecord,
    issuerClaimRecordOne, issuerClaimRecordTwo, issuerAuthorityRecordOne, issuerAuthorityRecordTwo, issuerRemovalRecord,
    epochOneRecord, epochTwoRecord, signingJwk, issuerKeyEnvelopeOne, issuerKeyEnvelopeTwo,
    issuerKeyEpochRecordOne, issuerKeyEpochRecordTwo, issuerKeyEpochOneState, issuerKeyEpochTwoState,
    issuanceOne, issuanceTwo, reservationOne, reservationTwo, statusInvalidation, statusInvalidationTwo,
    baseRepository, epochOneRepository, authorityState, authorityRepository, removedAuthorityState, removedAuthorityRepository,
    issuerKeyEpochOneRepository, issuerKeyEpochTwoRepository,
  };
}
