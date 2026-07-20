import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import {
  buildLedgerRepositoryEvidence,
  createAudienceKeyEpochPayload,
  createSignedLedgerRecord,
  evaluateLedgerCheckpointEligibility,
  evaluateReaderAccess,
  ledgerErrorReason,
  materializeLedgerLayout,
  mergeClaimLedger,
  resolveAuthoritativeClaimState,
  type ClaimArtifact,
  type LedgerRecord,
  type LedgerRecordValidationEvidence,
  type LedgerRepositoryEvidence,
  type LedgerValidationContext,
  type ReaderAccessRequest,
  type RevocationArtifact,
} from "./claim-ledger.js";
import {
  computeClaimId,
  subjectProofPayload,
  type ClaimAuthorityEvidence,
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
import type { AuthoredVector } from "./types.js";
import { AUX_RAND, consumeVector } from "./vector-helpers.js";

export type ClaimLedgerScenario = Awaited<ReturnType<typeof buildClaimLedgerScenario>>;

const REPLAY_TAG = "$heterodyne_replay_type";

export function encodeClaimLedgerReplayValue(value: unknown): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    return value;
  }
  if (value instanceof Uint8Array) {
    return { [REPLAY_TAG]: "bytes", hex: bytesToHex(value) };
  }
  if (value instanceof Map) {
    return {
      [REPLAY_TAG]: "map",
      entries: [...value.entries()].map(([key, entry]) => [
        encodeClaimLedgerReplayValue(key), encodeClaimLedgerReplayValue(entry),
      ]),
    };
  }
  if (value instanceof Set) {
    return { [REPLAY_TAG]: "set", values: [...value].map(encodeClaimLedgerReplayValue) };
  }
  if (Array.isArray(value)) return value.map(encodeClaimLedgerReplayValue);
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, entry]) => entry !== undefined)
        .map(([key, entry]) => [key, encodeClaimLedgerReplayValue(entry)]),
    );
  }
  throw new Error("claim-schema-invalid: unsupported replay input value");
}

function decodeClaimLedgerReplayValue(value: unknown): any {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(decodeClaimLedgerReplayValue);
  const object = value as Record<string, unknown>;
  if (object[REPLAY_TAG] === "bytes") return hexToBytes(String(object.hex));
  if (object[REPLAY_TAG] === "map") {
    return new Map((object.entries as unknown[][]).map(([key, entry]) => [
      decodeClaimLedgerReplayValue(key), decodeClaimLedgerReplayValue(entry),
    ]));
  }
  if (object[REPLAY_TAG] === "set") {
    return new Set((object.values as unknown[]).map(decodeClaimLedgerReplayValue));
  }
  return Object.fromEntries(Object.entries(object).map(([key, entry]) => [key, decodeClaimLedgerReplayValue(entry)]));
}

function replayMerge(spec: any) {
  return mergeClaimLedger(spec.left, spec.right, spec.checkpoint, spec.context);
}

export function replayClaimLedgerVector(encodedInput: unknown): unknown {
  const input = decodeClaimLedgerReplayValue(encodedInput) as any;
  switch (input.operation) {
    case "reader-authorized": {
      const decision = evaluateReaderAccess(input.reader_nid, replayMerge(input.merge), input.request);
      return { verdict: decision.allowed ? "accept" : "reject", authorization: decision };
    }
    case "reader-denied": {
      const decision = evaluateReaderAccess(input.reader_nid, replayMerge(input.merge), input.request);
      return { verdict: "reject", ...decisionReason(decision) };
    }
    case "authoritative-state": {
      const state = resolveAuthoritativeClaimState(input.claim_id, replayMerge(input.merge), input.evaluation_time);
      return { verdict: "reject", reason_code: input.reason_code, state };
    }
    case "reduction-precedence": {
      const state = replayMerge(input.merge);
      return {
        verdict: "accept",
        normalized: {
          conflicted_claim_ids: state.conflicted_claim_ids,
          target_state: resolveAuthoritativeClaimState(input.claim_id, state, input.evaluation_time),
        },
      };
    }
    case "conflict": {
      const state = replayMerge(input.merge);
      return { verdict: "reject", reason_code: "claim-repository-conflict", conflicted_claim_ids: state.conflicted_claim_ids };
    }
    case "merge-rejection":
      return mergeDecision(() => replayMerge(input.merge));
    case "layout-compare": {
      const first = materializeLedgerLayout(
        input.first.audience_key, input.first.epoch, input.first.commit_oid, input.first.nonce, input.first.records,
      );
      const second = materializeLedgerLayout(
        input.second.audience_key, input.second.epoch, input.second.commit_oid, input.second.nonce, input.second.records,
      );
      return {
        verdict: "accept",
        normalized: {
          first: layoutProjection(first),
          second: layoutProjection(second),
          changed_entries: first.entries.filter((entry, index) => entry.ciphertext !== second.entries[index].ciphertext).length,
        },
      };
    }
    case "reader-removal": {
      const state = replayMerge(input.merge);
      const removedAccess = evaluateReaderAccess(input.reader_nid, state, input.request);
      const nextEpoch = state.records.find(({ record_id }) => record_id === input.next_epoch_record_id);
      return { verdict: "accept", normalized: { removed_access: removedAccess, next_epoch: nextEpoch?.payload } };
    }
    case "reservations": {
      const state = replayMerge(input.merge);
      return {
        verdict: "accept",
        normalized: {
          reservation_record_ids: state.records
            .filter(({ record_type }) => record_type === "issuance-reservation")
            .map(({ record_id }) => record_id),
          allocation_algorithm: "deferred-to-claims-task-5",
        },
      };
    }
    case "checkpoint-eligibility": {
      const decision = evaluateLedgerCheckpointEligibility(input.now, input.checkpoint, input.maximum_age);
      return { verdict: "reject", ...decisionReason(decision) };
    }
    case "token-invalidation": {
      const state = replayMerge(input.merge);
      return {
        verdict: "accept",
        normalized: {
          source_claim_state: resolveAuthoritativeClaimState(input.claim_id, state, input.evaluation_time),
          token_invalidations: state.token_invalidations,
          status_encoding: "deferred-to-claims-task-7",
        },
      };
    }
    default:
      throw new Error("claim-schema-invalid: unknown Task 4 vector replay operation");
  }
}

export async function buildClaimLedgerScenario(fixtures: Fixtures) {
  const now = fixtures.test_epoch + 20_000;
  const persona = fixtures.personas.alice.cold_root.pubkey;
  const issuer = fixtures.personas.alice.epoch_keys.epoch_1;
  const writerOne = fixtures.ed25519_nids.alice_device_1;
  const writerTwo = fixtures.ed25519_nids.alice_device_2;
  const rid = fixtures.radicle_rids.alice;
  const resource = `${rid}#claim-ledger`;
  const audienceKeyOne = Uint8Array.from({ length: 32 }, () => 0x51);
  const audienceKeyTwo = Uint8Array.from({ length: 32 }, () => 0x52);
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
      namespace: "heterodyne.device",
      name: "claim-ledger-reader",
      value: true,
      issued_at: now,
      not_before: now,
      expires_at: now + 3_600,
      audience: [persona],
      resources: [resource],
      visibility: "repository-private",
      comms_version: "comms/0.5.0",
      registry_revision: 2,
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
    return { artifact: { event, semantic } satisfies ClaimArtifact, reader };
  };

  const claimOne = await makeClaim(writerOne);
  const claimTwo = await makeClaim(writerTwo);
  const alternateClaimOne = await makeClaim(writerOne, { expires_at: now + 1_800 });
  const allClaims = new Map([
    [claimOne.artifact.semantic.claim_id, claimOne.artifact.semantic],
    [claimTwo.artifact.semantic.claim_id, claimTwo.artifact.semantic],
    [alternateClaimOne.artifact.semantic.claim_id, alternateClaimOne.artifact.semantic],
  ]);

  const makeVerification = (
    claim: typeof claimOne,
    confirmed = new Set<string>([claim.artifact.semantic.claim_id]),
  ): ClaimVerificationContext => {
    const semantic = claim.artifact.semantic;
    const challenge: SubjectProofChallenge = {
      domain: "heterodyne-claim-pop-v1",
      claim_id: semantic.claim_id,
      nonce: bytesToHex(Uint8Array.from({ length: 16 }, (_, index) => (index + (claim.reader === writerOne ? 1 : 33)) & 0xff)),
      audience: persona,
      resource,
      operation: "read",
      issued_at: now + 11,
      expires_at: now + 71,
    };
    const signature = bytesToHex(ed25519.sign(
      utf8Bytes(subjectProofPayload(challenge)),
      hexToBytes(claim.reader.private_key),
    ));
    const authority: ClaimAuthorityEvidence = {
      claim_id: semantic.claim_id,
      issuer: semantic.issuer,
      event_id: claim.artifact.event.id,
      envelope_valid: true,
      core_kel_authority_valid: true,
      verified_at: now + 5,
      valid_until: now + 300,
    };
    return {
      now: now + 20,
      audience: persona,
      resource,
      requested_namespace: semantic.namespace,
      requested_operation: "read",
      expected_nonce: challenge.nonce,
      used_nonces: new Set(),
      trusted_issuers: [semantic.issuer],
      claim_authority_evidence: new Map([[semantic.claim_id, authority]]),
      revocation_authority_evidence: new Map(),
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
    envelope_context: { issuer_authorized: true, registry_revision: 2 },
    claims_by_id: new Map(allClaims),
    verification_context: makeVerification(claim),
  });

  const signRecord = (
    record_type: LedgerRecord["record_type"],
    payload: JsonValue,
    writer = writerOne,
    parents: string[] = [],
    created_at = now + 1,
  ) => createSignedLedgerRecord({ record_type, persona, writer_nid: writer.did_key, created_at, parents, payload }, writer.private_key);

  const claimRecordOne = signRecord("claim", { claim_artifact: claimOne.artifact });
  const claimRecordTwo = signRecord("claim", { claim_artifact: claimTwo.artifact }, writerTwo);
  const grantOne = signRecord("reader-change", {
    action: "grant", reader_nid: writerOne.did_key, claim_artifact: claimOne.artifact,
  }, writerOne, [claimRecordOne.record_id], now + 2);
  const grantDivergent = signRecord("reader-change", {
    action: "grant", reader_nid: writerOne.did_key, claim_artifact: alternateClaimOne.artifact,
  }, writerTwo, [claimRecordOne.record_id], now + 2);

  const revocationSemantic: ClaimRevocation = {
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
  const revocationRecord = signRecord("revocation", { revocation_artifact: revocationArtifact }, writerTwo, [claimRecordOne.record_id], now + 31);
  const reductionRecord = signRecord("authority-reduction", {
    role: "claim-ledger-reader", subject_nid: writerOne.did_key, revocation_artifact: revocationArtifact,
  }, writerTwo, [claimRecordOne.record_id], now + 31);
  const removalRecord = signRecord("reader-change", {
    action: "remove", reader_nid: writerOne.did_key, revocation_artifact: revocationArtifact,
  }, writerTwo, [claimRecordOne.record_id], now + 31);

  const evidence = new Map<string, LedgerRecordValidationEvidence>();
  const addClaimEvidence = (record: LedgerRecord, claim: typeof claimOne) => evidence.set(record.record_id, {
    record_id: record.record_id,
    payload_digest: record.payload_digest,
    claim_envelope_context: { issuer_authorized: true, registry_revision: 2 },
    claims_by_id: new Map(allClaims),
    claim_verification_context: makeVerification(claim),
  });
  addClaimEvidence(claimRecordOne, claimOne);
  addClaimEvidence(claimRecordTwo, claimTwo);
  addClaimEvidence(grantOne, claimOne);
  addClaimEvidence(grantDivergent, alternateClaimOne);
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

  const reservationOne = signRecord("issuance-reservation", {
    jti: "writer_one_token_0001", writer_nid: writerOne.did_key,
    source_claim_ids: [claimOne.artifact.semantic.claim_id], allocation_ref: "pending:writer-one:sequence-0",
  }, writerOne, [claimRecordOne.record_id], now + 70);
  const reservationTwo = signRecord("issuance-reservation", {
    jti: "writer_two_token_0001", writer_nid: writerTwo.did_key,
    source_claim_ids: [claimOne.artifact.semantic.claim_id], allocation_ref: "pending:writer-two:sequence-0",
  }, writerTwo, [claimRecordOne.record_id], now + 70);
  const statusInvalidation = signRecord("status-invalidation", {
    jti: "writer_one_token_0001", source_claim_id: claimOne.artifact.semantic.claim_id, revocation_artifact: revocationArtifact,
  }, writerTwo, [reservationOne.record_id], now + 71);
  for (const record of [reservationOne, reservationTwo]) evidence.set(record.record_id, {
    record_id: record.record_id, payload_digest: record.payload_digest,
  });
  evidence.set(statusInvalidation.record_id, {
    record_id: statusInvalidation.record_id, payload_digest: statusInvalidation.payload_digest,
    claims_by_id: new Map(allClaims), claim_verification_context: revocationVerification,
  });

  const makeContext = (repository: LedgerRepositoryEvidence): LedgerValidationContext => {
    const requestOne = requestFor(claimRecordOne, claimOne);
    const requestTwo = requestFor(claimRecordTwo, claimTwo);
    requestOne.verification_context.now = repository.checkpoint.observed_at;
    requestTwo.verification_context.now = repository.checkpoint.observed_at;
    return {
      record_evidence: new Map(evidence),
      repository,
      reader_requests: new Map([
        [claimRecordOne.record_id, requestOne],
        [claimRecordTwo.record_id, requestTwo],
      ]),
      audience_keys_by_epoch: new Map([[1, audienceKeyOne], [2, audienceKeyTwo]]),
    };
  };

  return {
    now, persona, issuer, writerOne, writerTwo, rid, resource, audienceKeyOne, audienceKeyTwo,
    claimOne, claimTwo, alternateClaimOne, allClaims, makeVerification, requestFor, evidence, makeContext,
    claimRecordOne, claimRecordTwo, grantOne, grantDivergent, revocationRecord, reductionRecord, removalRecord,
    epochOneRecord, epochTwoRecord, reservationOne, reservationTwo, statusInvalidation,
    baseRepository, epochOneRepository,
  };
}

function mergeDecision(run: () => unknown) {
  try {
    run();
    return { verdict: "accept" as const };
  } catch (error) {
    return { verdict: "reject" as const, reason_code: ledgerErrorReason(error) };
  }
}

export async function buildClaimLedgerVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const s = await buildClaimLedgerScenario(fixtures);
  const baseRecords = [s.claimRecordOne, s.claimRecordTwo];
  const epochOneRecords = [...baseRecords, s.epochOneRecord];
  const conflictRepo = buildLedgerRepositoryEvidence({
    repository_rid: s.rid,
    confirmed_records: [...baseRecords, s.grantOne, s.grantDivergent], observed_at: s.now + 80,
  });
  const conflictRecords = [...baseRecords, s.grantOne, s.grantDivergent];
  const finalRecords = [...epochOneRecords, s.removalRecord, s.epochTwoRecord];
  const finalRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: finalRecords, observed_at: s.now + 65, prior: s.epochOneRepository.repository });
  const reservations = [...baseRecords, s.reservationOne, s.reservationTwo];
  const reservationsRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: reservations, observed_at: s.now + 100 });
  const tokenRecords = [...baseRecords, s.reservationOne, s.revocationRecord, s.statusInvalidation];
  const tokenRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: tokenRecords, observed_at: s.now + 110 });
  const requestOne = s.requestFor(s.claimRecordOne, s.claimOne);
  requestOne.verification_context.now = s.baseRepository.checkpoint.observed_at;
  const finalRequestOne = s.requestFor(s.claimRecordOne, s.claimOne);
  finalRequestOne.verification_context.now = finalRepo.checkpoint.observed_at;
  const emptyRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: [], observed_at: s.now + 50 });
  const rollbackRepository = structuredClone(s.epochOneRepository.repository);
  rollbackRepository.commits[rollbackRepository.commits.length - 1].parents = [];

  const mergeInput = (
    left: LedgerRecord[], right: LedgerRecord[], checkpoint: unknown, context: unknown,
  ) => ({ left, right, checkpoint, context });
  const encoded = (value: unknown) => encodeClaimLedgerReplayValue(value) as Record<string, unknown>;
  const entry = (
    file: string, id: string, description: string, rawInput: unknown,
  ): [string, string, string, Record<string, unknown>, Record<string, unknown>] => {
    const input = encoded(rawInput);
    return [file, id, description, input, replayClaimLedgerVector(input) as Record<string, unknown>];
  };

  const entries: Array<[string, string, string, Record<string, unknown>, Record<string, unknown>]> = [
    entry("001-reader-nid-authorized.json", "reader-nid-authorized", "A signed, repository-final reader claim with fresh NID proof authorizes private-ledger access.", {
      operation: "reader-authorized", merge: mergeInput(baseRecords, [], s.baseRepository.checkpoint, s.makeContext(s.baseRepository.repository)), reader_nid: s.writerOne.did_key, request: requestOne,
    }),
    entry("002-nidless-reader-denied.json", "nidless-reader-denied", "NID-less readers fail before repository replication or decryption.", {
      operation: "reader-denied", merge: mergeInput(baseRecords, [], s.baseRepository.checkpoint, s.makeContext(s.baseRepository.repository)), reader_nid: null, request: requestOne,
    }),
    entry("003-delivered-grant-provisional.json", "delivered-grant-provisional", "A delivered signed claim outside the canonical tree remains provisional.", {
      operation: "authoritative-state", merge: mergeInput([], [s.claimRecordOne], emptyRepo.checkpoint, s.makeContext(emptyRepo.repository)), claim_id: s.claimOne.artifact.semantic.claim_id, evaluation_time: emptyRepo.checkpoint.observed_at, reason_code: "claim-repository-unconfirmed",
    }),
    entry("004-immediate-revocation.json", "immediate-revocation", "A Task-3-authenticated delivered revocation applies before repository finality.", {
      operation: "authoritative-state", merge: mergeInput(baseRecords, [s.revocationRecord], s.baseRepository.checkpoint, s.makeContext(s.baseRepository.repository)), claim_id: s.claimOne.artifact.semantic.claim_id, evaluation_time: s.baseRepository.checkpoint.observed_at, reason_code: "claim-revoked",
    }),
    entry("005-multiwriter-revocation-wins.json", "multiwriter-revocation-wins", "Concurrent divergent grants remain conflicted, but an authenticated revocation is absorbing.", {
      operation: "reduction-precedence", merge: mergeInput(conflictRecords, [s.revocationRecord], conflictRepo.checkpoint, s.makeContext(conflictRepo.repository)), claim_id: s.claimOne.artifact.semantic.claim_id, evaluation_time: conflictRepo.checkpoint.observed_at,
    }),
    entry("006-authority-reduction-wins.json", "authority-reduction-wins", "An authenticated role reduction is absorbing over concurrent divergent grants.", {
      operation: "reduction-precedence", merge: mergeInput(conflictRecords, [s.reductionRecord], conflictRepo.checkpoint, s.makeContext(conflictRepo.repository)), claim_id: s.claimOne.artifact.semantic.claim_id, evaluation_time: conflictRepo.checkpoint.observed_at,
    }),
    entry("007-nonmonotonic-conflict-blocks.json", "nonmonotonic-conflict-blocks", "Divergent widening changes fail closed without last-writer-wins.", {
      operation: "conflict", merge: mergeInput(conflictRecords, [], conflictRepo.checkpoint, s.makeContext(conflictRepo.repository)),
    }),
    entry("008-checkpoint-rollback-rejected.json", "checkpoint-rollback-rejected", "A mutated canonical head lacking the finalized ancestor fails executable commit-DAG validation.", {
      operation: "merge-rejection", merge: mergeInput(epochOneRecords, [], s.epochOneRepository.checkpoint, s.makeContext(rollbackRepository)),
    }),
    entry("009-keyed-path-metadata-private.json", "keyed-path-metadata-private", "Fixed 256-bucket materialization re-encrypts every equal-size opaque object per commit.", {
      operation: "layout-compare",
      first: { audience_key: s.audienceKeyOne, epoch: 1, commit_oid: s.baseRepository.checkpoint.commit_oid, nonce: "11".repeat(32), records: baseRecords },
      second: { audience_key: s.audienceKeyOne, epoch: 1, commit_oid: s.baseRepository.checkpoint.commit_oid, nonce: "11".repeat(32), records: [...baseRecords, s.grantOne] },
    }),
    entry("010-reader-removal-key-rotation.json", "reader-removal-key-rotation", "Authenticated removal precedes a distinct monotonic key epoch wrapped only to active remaining NIDs.", {
      operation: "reader-removal", merge: mergeInput(finalRecords, [], finalRepo.checkpoint, s.makeContext(finalRepo.repository)), reader_nid: s.writerOne.did_key, request: finalRequestOne, next_epoch_record_id: s.epochTwoRecord.record_id,
    }),
    entry("011-multiwriter-status-allocation.json", "multiwriter-status-allocation", "Task 4 merges opaque pending reservations without defining Task 5 allocation semantics.", {
      operation: "reservations", merge: mergeInput(reservations, [], reservationsRepo.checkpoint, s.makeContext(reservationsRepo.repository)),
    }),
    entry("012-stale-minter-denied.json", "stale-minter-denied", "The ledger boundary rejects a checkpoint older than the 300-second maximum.", {
      operation: "checkpoint-eligibility", checkpoint: s.baseRepository.checkpoint, now: s.baseRepository.checkpoint.observed_at + 301, maximum_age: 300,
    }),
    entry("013-source-claim-revokes-token.json", "source-claim-revokes-token", "Source revocation and token invalidation are separate executable effects; status encoding remains Task 7.", {
      operation: "token-invalidation", merge: mergeInput(tokenRecords, [], tokenRepo.checkpoint, s.makeContext(tokenRepo.repository)), claim_id: s.claimOne.artifact.semantic.claim_id, evaluation_time: tokenRepo.checkpoint.observed_at,
    }),
  ];

  return entries.map(([file, id, description, input, expected_output]) => consumeVector(`claim-ledger/${file}`, {
    vector_id: `claim-ledger/${id}`,
    spec_refs: ["temporary:claims-task-4"],
    description,
    input,
    expected_output,
  }));
}

function decisionReason(decision: { reason_code: string | null }) {
  return { reason_code: decision.reason_code ?? "claim-ledger-reader-unauthorized" };
}

function layoutProjection(layout: ReturnType<typeof materializeLedgerLayout>) {
  return {
    commit_metadata: layout.commit_metadata,
    paths: layout.entries.map(({ path }) => path),
    sizes: [...new Set(layout.entries.map(({ size }) => size))],
    ciphertext_digests: layout.entries.map(({ ciphertext }) => bytesToHex(sha256(hexToBytes(ciphertext)))),
  };
}
