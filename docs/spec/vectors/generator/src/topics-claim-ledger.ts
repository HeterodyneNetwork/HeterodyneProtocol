import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import {
  buildLedgerRepositoryEvidence,
  canReturnToken,
  createAudienceKeyEpochPayload,
  createIssuerKeyEnvelope,
  createIssuerKeyEpochPayload,
  createSignedLedgerRecord,
  createStatusInvalidationRecords,
  evaluateReaderAccess,
  evaluateMintingAttempt,
  ledgerErrorReason,
  materializeLedgerLayout,
  mergeClaimLedger,
  prepareLedgerReplayValidationContext,
  reserveStatusIndex,
  resolveAuthoritativeClaimState,
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
  CLAIM_REVOCATION_PROFILE,
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
import { OIDC_RSA_ONE, OIDC_RSA_TWO } from "./oidc-rsa-fixtures.js";

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

export function decodeClaimLedgerReplayValue(value: unknown): any {
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
  prepareLedgerReplayValidationContext(spec.context);
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
      const output: Record<string, unknown> = { verdict: "reject", reason_code: input.reason_code, state };
      if (Array.isArray(input.temporal_cases)) {
        output.temporal_transitions = input.temporal_cases.map((testCase: any) => {
          const temporalState = replayMerge(testCase.merge);
          return {
            name: testCase.name,
            states: testCase.evaluation_times.map((evaluationTime: number) =>
              resolveAuthoritativeClaimState(testCase.claim_id, temporalState, evaluationTime)
            ),
          };
        });
      }
      return output;
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
    case "multiwriter-mint-and-reserve": {
      const state = replayMerge(input.merge);
      const issuances = state.records
        .filter(({ record_type }) => record_type === "issuance-reservation")
        .map(({ record_id, writer_nid, payload }) => ({ record_id, writer_nid, issuance: payload as IssuanceRecord }));
      const writers = input.writers.map((writer: any) => {
        return {
          writer_nid: writer.writer_nid,
          signing_key_id: writer.envelope.signing_key_id,
          eligibility: evaluateMintingAttempt({
            now: input.now, manifest_max_age_seconds: input.maximum_age,
            writer_nid: writer.writer_nid, state,
            envelope: writer.envelope, audience_key: writer.audience_key,
          }),
        };
      });
      const finalization = issuances.map(({ record_id, writer_nid, issuance }) => {
        const writer = input.writers.find((candidate: any) => candidate.writer_nid === writer_nid);
        return {
          jti: issuance.jti,
          decision: writer === undefined
            ? { allowed: false, state: "invalid", reason_code: "oidc-issuer-authority-invalid" }
            : canReturnToken(record_id, state, writer.envelope, writer.audience_key),
        };
      });
      const allocationKeys = issuances.map(({ issuance }) => `${issuance.reservation.uri}\0${issuance.reservation.idx}`);
      const accepted = writers.every(({ eligibility }: any) => eligibility.allowed) &&
        finalization.every(({ decision }) => decision.allowed) &&
        new Set(allocationKeys).size === issuances.length;
      return {
        verdict: accepted ? "accept" : "reject",
        ...(accepted ? {} : { reason_code: writers.find(({ eligibility }: any) => !eligibility.allowed)?.eligibility.reason_code ??
          finalization.find(({ decision }) => !decision.allowed)?.decision.reason_code ?? "claim-repository-conflict" }),
        normalized: {
          synchronization: { checkpoint: state.checkpoint, canonical_record_ids: state.repository_confirmed_record_ids },
          writers,
          issuances,
          finalization,
          unique_allocation_count: new Set(allocationKeys).size,
          durable_before_return: finalization.every(({ decision }) => decision.allowed),
        },
      };
    }
    case "mint-freshness-and-removal": {
      const active = replayMerge(input.active_merge);
      const activeRecords = [...new Map(
        [...input.active_merge.left, ...input.active_merge.right]
          .map((record: LedgerRecord) => [record.record_id, record]),
      ).values()];
      const removed = mergeClaimLedger(
        activeRecords, [input.issuer_removal_record], input.active_merge.checkpoint, input.active_merge.context,
      );
      const removedRecords = [...activeRecords, input.issuer_removal_record];
      const removedRepository = buildLedgerRepositoryEvidence({
        repository_rid: input.active_merge.context.repository.repository_rid,
        confirmed_records: removedRecords,
        observed_at: input.removal_observed_at,
        prior: input.active_merge.context.repository,
      });
      const removedContext: LedgerValidationContext = {
        ...input.active_merge.context,
        repository: removedRepository.repository,
        record_evidence: new Map(input.active_merge.context.record_evidence),
        issuer_key_material_by_record_id: new Map(input.active_merge.context.issuer_key_material_by_record_id),
      };
      prepareLedgerReplayValidationContext(removedContext, input.active_merge.context);
      const rotatedRecords = [...removedRecords, input.rotated_epoch.record];
      const rotatedRepository = buildLedgerRepositoryEvidence({
        repository_rid: removedRepository.repository.repository_rid,
        confirmed_records: rotatedRecords,
        observed_at: input.rotation_observed_at,
        prior: removedRepository.repository,
      });
      const rotatedContext: LedgerValidationContext = {
        ...removedContext,
        repository: rotatedRepository.repository,
        record_evidence: new Map(removedContext.record_evidence),
        issuer_key_material_by_record_id: new Map(removedContext.issuer_key_material_by_record_id),
      };
      prepareLedgerReplayValidationContext(rotatedContext, removedContext);
      rotatedContext.record_evidence.set(input.rotated_epoch.record.record_id, {
        record_id: input.rotated_epoch.record.record_id,
        payload_digest: input.rotated_epoch.record.payload_digest,
      });
      rotatedContext.issuer_key_material_by_record_id!.set(input.rotated_epoch.record.record_id, {
        envelope: input.rotated_epoch.envelope,
        audience_key: input.rotated_epoch.audience_key,
      });
      const rotated = mergeClaimLedger(rotatedRecords, [], rotatedRepository.checkpoint, rotatedContext);
      const attempt = (state: any, envelope: any, audienceKey: any, writerNid: string, age: number) =>
        evaluateMintingAttempt({
          now: state.checkpoint.observed_at + age,
          manifest_max_age_seconds: input.maximum_age,
          writer_nid: writerNid, state, envelope, audience_key: audienceKey,
        });
      const primary = attempt(active, input.prior_envelope, input.prior_audience_key, input.writer_nid, input.evaluation_age);
      const boundary300 = attempt(active, input.prior_envelope, input.prior_audience_key, input.writer_nid, 300);
      const zeroBoundExact = evaluateMintingAttempt({
        now: active.checkpoint.observed_at,
        manifest_max_age_seconds: 0,
        writer_nid: input.writer_nid,
        state: active,
        envelope: input.prior_envelope,
        audience_key: input.prior_audience_key,
      });
      const zeroBoundAfterOne = evaluateMintingAttempt({
        now: active.checkpoint.observed_at + 1,
        manifest_max_age_seconds: 0,
        writer_nid: input.writer_nid,
        state: active,
        envelope: input.prior_envelope,
        audience_key: input.prior_audience_key,
      });
      const removal = attempt(removed, input.prior_envelope, input.prior_audience_key, input.remaining_writer_nid, 0);
      const postRotation = attempt(
        rotated, input.rotated_epoch.envelope, input.rotated_epoch.audience_key, input.remaining_writer_nid, 0,
      );
      const replayGenesisFork = (base: any, fork: any) => mergeDecision(() => {
        const records = [...new Map(
          [...base.left, ...base.right, fork.record].map((record: LedgerRecord) => [record.record_id, record]),
        ).values()];
        const repository = buildLedgerRepositoryEvidence({
          repository_rid: base.context.repository.repository_rid,
          confirmed_records: records,
          observed_at: base.checkpoint.observed_at + 1,
          prior: base.context.repository,
        });
        const context: LedgerValidationContext = {
          ...base.context,
          repository: repository.repository,
          record_evidence: new Map(base.context.record_evidence),
          issuer_key_material_by_record_id: new Map(base.context.issuer_key_material_by_record_id),
        };
        prepareLedgerReplayValidationContext(context, base.context);
        context.record_evidence.set(fork.record.record_id, {
          record_id: fork.record.record_id,
          payload_digest: fork.record.payload_digest,
        });
        context.issuer_key_material_by_record_id!.set(fork.record.record_id, {
          envelope: fork.envelope,
          audience_key: fork.audience_key,
        });
        mergeClaimLedger(records, [], repository.checkpoint, context);
      });
      const issuerEpochFork = replayGenesisFork(input.active_merge, input.genesis_fork);
      return {
        verdict: primary.allowed ? "accept" : "reject",
        ...(primary.allowed ? {} : { reason_code: primary.reason_code }),
        normalized: {
          immediate_sync_checkpoint: active.checkpoint,
          boundary_300: boundary300,
          boundary_301: primary,
          zero_bound_exact: zeroBoundExact,
          zero_bound_after_one: zeroBoundAfterOne,
          removal,
          post_rotation: postRotation,
          issuer_epoch_fork: issuerEpochFork,
          rotated_key: {
            previous_key_id: input.rotated_epoch.envelope.previous_key_id,
            audience_key_id: input.rotated_epoch.envelope.audience_key_id,
            recipients: input.rotated_epoch.envelope.recipient_wraps.map(({ writer_nid }: any) => writer_nid),
          },
        },
      };
    }
    case "source-and-key-invalidation": {
      const preState = replayMerge(input.generation.pre_merge);
      const generated = createStatusInvalidationRecords({
        state: preState,
        writer_nid: input.generation.writer_nid,
        writer_secret_key: input.generation.writer_secret_key,
        created_at: input.generation.created_at,
        compromised_signing_key_ids: input.generation.compromised_signing_key_ids,
      });
      const left = replayMerge(input.left_merge);
      const right = replayMerge(input.right_merge);
      const generatedMatches = jcsCanonicalize(generated) === jcsCanonicalize(input.committed_invalidations);
      const generatedIds = generated.map(({ record_id }) => record_id).sort();
      const leftDurable = generatedIds.every((recordId) => left.repository_confirmed_record_ids?.includes(recordId));
      const rightDurable = generatedIds.every((recordId) => right.repository_confirmed_record_ids?.includes(recordId));
      const converged = jcsCanonicalize(left.token_invalidations) === jcsCanonicalize(right.token_invalidations) &&
        jcsCanonicalize(left.records.filter(({ record_type }) => record_type === "status-invalidation")) ===
          jcsCanonicalize(right.records.filter(({ record_type }) => record_type === "status-invalidation"));
      const sourceState = resolveAuthoritativeClaimState(input.claim_id, left, input.evaluation_time);
      const expectedJtis = [...new Set(preState.records
        .filter(({ record_type }) => record_type === "issuance-reservation")
        .map(({ payload }) => String((payload as Record<string, unknown>).jti)))].sort();
      const accepted = generatedMatches && leftDurable && rightDurable && converged && sourceState === "revoked" &&
        jcsCanonicalize(left.token_invalidations) === jcsCanonicalize(expectedJtis) && generated.length === expectedJtis.length * 2;
      return {
        verdict: accepted ? "accept" : "reject",
        ...(accepted ? {} : { reason_code: generatedMatches ? "claim-repository-unconfirmed" : "claim-repository-conflict" }),
        normalized: {
          source_claim_state: sourceState,
          generated_record_ids: generatedIds,
          generated_matches_committed: generatedMatches,
          generated_record_count: generated.length,
          left_token_invalidations: left.token_invalidations,
          right_token_invalidations: right.token_invalidations,
          converged,
          canonically_durable: leftDurable && rightDurable,
          invalidation_record_jtis: left.records
            .filter(({ record_type }) => record_type === "status-invalidation")
            .map(({ payload }) => String((payload as Record<string, unknown>).jti)).sort(),
          causes: [...new Set(generated.map(({ payload }) => String((payload as Record<string, unknown>).cause)))].sort(),
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
      spec_version: "heterodyne/0.5.0",
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
    return { artifact: { event, semantic } satisfies ClaimArtifact, reader };
  };

  const claimOne = await makeClaim(writerOne);
  const claimTwo = await makeClaim(writerTwo);
  const issuerClaimOne = await makeClaim(writerOne, { name: "oidc-token-issuer", resources: [`${rid}#oidc-issuer`] });
  const issuerClaimTwo = await makeClaim(writerTwo, { name: "oidc-token-issuer", resources: [`${rid}#oidc-issuer`] });
  const alternateClaimOne = await makeClaim(writerOne, { expires_at: now + 1_800 });
  const temporalClaim = await makeClaim(writerOne, { not_before: now + 55, expires_at: now + 65 });
  const allClaims = new Map([
    [claimOne.artifact.semantic.claim_id, claimOne.artifact.semantic],
    [claimTwo.artifact.semantic.claim_id, claimTwo.artifact.semantic],
    [alternateClaimOne.artifact.semantic.claim_id, alternateClaimOne.artifact.semantic],
  ]);
  const issuerClaimsById = new Map([
    ...allClaims,
    [issuerClaimOne.artifact.semantic.claim_id, issuerClaimOne.artifact.semantic] as const,
    [issuerClaimTwo.artifact.semantic.claim_id, issuerClaimTwo.artifact.semantic] as const,
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
      utf8Bytes(subjectProofPayload(challenge)),
      hexToBytes(claim.reader.private_key),
    ));
    const authority: ClaimAuthorityEvidence = {
      claim_id: semantic.claim_id,
      issuer: semantic.issuer,
      event_id: claim.artifact.event.id,
      envelope_valid: true,
      core_kel_authority_valid: true,
      credential_ledger_persona: semantic.credential_ledger_persona,
      credential_ledger_generation: semantic.credential_ledger_generation,
      verified_at: now + 5,
      valid_until: now + 300,
    };
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
    envelope_context: {
      issuer_authorized: true,
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(allClaims),
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
      issuer_authorized: true,
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(allClaims),
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
      issuer_authorized: true,
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map([[temporalClaim.artifact.semantic.claim_id, temporalClaim.artifact.semantic]]),
    claim_verification_context: temporalVerification,
  };
  const grantOnlyEvidence: LedgerRecordValidationEvidence = {
    record_id: grantOnly.record_id,
    payload_digest: grantOnly.payload_digest,
    claim_envelope_context: {
      issuer_authorized: true,
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(allClaims),
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
      issuer_authorized: true,
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(issuerClaimsById),
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
    claimOne, claimTwo, issuerClaimOne, issuerClaimTwo, alternateClaimOne, temporalClaim, allClaims, makeClaim, makeVerification, requestFor, signRecord, evidence, temporalRecordEvidence, grantOnlyEvidence, makeContext, makeTask5Context,
    claimRecordOne, claimRecordTwo, temporalClaimRecord, grantOne, grantDivergent, grantOnly, revocationRecord, reductionRecord, removalRecord,
    issuerClaimRecordOne, issuerClaimRecordTwo, issuerAuthorityRecordOne, issuerAuthorityRecordTwo, issuerRemovalRecord,
    epochOneRecord, epochTwoRecord, signingJwk, issuerKeyEnvelopeOne, issuerKeyEnvelopeTwo,
    issuerKeyEpochRecordOne, issuerKeyEpochRecordTwo, issuerKeyEpochOneState, issuerKeyEpochTwoState,
    issuanceOne, issuanceTwo, reservationOne, reservationTwo, statusInvalidation, statusInvalidationTwo,
    baseRepository, epochOneRepository, authorityState, authorityRepository, removedAuthorityState, removedAuthorityRepository,
    issuerKeyEpochOneRepository, issuerKeyEpochTwoRepository,
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
  const issuerRecords = [
    s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
    s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
  ];
  const activeIssuerRecords = [...baseRecords, ...issuerRecords];
  const reservations = [...baseRecords, ...issuerRecords, s.reservationOne, s.reservationTwo];
  const reservationsRepo = buildLedgerRepositoryEvidence({
    repository_rid: s.rid, confirmed_records: reservations, observed_at: s.now + 100, prior: s.issuerKeyEpochOneRepository.repository,
  });
  const task5ContextForRecords = (
    repository: LedgerRepositoryEvidence,
    records: LedgerRecord[],
    additionalEvidenceRecords: LedgerRecord[] = [],
  ): LedgerValidationContext => {
    const context = s.makeTask5Context(repository);
    const permitted = new Set([...records, ...additionalEvidenceRecords].map(({ record_id }) => record_id));
    context.record_evidence = new Map(
      [...context.record_evidence].filter(([recordId]) => permitted.has(recordId)),
    );
    context.issuer_key_material_by_record_id = new Map(
      [...(context.issuer_key_material_by_record_id ?? [])]
        .filter(([recordId]) => permitted.has(recordId)),
    );
    return context;
  };
  const preInvalidationRecords = [
    ...baseRecords, ...issuerRecords, s.reservationOne, s.reservationTwo, s.revocationRecord,
  ];
  const preInvalidationRepo = buildLedgerRepositoryEvidence({
    repository_rid: s.rid, confirmed_records: preInvalidationRecords, observed_at: s.now + 110,
    prior: reservationsRepo.repository,
  });
  const preInvalidationState = mergeClaimLedger(
    preInvalidationRecords, [], preInvalidationRepo.checkpoint,
    task5ContextForRecords(preInvalidationRepo.repository, preInvalidationRecords),
  );
  const invalidationCreatedAt = preInvalidationRepo.checkpoint.observed_at + 1;
  const generatedInvalidations = createStatusInvalidationRecords({
    state: preInvalidationState,
    writer_nid: s.writerTwo.did_key,
    writer_secret_key: s.writerTwo.private_key,
    created_at: invalidationCreatedAt,
    compromised_signing_key_ids: [s.issuanceOne.signing_key_id],
  });
  const tokenRecords = [...preInvalidationRecords, ...generatedInvalidations];
  const tokenRepo = buildLedgerRepositoryEvidence({
    repository_rid: s.rid, confirmed_records: tokenRecords, observed_at: invalidationCreatedAt + 1,
    prior: preInvalidationRepo.repository,
  });
  const tokenContext = () => {
    const sourceEvidence = s.makeTask5Context(tokenRepo.repository)
      .record_evidence.get(s.statusInvalidation.record_id)!;
    const context = task5ContextForRecords(tokenRepo.repository, tokenRecords);
    for (const record of generatedInvalidations) {
      const payload = record.payload as Record<string, unknown>;
      context.record_evidence.set(record.record_id, {
        ...(payload.cause === "source-claim-revoked" ? sourceEvidence : {}),
        record_id: record.record_id,
        payload_digest: record.payload_digest,
      });
    }
    return context;
  };
  const alternateGenesisAudienceKey = Uint8Array.from({ length: 32 }, () => 0x76);
  const alternateGenesisEnvelope = createIssuerKeyEnvelope({
    persona: s.persona,
    repository_rid: s.rid,
    epoch: 1,
    audience_key: alternateGenesisAudienceKey,
    signing_jwk: OIDC_RSA_TWO.private_jwk,
    authority_state: s.authorityState,
    recipient_nids: [s.writerOne.did_key, s.writerTwo.did_key],
  });
  const alternateGenesisRecord = createSignedLedgerRecord({
    record_type: "audience-key-epoch",
    persona: s.persona,
    credential_ledger_generation: 0,
    writer_nid: s.writerOne.did_key,
    created_at: s.now + 65,
    parents: [s.issuerAuthorityRecordOne.record_id, s.issuerAuthorityRecordTwo.record_id].sort(),
    payload: createIssuerKeyEpochPayload({
      authority_state: s.authorityState,
      envelope: alternateGenesisEnvelope,
      previous_record: null,
    }) as unknown as JsonValue,
  }, s.writerOne.private_key);
  const requestOne = s.requestFor(s.claimRecordOne, s.claimOne);
  requestOne.verification_context.now = s.baseRepository.checkpoint.observed_at;
  const finalRequestOne = s.requestFor(s.claimRecordOne, s.claimOne);
  finalRequestOne.verification_context.now = finalRepo.checkpoint.observed_at;
  const emptyRepo = buildLedgerRepositoryEvidence({ repository_rid: s.rid, confirmed_records: [], observed_at: s.now + 50 });
  const temporalRepo = buildLedgerRepositoryEvidence({
    repository_rid: s.rid, confirmed_records: [s.temporalClaimRecord], observed_at: s.now + 50,
  });
  const grantOnlyRepo = buildLedgerRepositoryEvidence({
    repository_rid: s.rid, confirmed_records: [s.grantOnly], observed_at: s.now + 50,
  });
  const temporalContext = s.makeContext(temporalRepo.repository);
  temporalContext.record_evidence.set(s.temporalClaimRecord.record_id, s.temporalRecordEvidence);
  const temporalRequest = s.requestFor(s.temporalClaimRecord, s.temporalClaim);
  temporalRequest.verification_context.now = temporalRepo.checkpoint.observed_at;
  temporalContext.reader_requests.set(s.temporalClaimRecord.record_id, temporalRequest);
  const grantOnlyContext = s.makeContext(grantOnlyRepo.repository);
  grantOnlyContext.record_evidence.set(s.grantOnly.record_id, s.grantOnlyEvidence);
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
      temporal_cases: [
        {
          name: "signed-claim-time-window",
          merge: mergeInput([s.temporalClaimRecord], [], temporalRepo.checkpoint, temporalContext),
          claim_id: s.temporalClaim.artifact.semantic.claim_id,
          evaluation_times: [s.now + 50, s.now + 55, s.now + 65],
        },
        {
          name: "embedded-grant-not-confirmation",
          merge: mergeInput([s.grantOnly], [], grantOnlyRepo.checkpoint, grantOnlyContext),
          claim_id: s.claimOne.artifact.semantic.claim_id,
          evaluation_times: [s.now + 50],
        },
      ],
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
    entry("011-multiwriter-status-allocation.json", "multiwriter-status-allocation", "Two synchronized authorized writers sharing one signing key mint from executable authority/key evidence and durably reserve collision-free NID-derived status indexes.", {
      operation: "multiwriter-mint-and-reserve",
      merge: mergeInput(
        reservations, [], reservationsRepo.checkpoint,
        task5ContextForRecords(reservationsRepo.repository, reservations),
      ),
      now: reservationsRepo.checkpoint.observed_at,
      maximum_age: 300,
      writers: [
        { writer_nid: s.writerOne.did_key, envelope: s.issuerKeyEnvelopeOne, audience_key: s.issuerAudienceKeyOne },
        { writer_nid: s.writerTwo.did_key, envelope: s.issuerKeyEnvelopeOne, audience_key: s.issuerAudienceKeyOne },
      ],
    }),
    entry("012-stale-minter-denied.json", "stale-minter-denied", "A 301-second checkpoint age fails the exact at-most-300-second manifest bound; any later issuer removal blocks every remaining writer until a canonical exact-recipient key rotation.", {
      operation: "mint-freshness-and-removal",
      active_merge: mergeInput(
        activeIssuerRecords, [], s.issuerKeyEpochOneRepository.checkpoint,
        task5ContextForRecords(
          s.issuerKeyEpochOneRepository.repository,
          activeIssuerRecords,
          [s.issuerRemovalRecord, s.issuerKeyEpochRecordTwo],
        ),
      ),
      issuer_removal_record: s.issuerRemovalRecord,
      removal_observed_at: s.removedAuthorityRepository.checkpoint.observed_at,
      rotation_observed_at: s.issuerKeyEpochTwoRepository.checkpoint.observed_at,
      writer_nid: s.writerOne.did_key,
      remaining_writer_nid: s.writerTwo.did_key,
      maximum_age: 300,
      evaluation_age: 301,
      prior_envelope: s.issuerKeyEnvelopeOne,
      prior_audience_key: s.issuerAudienceKeyOne,
      rotated_epoch: {
        record: s.issuerKeyEpochRecordTwo,
        envelope: s.issuerKeyEnvelopeTwo,
        audience_key: s.issuerAudienceKeyTwo,
      },
      genesis_fork: {
        record: alternateGenesisRecord,
        envelope: alternateGenesisEnvelope,
        audience_key: alternateGenesisAudienceKey,
      },
    }),
    entry("013-source-claim-revokes-token.json", "source-claim-revokes-token", "An authorized writer deterministically creates signed source-revocation and signing-key-compromise invalidation records; both merge orders converge only after the exact records become canonical.", {
      operation: "source-and-key-invalidation",
      generation: {
        pre_merge: mergeInput(
          preInvalidationRecords, [], preInvalidationRepo.checkpoint,
          task5ContextForRecords(preInvalidationRepo.repository, preInvalidationRecords),
        ),
        writer_nid: s.writerTwo.did_key,
        writer_secret_key: s.writerTwo.private_key,
        created_at: invalidationCreatedAt,
        compromised_signing_key_ids: [s.issuanceOne.signing_key_id],
      },
      committed_invalidations: generatedInvalidations,
      left_merge: mergeInput(tokenRecords.slice(0, 5), tokenRecords.slice(5), tokenRepo.checkpoint, tokenContext()),
      right_merge: mergeInput([...tokenRecords].reverse().slice(0, 5), [...tokenRecords].reverse().slice(5), tokenRepo.checkpoint, tokenContext()),
      claim_id: s.claimOne.artifact.semantic.claim_id,
      evaluation_time: tokenRepo.checkpoint.observed_at,
    }),
  ];

  return entries.map(([file, id, description, input, expected_output]) => consumeVector(`claim-ledger/${file}`, {
    vector_id: `claim-ledger/${id}`,
    spec_refs: [id === "source-claim-revokes-token"
      ? "heterodyne:0.5.0#comms-claim-revocation"
      : /multiwriter-status-allocation|stale-minter-denied/.test(id)
        ? "heterodyne:0.5.0#comms-multiwriter-minting"
        : "heterodyne:0.5.0#comms-claim-ledger"],
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
