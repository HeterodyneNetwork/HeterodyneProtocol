import { beforeAll, describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import { createHmac } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import {
  buildLedgerRepositoryEvidence,
  buildReaderOnboardingBundle,
  createAudienceKeyEpochPayload,
  createSignedLedgerRecord,
  evaluateReaderAccess,
  materializeLedgerLayout,
  mergeClaimLedger,
  resolveAuthoritativeClaimState,
  validateReaderOnboardingBundle,
  type LedgerRecordValidationEvidence,
  type LedgerLayout,
  type ReaderAccessRequest,
} from "./claim-ledger.js";
import * as claimLedgerModule from "./claim-ledger.js";
import { buildFixtures } from "./fixtures.js";
import { bytesToHex, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { buildClaimLedgerScenario, type ClaimLedgerScenario } from "./topics-claim-ledger.js";
import * as claimLedgerTopics from "./topics-claim-ledger.js";

const fixtures = buildFixtures();
let s: ClaimLedgerScenario;

beforeAll(async () => {
  s = await buildClaimLedgerScenario(fixtures);
});

function cloneRequest(request: ReaderAccessRequest): ReaderAccessRequest {
  return structuredClone(request);
}

function boundEvidence(recordId: string, payloadDigest: string, source: LedgerRecordValidationEvidence) {
  return { ...source, record_id: recordId, payload_digest: payloadDigest };
}

function digestJson(value: unknown): string {
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize(value))));
}

describe("canonical evaluation time and confirmation", () => {
  it("rejects reader evaluation before the canonical checkpoint", () => {
    const records = [s.claimRecordOne, s.claimRecordTwo];
    const state = mergeClaimLedger(
      records, [], s.baseRepository.checkpoint, s.makeContext(s.baseRepository.repository),
    );
    const request = cloneRequest(s.requestFor(s.claimRecordOne, s.claimOne));
    request.verification_context.now = s.baseRepository.checkpoint.observed_at - 1;
    expect(evaluateReaderAccess(s.writerOne.did_key, state, request)).toMatchObject({
      allowed: false,
      state: "invalid",
    });
  });

  it("rejects evaluation before an applicable delivered reduction carrier", () => {
    const lateReduction = createSignedLedgerRecord({
      record_type: "authority-reduction",
      persona: s.persona,
      writer_nid: s.writerTwo.did_key,
      created_at: s.baseRepository.checkpoint.observed_at + 10,
      parents: [s.claimRecordOne.record_id],
      payload: s.reductionRecord.payload,
    }, s.writerTwo.private_key);
    const context = s.makeContext(s.baseRepository.repository);
    context.record_evidence.set(lateReduction.record_id, boundEvidence(
      lateReduction.record_id,
      lateReduction.payload_digest,
      s.evidence.get(s.reductionRecord.record_id)!,
    ));
    const state = mergeClaimLedger(
      [s.claimRecordOne, s.claimRecordTwo], [lateReduction], s.baseRepository.checkpoint, context,
    );
    const request = cloneRequest(s.requestFor(s.claimRecordOne, s.claimOne));
    request.verification_context.now = lateReduction.created_at - 1;
    expect(evaluateReaderAccess(s.writerOne.did_key, state, request)).toMatchObject({
      allowed: false,
      state: "invalid",
    });
    expect(resolveAuthoritativeClaimState(
      s.claimOne.artifact.semantic.claim_id,
      state,
      request.verification_context.now,
    )).toBe("invalid");
  });

  it("never confirms or revokes a delivered source claim through status invalidation", () => {
    const independentStatus = createSignedLedgerRecord({
      record_type: "status-invalidation",
      persona: s.persona,
      writer_nid: s.writerTwo.did_key,
      created_at: s.now + 71,
      parents: [],
      payload: s.statusInvalidation.payload,
    }, s.writerTwo.private_key);
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: [independentStatus],
      observed_at: s.now + 80,
    });
    const context = s.makeContext(repository.repository);
    context.record_evidence.set(independentStatus.record_id, boundEvidence(
      independentStatus.record_id,
      independentStatus.payload_digest,
      s.evidence.get(s.statusInvalidation.record_id)!,
    ));
    const state = mergeClaimLedger(
      [independentStatus], [s.claimRecordOne], repository.checkpoint, context,
    );
    const request = cloneRequest(s.requestFor(s.claimRecordOne, s.claimOne));
    request.verification_context.now = repository.checkpoint.observed_at;
    expect(resolveAuthoritativeClaimState(s.claimOne.artifact.semantic.claim_id, state)).toBe("provisional");
    expect(evaluateReaderAccess(s.writerOne.did_key, state, request)).toMatchObject({
      allowed: false,
      state: "provisional",
      reason_code: "claim-repository-unconfirmed",
    });
    expect(state.token_invalidations).toEqual(["writer_one_token_0001"]);
  });

  it("uses evaluation time for checkpoint, not-before, expiry, and immediate reduction boundaries", () => {
    const records = [s.claimRecordOne, s.claimRecordTwo];
    const state = mergeClaimLedger(
      records, [], s.baseRepository.checkpoint, s.makeContext(s.baseRepository.repository),
    );
    const checkpoint = state.checkpoint.observed_at;
    const claimId = s.claimOne.artifact.semantic.claim_id;
    expect(resolveAuthoritativeClaimState(claimId, state, checkpoint - 1)).toBe("invalid");
    expect(resolveAuthoritativeClaimState(claimId, state, checkpoint)).toBe("active");

    const temporalState = structuredClone(state);
    const temporalArtifact = (temporalState.records.find(({ record_id }) => record_id === s.claimRecordOne.record_id)!
      .payload as Record<string, any>).claim_artifact;
    temporalArtifact.semantic.not_before = checkpoint + 10;
    temporalArtifact.semantic.expires_at = checkpoint + 20;
    expect(resolveAuthoritativeClaimState(claimId, temporalState, checkpoint)).toBe("provisional");
    expect(resolveAuthoritativeClaimState(claimId, temporalState, checkpoint + 9)).toBe("provisional");
    expect(resolveAuthoritativeClaimState(claimId, temporalState, checkpoint + 10)).toBe("active");
    expect(resolveAuthoritativeClaimState(claimId, temporalState, checkpoint + 19)).toBe("active");
    expect(resolveAuthoritativeClaimState(claimId, temporalState, checkpoint + 20)).toBe("expired");
    expect(resolveAuthoritativeClaimState(claimId, temporalState, checkpoint + 21)).toBe("expired");

    const lateReduction = createSignedLedgerRecord({
      record_type: "authority-reduction",
      persona: s.persona,
      writer_nid: s.writerTwo.did_key,
      created_at: checkpoint + 10,
      parents: [s.claimRecordOne.record_id],
      payload: s.reductionRecord.payload,
    }, s.writerTwo.private_key);
    const context = s.makeContext(s.baseRepository.repository);
    context.record_evidence.set(lateReduction.record_id, boundEvidence(
      lateReduction.record_id,
      lateReduction.payload_digest,
      s.evidence.get(s.reductionRecord.record_id)!,
    ));
    const reduced = mergeClaimLedger(records, [lateReduction], state.checkpoint, context);
    expect(resolveAuthoritativeClaimState(claimId, reduced, checkpoint + 9)).toBe("invalid");
    expect(resolveAuthoritativeClaimState(claimId, reduced, checkpoint + 10)).toBe("revoked");
  });

  it("requires a canonical claim record rather than a confirmed embedded grant artifact", () => {
    const grantOnly = createSignedLedgerRecord({
      record_type: "reader-change",
      persona: s.persona,
      writer_nid: s.writerOne.did_key,
      created_at: s.grantOne.created_at,
      parents: [],
      payload: s.grantOne.payload,
    }, s.writerOne.private_key);
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: [grantOnly],
      observed_at: s.now + 50,
    });
    const context = s.makeContext(repository.repository);
    context.record_evidence.set(grantOnly.record_id, boundEvidence(
      grantOnly.record_id,
      grantOnly.payload_digest,
      s.evidence.get(s.grantOne.record_id)!,
    ));
    const state = mergeClaimLedger([grantOnly], [], repository.checkpoint, context);
    expect(resolveAuthoritativeClaimState(
      s.claimOne.artifact.semantic.claim_id,
      state,
      repository.checkpoint.observed_at,
    )).toBe("provisional");
  });
});

describe("exhaustive readers and canonical key epochs", () => {
  it("fails closed when a canonical reader claim is omitted from candidate evaluation", () => {
    const oneReaderPayload = createAudienceKeyEpochPayload({
      persona: s.persona,
      repository_rid: s.rid,
      checkpoint_commit_oid: s.baseRepository.checkpoint.commit_oid,
      epoch: 1,
      key_id: String((s.epochOneRecord.payload as Record<string, unknown>).key_id),
      audience_key: s.audienceKeyOne,
      previous_epoch: 0,
      previous_key_id: "00".repeat(32),
      reader_nids: [s.writerOne.did_key],
      removed_reader_nids: [],
    });
    const epoch = createSignedLedgerRecord({
      record_type: "audience-key-epoch",
      persona: s.persona,
      writer_nid: s.writerTwo.did_key,
      created_at: s.now + 51,
      parents: [s.claimRecordOne.record_id, s.claimRecordTwo.record_id],
      payload: oneReaderPayload as never,
    }, s.writerTwo.private_key);
    const records = [s.claimRecordOne, s.claimRecordTwo, epoch];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: records,
      observed_at: s.now + 60,
      prior: s.baseRepository.repository,
    });
    const context = s.makeContext(repository.repository);
    context.reader_requests.delete(s.claimRecordTwo.record_id);
    context.record_evidence.set(epoch.record_id, { record_id: epoch.record_id, payload_digest: epoch.payload_digest });
    expect(() => mergeClaimLedger(records, [], repository.checkpoint, context)).toThrow(/reader|candidate|context/);
  });

  it("requires the key identifier to be derived from supplied audience-key material", () => {
    expect(() => createAudienceKeyEpochPayload({
      persona: s.persona,
      repository_rid: s.rid,
      checkpoint_commit_oid: s.baseRepository.checkpoint.commit_oid,
      epoch: 1,
      key_id: "human-selected-label",
      audience_key: s.audienceKeyOne,
      previous_epoch: 0,
      previous_key_id: "ledger-genesis",
      reader_nids: [s.writerOne.did_key, s.writerTwo.did_key],
      removed_reader_nids: [],
    })).toThrow(/key.*id|digest/i);
  });

  it("rejects changed material that reuses the previous key identifier", () => {
    const previousKeyId = String((s.epochOneRecord.payload as Record<string, unknown>).key_id);
    expect(() => createAudienceKeyEpochPayload({
      persona: s.persona,
      repository_rid: s.rid,
      checkpoint_commit_oid: s.epochOneRepository.checkpoint.commit_oid,
      epoch: 2,
      key_id: previousKeyId,
      audience_key: s.audienceKeyTwo,
      previous_epoch: 1,
      previous_key_id: previousKeyId,
      reader_nids: [s.writerTwo.did_key],
      removed_reader_nids: [s.writerOne.did_key],
    })).toThrow(/key.*id|digest/i);

    const forgedPayload = structuredClone(s.epochTwoRecord.payload) as Record<string, unknown>;
    forgedPayload.key_id = previousKeyId;
    const epoch = createSignedLedgerRecord({
      record_type: "audience-key-epoch",
      persona: s.persona,
      writer_nid: s.writerTwo.did_key,
      created_at: s.now + 61,
      parents: [s.epochOneRecord.record_id, s.removalRecord.record_id],
      payload: forgedPayload as never,
    }, s.writerTwo.private_key);
    const records = [s.claimRecordOne, s.claimRecordTwo, s.epochOneRecord, s.removalRecord, epoch];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: s.rid,
      confirmed_records: records,
      observed_at: s.now + 70,
      prior: s.epochOneRepository.repository,
    });
    const context = s.makeContext(repository.repository);
    context.record_evidence.set(epoch.record_id, { record_id: epoch.record_id, payload_digest: epoch.payload_digest });
    expect(() => mergeClaimLedger(records, [], repository.checkpoint, context)).toThrow(/key|rotation|conflict/);
  });
});

describe("authenticated onboarding and snapshot-wide layout", () => {
  it("rejects forged signed-authorization identifiers even with a recomputed unkeyed digest", () => {
    const records = [s.claimRecordOne, s.claimRecordTwo, s.epochOneRecord];
    const state = mergeClaimLedger(
      records, [], s.epochOneRepository.checkpoint, s.makeContext(s.epochOneRepository.repository),
    );
    const request = cloneRequest(s.requestFor(s.claimRecordOne, s.claimOne));
    request.verification_context.now = s.epochOneRepository.checkpoint.observed_at;
    const bundle = buildReaderOnboardingBundle({
      reader_nid: s.writerOne.did_key,
      request,
      audience_key: s.audienceKeyOne,
      compact_state: { confirmed_claim_ids: [s.claimOne.artifact.semantic.claim_id] },
    }, state);
    const forged = structuredClone(bundle);
    forged.authorization.event_id = "00".repeat(32);
    forged.authorization.claim_id = "11".repeat(32);
    const { bundle_digest: _old, ...withoutDigest } = forged;
    forged.bundle_digest = digestJson(withoutDigest);
    expect(() => validateReaderOnboardingBundle(forged, state, request)).toThrow(/authorization|binding|MAC/i);
    forged.bundle_digest = createHmac("sha256", s.audienceKeyOne)
      .update("heterodyne-claim-ledger-onboarding-mac-v1\0", "utf8")
      .update(utf8Bytes(jcsCanonicalize(withoutDigest)))
      .digest("hex");
    expect(() => validateReaderOnboardingBundle(forged, state, request)).toThrow(/authorization|binding/i);
  });

  it("changes all 256 fixed-size objects when the snapshot changes under the same nonce", () => {
    const nonce = "33".repeat(32);
    const one = materializeLedgerLayout(s.audienceKeyOne, 1, s.baseRepository.checkpoint.commit_oid, nonce, [s.claimRecordOne]);
    const two = materializeLedgerLayout(s.audienceKeyOne, 1, s.baseRepository.checkpoint.commit_oid, nonce, [s.claimRecordOne, s.claimRecordTwo]);
    expect(one.entries).toHaveLength(256);
    expect(two.entries).toHaveLength(256);
    expect(one.entries.filter((entry, index) => entry.ciphertext !== two.entries[index].ciphertext)).toHaveLength(256);
    expect(new Set(two.entries.map(({ size }) => size))).toEqual(new Set([64]));
  });

  it("rejects nonce reuse when prior layout lifecycle context is available", () => {
    const nonce = "44".repeat(32);
    const previous = materializeLedgerLayout(s.audienceKeyOne, 1, s.baseRepository.checkpoint.commit_oid, nonce, [s.claimRecordOne]);
    const next = materializeLedgerLayout(s.audienceKeyOne, 1, s.epochOneRepository.checkpoint.commit_oid, nonce, [s.claimRecordOne, s.claimRecordTwo]);
    const validate = (claimLedgerModule as unknown as {
      validateLedgerLayoutTransition?: (priorLayout: LedgerLayout, nextLayout: LedgerLayout) => void;
    }).validateLedgerLayoutTransition;
    expect(validate).toBeTypeOf("function");
    expect(() => validate!(previous, next)).toThrow(/nonce|epoch|commit/i);
  });
});

describe("self-contained Task 4 vectors", () => {
  it("replays every committed vector input to its committed expected output", () => {
    const directory = new URL("../../claim-ledger/", import.meta.url);
    const files = readdirSync(directory).filter((file) => file.endsWith(".json")).sort();
    expect(files).toHaveLength(13);
    const replay = (claimLedgerTopics as unknown as {
      replayClaimLedgerVector?: (input: unknown) => unknown;
    }).replayClaimLedgerVector;
    expect(replay).toBeTypeOf("function");
    for (const file of files) {
      const vector = JSON.parse(readFileSync(new URL(file, directory), "utf8")) as {
        input: unknown;
        expected_output: unknown;
      };
      expect(replay!(vector.input), file).toEqual(vector.expected_output);
    }
  });

  it("replays authoritative not-before, post-checkpoint expiry, and grant-only confirmation transitions", () => {
    const vector = JSON.parse(readFileSync(
      new URL("../../claim-ledger/003-delivered-grant-provisional.json", import.meta.url),
      "utf8",
    )) as { input: Record<string, unknown>; expected_output: Record<string, any> };
    expect(vector.input.temporal_cases).toBeInstanceOf(Array);
    expect(vector.expected_output.temporal_transitions).toEqual([
      { name: "signed-claim-time-window", states: ["provisional", "active", "expired"] },
      { name: "embedded-grant-not-confirmation", states: ["provisional"] },
    ]);
    expect(claimLedgerTopics.replayClaimLedgerVector(vector.input)).toEqual(vector.expected_output);
  });
});
