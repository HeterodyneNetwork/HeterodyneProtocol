import {
  createReductionEvidence,
  createSignedLedgerRecord,
  deriveLedgerPath,
  evaluateReaderAccess,
  mergeClaimLedger,
  resolveAuthoritativeClaimState,
  type LedgerCheckpoint,
  type LedgerRecord,
} from "./claim-ledger.js";
import { computeClaimId, type ClaimSemanticBody, type JsonValue } from "./claims.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector } from "./types.js";
import { consumeVector } from "./vector-helpers.js";

export async function buildClaimLedgerVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const now = fixtures.test_epoch + 20_000;
  const persona = fixtures.personas.alice.cold_root.pubkey;
  const writerOne = fixtures.ed25519_nids.alice_device_1;
  const writerTwo = fixtures.ed25519_nids.alice_device_2;
  const rid = fixtures.radicle_rids.alice;
  const checkpoint: LedgerCheckpoint = {
    repository_rid: rid,
    branch: "main",
    commit_oid: "ab".repeat(20),
    observed_at: now + 100,
  };
  const claimBody = {
    issuer: { type: "nostr-secp256k1" as const, value: fixtures.personas.alice.epoch_keys.epoch_1.pubkey },
    subject: { type: "radicle-ed25519-nid" as const, value: writerOne.did_key },
    claim_class: "authorization" as const,
    namespace: "heterodyne.device",
    name: "claim-ledger-reader",
    value: true,
    issued_at: now,
    not_before: now,
    expires_at: now + 3_600,
    audience: [persona],
    resources: [`${rid}#claim-ledger`],
    visibility: "repository-private" as const,
    comms_version: "comms/0.5.0" as const,
    registry_revision: 2 as const,
  };
  const claim: ClaimSemanticBody = { claim_id: computeClaimId(claimBody), ...claimBody };
  const sign = (
    record_type: LedgerRecord["record_type"],
    payload: JsonValue,
    options: { writer?: typeof writerOne; parents?: string[]; created_at?: number } = {},
  ): LedgerRecord => {
    const writer = options.writer ?? writerOne;
    return createSignedLedgerRecord({
      record_type,
      persona,
      writer_nid: writer.did_key,
      created_at: options.created_at ?? now + 1,
      parents: options.parents ?? [],
      payload,
    }, writer.private_key);
  };
  const claimRecord = sign("claim", { claim });
  const confirmed = mergeClaimLedger([claimRecord], [], checkpoint);
  const empty = mergeClaimLedger([], [], checkpoint);
  const revocation = sign("revocation", {
    claim_id: claim.claim_id,
    reason_code: "claim-revoked",
    evidence: createReductionEvidence({
      claim_id: claim.claim_id,
      event_id: "31".repeat(32),
      authority: "claim-revocation",
      validated_at: now + 2,
      core_kel_authority_valid: true,
    }),
  }, { writer: writerTwo, parents: [claimRecord.record_id], created_at: now + 2 });
  const reduction = sign("authority-reduction", {
    claim_id: claim.claim_id,
    subject_nid: writerOne.did_key,
    authority: "claim-ledger-reader",
    evidence: createReductionEvidence({
      claim_id: claim.claim_id,
      event_id: "32".repeat(32),
      authority: "claim-ledger-reader",
      validated_at: now + 3,
      core_kel_authority_valid: true,
    }),
  }, { writer: writerTwo, parents: [claimRecord.record_id], created_at: now + 3 });
  const revocationState = mergeClaimLedger([claimRecord], [revocation], checkpoint);
  const reductionState = mergeClaimLedger([claimRecord], [reduction], checkpoint);
  const grantOne = sign("reader-change", {
    claim_id: claim.claim_id,
    reader_nid: writerOne.did_key,
    action: "grant",
  }, { parents: [claimRecord.record_id], created_at: now + 4 });
  const grantTwo = sign("reader-change", {
    claim_id: claim.claim_id,
    reader_nid: writerTwo.did_key,
    action: "grant",
  }, { writer: writerTwo, parents: [claimRecord.record_id], created_at: now + 4 });
  const conflictState = mergeClaimLedger([claimRecord, grantOne], [grantTwo], checkpoint);
  const rotation = sign("audience-key-epoch", {
    key_id: "ledger-epoch-b",
    previous_key_id: "ledger-epoch-a",
    reader_nids: [writerTwo.did_key],
    removed_reader_nids: [writerOne.did_key],
    radicle_access_removed: [writerOne.did_key],
    retire_previous_state: true,
    scrub_profile: "comms-encrypted-branch-cooperative-v1",
  }, { writer: writerTwo, parents: [reduction.record_id], created_at: now + 4 });
  const removalState = mergeClaimLedger([claimRecord], [reduction, rotation], checkpoint);
  const reservationOne = sign("issuance-reservation", {
    jti: "writer_one_token_0001",
    writer_nid: writerOne.did_key,
    source_claim_ids: [claim.claim_id],
    allocation_ref: "pending:writer-one:sequence-0",
  }, { parents: [claimRecord.record_id], created_at: now + 5 });
  const reservationTwo = sign("issuance-reservation", {
    jti: "writer_two_token_0001",
    writer_nid: writerTwo.did_key,
    source_claim_ids: [claim.claim_id],
    allocation_ref: "pending:writer-two:sequence-0",
  }, { writer: writerTwo, parents: [claimRecord.record_id], created_at: now + 5 });
  const allocationState = mergeClaimLedger([claimRecord, reservationOne], [reservationTwo], checkpoint);
  const invalidation = sign("status-invalidation", {
    jti: "writer_one_token_0001",
    source_claim_id: claim.claim_id,
    evidence: createReductionEvidence({
      claim_id: claim.claim_id,
      event_id: "34".repeat(32),
      authority: "source-claim",
      validated_at: now + 6,
      core_kel_authority_valid: true,
    }),
  }, { writer: writerTwo, parents: [reservationOne.record_id], created_at: now + 6 });
  const tokenState = mergeClaimLedger(
    [claimRecord, reservationOne],
    [revocation, invalidation],
    checkpoint,
  );
  const audienceKey = Uint8Array.from({ length: 32 }, () => 0x51);
  const opaquePath = deriveLedgerPath(audienceKey, claimRecord.record_id);

  return [
    consumeVector("claim-ledger/001-reader-nid-authorized.json", {
      vector_id: "claim-ledger/reader-nid-authorized",
      spec_refs: ["temporary:claims-task-4"],
      description: "A durable NID with a repository-final claim-ledger-reader authorization may replicate and decrypt the private ledger.",
      input: { reader_nid: writerOne.did_key, claims: [claim], canonical_records: [claimRecord], checkpoint },
      expected_output: { verdict: "accept", authorization: evaluateReaderAccess(writerOne.did_key, [claim], confirmed) },
    }),
    consumeVector("claim-ledger/002-nidless-reader-denied.json", {
      vector_id: "claim-ledger/nidless-reader-denied",
      spec_refs: ["temporary:claims-task-4"],
      description: "A NID-less session device cannot replicate or decrypt the private claim ledger.",
      input: { reader_nid: null, claims: [claim], checkpoint },
      expected_output: { verdict: "reject", reason_code: "claim-ledger-reader-unauthorized" },
    }),
    consumeVector("claim-ledger/003-delivered-grant-provisional.json", {
      vector_id: "claim-ledger/delivered-grant-provisional",
      spec_refs: ["temporary:claims-task-4"],
      description: "A valid DR-delivered reader grant remains provisional until reachable from canonical repository state.",
      input: { delivered_claim: claim, canonical_records: [], checkpoint },
      expected_output: {
        verdict: "reject",
        reason_code: "claim-repository-unconfirmed",
        state: resolveAuthoritativeClaimState(claim.claim_id, empty),
      },
    }),
    consumeVector("claim-ledger/004-immediate-revocation.json", {
      vector_id: "claim-ledger/immediate-revocation",
      spec_refs: ["temporary:claims-task-4"],
      description: "Authenticated claim-bound revocation evidence stops authorization immediately and remains absorbing when committed.",
      input: { prior_state: [claimRecord], authenticated_reduction: revocation, checkpoint },
      expected_output: { verdict: "reject", reason_code: "claim-revoked", state: resolveAuthoritativeClaimState(claim.claim_id, revocationState) },
    }),
    consumeVector("claim-ledger/005-multiwriter-revocation-wins.json", {
      vector_id: "claim-ledger/multiwriter-revocation-wins",
      spec_refs: ["temporary:claims-task-4"],
      description: "Concurrent writer branches converge by record ID and a valid revocation wins over a grant.",
      input: { writer_one_records: [claimRecord], writer_two_records: [revocation], checkpoint },
      expected_output: {
        verdict: "accept",
        normalized: { record_ids: revocationState.records.map(({ record_id }) => record_id), claim_state: "revoked" },
      },
    }),
    consumeVector("claim-ledger/006-authority-reduction-wins.json", {
      vector_id: "claim-ledger/authority-reduction-wins",
      spec_refs: ["temporary:claims-task-4"],
      description: "An authenticated reader-authority reduction wins over concurrent authorization and denies immediately.",
      input: { prior_state: [claimRecord], authenticated_reduction: reduction, checkpoint },
      expected_output: { verdict: "reject", reason_code: "claim-revoked", state: resolveAuthoritativeClaimState(claim.claim_id, reductionState) },
    }),
    consumeVector("claim-ledger/007-nonmonotonic-conflict-blocks.json", {
      vector_id: "claim-ledger/nonmonotonic-conflict-blocks",
      spec_refs: ["temporary:claims-task-4"],
      description: "Concurrent divergent widening changes are not resolved by last-writer-wins and block authorization and minting.",
      input: { canonical_claim: claimRecord, writer_one_change: grantOne, writer_two_change: grantTwo, checkpoint },
      expected_output: {
        verdict: "reject",
        reason_code: "claim-repository-conflict",
        conflicted_claim_ids: conflictState.conflicted_claim_ids,
        authorization: false,
        minting: false,
      },
    }),
    consumeVector("claim-ledger/008-checkpoint-rollback-rejected.json", {
      vector_id: "claim-ledger/checkpoint-rollback-rejected",
      spec_refs: ["temporary:claims-task-4"],
      description: "A main-branch checkpoint that does not descend from the finalized checkpoint is rejected as rollback.",
      input: {
        previous_checkpoint: { ...checkpoint, commit_oid: "cd".repeat(20), observed_at: now + 50 },
        candidate_checkpoint: checkpoint,
        canonical_ancestors: [],
      },
      expected_output: { verdict: "reject", reason_code: "claim-ledger-rollback" },
    }),
    consumeVector("claim-ledger/009-keyed-path-metadata-private.json", {
      vector_id: "claim-ledger/keyed-path-metadata-private",
      spec_refs: ["temporary:claims-task-4"],
      description: "A dedicated audience key derives an opaque Git path and fixed commit label with no semantic or membership metadata.",
      input: { audience_key: "51".repeat(32), record_id: claimRecord.record_id },
      expected_output: {
        verdict: "accept",
        normalized: {
          path: opaquePath,
          commit_message: "heterodyne private ledger update",
          exposed_semantic_fields: [],
          padding_policy: "fixed-profile-buckets",
        },
      },
    }),
    consumeVector("claim-ledger/010-reader-removal-key-rotation.json", {
      vector_id: "claim-ledger/reader-removal-key-rotation",
      spec_refs: ["temporary:claims-task-4"],
      description: "Reader removal denies immediately, rotates the dedicated audience key to remaining NIDs, removes access, and retires prior ciphertext.",
      input: { prior_records: [claimRecord], reduction, audience_key_epoch: rotation, checkpoint },
      expected_output: {
        verdict: "accept",
        normalized: {
          removed_reader_allowed: evaluateReaderAccess(writerOne.did_key, [claim], removalState).allowed,
          remaining_readers: [writerTwo.did_key],
          radicle_access_removed: [writerOne.did_key],
          retired_state_scrub: "cooperative-no-erasure-claim",
        },
      },
    }),
    consumeVector("claim-ledger/011-multiwriter-status-allocation.json", {
      vector_id: "claim-ledger/multiwriter-status-allocation",
      spec_refs: ["temporary:claims-task-4"],
      description: "Two writers append distinct opaque issuance-reservation records; Task 5 owns final writer namespace and index allocation.",
      input: { writer_one: reservationOne, writer_two: reservationTwo, checkpoint },
      expected_output: {
        verdict: "accept",
        normalized: {
          reservation_record_ids: allocationState.records
            .filter(({ record_type }) => record_type === "issuance-reservation")
            .map(({ record_id }) => record_id),
          allocation_algorithm: "deferred-to-claims-task-5",
        },
      },
    }),
    consumeVector("claim-ledger/012-stale-minter-denied.json", {
      vector_id: "claim-ledger/stale-minter-denied",
      spec_refs: ["temporary:claims-task-4"],
      description: "The ledger state boundary marks a checkpoint 301 seconds old ineligible; Task 5 owns complete mint eligibility.",
      input: { canonical_checkpoint: checkpoint, mint_evaluation_time: checkpoint.observed_at + 301, manifest_max_age_seconds: 300 },
      expected_output: { verdict: "reject", reason_code: "oidc-checkpoint-stale", minting: false, evaluation_owner: "claims-task-5" },
    }),
    consumeVector("claim-ledger/013-source-claim-revokes-token.json", {
      vector_id: "claim-ledger/source-claim-revokes-token",
      spec_refs: ["temporary:claims-task-4"],
      description: "A source-claim revocation makes its issuance mapping invalid in ledger state; Task 7 owns token-status encoding.",
      input: { issuance_reservation: reservationOne, source_revocation: revocation, status_invalidation: invalidation, checkpoint },
      expected_output: {
        verdict: "reject",
        reason_code: "claim-revoked",
        normalized: {
          source_claim_state: resolveAuthoritativeClaimState(claim.claim_id, tokenState),
          token_state: "invalid",
          status_encoding: "deferred-to-claims-task-7",
        },
      },
    }),
  ];
}
