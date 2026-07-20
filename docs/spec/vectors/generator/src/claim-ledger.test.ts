import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  buildReaderOnboardingBundle,
  createReductionEvidence,
  createSignedLedgerRecord,
  deriveLedgerPath,
  evaluateReaderAccess,
  mergeClaimLedger,
  resolveAuthoritativeClaimState,
  validateLedgerRecordOrThrow,
  type LedgerCheckpoint,
  type LedgerRecord,
} from "./claim-ledger.js";
import { computeClaimId, type ClaimSemanticBody } from "./claims.js";
import { buildFixtures } from "./fixtures.js";
import { buildClaimLedgerVectors } from "./topics-claim-ledger.js";

const fixtures = buildFixtures();
const persona = fixtures.personas.alice.cold_root.pubkey;
const writerOne = fixtures.ed25519_nids.alice_device_1;
const writerTwo = fixtures.ed25519_nids.alice_device_2;
const rid = fixtures.radicle_rids.alice;
const now = fixtures.test_epoch + 20_000;

const checkpoint = (overrides: Partial<LedgerCheckpoint> = {}): LedgerCheckpoint => ({
  repository_rid: rid,
  branch: "main",
  commit_oid: "ab".repeat(20),
  observed_at: now + 100,
  ...overrides,
});

const readerClaim = (readerNid = writerOne.did_key): ClaimSemanticBody => {
  const body = {
    issuer: { type: "nostr-secp256k1" as const, value: fixtures.personas.alice.epoch_keys.epoch_1.pubkey },
    subject: { type: "radicle-ed25519-nid" as const, value: readerNid },
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
  return { claim_id: computeClaimId(body), ...body };
};

function signedRecord(
  record_type: LedgerRecord["record_type"],
  payload: LedgerRecord["payload"],
  options: { writer?: typeof writerOne; parents?: string[]; created_at?: number; persona?: string } = {},
): LedgerRecord {
  const writer = options.writer ?? writerOne;
  return createSignedLedgerRecord({
    record_type,
    persona: options.persona ?? persona,
    writer_nid: writer.did_key,
    created_at: options.created_at ?? now + 1,
    parents: options.parents ?? [],
    payload,
  }, writer.private_key);
}

describe("claim-ledger record validation and convergence", () => {
  it("validates the closed record schema, digests, IDs, NID signatures, and parents", () => {
    const claim = readerClaim();
    const root = signedRecord("claim", { claim });
    const child = signedRecord("reader-change", {
      claim_id: claim.claim_id,
      reader_nid: writerOne.did_key,
      action: "grant",
    }, { parents: [root.record_id], created_at: now + 2 });

    expect(() => validateLedgerRecordOrThrow(root, new Map([[root.record_id, root]]))).not.toThrow();
    expect(() => validateLedgerRecordOrThrow(child, new Map([
      [root.record_id, root],
      [child.record_id, child],
    ]))).not.toThrow();

    for (const invalid of [
      { ...root, record_id: "00".repeat(32) },
      { ...root, payload_digest: "00".repeat(32) },
      { ...root, signature: "00".repeat(64) },
      { ...root, persona: "A".repeat(64) },
      { ...root, writer_nid: "did:key:znot-an-ed25519-nid" },
      { ...child, parents: ["11".repeat(32)] },
      { ...root, unexpected: true },
    ]) {
      expect(() => validateLedgerRecordOrThrow(invalid as LedgerRecord, new Map([
        [root.record_id, root],
        [child.record_id, child],
      ]))).toThrow();
    }

    const mismatchedEvidence = signedRecord("revocation", {
      claim_id: claim.claim_id,
      reason_code: "claim-revoked",
      evidence: createReductionEvidence({
        claim_id: "44".repeat(32),
        event_id: "45".repeat(32),
        authority: "claim-revocation",
        validated_at: now + 2,
        core_kel_authority_valid: true,
      }),
    });
    expect(() => validateLedgerRecordOrThrow(
      mismatchedEvidence,
      new Map([[mismatchedEvidence.record_id, mismatchedEvidence]]),
    )).toThrow(/target claim|authority/);
  });

  it("rejects each independently mutated integrity field and writer substitution", () => {
    const root = signedRecord("claim", { claim: readerClaim() });
    const records = new Map([[root.record_id, root]]);
    const mutations: LedgerRecord[] = [
      { ...root, record_id: `${root.record_id.slice(0, -1)}0` },
      { ...root, payload_digest: `${root.payload_digest.slice(0, -1)}0` },
      { ...root, signature: `${root.signature.slice(0, -1)}0` },
      { ...root, writer_nid: writerTwo.did_key },
      { ...root, payload: { claim: { ...readerClaim(), name: "oidc-token-issuer" } } },
    ];
    for (const mutation of mutations) {
      expect(() => validateLedgerRecordOrThrow(mutation, records)).toThrow();
    }
  });

  it("rejects unknown, future, cross-persona, and cyclic parent shapes", () => {
    const root = signedRecord("claim", { claim: readerClaim() });
    const unknownParent = signedRecord("reader-change", {
      claim_id: readerClaim().claim_id,
      reader_nid: writerOne.did_key,
      action: "grant",
    }, { parents: ["99".repeat(32)], created_at: now + 2 });
    expect(() => mergeClaimLedger([root], [unknownParent], checkpoint())).toThrow(/missing parent/);

    const futureParent = signedRecord("reader-change", {
      claim_id: readerClaim().claim_id,
      reader_nid: writerOne.did_key,
      action: "grant",
    }, { parents: [root.record_id], created_at: now });
    expect(() => mergeClaimLedger([root], [futureParent], checkpoint())).toThrow(/newer than child/);

    const cycleMutation = { ...root, parents: [root.record_id] };
    expect(() => validateLedgerRecordOrThrow(cycleMutation, new Map([[root.record_id, cycleMutation]])))
      .toThrow(/parent|record_id/);
  });

  it("rejects duplicate record IDs that name different bytes", () => {
    const root = signedRecord("claim", { claim: readerClaim() });
    const colliding = { ...root, signature: `${root.signature.slice(0, -2)}00` };
    expect(() => mergeClaimLedger([root], [colliding], checkpoint())).toThrow(/ID collision/);
  });

  it("merges append-only by deterministic record ID and rejects persona/checkpoint rollback", () => {
    const claim = readerClaim();
    const first = signedRecord("claim", { claim });
    const second = signedRecord("reader-change", {
      claim_id: claim.claim_id,
      reader_nid: writerOne.did_key,
      action: "grant",
    }, { writer: writerTwo, parents: [first.record_id], created_at: now + 2 });
    const merged = mergeClaimLedger([second], [first, second], checkpoint());
    expect(merged.records.map(({ record_id }) => record_id)).toEqual(
      [first.record_id, second.record_id].sort(),
    );

    const otherPersona = signedRecord("claim", { claim }, {
      writer: writerTwo,
      persona: fixtures.personas.bob.cold_root.pubkey,
    });
    expect(() => mergeClaimLedger([first], [otherPersona], checkpoint())).toThrow(/one persona|persona/i);
    expect(() => mergeClaimLedger([first], [], checkpoint({ branch: "dev" as "main" }))).toThrow(/main/);
    expect(() => mergeClaimLedger([first], [], checkpoint({ observed_at: now - 1 }))).toThrow(/stale|rollback/);
    expect(() => mergeClaimLedger([first], [], checkpoint(), {
      previous_checkpoint: checkpoint({ commit_oid: "cd".repeat(20), observed_at: now + 50 }),
      canonical_ancestors: [],
    })).toThrow(/rollback/);
  });

  it("keeps the exact three-argument merge pure and requires explicit evidence for ancestry checks", () => {
    const root = signedRecord("claim", { claim: readerClaim() });
    expect(mergeClaimLedger([root], [], checkpoint()).checkpoint).toEqual(checkpoint());
    expect(() => mergeClaimLedger([root], [], checkpoint(), {
      previous_checkpoint: checkpoint({ commit_oid: "cd".repeat(20), observed_at: now + 50 }),
      canonical_ancestors: ["cd".repeat(20)],
    })).not.toThrow();
  });

  it("makes authenticated reductions absorbing and fails closed on widening conflicts", () => {
    const claim = readerClaim();
    const claimRecord = signedRecord("claim", { claim });
    const revocation = signedRecord("revocation", {
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
    const revoked = mergeClaimLedger([claimRecord], [revocation], checkpoint());
    expect(resolveAuthoritativeClaimState(claim.claim_id, revoked)).toBe("revoked");

    const reduction = signedRecord("authority-reduction", {
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
    expect(resolveAuthoritativeClaimState(
      claim.claim_id,
      mergeClaimLedger([claimRecord], [reduction], checkpoint()),
    )).toBe("revoked");

    const grantOne = signedRecord("reader-change", {
      claim_id: claim.claim_id,
      reader_nid: writerOne.did_key,
      action: "grant",
    }, { writer: writerOne, parents: [claimRecord.record_id], created_at: now + 4 });
    const grantTwo = signedRecord("reader-change", {
      claim_id: claim.claim_id,
      reader_nid: writerTwo.did_key,
      action: "grant",
    }, { writer: writerTwo, parents: [claimRecord.record_id], created_at: now + 4 });
    const conflicted = mergeClaimLedger([claimRecord, grantOne], [grantTwo], checkpoint());
    expect(conflicted.conflicted_claim_ids).toEqual([claim.claim_id]);
    expect(resolveAuthoritativeClaimState(claim.claim_id, conflicted)).toBe("conflicted");
    expect(evaluateReaderAccess(writerOne.did_key, [claim], conflicted)).toEqual({
      allowed: false,
      state: "conflicted",
      reason_code: "claim-repository-conflict",
    });
  });

  it("deduplicates concurrent equivalent widening semantics without a false conflict", () => {
    const claim = readerClaim();
    const claimRecord = signedRecord("claim", { claim });
    const payload = { claim_id: claim.claim_id, reader_nid: writerOne.did_key, action: "grant" } as const;
    const writerOneGrant = signedRecord("reader-change", payload, {
      parents: [claimRecord.record_id],
      created_at: now + 4,
    });
    const writerTwoGrant = signedRecord("reader-change", payload, {
      writer: writerTwo,
      parents: [claimRecord.record_id],
      created_at: now + 4,
    });
    const state = mergeClaimLedger([claimRecord, writerOneGrant], [writerTwoGrant], checkpoint());
    expect(state.conflicted_claim_ids).toEqual([]);
    expect(resolveAuthoritativeClaimState(claim.claim_id, state)).toBe("active");
  });

  it("rejects reduction evidence with false Core authority or a target mismatch", () => {
    const claim = readerClaim();
    const falseAuthority = createReductionEvidence({
      claim_id: claim.claim_id,
      event_id: "51".repeat(32),
      authority: "claim-revocation",
      validated_at: now + 2,
      core_kel_authority_valid: true,
    });
    const forged = signedRecord("revocation", {
      claim_id: claim.claim_id,
      reason_code: "claim-revoked",
      evidence: { ...falseAuthority, core_kel_authority_valid: false },
    });
    expect(() => validateLedgerRecordOrThrow(forged, new Map([[forged.record_id, forged]])))
      .toThrow(/authority|schema/);

    const unregistered = signedRecord("revocation", {
      claim_id: claim.claim_id,
      reason_code: "invented-revocation-reason",
      evidence: createReductionEvidence({
        claim_id: claim.claim_id,
        event_id: "52".repeat(32),
        authority: "claim-revocation",
        validated_at: now + 2,
        core_kel_authority_valid: true,
      }),
    });
    expect(() => validateLedgerRecordOrThrow(unregistered, new Map([[unregistered.record_id, unregistered]])))
      .toThrow(/reason|registered/);
  });
});

describe("claim-ledger reader lifecycle and metadata privacy", () => {
  it("requires a repository-final, unexpired reader claim bound to a durable NID", () => {
    const claim = readerClaim();
    const empty = mergeClaimLedger([], [], checkpoint());
    expect(evaluateReaderAccess(null, [claim], empty)).toEqual({
      allowed: false,
      state: "invalid",
      reason_code: "claim-ledger-reader-unauthorized",
    });
    expect(evaluateReaderAccess(writerOne.did_key, [claim], empty)).toEqual({
      allowed: false,
      state: "provisional",
      reason_code: "claim-repository-unconfirmed",
    });

    const claimRecord = signedRecord("claim", { claim });
    const confirmed = mergeClaimLedger([claimRecord], [], checkpoint());
    expect(evaluateReaderAccess(writerOne.did_key, [claim], confirmed)).toEqual({
      allowed: true,
      state: "active",
      reason_code: null,
    });
  });

  it("denies a valid reader claim when the subject NID does not match the requester", () => {
    const claim = readerClaim(writerTwo.did_key);
    const claimRecord = signedRecord("claim", { claim });
    const state = mergeClaimLedger([claimRecord], [], checkpoint());
    expect(evaluateReaderAccess(writerOne.did_key, [claim], state)).toEqual({
      allowed: false,
      state: "invalid",
      reason_code: "claim-ledger-reader-unauthorized",
    });
  });

  it("binds reader authorization to the exact canonical claim, ledger RID, persona audience, and private visibility", () => {
    const claim = readerClaim();
    const claimRecord = signedRecord("claim", { claim });
    const state = mergeClaimLedger([claimRecord], [], checkpoint());
    const forged = { ...claim, name: "claim-ledger-reader", resources: ["rad:zWrong#claim-ledger"] };
    const { claim_id: _claimId, ...claimWithoutId } = claim;
    const wrongAudienceBody = {
      ...claimWithoutId,
      audience: [fixtures.personas.bob.cold_root.pubkey],
      visibility: "public" as const,
    };
    const wrongAudience = { claim_id: computeClaimId(wrongAudienceBody), ...wrongAudienceBody };
    const wrongAudienceRecord = signedRecord("claim", { claim: wrongAudience });
    const wrongAudienceState = mergeClaimLedger([wrongAudienceRecord], [], checkpoint());

    expect(evaluateReaderAccess(writerOne.did_key, [forged], state).allowed).toBe(false);
    expect(evaluateReaderAccess(writerOne.did_key, [wrongAudience], wrongAudienceState).allowed).toBe(false);
  });

  it("denies an otherwise repository-final reader claim at its expiry boundary", () => {
    const claim = readerClaim();
    const claimRecord = signedRecord("claim", { claim });
    const expiredCheckpoint = checkpoint({ observed_at: claim.expires_at! });
    const state = mergeClaimLedger([claimRecord], [], expiredCheckpoint);
    expect(evaluateReaderAccess(writerOne.did_key, [claim], state)).toEqual({
      allowed: false,
      state: "expired",
      reason_code: "claim-expired",
    });
  });

  it("models the DR self-DM onboarding bundle and reader-removal key rotation", () => {
    const claim = readerClaim();
    const claimRecord = signedRecord("claim", { claim });
    const confirmed = mergeClaimLedger([claimRecord], [], checkpoint());
    const bundle = buildReaderOnboardingBundle({
      reader_nid: writerOne.did_key,
      authorization: claim,
      repository_rid: rid,
      checkpoint: confirmed.checkpoint,
      audience_key: Uint8Array.from({ length: 32 }, () => 0x51),
      compact_state: { confirmed_claim_ids: [claim.claim_id] },
      radicle_access: { nid: writerOne.did_key, role: "fetch-and-seed" },
    }, confirmed);
    expect(bundle.transport).toBe("dr-self-dm");
    expect(bundle.audience_key).toBe("51".repeat(32));
    expect(bundle.radicle_access.nid).toBe(writerOne.did_key);

    const removal = signedRecord("authority-reduction", {
      claim_id: claim.claim_id,
      subject_nid: writerOne.did_key,
      authority: "claim-ledger-reader",
      evidence: createReductionEvidence({
        claim_id: claim.claim_id,
        event_id: "33".repeat(32),
        authority: "claim-ledger-reader",
        validated_at: now + 2,
        core_kel_authority_valid: true,
      }),
    }, { writer: writerTwo, parents: [claimRecord.record_id], created_at: now + 2 });
    const rotation = signedRecord("audience-key-epoch", {
      key_id: "ledger-epoch-b",
      previous_key_id: "ledger-epoch-a",
      reader_nids: [writerTwo.did_key],
      removed_reader_nids: [writerOne.did_key],
      radicle_access_removed: [writerOne.did_key],
      retire_previous_state: true,
      scrub_profile: "comms-encrypted-branch-cooperative-v1",
    }, { writer: writerTwo, parents: [removal.record_id], created_at: now + 3 });
    const removed = mergeClaimLedger([claimRecord], [removal, rotation], checkpoint());
    expect(evaluateReaderAccess(writerOne.did_key, [claim], removed).allowed).toBe(false);
    expect(rotation.payload).toEqual(expect.objectContaining({
      reader_nids: [writerTwo.did_key],
      removed_reader_nids: [writerOne.did_key],
      radicle_access_removed: [writerOne.did_key],
      retire_previous_state: true,
      scrub_profile: "comms-encrypted-branch-cooperative-v1",
    }));
  });

  it("rejects audience-key rotation that is unordered, retains a removed reader, or omits access removal", () => {
    const claim = readerClaim();
    const claimRecord = signedRecord("claim", { claim });
    const unordered = signedRecord("audience-key-epoch", {
      key_id: "ledger-epoch-b",
      previous_key_id: "ledger-epoch-a",
      reader_nids: [writerOne.did_key],
      removed_reader_nids: [writerOne.did_key],
      radicle_access_removed: [],
      retire_previous_state: true,
      scrub_profile: "comms-encrypted-branch-cooperative-v1",
    }, { writer: writerTwo, parents: [claimRecord.record_id], created_at: now + 3 });
    expect(() => mergeClaimLedger([claimRecord], [unordered], checkpoint())).toThrow(/rotation|removed|access/);
  });

  it("derives opaque keyed paths without leaking record semantics", () => {
    const key = Uint8Array.from({ length: 32 }, () => 0x51);
    const recordId = "de".repeat(32);
    const first = deriveLedgerPath(key, recordId);
    const second = deriveLedgerPath(key, "df".repeat(32));
    const otherKey = deriveLedgerPath(Uint8Array.from({ length: 32 }, () => 0x52), recordId);
    expect(first).toMatch(/^objects\/[0-9a-f]{2}\.bin$/);
    expect(new Set([first, second, otherKey]).size).toBe(3);
    for (const sensitive of ["claim", "revocation", "reader", "consent", persona, writerOne.did_key, recordId]) {
      expect(first).not.toContain(sensitive);
    }
    const visibleMetadata = JSON.stringify({
      path: first,
      message: "heterodyne private ledger update",
      tree_profile: "opaque-fixed-buckets-v1",
    });
    for (const sensitive of [
      "claim", "revocation", "reader", "authorization", "namespace", "count", "consent", "issuer",
      persona, writerOne.did_key, recordId,
    ]) {
      expect(visibleMetadata).not.toContain(sensitive);
    }
    expect(() => deriveLedgerPath(new Uint8Array(31), recordId)).toThrow(/32 bytes/);
    const undomained = createHmac("sha256", key).update(recordId, "hex").digest("hex");
    expect(first).not.toContain(undomained);
    expect(deriveLedgerPath(key, recordId)).toBe(first);
  });
});

describe("claim-ledger vector corpus", () => {
  it("authors the exact thirteen deterministic Task 4 vectors", async () => {
    const vectors = await buildClaimLedgerVectors(fixtures);
    expect(vectors.map(({ relativePath }) => relativePath)).toEqual([
      "claim-ledger/001-reader-nid-authorized.json",
      "claim-ledger/002-nidless-reader-denied.json",
      "claim-ledger/003-delivered-grant-provisional.json",
      "claim-ledger/004-immediate-revocation.json",
      "claim-ledger/005-multiwriter-revocation-wins.json",
      "claim-ledger/006-authority-reduction-wins.json",
      "claim-ledger/007-nonmonotonic-conflict-blocks.json",
      "claim-ledger/008-checkpoint-rollback-rejected.json",
      "claim-ledger/009-keyed-path-metadata-private.json",
      "claim-ledger/010-reader-removal-key-rotation.json",
      "claim-ledger/011-multiwriter-status-allocation.json",
      "claim-ledger/012-stale-minter-denied.json",
      "claim-ledger/013-source-claim-revokes-token.json",
    ]);
    expect(vectors.every(({ vector }) =>
      vector.owner_document === "comms" &&
      vector.owner_version === "comms/0.5.0" &&
      vector.registry_revision === 2
    )).toBe(true);
  });
});
