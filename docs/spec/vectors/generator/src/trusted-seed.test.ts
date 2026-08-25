import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import { bytesToHex } from "./hex.js";

const adminPrivateKey = "11".repeat(32);
const administratorAccount = bytesToHex(schnorr.getPublicKey(adminPrivateKey));
const accountA = "22".repeat(32);
const accountB = "33".repeat(32);
const seedA = "did:key:z6MkwQp8f8Y11L3WJYJ4hXa1";
const seedB = "did:key:z6Mkq7ZBA1Vh9fVhKo2H2iW4";
const privateRid = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
const now = 1_785_000_100;

async function moduleUnderTest() {
  return import("./trusted-seed.js");
}

async function signedAcl(
  patch: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const { trustedSeedAclProofBytes } = await moduleUnderTest();
  const acl = {
    profile: "heterodyne.trusted-seed-acl.v1",
    spec_version: "heterodyne/0.5.0",
    administrator_account: administratorAccount,
    accounts: [
      { account_key: accountA, roles: ["read", "write"] },
      { account_key: accountB, roles: ["read"] },
    ],
    h: "private-routing-id",
    private_rid: privateRid,
    seed_grants: [
      {
        seed_nid: seedA,
        relay_endpoint: "wss://seed-a.example/group",
        radicle_endpoint: privateRid,
        writer_ref: "refs/xyz.heterodyne.marmot/relays/seed-a",
        roles: ["read", "write"],
        state: "active",
      },
      {
        seed_nid: seedB,
        relay_endpoint: "wss://seed-b.example/group",
        radicle_endpoint: privateRid,
        writer_ref: "refs/xyz.heterodyne.marmot/relays/seed-b",
        roles: ["read", "write"],
        state: "active",
      },
    ],
    sequence: 0,
    predecessor: null,
    group_transition: {
      generation: 7,
      marmot_routing_event_id: "44".repeat(32),
      routing_binding_sha256: "55".repeat(32),
    },
    issued_at: now - 100,
    expires_at: now + 1_000,
    ...patch,
  };
  return {
    ...acl,
    signature: bytesToHex(schnorr.sign(trustedSeedAclProofBytes(acl), adminPrivateKey)),
  };
}

async function request(
  patch: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  return {
    acl_candidates: [await signedAcl()],
    expected_administrator_account: administratorAccount,
    authenticated_account: accountA,
    nip42_authenticated: true,
    operation: "write",
    seed_nid: seedA,
    h: "private-routing-id",
    private_rid: privateRid,
    writer_ref: "refs/xyz.heterodyne.marmot/relays/seed-a",
    group_transition: {
      generation: 7,
      marmot_routing_event_id: "44".repeat(32),
      routing_binding_sha256: "55".repeat(32),
    },
    now,
    nip01_raw: '["EVENT",{"content":"ciphertext"}]',
    ...patch,
  };
}

describe("trusted private seed admission", () => {
  it("authenticates with NIP-42 and admits each concurrent seed only to its own ref", async () => {
    const { evaluateTrustedSeedAdmission } = await moduleUnderTest();
    const acl = await signedAcl();
    const first = await request({ acl_candidates: [acl] });
    const second = await request({
      acl_candidates: [acl],
      seed_nid: seedB,
      writer_ref: "refs/xyz.heterodyne.marmot/relays/seed-b",
    });

    expect(evaluateTrustedSeedAdmission(first)).toMatchObject({
      verdict: "accept",
      seed_nid: seedA,
      writer_ref: "refs/xyz.heterodyne.marmot/relays/seed-a",
      nip01_raw: '["EVENT",{"content":"ciphertext"}]',
    });
    expect(evaluateTrustedSeedAdmission(second)).toMatchObject({
      verdict: "accept",
      seed_nid: seedB,
      writer_ref: "refs/xyz.heterodyne.marmot/relays/seed-b",
    });
    expect(evaluateTrustedSeedAdmission(await request({
      acl_candidates: [acl],
      writer_ref: "refs/xyz.heterodyne.marmot/relays/seed-b",
    }))).toEqual({ verdict: "reject", reason_code: "trusted-seed-unauthorized" });
  });

  it("fails closed for missing, expired, stale, conflicting, and ambiguous ACL state", async () => {
    const { evaluateTrustedSeedAdmission, trustedSeedAclDigest } = await moduleUnderTest();
    expect(evaluateTrustedSeedAdmission(await request({ acl_candidates: [] })))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-acl-missing" });
    expect(evaluateTrustedSeedAdmission(await request({
      acl_candidates: [await signedAcl({ expires_at: now })],
    }))).toEqual({ verdict: "reject", reason_code: "trusted-seed-acl-expired" });

    const previous = await signedAcl();
    expect(evaluateTrustedSeedAdmission(await request({
      acl_candidates: [previous],
      previous_acl: previous,
    }))).toEqual({ verdict: "reject", reason_code: "trusted-seed-acl-stale" });

    const conflictingA = await signedAcl({ accounts: [{ account_key: accountA, roles: ["read"] }] });
    const conflictingB = await signedAcl({ accounts: [{ account_key: accountA, roles: ["write"] }] });
    expect(evaluateTrustedSeedAdmission(await request({
      acl_candidates: [conflictingA, conflictingB],
    }))).toEqual({ verdict: "reject", reason_code: "trusted-seed-acl-conflict" });

    const previousDigest = trustedSeedAclDigest(previous);
    const ambiguous = await signedAcl({
      sequence: 1,
      predecessor: `${previousDigest.slice(0, -1)}0`,
    });
    expect(evaluateTrustedSeedAdmission(await request({
      acl_candidates: [ambiguous],
      previous_acl: previous,
    }))).toEqual({ verdict: "reject", reason_code: "trusted-seed-acl-ambiguous" });
  });

  it("rejects revoked, unauthorized, unauthenticated, and route-mismatched access", async () => {
    const { evaluateTrustedSeedAdmission } = await moduleUnderTest();
    const revoked = await signedAcl({
      seed_grants: [{
        seed_nid: seedA,
        relay_endpoint: "wss://seed-a.example/group",
        radicle_endpoint: privateRid,
        writer_ref: "refs/xyz.heterodyne.marmot/relays/seed-a",
        roles: ["read", "write"],
        state: "revoked",
      }],
    });
    expect(evaluateTrustedSeedAdmission(await request({ acl_candidates: [revoked] })))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-revoked" });
    expect(evaluateTrustedSeedAdmission(await request({ authenticated_account: "66".repeat(32) })))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-unauthorized" });
    expect(evaluateTrustedSeedAdmission(await request({ nip42_authenticated: false })))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-nip42-required" });
    expect(evaluateTrustedSeedAdmission(await request({ h: "wrong-route" })))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-route-mismatch" });
    expect(evaluateTrustedSeedAdmission(await request({
      group_transition: {
        generation: 8,
        marmot_routing_event_id: "77".repeat(32),
        routing_binding_sha256: "88".repeat(32),
      },
    }))).toEqual({ verdict: "reject", reason_code: "trusted-seed-acl-stale" });
  });

  it("refuses MLS secrets, plaintext, and content-decryption material at the seed boundary", async () => {
    const { evaluateTrustedSeedAdmission } = await moduleUnderTest();
    for (const patch of [
      { mls_leaf_secret: "secret" },
      { plaintext: "hello" },
      { content_decryption_key: "secret" },
    ]) {
      expect(evaluateTrustedSeedAdmission(await request(patch))).toEqual({
        verdict: "reject",
        reason_code: "trusted-seed-secret-material-forbidden",
      });
    }
  });
});
