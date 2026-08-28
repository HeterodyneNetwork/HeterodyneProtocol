import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import { bytesToHex } from "./hex.js";
import { signEvent } from "./nostr.js";

const adminPrivateKey = "11".repeat(32);
const administratorAccount = bytesToHex(schnorr.getPublicKey(adminPrivateKey));
const account = "22".repeat(32);
const seedNid = "did:key:z6MkwQp8f8Y11L3WJYJ4hXa1";
const privateRid = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
const route = "private-routing-id";
const writerRef = "refs/xyz.heterodyne.marmot/relays/seed-a";
const now = 1_785_000_100;
const transition = {
  generation: 7,
  marmot_routing_event_id: "44".repeat(32),
  routing_binding_sha256: "55".repeat(32),
};

type Authority = object;
type Capability = object;
type AuthorityBundle = {
  authority: Authority;
  mintRequestCapability(session: unknown, request: unknown): Capability | null;
};
type TrustedSeedApi = {
  createTrustedSeedAdmissionAuthority?: (config: unknown) => AuthorityBundle | null;
  evaluateTrustedSeedAdmission?: (
    authority: unknown,
    request: unknown,
  ) => { verdict: "accept" | "reject"; reason_code?: string; seed_nid?: string };
  trustedSeedAclProofBytes(value: Record<string, unknown>): Uint8Array;
};

async function moduleUnderTest(): Promise<TrustedSeedApi> {
  return await import("./trusted-seed.js") as TrustedSeedApi;
}

function authResult(patch: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    verdict: "accept",
    account_key: account,
    connection_id: "connection-1",
    challenge_id: "challenge-1",
    request_id: "request-1",
    authenticated_at: now - 1,
    expires_at: now + 60,
    ...patch,
  };
}

async function signedAcl(
  api: TrustedSeedApi,
  patch: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const acl = {
    profile: "heterodyne.trusted-seed-acl.v1",
    spec_version: "heterodyne/0.6.0",
    administrator_account: administratorAccount,
    accounts: [{ account_key: account, roles: ["read", "write"] }],
    h: route,
    private_rid: privateRid,
    seed_grants: [{
      seed_nid: seedNid,
      relay_endpoint: "wss://seed-a.example/group",
      radicle_endpoint: privateRid,
      writer_ref: writerRef,
      roles: ["read", "write"],
      state: "active",
    }],
    sequence: 0,
    predecessor: null,
    group_transition: transition,
    issued_at: now - 100,
    expires_at: now + 1_000,
    ...patch,
  };
  return {
    ...acl,
    signature: bytesToHex(schnorr.sign(
      api.trustedSeedAclProofBytes(acl),
      adminPrivateKey,
    )),
  };
}

async function signedMarmotEvent(): Promise<string> {
  return JSON.stringify(await signEvent({
    secretKey: "77".repeat(32),
    created_at: now - 1,
    kind: 445,
    tags: [["h", route]],
    content: "marmot-ciphertext",
    auxRand: "88".repeat(32),
  }));
}

async function harness(overrides: {
  clock?: () => unknown;
  authenticate?: () => unknown;
  loadState?: () => unknown;
  consume?: (binding: unknown) => unknown;
} = {}) {
  const api = await moduleUnderTest();
  expect(api.createTrustedSeedAdmissionAuthority).toBeTypeOf("function");
  const acl = await signedAcl(api);
  let state: unknown = {
    administrator_account: administratorAccount,
    acl_candidates: [acl],
    previous_acl: null,
    group_transition: transition,
    revision: 4,
  };
  let consumeResult: unknown = { verdict: "accept" };
  const config = {
    seed_nid: seedNid,
    administrator_account: administratorAccount,
    trusted_now: overrides.clock ?? (() => ({ now })),
    authenticate_nip42: overrides.authenticate ?? (() => authResult()),
    load_current_state: overrides.loadState ?? (() => state),
    consume_once: overrides.consume ?? (() => consumeResult),
  };
  const bundle = api.createTrustedSeedAdmissionAuthority?.(config);
  expect(bundle).not.toBeNull();
  const write = {
    operation: "write",
    h: route,
    private_rid: privateRid,
    writer_ref: writerRef,
    nip01_raw: await signedMarmotEvent(),
  };
  return {
    api,
    bundle: bundle!,
    config,
    write,
    setState(value: unknown) { state = value; },
    setConsumeResult(value: unknown) { consumeResult = value; },
  };
}

describe("trusted private seed admission authority", () => {
  it("derives authentication, trust roots, time, and current state outside caller input", async () => {
    const { api, bundle, write } = await harness();
    const capability = bundle.mintRequestCapability({ connection: "opaque" }, write);
    expect(capability).not.toBeNull();
    expect(api.evaluateTrustedSeedAdmission?.(bundle.authority, capability)).toMatchObject({
      verdict: "accept",
      seed_nid: seedNid,
    });

    for (const untrusted of [
      { ...write, nip42_authenticated: true },
      { ...write, authenticated_account: account },
      { ...write, expected_administrator_account: administratorAccount },
      { ...write, acl_candidates: [] },
      { ...write, previous_acl: {} },
      { ...write, group_transition: transition },
      { ...write, now },
      { ...write, seed_nid: seedNid },
    ]) {
      expect(bundle.mintRequestCapability({}, untrusted)).toBeNull();
    }
  });

  it("rejects cross-authority and repeated capabilities after burning before decision", async () => {
    const first = await harness();
    const second = await harness();
    const capability = first.bundle.mintRequestCapability({}, first.write);
    expect(first.api.evaluateTrustedSeedAdmission?.(second.bundle.authority, capability))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-request-invalid" });

    const ownCapability = first.bundle.mintRequestCapability({}, first.write);
    expect(first.api.evaluateTrustedSeedAdmission?.(first.bundle.authority, ownCapability))
      .toMatchObject({ verdict: "accept" });
    expect(first.api.evaluateTrustedSeedAdmission?.(first.bundle.authority, ownCapability))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-request-replay" });
  });

  it("burns before current-state validation and fails a repaired retry as replay", async () => {
    const fixture = await harness();
    const capability = fixture.bundle.mintRequestCapability({}, fixture.write);
    fixture.setState({ malformed: true });
    expect(fixture.api.evaluateTrustedSeedAdmission?.(fixture.bundle.authority, capability))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-acl-invalid" });
    const acl = await signedAcl(fixture.api);
    fixture.setState({
      administrator_account: administratorAccount,
      acl_candidates: [acl],
      previous_acl: null,
      group_transition: transition,
      revision: 5,
    });
    expect(fixture.api.evaluateTrustedSeedAdmission?.(fixture.bundle.authority, capability))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-request-replay" });
  });

  it("distinguishes an absent ACL projection from malformed ACL state", async () => {
    const fixture = await harness();
    fixture.setState({
      administrator_account: administratorAccount,
      acl_candidates: [],
      previous_acl: null,
      group_transition: transition,
      revision: 5,
    });
    const capability = fixture.bundle.mintRequestCapability({}, fixture.write);
    expect(fixture.api.evaluateTrustedSeedAdmission?.(fixture.bundle.authority, capability))
      .toEqual({ verdict: "reject", reason_code: "trusted-seed-acl-missing" });
  });

  it("snapshots every callback result and rejects accessors without invoking them", async () => {
    let getterCalls = 0;
    const accessorAuth = Object.defineProperty(
      { ...authResult() },
      "account_key",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          return account;
        },
      },
    );
    const authFixture = await harness({ authenticate: () => accessorAuth });
    expect(authFixture.bundle.mintRequestCapability({}, authFixture.write)).toBeNull();
    expect(getterCalls).toBe(0);

    for (const override of [
      { clock: () => ({ now, extra: true }) },
      { authenticate: () => ({ ...authResult(), extra: true }) },
      { loadState: () => ({ malformed: true }) },
      { consume: () => ({ verdict: "accept", extra: true }) },
    ]) {
      const fixture = await harness(override);
      const capability = fixture.bundle.mintRequestCapability({}, fixture.write);
      const result = fixture.api.evaluateTrustedSeedAdmission?.(
        fixture.bundle.authority,
        capability,
      );
      expect(result?.verdict).toBe("reject");
    }
  });

  it("captures callback identities once and rejects proxy configuration without traps", async () => {
    const fixture = await harness();
    fixture.config.trusted_now = () => ({ now: now + 100_000 });
    const capability = fixture.bundle.mintRequestCapability({}, fixture.write);
    expect(capability).not.toBeNull();

    let traps = 0;
    const proxy = new Proxy(fixture.config, {
      ownKeys() {
        traps += 1;
        return Reflect.ownKeys(fixture.config);
      },
    });
    expect(fixture.api.createTrustedSeedAdmissionAuthority?.(proxy)).toBeNull();
    expect(traps).toBe(0);
  });

  it("reloads current ACL state and enforces revocation, expiry, and route state", async () => {
    for (const aclPatch of [
      { expires_at: now },
      { h: "different-route" },
      { seed_grants: [{
        seed_nid: seedNid,
        relay_endpoint: "wss://seed-a.example/group",
        radicle_endpoint: privateRid,
        writer_ref: writerRef,
        roles: ["read", "write"],
        state: "revoked",
      }] },
    ]) {
      const fixture = await harness();
      fixture.setState({
        administrator_account: administratorAccount,
        acl_candidates: [await signedAcl(fixture.api, aclPatch)],
        previous_acl: null,
        group_transition: transition,
        revision: 5,
      });
      const capability = fixture.bundle.mintRequestCapability({}, fixture.write);
      expect(fixture.api.evaluateTrustedSeedAdmission?.(fixture.bundle.authority, capability)?.verdict)
        .toBe("reject");
    }
  });

  it("atomically binds persistence to the byte-exact verified write", async () => {
    let consumedBinding: unknown;
    const fixture = await harness({
      consume: (binding) => {
        consumedBinding = binding;
        return { verdict: "accept" };
      },
    });
    fixture.write.nip01_raw = ` \n${fixture.write.nip01_raw}\n`;
    const capability = fixture.bundle.mintRequestCapability({}, fixture.write);
    expect(fixture.api.evaluateTrustedSeedAdmission?.(
      fixture.bundle.authority,
      capability,
    )).toMatchObject({ verdict: "accept", nip01_raw: fixture.write.nip01_raw });
    expect(consumedBinding).toMatchObject({
      event_id: JSON.parse(fixture.write.nip01_raw).id,
      nip01_raw: fixture.write.nip01_raw,
      writer_ref: writerRef,
    });
    expect(Object.isFrozen(consumedBinding)).toBe(true);
  });

  it("fails closed for replay, conflict, malformed, throwing, or uncertain consume results", async () => {
    for (const consume of [
      () => ({ verdict: "replay" }),
      () => ({ verdict: "conflict" }),
      () => ({ verdict: "effect-failed" }),
      () => ({ verdict: "accept", revision: 7 }),
      () => { throw new Error("persistence unavailable"); },
    ]) {
      const fixture = await harness({ consume });
      const capability = fixture.bundle.mintRequestCapability({}, fixture.write);
      expect(fixture.api.evaluateTrustedSeedAdmission?.(fixture.bundle.authority, capability)?.verdict)
        .toBe("reject");
    }
  });
});
