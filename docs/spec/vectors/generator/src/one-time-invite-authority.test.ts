import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import { jcsCanonicalize } from "./jcs.js";
import { getPublicKey } from "./nostr.js";
import {
  descriptorDigest,
  responseProof,
  secretCommitment,
  type InviteDescriptor,
  type InviteEnvelope,
  type InvitePurpose,
} from "./one-time-invite.js";
import {
  createOneTimeInviteAuthority,
  redeemOneTimeInvite,
  type OneTimeInviteAuthorityConfig,
  type OneTimeInviteRedemption,
} from "./one-time-invite-authority.js";
import type {
  DurableAuthorityRecord,
  DurableAuthorityStore,
} from "./security-authority-support.js";

type InviteOutput = Readonly<{ group_id: string; response_digest: string }>;
const INVITER_SECRET = "01".padStart(64, "0");
const INVITER = getPublicKey(INVITER_SECRET);
const RECIPIENT = "33".repeat(32);
const SECRET = "ab".repeat(32);
const KEY_PACKAGE = new Uint8Array([1, 2, 3]);
const GROUP_TRANSITION = new Uint8Array([4, 5, 6]);
const GROUP_ID = "44".repeat(32);
const NOW = 1_001;

class MemoryStore implements DurableAuthorityStore<InviteOutput> {
  readonly records = new Map<string, DurableAuthorityRecord<InviteOutput>>();
  acquireResult: "acquired" | "replay" | "conflict" | "unavailable" | null = null;
  commitResult: "committed" | "conflict" | "unknown" = "committed";
  preserveExecutingOnMark = false;
  acquireCalls = 0;
  commitCalls = 0;
  markCalls = 0;

  async load(key: string): Promise<DurableAuthorityRecord<InviteOutput> | null> {
    return this.records.get(key) ?? null;
  }

  async acquire(input: Readonly<{
    key: string; expected_revision: number | null;
    binding_digest: string; execution_token: string;
  }>): Promise<"acquired" | "replay" | "conflict" | "unavailable"> {
    this.acquireCalls += 1;
    if (this.acquireResult !== null && this.acquireResult !== "acquired") {
      return this.acquireResult;
    }
    const current = this.records.get(input.key);
    if (current !== undefined) {
      return current.binding_digest === input.binding_digest ? "replay" : "conflict";
    }
    this.records.set(input.key, Object.freeze({
      state: "executing", revision: 0,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
    }));
    return "acquired";
  }

  async compareAndSwap(): Promise<"committed" | "conflict" | "unknown"> {
    return "conflict";
  }

  async commit(input: Readonly<{
    key: string; binding_digest: string; execution_token: string;
    output_digest: string; output: InviteOutput;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.commitCalls += 1;
    if (this.commitResult !== "committed") return this.commitResult;
    this.records.set(input.key, Object.freeze({
      state: "committed", revision: 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      output_digest: input.output_digest,
      output: input.output,
    }));
    return "committed";
  }

  async markIndeterminate(input: Readonly<{
    key: string; binding_digest: string; execution_token: string;
    reconciliation_digest: string;
  }>): Promise<"indeterminate"> {
    this.markCalls += 1;
    if (this.preserveExecutingOnMark) return "indeterminate";
    this.records.set(input.key, Object.freeze({
      state: "indeterminate", revision: 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      reconciliation_digest: input.reconciliation_digest,
    }));
    return "indeterminate";
  }
}

function signedEnvelope(
  overrides: Partial<InviteDescriptor> = {},
  secret = SECRET,
): InviteEnvelope {
  const descriptor: InviteDescriptor = {
    version: 1,
    purpose: "dm",
    inviter_account: INVITER,
    invite_id: "11".repeat(32),
    rendezvous_pubkey: "22".repeat(32),
    relay_hints: ["wss://relay.example"],
    issued_at: 1_000,
    expires_at: 2_000,
    secret_sha256: secretCommitment(secret),
    approval_mode: "interactive",
    expected_client_pubkey: RECIPIENT,
    ...overrides,
  };
  return {
    descriptor,
    signature: Buffer.from(
      schnorr.sign(descriptorDigest(descriptor), INVITER_SECRET, new Uint8Array(32)),
    ).toString("hex"),
    secret,
  };
}

function responseBytes(
  envelope: InviteEnvelope,
  overrides: Record<string, unknown> = {},
): Uint8Array {
  const withoutProof = {
    spec_version: "heterodyne/0.6.0",
    purpose: envelope.descriptor.purpose,
    descriptor_digest: Buffer.from(descriptorDigest(envelope.descriptor)).toString("hex"),
    responder_account: RECIPIENT,
    mls_key_package: Buffer.from(KEY_PACKAGE).toString("base64url"),
    requested_class: envelope.descriptor.purpose === "dm"
      ? "conversation-peer"
      : envelope.descriptor.purpose === "control-enrollment" ? "human-light" : "light-device",
    capabilities: ["chat"],
    ...overrides,
  };
  const response = {
    ...withoutProof,
    proof: responseProof(envelope.secret, withoutProof),
  };
  return new TextEncoder().encode(jcsCanonicalize(response));
}

function changedCanonicalResponse(bytes: Uint8Array): Uint8Array {
  const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
  parsed.capabilities = ["chat", "files"];
  return new TextEncoder().encode(jcsCanonicalize(parsed));
}

function redemption(
  overrides: Partial<OneTimeInviteRedemption> = {},
  envelope = signedEnvelope(),
): OneTimeInviteRedemption {
  return {
    envelope,
    response_bytes: responseBytes(envelope),
    response_purpose: envelope.descriptor.purpose,
    recipient: RECIPIENT,
    key_package_bytes: new Uint8Array(KEY_PACKAGE),
    group_transition: new Uint8Array(GROUP_TRANSITION),
    ...overrides,
  };
}

function config(
  store: MemoryStore,
  overrides: Partial<OneTimeInviteAuthorityConfig> = {},
): OneTimeInviteAuthorityConfig {
  return {
    authority_id: "local-one-time-invite",
    trusted_now: () => NOW,
    store,
    load_invite_state: async () => ({ state: "active", revision: 7 }),
    establish_group: async (bytes) => ({
      group_id: Buffer.from(bytes).equals(Buffer.from(GROUP_TRANSITION)) ? GROUP_ID : "55".repeat(32),
      response_digest: "",
    }),
    ...overrides,
  };
}

function withComputedEstablisher(store: MemoryStore, overrides: Partial<OneTimeInviteAuthorityConfig> = {}) {
  return config(store, {
    establish_group: async (bytes) => ({
      group_id: Buffer.from(bytes).equals(Buffer.from(GROUP_TRANSITION)) ? GROUP_ID : "55".repeat(32),
      response_digest: currentResponseDigest,
    }),
    ...overrides,
  });
}

let currentResponseDigest = "";

describe("one-time invite authority", () => {
  it("redeems one signed purpose-bound response and returns exact committed output", async () => {
    const store = new MemoryStore();
    const input = redemption();
    currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store));
    await expect(redeemOneTimeInvite(authority, input)).resolves.toEqual({
      verdict: "accept",
      output: { group_id: GROUP_ID, response_digest: currentResponseDigest },
    });
    expect(store.commitCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local returns cached output for an exact restart-stable retry", async () => {
    const store = new MemoryStore();
    const input = redemption();
    currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
    let effects = 0;
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store, {
      establish_group: async () => {
        effects += 1;
        return { group_id: GROUP_ID, response_digest: currentResponseDigest };
      },
    }));
    expect((await redeemOneTimeInvite(authority, input)).verdict).toBe("accept");
    const reconstructed = createOneTimeInviteAuthority(withComputedEstablisher(store, {
      establish_group: async () => {
        effects += 1;
        return { group_id: GROUP_ID, response_digest: currentResponseDigest };
      },
    }));
    await expect(redeemOneTimeInvite(reconstructed, input)).resolves.toMatchObject({
      verdict: "accept",
      output: { group_id: GROUP_ID, response_digest: currentResponseDigest },
    });
    expect(effects).toBe(1);
  });

  it.each([
    ["wrong purpose", (input: OneTimeInviteRedemption) => ({ ...input, response_purpose: "device-enrollment" as InvitePurpose })],
    ["wrong transcript", (input: OneTimeInviteRedemption) => ({ ...input, response_bytes: changedCanonicalResponse(input.response_bytes) })],
    ["wrong recipient", (input: OneTimeInviteRedemption) => ({ ...input, recipient: "55".repeat(32) })],
    ["wrong secret", (input: OneTimeInviteRedemption) => ({ ...input, envelope: { ...input.envelope, secret: "cd".repeat(32) } })],
    ["wrong KeyPackage", (input: OneTimeInviteRedemption) => ({ ...input, key_package_bytes: new Uint8Array([9]) })],
    ["empty group transition", (input: OneTimeInviteRedemption) => ({ ...input, group_transition: new Uint8Array() })],
  ])("BLUE TEAM VALIDATION: synthetic/local rejects %s before reservation", async (_name, mutate) => {
    const store = new MemoryStore();
    const input = mutate(redemption());
    currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store));
    await expect(redeemOneTimeInvite(authority, input)).resolves.toEqual({
      verdict: "reject", reason_code: "invite-authentication-invalid",
    });
    expect(store.acquireCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local enforces closed descriptor approval relationships", async () => {
    const invalidEnvelopes = [
      signedEnvelope({
        purpose: "control-enrollment",
        approval_mode: "preauthorized",
      }),
      signedEnvelope({
        purpose: "dm",
        approval_mode: "interactive",
        preauthorization: { unexpected: true },
      }),
      signedEnvelope({
        purpose: "device-enrollment",
        approval_mode: "preauthorized",
        preauthorization: { unexpected: true },
      }),
      signedEnvelope({ expires_at: 1_000 + 7 * 24 * 60 * 60 + 1 }),
    ];
    for (const envelope of invalidEnvelopes) {
      const store = new MemoryStore();
      const input = redemption({}, envelope);
      currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
      const authority = createOneTimeInviteAuthority(withComputedEstablisher(store));
      await expect(redeemOneTimeInvite(authority, input)).resolves.toEqual({
        verdict: "reject", reason_code: "invite-authentication-invalid",
      });
      expect(store.acquireCalls).toBe(0);
    }
  });

  it.each([
    ["expiry", { trusted_now: () => 2_000 }],
    ["revocation", { load_invite_state: async () => ({ state: "revoked" as const, revision: 8 }) }],
  ])("BLUE TEAM VALIDATION: synthetic/local rejects current %s before reservation", async (_name, override) => {
    const store = new MemoryStore();
    const input = redemption();
    currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store, override));
    await expect(redeemOneTimeInvite(authority, input)).resolves.toEqual({
      verdict: "reject", reason_code: "invite-authentication-invalid",
    });
    expect(store.acquireCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a mismatched committed retry", async () => {
    const store = new MemoryStore();
    const first = redemption();
    currentResponseDigest = createHash("sha256").update(first.response_bytes).digest("hex");
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store));
    expect((await redeemOneTimeInvite(authority, first)).verdict).toBe("accept");
    const changedEnvelope = signedEnvelope({ relay_hints: ["wss://other.example"] });
    const changed = redemption({}, changedEnvelope);
    currentResponseDigest = createHash("sha256").update(changed.response_bytes).digest("hex");
    await expect(redeemOneTimeInvite(authority, changed)).resolves.toEqual({
      verdict: "reject", reason_code: "invite-authentication-invalid",
    });
    expect(store.commitCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes an unknown post-effect commit absorbing and non-repeating", async () => {
    const store = new MemoryStore();
    store.commitResult = "unknown";
    const input = redemption();
    currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
    let effects = 0;
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store, {
      establish_group: async () => {
        effects += 1;
        return { group_id: GROUP_ID, response_digest: currentResponseDigest };
      },
    }));
    const first = await redeemOneTimeInvite(authority, input);
    expect(first).toMatchObject({ verdict: "indeterminate" });
    if (first.verdict !== "indeterminate") throw new Error("expected indeterminate");
    expect(first.reconciliation_digest).toMatch(/^[0-9a-f]{64}$/u);
    expect(store.markCalls).toBe(1);
    await expect(redeemOneTimeInvite(authority, input)).resolves.toMatchObject({
      verdict: "indeterminate",
    });
    expect(effects).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local treats an acquire conflict without an exact terminal as indeterminate", async () => {
    const store = new MemoryStore();
    store.acquireResult = "conflict";
    const input = redemption();
    currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store));
    const decision = await redeemOneTimeInvite(authority, input);
    expect(decision).toMatchObject({ verdict: "indeterminate" });
    expect(store.commitCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local never repeats an executing group effect", async () => {
    const store = new MemoryStore();
    store.commitResult = "unknown";
    store.preserveExecutingOnMark = true;
    const input = redemption();
    currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
    let effects = 0;
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store, {
      establish_group: async () => {
        effects += 1;
        return { group_id: GROUP_ID, response_digest: currentResponseDigest };
      },
    }));
    expect((await redeemOneTimeInvite(authority, input)).verdict).toBe("indeterminate");
    expect((await redeemOneTimeInvite(authority, input)).verdict).toBe("indeterminate");
    expect(effects).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures the entire redemption before asynchronous state reads", async () => {
    const store = new MemoryStore();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const input = redemption() as OneTimeInviteRedemption & {
      response_bytes: Uint8Array; key_package_bytes: Uint8Array; group_transition: Uint8Array;
    };
    currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
    const expectedDigest = currentResponseDigest;
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store, {
      load_invite_state: async () => {
        await gate;
        return { state: "active", revision: 7 };
      },
      establish_group: async (bytes) => ({
        group_id: Buffer.from(bytes).equals(Buffer.from(GROUP_TRANSITION)) ? GROUP_ID : "55".repeat(32),
        response_digest: expectedDigest,
      }),
    }));
    const pending = redeemOneTimeInvite(authority, input);
    input.response_bytes[0] = 0;
    input.key_package_bytes[0] = 0;
    input.group_transition[0] = 0;
    release();
    await expect(pending).resolves.toEqual({
      verdict: "accept",
      output: { group_id: GROUP_ID, response_digest: expectedDigest },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures constructor callbacks and store methods once", async () => {
    const store = new MemoryStore();
    const input = redemption();
    currentResponseDigest = createHash("sha256").update(input.response_bytes).digest("hex");
    const mutableConfig = withComputedEstablisher(store) as OneTimeInviteAuthorityConfig & {
      load_invite_state: OneTimeInviteAuthorityConfig["load_invite_state"];
      establish_group: OneTimeInviteAuthorityConfig["establish_group"];
    };
    const authority = createOneTimeInviteAuthority(mutableConfig);
    mutableConfig.load_invite_state = async () => ({ state: "revoked", revision: 8 });
    mutableConfig.establish_group = async () => ({
      group_id: "55".repeat(32), response_digest: "66".repeat(32),
    });
    Object.defineProperty(store, "commit", {
      value: async () => { throw new Error("replaced"); },
    });
    await expect(redeemOneTimeInvite(authority, input)).resolves.toEqual({
      verdict: "accept",
      output: { group_id: GROUP_ID, response_digest: currentResponseDigest },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned authority handles", async () => {
    const store = new MemoryStore();
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store));
    const input = redemption();
    await expect(redeemOneTimeInvite(Object.freeze({ ...authority }), input)).resolves.toEqual({
      verdict: "reject", reason_code: "invite-authentication-invalid",
    });
    expect(store.acquireCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxy and accessor inputs without invoking them", async () => {
    const store = new MemoryStore();
    const authority = createOneTimeInviteAuthority(withComputedEstablisher(store));
    let traps = 0;
    const proxied = new Proxy(redemption(), {
      get() { traps += 1; throw new Error("trap"); },
      ownKeys() { traps += 1; throw new Error("trap"); },
    });
    const accessor = { ...redemption() };
    Object.defineProperty(accessor, "recipient", {
      enumerable: true,
      get() { traps += 1; return RECIPIENT; },
    });
    for (const input of [proxied, accessor]) {
      await expect(redeemOneTimeInvite(authority, input)).resolves.toEqual({
        verdict: "reject", reason_code: "invite-authentication-invalid",
      });
    }
    expect(traps).toBe(0);
    expect(store.acquireCalls).toBe(0);
  });
});
