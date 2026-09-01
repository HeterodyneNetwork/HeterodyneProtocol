import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  admitPersonaInboxBundle,
  createPersonaInboxAdmissionAuthority,
  type PersonaInboxAdmission,
  type PersonaInboxAdmissionAuthorityConfig,
  type PersonaInboxBundle,
} from "./persona-inbox-admission-authority.js";
import type {
  DurableAuthorityRecord,
  DurableAuthorityStore,
} from "./security-authority-support.js";

const RECIPIENT = "11".repeat(32);
const SENDER = "22".repeat(32);
const RECIPIENT_NID = "did:key:z6MkrRecipient";
const SENDER_REF = "refs/xyz.heterodyne.marmot/writers/sender-a";
const KEY_PACKAGE = new Uint8Array([1, 2, 3, 4]);
const KEY_PACKAGE_REF = createHash("sha256").update(KEY_PACKAGE).digest("hex");
const GROUP_TRANSITION = new Uint8Array([5, 6, 7, 8]);
const GROUP_ID = createHash("sha256").update(GROUP_TRANSITION).digest("hex");

class MemoryStore<O> implements DurableAuthorityStore<O> {
  readonly records = new Map<string, DurableAuthorityRecord<O>>();
  commitResult: "committed" | "conflict" | "unknown" = "committed";
  acquireCalls = 0;
  commitCalls = 0;
  markCalls = 0;

  async load(key: string): Promise<DurableAuthorityRecord<O> | null> {
    return this.records.get(key) ?? null;
  }

  async acquire(input: Readonly<{
    key: string; expected_revision: number | null;
    binding_digest: string; execution_token: string;
  }>): Promise<"acquired" | "replay" | "conflict" | "unavailable"> {
    this.acquireCalls += 1;
    const current = this.records.get(input.key);
    if (current !== undefined) {
      return current.binding_digest === input.binding_digest ? "replay" : "conflict";
    }
    this.records.set(input.key, Object.freeze({
      state: "executing",
      revision: 0,
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
    output_digest: string; output: O;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.commitCalls += 1;
    if (this.commitResult !== "committed") return this.commitResult;
    this.records.set(input.key, Object.freeze({
      state: "committed",
      revision: 1,
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
    this.records.set(input.key, Object.freeze({
      state: "indeterminate",
      revision: 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      reconciliation_digest: input.reconciliation_digest,
    }));
    return "indeterminate";
  }
}

function bundle(overrides: Partial<PersonaInboxBundle> = {}): PersonaInboxBundle {
  return {
    recipient: RECIPIENT,
    sender: SENDER,
    sender_kind: "persona",
    sender_ref: SENDER_REF,
    purpose: "marmot-first-contact",
    required_agent_scope: null,
    key_package_bytes: new Uint8Array(KEY_PACKAGE),
    key_package_ref: KEY_PACKAGE_REF,
    group_transition: new Uint8Array(GROUP_TRANSITION),
    ...overrides,
  };
}

function config(
  store: MemoryStore<PersonaInboxAdmission>,
  overrides: Partial<PersonaInboxAdmissionAuthorityConfig> = {},
): PersonaInboxAdmissionAuthorityConfig {
  return {
    authority_id: "local-persona-inbox",
    trusted_now: () => 1_000,
    store,
    load_inbox: async () => Object.freeze({
      checkpoint: "inbox-checkpoint-1",
      recipient_nid: RECIPIENT_NID,
      consumed_key_packages: Object.freeze([]),
      allowed_agent_scopes: Object.freeze(["marmot:first-contact"]),
    }),
    ...overrides,
  };
}

describe("persona inbox admission authority", () => {
  it("accepts a captured persona first-contact transition", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store));

    await expect(admitPersonaInboxBundle(authority, bundle())).resolves.toEqual({
      verdict: "accept",
      output: { group_id: GROUP_ID, key_package_ref: KEY_PACKAGE_REF },
    });
    expect(store.commitCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local burns one KeyPackage under concurrent admission", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store));
    const [left, right] = await Promise.all([
      admitPersonaInboxBundle(authority, bundle()),
      admitPersonaInboxBundle(authority, bundle()),
    ]);
    expect([left, right].filter((x) => x.verdict === "accept")).toHaveLength(1);
    expect([left, right].filter((x) => x.verdict === "reject"))
      .toEqual([{ verdict: "reject", reason_code: "marmot-keypackage-replayed" }]);
    expect(store.commitCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local requires current private-inbox NID authority", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store, {
      load_inbox: async () => ({
        checkpoint: "inbox-checkpoint-1",
        recipient_nid: null,
        consumed_key_packages: [],
        allowed_agent_scopes: [],
      }),
    }));
    await expect(admitPersonaInboxBundle(authority, bundle())).resolves.toEqual({
      verdict: "reject",
      reason_code: "marmot-private-inbox-nid-required",
    });
    expect(store.acquireCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects an unauthorized agent scope", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store));
    await expect(admitPersonaInboxBundle(authority, bundle({
      sender_kind: "agent",
      required_agent_scope: "marmot:admin",
    }))).resolves.toEqual({
      verdict: "reject",
      reason_code: "marmot-agent-scope-denied",
    });
    expect(store.acquireCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a KeyPackage already consumed in current state", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store, {
      load_inbox: async () => ({
        checkpoint: "inbox-checkpoint-1",
        recipient_nid: RECIPIENT_NID,
        consumed_key_packages: [KEY_PACKAGE_REF],
        allowed_agent_scopes: [],
      }),
    }));
    await expect(admitPersonaInboxBundle(authority, bundle())).resolves.toEqual({
      verdict: "reject",
      reason_code: "marmot-keypackage-replayed",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects changed KeyPackage, ref, sender ref, purpose, and transition before acquire", async () => {
    for (const malformed of [
      bundle({ key_package_bytes: new Uint8Array([9]) }),
      bundle({ key_package_ref: "33".repeat(32) }),
      bundle({ sender_ref: "refs/heads/main" }),
      { ...bundle(), purpose: "device-enrollment" } as unknown as PersonaInboxBundle,
      bundle({ group_transition: new Uint8Array() }),
    ]) {
      const store = new MemoryStore<PersonaInboxAdmission>();
      const authority = createPersonaInboxAdmissionAuthority(config(store));
      const decision = await admitPersonaInboxBundle(authority, malformed);
      expect(decision.verdict).not.toBe("accept");
      expect(store.acquireCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures bytes and state before asynchronous reads", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const authority = createPersonaInboxAdmissionAuthority(config(store, {
      load_inbox: async () => {
        await gate;
        return {
          checkpoint: "inbox-checkpoint-1",
          recipient_nid: RECIPIENT_NID,
          consumed_key_packages: [],
          allowed_agent_scopes: [],
        };
      },
    }));
    const mutable = bundle() as {
      key_package_bytes: Uint8Array; group_transition: Uint8Array; sender_ref: string;
    } & PersonaInboxBundle;
    const pending = admitPersonaInboxBundle(authority, mutable);
    mutable.key_package_bytes[0] = 99;
    mutable.group_transition[0] = 99;
    mutable.sender_ref = "refs/heads/main";
    release();
    await expect(pending).resolves.toEqual({
      verdict: "accept",
      output: { group_id: GROUP_ID, key_package_ref: KEY_PACKAGE_REF },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures constructor callbacks and store methods once", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const mutableConfig = config(store) as PersonaInboxAdmissionAuthorityConfig & {
      load_inbox: PersonaInboxAdmissionAuthorityConfig["load_inbox"];
    };
    const authority = createPersonaInboxAdmissionAuthority(mutableConfig);
    mutableConfig.load_inbox = async () => ({
      checkpoint: "replaced",
      recipient_nid: null,
      consumed_key_packages: [],
      allowed_agent_scopes: [],
    });
    Object.defineProperty(store, "commit", {
      value: async () => { throw new Error("replaced"); },
    });
    await expect(admitPersonaInboxBundle(authority, bundle())).resolves.toMatchObject({
      verdict: "accept",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned and forged authority handles", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store));
    for (const forged of [
      Object.freeze({}),
      Object.freeze({ ...authority }),
    ]) {
      await expect(admitPersonaInboxBundle(forged, bundle())).resolves.toMatchObject({
        verdict: "reject",
      });
    }
    expect(store.acquireCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxies and accessors without invoking them", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store));
    let traps = 0;
    const proxied = new Proxy(bundle(), {
      get() { traps += 1; throw new Error("trap"); },
      ownKeys() { traps += 1; throw new Error("trap"); },
    });
    const accessor = { ...bundle() };
    Object.defineProperty(accessor, "sender", {
      enumerable: true,
      get() { traps += 1; return SENDER; },
    });
    await expect(admitPersonaInboxBundle(authority, proxied)).resolves.toMatchObject({
      verdict: "reject",
    });
    await expect(admitPersonaInboxBundle(authority, accessor)).resolves.toMatchObject({
      verdict: "reject",
    });
    expect(traps).toBe(0);
    expect(store.acquireCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes an unknown durable commit absorbing", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    store.commitResult = "unknown";
    const authority = createPersonaInboxAdmissionAuthority(config(store));
    const first = await admitPersonaInboxBundle(authority, bundle());
    expect(first).toMatchObject({ verdict: "indeterminate" });
    if (first.verdict !== "indeterminate") throw new Error("expected indeterminate");
    expect(first.reconciliation_digest).toMatch(/^[0-9a-f]{64}$/u);
    expect(store.markCalls).toBe(1);
    await expect(admitPersonaInboxBundle(authority, bundle())).resolves.toEqual({
      verdict: "reject",
      reason_code: "marmot-keypackage-replayed",
    });
    expect(store.commitCalls).toBe(1);
  });
});
