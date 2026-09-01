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
  acquireResult: "acquired" | "replay" | "conflict" | "unavailable" | null = null;
  preserveExecutingOnMark = false;
  commitResult: "committed" | "conflict" | "unknown" = "committed";
  commitConflictWritesExact = false;
  acquireCalls = 0;
  commitCalls = 0;
  markCalls = 0;
  onLoad: (() => void) | null = null;
  onAcquire: (() => void) | null = null;
  onCommit: (() => void) | null = null;

  async load(key: string): Promise<DurableAuthorityRecord<O> | null> {
    const result = this.records.get(key) ?? null;
    this.onLoad?.();
    this.onLoad = null;
    return result;
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
      state: "executing",
      revision: 0,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
    }));
    this.onAcquire?.();
    this.onAcquire = null;
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
    if (this.commitResult === "conflict" && this.commitConflictWritesExact) {
      this.records.set(input.key, Object.freeze({
        state: "committed",
        revision: 1,
        binding_digest: input.binding_digest,
        execution_token: input.execution_token,
        output_digest: input.output_digest,
        output: input.output,
      }));
    }
    this.onCommit?.();
    this.onCommit = null;
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
    if (this.preserveExecutingOnMark) return "indeterminate";
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
    const unresolved = [left, right].filter((x) => x.verdict === "indeterminate");
    expect(unresolved).toHaveLength(1);
    expect(unresolved[0]).toMatchObject({ verdict: "indeterminate" });
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

  it("BLUE TEAM VALIDATION: synthetic/local rejects extended, wrong-prototype, and sparse closed inputs", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store));
    const extended = { ...bundle(), extra: true } as unknown as PersonaInboxBundle;
    const wrongPrototype = Object.assign(Object.create(null), bundle()) as PersonaInboxBundle;
    const sparseScopes = new Array<string>(1);
    const sparseAuthority = createPersonaInboxAdmissionAuthority(config(store, {
      load_inbox: async () => ({
        checkpoint: "inbox-checkpoint-1",
        recipient_nid: RECIPIENT_NID,
        consumed_key_packages: [],
        allowed_agent_scopes: sparseScopes,
      }),
    }));
    for (const [candidateAuthority, input] of [
      [authority, extended],
      [authority, wrongPrototype],
      [sparseAuthority, bundle()],
    ] as const) {
      const decision = await admitPersonaInboxBundle(candidateAuthority, input);
      expect(decision.verdict).not.toBe("accept");
    }
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
    const retry = await admitPersonaInboxBundle(authority, bundle());
    expect(retry).toEqual(first);
    expect(store.commitCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local returns stable indeterminate for an executing KeyPackage reservation", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    store.commitResult = "unknown";
    store.preserveExecutingOnMark = true;
    const authority = createPersonaInboxAdmissionAuthority(config(store));
    const first = await admitPersonaInboxBundle(authority, bundle());
    const retry = await admitPersonaInboxBundle(authority, bundle());
    expect(first).toMatchObject({ verdict: "indeterminate" });
    expect(retry).toEqual(first);
    expect(store.commitCalls).toBe(1);
  });

  it.each(["unavailable", "conflict"] as const)(
    "BLUE TEAM VALIDATION: synthetic/local returns stable indeterminate for %s acquire without a terminal",
    async (result) => {
      const store = new MemoryStore<PersonaInboxAdmission>();
      store.acquireResult = result;
      const authority = createPersonaInboxAdmissionAuthority(config(store));
      const first = await admitPersonaInboxBundle(authority, bundle());
      const retry = await admitPersonaInboxBundle(authority, bundle());
      expect(first).toMatchObject({ verdict: "indeterminate" });
      expect(retry).toEqual(first);
      expect(store.commitCalls).toBe(0);
    },
  );

  it("BLUE TEAM VALIDATION: synthetic/local reserves replay for committed, available, and binding-conflict consumption", async () => {
    for (const terminal of ["committed", "available", "binding-conflict"] as const) {
      const store = new MemoryStore<PersonaInboxAdmission>();
      const authority = createPersonaInboxAdmissionAuthority(config(store));
      expect((await admitPersonaInboxBundle(authority, bundle())).verdict).toBe("accept");
      const [key, current] = [...store.records.entries()][0] ?? [];
      if (key === undefined || current?.state !== "committed") throw new Error("missing committed fixture");
      if (terminal === "available") {
        store.records.set(key, Object.freeze({
          state: "available",
          revision: current.revision + 1,
          binding_digest: current.binding_digest,
          output: current.output,
        }));
      } else if (terminal === "binding-conflict") {
        store.records.set(key, Object.freeze({ ...current, binding_digest: "aa".repeat(32) }));
      }
      await expect(admitPersonaInboxBundle(authority, bundle())).resolves.toEqual({
        verdict: "reject", reason_code: "marmot-keypackage-replayed",
      });
      expect(store.commitCalls).toBe(1);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local treats a malformed durable terminal as indeterminate", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store));
    expect((await admitPersonaInboxBundle(authority, bundle())).verdict).toBe("accept");
    const [key, current] = [...store.records.entries()][0] ?? [];
    if (key === undefined || current === undefined) throw new Error("missing durable fixture");
    store.records.set(key, { ...current, extra: true } as unknown as DurableAuthorityRecord<PersonaInboxAdmission>);
    const first = await admitPersonaInboxBundle(authority, bundle());
    const retry = await admitPersonaInboxBundle(authority, bundle());
    expect(first).toMatchObject({ verdict: "indeterminate" });
    expect(retry).toEqual(first);
    expect(store.commitCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local revalidates a removed NID after durable load", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    let currentNid: string | null = RECIPIENT_NID;
    store.onLoad = () => { currentNid = null; };
    const authority = createPersonaInboxAdmissionAuthority(config(store, {
      load_inbox: async () => ({
        checkpoint: currentNid === null ? "inbox-checkpoint-2" : "inbox-checkpoint-1",
        recipient_nid: currentNid,
        consumed_key_packages: [],
        allowed_agent_scopes: ["marmot:first-contact"],
      }),
    }));
    await expect(admitPersonaInboxBundle(authority, bundle())).resolves.toEqual({
      verdict: "reject", reason_code: "marmot-private-inbox-nid-required",
    });
    expect(store.acquireCalls).toBe(0);
    expect(store.commitCalls).toBe(0);
  });

  it.each([
    ["agent scope removal", "scope"],
    ["external KeyPackage consumption", "consumed"],
    ["recipient NID removal", "nid"],
  ] as const)("BLUE TEAM VALIDATION: synthetic/local revalidates %s after durable acquire", async (_name, change) => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    let checkpoint = "inbox-checkpoint-1";
    let currentNid: string | null = RECIPIENT_NID;
    let scopes = ["marmot:first-contact"];
    let consumed: string[] = [];
    store.onAcquire = () => {
      checkpoint = "inbox-checkpoint-2";
      if (change === "scope") scopes = [];
      if (change === "consumed") consumed = [KEY_PACKAGE_REF];
      if (change === "nid") currentNid = null;
    };
    const authority = createPersonaInboxAdmissionAuthority(config(store, {
      load_inbox: async () => ({
        checkpoint,
        recipient_nid: currentNid,
        consumed_key_packages: consumed,
        allowed_agent_scopes: scopes,
      }),
    }));
    const input = change === "scope"
      ? bundle({ sender_kind: "agent", required_agent_scope: "marmot:first-contact" })
      : bundle();
    const decision = await admitPersonaInboxBundle(authority, input);
    expect(decision.verdict).not.toBe("accept");
    expect(store.commitCalls).toBe(0);
    expect(store.markCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local revalidates current NID after commit-conflict readback", async () => {
    const store = new MemoryStore<PersonaInboxAdmission>();
    store.commitResult = "conflict";
    store.commitConflictWritesExact = true;
    let currentNid: string | null = RECIPIENT_NID;
    let checkpoint = "inbox-checkpoint-1";
    store.onCommit = () => {
      store.onLoad = () => { currentNid = null; checkpoint = "inbox-checkpoint-2"; };
    };
    const authority = createPersonaInboxAdmissionAuthority(config(store, {
      load_inbox: async () => ({
        checkpoint,
        recipient_nid: currentNid,
        consumed_key_packages: [],
        allowed_agent_scopes: [],
      }),
    }));
    const decision = await admitPersonaInboxBundle(authority, bundle());
    expect(decision.verdict).not.toBe("accept");
    expect(decision).not.toEqual({
      verdict: "reject", reason_code: "marmot-keypackage-replayed",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local bounds KeyPackage, transition, scope, and aggregate operation input", async () => {
    const oversizedKeyPackage = new Uint8Array(1_048_577);
    oversizedKeyPackage[0] = 1;
    const oversizedTransition = new Uint8Array(1_048_577);
    oversizedTransition[0] = 1;
    const cases = [
      bundle({
        key_package_bytes: oversizedKeyPackage,
        key_package_ref: createHash("sha256").update(oversizedKeyPackage).digest("hex"),
      }),
      bundle({ group_transition: oversizedTransition }),
      bundle({
        sender_kind: "agent",
        required_agent_scope: "s".repeat(257),
      }),
    ];
    for (const input of cases) {
      const store = new MemoryStore<PersonaInboxAdmission>();
      const authority = createPersonaInboxAdmissionAuthority(config(store, {
        load_inbox: async () => ({
          checkpoint: "inbox-checkpoint-1",
          recipient_nid: RECIPIENT_NID,
          consumed_key_packages: [],
          allowed_agent_scopes: ["s".repeat(257)],
        }),
      }));
      const decision = await admitPersonaInboxBundle(authority, input);
      expect(decision.verdict).not.toBe("accept");
      expect(store.acquireCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local bounds authenticated inbox collections", async () => {
    const hexRef = (value: number) => value.toString(16).padStart(64, "0");
    for (const state of [
      {
        checkpoint: "inbox-checkpoint-1",
        recipient_nid: RECIPIENT_NID,
        consumed_key_packages: Array.from({ length: 1_025 }, (_, index) => hexRef(index + 1)),
        allowed_agent_scopes: [],
      },
      {
        checkpoint: "inbox-checkpoint-1",
        recipient_nid: RECIPIENT_NID,
        consumed_key_packages: [],
        allowed_agent_scopes: Array.from({ length: 257 }, (_, index) => `scope-${index}`),
      },
    ]) {
      const store = new MemoryStore<PersonaInboxAdmission>();
      const authority = createPersonaInboxAdmissionAuthority(config(store, {
        load_inbox: async () => state,
      }));
      const decision = await admitPersonaInboxBundle(authority, bundle());
      expect(decision.verdict).not.toBe("accept");
      expect(store.acquireCalls).toBe(0);
    }
  });

  it("accepts exact bounded inbox collection and byte limits", async () => {
    const keyPackage = new Uint8Array(1_048_576);
    keyPackage[0] = 1;
    const transition = new Uint8Array(1_048_576);
    transition[0] = 2;
    const store = new MemoryStore<PersonaInboxAdmission>();
    const authority = createPersonaInboxAdmissionAuthority(config(store, {
      load_inbox: async () => ({
        checkpoint: "c".repeat(256),
        recipient_nid: RECIPIENT_NID,
        consumed_key_packages: Array.from(
          { length: 1_024 },
          (_, index) => (index + 1).toString(16).padStart(64, "0"),
        ),
        allowed_agent_scopes: Array.from({ length: 256 }, (_, index) => `scope-${index}`),
      }),
    }));
    await expect(admitPersonaInboxBundle(authority, bundle({
      key_package_bytes: keyPackage,
      key_package_ref: createHash("sha256").update(keyPackage).digest("hex"),
      group_transition: transition,
    }))).resolves.toMatchObject({ verdict: "accept" });
  });
});
