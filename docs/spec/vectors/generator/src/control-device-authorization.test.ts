import { describe, expect, it } from "vitest";
import {
  createControlDeviceAuthorizationAuthority,
  createControlDeviceTransaction,
  pollControlDeviceAuthorization,
  type ControlDeviceAuthorizationAuthorityConfig,
  type ControlDeviceTransactionRequest,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
} from "./control-device-authorization.js";

type DeviceState = Readonly<{
  transaction_id: string;
  state: "pending" | "approved" | "denied" | "expired";
}>;

type MutableDeviceConfig = {
  -readonly [K in keyof ControlDeviceAuthorizationAuthorityConfig]:
    ControlDeviceAuthorizationAuthorityConfig[K];
};

class DeviceStore implements DurableAuthorityStore<DeviceState> {
  readonly records = new Map<string, DurableAuthorityRecord<DeviceState>>();
  readonly calls = { load: 0, acquire: 0, compareAndSwap: 0, commit: 0, mark: 0 };
  nextCompare: "committed" | "conflict" | "unknown" | null = null;
  nextAcquire: "acquired" | "replay" | "conflict" | "unavailable" | null = null;
  nextCommit: "committed" | "conflict" | "unknown" | null = null;
  nextMark: "indeterminate" | "conflict" | "unknown" | null = null;

  get output(): DeviceState {
    const record = [...this.records.values()].at(-1);
    if (record === undefined || !("output" in record)) throw new Error("no synthetic output");
    return record.output;
  }

  async load(key: string): Promise<DurableAuthorityRecord<DeviceState> | null> {
    this.calls.load += 1;
    return this.records.get(key) ?? null;
  }

  async acquire(input: Readonly<{
    key: string;
    expected_revision: number | null;
    binding_digest: string;
    execution_token: string;
  }>): Promise<"acquired" | "replay" | "conflict" | "unavailable"> {
    this.calls.acquire += 1;
    if (this.nextAcquire !== null) {
      const result = this.nextAcquire;
      this.nextAcquire = null;
      return result;
    }
    const current = this.records.get(input.key);
    if (current?.state === "executing"
      && current.binding_digest === input.binding_digest
      && current.execution_token === input.execution_token) return "replay";
    if (current?.state !== "available" || current.revision !== input.expected_revision
      || current.binding_digest !== input.binding_digest) return "conflict";
    this.records.set(input.key, Object.freeze({
      state: "executing" as const,
      revision: current.revision + 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
    }));
    return "acquired";
  }

  async compareAndSwap(input: Readonly<{
    key: string;
    expected_revision: number | null;
    next: DurableAuthorityRecord<DeviceState>;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.calls.compareAndSwap += 1;
    if (this.nextCompare !== null) {
      const result = this.nextCompare;
      this.nextCompare = null;
      return result;
    }
    const current = this.records.get(input.key);
    if ((current?.revision ?? null) !== input.expected_revision) return "conflict";
    this.records.set(input.key, input.next);
    return "committed";
  }

  async commit(input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    output_digest: string;
    output: DeviceState;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.calls.commit += 1;
    if (this.nextCommit !== null) {
      const result = this.nextCommit;
      this.nextCommit = null;
      return result;
    }
    const current = this.records.get(input.key);
    if (current?.state !== "executing"
      || current.binding_digest !== input.binding_digest
      || current.execution_token !== input.execution_token) return "conflict";
    this.records.set(input.key, Object.freeze({
      state: "committed" as const,
      revision: current.revision + 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      output_digest: input.output_digest,
      output: input.output,
    }));
    return "committed";
  }

  async markIndeterminate(input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    reconciliation_digest: string;
  }>): Promise<"indeterminate" | "conflict" | "unknown"> {
    this.calls.mark += 1;
    if (this.nextMark !== null) {
      const result = this.nextMark;
      this.nextMark = null;
      return result;
    }
    const current = this.records.get(input.key);
    if (current?.state !== "executing"
      || current.binding_digest !== input.binding_digest
      || current.execution_token !== input.execution_token) return "conflict";
    this.records.set(input.key, Object.freeze({
      state: "indeterminate" as const,
      revision: current.revision + 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      reconciliation_digest: input.reconciliation_digest,
    }));
    return "indeterminate";
  }

  async approve(transactionId: string): Promise<void> {
    const current = this.records.get(transactionId);
    if (current?.state !== "available") throw new Error("synthetic transaction unavailable");
    const result = await this.compareAndSwap({
      key: transactionId,
      expected_revision: current.revision,
      next: Object.freeze({
        ...current,
        revision: current.revision + 1,
        output: Object.freeze({ ...current.output, state: "approved" as const }),
      }),
    });
    if (result !== "committed") throw new Error("synthetic approval failed");
  }
}

function sequenceRandom(): (length: number) => Uint8Array {
  let seed = 1;
  return (length) => Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff, seed++);
}

function setup(overrides: Partial<ControlDeviceAuthorizationAuthorityConfig> = {}) {
  let now = 1_900_000_000;
  const store = (overrides.store as DeviceStore | undefined) ?? new DeviceStore();
  const config: MutableDeviceConfig = {
    authority_id: "synthetic-local-control-device-authority-A",
    trusted_now: () => now,
    random_bytes: sequenceRandom(),
    store,
    ...overrides,
  };
  return {
    authority: createControlDeviceAuthorizationAuthority(config),
    config,
    store,
    now: () => now,
    setNow: (value: number) => { now = value; },
  };
}

function request(
  overrides: Partial<ControlDeviceTransactionRequest> = {},
): ControlDeviceTransactionRequest {
  return {
    client_id: "synthetic-local-nip46-client",
    persona: "synthetic-local-persona",
    verification_uri: "https://device.invalid/activate",
    display_fingerprint: "SYNTHETIC-CLIENT-FINGERPRINT",
    polling_interval_seconds: 5,
    expires_in_seconds: 600,
    failure_budget: 5,
    ...overrides,
  };
}

async function transaction(value = setup()) {
  const created = await createControlDeviceTransaction(value.authority, request());
  expect(created.verdict).toBe("accept");
  if (created.verdict !== "accept") throw new Error("synthetic transaction rejected");
  return { ...value, tx: created.output };
}

function correctPoll(tx: Awaited<ReturnType<typeof transaction>>["tx"]) {
  return {
    device_code: tx.device_code,
    user_code: tx.user_code,
    displayed_fingerprint: "SYNTHETIC-CLIENT-FINGERPRINT",
  };
}

function badPoll(tx: Awaited<ReturnType<typeof transaction>>["tx"]) {
  return { ...correctPoll(tx), user_code: "ZZZZ-ZZZZ" };
}

describe("Control device authorization authority", () => {
  it("creates a durable high-entropy transaction and polls authoritative approval", async () => {
    const lengths: number[] = [];
    const random = sequenceRandom();
    const value = setup({ random_bytes: (length) => {
      lengths.push(length);
      return random(length);
    } });
    const created = await transaction(value);
    expect(lengths).toEqual([16, 5]);
    expect(created.tx.device_code).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(created.tx.user_code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(created.tx).toEqual({
      transaction_id: expect.stringMatching(/^[0-9a-f]{64}$/),
      device_code: created.tx.device_code,
      user_code: created.tx.user_code,
      verification_uri: "https://device.invalid/activate",
      expires_at: value.now() + 600,
      interval_seconds: 5,
    });
    expect(JSON.stringify(created.store.output)).not.toContain(created.tx.device_code);
    expect(JSON.stringify(created.store.output)).not.toContain(created.tx.user_code);

    await expect(pollControlDeviceAuthorization(
      created.authority,
      correctPoll(created.tx),
    )).resolves.toEqual({
      verdict: "accept",
      output: { transaction_id: created.tx.transaction_id, state: "pending" },
    });
    value.setNow(value.now() + 5);
    await created.store.approve(created.tx.transaction_id);
    await expect(pollControlDeviceAuthorization(
      created.authority,
      correctPoll(created.tx),
    )).resolves.toEqual({
      verdict: "accept",
      output: { transaction_id: created.tx.transaction_id, state: "approved" },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local retries deterministic code collisions and exhausts boundedly", async () => {
    // Fixed local bytes model only a deterministic collision and are not deployable entropy.
    let calls = 0;
    const value = setup({ random_bytes: (length) => {
      calls += 1;
      return new Uint8Array(length).fill(7);
    } });
    expect((await createControlDeviceTransaction(value.authority, request())).verdict).toBe("accept");
    await expect(createControlDeviceTransaction(value.authority, request())).resolves.toEqual({
      verdict: "reject",
      reason_code: "control-device-code-invalid",
    });
    expect(calls).toBe(18);
    expect(value.store.records.size).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects malformed and unknown codes without state change", async () => {
    const value = await transaction();
    const before = value.store.records.get(value.tx.transaction_id);
    await expect(pollControlDeviceAuthorization(value.authority, {
      ...correctPoll(value.tx),
      device_code: "not-a-device-code",
    })).resolves.toEqual({ verdict: "reject", reason_code: "control-device-code-invalid" });
    await expect(pollControlDeviceAuthorization(value.authority, {
      ...correctPoll(value.tx),
      device_code: "AAAAAAAAAAAAAAAAAAAAAA",
    })).resolves.toEqual({ verdict: "reject", reason_code: "control-device-code-invalid" });
    expect(value.store.records.get(value.tx.transaction_id)).toBe(before);
  });

  it("BLUE TEAM VALIDATION: synthetic/local atomically denies a display mismatch", async () => {
    const value = await transaction();
    const poll = { ...correctPoll(value.tx), displayed_fingerprint: "OTHER-DISPLAY" };
    await expect(pollControlDeviceAuthorization(value.authority, poll)).resolves.toEqual({
      verdict: "reject",
      reason_code: "control-device-code-display-mismatch",
    });
    expect((await value.store.load(value.tx.transaction_id))?.state).toBe("committed");
    expect(value.store.output.state).toBe("denied");
    const commitCalls = value.store.calls.commit;
    await expect(pollControlDeviceAuthorization(value.authority, poll)).resolves.toEqual({
      verdict: "reject",
      reason_code: "control-device-code-display-mismatch",
    });
    expect(value.store.calls.commit).toBe(commitCalls);
  });

  it("BLUE TEAM VALIDATION: synthetic/local applies RFC 8628 interval and slow-down state atomically", async () => {
    const value = await transaction();
    expect((await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx))).verdict)
      .toBe("accept");
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toEqual({
        verdict: "reject",
        reason_code: "control-device-code-rate-limited",
      });
    expect((value.store.output as DeviceState & { interval_seconds: number }).interval_seconds).toBe(10);
    value.setNow(value.now() + 10);
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toMatchObject({ verdict: "accept", output: { state: "pending" } });
  });

  it("BLUE TEAM VALIDATION: synthetic/local atomically invalidates the fifth bad code", async () => {
    const value = await transaction();
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      await expect(pollControlDeviceAuthorization(value.authority, badPoll(value.tx)))
        .resolves.toMatchObject({
          verdict: "reject",
          reason_code: "control-device-code-invalid",
        });
    }
    expect((await value.store.load(value.tx.transaction_id))?.state).toBe("committed");
    expect(value.store.output.state).toBe("denied");
    const compareCalls = value.store.calls.compareAndSwap;
    await expect(pollControlDeviceAuthorization(value.authority, badPoll(value.tx)))
      .resolves.toMatchObject({
        verdict: "reject",
        reason_code: "control-device-code-invalid",
      });
    expect(value.store.calls.compareAndSwap).toBe(compareCalls);
  });

  it("BLUE TEAM VALIDATION: synthetic/local expires atomically and never reopens", async () => {
    const value = await transaction();
    value.setNow(value.tx.expires_at);
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toEqual({ verdict: "reject", reason_code: "control-device-code-invalid" });
    expect(value.store.output.state).toBe("expired");
    const acquired = value.store.calls.acquire;
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toEqual({ verdict: "reject", reason_code: "control-device-code-invalid" });
    expect(value.store.calls.acquire).toBe(acquired);
  });

  it("returns the exact committed approval on retry without another transition", async () => {
    const value = await transaction();
    await value.store.approve(value.tx.transaction_id);
    const first = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    const transitions = { ...value.store.calls };
    const retry = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(retry).toEqual(first);
    expect(value.store.calls.acquire).toBe(transitions.acquire);
    expect(value.store.calls.commit).toBe(transitions.commit);
    expect(value.store.calls.compareAndSwap).toBe(transitions.compareAndSwap);
  });

  it("BLUE TEAM VALIDATION: synthetic/local fails closed on a concurrent CAS conflict", async () => {
    const value = await transaction();
    value.store.nextCompare = "conflict";
    const decision = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(decision).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(value.store.output.state).toBe("pending");
    expect(value.store.calls.compareAndSwap).toBe(2);
  });

  it("BLUE TEAM VALIDATION: synthetic/local burns unknown and executing terminal outcomes without repeat", async () => {
    const value = await transaction();
    await value.store.approve(value.tx.transaction_id);
    value.store.nextCommit = "unknown";
    const first = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(first).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect((await value.store.load(value.tx.transaction_id))?.state).toBe("indeterminate");
    const commits = value.store.calls.commit;
    const retry = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(retry).toEqual(first);
    expect(value.store.calls.commit).toBe(commits);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects mutation while retaining immutable captured inputs", async () => {
    const value = setup();
    const mutable = request() as { -readonly [K in keyof ControlDeviceTransactionRequest]:
      ControlDeviceTransactionRequest[K] };
    const pending = createControlDeviceTransaction(value.authority, mutable);
    mutable.client_id = "mutated-client";
    mutable.display_fingerprint = "MUTATED-DISPLAY";
    const created = await pending;
    expect(created.verdict).toBe("accept");
    if (created.verdict !== "accept") throw new Error("synthetic transaction rejected");
    const stored = value.store.output as DeviceState & {
      client_id: string;
      display_fingerprint: string;
    };
    expect(stored.client_id).toBe("synthetic-local-nip46-client");
    expect(stored.display_fingerprint).toBe("SYNTHETIC-CLIENT-FINGERPRINT");
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxy and accessor inputs without traps", async () => {
    const value = await transaction();
    let proxyTraps = 0;
    const proxy = new Proxy(correctPoll(value.tx), {
      get() { proxyTraps += 1; throw new Error("synthetic proxy trap"); },
      ownKeys() { proxyTraps += 1; throw new Error("synthetic proxy trap"); },
      getOwnPropertyDescriptor() { proxyTraps += 1; throw new Error("synthetic proxy trap"); },
    });
    await expect(pollControlDeviceAuthorization(value.authority, proxy)).resolves.toEqual({
      verdict: "reject",
      reason_code: "control-device-code-invalid",
    });
    expect(proxyTraps).toBe(0);

    let accessorReads = 0;
    const accessor = { ...correctPoll(value.tx) };
    Object.defineProperty(accessor, "user_code", {
      enumerable: true,
      get() { accessorReads += 1; return value.tx.user_code; },
    });
    await expect(pollControlDeviceAuthorization(value.authority, accessor)).resolves.toEqual({
      verdict: "reject",
      reason_code: "control-device-code-invalid",
    });
    expect(accessorReads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects config proxies and captures callback identities once", async () => {
    let proxyTraps = 0;
    const proxy = new Proxy({} as ControlDeviceAuthorizationAuthorityConfig, {
      get() { proxyTraps += 1; throw new Error("synthetic config trap"); },
      ownKeys() { proxyTraps += 1; throw new Error("synthetic config trap"); },
      getOwnPropertyDescriptor() { proxyTraps += 1; throw new Error("synthetic config trap"); },
    });
    expect(() => createControlDeviceAuthorizationAuthority(proxy)).toThrow(/config/i);
    expect(proxyTraps).toBe(0);

    const value = setup();
    const originalStore = value.store;
    value.config.random_bytes = (() => { throw new Error("substituted entropy"); }) as never;
    value.config.store = new DeviceStore();
    await expect(createControlDeviceTransaction(value.authority, request()))
      .resolves.toMatchObject({ verdict: "accept" });
    expect(originalStore.records.size).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxied callbacks without invoking traps", () => {
    let callbackTraps = 0;
    const proxiedClock = new Proxy(() => 1_900_000_000, {
      apply() { callbackTraps += 1; throw new Error("synthetic clock trap"); },
      get() { callbackTraps += 1; throw new Error("synthetic clock trap"); },
    });
    expect(() => createControlDeviceAuthorizationAuthority({
      authority_id: "synthetic-local-proxied-callback-authority",
      trusted_now: proxiedClock,
      random_bytes: sequenceRandom(),
      store: new DeviceStore(),
    })).toThrow(/config/i);
    expect(callbackTraps).toBe(0);

    let methodTraps = 0;
    const store = new DeviceStore();
    const proxiedLoad = new Proxy(store.load, {
      apply() { methodTraps += 1; throw new Error("synthetic store trap"); },
      get() { methodTraps += 1; throw new Error("synthetic store trap"); },
    });
    Object.defineProperty(store, "load", { value: proxiedLoad, enumerable: true });
    expect(() => createControlDeviceAuthorizationAuthority({
      authority_id: "synthetic-local-proxied-store-method-authority",
      trusted_now: () => 1_900_000_000,
      random_bytes: sequenceRandom(),
      store,
    })).toThrow(/store/i);
    expect(methodTraps).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cross-authority code use", async () => {
    const shared = new DeviceStore();
    const first = setup({ store: shared });
    const created = await transaction(first);
    const second = setup({
      authority_id: "synthetic-local-control-device-authority-B",
      store: shared,
    });
    await expect(pollControlDeviceAuthorization(second.authority, correctPoll(created.tx)))
      .resolves.toEqual({ verdict: "reject", reason_code: "control-device-code-invalid" });
    expect(shared.output.state).toBe("pending");
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects invalid entropy and malformed durable records", async () => {
    const badEntropy = setup({ random_bytes: (length) => new Uint8Array(length - 1) });
    await expect(createControlDeviceTransaction(badEntropy.authority, request())).resolves.toEqual({
      verdict: "reject",
      reason_code: "control-device-code-invalid",
    });

    const value = await transaction();
    const current = value.store.records.get(value.tx.transaction_id);
    if (current?.state !== "available") throw new Error("synthetic record unavailable");
    value.store.records.set(value.tx.transaction_id, {
      ...current,
      output: { ...current.output, injected: true } as DeviceState,
    });
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toEqual({
        verdict: "indeterminate",
        reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
  });
});
