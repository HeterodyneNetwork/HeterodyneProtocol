import { describe, expect, it } from "vitest";
import {
  createControlDeviceAuthorizationAuthority,
  createControlDeviceTransaction,
  pollControlDeviceAuthorization,
  type ControlDeviceAuthorizationAuthorityConfig,
  type ControlDeviceTransactionRequest,
} from "./control-device-authorization.js";
import {
  authorityBindingDigest,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
} from "./security-authority-support.js";

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
  markDigestOverride: string | null = null;
  persistUnknownCompare = false;
  failReadbackAfterCompare = false;
  loadFailures = 0;
  commitOverride: ((input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    output_digest: string;
    output: DeviceState;
  }>, current: Extract<DurableAuthorityRecord<DeviceState>, { state: "executing" }>) =>
    DurableAuthorityRecord<DeviceState>) | null = null;

  get output(): DeviceState {
    const record = [...this.records.values()].at(-1);
    if (record === undefined || !("output" in record)) throw new Error("no synthetic output");
    return record.output;
  }

  async load(key: string): Promise<DurableAuthorityRecord<DeviceState> | null> {
    this.calls.load += 1;
    if (this.loadFailures > 0) {
      this.loadFailures -= 1;
      throw new Error("synthetic local durable readback unavailable");
    }
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
      if (result === "unknown" && this.persistUnknownCompare) {
        this.records.set(input.key, input.next);
      }
      return result;
    }
    const current = this.records.get(input.key);
    if ((current?.revision ?? null) !== input.expected_revision) return "conflict";
    this.records.set(input.key, input.next);
    if (this.failReadbackAfterCompare) {
      this.failReadbackAfterCompare = false;
      this.loadFailures += 1;
    }
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
    if (this.commitOverride !== null) {
      this.records.set(input.key, this.commitOverride(input, current));
      return "committed";
    }
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
      reconciliation_digest: this.markDigestOverride ?? input.reconciliation_digest,
    }));
    return "indeterminate";
  }

  async approve(transactionId: string): Promise<void> {
    const current = this.records.get(transactionId);
    if (current?.state !== "available") throw new Error("synthetic transaction unavailable");
    const output = Object.freeze({ ...current.output, state: "approved" as const });
    const result = await this.compareAndSwap({
      key: transactionId,
      expected_revision: current.revision,
      next: Object.freeze({
        ...current,
        revision: current.revision + 1,
        binding_digest: authorityBindingDigest(
          "heterodyne-control-device-state-v1",
          output as Readonly<Record<string, unknown>>,
        ),
        output,
      }),
    });
    if (result !== "committed") throw new Error("synthetic approval failed");
  }
}

function testPollDigest(
  authorityId: string,
  poll: Readonly<{ device_code: string; user_code: string; displayed_fingerprint: string }>,
): string {
  return authorityBindingDigest("heterodyne-control-device-poll-v1", {
    authority_id: authorityId,
    device_code: poll.device_code,
    displayed_fingerprint: poll.displayed_fingerprint,
    user_code: poll.user_code,
  });
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

function installCommittedTerminal(
  value: Awaited<ReturnType<typeof transaction>>,
  poll: ReturnType<typeof correctPoll>,
  overrides: Readonly<Record<string, unknown>>,
  priorOverrides?: Readonly<Record<string, unknown>>,
): void {
  const current = value.store.records.get(value.tx.transaction_id);
  if (current?.state !== "available") throw new Error("synthetic record unavailable");
  const output = Object.freeze({
    ...current.output as DeviceState & Readonly<Record<string, unknown>>,
    terminal_poll_digest: testPollDigest(
      "synthetic-local-control-device-authority-A",
      poll,
    ),
    ...overrides,
  }) as DeviceState & Readonly<Record<string, unknown>>;
  const outputDigest = authorityBindingDigest(
    "heterodyne-control-device-output-v1",
    output,
  );
  const bindingDigest = priorOverrides === undefined ? current.binding_digest
    : authorityBindingDigest("heterodyne-control-device-state-v1", {
      ...output,
      terminal_reason: null,
      terminal_poll_digest: null,
      ...priorOverrides,
    });
  value.store.records.set(value.tx.transaction_id, Object.freeze({
    state: "committed" as const,
    revision: current.revision + 2,
    binding_digest: bindingDigest,
    execution_token: authorityBindingDigest(
      "heterodyne-control-device-execution-v1",
      {
        authority_id: "synthetic-local-control-device-authority-A",
        transaction_id: value.tx.transaction_id,
        expected_revision: current.revision,
        prior_binding_digest: bindingDigest,
        request_digest: output.terminal_poll_digest,
        next_output_digest: outputDigest,
        terminal_state: output.state,
        terminal_reason: output.terminal_reason,
        terminal_poll_digest: output.terminal_poll_digest,
      },
    ),
    output_digest: outputDigest,
    output: output as DeviceState,
  }));
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

    value.setNow(value.now() + 5);
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
    value.setNow(value.now() + 5);
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

  it("BLUE TEAM VALIDATION: synthetic/local enforces the stored interval before exposing approval", async () => {
    const value = await transaction();
    value.setNow(value.now() + 5);
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toMatchObject({ verdict: "accept", output: { state: "pending" } });
    await value.store.approve(value.tx.transaction_id);
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toEqual({
        verdict: "reject",
        reason_code: "control-device-code-rate-limited",
      });
    value.setNow(value.now() + 10);
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toMatchObject({ verdict: "accept", output: { state: "approved" } });
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
    value.setNow(value.now() + 5);
    const first = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    const transitions = { ...value.store.calls };
    const retry = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(retry).toEqual(first);
    expect(value.store.calls.acquire).toBe(transitions.acquire);
    expect(value.store.calls.commit).toBe(transitions.commit);
    expect(value.store.calls.compareAndSwap).toBe(transitions.compareAndSwap);
  });

  it("BLUE TEAM VALIDATION: synthetic/local never exposes approval from a substituted denied terminal readback", async () => {
    const value = await transaction();
    await value.store.approve(value.tx.transaction_id);
    value.setNow(value.now() + 5);
    value.store.commitOverride = (input, executing) => {
      const attempted = input.output as DeviceState & Readonly<Record<string, unknown>>;
      const denied = Object.freeze({
        ...attempted,
        state: "denied" as const,
        terminal_reason: "control-device-code-display-mismatch",
      });
      const outputDigest = authorityBindingDigest(
        "heterodyne-control-device-output-v1",
        denied,
      );
      return Object.freeze({
        state: "committed" as const,
        revision: executing.revision + 1,
        binding_digest: input.binding_digest,
        execution_token: authorityBindingDigest(
          "heterodyne-control-device-execution-v1",
          {
            authority_id: "synthetic-local-control-device-authority-A",
            transaction_id: value.tx.transaction_id,
            expected_revision: executing.revision - 1,
            prior_binding_digest: input.binding_digest,
            request_digest:
              (denied as Readonly<Record<string, unknown>>).terminal_poll_digest,
            next_output_digest: outputDigest,
            terminal_state: "denied",
            terminal_reason: "control-device-code-display-mismatch",
            terminal_poll_digest:
              (denied as Readonly<Record<string, unknown>>).terminal_poll_digest,
          },
        ),
        output_digest: outputDigest,
        output: denied,
      });
    };
    const decision = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(decision).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(value.store.output.state).toBe("denied");
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a self-consistent approved terminal at the failure threshold", async () => {
    const value = await transaction();
    const poll = correctPoll(value.tx);
    installCommittedTerminal(value, poll, {
      state: "approved",
      failed_guesses: 5,
      terminal_reason: null,
    }, {
      state: "approved",
      failed_guesses: 5,
    });
    await expect(pollControlDeviceAuthorization(value.authority, poll)).resolves.toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(value.store.calls.acquire).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects contradictory terminal failure invariants", async () => {
    const cases = [
      {
        pollFingerprint: "OTHER-DISPLAY",
        output: {
          state: "denied",
          failed_guesses: 5,
          terminal_reason: "control-device-code-display-mismatch",
        },
        prior: { state: "pending", failed_guesses: 5 },
      },
      {
        pollFingerprint: "SYNTHETIC-CLIENT-FINGERPRINT",
        output: {
          state: "expired",
          failed_guesses: 5,
          terminal_reason: "control-device-code-invalid",
        },
        prior: { state: "pending", failed_guesses: 5 },
      },
      {
        pollFingerprint: "SYNTHETIC-CLIENT-FINGERPRINT",
        output: {
          state: "denied",
          failed_guesses: 4,
          terminal_reason: "control-device-code-invalid",
        },
        prior: { state: "pending", failed_guesses: 3 },
      },
    ] as const;
    for (const candidate of cases) {
      const value = await transaction();
      const poll = {
        ...correctPoll(value.tx),
        displayed_fingerprint: candidate.pollFingerprint,
      };
      installCommittedTerminal(value, poll, candidate.output, candidate.prior);
      await expect(pollControlDeviceAuthorization(value.authority, poll)).resolves.toEqual({
        verdict: "indeterminate",
        reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
      expect(value.store.calls.acquire).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local fails closed on a concurrent CAS conflict", async () => {
    const value = await transaction();
    value.store.nextCompare = "conflict";
    const decision = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(decision).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect((await value.store.load(value.tx.transaction_id))?.state).toBe("indeterminate");
    expect(value.store.calls.compareAndSwap).toBe(2);
  });

  it("BLUE TEAM VALIDATION: synthetic/local absorbs an ambiguous nonterminal CAS without repeating it", async () => {
    const value = await transaction();
    value.setNow(value.now() + 5);
    value.store.nextCompare = "unknown";
    const first = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(first).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect((await value.store.load(value.tx.transaction_id))?.state)
      .toMatch(/^(executing|indeterminate)$/);
    const compareCalls = value.store.calls.compareAndSwap;
    const retry = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(retry).toEqual(first);
    expect(value.store.calls.compareAndSwap).toBe(compareCalls);
  });

  it("BLUE TEAM VALIDATION: synthetic/local accepts only an exact proposed nonterminal CAS after unknown", async () => {
    const value = await transaction();
    value.setNow(value.now() + 5);
    value.store.persistUnknownCompare = true;
    value.store.nextCompare = "unknown";
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toEqual({
        verdict: "accept",
        output: { transaction_id: value.tx.transaction_id, state: "pending" },
      });
    expect((await value.store.load(value.tx.transaction_id))?.state).toBe("available");
  });

  it("BLUE TEAM VALIDATION: synthetic/local absorbs an unreadable nonterminal CAS readback", async () => {
    const value = await transaction();
    value.setNow(value.now() + 5);
    value.store.failReadbackAfterCompare = true;
    const first = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(first).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect((await value.store.load(value.tx.transaction_id))?.state).toBe("indeterminate");
    const compareCalls = value.store.calls.compareAndSwap;
    const retry = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(retry).toEqual(first);
    expect(value.store.calls.compareAndSwap).toBe(compareCalls);
  });

  it("BLUE TEAM VALIDATION: synthetic/local burns unknown and executing terminal outcomes without repeat", async () => {
    const value = await transaction();
    await value.store.approve(value.tx.transaction_id);
    value.setNow(value.now() + 5);
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

  it("BLUE TEAM VALIDATION: synthetic/local ignores changing store-selected reconciliation digests on exact retry", async () => {
    const value = await transaction();
    await value.store.approve(value.tx.transaction_id);
    value.setNow(value.now() + 5);
    value.store.nextCommit = "unknown";
    value.store.markDigestOverride = "c".repeat(64);
    const first = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    const durable = value.store.records.get(value.tx.transaction_id);
    if (durable?.state !== "indeterminate") {
      throw new Error("synthetic transition did not enter the indeterminate fence");
    }
    value.store.records.set(value.tx.transaction_id, Object.freeze({
      ...durable,
      reconciliation_digest: "d".repeat(64),
    }));
    const retry = await pollControlDeviceAuthorization(value.authority, correctPoll(value.tx));
    expect(retry).toEqual(first);
    expect(first).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    if (first.verdict !== "indeterminate") throw new Error("synthetic transition did not fail closed");
    expect(first.reconciliation_digest).not.toBe("c".repeat(64));
    expect(first.reconciliation_digest).not.toBe("d".repeat(64));
    expect(value.store.calls.commit).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local binds reconciliation to the exact poll request", async () => {
    const firstValue = await transaction();
    const secondValue = await transaction();
    firstValue.store.nextCompare = "conflict";
    secondValue.store.nextCompare = "conflict";
    const first = await pollControlDeviceAuthorization(
      firstValue.authority,
      correctPoll(firstValue.tx),
    );
    const second = await pollControlDeviceAuthorization(secondValue.authority, {
      ...correctPoll(secondValue.tx),
      displayed_fingerprint: "OTHER-DISPLAY",
    });
    expect(first).toMatchObject({ verdict: "indeterminate" });
    expect(second).toMatchObject({ verdict: "indeterminate" });
    if (first.verdict !== "indeterminate" || second.verdict !== "indeterminate") {
      throw new Error("synthetic transitions did not fail closed");
    }
    expect(first.reconciliation_digest).not.toBe(second.reconciliation_digest);
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
      client_fingerprint: string;
    };
    expect(stored.client_id).toBe("synthetic-local-nip46-client");
    expect(stored.client_fingerprint).toBe("SYNTHETIC-CLIENT-FINGERPRINT");
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
    const malformed = {
      ...current.output as DeviceState & Readonly<Record<string, unknown>>,
      client_id: 7,
    };
    value.store.records.set(value.tx.transaction_id, {
      ...current,
      binding_digest: authorityBindingDigest(
        "heterodyne-control-device-state-v1",
        malformed,
      ),
      output: malformed as unknown as DeviceState,
    });
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toEqual({
        verdict: "indeterminate",
        reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      });

    const invalidUri = {
      ...current.output as DeviceState & Readonly<Record<string, unknown>>,
      verification_uri: "not-an-https-verification-uri",
    };
    value.store.records.set(value.tx.transaction_id, {
      ...current,
      binding_digest: authorityBindingDigest(
        "heterodyne-control-device-state-v1",
        invalidUri,
      ),
      output: invalidUri as unknown as DeviceState,
    });
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toMatchObject({ verdict: "indeterminate" });

    const earlyInitialPoll = {
      ...current.output as DeviceState & Readonly<Record<string, unknown>>,
      next_poll_at:
        (current.output as DeviceState & Readonly<Record<string, unknown>>).issued_at,
    };
    value.store.records.set(value.tx.transaction_id, {
      ...current,
      binding_digest: authorityBindingDigest(
        "heterodyne-control-device-state-v1",
        earlyInitialPoll,
      ),
      output: earlyInitialPoll as unknown as DeviceState,
    });
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toMatchObject({ verdict: "indeterminate" });

    const nullPrototype = Object.assign(Object.create(null), current.output) as DeviceState;
    value.store.records.set(value.tx.transaction_id, { ...current, output: nullPrototype });
    await expect(pollControlDeviceAuthorization(value.authority, correctPoll(value.tx)))
      .resolves.toMatchObject({ verdict: "indeterminate" });

    const poll = correctPoll(value.tx);
    const pendingTerminal = Object.freeze({
      ...current.output as DeviceState & Readonly<Record<string, unknown>>,
      terminal_poll_digest: testPollDigest(
        "synthetic-local-control-device-authority-A",
        poll,
      ),
    });
    const pendingOutputDigest = authorityBindingDigest(
      "heterodyne-control-device-output-v1",
      pendingTerminal,
    );
    value.store.records.set(value.tx.transaction_id, Object.freeze({
      state: "committed" as const,
      revision: 2,
      binding_digest: current.binding_digest,
      execution_token: authorityBindingDigest(
        "heterodyne-control-device-execution-v1",
        {
          authority_id: "synthetic-local-control-device-authority-A",
          transaction_id: value.tx.transaction_id,
          expected_revision: 0,
          prior_binding_digest: current.binding_digest,
          request_digest:
            (pendingTerminal as Readonly<Record<string, unknown>>).terminal_poll_digest,
          next_output_digest: pendingOutputDigest,
          terminal_state: "pending",
          terminal_reason: null,
          terminal_poll_digest:
            (pendingTerminal as Readonly<Record<string, unknown>>).terminal_poll_digest,
        },
      ),
      output_digest: pendingOutputDigest,
      output: pendingTerminal,
    }));
    await expect(pollControlDeviceAuthorization(value.authority, poll)).resolves.toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });

    value.store.records.set(value.tx.transaction_id, Object.freeze({
      state: "indeterminate" as const,
      revision: 1,
      binding_digest: current.binding_digest,
      execution_token: "a".repeat(64),
      reconciliation_digest: "b".repeat(64),
    }));
    const malformedIndeterminate = await pollControlDeviceAuthorization(
      value.authority,
      poll,
    );
    expect(malformedIndeterminate).toMatchObject({ verdict: "indeterminate" });
    if (malformedIndeterminate.verdict !== "indeterminate") {
      throw new Error("synthetic malformed record did not fail closed");
    }
    expect(malformedIndeterminate.reconciliation_digest).not.toBe("b".repeat(64));
  });

  it("BLUE TEAM VALIDATION: synthetic/local persists the RFC transaction projection with shared authority binding", async () => {
    const value = await transaction();
    const record = await value.store.load(value.tx.transaction_id);
    if (record?.state !== "available") throw new Error("synthetic record unavailable");
    const output = record.output as DeviceState & Readonly<Record<string, unknown>>;
    expect(output).toMatchObject({
      device_code_sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      user_code_sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      device_code_entropy_bits: 128,
      user_code_entropy_bits: 40,
      normalization: "uppercase-ascii-remove-hyphen",
      client_fingerprint: "SYNTHETIC-CLIENT-FINGERPRINT",
      failed_guesses: 0,
      max_failed_guesses: 5,
    });
    expect(Object.hasOwn(output, "device_code_hash")).toBe(false);
    expect(Object.hasOwn(output, "user_code_hash")).toBe(false);
    expect(record.binding_digest).toBe(authorityBindingDigest(
      "heterodyne-control-device-state-v1",
      output,
    ));
  });
});
