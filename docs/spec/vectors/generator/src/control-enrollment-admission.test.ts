import { describe, expect, it } from "vitest";
import {
  admitControlEnrollment,
  createControlEnrollmentAdmissionAuthority,
  type ControlEnrollmentAdmissionAuthorityConfig,
  type ControlEnrollmentAdmissionRequest,
} from "./control-enrollment-admission.js";
import type {
  DurableAuthorityRecord,
  DurableAuthorityStore,
} from "./security-authority-support.js";

type EnrollmentOutput = Readonly<{ enrollment_id: string; group_id: string }>;
type Inventory = Awaited<ReturnType<ControlEnrollmentAdmissionAuthorityConfig["load_inventory"]>>;
type Invite = Awaited<ReturnType<ControlEnrollmentAdmissionAuthorityConfig["load_invite_state"]>>;
type MutableConfig = {
  -readonly [K in keyof ControlEnrollmentAdmissionAuthorityConfig]:
    ControlEnrollmentAdmissionAuthorityConfig[K];
};

class EnrollmentStore implements DurableAuthorityStore<EnrollmentOutput> {
  readonly records = new Map<string, DurableAuthorityRecord<EnrollmentOutput>>();
  readonly calls = { load: 0, acquire: 0, compareAndSwap: 0, commit: 0, mark: 0 };
  nextAcquire: "acquired" | "replay" | "conflict" | "unavailable" | null = null;
  nextCommit: "committed" | "conflict" | "unknown" | null = null;
  nextMark: "indeterminate" | "conflict" | "unknown" | null = null;
  persistUnknownCommit = false;
  holdCommit: Promise<void> | null = null;

  get effectCalls(): number {
    return this.calls.commit;
  }

  async load(key: string): Promise<DurableAuthorityRecord<EnrollmentOutput> | null> {
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
    if (current === undefined && input.expected_revision === null) {
      this.records.set(input.key, Object.freeze({
        state: "executing" as const,
        revision: 0,
        binding_digest: input.binding_digest,
        execution_token: input.execution_token,
      }));
      return "acquired";
    }
    if (current?.binding_digest !== input.binding_digest) return "conflict";
    if (current.state === "executing" || current.state === "committed"
      || current.state === "indeterminate") return "replay";
    if (current.state !== "available" || current.revision !== input.expected_revision) {
      return "conflict";
    }
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
    next: DurableAuthorityRecord<EnrollmentOutput>;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.calls.compareAndSwap += 1;
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
    output: EnrollmentOutput;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.calls.commit += 1;
    if (this.holdCommit !== null) await this.holdCommit;
    const current = this.records.get(input.key);
    if (current?.state !== "executing"
      || current.binding_digest !== input.binding_digest
      || current.execution_token !== input.execution_token) return "conflict";
    const terminal = Object.freeze({
      state: "committed" as const,
      revision: current.revision + 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      output_digest: input.output_digest,
      output: input.output,
    });
    if (this.nextCommit !== null) {
      const result = this.nextCommit;
      this.nextCommit = null;
      if (result === "unknown" && this.persistUnknownCommit) {
        this.records.set(input.key, terminal);
      }
      return result;
    }
    this.records.set(input.key, terminal);
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
}

function inventory(overrides: Partial<Inventory> = {}): Inventory {
  return Object.freeze({
    revision: 7,
    pending_for_account: 0,
    global_pending: 0,
    global_pending_cap: 2,
    reserved_slots: Object.freeze(["synthetic-local-slot-A"]),
    replenishment_state: "ready" as const,
    current_clients: Object.freeze([]),
    enrolled_accounts: Object.freeze([]),
    enrolled_devices: Object.freeze([]),
    rate_window_started_at: 900,
    attempts_in_window: 0,
    attempt_budget: 5,
    ...overrides,
  });
}

function invite(overrides: Partial<Invite> = {}): Invite {
  return Object.freeze({
    revision: 3,
    purpose: "control-enrollment" as const,
    state: "active" as const,
    account: "synthetic-local-account-A",
    client_key: "synthetic-local-client-key-A",
    expires_at: 1_100,
    ...overrides,
  });
}

function request(
  overrides: Partial<ControlEnrollmentAdmissionRequest> = {},
): ControlEnrollmentAdmissionRequest {
  return {
    persona: "synthetic-local-persona-A",
    account: "synthetic-local-account-A",
    device_id: "synthetic-local-device-A",
    client_key: "synthetic-local-client-key-A",
    group_id: "synthetic-local-group-A",
    invite_id: "synthetic-local-invite-A",
    invite_purpose: "control-enrollment",
    key_package_bytes: Uint8Array.from([0x01, 0x02, 0x03, 0x04]),
    expected_key_package_ref: "synthetic-local-keypackage-ref-A",
    reserved_slot: "synthetic-local-slot-A",
    ...overrides,
  };
}

function setup(overrides: Partial<ControlEnrollmentAdmissionAuthorityConfig> = {}) {
  let now = 1_000;
  const store = (overrides.store as EnrollmentStore | undefined) ?? new EnrollmentStore();
  let inventories = [inventory()];
  let invites = [invite()];
  let inventoryCalls = 0;
  let inviteCalls = 0;
  let verifyCalls = 0;
  const config: MutableConfig = {
    authority_id: "synthetic-local-control-enrollment-authority-A",
    trusted_now: () => now,
    store,
    load_inventory: async () => {
      const value = inventories[Math.min(inventoryCalls, inventories.length - 1)];
      inventoryCalls += 1;
      return value;
    },
    load_invite_state: async () => {
      const value = invites[Math.min(inviteCalls, invites.length - 1)];
      inviteCalls += 1;
      return value;
    },
    verify_key_package: (bytes) => {
      verifyCalls += 1;
      if (Buffer.from(bytes).toString("hex") !== "01020304") return null;
      return Object.freeze({
        account: "synthetic-local-account-A",
        reference: "synthetic-local-keypackage-ref-A",
        expires_at: 1_100,
      });
    },
    ...overrides,
  };
  return {
    authority: createControlEnrollmentAdmissionAuthority(config),
    config,
    store,
    inventoryCalls: () => inventoryCalls,
    inviteCalls: () => inviteCalls,
    verifyCalls: () => verifyCalls,
    setInventories: (...values: Inventory[]) => { inventories = values; inventoryCalls = 0; },
    setInvites: (...values: Invite[]) => { invites = values; inviteCalls = 0; },
    setNow: (value: number) => { now = value; },
  };
}

const INVALID_KEY_PACKAGE = Object.freeze({
  verdict: "reject" as const,
  reason_code: "control-keypackage-invalid" as const,
});
const UNAVAILABLE = Object.freeze({
  verdict: "reject" as const,
  reason_code: "control-enrollment-unavailable" as const,
});

describe("Control enrollment admission authority", () => {
  it("admits an exact authenticated enrollment through one durable reservation", async () => {
    const fixture = setup();
    const result = await admitControlEnrollment(fixture.authority, request());
    expect(result).toEqual({
      verdict: "accept",
      output: {
        enrollment_id: expect.stringMatching(/^[0-9a-f]{64}$/),
        group_id: "synthetic-local-group-A",
      },
    });
    expect(fixture.inventoryCalls()).toBe(2);
    expect(fixture.inviteCalls()).toBe(2);
    expect(fixture.store.effectCalls).toBe(1);
    expect([...fixture.store.records.values()]).toHaveLength(1);
    expect([...fixture.store.records.values()][0]?.state).toBe("committed");
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects malformed, unbound, expired, and replayed KeyPackages", async () => {
    const cases: readonly Readonly<{
      name: string;
      configure: (fixture: ReturnType<typeof setup>) => void;
    }>[] = [
      {
        name: "malformed",
        configure: (fixture) => {
          fixture.config.verify_key_package = () => null;
        },
      },
      {
        name: "wrong account",
        configure: (fixture) => {
          fixture.config.verify_key_package = () => ({
            account: "synthetic-local-account-B",
            reference: "synthetic-local-keypackage-ref-A",
            expires_at: 1_100,
          });
        },
      },
      {
        name: "wrong exact reference",
        configure: (fixture) => {
          fixture.config.verify_key_package = () => ({
            account: "synthetic-local-account-A",
            reference: "synthetic-local-keypackage-ref-B",
            expires_at: 1_100,
          });
        },
      },
      {
        name: "expired",
        configure: (fixture) => {
          fixture.config.verify_key_package = () => ({
            account: "synthetic-local-account-A",
            reference: "synthetic-local-keypackage-ref-A",
            expires_at: 1_000,
          });
        },
      },
      {
        name: "replayed client",
        configure: (fixture) => {
          fixture.setInventories(inventory({
            current_clients: ["synthetic-local-client-key-A"],
          }));
        },
      },
    ];
    for (const candidate of cases) {
      const fixture = setup();
      candidate.configure(fixture);
      const authority = createControlEnrollmentAdmissionAuthority(fixture.config);
      await expect(admitControlEnrollment(authority, request()), candidate.name)
        .resolves.toEqual(INVALID_KEY_PACKAGE);
      expect(fixture.store.effectCalls, candidate.name).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects an independently expired invite", async () => {
    const fixture = setup();
    fixture.setInvites(invite({ expires_at: 1_000 }));
    await expect(admitControlEnrollment(fixture.authority, request())).resolves.toEqual(UNAVAILABLE);
    expect(fixture.store.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local enforces invite purpose, state, account, and client binding", async () => {
    const cases: Invite[] = [
      invite({ state: "revoked" }),
      invite({ state: "consumed" }),
      invite({ account: "synthetic-local-account-B" }),
      invite({ client_key: "synthetic-local-client-key-B" }),
    ];
    for (const currentInvite of cases) {
      const fixture = setup();
      fixture.setInvites(currentInvite);
      await expect(admitControlEnrollment(fixture.authority, request()))
        .resolves.toEqual(UNAVAILABLE);
      expect(fixture.store.effectCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local enforces the authenticated enrollment rate budget", async () => {
    const fixture = setup();
    fixture.setInventories(inventory({ attempts_in_window: 5, attempt_budget: 5 }));
    await expect(admitControlEnrollment(fixture.authority, request())).resolves.toEqual(UNAVAILABLE);
    expect(fixture.store.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects already enrolled accounts and devices", async () => {
    const cases: Inventory[] = [
      inventory({ enrolled_accounts: ["synthetic-local-account-A"] }),
      inventory({ enrolled_devices: ["synthetic-local-device-A"] }),
    ];
    for (const currentInventory of cases) {
      const fixture = setup();
      fixture.setInventories(currentInventory);
      await expect(admitControlEnrollment(fixture.authority, request()))
        .resolves.toEqual(UNAVAILABLE);
      expect(fixture.store.effectCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local enforces account, global, and reserved-slot capacity", async () => {
    const cases: Readonly<{
      state: Inventory;
      request: ControlEnrollmentAdmissionRequest;
    }>[] = [
      { state: inventory({ pending_for_account: 1 }), request: request() },
      {
        state: inventory({ global_pending: 2, global_pending_cap: 2 }),
        request: request({ reserved_slot: null }),
      },
      { state: inventory({ reserved_slots: [] }), request: request() },
    ];
    for (const candidate of cases) {
      const fixture = setup();
      fixture.setInventories(candidate.state);
      await expect(admitControlEnrollment(fixture.authority, candidate.request))
        .resolves.toEqual(UNAVAILABLE);
      expect(fixture.store.effectCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local derives replenishment pause from current authenticated state", async () => {
    const fixture = setup();
    fixture.setInventories(inventory({ replenishment_state: "paused" }));
    await expect(admitControlEnrollment(fixture.authority, request())).resolves.toEqual({
      verdict: "reject",
      reason_code: "control-keypackage-replenishment-paused",
    });
    expect(fixture.store.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local reloads capacity before reservation", async () => {
    const fixture = setup();
    fixture.setInventories(
      inventory(),
      inventory({ global_pending: 2, global_pending_cap: 2, reserved_slots: [] }),
    );
    const result = await admitControlEnrollment(fixture.authority, request());
    expect(result).toEqual(UNAVAILABLE);
    expect(fixture.inventoryCalls()).toBe(2);
    expect(fixture.store.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local lets the durable store arbitrate a concurrent reservation", async () => {
    const fixture = setup();
    let release = (): void => undefined;
    fixture.store.holdCommit = new Promise<void>((resolve) => { release = resolve; });
    const first = admitControlEnrollment(fixture.authority, request());
    await new Promise<void>((resolve) => setImmediate(resolve));
    const second = await admitControlEnrollment(fixture.authority, request({
      device_id: "synthetic-local-device-B",
    }));
    expect(second).toEqual(UNAVAILABLE);
    release();
    await expect(first).resolves.toMatchObject({ verdict: "accept" });
    expect(fixture.store.effectCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes effect uncertainty absorbing and retry-stable", async () => {
    const fixture = setup();
    fixture.store.nextCommit = "unknown";
    const first = await admitControlEnrollment(fixture.authority, request());
    expect(first).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect([...fixture.store.records.values()][0]?.state).toBe("indeterminate");
    const commits = fixture.store.effectCalls;
    const retry = await admitControlEnrollment(fixture.authority, request());
    expect(retry).toEqual(first);
    expect(fixture.store.effectCalls).toBe(commits);
  });

  it("returns the exact committed enrollment on retry without another effect", async () => {
    const fixture = setup();
    const first = await admitControlEnrollment(fixture.authority, request());
    const effects = fixture.store.effectCalls;
    fixture.setNow(1_200);
    fixture.setInvites(invite({ state: "consumed", expires_at: 1_100 }));
    fixture.setInventories(inventory({ enrolled_accounts: ["synthetic-local-account-A"] }));
    const retry = await admitControlEnrollment(fixture.authority, request());
    expect(retry).toEqual(first);
    expect(fixture.store.effectCalls).toBe(effects);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects authority clones and request proxies", async () => {
    const fixture = setup();
    await expect(admitControlEnrollment(
      { ...fixture.authority },
      request(),
    )).resolves.toEqual(UNAVAILABLE);
    await expect(admitControlEnrollment(
      fixture.authority,
      new Proxy(request(), {}),
    )).resolves.toEqual(INVALID_KEY_PACKAGE);
    expect(fixture.store.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures exact request bytes before asynchronous mutation", async () => {
    const fixture = setup();
    const mutable = request() as {
      -readonly [K in keyof ControlEnrollmentAdmissionRequest]:
        ControlEnrollmentAdmissionRequest[K];
    };
    const pending = admitControlEnrollment(fixture.authority, mutable);
    mutable.group_id = "synthetic-local-group-mutated";
    mutable.key_package_bytes[0] = 0xff;
    await expect(pending).resolves.toMatchObject({
      verdict: "accept",
      output: { group_id: "synthetic-local-group-A" },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects accessor-backed input without invoking it", async () => {
    const fixture = setup();
    let reads = 0;
    const hostile = { ...request() } as Record<string, unknown>;
    Object.defineProperty(hostile, "reserved_slot", {
      enumerable: true,
      get: () => { reads += 1; return "synthetic-local-slot-A"; },
    });
    await expect(admitControlEnrollment(
      fixture.authority,
      hostile as ControlEnrollmentAdmissionRequest,
    )).resolves.toEqual(INVALID_KEY_PACKAGE);
    expect(reads).toBe(0);
    expect(fixture.store.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures callbacks and store methods at construction", async () => {
    const fixture = setup();
    const originalStore = fixture.store;
    const replacementStore = new EnrollmentStore();
    fixture.config.trusted_now = () => 1_200;
    fixture.config.load_inventory = async () => inventory({
      enrolled_accounts: ["synthetic-local-account-A"],
    });
    fixture.config.load_invite_state = async () => invite({ state: "revoked" });
    fixture.config.verify_key_package = () => null;
    fixture.config.store = replacementStore;
    originalStore.commit = async () => "conflict";
    await expect(admitControlEnrollment(fixture.authority, request()))
      .resolves.toMatchObject({ verdict: "accept" });
    expect(replacementStore.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxy and accessor authority configuration", () => {
    const fixture = setup();
    expect(() => createControlEnrollmentAdmissionAuthority(
      new Proxy(fixture.config, {}),
    )).toThrow(TypeError);
    let reads = 0;
    const hostile = { ...fixture.config } as Record<string, unknown>;
    Object.defineProperty(hostile, "verify_key_package", {
      enumerable: true,
      get: () => { reads += 1; return fixture.config.verify_key_package; },
    });
    expect(() => createControlEnrollmentAdmissionAuthority(
      hostile as ControlEnrollmentAdmissionAuthorityConfig,
    )).toThrow(TypeError);
    expect(reads).toBe(0);
  });
});
