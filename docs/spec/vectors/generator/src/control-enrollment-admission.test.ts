import { describe, expect, it } from "vitest";
import {
  admitControlEnrollment,
  createControlEnrollmentAdmissionAuthority,
  type ControlEnrollmentAdmissionAuthorityConfig,
  type ControlEnrollmentAdmissionRequest,
  type ControlEnrollmentReservationInput,
  type ControlEnrollmentReservationRecord,
  type ControlEnrollmentReservationState,
  type ControlEnrollmentReservationStore,
} from "./control-enrollment-admission.js";

type EnrollmentOutput = Readonly<{ enrollment_id: string; group_id: string }>;
type Inventory = Awaited<ReturnType<ControlEnrollmentAdmissionAuthorityConfig["load_inventory"]>>;
type Invite = Awaited<ReturnType<ControlEnrollmentAdmissionAuthorityConfig["load_invite_state"]>>;
type MutableConfig = {
  -readonly [K in keyof ControlEnrollmentAdmissionAuthorityConfig]:
    ControlEnrollmentAdmissionAuthorityConfig[K];
};

class EnrollmentStore implements ControlEnrollmentReservationStore {
  readonly records = new Map<string, ControlEnrollmentReservationRecord>();
  readonly calls = { load: 0, reserve: 0, commit: 0, mark: 0 };
  inventoryState: Inventory = inventory();
  readonly inviteStates = new Map<string, Invite>([
    ["synthetic-local-invite-A", invite()],
  ]);
  readonly accountPending = new Map<string, number>();
  nextReserve: "acquired" | "replay" | "conflict" | "unavailable" | "unknown" | null = null;
  nextCommit: "committed" | "conflict" | "unknown" | null = null;
  nextMark: "indeterminate" | "conflict" | "unknown" | null = null;
  persistUnknownCommit = false;
  holdCommit: Promise<void> | null = null;
  holdReserve: Promise<void> | null = null;
  reserveEntered = 0;
  beforeReserve: (() => void) | null = null;
  acquiredReadbackFault:
    "null" | "malformed" | "mismatched" | "capacity" | "throw" | null = null;
  private pendingAcquiredReadbackFault:
    "null" | "malformed" | "mismatched" | "capacity" | "throw" | null = null;
  corruptCommittedReservation = false;

  get effectCalls(): number {
    return this.calls.commit;
  }

  async load(key: string): Promise<ControlEnrollmentReservationRecord | null> {
    this.calls.load += 1;
    if (this.pendingAcquiredReadbackFault !== null) {
      const fault = this.pendingAcquiredReadbackFault;
      this.pendingAcquiredReadbackFault = null;
      if (fault === "throw") throw new Error("synthetic local acquired readback failure");
      if (fault === "null") return null;
      if (fault === "malformed") {
        return { state: "executing" } as unknown as ControlEnrollmentReservationRecord;
      }
      const current = this.records.get(key);
      if (fault === "capacity") return current === undefined ? null : {
        ...current,
        reservation: {
          ...current.reservation,
          global_pending_cap: current.reservation.global_pending_cap + 1,
        },
      };
      return current === undefined ? null : {
        ...current,
        execution_token: "0".repeat(64),
      };
    }
    return this.records.get(key) ?? null;
  }

  private sameStrings(left: readonly string[], right: readonly string[]): boolean {
    return left.length === right.length && left.every((value, index) => value === right[index]);
  }

  private currentPending(account: string): number {
    return this.accountPending.get(account) ?? this.inventoryState.pending_for_account;
  }

  private reservationFromInput(
    input: ControlEnrollmentReservationInput,
  ): ControlEnrollmentReservationState {
    const { key: _key, binding_digest: _binding, reservation_digest: _digest,
      execution_token: _token, ...reservation } = input;
    return Object.freeze(reservation);
  }

  snapshotInventory(account = "synthetic-local-account-A"): Inventory {
    return inventory({
      ...this.inventoryState,
      pending_for_account: this.currentPending(account),
    });
  }

  async reserve(input: ControlEnrollmentReservationInput): Promise<
    | "acquired" | "replay" | "conflict" | "unavailable" | "unknown"
    | "keypackage-invalid" | "replenishment-paused"
  > {
    this.calls.reserve += 1;
    this.reserveEntered += 1;
    if (this.holdReserve !== null) await this.holdReserve;
    if (this.beforeReserve !== null) {
      const callback = this.beforeReserve;
      this.beforeReserve = null;
      callback();
    }
    const current = this.records.get(input.key);
    if (current?.binding_digest !== undefined) {
      if (current.binding_digest !== input.binding_digest) return "conflict";
      return "replay";
    }
    const currentInvite = this.inviteStates.get(input.invite_id);
    const state = this.inventoryState;
    const exactSnapshot = currentInvite !== undefined
      && input.inventory_revision === state.revision
      && input.invite_revision === currentInvite.revision
      && input.pending_for_account === this.currentPending(input.account)
      && input.global_pending === state.global_pending
      && input.global_pending_cap === state.global_pending_cap
      && input.replenishment_state === state.replenishment_state
      && input.rate_window_started_at === state.rate_window_started_at
      && input.attempts_in_window === state.attempts_in_window
      && input.attempt_budget === state.attempt_budget
      && this.sameStrings(input.reserved_slots, state.reserved_slots)
      && this.sameStrings(input.current_clients, state.current_clients)
      && this.sameStrings(input.enrolled_accounts, state.enrolled_accounts)
      && this.sameStrings(input.enrolled_devices, state.enrolled_devices)
      && input.invite_state === currentInvite.state
      && input.invite_purpose === currentInvite.purpose
      && input.invite_account === currentInvite.account
      && input.invite_client_key === currentInvite.client_key
      && input.invite_expires_at === currentInvite.expires_at;
    if (!exactSnapshot) {
      if (state.current_clients.includes(input.client_key)) return "keypackage-invalid";
      if (state.replenishment_state === "paused") return "replenishment-paused";
      return "unavailable";
    }
    if (currentInvite.state !== "active"
      || currentInvite.purpose !== "control-enrollment"
      || currentInvite.account !== input.account
      || currentInvite.client_key !== input.client_key
      || input.trusted_now >= currentInvite.expires_at
      || input.trusted_now >= input.key_package_expires_at
      || state.enrolled_accounts.includes(input.account)
      || state.enrolled_devices.includes(input.device_id)
      || this.currentPending(input.account) > 0
      || state.attempts_in_window >= state.attempt_budget
      || state.global_pending > state.global_pending_cap
      || (input.reserved_slot === null && state.global_pending >= state.global_pending_cap)
      || (input.reserved_slot !== null && !state.reserved_slots.includes(input.reserved_slot))) {
      return "unavailable";
    }
    if (state.current_clients.includes(input.client_key)) return "keypackage-invalid";
    if (state.replenishment_state === "paused") return "replenishment-paused";
    this.records.set(input.key, Object.freeze({
      state: "executing" as const,
      revision: 0,
      key: input.key,
      binding_digest: input.binding_digest,
      reservation_digest: input.reservation_digest,
      execution_token: input.execution_token,
      reservation: this.reservationFromInput(input),
    }));
    const reservedSlots = input.reserved_slot === null ? state.reserved_slots
      : state.reserved_slots.filter((slot) => slot !== input.reserved_slot);
    this.accountPending.set(input.account, this.currentPending(input.account) + 1);
    this.inventoryState = inventory({
      ...state,
      revision: state.revision + 1,
      pending_for_account: this.currentPending(input.account),
      global_pending: state.global_pending + 1,
      reserved_slots: reservedSlots,
      current_clients: [...state.current_clients, input.client_key],
      attempts_in_window: state.attempts_in_window + 1,
    });
    this.inviteStates.set(input.invite_id, invite({
      ...currentInvite,
      revision: currentInvite.revision + 1,
      state: "consumed",
    }));
    this.pendingAcquiredReadbackFault = this.acquiredReadbackFault;
    if (this.nextReserve !== null) {
      const result = this.nextReserve;
      this.nextReserve = null;
      return result;
    }
    return "acquired";
  }

  async commit(input: Readonly<{
    key: string;
    binding_digest: string;
    reservation_digest: string;
    execution_token: string;
    reservation: ControlEnrollmentReservationState;
    output_digest: string;
    output: EnrollmentOutput;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.calls.commit += 1;
    if (this.holdCommit !== null) await this.holdCommit;
    const current = this.records.get(input.key);
    if (current?.state !== "executing"
      || current.binding_digest !== input.binding_digest
      || current.reservation_digest !== input.reservation_digest
      || current.execution_token !== input.execution_token) return "conflict";
    const terminal = Object.freeze({
      state: "committed" as const,
      revision: current.revision + 1,
      key: input.key,
      binding_digest: input.binding_digest,
      reservation_digest: input.reservation_digest,
      execution_token: input.execution_token,
      reservation: this.corruptCommittedReservation ? Object.freeze({
        ...input.reservation,
        attempts_in_window: input.reservation.attempts_in_window + 1,
      }) : input.reservation,
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
    reservation_digest: string;
    execution_token: string;
    reservation: ControlEnrollmentReservationState;
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
      || current.reservation_digest !== input.reservation_digest
      || current.execution_token !== input.execution_token) return "conflict";
    this.records.set(input.key, Object.freeze({
      state: "indeterminate" as const,
      revision: current.revision + 1,
      key: input.key,
      binding_digest: input.binding_digest,
      reservation_digest: input.reservation_digest,
      execution_token: input.execution_token,
      reservation: input.reservation,
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
  let inventories: Inventory[] | null = null;
  const inviteSequences = new Map<string, Invite[]>();
  let inventoryCalls = 0;
  let inviteCalls = 0;
  let verifyCalls = 0;
  const config: MutableConfig = {
    authority_id: "synthetic-local-control-enrollment-authority-A",
    trusted_now: () => now,
    store,
    load_inventory: async () => {
      const values = inventories;
      const value = values === null
        ? store.snapshotInventory()
        : values[Math.min(inventoryCalls, values.length - 1)];
      inventoryCalls += 1;
      return value;
    },
    load_invite_state: async (inviteId) => {
      const values = inviteSequences.get(inviteId);
      const value = values === undefined
        ? store.inviteStates.get(inviteId)
        : values[Math.min(inviteCalls, values.length - 1)];
      inviteCalls += 1;
      if (value === undefined) throw new Error("synthetic local invite unavailable");
      return value;
    },
    verify_key_package: (bytes) => {
      verifyCalls += 1;
      const hex = Buffer.from(bytes).toString("hex");
      if (hex !== "01020304" && hex !== "05060708" && hex !== "090a0b0c") return null;
      return Object.freeze({
        account: hex === "05060708"
          ? "synthetic-local-account-B"
          : "synthetic-local-account-A",
        reference: hex === "01020304"
          ? "synthetic-local-keypackage-ref-A"
          : "synthetic-local-keypackage-ref-B",
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
    setInventories: (...values: Inventory[]) => {
      inventories = values;
      store.inventoryState = values.at(-1) ?? inventory();
      inventoryCalls = 0;
    },
    setInvites: (...values: Invite[]) => {
      inviteSequences.set("synthetic-local-invite-A", values);
      store.inviteStates.set("synthetic-local-invite-A", values.at(-1) ?? invite());
      inviteCalls = 0;
    },
    setInvite: (inviteId: string, value: Invite) => {
      inviteSequences.set(inviteId, [value]);
      store.inviteStates.set(inviteId, value);
    },
    setNow: (value: number) => { now = value; },
  };
}

function secondRequest(
  overrides: Partial<ControlEnrollmentAdmissionRequest> = {},
): ControlEnrollmentAdmissionRequest {
  return request({
    account: "synthetic-local-account-B",
    device_id: "synthetic-local-device-B",
    client_key: "synthetic-local-client-key-B",
    group_id: "synthetic-local-group-B",
    invite_id: "synthetic-local-invite-B",
    key_package_bytes: Uint8Array.from([0x05, 0x06, 0x07, 0x08]),
    expected_key_package_ref: "synthetic-local-keypackage-ref-B",
    ...overrides,
  });
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

  const contestedResources: readonly Readonly<{
    name: string;
    state: Inventory;
    second: ControlEnrollmentAdmissionRequest;
    secondInvite: Invite;
  }>[] = [
    {
      name: "one account-pending slot",
      state: inventory({ global_pending_cap: 10, reserved_slots: [] }),
      second: secondRequest({
        account: "synthetic-local-account-A",
        key_package_bytes: Uint8Array.from([0x09, 0x0a, 0x0b, 0x0c]),
        reserved_slot: null,
      }),
      secondInvite: invite({
        account: "synthetic-local-account-A",
        client_key: "synthetic-local-client-key-B",
      }),
    },
    {
      name: "one global slot",
      state: inventory({ global_pending_cap: 1, reserved_slots: [] }),
      second: secondRequest({ reserved_slot: null }),
      secondInvite: invite({
        account: "synthetic-local-account-B",
        client_key: "synthetic-local-client-key-B",
      }),
    },
    {
      name: "one exact reserved slot",
      state: inventory({ global_pending_cap: 0 }),
      second: secondRequest(),
      secondInvite: invite({
        account: "synthetic-local-account-B",
        client_key: "synthetic-local-client-key-B",
      }),
    },
    {
      name: "the last rate attempt",
      state: inventory({
        attempt_budget: 1,
        global_pending_cap: 10,
        reserved_slots: [],
      }),
      second: secondRequest({ reserved_slot: null }),
      secondInvite: invite({
        account: "synthetic-local-account-B",
        client_key: "synthetic-local-client-key-B",
      }),
    },
  ];

  it.each(contestedResources)(
    "BLUE TEAM VALIDATION: synthetic/local atomically arbitrates $name across different invites",
    async (candidate) => {
      const fixture = setup();
      fixture.setInventories(candidate.state);
      fixture.setInvite("synthetic-local-invite-B", candidate.secondInvite);
      let release = (): void => undefined;
      fixture.store.holdReserve = new Promise<void>((resolve) => { release = resolve; });
      const decisions = [
        admitControlEnrollment(fixture.authority, request({
          reserved_slot: candidate.state.reserved_slots[0] ?? null,
        })),
        admitControlEnrollment(fixture.authority, candidate.second),
      ];
      for (let attempt = 0; attempt < 20 && fixture.store.reserveEntered < 2; attempt += 1) {
        await new Promise<void>((resolve) => setImmediate(resolve));
      }
      expect(fixture.store.reserveEntered).toBe(2);
      release();
      const results = await Promise.all(decisions);
      expect(results.filter((decision) => decision.verdict === "accept")).toHaveLength(1);
      expect(results.filter((decision) => decision.verdict === "reject"))
        .toEqual([UNAVAILABLE]);
      expect(fixture.store.effectCalls).toBe(1);
      expect(fixture.store.records.size).toBe(1);
    },
  );

  it("BLUE TEAM VALIDATION: synthetic/local rejects state changed at the atomic reservation boundary", async () => {
    const fixture = setup();
    fixture.store.beforeReserve = () => {
      fixture.store.inventoryState = inventory({
        ...fixture.store.inventoryState,
        revision: fixture.store.inventoryState.revision + 1,
        global_pending: fixture.store.inventoryState.global_pending_cap,
        reserved_slots: [],
      });
    };
    await expect(admitControlEnrollment(fixture.authority, request()))
      .resolves.toEqual(UNAVAILABLE);
    expect(fixture.store.effectCalls).toBe(0);
    expect(fixture.store.records.size).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes ambiguous atomic reservation absorbing", async () => {
    const fixture = setup();
    fixture.store.nextReserve = "unknown";
    const first = await admitControlEnrollment(fixture.authority, request());
    expect(first).toEqual({
      verdict: "indeterminate",
      reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(fixture.store.effectCalls).toBe(0);
    const reservations = fixture.store.calls.reserve;
    const retry = await admitControlEnrollment(fixture.authority, request());
    expect(retry).toEqual(first);
    expect(fixture.store.calls.reserve).toBe(reservations);
    expect(fixture.store.effectCalls).toBe(0);
  });

  it.each(["null", "malformed", "mismatched", "capacity", "throw"] as const)(
    "BLUE TEAM VALIDATION: synthetic/local makes %s acquired-record readback absorbing before effect",
    async (fault) => {
      const fixture = setup();
      fixture.store.acquiredReadbackFault = fault;
      const first = await admitControlEnrollment(fixture.authority, request());
      expect(first).toEqual({
        verdict: "indeterminate",
        reconciliation_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
      expect(fixture.store.calls.reserve).toBe(1);
      expect(fixture.store.calls.commit).toBe(0);
      expect(fixture.store.effectCalls).toBe(0);

      const retry = await admitControlEnrollment(fixture.authority, request());
      const reconstructed = createControlEnrollmentAdmissionAuthority(fixture.config);
      const reconstructedRetry = await admitControlEnrollment(reconstructed, request());
      expect(retry).toEqual(first);
      expect(reconstructedRetry).toEqual(first);
      expect(fixture.store.calls.reserve).toBe(1);
      expect(fixture.store.calls.commit).toBe(0);
      expect(fixture.store.effectCalls).toBe(0);
    },
  );

  it("BLUE TEAM VALIDATION: synthetic/local requires exact committed reservation-state readback", async () => {
    const fixture = setup();
    fixture.store.corruptCommittedReservation = true;
    await expect(admitControlEnrollment(fixture.authority, request())).resolves.toMatchObject({
      verdict: "indeterminate",
    });
    expect(fixture.store.calls.reserve).toBe(1);
    expect(fixture.store.calls.commit).toBe(1);
    const retry = await admitControlEnrollment(fixture.authority, request());
    expect(retry.verdict).toBe("indeterminate");
    expect(fixture.store.calls.reserve).toBe(1);
    expect(fixture.store.calls.commit).toBe(1);
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
    )).resolves.toEqual(UNAVAILABLE);
    expect(fixture.store.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local keeps envelope failures out of KeyPackage reason ownership", async () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const cases: unknown[] = [
      { ...request(), persona: "" },
      { ...request(), invite_purpose: "dm" },
      { ...request(), reserved_slot: 7 },
      { ...request(), unexpected: circular },
    ];
    for (const hostile of cases) {
      const fixture = setup();
      await expect(admitControlEnrollment(
        fixture.authority,
        hostile as ControlEnrollmentAdmissionRequest,
      )).resolves.toEqual(UNAVAILABLE);
      expect(fixture.verifyCalls()).toBe(0);
      expect(fixture.store.calls.load).toBe(0);
      expect(fixture.store.effectCalls).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local bounds public strings and KeyPackage bytes before callbacks", async () => {
    const oversizedEnvelope = setup();
    await expect(admitControlEnrollment(oversizedEnvelope.authority, request({
      persona: "p".repeat(513),
    }))).resolves.toEqual(UNAVAILABLE);
    expect(oversizedEnvelope.verifyCalls()).toBe(0);
    expect(oversizedEnvelope.inventoryCalls()).toBe(0);
    expect(oversizedEnvelope.store.calls.load).toBe(0);

    const oversizedKeyPackage = setup();
    await expect(admitControlEnrollment(oversizedKeyPackage.authority, request({
      key_package_bytes: new Uint8Array(65_537),
    }))).resolves.toEqual(INVALID_KEY_PACKAGE);
    expect(oversizedKeyPackage.verifyCalls()).toBe(0);
    expect(oversizedKeyPackage.inventoryCalls()).toBe(0);
    expect(oversizedKeyPackage.store.calls.load).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxied KeyPackage bytes with zero proxy traps", async () => {
    const fixture = setup();
    let traps = 0;
    const bytes = new Proxy(Uint8Array.from([1, 2, 3, 4]), {
      getPrototypeOf: () => { traps += 1; throw new Error("synthetic proxy trap"); },
    });
    await expect(admitControlEnrollment(fixture.authority, request({
      key_package_bytes: bytes,
    }))).resolves.toEqual(INVALID_KEY_PACKAGE);
    expect(traps).toBe(0);
    expect(fixture.verifyCalls()).toBe(0);
    expect(fixture.store.calls.load).toBe(0);
  });

  it.each(["length", "extra", "symbol"] as const)(
    "BLUE TEAM VALIDATION: synthetic/local rejects KeyPackage bytes with own %s metadata with zero traps",
    async (kind) => {
      const fixture = setup();
      let traps = 0;
      const bytes = Uint8Array.from([1, 2, 3, 4]);
      const key: PropertyKey = kind === "symbol" ? Symbol("synthetic-local") : kind;
      Object.defineProperty(bytes, key, {
        enumerable: true,
        configurable: true,
        get: () => { traps += 1; throw new Error("synthetic local byte metadata trap"); },
      });
      await expect(admitControlEnrollment(fixture.authority, request({
        key_package_bytes: bytes,
      }))).resolves.toEqual(INVALID_KEY_PACKAGE);
      expect(traps).toBe(0);
      expect(fixture.verifyCalls()).toBe(0);
      expect(fixture.store.calls.load).toBe(0);
    },
  );

  it("BLUE TEAM VALIDATION: synthetic/local bounds authenticated callback lists and aggregates", async () => {
    const tooMany = setup();
    tooMany.setInventories(inventory({
      current_clients: Array.from({ length: 257 }, (_, index) => `client-${index}`),
    }));
    await expect(admitControlEnrollment(tooMany.authority, request())).resolves.toEqual(UNAVAILABLE);
    expect(tooMany.store.calls.reserve).toBe(0);
    expect(tooMany.store.effectCalls).toBe(0);

    const aggregate = setup();
    aggregate.setInventories(inventory({
      enrolled_devices: Array.from(
        { length: 200 },
        (_, index) => `${index}-`.padEnd(512, "d"),
      ),
    }));
    await expect(admitControlEnrollment(aggregate.authority, request()))
      .resolves.toEqual(UNAVAILABLE);
    expect(aggregate.store.calls.reserve).toBe(0);
    expect(aggregate.store.effectCalls).toBe(0);
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
    )).resolves.toEqual(UNAVAILABLE);
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

  it("BLUE TEAM VALIDATION: synthetic/local bounds durable-store prototype traversal", () => {
    const fixture = setup();
    let deepStore: object = fixture.store;
    for (let depth = 0; depth < 16; depth += 1) deepStore = Object.create(deepStore);
    expect(() => createControlEnrollmentAdmissionAuthority({
      ...fixture.config,
      store: deepStore as ControlEnrollmentReservationStore,
    })).toThrow(TypeError);
  });
});
