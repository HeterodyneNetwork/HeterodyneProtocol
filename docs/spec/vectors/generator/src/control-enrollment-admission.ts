import { types as utilTypes } from "node:util";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type AuthorityDecision,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
} from "./security-authority-support.js";

export type ControlEnrollmentAdmissionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  store: DurableAuthorityStore<Readonly<{ enrollment_id: string; group_id: string }>>;
  load_inventory: (persona: string) => Promise<Readonly<{
    revision: number;
    pending_for_account: number;
    global_pending: number;
    global_pending_cap: number;
    reserved_slots: readonly string[];
    replenishment_state: "ready" | "paused";
    current_clients: readonly string[];
    enrolled_accounts: readonly string[];
    enrolled_devices: readonly string[];
    rate_window_started_at: number;
    attempts_in_window: number;
    attempt_budget: number;
  }>>;
  load_invite_state: (invite_id: string) => Promise<Readonly<{
    revision: number;
    purpose: "control-enrollment";
    state: "active" | "revoked" | "consumed";
    account: string;
    client_key: string;
    expires_at: number;
  }>>;
  verify_key_package: (bytes: Uint8Array) => Readonly<{
    account: string;
    reference: string;
    expires_at: number;
  }> | null;
}>;

export type ControlEnrollmentAdmissionRequest = Readonly<{
  persona: string;
  account: string;
  device_id: string;
  client_key: string;
  group_id: string;
  invite_id: string;
  invite_purpose: "control-enrollment";
  key_package_bytes: Uint8Array;
  expected_key_package_ref: string;
  reserved_slot: string | null;
}>;

export type ControlEnrollmentAdmissionDecision = AuthorityDecision<
  | "control-enrollment-unavailable"
  | "control-keypackage-invalid"
  | "control-keypackage-replenishment-paused",
  Readonly<{ enrollment_id: string; group_id: string }>
>;

export type ControlEnrollmentAdmissionAuthority = Readonly<Record<never, never>>;

type EnrollmentOutput = Readonly<{ enrollment_id: string; group_id: string }>;
type StoreCallbacks = Readonly<{
  load: DurableAuthorityStore<EnrollmentOutput>["load"];
  acquire: DurableAuthorityStore<EnrollmentOutput>["acquire"];
  compareAndSwap: DurableAuthorityStore<EnrollmentOutput>["compareAndSwap"];
  commit: DurableAuthorityStore<EnrollmentOutput>["commit"];
  markIndeterminate: DurableAuthorityStore<EnrollmentOutput>["markIndeterminate"];
}>;
type AuthorityRecord = Readonly<{
  authority_id: string;
  trusted_now: ControlEnrollmentAdmissionAuthorityConfig["trusted_now"];
  load_inventory: ControlEnrollmentAdmissionAuthorityConfig["load_inventory"];
  load_invite_state: ControlEnrollmentAdmissionAuthorityConfig["load_invite_state"];
  verify_key_package: ControlEnrollmentAdmissionAuthorityConfig["verify_key_package"];
  store: StoreCallbacks;
}>;
type Inventory = Awaited<ReturnType<AuthorityRecord["load_inventory"]>>;
type Invite = Awaited<ReturnType<AuthorityRecord["load_invite_state"]>>;
type VerifiedKeyPackage = NonNullable<ReturnType<AuthorityRecord["verify_key_package"]>>;
type DurableRequest = Readonly<{
  key: string;
  binding_digest: string;
  execution_token: string;
  output_digest: string;
  reconciliation_digest: string;
  output: EnrollmentOutput;
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const HEX_32 = /^[0-9a-f]{64}$/;
const REQUEST_KEYS = [
  "account",
  "client_key",
  "device_id",
  "expected_key_package_ref",
  "group_id",
  "invite_id",
  "invite_purpose",
  "key_package_bytes",
  "persona",
  "reserved_slot",
] as const;
const INVENTORY_KEYS = [
  "attempt_budget",
  "attempts_in_window",
  "current_clients",
  "enrolled_accounts",
  "enrolled_devices",
  "global_pending",
  "global_pending_cap",
  "pending_for_account",
  "rate_window_started_at",
  "replenishment_state",
  "reserved_slots",
  "revision",
] as const;
const INVITE_KEYS = [
  "account",
  "client_key",
  "expires_at",
  "purpose",
  "revision",
  "state",
] as const;
const KEY_PACKAGE_KEYS = ["account", "expires_at", "reference"] as const;

const INVALID_KEY_PACKAGE = Object.freeze({
  verdict: "reject" as const,
  reason_code: "control-keypackage-invalid" as const,
});
const UNAVAILABLE = Object.freeze({
  verdict: "reject" as const,
  reason_code: "control-enrollment-unavailable" as const,
});
const REPLENISHMENT_PAUSED = Object.freeze({
  verdict: "reject" as const,
  reason_code: "control-keypackage-replenishment-paused" as const,
});

function exactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && expected.every((key, index) => actual[index] === key);
}

function ownDataProperty(object: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
    throw new TypeError(`Control enrollment config requires data property ${name}`);
  }
  return descriptor.value;
}

function boundMethod<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  let owner: object | null = object;
  while (owner !== null) {
    if (utilTypes.isProxy(owner)) {
      throw new TypeError("Control enrollment store cannot be a proxy");
    }
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function"
        || utilTypes.isProxy(descriptor.value)) {
        throw new TypeError(`Control enrollment store requires data method ${name}`);
      }
      return descriptor.value.bind(object) as T;
    }
    owner = Object.getPrototypeOf(owner) as object | null;
  }
  throw new TypeError(`Control enrollment store requires method ${name}`);
}

function captureConfig(config: ControlEnrollmentAdmissionAuthorityConfig): AuthorityRecord {
  if (config === null || typeof config !== "object" || utilTypes.isProxy(config)
    || Object.getPrototypeOf(config) !== Object.prototype) {
    throw new TypeError("Control enrollment authority config must be an ordinary object");
  }
  const descriptors = Object.getOwnPropertyDescriptors(config);
  const required = [
    "authority_id",
    "load_inventory",
    "load_invite_state",
    "store",
    "trusted_now",
    "verify_key_package",
  ];
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string") || keys.length !== required.length
    || !required.every((key) => Object.hasOwn(descriptors, key))) {
    throw new TypeError("Control enrollment authority config must be closed");
  }
  const authorityId = ownDataProperty(config, "authority_id");
  const trustedNow = ownDataProperty(config, "trusted_now");
  const store = ownDataProperty(config, "store");
  const loadInventory = ownDataProperty(config, "load_inventory");
  const loadInviteState = ownDataProperty(config, "load_invite_state");
  const verifyKeyPackage = ownDataProperty(config, "verify_key_package");
  if (typeof authorityId !== "string" || authorityId.length === 0
    || typeof trustedNow !== "function" || utilTypes.isProxy(trustedNow)
    || typeof loadInventory !== "function" || utilTypes.isProxy(loadInventory)
    || typeof loadInviteState !== "function" || utilTypes.isProxy(loadInviteState)
    || typeof verifyKeyPackage !== "function" || utilTypes.isProxy(verifyKeyPackage)
    || store === null || typeof store !== "object" || utilTypes.isProxy(store)) {
    throw new TypeError("Control enrollment authority config is invalid");
  }
  return Object.freeze({
    authority_id: authorityId,
    trusted_now: trustedNow as AuthorityRecord["trusted_now"],
    load_inventory: loadInventory as AuthorityRecord["load_inventory"],
    load_invite_state: loadInviteState as AuthorityRecord["load_invite_state"],
    verify_key_package: verifyKeyPackage as AuthorityRecord["verify_key_package"],
    store: Object.freeze({
      load: boundMethod<StoreCallbacks["load"]>(store, "load"),
      acquire: boundMethod<StoreCallbacks["acquire"]>(store, "acquire"),
      compareAndSwap: boundMethod<StoreCallbacks["compareAndSwap"]>(store, "compareAndSwap"),
      commit: boundMethod<StoreCallbacks["commit"]>(store, "commit"),
      markIndeterminate: boundMethod<StoreCallbacks["markIndeterminate"]>(
        store,
        "markIndeterminate",
      ),
    }),
  });
}

export function createControlEnrollmentAdmissionAuthority(
  config: ControlEnrollmentAdmissionAuthorityConfig,
): ControlEnrollmentAdmissionAuthority {
  const record = captureConfig(config);
  const authority = Object.freeze({});
  AUTHORITIES.set(authority, record);
  return authority;
}

function captureRequest(value: ControlEnrollmentAdmissionRequest):
ControlEnrollmentAdmissionRequest | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)
      || !exactKeys(captured as Readonly<Record<string, unknown>>, REQUEST_KEYS)) return null;
    const request = captured as ControlEnrollmentAdmissionRequest;
    if (typeof request.persona !== "string" || request.persona.length === 0
      || typeof request.account !== "string" || request.account.length === 0
      || typeof request.device_id !== "string" || request.device_id.length === 0
      || typeof request.client_key !== "string" || request.client_key.length === 0
      || typeof request.group_id !== "string" || request.group_id.length === 0
      || typeof request.invite_id !== "string" || request.invite_id.length === 0
      || request.invite_purpose !== "control-enrollment"
      || !(request.key_package_bytes instanceof Uint8Array)
      || request.key_package_bytes.length === 0
      || typeof request.expected_key_package_ref !== "string"
      || request.expected_key_package_ref.length === 0
      || (request.reserved_slot !== null
        && (typeof request.reserved_slot !== "string" || request.reserved_slot.length === 0))) {
      return null;
    }
    return Object.freeze({
      ...request,
      key_package_bytes: new Uint8Array(request.key_package_bytes),
    });
  } catch {
    return null;
  }
}

function captureKeyPackage(value: unknown): VerifiedKeyPackage | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)
      || !exactKeys(captured as Readonly<Record<string, unknown>>, KEY_PACKAGE_KEYS)) return null;
    const keyPackage = captured as VerifiedKeyPackage;
    return typeof keyPackage.account === "string" && keyPackage.account.length > 0
      && typeof keyPackage.reference === "string" && keyPackage.reference.length > 0
      && Number.isSafeInteger(keyPackage.expires_at) && keyPackage.expires_at >= 0
      ? keyPackage : null;
  } catch {
    return null;
  }
}

function captureStringArray(value: unknown): readonly string[] | null {
  if (!Array.isArray(value)
    || !value.every((entry) => typeof entry === "string" && entry.length > 0)
    || new Set(value).size !== value.length) return null;
  return Object.freeze([...value]);
}

function captureInventory(value: unknown): Inventory | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)
      || !exactKeys(captured as Readonly<Record<string, unknown>>, INVENTORY_KEYS)) return null;
    const candidate = captured as Inventory;
    const reservedSlots = captureStringArray(candidate.reserved_slots);
    const currentClients = captureStringArray(candidate.current_clients);
    const enrolledAccounts = captureStringArray(candidate.enrolled_accounts);
    const enrolledDevices = captureStringArray(candidate.enrolled_devices);
    if (!Number.isSafeInteger(candidate.revision) || candidate.revision < 0
      || !Number.isSafeInteger(candidate.pending_for_account)
      || candidate.pending_for_account < 0
      || !Number.isSafeInteger(candidate.global_pending) || candidate.global_pending < 0
      || !Number.isSafeInteger(candidate.global_pending_cap)
      || candidate.global_pending_cap < 0
      || !Number.isSafeInteger(candidate.rate_window_started_at)
      || candidate.rate_window_started_at < 0
      || !Number.isSafeInteger(candidate.attempts_in_window)
      || candidate.attempts_in_window < 0
      || !Number.isSafeInteger(candidate.attempt_budget) || candidate.attempt_budget < 1
      || candidate.attempts_in_window > candidate.attempt_budget
      || !["ready", "paused"].includes(candidate.replenishment_state)
      || reservedSlots === null || currentClients === null
      || enrolledAccounts === null || enrolledDevices === null) return null;
    return Object.freeze({
      ...candidate,
      reserved_slots: reservedSlots,
      current_clients: currentClients,
      enrolled_accounts: enrolledAccounts,
      enrolled_devices: enrolledDevices,
    });
  } catch {
    return null;
  }
}

function captureInvite(value: unknown): Invite | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)
      || !exactKeys(captured as Readonly<Record<string, unknown>>, INVITE_KEYS)) return null;
    const candidate = captured as Invite;
    return Number.isSafeInteger(candidate.revision) && candidate.revision >= 0
      && candidate.purpose === "control-enrollment"
      && ["active", "revoked", "consumed"].includes(candidate.state)
      && typeof candidate.account === "string" && candidate.account.length > 0
      && typeof candidate.client_key === "string" && candidate.client_key.length > 0
      && Number.isSafeInteger(candidate.expires_at) && candidate.expires_at >= 0
      ? candidate : null;
  } catch {
    return null;
  }
}

function trustedNow(authority: AuthorityRecord): number | null {
  try {
    const now = authority.trusted_now();
    return Number.isSafeInteger(now) && now >= 0 ? now : null;
  } catch {
    return null;
  }
}

function reservationKey(authority: AuthorityRecord, request: ControlEnrollmentAdmissionRequest):
string {
  return authorityBindingDigest("heterodyne.control-enrollment.reservation-key/v1", {
    authority_id: authority.authority_id,
    invite_id: request.invite_id,
  });
}

function durableRequest(
  authority: AuthorityRecord,
  request: ControlEnrollmentAdmissionRequest,
  keyPackage: VerifiedKeyPackage,
): DurableRequest {
  const key = reservationKey(authority, request);
  const requestDigest = authorityBindingDigest("heterodyne.control-enrollment.request/v1", {
    persona: request.persona,
    account: request.account,
    device_id: request.device_id,
    client_key: request.client_key,
    group_id: request.group_id,
    invite_id: request.invite_id,
    invite_purpose: request.invite_purpose,
    key_package_bytes: request.key_package_bytes,
    expected_key_package_ref: request.expected_key_package_ref,
    reserved_slot: request.reserved_slot,
    verified_key_package: keyPackage,
  });
  const bindingDigest = authorityBindingDigest(
    "heterodyne.control-enrollment.reservation-binding/v1",
    { authority_id: authority.authority_id, key, request_digest: requestDigest },
  );
  const executionToken = authorityBindingDigest(
    "heterodyne.control-enrollment.execution/v1",
    { authority_id: authority.authority_id, key, binding_digest: bindingDigest },
  );
  const output = Object.freeze({
    enrollment_id: authorityBindingDigest("heterodyne.control-enrollment.identifier/v1", {
      authority_id: authority.authority_id,
      key,
      binding_digest: bindingDigest,
    }),
    group_id: request.group_id,
  });
  const outputDigest = authorityBindingDigest(
    "heterodyne.control-enrollment.output/v1",
    output,
  );
  const reconciliationDigest = authorityBindingDigest(
    "heterodyne.control-enrollment.reconciliation/v1",
    {
      authority_id: authority.authority_id,
      key,
      binding_digest: bindingDigest,
      execution_token: executionToken,
    },
  );
  return Object.freeze({
    key,
    binding_digest: bindingDigest,
    execution_token: executionToken,
    output_digest: outputDigest,
    reconciliation_digest: reconciliationDigest,
    output,
  });
}

function indeterminate(reconciliationDigest: string): ControlEnrollmentAdmissionDecision {
  return Object.freeze({
    verdict: "indeterminate" as const,
    reconciliation_digest: reconciliationDigest,
  });
}

function failureDigest(
  authority: AuthorityRecord,
  key: string,
  phase: string,
): ControlEnrollmentAdmissionDecision {
  return indeterminate(authorityBindingDigest("heterodyne.control-enrollment.failure/v1", {
    authority_id: authority.authority_id,
    key,
    phase,
  }));
}

function captureOutput(value: unknown): EnrollmentOutput | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)
      || !exactKeys(captured as Readonly<Record<string, unknown>>, [
        "enrollment_id", "group_id",
      ])) return null;
    const output = captured as EnrollmentOutput;
    return typeof output.enrollment_id === "string" && HEX_32.test(output.enrollment_id)
      && typeof output.group_id === "string" && output.group_id.length > 0
      ? Object.freeze(output) : null;
  } catch {
    return null;
  }
}

function captureDurableRecord(value: unknown): DurableAuthorityRecord<EnrollmentOutput> | null {
  if (value === null) return null;
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) {
      throw new TypeError("invalid durable record");
    }
    const record = captured as unknown as DurableAuthorityRecord<EnrollmentOutput>;
    if (!Number.isSafeInteger(record.revision) || record.revision < 0
      || typeof record.binding_digest !== "string" || !HEX_32.test(record.binding_digest)) {
      throw new TypeError("invalid durable record");
    }
    if (record.state === "available") {
      if (!exactKeys(record as unknown as Readonly<Record<string, unknown>>, [
        "binding_digest", "output", "revision", "state",
      ]) || captureOutput(record.output) === null) throw new TypeError("invalid available record");
    } else if (record.state === "executing") {
      if (!exactKeys(record as unknown as Readonly<Record<string, unknown>>, [
        "binding_digest", "execution_token", "revision", "state",
      ]) || typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)) {
        throw new TypeError("invalid executing record");
      }
    } else if (record.state === "committed") {
      if (!exactKeys(record as unknown as Readonly<Record<string, unknown>>, [
        "binding_digest", "execution_token", "output", "output_digest", "revision", "state",
      ]) || typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)
        || typeof record.output_digest !== "string" || !HEX_32.test(record.output_digest)
        || captureOutput(record.output) === null) throw new TypeError("invalid committed record");
    } else if (record.state === "indeterminate") {
      if (!exactKeys(record as unknown as Readonly<Record<string, unknown>>, [
        "binding_digest", "execution_token", "reconciliation_digest", "revision", "state",
      ]) || typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)
        || typeof record.reconciliation_digest !== "string"
        || !HEX_32.test(record.reconciliation_digest)) {
        throw new TypeError("invalid indeterminate record");
      }
    } else {
      throw new TypeError("invalid durable state");
    }
    return record;
  } catch {
    throw new TypeError("invalid durable record");
  }
}

function exactOutput(left: EnrollmentOutput, right: EnrollmentOutput): boolean {
  return left.enrollment_id === right.enrollment_id && left.group_id === right.group_id;
}

function durableDecision(
  record: DurableAuthorityRecord<EnrollmentOutput> | null,
  expected: DurableRequest,
): ControlEnrollmentAdmissionDecision | null {
  if (record === null || record.binding_digest !== expected.binding_digest) return null;
  if (record.state === "committed") {
    const output = captureOutput(record.output);
    if (record.execution_token !== expected.execution_token
      || record.output_digest !== expected.output_digest
      || output === null || !exactOutput(output, expected.output)) return null;
    return Object.freeze({ verdict: "accept" as const, output });
  }
  if (record.state === "indeterminate") {
    return record.execution_token === expected.execution_token
      && record.reconciliation_digest === expected.reconciliation_digest
      ? indeterminate(expected.reconciliation_digest) : null;
  }
  if (record.state === "executing") {
    return record.execution_token === expected.execution_token
      ? indeterminate(expected.reconciliation_digest) : null;
  }
  return null;
}

function exactAvailable(
  record: DurableAuthorityRecord<EnrollmentOutput> | null,
  expected: DurableRequest,
): record is Extract<DurableAuthorityRecord<EnrollmentOutput>, { state: "available" }> {
  return record?.state === "available"
    && record.binding_digest === expected.binding_digest
    && exactOutput(record.output, expected.output);
}

async function loadDurable(
  authority: AuthorityRecord,
  key: string,
): Promise<DurableAuthorityRecord<EnrollmentOutput> | null | undefined> {
  try {
    return captureDurableRecord(await authority.store.load(key));
  } catch {
    return undefined;
  }
}

function validateInvite(
  inviteState: Invite | null,
  request: ControlEnrollmentAdmissionRequest,
  now: number,
): boolean {
  return inviteState !== null
    && request.invite_purpose === "control-enrollment"
    && inviteState.purpose === request.invite_purpose
    && inviteState.state === "active"
    && inviteState.account === request.account
    && inviteState.client_key === request.client_key
    && now < inviteState.expires_at;
}

function inventoryDecision(
  inventoryState: Inventory | null,
  request: ControlEnrollmentAdmissionRequest,
  now: number,
): ControlEnrollmentAdmissionDecision | null {
  if (inventoryState === null || inventoryState.rate_window_started_at > now) return UNAVAILABLE;
  if (inventoryState.current_clients.includes(request.client_key)) return INVALID_KEY_PACKAGE;
  if (inventoryState.replenishment_state === "paused") return REPLENISHMENT_PAUSED;
  if (inventoryState.enrolled_accounts.includes(request.account)
    || inventoryState.enrolled_devices.includes(request.device_id)
    || inventoryState.pending_for_account > 0
    || inventoryState.attempts_in_window >= inventoryState.attempt_budget
    || inventoryState.global_pending > inventoryState.global_pending_cap) return UNAVAILABLE;
  if (request.reserved_slot !== null) {
    if (!inventoryState.reserved_slots.includes(request.reserved_slot)) return UNAVAILABLE;
  } else if (inventoryState.global_pending >= inventoryState.global_pending_cap) {
    return UNAVAILABLE;
  }
  return null;
}

async function loadCurrentState(
  authority: AuthorityRecord,
  request: ControlEnrollmentAdmissionRequest,
): Promise<Readonly<{ inventory: Inventory | null; invite: Invite | null }> | null> {
  try {
    const [inventoryValue, inviteValue] = await Promise.all([
      authority.load_inventory(request.persona),
      authority.load_invite_state(request.invite_id),
    ]);
    return Object.freeze({
      inventory: captureInventory(inventoryValue),
      invite: captureInvite(inviteValue),
    });
  } catch {
    return null;
  }
}

function currentDecision(
  current: Awaited<ReturnType<typeof loadCurrentState>>,
  request: ControlEnrollmentAdmissionRequest,
  now: number,
): ControlEnrollmentAdmissionDecision | null {
  if (current === null || !validateInvite(current.invite, request, now)) return UNAVAILABLE;
  return inventoryDecision(current.inventory, request, now);
}

async function reconcileAfterEffect(
  authority: AuthorityRecord,
  expected: DurableRequest,
): Promise<ControlEnrollmentAdmissionDecision> {
  let observed = await loadDurable(authority, expected.key);
  if (observed !== undefined) {
    const terminal = durableDecision(observed, expected);
    if (terminal !== null && observed?.state !== "executing") return terminal;
  }
  try {
    await authority.store.markIndeterminate({
      key: expected.key,
      binding_digest: expected.binding_digest,
      execution_token: expected.execution_token,
      reconciliation_digest: expected.reconciliation_digest,
    });
  } catch {
    // Readback below is authoritative; a thrown terminal write cannot reopen the effect.
  }
  observed = await loadDurable(authority, expected.key);
  if (observed !== undefined) {
    const terminal = durableDecision(observed, expected);
    if (terminal !== null) return terminal;
  }
  return indeterminate(expected.reconciliation_digest);
}

async function ensureAvailable(
  authority: AuthorityRecord,
  expected: DurableRequest,
  observed: DurableAuthorityRecord<EnrollmentOutput> | null,
): Promise<
  | Extract<DurableAuthorityRecord<EnrollmentOutput>, { state: "available" }>
  | ControlEnrollmentAdmissionDecision
> {
  if (exactAvailable(observed, expected)) return observed;
  if (observed !== null) {
    const terminal = durableDecision(observed, expected);
    return terminal ?? UNAVAILABLE;
  }
  const available = Object.freeze({
    state: "available" as const,
    revision: 0,
    binding_digest: expected.binding_digest,
    output: expected.output,
  });
  let result: "committed" | "conflict" | "unknown";
  try {
    result = await authority.store.compareAndSwap({
      key: expected.key,
      expected_revision: null,
      next: available,
    });
  } catch {
    result = "unknown";
  }
  const current = await loadDurable(authority, expected.key);
  if (current === undefined) return failureDigest(authority, expected.key, "reservation-readback");
  if (exactAvailable(current, expected)) return current;
  const terminal = durableDecision(current, expected);
  if (terminal !== null) return terminal;
  return result === "unknown"
    ? failureDigest(authority, expected.key, "reservation-unknown")
    : UNAVAILABLE;
}

export async function admitControlEnrollment(
  authority: ControlEnrollmentAdmissionAuthority,
  value: ControlEnrollmentAdmissionRequest,
): Promise<ControlEnrollmentAdmissionDecision> {
  const authorityRecord = AUTHORITIES.get(authority);
  if (authorityRecord === undefined) return UNAVAILABLE;
  const request = captureRequest(value);
  if (request === null) return INVALID_KEY_PACKAGE;

  let keyPackage: VerifiedKeyPackage | null;
  try {
    keyPackage = captureKeyPackage(authorityRecord.verify_key_package(
      new Uint8Array(request.key_package_bytes),
    ));
  } catch {
    keyPackage = null;
  }
  if (keyPackage === null
    || keyPackage.account !== request.account
    || keyPackage.reference !== request.expected_key_package_ref) return INVALID_KEY_PACKAGE;

  const expected = durableRequest(authorityRecord, request, keyPackage);
  const initialDurable = await loadDurable(authorityRecord, expected.key);
  if (initialDurable === undefined) {
    return failureDigest(authorityRecord, expected.key, "initial-load");
  }
  if (initialDurable !== null && initialDurable.state !== "available") {
    return durableDecision(initialDurable, expected) ?? UNAVAILABLE;
  }

  const now = trustedNow(authorityRecord);
  if (now === null) return UNAVAILABLE;
  if (now >= keyPackage.expires_at) return INVALID_KEY_PACKAGE;

  const initialCurrent = await loadCurrentState(authorityRecord, request);
  const initialDecision = currentDecision(initialCurrent, request, now);
  if (initialDecision !== null) return initialDecision;

  const available = await ensureAvailable(authorityRecord, expected, initialDurable);
  if (!("state" in available)) return available;

  const effectNow = trustedNow(authorityRecord);
  if (effectNow === null) return UNAVAILABLE;
  if (effectNow >= keyPackage.expires_at) return INVALID_KEY_PACKAGE;
  const effectCurrent = await loadCurrentState(authorityRecord, request);
  const effectDecision = currentDecision(effectCurrent, request, effectNow);
  if (effectDecision !== null) return effectDecision;

  let acquired: "acquired" | "replay" | "conflict" | "unavailable";
  try {
    acquired = await authorityRecord.store.acquire({
      key: expected.key,
      expected_revision: available.revision,
      binding_digest: expected.binding_digest,
      execution_token: expected.execution_token,
    });
  } catch {
    return failureDigest(authorityRecord, expected.key, "acquire-throw");
  }
  if (acquired !== "acquired") {
    const observed = await loadDurable(authorityRecord, expected.key);
    if (observed !== undefined) {
      const terminal = durableDecision(observed, expected);
      if (terminal !== null) return terminal;
    }
    return acquired === "unavailable" || acquired === "conflict"
      ? UNAVAILABLE
      : indeterminate(expected.reconciliation_digest);
  }

  let committed: "committed" | "conflict" | "unknown";
  try {
    committed = await authorityRecord.store.commit({
      key: expected.key,
      binding_digest: expected.binding_digest,
      execution_token: expected.execution_token,
      output_digest: expected.output_digest,
      output: expected.output,
    });
  } catch {
    committed = "unknown";
  }
  if (committed === "committed") {
    const observed = await loadDurable(authorityRecord, expected.key);
    if (observed !== undefined) {
      const terminal = durableDecision(observed, expected);
      if (terminal !== null && observed?.state === "committed") return terminal;
    }
  }
  return reconcileAfterEffect(authorityRecord, expected);
}
