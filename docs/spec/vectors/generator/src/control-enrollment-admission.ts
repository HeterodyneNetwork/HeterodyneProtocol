import { types as utilTypes } from "node:util";
import {
  authorityBindingDigest,
  type AuthorityDecision,
} from "./security-authority-support.js";

type EnrollmentOutput = Readonly<{ enrollment_id: string; group_id: string }>;

export type ControlEnrollmentReservationRecord = Readonly<
  | {
    state: "executing";
    revision: number;
    binding_digest: string;
    reservation_digest: string;
    execution_token: string;
  }
  | {
    state: "committed";
    revision: number;
    binding_digest: string;
    reservation_digest: string;
    execution_token: string;
    output_digest: string;
    output: EnrollmentOutput;
  }
  | {
    state: "indeterminate";
    revision: number;
    binding_digest: string;
    reservation_digest: string;
    execution_token: string;
    reconciliation_digest: string;
  }
>;

export type ControlEnrollmentReservationInput = Readonly<{
  key: string;
  authority_id: string;
  binding_digest: string;
  reservation_digest: string;
  execution_token: string;
  persona: string;
  account: string;
  device_id: string;
  client_key: string;
  group_id: string;
  invite_id: string;
  reserved_slot: string | null;
  trusted_now: number;
  key_package_expires_at: number;
  inventory_revision: number;
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
  invite_revision: number;
  invite_purpose: "control-enrollment";
  invite_state: "active" | "revoked" | "consumed";
  invite_account: string;
  invite_client_key: string;
  invite_expires_at: number;
}>;

export interface ControlEnrollmentReservationStore {
  load(key: string): Promise<ControlEnrollmentReservationRecord | null>;
  reserve(input: ControlEnrollmentReservationInput): Promise<
    | "acquired"
    | "replay"
    | "conflict"
    | "unavailable"
    | "keypackage-invalid"
    | "replenishment-paused"
    | "unknown"
  >;
  commit(input: Readonly<{
    key: string;
    binding_digest: string;
    reservation_digest: string;
    execution_token: string;
    output_digest: string;
    output: EnrollmentOutput;
  }>): Promise<"committed" | "conflict" | "unknown">;
  markIndeterminate(input: Readonly<{
    key: string;
    binding_digest: string;
    reservation_digest: string;
    execution_token: string;
    reconciliation_digest: string;
  }>): Promise<"indeterminate" | "conflict" | "unknown">;
}

export type ControlEnrollmentAdmissionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  store: ControlEnrollmentReservationStore;
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

type StoreCallbacks = Readonly<{
  load: ControlEnrollmentReservationStore["load"];
  reserve: ControlEnrollmentReservationStore["reserve"];
  commit: ControlEnrollmentReservationStore["commit"];
  markIndeterminate: ControlEnrollmentReservationStore["markIndeterminate"];
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
type CurrentState = Readonly<{ inventory: Inventory; invite: Invite }>;
type DurableBase = Readonly<{
  key: string;
  binding_digest: string;
}>;
type DurableRequest = DurableBase & Readonly<{
  reservation_digest: string;
  execution_token: string;
  output_digest: string;
  reconciliation_digest: string;
  output: EnrollmentOutput;
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const HEX_32 = /^[0-9a-f]{64}$/;
const MAX_IDENTIFIER_CHARS = 512;
const MAX_KEY_PACKAGE_BYTES = 65_536;
const MAX_LIST_ITEMS = 256;
const MAX_LIST_AGGREGATE_CHARS = 65_536;
const MAX_PUBLIC_AGGREGATE = 73_728;
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

function boundedString(value: unknown, allowEmpty = false): value is string {
  return typeof value === "string"
    && value.length <= MAX_IDENTIFIER_CHARS
    && (allowEmpty || value.length > 0);
}

function shallowRecord(
  value: unknown,
  expectedKeys: readonly string[] | null,
  maximumKeys = expectedKeys?.length ?? 0,
): Readonly<Record<string, unknown>> | null {
  if (value === null || typeof value !== "object" || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Object.prototype) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string") || keys.length > maximumKeys) return null;
  if (expectedKeys !== null && (keys.length !== expectedKeys.length
    || !expectedKeys.every((key) => Object.hasOwn(descriptors, key)))) return null;
  const result: Record<string, unknown> = {};
  for (const key of keys as string[]) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      return null;
    }
    result[key] = descriptor.value;
  }
  return result;
}

function boundedBytes(value: unknown): Uint8Array | null {
  if (value === null || typeof value !== "object" || utilTypes.isProxy(value)
    || !(value instanceof Uint8Array)
    || Object.getPrototypeOf(value) !== Uint8Array.prototype
    || value.length === 0 || value.length > MAX_KEY_PACKAGE_BYTES) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== value.length || keys.some((key) => typeof key !== "string"
    || !/^(0|[1-9][0-9]*)$/.test(key))) return null;
  return new Uint8Array(value);
}

function boundedStringList(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Array.prototype) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as
    Record<PropertyKey, PropertyDescriptor>;
  const lengthDescriptor = descriptors.length;
  if (lengthDescriptor === undefined || !Number.isSafeInteger(lengthDescriptor.value)
    || lengthDescriptor.value < 0
    || lengthDescriptor.value > MAX_LIST_ITEMS) return null;
  const length = lengthDescriptor.value as number;
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length !== length + 1) return null;
  let aggregate = 0;
  const result: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true
      || !boundedString(descriptor.value)) return null;
    aggregate += descriptor.value.length;
    if (aggregate > MAX_LIST_AGGREGATE_CHARS) return null;
    result.push(descriptor.value);
  }
  return new Set(result).size === result.length ? Object.freeze(result) : null;
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
  let depth = 0;
  while (owner !== null && depth < 8) {
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
    depth += 1;
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
  if (!boundedString(authorityId)
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
      reserve: boundMethod<StoreCallbacks["reserve"]>(store, "reserve"),
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

type RequestCapture = Readonly<
  | { kind: "captured"; request: ControlEnrollmentAdmissionRequest }
  | { kind: "keypackage-invalid" }
  | { kind: "unavailable" }
>;

function captureRequest(value: ControlEnrollmentAdmissionRequest): RequestCapture {
  const captured = shallowRecord(value, REQUEST_KEYS);
  if (captured === null) return Object.freeze({ kind: "unavailable" });
  if (!boundedString(captured.persona)
    || !boundedString(captured.account)
    || !boundedString(captured.device_id)
    || !boundedString(captured.client_key)
    || !boundedString(captured.group_id)
    || !boundedString(captured.invite_id)
    || captured.invite_purpose !== "control-enrollment"
    || (captured.reserved_slot !== null && !boundedString(captured.reserved_slot))) {
    return Object.freeze({ kind: "unavailable" });
  }
  const keyPackageBytes = boundedBytes(captured.key_package_bytes);
  if (keyPackageBytes === null || !boundedString(captured.expected_key_package_ref)) {
    return Object.freeze({ kind: "keypackage-invalid" });
  }
  const aggregate = captured.persona.length + captured.account.length
    + captured.device_id.length + captured.client_key.length + captured.group_id.length
    + captured.invite_id.length + captured.expected_key_package_ref.length
    + (captured.reserved_slot?.length ?? 0) + keyPackageBytes.length;
  if (aggregate > MAX_PUBLIC_AGGREGATE) {
    return Object.freeze({ kind: "unavailable" });
  }
  return Object.freeze({
    kind: "captured",
    request: Object.freeze({
      persona: captured.persona,
      account: captured.account,
      device_id: captured.device_id,
      client_key: captured.client_key,
      group_id: captured.group_id,
      invite_id: captured.invite_id,
      invite_purpose: captured.invite_purpose,
      key_package_bytes: keyPackageBytes,
      expected_key_package_ref: captured.expected_key_package_ref,
      reserved_slot: captured.reserved_slot,
    }),
  });
}

function captureKeyPackage(value: unknown): VerifiedKeyPackage | null {
  const captured = shallowRecord(value, KEY_PACKAGE_KEYS);
  if (captured === null || !boundedString(captured.account)
    || !boundedString(captured.reference)
    || !Number.isSafeInteger(captured.expires_at) || (captured.expires_at as number) < 0) {
    return null;
  }
  return Object.freeze({
    account: captured.account,
    reference: captured.reference,
    expires_at: captured.expires_at as number,
  });
}

function captureInventory(value: unknown): Inventory | null {
  const candidate = shallowRecord(value, INVENTORY_KEYS);
  if (candidate === null) return null;
  const reservedSlots = boundedStringList(candidate.reserved_slots);
  const currentClients = boundedStringList(candidate.current_clients);
  const enrolledAccounts = boundedStringList(candidate.enrolled_accounts);
  const enrolledDevices = boundedStringList(candidate.enrolled_devices);
  if (!Number.isSafeInteger(candidate.revision) || (candidate.revision as number) < 0
    || !Number.isSafeInteger(candidate.pending_for_account)
    || (candidate.pending_for_account as number) < 0
    || !Number.isSafeInteger(candidate.global_pending) || (candidate.global_pending as number) < 0
    || !Number.isSafeInteger(candidate.global_pending_cap)
    || (candidate.global_pending_cap as number) < 0
    || !Number.isSafeInteger(candidate.rate_window_started_at)
    || (candidate.rate_window_started_at as number) < 0
    || !Number.isSafeInteger(candidate.attempts_in_window)
    || (candidate.attempts_in_window as number) < 0
    || !Number.isSafeInteger(candidate.attempt_budget) || (candidate.attempt_budget as number) < 1
    || (candidate.attempts_in_window as number) > (candidate.attempt_budget as number)
    || !["ready", "paused"].includes(candidate.replenishment_state as string)
    || reservedSlots === null || currentClients === null
    || enrolledAccounts === null || enrolledDevices === null
    || reservedSlots.reduce((sum, item) => sum + item.length, 0)
      + currentClients.reduce((sum, item) => sum + item.length, 0)
      + enrolledAccounts.reduce((sum, item) => sum + item.length, 0)
      + enrolledDevices.reduce((sum, item) => sum + item.length, 0)
        > MAX_LIST_AGGREGATE_CHARS) return null;
  return Object.freeze({
    revision: candidate.revision as number,
    pending_for_account: candidate.pending_for_account as number,
    global_pending: candidate.global_pending as number,
    global_pending_cap: candidate.global_pending_cap as number,
    reserved_slots: reservedSlots,
    replenishment_state: candidate.replenishment_state as "ready" | "paused",
    current_clients: currentClients,
    enrolled_accounts: enrolledAccounts,
    enrolled_devices: enrolledDevices,
    rate_window_started_at: candidate.rate_window_started_at as number,
    attempts_in_window: candidate.attempts_in_window as number,
    attempt_budget: candidate.attempt_budget as number,
  });
}

function captureInvite(value: unknown): Invite | null {
  const candidate = shallowRecord(value, INVITE_KEYS);
  if (candidate === null || !Number.isSafeInteger(candidate.revision)
    || (candidate.revision as number) < 0 || candidate.purpose !== "control-enrollment"
    || !["active", "revoked", "consumed"].includes(candidate.state as string)
    || !boundedString(candidate.account) || !boundedString(candidate.client_key)
    || !Number.isSafeInteger(candidate.expires_at) || (candidate.expires_at as number) < 0) {
    return null;
  }
  return Object.freeze({
    revision: candidate.revision as number,
    purpose: "control-enrollment",
    state: candidate.state as Invite["state"],
    account: candidate.account,
    client_key: candidate.client_key,
    expires_at: candidate.expires_at as number,
  });
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

function durableBase(
  authority: AuthorityRecord,
  request: ControlEnrollmentAdmissionRequest,
  keyPackage: VerifiedKeyPackage,
): DurableBase {
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
  return Object.freeze({ key, binding_digest: bindingDigest });
}

function durableRequest(
  authority: AuthorityRecord,
  request: ControlEnrollmentAdmissionRequest,
  base: DurableBase,
  reservationDigest: string,
): DurableRequest {
  const executionToken = authorityBindingDigest(
    "heterodyne.control-enrollment.execution/v1",
    {
      authority_id: authority.authority_id,
      key: base.key,
      binding_digest: base.binding_digest,
      reservation_digest: reservationDigest,
    },
  );
  const output = Object.freeze({
    enrollment_id: authorityBindingDigest("heterodyne.control-enrollment.identifier/v1", {
      authority_id: authority.authority_id,
      key: base.key,
      binding_digest: base.binding_digest,
      reservation_digest: reservationDigest,
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
      key: base.key,
      binding_digest: base.binding_digest,
      reservation_digest: reservationDigest,
      execution_token: executionToken,
    },
  );
  return Object.freeze({
    ...base,
    reservation_digest: reservationDigest,
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
  const captured = shallowRecord(value, ["enrollment_id", "group_id"]);
  return captured !== null && typeof captured.enrollment_id === "string"
    && HEX_32.test(captured.enrollment_id) && boundedString(captured.group_id)
    ? Object.freeze({
      enrollment_id: captured.enrollment_id,
      group_id: captured.group_id,
    }) : null;
}

function captureDurableRecord(value: unknown): ControlEnrollmentReservationRecord | null {
  if (value === null) return null;
  const captured = shallowRecord(value, null, 8);
  if (captured === null || !Number.isSafeInteger(captured.revision)
    || (captured.revision as number) < 0
    || typeof captured.binding_digest !== "string" || !HEX_32.test(captured.binding_digest)
    || typeof captured.reservation_digest !== "string" || !HEX_32.test(captured.reservation_digest)
    || typeof captured.execution_token !== "string" || !HEX_32.test(captured.execution_token)) {
    throw new TypeError("invalid durable record");
  }
  const common = {
    revision: captured.revision as number,
    binding_digest: captured.binding_digest,
    reservation_digest: captured.reservation_digest,
    execution_token: captured.execution_token,
  };
  if (captured.state === "executing" && exactKeys(captured, [
    "binding_digest", "execution_token", "reservation_digest", "revision", "state",
  ])) return Object.freeze({ state: "executing" as const, ...common });
  if (captured.state === "committed" && exactKeys(captured, [
    "binding_digest", "execution_token", "output", "output_digest", "reservation_digest",
    "revision", "state",
  ]) && typeof captured.output_digest === "string" && HEX_32.test(captured.output_digest)) {
    const output = captureOutput(captured.output);
    if (output !== null) return Object.freeze({
      state: "committed" as const,
      ...common,
      output_digest: captured.output_digest,
      output,
    });
  }
  if (captured.state === "indeterminate" && exactKeys(captured, [
    "binding_digest", "execution_token", "reconciliation_digest", "reservation_digest",
    "revision", "state",
  ]) && typeof captured.reconciliation_digest === "string"
    && HEX_32.test(captured.reconciliation_digest)) return Object.freeze({
    state: "indeterminate" as const,
    ...common,
    reconciliation_digest: captured.reconciliation_digest,
  });
  throw new TypeError("invalid durable record");
}

function exactOutput(left: EnrollmentOutput, right: EnrollmentOutput): boolean {
  return left.enrollment_id === right.enrollment_id && left.group_id === right.group_id;
}

function durableDecision(
  authority: AuthorityRecord,
  request: ControlEnrollmentAdmissionRequest,
  record: ControlEnrollmentReservationRecord | null,
  base: DurableBase,
): ControlEnrollmentAdmissionDecision | null {
  if (record === null || record.binding_digest !== base.binding_digest) return null;
  const expected = durableRequest(authority, request, base, record.reservation_digest);
  if (record.execution_token !== expected.execution_token) return null;
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

async function loadDurable(
  authority: AuthorityRecord,
  key: string,
): Promise<ControlEnrollmentReservationRecord | null | undefined> {
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
): Promise<CurrentState | null> {
  try {
    const [inventoryValue, inviteValue] = await Promise.all([
      authority.load_inventory(request.persona),
      authority.load_invite_state(request.invite_id),
    ]);
    const inventory = captureInventory(inventoryValue);
    const invite = captureInvite(inviteValue);
    return inventory === null || invite === null ? null : Object.freeze({ inventory, invite });
  } catch {
    return null;
  }
}

function currentDecision(
  current: CurrentState | null,
  request: ControlEnrollmentAdmissionRequest,
  now: number,
): ControlEnrollmentAdmissionDecision | null {
  if (current === null || !validateInvite(current.invite, request, now)) return UNAVAILABLE;
  return inventoryDecision(current.inventory, request, now);
}

function reservationDigest(
  authority: AuthorityRecord,
  request: ControlEnrollmentAdmissionRequest,
  keyPackage: VerifiedKeyPackage,
  current: CurrentState,
  now: number,
): string {
  return authorityBindingDigest("heterodyne.control-enrollment.atomic-state/v1", {
    authority_id: authority.authority_id,
    persona: request.persona,
    account: request.account,
    device_id: request.device_id,
    client_key: request.client_key,
    group_id: request.group_id,
    invite_id: request.invite_id,
    reserved_slot: request.reserved_slot,
    trusted_now: now,
    key_package_expires_at: keyPackage.expires_at,
    inventory: current.inventory,
    invite: current.invite,
  });
}

function reservationInput(
  authority: AuthorityRecord,
  request: ControlEnrollmentAdmissionRequest,
  keyPackage: VerifiedKeyPackage,
  current: CurrentState,
  now: number,
  expected: DurableRequest,
): ControlEnrollmentReservationInput {
  return Object.freeze({
    key: expected.key,
    authority_id: authority.authority_id,
    binding_digest: expected.binding_digest,
    reservation_digest: expected.reservation_digest,
    execution_token: expected.execution_token,
    persona: request.persona,
    account: request.account,
    device_id: request.device_id,
    client_key: request.client_key,
    group_id: request.group_id,
    invite_id: request.invite_id,
    reserved_slot: request.reserved_slot,
    trusted_now: now,
    key_package_expires_at: keyPackage.expires_at,
    inventory_revision: current.inventory.revision,
    pending_for_account: current.inventory.pending_for_account,
    global_pending: current.inventory.global_pending,
    global_pending_cap: current.inventory.global_pending_cap,
    reserved_slots: current.inventory.reserved_slots,
    replenishment_state: current.inventory.replenishment_state,
    current_clients: current.inventory.current_clients,
    enrolled_accounts: current.inventory.enrolled_accounts,
    enrolled_devices: current.inventory.enrolled_devices,
    rate_window_started_at: current.inventory.rate_window_started_at,
    attempts_in_window: current.inventory.attempts_in_window,
    attempt_budget: current.inventory.attempt_budget,
    invite_revision: current.invite.revision,
    invite_purpose: current.invite.purpose,
    invite_state: current.invite.state,
    invite_account: current.invite.account,
    invite_client_key: current.invite.client_key,
    invite_expires_at: current.invite.expires_at,
  });
}

async function reconcileAfterEffect(
  authority: AuthorityRecord,
  request: ControlEnrollmentAdmissionRequest,
  base: DurableBase,
  expected: DurableRequest,
): Promise<ControlEnrollmentAdmissionDecision> {
  let observed = await loadDurable(authority, expected.key);
  if (observed !== undefined) {
    const terminal = durableDecision(authority, request, observed, base);
    if (terminal !== null && observed?.state !== "executing") return terminal;
  }
  try {
    await authority.store.markIndeterminate({
      key: expected.key,
      binding_digest: expected.binding_digest,
      reservation_digest: expected.reservation_digest,
      execution_token: expected.execution_token,
      reconciliation_digest: expected.reconciliation_digest,
    });
  } catch {
    // Readback below is authoritative; a thrown terminal write cannot reopen the effect.
  }
  observed = await loadDurable(authority, expected.key);
  if (observed !== undefined) {
    const terminal = durableDecision(authority, request, observed, base);
    if (terminal !== null) return terminal;
  }
  return indeterminate(expected.reconciliation_digest);
}

export async function admitControlEnrollment(
  authority: ControlEnrollmentAdmissionAuthority,
  value: ControlEnrollmentAdmissionRequest,
): Promise<ControlEnrollmentAdmissionDecision> {
  const authorityRecord = AUTHORITIES.get(authority);
  if (authorityRecord === undefined) return UNAVAILABLE;
  const capturedRequest = captureRequest(value);
  if (capturedRequest.kind === "unavailable") return UNAVAILABLE;
  if (capturedRequest.kind === "keypackage-invalid") return INVALID_KEY_PACKAGE;
  const request = capturedRequest.request;

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

  const base = durableBase(authorityRecord, request, keyPackage);
  const initialDurable = await loadDurable(authorityRecord, base.key);
  if (initialDurable === undefined) {
    return failureDigest(authorityRecord, base.key, "initial-load");
  }
  if (initialDurable !== null) {
    return durableDecision(authorityRecord, request, initialDurable, base) ?? UNAVAILABLE;
  }

  const now = trustedNow(authorityRecord);
  if (now === null) return UNAVAILABLE;
  if (now >= keyPackage.expires_at) return INVALID_KEY_PACKAGE;

  const initialCurrent = await loadCurrentState(authorityRecord, request);
  const initialDecision = currentDecision(initialCurrent, request, now);
  if (initialDecision !== null) return initialDecision;

  const effectNow = trustedNow(authorityRecord);
  if (effectNow === null) return UNAVAILABLE;
  if (effectNow >= keyPackage.expires_at) return INVALID_KEY_PACKAGE;
  const effectCurrent = await loadCurrentState(authorityRecord, request);
  const effectDecision = currentDecision(effectCurrent, request, effectNow);
  if (effectDecision !== null) return effectDecision;
  if (effectCurrent === null) return UNAVAILABLE;
  const expected = durableRequest(
    authorityRecord,
    request,
    base,
    reservationDigest(authorityRecord, request, keyPackage, effectCurrent, effectNow),
  );

  let acquired: Awaited<ReturnType<StoreCallbacks["reserve"]>>;
  try {
    acquired = await authorityRecord.store.reserve(reservationInput(
      authorityRecord,
      request,
      keyPackage,
      effectCurrent,
      effectNow,
      expected,
    ));
  } catch {
    acquired = "unknown";
  }
  if (acquired !== "acquired") {
    const observed = await loadDurable(authorityRecord, expected.key);
    if (observed !== undefined) {
      const terminal = durableDecision(authorityRecord, request, observed, base);
      if (terminal !== null) return terminal;
    }
    if (acquired === "keypackage-invalid") return INVALID_KEY_PACKAGE;
    if (acquired === "replenishment-paused") return REPLENISHMENT_PAUSED;
    if (acquired === "unavailable" || acquired === "conflict") return UNAVAILABLE;
    return reconcileAfterEffect(authorityRecord, request, base, expected);
  }

  let committed: "committed" | "conflict" | "unknown";
  try {
    committed = await authorityRecord.store.commit({
      key: expected.key,
      binding_digest: expected.binding_digest,
      reservation_digest: expected.reservation_digest,
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
      const terminal = durableDecision(authorityRecord, request, observed, base);
      if (terminal !== null && observed?.state === "committed") return terminal;
    }
  }
  return reconcileAfterEffect(authorityRecord, request, base, expected);
}
