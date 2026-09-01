import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import { captureExactDataObject, snapshotClosedDataTree } from "./closed-data.js";

// Structurally identical to the shared Task 2 authority support contract. This
// isolated lane replaces these declarations with type-only imports when the
// prerequisite commit is composed.
export type IndeterminateDecision<I extends string = never> = Readonly<
  [I] extends [never]
    ? { verdict: "indeterminate"; reconciliation_digest: string }
    : { verdict: "indeterminate"; reason_code: I; reconciliation_digest: string }
>;

export type AuthorityDecision<R extends string, O, I extends string = never> = Readonly<
  | { verdict: "accept"; output: O }
  | { verdict: "reject"; reason_code: R }
  | IndeterminateDecision<I>
>;

export type DurableAuthorityRecord<O> = Readonly<
  | { state: "available"; revision: number; binding_digest: string; output: O }
  | { state: "executing"; revision: number; binding_digest: string; execution_token: string }
  | { state: "committed"; revision: number; binding_digest: string; execution_token: string;
      output_digest: string; output: O }
  | { state: "indeterminate"; revision: number; binding_digest: string; execution_token: string;
      reconciliation_digest: string }
>;

export interface DurableAuthorityStore<O> {
  load(key: string): Promise<DurableAuthorityRecord<O> | null>;
  acquire(input: Readonly<{
    key: string; expected_revision: number | null;
    binding_digest: string; execution_token: string;
  }>): Promise<"acquired" | "replay" | "conflict" | "unavailable">;
  compareAndSwap(input: Readonly<{
    key: string; expected_revision: number | null; next: DurableAuthorityRecord<O>;
  }>): Promise<"committed" | "conflict" | "unknown">;
  commit(input: Readonly<{
    key: string; binding_digest: string; execution_token: string;
    output_digest: string; output: O;
  }>): Promise<"committed" | "conflict" | "unknown">;
  markIndeterminate(input: Readonly<{
    key: string; binding_digest: string; execution_token: string;
    reconciliation_digest: string;
  }>): Promise<"indeterminate" | "conflict" | "unknown">;
}

type PublicDeviceState = Readonly<{
  transaction_id: string;
  state: "pending" | "approved" | "denied" | "expired";
}>;

export type ControlDeviceAuthorizationAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  random_bytes: (length: number) => Uint8Array;
  store: DurableAuthorityStore<PublicDeviceState>;
}>;

export type ControlDeviceTransactionRequest = Readonly<{
  client_id: string;
  persona: string;
  verification_uri: string;
  display_fingerprint: string;
  polling_interval_seconds: number;
  expires_in_seconds: number;
  failure_budget: 5;
}>;

export type ControlDevicePollRequest = Readonly<{
  device_code: string;
  user_code: string;
  displayed_fingerprint: string;
}>;

export type ControlDeviceTransaction = Readonly<{
  transaction_id: string;
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_at: number;
  interval_seconds: number;
}>;

export type ControlDeviceDecision = AuthorityDecision<
  | "control-device-code-invalid"
  | "control-device-code-rate-limited"
  | "control-device-code-display-mismatch",
  Readonly<{ transaction_id: string; state: "pending" | "approved" }>
>;

export type ControlDeviceAuthorizationAuthority = Readonly<Record<never, never>>;

type StoreCallbacks = Readonly<{
  load: DurableAuthorityStore<PublicDeviceState>["load"];
  acquire: DurableAuthorityStore<PublicDeviceState>["acquire"];
  compareAndSwap: DurableAuthorityStore<PublicDeviceState>["compareAndSwap"];
  commit: DurableAuthorityStore<PublicDeviceState>["commit"];
  markIndeterminate: DurableAuthorityStore<PublicDeviceState>["markIndeterminate"];
}>;

type AuthorityRecord = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  random_bytes: (length: number) => Uint8Array;
  store: StoreCallbacks;
}>;

type TerminalReason = "control-device-code-invalid" | "control-device-code-display-mismatch";

type StoredTransaction = Readonly<{
  transaction_id: string;
  state: "pending" | "approved" | "denied" | "expired";
  authority_id: string;
  client_id: string;
  persona: string;
  verification_uri: string;
  display_fingerprint: string;
  device_code_hash: string;
  user_code_hash: string;
  device_entropy_bits: 128;
  user_code_entropy_bits: 40;
  issued_at: number;
  expires_at: number;
  initial_interval_seconds: number;
  interval_seconds: number;
  next_poll_at: number;
  failed_attempts: number;
  failure_budget: 5;
  rate_violations: number;
  terminal_reason: TerminalReason | null;
  terminal_poll_digest: string | null;
}>;

type CapturedRecord = DurableAuthorityRecord<StoredTransaction>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const DEVICE_BYTES = 16;
const USER_BYTES = 5;
const COLLISION_ATTEMPTS = 8;
const HEX_32 = /^[0-9a-f]{64}$/;
const DEVICE_CODE = /^[A-Za-z0-9_-]{22}$/;
const USER_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const STORED_KEYS = [
  "authority_id", "client_id", "device_code_hash", "device_entropy_bits",
  "display_fingerprint", "expires_at", "failed_attempts", "failure_budget",
  "initial_interval_seconds", "interval_seconds", "issued_at", "next_poll_at",
  "persona", "rate_violations", "state", "terminal_poll_digest", "terminal_reason",
  "transaction_id", "user_code_entropy_bits", "user_code_hash", "verification_uri",
] as const;

const INVALID = Object.freeze({
  verdict: "reject" as const,
  reason_code: "control-device-code-invalid" as const,
});
const RATE_LIMITED = Object.freeze({
  verdict: "reject" as const,
  reason_code: "control-device-code-rate-limited" as const,
});
const DISPLAY_MISMATCH = Object.freeze({
  verdict: "reject" as const,
  reason_code: "control-device-code-display-mismatch" as const,
});

function sha256(domain: string, ...parts: readonly string[]): string {
  const hash = createHash("sha256").update(domain, "utf8");
  for (const part of parts) hash.update("\0", "utf8").update(part, "utf8");
  return hash.digest("hex");
}

function canonical(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return `s:${JSON.stringify(value)}`;
  if (typeof value === "number") return `n:${String(value)}`;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return `a:[${value.map(canonical).join(",")}]`;
  const object = value as Readonly<Record<string, unknown>>;
  return `o:{${Object.keys(object).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical(object[key])}`
  ).join(",")}}`;
}

function digestClosed(domain: string, value: Readonly<Record<string, unknown>>): string {
  return sha256(domain, canonical(value));
}

function indeterminate(
  authority: AuthorityRecord,
  key: string,
  phase: string,
  bindingDigest = "unavailable",
): IndeterminateDecision {
  return Object.freeze({
    verdict: "indeterminate" as const,
    reconciliation_digest: sha256(
      "heterodyne-control-device-reconciliation-v1",
      authority.authority_id,
      key,
      phase,
      bindingDigest,
    ),
  });
}

function ownDataProperty(object: object, name: string, label: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
    throw new TypeError(`${label} requires enumerable data property ${name}`);
  }
  return descriptor.value;
}

function boundMethod<T extends (...args: never[]) => unknown>(
  object: object,
  name: string,
): T {
  let owner: object | null = object;
  while (owner !== null) {
    if (utilTypes.isProxy(owner)) throw new TypeError("Control device store cannot be a proxy");
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new TypeError(`Control device store requires data method ${name}`);
      }
      if (utilTypes.isProxy(descriptor.value)) {
        throw new TypeError(`Control device store method ${name} cannot be a proxy`);
      }
      return descriptor.value.bind(object) as T;
    }
    owner = Object.getPrototypeOf(owner) as object | null;
  }
  throw new TypeError(`Control device store requires method ${name}`);
}

function captureConfig(config: ControlDeviceAuthorizationAuthorityConfig): AuthorityRecord {
  if (config === null || typeof config !== "object" || utilTypes.isProxy(config)
    || Object.getPrototypeOf(config) !== Object.prototype) {
    throw new TypeError("Control device authority config must be an ordinary object");
  }
  const descriptors = Object.getOwnPropertyDescriptors(config);
  const keys = Reflect.ownKeys(descriptors);
  const required = ["authority_id", "random_bytes", "store", "trusted_now"];
  if (keys.some((key) => typeof key !== "string") || keys.length !== required.length
    || !required.every((key) => Object.hasOwn(descriptors, key))) {
    throw new TypeError("Control device authority config must be closed");
  }
  const authorityId = ownDataProperty(config, "authority_id", "Control device config");
  const trustedNow = ownDataProperty(config, "trusted_now", "Control device config");
  const randomBytes = ownDataProperty(config, "random_bytes", "Control device config");
  const store = ownDataProperty(config, "store", "Control device config");
  if (typeof authorityId !== "string" || authorityId.length === 0
    || typeof trustedNow !== "function" || typeof randomBytes !== "function"
    || utilTypes.isProxy(trustedNow) || utilTypes.isProxy(randomBytes)
    || store === null || typeof store !== "object" || utilTypes.isProxy(store)) {
    throw new TypeError("Control device authority config is invalid");
  }
  return Object.freeze({
    authority_id: authorityId,
    trusted_now: trustedNow as () => number,
    random_bytes: randomBytes as (length: number) => Uint8Array,
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

export function createControlDeviceAuthorizationAuthority(
  config: ControlDeviceAuthorizationAuthorityConfig,
): ControlDeviceAuthorizationAuthority {
  const record = captureConfig(config);
  const authority = Object.freeze({});
  AUTHORITIES.set(authority, record);
  return authority;
}

function trustedNow(authority: AuthorityRecord): number {
  const now = authority.trusted_now();
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("trusted time unavailable");
  return now;
}

function entropy(authority: AuthorityRecord, length: number): Uint8Array {
  const value = authority.random_bytes(length);
  if (!(value instanceof Uint8Array) || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Uint8Array.prototype || value.length !== length) {
    throw new Error("authority entropy unavailable");
  }
  return new Uint8Array(value);
}

function encodeUserCode(bytes: Uint8Array): string {
  let bits = 0;
  let accumulator = 0;
  let normalized = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      normalized += USER_ALPHABET[(accumulator >>> bits) & 31];
    }
  }
  return `${normalized.slice(0, 4)}-${normalized.slice(4)}`;
}

function normalizeDeviceCode(value: string): string | null {
  if (!DEVICE_CODE.test(value)) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.length !== DEVICE_BYTES || decoded.toString("base64url") !== value) return null;
    return value;
  } catch {
    return null;
  }
}

function normalizeUserCode(value: string): string | null {
  if (!/^[0-9A-Za-z -]+$/.test(value)) return null;
  const normalized = value.replace(/[ -]/g, "").toUpperCase();
  return normalized.length === 8
    && [...normalized].every((character) => USER_ALPHABET.includes(character))
    ? normalized
    : null;
}

function transactionId(authority: AuthorityRecord, deviceCode: string): string {
  return sha256(
    "heterodyne-control-device-transaction-v1",
    authority.authority_id,
    sha256("heterodyne-control-device-code-v1", deviceCode),
  );
}

function staticBinding(output: StoredTransaction): Readonly<Record<string, unknown>> {
  return {
    authority_id: output.authority_id,
    client_id: output.client_id,
    device_code_hash: output.device_code_hash,
    device_entropy_bits: output.device_entropy_bits,
    display_fingerprint: output.display_fingerprint,
    expires_at: output.expires_at,
    failure_budget: output.failure_budget,
    initial_interval_seconds: output.initial_interval_seconds,
    issued_at: output.issued_at,
    persona: output.persona,
    transaction_id: output.transaction_id,
    user_code_entropy_bits: output.user_code_entropy_bits,
    user_code_hash: output.user_code_hash,
    verification_uri: output.verification_uri,
  };
}

function bindingDigest(output: StoredTransaction): string {
  return digestClosed("heterodyne-control-device-binding-v1", staticBinding(output));
}

function outputDigest(output: StoredTransaction): string {
  return digestClosed(
    "heterodyne-control-device-output-v1",
    output as unknown as Readonly<Record<string, unknown>>,
  );
}

function pollDigest(authority: AuthorityRecord, request: ControlDevicePollRequest): string {
  return digestClosed("heterodyne-control-device-poll-v1", {
    authority_id: authority.authority_id,
    device_code: request.device_code,
    displayed_fingerprint: request.displayed_fingerprint,
    user_code: request.user_code,
  });
}

function exactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length
    && [...keys].sort().every((key, index) => actual[index] === key);
}

function captureStored(value: unknown): StoredTransaction | null {
  try {
    const captured = snapshotClosedDataTree(value, "Control device durable output");
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)
      || !exactKeys(captured as Readonly<Record<string, unknown>>, STORED_KEYS)) return null;
    const output = captured as StoredTransaction;
    if (!HEX_32.test(output.transaction_id) || output.authority_id.length === 0
      || output.client_id.length === 0 || output.persona.length === 0
      || output.verification_uri.length === 0 || output.display_fingerprint.length === 0
      || !HEX_32.test(output.device_code_hash) || !HEX_32.test(output.user_code_hash)
      || output.device_entropy_bits !== 128 || output.user_code_entropy_bits !== 40
      || !Number.isSafeInteger(output.issued_at) || output.issued_at < 0
      || !Number.isSafeInteger(output.expires_at) || output.expires_at <= output.issued_at
      || !Number.isSafeInteger(output.initial_interval_seconds)
      || output.initial_interval_seconds < 1
      || !Number.isSafeInteger(output.interval_seconds)
      || output.interval_seconds < output.initial_interval_seconds
      || !Number.isSafeInteger(output.next_poll_at) || output.next_poll_at < output.issued_at
      || !Number.isSafeInteger(output.failed_attempts) || output.failed_attempts < 0
      || output.failed_attempts > output.failure_budget || output.failure_budget !== 5
      || !Number.isSafeInteger(output.rate_violations) || output.rate_violations < 0
      || !["pending", "approved", "denied", "expired"].includes(output.state)
      || (output.terminal_reason !== null
        && output.terminal_reason !== "control-device-code-invalid"
        && output.terminal_reason !== "control-device-code-display-mismatch")
      || (output.terminal_poll_digest !== null && !HEX_32.test(output.terminal_poll_digest))) {
      return null;
    }
    return output;
  } catch {
    return null;
  }
}

function captureRecord(value: unknown): CapturedRecord | null {
  try {
    const captured = snapshotClosedDataTree(value, "Control device durable record");
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const record = captured as Readonly<Record<string, unknown>>;
    if (typeof record.state !== "string" || !Number.isSafeInteger(record.revision)
      || (record.revision as number) < 0 || typeof record.binding_digest !== "string"
      || !HEX_32.test(record.binding_digest)) return null;
    if (record.state === "available") {
      if (!exactKeys(record, ["binding_digest", "output", "revision", "state"])) return null;
      const output = captureStored(record.output);
      return output === null ? null : { ...record, output } as CapturedRecord;
    }
    if (record.state === "executing") {
      return exactKeys(record, ["binding_digest", "execution_token", "revision", "state"])
        && typeof record.execution_token === "string" && HEX_32.test(record.execution_token)
        ? record as CapturedRecord : null;
    }
    if (record.state === "committed") {
      if (!exactKeys(record, [
        "binding_digest", "execution_token", "output", "output_digest", "revision", "state",
      ]) || typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)
        || typeof record.output_digest !== "string" || !HEX_32.test(record.output_digest)) {
        return null;
      }
      const output = captureStored(record.output);
      return output === null ? null : { ...record, output } as CapturedRecord;
    }
    if (record.state === "indeterminate") {
      return exactKeys(record, [
        "binding_digest", "execution_token", "reconciliation_digest", "revision", "state",
      ]) && typeof record.execution_token === "string" && HEX_32.test(record.execution_token)
        && typeof record.reconciliation_digest === "string"
        && HEX_32.test(record.reconciliation_digest)
        ? record as CapturedRecord : null;
    }
    return null;
  } catch {
    return null;
  }
}

function captureTransactionRequest(value: ControlDeviceTransactionRequest): ControlDeviceTransactionRequest {
  return captureExactDataObject(value, [[
    "client_id", "display_fingerprint", "expires_in_seconds", "failure_budget", "persona",
    "polling_interval_seconds", "verification_uri",
  ]], "Control device transaction request") as ControlDeviceTransactionRequest;
}

function validTransactionRequest(value: ControlDeviceTransactionRequest): boolean {
  if (typeof value.client_id !== "string" || value.client_id.length === 0
    || typeof value.persona !== "string" || value.persona.length === 0
    || typeof value.verification_uri !== "string" || value.verification_uri.length === 0
    || typeof value.display_fingerprint !== "string" || value.display_fingerprint.length === 0
    || !Number.isSafeInteger(value.polling_interval_seconds)
    || value.polling_interval_seconds < 1
    || !Number.isSafeInteger(value.expires_in_seconds)
    || value.expires_in_seconds < value.polling_interval_seconds
    || value.failure_budget !== 5) return false;
  try {
    const uri = new URL(value.verification_uri);
    return uri.protocol === "https:" && uri.username === "" && uri.password === ""
      && uri.search === "" && uri.hash === "";
  } catch {
    return false;
  }
}

function capturePollRequest(value: ControlDevicePollRequest): ControlDevicePollRequest {
  return captureExactDataObject(value, [[
    "device_code", "displayed_fingerprint", "user_code",
  ]], "Control device poll request") as ControlDevicePollRequest;
}

function validPollStrings(value: ControlDevicePollRequest): boolean {
  return typeof value.device_code === "string" && typeof value.user_code === "string"
    && typeof value.displayed_fingerprint === "string";
}

async function loadRecord(authority: AuthorityRecord, key: string): Promise<CapturedRecord | null> {
  return captureRecord(await authority.store.load(key));
}

function publicTransaction(
  output: StoredTransaction,
  deviceCode: string,
  userCode: string,
): ControlDeviceTransaction {
  return Object.freeze({
    transaction_id: output.transaction_id,
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: output.verification_uri,
    expires_at: output.expires_at,
    interval_seconds: output.initial_interval_seconds,
  });
}

export async function createControlDeviceTransaction(
  authority: ControlDeviceAuthorizationAuthority,
  request: ControlDeviceTransactionRequest,
): Promise<AuthorityDecision<"control-device-code-invalid", ControlDeviceTransaction>> {
  const retained = AUTHORITIES.get(authority);
  if (retained === undefined) return INVALID;
  let captured: ControlDeviceTransactionRequest;
  try {
    captured = captureTransactionRequest(request);
  } catch {
    return INVALID;
  }
  if (!validTransactionRequest(captured)) return INVALID;

  let now: number;
  try {
    now = trustedNow(retained);
  } catch {
    return indeterminate(retained, "creation", "trusted-time");
  }
  if (now + captured.expires_in_seconds > Number.MAX_SAFE_INTEGER) return INVALID;

  for (let attempt = 0; attempt < COLLISION_ATTEMPTS; attempt += 1) {
    let deviceBytes: Uint8Array;
    let userBytes: Uint8Array;
    try {
      deviceBytes = entropy(retained, DEVICE_BYTES);
      userBytes = entropy(retained, USER_BYTES);
    } catch {
      return INVALID;
    }
    const deviceCode = Buffer.from(deviceBytes).toString("base64url");
    const userCode = encodeUserCode(userBytes);
    const normalizedUserCode = normalizeUserCode(userCode);
    if (normalizedUserCode === null) return INVALID;
    const id = transactionId(retained, deviceCode);
    const output: StoredTransaction = Object.freeze({
      transaction_id: id,
      state: "pending",
      authority_id: retained.authority_id,
      client_id: captured.client_id,
      persona: captured.persona,
      verification_uri: captured.verification_uri,
      display_fingerprint: captured.display_fingerprint,
      device_code_hash: sha256("heterodyne-control-device-code-v1", deviceCode),
      user_code_hash: sha256("heterodyne-control-user-code-v1", normalizedUserCode),
      device_entropy_bits: 128,
      user_code_entropy_bits: 40,
      issued_at: now,
      expires_at: now + captured.expires_in_seconds,
      initial_interval_seconds: captured.polling_interval_seconds,
      interval_seconds: captured.polling_interval_seconds,
      next_poll_at: now,
      failed_attempts: 0,
      failure_budget: 5,
      rate_violations: 0,
      terminal_reason: null,
      terminal_poll_digest: null,
    });
    const binding = bindingDigest(output);
    const next: DurableAuthorityRecord<PublicDeviceState> = Object.freeze({
      state: "available",
      revision: 0,
      binding_digest: binding,
      output,
    });
    let result: "committed" | "conflict" | "unknown";
    try {
      result = await retained.store.compareAndSwap({
        key: id,
        expected_revision: null,
        next,
      });
    } catch {
      return indeterminate(retained, id, "creation-store", binding);
    }
    if (result === "conflict") continue;
    if (result !== "committed" && result !== "unknown") {
      return indeterminate(retained, id, "creation-response", binding);
    }
    try {
      const durable = await loadRecord(retained, id);
      if (durable?.state === "available" && durable.revision === 0
        && durable.binding_digest === binding && outputDigest(durable.output) === outputDigest(output)) {
        return Object.freeze({ verdict: "accept" as const, output: publicTransaction(
          output,
          deviceCode,
          userCode,
        ) });
      }
    } catch {
      // The fail-closed result below deliberately does not try another code.
    }
    return indeterminate(retained, id, "creation-readback", binding);
  }
  return INVALID;
}

function outputMatches(
  authority: AuthorityRecord,
  key: string,
  output: StoredTransaction,
  deviceCode: string,
): boolean {
  return output.authority_id === authority.authority_id
    && output.transaction_id === key
    && output.device_code_hash === sha256("heterodyne-control-device-code-v1", deviceCode);
}

function acceptedOutput(output: StoredTransaction): Readonly<{
  transaction_id: string;
  state: "pending" | "approved";
}> {
  if (output.state !== "pending" && output.state !== "approved") {
    throw new Error("Control device state is not accepting");
  }
  return Object.freeze({ transaction_id: output.transaction_id, state: output.state });
}

function committedDecision(
  authority: AuthorityRecord,
  record: Extract<CapturedRecord, { state: "committed" }>,
  request: ControlDevicePollRequest,
  normalizedUserCode: string | null,
  requestDigest: string,
): ControlDeviceDecision {
  const output = record.output;
  if (record.binding_digest !== bindingDigest(output)
    || record.output_digest !== outputDigest(output)
    || record.execution_token !== sha256(
      "heterodyne-control-device-execution-v1",
      authority.authority_id,
      output.transaction_id,
      String(record.revision - 2),
      output.state,
      output.terminal_reason ?? "approved",
      output.terminal_poll_digest ?? "missing",
    )) return indeterminate(authority, output.transaction_id, "committed-binding", record.binding_digest);
  if (output.terminal_poll_digest !== requestDigest) return INVALID;
  if (normalizedUserCode === null || output.user_code_hash
    !== sha256("heterodyne-control-user-code-v1", normalizedUserCode)) return INVALID;
  if (output.state === "approved" && output.terminal_reason === null
    && request.displayed_fingerprint === output.display_fingerprint) {
    return Object.freeze({ verdict: "accept" as const, output: acceptedOutput(output) });
  }
  if (output.state === "denied"
    && output.terminal_reason === "control-device-code-display-mismatch"
    && request.displayed_fingerprint !== output.display_fingerprint) return DISPLAY_MISMATCH;
  return INVALID;
}

async function terminalTransition(
  authority: AuthorityRecord,
  record: Extract<CapturedRecord, { state: "available" }>,
  request: ControlDevicePollRequest,
  state: "approved" | "denied" | "expired",
  reason: TerminalReason | null,
  terminalDecision: ControlDeviceDecision,
): Promise<ControlDeviceDecision> {
  const requestDigest = pollDigest(authority, request);
  const output: StoredTransaction = Object.freeze({
    ...record.output,
    state,
    terminal_reason: reason,
    terminal_poll_digest: requestDigest,
  });
  const token = sha256(
    "heterodyne-control-device-execution-v1",
    authority.authority_id,
    output.transaction_id,
    String(record.revision),
    state,
    reason ?? "approved",
    requestDigest,
  );
  const reconciliation = sha256(
    "heterodyne-control-device-reconciliation-v1",
    authority.authority_id,
    output.transaction_id,
    token,
    outputDigest(output),
  );
  let acquired: "acquired" | "replay" | "conflict" | "unavailable";
  try {
    acquired = await authority.store.acquire({
      key: output.transaction_id,
      expected_revision: record.revision,
      binding_digest: record.binding_digest,
      execution_token: token,
    });
  } catch {
    return indeterminate(authority, output.transaction_id, "terminal-acquire", record.binding_digest);
  }
  if (acquired !== "acquired") {
    if (acquired === "replay") {
      try {
        const replay = await loadRecord(authority, output.transaction_id);
        if (replay?.state === "committed") {
          return committedDecision(authority, replay, request, normalizeUserCode(request.user_code), requestDigest);
        }
        if (replay?.state === "indeterminate") {
          return Object.freeze({
            verdict: "indeterminate" as const,
            reconciliation_digest: replay.reconciliation_digest,
          });
        }
      } catch {
        // Return the deterministic fail-closed decision below.
      }
    }
    return indeterminate(authority, output.transaction_id, `terminal-${acquired}`, record.binding_digest);
  }
  let committed: "committed" | "conflict" | "unknown";
  try {
    committed = await authority.store.commit({
      key: output.transaction_id,
      binding_digest: record.binding_digest,
      execution_token: token,
      output_digest: outputDigest(output),
      output,
    });
  } catch {
    committed = "unknown";
  }
  if (committed !== "committed") {
    try {
      await authority.store.markIndeterminate({
        key: output.transaction_id,
        binding_digest: record.binding_digest,
        execution_token: token,
        reconciliation_digest: reconciliation,
      });
    } catch {
      // The acquired/executing record remains a durable no-repeat fence.
    }
    return Object.freeze({ verdict: "indeterminate" as const, reconciliation_digest: reconciliation });
  }
  try {
    const durable = await loadRecord(authority, output.transaction_id);
    if (durable?.state === "committed") {
      const decision = committedDecision(
        authority,
        durable,
        request,
        normalizeUserCode(request.user_code),
        requestDigest,
      );
      return decision.verdict === "indeterminate" ? decision : terminalDecision;
    }
  } catch {
    // Fall through to fail closed.
  }
  return indeterminate(authority, output.transaction_id, "terminal-readback", record.binding_digest);
}

async function casAvailable(
  authority: AuthorityRecord,
  record: Extract<CapturedRecord, { state: "available" }>,
  output: StoredTransaction,
  decision: ControlDeviceDecision,
): Promise<ControlDeviceDecision> {
  const next: DurableAuthorityRecord<PublicDeviceState> = Object.freeze({
    state: "available",
    revision: record.revision + 1,
    binding_digest: record.binding_digest,
    output,
  });
  let result: "committed" | "conflict" | "unknown";
  try {
    result = await authority.store.compareAndSwap({
      key: output.transaction_id,
      expected_revision: record.revision,
      next,
    });
  } catch {
    return indeterminate(authority, output.transaction_id, "poll-cas", record.binding_digest);
  }
  if (result !== "committed") {
    return indeterminate(authority, output.transaction_id, `poll-${result}`, record.binding_digest);
  }
  try {
    const durable = await loadRecord(authority, output.transaction_id);
    if (durable?.state === "available" && durable.revision === next.revision
      && durable.binding_digest === record.binding_digest
      && outputDigest(durable.output) === outputDigest(output)) return decision;
  } catch {
    // Fall through to fail closed.
  }
  return indeterminate(authority, output.transaction_id, "poll-readback", record.binding_digest);
}

export async function pollControlDeviceAuthorization(
  authority: ControlDeviceAuthorizationAuthority,
  request: ControlDevicePollRequest,
): Promise<ControlDeviceDecision> {
  const retained = AUTHORITIES.get(authority);
  if (retained === undefined) return INVALID;
  let captured: ControlDevicePollRequest;
  try {
    captured = capturePollRequest(request);
  } catch {
    return INVALID;
  }
  if (!validPollStrings(captured)) return INVALID;
  const deviceCode = normalizeDeviceCode(captured.device_code);
  if (deviceCode === null) return INVALID;
  const key = transactionId(retained, deviceCode);
  let record: CapturedRecord | null;
  try {
    const raw = await retained.store.load(key);
    if (raw === null) return INVALID;
    record = captureRecord(raw);
  } catch {
    return indeterminate(retained, key, "poll-load");
  }
  if (record === null) return indeterminate(retained, key, "poll-record");
  if (record.state === "executing") {
    return indeterminate(retained, key, "poll-executing", record.binding_digest);
  }
  if (record.state === "indeterminate") {
    return Object.freeze({
      verdict: "indeterminate" as const,
      reconciliation_digest: record.reconciliation_digest,
    });
  }
  const normalizedUserCode = normalizeUserCode(captured.user_code);
  const requestDigest = pollDigest(retained, captured);
  if (record.state === "committed") {
    if (!outputMatches(retained, key, record.output, deviceCode)) {
      return indeterminate(retained, key, "committed-output", record.binding_digest);
    }
    return committedDecision(retained, record, captured, normalizedUserCode, requestDigest);
  }
  const output = record.output;
  if (!outputMatches(retained, key, output, deviceCode)
    || record.binding_digest !== bindingDigest(output)
    || (output.state !== "pending" && output.state !== "approved")
    || output.terminal_reason !== null || output.terminal_poll_digest !== null) {
    return indeterminate(retained, key, "available-output", record.binding_digest);
  }
  let now: number;
  try {
    now = trustedNow(retained);
  } catch {
    return indeterminate(retained, key, "poll-time", record.binding_digest);
  }
  if (now >= output.expires_at) {
    return terminalTransition(retained, record, captured, "expired", "control-device-code-invalid", INVALID);
  }
  if (normalizedUserCode === null
    || output.user_code_hash !== sha256("heterodyne-control-user-code-v1", normalizedUserCode)) {
    const failedAttempts = output.failed_attempts + 1;
    if (failedAttempts >= output.failure_budget) {
      const failed = Object.freeze({ ...record, output: Object.freeze({
        ...output,
        failed_attempts: failedAttempts,
      }) }) as Extract<CapturedRecord, { state: "available" }>;
      return terminalTransition(
        retained,
        failed,
        captured,
        "denied",
        "control-device-code-invalid",
        INVALID,
      );
    }
    return casAvailable(retained, record, Object.freeze({
      ...output,
      failed_attempts: failedAttempts,
    }), INVALID);
  }
  if (captured.displayed_fingerprint !== output.display_fingerprint) {
    return terminalTransition(
      retained,
      record,
      captured,
      "denied",
      "control-device-code-display-mismatch",
      DISPLAY_MISMATCH,
    );
  }
  if (output.state === "approved") {
    return terminalTransition(
      retained,
      record,
      captured,
      "approved",
      null,
      Object.freeze({ verdict: "accept" as const, output: acceptedOutput(output) }),
    );
  }
  if (now < output.next_poll_at) {
    const interval = output.interval_seconds + 5;
    if (!Number.isSafeInteger(interval) || now + interval > Number.MAX_SAFE_INTEGER) {
      return indeterminate(retained, key, "rate-overflow", record.binding_digest);
    }
    return casAvailable(retained, record, Object.freeze({
      ...output,
      interval_seconds: interval,
      next_poll_at: now + interval,
      rate_violations: output.rate_violations + 1,
    }), RATE_LIMITED);
  }
  if (now + output.interval_seconds > Number.MAX_SAFE_INTEGER) {
    return indeterminate(retained, key, "interval-overflow", record.binding_digest);
  }
  const nextOutput = Object.freeze({
    ...output,
    next_poll_at: now + output.interval_seconds,
  });
  return casAvailable(retained, record, nextOutput, Object.freeze({
    verdict: "accept" as const,
    output: acceptedOutput(nextOutput),
  }));
}
