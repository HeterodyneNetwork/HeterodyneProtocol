import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type AuthorityDecision,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
  type IndeterminateDecision,
} from "./security-authority-support.js";

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

/**
 * Private RFC 8628 transaction projection. It is not the later, schema-bound
 * OIDC/NIP-46 authorization record described by
 * control-device-authorization-state-v1.schema.json.
 */
type StoredTransaction = Readonly<{
  transaction_id: string;
  state: "pending" | "approved" | "denied" | "expired";
  authority_id: string;
  client_id: string;
  persona: string;
  verification_uri: string;
  client_fingerprint: string;
  device_code_sha256: string;
  user_code_sha256: string;
  device_code_entropy_bits: 128;
  user_code_entropy_bits: 40;
  normalization: "uppercase-ascii-remove-hyphen";
  issued_at: number;
  expires_at: number;
  initial_interval_seconds: number;
  interval_seconds: number;
  next_poll_at: number;
  failed_guesses: number;
  max_failed_guesses: 5;
  slow_down_count: number;
  terminal_reason: TerminalReason | null;
  terminal_poll_digest: string | null;
}>;

type CapturedRecord = DurableAuthorityRecord<StoredTransaction>;
type AvailableRecord = Extract<CapturedRecord, { state: "available" }>;
type CommittedRecord = Extract<CapturedRecord, { state: "committed" }>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const DEVICE_BYTES = 16;
const USER_BYTES = 5;
const COLLISION_ATTEMPTS = 8;
const HEX_32 = /^[0-9a-f]{64}$/;
const DEVICE_CODE = /^[A-Za-z0-9_-]{22}$/;
const USER_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const STORED_KEYS = [
  "authority_id", "client_fingerprint", "client_id", "device_code_entropy_bits",
  "device_code_sha256", "expires_at", "failed_guesses", "initial_interval_seconds",
  "interval_seconds", "issued_at", "max_failed_guesses", "next_poll_at",
  "normalization", "persona", "slow_down_count", "state", "terminal_poll_digest",
  "terminal_reason", "transaction_id", "user_code_entropy_bits", "user_code_sha256",
  "verification_uri",
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

function exactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length
    && [...keys].sort().every((key, index) => actual[index] === key);
}

function rawHash(domain: string, value: string): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update("\0", "utf8")
    .update(value, "utf8")
    .digest("hex");
}

function stateBinding(output: StoredTransaction): string {
  return authorityBindingDigest(
    "heterodyne-control-device-state-v1",
    output as unknown as Readonly<Record<string, unknown>>,
  );
}

function storedOutputDigest(output: StoredTransaction): string {
  return authorityBindingDigest(
    "heterodyne-control-device-output-v1",
    output as unknown as Readonly<Record<string, unknown>>,
  );
}

function pollBinding(authority: AuthorityRecord, request: ControlDevicePollRequest): string {
  return authorityBindingDigest("heterodyne-control-device-poll-v1", {
    authority_id: authority.authority_id,
    device_code: request.device_code,
    displayed_fingerprint: request.displayed_fingerprint,
    user_code: request.user_code,
  });
}

function executionToken(
  authority: Readonly<{ authority_id: string }>,
  record: Readonly<{ revision: number; binding_digest: string }>,
  nextOutput: StoredTransaction,
): string {
  return authorityBindingDigest("heterodyne-control-device-execution-v1", {
    authority_id: authority.authority_id,
    transaction_id: nextOutput.transaction_id,
    expected_revision: record.revision,
    prior_binding_digest: record.binding_digest,
    next_output_digest: storedOutputDigest(nextOutput),
    terminal_state: nextOutput.state,
    terminal_reason: nextOutput.terminal_reason,
    terminal_poll_digest: nextOutput.terminal_poll_digest,
  });
}

function reconciliationDigest(
  authority: AuthorityRecord,
  key: string,
  token: string,
): string {
  return authorityBindingDigest("heterodyne-control-device-reconciliation-v1", {
    authority_id: authority.authority_id,
    transaction_id: key,
    execution_token: token,
  });
}

function indeterminate(
  authority: AuthorityRecord,
  key: string,
  phase: string,
  bindingDigest = "unavailable",
  token = "unavailable",
): IndeterminateDecision {
  return Object.freeze({
    verdict: "indeterminate" as const,
    reconciliation_digest: authorityBindingDigest(
      "heterodyne-control-device-failure-v1",
      {
        authority_id: authority.authority_id,
        transaction_id: key,
        phase,
        binding_digest: bindingDigest,
        execution_token: token,
      },
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

function boundMethod<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  let owner: object | null = object;
  while (owner !== null) {
    if (utilTypes.isProxy(owner)) throw new TypeError("Control device store cannot be a proxy");
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function"
        || utilTypes.isProxy(descriptor.value)) {
        throw new TypeError(`Control device store requires data method ${name}`);
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
    return decoded.length === DEVICE_BYTES && decoded.toString("base64url") === value ? value : null;
  } catch {
    return null;
  }
}

function normalizeUserCode(value: string): string | null {
  if (!/^[0-9A-HJKMNP-TV-Z]{4}-?[0-9A-HJKMNP-TV-Z]{4}$/.test(value)) return null;
  return value.replace("-", "");
}

function transactionId(authority: AuthorityRecord, deviceCodeHash: string): string {
  return authorityBindingDigest("heterodyne-control-device-transaction-v1", {
    authority_id: authority.authority_id,
    device_code_sha256: deviceCodeHash,
  });
}

function captureTransactionRequest(value: ControlDeviceTransactionRequest):
ControlDeviceTransactionRequest | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)
      || !exactKeys(captured as Readonly<Record<string, unknown>>, [
        "client_id", "display_fingerprint", "expires_in_seconds", "failure_budget", "persona",
        "polling_interval_seconds", "verification_uri",
      ])) return null;
    const request = captured as ControlDeviceTransactionRequest;
    if (typeof request.client_id !== "string" || request.client_id.length === 0
      || typeof request.persona !== "string" || request.persona.length === 0
      || typeof request.verification_uri !== "string" || request.verification_uri.length === 0
      || typeof request.display_fingerprint !== "string"
      || request.display_fingerprint.length === 0 || request.display_fingerprint.length > 256
      || !Number.isSafeInteger(request.polling_interval_seconds)
      || request.polling_interval_seconds < 1
      || !Number.isSafeInteger(request.expires_in_seconds)
      || request.expires_in_seconds < request.polling_interval_seconds
      || request.failure_budget !== 5) return null;
    if (!validVerificationUri(request.verification_uri)) return null;
    return request;
  } catch {
    return null;
  }
}

function capturePollRequest(value: ControlDevicePollRequest): ControlDevicePollRequest | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)
      || !exactKeys(captured as Readonly<Record<string, unknown>>, [
        "device_code", "displayed_fingerprint", "user_code",
      ])) return null;
    const request = captured as ControlDevicePollRequest;
    return typeof request.device_code === "string" && typeof request.user_code === "string"
      && typeof request.displayed_fingerprint === "string" ? request : null;
  } catch {
    return null;
  }
}

function validVerificationUri(value: string): boolean {
  try {
    const uri = new URL(value);
    return uri.protocol === "https:" && uri.username === "" && uri.password === ""
      && uri.search === "" && uri.hash === "";
  } catch {
    return false;
  }
}

function validStoredScalars(output: StoredTransaction): boolean {
  return typeof output.transaction_id === "string" && HEX_32.test(output.transaction_id)
    && typeof output.state === "string"
    && ["pending", "approved", "denied", "expired"].includes(output.state)
    && typeof output.authority_id === "string" && output.authority_id.length > 0
    && typeof output.client_id === "string" && output.client_id.length > 0
    && typeof output.persona === "string" && output.persona.length > 0
    && typeof output.verification_uri === "string" && validVerificationUri(output.verification_uri)
    && typeof output.client_fingerprint === "string"
    && output.client_fingerprint.length > 0 && output.client_fingerprint.length <= 256
    && typeof output.device_code_sha256 === "string" && HEX_32.test(output.device_code_sha256)
    && typeof output.user_code_sha256 === "string" && HEX_32.test(output.user_code_sha256)
    && output.device_code_entropy_bits === 128 && output.user_code_entropy_bits === 40
    && output.normalization === "uppercase-ascii-remove-hyphen"
    && Number.isSafeInteger(output.issued_at) && output.issued_at >= 0
    && Number.isSafeInteger(output.expires_at) && output.expires_at > output.issued_at
    && Number.isSafeInteger(output.initial_interval_seconds)
    && output.initial_interval_seconds >= 1
    && Number.isSafeInteger(output.interval_seconds)
    && output.interval_seconds >= output.initial_interval_seconds
    && Number.isSafeInteger(output.next_poll_at)
    && output.next_poll_at >= output.issued_at + output.initial_interval_seconds
    && Number.isSafeInteger(output.failed_guesses) && output.failed_guesses >= 0
    && output.failed_guesses <= output.max_failed_guesses
    && output.max_failed_guesses === 5
    && Number.isSafeInteger(output.slow_down_count) && output.slow_down_count >= 0
    && output.interval_seconds
      === output.initial_interval_seconds + (output.slow_down_count * 5)
    && (output.terminal_reason === null
      || output.terminal_reason === "control-device-code-invalid"
      || output.terminal_reason === "control-device-code-display-mismatch")
    && (output.terminal_poll_digest === null
      || (typeof output.terminal_poll_digest === "string"
        && HEX_32.test(output.terminal_poll_digest)));
}

function captureStored(value: unknown): StoredTransaction | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)
      || !exactKeys(captured as Readonly<Record<string, unknown>>, STORED_KEYS)) return null;
    const output = captured as StoredTransaction;
    return validStoredScalars(output) ? output : null;
  } catch {
    return null;
  }
}

function liveOutput(output: StoredTransaction): boolean {
  return (output.state === "pending" || output.state === "approved")
    && output.failed_guesses < output.max_failed_guesses
    && output.terminal_reason === null && output.terminal_poll_digest === null;
}

function terminalOutput(output: StoredTransaction): boolean {
  if (output.terminal_poll_digest === null) return false;
  if (output.state === "approved") return output.terminal_reason === null;
  if (output.state === "expired") return output.terminal_reason === "control-device-code-invalid";
  if (output.state !== "denied" || output.terminal_reason === null) return false;
  return output.terminal_reason === "control-device-code-display-mismatch"
    || (output.terminal_reason === "control-device-code-invalid"
      && output.failed_guesses === output.max_failed_guesses);
}

function captureRecord(value: unknown): CapturedRecord | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const record = captured as Readonly<Record<string, unknown>>;
    if (typeof record.state !== "string" || !Number.isSafeInteger(record.revision)
      || (record.revision as number) < 0 || typeof record.binding_digest !== "string"
      || !HEX_32.test(record.binding_digest)) return null;
    if (record.state === "available") {
      if (!exactKeys(record, ["binding_digest", "output", "revision", "state"])) return null;
      const output = captureStored(record.output);
      if (output === null || !liveOutput(output) || record.binding_digest !== stateBinding(output)) {
        return null;
      }
      return Object.freeze({ ...record, output }) as CapturedRecord;
    }
    if (record.state === "executing") {
      return exactKeys(record, ["binding_digest", "execution_token", "revision", "state"])
        && typeof record.execution_token === "string" && HEX_32.test(record.execution_token)
        ? record as CapturedRecord : null;
    }
    if (record.state === "indeterminate") {
      return exactKeys(record, [
        "binding_digest", "execution_token", "reconciliation_digest", "revision", "state",
      ]) && typeof record.execution_token === "string" && HEX_32.test(record.execution_token)
        && typeof record.reconciliation_digest === "string"
        && HEX_32.test(record.reconciliation_digest)
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
      if (output === null || !terminalOutput(output)
        || record.output_digest !== storedOutputDigest(output)) return null;
      const prior = { revision: (record.revision as number) - 2, binding_digest: record.binding_digest };
      if (prior.revision < 0 || record.execution_token !== executionToken(
        { authority_id: output.authority_id },
        prior,
        output,
      )) return null;
      return Object.freeze({ ...record, output }) as CapturedRecord;
    }
    return null;
  } catch {
    return null;
  }
}

function sameOutput(left: StoredTransaction, right: StoredTransaction): boolean {
  return storedOutputDigest(left) === storedOutputDigest(right);
}

function exactAvailable(record: CapturedRecord | null, expected: AvailableRecord):
record is AvailableRecord {
  return record?.state === "available" && record.revision === expected.revision
    && record.binding_digest === expected.binding_digest
    && sameOutput(record.output, expected.output);
}

function exactCommitted(record: CapturedRecord | null, expected: CommittedRecord):
record is CommittedRecord {
  return record?.state === "committed" && record.revision === expected.revision
    && record.binding_digest === expected.binding_digest
    && record.execution_token === expected.execution_token
    && record.output_digest === expected.output_digest
    && sameOutput(record.output, expected.output);
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

function outputMatches(
  authority: AuthorityRecord,
  key: string,
  output: StoredTransaction,
  deviceCode: string,
): boolean {
  return output.authority_id === authority.authority_id
    && output.transaction_id === key
    && output.device_code_sha256 === rawHash("heterodyne-control-device-code-v1", deviceCode);
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

export async function createControlDeviceTransaction(
  authority: ControlDeviceAuthorizationAuthority,
  request: ControlDeviceTransactionRequest,
): Promise<AuthorityDecision<"control-device-code-invalid", ControlDeviceTransaction>> {
  const retained = AUTHORITIES.get(authority);
  if (retained === undefined) return INVALID;
  const captured = captureTransactionRequest(request);
  if (captured === null) return INVALID;
  let now: number;
  try {
    now = trustedNow(retained);
  } catch {
    return indeterminate(retained, "creation", "trusted-time");
  }
  if (now + captured.expires_in_seconds > Number.MAX_SAFE_INTEGER
    || now + captured.polling_interval_seconds > Number.MAX_SAFE_INTEGER) return INVALID;

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
    const deviceCodeHash = rawHash("heterodyne-control-device-code-v1", deviceCode);
    const id = transactionId(retained, deviceCodeHash);
    const output: StoredTransaction = Object.freeze({
      transaction_id: id,
      state: "pending",
      authority_id: retained.authority_id,
      client_id: captured.client_id,
      persona: captured.persona,
      verification_uri: captured.verification_uri,
      client_fingerprint: captured.display_fingerprint,
      device_code_sha256: deviceCodeHash,
      user_code_sha256: rawHash("heterodyne-control-user-code-v1", normalizedUserCode),
      device_code_entropy_bits: 128,
      user_code_entropy_bits: 40,
      normalization: "uppercase-ascii-remove-hyphen",
      issued_at: now,
      expires_at: now + captured.expires_in_seconds,
      initial_interval_seconds: captured.polling_interval_seconds,
      interval_seconds: captured.polling_interval_seconds,
      next_poll_at: now + captured.polling_interval_seconds,
      failed_guesses: 0,
      max_failed_guesses: 5,
      slow_down_count: 0,
      terminal_reason: null,
      terminal_poll_digest: null,
    });
    const expected: AvailableRecord = Object.freeze({
      state: "available",
      revision: 0,
      binding_digest: stateBinding(output),
      output,
    });
    let result: "committed" | "conflict" | "unknown";
    try {
      result = await retained.store.compareAndSwap({
        key: id,
        expected_revision: null,
        next: expected,
      });
    } catch {
      return indeterminate(retained, id, "creation-store", expected.binding_digest);
    }
    if (result === "conflict") continue;
    if (result !== "committed" && result !== "unknown") {
      return indeterminate(retained, id, "creation-response", expected.binding_digest);
    }
    try {
      const durable = await loadRecord(retained, id);
      if (exactAvailable(durable, expected)) {
        return Object.freeze({
          verdict: "accept" as const,
          output: publicTransaction(output, deviceCode, userCode),
        });
      }
    } catch {
      // Do not generate another transaction after an ambiguous write.
    }
    return indeterminate(retained, id, "creation-readback", expected.binding_digest);
  }
  return INVALID;
}

function committedDecision(
  authority: AuthorityRecord,
  record: CommittedRecord,
  request: ControlDevicePollRequest,
  normalizedUserCode: string | null,
  requestDigest: string,
): ControlDeviceDecision {
  const output = record.output;
  if (output.authority_id !== authority.authority_id
    || output.terminal_poll_digest !== requestDigest
    || normalizedUserCode === null
    || output.user_code_sha256 !== rawHash(
      "heterodyne-control-user-code-v1",
      normalizedUserCode,
    )) return INVALID;
  if (output.state === "approved" && request.displayed_fingerprint === output.client_fingerprint) {
    return Object.freeze({ verdict: "accept" as const, output: acceptedOutput(output) });
  }
  if (output.state === "denied"
    && output.terminal_reason === "control-device-code-display-mismatch"
    && request.displayed_fingerprint !== output.client_fingerprint) return DISPLAY_MISMATCH;
  return INVALID;
}

async function markTransitionIndeterminate(
  authority: AuthorityRecord,
  key: string,
  bindingDigest: string,
  token: string,
): Promise<IndeterminateDecision> {
  const reconciliation = reconciliationDigest(authority, key, token);
  try {
    await authority.store.markIndeterminate({
      key,
      binding_digest: bindingDigest,
      execution_token: token,
      reconciliation_digest: reconciliation,
    });
    const durable = await loadRecord(authority, key);
    if (durable?.state === "indeterminate" && durable.binding_digest === bindingDigest
      && durable.execution_token === token) {
      return Object.freeze({
        verdict: "indeterminate" as const,
        reconciliation_digest: durable.reconciliation_digest,
      });
    }
  } catch {
    // The executing record remains an absorbing no-repeat fence.
  }
  return Object.freeze({ verdict: "indeterminate" as const, reconciliation_digest: reconciliation });
}

async function acquireTransition(
  authority: AuthorityRecord,
  record: AvailableRecord,
  token: string,
): Promise<"acquired" | IndeterminateDecision> {
  let result: "acquired" | "replay" | "conflict" | "unavailable";
  try {
    result = await authority.store.acquire({
      key: record.output.transaction_id,
      expected_revision: record.revision,
      binding_digest: record.binding_digest,
      execution_token: token,
    });
  } catch {
    return indeterminate(
      authority,
      record.output.transaction_id,
      "transition-acquire",
      record.binding_digest,
      token,
    );
  }
  if (result === "acquired") return "acquired";
  if (result === "replay") {
    try {
      const durable = await loadRecord(authority, record.output.transaction_id);
      if (durable?.state === "indeterminate" && durable.binding_digest === record.binding_digest
        && durable.execution_token === token) {
        return Object.freeze({
          verdict: "indeterminate" as const,
          reconciliation_digest: durable.reconciliation_digest,
        });
      }
      if (durable?.state === "executing" && durable.binding_digest === record.binding_digest
        && durable.execution_token === token) {
        return Object.freeze({
          verdict: "indeterminate" as const,
          reconciliation_digest: reconciliationDigest(
            authority,
            record.output.transaction_id,
            token,
          ),
        });
      }
    } catch {
      // Return the fail-closed decision below.
    }
  }
  return indeterminate(
    authority,
    record.output.transaction_id,
    `transition-${result}`,
    record.binding_digest,
    token,
  );
}

async function nonterminalTransition(
  authority: AuthorityRecord,
  record: AvailableRecord,
  nextOutput: StoredTransaction,
  decision: ControlDeviceDecision,
): Promise<ControlDeviceDecision> {
  const token = executionToken(authority, record, nextOutput);
  const acquired = await acquireTransition(authority, record, token);
  if (acquired !== "acquired") return acquired;
  const expected: AvailableRecord = Object.freeze({
    state: "available",
    revision: record.revision + 2,
    binding_digest: stateBinding(nextOutput),
    output: nextOutput,
  });
  let result: "committed" | "conflict" | "unknown";
  try {
    result = await authority.store.compareAndSwap({
      key: nextOutput.transaction_id,
      expected_revision: record.revision + 1,
      next: expected,
    });
  } catch {
    result = "unknown";
  }
  try {
    const durable = await loadRecord(authority, nextOutput.transaction_id);
    if (exactAvailable(durable, expected)) return decision;
    if (durable?.state === "indeterminate" && durable.binding_digest === record.binding_digest
      && durable.execution_token === token) {
      return Object.freeze({
        verdict: "indeterminate" as const,
        reconciliation_digest: durable.reconciliation_digest,
      });
    }
    if (durable?.state === "executing" && durable.binding_digest === record.binding_digest
      && durable.execution_token === token) {
      return markTransitionIndeterminate(
        authority,
        nextOutput.transaction_id,
        record.binding_digest,
        token,
      );
    }
  } catch {
    // Recover the exact reopened record into an absorbing fence below.
  }
  const recoveryToken = authorityBindingDigest(
    "heterodyne-control-device-readback-recovery-v1",
    {
      authority_id: authority.authority_id,
      transaction_id: nextOutput.transaction_id,
      transition_token: token,
      expected_revision: expected.revision,
      expected_binding_digest: expected.binding_digest,
    },
  );
  try {
    const recovery = await authority.store.acquire({
      key: nextOutput.transaction_id,
      expected_revision: expected.revision,
      binding_digest: expected.binding_digest,
      execution_token: recoveryToken,
    });
    if (recovery === "acquired" || recovery === "replay") {
      return markTransitionIndeterminate(
        authority,
        nextOutput.transaction_id,
        expected.binding_digest,
        recoveryToken,
      );
    }
  } catch {
    // A different durable record cannot authorize this transition.
  }
  return indeterminate(
    authority,
    nextOutput.transaction_id,
    `nonterminal-${result}`,
    record.binding_digest,
    token,
  );
}

async function terminalTransition(
  authority: AuthorityRecord,
  record: AvailableRecord,
  nextOutput: StoredTransaction,
  request: ControlDevicePollRequest,
): Promise<ControlDeviceDecision> {
  const token = executionToken(authority, record, nextOutput);
  const acquired = await acquireTransition(authority, record, token);
  if (acquired !== "acquired") return acquired;
  const expected: CommittedRecord = Object.freeze({
    state: "committed",
    revision: record.revision + 2,
    binding_digest: record.binding_digest,
    execution_token: token,
    output_digest: storedOutputDigest(nextOutput),
    output: nextOutput,
  });
  let result: "committed" | "conflict" | "unknown";
  try {
    result = await authority.store.commit({
      key: nextOutput.transaction_id,
      binding_digest: record.binding_digest,
      execution_token: token,
      output_digest: expected.output_digest,
      output: nextOutput,
    });
  } catch {
    result = "unknown";
  }
  if (result !== "committed") {
    return markTransitionIndeterminate(
      authority,
      nextOutput.transaction_id,
      record.binding_digest,
      token,
    );
  }
  try {
    const durable = await loadRecord(authority, nextOutput.transaction_id);
    if (exactCommitted(durable, expected)) {
      return committedDecision(
        authority,
        durable,
        request,
        normalizeUserCode(request.user_code),
        pollBinding(authority, request),
      );
    }
  } catch {
    // Fall through to a stable fail-closed result.
  }
  return indeterminate(
    authority,
    nextOutput.transaction_id,
    "terminal-readback",
    record.binding_digest,
    token,
  );
}

export async function pollControlDeviceAuthorization(
  authority: ControlDeviceAuthorizationAuthority,
  request: ControlDevicePollRequest,
): Promise<ControlDeviceDecision> {
  const retained = AUTHORITIES.get(authority);
  if (retained === undefined) return INVALID;
  const captured = capturePollRequest(request);
  if (captured === null) return INVALID;
  const deviceCode = normalizeDeviceCode(captured.device_code);
  if (deviceCode === null) return INVALID;
  const deviceCodeHash = rawHash("heterodyne-control-device-code-v1", deviceCode);
  const key = transactionId(retained, deviceCodeHash);
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
    return Object.freeze({
      verdict: "indeterminate" as const,
      reconciliation_digest: reconciliationDigest(retained, key, record.execution_token),
    });
  }
  if (record.state === "indeterminate") {
    const expectedReconciliation = reconciliationDigest(retained, key, record.execution_token);
    if (record.reconciliation_digest !== expectedReconciliation) {
      return indeterminate(
        retained,
        key,
        "indeterminate-record",
        record.binding_digest,
        record.execution_token,
      );
    }
    return Object.freeze({
      verdict: "indeterminate" as const,
      reconciliation_digest: record.reconciliation_digest,
    });
  }
  const normalizedUserCode = normalizeUserCode(captured.user_code);
  const requestDigest = pollBinding(retained, captured);
  if (record.state === "committed") {
    if (!outputMatches(retained, key, record.output, deviceCode)) {
      return indeterminate(retained, key, "committed-output", record.binding_digest);
    }
    return committedDecision(retained, record, captured, normalizedUserCode, requestDigest);
  }
  const output = record.output;
  if (!outputMatches(retained, key, output, deviceCode)) {
    return indeterminate(retained, key, "available-output", record.binding_digest);
  }
  let now: number;
  try {
    now = trustedNow(retained);
  } catch {
    return indeterminate(retained, key, "poll-time", record.binding_digest);
  }
  if (now >= output.expires_at) {
    return terminalTransition(retained, record, Object.freeze({
      ...output,
      state: "expired",
      terminal_reason: "control-device-code-invalid",
      terminal_poll_digest: requestDigest,
    }), captured);
  }
  if (normalizedUserCode === null || output.user_code_sha256 !== rawHash(
    "heterodyne-control-user-code-v1",
    normalizedUserCode,
  )) {
    const failedGuesses = output.failed_guesses + 1;
    if (failedGuesses >= output.max_failed_guesses) {
      return terminalTransition(retained, record, Object.freeze({
        ...output,
        state: "denied",
        failed_guesses: failedGuesses,
        terminal_reason: "control-device-code-invalid",
        terminal_poll_digest: requestDigest,
      }), captured);
    }
    return nonterminalTransition(retained, record, Object.freeze({
      ...output,
      failed_guesses: failedGuesses,
    }), INVALID);
  }
  if (now < output.next_poll_at) {
    const interval = output.interval_seconds + 5;
    if (!Number.isSafeInteger(interval) || now + interval > Number.MAX_SAFE_INTEGER) {
      return indeterminate(retained, key, "rate-overflow", record.binding_digest);
    }
    return nonterminalTransition(retained, record, Object.freeze({
      ...output,
      interval_seconds: interval,
      next_poll_at: now + interval,
      slow_down_count: output.slow_down_count + 1,
    }), RATE_LIMITED);
  }
  if (captured.displayed_fingerprint !== output.client_fingerprint) {
    return terminalTransition(retained, record, Object.freeze({
      ...output,
      state: "denied",
      terminal_reason: "control-device-code-display-mismatch",
      terminal_poll_digest: requestDigest,
    }), captured);
  }
  if (output.state === "approved") {
    return terminalTransition(retained, record, Object.freeze({
      ...output,
      terminal_poll_digest: requestDigest,
    }), captured);
  }
  if (now + output.interval_seconds > Number.MAX_SAFE_INTEGER) {
    return indeterminate(retained, key, "interval-overflow", record.binding_digest);
  }
  const nextOutput = Object.freeze({
    ...output,
    next_poll_at: now + output.interval_seconds,
  });
  return nonterminalTransition(retained, record, nextOutput, Object.freeze({
    verdict: "accept" as const,
    output: acceptedOutput(nextOutput),
  }));
}
