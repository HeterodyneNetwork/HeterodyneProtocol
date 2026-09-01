import { createHash, timingSafeEqual } from "node:crypto";
import { types as utilTypes } from "node:util";
import { jcsCanonicalize } from "./jcs.js";
import {
  descriptorDigest,
  responseProof,
  secretCommitment,
  verifyInviteSignature,
  type InviteDescriptor,
  type InviteEnvelope,
  type InvitePurpose,
} from "./one-time-invite.js";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type AuthorityDecision,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
} from "./security-authority-support.js";

const HEX_32 = /^[0-9a-f]{64}$/u;
const HEX_64 = /^[0-9a-f]{128}$/u;
const REJECT = Object.freeze({
  verdict: "reject" as const,
  reason_code: "invite-authentication-invalid" as const,
});
const PURPOSES = new Set<InvitePurpose>(["dm", "control-enrollment", "device-enrollment"]);
const MAX_AUTHORITY_BYTES = 1_048_576;
const MAX_AUTHORITY_TOTAL_BYTES = 2_097_152;
const MAX_POLICY_STRING_BYTES = 256;
const MAX_KEY_PACKAGE_BASE64URL_BYTES = Math.ceil(MAX_AUTHORITY_BYTES * 4 / 3);
const MAX_RELAY_HINTS = 16;
const MAX_RESPONSE_CAPABILITIES = 64;
const MAX_PREAUTHORIZATION_ENTRIES = 64;
const RESPONSE_CLASSES: Readonly<Record<InvitePurpose, ReadonlySet<string>>> = Object.freeze({
  dm: new Set(["conversation-peer"]),
  "control-enrollment": new Set(["human-light", "automated"]),
  "device-enrollment": new Set(["light-device", "full-device", "recovery-device"]),
});

export type OneTimeInviteAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  store: DurableAuthorityStore<Readonly<{ group_id: string; response_digest: string }>>;
  load_invite_state: (invite_id: string) => Promise<Readonly<{
    state: "active" | "revoked";
    revision: number;
  }>>;
  establish_group: (bytes: Uint8Array, execution_token: string) => Promise<Readonly<{
    group_id: string;
    response_digest: string;
  }>>;
}>;

export type OneTimeInviteRedemption = Readonly<{
  envelope: InviteEnvelope;
  response_bytes: Uint8Array;
  response_purpose: InvitePurpose;
  recipient: string;
  key_package_bytes: Uint8Array;
  group_transition: Uint8Array;
}>;

export type OneTimeInviteOutput = Readonly<{
  group_id: string;
  response_digest: string;
}>;

export type OneTimeInviteAuthority = Readonly<Record<never, never>>;
export type OneTimeInviteDecision = AuthorityDecision<
  "invite-authentication-invalid",
  OneTimeInviteOutput
>;

type StoreCallbacks = Readonly<{
  load: DurableAuthorityStore<OneTimeInviteOutput>["load"];
  acquire: DurableAuthorityStore<OneTimeInviteOutput>["acquire"];
  compareAndSwap: DurableAuthorityStore<OneTimeInviteOutput>["compareAndSwap"];
  commit: DurableAuthorityStore<OneTimeInviteOutput>["commit"];
  markIndeterminate: DurableAuthorityStore<OneTimeInviteOutput>["markIndeterminate"];
}>;

type AuthorityRecord = Readonly<{
  authority_id: string;
  trusted_now: OneTimeInviteAuthorityConfig["trusted_now"];
  load_invite_state: OneTimeInviteAuthorityConfig["load_invite_state"];
  establish_group: OneTimeInviteAuthorityConfig["establish_group"];
  store: StoreCallbacks;
}>;

type InviteState = Readonly<{ state: "active" | "revoked"; revision: number }>;

type InviteResponse = Readonly<{
  spec_version: "heterodyne/0.6.0";
  purpose: InvitePurpose;
  descriptor_digest: string;
  responder_account: string;
  mls_key_package: string;
  requested_class: string;
  capabilities: readonly string[];
  proof: string;
}>;

type CapturedRedemption = Readonly<{
  envelope: Readonly<{
    descriptor: Readonly<InviteDescriptor>;
    signature: string;
    secret: string;
  }>;
  response_bytes: Uint8Array;
  response: InviteResponse;
  response_purpose: InvitePurpose;
  recipient: string;
  key_package_bytes: Uint8Array;
  group_transition: Uint8Array;
  descriptor_digest: string;
  response_digest: string;
  key_package_digest: string;
  transition_digest: string;
}>;

type DurableRequest = Readonly<{
  key: string;
  binding_digest: string;
  execution_token: string;
  reconciliation_digest: string;
}>;

type DurableIdentity = Readonly<{
  key: string;
  execution_token: string;
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();

type PreflightLimits = Readonly<{
  max_depth: number;
  max_nodes: number;
  max_properties: number;
  max_array_length: number;
  max_string_bytes: number;
  max_total_string_bytes: number;
  max_byte_length: number;
  max_total_bytes: number;
}>;

function boundedClosedPreflight(value: unknown, limits: PreflightLimits): boolean {
  const active = new Set<object>();
  let nodes = 0;
  let totalStringBytes = 0;
  let totalBytes = 0;
  const addString = (text: string): boolean => {
    if (text.length > limits.max_string_bytes) return false;
    const bytes = Buffer.byteLength(text, "utf8");
    if (bytes > limits.max_string_bytes) return false;
    totalStringBytes += bytes;
    return totalStringBytes <= limits.max_total_string_bytes;
  };
  const visit = (current: unknown, depth: number): boolean => {
    nodes += 1;
    if (nodes > limits.max_nodes || depth > limits.max_depth) return false;
    if (current === null || typeof current === "boolean") return true;
    if (typeof current === "string") return addString(current);
    if (typeof current === "number") return Number.isFinite(current);
    if (typeof current !== "object" || utilTypes.isProxy(current)) return false;
    if (current instanceof Uint8Array) {
      if (Object.getPrototypeOf(current) !== Uint8Array.prototype
        || current.length > limits.max_byte_length) return false;
      totalBytes += current.length;
      return totalBytes <= limits.max_total_bytes;
    }
    if (active.has(current)) return false;
    active.add(current);
    try {
      if (Array.isArray(current)) {
        if (Object.getPrototypeOf(current) !== Array.prototype) return false;
        const lengthDescriptor = Object.getOwnPropertyDescriptor(current, "length");
        if (lengthDescriptor === undefined || !("value" in lengthDescriptor)
          || !Number.isSafeInteger(lengthDescriptor.value)
          || lengthDescriptor.value < 0
          || lengthDescriptor.value > limits.max_array_length) return false;
        const descriptors = Object.getOwnPropertyDescriptors(current);
        const keys = Reflect.ownKeys(descriptors);
        if (keys.length !== lengthDescriptor.value + 1) return false;
        for (let index = 0; index < lengthDescriptor.value; index += 1) {
          const descriptor = descriptors[String(index)];
          if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true
            || !visit(descriptor.value, depth + 1)) return false;
        }
        return true;
      }
      if (Object.getPrototypeOf(current) !== Object.prototype) return false;
      const descriptors = Object.getOwnPropertyDescriptors(current);
      const keys = Reflect.ownKeys(descriptors);
      if (keys.length > limits.max_properties || keys.some((key) => typeof key !== "string")) {
        return false;
      }
      for (const key of keys as string[]) {
        const descriptor = descriptors[key];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true
          || !addString(key) || !visit(descriptor.value, depth + 1)) return false;
      }
      return true;
    } finally {
      active.delete(current);
    }
  };
  return visit(value, 0);
}

function ownBoundedDataValue(object: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  return descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
}

const REDEMPTION_LIMITS: PreflightLimits = Object.freeze({
  max_depth: 8,
  max_nodes: 1_024,
  max_properties: 64,
  max_array_length: MAX_PREAUTHORIZATION_ENTRIES,
  max_string_bytes: MAX_POLICY_STRING_BYTES,
  max_total_string_bytes: 65_536,
  max_byte_length: MAX_AUTHORITY_BYTES,
  max_total_bytes: MAX_AUTHORITY_TOTAL_BYTES,
});

const RESPONSE_LIMITS: PreflightLimits = Object.freeze({
  max_depth: 4,
  max_nodes: 256,
  max_properties: 16,
  max_array_length: MAX_RESPONSE_CAPABILITIES,
  max_string_bytes: MAX_KEY_PACKAGE_BASE64URL_BYTES,
  max_total_string_bytes: MAX_AUTHORITY_BYTES,
  max_byte_length: 0,
  max_total_bytes: 0,
});

const TERMINAL_LIMITS: PreflightLimits = Object.freeze({
  max_depth: 4,
  max_nodes: 32,
  max_properties: 8,
  max_array_length: 0,
  max_string_bytes: MAX_POLICY_STRING_BYTES,
  max_total_string_bytes: 4_096,
  max_byte_length: 0,
  max_total_bytes: 0,
});

function boundedRedemptionShape(value: unknown): boolean {
  if (!boundedClosedPreflight(value, REDEMPTION_LIMITS)
    || value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const envelope = ownBoundedDataValue(value, "envelope");
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) return false;
  const descriptor = ownBoundedDataValue(envelope, "descriptor");
  if (descriptor === null || typeof descriptor !== "object" || Array.isArray(descriptor)) return false;
  const relayHints = ownBoundedDataValue(descriptor, "relay_hints");
  return Array.isArray(relayHints) && relayHints.length <= MAX_RELAY_HINTS;
}

function exactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && expected.every((key, index) => actual[index] === key);
}

function ownDataProperty(object: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`one-time invite config requires data property ${name}`);
  }
  return descriptor.value;
}

function boundMethod<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  let owner: object | null = object;
  while (owner !== null) {
    if (utilTypes.isProxy(owner)) throw new TypeError("one-time invite store cannot be a proxy");
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new TypeError(`one-time invite store requires data method ${name}`);
      }
      return descriptor.value.bind(object) as T;
    }
    owner = Object.getPrototypeOf(owner) as object | null;
  }
  throw new TypeError(`one-time invite store requires method ${name}`);
}

function snapshotConfig(config: OneTimeInviteAuthorityConfig): AuthorityRecord {
  if (
    config === null
    || typeof config !== "object"
    || utilTypes.isProxy(config)
    || Object.getPrototypeOf(config) !== Object.prototype
  ) throw new TypeError("one-time invite config must be an ordinary object");
  const descriptors = Object.getOwnPropertyDescriptors(config);
  const required = ["authority_id", "trusted_now", "store", "load_invite_state", "establish_group"];
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
    || Object.keys(descriptors).length !== required.length
    || !required.every((name) => Object.hasOwn(descriptors, name))
  ) throw new TypeError("one-time invite config must be closed");
  const authorityId = ownDataProperty(config, "authority_id");
  const trustedNow = ownDataProperty(config, "trusted_now");
  const store = ownDataProperty(config, "store");
  const loadInviteState = ownDataProperty(config, "load_invite_state");
  const establishGroup = ownDataProperty(config, "establish_group");
  if (
    typeof authorityId !== "string" || authorityId.length === 0 || authorityId.length > 256
    || typeof trustedNow !== "function" || utilTypes.isProxy(trustedNow)
    || typeof loadInviteState !== "function" || utilTypes.isProxy(loadInviteState)
    || typeof establishGroup !== "function" || utilTypes.isProxy(establishGroup)
    || store === null || typeof store !== "object" || utilTypes.isProxy(store)
  ) throw new TypeError("invalid one-time invite config");
  return Object.freeze({
    authority_id: authorityId,
    trusted_now: trustedNow as OneTimeInviteAuthorityConfig["trusted_now"],
    load_invite_state: loadInviteState as OneTimeInviteAuthorityConfig["load_invite_state"],
    establish_group: establishGroup as OneTimeInviteAuthorityConfig["establish_group"],
    store: Object.freeze({
      load: boundMethod<StoreCallbacks["load"]>(store, "load"),
      acquire: boundMethod<StoreCallbacks["acquire"]>(store, "acquire"),
      compareAndSwap: boundMethod<StoreCallbacks["compareAndSwap"]>(store, "compareAndSwap"),
      commit: boundMethod<StoreCallbacks["commit"]>(store, "commit"),
      markIndeterminate: boundMethod<StoreCallbacks["markIndeterminate"]>(store, "markIndeterminate"),
    }),
  });
}

export function createOneTimeInviteAuthority(
  config: OneTimeInviteAuthorityConfig,
): OneTimeInviteAuthority {
  const authority = Object.freeze({});
  AUTHORITIES.set(authority, snapshotConfig(config));
  return authority;
}

function validRelayHint(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "wss:"
      && parsed.hostname.length > 0
      && parsed.username === ""
      && parsed.password === ""
      && parsed.hash === ""
      && (parsed.href === value
        || (parsed.pathname === "/" && parsed.search === "" && parsed.href === `${value}/`));
  } catch {
    return false;
  }
}

function validPreauthorization(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const template = value as Readonly<Record<string, unknown>>;
  if (!exactKeys(template, [
    "client_class", "methods", "objects", "limits", "agent_role",
    "token_lifetime_ceiling_seconds", "unbound_bearer",
  ])) return false;
  if (
    template.client_class !== "human-light" && template.client_class !== "automated"
    || !Array.isArray(template.methods)
    || template.methods.length > MAX_PREAUTHORIZATION_ENTRIES
    || !template.methods.every((item) => typeof item === "string" && item.length > 0)
    || new Set(template.methods).size !== template.methods.length
    || !Array.isArray(template.objects)
    || template.objects.length > MAX_PREAUTHORIZATION_ENTRIES
    || !template.objects.every((item) => typeof item === "string" && item.length > 0)
    || new Set(template.objects).size !== template.objects.length
    || template.limits === null || typeof template.limits !== "object"
    || Array.isArray(template.limits)
    || Object.keys(template.limits).length === 0
    || Object.keys(template.limits).length > MAX_PREAUTHORIZATION_ENTRIES
    || !Object.values(template.limits).every((limit) => Number.isSafeInteger(limit) && (limit as number) >= 1)
    || (template.agent_role !== null
      && (typeof template.agent_role !== "string" || template.agent_role.length === 0))
    || !Number.isSafeInteger(template.token_lifetime_ceiling_seconds)
    || (template.token_lifetime_ceiling_seconds as number) < 1
    || (template.token_lifetime_ceiling_seconds as number) > 3_600
    || typeof template.unbound_bearer !== "boolean"
  ) return false;
  return true;
}

function validDescriptor(descriptor: Readonly<InviteDescriptor>): boolean {
  const value = descriptor as unknown as Readonly<Record<string, unknown>>;
  const allowed = [
    "version", "purpose", "inviter_account", "invite_id", "rendezvous_pubkey",
    "relay_hints", "issued_at", "expires_at", "secret_sha256", "approval_mode",
    "preauthorization", "expected_client_pubkey",
  ];
  const required = allowed.slice(0, 10);
  if (
    !Object.keys(value).every((key) => allowed.includes(key))
    || !required.every((key) => Object.hasOwn(value, key))
    || value.version !== 1
    || typeof value.purpose !== "string" || !PURPOSES.has(value.purpose as InvitePurpose)
    || typeof value.inviter_account !== "string" || !HEX_32.test(value.inviter_account)
    || typeof value.invite_id !== "string" || !HEX_32.test(value.invite_id)
    || typeof value.rendezvous_pubkey !== "string" || !HEX_32.test(value.rendezvous_pubkey)
    || !Array.isArray(value.relay_hints) || value.relay_hints.length === 0
    || value.relay_hints.length > MAX_RELAY_HINTS
    || !value.relay_hints.every((hint) => typeof hint === "string" && validRelayHint(hint))
    || new Set(value.relay_hints).size !== value.relay_hints.length
    || !Number.isSafeInteger(value.issued_at) || (value.issued_at as number) < 0
    || !Number.isSafeInteger(value.expires_at)
    || (value.expires_at as number) <= (value.issued_at as number)
    || typeof value.secret_sha256 !== "string" || !HEX_32.test(value.secret_sha256)
    || (value.approval_mode !== "interactive" && value.approval_mode !== "preauthorized")
  ) return false;
  if (Object.hasOwn(value, "expected_client_pubkey")
    && (typeof value.expected_client_pubkey !== "string" || !HEX_32.test(value.expected_client_pubkey))) {
    return false;
  }
  const duration = (value.expires_at as number) - (value.issued_at as number);
  if (duration > (value.purpose === "dm" ? 7 * 24 * 60 * 60 : 3_600)) return false;
  const hasPreauthorization = Object.hasOwn(value, "preauthorization");
  if (value.approval_mode === "preauthorized") {
    return value.purpose === "control-enrollment"
      && hasPreauthorization
      && validPreauthorization(value.preauthorization);
  }
  return !hasPreauthorization;
}

function decodeCanonicalBase64url(value: string): Uint8Array | null {
  if (value.length > MAX_KEY_PACKAGE_BASE64URL_BYTES || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    return null;
  }
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.length === 0 || bytes.length > MAX_AUTHORITY_BYTES
      || bytes.toString("base64url") !== value) return null;
    return new Uint8Array(bytes);
  } catch {
    return null;
  }
}

function boundedPolicyString(value: unknown): value is string {
  return typeof value === "string"
    && value.length > 0
    && Buffer.byteLength(value, "utf8") <= MAX_POLICY_STRING_BYTES;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function equalHex(left: string, right: string): boolean {
  if (left.length !== right.length || !/^[0-9a-f]+$/u.test(left) || !/^[0-9a-f]+$/u.test(right)) {
    return false;
  }
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function parseResponse(bytes: Uint8Array): InviteResponse | null {
  try {
    const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parsed: unknown = JSON.parse(source);
    if (!boundedClosedPreflight(parsed, RESPONSE_LIMITS)) return null;
    const captured = captureAuthorityInput(parsed);
    if (
      captured === null || typeof captured !== "object" || Array.isArray(captured)
      || jcsCanonicalize(captured) !== source
    ) return null;
    const response = captured as unknown as Readonly<Record<string, unknown>>;
    if (!exactKeys(response, [
      "spec_version", "purpose", "descriptor_digest", "responder_account",
      "mls_key_package", "requested_class", "capabilities", "proof",
    ])) return null;
    if (
      response.spec_version !== "heterodyne/0.6.0"
      || typeof response.purpose !== "string" || !PURPOSES.has(response.purpose as InvitePurpose)
      || typeof response.descriptor_digest !== "string" || !HEX_32.test(response.descriptor_digest)
      || typeof response.responder_account !== "string" || !HEX_32.test(response.responder_account)
      || typeof response.mls_key_package !== "string"
      || decodeCanonicalBase64url(response.mls_key_package) === null
      || !boundedPolicyString(response.requested_class)
      || !RESPONSE_CLASSES[response.purpose as InvitePurpose].has(response.requested_class)
      || !Array.isArray(response.capabilities)
      || response.capabilities.length > MAX_RESPONSE_CAPABILITIES
      || !response.capabilities.every(boundedPolicyString)
      || new Set(response.capabilities).size !== response.capabilities.length
      || typeof response.proof !== "string" || !HEX_32.test(response.proof)
    ) return null;
    return response as unknown as InviteResponse;
  } catch {
    return null;
  }
}

function captureRedemption(value: OneTimeInviteRedemption): CapturedRedemption | null {
  try {
    if (!boundedRedemptionShape(value)) return null;
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const input = captured as unknown as Readonly<Record<string, unknown>>;
    if (!exactKeys(input, [
      "envelope", "response_bytes", "response_purpose", "recipient",
      "key_package_bytes", "group_transition",
    ])) return null;
    if (input.envelope === null || typeof input.envelope !== "object" || Array.isArray(input.envelope)) {
      return null;
    }
    const envelope = input.envelope as Readonly<Record<string, unknown>>;
    if (!exactKeys(envelope, ["descriptor", "signature", "secret"])
      || envelope.descriptor === null || typeof envelope.descriptor !== "object"
      || Array.isArray(envelope.descriptor)
      || typeof envelope.signature !== "string" || !HEX_64.test(envelope.signature)
      || typeof envelope.secret !== "string" || !HEX_32.test(envelope.secret)
      || !(input.response_bytes instanceof Uint8Array) || input.response_bytes.length === 0
      || typeof input.response_purpose !== "string" || !PURPOSES.has(input.response_purpose as InvitePurpose)
      || typeof input.recipient !== "string" || !HEX_32.test(input.recipient)
      || !(input.key_package_bytes instanceof Uint8Array) || input.key_package_bytes.length === 0
      || !(input.group_transition instanceof Uint8Array) || input.group_transition.length === 0
    ) return null;
    const descriptor = envelope.descriptor as Readonly<InviteDescriptor>;
    if (!validDescriptor(descriptor)) return null;
    const inviteEnvelope = Object.freeze({
      descriptor,
      signature: envelope.signature,
      secret: envelope.secret,
    });
    if (
      !verifyInviteSignature(descriptor as InviteDescriptor, envelope.signature)
      || !equalHex(secretCommitment(envelope.secret), descriptor.secret_sha256)
    ) return null;
    const responseBytes = new Uint8Array(input.response_bytes);
    const response = parseResponse(responseBytes);
    if (response === null) return null;
    const descriptorDigestHex = Buffer.from(descriptorDigest(descriptor as InviteDescriptor)).toString("hex");
    const keyPackageBytes = new Uint8Array(input.key_package_bytes);
    const encodedKeyPackage = decodeCanonicalBase64url(response.mls_key_package);
    if (
      descriptor.purpose !== input.response_purpose
      || response.purpose !== input.response_purpose
      || !equalHex(response.descriptor_digest, descriptorDigestHex)
      || response.responder_account !== input.recipient
      || (descriptor.expected_client_pubkey !== undefined
        && descriptor.expected_client_pubkey !== input.recipient)
      || encodedKeyPackage === null || !equalBytes(encodedKeyPackage, keyPackageBytes)
    ) return null;
    const withoutProof = {
      spec_version: response.spec_version,
      purpose: response.purpose,
      descriptor_digest: response.descriptor_digest,
      responder_account: response.responder_account,
      mls_key_package: response.mls_key_package,
      requested_class: response.requested_class,
      capabilities: response.capabilities,
    };
    if (!equalHex(response.proof, responseProof(envelope.secret, withoutProof))) return null;
    const groupTransition = new Uint8Array(input.group_transition);
    return Object.freeze({
      envelope: inviteEnvelope,
      response_bytes: responseBytes,
      response,
      response_purpose: input.response_purpose as InvitePurpose,
      recipient: input.recipient,
      key_package_bytes: keyPackageBytes,
      group_transition: groupTransition,
      descriptor_digest: descriptorDigestHex,
      response_digest: createHash("sha256").update(responseBytes).digest("hex"),
      key_package_digest: createHash("sha256").update(keyPackageBytes).digest("hex"),
      transition_digest: createHash("sha256").update(groupTransition).digest("hex"),
    });
  } catch {
    return null;
  }
}

function captureInviteState(value: unknown): InviteState | null {
  try {
    if (!boundedClosedPreflight(value, TERMINAL_LIMITS)) return null;
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const state = captured as unknown as Readonly<Record<string, unknown>>;
    if (
      !exactKeys(state, ["state", "revision"])
      || (state.state !== "active" && state.state !== "revoked")
      || !Number.isSafeInteger(state.revision) || (state.revision as number) < 0
    ) return null;
    return state as unknown as InviteState;
  } catch {
    return null;
  }
}

function captureOutput(value: unknown): OneTimeInviteOutput | null {
  try {
    if (!boundedClosedPreflight(value, TERMINAL_LIMITS)) return null;
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const output = captured as unknown as Readonly<Record<string, unknown>>;
    if (!exactKeys(output, ["group_id", "response_digest"])
      || typeof output.group_id !== "string" || !HEX_32.test(output.group_id)
      || typeof output.response_digest !== "string" || !HEX_32.test(output.response_digest)) {
      return null;
    }
    return output as OneTimeInviteOutput;
  } catch {
    return null;
  }
}

function captureDurableRecord(
  value: DurableAuthorityRecord<OneTimeInviteOutput> | null,
): DurableAuthorityRecord<OneTimeInviteOutput> | null | undefined {
  if (value === null) return null;
  try {
    if (!boundedClosedPreflight(value, TERMINAL_LIMITS)) return undefined;
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return undefined;
    const record = captured as unknown as Readonly<Record<string, unknown>>;
    if (!Number.isSafeInteger(record.revision) || (record.revision as number) < 0
      || typeof record.binding_digest !== "string" || !HEX_32.test(record.binding_digest)) {
      return undefined;
    }
    if (record.state === "available") {
      if (!exactKeys(record, ["state", "revision", "binding_digest", "output"])
        || captureOutput(record.output) === null) return undefined;
    } else if (record.state === "executing") {
      if (!exactKeys(record, ["state", "revision", "binding_digest", "execution_token"])
        || typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)) {
        return undefined;
      }
    } else if (record.state === "committed") {
      if (!exactKeys(record, [
        "state", "revision", "binding_digest", "execution_token", "output_digest", "output",
      ])
        || typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)
        || typeof record.output_digest !== "string" || !HEX_32.test(record.output_digest)
        || captureOutput(record.output) === null) return undefined;
    } else if (record.state === "indeterminate") {
      if (!exactKeys(record, [
        "state", "revision", "binding_digest", "execution_token", "reconciliation_digest",
      ])
        || typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)
        || typeof record.reconciliation_digest !== "string"
        || !HEX_32.test(record.reconciliation_digest)) return undefined;
    } else return undefined;
    return captured;
  } catch {
    return undefined;
  }
}

function identityFor(authorityId: string, input: CapturedRedemption): DurableIdentity {
  const key = authorityBindingDigest("heterodyne.one-time-invite.key/v1", {
    authority_id: authorityId,
    invite_id: input.envelope.descriptor.invite_id,
  });
  return Object.freeze({
    key,
    execution_token: authorityBindingDigest("heterodyne.one-time-invite.execution/v1", {
      authority_id: authorityId,
      key,
      descriptor_digest: input.descriptor_digest,
      signature: input.envelope.signature,
      secret_commitment: input.envelope.descriptor.secret_sha256,
      response_digest: input.response_digest,
      purpose: input.response_purpose,
      recipient: input.recipient,
      key_package_digest: input.key_package_digest,
      transition_digest: input.transition_digest,
    }),
  });
}

function requestFor(
  authorityId: string,
  input: CapturedRedemption,
  state: InviteState,
  identity: DurableIdentity,
): DurableRequest {
  const { key, execution_token: executionToken } = identity;
  const bindingDigest = authorityBindingDigest("heterodyne.one-time-invite.binding/v1", {
    authority_id: authorityId,
    key,
    invite_revision: state.revision,
    state_fingerprint: authorityBindingDigest("heterodyne.one-time-invite.state/v1", {
      state: state.state,
      revision: state.revision,
    }),
    descriptor_digest: input.descriptor_digest,
    signature: input.envelope.signature,
    secret_commitment: input.envelope.descriptor.secret_sha256,
    response_digest: input.response_digest,
    purpose: input.response_purpose,
    recipient: input.recipient,
    key_package_digest: input.key_package_digest,
    transition_digest: input.transition_digest,
  });
  return Object.freeze({
    key,
    binding_digest: bindingDigest,
    execution_token: executionToken,
    reconciliation_digest: authorityBindingDigest("heterodyne.one-time-invite.reconciliation/v1", {
      authority_id: authorityId, key, binding_digest: bindingDigest,
      execution_token: executionToken,
    }),
  });
}

function committedReconciliation(
  authorityId: string,
  input: CapturedRedemption,
  identity: DurableIdentity,
  record: DurableAuthorityRecord<OneTimeInviteOutput> | null | undefined,
): OneTimeInviteDecision | null {
  if (record === undefined || record === null || record.state !== "committed"
    || record.execution_token !== identity.execution_token) return null;
  const output = captureOutput(record.output);
  if (output === null || output.response_digest !== input.response_digest
    || record.output_digest !== outputDigest(output)) return null;
  return indeterminate(Object.freeze({
    key: identity.key,
    binding_digest: record.binding_digest,
    execution_token: record.execution_token,
    reconciliation_digest: authorityBindingDigest("heterodyne.one-time-invite.reconciliation/v1", {
      authority_id: authorityId,
      key: identity.key,
      binding_digest: record.binding_digest,
      execution_token: record.execution_token,
    }),
  }));
}

function outputDigest(output: OneTimeInviteOutput): string {
  return authorityBindingDigest("heterodyne.one-time-invite.output/v1", output);
}

function committedOutput(
  record: DurableAuthorityRecord<OneTimeInviteOutput>,
  request: DurableRequest,
  responseDigest: string,
): OneTimeInviteOutput | null {
  if (record.state !== "committed"
    || record.binding_digest !== request.binding_digest
    || record.execution_token !== request.execution_token) return null;
  const output = captureOutput(record.output);
  if (output === null
    || output.response_digest !== responseDigest
    || record.output_digest !== outputDigest(output)) return null;
  return output;
}

function indeterminate(request: DurableRequest): OneTimeInviteDecision {
  return Object.freeze({
    verdict: "indeterminate",
    reconciliation_digest: request.reconciliation_digest,
  });
}

async function loadRecord(store: StoreCallbacks, key: string) {
  try {
    return captureDurableRecord(await store.load(key));
  } catch {
    return undefined;
  }
}

async function markIndeterminate(store: StoreCallbacks, request: DurableRequest): Promise<void> {
  try {
    await store.markIndeterminate(Object.freeze({
      key: request.key,
      binding_digest: request.binding_digest,
      execution_token: request.execution_token,
      reconciliation_digest: request.reconciliation_digest,
    }));
  } catch {
    // The deterministic reconciliation digest is still the only public result.
  }
}

async function reloadInviteState(
  authority: AuthorityRecord,
  input: CapturedRedemption,
): Promise<InviteState | null> {
  try {
    return captureInviteState(await authority.load_invite_state(
      input.envelope.descriptor.invite_id,
    ));
  } catch {
    return null;
  }
}

function validInviteTime(authority: AuthorityRecord, input: CapturedRedemption): boolean {
  try {
    const now = authority.trusted_now();
    return Number.isSafeInteger(now)
      && now >= input.envelope.descriptor.issued_at
      && now < input.envelope.descriptor.expires_at;
  } catch {
    return false;
  }
}

async function currentInviteStateIsExact(
  authority: AuthorityRecord,
  input: CapturedRedemption,
  expected: InviteState,
): Promise<boolean> {
  if (!validInviteTime(authority, input)) return false;
  const current = await reloadInviteState(authority, input);
  return validInviteTime(authority, input)
    && current !== null
    && current.state === "active"
    && current.state === expected.state
    && current.revision === expected.revision;
}

function sameOutput(left: OneTimeInviteOutput, right: OneTimeInviteOutput): boolean {
  return left.group_id === right.group_id && left.response_digest === right.response_digest;
}

export async function redeemOneTimeInvite(
  authority: OneTimeInviteAuthority,
  input: OneTimeInviteRedemption,
): Promise<OneTimeInviteDecision> {
  const authorityRecord = AUTHORITIES.get(authority);
  if (authorityRecord === undefined) return REJECT;
  const captured = captureRedemption(input);
  if (captured === null) return REJECT;
  const identity = identityFor(authorityRecord.authority_id, captured);
  const state = await reloadInviteState(authorityRecord, captured);
  if (!validInviteTime(authorityRecord, captured) || state === null || state.state !== "active") {
    const terminal = await loadRecord(authorityRecord.store, identity.key);
    return committedReconciliation(
      authorityRecord.authority_id, captured, identity, terminal,
    ) ?? REJECT;
  }

  const request = requestFor(authorityRecord.authority_id, captured, state, identity);
  let loaded = await loadRecord(authorityRecord.store, request.key);
  const currentStateExact = await currentInviteStateIsExact(authorityRecord, captured, state);
  if (loaded === undefined) return currentStateExact ? indeterminate(request) : REJECT;
  if (loaded !== null) {
    if (loaded.binding_digest !== request.binding_digest) {
      return committedReconciliation(
        authorityRecord.authority_id, captured, identity, loaded,
      ) ?? REJECT;
    }
    const cached = committedOutput(loaded, request, captured.response_digest);
    if (!currentStateExact) return cached === null ? REJECT : indeterminate(request);
    if (cached !== null) return Object.freeze({ verdict: "accept", output: cached });
    return indeterminate(request);
  }
  if (!currentStateExact) return REJECT;

  let acquired: "acquired" | "replay" | "conflict" | "unavailable";
  try {
    acquired = await authorityRecord.store.acquire(Object.freeze({
      key: request.key,
      expected_revision: null,
      binding_digest: request.binding_digest,
      execution_token: request.execution_token,
    }));
  } catch {
    return indeterminate(request);
  }
  if (acquired !== "acquired") {
    loaded = await loadRecord(authorityRecord.store, request.key);
    if (!await currentInviteStateIsExact(authorityRecord, captured, state)) return REJECT;
    if (loaded === undefined || loaded === null) return indeterminate(request);
    if (loaded.binding_digest !== request.binding_digest) return REJECT;
    const cached = committedOutput(loaded, request, captured.response_digest);
    return cached === null
      ? indeterminate(request)
      : Object.freeze({ verdict: "accept", output: cached });
  }

  if (!await currentInviteStateIsExact(authorityRecord, captured, state)) {
    await markIndeterminate(authorityRecord.store, request);
    return REJECT;
  }

  let output: OneTimeInviteOutput | null;
  try {
    output = captureOutput(await authorityRecord.establish_group(
      new Uint8Array(captured.group_transition),
      request.execution_token,
    ));
  } catch {
    output = null;
  }
  if (output === null || output.response_digest !== captured.response_digest) {
    await markIndeterminate(authorityRecord.store, request);
    return indeterminate(request);
  }
  if (!await currentInviteStateIsExact(authorityRecord, captured, state)) {
    await markIndeterminate(authorityRecord.store, request);
    return indeterminate(request);
  }
  const digest = outputDigest(output);
  let committed: "committed" | "conflict" | "unknown";
  try {
    committed = await authorityRecord.store.commit(Object.freeze({
      key: request.key,
      binding_digest: request.binding_digest,
      execution_token: request.execution_token,
      output_digest: digest,
      output,
    }));
  } catch {
    committed = "unknown";
  }
  if (committed !== "committed") {
    if (committed === "conflict") {
      const raced = await loadRecord(authorityRecord.store, request.key);
      if (!await currentInviteStateIsExact(authorityRecord, captured, state)) {
        await markIndeterminate(authorityRecord.store, request);
        return indeterminate(request);
      }
      if (raced !== undefined && raced !== null) {
        const cached = committedOutput(raced, request, captured.response_digest);
        if (cached !== null && sameOutput(cached, output)) {
          return Object.freeze({ verdict: "accept", output: cached });
        }
      }
    }
    await markIndeterminate(authorityRecord.store, request);
    return indeterminate(request);
  }
  const terminal = await loadRecord(authorityRecord.store, request.key);
  if (terminal === undefined || terminal === null) {
    await markIndeterminate(authorityRecord.store, request);
    return indeterminate(request);
  }
  const readback = committedOutput(terminal, request, captured.response_digest);
  if (readback === null || !sameOutput(readback, output)) {
    await markIndeterminate(authorityRecord.store, request);
    return indeterminate(request);
  }
  if (!await currentInviteStateIsExact(authorityRecord, captured, state)) {
    await markIndeterminate(authorityRecord.store, request);
    return indeterminate(request);
  }
  return Object.freeze({ verdict: "accept", output: readback });
}
