import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type AuthorityDecision,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
} from "./security-authority-support.js";

const HEX_32 = /^[0-9a-f]{64}$/u;
const ACCOUNT = HEX_32;
const NID = /^did:key:z[1-9A-HJ-NP-Za-km-z]+$/u;
const SENDER_REF = /^refs\/xyz\.heterodyne\.marmot\/(?:writers|relays)\/[A-Za-z0-9._-]+$/u;
const NID_REQUIRED = Object.freeze({
  verdict: "reject" as const,
  reason_code: "marmot-private-inbox-nid-required" as const,
});
const SCOPE_DENIED = Object.freeze({
  verdict: "reject" as const,
  reason_code: "marmot-agent-scope-denied" as const,
});
const REPLAYED = Object.freeze({
  verdict: "reject" as const,
  reason_code: "marmot-keypackage-replayed" as const,
});

export type PersonaInboxAdmissionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  store: DurableAuthorityStore<Readonly<{ group_id: string; key_package_ref: string }>>;
  load_inbox: (recipient: string) => Promise<Readonly<{
    checkpoint: string;
    recipient_nid: string | null;
    consumed_key_packages: readonly string[];
    allowed_agent_scopes: readonly string[];
  }>>;
}>;

export type PersonaInboxBundle = Readonly<{
  recipient: string;
  sender: string;
  sender_kind: "persona" | "agent";
  sender_ref: string;
  purpose: "marmot-first-contact";
  required_agent_scope: string | null;
  key_package_bytes: Uint8Array;
  key_package_ref: string;
  group_transition: Uint8Array;
}>;

export type PersonaInboxAdmission = Readonly<{
  group_id: string;
  key_package_ref: string;
}>;

export type PersonaInboxAdmissionAuthority = Readonly<Record<never, never>>;
export type PersonaInboxAdmissionDecision = AuthorityDecision<
  | "marmot-agent-scope-denied"
  | "marmot-keypackage-replayed"
  | "marmot-private-inbox-nid-required",
  PersonaInboxAdmission
>;

type StoreCallbacks = Readonly<{
  load: DurableAuthorityStore<PersonaInboxAdmission>["load"];
  acquire: DurableAuthorityStore<PersonaInboxAdmission>["acquire"];
  compareAndSwap: DurableAuthorityStore<PersonaInboxAdmission>["compareAndSwap"];
  commit: DurableAuthorityStore<PersonaInboxAdmission>["commit"];
  markIndeterminate: DurableAuthorityStore<PersonaInboxAdmission>["markIndeterminate"];
}>;

type AuthorityRecord = Readonly<{
  authority_id: string;
  trusted_now: PersonaInboxAdmissionAuthorityConfig["trusted_now"];
  load_inbox: PersonaInboxAdmissionAuthorityConfig["load_inbox"];
  store: StoreCallbacks;
}>;

type CapturedBundle = Readonly<{
  recipient: string;
  sender: string;
  sender_kind: "persona" | "agent";
  sender_ref: string;
  purpose: "marmot-first-contact";
  required_agent_scope: string | null;
  key_package_bytes: Uint8Array;
  key_package_ref: string;
  group_transition: Uint8Array;
  group_id: string;
  key_package_digest: string;
  transition_digest: string;
}>;

type InboxState = Readonly<{
  checkpoint: string;
  recipient_nid: string | null;
  consumed_key_packages: readonly string[];
  allowed_agent_scopes: readonly string[];
}>;

type DurableRequest = Readonly<{
  key: string;
  binding_digest: string;
  execution_token: string;
  reconciliation_digest: string;
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();

function exactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && expected.every((key, index) => actual[index] === key);
}

function ownDataProperty(object: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`persona inbox config requires data property ${name}`);
  }
  return descriptor.value;
}

function boundMethod<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  let owner: object | null = object;
  while (owner !== null) {
    if (utilTypes.isProxy(owner)) throw new TypeError("persona inbox store cannot be a proxy");
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new TypeError(`persona inbox store requires data method ${name}`);
      }
      return descriptor.value.bind(object) as T;
    }
    owner = Object.getPrototypeOf(owner) as object | null;
  }
  throw new TypeError(`persona inbox store requires method ${name}`);
}

function snapshotConfig(config: PersonaInboxAdmissionAuthorityConfig): AuthorityRecord {
  if (
    config === null
    || typeof config !== "object"
    || utilTypes.isProxy(config)
    || Object.getPrototypeOf(config) !== Object.prototype
  ) throw new TypeError("persona inbox config must be an ordinary object");
  const descriptors = Object.getOwnPropertyDescriptors(config);
  const required = ["authority_id", "trusted_now", "store", "load_inbox"];
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
    || Object.keys(descriptors).length !== required.length
    || !required.every((name) => Object.hasOwn(descriptors, name))
  ) throw new TypeError("persona inbox config must be closed");
  const authorityId = ownDataProperty(config, "authority_id");
  const trustedNow = ownDataProperty(config, "trusted_now");
  const store = ownDataProperty(config, "store");
  const loadInbox = ownDataProperty(config, "load_inbox");
  if (
    typeof authorityId !== "string"
    || authorityId.length === 0
    || authorityId.length > 256
    || typeof trustedNow !== "function"
    || utilTypes.isProxy(trustedNow)
    || typeof loadInbox !== "function"
    || utilTypes.isProxy(loadInbox)
    || store === null
    || typeof store !== "object"
    || utilTypes.isProxy(store)
  ) throw new TypeError("invalid persona inbox config");
  return Object.freeze({
    authority_id: authorityId,
    trusted_now: trustedNow as PersonaInboxAdmissionAuthorityConfig["trusted_now"],
    load_inbox: loadInbox as PersonaInboxAdmissionAuthorityConfig["load_inbox"],
    store: Object.freeze({
      load: boundMethod<StoreCallbacks["load"]>(store, "load"),
      acquire: boundMethod<StoreCallbacks["acquire"]>(store, "acquire"),
      compareAndSwap: boundMethod<StoreCallbacks["compareAndSwap"]>(store, "compareAndSwap"),
      commit: boundMethod<StoreCallbacks["commit"]>(store, "commit"),
      markIndeterminate: boundMethod<StoreCallbacks["markIndeterminate"]>(store, "markIndeterminate"),
    }),
  });
}

export function createPersonaInboxAdmissionAuthority(
  config: PersonaInboxAdmissionAuthorityConfig,
): PersonaInboxAdmissionAuthority {
  const authority = Object.freeze({});
  AUTHORITIES.set(authority, snapshotConfig(config));
  return authority;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function captureBundle(value: PersonaInboxBundle): CapturedBundle | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const input = captured as unknown as Readonly<Record<string, unknown>>;
    if (!exactKeys(input, [
      "recipient", "sender", "sender_kind", "sender_ref", "purpose",
      "required_agent_scope", "key_package_bytes", "key_package_ref", "group_transition",
    ])) return null;
    if (
      typeof input.recipient !== "string" || !ACCOUNT.test(input.recipient)
      || typeof input.sender !== "string" || !ACCOUNT.test(input.sender)
      || (input.sender_kind !== "persona" && input.sender_kind !== "agent")
      || typeof input.sender_ref !== "string" || !SENDER_REF.test(input.sender_ref)
      || input.purpose !== "marmot-first-contact"
      || (input.required_agent_scope !== null && (
        typeof input.required_agent_scope !== "string" || input.required_agent_scope.length === 0
      ))
      || !(input.key_package_bytes instanceof Uint8Array)
      || input.key_package_bytes.length === 0
      || typeof input.key_package_ref !== "string" || !HEX_32.test(input.key_package_ref)
      || !(input.group_transition instanceof Uint8Array)
      || input.group_transition.length === 0
    ) return null;
    const keyPackageBytes = new Uint8Array(input.key_package_bytes);
    const groupTransition = new Uint8Array(input.group_transition);
    const keyPackageDigest = sha256(keyPackageBytes);
    if (input.key_package_ref !== keyPackageDigest) return null;
    return Object.freeze({
      recipient: input.recipient,
      sender: input.sender,
      sender_kind: input.sender_kind,
      sender_ref: input.sender_ref,
      purpose: input.purpose,
      required_agent_scope: input.required_agent_scope,
      key_package_bytes: keyPackageBytes,
      key_package_ref: input.key_package_ref,
      group_transition: groupTransition,
      group_id: sha256(groupTransition),
      key_package_digest: keyPackageDigest,
      transition_digest: sha256(groupTransition),
    });
  } catch {
    return null;
  }
}

function captureInboxState(value: unknown): InboxState | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const state = captured as unknown as Readonly<Record<string, unknown>>;
    if (!exactKeys(state, [
      "checkpoint", "recipient_nid", "consumed_key_packages", "allowed_agent_scopes",
    ])) return null;
    if (
      typeof state.checkpoint !== "string" || state.checkpoint.length === 0
      || (state.recipient_nid !== null && (
        typeof state.recipient_nid !== "string" || !NID.test(state.recipient_nid)
      ))
      || !Array.isArray(state.consumed_key_packages)
      || !state.consumed_key_packages.every((item) => typeof item === "string" && HEX_32.test(item))
      || new Set(state.consumed_key_packages).size !== state.consumed_key_packages.length
      || !Array.isArray(state.allowed_agent_scopes)
      || !state.allowed_agent_scopes.every((item) => typeof item === "string" && item.length > 0)
      || new Set(state.allowed_agent_scopes).size !== state.allowed_agent_scopes.length
    ) return null;
    return state as unknown as InboxState;
  } catch {
    return null;
  }
}

function captureOutput(value: unknown): PersonaInboxAdmission | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const output = captured as unknown as Readonly<Record<string, unknown>>;
    if (
      !exactKeys(output, ["group_id", "key_package_ref"])
      || typeof output.group_id !== "string" || !HEX_32.test(output.group_id)
      || typeof output.key_package_ref !== "string" || !HEX_32.test(output.key_package_ref)
    ) return null;
    return output as PersonaInboxAdmission;
  } catch {
    return null;
  }
}

function captureDurableRecord(
  value: DurableAuthorityRecord<PersonaInboxAdmission> | null,
): DurableAuthorityRecord<PersonaInboxAdmission> | null | undefined {
  if (value === null) return null;
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return undefined;
    const record = captured as unknown as Readonly<Record<string, unknown>>;
    if (
      !Number.isSafeInteger(record.revision) || (record.revision as number) < 0
      || typeof record.binding_digest !== "string" || !HEX_32.test(record.binding_digest)
    ) return undefined;
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

function requestFor(authorityId: string, input: CapturedBundle, state: InboxState): DurableRequest {
  const key = authorityBindingDigest("heterodyne.persona-inbox.key/v1", {
    authority_id: authorityId,
    key_package_ref: input.key_package_ref,
  });
  const bindingDigest = authorityBindingDigest("heterodyne.persona-inbox.binding/v1", {
    authority_id: authorityId,
    key,
    checkpoint: state.checkpoint,
    recipient_nid: state.recipient_nid,
    recipient: input.recipient,
    sender: input.sender,
    sender_kind: input.sender_kind,
    sender_ref: input.sender_ref,
    purpose: input.purpose,
    required_agent_scope: input.required_agent_scope,
    key_package_ref: input.key_package_ref,
    key_package_digest: input.key_package_digest,
    transition_digest: input.transition_digest,
  });
  const executionToken = authorityBindingDigest("heterodyne.persona-inbox.execution/v1", {
    authority_id: authorityId, key, binding_digest: bindingDigest,
  });
  return Object.freeze({
    key,
    binding_digest: bindingDigest,
    execution_token: executionToken,
    reconciliation_digest: authorityBindingDigest("heterodyne.persona-inbox.reconciliation/v1", {
      authority_id: authorityId, key, binding_digest: bindingDigest,
      execution_token: executionToken,
    }),
  });
}

function outputDigest(output: PersonaInboxAdmission): string {
  return authorityBindingDigest("heterodyne.persona-inbox.output/v1", output);
}

function indeterminate(request: DurableRequest): PersonaInboxAdmissionDecision {
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

export async function admitPersonaInboxBundle(
  authority: PersonaInboxAdmissionAuthority,
  bundle: PersonaInboxBundle,
): Promise<PersonaInboxAdmissionDecision> {
  const authorityRecord = AUTHORITIES.get(authority);
  if (authorityRecord === undefined) return NID_REQUIRED;
  const input = captureBundle(bundle);
  if (input === null) return NID_REQUIRED;
  let now: number;
  try {
    now = authorityRecord.trusted_now();
  } catch {
    return NID_REQUIRED;
  }
  if (!Number.isSafeInteger(now) || now < 0) return NID_REQUIRED;
  let state: InboxState | null;
  try {
    state = captureInboxState(await authorityRecord.load_inbox(input.recipient));
  } catch {
    state = null;
  }
  if (state === null || state.recipient_nid === null) return NID_REQUIRED;
  if (
    input.sender_kind === "agent"
      ? input.required_agent_scope === null
        || !state.allowed_agent_scopes.includes(input.required_agent_scope)
      : input.required_agent_scope !== null
  ) return SCOPE_DENIED;
  if (state.consumed_key_packages.includes(input.key_package_ref)) return REPLAYED;

  const request = requestFor(authorityRecord.authority_id, input, state);
  let loaded = await loadRecord(authorityRecord.store, request.key);
  if (loaded === undefined) return indeterminate(request);
  if (loaded !== null) return REPLAYED;

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
    return loaded === undefined || loaded === null ? indeterminate(request) : REPLAYED;
  }

  const output = Object.freeze({
    group_id: input.group_id,
    key_package_ref: input.key_package_ref,
  });
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
      loaded = await loadRecord(authorityRecord.store, request.key);
      if (loaded !== undefined && loaded !== null) return REPLAYED;
    }
    await markIndeterminate(authorityRecord.store, request);
    return indeterminate(request);
  }
  const terminal = await loadRecord(authorityRecord.store, request.key);
  if (
    terminal === undefined
    || terminal === null
    || terminal.state !== "committed"
    || terminal.binding_digest !== request.binding_digest
    || terminal.execution_token !== request.execution_token
    || terminal.output_digest !== digest
  ) {
    await markIndeterminate(authorityRecord.store, request);
    return indeterminate(request);
  }
  const readback = captureOutput(terminal.output);
  if (
    readback === null
    || outputDigest(readback) !== digest
    || readback.group_id !== output.group_id
    || readback.key_package_ref !== output.key_package_ref
  ) {
    await markIndeterminate(authorityRecord.store, request);
    return indeterminate(request);
  }
  return Object.freeze({ verdict: "accept", output: readback });
}
