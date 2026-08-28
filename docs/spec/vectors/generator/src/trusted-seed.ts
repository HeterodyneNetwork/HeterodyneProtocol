import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import { schnorr } from "@noble/curves/secp256k1";
import { Ajv, type AnySchema } from "ajv";
import trustedSeedAclSchema from "../../../schemas/comms/trusted-seed-acl-v1.schema.json" with { type: "json" };
import { hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { snapshotAndVerifyNostrEvent, type VerifiedNostrEvent } from "./nostr.js";
import { proofBytes } from "./proof-bytes.js";

export type TrustedSeedRole = "read" | "write";

export type TrustedSeedAcl = {
  profile: "heterodyne.trusted-seed-acl.v1";
  spec_version: "heterodyne/0.6.0";
  administrator_account: string;
  accounts: Array<{ account_key: string; roles: TrustedSeedRole[] }>;
  h: string;
  private_rid: string;
  seed_grants: Array<{
    seed_nid: string;
    relay_endpoint: string;
    radicle_endpoint: string;
    writer_ref: string;
    roles: TrustedSeedRole[];
    state: "active" | "revoked";
  }>;
  sequence: number;
  predecessor: string | null;
  group_transition: {
    generation: number;
    marmot_routing_event_id: string;
    routing_binding_sha256: string;
  };
  issued_at: number;
  expires_at: number;
  signature: string;
};

declare const trustedSeedAdmissionAuthorityBrand: unique symbol;
export type TrustedSeedAdmissionAuthority = {
  readonly [trustedSeedAdmissionAuthorityBrand]: true;
};
declare const trustedSeedRequestCapabilityBrand: unique symbol;
export type TrustedSeedRequestCapability = {
  readonly [trustedSeedRequestCapabilityBrand]: true;
};

export type TrustedSeedAdmissionAuthorityBundle = {
  authority: TrustedSeedAdmissionAuthority;
  mintRequestCapability(
    session: unknown,
    request: unknown,
  ): TrustedSeedRequestCapability | null;
};

export type TrustedSeedAdmissionResult =
  | {
      verdict: "accept";
      acl_digest: string;
      seed_nid: string;
      h: string;
      private_rid: string;
      writer_ref?: string;
      nip01_raw?: string;
    }
  | { verdict: "reject"; reason_code: string };

type AuthorityConfiguration = {
  seed_nid: string;
  administrator_account: string;
  trusted_now: () => unknown;
  authenticate_nip42: (session: unknown, request: unknown) => unknown;
  load_current_state: () => unknown;
  consume_once: (binding: unknown) => unknown;
};

type StoredAuthority = AuthorityConfiguration & {
  authority: TrustedSeedAdmissionAuthority;
};

type AdmissionRequest = {
  operation: TrustedSeedRole;
  h: string;
  private_rid: string;
  writer_ref?: string;
  nip01_raw?: string;
};

type Authentication = {
  verdict: "accept";
  account_key: string;
  connection_id: string;
  challenge_id: string;
  request_id: string;
  authenticated_at: number;
  expires_at: number;
};

type CapabilityBinding = {
  authority: TrustedSeedAdmissionAuthority;
  request: Readonly<AdmissionRequest>;
  authentication: Readonly<Authentication>;
  used: boolean;
};

type CurrentState = {
  administrator_account: string;
  acl_candidates: TrustedSeedAcl[];
  previous_acl: TrustedSeedAcl | null;
  group_transition: TrustedSeedAcl["group_transition"];
  revision: number;
};

const ajv = new Ajv({ allErrors: true, strict: false });
const validateAcl = ajv.compile<TrustedSeedAcl>(trustedSeedAclSchema as AnySchema);
const AUTHORITIES = new WeakMap<object, StoredAuthority>();
const CAPABILITIES = new WeakMap<object, CapabilityBinding>();
const HEX_32 = /^[0-9a-f]{64}$/;
const CONFIGURATION_MEMBERS = [
  "administrator_account",
  "authenticate_nip42",
  "consume_once",
  "load_current_state",
  "seed_nid",
  "trusted_now",
] as const;

export function trustedSeedAclProofBytes(
  value: Omit<TrustedSeedAcl, "signature"> | Record<string, unknown>,
): Uint8Array {
  const { signature: _signature, ...unsigned } = value as Record<string, unknown>;
  return proofBytes("heterodyne-trusted-seed-acl-v1", unsigned);
}

export function trustedSeedAclDigest(value: unknown): string {
  return createHash("sha256")
    .update(utf8Bytes(jcsCanonicalize(value)))
    .digest("hex");
}

export function createTrustedSeedAdmissionAuthority(
  value: unknown,
): TrustedSeedAdmissionAuthorityBundle | null {
  const config = captureConfiguration(value);
  if (config === null) return null;
  const authority = Object.freeze({}) as TrustedSeedAdmissionAuthority;
  const stored: StoredAuthority = { ...config, authority };
  AUTHORITIES.set(authority, stored);
  const mintRequestCapability = (
    session: unknown,
    requestValue: unknown,
  ): TrustedSeedRequestCapability | null => {
    const request = captureRequest(requestValue);
    if (request === null) return null;
    const clock = callAndSnapshot(stored.trusted_now);
    if (!isClockResult(clock)) return null;
    const authentication = callAndSnapshot(
      stored.authenticate_nip42,
      session,
      request,
    );
    if (!isAuthentication(authentication)) return null;
    if (
      authentication.authenticated_at > clock.now
      || clock.now >= authentication.expires_at
    ) return null;
    const capability = Object.freeze({}) as TrustedSeedRequestCapability;
    CAPABILITIES.set(capability, {
      authority,
      request,
      authentication,
      used: false,
    });
    return capability;
  };
  return Object.freeze({ authority, mintRequestCapability });
}

export function evaluateTrustedSeedAdmission(
  authorityValue: unknown,
  capabilityValue: unknown,
): TrustedSeedAdmissionResult {
  if (
    authorityValue === null
    || typeof authorityValue !== "object"
    || capabilityValue === null
    || typeof capabilityValue !== "object"
  ) return denied("trusted-seed-request-invalid");
  const authority = AUTHORITIES.get(authorityValue);
  const capability = CAPABILITIES.get(capabilityValue);
  if (
    authority === undefined
    || capability === undefined
    || capability.authority !== authorityValue
  ) return denied("trusted-seed-request-invalid");
  if (capability.used) return denied("trusted-seed-request-replay");
  capability.used = true;

  const clock = callAndSnapshot(authority.trusted_now);
  if (!isClockResult(clock)) return denied("trusted-seed-request-invalid");
  if (clock.now >= capability.authentication.expires_at) {
    return denied("trusted-seed-nip42-required");
  }
  const stateValue = callAndSnapshot(authority.load_current_state);
  const state = parseCurrentState(stateValue);
  if (state === null) return denied("trusted-seed-acl-invalid");
  if (
    state.administrator_account !== authority.administrator_account
    || state.acl_candidates.some(
      (candidate) => candidate.administrator_account !== authority.administrator_account,
    )
  ) return denied("trusted-seed-unauthorized");

  const aclDecision = selectCurrentAcl(state, clock.now);
  if ("reason_code" in aclDecision) return denied(aclDecision.reason_code);
  const acl = aclDecision.acl;
  const request = capability.request;
  if (acl.h !== request.h || acl.private_rid !== request.private_rid) {
    return denied("trusted-seed-route-mismatch");
  }
  if (!sameTransition(acl.group_transition, state.group_transition)) {
    return acl.group_transition.generation < state.group_transition.generation
      ? denied("trusted-seed-acl-stale")
      : denied("trusted-seed-route-mismatch");
  }
  if (
    hasDuplicate(acl.accounts.map(({ account_key }) => account_key))
    || hasDuplicate(acl.seed_grants.map(({ seed_nid }) => seed_nid))
    || hasDuplicate(acl.seed_grants.map(({ writer_ref }) => writer_ref))
  ) return denied("trusted-seed-acl-ambiguous");

  const grant = acl.seed_grants.find(({ seed_nid }) => seed_nid === authority.seed_nid);
  if (grant?.state === "revoked") return denied("trusted-seed-revoked");
  if (grant === undefined || !grant.roles.includes(request.operation)) {
    return denied("trusted-seed-unauthorized");
  }
  const account = acl.accounts.find(
    ({ account_key }) => account_key === capability.authentication.account_key,
  );
  if (account === undefined || !account.roles.includes(request.operation)) {
    return denied("trusted-seed-unauthorized");
  }

  let event: VerifiedNostrEvent | null = null;
  if (request.operation === "write") {
    if (request.writer_ref !== grant.writer_ref || request.nip01_raw === undefined) {
      return denied("trusted-seed-unauthorized");
    }
    const eventDecision = validateMarmotEvent(request.nip01_raw, request.h);
    if ("reason_code" in eventDecision) return denied(eventDecision.reason_code);
    event = eventDecision.event;
  }

  const aclDigest = trustedSeedAclDigest(acl);
  const consumeBinding = deepFreeze({
    authority_seed_nid: authority.seed_nid,
    account_key: capability.authentication.account_key,
    connection_id: capability.authentication.connection_id,
    challenge_id: capability.authentication.challenge_id,
    request_id: capability.authentication.request_id,
    acl_digest: aclDigest,
    state_revision: state.revision,
    group_transition: state.group_transition,
    operation: request.operation,
    h: request.h,
    private_rid: request.private_rid,
    writer_ref: request.writer_ref ?? null,
    event_id: event?.id ?? null,
    nip01_raw: request.nip01_raw ?? null,
  });
  const consumed = callAndSnapshot(authority.consume_once, consumeBinding);
  if (!isConsumeResult(consumed)) return denied("trusted-seed-request-invalid");
  if (consumed.verdict === "replay") return denied("trusted-seed-request-replay");
  if (consumed.verdict !== "accept") return denied("trusted-seed-request-invalid");

  return {
    verdict: "accept",
    acl_digest: aclDigest,
    seed_nid: authority.seed_nid,
    h: request.h,
    private_rid: request.private_rid,
    ...(request.operation === "write"
      ? { writer_ref: grant.writer_ref, nip01_raw: request.nip01_raw }
      : {}),
  };
}

function captureConfiguration(value: unknown): AuthorityConfiguration | null {
  const descriptors = ordinaryObjectDescriptors(value);
  if (descriptors === null || !hasExactDescriptorMembers(descriptors, CONFIGURATION_MEMBERS)) {
    return null;
  }
  const member = (name: typeof CONFIGURATION_MEMBERS[number]): unknown =>
    dataDescriptorValue(descriptors[name]);
  const seedNid = member("seed_nid");
  const administrator = member("administrator_account");
  const trustedNow = member("trusted_now");
  const authenticate = member("authenticate_nip42");
  const loadCurrentState = member("load_current_state");
  const consumeOnce = member("consume_once");
  if (
    typeof seedNid !== "string" || seedNid.length === 0
    || typeof administrator !== "string" || !HEX_32.test(administrator)
    || typeof trustedNow !== "function"
    || typeof authenticate !== "function"
    || typeof loadCurrentState !== "function"
    || typeof consumeOnce !== "function"
  ) return null;
  return {
    seed_nid: seedNid,
    administrator_account: administrator,
    trusted_now: trustedNow as () => unknown,
    authenticate_nip42: authenticate as (session: unknown, request: unknown) => unknown,
    load_current_state: loadCurrentState as () => unknown,
    consume_once: consumeOnce as (binding: unknown) => unknown,
  };
}

function captureRequest(value: unknown): Readonly<AdmissionRequest> | null {
  const snapshot = snapshotClosedData(value);
  if (!isRecord(snapshot)) return null;
  const operation = snapshot.operation;
  const write = operation === "write";
  const expected = write
    ? ["h", "nip01_raw", "operation", "private_rid", "writer_ref"]
    : ["h", "operation", "private_rid"];
  if (
    !hasExactMembers(snapshot, expected)
    || !["read", "write"].includes(operation as string)
    || typeof snapshot.h !== "string"
    || typeof snapshot.private_rid !== "string"
    || (write && (
      typeof snapshot.writer_ref !== "string" || snapshot.writer_ref.length === 0
      || typeof snapshot.nip01_raw !== "string" || snapshot.nip01_raw.length === 0
    ))
  ) return null;
  return snapshot as AdmissionRequest;
}

function parseCurrentState(value: unknown): Readonly<CurrentState> | null {
  if (!isRecord(value) || !hasExactMembers(value, [
    "acl_candidates",
    "administrator_account",
    "group_transition",
    "previous_acl",
    "revision",
  ])) return null;
  if (
    typeof value.administrator_account !== "string"
    || !HEX_32.test(value.administrator_account)
    || !Array.isArray(value.acl_candidates)
    || value.acl_candidates.length === 0
    || !Number.isSafeInteger(value.revision)
    || (value.revision as number) < 0
    || !isGroupTransition(value.group_transition)
    || !(value.previous_acl === null || isRecord(value.previous_acl))
  ) return null;
  const candidates: TrustedSeedAcl[] = [];
  for (const candidate of value.acl_candidates) {
    if (!validateAcl(candidate)) return null;
    candidates.push(candidate as TrustedSeedAcl);
  }
  if (value.previous_acl !== null && !validateAcl(value.previous_acl)) return null;
  return value as unknown as Readonly<CurrentState>;
}

function selectCurrentAcl(
  state: Readonly<CurrentState>,
  now: number,
): { acl: TrustedSeedAcl } | { reason_code: string } {
  if (state.acl_candidates.some((candidate) => !verifyAclSignature(candidate))) {
    return { reason_code: "trusted-seed-acl-invalid" };
  }
  const greatest = Math.max(...state.acl_candidates.map(({ sequence }) => sequence));
  const heads = deduplicateAcls(
    state.acl_candidates.filter(({ sequence }) => sequence === greatest),
  );
  if (heads.length !== 1) return { reason_code: "trusted-seed-acl-conflict" };
  const acl = heads[0]!;
  if (acl.issued_at > now || acl.expires_at <= acl.issued_at) {
    return { reason_code: "trusted-seed-acl-invalid" };
  }
  if (now >= acl.expires_at) return { reason_code: "trusted-seed-acl-expired" };
  const previous = state.previous_acl;
  if (previous === null) {
    if (acl.sequence !== 0 || acl.predecessor !== null) {
      return { reason_code: "trusted-seed-acl-ambiguous" };
    }
  } else {
    if (
      previous.administrator_account !== state.administrator_account
      || !verifyAclSignature(previous)
    ) return { reason_code: "trusted-seed-acl-invalid" };
    if (acl.sequence <= previous.sequence) return { reason_code: "trusted-seed-acl-stale" };
    if (
      acl.sequence !== previous.sequence + 1
      || acl.predecessor !== trustedSeedAclDigest(previous)
    ) return { reason_code: "trusted-seed-acl-ambiguous" };
  }
  return { acl };
}

function validateMarmotEvent(
  raw: string,
  expectedH: string,
): { event: VerifiedNostrEvent } | {
  reason_code: "trusted-seed-event-invalid" | "trusted-seed-route-mismatch";
} {
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    return { reason_code: "trusted-seed-event-invalid" };
  }
  const event = snapshotAndVerifyNostrEvent(value);
  if (event === null || event.kind !== 445) {
    return { reason_code: "trusted-seed-event-invalid" };
  }
  const routingTags = event.tags.filter(([name]) => name === "h");
  if (
    routingTags.length !== 1
    || routingTags[0]!.length !== 2
    || routingTags[0]![1] !== expectedH
  ) return { reason_code: "trusted-seed-route-mismatch" };
  return { event };
}

function verifyAclSignature(acl: TrustedSeedAcl): boolean {
  try {
    return schnorr.verify(
      hexToBytes(acl.signature),
      trustedSeedAclProofBytes(acl),
      hexToBytes(acl.administrator_account),
    );
  } catch {
    return false;
  }
}

function isClockResult(value: unknown): value is Readonly<{ now: number }> {
  return isRecord(value)
    && hasExactMembers(value, ["now"])
    && Number.isSafeInteger(value.now)
    && (value.now as number) >= 0;
}

function isAuthentication(value: unknown): value is Readonly<Authentication> {
  return isRecord(value)
    && hasExactMembers(value, [
      "account_key",
      "authenticated_at",
      "challenge_id",
      "connection_id",
      "expires_at",
      "request_id",
      "verdict",
    ])
    && value.verdict === "accept"
    && typeof value.account_key === "string" && HEX_32.test(value.account_key)
    && typeof value.connection_id === "string" && value.connection_id.length > 0
    && typeof value.challenge_id === "string" && value.challenge_id.length > 0
    && typeof value.request_id === "string" && value.request_id.length > 0
    && Number.isSafeInteger(value.authenticated_at)
    && (value.authenticated_at as number) >= 0
    && Number.isSafeInteger(value.expires_at)
    && (value.expires_at as number) > (value.authenticated_at as number);
}

function isConsumeResult(value: unknown): value is Readonly<{
  verdict: "accept" | "replay" | "conflict" | "effect-failed";
}> {
  return isRecord(value)
    && hasExactMembers(value, ["verdict"])
    && ["accept", "replay", "conflict", "effect-failed"].includes(value.verdict as string);
}

function callAndSnapshot(callback: (...args: unknown[]) => unknown, ...args: unknown[]): unknown {
  try {
    return snapshotClosedData(Reflect.apply(callback, undefined, args));
  } catch {
    return null;
  }
}

function snapshotClosedData(value: unknown, ancestors = new Set<object>()): unknown {
  if (
    value === null
    || typeof value === "string"
    || typeof value === "boolean"
    || typeof value === "number" && Number.isFinite(value)
  ) return value;
  if (typeof value !== "object" || utilTypes.isProxy(value) || ancestors.has(value)) {
    return undefined;
  }
  try {
    const array = Array.isArray(value);
    if (Object.getPrototypeOf(value) !== (array ? Array.prototype : Object.prototype)) {
      return undefined;
    }
    const descriptors = Object.getOwnPropertyDescriptors(value) as PropertyDescriptorMap;
    if (Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")) return undefined;
    ancestors.add(value);
    if (array) {
      const lengthDescriptor = descriptors.length;
      if (
        lengthDescriptor === undefined || !("value" in lengthDescriptor)
        || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0
      ) return undefined;
      const length = lengthDescriptor.value as number;
      if (Reflect.ownKeys(descriptors).length !== length + 1) return undefined;
      const snapshot: unknown[] = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = descriptors[String(index)];
        const member = dataDescriptorValue(descriptor);
        const captured = snapshotClosedData(member, ancestors);
        if (member === undefined || captured === undefined) return undefined;
        snapshot.push(captured);
      }
      return Object.freeze(snapshot);
    }
    const snapshot: Record<string, unknown> = {};
    for (const key of Object.keys(descriptors)) {
      const member = dataDescriptorValue(descriptors[key]);
      const captured = snapshotClosedData(member, ancestors);
      if (member === undefined || captured === undefined) return undefined;
      snapshot[key] = captured;
    }
    return Object.freeze(snapshot);
  } catch {
    return undefined;
  } finally {
    ancestors.delete(value);
  }
}

function ordinaryObjectDescriptors(value: unknown): PropertyDescriptorMap | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  try {
    if (utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
    return Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
}

function dataDescriptorValue(descriptor: PropertyDescriptor | undefined): unknown {
  return descriptor !== undefined
    && "value" in descriptor
    && descriptor.enumerable === true
    ? descriptor.value
    : undefined;
}

function hasExactDescriptorMembers(
  descriptors: PropertyDescriptorMap,
  members: readonly string[],
): boolean {
  const keys = Reflect.ownKeys(descriptors);
  return keys.length === members.length
    && keys.every((key) => typeof key === "string" && members.includes(key))
    && members.every((member) => dataDescriptorValue(descriptors[member]) !== undefined);
}

function isGroupTransition(value: unknown): value is TrustedSeedAcl["group_transition"] {
  return isRecord(value)
    && hasExactMembers(value, [
      "generation",
      "marmot_routing_event_id",
      "routing_binding_sha256",
    ])
    && Number.isSafeInteger(value.generation)
    && (value.generation as number) >= 0
    && typeof value.marmot_routing_event_id === "string"
    && HEX_32.test(value.marmot_routing_event_id)
    && typeof value.routing_binding_sha256 === "string"
    && HEX_32.test(value.routing_binding_sha256);
}

function sameTransition(
  left: TrustedSeedAcl["group_transition"],
  right: TrustedSeedAcl["group_transition"],
): boolean {
  return left.generation === right.generation
    && left.marmot_routing_event_id === right.marmot_routing_event_id
    && left.routing_binding_sha256 === right.routing_binding_sha256;
}

function deduplicateAcls(acls: TrustedSeedAcl[]): TrustedSeedAcl[] {
  return [...new Map(acls.map((acl) => [trustedSeedAclDigest(acl), acl])).values()];
}

function hasDuplicate(values: string[]): boolean {
  return new Set(values).size !== values.length;
}

function hasExactMembers(value: Record<string, unknown>, members: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === members.length && members.every((member) => Object.hasOwn(value, member));
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function denied(reason_code: string): TrustedSeedAdmissionResult {
  return { verdict: "reject", reason_code };
}
