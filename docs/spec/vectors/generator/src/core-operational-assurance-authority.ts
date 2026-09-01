import { types as utilTypes } from "node:util";
import { sha256 } from "@noble/hashes/sha2";
import { captureExactDataObject } from "./closed-data.js";
import { bytesToHex } from "./hex.js";
import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";

declare const coreOperationalAssuranceAuthorityBrand: unique symbol;

export type AuthorityDecision<Reason extends string, View> = Readonly<
  | { verdict: "accept"; view: View }
  | { verdict: "reject"; reason_code: Reason }
>;

export type CoreOperationalAssuranceAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  capture_transport: () => Readonly<{
    role: "public-reader" | "authenticated-light" | "full-node";
    strict_profile: boolean;
    route: "tor" | "clearnet";
  }>;
}>;

export type CoreOperationalAssuranceAuthority = Readonly<{
  readonly [coreOperationalAssuranceAuthorityBrand]: true;
}>;

export type VerifiedCoreOperationalView = Readonly<Record<never, never>>;

type TransportSnapshot = ReturnType<
  CoreOperationalAssuranceAuthorityConfig["capture_transport"]
>;

type CapturedAuthority = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  transport: TransportSnapshot;
}>;

type ViewRecord = Readonly<{
  authority: CoreOperationalAssuranceAuthority;
  authority_id: string;
  observed_at: number;
  purpose: "cache-candidate" | "relay-profile-carrier" | "strict-transport";
  event: VerifiedNostrEvent | null;
  retained_bytes_digest: string | null;
  transport: TransportSnapshot | null;
}>;

const AUTHORITIES = new WeakMap<object, CapturedAuthority>();
const VIEWS = new WeakMap<object, ViewRecord>();
const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const HEX_32 = /^[0-9a-f]{64}$/u;
const MAX_EVENT_CONTENT_BYTES = 65_536;
const MAX_EVENT_TAGS = 256;
const MAX_TAG_WIDTH = 8;
const MAX_TAG_MEMBER_BYTES = 1_024;
const MAX_RETAINED_EVENT_BYTES = 131_072;
const MAX_EVENT_BYTES = 131_072;
const EVENT_MEMBERS = [
  "content",
  "created_at",
  "id",
  "kind",
  "pubkey",
  "sig",
  "tags",
] as const;

export function createCoreOperationalAssuranceAuthority(
  config: CoreOperationalAssuranceAuthorityConfig,
): CoreOperationalAssuranceAuthority {
  try {
    const captured = captureExactDataObject(config, [[
      "authority_id",
      "trusted_now",
      "capture_transport",
    ]], "Core operational assurance authority config");
    if (
      typeof captured.authority_id !== "string"
      || captured.authority_id.length === 0
      || captured.authority_id.length > 256
      || typeof captured.trusted_now !== "function"
      || utilTypes.isProxy(captured.trusted_now)
      || typeof captured.capture_transport !== "function"
      || utilTypes.isProxy(captured.capture_transport)
    ) throw invalid();
    const transport = captureTransport(
      (captured.capture_transport as () => unknown)(),
    );
    if (transport === null) throw invalid();

    const authority = Object.freeze({}) as CoreOperationalAssuranceAuthority;
    AUTHORITIES.set(authority, Object.freeze({
      authority_id: captured.authority_id,
      trusted_now: captured.trusted_now as () => number,
      transport,
    }));
    return authority;
  } catch {
    throw invalid();
  }
}

export function verifyCacheCandidate(
  authorityValue: CoreOperationalAssuranceAuthority,
  inputValue: Readonly<{ event: NostrSignedEvent; expected_persona: string }>,
): AuthorityDecision<"unauthorized_cache_content", VerifiedCoreOperationalView> {
  const rejected = reject("unauthorized_cache_content");
  const authority = opaqueAuthority(authorityValue);
  if (authority === null) return rejected;
  try {
    const observedAt = trustedNow(authority);
    if (observedAt === null) return rejected;
    const input = captureExactDataObject(inputValue, [[
      "event",
      "expected_persona",
    ]], "Core cache candidate input");
    if (
      typeof input.expected_persona !== "string"
      || !HEX_32.test(input.expected_persona)
    ) return rejected;
    const event = snapshotBoundedEvent(input.event);
    if (event === null || event.pubkey !== input.expected_persona) return rejected;
    return accept(authorityValue, authority, observedAt, {
      purpose: "cache-candidate",
      event,
      retained_bytes_digest: null,
      transport: null,
    });
  } catch {
    return rejected;
  }
}

export function verifyRelayProfileCarrier(
  authorityValue: CoreOperationalAssuranceAuthority,
  inputValue: Readonly<{ event: NostrSignedEvent; retained_bytes: Uint8Array }>,
): AuthorityDecision<"relay_profile_mutation", VerifiedCoreOperationalView> {
  const rejected = reject("relay_profile_mutation");
  const authority = opaqueAuthority(authorityValue);
  if (authority === null) return rejected;
  try {
    const observedAt = trustedNow(authority);
    if (observedAt === null) return rejected;
    const input = captureExactDataObject(inputValue, [[
      "event",
      "retained_bytes",
    ]], "Core relay profile carrier input");
    const exposed = snapshotBoundedEvent(input.event);
    const retainedBytes = captureRetainedBytes(input.retained_bytes);
    if (exposed === null || exposed.kind !== 0 || retainedBytes === null) return rejected;
    const retainedValue: unknown = JSON.parse(UTF8_DECODER.decode(retainedBytes));
    const retained = snapshotBoundedEvent(retainedValue);
    if (
      retained === null
      || retained.kind !== 0
      || !sameEvent(exposed, retained)
    ) return rejected;
    return accept(authorityValue, authority, observedAt, {
      purpose: "relay-profile-carrier",
      event: exposed,
      retained_bytes_digest: bytesToHex(sha256(retainedBytes)),
      transport: null,
    });
  } catch {
    return rejected;
  }
}

export function verifyStrictTransport(
  authorityValue: CoreOperationalAssuranceAuthority,
): AuthorityDecision<"strict_mode_tor_disabled", VerifiedCoreOperationalView> {
  const rejected = reject("strict_mode_tor_disabled");
  const authority = opaqueAuthority(authorityValue);
  if (authority === null) return rejected;
  const observedAt = trustedNow(authority);
  if (
    observedAt === null
    || authority.transport.strict_profile && authority.transport.route !== "tor"
  ) return rejected;
  return accept(authorityValue, authority, observedAt, {
    purpose: "strict-transport",
    event: null,
    retained_bytes_digest: null,
    transport: authority.transport,
  });
}

function accept<Reason extends string>(
  authorityValue: CoreOperationalAssuranceAuthority,
  authority: CapturedAuthority,
  observedAt: number,
  evidence: Pick<
    ViewRecord,
    "purpose" | "event" | "retained_bytes_digest" | "transport"
  >,
): AuthorityDecision<Reason, VerifiedCoreOperationalView> {
  const view = Object.freeze({}) as VerifiedCoreOperationalView;
  VIEWS.set(view, Object.freeze({
    authority: authorityValue,
    authority_id: authority.authority_id,
    observed_at: observedAt,
    ...evidence,
  }));
  return Object.freeze({ verdict: "accept", view });
}

function reject<Reason extends string>(
  reasonCode: Reason,
): AuthorityDecision<Reason, never> {
  return Object.freeze({ verdict: "reject", reason_code: reasonCode });
}

function opaqueAuthority(value: unknown): CapturedAuthority | null {
  if (value === null || typeof value !== "object" || utilTypes.isProxy(value)) {
    return null;
  }
  return AUTHORITIES.get(value) ?? null;
}

function trustedNow(authority: CapturedAuthority): number | null {
  try {
    const value = authority.trusted_now();
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  } catch {
    return null;
  }
}

function captureTransport(value: unknown): TransportSnapshot | null {
  try {
    const captured = captureExactDataObject(value, [[
      "role",
      "strict_profile",
      "route",
    ]], "Core transport observation");
    if (
      !(
        captured.role === "public-reader"
        || captured.role === "authenticated-light"
        || captured.role === "full-node"
      )
      || typeof captured.strict_profile !== "boolean"
      || !(captured.route === "tor" || captured.route === "clearnet")
    ) return null;
    return Object.freeze({
      role: captured.role,
      strict_profile: captured.strict_profile,
      route: captured.route,
    });
  } catch {
    return null;
  }
}

function captureRetainedBytes(value: unknown): Uint8Array | null {
  if (
    !(value instanceof Uint8Array)
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Uint8Array.prototype
    || value.byteLength === 0
    || value.byteLength > MAX_RETAINED_EVENT_BYTES
  ) return null;
  return Uint8Array.from(value);
}

function snapshotBoundedEvent(value: unknown): VerifiedNostrEvent | null {
  if (!eventShapeWithinBounds(value)) return null;
  return snapshotAndVerifyNostrEvent(value);
}

function eventShapeWithinBounds(value: unknown): boolean {
  try {
    if (
      value === null
      || typeof value !== "object"
      || Array.isArray(value)
      || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Object.prototype
    ) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.some((key) => typeof key !== "string")
      || keys.length !== EVENT_MEMBERS.length
      || !EVENT_MEMBERS.every((member) => Object.hasOwn(descriptors, member))
    ) return false;
    const content = dataMember(descriptors, "content");
    const createdAt = dataMember(descriptors, "created_at");
    const id = dataMember(descriptors, "id");
    const kind = dataMember(descriptors, "kind");
    const pubkey = dataMember(descriptors, "pubkey");
    const sig = dataMember(descriptors, "sig");
    const tags = dataMember(descriptors, "tags");
    if (
      typeof content !== "string"
      || UTF8_ENCODER.encode(content).byteLength > MAX_EVENT_CONTENT_BYTES
      || !Number.isSafeInteger(createdAt)
      || !Number.isSafeInteger(kind)
      || typeof id !== "string"
      || id.length !== 64
      || typeof pubkey !== "string"
      || pubkey.length !== 64
      || typeof sig !== "string"
      || sig.length !== 128
    ) return false;
    let totalBytes = UTF8_ENCODER.encode(content).byteLength + 256;
    const tagValues = captureDenseArray(tags, MAX_EVENT_TAGS);
    if (tagValues === null) return false;
    for (const tag of tagValues) {
      const members = captureDenseArray(tag, MAX_TAG_WIDTH);
      if (
        members === null
        || members.length === 0
        || members.some((member) =>
          typeof member !== "string"
          || UTF8_ENCODER.encode(member).byteLength > MAX_TAG_MEMBER_BYTES
        )
      ) return false;
      for (const member of members as string[]) {
        totalBytes += UTF8_ENCODER.encode(member).byteLength;
        if (totalBytes > MAX_EVENT_BYTES) return false;
      }
    }
    return totalBytes <= MAX_EVENT_BYTES;
  } catch {
    return false;
  }
}

function dataMember(
  descriptors: PropertyDescriptorMap,
  member: string,
): unknown {
  const descriptor = descriptors[member];
  return descriptor !== undefined
    && descriptor.enumerable === true
    && "value" in descriptor
    ? descriptor.value
    : undefined;
}

function captureDenseArray(value: unknown, maximum: number): unknown[] | null {
  if (
    !Array.isArray(value)
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Array.prototype
  ) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = Reflect.get(
    descriptors,
    "length",
  ) as PropertyDescriptor | undefined;
  if (
    lengthDescriptor === undefined
    || !("value" in lengthDescriptor)
    || !Number.isSafeInteger(lengthDescriptor.value)
    || lengthDescriptor.value < 0
    || lengthDescriptor.value > maximum
  ) return null;
  const length = lengthDescriptor.value as number;
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some((key) => typeof key !== "string")
    || keys.length !== length + 1
  ) return null;
  const captured: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor === undefined
      || descriptor.enumerable !== true
      || !("value" in descriptor)
    ) return null;
    captured.push(descriptor.value);
  }
  return captured;
}

function sameEvent(left: VerifiedNostrEvent, right: VerifiedNostrEvent): boolean {
  return left.id === right.id
    && left.sig === right.sig
    && left.pubkey === right.pubkey
    && left.created_at === right.created_at
    && left.kind === right.kind
    && left.content === right.content
    && JSON.stringify(left.tags) === JSON.stringify(right.tags);
}

function invalid(): Error {
  return new Error("core-operational-authority-invalid");
}
