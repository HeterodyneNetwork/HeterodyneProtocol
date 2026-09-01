import { types as utilTypes } from "node:util";
import { sha256 } from "@noble/hashes/sha2";
import * as nip19 from "nostr-tools/nip19";
import { captureExactDataObject } from "./closed-data.js";
import {
  isCanonicalCoreGitRef,
  isCanonicalCoreRepositoryRid,
} from "./core-policy.js";
import type { CurrentRepositoryWriterBinding } from "./core-writer-binding.js";
import { bytesToHex, utf8Bytes } from "./hex.js";
import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";
import {
  selectCurrentReplaceableEvent,
  type ReplaceableSelectionAuthority,
} from "./replaceable-selection.js";

declare const canonicalProfileSelectionAuthorityBrand: unique symbol;

export type AuthorityDecision<Reason extends string, View> = Readonly<
  | { verdict: "accept"; view: View }
  | { verdict: "reject"; reason_code: Reason }
>;

export type CanonicalProfileSelectionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  replaceable_selection: ReplaceableSelectionAuthority;
  authenticate_repository_candidate: (
    event: NostrSignedEvent,
    rid: string,
    ref: string,
  ) => Promise<CurrentRepositoryWriterBinding | null>;
}>;

export type CanonicalProfileSelectionInput = Readonly<{
  relay_candidates: readonly NostrSignedEvent[];
  repository_candidates: readonly Readonly<{
    event: NostrSignedEvent;
    repository_rid: string;
    ref: string;
  }>[];
}>;

export type CanonicalProfileSelectionAuthority = Readonly<{
  readonly [canonicalProfileSelectionAuthorityBrand]: true;
}>;

export type CanonicalProfileView = Readonly<Record<never, never>>;

type CapturedAuthority = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  replaceable_selection: ReplaceableSelectionAuthority;
  authenticate_repository_candidate:
    CanonicalProfileSelectionAuthorityConfig["authenticate_repository_candidate"];
}>;

type RepositoryCandidate = Readonly<{
  event: VerifiedNostrEvent;
  repository_rid: string;
  ref: string;
}>;

type ViewRecord = Readonly<{
  authority: CanonicalProfileSelectionAuthority;
  authority_id: string;
  observed_at: number;
  selected: VerifiedNostrEvent;
  repository_rid: string | null;
  repository_binding: CurrentRepositoryWriterBinding | null;
  binding_digest: string;
}>;

const AUTHORITIES = new WeakMap<object, CapturedAuthority>();
const VIEWS = new WeakMap<object, ViewRecord>();
const UTF8_ENCODER = new TextEncoder();
const HEX_32 = /^[0-9a-f]{64}$/u;
const MAX_CANDIDATES_PER_CARRIER = 64;
const MAX_TOTAL_CANDIDATES = 128;
const MAX_EVENT_CONTENT_BYTES = 65_536;
const MAX_EVENT_TAGS = 256;
const MAX_TAG_WIDTH = 8;
const MAX_TAG_MEMBER_BYTES = 1_024;
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

const REJECTED = Object.freeze({
  verdict: "reject" as const,
  reason_code: "profile-repository-selection-required" as const,
});

export function createCanonicalProfileSelectionAuthority(
  config: CanonicalProfileSelectionAuthorityConfig,
): CanonicalProfileSelectionAuthority {
  try {
    const captured = captureExactDataObject(config, [[
      "authority_id",
      "trusted_now",
      "replaceable_selection",
      "authenticate_repository_candidate",
    ]], "Canonical profile selection authority config");
    if (
      typeof captured.authority_id !== "string"
      || captured.authority_id.length === 0
      || captured.authority_id.length > 256
      || typeof captured.trusted_now !== "function"
      || utilTypes.isProxy(captured.trusted_now)
      || captured.replaceable_selection === null
      || typeof captured.replaceable_selection !== "object"
      || utilTypes.isProxy(captured.replaceable_selection)
      || typeof captured.authenticate_repository_candidate !== "function"
      || utilTypes.isProxy(captured.authenticate_repository_candidate)
    ) throw invalid();

    const authority = Object.freeze({}) as CanonicalProfileSelectionAuthority;
    AUTHORITIES.set(authority, Object.freeze({
      authority_id: captured.authority_id,
      trusted_now: captured.trusted_now as () => number,
      replaceable_selection:
        captured.replaceable_selection as ReplaceableSelectionAuthority,
      authenticate_repository_candidate:
        captured.authenticate_repository_candidate as CapturedAuthority[
          "authenticate_repository_candidate"
        ],
    }));
    return authority;
  } catch {
    throw invalid();
  }
}

export async function selectCanonicalProfile(
  authorityValue: CanonicalProfileSelectionAuthority,
  inputValue: CanonicalProfileSelectionInput,
): Promise<AuthorityDecision<
  "profile-repository-selection-required",
  CanonicalProfileView
>> {
  const authority = opaqueAuthority(authorityValue);
  if (authority === null) return REJECTED;

  try {
    const observedAt = authority.trusted_now();
    if (!Number.isSafeInteger(observedAt) || observedAt < 0) return REJECTED;
    const input = captureInput(inputValue);
    if (input === null) return REJECTED;

    const relayEvents: VerifiedNostrEvent[] = [];
    for (const source of input.relay_candidates) {
      const event = snapshotBoundedEvent(source);
      if (event !== null && event.kind === 0 && profileContent(event.content) !== undefined) {
        relayEvents.push(event);
      }
    }

    const authenticated = new Map<string, Readonly<{
      candidate: RepositoryCandidate;
      binding: CurrentRepositoryWriterBinding;
    }>>();
    for (const source of input.repository_candidates) {
      const event = snapshotBoundedEvent(source.event);
      if (event === null || event.kind !== 0) continue;
      const repositoryRid = profileContent(event.content);
      if (repositoryRid === undefined) continue;
      if (repositoryRid !== null && repositoryRid !== source.repository_rid) continue;
      const binding = await authority.authenticate_repository_candidate(
        event,
        source.repository_rid,
        source.ref,
      );
      if (!opaqueWriterBinding(binding)) continue;
      authenticated.set(event.id, Object.freeze({
        candidate: Object.freeze({
          event,
          repository_rid: source.repository_rid,
          ref: source.ref,
        }),
        binding,
      }));
    }

    const union = new Map<string, VerifiedNostrEvent>();
    for (const event of relayEvents) union.set(event.id, event);
    for (const { candidate } of authenticated.values()) {
      union.set(candidate.event.id, candidate.event);
    }
    if (new Set([...union.values()].map(({ pubkey }) => pubkey)).size > 1) {
      return REJECTED;
    }

    const selected = selectCurrentReplaceableEvent(
      authority.replaceable_selection,
      [...union.values()],
    ).selected;
    if (selected === null || selected.kind !== 0) return REJECTED;
    const requiredRepositoryRid = profileContent(selected.content);
    if (requiredRepositoryRid === undefined) return REJECTED;
    const authenticatedSelection = authenticated.get(selected.id) ?? null;
    if (
      requiredRepositoryRid !== null
      && (
        authenticatedSelection === null
        || authenticatedSelection.candidate.repository_rid !== requiredRepositoryRid
      )
    ) return REJECTED;

    const view = Object.freeze({}) as CanonicalProfileView;
    const bindingDigest = bytesToHex(sha256(utf8Bytes(JSON.stringify({
      authority_id: authority.authority_id,
      observed_at: observedAt,
      event_id: selected.id,
      repository_rid: requiredRepositoryRid,
      repository_ref: authenticatedSelection?.candidate.ref ?? null,
    }))));
    VIEWS.set(view, Object.freeze({
      authority: authorityValue,
      authority_id: authority.authority_id,
      observed_at: observedAt,
      selected,
      repository_rid: requiredRepositoryRid,
      repository_binding: authenticatedSelection?.binding ?? null,
      binding_digest: bindingDigest,
    }));
    return Object.freeze({ verdict: "accept", view });
  } catch {
    return REJECTED;
  }
}

function opaqueAuthority(value: unknown): CapturedAuthority | null {
  if (value === null || typeof value !== "object" || utilTypes.isProxy(value)) {
    return null;
  }
  return AUTHORITIES.get(value) ?? null;
}

function opaqueWriterBinding(
  value: unknown,
): value is CurrentRepositoryWriterBinding {
  return value !== null
    && typeof value === "object"
    && !utilTypes.isProxy(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.isFrozen(value)
    && Reflect.ownKeys(value).length === 0;
}

function captureInput(value: unknown): Readonly<{
  relay_candidates: readonly NostrSignedEvent[];
  repository_candidates: readonly Readonly<{
    event: NostrSignedEvent;
    repository_rid: string;
    ref: string;
  }>[];
}> | null {
  try {
    const captured = captureExactDataObject(value, [[
      "relay_candidates",
      "repository_candidates",
    ]], "Canonical profile selection input");
    const relayCandidates = captureDenseArray(
      captured.relay_candidates,
      MAX_CANDIDATES_PER_CARRIER,
    );
    const repositorySources = captureDenseArray(
      captured.repository_candidates,
      MAX_CANDIDATES_PER_CARRIER,
    );
    if (
      relayCandidates === null
      || repositorySources === null
      || relayCandidates.length + repositorySources.length > MAX_TOTAL_CANDIDATES
    ) return null;

    const repositoryCandidates: Array<Readonly<{
      event: NostrSignedEvent;
      repository_rid: string;
      ref: string;
    }>> = [];
    for (const source of repositorySources) {
      const candidate = captureExactDataObject(source, [[
        "event",
        "repository_rid",
        "ref",
      ]], "Canonical profile repository candidate");
      if (
        !isCanonicalCoreRepositoryRid(candidate.repository_rid)
        || !isCanonicalCoreGitRef(candidate.ref)
      ) return null;
      repositoryCandidates.push(Object.freeze({
        event: candidate.event as NostrSignedEvent,
        repository_rid: candidate.repository_rid,
        ref: candidate.ref,
      }));
    }
    return Object.freeze({
      relay_candidates: Object.freeze(relayCandidates as NostrSignedEvent[]),
      repository_candidates: Object.freeze(repositoryCandidates),
    });
  } catch {
    return null;
  }
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

/**
 * Returns the required repository RID, null for a valid ordinary profile with
 * no valid extension, and undefined when the kind-0 content itself is invalid.
 */
function profileContent(content: string): string | null | undefined {
  try {
    const value: unknown = JSON.parse(content);
    if (
      value === null
      || typeof value !== "object"
      || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
    ) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const heterodyneDescriptor = descriptors.heterodyne;
    if (heterodyneDescriptor === undefined) return null;
    if (
      heterodyneDescriptor.enumerable !== true
      || !("value" in heterodyneDescriptor)
      || !validHeterodyneExtension(heterodyneDescriptor.value)
    ) return null;
    return (heterodyneDescriptor.value as { profile: string }).profile;
  } catch {
    return undefined;
  }
}

function validHeterodyneExtension(value: unknown): boolean {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  const allowed = new Set([
    "profile",
    "identity_chain",
    "cold_root",
    "succession_authority",
  ]);
  if (
    keys.some((key) => typeof key !== "string" || !allowed.has(key))
    || !Object.hasOwn(descriptors, "profile")
  ) return false;
  for (const key of keys as string[]) {
    const descriptor = descriptors[key];
    if (
      descriptor === undefined
      || descriptor.enumerable !== true
      || !("value" in descriptor)
    ) return false;
  }
  const profile = dataMember(descriptors, "profile");
  const identityChain = dataMember(descriptors, "identity_chain");
  const coldRoot = dataMember(descriptors, "cold_root");
  const successionAuthority = dataMember(descriptors, "succession_authority");
  return isCanonicalCoreRepositoryRid(profile)
    && (identityChain === undefined || isCanonicalNaddr(identityChain))
    && (coldRoot === undefined || typeof coldRoot === "string" && HEX_32.test(coldRoot))
    && (successionAuthority === undefined
      || typeof successionAuthority === "string" && HEX_32.test(successionAuthority));
}

function isCanonicalNaddr(value: unknown): boolean {
  if (
    typeof value !== "string"
    || !value.startsWith("naddr1")
    || value.length > 1_024
  ) return false;
  try {
    const decoded = nip19.decode(value);
    return decoded.type === "naddr" && nip19.naddrEncode(decoded.data) === value;
  } catch {
    return false;
  }
}

function invalid(): Error {
  return new Error("canonical-profile-authority-invalid");
}
