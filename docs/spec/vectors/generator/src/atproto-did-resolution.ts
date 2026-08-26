import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { snapshotAndVerifyNostrEvent, type NostrSignedEvent } from "./nostr.js";

export type AtprotoResolutionEnvelope = {
  domain: "heterodyne-atproto-did-resolution-v1";
  did: string;
  resolution_method: "did:web" | "did:plc";
  canonical_https_url: string | null;
  plc_log_head: string | null;
  plc_log_hash: string | null;
  canonical_document: string;
  document_sha256: string;
  selected_verification_method_id: string;
  resolved_at: number;
  expires_at: number;
  resolver_policy: string;
  resolver_version: string;
};

export type AtprotoResolverTrustAnchor = {
  suite: "ed25519" | "bip340";
  public_key: string;
};

export type AtprotoResolutionEvidence = {
  envelope: AtprotoResolutionEnvelope;
  signature: string;
};

export type AtprotoBindingObservationEnvelope = {
  domain: "heterodyne-atproto-binding-observation-v2";
  binding_event_id: string;
  binding_hash: string;
  did_signature_digest: string;
  did: string;
  pubkey: string;
  generation: number;
  observed_at: number;
  checkpoint_reference: string;
  resolution_envelope_hash: string;
  resolver_policy: string;
  resolver_version: string;
};

export type AtprotoBindingObservationEvidence = {
  envelope: AtprotoBindingObservationEnvelope;
  signature: string;
};

declare const atprotoResolverAuthorityBrand: unique symbol;
export type AtprotoResolverAuthority = {
  readonly [atprotoResolverAuthorityBrand]: true;
};

declare const atprotoDidResolutionBrand: unique symbol;
export type AtprotoDidResolution = {
  readonly [atprotoDidResolutionBrand]: true;
};

type VerificationMethod = {
  id: string;
  controller: string;
  type: "Ed25519VerificationKey2020";
  publicKeyHex: string;
};

type ResolverAuthorityConfig = {
  trust_anchors: readonly AtprotoResolverTrustAnchor[];
  allowed_policies: readonly string[];
  minimum_version: readonly [number, number, number];
  max_ttl: number;
};

const RESOLVER_AUTHORITIES = new WeakMap<object, ResolverAuthorityConfig>();
const RESOLUTIONS = new WeakMap<object, {
  authority: AtprotoResolverAuthority;
  envelope: AtprotoResolutionEnvelope;
  document: unknown;
  method: VerificationMethod;
}>();
const ENVELOPE_DOMAIN = "heterodyne:atproto-did-resolution:v1\0";
const OBSERVATION_DOMAIN = "heterodyne:atproto-binding-observation:v2\0";
const HEX_32 = /^[0-9a-f]{64}$/u;
const HEX_64 = /^[0-9a-f]{128}$/u;
const ENVELOPE_KEYS = [
  "canonical_document", "canonical_https_url", "did", "document_sha256", "domain",
  "expires_at", "plc_log_hash", "plc_log_head", "resolution_method", "resolved_at",
  "resolver_policy", "resolver_version", "selected_verification_method_id",
].join("\0");
const OBSERVATION_KEYS = [
  "binding_event_id", "binding_hash", "checkpoint_reference", "did",
  "did_signature_digest", "domain", "generation", "observed_at", "pubkey",
  "resolution_envelope_hash",
  "resolver_policy", "resolver_version",
].join("\0");

export function createAtprotoResolverAuthority(input: {
  trust_anchors: AtprotoResolverTrustAnchor[];
  allowed_policies: string[];
  minimum_version: string;
  max_ttl: number;
}): AtprotoResolverAuthority {
  const version = parseSemver(input.minimum_version);
  if (
    input === null
    || typeof input !== "object"
    || Object.keys(input).sort().join("\0")
      !== "allowed_policies\0max_ttl\0minimum_version\0trust_anchors"
    || !Array.isArray(input.trust_anchors)
    || input.trust_anchors.length === 0
    || !input.trust_anchors.every(validTrustAnchor)
    || new Set(input.trust_anchors.map((anchor) =>
      `${anchor.suite}:${anchor.public_key}`)).size !== input.trust_anchors.length
    || !Array.isArray(input.allowed_policies)
    || input.allowed_policies.length === 0
    || !input.allowed_policies.every((policy) =>
      typeof policy === "string" && /^[A-Za-z0-9._:-]{1,128}$/u.test(policy))
    || new Set(input.allowed_policies).size !== input.allowed_policies.length
    || version === null
    || !Number.isSafeInteger(input.max_ttl)
    || input.max_ttl < 1
  ) throw new Error("atproto-resolver-authority-invalid");
  const authority = Object.freeze({}) as AtprotoResolverAuthority;
  RESOLVER_AUTHORITIES.set(authority, deepFreeze({
    trust_anchors: structuredClone(input.trust_anchors),
    allowed_policies: structuredClone(input.allowed_policies),
    minimum_version: version,
    max_ttl: input.max_ttl,
  }));
  return authority;
}

export function authenticateAtprotoDidResolution(input: {
  authority: AtprotoResolverAuthority;
  evidence: AtprotoResolutionEvidence;
  validation_time: number;
}): { verdict: "accept"; resolution: AtprotoDidResolution } | {
  verdict: "reject";
  reason_code: "atproto-did-resolution-invalid";
} {
  if (
    input === null
    || typeof input !== "object"
    || Object.keys(input).sort().join("\0") !== "authority\0evidence\0validation_time"
    || input.authority === null
    || typeof input.authority !== "object"
  ) return { verdict: "reject", reason_code: "atproto-did-resolution-invalid" };
  const config = RESOLVER_AUTHORITIES.get(input.authority);
  const evidence = snapshotResolverData(input.evidence) as AtprotoResolutionEvidence | null;
  const parsed = config === undefined || !validResolutionEvidence(evidence)
    ? null
    : parseEnvelope(evidence.envelope, input.validation_time, config);
  if (
    parsed === null
    || evidence === null
    || !verifyResolverAttestation(parsed.envelope, evidence.signature, config as ResolverAuthorityConfig)
  ) return { verdict: "reject", reason_code: "atproto-did-resolution-invalid" };
  const snapshot = deepFreeze(structuredClone(parsed));
  const resolution = Object.freeze({}) as AtprotoDidResolution;
  RESOLUTIONS.set(resolution, { authority: input.authority, ...snapshot });
  return { verdict: "accept", resolution };
}

export function authenticateAtprotoBindingObservation(input: {
  authority: AtprotoResolverAuthority;
  evidence: AtprotoBindingObservationEvidence;
  resolution_evidence: AtprotoResolutionEvidence;
  expected_binding: {
    binding_event_id: string;
    binding_hash: string;
    canonical_payload: string;
    did: string;
    did_signature: string;
    did_signing_key_id: string;
    pubkey: string;
    generation: number;
    event_created_at: number;
    nostr_event: NostrSignedEvent;
  };
}): { verdict: "accept" } | {
  verdict: "reject";
  reason_code: "atproto-binding-observation-invalid";
} {
  const rejected = {
    verdict: "reject" as const,
    reason_code: "atproto-binding-observation-invalid" as const,
  };
  const captured = snapshotObservationAuthenticationInput(input);
  if (captured === null) return rejected;
  const config = RESOLVER_AUTHORITIES.get(captured.authority);
  const evidence = captured.evidence;
  const resolutionEvidence = captured.resolution_evidence;
  const expected = captured.expected_binding as {
    binding_event_id: string;
    binding_hash: string;
    canonical_payload: string;
    did: string;
    did_signature: string;
    did_signing_key_id: string;
    pubkey: string;
    generation: number;
    event_created_at: number;
    nostr_event: NostrSignedEvent;
  };
  if (
    evidence === null
    || resolutionEvidence === null
    || !validObservationEvidence(evidence)
    || !validResolutionEvidence(resolutionEvidence)
  ) return rejected;
  const observation = evidence.envelope;
  if (
    typeof observation.domain !== "string"
    || typeof observation.binding_event_id !== "string"
    || typeof observation.binding_hash !== "string"
    || typeof observation.did_signature_digest !== "string"
    || typeof observation.did !== "string"
    || typeof observation.pubkey !== "string"
    || !Number.isSafeInteger(observation.generation)
    || !Number.isSafeInteger(observation.observed_at)
    || typeof observation.checkpoint_reference !== "string"
    || typeof observation.resolution_envelope_hash !== "string"
    || typeof observation.resolver_policy !== "string"
    || typeof observation.resolver_version !== "string"
    || typeof expected.binding_event_id !== "string"
    || typeof expected.binding_hash !== "string"
    || typeof expected.canonical_payload !== "string"
    || typeof expected.did !== "string"
    || typeof expected.did_signature !== "string"
    || typeof expected.did_signing_key_id !== "string"
    || typeof expected.pubkey !== "string"
    || !Number.isSafeInteger(expected.generation)
    || !Number.isSafeInteger(expected.event_created_at)
  ) return rejected;
  const observedResolution = config === undefined
    ? null
    : parseEnvelope(
      resolutionEvidence.envelope,
      observation.observed_at,
      config,
    );
  const bindingResolution = config === undefined
    ? null
    : parseEnvelope(
      resolutionEvidence.envelope,
      expected.event_created_at,
      config,
    );
  const event = snapshotAndVerifyNostrEvent(expected.nostr_event);
  if (
    config === undefined
    || observedResolution === null
    || bindingResolution === null
    || !verifyResolverAttestation(
      observedResolution.envelope,
      resolutionEvidence.signature,
      config,
    )
    || observation.domain !== "heterodyne-atproto-binding-observation-v2"
    || observation.binding_event_id !== expected.binding_event_id
    || observation.binding_hash !== expected.binding_hash
    || observation.did !== expected.did
    || observation.pubkey !== expected.pubkey
    || observation.generation !== expected.generation
    || !HEX_64.test(expected.did_signature)
    || observation.did_signature_digest !== bytesToHex(sha256(
      hexToBytes(expected.did_signature),
    ))
    || !HEX_32.test(observation.did_signature_digest)
    || !HEX_32.test(observation.binding_event_id)
    || !HEX_32.test(observation.binding_hash)
    || !isCanonicalDid(observation.did)
    || !HEX_32.test(observation.pubkey)
    || !Number.isSafeInteger(observation.generation)
    || observation.generation < 1
    || !Number.isSafeInteger(expected.event_created_at)
    || expected.event_created_at < 0
    || event === null
    || event.id !== expected.binding_event_id
    || event.pubkey !== expected.pubkey
    || event.kind !== 31009
    || event.created_at !== expected.event_created_at
    || event.content !== expected.canonical_payload
    || expected.binding_hash !== bytesToHex(sha256(utf8Bytes(expected.canonical_payload)))
    || !hasExactSingletonTag(event, ["d", expected.did])
    || !hasExactSingletonTag(event, ["heterodyne", "atproto_link"])
    || !hasExactSingletonTag(event, ["pubkey", expected.pubkey])
    || !hasExactSingletonTag(event, ["did", expected.did])
    || bindingResolution.method.id !== expected.did_signing_key_id
    || bindingResolution.method.controller !== expected.did
    || !verifyResolvedDidSignature(
      bindingResolution.method,
      expected.canonical_payload,
      expected.did_signature,
    )
    || !Number.isSafeInteger(observation.observed_at)
    || observation.observed_at < expected.event_created_at
    || !validCheckpointReference(
      observation.checkpoint_reference,
      observation.binding_event_id,
      observation.did,
    )
    || observation.resolution_envelope_hash !== bytesToHex(sha256(
      utf8Bytes(serializeEnvelope(observedResolution.envelope)),
    ))
    || observation.resolver_policy !== observedResolution.envelope.resolver_policy
    || observation.resolver_version !== observedResolution.envelope.resolver_version
    || !verifyResolverObservation(observation, evidence.signature, config)
  ) return rejected;
  return { verdict: "accept" };
}

export function verifyAtprotoDidSignature(input: {
  authority: AtprotoResolverAuthority;
  resolution: unknown;
  did: string;
  verification_method_id: string;
  payload: string;
  signature: string;
  validation_time: number;
}): boolean {
  const resolved = resolutionBinding(
    input.authority,
    input.resolution,
    input.did,
    input.validation_time,
  );
  if (
    resolved === null
    || resolved.method.id !== input.verification_method_id
    || !HEX_64.test(input.signature)
  ) return false;
  try {
    return ed25519.verify(
      hexToBytes(input.signature),
      sha256(utf8Bytes(input.payload)),
      hexToBytes(resolved.method.publicKeyHex),
    );
  } catch {
    return false;
  }
}

export function currentAtprotoDidMethod(input: {
  authority: AtprotoResolverAuthority;
  resolution: unknown;
  did: string;
  validation_time: number;
}): string | null {
  return resolutionBinding(
    input.authority,
    input.resolution,
    input.did,
    input.validation_time,
  )?.method.id ?? null;
}

function parseEnvelope(
  value: unknown,
  validationTime: number,
  config: ResolverAuthorityConfig,
): {
  envelope: AtprotoResolutionEnvelope;
  document: unknown;
  method: VerificationMethod;
} | null {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).sort().join("\0") !== ENVELOPE_KEYS
  ) return null;
  const record = value as Record<string, unknown>;
  if (
    record.domain !== "heterodyne-atproto-did-resolution-v1"
    || typeof record.did !== "string"
    || !isCanonicalDid(record.did)
    || record.resolution_method !== "did:web" && record.resolution_method !== "did:plc"
    || record.resolution_method === "did:web" && !record.did.startsWith("did:web:")
    || record.resolution_method === "did:plc" && !record.did.startsWith("did:plc:")
    || typeof record.canonical_document !== "string"
    || typeof record.document_sha256 !== "string"
    || !HEX_32.test(record.document_sha256)
    || typeof record.selected_verification_method_id !== "string"
    || !record.selected_verification_method_id.startsWith(`${record.did}#`)
    || !Number.isSafeInteger(record.resolved_at)
    || !Number.isSafeInteger(record.expires_at)
    || !Number.isSafeInteger(validationTime)
    || (record.resolved_at as number) < 0
    || (record.expires_at as number) <= (record.resolved_at as number)
    || validationTime < (record.resolved_at as number)
    || validationTime >= (record.expires_at as number)
    || typeof record.resolver_policy !== "string"
    || !/^[A-Za-z0-9._:-]{1,128}$/u.test(record.resolver_policy)
    || typeof record.resolver_version !== "string"
    || !config.allowed_policies.includes(record.resolver_policy)
    || compareSemver(record.resolver_version, config.minimum_version) < 0
    || (record.expires_at as number) - (record.resolved_at as number) > config.max_ttl
  ) return null;
  if (record.resolution_method === "did:web") {
    if (
      typeof record.canonical_https_url !== "string"
      || record.canonical_https_url !== didWebUrl(record.did)
      || record.plc_log_head !== null
      || record.plc_log_hash !== null
    ) return null;
  } else if (
    record.canonical_https_url !== null
    || typeof record.plc_log_head !== "string"
    || !/^[A-Za-z0-9]{16,200}$/u.test(record.plc_log_head)
    || typeof record.plc_log_hash !== "string"
    || !HEX_32.test(record.plc_log_hash)
  ) return null;
  let document: unknown;
  let canonicalDocument: string;
  try {
    document = JSON.parse(record.canonical_document);
    canonicalDocument = canonicalize(document);
  } catch {
    return null;
  }
  if (
    canonicalDocument !== record.canonical_document
    || bytesToHex(sha256(utf8Bytes(record.canonical_document))) !== record.document_sha256
  ) return null;
  const method = selectedMethod(document, record.did, record.selected_verification_method_id);
  if (method === null) return null;
  return { envelope: record as AtprotoResolutionEnvelope, document, method };
}

function selectedMethod(
  document: unknown,
  did: string,
  methodId: string,
): VerificationMethod | null {
  if (document === null || typeof document !== "object" || Array.isArray(document)) return null;
  const record = document as Record<string, unknown>;
  if (record.id !== did || !Array.isArray(record.verificationMethod)) return null;
  const matches = record.verificationMethod.filter((value): value is VerificationMethod => {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const method = value as Record<string, unknown>;
    return method.id === methodId
      && method.controller === did
      && method.type === "Ed25519VerificationKey2020"
      && typeof method.publicKeyHex === "string"
      && HEX_32.test(method.publicKeyHex);
  });
  return matches.length === 1 ? matches[0] : null;
}

function resolutionBinding(
  authority: AtprotoResolverAuthority,
  capability: unknown,
  did: string,
  validationTime: number,
): {
  authority: AtprotoResolverAuthority;
  envelope: AtprotoResolutionEnvelope;
  document: unknown;
  method: VerificationMethod;
} | null {
  if (capability === null || typeof capability !== "object" || Array.isArray(capability)) {
    return null;
  }
  const resolved = RESOLUTIONS.get(capability);
  return resolved !== undefined
    && resolved.authority === authority
    && RESOLVER_AUTHORITIES.has(authority)
    && resolved.envelope.did === did
    && Number.isSafeInteger(validationTime)
    && validationTime >= resolved.envelope.resolved_at
    && validationTime < resolved.envelope.expires_at
    ? resolved
    : null;
}

function verifyResolverAttestation(
  envelope: AtprotoResolutionEnvelope,
  signature: string,
  config: ResolverAuthorityConfig,
): boolean {
  const digest = sha256(utf8Bytes(`${ENVELOPE_DOMAIN}${serializeEnvelope(envelope)}`));
  for (const trustAnchor of config.trust_anchors) {
    try {
      const valid = trustAnchor.suite === "ed25519"
        ? ed25519.verify(hexToBytes(signature), digest, hexToBytes(trustAnchor.public_key))
        : schnorr.verify(hexToBytes(signature), digest, hexToBytes(trustAnchor.public_key));
      if (valid) return true;
    } catch {
      // Try the next locally configured anchor.
    }
  }
  return false;
}

function verifyResolverObservation(
  envelope: AtprotoBindingObservationEnvelope,
  signature: string,
  config: ResolverAuthorityConfig,
): boolean {
  const digest = sha256(utf8Bytes(
    `${OBSERVATION_DOMAIN}${serializeObservationEnvelope(envelope)}`,
  ));
  for (const trustAnchor of config.trust_anchors) {
    try {
      const valid = trustAnchor.suite === "ed25519"
        ? ed25519.verify(hexToBytes(signature), digest, hexToBytes(trustAnchor.public_key))
        : schnorr.verify(hexToBytes(signature), digest, hexToBytes(trustAnchor.public_key));
      if (valid) return true;
    } catch {
      // Try the next locally configured anchor.
    }
  }
  return false;
}

function validTrustAnchor(value: AtprotoResolverTrustAnchor): boolean {
  return value !== null
    && typeof value === "object"
    && Object.keys(value).sort().join("\0") === "public_key\0suite"
    && (value.suite === "ed25519" || value.suite === "bip340")
    && HEX_32.test(value.public_key);
}

function validResolutionEvidence(value: unknown): value is AtprotoResolutionEvidence {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).sort().join("\0") === "envelope\0signature"
    && typeof (value as Record<string, unknown>).signature === "string"
    && HEX_64.test((value as Record<string, unknown>).signature as string);
}

function validObservationEvidence(
  value: unknown,
): value is AtprotoBindingObservationEvidence {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).sort().join("\0") !== "envelope\0signature"
  ) return false;
  const record = value as Record<string, unknown>;
  return typeof record.signature === "string"
    && HEX_64.test(record.signature)
    && record.envelope !== null
    && typeof record.envelope === "object"
    && !Array.isArray(record.envelope)
    && Object.keys(record.envelope).sort().join("\0") === OBSERVATION_KEYS;
}

function parseSemver(value: unknown): [number, number, number] | null {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.test(value)) {
    return null;
  }
  const members = value.split(".").map(Number);
  return members.every(Number.isSafeInteger)
    ? members as [number, number, number]
    : null;
}

function compareSemver(value: unknown, minimum: readonly [number, number, number]): number {
  const parsed = parseSemver(value);
  if (parsed === null) return -1;
  for (let index = 0; index < 3; index += 1) {
    if (parsed[index] !== minimum[index]) return parsed[index] - minimum[index];
  }
  return 0;
}

const INVALID_RESOLVER_SNAPSHOT = Symbol("invalid-resolver-snapshot");

function snapshotResolverData<T>(value: T): T | null {
  const snapshot = snapshotResolverNode(value, new WeakSet());
  return snapshot === INVALID_RESOLVER_SNAPSHOT
    ? null
    : deepFreeze(snapshot) as T;
}

function snapshotResolverNode(
  value: unknown,
  seen: WeakSet<object>,
): unknown | typeof INVALID_RESOLVER_SNAPSHOT {
  if (
    value === null
    || typeof value === "string"
    || typeof value === "number"
    || typeof value === "boolean"
  ) return value;
  if (typeof value !== "object" || seen.has(value)) return INVALID_RESOLVER_SNAPSHOT;
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Object.getPrototypeOf(value) as object | null;
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return INVALID_RESOLVER_SNAPSHOT;
  }
  const array = Array.isArray(value);
  if (
    prototype !== (array ? Array.prototype : Object.prototype)
    || Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
  ) return INVALID_RESOLVER_SNAPSHOT;
  seen.add(value);
  try {
    if (array) {
      const lengthDescriptor = descriptors.length;
      if (
        lengthDescriptor === undefined
        || !("value" in lengthDescriptor)
        || !Number.isSafeInteger(lengthDescriptor.value)
        || lengthDescriptor.value < 0
      ) return INVALID_RESOLVER_SNAPSHOT;
      const length = lengthDescriptor.value as number;
      const keys = Object.keys(descriptors).filter((key) => key !== "length");
      if (keys.length !== length || keys.some((key, index) => key !== String(index))) {
        return INVALID_RESOLVER_SNAPSHOT;
      }
      const snapshot: unknown[] = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (
          descriptor === undefined
          || !("value" in descriptor)
          || descriptor.enumerable !== true
        ) {
          return INVALID_RESOLVER_SNAPSHOT;
        }
        const member = snapshotResolverNode(descriptor.value, seen);
        if (member === INVALID_RESOLVER_SNAPSHOT) return INVALID_RESOLVER_SNAPSHOT;
        snapshot.push(member);
      }
      return snapshot;
    }
    const snapshot: Record<string, unknown> = {};
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key];
      if (
        descriptor === undefined
        || !("value" in descriptor)
        || descriptor.enumerable !== true
      ) {
        return INVALID_RESOLVER_SNAPSHOT;
      }
      const member = snapshotResolverNode(descriptor.value, seen);
      if (member === INVALID_RESOLVER_SNAPSHOT) return INVALID_RESOLVER_SNAPSHOT;
      Object.defineProperty(snapshot, key, {
        value: member,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return snapshot;
  } finally {
    seen.delete(value);
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function serializeEnvelope(value: AtprotoResolutionEnvelope): string {
  return JSON.stringify({
    domain: value.domain,
    did: value.did,
    resolution_method: value.resolution_method,
    canonical_https_url: value.canonical_https_url,
    plc_log_head: value.plc_log_head,
    plc_log_hash: value.plc_log_hash,
    canonical_document: value.canonical_document,
    document_sha256: value.document_sha256,
    selected_verification_method_id: value.selected_verification_method_id,
    resolved_at: value.resolved_at,
    expires_at: value.expires_at,
    resolver_policy: value.resolver_policy,
    resolver_version: value.resolver_version,
  });
}

function serializeObservationEnvelope(
  value: AtprotoBindingObservationEnvelope,
): string {
  return JSON.stringify({
    domain: value.domain,
    binding_event_id: value.binding_event_id,
    binding_hash: value.binding_hash,
    did_signature_digest: value.did_signature_digest,
    did: value.did,
    pubkey: value.pubkey,
    generation: value.generation,
    observed_at: value.observed_at,
    checkpoint_reference: value.checkpoint_reference,
    resolution_envelope_hash: value.resolution_envelope_hash,
    resolver_policy: value.resolver_policy,
    resolver_version: value.resolver_version,
  });
}

function snapshotObservationAuthenticationInput(value: unknown): {
  authority: AtprotoResolverAuthority;
  evidence: AtprotoBindingObservationEvidence;
  resolution_evidence: AtprotoResolutionEvidence;
  expected_binding: Readonly<Record<string, unknown>>;
} | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Object.getPrototypeOf(value) as object | null;
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  if (
    prototype !== Object.prototype
    || Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
    || Object.keys(descriptors).sort().join("\0")
      !== "authority\0evidence\0expected_binding\0resolution_evidence"
    || Object.values(descriptors).some((descriptor) =>
      !("value" in descriptor) || descriptor.enumerable !== true)
  ) return null;
  const authority = (descriptors.authority as PropertyDescriptor & { value: unknown }).value;
  if (authority === null || typeof authority !== "object" || Array.isArray(authority)) {
    return null;
  }
  const evidence = snapshotResolverData(
    (descriptors.evidence as PropertyDescriptor & { value: unknown }).value,
  );
  const resolutionEvidence = snapshotResolverData(
    (descriptors.resolution_evidence as PropertyDescriptor & { value: unknown }).value,
  );
  const expected = snapshotResolverData(
    (descriptors.expected_binding as PropertyDescriptor & { value: unknown }).value,
  );
  if (
    evidence === null
    || resolutionEvidence === null
    || expected === null
    || typeof expected !== "object"
    || Array.isArray(expected)
    || Object.keys(expected).sort().join("\0") !== [
      "binding_event_id", "binding_hash", "canonical_payload", "did", "did_signature",
      "did_signing_key_id", "event_created_at", "generation", "nostr_event", "pubkey",
    ].join("\0")
  ) return null;
  return Object.freeze({
    authority: authority as AtprotoResolverAuthority,
    evidence: evidence as AtprotoBindingObservationEvidence,
    resolution_evidence: resolutionEvidence as AtprotoResolutionEvidence,
    expected_binding: expected as Readonly<Record<string, unknown>>,
  });
}

function verifyResolvedDidSignature(
  method: VerificationMethod,
  payload: string,
  signature: string,
): boolean {
  if (!HEX_64.test(signature)) return false;
  try {
    return ed25519.verify(
      hexToBytes(signature),
      sha256(utf8Bytes(payload)),
      hexToBytes(method.publicKeyHex),
    );
  } catch {
    return false;
  }
}

function hasExactSingletonTag(event: NostrSignedEvent, expected: string[]): boolean {
  const matches = event.tags.filter((tag) => tag[0] === expected[0]);
  return matches.length === 1
    && matches[0].length === expected.length
    && matches[0].every((member, index) => member === expected[index]);
}

function validCheckpointReference(value: unknown, eventId: string, did: string): boolean {
  if (typeof value !== "string") return false;
  if (value === `nostr:event:${eventId}`) return true;
  const match = /^atproto:repo:(did:(?:web|plc):[^\s]+):([0-9a-f]{64})$/u.exec(value);
  return match !== null && match[1] === did && isCanonicalDid(match[1]);
}

function didWebUrl(did: string): string | null {
  if (!did.startsWith("did:web:")) return null;
  const [host, ...path] = did.slice("did:web:".length).split(":");
  return path.length === 0
    ? `https://${host}/.well-known/did.json`
    : `https://${host}/${path.join("/")}/did.json`;
}

function isCanonicalDid(value: string): boolean {
  if (/^did:plc:[a-z2-7]{24}$/u.test(value)) return true;
  if (!value.startsWith("did:web:")) return false;
  const [host, ...path] = value.slice("did:web:".length).split(":");
  return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(host)
    && !host.includes("..")
    && path.every((segment) => /^[A-Za-z0-9._~-]+$/u.test(segment));
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite JSON number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
  }
  throw new Error("non-JSON DID document");
}
