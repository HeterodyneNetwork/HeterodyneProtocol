import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";

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

const RESOLUTIONS = new WeakMap<object, {
  envelope: AtprotoResolutionEnvelope;
  method: VerificationMethod;
}>();
const ENVELOPE_DOMAIN = "heterodyne:atproto-did-resolution:v1\0";
const HEX_32 = /^[0-9a-f]{64}$/u;
const HEX_64 = /^[0-9a-f]{128}$/u;
const ENVELOPE_KEYS = [
  "canonical_document", "canonical_https_url", "did", "document_sha256", "domain",
  "expires_at", "plc_log_hash", "plc_log_head", "resolution_method", "resolved_at",
  "resolver_policy", "resolver_version", "selected_verification_method_id",
].join("\0");

export function authenticateAtprotoDidResolution(input: {
  envelope: unknown;
  signature: string;
  trust_anchor: AtprotoResolverTrustAnchor;
  now: number;
}): { verdict: "accept"; resolution: AtprotoDidResolution } | {
  verdict: "reject";
  reason_code: "atproto-did-resolution-invalid";
} {
  const parsed = parseEnvelope(input.envelope, input.now);
  if (
    parsed === null
    || !validTrustAnchor(input.trust_anchor)
    || !HEX_64.test(input.signature)
    || !verifyResolverAttestation(parsed.envelope, input.signature, input.trust_anchor)
  ) return { verdict: "reject", reason_code: "atproto-did-resolution-invalid" };
  const resolution = Object.freeze({}) as AtprotoDidResolution;
  RESOLUTIONS.set(resolution, parsed);
  return { verdict: "accept", resolution };
}

export function verifyAtprotoDidSignature(input: {
  resolution: unknown;
  did: string;
  verification_method_id: string;
  payload: string;
  signature: string;
  now: number;
}): boolean {
  const resolved = resolutionBinding(input.resolution, input.did, input.now);
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
  resolution: unknown;
  did: string;
  now: number;
}): string | null {
  return resolutionBinding(input.resolution, input.did, input.now)?.method.id ?? null;
}

function parseEnvelope(value: unknown, now: number): {
  envelope: AtprotoResolutionEnvelope;
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
    || !Number.isSafeInteger(now)
    || (record.resolved_at as number) < 0
    || (record.expires_at as number) <= (record.resolved_at as number)
    || now < (record.resolved_at as number)
    || now >= (record.expires_at as number)
    || typeof record.resolver_policy !== "string"
    || !/^[A-Za-z0-9._:-]{1,128}$/u.test(record.resolver_policy)
    || typeof record.resolver_version !== "string"
    || !/^[A-Za-z0-9._+-]{1,64}$/u.test(record.resolver_version)
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
  try {
    document = JSON.parse(record.canonical_document);
  } catch {
    return null;
  }
  if (
    canonicalize(document) !== record.canonical_document
    || bytesToHex(sha256(utf8Bytes(record.canonical_document))) !== record.document_sha256
  ) return null;
  const method = selectedMethod(document, record.did, record.selected_verification_method_id);
  if (method === null) return null;
  return { envelope: record as AtprotoResolutionEnvelope, method };
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
  capability: unknown,
  did: string,
  now: number,
): { envelope: AtprotoResolutionEnvelope; method: VerificationMethod } | null {
  if (capability === null || typeof capability !== "object" || Array.isArray(capability)) {
    return null;
  }
  const resolved = RESOLUTIONS.get(capability);
  return resolved !== undefined
    && resolved.envelope.did === did
    && Number.isSafeInteger(now)
    && now >= resolved.envelope.resolved_at
    && now < resolved.envelope.expires_at
    ? resolved
    : null;
}

function verifyResolverAttestation(
  envelope: AtprotoResolutionEnvelope,
  signature: string,
  trustAnchor: AtprotoResolverTrustAnchor,
): boolean {
  const digest = sha256(utf8Bytes(`${ENVELOPE_DOMAIN}${serializeEnvelope(envelope)}`));
  try {
    return trustAnchor.suite === "ed25519"
      ? ed25519.verify(hexToBytes(signature), digest, hexToBytes(trustAnchor.public_key))
      : schnorr.verify(hexToBytes(signature), digest, hexToBytes(trustAnchor.public_key));
  } catch {
    return false;
  }
}

function validTrustAnchor(value: AtprotoResolverTrustAnchor): boolean {
  return value !== null
    && typeof value === "object"
    && Object.keys(value).sort().join("\0") === "public_key\0suite"
    && (value.suite === "ed25519" || value.suite === "bip340")
    && HEX_32.test(value.public_key);
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
