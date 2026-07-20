import { createPublicKey, verify as verifyNativeSignature, type JsonWebKey } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/nist";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { type NostrSignedEvent, verifyEventSignature } from "./nostr.js";
import { didKeyFromEd25519 } from "./radicle.js";
import { reasonCodeValues } from "./reason-codes.js";
import {
  validateClaimRevocationSchemaOrThrow,
  validateKeyClaimSchemaOrThrow,
} from "./schema.js";

export type KeyRef =
  | { type: "nostr-secp256k1"; value: string }
  | { type: "radicle-ed25519-nid"; value: string }
  | { type: "jwk-thumbprint"; value: string };

export type ClaimClass = "descriptive" | "authorization";
export type ClaimVisibility = "public" | "pairwise-private" | "repository-private" | "local-only";
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export type DelegationConstraints = {
  namespaces: string[];
  audiences: string[];
  resources: string[];
  remaining_depth: number;
};

export type ClaimSemanticBody = {
  claim_id: string;
  issuer: KeyRef;
  subject: KeyRef;
  claim_class: ClaimClass;
  namespace: string;
  name: string;
  value: JsonValue;
  issued_at: number;
  not_before: number;
  expires_at?: number;
  audience?: string[];
  resources?: string[];
  visibility: ClaimVisibility;
  parent_claim_id?: string;
  constraints?: DelegationConstraints;
  revokers?: KeyRef[];
  comms_version: "comms/0.5.0";
  registry_revision: 2;
};

export type KeyProof =
  | { type: "nostr-bip340"; signature: string }
  | { type: "radicle-ed25519"; public_key: string; signature: string }
  | { type: "jwk-jws"; jwk: Record<string, JsonValue>; protected: string; signature: string };

export type ClaimRevocation = {
  claim_id: string;
  revoked_at: number;
  reason_code: string;
  revoker: KeyRef;
  proof?: KeyProof;
};

export type VerifiedRevocation = ClaimRevocation & { signer: KeyRef; event_id: string };

export type SubjectProofChallenge = {
  domain: "heterodyne-claim-pop-v1";
  claim_id: string;
  nonce: string;
  audience: string;
  resource: string;
  operation: string;
  issued_at: number;
  expires_at: number;
};

export type ClaimEnvelopeContext = {
  issuer_authorized: boolean;
  registry_revision: 2;
  existing_semantic_body?: ClaimSemanticBody;
};

type RevocationProofBody = Pick<ClaimRevocation, "claim_id" | "revoked_at" | "reason_code">;

const CLAIM_KIND = 31013;
const REVOCATION_KIND = 31014;
const CLAIM_ID_PATTERN = /^[0-9a-f]{64}$/;
const LOWER_HEX_32_PATTERN = /^[0-9a-f]{64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const REGISTERED_REASON_CODES = new Set(reasonCodeValues());
const PRIVATE_JWK_MEMBERS = new Set(["d", "k", "p", "q", "dp", "dq", "qi", "oth"]);
const REMOTE_JWK_MEMBERS = new Set(["jku", "x5u"]);
const NIP01_SIGNED_EVENT_FIELDS = ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"];

export function computeClaimId(body: Omit<ClaimSemanticBody, "claim_id">): string {
  const { claim_id: _omitted, ...semantic } = body as Omit<ClaimSemanticBody, "claim_id"> & {
    claim_id?: unknown;
  };
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize(semantic))));
}

export function validateClaimId(body: ClaimSemanticBody): void {
  if (!CLAIM_ID_PATTERN.test(body.claim_id)) {
    throw new Error("claim_id must be lowercase 64-character hexadecimal");
  }
  if (body.claim_id !== computeClaimId(body)) {
    throw new Error("claim-id-mismatch: claim_id does not match the canonical semantic body");
  }
}

export function validateClaimEnvelope(
  event: NostrSignedEvent,
  context: ClaimEnvelopeContext,
): ClaimSemanticBody {
  assertNip01EventStructure(event);
  assertAddressedCommsEvent(event, CLAIM_KIND);
  const parsed = parseCanonicalContent(event.content, "claim") as unknown;
  validateKeyClaimSchemaOrThrow(parsed);
  const body = parsed as ClaimSemanticBody;
  validateKeyRef(body.issuer);
  validateKeyRef(body.subject);
  for (const revoker of body.revokers ?? []) validateKeyRef(revoker);
  if (body.issuer.type !== "nostr-secp256k1" || body.issuer.value !== event.pubkey) {
    throw new Error("claim-key-reference-invalid: outer Nostr signer must equal the typed claim issuer");
  }
  validateClaimId(body);
  assertSingleAddress(event, body.claim_id);
  assertOuterSignature(event);
  if (context.registry_revision !== 2 || body.registry_revision !== context.registry_revision) {
    throw new Error("claim-schema-invalid: registry revision does not match the supplied context");
  }
  if (!context.issuer_authorized) {
    throw new Error("claim-issuer-authority-invalid: Core did not authorize the issuer at issuance time");
  }
  if (
    context.existing_semantic_body !== undefined &&
    jcsCanonicalize(context.existing_semantic_body) !== jcsCanonicalize(body)
  ) {
    throw new Error("claim-repository-conflict: semantic body at an existing address must be identical");
  }
  return body;
}

export function revocationProofPayload(body: RevocationProofBody): string {
  return jcsCanonicalize({
    domain: "heterodyne-claim-revocation-v1",
    claim_id: body.claim_id,
    revoked_at: body.revoked_at,
    reason_code: body.reason_code,
  });
}

export function validateClaimRevocationEnvelope(event: NostrSignedEvent): VerifiedRevocation {
  assertNip01EventStructure(event);
  assertAddressedCommsEvent(event, REVOCATION_KIND);
  const parsed = parseCanonicalContent(event.content, "revocation") as unknown;
  validateClaimRevocationSchemaOrThrow(parsed);
  const revocation = parsed as ClaimRevocation;
  validateKeyRef(revocation.revoker);
  assertSingleAddress(event, revocation.claim_id);
  if (!REGISTERED_REASON_CODES.has(revocation.reason_code)) {
    throw new Error(`claim-schema-invalid: unregistered reason_code ${revocation.reason_code}`);
  }
  assertOuterSignature(event);
  verifyRevocationProof(event, revocation);
  return { ...revocation, signer: revocation.revoker, event_id: event.id };
}

export function validateKeyRef(key: KeyRef): void {
  if (key.type === "nostr-secp256k1") {
    if (!LOWER_HEX_32_PATTERN.test(key.value)) {
      throw new Error("claim-key-reference-invalid: Nostr key must be lowercase 32-byte x-only hex");
    }
    try {
      schnorr.utils.lift_x(BigInt(`0x${key.value}`));
    } catch {
      throw new Error("claim-key-reference-invalid: Nostr key is not a secp256k1 x-coordinate");
    }
    return;
  }
  if (key.type === "radicle-ed25519-nid") {
    decodeEd25519Nid(key.value);
    return;
  }
  if (key.type === "jwk-thumbprint") {
    if (!/^[A-Za-z0-9_-]{43}$/.test(key.value)) {
      throw new Error("claim-key-reference-invalid: JWK thumbprint must be a canonical SHA-256 base64url value");
    }
    const decoded = decodeCanonicalBase64url(key.value, "JWK thumbprint");
    if (decoded.length !== 32) {
      throw new Error("claim-key-reference-invalid: JWK thumbprint must decode to exactly 32 bytes");
    }
    return;
  }
  throw new Error("claim-key-reference-invalid: unsupported typed key reference");
}

export function computeJwkThumbprint(jwk: Record<string, JsonValue>): string {
  assertPublicJwk(jwk);
  const required = thumbprintMembers(jwk);
  return Buffer.from(sha256(utf8Bytes(jcsCanonicalize(required)))).toString("base64url");
}

function assertAddressedCommsEvent(event: NostrSignedEvent, expectedKind: number): void {
  if (event.kind !== expectedKind) {
    throw new Error(`claim-schema-invalid: expected kind:${expectedKind}`);
  }
}

function assertNip01EventStructure(event: NostrSignedEvent): void {
  if (event === null || Array.isArray(event) || typeof event !== "object") {
    throw new Error("claim-event-signature-invalid: NIP-01 event structure must be an object");
  }
  const fields = Reflect.ownKeys(event);
  if (
    fields.some((field) => typeof field !== "string") ||
    fields.length !== NIP01_SIGNED_EVENT_FIELDS.length ||
    [...(fields as string[])].sort().some((field, index) => field !== NIP01_SIGNED_EVENT_FIELDS[index])
  ) {
    throw new Error("claim-event-signature-invalid: NIP-01 signed event has unexpected or missing fields");
  }
  if (
    typeof event.id !== "string" ||
    typeof event.pubkey !== "string" ||
    !LOWER_HEX_32_PATTERN.test(event.id) ||
    !LOWER_HEX_32_PATTERN.test(event.pubkey)
  ) {
    throw new Error("claim-event-signature-invalid: NIP-01 id and pubkey require lowercase 64-hex encoding");
  }
  if (typeof event.sig !== "string" || !/^[0-9a-f]{128}$/.test(event.sig)) {
    throw new Error("claim-event-signature-invalid: NIP-01 sig requires lowercase 128-hex encoding");
  }
  if (!Number.isSafeInteger(event.created_at) || event.created_at < 0) {
    throw new Error("claim-event-signature-invalid: NIP-01 created_at must be a nonnegative safe integer");
  }
  if (!Number.isInteger(event.kind) || typeof event.content !== "string" || !Array.isArray(event.tags)) {
    throw new Error("claim-event-signature-invalid: NIP-01 kind, content, or tags has the wrong type");
  }
  for (const tag of event.tags) {
    if (!Array.isArray(tag) || tag.length === 0 || tag.some((member) => typeof member !== "string")) {
      throw new Error("claim-event-signature-invalid: every NIP-01 tag must be a non-empty string array");
    }
  }
}

function assertSingleAddress(event: NostrSignedEvent, expected: string): void {
  const addresses = event.tags.filter((tag) => tag[0] === "d");
  if (addresses.length !== 1 || addresses[0].length !== 2 || addresses[0][1] !== expected) {
    throw new Error("claim-schema-invalid: event requires a single exact d=claim_id address tag");
  }
}

function parseCanonicalContent(content: string, label: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content) as unknown;
  } catch {
    throw new Error(`claim-schema-invalid: ${label} content is not JSON`);
  }
  let canonical: string;
  try {
    canonical = jcsCanonicalize(parsed);
  } catch (error) {
    throw new Error(`claim-schema-invalid: ${error instanceof Error ? error.message : "invalid JCS content"}`);
  }
  if (content !== canonical) {
    throw new Error(`claim-schema-invalid: ${label} content is not canonical RFC 8785 JCS`);
  }
  return parsed;
}

function assertOuterSignature(event: NostrSignedEvent): void {
  try {
    if (!verifyEventSignature(event)) throw new Error("invalid");
  } catch {
    throw new Error("claim-event-signature-invalid: invalid canonical NIP-01 id or BIP-340 signature");
  }
}

function verifyRevocationProof(event: NostrSignedEvent, revocation: ClaimRevocation): void {
  if (revocation.revoker.type === "nostr-secp256k1") {
    if (revocation.proof !== undefined) {
      throw new Error("claim-key-reference-invalid: Nostr revocation uses only the outer event signature");
    }
    if (revocation.revoker.value !== event.pubkey) {
      throw new Error("claim-key-reference-invalid: Nostr revoker does not match the outer event signer");
    }
    return;
  }

  const payload = revocationProofPayload(revocation);
  if (revocation.revoker.type === "radicle-ed25519-nid") {
    const proof = revocation.proof;
    if (proof?.type !== "radicle-ed25519") {
      throw new Error("claim-key-reference-invalid: Radicle revoker requires a radicle-ed25519 proof");
    }
    const publicKey = parseLowerHex(proof.public_key, 32, "Ed25519 public key");
    if (didKeyFromEd25519(proof.public_key) !== revocation.revoker.value) {
      throw new Error("claim-key-reference-invalid: Ed25519 public key does not derive the named NID");
    }
    const signature = parseLowerHex(proof.signature, 64, "Ed25519 signature");
    let valid = false;
    try {
      valid = ed25519.verify(signature, utf8Bytes(payload), publicKey);
    } catch {
      valid = false;
    }
    if (!valid) throw new Error("claim-subject-proof-invalid: Ed25519 revocation proof is invalid");
    return;
  }

  const proof = revocation.proof;
  if (proof?.type !== "jwk-jws") {
    throw new Error("claim-key-reference-invalid: JWK revoker requires a jwk-jws proof");
  }
  if (computeJwkThumbprint(proof.jwk) !== revocation.revoker.value) {
    throw new Error("claim-key-reference-invalid: embedded JWK does not match the named thumbprint");
  }
  verifyDetachedJws(proof, payload);
}

function decodeEd25519Nid(value: string): Uint8Array {
  if (!value.startsWith("did:key:z")) {
    throw new Error("claim-key-reference-invalid: Radicle NID must use did:key base58btc");
  }
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(value.slice("did:key:z".length));
  } catch {
    throw new Error("claim-key-reference-invalid: Radicle NID has invalid base58btc");
  }
  if (
    decoded.length !== 34 ||
    decoded[0] !== 0xed ||
    decoded[1] !== 0x01 ||
    `did:key:z${base58.encode(decoded)}` !== value
  ) {
    throw new Error("claim-key-reference-invalid: Radicle NID is not a canonical Ed25519 did:key");
  }
  return decoded.slice(2);
}

function parseLowerHex(value: string, bytes: number, label: string): Uint8Array {
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) {
    throw new Error(`claim-key-reference-invalid: ${label} must be lowercase ${bytes}-byte hex`);
  }
  return hexToBytes(value);
}

function thumbprintMembers(jwk: Record<string, JsonValue>): Record<string, string> {
  const kty = requireJwkString(jwk, "kty");
  if (kty === "RSA") {
    const n = requireBase64urlUInt(jwk, "n");
    const e = requireBase64urlUInt(jwk, "e");
    const modulusBits = (n.bytes.length - 1) * 8 + (32 - Math.clz32(n.bytes[0]));
    if (modulusBits < 2048) {
      throw new Error("claim-key-reference-invalid: RSA modulus must be at least 2048 bits");
    }
    if ((n.bytes[n.bytes.length - 1] & 1) === 0) {
      throw new Error("claim-key-reference-invalid: RSA modulus is not a valid odd public modulus");
    }
    const exponent = bytesToBigInt(e.bytes);
    if (exponent < 3n || (exponent & 1n) === 0n) {
      throw new Error("claim-key-reference-invalid: RSA exponent is not a valid odd public exponent");
    }
    return { e: e.value, kty, n: n.value };
  }
  if (kty === "EC") {
    const crv = requireJwkString(jwk, "crv");
    if (crv !== "P-256") {
      throw new Error(`claim-key-reference-invalid: unsupported EC curve ${crv}`);
    }
    const x = requireExactBase64urlMember(jwk, "x", 32);
    const y = requireExactBase64urlMember(jwk, "y", 32);
    const encoded = new Uint8Array(65);
    encoded[0] = 0x04;
    encoded.set(x.bytes, 1);
    encoded.set(y.bytes, 33);
    try {
      p256.Point.fromBytes(encoded).assertValidity();
    } catch {
      throw new Error("claim-key-reference-invalid: P-256 coordinates do not encode a valid public point");
    }
    return {
      crv,
      kty,
      x: x.value,
      y: y.value,
    };
  }
  if (kty === "OKP") {
    const crv = requireJwkString(jwk, "crv");
    if (crv !== "Ed25519") {
      throw new Error(`claim-key-reference-invalid: unsupported OKP curve ${crv}`);
    }
    const x = requireExactBase64urlMember(jwk, "x", 32);
    try {
      const point = ed25519.Point.fromBytes(x.bytes, false);
      point.assertValidity();
      if (point.isSmallOrder() || !point.isTorsionFree()) throw new Error("invalid subgroup");
    } catch {
      throw new Error("claim-key-reference-invalid: Ed25519 x does not encode a valid prime-order public point");
    }
    return { crv, kty, x: x.value };
  }
  throw new Error(`claim-key-reference-invalid: unsupported public JWK kty ${kty}`);
}

function assertPublicJwk(jwk: Record<string, JsonValue>): void {
  if (jwk === null || Array.isArray(jwk) || typeof jwk !== "object") {
    throw new Error("claim-key-reference-invalid: JWK must be an object");
  }
  for (const member of PRIVATE_JWK_MEMBERS) {
    if (Object.prototype.hasOwnProperty.call(jwk, member)) {
      throw new Error(`claim-key-reference-invalid: embedded JWK contains private key member ${member}`);
    }
  }
  for (const member of REMOTE_JWK_MEMBERS) {
    if (Object.prototype.hasOwnProperty.call(jwk, member)) {
      throw new Error(`claim-key-reference-invalid: embedded JWK contains prohibited remote-key metadata ${member}`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(jwk, "use") && jwk.use !== "sig") {
    throw new Error("claim-key-reference-invalid: JWK use metadata must be the string sig");
  }
  if (Object.prototype.hasOwnProperty.call(jwk, "key_ops")) {
    const operations = jwk.key_ops;
    if (
      !Array.isArray(operations) ||
      operations.some((operation) => typeof operation !== "string") ||
      new Set(operations).size !== operations.length ||
      operations.length !== 1 ||
      operations[0] !== "verify"
    ) {
      throw new Error("claim-key-reference-invalid: JWK key_ops must contain exactly one unique verify operation");
    }
  }
  if (Object.prototype.hasOwnProperty.call(jwk, "alg") && typeof jwk.alg !== "string") {
    throw new Error("claim-key-reference-invalid: JWK alg metadata must be a string");
  }
}

function requireJwkString(jwk: Record<string, JsonValue>, member: string): string {
  const value = jwk[member];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`claim-key-reference-invalid: JWK ${member} must be a non-empty string`);
  }
  return value;
}

function requireExactBase64urlMember(
  jwk: Record<string, JsonValue>,
  member: string,
  bytes: number,
): { value: string; bytes: Buffer } {
  const value = requireJwkString(jwk, member);
  const decoded = decodeCanonicalBase64url(value, `JWK ${member}`);
  if (decoded.length !== bytes) {
    throw new Error(`claim-key-reference-invalid: JWK ${member} must decode to exactly ${bytes} bytes`);
  }
  return { value, bytes: decoded };
}

function requireBase64urlUInt(
  jwk: Record<string, JsonValue>,
  member: string,
): { value: string; bytes: Buffer } {
  const value = requireJwkString(jwk, member);
  const bytes = decodeCanonicalBase64url(value, `JWK ${member}`);
  if (bytes.length > 1 && bytes[0] === 0) {
    throw new Error(`claim-key-reference-invalid: JWK ${member} Base64urlUInt is not minimal (leading zero)`);
  }
  return { value, bytes };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function decodeCanonicalBase64url(value: string, label: string): Buffer {
  if (!BASE64URL_PATTERN.test(value)) {
    throw new Error(`claim-key-reference-invalid: ${label} is not unpadded base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length === 0 || decoded.toString("base64url") !== value) {
    throw new Error(`claim-key-reference-invalid: ${label} is not canonical base64url`);
  }
  return decoded;
}

function verifyDetachedJws(proof: Extract<KeyProof, { type: "jwk-jws" }>, payload: string): void {
  const protectedBytes = decodeCanonicalBase64url(proof.protected, "JWS protected header");
  const signature = decodeCanonicalBase64url(proof.signature, "JWS signature");
  let header: unknown;
  try {
    header = JSON.parse(protectedBytes.toString("utf8")) as unknown;
  } catch {
    throw new Error("claim-subject-proof-invalid: JWS protected header is not JSON");
  }
  if (
    header === null ||
    Array.isArray(header) ||
    typeof header !== "object" ||
    Object.keys(header).length !== 1 ||
    typeof (header as { alg?: unknown }).alg !== "string"
  ) {
    throw new Error("claim-subject-proof-invalid: JWS protected header must contain only alg");
  }
  if (protectedBytes.toString("utf8") !== jcsCanonicalize(header)) {
    throw new Error("claim-subject-proof-invalid: JWS protected header is ambiguous or non-canonical");
  }
  const alg = (header as { alg: string }).alg;
  const expectedAlgorithm = algorithmForJwk(proof.jwk);
  if (alg !== expectedAlgorithm) {
    throw new Error(`claim-subject-proof-invalid: unsupported or mismatched JWS alg ${alg}`);
  }
  if (typeof proof.jwk.alg === "string" && proof.jwk.alg !== alg) {
    throw new Error("claim-subject-proof-invalid: JWK alg does not match protected alg");
  }
  if (Array.isArray(proof.jwk.key_ops) && !proof.jwk.key_ops.includes("verify")) {
    throw new Error("claim-subject-proof-invalid: JWK key_ops does not permit verification");
  }
  const signingInput = utf8Bytes(
    `${proof.protected}.${Buffer.from(payload, "utf8").toString("base64url")}`,
  );
  let key;
  try {
    key = createPublicKey({ key: proof.jwk as JsonWebKey, format: "jwk" });
  } catch {
    throw new Error("claim-key-reference-invalid: embedded JWK is not a valid public key");
  }
  let valid = false;
  try {
    if (alg === "EdDSA") {
      valid = verifyNativeSignature(null, signingInput, key, signature);
    } else if (alg === "RS256") {
      valid = verifyNativeSignature("RSA-SHA256", signingInput, key, signature);
    } else {
      valid = verifyNativeSignature("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature);
    }
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("claim-subject-proof-invalid: detached JWS revocation proof is invalid");
}

function algorithmForJwk(jwk: Record<string, JsonValue>): "EdDSA" | "RS256" | "ES256" {
  assertPublicJwk(jwk);
  thumbprintMembers(jwk);
  const kty = requireJwkString(jwk, "kty");
  if (kty === "OKP" && requireJwkString(jwk, "crv") === "Ed25519") {
    return "EdDSA";
  }
  if (kty === "RSA") {
    return "RS256";
  }
  if (kty === "EC" && requireJwkString(jwk, "crv") === "P-256") {
    return "ES256";
  }
  throw new Error(`claim-subject-proof-invalid: unsupported JWS key or algorithm for ${kty}`);
}
