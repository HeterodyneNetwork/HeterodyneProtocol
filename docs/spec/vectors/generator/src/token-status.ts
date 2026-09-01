import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type JsonWebKey,
} from "node:crypto";
import { deflateSync, inflateSync } from "node:zlib";
import { types as utilTypes } from "node:util";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { nip19 } from "nostr-tools";
import {
  canonicalValidatedCheckpoint,
  activeIssuerWriterNidsAt,
  currentIssuerSigningKeyId,
  validateIssuanceRecordOrThrow,
  type IssuanceRecord,
  type LedgerCheckpoint,
  type LedgerMergeResult,
} from "./claim-ledger.js";
import { type AuthorizationDecision, type JsonValue, type KeyProof } from "./claims.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  createValidatedProjectedJwtContext,
  assertValidatedProjectedJwtContext,
  validatePersonaBinding,
  type JwtValidationOptions,
  type PersonaIdentityState,
  type ValidatedProjectedJwtContext,
} from "./oidc.js";
import {
  revalidateAuthorizationViewAtEffect,
  type CurrentAuthorizationView,
} from "./authorization-freshness.js";
import type {
  ControlAuthorizationObject,
  ControlAuthorizationRecord,
} from "./control-profile.js";
import { captureAuthorityInput } from "./security-authority-support.js";
import { proofBytes } from "./proof-bytes.js";
import { didKeyFromEd25519 } from "./radicle.js";
import { validateOidcContinuityManifestSchemaOrThrow } from "./schema.js";
import {
  evaluateCredentialGeneration,
  isCredentialLedgerBinding,
} from "./credential-generation.js";

export const STATUS_LIST_MEDIA_TYPE = "application/statuslist+jwt" as const;
export const MAX_STATUS_LIST_BYTES = 1_048_576;
export type TokenStatus = 0 | 1;

export type StatusListToken = {
  protected_header: { alg: "RS256"; kid: string; typ: "statuslist+jwt" };
  claims: {
    credential_ledger_persona: string;
    credential_ledger_generation: number;
    sub: string;
    iat: number;
    exp: number;
    ttl: number;
    status_list: { bits: 1; lst: string };
  };
  media_type: typeof STATUS_LIST_MEDIA_TYPE;
  compact: string;
};

export type ContinuityManifestBody = {
  profile: "heterodyne-oidc-continuity-v1";
  repository_rid: string;
  branch: "main";
  persona_npub: string;
  persona_key: string;
  issuer: string;
  sequence: number;
  predecessor_digest: string | null;
  max_checkpoint_age_seconds: number;
  authorization_view_max_age: number;
  current_jwks_sha256: string;
  current_signing_key_id: string;
  current_signing_jwk_sha256: string;
  retiring_signing_key_ids: string[];
  retiring_jwks_sha256: string[];
  status_lists: Array<{ path: string; sha256: string; issuer: string; uri: string }>;
  successor: { issuer: string; manifest_sha256: string } | null;
  authority: { writer_nid: string; issued_at: number; checkpoint: LedgerCheckpoint };
};

export type ContinuityManifest = ContinuityManifestBody & { authority_proof: KeyProof };

export type ContinuityValidationContext = {
  identity: PersonaIdentityState;
  repository_rid: string;
  canonical_branch: "main";
  writer_nid: string;
  now: number;
  ledger_state: LedgerMergeResult | null;
  succession_authority: PersonaSuccessionProof | null;
  active_persona_authority: {
    persona_key: string;
    valid_from: number;
    valid_until: number;
  } | null;
};

export type PersonaSuccessionProof = {
  authority: "active-persona";
  signer_pubkey: string;
  signature: string;
};

export type ContinuityResolution = AuthorizationDecision & {
  active_issuer?: string;
  standard_oidc_action?: "retain-exact-issuer" | "register-successor";
  heterodyne_fallback?: "radicle-canonical-main";
};

export type ValidatedContinuityChainContext = {
  manifests: ContinuityManifest[];
  current: ContinuityManifest;
};

const VALIDATED_CONTINUITY_CHAINS = new WeakMap<object, string>();

declare const CURRENT_CONTROL_GRANT_VIEW: unique symbol;

export type CurrentControlGrantView = CurrentAuthorizationView & Readonly<{
  readonly [CURRENT_CONTROL_GRANT_VIEW]: true;
}>;

export type CurrentControlGrantBinding = Readonly<{
  authority_id: string;
  authorization_id: string;
  credential_ledger_persona: string;
  grant_generation: number;
  subject: string;
  sender_key: string;
  client_id: string;
  client_class: "human-light" | "automated";
  marmot_group_id: string;
  registry_checkpoint: string;
  scopes: readonly string[];
  methods: readonly string[];
  objects: readonly ControlAuthorizationObject[];
  expires_at: number;
  status: "active";
}>;

declare const CURRENT_CONTROL_GRANT_RESOLVER: unique symbol;
declare const VERIFIED_CURRENT_CONTROL_GRANT: unique symbol;

export type CurrentControlGrantResolver = Readonly<{
  readonly [CURRENT_CONTROL_GRANT_RESOLVER]: true;
}>;

export type VerifiedCurrentControlGrant = Readonly<{
  readonly [VERIFIED_CURRENT_CONTROL_GRANT]: true;
}>;

export type CurrentControlGrantResolverConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  expected_signer: string;
  load_current_grant: (
    authorization_id: string,
  ) => Promise<ControlAuthorizationRecord | null>;
}>;

export type CurrentControlGrantViewInput = Readonly<{
  authorization_view: CurrentAuthorizationView;
  grant: VerifiedCurrentControlGrant;
  validated_jwt: ValidatedProjectedJwtContext;
  status_list: StatusListToken;
  status_jwks_bytes: Uint8Array;
  status_resolved_at: number;
  continuity: ValidatedContinuityChainContext;
}>;

export type CurrentControlGrantUseExpectation = Readonly<{
  authority_id: string;
  compact_jwt: string;
  expected_issuer: string;
  expected_audience: string;
  jwks: JsonValue;
  now: number;
  sender_key: string;
  marmot_group_id: string;
  authorization_id: string;
  grant_generation: number;
  required_scope: string;
  method: string;
  object: ControlAuthorizationObject;
}>;

type CurrentControlGrantRecord = Readonly<{
  grant: CurrentControlGrantBinding;
  grant_artifact: VerifiedCurrentControlGrant;
  validated_jwt: ValidatedProjectedJwtContext;
  status_list: StatusListToken;
  status_jwks_bytes: Uint8Array;
  status_resolved_at: number;
  continuity: ValidatedContinuityChainContext;
}>;

const CURRENT_CONTROL_GRANTS = new WeakMap<object, CurrentControlGrantRecord>();

type GrantResolverRecord = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  expected_signer: string;
  load_current_grant: CurrentControlGrantResolverConfig["load_current_grant"];
}>;

type VerifiedGrantRecord = Readonly<{
  authority: GrantResolverRecord;
  authorization: ControlAuthorizationRecord;
  fingerprint: string;
}>;

const CONTROL_GRANT_RESOLVERS = new WeakMap<object, GrantResolverRecord>();
const VERIFIED_CONTROL_GRANTS = new WeakMap<object, VerifiedGrantRecord>();

const SHA256_HEX = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** Exact Comms 0.6 profile of draft-ietf-oauth-status-list-21 section 4.1. */
export function encodeStatusList(statuses: TokenStatus[]): { bits: 1; lst: string } {
  if (!Array.isArray(statuses) || statuses.length === 0 || statuses.some((status) => status !== 0 && status !== 1)) {
    throw new Error("oidc-status-invalid: status list must contain one or more one-bit values");
  }
  const bytes = Buffer.alloc(Math.ceil(statuses.length / 8));
  statuses.forEach((status, index) => { bytes[Math.floor(index / 8)] |= status << (index % 8); });
  return { bits: 1, lst: deflateSync(bytes, { level: 9 }).toString("base64url") };
}

export function generateStatusListToken(input: {
  state: LedgerMergeResult;
  uri: string;
  private_jwk: JsonValue;
  iat: number;
  exp: number;
  ttl: number;
}): StatusListToken {
  canonicalValidatedCheckpoint(input.state);
  requireExactStatusUri(input.uri);
  requireSafeTime(input.iat, "iat");
  requireSafeTime(input.exp, "exp");
  if (input.exp <= input.iat || !Number.isFinite(input.ttl) || input.ttl <= 0) {
    throw new Error("oidc-status-invalid: exp and positive finite ttl are required");
  }
  if (input.iat < input.state.checkpoint.observed_at) {
    throw new Error("oidc-status-invalid: status iat predates its authoritative ledger checkpoint");
  }
  const confirmed = new Set(input.state.repository_confirmed_record_ids ?? []);
  const issuanceRecords = input.state.records
    .filter(({ record_type, record_id }) =>
      record_type === "issuance-reservation" && confirmed.has(record_id));
  const issuances = issuanceRecords.map(({ payload }) => payload as unknown as IssuanceRecord);
  for (const [index, issuance] of issuances.entries()) {
    validateIssuanceRecordOrThrow(issuance);
    if (issuanceRecords[index].credential_ledger_generation !== issuance.credential_ledger_generation) {
      throw new Error("credential_generation_stale");
    }
  }
  assertCollisionFreeIssuances(issuances);
  const relativeUri = new URL(input.uri).pathname.replace(/^\/oidc\/npub1[^/]+\//, "");
  const selected = issuances.filter(({ reservation }) => reservation.uri === relativeUri)
    .sort((left, right) => left.reservation.idx - right.reservation.idx);
  if (selected.length === 0 || selected.some(({ reservation }, index) => reservation.idx !== index)) {
    throw new Error("oidc-status-invalid: status URI allocations are absent or non-contiguous");
  }
  const invalidated = new Set(input.state.token_invalidations ?? []);
  const status_list = encodeStatusList(selected.map(({ jti }) => invalidated.has(jti) ? 1 : 0));
  const privateJwk = exactPrivateRsaJwk(input.private_jwk);
  const issuerEpochs = input.state.records
    .filter(({ record_type, record_id, credential_ledger_generation }) =>
      record_type === "audience-key-epoch" && confirmed.has(record_id) &&
      credential_ledger_generation === input.state.credential_ledger.credential_ledger_generation)
    .map(({ payload }) => objectValue(payload))
    .filter((payload): payload is Record<string, JsonValue> => payload !== null && payload.scope === "oidc-issuer-key")
    .sort((left, right) => Number(right.epoch) - Number(left.epoch));
  if (issuerEpochs.length === 0 || issuerEpochs[0].key_digest !== privateJwk.kid) {
    throw new Error("oidc-signing-key-unavailable: status token key is not the current validated issuer epoch");
  }
  const uriRoot = new URL(input.uri).pathname.split("/")[2];
  let uriRootHex = "";
  try { const decoded = nip19.decode(uriRoot); uriRootHex = decoded.type === "npub" ? String(decoded.data) : ""; } catch { /* fail below */ }
  if (uriRootHex === "" || input.state.records.some(({ persona }) => persona !== uriRootHex)) {
    throw new Error("oidc-issuer-mismatch: status URI is not bound to the validated ledger persona");
  }
  const protected_header = { alg: "RS256", kid: privateJwk.kid, typ: "statuslist+jwt" } as const;
  const claims = {
    ...input.state.credential_ledger,
    sub: input.uri,
    iat: input.iat,
    exp: input.exp,
    ttl: input.ttl,
    status_list,
  };
  const compact = signCompact(protected_header, claims, privateJwk);
  return { protected_header, claims, media_type: STATUS_LIST_MEDIA_TYPE, compact };
}

export function validateTokenStatus(
  referencedJwt: ValidatedProjectedJwtContext,
  statusListJwt: StatusListToken,
  jwksBytes: Uint8Array,
  now: number,
  resolvedAt: number,
  continuity: ValidatedContinuityChainContext,
): AuthorizationDecision {
  try {
    assertValidatedProjectedJwtContext(referencedJwt);
    assertValidatedContinuityChain(continuity);
    const expectedCredentialLedger = {
      credential_ledger_persona: referencedJwt.claims.credential_ledger_persona,
      credential_ledger_generation: referencedJwt.claims.credential_ledger_generation,
    };
    if (!isCredentialLedgerBinding(expectedCredentialLedger)) return denied("oidc-token-type-invalid");
    if (!Object.prototype.hasOwnProperty.call(
      statusListJwt.claims,
      "credential_ledger_generation",
    )) {
      return denied("credential_generation_missing");
    }
    if (typeof statusListJwt.claims.credential_ledger_persona !== "string" ||
        !SHA256_HEX.test(statusListJwt.claims.credential_ledger_persona) ||
        typeof statusListJwt.claims.credential_ledger_generation !== "number" ||
        !Number.isSafeInteger(statusListJwt.claims.credential_ledger_generation) ||
        statusListJwt.claims.credential_ledger_generation < 0) {
      return denied("oidc-status-invalid");
    }
    requireSafeTime(now, "validation time");
    requireFiniteTime(resolvedAt, "status resolution time");
    if (!Number.isSafeInteger(referencedJwt.claims.iat) || !Number.isSafeInteger(referencedJwt.claims.exp) ||
        Number(referencedJwt.claims.iat) > now || Number(referencedJwt.claims.exp) <= now) {
      return denied("oidc-token-type-invalid");
    }
    const reference = objectValue(objectValue(referencedJwt.claims.status)?.status_list);
    const mirror = objectValue(referencedJwt.claims["https://heterodyne.network/jwt/status-mirror"]);
    const anchor = continuity.manifests[0];
    const current = continuity.current;
    const currentStatus = current.status_lists.find(({ path }) => path === mirror?.path);
    if (reference === null || mirror === null || !Number.isSafeInteger(reference.idx) || Number(reference.idx) < 0 ||
        typeof reference.uri !== "string" || typeof mirror.sha256 !== "string" ||
        mirror.repository_rid !== anchor.repository_rid || mirror.branch !== "main" ||
        continuityManifestDigest(anchor) !== mirror.sha256 || current.repository_rid !== mirror.repository_rid ||
        current.branch !== mirror.branch || typeof mirror.path !== "string" || currentStatus === undefined ||
        currentStatus.uri !== reference.uri ||
        sha256Hex(utf8Bytes(statusListJwt.compact)) !== currentStatus.sha256) {
      return denied("oidc-status-invalid");
    }
    const jwks = validateManifestJwks(current, jwksBytes);
    const parsed = verifyStatusListCompact(statusListJwt.compact, jwks);
    if (jcsCanonicalize(parsed.header) !== jcsCanonicalize(statusListJwt.protected_header) ||
        jcsCanonicalize(parsed.claims) !== jcsCanonicalize(statusListJwt.claims) ||
        statusListJwt.media_type !== STATUS_LIST_MEDIA_TYPE) return denied("oidc-status-invalid");
    const claims = parsed.claims;
    const generation = evaluateCredentialGeneration(claims, expectedCredentialLedger);
    if (!generation.valid) return denied(generation.reason_code);
    if (claims.sub !== reference.uri || claims.sub !== currentStatus.uri ||
        !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) ||
        typeof claims.ttl !== "number" || !Number.isFinite(claims.ttl) || claims.ttl <= 0 || resolvedAt > now ||
        Number(claims.iat) < current.authority.checkpoint.observed_at || Number(claims.iat) > now ||
        Number(claims.exp) <= now || resolvedAt + claims.ttl < now) {
      return denied("oidc-status-invalid");
    }
    const list = objectValue(claims.status_list);
    if (list === null || list.bits !== 1 || typeof list.lst !== "string" || !canonicalBase64url(list.lst)) {
      return denied("oidc-status-invalid");
    }
    const compressed = Buffer.from(list.lst, "base64url");
    const bytes = inflateSync(compressed, { maxOutputLength: MAX_STATUS_LIST_BYTES });
    const idx = Number(reference.idx);
    if (idx >= bytes.length * 8) return denied("oidc-status-invalid");
    const status = (bytes[Math.floor(idx / 8)] >> (idx % 8)) & 1;
    return status === 0 ? accepted() : denied("oidc-status-invalid");
  } catch {
    return denied("oidc-status-invalid");
  }
}

const CONTROL_GRANT_INPUT_KEYS = [
  "authorization_view",
  "continuity",
  "grant",
  "status_jwks_bytes",
  "status_list",
  "status_resolved_at",
  "validated_jwt",
] as const;
const CONTROL_GRANT_RESOLVER_KEYS = [
  "authority_id", "expected_signer", "load_current_grant", "trusted_now",
] as const;
const CONTROL_AUTHORIZATION_RECORD_KEYS = [
  "approving_authority", "approving_node", "capabilities", "client_class",
  "client_key", "created_at", "expires_at", "inbound_execution", "limits",
  "methods", "objects", "persona", "predecessor", "record_id", "signature",
  "signer", "state", "token_lifetime_default_seconds", "token_lifetime_max_seconds",
] as const;
const CONTROL_AUTHORIZATION_RECORD_AGENT_KEYS = [
  ...CONTROL_AUTHORIZATION_RECORD_KEYS,
  "agent_role",
] as const;
const CONTROL_EXPECTATION_KEYS = [
  "authority_id",
  "authorization_id",
  "compact_jwt",
  "expected_audience",
  "expected_issuer",
  "grant_generation",
  "jwks",
  "marmot_group_id",
  "method",
  "now",
  "object",
  "required_scope",
  "sender_key",
] as const;
const CONTROL_OBJECT_KEYS = ["class", "id"] as const;
const CONTROL_OBJECT_CLASSES = new Set([
  "none",
  "session",
  "repository",
  "config_namespace",
  "marmot_group",
  "feed",
  "media",
  "device",
]);
const CONTROL_IDENTIFIER_MAX_BYTES = 2_048;
const CONTROL_LIST_MAX_ITEMS = 256;
const CONTROL_JWT_MAX_BYTES = 131_072;
const CONTROL_STATUS_JWKS_MAX_BYTES = 1_048_576;
const CONTROL_DATA_MAX_DEPTH = 16;
const CONTROL_DATA_MAX_NODES = 8_192;
const CONTROL_DATA_MAX_STRING_BYTES = 1_048_576;
const TYPED_ARRAY_LENGTH_GETTER = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  "length",
)?.get;
const UINT8_ARRAY_SET = Uint8Array.prototype.set;

function exactDescriptorValues(
  value: unknown,
  keys: readonly string[],
): Readonly<Record<string, unknown>> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
  const ownKeys = boundedOwnKeys(value, keys.length);
  if (ownKeys === null) return null;
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== "string")
    || !keys.every((key) => ownKeys.includes(key))) return null;
  const result: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      return null;
    }
    result[key] = descriptor.value;
  }
  return result;
}

function boundedOwnKeys(value: object, maximum: number): readonly PropertyKey[] | null {
  let enumerableCount = 0;
  for (const key in value) {
    if (Object.hasOwn(value, key) && ++enumerableCount > maximum) return null;
  }
  const keys = Reflect.ownKeys(value);
  return keys.length <= maximum ? keys : null;
}

function captureExactUint8Array(value: unknown, maximum: number): Uint8Array | null {
  if (value === null || typeof value !== "object" || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Uint8Array.prototype
    || TYPED_ARRAY_LENGTH_GETTER === undefined) return null;
  let length: number;
  try {
    length = Reflect.apply(TYPED_ARRAY_LENGTH_GETTER, value, []) as number;
  } catch {
    return null;
  }
  if (!Number.isSafeInteger(length) || length <= 0 || length > maximum) return null;
  const keys = boundedOwnKeys(value, length);
  if (keys === null || keys.length !== length
    || keys.some((key, index) => typeof key !== "string" || key !== String(index))) return null;
  const captured = new Uint8Array(length);
  try {
    Reflect.apply(UINT8_ARRAY_SET, captured, [value]);
  } catch {
    return null;
  }
  return captured;
}

function hasOnlyUnicodeScalars(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function boundedControlString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0
    && hasOnlyUnicodeScalars(value)
    && Buffer.byteLength(value, "utf8") <= CONTROL_IDENTIFIER_MAX_BYTES;
}

function boundedControlJwt(value: unknown): value is string {
  return typeof value === "string" && value.length > 0
    && hasOnlyUnicodeScalars(value)
    && Buffer.byteLength(value, "utf8") <= CONTROL_JWT_MAX_BYTES;
}

function preflightControlData(value: unknown): boolean {
  let nodes = 0;
  let stringBytes = 0;
  const active = new Set<object>();
  const visit = (current: unknown, depth: number): boolean => {
    nodes += 1;
    if (nodes > CONTROL_DATA_MAX_NODES || depth > CONTROL_DATA_MAX_DEPTH) return false;
    if (current === null || typeof current === "boolean") return true;
    if (typeof current === "number") return Number.isFinite(current);
    if (typeof current === "string") {
      if (!hasOnlyUnicodeScalars(current)) return false;
      stringBytes += Buffer.byteLength(current, "utf8");
      return stringBytes <= CONTROL_DATA_MAX_STRING_BYTES;
    }
    if (typeof current !== "object" || utilTypes.isProxy(current) || active.has(current)) return false;
    const prototype = Object.getPrototypeOf(current);
    if (prototype !== Object.prototype && prototype !== Array.prototype) return false;
    active.add(current);
    try {
      if (Array.isArray(current)) {
        const lengthDescriptor = Object.getOwnPropertyDescriptor(current, "length");
        const length = lengthDescriptor !== undefined && "value" in lengthDescriptor
          ? lengthDescriptor.value
          : undefined;
        if (!Number.isSafeInteger(length) || length < 0
          || length > Math.floor((CONTROL_DATA_MAX_NODES - nodes) / 2)) return false;
        const keys = boundedOwnKeys(current, length + 1);
        if (keys === null || keys.length !== length + 1) return false;
        nodes += length;
        for (let index = 0; index < length; index += 1) {
          const key = String(index);
          const descriptor = Object.getOwnPropertyDescriptor(current, key);
          if (descriptor === undefined || !("value" in descriptor)
            || descriptor.enumerable !== true || !hasOnlyUnicodeScalars(key)) return false;
          stringBytes += Buffer.byteLength(key, "utf8");
          if (stringBytes > CONTROL_DATA_MAX_STRING_BYTES
            || !visit(descriptor.value, depth + 1)) return false;
        }
        return true;
      }
      const maximumProperties = Math.floor((CONTROL_DATA_MAX_NODES - nodes) / 2);
      const keys = boundedOwnKeys(current, maximumProperties);
      if (keys === null || keys.some((key) => typeof key !== "string"
        || !hasOnlyUnicodeScalars(key))) return false;
      nodes += keys.length;
      for (const key of keys as string[]) {
        const descriptor = Object.getOwnPropertyDescriptor(current, key);
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true
          || !hasOnlyUnicodeScalars(key)) return false;
        stringBytes += Buffer.byteLength(key, "utf8");
        if (stringBytes > CONTROL_DATA_MAX_STRING_BYTES
          || !visit(descriptor.value, depth + 1)) return false;
      }
      return true;
    } finally {
      active.delete(current);
    }
  };
  return visit(value, 0);
}

function exactControlStringList(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.length > 0 && value.length <= CONTROL_LIST_MAX_ITEMS
    && value.every(boundedControlString) && new Set(value).size === value.length
    && jcsCanonicalize(value) === jcsCanonicalize([...value].sort());
}

function validControlObject(value: unknown): value is ControlAuthorizationObject {
  const object = exactDescriptorValues(value, CONTROL_OBJECT_KEYS);
  return object !== null && boundedControlString(object.class)
    && CONTROL_OBJECT_CLASSES.has(object.class) && boundedControlString(object.id);
}

function validControlObjects(value: unknown): value is readonly ControlAuthorizationObject[] {
  return Array.isArray(value) && value.length > 0 && value.length <= CONTROL_LIST_MAX_ITEMS
    && value.every(validControlObject)
    && new Set(value.map((object) => jcsCanonicalize(object))).size === value.length
    && jcsCanonicalize(value) === jcsCanonicalize(
      [...value].sort((left, right) => jcsCanonicalize(left).localeCompare(jcsCanonicalize(right))),
    );
}

function controlGrantClaimsMatch(
  claims: Readonly<Record<string, JsonValue>>,
  grant: CurrentControlGrantBinding,
): boolean {
  const confirmation = objectValue(claims.cnf);
  const checkpoint = objectValue(claims["https://heterodyne.network/jwt/ledger-checkpoint"]);
  return claims.authorization_id === grant.authorization_id
    && claims.credential_ledger_persona === grant.credential_ledger_persona
    && claims.credential_ledger_generation === grant.grant_generation
    && claims.grant_generation === grant.grant_generation
    && claims.sub === grant.subject
    && confirmation?.jkt === grant.sender_key
    && claims.client_id === grant.client_id
    && claims.client_class === grant.client_class
    && claims.group_id === grant.marmot_group_id
    && claims.registry_checkpoint === grant.registry_checkpoint
    && checkpoint?.commit_oid === grant.registry_checkpoint
    && claims.scope === grant.scopes.join(" ")
    && jcsCanonicalize(claims.methods) === jcsCanonicalize(grant.methods)
    && jcsCanonicalize(claims.objects) === jcsCanonicalize(grant.objects)
    && claims.exp === grant.expires_at;
}

function validateControlGrantShape(grant: CurrentControlGrantBinding): void {
  if (!boundedControlString(grant.authority_id)
    || !boundedControlString(grant.authorization_id)
    || !/^[0-9a-f]{64}$/u.test(grant.credential_ledger_persona)
    || !Number.isSafeInteger(grant.grant_generation) || grant.grant_generation < 0
    || !boundedControlString(grant.subject)
    || !boundedControlString(grant.sender_key)
    || !boundedControlString(grant.client_id)
    || (grant.client_class !== "human-light" && grant.client_class !== "automated")
    || !boundedControlString(grant.marmot_group_id)
    || !/^[0-9a-f]{64}$/u.test(grant.registry_checkpoint)
    || !exactControlStringList(grant.scopes)
    || !exactControlStringList(grant.methods)
    || !validControlObjects(grant.objects)
    || !Number.isSafeInteger(grant.expires_at) || grant.expires_at < 0
    || grant.status !== "active") {
    throw new Error("control-token-invalid");
  }
}

function exactControlLimits(value: unknown): value is Readonly<Record<string, number>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const keys = boundedOwnKeys(value, CONTROL_LIST_MAX_ITEMS);
  if (keys === null) return false;
  return keys.length > 0 && keys.length <= CONTROL_LIST_MAX_ITEMS
    && keys.every((key) => typeof key === "string" && boundedControlString(key)
      && (() => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor !== undefined && "value" in descriptor
          && descriptor.enumerable === true
          && Number.isSafeInteger(descriptor.value) && Number(descriptor.value) > 0;
      })())
    && jcsCanonicalize(keys) === jcsCanonicalize([...keys].sort());
}

function exactControlCapabilities(value: unknown): value is ControlAuthorizationRecord["capabilities"] {
  const allowed = new Set([
    "control.token.extended", "control.inbound-execution", "control.approve",
  ]);
  return Array.isArray(value) && value.length <= CONTROL_LIST_MAX_ITEMS
    && value.every((item) => typeof item === "string" && allowed.has(item))
    && new Set(value).size === value.length
    && jcsCanonicalize(value) === jcsCanonicalize([...value].sort());
}

function captureVerifiedAuthorizationRecord(
  value: unknown,
  authority: GrantResolverRecord,
  expectedAuthorizationId: string,
  now: number,
): ControlAuthorizationRecord | null {
  if (!preflightControlData(value)) return null;
  const hasAgentRole = value !== null && typeof value === "object"
    && Object.hasOwn(value, "agent_role");
  const raw = exactDescriptorValues(
    value,
    hasAgentRole ? CONTROL_AUTHORIZATION_RECORD_AGENT_KEYS : CONTROL_AUTHORIZATION_RECORD_KEYS,
  );
  if (raw === null) return null;
  let record: ControlAuthorizationRecord;
  try {
    record = captureAuthorityInput(raw) as unknown as ControlAuthorizationRecord;
  } catch {
    return null;
  }
  if (record.record_id !== expectedAuthorizationId
    || !/^[0-9a-f]{64}$/u.test(record.record_id)
    || !/^[0-9a-f]{64}$/u.test(record.persona)
    || !boundedControlString(record.client_key)
    || (record.client_class !== "human-light" && record.client_class !== "automated")
    || !/^[0-9a-f]{64}$/u.test(record.approving_node)
    || !boundedControlString(record.approving_authority)
    || !exactControlStringList(record.methods)
    || !validControlObjects(record.objects)
    || !exactControlLimits(record.limits)
    || !exactControlCapabilities(record.capabilities)
    || record.token_lifetime_default_seconds !== 300
    || !Number.isSafeInteger(record.token_lifetime_max_seconds)
    || record.token_lifetime_max_seconds < 300 || record.token_lifetime_max_seconds > 3_600
    || typeof record.inbound_execution !== "boolean"
    || (record.predecessor !== null && !/^[0-9a-f]{64}$/u.test(record.predecessor))
    || record.state !== "active"
    || !Number.isSafeInteger(record.created_at) || record.created_at < 0 || record.created_at > now
    || (record.expires_at !== null && (!Number.isSafeInteger(record.expires_at)
      || record.expires_at <= record.created_at || record.expires_at <= now))
    || record.signer !== authority.expected_signer
    || !/^[0-9a-f]{64}$/u.test(record.signer)
    || !/^[0-9a-f]{128}$/u.test(record.signature)
    || (record.agent_role !== undefined && !boundedControlString(record.agent_role))) return null;
  const { signature: _signature, ...unsigned } = record;
  try {
    if (!schnorr.verify(
      hexToBytes(record.signature),
      proofBytes("heterodyne-control-authorization-record-v1", unsigned),
      hexToBytes(record.signer),
    )) return null;
  } catch {
    return null;
  }
  return record;
}

async function loadVerifiedCurrentGrant(
  authority: GrantResolverRecord,
  authorizationId: string,
  expectedFingerprint?: string,
): Promise<ControlAuthorizationRecord | null> {
  let now: number;
  let loaded: ControlAuthorizationRecord | null;
  try {
    now = authority.trusted_now();
    if (!Number.isSafeInteger(now) || now < 0) return null;
    loaded = await authority.load_current_grant(authorizationId);
  } catch {
    return null;
  }
  const record = captureVerifiedAuthorizationRecord(loaded, authority, authorizationId, now);
  if (record === null) return null;
  const fingerprint = createHash("sha256").update(
    proofBytes("heterodyne-control-current-authorization-v1", record),
  ).digest("hex");
  return expectedFingerprint === undefined || fingerprint === expectedFingerprint ? record : null;
}

export function createCurrentControlGrantResolver(
  config: CurrentControlGrantResolverConfig,
): CurrentControlGrantResolver {
  const values = exactDescriptorValues(config, CONTROL_GRANT_RESOLVER_KEYS);
  if (values === null || !boundedControlString(values.authority_id)
    || typeof values.expected_signer !== "string"
    || !/^[0-9a-f]{64}$/u.test(values.expected_signer)
    || typeof values.trusted_now !== "function" || utilTypes.isProxy(values.trusted_now)
    || typeof values.load_current_grant !== "function" || utilTypes.isProxy(values.load_current_grant)) {
    throw new TypeError("closed current Control grant resolver configuration required");
  }
  const resolver = Object.freeze({}) as CurrentControlGrantResolver;
  CONTROL_GRANT_RESOLVERS.set(resolver, Object.freeze({
    authority_id: values.authority_id,
    trusted_now: values.trusted_now as CurrentControlGrantResolverConfig["trusted_now"],
    expected_signer: values.expected_signer,
    load_current_grant: values.load_current_grant as CurrentControlGrantResolverConfig["load_current_grant"],
  }));
  return resolver;
}

export async function resolveCurrentControlGrant(
  resolver: CurrentControlGrantResolver,
  authorization_id: string,
): Promise<Readonly<
  | { verdict: "accept"; output: VerifiedCurrentControlGrant }
  | { verdict: "reject"; reason_code: "control-token-invalid" }
>> {
  const authority = resolver !== null && typeof resolver === "object"
    ? CONTROL_GRANT_RESOLVERS.get(resolver as object)
    : undefined;
  if (authority === undefined || !boundedControlString(authorization_id)) {
    return Object.freeze({ verdict: "reject", reason_code: "control-token-invalid" });
  }
  const authorization = await loadVerifiedCurrentGrant(authority, authorization_id);
  if (authorization === null) {
    return Object.freeze({ verdict: "reject", reason_code: "control-token-invalid" });
  }
  const fingerprint = createHash("sha256").update(
    proofBytes("heterodyne-control-current-authorization-v1", authorization),
  ).digest("hex");
  const grant = Object.freeze({}) as VerifiedCurrentControlGrant;
  VERIFIED_CONTROL_GRANTS.set(grant, Object.freeze({ authority, authorization, fingerprint }));
  return Object.freeze({ verdict: "accept", output: grant });
}

async function revalidateVerifiedCurrentControlGrant(
  grant: VerifiedCurrentControlGrant,
  now: number,
): Promise<VerifiedGrantRecord | null> {
  const retained = grant !== null && typeof grant === "object"
    ? VERIFIED_CONTROL_GRANTS.get(grant as object)
    : undefined;
  if (retained === undefined) return null;
  let trusted: number;
  try {
    trusted = retained.authority.trusted_now();
  } catch {
    return null;
  }
  if (trusted !== now) return null;
  const current = await loadVerifiedCurrentGrant(
    retained.authority,
    retained.authorization.record_id,
    retained.fingerprint,
  );
  return current === null ? null : retained;
}

/**
 * Elevates one genuine freshness view into a Control-grant-specific opaque view.
 * The returned object is still the original opaque freshness handle; all added
 * grant and status material remains module-private.
 */
export function createCurrentControlGrantView(
  input: CurrentControlGrantViewInput,
): CurrentControlGrantView {
  const container = exactDescriptorValues(input, CONTROL_GRANT_INPUT_KEYS);
  if (container === null) throw new Error("control-token-invalid");
  const grantArtifact = container.grant as VerifiedCurrentControlGrant;
  const verifiedGrant = grantArtifact !== null && typeof grantArtifact === "object"
    ? VERIFIED_CONTROL_GRANTS.get(grantArtifact as object)
    : undefined;
  if (verifiedGrant === undefined) throw new Error("control-token-invalid");
  const validatedJwt = container.validated_jwt as ValidatedProjectedJwtContext;
  const continuity = container.continuity as ValidatedContinuityChainContext;
  if (!preflightControlData(validatedJwt) || !preflightControlData(container.status_list)
    || !preflightControlData(continuity)) throw new Error("control-token-invalid");
  const statusJwksBytes = captureExactUint8Array(
    container.status_jwks_bytes,
    CONTROL_STATUS_JWKS_MAX_BYTES,
  );
  const statusResolvedAt = container.status_resolved_at;
  if (statusJwksBytes === null
    || typeof statusResolvedAt !== "number" || !Number.isFinite(statusResolvedAt)
    || statusResolvedAt < 0) {
    throw new Error("control-token-invalid");
  }
  assertValidatedProjectedJwtContext(validatedJwt);
  const statusList = captureAuthorityInput(container.status_list) as unknown as StatusListToken;
  const authorizationView = container.authorization_view as CurrentAuthorizationView;
  const freshness = revalidateAuthorizationViewAtEffect(authorizationView);
  if (freshness.verdict !== "accept") throw new Error("control-token-invalid");
  const authorization = verifiedGrant.authorization;
  const claims = validatedJwt.claims;
  const confirmation = objectValue(claims.cnf);
  const checkpoint = objectValue(claims["https://heterodyne.network/jwt/ledger-checkpoint"]);
  const scopes = ["control", ...authorization.capabilities].sort();
  const grant: CurrentControlGrantBinding = Object.freeze({
    authority_id: verifiedGrant.authority.authority_id,
    authorization_id: authorization.record_id,
    credential_ledger_persona: authorization.persona,
    grant_generation: Number(claims.credential_ledger_generation),
    subject: String(claims.sub),
    sender_key: String(confirmation?.jkt),
    client_id: String(claims.client_id),
    client_class: authorization.client_class,
    marmot_group_id: String(claims.group_id),
    registry_checkpoint: String(claims.registry_checkpoint),
    scopes,
    methods: authorization.methods,
    objects: authorization.objects,
    expires_at: Number(claims.exp),
    status: "active",
  });
  validateControlGrantShape(grant);
  if (freshness.evaluated_at !== validatedJwt.validated_at
    || authorization.client_key !== grant.sender_key
    || authorization.client_class !== claims.client_class
    || authorization.created_at > Number(claims.iat)
    || (authorization.expires_at !== null && grant.expires_at > authorization.expires_at)
    || grant.expires_at - Number(claims.iat) > authorization.token_lifetime_max_seconds
    || freshness.persona_key !== grant.credential_ledger_persona
    || freshness.checkpoint.commit_oid !== grant.registry_checkpoint
    || checkpoint?.commit_oid !== grant.registry_checkpoint
    || !controlGrantClaimsMatch(validatedJwt.claims, grant)
    || grant.expires_at <= freshness.evaluated_at
    || !validateTokenStatus(
      validatedJwt,
      statusList,
      statusJwksBytes,
      freshness.evaluated_at,
      statusResolvedAt,
      continuity,
    ).allowed) {
    throw new Error("control-token-invalid");
  }
  const existing = CURRENT_CONTROL_GRANTS.get(authorizationView as object);
  if (existing !== undefined) throw new Error("control-token-invalid");
  CURRENT_CONTROL_GRANTS.set(authorizationView as object, Object.freeze({
    grant,
    grant_artifact: grantArtifact,
    validated_jwt: validatedJwt,
    status_list: statusList,
    status_jwks_bytes: statusJwksBytes,
    status_resolved_at: statusResolvedAt,
    continuity,
  }));
  return authorizationView as CurrentControlGrantView;
}

/**
 * Checks one exact token/use tuple against a private current grant/status view.
 * Success returns no structural authority; callers must mint their own opaque
 * consuming capability only after this assertion and freshness revalidation.
 */
export async function assertCurrentControlGrantUse(
  view: CurrentAuthorizationView,
  expectation: CurrentControlGrantUseExpectation,
): Promise<void> {
  const retained = view !== null && typeof view === "object"
    ? CURRENT_CONTROL_GRANTS.get(view as object)
    : undefined;
  const captured = exactDescriptorValues(expectation, CONTROL_EXPECTATION_KEYS);
  if (retained === undefined || captured === null || !preflightControlData(captured)) {
    throw new Error("control-token-invalid");
  }
  const expected = captureAuthorityInput(captured) as unknown as CurrentControlGrantUseExpectation;
  if (!boundedControlString(expected.authority_id)
    || !boundedControlJwt(expected.compact_jwt)
    || !boundedControlString(expected.expected_issuer)
    || !boundedControlString(expected.expected_audience)
    || !Number.isSafeInteger(expected.now) || expected.now < 0
    || !boundedControlString(expected.sender_key)
    || !boundedControlString(expected.marmot_group_id)
    || !boundedControlString(expected.authorization_id)
    || !Number.isSafeInteger(expected.grant_generation) || expected.grant_generation < 0
    || !boundedControlString(expected.required_scope)
    || !boundedControlString(expected.method)
    || !validControlObject(expected.object)) throw new Error("control-token-invalid");
  if (await revalidateVerifiedCurrentControlGrant(retained.grant_artifact, expected.now) === null) {
    throw new Error("control-token-invalid");
  }
  assertValidatedProjectedJwtContext(retained.validated_jwt);
  const options: JwtValidationOptions = {
    now: expected.now,
    token_use: "access_token",
    client_id: retained.grant.client_id,
    cnf: { jkt: retained.grant.sender_key },
    sender_constraint: "dpop",
    permitted_audiences: [expected.expected_audience],
    credential_ledger: {
      credential_ledger_persona: retained.grant.credential_ledger_persona,
      credential_ledger_generation: retained.grant.grant_generation,
    },
  };
  const presented = createValidatedProjectedJwtContext(
    expected.compact_jwt,
    expected.expected_issuer,
    expected.expected_audience,
    expected.jwks,
    options,
  );
  if (!validateTokenStatus(
    presented,
    retained.status_list,
    retained.status_jwks_bytes,
    expected.now,
    retained.status_resolved_at,
    retained.continuity,
  ).allowed
    || retained.validated_jwt.compact !== expected.compact_jwt
    || !controlGrantClaimsMatch(presented.claims, retained.grant)
    || retained.grant.status !== "active"
    || retained.grant.expires_at <= expected.now
    || retained.grant.authority_id !== expected.authority_id
    || retained.grant.authorization_id !== expected.authorization_id
    || retained.grant.grant_generation !== expected.grant_generation
    || retained.grant.sender_key !== expected.sender_key
    || retained.grant.marmot_group_id !== expected.marmot_group_id
    || !retained.grant.scopes.includes(expected.required_scope)
    || !retained.grant.methods.includes(expected.method)
    || !retained.grant.objects.some((object) =>
      jcsCanonicalize(object) === jcsCanonicalize(expected.object))) {
    throw new Error("control-token-invalid");
  }
}

export function createContinuityAuthorityProof(
  body: ContinuityManifestBody | Omit<ContinuityManifest, "authority_proof">,
  writerSecretKeyHex: string,
): Extract<KeyProof, { type: "radicle-ed25519" }> {
  if (!/^[0-9a-f]{64}$/.test(writerSecretKeyHex)) throw new Error("claim-subject-proof-invalid: invalid Ed25519 secret");
  const publicKey = ed25519.getPublicKey(hexToBytes(writerSecretKeyHex));
  const payload = continuityProofPayload(body);
  return { type: "radicle-ed25519", public_key: bytesToHex(publicKey),
    signature: bytesToHex(ed25519.sign(utf8Bytes(payload), hexToBytes(writerSecretKeyHex))) };
}

export function createPersonaSuccessionProof(
  candidate: ContinuityManifestBody | ContinuityManifest,
  authority: PersonaSuccessionProof["authority"],
  secretKeyHex: string,
): PersonaSuccessionProof {
  if (!/^[0-9a-f]{64}$/.test(secretKeyHex)) throw new Error("oidc-issuer-authority-invalid: invalid persona authority key");
  const publicKey = bytesToHex(schnorr.getPublicKey(hexToBytes(secretKeyHex)));
  const message = personaSuccessionPayload(publicKey, candidate);
  return { authority, signer_pubkey: publicKey,
    signature: bytesToHex(schnorr.sign(utf8Bytes(message), hexToBytes(secretKeyHex), new Uint8Array(32))) };
}

export function buildContinuityTree(
  manifest: ContinuityManifest,
  discovery: JsonValue,
  jwksBytes: Uint8Array,
  statusTokens: Map<string, Uint8Array>,
): Map<string, Uint8Array> {
  validateOidcContinuityManifestSchemaOrThrow(manifest);
  validateManifestIntrinsic(manifest);
  if (!verifyContinuityProof(manifest)) throw new Error("oidc-issuer-authority-invalid: invalid manifest proof");
  const root = `.well-known/${manifest.persona_npub}`;
  const expectedStatus = new Map(manifest.status_lists.map((entry) => [entry.path, entry.sha256]));
  if (statusTokens.size !== expectedStatus.size) throw new Error("oidc-status-invalid: status set differs from manifest");
  const publicJwks = validateManifestJwks(manifest, jwksBytes);
  for (const [path, bytes] of statusTokens) {
    if (!path.startsWith(`${root}/status-lists/`) || expectedStatus.get(path) !== sha256Hex(bytes)) {
      throw new Error("oidc-status-invalid: status bytes differ from manifest");
    }
    const compact = Buffer.from(bytes).toString("utf8");
    const parsedStatus = verifyStatusListCompact(compact, publicJwks);
    const expectedEntry = manifest.status_lists.find((entry) => entry.path === path);
    if (expectedEntry === undefined || parsedStatus.claims.sub !== expectedEntry.uri ||
        !Number.isSafeInteger(parsedStatus.claims.iat) ||
        Number(parsedStatus.claims.iat) < manifest.authority.checkpoint.observed_at) {
      throw new Error("oidc-status-invalid: status subject/path differs from manifest");
    }
  }
  const discoveryBytes = utf8Bytes(jcsCanonicalize(discovery));
  const discoveryIssuer = objectValue(discovery)?.issuer;
  if (discoveryIssuer !== manifest.issuer) throw new Error("oidc-issuer-mismatch: discovery differs from manifest");
  const tree = new Map<string, Uint8Array>([
    [`${root}/issuer.json`, utf8Bytes(jcsCanonicalize({ issuer: manifest.issuer,
      ...(manifest.successor === null ? {} : { successor: manifest.successor }) }))],
    [`${root}/openid-configuration`, discoveryBytes],
    [`${root}/jwks.json`, Uint8Array.from(jwksBytes)],
    [`${root}/manifest.json`, utf8Bytes(jcsCanonicalize(manifest))],
  ]);
  for (const [path, bytes] of statusTokens) tree.set(path, Uint8Array.from(bytes));
  return tree;
}

export function resolveIssuerContinuity(
  previous: ContinuityManifest | null,
  candidate: ContinuityManifest,
  context: ContinuityValidationContext,
): ContinuityResolution {
  try {
    validateOidcContinuityManifestSchemaOrThrow(candidate);
    validateManifestIntrinsic(candidate);
    const checkpoint = context.ledger_state === null ? null : canonicalValidatedCheckpoint(context.ledger_state);
    if (context.canonical_branch !== "main" || candidate.branch !== "main" ||
        candidate.repository_rid !== context.repository_rid || candidate.repository_rid !== context.repository_rid ||
        !validatePersonaBinding(candidate.persona_npub, context.identity).allowed ||
        candidate.persona_npub !== context.identity.persona_npub ||
        candidate.persona_key !== context.identity.persona_key ||
        candidate.authority.writer_nid !== context.writer_nid || context.ledger_state === null || checkpoint === null ||
        context.ledger_state.credential_ledger.credential_ledger_persona !== candidate.persona_key ||
        checkpoint.repository_rid !== candidate.repository_rid ||
        jcsCanonicalize(candidate.authority.checkpoint) !== jcsCanonicalize(checkpoint) ||
        currentIssuerSigningKeyId(context.ledger_state) !== candidate.current_signing_key_id ||
        [...compromisedSigningKeyIds(context.ledger_state)]
          .some((keyId) => keyId === candidate.current_signing_key_id || candidate.retiring_signing_key_ids.includes(keyId)) ||
        !activeIssuerWriterNidsAt(context.ledger_state, candidate.authority.issued_at).includes(context.writer_nid) ||
        candidate.authority.issued_at < checkpoint.observed_at || candidate.authority.issued_at > context.now ||
        !verifyContinuityProof(candidate)) {
      return deniedContinuity("oidc-issuer-authority-invalid");
    }
    retainUnexpiredMaterial(candidate, context);
    if (previous === null) {
      if (candidate.sequence !== 0 || candidate.predecessor_digest !== null) {
        return deniedContinuity("oidc-issuer-mismatch");
      }
      if (candidate.successor !== null && !verifyPersonaSuccessionProof(candidate, context)) {
        return deniedContinuity("oidc-issuer-authority-invalid");
      }
      return acceptedContinuity(candidate.issuer, "retain-exact-issuer");
    }
    validateOidcContinuityManifestSchemaOrThrow(previous);
    validateManifestIntrinsic(previous);
    if (!verifyContinuityProof(previous) || previous.repository_rid !== candidate.repository_rid ||
        (previous.issuer === candidate.issuer &&
          (previous.persona_npub !== candidate.persona_npub || previous.persona_key !== candidate.persona_key))) {
      return deniedContinuity("oidc-issuer-authority-invalid");
    }
    if (candidate.sequence !== previous.sequence + 1 ||
        candidate.predecessor_digest !== continuityManifestDigest(previous)) {
      return deniedContinuity("oidc-status-invalid");
    }
    validateRetainedStatusProvenance(previous, candidate);
    if (candidate.successor !== null && jcsCanonicalize(candidate.successor) !== jcsCanonicalize(previous.successor) &&
        !verifyPersonaSuccessionProof(candidate, context)) {
      return deniedContinuity("oidc-issuer-authority-invalid");
    }
    if (previous.successor !== null && candidate.issuer === previous.issuer) {
      return deniedContinuity("oidc-issuer-authority-invalid");
    }
    if (candidate.issuer !== previous.issuer) {
      if (previous.successor === null || previous.successor.issuer !== candidate.issuer ||
          previous.successor.manifest_sha256 !== continuitySuccessorDigest(candidate) ||
          !verifyPersonaSuccessionProof(candidate, context)) {
        return deniedContinuity("oidc-issuer-authority-invalid");
      }
      return acceptedContinuity(candidate.issuer, "register-successor");
    }
    return acceptedContinuity(candidate.issuer, "retain-exact-issuer");
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (message.includes("digest") || message.includes("retained")) return deniedContinuity("oidc-status-invalid");
    return deniedContinuity("oidc-issuer-authority-invalid");
  }
}

export function validateIssuerContinuityChain(
  entries: Array<{ manifest: ContinuityManifest; context: ContinuityValidationContext }>,
): ValidatedContinuityChainContext {
  if (entries.length === 0) throw new Error("oidc-status-invalid: continuity chain is empty");
  let previous: ContinuityManifest | null = null;
  const manifests: ContinuityManifest[] = [];
  for (const entry of entries) {
    const decision = resolveIssuerContinuity(previous, entry.manifest, entry.context);
    if (!decision.allowed) throw new Error(`${decision.reason_code}: continuity chain validation failed`);
    const manifest = structuredClone(entry.manifest);
    manifests.push(manifest);
    previous = manifest;
  }
  const result = { manifests, current: manifests[manifests.length - 1] };
  VALIDATED_CONTINUITY_CHAINS.set(result, continuityChainFingerprint(result));
  return result;
}

function assertValidatedContinuityChain(context: ValidatedContinuityChainContext): void {
  if (VALIDATED_CONTINUITY_CHAINS.get(context) !== continuityChainFingerprint(context) ||
      context.current !== context.manifests[context.manifests.length - 1]) {
    throw new Error("oidc-status-invalid: validated continuity chain is absent or mutated");
  }
}

function continuityChainFingerprint(context: ValidatedContinuityChainContext): string {
  return sha256Hex(utf8Bytes(jcsCanonicalize(context.manifests)));
}

function verifyPersonaSuccessionProof(candidate: ContinuityManifest, context: ContinuityValidationContext): boolean {
  const proof = context.succession_authority;
  const authority = context.active_persona_authority;
  const ledgerPersona = context.ledger_state?.credential_ledger
    .credential_ledger_persona;
  if (proof === null || authority === null || proof.authority !== "active-persona" ||
      !/^[0-9a-f]{64}$/.test(proof.signer_pubkey) || !/^[0-9a-f]{128}$/.test(proof.signature)) return false;
  const authorized = authority.persona_key === context.identity.persona_key &&
    authority.persona_key === ledgerPersona &&
    proof.signer_pubkey === authority.persona_key &&
    authority.valid_from <= candidate.authority.issued_at && candidate.authority.issued_at < authority.valid_until;
  return authorized && schnorr.verify(
    hexToBytes(proof.signature),
    utf8Bytes(personaSuccessionPayload(context.identity.persona_key, candidate)),
    hexToBytes(proof.signer_pubkey),
  );
}

function personaSuccessionPayload(
  currentPersonaKey: string,
  candidate: ContinuityManifestBody | ContinuityManifest,
): string {
  return `heterodyne-oidc-issuer-successor-v1\0${currentPersonaKey}\0${continuitySuccessorDigest(candidate as ContinuityManifest)}`;
}

export function continuityManifestDigest(manifest: ContinuityManifest): string {
  return sha256Hex(utf8Bytes(jcsCanonicalize(manifest)));
}

export function continuitySuccessorDigest(manifest: ContinuityManifest): string {
  const { authority_proof: _proof, predecessor_digest: _predecessor, ...commitment } = manifest;
  return sha256Hex(utf8Bytes(jcsCanonicalize(commitment)));
}

function retainUnexpiredMaterial(
  candidate: ContinuityManifest,
  context: ContinuityValidationContext,
): void {
  if (context.ledger_state === null) throw new Error("unexpired token material cannot be established");
  canonicalValidatedCheckpoint(context.ledger_state);
  const confirmed = new Set(context.ledger_state.repository_confirmed_record_ids ?? []);
  const issuances = context.ledger_state.records
    .filter(({ record_type, record_id }) => record_type === "issuance-reservation" && confirmed.has(record_id))
    .map(({ payload }) => payload as unknown as IssuanceRecord);
  for (const issuance of issuances) validateIssuanceRecordOrThrow(issuance);
  const unexpired = issuances.filter(({ expires_at }) => expires_at > context.now);
  const compromisedKeyIds = compromisedSigningKeyIds(context.ledger_state);
  const requiredKeyIds = new Set(unexpired.map(({ signing_key_id }) => signing_key_id)
    .filter((keyId) => !compromisedKeyIds.has(keyId)));
  const availableKeyIds = new Set([candidate.current_signing_key_id, ...candidate.retiring_signing_key_ids]);
  for (const keyId of requiredKeyIds) {
    if (!availableKeyIds.has(keyId)) throw new Error("prior JWKS not retained through token expiry");
  }
  for (const keyId of compromisedKeyIds) {
    if (availableKeyIds.has(keyId)) throw new Error("compromised JWKS remains trusted");
  }
  const candidatePaths = new Set(candidate.status_lists.map(({ path }) => path));
  const requiredPaths = new Set(unexpired.map(({ reservation }) =>
    `.well-known/${candidate.persona_npub}/${reservation.uri}`));
  for (const path of requiredPaths) {
    if (!candidatePaths.has(path)) throw new Error("prior status list not retained through token expiry");
  }
}

function validateRetainedStatusProvenance(previous: ContinuityManifest, candidate: ContinuityManifest): void {
  const prior = new Map(previous.status_lists.map((entry) => [entry.path, entry]));
  for (const entry of candidate.status_lists) {
    if (entry.issuer === candidate.issuer) continue;
    const predecessor = prior.get(entry.path);
    if (predecessor === undefined || predecessor.issuer !== entry.issuer || predecessor.uri !== entry.uri) {
      throw new Error("retained status list issuer/URI lacks predecessor provenance");
    }
  }
}

function compromisedSigningKeyIds(state: LedgerMergeResult): Set<string> {
  const confirmed = new Set(state.repository_confirmed_record_ids ?? []);
  return new Set(state.records
    .filter(({ record_type, record_id }) => record_type === "status-invalidation" && confirmed.has(record_id))
    .map(({ payload }) => objectValue(payload))
    .filter((payload): payload is Record<string, JsonValue> =>
      payload !== null && payload.cause === "signing-key-compromised" && typeof payload.signing_key_id === "string")
    .map(({ signing_key_id }) => String(signing_key_id)));
}

function verifyContinuityProof(manifest: ContinuityManifest): boolean {
  const proof = manifest.authority_proof;
  if (proof.type !== "radicle-ed25519" || didKeyFromEd25519(proof.public_key) !== manifest.authority.writer_nid) return false;
  return ed25519.verify(hexToBytes(proof.signature), utf8Bytes(continuityProofPayload(manifest)), hexToBytes(proof.public_key));
}

function continuityProofPayload(body: ContinuityManifestBody | Omit<ContinuityManifest, "authority_proof"> | ContinuityManifest): string {
  const { authority_proof: _proof, ...unsigned } = body as ContinuityManifest;
  return `heterodyne-oidc-continuity-manifest-v1\0${jcsCanonicalize(unsigned)}`;
}

function validateManifestIntrinsic(manifest: ContinuityManifest): void {
  const decoded = nip19.decode(manifest.persona_npub);
  if (decoded.type !== "npub" || decoded.data !== manifest.persona_key || nip19.npubEncode(manifest.persona_key) !== manifest.persona_npub) {
    throw new Error("oidc-issuer-mismatch: active-persona npub/key mismatch");
  }
  const parsed = new URL(manifest.issuer);
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "" ||
      `${parsed.origin}${parsed.pathname}` !== manifest.issuer || parsed.pathname !== `/oidc/${manifest.persona_npub}`) {
    throw new Error("oidc-issuer-mismatch: manifest issuer is not exact");
  }
  if (!Number.isSafeInteger(manifest.max_checkpoint_age_seconds) || manifest.max_checkpoint_age_seconds < 0 ||
      manifest.max_checkpoint_age_seconds > 300 ||
      !Number.isSafeInteger(manifest.authorization_view_max_age) || manifest.authorization_view_max_age < 1 ||
      manifest.authorization_view_max_age > 86_400 ||
      manifest.retiring_jwks_sha256.includes(manifest.current_signing_jwk_sha256) ||
      manifest.retiring_signing_key_ids.includes(manifest.current_signing_key_id) ||
      manifest.retiring_signing_key_ids.length !== manifest.retiring_jwks_sha256.length ||
      jcsCanonicalize(manifest.retiring_signing_key_ids) !== jcsCanonicalize([...manifest.retiring_signing_key_ids].sort()) ||
      jcsCanonicalize(manifest.retiring_jwks_sha256) !== jcsCanonicalize([...manifest.retiring_jwks_sha256].sort()) ||
      jcsCanonicalize(manifest.status_lists) !== jcsCanonicalize([...manifest.status_lists].sort((a, b) => a.path.localeCompare(b.path))) ||
      manifest.status_lists.some(({ path }) => !path.startsWith(`.well-known/${manifest.persona_npub}/status-lists/`)) ||
      manifest.status_lists.some((entry) => !validStatusEntry(entry, manifest.persona_npub)) ||
      (manifest.sequence === 0 && manifest.status_lists.some((entry) => entry.issuer !== manifest.issuer)) ||
      new Set(manifest.status_lists.map(({ path }) => path)).size !== manifest.status_lists.length) {
    throw new Error("oidc-status-invalid: manifest set is noncanonical");
  }
}

function validStatusEntry(
  entry: ContinuityManifest["status_lists"][number],
  personaNpub: string,
): boolean {
  try {
    const issuer = new URL(entry.issuer);
    return issuer.protocol === "https:" && issuer.username === "" && issuer.password === "" &&
      issuer.search === "" && issuer.hash === "" && `${issuer.origin}${issuer.pathname}` === entry.issuer &&
      issuer.pathname === `/oidc/${personaNpub}` &&
      entry.uri === `${entry.issuer}/${entry.path.slice(`.well-known/${personaNpub}/`.length)}`;
  } catch { return false; }
}

function validateManifestJwks(manifest: ContinuityManifest, jwksBytes: Uint8Array): JsonValue {
  if (!(jwksBytes instanceof Uint8Array)) {
    throw new Error("oidc-status-invalid: exact raw JWKS bytes are required");
  }
  let publicJwks: JsonValue;
  try { publicJwks = JSON.parse(Buffer.from(jwksBytes).toString("utf8")) as JsonValue; }
  catch { throw new Error("oidc-status-invalid: JWKS bytes are not JSON"); }
  const jwksObject = objectValue(publicJwks);
  if (jwksObject === null || Object.keys(jwksObject).length !== 1 || !Array.isArray(jwksObject.keys)) {
    throw new Error("oidc-status-invalid: JWKS bytes are not the closed public set");
  }
  if (sha256Hex(jwksBytes) !== manifest.current_jwks_sha256) {
    throw new Error("oidc-status-invalid: exact JWKS bytes differ from manifest");
  }
  const keys = jwksObject.keys.map((value) => {
    const key = objectValue(value);
    if (key === null) throw new Error("oidc-status-invalid: invalid public JWK");
    return exactPublicRsaJwk(key);
  });
  const keyDigests = keys.map((value) => sha256Hex(utf8Bytes(jcsCanonicalize(value)))).sort();
  const keyIds = keys.map(({ kid }) => String(kid)).sort();
  const expectedKeyDigests = [manifest.current_signing_jwk_sha256, ...manifest.retiring_jwks_sha256].sort();
  const expectedKeyIds = [manifest.current_signing_key_id, ...manifest.retiring_signing_key_ids].sort();
  const currentKey = keys.find(({ kid }) => kid === manifest.current_signing_key_id);
  if (currentKey === undefined ||
      sha256Hex(utf8Bytes(jcsCanonicalize(currentKey))) !== manifest.current_signing_jwk_sha256 ||
      jcsCanonicalize(keyDigests) !== jcsCanonicalize(expectedKeyDigests) ||
      jcsCanonicalize(keyIds) !== jcsCanonicalize(expectedKeyIds)) {
    throw new Error("oidc-status-invalid: current/retiring JWKS keys differ from manifest");
  }
  return publicJwks;
}

function verifyStatusListCompact(compact: string, jwks: JsonValue): {
  header: Record<string, JsonValue>; claims: Record<string, JsonValue>;
} {
  const segments = compact.split(".");
  if (segments.length !== 3 || segments.some((segment) => !canonicalBase64url(segment))) throw new Error("compact");
  const header = parseCanonicalObject(segments[0]);
  const claims = parseCanonicalObject(segments[1]);
  if (jcsCanonicalize(Object.keys(header).sort()) !== jcsCanonicalize(["alg", "kid", "typ"]) ||
      header.alg !== "RS256" || header.typ !== "statuslist+jwt" || typeof header.kid !== "string") throw new Error("header");
  const root = objectValue(jwks);
  if (root === null || Object.keys(root).length !== 1 || !Array.isArray(root.keys)) throw new Error("jwks");
  const matches = root.keys.map(objectValue).filter((key) => key !== null && key.kid === header.kid);
  if (matches.length !== 1) throw new Error("kid");
  const key = exactPublicRsaJwk(matches[0]!);
  const publicKey = createPublicKey({ key: key as JsonWebKey, format: "jwk" });
  if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048 ||
      !verify("RSA-SHA256", Buffer.from(`${segments[0]}.${segments[1]}`), publicKey, Buffer.from(segments[2], "base64url"))) {
    throw new Error("signature");
  }
  if (jcsCanonicalize(Object.keys(claims).sort()) !== jcsCanonicalize([
    "credential_ledger_generation",
    "credential_ledger_persona",
    "exp",
    "iat",
    "status_list",
    "sub",
    "ttl",
  ])) throw new Error("claims");
  return { header, claims };
}

function signCompact(header: JsonValue, claims: JsonValue, jwk: Record<string, JsonValue>): string {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedClaims = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const key = createPrivateKey({ key: jwk as JsonWebKey, format: "jwk" });
  return `${signingInput}.${sign("RSA-SHA256", Buffer.from(signingInput), key).toString("base64url")}`;
}

function exactPrivateRsaJwk(value: JsonValue): Record<string, JsonValue> & { kid: string } {
  const key = objectValue(value);
  if (key === null || key.kty !== "RSA" || key.alg !== "RS256" || key.use !== "sig" ||
      !Array.isArray(key.key_ops) || jcsCanonicalize(key.key_ops) !== jcsCanonicalize(["sign"]) ||
      typeof key.kid !== "string" || !canonicalBase64url(key.kid) || Buffer.from(key.kid, "base64url").length !== 32 ||
      !["n", "e", "d", "p", "q", "dp", "dq", "qi"].every((member) => typeof key[member] === "string" && canonicalBase64url(String(key[member])))) {
    throw new Error("oidc-signing-key-unavailable: strict private RS256 JWK required");
  }
  const thumbprint = createHash("sha256").update(jcsCanonicalize({ e: key.e, kty: "RSA", n: key.n })).digest("base64url");
  if (thumbprint !== key.kid) throw new Error("oidc-signing-key-unavailable: JWK thumbprint mismatch");
  return key as Record<string, JsonValue> & { kid: string };
}

function exactPublicRsaJwk(value: Record<string, JsonValue>): Record<string, JsonValue> {
  if (jcsCanonicalize(Object.keys(value).sort()) !== jcsCanonicalize(["alg", "e", "key_ops", "kid", "kty", "n", "use"]) ||
      value.kty !== "RSA" || value.alg !== "RS256" || value.use !== "sig" ||
      !Array.isArray(value.key_ops) || jcsCanonicalize(value.key_ops) !== jcsCanonicalize(["verify"]) ||
      typeof value.n !== "string" || typeof value.e !== "string" || typeof value.kid !== "string" ||
      !canonicalBase64url(value.n) || !canonicalBase64url(value.e) || !canonicalBase64url(value.kid)) throw new Error("public JWK");
  const thumbprint = createHash("sha256").update(jcsCanonicalize({ e: value.e, kty: "RSA", n: value.n })).digest("base64url");
  if (thumbprint !== value.kid) throw new Error("thumbprint");
  return value;
}

function assertCollisionFreeIssuances(issuances: IssuanceRecord[]): void {
  const allocations = new Set<string>();
  for (const issuance of issuances) {
    const allocation = `${issuance.reservation.uri}\0${issuance.reservation.idx}`;
    if (allocations.has(allocation)) throw new Error("claim-repository-conflict: duplicate status allocation");
    allocations.add(allocation);
  }
}

function requireExactStatusUri(value: string): void {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "" || parsed.search !== "" || parsed.hash !== "" ||
      `${parsed.origin}${parsed.pathname}` !== value || !/^\/oidc\/npub1[^/]+\/status-lists\/[0-9]+\/[0-9a-f]{32}\/[0-9]+\.jwt$/.test(parsed.pathname)) {
    throw new Error("oidc-status-invalid: exact HTTPS status URI required");
  }
}

function parseCanonicalObject(segment: string): Record<string, JsonValue> {
  const bytes = Buffer.from(segment, "base64url");
  const value = JSON.parse(bytes.toString("utf8")) as JsonValue;
  const object = objectValue(value);
  if (object === null || Buffer.from(JSON.stringify(object)).toString("base64url") !== segment) throw new Error("canonical JSON");
  return object;
}

function canonicalBase64url(value: string): boolean {
  return BASE64URL.test(value) && Buffer.from(value, "base64url").toString("base64url") === value;
}

function objectValue(value: unknown): Record<string, JsonValue> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, JsonValue> : null;
}

function sha256Hex(value: Uint8Array): string { return createHash("sha256").update(value).digest("hex"); }
function requireSafeTime(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`oidc-status-invalid: invalid ${label}`);
}
function requireFiniteTime(value: number, label: string): void {
  if (!Number.isFinite(value) || value < 0) throw new Error(`oidc-status-invalid: invalid ${label}`);
}
function accepted(): AuthorizationDecision { return { allowed: true, state: "active", reason_code: null }; }
function denied(reason_code: string): AuthorizationDecision { return { allowed: false, state: "invalid", reason_code }; }
function acceptedContinuity(active_issuer: string, standard_oidc_action: "retain-exact-issuer" | "register-successor"): ContinuityResolution {
  return { ...accepted(), active_issuer, standard_oidc_action, heterodyne_fallback: "radicle-canonical-main" };
}
function deniedContinuity(reason_code: string): ContinuityResolution { return denied(reason_code); }
