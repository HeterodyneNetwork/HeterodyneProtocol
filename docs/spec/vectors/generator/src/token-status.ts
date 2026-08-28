import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type JsonWebKey,
} from "node:crypto";
import { deflateSync, inflateSync } from "node:zlib";
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
  assertValidatedProjectedJwtContext,
  validatePersonaBinding,
  type PersonaIdentityState,
  type ValidatedProjectedJwtContext,
} from "./oidc.js";
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

const SHA256_HEX = /^[0-9a-f]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** Exact Comms 0.5 profile of draft-ietf-oauth-status-list-21 section 4.1. */
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
