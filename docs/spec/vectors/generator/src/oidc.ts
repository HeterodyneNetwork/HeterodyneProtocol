import { createHmac, createPrivateKey, createPublicKey, sign, verify, type JsonWebKey } from "node:crypto";
import { nip19 } from "nostr-tools";
import type { AuthorizationDecision, JsonValue } from "./claims.js";
import { jcsCanonicalize } from "./jcs.js";
import { validateIssuanceRecordOrThrow, type IssuanceRecord, type LedgerCheckpoint, type MintingEligibility } from "./claim-ledger.js";
import { validateOidcIssuerMetadataSchemaOrThrow } from "./schema.js";

export const KEY_REF_SCOPE = "heterodyne:key-ref";
export const KEY_REF_CLAIM = "https://heterodyne.network/jwt/key-ref";
export const CHECKPOINT_CLAIM = "https://heterodyne.network/jwt/ledger-checkpoint";
export const STATUS_MIRROR_CLAIM = "https://heterodyne.network/jwt/status-mirror";
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

export type DiscoveryPaths = {
  issuer: string;
  oidc_discovery: string;
  rfc8414_alias: string;
};

export type IssuerMetadata = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  device_authorization_endpoint: string;
  jwks_uri: string;
  response_types_supported: ["code"];
  grant_types_supported: ["authorization_code", typeof DEVICE_GRANT];
  code_challenge_methods_supported: ["S256"];
  subject_types_supported: ["pairwise"];
  id_token_signing_alg_values_supported: Array<"RS256" | "ES256" | "EdDSA">;
  token_endpoint_auth_signing_alg_values_supported: ["RS256"];
};

export type StatusMirror = {
  repository_rid: string;
  branch: "main";
  path: string;
  sha256: string;
};

export type JwtProjectionInput = {
  issuer: string;
  client_id: string;
  audience: string[];
  pairwise_sub: string;
  scopes: string[];
  now: number;
  expires_at: number;
  nonce?: string;
  cnf?: Record<string, JsonValue>;
  sender_constraint: "none" | "dpop" | "mtls";
  issuance: IssuanceRecord;
  released_claims: Record<string, JsonValue>;
  status_mirror: StatusMirror;
  release_decision: OidcAuthorizationDecision;
  mint_eligibility: MintingEligibility;
  historical_returnability: AuthorizationDecision;
};

export type ProjectedJwt = {
  protected_header: Record<string, JsonValue>;
  claims: Record<string, JsonValue>;
  compact: string;
};

export type RegisteredClient = {
  client_id: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  audiences: string[];
  assertion_profiles?: string[];
  sector_identifier: string;
};

export type OidcAuthorizationDecision = AuthorizationDecision & {
  pairwise_sub?: string;
  scopes?: string[];
  audience?: string[];
  released_claims?: Record<string, JsonValue>;
  source_claim_ids?: string[];
  checkpoint?: LedgerCheckpoint;
};

export type JwtValidationOptions = {
  now: number;
  token_use: "id_token" | "access_token" | "jwt_assertion";
  nonce?: string;
  client_id: string;
  assertion_profile?: string;
  cnf?: Record<string, JsonValue>;
  sender_constraint: "none" | "dpop" | "mtls";
};

export function issuerUrl(origin: string, coldRootNpub: string): string {
  const canonicalOrigin = exactHttpsOrigin(origin);
  let decoded: ReturnType<typeof nip19.decode>;
  try {
    decoded = nip19.decode(coldRootNpub);
  } catch {
    throw new Error("oidc-issuer-mismatch: cold-root npub is invalid");
  }
  if (decoded.type !== "npub" || typeof decoded.data !== "string" ||
      !/^[0-9a-f]{64}$/.test(decoded.data) || nip19.npubEncode(decoded.data) !== coldRootNpub) {
    throw new Error("oidc-issuer-mismatch: exact lowercase cold-root npub is required");
  }
  return `${canonicalOrigin}/oidc/${coldRootNpub}`;
}

export function discoveryPaths(origin: string, coldRootNpub: string): DiscoveryPaths {
  const exactOrigin = exactHttpsOrigin(origin);
  const issuer = issuerUrl(exactOrigin, coldRootNpub);
  return {
    issuer,
    oidc_discovery: `${issuer}/.well-known/openid-configuration`,
    rfc8414_alias: `${exactOrigin}/.well-known/oauth-authorization-server/oidc/${coldRootNpub}`,
  };
}

export function issuerMetadata(
  origin: string,
  coldRootNpub: string,
  optionalAlgorithms: Array<"ES256" | "EdDSA"> = [],
): IssuerMetadata {
  const { issuer } = discoveryPaths(origin, coldRootNpub);
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    device_authorization_endpoint: `${issuer}/device_authorization`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", DEVICE_GRANT],
    code_challenge_methods_supported: ["S256"],
    subject_types_supported: ["pairwise"],
    id_token_signing_alg_values_supported: ["RS256", ...uniqueSorted(optionalAlgorithms) as Array<"ES256" | "EdDSA">],
    token_endpoint_auth_signing_alg_values_supported: ["RS256"],
  };
}

export function validateIssuerMetadata(
  metadata: Record<string, JsonValue> | IssuerMetadata,
  expectedIssuer: string,
  expectedJwksUri: string,
): AuthorizationDecision {
  if (metadata.issuer !== expectedIssuer || metadata.jwks_uri !== expectedJwksUri ||
      expectedJwksUri !== `${expectedIssuer}/.well-known/jwks.json`) {
    return denied("oidc-issuer-mismatch");
  }
  try {
    validateOidcIssuerMetadataSchemaOrThrow(metadata);
    const issuer = new URL(expectedIssuer);
    if (issuer.protocol !== "https:" || issuer.username !== "" || issuer.password !== "" ||
        issuer.search !== "" || issuer.hash !== "" || !/^\/oidc\/npub1[023456789acdefghjklmnpqrstuvwxyz]+$/.test(issuer.pathname)) {
      return denied("oidc-issuer-mismatch");
    }
    const root = issuer.pathname.slice("/oidc/".length);
    if (!validateColdRootBinding(root, { cold_root_npub: root, epoch_npubs: [] }).allowed) return denied("oidc-issuer-mismatch");
    const algorithms = Array.isArray(metadata.id_token_signing_alg_values_supported)
      ? metadata.id_token_signing_alg_values_supported
      : [];
    const optional = algorithms.filter((value): value is "ES256" | "EdDSA" => value === "ES256" || value === "EdDSA");
    const expected = issuerMetadata(issuer.origin, root, optional);
    if (jcsCanonicalize(metadata as unknown as JsonValue) !== jcsCanonicalize(expected as unknown as JsonValue)) {
      return denied("oidc-issuer-mismatch");
    }
  } catch {
    return denied("oidc-issuer-mismatch");
  }
  return accepted();
}

export function validateColdRootBinding(
  candidateNpub: string,
  identity: { cold_root_npub: string; epoch_npubs: string[] },
): AuthorizationDecision {
  try {
    const candidate = canonicalNpub(candidateNpub);
    const coldRoot = canonicalNpub(identity.cold_root_npub);
    const epochs = identity.epoch_npubs.map(canonicalNpub);
    return candidate === coldRoot && !epochs.includes(candidate) && new Set(epochs).size === epochs.length
      ? accepted()
      : denied("oidc-issuer-mismatch");
  } catch {
    return denied("oidc-issuer-mismatch");
  }
}

export function derivePairwiseSubject(localSubject: string, sectorIdentifier: string, secretHex: string): string {
  if (!/^[A-Za-z0-9._~-]{1,255}$/.test(localSubject) || !/^[0-9a-f]{64}$/.test(secretHex)) {
    throw new Error("oidc-claim-release-denied: invalid pairwise subject derivation input");
  }
  const sector = exactHttpsOrigin(sectorIdentifier);
  return createHmac("sha256", Buffer.from(secretHex, "hex"))
    .update(`heterodyne-oidc-pairwise-sub-v1\0${sector}\0${localSubject}`, "utf8")
    .digest("base64url");
}

export function validateAuthorizationRequest(input: Record<string, JsonValue>): OidcAuthorizationDecision {
  const registration = asObject(input.registration);
  const clientId = stringValue(input.client_id);
  if (registration === null || input.registration_status !== "active" || clientId === null || registration.client_id !== clientId) {
    return denied("oidc-client-unregistered");
  }
  const registeredGrants = stringArray(registration.grant_types);
  const grant = stringValue(input.grant_type);
  const flow = stringValue(input.flow);
  if (grant === null || !registeredGrants.includes(grant) ||
      !((flow === "authorization_code" && grant === "authorization_code") ||
        (flow === "device_authorization" && grant === DEVICE_GRANT))) {
    return denied("oidc-grant-prohibited");
  }
  if (["implicit", "password", "client_credentials"].includes(grant)) {
    return denied("oidc-grant-prohibited");
  }
  if (flow === "authorization_code") {
    const redirect = stringValue(input.redirect_uri);
    if (input.response_type !== "code" || redirect === null ||
        !stringArray(registration.redirect_uris).includes(redirect) ||
        input.code_challenge_method !== "S256" ||
        !/^[A-Za-z0-9_-]{43,128}$/.test(String(input.code_challenge ?? ""))) {
      return denied("oidc-grant-prohibited");
    }
  }
  const registeredScopes = new Set(stringArray(registration.scopes));
  const registeredAudience = new Set(stringArray(registration.audiences));
  const consentedScopes = new Set(stringArray(input.consented_scopes));
  const consentedAudience = new Set(stringArray(input.consented_audiences));
  const scopes = uniqueSorted(stringArray(input.requested_scopes)
    .filter((scope) => registeredScopes.has(scope) && consentedScopes.has(scope)));
  const audience = uniqueSorted(stringArray(input.requested_audiences)
    .filter((value) => registeredAudience.has(value) && consentedAudience.has(value)));
  if (!scopes.includes("openid") || audience.length === 0) return denied("oidc-consent-required");
  const pairwiseContext = asObject(input.pairwise_subject_context);
  let pairwiseSub: string;
  try {
    if (pairwiseContext === null || pairwiseContext.sector_identifier !== registration.sector_identifier) throw new Error("binding");
    pairwiseSub = derivePairwiseSubject(
      String(pairwiseContext.local_subject ?? ""),
      String(pairwiseContext.sector_identifier ?? ""),
      String(pairwiseContext.secret ?? ""),
    );
    if (input.pairwise_sub !== undefined && input.pairwise_sub !== pairwiseSub) throw new Error("caller-arbitrary sub");
  } catch {
    return denied("oidc-claim-release-denied");
  }
  const trusted = new Set(stringArray(input.trusted_namespaces));
  const ledgerCheckpoint = asObject(input.ledger_checkpoint);
  if (input.canonical_claim_state !== true || !validCheckpoint(ledgerCheckpoint)) {
    return denied("oidc-claim-release-denied");
  }
  const consentedClaims = new Set(stringArray(input.consented_claims));
  const released: Record<string, JsonValue> = {};
  const sourceClaimIds: string[] = [];
  let stableKeyClaims = 0;
  const claims = Array.isArray(input.active_claims) ? input.active_claims : [];
  for (const candidate of claims) {
    const claim = asObject(candidate);
    if (claim === null || claim.state !== "active" || claim.repository_confirmed !== true ||
        claim.issuer_trusted !== true || claim.subject_proof_valid !== true ||
        typeof claim.claim_id !== "string" || !/^[0-9a-f]{64}$/.test(claim.claim_id)) continue;
    const namespace = stringValue(claim.namespace);
    const name = stringValue(claim.name);
    if (namespace === null || name === null || !trusted.has(namespace) || claim.value === undefined) continue;
    if (namespace === "heterodyne.device" && name === "key-ref") {
      stableKeyClaims += 1;
      if (scopes.includes(KEY_REF_SCOPE) && registeredScopes.has(KEY_REF_SCOPE) &&
          consentedScopes.has(KEY_REF_SCOPE) && consentedClaims.has(KEY_REF_CLAIM)) {
        released[KEY_REF_CLAIM] = claim.value;
        sourceClaimIds.push(claim.claim_id);
      }
      continue;
    }
    if (consentedClaims.has(name) && scopes.includes(namespace)) {
      if (Object.prototype.hasOwnProperty.call(released, name)) return denied("oidc-claim-release-denied");
      released[name] = claim.value;
      sourceClaimIds.push(claim.claim_id);
    }
  }
  if (stableKeyClaims > 1) return denied("oidc-claim-release-denied");
  return {
    ...accepted(),
    pairwise_sub: pairwiseSub,
    scopes,
    audience,
    released_claims: released,
    source_claim_ids: uniqueSorted(sourceClaimIds),
    checkpoint: ledgerCheckpoint,
  };
}

export function projectIdToken(input: JwtProjectionInput, privateJwk: JsonValue): ProjectedJwt {
  if (input.nonce === undefined || input.nonce.length === 0) {
    throw new Error("oidc-token-type-invalid: ID Token nonce is required by this projection");
  }
  return project(input, privateJwk, "JWT", { nonce: input.nonce });
}

export function projectAccessToken(input: JwtProjectionInput, privateJwk: JsonValue): ProjectedJwt {
  return project(input, privateJwk, "at+jwt", {});
}

export function projectJwtAssertion(
  input: JwtProjectionInput,
  privateJwk: JsonValue,
  assertionProfile: string,
  registration: RegisteredClient,
): ProjectedJwt {
  if (registration.client_id !== input.client_id || !registration.assertion_profiles?.includes(assertionProfile)) {
    throw new Error("oidc-client-unregistered: JWT assertion profile is not registered");
  }
  return project(input, privateJwk, "heterodyne-assertion+jwt", { assertion_profile: assertionProfile });
}

export function validateProjectedJwt(
  jwt: string,
  expectedIssuer: string,
  expectedAudience: string,
  jwks: JsonValue,
  options: JwtValidationOptions,
): AuthorizationDecision {
  try {
    const trustedIssuer = new URL(expectedIssuer);
    const trustedRoot = trustedIssuer.pathname.startsWith("/oidc/")
      ? trustedIssuer.pathname.slice("/oidc/".length)
      : "";
    if (trustedIssuer.protocol !== "https:" || trustedIssuer.username !== "" || trustedIssuer.password !== "" ||
        trustedIssuer.search !== "" || trustedIssuer.hash !== "" || `${trustedIssuer.origin}${trustedIssuer.pathname}` !== expectedIssuer ||
        !validateColdRootBinding(trustedRoot, { cold_root_npub: trustedRoot, epoch_npubs: [] }).allowed) {
      return denied("oidc-issuer-mismatch");
    }
    const segments = jwt.split(".");
    if (segments.length !== 3 || segments.some((segment) => !/^[A-Za-z0-9_-]+$/.test(segment) ||
        base64url(fromBase64url(segment)) !== segment)) {
      return denied("oidc-token-type-invalid");
    }
    const header = parseSegment(segments[0]);
    const claims = parseSegment(segments[1]);
    if (header.alg !== "RS256" || typeof header.kid !== "string" || !/^[0-9a-f]{64}$/.test(header.kid)) return denied("oidc-token-type-invalid");
    const keysObject = asObject(jwks);
    const keys = keysObject === null || !Array.isArray(keysObject.keys) ? [] : keysObject.keys;
    const matching = keys.filter((candidate) => {
      const key = asObject(candidate);
      return key?.kid === header.kid && key.kty === "RSA" && key.alg === "RS256" && key.use === "sig" && key.d === undefined;
    });
    if (matching.length !== 1) return denied("oidc-token-type-invalid");
    const publicKey = createPublicKey({ key: matching[0] as JsonWebKey, format: "jwk" });
    if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) return denied("oidc-token-type-invalid");
    if (!verify("RSA-SHA256", Buffer.from(`${segments[0]}.${segments[1]}`), publicKey, fromBase64url(segments[2]))) {
      return denied("oidc-token-type-invalid");
    }
    if (claims.iss !== expectedIssuer) return denied("oidc-issuer-mismatch");
    if ((options.token_use === "access_token" && header.typ !== "at+jwt") ||
        (options.token_use === "id_token" && header.typ !== "JWT") ||
        (options.token_use === "jwt_assertion" && header.typ !== "heterodyne-assertion+jwt")) {
      return denied("oidc-token-type-invalid");
    }
    const audiences = typeof claims.aud === "string" ? [claims.aud] : stringArray(claims.aud);
    if (!audiences.includes(expectedAudience)) return denied("oidc-audience-invalid");
    if (!Number.isSafeInteger(options.now) || options.now < 0 || options.client_id.length === 0) {
      return denied("oidc-token-type-invalid");
    }
    const now = options.now;
    if (!safeTime(claims.iat) || !safeTime(claims.exp) || Number(claims.iat) > now || Number(claims.exp) <= now ||
        typeof claims.sub !== "string" || typeof claims.jti !== "string" || typeof claims.client_id !== "string" ||
        typeof claims.scope !== "string" || !claims.scope.split(" ").every((scope) => scope.length > 0)) {
      return denied("oidc-token-type-invalid");
    }
    if (claims.client_id !== options.client_id) return denied("oidc-token-type-invalid");
    const expectedUse = options.token_use;
    if (expectedUse === "access_token" && header.typ !== "at+jwt") return denied("oidc-token-type-invalid");
    if (expectedUse === "id_token" && (header.typ !== "JWT" || claims.nonce !== options.nonce || typeof options.nonce !== "string")) {
      return denied("oidc-token-type-invalid");
    }
    if (expectedUse === "jwt_assertion" && (header.typ !== "heterodyne-assertion+jwt" ||
        claims.assertion_profile !== options.assertion_profile || typeof options.assertion_profile !== "string")) {
      return denied("oidc-token-type-invalid");
    }
    if ((claims.cnf !== undefined || options.cnf !== undefined || options.sender_constraint !== "none") &&
        (options.cnf === undefined || !validConfirmation(options.cnf, options.sender_constraint) ||
         jcsCanonicalize(claims.cnf) !== jcsCanonicalize(options.cnf))) {
      return denied("oidc-token-type-invalid");
    }
    if (options.sender_constraint === "none" && claims.cnf !== undefined) return denied("oidc-token-type-invalid");
    const checkpoint = asObject(claims[CHECKPOINT_CLAIM]);
    const mirror = asObject(claims[STATUS_MIRROR_CLAIM]);
    const status = asObject(claims.status);
    const statusList = asObject(status?.status_list);
    if (!validCheckpoint(checkpoint) || !validStatusMirror(mirror) || statusList === null ||
        typeof statusList.uri !== "string" || !safeTime(statusList.idx)) {
      return denied("oidc-token-type-invalid");
    }
    const root = new URL(expectedIssuer).pathname.slice("/oidc/".length);
    const mirrorPrefix = `.well-known/${root}/`;
    if (!mirror.path.startsWith(mirrorPrefix) || statusList.uri !== `${expectedIssuer}/${mirror.path.slice(mirrorPrefix.length)}` ||
        checkpoint.repository_rid !== mirror.repository_rid) return denied("oidc-token-type-invalid");
    return accepted();
  } catch {
    return denied("oidc-token-type-invalid");
  }
}

function project(
  input: JwtProjectionInput,
  privateJwkValue: JsonValue,
  typ: "JWT" | "at+jwt" | "heterodyne-assertion+jwt",
  extraClaims: Record<string, JsonValue>,
): ProjectedJwt {
  validateProjectionInput(input);
  const privateJwk = asObject(privateJwkValue);
  if (privateJwk === null || privateJwk.kty !== "RSA" || privateJwk.alg !== "RS256" ||
      privateJwk.use !== "sig" || typeof privateJwk.kid !== "string" || !/^[0-9a-f]{64}$/.test(privateJwk.kid) ||
      typeof privateJwk.d !== "string") {
    throw new Error("RS256 private signing JWK with immutable lowercase kid is required");
  }
  if (privateJwk.kid !== input.issuance.signing_key_id) {
    throw new Error("oidc-signing-key-unavailable: signing JWK does not match canonical issuance key");
  }
  const protected_header: Record<string, JsonValue> = { alg: "RS256", kid: privateJwk.kid, typ };
  const statusUri = `${input.issuer}/${input.issuance.reservation.uri}`;
  const claims: Record<string, JsonValue> = {
    iss: input.issuer,
    sub: input.pairwise_sub,
    aud: typ === "JWT" ? [input.client_id] : [...input.audience],
    exp: input.expires_at,
    iat: input.now,
    jti: input.issuance.jti,
    client_id: input.client_id,
    scope: uniqueSorted(input.scopes).join(" "),
    ...input.released_claims,
    ...extraClaims,
    ...(input.cnf === undefined ? {} : { cnf: input.cnf }),
    [CHECKPOINT_CLAIM]: input.issuance.checkpoint,
    status: { status_list: { uri: statusUri, idx: input.issuance.reservation.idx } },
    [STATUS_MIRROR_CLAIM]: input.status_mirror,
  };
  for (const forbidden of ["source_claim_ids", "consent", "provenance", "ledger_contents", "reader_membership"]) {
    if (forbidden in claims) throw new Error("oidc-claim-release-denied: private ledger data cannot be projected");
  }
  const encodedHeader = base64url(Buffer.from(JSON.stringify(protected_header)));
  const encodedClaims = base64url(Buffer.from(JSON.stringify(claims)));
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const key = createPrivateKey({ key: privateJwk as JsonWebKey, format: "jwk" });
  if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new Error("RS256 signing key must have a modulus of at least 2048 bits");
  }
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), key);
  return { protected_header, claims, compact: `${signingInput}.${base64url(signature)}` };
}

function validateProjectionInput(input: JwtProjectionInput): void {
  validateIssuanceRecordOrThrow(input.issuance);
  if (!Number.isSafeInteger(input.now) || !Number.isSafeInteger(input.expires_at) ||
      input.now !== input.issuance.issued_at || input.expires_at !== input.issuance.expires_at ||
      input.expires_at <= input.now || input.audience.length === 0 || input.scopes.length === 0 ||
      !input.scopes.every(nonempty) || !input.audience.every(exactHttpsResource) ||
      !nonempty(input.client_id) || !/^[A-Za-z0-9._~-]{16,255}$/.test(input.pairwise_sub) ||
      !validStatusMirror(input.status_mirror) || input.status_mirror.repository_rid !== input.issuance.checkpoint.repository_rid ||
      !input.release_decision.allowed || input.release_decision.state !== "active" ||
      !input.mint_eligibility.allowed || input.mint_eligibility.reason_code !== null ||
      input.mint_eligibility.checkpoint.commit_oid !== input.issuance.checkpoint.commit_oid ||
      !input.historical_returnability.allowed || input.historical_returnability.state !== "active" ||
      input.release_decision.pairwise_sub !== input.pairwise_sub ||
      jcsCanonicalize(input.release_decision.scopes) !== jcsCanonicalize(uniqueSorted(input.scopes)) ||
      jcsCanonicalize(input.release_decision.audience) !== jcsCanonicalize(uniqueSorted(input.audience)) ||
      jcsCanonicalize(input.release_decision.released_claims) !== jcsCanonicalize(input.released_claims) ||
      jcsCanonicalize(input.release_decision.source_claim_ids) !== jcsCanonicalize(uniqueSorted(input.issuance.source_claim_ids)) ||
      jcsCanonicalize(input.release_decision.checkpoint) !== jcsCanonicalize(input.issuance.checkpoint)) {
    throw new Error("oidc-token-type-invalid: invalid JWT projection input");
  }
  const parsed = new URL(input.issuer);
  const root = parsed.pathname.startsWith("/oidc/") ? parsed.pathname.slice("/oidc/".length) : "";
  if (parsed.protocol !== "https:" || parsed.search !== "" || parsed.hash !== "" || parsed.pathname.endsWith("/") ||
      !validateColdRootBinding(root, { cold_root_npub: root, epoch_npubs: [] }).allowed) {
    throw new Error("oidc-issuer-mismatch: exact HTTPS issuer is required");
  }
  const expectedStatusSuffix = `/${input.issuance.reservation.uri}`;
  if (!input.status_mirror.path.endsWith(expectedStatusSuffix)) {
    throw new Error("oidc-token-type-invalid: status mirror does not bind issuance reservation");
  }
  if ((input.sender_constraint === "none") !== (input.cnf === undefined) ||
      (input.cnf !== undefined && !validConfirmation(input.cnf, input.sender_constraint))) {
    throw new Error("oidc-token-type-invalid: cnf must contain exactly one DPoP jkt or mTLS x5t#S256 thumbprint");
  }
  const reserved = new Set([
    "iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope", "nonce", "cnf",
    "status", "assertion_profile", CHECKPOINT_CLAIM, STATUS_MIRROR_CLAIM,
    "source_claim_ids", "consent", "provenance", "ledger_contents", "reader_membership",
  ]);
  if (Object.keys(input.released_claims).some((claim) => reserved.has(claim))) {
    throw new Error("oidc-claim-release-denied: reserved or private claim cannot be projected");
  }
  if (Object.values(input.released_claims).some((value) => containsForbiddenField(value, reserved))) {
    throw new Error("oidc-claim-release-denied: private claim provenance cannot be projected");
  }
}

function exactHttpsOrigin(origin: string): string {
  let parsed: URL;
  try { parsed = new URL(origin); } catch { throw new Error("oidc-issuer-mismatch: invalid issuer origin"); }
  const serialized = parsed.origin;
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "" ||
      parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "" ||
      origin !== serialized) {
    throw new Error("oidc-issuer-mismatch: exact HTTPS origin without aliases is required");
  }
  return serialized;
}

function validCheckpoint(value: Record<string, JsonValue> | null): value is LedgerCheckpoint & Record<string, JsonValue> {
  return value !== null && typeof value.repository_rid === "string" && /^rad:z[1-9A-HJ-NP-Za-km-z]+$/.test(value.repository_rid) &&
    value.branch === "main" && typeof value.commit_oid === "string" && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value.commit_oid) &&
    safeTime(value.observed_at);
}

function validStatusMirror(value: unknown): value is StatusMirror {
  const mirror = asObject(value);
  return mirror !== null && typeof mirror.repository_rid === "string" && /^rad:z[1-9A-HJ-NP-Za-km-z]+$/.test(mirror.repository_rid) &&
    mirror.branch === "main" && typeof mirror.path === "string" && /^\.well-known\/npub1[^/]+\/status-lists\/[0-9]+\/[0-9a-f]{32}\/[0-9]+\.jwt$/.test(mirror.path) &&
    typeof mirror.sha256 === "string" && /^[0-9a-f]{64}$/.test(mirror.sha256);
}

function validConfirmation(value: Record<string, JsonValue>, method: "none" | "dpop" | "mtls"): boolean {
  const keys = Object.keys(value);
  return keys.length === 1 && ((method === "dpop" && keys[0] === "jkt" && typeof value.jkt === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.jkt)) ||
    (method === "mtls" && keys[0] === "x5t#S256" && typeof value["x5t#S256"] === "string" && /^[A-Za-z0-9_-]{43}$/.test(value["x5t#S256"])));
}

function denied(reason_code: string): OidcAuthorizationDecision {
  return { allowed: false, state: "invalid", reason_code };
}

function accepted(): AuthorizationDecision {
  return { allowed: true, state: "active", reason_code: null };
}

function asObject(value: unknown): Record<string, JsonValue> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, JsonValue>
    : null;
}

function stringValue(value: JsonValue | undefined): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function stringArray(value: JsonValue | undefined): string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string") ? value : [];
}

function uniqueSorted(values: string[]): string[] { return [...new Set(values)].sort(); }
function nonempty(value: string): boolean { return value.length > 0; }
function exactHttpsResource(value: string): boolean {
  try { const parsed = new URL(value); return parsed.protocol === "https:" && parsed.search === "" && parsed.hash === ""; } catch { return false; }
}
function safeTime(value: JsonValue | undefined): boolean { return typeof value === "number" && Number.isSafeInteger(value) && value >= 0; }
function base64url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }
function fromBase64url(value: string): Buffer { return Buffer.from(value, "base64url"); }
function parseSegment(value: string): Record<string, JsonValue> {
  const decoded = JSON.parse(fromBase64url(value).toString("utf8")) as unknown;
  const object = asObject(decoded);
  if (object === null) throw new Error("JWT segment is not an object");
  if (base64url(Buffer.from(JSON.stringify(object))) !== value) throw new Error("JWT JSON serialization is not canonical");
  return object;
}

function canonicalNpub(value: string): string {
  const decoded = nip19.decode(value);
  if (decoded.type !== "npub" || typeof decoded.data !== "string" || nip19.npubEncode(decoded.data) !== value) {
    throw new Error("invalid npub");
  }
  return value;
}

function containsForbiddenField(value: JsonValue, forbidden: Set<string>): boolean {
  if (Array.isArray(value)) return value.some((entry) => containsForbiddenField(entry, forbidden));
  if (value !== null && typeof value === "object") {
    return Object.entries(value).some(([key, entry]) => forbidden.has(key) || containsForbiddenField(entry, forbidden));
  }
  return false;
}
