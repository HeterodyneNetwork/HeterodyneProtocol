import { createHash, createHmac, createPrivateKey, createPublicKey, sign, verify, type JsonWebKey } from "node:crypto";
import { types as utilTypes } from "node:util";
import { nip19 } from "nostr-tools";
import {
  claimArtifactBindingDigest,
  claimRevocationArtifactBindingDigest,
  inspectVerifiedClaim,
  type AuthorizationDecision,
  type ClaimVerificationContext,
  type JsonValue,
} from "./claims.js";
import {
  authorizeClaimEffect,
  revalidateAcceptedClaimEffect,
  type ClaimAuthorizationAuthority,
  type ClaimEffectAuthorizationResult,
  type ClaimEffectOutcome,
  type CurrentClaimEffectBindingView,
} from "./claim-authorization.js";
import { captureExactDataObject, snapshotClosedDataTree } from "./closed-data.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  activeCanonicalClaimSemanticsAt,
  canReturnToken,
  canonicalValidatedCheckpoint,
  evaluateMintingAttempt,
  replayConfirmedClaimForAuthorization,
  unwrapIssuerSigningJwk,
  validateIssuanceRecordOrThrow,
  type IssuanceRecord,
  type IssuerKeyEnvelope,
  type LedgerCheckpoint,
  type LedgerMergeResult,
} from "./claim-ledger.js";
import { validateOidcIssuerMetadataSchemaOrThrow } from "./schema.js";
import {
  evaluateCredentialGeneration,
  isCredentialLedgerBinding,
  type CredentialLedgerBinding,
} from "./credential-generation.js";

export const KEY_REF_SCOPE = "heterodyne:key-ref";
export const KEY_REF_CLAIM = "https://heterodyne.network/jwt/key-ref";
export const CHECKPOINT_CLAIM = "https://heterodyne.network/jwt/ledger-checkpoint";
export const STATUS_MIRROR_CLAIM = "https://heterodyne.network/jwt/status-mirror";
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

export type PersonaIdentityState = { persona_npub: string; persona_key: string };

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
  issuance_record_id: string;
  state: LedgerMergeResult;
  authorization_authority: ClaimAuthorizationAuthority;
  authorization: OidcAuthorizedRelease;
  issuer_envelope: IssuerKeyEnvelope;
  issuer_audience_key: Uint8Array;
  issuer_writer_nid: string;
  identity: PersonaIdentityState;
  status_mirror: StatusMirror;
};

export type ProjectedJwt = {
  protected_header: Record<string, JsonValue>;
  claims: Record<string, JsonValue>;
  compact: string;
};

export type ValidatedProjectedJwtContext = {
  compact: string;
  claims: Record<string, JsonValue>;
  validated_at: number;
  token_use: JwtValidationOptions["token_use"];
};

const VALIDATED_PROJECTED_JWTS = new WeakMap<object, string>();

export type RegisteredClient = {
  client_id: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  audiences: string[];
  claims: string[];
  assertion_profiles?: string[];
  sector_identifier: string;
};

export type OidcAuthorizationDecision = AuthorizationDecision & {
  credential_ledger_persona?: string;
  credential_ledger_generation?: number;
  pairwise_sub?: string;
  scopes?: string[];
  audience?: string[];
  released_claims?: Record<string, JsonValue>;
  source_claim_ids?: string[];
  checkpoint?: LedgerCheckpoint;
  request_digest?: string;
  registration_record_id?: string;
  consent_record_id?: string;
  source_record_ids?: string[];
  release_digest?: string;
  assertion_profiles?: string[];
  nonce?: string;
  cnf?: Record<string, JsonValue>;
  sender_constraint?: "none" | "dpop" | "mtls";
};

declare const oidcAuthorizedReleaseBrand: unique symbol;

export type OidcAuthorizationPurpose =
  | "authorization_code"
  | "device_authorization"
  | "jwt_projection";

export type OidcProjectionSubtype = "id_token" | "access_token" | "jwt_assertion";

export type OidcAuthorizedRelease = Readonly<{
  readonly [oidcAuthorizedReleaseBrand]: true;
}>;

type AuthorizedReleaseRecord = {
  authority: ClaimAuthorizationAuthority;
  effect_result: ClaimEffectAuthorizationResult<unknown>;
  purpose: OidcAuthorizationPurpose;
  projection_subtype: OidcProjectionSubtype | null;
  assertion_profile: string | null;
  idempotency_key: string;
  authorized_at: number;
  expires_at: number;
  view_fingerprint: string;
  consumed: boolean;
  request: OidcAuthorizationRequest;
  release: CompleteOidcAuthorizationRelease;
};

type CompleteOidcAuthorizationRelease = OidcAuthorizationDecision & Required<Pick<
  OidcAuthorizationDecision,
  | "pairwise_sub"
  | "scopes"
  | "audience"
  | "released_claims"
  | "source_claim_ids"
  | "checkpoint"
  | "request_digest"
  | "release_digest"
>>;

type CapturedAuthorizationEffectInput<T> = Readonly<{
  request: OidcAuthorizationRequest;
  idempotency_key: string;
  purpose: OidcAuthorizationPurpose;
  projection_subtype: OidcProjectionSubtype | null;
  assertion_profile: string | null;
  authorization_validity_seconds: number;
  effect(
    release: OidcAuthorizationDecision,
    executionToken: string,
  ): ClaimEffectOutcome<T> | Promise<ClaimEffectOutcome<T>>;
}>;

type OidcAuthorizationSession = {
  exact_input_digest: string;
  authorized_at?: number;
  expires_at?: number;
  view_fingerprint?: string;
};

const AUTHORIZED_RELEASES = new WeakMap<object, AuthorizedReleaseRecord>();
const ISSUED_GRANTS = new WeakMap<object, Map<string, unknown>>();
const AUTHORIZATION_SESSIONS = new WeakMap<object, Map<string, OidcAuthorizationSession>>();

export type OidcAuthorizationEffectResult<T> =
  | (Extract<ClaimEffectAuthorizationResult<T>, { verdict: "accept" }> & Readonly<{
      authorization: OidcAuthorizedRelease;
    }>)
  | Exclude<ClaimEffectAuthorizationResult<T>, { verdict: "accept" }>;

export type OidcClaimEvidence = {
  claim_record_id: string;
  verification_context: ClaimVerificationContext;
};

export type OidcAuthorizationRequest = {
  flow: "authorization_code" | "device_authorization";
  grant_type: "authorization_code" | typeof DEVICE_GRANT;
  response_type?: "code";
  client_id: string;
  redirect_uri?: string;
  code_challenge?: string;
  code_challenge_method?: "S256";
  requested_scopes: string[];
  requested_audiences: string[];
  requested_claims: string[];
  pairwise_secret: string;
  state: LedgerMergeResult;
  registration: OidcClaimEvidence;
  consent: OidcClaimEvidence;
  source_claims: OidcClaimEvidence[];
  nonce: string;
  cnf?: Record<string, JsonValue>;
  sender_constraint: "none" | "dpop" | "mtls";
};

export type JwtValidationOptions = {
  now: number;
  token_use: "id_token" | "access_token" | "jwt_assertion";
  nonce?: string;
  client_id: string;
  assertion_profile?: string;
  cnf?: Record<string, JsonValue>;
  sender_constraint: "none" | "dpop" | "mtls";
  permitted_audiences: string[];
  credential_ledger: CredentialLedgerBinding;
};

export type AuthorizationCodeRecord = CredentialLedgerBinding & {
  code: string; client_id: string; redirect_uri: string; code_challenge: string;
  issued_at: number; expires_at: number; release_digest: string;
};

export type DeviceAuthorizationRecord = CredentialLedgerBinding & {
  device_code: string; user_code: string; client_id: string; scopes: string[];
  issued_at: number; expires_at: number; interval: number; last_poll_at: number | null;
  status: "pending" | "approved" | "denied" | "consumed"; release_digest: string;
};

export function issueAuthorizationCode(
  authority: ClaimAuthorizationAuthority,
  authorization: OidcAuthorizedRelease,
  lifetimeSeconds = 300,
): AuthorizationCodeRecord {
  const { retained } = consumeAuthorizedRelease(
    authority,
    authorization,
    "authorization_code",
  );
  const now = retained.authorized_at;
  const { request, release: decision } = retained;
  if (decision.release_digest === undefined || request.flow !== "authorization_code" ||
      request.redirect_uri === undefined || !canonicalPkceValue(request.code_challenge) ||
      !Number.isSafeInteger(now) || !Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > 600) {
    throw new Error("oidc-grant-prohibited: authorization code prerequisites failed");
  }
  const core = { ...request.state.credential_ledger,
    client_id: request.client_id, redirect_uri: request.redirect_uri,
    code_challenge: request.code_challenge, issued_at: now, expires_at: now + lifetimeSeconds,
    release_digest: decision.release_digest };
  return issuedGrant(retained, "authorization-code", jsonDigest(core), () => ({
    code: createHash("sha256").update(`heterodyne-authorization-code-v1\0${jcsCanonicalize(core)}`).digest("base64url"),
    ...core,
  }));
}

export function redeemAuthorizationCode(
  record: AuthorizationCodeRecord,
  input: {
    code: string;
    client_id: string;
    redirect_uri: string;
    code_verifier: string;
    now: number;
    credential_ledger: CredentialLedgerBinding;
  },
  consumedCodes: Set<string>,
): AuthorizationDecision {
  if (!Object.prototype.hasOwnProperty.call(record, "credential_ledger_generation")) {
    return denied("credential_generation_missing");
  }
  if (consumedCodes.has(record.code) || input.code !== record.code || input.client_id !== record.client_id ||
      input.redirect_uri !== record.redirect_uri || input.now < record.issued_at || input.now >= record.expires_at ||
      typeof input.code_verifier !== "string" || !/^[A-Za-z0-9\-._~]{43,128}$/.test(input.code_verifier) ||
      createHash("sha256").update(input.code_verifier).digest("base64url") !== record.code_challenge) {
    return denied("oidc-grant-prohibited");
  }
  const generation = evaluateCredentialGeneration(record, input.credential_ledger);
  if (!generation.valid) {
    return denied(generation.reason_code === "credential_schema_invalid"
      ? "oidc-grant-prohibited"
      : generation.reason_code);
  }
  consumedCodes.add(record.code);
  return accepted();
}

export function issueDeviceAuthorization(
  authority: ClaimAuthorizationAuthority,
  authorization: OidcAuthorizedRelease,
  lifetimeSeconds = 600,
  interval = 5,
): DeviceAuthorizationRecord {
  const { retained } = consumeAuthorizedRelease(
    authority,
    authorization,
    "device_authorization",
  );
  const now = retained.authorized_at;
  const { request, release: decision } = retained;
  if (decision.release_digest === undefined || request.flow !== "device_authorization" ||
      !Number.isSafeInteger(now) || !Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 ||
      !Number.isSafeInteger(interval) || interval < 1) throw new Error("oidc-grant-prohibited: device authorization prerequisites failed");
  const core = { ...request.state.credential_ledger,
    client_id: request.client_id, scopes: uniqueSorted(decision.scopes ?? []), issued_at: now,
    expires_at: now + lifetimeSeconds, interval, release_digest: decision.release_digest };
  const digest = createHash("sha256").update(`heterodyne-device-code-v1\0${jcsCanonicalize(core)}`).digest();
  return issuedGrant(retained, "device-authorization", jsonDigest(core), () => ({
    device_code: digest.toString("base64url"),
    user_code: digest.subarray(0, 5).toString("hex").toUpperCase(),
    ...core,
    last_poll_at: null,
    status: "pending" as const,
  }));
}

export function decideDeviceAuthorization(
  record: DeviceAuthorizationRecord,
  decision: "approve" | "deny",
  now: number,
  currentCredentialLedger: CredentialLedgerBinding,
): DeviceAuthorizationRecord {
  if (!Object.prototype.hasOwnProperty.call(record, "credential_ledger_generation")) {
    throw new Error("credential_generation_missing");
  }
  if (record.status !== "pending" || now < record.issued_at || now >= record.expires_at) {
    throw new Error("expired_token");
  }
  const generation = evaluateCredentialGeneration(record, currentCredentialLedger);
  if (!generation.valid) {
    throw new Error(generation.reason_code === "credential_schema_invalid"
      ? "oidc-grant-prohibited"
      : generation.reason_code);
  }
  return { ...record, status: decision === "approve" ? "approved" : "denied" };
}

export function redeemDeviceCode(
  record: DeviceAuthorizationRecord,
  input: {
    device_code: string;
    client_id: string;
    now: number;
    credential_ledger: CredentialLedgerBinding;
  },
): { record: DeviceAuthorizationRecord; result: "authorization_pending" | "slow_down" | "access_denied" | "expired_token" | "success" } {
  if (!evaluateCredentialGeneration(record, input.credential_ledger).valid) {
    return { record, result: "access_denied" };
  }
  if (input.device_code !== record.device_code || input.client_id !== record.client_id) {
    return { record, result: "access_denied" };
  }
  if (input.now >= record.expires_at || record.status === "consumed") return { record, result: "expired_token" };
  if (record.status === "denied") return { record, result: "access_denied" };
  if (record.last_poll_at !== null && input.now < record.last_poll_at + record.interval) {
    return { record: { ...record, interval: record.interval + 5, last_poll_at: input.now }, result: "slow_down" };
  }
  if (record.status === "pending") return { record: { ...record, last_poll_at: input.now }, result: "authorization_pending" };
  return { record: { ...record, last_poll_at: input.now, status: "consumed" }, result: "success" };
}

export function purgeOidcTransactionsForCredentialReset(
  authorizationCodes: readonly AuthorizationCodeRecord[],
  deviceAuthorizations: readonly DeviceAuthorizationRecord[],
  currentCredentialLedger: CredentialLedgerBinding,
): {
  retained_authorization_codes: AuthorizationCodeRecord[];
  retained_device_authorizations: DeviceAuthorizationRecord[];
  purged_authorization_codes: string[];
  purged_device_codes: string[];
  requires_authority_reissue: true;
  requires_status_reissue: true;
} {
  if (!isCredentialLedgerBinding(currentCredentialLedger)) {
    throw new Error("credential_schema_invalid");
  }
  const retainedAuthorizationCodes = authorizationCodes
    .filter((record) => evaluateCredentialGeneration(record, currentCredentialLedger).valid);
  const retainedDeviceAuthorizations = deviceAuthorizations
    .filter((record) => evaluateCredentialGeneration(record, currentCredentialLedger).valid);
  const retainedCodeIds = new Set(retainedAuthorizationCodes.map(({ code }) => code));
  const retainedDeviceIds = new Set(retainedDeviceAuthorizations.map(({ device_code }) => device_code));
  return {
    retained_authorization_codes: retainedAuthorizationCodes,
    retained_device_authorizations: retainedDeviceAuthorizations,
    purged_authorization_codes: authorizationCodes
      .map(({ code }) => code)
      .filter((code) => !retainedCodeIds.has(code))
      .sort(),
    purged_device_codes: deviceAuthorizations
      .map(({ device_code }) => device_code)
      .filter((deviceCode) => !retainedDeviceIds.has(deviceCode))
      .sort(),
    requires_authority_reissue: true,
    requires_status_reissue: true,
  };
}

export function issuerUrl(origin: string, personaNpub: string, identity: PersonaIdentityState): string {
  const canonicalOrigin = exactHttpsOrigin(origin);
  if (!validatePersonaBinding(personaNpub, identity).allowed) {
    throw new Error("oidc-issuer-mismatch: issuer path is not the active persona");
  }
  let decoded: ReturnType<typeof nip19.decode>;
  try {
    decoded = nip19.decode(personaNpub);
  } catch {
    throw new Error("oidc-issuer-mismatch: persona npub is invalid");
  }
  if (decoded.type !== "npub" || typeof decoded.data !== "string" ||
      !/^[0-9a-f]{64}$/.test(decoded.data) || nip19.npubEncode(decoded.data) !== personaNpub) {
    throw new Error("oidc-issuer-mismatch: exact active-persona npub is required");
  }
  return `${canonicalOrigin}/oidc/${personaNpub}`;
}

export function discoveryPaths(origin: string, personaNpub: string, identity: PersonaIdentityState): DiscoveryPaths {
  const exactOrigin = exactHttpsOrigin(origin);
  const issuer = issuerUrl(exactOrigin, personaNpub, identity);
  return {
    issuer,
    oidc_discovery: `${issuer}/.well-known/openid-configuration`,
    rfc8414_alias: `${exactOrigin}/.well-known/oauth-authorization-server/oidc/${personaNpub}`,
  };
}

export function issuerMetadata(
  origin: string,
  personaNpub: string,
  identity: PersonaIdentityState,
): IssuerMetadata {
  const { issuer } = discoveryPaths(origin, personaNpub, identity);
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
    id_token_signing_alg_values_supported: ["RS256"],
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
    canonicalNpub(root);
    const algorithms = Array.isArray(metadata.id_token_signing_alg_values_supported)
      ? metadata.id_token_signing_alg_values_supported
      : [];
    if (algorithms.length !== 1 || algorithms[0] !== "RS256") return denied("oidc-issuer-mismatch");
    const decoded = nip19.decode(root);
    if (decoded.type !== "npub" || typeof decoded.data !== "string") {
      return denied("oidc-issuer-mismatch");
    }
    const expected = issuerMetadata(issuer.origin, root, {
      persona_npub: root,
      persona_key: decoded.data,
    });
    if (jcsCanonicalize(metadata as unknown as JsonValue) !== jcsCanonicalize(expected as unknown as JsonValue)) {
      return denied("oidc-issuer-mismatch");
    }
  } catch {
    return denied("oidc-issuer-mismatch");
  }
  return accepted();
}

export function validatePersonaBinding(
  candidateNpub: string,
  identity: PersonaIdentityState,
): AuthorizationDecision {
  try {
    const prototype = Object.getPrototypeOf(identity);
    const descriptors = Object.getOwnPropertyDescriptors(identity);
    const members = Reflect.ownKeys(descriptors);
    if ((prototype !== Object.prototype && prototype !== null) ||
        members.length !== 2 ||
        !members.every((member) => typeof member === "string" &&
          (member === "persona_key" || member === "persona_npub") &&
          descriptors[member].enumerable === true &&
          Object.hasOwn(descriptors[member], "value"))) {
      return denied("oidc-issuer-mismatch");
    }
    const candidate = canonicalNpub(candidateNpub);
    const persona = canonicalNpub(identity.persona_npub);
    const decoded = nip19.decode(persona);
    return candidate === persona && decoded.type === "npub" &&
      decoded.data === identity.persona_key && nip19.npubEncode(identity.persona_key) === persona
      ? accepted()
      : denied("oidc-issuer-mismatch");
  } catch {
    return denied("oidc-issuer-mismatch");
  }
}

export function derivePairwiseSubject(localSubject: string, sectorIdentifier: string, secretHex: string): string {
  if (!/^[0-9a-f]{64}$/.test(localSubject) || !/^[0-9a-f]{64}$/.test(secretHex)) {
    throw new Error("oidc-claim-release-denied: invalid pairwise subject derivation input");
  }
  const sector = exactHttpsOrigin(sectorIdentifier);
  return createHmac("sha256", Buffer.from(secretHex, "hex"))
    .update(`heterodyne-oidc-pairwise-sub-v1\0${sector}\0${localSubject}`, "utf8")
    .digest("base64url");
}

export function validateAuthorizationRequest(input: OidcAuthorizationRequest): OidcAuthorizationDecision {
  try {
    if (typeof input.nonce !== "string" || input.nonce.length === 0) {
      return denied("oidc-claim-release-denied");
    }
    const canonicalCheckpoint = canonicalValidatedCheckpoint(input.state);
    const credentialLedger = input.state.credential_ledger;
    const requestCore = {
      flow: input.flow, grant_type: input.grant_type,
      ...(input.response_type === undefined ? {} : { response_type: input.response_type }),
      client_id: input.client_id,
      ...(input.redirect_uri === undefined ? {} : { redirect_uri: input.redirect_uri }),
      ...(input.code_challenge === undefined ? {} : { code_challenge: input.code_challenge }),
      ...(input.code_challenge_method === undefined ? {} : { code_challenge_method: input.code_challenge_method }),
      requested_scopes: uniqueSorted(input.requested_scopes),
      requested_audiences: uniqueSorted(input.requested_audiences),
      requested_claims: uniqueSorted(input.requested_claims),
      nonce: input.nonce,
      ...(input.cnf === undefined ? {} : { cnf: input.cnf }),
      sender_constraint: input.sender_constraint,
      registration_record_id: input.registration.claim_record_id,
      consent_record_id: input.consent.claim_record_id,
      source_record_ids: uniqueSorted(input.source_claims.map(({ claim_record_id }) => claim_record_id)),
      checkpoint: canonicalCheckpoint,
      ...credentialLedger,
    };
    const request_digest = jsonDigest(requestCore);
    const registrationReplay = replayConfirmedClaimForAuthorization({
      state: input.state, claim_record_id: input.registration.claim_record_id,
      verification_context: input.registration.verification_context,
    });
    const consentReplay = replayConfirmedClaimForAuthorization({
      state: input.state, claim_record_id: input.consent.claim_record_id,
      verification_context: input.consent.verification_context,
    });
    if (registrationReplay.decision.state !== "active" ||
        consentReplay.decision.state !== "active" ||
        registrationReplay.semantic.namespace !== "heterodyne.oidc" ||
        registrationReplay.semantic.name !== "client-registration" ||
        consentReplay.semantic.namespace !== "heterodyne.oidc" || consentReplay.semantic.name !== "consent" ||
        registrationReplay.semantic.visibility !== "repository-private" ||
        consentReplay.semantic.visibility !== "repository-private" ||
        jcsCanonicalize(registrationReplay.semantic.subject) !== jcsCanonicalize(consentReplay.semantic.subject)) {
      return denied("oidc-client-unregistered");
    }
    const registration = validateRegisteredClientValue(registrationReplay.semantic.value);
    const consent = validateConsentValue(consentReplay.semantic.value);
    if (registration.client_id !== input.client_id || consent.client_id !== input.client_id) {
      return denied("oidc-client-unregistered");
    }
    const subject = jcsCanonicalize(registrationReplay.semantic.subject);
    const activeOidcClaims = activeCanonicalClaimSemanticsAt(input.state, Math.max(
      input.registration.verification_context.now,
      input.consent.verification_context.now,
    ))
      .filter((claim) => claim.namespace === "heterodyne.oidc" &&
        claim.visibility === "repository-private" && jcsCanonicalize(claim.subject) === subject);
    const registrationValues = activeOidcClaims
      .filter(({ name }) => name === "client-registration")
      .map(({ value }) => validateRegisteredClientValue(value))
      .filter(({ client_id }) => client_id === input.client_id)
      .map((value) => jcsCanonicalize(value));
    const consentValues = activeOidcClaims
      .filter(({ name }) => name === "consent")
      .map(({ value }) => validateConsentValue(value))
      .filter(({ client_id }) => client_id === input.client_id)
      .map((value) => jcsCanonicalize(value));
    if (new Set(registrationValues).size !== 1 || new Set(consentValues).size !== 1 ||
        registrationValues[0] !== jcsCanonicalize(registration) ||
        consentValues[0] !== jcsCanonicalize(consent)) {
      return denied("claim-repository-conflict");
    }
    if (!registration.grant_types.includes(input.grant_type) ||
        !((input.flow === "authorization_code" && input.grant_type === "authorization_code") ||
          (input.flow === "device_authorization" && input.grant_type === DEVICE_GRANT))) {
      return denied("oidc-grant-prohibited");
    }
    if (input.flow === "authorization_code" && (input.response_type !== "code" ||
        input.redirect_uri === undefined || !registration.redirect_uris.includes(input.redirect_uri) ||
        input.code_challenge_method !== "S256" || !canonicalPkceValue(input.code_challenge))) {
      return denied("oidc-grant-prohibited");
    }
    if (input.flow === "device_authorization" &&
        [input.response_type, input.redirect_uri, input.code_challenge, input.code_challenge_method]
          .some((value) => value !== undefined)) return denied("oidc-grant-prohibited");
    const scopes = exactIntersection(input.requested_scopes, registration.scopes, consent.scopes);
    const audience = exactIntersection(input.requested_audiences, registration.audiences, consent.audiences);
    const permittedClaims = new Set(exactIntersection(input.requested_claims, registration.claims, consent.claims));
    if (!scopes.includes("openid") || audience.length === 0) return denied("oidc-consent-required");
    const pairwise_sub = derivePairwiseSubject(
      jsonDigest(registrationReplay.semantic.subject), registration.sector_identifier, input.pairwise_secret,
    );
    if ((input.sender_constraint === "none") !== (input.cnf === undefined) ||
        (input.cnf !== undefined && !validConfirmation(input.cnf, input.sender_constraint))) {
      return denied("oidc-claim-release-denied");
    }
    const released_claims: Record<string, JsonValue> = {};
    const sourceClaimIds = [registrationReplay.semantic.claim_id, consentReplay.semantic.claim_id];
    const sourceRecordIds = [registrationReplay.record.record_id, consentReplay.record.record_id];
    for (const evidence of input.source_claims) {
      const replay = replayConfirmedClaimForAuthorization({
        state: input.state, claim_record_id: evidence.claim_record_id,
        verification_context: evidence.verification_context,
      });
      const semantic = replay.semantic;
      if (replay.decision.state !== "active" || semantic.visibility !== "repository-private" ||
          jcsCanonicalize(semantic.subject) !== jcsCanonicalize(registrationReplay.semantic.subject) ||
          evidence.verification_context.audience !== registrationReplay.record.persona ||
          evidence.verification_context.requested_namespace !== semantic.namespace ||
          !audience.includes(evidence.verification_context.resource)) return denied("oidc-claim-release-denied");
      const projectedName = semantic.namespace === "heterodyne.device" && semantic.name === "key-ref"
        ? KEY_REF_CLAIM : semantic.name;
      const requiredScope = projectedName === KEY_REF_CLAIM ? KEY_REF_SCOPE : semantic.namespace;
      if (!permittedClaims.has(projectedName) || !scopes.includes(requiredScope) ||
          !consent.source_claim_ids.includes(semantic.claim_id)) continue;
      if (Object.prototype.hasOwnProperty.call(released_claims, projectedName)) return denied("oidc-claim-release-denied");
      released_claims[projectedName] = semantic.value;
      sourceClaimIds.push(semantic.claim_id);
      sourceRecordIds.push(replay.record.record_id);
    }
    if (!consent.source_claim_ids.every((claimId) => sourceClaimIds.includes(claimId))) {
      return denied("oidc-claim-release-denied");
    }
    const releaseCore = {
      request_digest,
      registration_record_id: registrationReplay.record.record_id,
      consent_record_id: consentReplay.record.record_id,
      source_record_ids: uniqueSorted(sourceRecordIds), source_claim_ids: uniqueSorted(sourceClaimIds),
      pairwise_sub, scopes, audience, released_claims,
      assertion_profiles: [...(registration.assertion_profiles ?? [])].sort(),
      nonce: input.nonce,
      ...(input.cnf === undefined ? {} : { cnf: input.cnf }),
      sender_constraint: input.sender_constraint,
      checkpoint: canonicalCheckpoint,
      ...credentialLedger,
    };
    return { ...accepted(), ...releaseCore, release_digest: jsonDigest(releaseCore) };
  } catch {
    return denied("oidc-claim-release-denied");
  }
}

export async function authorizeAuthorizationRequestEffect<T>(
  authority: ClaimAuthorizationAuthority,
  input: Readonly<{
    request: OidcAuthorizationRequest;
    idempotency_key: string;
    purpose: OidcAuthorizationPurpose;
    projection_subtype: OidcProjectionSubtype | null;
    assertion_profile: string | null;
    authorization_validity_seconds: number;
    effect(
      release: OidcAuthorizationDecision,
      executionToken: string,
    ): ClaimEffectOutcome<T> | Promise<ClaimEffectOutcome<T>>;
  }>,
): Promise<OidcAuthorizationEffectResult<T>> {
  let captured: CapturedAuthorizationEffectInput<T>;
  try {
    captured = captureAuthorizationEffectInput(input);
  } catch {
    return Object.freeze({
      verdict: "reject" as const,
      allowed: false as const,
      state: "invalid" as const,
      reason_code: "oidc-claim-release-denied",
    });
  }
  const preparedRelease = validateAuthorizationRequest(captured.request);
  if (!completeAuthorizedRelease(preparedRelease) ||
      !purposeMatchesRequest(captured.purpose, captured.request)) return Object.freeze({
    verdict: "reject" as const,
    allowed: false as const,
    state: "invalid" as const,
    reason_code: preparedRelease.reason_code ?? "oidc-claim-release-denied",
  });
  let session: OidcAuthorizationSession;
  try {
    session = authorizationSession(authority, captured, preparedRelease);
  } catch {
    return Object.freeze({
      verdict: "reject" as const,
      allowed: false as const,
      state: "invalid" as const,
      reason_code: "oidc-claim-release-denied",
    });
  }
  let consent: ReturnType<typeof replayConfirmedClaimForAuthorization>;
  try {
    consent = replayConfirmedClaimForAuthorization({
      state: captured.request.state,
      claim_record_id: captured.request.consent.claim_record_id,
      verification_context: captured.request.consent.verification_context,
    });
  } catch {
    return Object.freeze({
      verdict: "reject" as const,
      allowed: false as const,
      state: "invalid" as const,
      reason_code: "oidc-claim-release-denied",
    });
  }
  if (consent.decision.state !== "active") {
    return Object.freeze({
      verdict: "reject" as const,
      allowed: false as const,
      state: consent.decision.state,
      reason_code: consent.decision.reason_code ?? "oidc-claim-release-denied",
    });
  }
  const verification = captured.request.consent.verification_context;
  let effectTime: AuthorizedReleaseRecord | undefined;
  const result = await authorizeClaimEffect(authority, {
    leaf: consent.verified_claim,
    chain: consent.chain,
    audience: verification.audience,
    resource: verification.resource,
    requested_namespace: verification.requested_namespace,
    operation: verification.requested_operation,
    nonce: verification.expected_nonce,
    subject_proof: verification.subject_proof,
    idempotency_key: captured.idempotency_key,
    effect_digest: jsonDigest({
      domain: "heterodyne-oidc-durable-release-effect-v1",
      request_digest: preparedRelease.request_digest,
      release_digest: preparedRelease.release_digest,
      purpose: captured.purpose,
      projection_subtype: captured.projection_subtype,
      assertion_profile: captured.assertion_profile,
      authorization_validity_seconds: captured.authorization_validity_seconds,
    }),
    current_effect_binding: (view) => {
      const currentRequest = authorizationRequestAtView(captured.request, view);
      const release = validateAuthorizationRequest(currentRequest);
      if (!completeAuthorizedRelease(release) || !releaseSourcesAreCurrent(release, view)) {
        throw new Error("oidc-claim-release-denied: current release evidence is incomplete");
      }
      const currentFingerprint = oidcCurrentViewFingerprint(view);
      if (session.authorized_at === undefined) {
        session.authorized_at = view.trusted_now;
        session.expires_at = view.trusted_now + captured.authorization_validity_seconds;
        session.view_fingerprint = currentFingerprint;
      }
      if (session.authorized_at === undefined || session.expires_at === undefined ||
          session.view_fingerprint === undefined ||
          view.trusted_now < session.authorized_at || view.trusted_now >= session.expires_at ||
          currentFingerprint !== session.view_fingerprint) {
        throw new Error("oidc-claim-release-denied: durable authorization is stale");
      }
      effectTime = {
        authority,
        effect_result: undefined as never,
        purpose: captured.purpose,
        projection_subtype: captured.projection_subtype,
        assertion_profile: captured.assertion_profile,
        idempotency_key: captured.idempotency_key,
        authorized_at: session.authorized_at,
        expires_at: session.expires_at,
        view_fingerprint: session.view_fingerprint,
        consumed: false,
        request: currentRequest,
        release: snapshotClosedDataTree(release, "OIDC effect-time release"),
      };
      return Object.freeze({
        request_digest: release.request_digest,
        release_digest: release.release_digest,
        purpose: captured.purpose,
        projection_subtype: captured.projection_subtype,
        assertion_profile: captured.assertion_profile,
        authorized_at: session.authorized_at,
        expires_at: session.expires_at,
        current_view_fingerprint: session.view_fingerprint,
      });
    },
    effect: (executionToken) => {
      if (effectTime === undefined) {
        throw new Error("oidc-claim-release-denied: effect-time release was not captured");
      }
      return captured.effect(effectTime.release, executionToken);
    },
  });
  if (result.verdict !== "accept") {
    if (result.verdict === "reject" &&
        (result.reason_code === "claim-release-denied" ||
          result.reason_code === "claim-issuer-authority-invalid")) {
      return Object.freeze({
        ...result,
        reason_code: "oidc-claim-release-denied",
      });
    }
    return result;
  }
  if (effectTime === undefined) return Object.freeze({
    verdict: "reject" as const,
    allowed: false as const,
    state: "invalid" as const,
    reason_code: "oidc-claim-release-denied",
  });
  const authorization = Object.freeze({}) as OidcAuthorizedRelease;
  effectTime.effect_result = result as ClaimEffectAuthorizationResult<unknown>;
  AUTHORIZED_RELEASES.set(authorization, effectTime);
  return Object.freeze({ ...result, authorization });
}

export function inspectOidcAuthorizedRelease(
  authorization: OidcAuthorizedRelease,
): OidcAuthorizationDecision {
  return snapshotClosedDataTree(
    requireAuthorizedRelease(authorization).release,
    "OIDC authorized release inspection",
  );
}

export function projectIdToken(input: JwtProjectionInput): ProjectedJwt {
  return project(input, "JWT", {});
}

export function projectAccessToken(input: JwtProjectionInput): ProjectedJwt {
  return project(input, "at+jwt", {});
}

export function projectJwtAssertion(
  input: JwtProjectionInput,
  assertionProfile: string,
): ProjectedJwt {
  return project(input, "heterodyne-assertion+jwt", { assertion_profile: assertionProfile });
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
        canonicalNpub(trustedRoot) !== trustedRoot) {
      return denied("oidc-issuer-mismatch");
    }
    const segments = jwt.split(".");
    if (segments.length !== 3 || segments.some((segment) => !/^[A-Za-z0-9_-]+$/.test(segment) ||
        base64url(fromBase64url(segment)) !== segment)) {
      return denied("oidc-token-type-invalid");
    }
    const header = parseSegment(segments[0]);
    const claims = parseSegment(segments[1]);
    if (!Object.prototype.hasOwnProperty.call(claims, "credential_ledger_generation")) {
      return denied("credential_generation_missing");
    }
    if (typeof claims.credential_ledger_persona !== "string" ||
        !/^[0-9a-f]{64}$/.test(claims.credential_ledger_persona) ||
        typeof claims.credential_ledger_generation !== "number" ||
        !Number.isSafeInteger(claims.credential_ledger_generation) ||
        claims.credential_ledger_generation < 0) {
      return denied("oidc-token-type-invalid");
    }
    if (!exactObjectKeys(header, ["alg", "kid", "typ"]) || header.alg !== "RS256" ||
        !canonicalSha256Base64url(header.kid)) return denied("oidc-token-type-invalid");
    const keysObject = asObject(jwks);
    if (keysObject === null || !exactObjectKeys(keysObject, ["keys"]) || !Array.isArray(keysObject.keys)) {
      return denied("oidc-token-type-invalid");
    }
    const keys = keysObject.keys;
    if (keys.length === 0 || !keys.every((candidate) => {
      const key = asObject(candidate);
      return key !== null && validPublicRsaJwk(key);
    })) return denied("oidc-token-type-invalid");
    const matching = keys.filter((candidate) => {
      const key = asObject(candidate);
      return key !== null && validPublicRsaJwk(key) && key.kid === header.kid;
    });
    if (matching.length !== 1) return denied("oidc-token-type-invalid");
    const publicKey = createPublicKey({ key: matching[0] as JsonWebKey, format: "jwk" });
    if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) return denied("oidc-token-type-invalid");
    if (!verify("RSA-SHA256", Buffer.from(`${segments[0]}.${segments[1]}`), publicKey, fromBase64url(segments[2]))) {
      return denied("oidc-token-type-invalid");
    }
    if (claims.iss !== expectedIssuer) return denied("oidc-issuer-mismatch");
    const generation = evaluateCredentialGeneration(claims, options.credential_ledger);
    if (!generation.valid) return denied(generation.reason_code);
    if ((options.token_use === "access_token" && header.typ !== "at+jwt") ||
        (options.token_use === "id_token" && header.typ !== "JWT") ||
        (options.token_use === "jwt_assertion" && header.typ !== "heterodyne-assertion+jwt")) {
      return denied("oidc-token-type-invalid");
    }
    const audiences = typeof claims.aud === "string" ? [claims.aud] : stringArray(claims.aud);
    const expectedAudiences = options.token_use === "id_token"
      ? [options.client_id]
      : uniqueSorted(options.permitted_audiences);
    if (jcsCanonicalize(audiences) !== jcsCanonicalize(expectedAudiences) ||
        !expectedAudiences.includes(expectedAudience)) return denied("oidc-audience-invalid");
    if (!Number.isSafeInteger(options.now) || options.now < 0 || options.client_id.length === 0) {
      return denied("oidc-token-type-invalid");
    }
    const now = options.now;
    const scopeTokens = typeof claims.scope === "string" ? claims.scope.split(" ") : [];
    if (!safeTime(claims.iat) || !safeTime(claims.exp) || Number(claims.iat) > now || Number(claims.exp) <= now ||
        !canonicalSha256Base64url(claims.sub) || typeof claims.jti !== "string" ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(claims.jti) || typeof claims.client_id !== "string" ||
        scopeTokens.length === 0 || scopeTokens.some((scope) => !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope)) ||
        jcsCanonicalize(scopeTokens) !== jcsCanonicalize(uniqueSorted(scopeTokens))) {
      return denied("oidc-token-type-invalid");
    }
    if (claims.client_id !== options.client_id) return denied("oidc-token-type-invalid");
    const expectedUse = options.token_use;
    if (expectedUse === "access_token" && header.typ !== "at+jwt") return denied("oidc-token-type-invalid");
    if (expectedUse === "id_token" && (
      header.typ !== "JWT"
      || typeof claims.nonce !== "string"
      || claims.nonce.length === 0
      || typeof options.nonce !== "string"
      || options.nonce.length === 0
      || claims.nonce !== options.nonce
    )) {
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

export function createValidatedProjectedJwtContext(
  jwt: string,
  expectedIssuer: string,
  expectedAudience: string,
  jwks: JsonValue,
  options: JwtValidationOptions,
): ValidatedProjectedJwtContext {
  const decision = validateProjectedJwt(jwt, expectedIssuer, expectedAudience, jwks, options);
  if (!decision.allowed) {
    throw new Error(`${decision.reason_code ?? "oidc-token-type-invalid"}: referenced JWT validation failed`);
  }
  const segments = jwt.split(".");
  const context: ValidatedProjectedJwtContext = Object.freeze({
    compact: jwt,
    claims: Object.freeze(parseSegment(segments[1])),
    validated_at: options.now,
    token_use: options.token_use,
  });
  VALIDATED_PROJECTED_JWTS.set(context, validatedContextFingerprint(context));
  return context;
}

export function assertValidatedProjectedJwtContext(
  context: ValidatedProjectedJwtContext,
): asserts context is ValidatedProjectedJwtContext {
  if (VALIDATED_PROJECTED_JWTS.get(context) !== validatedContextFingerprint(context)) {
    throw new Error("oidc-token-type-invalid: referenced JWT context was not fully validated");
  }
}

function validatedContextFingerprint(context: ValidatedProjectedJwtContext): string {
  return createHash("sha256").update(jcsCanonicalize({
    compact: context.compact,
    claims: context.claims,
    validated_at: context.validated_at,
    token_use: context.token_use,
  })).digest("hex");
}

function project(
  input: JwtProjectionInput,
  typ: "JWT" | "at+jwt" | "heterodyne-assertion+jwt",
  extraClaims: Record<string, JsonValue>,
): ProjectedJwt {
  const projectionSubtype: OidcProjectionSubtype = typ === "JWT"
    ? "id_token"
    : typ === "at+jwt"
      ? "access_token"
      : "jwt_assertion";
  const assertionProfile = projectionSubtype === "jwt_assertion" &&
      typeof extraClaims.assertion_profile === "string"
    ? extraClaims.assertion_profile
    : null;
  const { issuance, release, private_jwk, authorization } = validateProjectionInput(
    input,
    projectionSubtype,
    assertionProfile,
  );
  if (typ === "JWT") {
    if (typeof release.nonce !== "string" || release.nonce.length === 0) {
      throw new Error("oidc-token-type-invalid: signed authorization request nonce is required");
    }
    extraClaims = { ...extraClaims, nonce: release.nonce };
  }
  if (typ === "heterodyne-assertion+jwt" && (typeof extraClaims.assertion_profile !== "string" ||
      !release.assertion_profiles?.includes(extraClaims.assertion_profile))) {
    throw new Error("oidc-client-unregistered: JWT assertion profile is not signed in canonical registration");
  }
  const privateJwk = asObject(private_jwk);
  if (privateJwk === null || privateJwk.kty !== "RSA" || privateJwk.alg !== "RS256" ||
      privateJwk.use !== "sig" || typeof privateJwk.kid !== "string" || !canonicalSha256Base64url(privateJwk.kid) ||
      !Array.isArray(privateJwk.key_ops) || privateJwk.key_ops.length !== 1 || privateJwk.key_ops[0] !== "sign" ||
      typeof privateJwk.d !== "string") {
    throw new Error("RS256 private signing JWK with RFC 7638 kid is required");
  }
  if (privateJwk.kid !== issuance.signing_key_id || privateJwk.kid !== input.issuer_envelope.signing_key_id) {
    throw new Error("oidc-signing-key-unavailable: signing JWK does not match canonical issuance key");
  }
  const protected_header: Record<string, JsonValue> = { alg: "RS256", kid: privateJwk.kid, typ };
  const statusUri = `${input.issuer}/${issuance.reservation.uri}`;
  const claims: Record<string, JsonValue> = {
    iss: input.issuer,
    sub: input.pairwise_sub,
    aud: typ === "JWT" ? [input.client_id] : [...release.audience],
    exp: input.expires_at,
    iat: input.now,
    jti: issuance.jti,
    client_id: input.client_id,
    scope: uniqueSorted(input.scopes).join(" "),
    ...input.state.credential_ledger,
    ...release.released_claims,
    ...extraClaims,
    ...(release.cnf === undefined ? {} : { cnf: release.cnf }),
    [CHECKPOINT_CLAIM]: issuance.checkpoint,
    status: { status_list: { uri: statusUri, idx: issuance.reservation.idx } },
    [STATUS_MIRROR_CLAIM]: input.status_mirror,
  };
  for (const forbidden of ["source_claim_ids", "consent", "provenance", "ledger_contents", "reader_membership"]) {
    if (forbidden in claims) throw new Error("oidc-claim-release-denied: private ledger data cannot be projected");
  }
  const encodedHeader = base64url(Buffer.from(JSON.stringify(protected_header)));
  const encodedClaims = base64url(Buffer.from(JSON.stringify(claims)));
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const projectionDigest = exactProjectionInputDigest(
    input,
    issuance,
    release,
    projectionSubtype,
    assertionProfile,
  );
  return issuedGrant(authorization, "jwt-projection", projectionDigest, () => {
    const key = createPrivateKey({ key: privateJwk as JsonWebKey, format: "jwk" });
    if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw new Error("RS256 signing key must have a modulus of at least 2048 bits");
    }
    const signature = sign("RSA-SHA256", Buffer.from(signingInput), key);
    return {
      protected_header,
      claims,
      compact: `${signingInput}.${base64url(signature)}`,
    };
  });
}

function validateProjectionInput(
  input: JwtProjectionInput,
  projectionSubtype: OidcProjectionSubtype,
  assertionProfile: string | null,
): {
  issuance: IssuanceRecord;
  release: CompleteOidcAuthorizationRelease;
  private_jwk: JsonValue;
  authorization: AuthorizedReleaseRecord;
} {
  const consumed = consumeAuthorizedRelease(
    input.authorization_authority,
    input.authorization,
    "jwt_projection",
    projectionSubtype,
    assertionProfile,
  );
  const authorization = consumed.retained;
  const authorizationRequest = authorization.request;
  const currentCheckpoint = canonicalValidatedCheckpoint(input.state);
  const releaseCheckpoint = canonicalValidatedCheckpoint(authorizationRequest.state);
  const record = input.state.records.find(({ record_id }) => record_id === input.issuance_record_id);
  if (record?.record_type !== "issuance-reservation" ||
      !(input.state.repository_confirmed_record_ids ?? []).includes(input.issuance_record_id)) {
    throw new Error("oidc-token-type-invalid: canonical issuance record is absent");
  }
  const issuance = record.payload as unknown as IssuanceRecord;
  validateIssuanceRecordOrThrow(issuance, input.state.credential_ledger);
  const release = authorization.release;
  const mint = evaluateMintingAttempt({ now: input.now, manifest_max_age_seconds: issuance.manifest_max_age_seconds,
    writer_nid: input.issuer_writer_nid, state: authorizationRequest.state, envelope: input.issuer_envelope,
    audience_key: input.issuer_audience_key });
  const currentReturn = canReturnToken(
    input.issuance_record_id, input.state, input.issuer_envelope, input.issuer_audience_key,
  );
  if (!release.allowed || release.pairwise_sub === undefined || release.scopes === undefined ||
      release.audience === undefined || release.released_claims === undefined || release.source_claim_ids === undefined ||
      release.checkpoint === undefined || release.request_digest === undefined || release.release_digest === undefined ||
      !mint.allowed || !currentReturn.allowed) {
    throw new Error("oidc-token-type-invalid: evidence-derived authorization or minting failed");
  }
  const private_jwk = unwrapIssuerSigningJwk(input.issuer_envelope, input.issuer_writer_nid, input.issuer_audience_key);
  if (!Number.isSafeInteger(input.now) || !Number.isSafeInteger(input.expires_at) ||
      input.now !== issuance.issued_at || input.expires_at !== issuance.expires_at ||
      input.expires_at <= input.now || input.audience.length === 0 || input.scopes.length === 0 ||
      !input.scopes.every(nonempty) || !input.audience.every(exactHttpsResource) ||
      !nonempty(input.client_id) || input.client_id !== authorizationRequest.client_id ||
      !/^[A-Za-z0-9._~-]{16,255}$/.test(input.pairwise_sub) ||
      !validStatusMirror(input.status_mirror) || input.status_mirror.repository_rid !== issuance.checkpoint.repository_rid ||
      releaseCheckpoint.repository_rid !== issuance.checkpoint.repository_rid ||
      currentCheckpoint.repository_rid !== issuance.checkpoint.repository_rid ||
      input.issuer_envelope.repository_rid !== issuance.checkpoint.repository_rid ||
      record.persona !== input.state.credential_ledger.credential_ledger_persona ||
      record.credential_ledger_generation !== issuance.credential_ledger_generation ||
      input.issuer_envelope.persona !== input.state.credential_ledger.credential_ledger_persona ||
      input.issuer_envelope.credential_ledger_generation !== issuance.credential_ledger_generation ||
      release.pairwise_sub !== input.pairwise_sub ||
      issuance.client_id !== input.client_id ||
      issuance.authorization_request_digest !== release.request_digest ||
      issuance.release_digest !== release.release_digest ||
      jcsCanonicalize(release.scopes) !== jcsCanonicalize(uniqueSorted(input.scopes)) ||
      jcsCanonicalize(release.audience) !== jcsCanonicalize(uniqueSorted(input.audience)) ||
      jcsCanonicalize(release.source_claim_ids) !== jcsCanonicalize(uniqueSorted(issuance.source_claim_ids)) ||
      jcsCanonicalize(release.checkpoint) !== jcsCanonicalize(issuance.checkpoint)) {
    throw new Error("oidc-token-type-invalid: invalid JWT projection input");
  }
  const parsed = new URL(input.issuer);
  const root = parsed.pathname.startsWith("/oidc/") ? parsed.pathname.slice("/oidc/".length) : "";
  const decodedRoot = nip19.decode(root);
  const rootPersona = decodedRoot.type === "npub" && typeof decodedRoot.data === "string" ? decodedRoot.data : "";
  if (parsed.protocol !== "https:" || parsed.search !== "" || parsed.hash !== "" || parsed.pathname.endsWith("/") ||
      !validatePersonaBinding(root, input.identity).allowed ||
      issuerUrl(parsed.origin, root, input.identity) !== input.issuer || rootPersona !== input.issuer_envelope.persona ||
      input.state.records.some(({ persona }) => persona !== rootPersona) ||
      authorizationRequest.state.records.some(({ persona }) => persona !== rootPersona)) {
    throw new Error("oidc-issuer-mismatch: exact HTTPS issuer is required");
  }
  const expectedStatusPath = `.well-known/${root}/${issuance.reservation.uri}`;
  if (input.status_mirror.path !== expectedStatusPath) {
    throw new Error("oidc-token-type-invalid: status mirror does not bind issuance reservation");
  }
  const reserved = new Set([
    "iss", "sub", "aud", "exp", "iat", "jti", "client_id", "scope", "nonce", "cnf",
    "credential_ledger_persona", "credential_ledger_generation",
    "status", "assertion_profile", CHECKPOINT_CLAIM, STATUS_MIRROR_CLAIM,
    "source_claim_ids", "consent", "provenance", "ledger_contents", "reader_membership",
  ]);
  if (Object.keys(release.released_claims).some((claim) => reserved.has(claim))) {
    throw new Error("oidc-claim-release-denied: reserved or private claim cannot be projected");
  }
  if (Object.values(release.released_claims).some((value) => containsForbiddenField(value, reserved))) {
    throw new Error("oidc-claim-release-denied: private claim provenance cannot be projected");
  }
  return { issuance, release, private_jwk, authorization };
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
  const thumbprint = method === "dpop" ? value.jkt : value["x5t#S256"];
  return keys.length === 1 && ((method === "dpop" && keys[0] === "jkt") ||
    (method === "mtls" && keys[0] === "x5t#S256")) && canonicalSha256Base64url(thumbprint);
}

function canonicalSha256Base64url(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}

function canonicalPkceValue(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}

function captureAuthorizationEffectInput<T>(
  value: unknown,
): CapturedAuthorizationEffectInput<T> {
  const members = captureExactDataObject(value, [[
    "request",
    "idempotency_key",
    "purpose",
    "projection_subtype",
    "assertion_profile",
    "authorization_validity_seconds",
    "effect",
  ]], "OIDC authorization effect request");
  const idempotencyKey = members.idempotency_key;
  if (typeof idempotencyKey !== "string" || idempotencyKey.length === 0 || idempotencyKey.length > 4_096) {
    throw new Error("oidc-claim-release-denied: invalid idempotency key");
  }
  const effect = members.effect;
  if (typeof effect !== "function" || utilTypes.isProxy(effect)) {
    throw new Error("oidc-claim-release-denied: invalid effect callback");
  }
  if ((members.purpose !== "authorization_code" &&
      members.purpose !== "device_authorization" &&
      members.purpose !== "jwt_projection") ||
      !Number.isSafeInteger(members.authorization_validity_seconds) ||
      (members.authorization_validity_seconds as number) < 1 ||
      (members.authorization_validity_seconds as number) > 600) {
    throw new Error("oidc-claim-release-denied: invalid durable authorization purpose or validity");
  }
  const projectionSubtype = members.projection_subtype;
  const assertionProfile = members.assertion_profile;
  if ((projectionSubtype !== null && projectionSubtype !== "id_token" &&
      projectionSubtype !== "access_token" && projectionSubtype !== "jwt_assertion") ||
      (assertionProfile !== null && (typeof assertionProfile !== "string" || assertionProfile.length === 0 ||
        assertionProfile.length > 4_096)) ||
      (members.purpose === "jwt_projection") !== (projectionSubtype !== null) ||
      (projectionSubtype === "jwt_assertion") !== (assertionProfile !== null)) {
    throw new Error("oidc-claim-release-denied: invalid durable projection subtype");
  }
  return Object.freeze({
    request: captureAuthorizationRequest(members.request),
    idempotency_key: idempotencyKey,
    purpose: members.purpose,
    projection_subtype: projectionSubtype as OidcProjectionSubtype | null,
    assertion_profile: assertionProfile as string | null,
    authorization_validity_seconds: members.authorization_validity_seconds as number,
    effect: effect as CapturedAuthorizationEffectInput<T>["effect"],
  });
}

function captureAuthorizationRequest(value: unknown): OidcAuthorizationRequest {
  const required = [
    "flow", "grant_type", "client_id", "requested_scopes", "requested_audiences",
    "requested_claims", "pairwise_secret", "state", "registration", "consent",
    "source_claims", "nonce", "sender_constraint",
  ];
  const optional = ["response_type", "redirect_uri", "code_challenge", "code_challenge_method", "cnf"];
  const keySets = Array.from({ length: 1 << optional.length }, (_, mask) => [
    ...required,
    ...optional.filter((_, index) => (mask & (1 << index)) !== 0),
  ]);
  const members = captureExactDataObject(value, keySets, "OIDC authorization request");
  if (members.state === null || typeof members.state !== "object" || utilTypes.isProxy(members.state)) {
    throw new Error("OIDC authorization state must be an opaque local ledger result");
  }
  const registration = captureClaimEvidence(members.registration, "OIDC registration evidence");
  const consent = captureClaimEvidence(members.consent, "OIDC consent evidence");
  const sources = captureOrdinaryArray(members.source_claims, "OIDC source claims", 256)
    .map((entry, index) => captureClaimEvidence(entry, `OIDC source claim ${index}`));
  const stringArray = (member: unknown, label: string): string[] =>
    captureOrdinaryArray(member, label, 256).map((entry) => {
      if (typeof entry !== "string" || entry.length > 4_096) {
        throw new Error(`${label} must contain bounded strings`);
      }
      return entry;
    });
  return Object.freeze({
    flow: members.flow as OidcAuthorizationRequest["flow"],
    grant_type: members.grant_type as OidcAuthorizationRequest["grant_type"],
    ...(members.response_type === undefined ? {} : { response_type: members.response_type as "code" }),
    client_id: members.client_id as string,
    ...(members.redirect_uri === undefined ? {} : { redirect_uri: members.redirect_uri as string }),
    ...(members.code_challenge === undefined ? {} : { code_challenge: members.code_challenge as string }),
    ...(members.code_challenge_method === undefined ? {} : {
      code_challenge_method: members.code_challenge_method as "S256",
    }),
    requested_scopes: Object.freeze(stringArray(members.requested_scopes, "OIDC requested scopes")) as string[],
    requested_audiences: Object.freeze(stringArray(members.requested_audiences, "OIDC requested audiences")) as string[],
    requested_claims: Object.freeze(stringArray(members.requested_claims, "OIDC requested claims")) as string[],
    pairwise_secret: members.pairwise_secret as string,
    state: members.state as LedgerMergeResult,
    registration,
    consent,
    source_claims: Object.freeze(sources) as OidcClaimEvidence[],
    nonce: members.nonce as string,
    ...(members.cnf === undefined ? {} : {
      cnf: snapshotClosedDataTree(members.cnf, "OIDC confirmation") as Record<string, JsonValue>,
    }),
    sender_constraint: members.sender_constraint as OidcAuthorizationRequest["sender_constraint"],
  });
}

function captureClaimEvidence(value: unknown, label: string): OidcClaimEvidence {
  const members = captureExactDataObject(value, [[
    "claim_record_id",
    "verification_context",
  ]], label);
  if (typeof members.claim_record_id !== "string" || !/^[0-9a-f]{64}$/u.test(members.claim_record_id)) {
    throw new Error(`${label} has an invalid record ID`);
  }
  return Object.freeze({
    claim_record_id: members.claim_record_id,
    verification_context: captureClaimVerificationContext(members.verification_context),
  });
}

function captureClaimVerificationContext(value: unknown): ClaimVerificationContext {
  const members = captureExactDataObject(value, [[
    "now", "audience", "resource", "requested_namespace", "requested_operation",
    "expected_nonce", "used_nonces", "trusted_issuers", "credential_ledger",
    "repository_confirmed", "repository_conflicted", "revocations", "subject_proof",
  ]], "OIDC claim verification context");
  return Object.freeze({
    now: members.now as number,
    audience: members.audience as string,
    resource: members.resource as string,
    requested_namespace: members.requested_namespace as string,
    requested_operation: members.requested_operation as string,
    expected_nonce: members.expected_nonce as string,
    used_nonces: captureStringSet(members.used_nonces, "OIDC used nonces"),
    trusted_issuers: snapshotClosedDataTree(
      members.trusted_issuers,
      "OIDC trusted issuers",
    ) as ClaimVerificationContext["trusted_issuers"],
    credential_ledger: snapshotClosedDataTree(
      members.credential_ledger,
      "OIDC credential ledger",
    ) as ClaimVerificationContext["credential_ledger"],
    repository_confirmed: captureStringSet(
      members.repository_confirmed,
      "OIDC confirmed claims",
    ),
    repository_conflicted: captureStringSet(
      members.repository_conflicted,
      "OIDC conflicted claims",
    ),
    revocations: Object.freeze(captureOrdinaryArray(
      members.revocations,
      "OIDC revocations",
      256,
    )),
    subject_proof: members.subject_proof === null
      ? null
      : snapshotClosedDataTree(members.subject_proof, "OIDC subject proof") as NonNullable<
          ClaimVerificationContext["subject_proof"]
        >,
  });
}

function captureOrdinaryArray(value: unknown, label: string, maximum: number): unknown[] {
  if (!Array.isArray(value) || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw new Error(`${label} must be an ordinary array`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = Reflect.get(descriptors, "length") as PropertyDescriptor | undefined;
  const length = lengthDescriptor?.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum ||
      Reflect.ownKeys(descriptors).map(String).sort().join("\0") !==
        ["length", ...Array.from({ length }, (_, index) => String(index))].sort().join("\0")) {
    throw new Error(`${label} must be a bounded dense array`);
  }
  return Array.from({ length }, (_, index) => {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined || descriptor.enumerable !== true || !("value" in descriptor)) {
      throw new Error(`${label} must use data descriptors`);
    }
    return descriptor.value;
  });
}

function captureStringSet(value: unknown, label: string): Set<string> {
  if (value === null || typeof value !== "object" || utilTypes.isProxy(value) ||
      !(value instanceof Set) || Object.getPrototypeOf(value) !== Set.prototype || value.size > 256) {
    throw new Error(`${label} must be an ordinary bounded set`);
  }
  const captured = new Set<string>();
  for (const entry of Set.prototype.values.call(value) as SetIterator<unknown>) {
    if (typeof entry !== "string" || entry.length > 4_096) throw new Error(`${label} contains an invalid member`);
    captured.add(entry);
  }
  return captured;
}

function completeAuthorizedRelease(
  release: OidcAuthorizationDecision,
): release is CompleteOidcAuthorizationRelease {
  return release.allowed === true && release.state === "active" &&
    typeof release.pairwise_sub === "string" && Array.isArray(release.scopes) &&
    Array.isArray(release.audience) && release.released_claims !== undefined &&
    Array.isArray(release.source_claim_ids) && release.checkpoint !== undefined &&
    typeof release.request_digest === "string" && typeof release.release_digest === "string";
}

function releaseSourcesAreCurrent(
  release: CompleteOidcAuthorizationRelease,
  view: CurrentClaimEffectBindingView,
): boolean {
  const current = new Set(view.claims.map((artifact) => inspectVerifiedClaim(artifact).claim_id));
  return release.source_claim_ids.every((claimId) => current.has(claimId));
}

function authorizationRequestAtView(
  request: OidcAuthorizationRequest,
  view: CurrentClaimEffectBindingView,
): OidcAuthorizationRequest {
  const evidenceAtCurrentTime = (evidence: OidcClaimEvidence): OidcClaimEvidence => Object.freeze({
    claim_record_id: evidence.claim_record_id,
    verification_context: Object.freeze({
      ...evidence.verification_context,
      now: view.trusted_now,
    }),
  });
  return Object.freeze({
    ...request,
    state: view.ledger_state,
    registration: evidenceAtCurrentTime(request.registration),
    consent: evidenceAtCurrentTime(request.consent),
    source_claims: Object.freeze(request.source_claims.map(evidenceAtCurrentTime)) as OidcClaimEvidence[],
  });
}

function purposeMatchesRequest(
  purpose: OidcAuthorizationPurpose,
  request: OidcAuthorizationRequest,
): boolean {
  return purpose === "jwt_projection" ||
    (purpose === "authorization_code" && request.flow === "authorization_code") ||
    (purpose === "device_authorization" && request.flow === "device_authorization");
}

function authorizationSession<T>(
  authority: ClaimAuthorizationAuthority,
  input: CapturedAuthorizationEffectInput<T>,
  release: CompleteOidcAuthorizationRelease,
): OidcAuthorizationSession {
  let sessions = AUTHORIZATION_SESSIONS.get(authority);
  if (sessions === undefined) {
    sessions = new Map<string, OidcAuthorizationSession>();
    AUTHORIZATION_SESSIONS.set(authority, sessions);
  }
  const exactInputDigest = jsonDigest({
    purpose: input.purpose,
    projection_subtype: input.projection_subtype,
    assertion_profile: input.assertion_profile,
    authorization_validity_seconds: input.authorization_validity_seconds,
    request_digest: release.request_digest,
    release_digest: release.release_digest,
  });
  const existing = sessions.get(input.idempotency_key);
  if (existing !== undefined) {
    if (existing.exact_input_digest !== exactInputDigest) {
      throw new Error("oidc-claim-release-denied: idempotency binding conflict");
    }
    return existing;
  }
  const created: OidcAuthorizationSession = { exact_input_digest: exactInputDigest };
  sessions.set(input.idempotency_key, created);
  return created;
}

function oidcCurrentViewFingerprint(view: CurrentClaimEffectBindingView): string {
  return jsonDigest({
    credential_ledger: view.credential_ledger,
    checkpoint_digest: view.checkpoint_digest,
    repository_revision: view.repository_revision,
    claims: view.claims.map((artifact) => Object.freeze({
      claim_id: inspectVerifiedClaim(artifact).claim_id,
      binding_digest: claimArtifactBindingDigest(artifact),
    })).sort((left, right) => left.claim_id.localeCompare(right.claim_id)),
    revocations: view.revocations.map(claimRevocationArtifactBindingDigest).sort(),
    conflicted_claim_ids: [...view.conflicted_claim_ids].sort(),
  });
}

function exactProjectionInputDigest(
  input: JwtProjectionInput,
  issuance: IssuanceRecord,
  release: CompleteOidcAuthorizationRelease,
  projectionSubtype: OidcProjectionSubtype,
  assertionProfile: string | null,
): string {
  return jsonDigest({
    projection_subtype: projectionSubtype,
    assertion_profile: assertionProfile,
    issuer: input.issuer,
    client_id: input.client_id,
    audience: input.audience,
    pairwise_sub: input.pairwise_sub,
    scopes: input.scopes,
    now: input.now,
    expires_at: input.expires_at,
    issuance_record_id: input.issuance_record_id,
    current_checkpoint: canonicalValidatedCheckpoint(input.state),
    current_credential_ledger: input.state.credential_ledger,
    issuance,
    release,
    issuer_envelope: input.issuer_envelope,
    issuer_audience_key_digest: createHash("sha256")
      .update(input.issuer_audience_key)
      .digest("hex"),
    issuer_writer_nid: input.issuer_writer_nid,
    identity: input.identity,
    status_mirror: input.status_mirror,
  });
}

function consumeAuthorizedRelease(
  authority: ClaimAuthorizationAuthority,
  authorization: OidcAuthorizedRelease,
  purpose: OidcAuthorizationPurpose,
  projectionSubtype: OidcProjectionSubtype | null = null,
  assertionProfile: string | null = null,
): Readonly<{ retained: AuthorizedReleaseRecord; trusted_now: number }> {
  const retained = requireAuthorizedRelease(authorization);
  if (retained.consumed) {
    throw new Error("oidc-grant-prohibited: durable authorization already consumed");
  }
  retained.consumed = true;
  if (retained.authority !== authority || retained.purpose !== purpose ||
      retained.projection_subtype !== projectionSubtype ||
      retained.assertion_profile !== assertionProfile) {
    throw new Error("oidc-grant-prohibited: durable authorization authority or purpose mismatch");
  }
  const revalidated = revalidateAcceptedClaimEffect(authority, retained.effect_result);
  if (revalidated.verdict !== "accept" ||
      revalidated.trusted_now < retained.authorized_at ||
      revalidated.trusted_now >= retained.expires_at) {
    throw new Error("oidc-grant-prohibited: durable authorization is stale");
  }
  return Object.freeze({ retained, trusted_now: revalidated.trusted_now });
}

function issuedGrant<T>(
  retained: AuthorizedReleaseRecord,
  kind: string,
  exactInputDigest: string,
  issue: () => T,
): T {
  let grants = ISSUED_GRANTS.get(retained.authority);
  if (grants === undefined) {
    grants = new Map<string, unknown>();
    ISSUED_GRANTS.set(retained.authority, grants);
  }
  const key = jsonDigest({
    kind,
    purpose: retained.purpose,
    projection_subtype: retained.projection_subtype,
    assertion_profile: retained.assertion_profile,
    idempotency_key: retained.idempotency_key,
    authorized_at: retained.authorized_at,
    expires_at: retained.expires_at,
    view_fingerprint: retained.view_fingerprint,
    request_digest: retained.release.request_digest,
    release_digest: retained.release.release_digest,
  });
  const existing = grants.get(key) as Readonly<{ input_digest: string; output: T }> | undefined;
  if (existing !== undefined) {
    if (existing.input_digest !== exactInputDigest) {
      throw new Error("oidc-grant-prohibited: cached issuance input mismatch");
    }
    return existing.output;
  }
  const issued = snapshotClosedDataTree(issue(), "OIDC issued output") as T;
  grants.set(key, Object.freeze({ input_digest: exactInputDigest, output: issued }));
  return issued;
}

function requireAuthorizedRelease(authorization: unknown): AuthorizedReleaseRecord {
  if (authorization === null || typeof authorization !== "object" || utilTypes.isProxy(authorization)) {
    throw new Error("oidc-grant-prohibited: durable authorization is required");
  }
  const retained = AUTHORIZED_RELEASES.get(authorization);
  if (retained === undefined) {
    throw new Error("oidc-grant-prohibited: durable authorization is required");
  }
  return retained;
}

function jsonDigest(value: unknown): string {
  return createHash("sha256").update(jcsCanonicalize(value)).digest("hex");
}

function exactIntersection(...sets: string[][]): string[] {
  if (sets.some((values) => values.some((value) => typeof value !== "string" || value.length === 0) ||
      new Set(values).size !== values.length)) throw new Error("non-canonical set");
  const rest = sets.slice(1).map((values) => new Set(values));
  return uniqueSorted(sets[0].filter((value) => rest.every((set) => set.has(value))));
}

function validateRegisteredClientValue(value: JsonValue): RegisteredClient {
  const client = asObject(value);
  const expected = ["assertion_profiles", "audiences", "claims", "client_id", "grant_types", "redirect_uris", "scopes", "sector_identifier"];
  if (client === null || jcsCanonicalize(Object.keys(client).sort()) !== jcsCanonicalize(expected) ||
      !nonempty(String(client.client_id ?? "")) || !Array.isArray(client.redirect_uris) ||
      !Array.isArray(client.grant_types) || !Array.isArray(client.scopes) || !Array.isArray(client.audiences) ||
      !Array.isArray(client.claims) || !Array.isArray(client.assertion_profiles) ||
      ![client.redirect_uris, client.grant_types, client.scopes, client.audiences, client.claims, client.assertion_profiles]
        .every((values) => values.every((entry) => typeof entry === "string" && entry.length > 0) && new Set(values).size === values.length) ||
      typeof client.sector_identifier !== "string") throw new Error("client-registration");
  exactHttpsOrigin(client.sector_identifier);
  for (const redirect of client.redirect_uris) {
    if (typeof redirect !== "string" || !exactHttpsResource(redirect)) throw new Error("client-registration");
  }
  for (const audience of client.audiences) {
    if (typeof audience !== "string" || !exactHttpsResource(audience)) throw new Error("client-registration");
  }
  return client as unknown as RegisteredClient;
}

function validateConsentValue(value: JsonValue): {
  client_id: string; scopes: string[]; audiences: string[]; claims: string[]; source_claim_ids: string[];
} {
  const consent = asObject(value);
  const expected = ["audiences", "claims", "client_id", "scopes", "source_claim_ids"];
  if (consent === null || jcsCanonicalize(Object.keys(consent).sort()) !== jcsCanonicalize(expected) ||
      typeof consent.client_id !== "string" || !Array.isArray(consent.scopes) || !Array.isArray(consent.audiences) ||
      !Array.isArray(consent.claims) || !Array.isArray(consent.source_claim_ids) ||
      ![consent.scopes, consent.audiences, consent.claims, consent.source_claim_ids].every((values) =>
        values.every((entry) => typeof entry === "string" && entry.length > 0) && new Set(values).size === values.length) ||
      !consent.source_claim_ids.every((id) => typeof id === "string" && /^[0-9a-f]{64}$/.test(id))) throw new Error("consent");
  return consent as unknown as { client_id: string; scopes: string[]; audiences: string[]; claims: string[]; source_claim_ids: string[] };
}

function exactObjectKeys(value: Record<string, JsonValue>, keys: string[]): boolean {
  return jcsCanonicalize(Object.keys(value).sort()) === jcsCanonicalize([...keys].sort());
}

function validPublicRsaJwk(key: Record<string, JsonValue>): boolean {
  try {
    if (!exactObjectKeys(key, ["alg", "e", "key_ops", "kid", "kty", "n", "use"]) ||
        key.kty !== "RSA" || key.alg !== "RS256" || key.use !== "sig" ||
        !Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== "verify" ||
        typeof key.n !== "string" || typeof key.e !== "string" || !canonicalSha256Base64url(key.kid)) return false;
    for (const member of [key.n, key.e]) {
      if (!/^[A-Za-z0-9_-]+$/.test(member)) return false;
      const bytes = Buffer.from(member, "base64url");
      if (bytes.length === 0 || bytes.toString("base64url") !== member || (bytes.length > 1 && bytes[0] === 0)) return false;
    }
    const thumbprint = createHash("sha256")
      .update(jcsCanonicalize({ e: key.e, kty: "RSA", n: key.n }))
      .digest("base64url");
    if (key.kid !== thumbprint) return false;
    const publicKey = createPublicKey({ key: key as JsonWebKey, format: "jwk" });
    return (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048;
  } catch { return false; }
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
