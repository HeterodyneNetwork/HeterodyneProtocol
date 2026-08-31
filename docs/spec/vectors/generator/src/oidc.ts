import { createHash, createHmac, createPrivateKey, createPublicKey, sign, verify, type JsonWebKey } from "node:crypto";
import { nip19 } from "nostr-tools";
import type { AuthorizationDecision, ClaimVerificationContext, JsonValue } from "./claims.js";
import {
  authorizeClaimEffect,
  type ClaimAuthorizationAuthority,
  type ClaimEffectAuthorizationResult,
  type ClaimEffectOutcome,
} from "./claim-authorization.js";
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
  authorization_request: OidcAuthorizationRequest;
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
  request: OidcAuthorizationRequest,
  now: number,
  lifetimeSeconds = 300,
): AuthorizationCodeRecord {
  const decision = validateAuthorizationRequest(request);
  if (!decision.allowed || decision.release_digest === undefined || request.flow !== "authorization_code" ||
      request.redirect_uri === undefined || !canonicalPkceValue(request.code_challenge) ||
      !Number.isSafeInteger(now) || !Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > 600) {
    throw new Error("oidc-grant-prohibited: authorization code prerequisites failed");
  }
  const core = { ...request.state.credential_ledger,
    client_id: request.client_id, redirect_uri: request.redirect_uri,
    code_challenge: request.code_challenge, issued_at: now, expires_at: now + lifetimeSeconds,
    release_digest: decision.release_digest };
  return { code: createHash("sha256").update(`heterodyne-authorization-code-v1\0${jcsCanonicalize(core)}`).digest("base64url"), ...core };
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
  request: OidcAuthorizationRequest,
  now: number,
  lifetimeSeconds = 600,
  interval = 5,
): DeviceAuthorizationRecord {
  const decision = validateAuthorizationRequest(request);
  if (!decision.allowed || decision.release_digest === undefined || request.flow !== "device_authorization" ||
      !Number.isSafeInteger(now) || !Number.isSafeInteger(lifetimeSeconds) || lifetimeSeconds < 1 ||
      !Number.isSafeInteger(interval) || interval < 1) throw new Error("oidc-grant-prohibited: device authorization prerequisites failed");
  const core = { ...request.state.credential_ledger,
    client_id: request.client_id, scopes: uniqueSorted(decision.scopes ?? []), issued_at: now,
    expires_at: now + lifetimeSeconds, interval, release_digest: decision.release_digest };
  const digest = createHash("sha256").update(`heterodyne-device-code-v1\0${jcsCanonicalize(core)}`).digest();
  return { device_code: digest.toString("base64url"), user_code: digest.subarray(0, 5).toString("hex").toUpperCase(),
    ...core, last_poll_at: null, status: "pending" };
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
    effect_digest: string;
    effect(
      release: OidcAuthorizationDecision,
      executionToken: string,
    ): ClaimEffectOutcome<T> | Promise<ClaimEffectOutcome<T>>;
  }>,
): Promise<ClaimEffectAuthorizationResult<T>> {
  const release = validateAuthorizationRequest(input.request);
  if (!release.allowed) {
    return Object.freeze({
      verdict: "reject" as const,
      allowed: false as const,
      state: "invalid" as const,
      reason_code: release.reason_code ?? "oidc-claim-release-denied",
    });
  }
  let consent: ReturnType<typeof replayConfirmedClaimForAuthorization>;
  try {
    consent = replayConfirmedClaimForAuthorization({
      state: input.request.state,
      claim_record_id: input.request.consent.claim_record_id,
      verification_context: input.request.consent.verification_context,
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
  const verification = input.request.consent.verification_context;
  return authorizeClaimEffect(authority, {
    leaf: consent.verified_claim,
    chain: consent.chain,
    audience: verification.audience,
    resource: verification.resource,
    requested_namespace: verification.requested_namespace,
    operation: verification.requested_operation,
    nonce: verification.expected_nonce,
    subject_proof: verification.subject_proof,
    idempotency_key: input.idempotency_key,
    effect_digest: input.effect_digest,
    effect: (executionToken) => input.effect(release, executionToken),
  });
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
  const { issuance, release, private_jwk } = validateProjectionInput(input);
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
  const key = createPrivateKey({ key: privateJwk as JsonWebKey, format: "jwk" });
  if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new Error("RS256 signing key must have a modulus of at least 2048 bits");
  }
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), key);
  return { protected_header, claims, compact: `${signingInput}.${base64url(signature)}` };
}

function validateProjectionInput(input: JwtProjectionInput): {
  issuance: IssuanceRecord;
  release: OidcAuthorizationDecision & Required<Pick<OidcAuthorizationDecision, "pairwise_sub" | "scopes" | "audience" | "released_claims" | "source_claim_ids" | "checkpoint">>;
  private_jwk: JsonValue;
} {
  const currentCheckpoint = canonicalValidatedCheckpoint(input.state);
  const releaseCheckpoint = canonicalValidatedCheckpoint(input.authorization_request.state);
  const record = input.state.records.find(({ record_id }) => record_id === input.issuance_record_id);
  if (record?.record_type !== "issuance-reservation" ||
      !(input.state.repository_confirmed_record_ids ?? []).includes(input.issuance_record_id)) {
    throw new Error("oidc-token-type-invalid: canonical issuance record is absent");
  }
  const issuance = record.payload as unknown as IssuanceRecord;
  validateIssuanceRecordOrThrow(issuance, input.state.credential_ledger);
  const release = validateAuthorizationRequest(input.authorization_request);
  const mint = evaluateMintingAttempt({ now: input.now, manifest_max_age_seconds: issuance.manifest_max_age_seconds,
    writer_nid: input.issuer_writer_nid, state: input.authorization_request.state, envelope: input.issuer_envelope,
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
      !nonempty(input.client_id) || input.client_id !== input.authorization_request.client_id ||
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
      input.authorization_request.state.records.some(({ persona }) => persona !== rootPersona)) {
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
  return { issuance, release: release as never, private_jwk };
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
