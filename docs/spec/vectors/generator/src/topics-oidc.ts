import { nip19 } from "nostr-tools";
import type { JsonValue } from "./claims.js";
import type { IssuanceRecord } from "./claim-ledger.js";
import type { Fixtures } from "./fixtures.js";
import {
  discoveryPaths,
  derivePairwiseSubject,
  issuerMetadata,
  projectAccessToken,
  projectIdToken,
  projectJwtAssertion,
  validateAuthorizationRequest,
  validateIssuerMetadata,
  validateProjectedJwt,
  type IssuerMetadata,
  type JwtProjectionInput,
  type JwtValidationOptions,
  type RegisteredClient,
} from "./oidc.js";
import type { AuthoredVector } from "./types.js";
import { consumeVector } from "./vector-helpers.js";

const PRIVATE_JWK: JsonValue = {
  kty: "RSA",
  n: "zvh2fntchh51kVXPblIG2eeggjb0bya6jHF5xOsHTUhr8bi01jmbNjP29oPeFyoztGGKpndDxqt9qHvOL5x3euFKrm6kZywZ_XDVfdZVm7icnpybEmNdammqZcf97EIwOr_mczhRZ9QYK7SsSnBEQW1-BAs9dEHxNT39VqHjCq81uhzLKeemrpW4Kim_s4iYmoRoVkiPHghPhGo9CKXNXj2tGyDmj5hwuXa_gv5sZu5C7u0L9y4T25a-VHFVyUnCoa1yhyiT3teW3256KPmA6rBz1YhdLOCnwWDqIaBGOe4J6gkIODNCuCHwtI8JnX3gcRni_Pz19f3SNqtEJMvWjw",
  e: "AQAB",
  d: "P5h-BIBQXk-2rWkyG0JuI3-2RLyxIARE9wmZMoZLUJZrwLMSMe8yf5W5EWdUk0ae65K7QUpNU5r3OhGMufl4hxP52B5cOu2EsOj-WLPGy1oPGfeh-KT6m8uLFco9fl6aJjs4CvhnnyE_KhLSi-7yMi58Na7ke7gVb1g0Y23L70h4mOXAImpPwUp_0nfeAelfyMvGyzZ5uTBUNQM-AbtrnKBCXUwws-UjewFKiQsvQjw4nZgH17iVnbMFElWVT9sk2xOmDujDl8_Ewb9Zjd1azOH9eCjZkr_JAOHzfu85Cqix4Aqqp4B78_gU1qwq69QiKjdgHxHUB_8CxjLa3KzDZQ",
  p: "66Wvrwj9QlOEZJYqKz7IUS-15_Y807PqFMzOEobId5LHJyKsDNSfxp0EWW1LOQmBNnPwXJm9n9bHkQbCfTwheVehY9hX1sA7tesq7f5-5KdS8IDGe1qHE8no4iPfe83H8DM7YteFWF8gbR59IJpYfXRvTk9a7zjyGWGzuQBHKvs",
  q: "4Ni3kTJiJh6xOwFMhFH6LrBlB7006lWrUKyE2DMrDJuVJenUdKN_4jdjRS_IkRIPQC9Wv40hqz69J0XuxPSoVm5ns2Y46yHBzK8HmPB6ltg1AzYqsc4Pq4pBaB53WA4XdiG1mp7i_1l4MEb9u-72zsqvrJqkE__7w6XNNBR8bn0",
  dp: "dWtJ7137VGFpRvXMbWALUOkFK2B3TsYHjfW_eVvP6EUrF0UflgUc2ErFMApVwUYLLKb4ziuNYWgUaR-FKgIca-pOcQIMQuXm2u8jpRN7B1SY7147iJvDUwj5EjXt1jLjvbzJiqb5ut8ruTPIBcbi8SBjlhHUrf8iI6ObekO5MqE",
  dq: "nTbrI5sXBZBwW9GMrvii9gJgogip9y_vmXkHaiRc9XPT1a6p3uRzhrkzsCy5ELaP81EmVslXwWUc3VkImq53BfgsikPviHkSCQxZQ5biIJcMejJlp-1tB4SkNykWSXuQ7Ail8ncmQWVNpHP-9mkgKXePXiDCmTlj0GkeEkxAtQ",
  qi: "VKMYvlDjM_Egmzs2h1BDzQaiDHRfKWdBBB6KYqyIodnPbveXy3ZFJMdehBNEx3OJYzcEV501JyxUJBTvr9dCakZt-R5ZYrDrQLT3u-9P_Egblnn8HxBRBrrNkYbhdXQZovahuQEg3My6LxgwfMZGPgHyKLZZilBFVn4jnU-eVAY",
  kid: "11".repeat(32),
  alg: "RS256",
  use: "sig",
};

const PUBLIC_JWK: JsonValue = {
  kty: "RSA",
  n: (PRIVATE_JWK as Record<string, JsonValue>).n,
  e: "AQAB",
  kid: "11".repeat(32),
  alg: "RS256",
  use: "sig",
};

const CLIENT: RegisteredClient = {
  client_id: "registered-client",
  redirect_uris: ["https://client.example/cb"],
  grant_types: ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"],
  scopes: ["heterodyne:key-ref", "openid", "profile"],
  audiences: ["https://api.example"],
  assertion_profiles: ["urn:example:jwt-assertion:v1"],
  sector_identifier: "https://client.example",
};

type ReplayInput = Record<string, JsonValue>;

export function replayOidcVector(input: unknown): unknown {
  const spec = input as ReplayInput;
  const operation = String(spec.operation);
  if (operation === "discovery") {
    const origin = String(spec.origin);
    const root = String(spec.cold_root_npub);
    const metadata = issuerMetadata(origin, root);
    return {
      verdict: "accept",
      normalized: {
        paths: discoveryPaths(origin, root),
        metadata,
        metadata_validation: validateIssuerMetadata(metadata, metadata.issuer, metadata.jwks_uri),
      },
    };
  }
  if (operation === "metadata-validation") {
    const metadata = spec.metadata as unknown as IssuerMetadata;
    const decision = validateIssuerMetadata(metadata, String(spec.expected_issuer), String(spec.expected_jwks_uri));
    return decision.allowed ? { verdict: "accept", normalized: decision } :
      { verdict: "reject", reason_code: decision.reason_code, normalized: decision };
  }
  if (operation === "authorization") return authorizationResult(validateAuthorizationRequest(spec.request as Record<string, JsonValue>));
  if (operation === "authorization-cases") {
    const decisions = (spec.requests as JsonValue[]).map((request) => validateAuthorizationRequest(request as Record<string, JsonValue>));
    return { verdict: decisions.every(({ allowed }) => !allowed) ? "reject" : "accept", reason_code: "oidc-grant-prohibited", normalized: { decisions } };
  }
  if (operation === "jwt-validation") {
    const metadata = spec.metadata as unknown as IssuerMetadata;
    const metadataDecision = validateIssuerMetadata(metadata, String(spec.expected_issuer), String(spec.expected_jwks_uri));
    const decision = metadataDecision.allowed
      ? validateProjectedJwt(String(spec.compact), metadata.issuer, String(spec.expected_audience), spec.jwks!, spec.options as unknown as JwtValidationOptions)
      : metadataDecision;
    const decoded = decodeCompact(String(spec.compact));
    return decision.allowed
      ? { verdict: "accept", normalized: { metadata_validation: metadataDecision, jwt_validation: decision, ...decoded } }
      : { verdict: "reject", reason_code: decision.reason_code, normalized: { metadata_validation: metadataDecision, jwt_validation: decision, ...decoded } };
  }
  throw new Error(`unknown OIDC replay operation: ${operation}`);
}

export function buildOidcVectors(fixtures: Fixtures): AuthoredVector[] {
  const root = nip19.npubEncode(fixtures.personas.alice.cold_root.pubkey);
  const metadata = issuerMetadata("https://node.example", root);
  const now = fixtures.test_epoch + 5_000;
  const pairwiseSecret = "aa".repeat(32);
  const pairwiseSub = derivePairwiseSubject("persona-local-subject", CLIENT.sector_identifier, pairwiseSecret);
  const issuance: IssuanceRecord = {
    jti: "oidc-vector-jti-0001",
    reservation: {
      uri: "status-lists/20454/00112233445566778899aabbccddeeff/0.jwt",
      idx: 7,
      expiry_bucket: "20454",
      writer_nid_fingerprint: "00112233445566778899aabbccddeeff",
      list_sequence: 0,
    },
    checkpoint: {
      repository_rid: fixtures.radicle_rids.alice,
      branch: "main",
      commit_oid: "12".repeat(20),
      observed_at: now - 1,
    },
    manifest_max_age_seconds: 300,
    signing_key_id: "11".repeat(32),
    source_claim_ids: ["22".repeat(32)],
    issued_at: now,
    expires_at: now + 600,
  };
  const release = {
    allowed: true,
    state: "active" as const,
    reason_code: null,
    pairwise_sub: pairwiseSub,
    scopes: ["openid", "profile"],
    audience: ["https://api.example"],
    released_claims: { name: "Alice" },
    source_claim_ids: ["22".repeat(32)],
    checkpoint: issuance.checkpoint,
  };
  const projection = (cnf?: Record<string, JsonValue>): JwtProjectionInput => ({
    issuer: metadata.issuer,
    client_id: CLIENT.client_id,
    audience: ["https://api.example"],
    pairwise_sub: release.pairwise_sub,
    scopes: [...release.scopes],
    now,
    expires_at: issuance.expires_at,
    nonce: "oidc-vector-nonce",
    sender_constraint: cnf === undefined ? "none" : ("jkt" in cnf ? "dpop" : "mtls"),
    ...(cnf === undefined ? {} : { cnf }),
    issuance,
    released_claims: { ...release.released_claims },
    status_mirror: {
      repository_rid: fixtures.radicle_rids.alice,
      branch: "main",
      path: `.well-known/${root}/${issuance.reservation.uri}`,
      sha256: "33".repeat(32),
    },
    release_decision: release,
    mint_eligibility: { allowed: true, reason_code: null, checkpoint: issuance.checkpoint },
    historical_returnability: { allowed: true, state: "active", reason_code: null },
  });
  const request = (overrides: Record<string, JsonValue> = {}): Record<string, JsonValue> => ({
    flow: "authorization_code",
    grant_type: "authorization_code",
    response_type: "code",
    client_id: CLIENT.client_id,
    registration: CLIENT as unknown as JsonValue,
    registration_status: "active",
    redirect_uri: CLIENT.redirect_uris[0],
    code_challenge: "Wz4aL3h4c3Nad0JzV2k1NVJiUU1JQjRXM1c4SjJVUGV5TQ",
    code_challenge_method: "S256",
    requested_scopes: ["openid", "profile", "heterodyne:key-ref"],
    requested_audiences: ["https://api.example"],
    consented_scopes: ["openid", "profile"],
    consented_audiences: ["https://api.example"],
    consented_claims: ["name"],
    trusted_namespaces: ["profile"],
    pairwise_subject_context: {
      local_subject: "persona-local-subject",
      sector_identifier: CLIENT.sector_identifier,
      secret: pairwiseSecret,
    },
    pairwise_sub: release.pairwise_sub,
    canonical_claim_state: true,
    ledger_checkpoint: issuance.checkpoint as unknown as JsonValue,
    active_claims: [
      { claim_id: "22".repeat(32), namespace: "profile", name: "name", value: "Alice", state: "active", repository_confirmed: true, issuer_trusted: true, subject_proof_valid: true },
      { claim_id: "23".repeat(32), namespace: "internal", name: "private-provenance", value: "never-release", state: "active", repository_confirmed: true, issuer_trusted: true, subject_proof_valid: true },
    ],
    ...overrides,
  });
  const publicMaterial = { metadata, jwks: { keys: [PUBLIC_JWK] } } as const;
  const id = projectIdToken(projection(), PRIVATE_JWK);
  const access = projectAccessToken({ ...projection(), nonce: undefined }, PRIVATE_JWK);
  const dpopThumbprint = "Q".repeat(43);
  const mtlsThumbprint = "R".repeat(43);
  const dpop = projectAccessToken({ ...projection({ jkt: dpopThumbprint }), nonce: undefined }, PRIVATE_JWK);
  const mtls = projectAccessToken({ ...projection({ "x5t#S256": mtlsThumbprint }), nonce: undefined }, PRIVATE_JWK);
  const assertion = projectJwtAssertion({ ...projection(), nonce: undefined }, PRIVATE_JWK, "urn:example:jwt-assertion:v1", CLIENT);

  const jwtInput = (token: typeof id, options: JwtValidationOptions): ReplayInput => ({
    operation: "jwt-validation",
    metadata: publicMaterial.metadata as unknown as JsonValue,
    jwks: publicMaterial.jwks as unknown as JsonValue,
    compact: token.compact,
    expected_audience: options.token_use === "id_token" ? CLIENT.client_id : "https://api.example",
    expected_issuer: metadata.issuer,
    expected_jwks_uri: metadata.jwks_uri,
    options: options as unknown as JsonValue,
  });
  const authored = (path: string, vector_id: string, description: string, input: ReplayInput): AuthoredVector => {
    const expected = replayOidcVector(input) as Record<string, JsonValue>;
    return consumeVector(`oidc/${path}`, {
      vector_id: `oidc/${vector_id}`,
      spec_refs: ["heterodyne:comms/0.5.0#comms-conformance"],
      description,
      input,
      expected_output: expected,
    });
  };

  const mismatchInput: ReplayInput = {
    operation: "metadata-validation",
    metadata: { ...metadata, issuer: `${metadata.issuer}/` } as unknown as JsonValue,
    expected_issuer: metadata.issuer,
    expected_jwks_uri: metadata.jwks_uri,
  };
  const deviceRequest = request({
    flow: "device_authorization",
    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
    response_type: null,
    redirect_uri: null,
    code_challenge: null,
    code_challenge_method: null,
  });
  const prohibited = ["implicit", "password", "client_credentials"].map((grant_type) => request({ grant_type }));
  const keyClaim = { claim_id: "24".repeat(32), namespace: "heterodyne.device", name: "key-ref", value: "nostr:device-key", state: "active", repository_confirmed: true, issuer_trusted: true, subject_proof_valid: true };
  const keyRequest = request({
    consented_scopes: ["heterodyne:key-ref", "openid", "profile"],
    consented_claims: ["https://heterodyne.network/jwt/key-ref", "name"],
    trusted_namespaces: ["heterodyne.device", "profile"],
    active_claims: [...request().active_claims as JsonValue[], keyClaim],
  });
  const common = { now, client_id: CLIENT.client_id };
  return [
    authored("001-discovery-exact-issuer.json", "discovery-exact-issuer", "The immutable lowercase cold-root npub produces the exact issuer, OIDC discovery path, RFC 8414 alias, and RS256 metadata.", { operation: "discovery", origin: "https://node.example", cold_root_npub: root }),
    authored("002-issuer-mismatch-rejected.json", "issuer-mismatch-rejected", "A trailing-slash issuer alias is rejected even when every other discovery member is unchanged.", mismatchInput),
    authored("003-authorization-code-pkce.json", "authorization-code-pkce", "A registered Authorization Code client with exact redirect URI and S256 PKCE receives only the consented intersection.", { operation: "authorization", request: request() }),
    authored("004-device-authorization.json", "device-authorization", "A registered RFC 8628 device-code client receives the same minimized pairwise release without browser redirect or PKCE fields.", { operation: "authorization", request: deviceRequest }),
    authored("005-prohibited-grants.json", "prohibited-grants", "Implicit, password, and Client Credentials grants are each prohibited for persona authentication.", { operation: "authorization-cases", requests: prohibited }),
    authored("006-pairwise-subject.json", "pairwise-subject", "The accepted release uses a registration-bound pairwise subject and does not expose a persona or key identifier as sub.", { operation: "authorization", request: request() }),
    authored("007-stable-key-consent-gated.json", "stable-key-consent-gated", "The stable key reference is released only at the intersection of requested and registered scope, explicit consent, trusted namespace, active state, and proof of possession.", { operation: "authorization", request: keyRequest }),
    authored("008-id-token-valid.json", "id-token-valid", "A deterministic RS256 OIDC ID Token validates from exact HTTPS discovery and public JWKS with nonce, time, audience, client, checkpoint, and status bindings.", jwtInput(id, { ...common, token_use: "id_token", nonce: "oidc-vector-nonce", sender_constraint: "none" })),
    authored("009-rfc9068-access-token-valid.json", "rfc9068-access-token-valid", "A deterministic RFC 9068 RS256 access token uses typ at+jwt and validates using only exact HTTPS discovery and public JWKS.", jwtInput(access, { ...common, token_use: "access_token", sender_constraint: "none" })),
    authored("010-token-type-confusion-rejected.json", "token-type-confusion-rejected", "A valid at+jwt presented to the ID Token validator is rejected before its claims can be confused with an ID Token.", jwtInput(access, { ...common, token_use: "id_token", nonce: "oidc-vector-nonce", sender_constraint: "none" })),
    authored("011-dpop-confirmation-bound.json", "dpop-confirmation-bound", "An RFC 9449 sender-constrained access token validates only with the exact registered DPoP JWK thumbprint confirmation.", jwtInput(dpop, { ...common, token_use: "access_token", cnf: { jkt: dpopThumbprint }, sender_constraint: "dpop" })),
    authored("012-registered-jwt-assertion.json", "registered-jwt-assertion", "A signed JWT assertion is type-separated and accepted only under its separately registered assertion profile.", jwtInput(assertion, { ...common, token_use: "jwt_assertion", assertion_profile: "urn:example:jwt-assertion:v1", sender_constraint: "none" })),
    authored("013-mtls-confirmation-bound.json", "mtls-confirmation-bound", "An RFC 8705 sender-constrained access token validates only with the exact mutual-TLS certificate thumbprint confirmation.", jwtInput(mtls, { ...common, token_use: "access_token", cnf: { "x5t#S256": mtlsThumbprint }, sender_constraint: "mtls" })),
  ];
}

function authorizationResult(decision: ReturnType<typeof validateAuthorizationRequest>): Record<string, JsonValue> {
  return decision.allowed
    ? { verdict: "accept", normalized: decision as unknown as JsonValue }
    : { verdict: "reject", reason_code: decision.reason_code, normalized: decision as unknown as JsonValue };
}

function decodeCompact(compact: string): { protected_header: JsonValue; claims: JsonValue } {
  const [header, payload] = compact.split(".");
  return {
    protected_header: JSON.parse(Buffer.from(header, "base64url").toString("utf8")) as JsonValue,
    claims: JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as JsonValue,
  };
}
