import { generateKeyPairSync } from "node:crypto";
import { nip19 } from "nostr-tools";
import { describe, expect, it } from "vitest";
import {
  discoveryPaths,
  issuerMetadata,
  issuerUrl,
  projectAccessToken,
  projectIdToken,
  projectJwtAssertion,
  validateAuthorizationRequest,
  validateIssuerMetadata,
  validateProjectedJwt,
  validateColdRootBinding,
  derivePairwiseSubject,
  type JwtProjectionInput,
} from "./oidc.js";
import type { IssuanceRecord } from "./claim-ledger.js";
import type { JsonValue } from "./claims.js";
import { validateOidcIssuerMetadataSchemaOrThrow } from "./schema.js";
import { buildFixtures } from "./fixtures.js";
import { buildOidcVectors, replayOidcVector } from "./topics-oidc.js";

const now = 1_767_227_600;
const rootHex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const root = nip19.npubEncode(rootHex);
const issuer = `https://node.example/oidc/${root}`;
const pairwiseSecret = "aa".repeat(32);
const pairwiseSub = derivePairwiseSubject("persona-local-subject", "https://client.example", pairwiseSecret);
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateJwk = { ...privateKey.export({ format: "jwk" }), kid: "11".repeat(32), alg: "RS256", use: "sig" };
const publicJwk = { ...publicKey.export({ format: "jwk" }), kid: privateJwk.kid, alg: "RS256", use: "sig" };
const jwks = { keys: [publicJwk] };
const issuance: IssuanceRecord = {
  jti: "deterministic-jti-0001",
  reservation: {
    uri: "status-lists/20454/00112233445566778899aabbccddeeff/0.jwt",
    idx: 7,
    expiry_bucket: "20454",
    writer_nid_fingerprint: "00112233445566778899aabbccddeeff",
    list_sequence: 0,
  },
  checkpoint: {
    repository_rid: "rad:z2TJoDAhK5pTmLzqmK9W4FMdtjyy1",
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

const projection = (overrides: Partial<JwtProjectionInput> = {}): JwtProjectionInput => ({
  issuer,
  client_id: "registered-client",
  audience: ["https://api.example"],
  pairwise_sub: pairwiseSub,
  scopes: ["openid", "profile"],
  now,
  expires_at: now + 600,
  nonce: "nonce-123",
  sender_constraint: "none",
  issuance,
  released_claims: { name: "Alice" },
  status_mirror: {
    repository_rid: issuance.checkpoint.repository_rid,
    branch: "main",
    path: `.well-known/${root}/${issuance.reservation.uri}`,
    sha256: "33".repeat(32),
  },
  release_decision: {
    allowed: true,
    state: "active",
    reason_code: null,
    pairwise_sub: pairwiseSub,
    scopes: ["openid", "profile"],
    audience: ["https://api.example"],
    released_claims: { name: "Alice" },
    source_claim_ids: ["22".repeat(32)],
    checkpoint: issuance.checkpoint,
  },
  mint_eligibility: { allowed: true, reason_code: null, checkpoint: issuance.checkpoint },
  historical_returnability: { allowed: true, state: "active", reason_code: null },
  ...overrides,
});

describe("exact persona issuer identity and metadata", () => {
  it("uses one canonical lowercase cold-root npub at both discovery paths", () => {
    expect(issuerUrl("https://node.example", root)).toBe(issuer);
    expect(discoveryPaths("https://node.example", root)).toEqual({
      issuer,
      oidc_discovery: `${issuer}/.well-known/openid-configuration`,
      rfc8414_alias: `https://node.example/.well-known/oauth-authorization-server/oidc/${root}`,
    });
    const metadata = issuerMetadata("https://node.example", root);
    expect(() => validateOidcIssuerMetadataSchemaOrThrow(metadata)).not.toThrow();
    expect(metadata.issuer).toBe(issuer);
    expect(metadata.jwks_uri).toBe(`${issuer}/.well-known/jwks.json`);
    expect(validateIssuerMetadata(metadata, issuer, metadata.jwks_uri)).toMatchObject({ allowed: true });
    expect(issuerMetadata("https://node.example", root, ["EdDSA", "ES256"]).id_token_signing_alg_values_supported)
      .toEqual(["RS256", "ES256", "EdDSA"]);
  });

  it.each([
    ["http origin", "http://node.example", root],
    ["origin path", "https://node.example/a/../", root],
    ["origin query", "https://node.example?alias=1", root],
    ["trailing slash alias", "https://node.example/", root],
    ["uppercase bech32", "https://node.example", root.toUpperCase()],
    ["raw mutable epoch key", "https://node.example", rootHex],
    ["invalid bech32", "https://node.example", `${root.slice(0, -1)}x`],
  ])("rejects %s", (_label, origin, identity) => {
    expect(() => issuerUrl(origin, identity)).toThrow(/issuer|cold-root|npub/i);
  });

  it("rejects a valid mutable epoch npub against authenticated cold-root identity state", () => {
    const epoch = nip19.npubEncode("c6047f9441ed7d6d3045406e95c07cd85a93111a0b3c7e18c6db91cc5a5c39f8");
    expect(validateColdRootBinding(root, { cold_root_npub: root, epoch_npubs: [epoch] })).toMatchObject({ allowed: true });
    expect(validateColdRootBinding(epoch, { cold_root_npub: root, epoch_npubs: [epoch] })).toMatchObject({
      allowed: false, reason_code: "oidc-issuer-mismatch",
    });
  });

  it("rejects issuer and JWKS aliases byte-exactly", () => {
    const metadata = issuerMetadata("https://node.example", root);
    expect(validateIssuerMetadata({ ...metadata, issuer: `${issuer}/` }, issuer, metadata.jwks_uri)).toMatchObject({
      allowed: false,
      reason_code: "oidc-issuer-mismatch",
    });
    expect(validateIssuerMetadata(metadata, issuer, `${metadata.jwks_uri}/`)).toMatchObject({
      allowed: false,
      reason_code: "oidc-issuer-mismatch",
    });
    expect(validateIssuerMetadata({ ...metadata, token_endpoint: `${issuer}/token-alias` }, issuer, metadata.jwks_uri))
      .toMatchObject({ allowed: false, reason_code: "oidc-issuer-mismatch" });
  });
});

describe("authored OIDC conformance corpus", () => {
  it("contains exactly 13 public-input, deterministic, replayable vectors", () => {
    const vectors = buildOidcVectors(buildFixtures());
    expect(vectors).toHaveLength(13);
    expect(vectors.map(({ relativePath }) => relativePath)).toEqual([
      "oidc/001-discovery-exact-issuer.json",
      "oidc/002-issuer-mismatch-rejected.json",
      "oidc/003-authorization-code-pkce.json",
      "oidc/004-device-authorization.json",
      "oidc/005-prohibited-grants.json",
      "oidc/006-pairwise-subject.json",
      "oidc/007-stable-key-consent-gated.json",
      "oidc/008-id-token-valid.json",
      "oidc/009-rfc9068-access-token-valid.json",
      "oidc/010-token-type-confusion-rejected.json",
      "oidc/011-dpop-confirmation-bound.json",
      "oidc/012-registered-jwt-assertion.json",
      "oidc/013-mtls-confirmation-bound.json",
    ]);
    for (const { vector } of vectors) {
      expect(replayOidcVector(vector.input)).toEqual(vector.expected_output);
      expect(JSON.stringify(vector)).not.toContain('"d":"');
    }
  });

  it("rejects a bit-changed authored JWT without private or ledger inputs", () => {
    const vector = buildOidcVectors(buildFixtures())[7].vector;
    const compact = String(vector.input.compact);
    const mutated = { ...vector.input, compact: `${compact.slice(0, -2)}AA` };
    expect(replayOidcVector(mutated)).toMatchObject({ verdict: "reject", reason_code: "oidc-token-type-invalid" });
  });
});

const registration = {
  client_id: "registered-client",
  redirect_uris: ["https://client.example/cb"],
  grant_types: ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"],
  scopes: ["openid", "profile", "heterodyne:key-ref"],
  audiences: ["https://api.example"],
  assertion_profiles: ["urn:example:jwt-assertion:v1"],
  sector_identifier: "https://client.example",
};

const authorization = (overrides: Record<string, unknown> = {}) => ({
  flow: "authorization_code",
  grant_type: "authorization_code",
  response_type: "code",
  client_id: registration.client_id,
  registration,
  registration_status: "active",
  redirect_uri: registration.redirect_uris[0],
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
    sector_identifier: "https://client.example",
    secret: pairwiseSecret,
  },
  pairwise_sub: pairwiseSub,
  canonical_claim_state: true,
  ledger_checkpoint: issuance.checkpoint,
  active_claims: [
    { claim_id: "22".repeat(32), namespace: "profile", name: "name", value: "Alice", state: "active", repository_confirmed: true, issuer_trusted: true, subject_proof_valid: true },
    { claim_id: "23".repeat(32), namespace: "internal", name: "ledger", value: "secret", state: "active", repository_confirmed: true, issuer_trusted: true, subject_proof_valid: true },
  ],
  ...overrides,
});

describe("registered OAuth flows and minimized release", () => {
  it("accepts authorization code only with exact registration and S256 PKCE", () => {
    expect(validateAuthorizationRequest(authorization())).toEqual({
      allowed: true,
      state: "active",
      reason_code: null,
      pairwise_sub: pairwiseSub,
      scopes: ["openid", "profile"],
      audience: ["https://api.example"],
      released_claims: { name: "Alice" },
      source_claim_ids: ["22".repeat(32)],
      checkpoint: issuance.checkpoint,
    });
  });

  it("accepts RFC 8628 Device Authorization under explicit registration", () => {
    expect(validateAuthorizationRequest(authorization({
      flow: "device_authorization",
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      response_type: undefined,
      redirect_uri: undefined,
      code_challenge: undefined,
      code_challenge_method: undefined,
    }))).toMatchObject({ allowed: true, pairwise_sub: pairwiseSub });
  });

  it.each(["implicit", "password", "client_credentials"])("rejects prohibited %s grant", (grant_type) => {
    expect(validateAuthorizationRequest(authorization({ grant_type }))).toMatchObject({
      allowed: false,
      reason_code: "oidc-grant-prohibited",
    });
  });

  it("rejects unregistered clients and plain or missing PKCE", () => {
    expect(validateAuthorizationRequest(authorization({ registration: undefined }))).toMatchObject({
      allowed: false, reason_code: "oidc-client-unregistered",
    });
    expect(validateAuthorizationRequest(authorization({ registration_status: "pending" }))).toMatchObject({
      allowed: false, reason_code: "oidc-client-unregistered",
    });
    expect(validateAuthorizationRequest(authorization({ code_challenge_method: "plain" }))).toMatchObject({
      allowed: false, reason_code: "oidc-grant-prohibited",
    });
  });

  it("releases a stable key only when scope, registration, consent, active state, trust, and PoP all agree", () => {
    const active_claims = [
      ...authorization().active_claims as object[],
      { claim_id: "24".repeat(32), namespace: "heterodyne.device", name: "key-ref", value: "nostr:abc", state: "active", repository_confirmed: true, issuer_trusted: true, subject_proof_valid: true },
    ];
    const accepted = validateAuthorizationRequest(authorization({
      consented_scopes: ["openid", "profile", "heterodyne:key-ref"],
      consented_claims: ["name", "https://heterodyne.network/jwt/key-ref"],
      trusted_namespaces: ["profile", "heterodyne.device"],
      active_claims,
    }));
    expect(accepted).toMatchObject({
      released_claims: { name: "Alice", "https://heterodyne.network/jwt/key-ref": "nostr:abc" },
    });
    expect(validateAuthorizationRequest(authorization({ active_claims }))).toMatchObject({
      released_claims: { name: "Alice" },
    });
  });

  it("rejects caller-selected pairwise subjects and ambiguous duplicate claim names", () => {
    expect(validateAuthorizationRequest(authorization({ pairwise_sub: "caller-selected-subject" }))).toMatchObject({
      allowed: false, reason_code: "oidc-claim-release-denied",
    });
    const duplicate = {
      claim_id: "25".repeat(32), namespace: "profile", name: "name", value: "Mallory",
      state: "active", repository_confirmed: true, issuer_trusted: true, subject_proof_valid: true,
    };
    expect(validateAuthorizationRequest(authorization({
      active_claims: [...authorization().active_claims, duplicate],
    }))).toMatchObject({ allowed: false, reason_code: "oidc-claim-release-denied" });
  });
});

describe("signed interoperable JWT projections", () => {
  it("projects and validates an RS256 OIDC ID Token with nonce", () => {
    const token = projectIdToken(projection(), privateJwk);
    expect(token.protected_header).toEqual({ alg: "RS256", kid: privateJwk.kid, typ: "JWT" });
    expect(token.claims).toMatchObject({ iss: issuer, aud: ["registered-client"], nonce: "nonce-123" });
    expect(validateProjectedJwt(token.compact, issuer, "registered-client", jwks, {
      now, token_use: "id_token", nonce: "nonce-123", client_id: "registered-client", sender_constraint: "none",
    })).toMatchObject({ allowed: true });
  });

  it("requires active exact release and mint decisions and rejects private claim leakage", () => {
    expect(() => projectIdToken(projection({
      mint_eligibility: { allowed: false, reason_code: "oidc-checkpoint-stale", checkpoint: issuance.checkpoint },
    }), privateJwk)).toThrow(/projection input/i);
    expect(() => projectIdToken(projection({
      released_claims: { provenance: "private" },
    }), privateJwk)).toThrow(/projection input|private claim/i);
    const nestedPrivate = { profile: { provenance: "private-ledger-source" } };
    expect(() => projectIdToken(projection({
      released_claims: nestedPrivate,
      release_decision: { ...projection().release_decision, released_claims: nestedPrivate },
    }), privateJwk)).toThrow(/private claim/i);
    expect(() => projectIdToken(projection({
      historical_returnability: { allowed: false, state: "revoked", reason_code: "claim-revoked" },
    }), privateJwk)).toThrow(/projection input/i);
  });

  it("projects and validates an RFC 9068 at+jwt with required claims", () => {
    const token = projectAccessToken(projection({ nonce: undefined }), privateJwk);
    expect(token.protected_header.typ).toBe("at+jwt");
    expect(token.claims).toMatchObject({
      iss: issuer, sub: projection().pairwise_sub, exp: now + 600, iat: now,
      jti: issuance.jti, client_id: "registered-client", scope: "openid profile",
    });
    expect(validateProjectedJwt(token.compact, issuer, "https://api.example", jwks, {
      now, token_use: "access_token", client_id: "registered-client", sender_constraint: "none",
    })).toMatchObject({ allowed: true });
  });

  it("rejects ID/access type confusion even with a valid signature", () => {
    const accessAsId = projectAccessToken(projection({ nonce: undefined }), privateJwk);
    expect(validateProjectedJwt(accessAsId.compact, issuer, "https://api.example", jwks, {
      now, token_use: "id_token", nonce: "nonce-123", client_id: "registered-client", sender_constraint: "none",
    })).toMatchObject({ allowed: false, reason_code: "oidc-token-type-invalid" });
    const idAsAccess = projectIdToken(projection(), privateJwk);
    expect(validateProjectedJwt(idAsAccess.compact, issuer, "https://api.example", jwks, {
      now, token_use: "access_token", client_id: "registered-client", sender_constraint: "none",
    })).toMatchObject({ allowed: false, reason_code: "oidc-token-type-invalid" });
  });

  it("binds sender-constrained access tokens to exact DPoP or mTLS cnf", () => {
    for (const [sender_constraint, cnf] of [["dpop", { jkt: "Q".repeat(43) }], ["mtls", { "x5t#S256": "R".repeat(43) }]] as Array<["dpop" | "mtls", Record<string, JsonValue>]>) {
      const token = projectAccessToken(projection({ nonce: undefined, cnf, sender_constraint }), privateJwk);
      expect(validateProjectedJwt(token.compact, issuer, "https://api.example", jwks, {
        now, token_use: "access_token", client_id: "registered-client", cnf, sender_constraint,
      })).toMatchObject({ allowed: true });
      expect(validateProjectedJwt(token.compact, issuer, "https://api.example", jwks, {
        now, token_use: "access_token", client_id: "registered-client", cnf: { jkt: "wrong" }, sender_constraint,
      })).toMatchObject({ allowed: false });
    }
  });

  it("issues only separately registered JWT assertions", () => {
    const token = projectJwtAssertion(projection({ nonce: undefined }), privateJwk, "urn:example:jwt-assertion:v1", registration);
    expect(token.protected_header.typ).toBe("heterodyne-assertion+jwt");
    expect(validateProjectedJwt(token.compact, issuer, "https://api.example", jwks, {
      now, token_use: "jwt_assertion", assertion_profile: "urn:example:jwt-assertion:v1",
      client_id: "registered-client", sender_constraint: "none",
    })).toMatchObject({ allowed: true });
    expect(() => projectJwtAssertion(projection({ nonce: undefined }), privateJwk, "urn:unregistered", registration))
      .toThrow(/registered/i);
  });

  it("rejects signature, issuer, audience, time, nonce, client, and algorithm substitutions", () => {
    const token = projectIdToken(projection(), privateJwk);
    const common = { now, token_use: "id_token" as const, nonce: "nonce-123", client_id: "registered-client", sender_constraint: "none" as const };
    const changedLast = token.compact.endsWith("A") ? "B" : "A";
    expect(validateProjectedJwt(`${token.compact.slice(0, -1)}${changedLast}`, issuer, "registered-client", jwks, common)).toMatchObject({ allowed: false });
    expect(validateProjectedJwt(token.compact, `${issuer}/`, "registered-client", jwks, common)).toMatchObject({ allowed: false, reason_code: "oidc-issuer-mismatch" });
    expect(validateProjectedJwt(token.compact, issuer, "https://other.example", jwks, common)).toMatchObject({ allowed: false, reason_code: "oidc-audience-invalid" });
    expect(validateProjectedJwt(token.compact, issuer, "registered-client", jwks, { ...common, now: now + 601 })).toMatchObject({ allowed: false });
    expect(validateProjectedJwt(token.compact, issuer, "registered-client", jwks, { ...common, nonce: "wrong" })).toMatchObject({ allowed: false });
    expect(validateProjectedJwt(token.compact, issuer, "registered-client", jwks, { ...common, client_id: "wrong" })).toMatchObject({ allowed: false });
    expect(validateProjectedJwt(token.compact, issuer, "registered-client", jwks, undefined as never)).toMatchObject({ allowed: false });
    expect(() => projectIdToken(projection(), { ...privateJwk, alg: "none" })).toThrow(/RS256/);
    expect(() => projectIdToken(projection(), { ...privateJwk, kid: "44".repeat(32) })).toThrow(/signing|projection|key/i);
  });
});
