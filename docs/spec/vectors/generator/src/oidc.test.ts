import { createHash, createPrivateKey, sign, type JsonWebKey } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import {
  decideDeviceAuthorization,
  discoveryPaths,
  issueAuthorizationCode,
  issueDeviceAuthorization,
  issuerMetadata,
  issuerUrl,
  projectAccessToken,
  projectIdToken,
  projectJwtAssertion,
  redeemAuthorizationCode,
  redeemDeviceCode,
  validateAuthorizationRequest,
  validateColdRootBinding,
  validateIssuerMetadata,
  validateProjectedJwt,
  type JwtValidationOptions,
  type OidcAuthorizationRequest,
} from "./oidc.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import { buildOidcScenario, buildOidcVectors, replayOidcVector } from "./topics-oidc.js";
import { buildLedgerRepositoryEvidence, mergeClaimLedger } from "./claim-ledger.js";

const fixtures = buildFixtures();
let x: Awaited<ReturnType<typeof buildOidcScenario>>;

beforeAll(async () => { x = await buildOidcScenario(fixtures); });

const options = (token_use: JwtValidationOptions["token_use"], extra: Partial<JwtValidationOptions> = {}): JwtValidationOptions => ({
  now: x.issuance.issued_at, token_use, client_id: "registered-client", sender_constraint: "none",
  permitted_audiences: ["https://api.example"], ...extra,
});

function resignJwt(jwt: string, mutate: (claims: Record<string, unknown>) => void): string {
  const [header, payload] = jwt.split(".");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>;
  mutate(claims);
  const encodedClaims = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signingInput = `${header}.${encodedClaims}`;
  const privateKey = createPrivateKey({ key: OIDC_RSA_ONE.private_jwk as JsonWebKey, format: "jwk" });
  return `${signingInput}.${sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url")}`;
}

describe("cold-root issuer and exact origin identity", () => {
  it("requires authenticated cold-root identity at every issuer constructor", () => {
    expect(issuerUrl("https://node.example", x.root, x.identity)).toBe(x.metadata.issuer);
    expect(discoveryPaths("https://node.example", x.root, x.identity).issuer).toBe(x.metadata.issuer);
    expect(issuerMetadata("https://node.example", x.root, x.identity)).toEqual(x.metadata);
    expect(validateIssuerMetadata(x.metadata, x.metadata.issuer, x.metadata.jwks_uri)).toMatchObject({ allowed: true });
    expect(() => issuerUrl("https://node.example", x.epoch, x.identity)).toThrow(/cold root|issuer/i);
    expect(validateColdRootBinding(x.epoch, x.identity)).toMatchObject({ allowed: false });
  });

  it("advertises and accepts only the implemented RS256 signing profile", () => {
    expect(x.metadata.id_token_signing_alg_values_supported).toEqual(["RS256"]);
    expect(validateIssuerMetadata({ ...x.metadata,
      id_token_signing_alg_values_supported: ["RS256", "ES256"] as never,
    }, x.metadata.issuer, x.metadata.jwks_uri)).toMatchObject({ allowed: false });
  });

  it.each([
    "http://node.example", "https://node.example/", "https://NODE.example", "https://node.example:443",
    "https://user@node.example", "https://node.example?x=1", "https://node.example#x",
  ])("rejects non-exact origin %s", (origin) => {
    expect(() => issuerUrl(origin, x.root, x.identity)).toThrow(/origin|issuer/i);
  });
});

describe("evidence-bound release and OAuth state machines", () => {
  it("replays signed registration, consent and source claims and binds the full checkpoint", () => {
    const release = validateAuthorizationRequest(x.request);
    expect(release).toMatchObject({
      allowed: true, scopes: ["heterodyne:key-ref", "openid", "profile"], audience: ["https://api.example"],
      released_claims: {
        name: "Alice",
        "https://heterodyne.network/jwt/key-ref": {
          type: "nostr-secp256k1", value: fixtures.personas.alice.epoch_keys.epoch_1.pubkey,
        },
      }, checkpoint: x.preMintRepository.checkpoint,
      registration_record_id: x.registrationRecord.record_id,
      consent_record_id: x.consentRecord.record_id,
    });
    expect(release.source_claim_ids).toEqual(x.issuance.source_claim_ids);
    expect(release.request_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(release.release_digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects evidence/request substitution and does not accept caller booleans", () => {
    expect(validateAuthorizationRequest({ ...x.request, client_id: "other-client" })).toMatchObject({ allowed: false });
    expect(validateAuthorizationRequest({ ...x.request, registration: x.request.consent })).toMatchObject({ allowed: false });
    expect(validateAuthorizationRequest({ ...x.request, canonical_claim_state: true, issuer_trusted: true } as never))
      .toMatchObject({ allowed: true });
    const badContext = structuredClone(x.request.source_claims[0]);
    badContext.verification_context.resource = "https://other.example";
    expect(validateAuthorizationRequest({ ...x.request, source_claims: [badContext] })).toMatchObject({ allowed: false });
  });

  it("fails closed on concurrent non-identical registration or consent for one subject and client", async () => {
    for (const [name, selectedRecord] of [
      ["client-registration", x.registrationRecord],
      ["consent", x.consentRecord],
    ] as const) {
      const existing = (selectedRecord.payload as unknown as {
        claim_artifact: { semantic: { value: Record<string, unknown>; resources: string[] } };
      }).claim_artifact.semantic;
      const alternate = await x.s.makeClaim(x.s.writerOne, {
        namespace: "heterodyne.oidc",
        name,
        value: { ...existing.value, scopes: ["openid"] } as never,
        resources: existing.resources,
      });
      const alternateRecord = x.s.signRecord("claim", { claim_artifact: alternate.artifact });
      x.allClaims.set(alternate.artifact.semantic.claim_id, alternate.artifact.semantic);
      try {
        const records = [...x.preMintRecords, alternateRecord];
        const repository = buildLedgerRepositoryEvidence({
          repository_rid: x.s.rid,
          confirmed_records: records,
          observed_at: x.preMintRepository.checkpoint.observed_at + 1,
          prior: x.preMintRepository.repository,
        });
        const context = x.s.makeTask5Context(repository.repository);
        for (const [recordId, evidence] of x.preMintContext.record_evidence) {
          context.record_evidence.set(recordId, evidence);
        }
        context.record_evidence.set(alternateRecord.record_id, x.evidenceFor(alternateRecord, alternate));
        const state = mergeClaimLedger(records, [], repository.checkpoint, context);
        expect(validateAuthorizationRequest({ ...x.request, state }), name).toMatchObject({
          allowed: false,
          reason_code: "claim-repository-conflict",
        });
      } finally {
        x.allClaims.delete(alternate.artifact.semantic.claim_id);
      }
    }
  });

  it("rejects post-merge injection into mutable record, confirmation, and evidence arrays", () => {
    const injected = x.s.signRecord("claim", x.dataRecord.payload, x.s.writerOne,
      [x.dataRecord.record_id], x.s.now + 10);
    const sourceEvidence = x.preMintContext.record_evidence.get(x.dataRecord.record_id)!;
    x.preMintContext.record_evidence.set(injected.record_id, {
      ...sourceEvidence, record_id: injected.record_id, payload_digest: injected.payload_digest,
    });
    x.preMintState.records.push(injected);
    x.preMintState.repository_confirmed_record_ids!.push(injected.record_id);
    try {
      const sources = x.request.source_claims.map((source) => source.claim_record_id === x.dataRecord.record_id
        ? { ...source, claim_record_id: injected.record_id } : source);
      expect(validateAuthorizationRequest({ ...x.request, source_claims: sources })).toMatchObject({ allowed: false });
    } finally {
      x.preMintState.records.pop();
      x.preMintState.repository_confirmed_record_ids!.pop();
      x.preMintContext.record_evidence.delete(injected.record_id);
    }
  });

  it("enforces S256, client, redirect, expiry and one-time authorization-code redemption", () => {
    const code = issueAuthorizationCode(x.request, x.issuance.issued_at);
    const consumed = new Set<string>();
    const redeem = (overrides = {}) => redeemAuthorizationCode(code, {
      code: code.code, client_id: x.request.client_id, redirect_uri: x.request.redirect_uri!,
      code_verifier: x.codeVerifier, now: x.issuance.issued_at + 1, ...overrides,
    }, consumed);
    expect(redeem()).toMatchObject({ allowed: true });
    expect(redeem()).toMatchObject({ allowed: false });
    expect(redeemAuthorizationCode(code, { code: code.code, client_id: "wrong", redirect_uri: x.request.redirect_uri!,
      code_verifier: x.codeVerifier, now: x.issuance.issued_at + 1 }, new Set())).toMatchObject({ allowed: false });
    expect(redeemAuthorizationCode(code, { code: code.code, client_id: x.request.client_id, redirect_uri: "https://client.example/wrong",
      code_verifier: x.codeVerifier, now: x.issuance.issued_at + 1 }, new Set())).toMatchObject({ allowed: false });
    expect(redeemAuthorizationCode(code, { code: code.code, client_id: x.request.client_id, redirect_uri: x.request.redirect_uri!,
      code_verifier: `${x.codeVerifier}x`, now: x.issuance.issued_at + 1 }, new Set())).toMatchObject({ allowed: false });
    expect(() => issueAuthorizationCode({ ...x.request, client_id: "attacker" }, x.issuance.issued_at))
      .toThrow(/prerequisites|grant/i);
  });

  it("executes RFC 8628 pending, slow_down, denial, expiry and success states", () => {
    const request = { ...x.request, flow: "device_authorization", grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      response_type: undefined, redirect_uri: undefined, code_challenge: undefined, code_challenge_method: undefined } as OidcAuthorizationRequest;
    let record = issueDeviceAuthorization(request, x.issuance.issued_at);
    const pending = redeemDeviceCode(record, { device_code: record.device_code, client_id: record.client_id, now: x.issuance.issued_at + 1 });
    expect(pending.result).toBe("authorization_pending");
    const slow = redeemDeviceCode(pending.record, { device_code: record.device_code, client_id: record.client_id, now: x.issuance.issued_at + 2 });
    expect(slow.result).toBe("slow_down");
    record = decideDeviceAuthorization(slow.record, "approve", x.issuance.issued_at + 3);
    const success = redeemDeviceCode(record, { device_code: record.device_code, client_id: record.client_id, now: x.issuance.issued_at + 20 });
    expect(success.result).toBe("success");
    expect(redeemDeviceCode(success.record, { device_code: record.device_code, client_id: record.client_id, now: x.issuance.issued_at + 21 }).result).toBe("expired_token");
    const denied = decideDeviceAuthorization(issueDeviceAuthorization(request, x.issuance.issued_at), "deny", x.issuance.issued_at + 1);
    expect(redeemDeviceCode(denied, { device_code: denied.device_code, client_id: denied.client_id, now: x.issuance.issued_at + 2 }).result).toBe("access_denied");
  });
});

describe("evidence-derived strict JOSE projection", () => {
  it("unwraps the exact Task5 key and projects a strict ID Token", () => {
    const token = projectIdToken(x.projection);
    expect(token.protected_header).toEqual({ alg: "RS256", kid: OIDC_RSA_ONE.key_id, typ: "JWT" });
    expect(token.claims.aud).toEqual(["registered-client"]);
    expect(validateProjectedJwt(token.compact, x.metadata.issuer, "registered-client", { keys: [OIDC_RSA_ONE.public_jwk] },
      options("id_token", { nonce: "oidc-vector-nonce" }))).toMatchObject({ allowed: true });
  });

  it("recomputes release, mint eligibility, returnability and full checkpoint", () => {
    expect(() => projectIdToken({ ...x.projection, client_id: "caller-substitution" })).toThrow(/projection|token/i);
    expect(() => projectIdToken({ ...x.projection, issuance_record_id: x.registrationRecord.record_id })).toThrow(/issuance/i);
    expect(() => projectIdToken({ ...x.projection,
      authorization_request: { ...x.request, requested_claims: [] } })).toThrow(/projection|authorization/i);
    expect(() => projectIdToken({ ...x.projection,
      authorization_request: { ...x.request, nonce: "substituted-nonce" } })).toThrow(/projection|token/i);
    const otherIdentity = { cold_root_npub: x.epoch, epoch_npubs: [x.root] };
    expect(() => projectIdToken({ ...x.projection, identity: otherIdentity,
      issuer: `https://node.example/oidc/${x.epoch}` })).toThrow(/issuer/i);
    expect(() => projectJwtAssertion({ ...x.projection,
      authorization_request: { ...x.request, registration: x.request.consent } }, "urn:example:jwt-assertion:v1"))
      .toThrow(/registered|authorization|token/i);
  });

  it("requires closed JWKS and exact RSA public-key metadata", () => {
    const token = projectIdToken(x.projection);
    const common = options("id_token", { nonce: "oidc-vector-nonce" });
    for (const jwks of [
      { keys: [OIDC_RSA_ONE.public_jwk], extra: true },
      { keys: [{ ...OIDC_RSA_ONE.public_jwk, extra: true }] },
      { keys: [{ ...OIDC_RSA_ONE.public_jwk, d: "private" }] },
      { keys: [{ ...OIDC_RSA_ONE.public_jwk, key_ops: ["sign"] }] },
      { keys: [{ ...OIDC_RSA_ONE.public_jwk, kid: createHash("sha256").update("wrong").digest("base64url") }] },
      { keys: [OIDC_RSA_ONE.public_jwk, { ...OIDC_RSA_ONE.public_jwk, x5u: "https://remote.example/key" }] },
      { keys: [OIDC_RSA_ONE.public_jwk, { kty: "EC", crv: "P-256", alg: "ES256", use: "sig",
        key_ops: ["verify"], kid: "Q".repeat(43), x: "Q".repeat(43), y: "Q".repeat(43) }] },
    ]) expect(validateProjectedJwt(token.compact, x.metadata.issuer, "registered-client", jwks as never, common))
      .toMatchObject({ allowed: false, reason_code: "oidc-token-type-invalid" });
  });

  it("enforces exact access audience sets, token types, and canonical 32-byte cnf", () => {
    const access = projectAccessToken(x.projection);
    expect(validateProjectedJwt(access.compact, x.metadata.issuer, "https://api.example", { keys: [OIDC_RSA_ONE.public_jwk] },
      options("access_token"))).toMatchObject({ allowed: true });
    expect(validateProjectedJwt(access.compact, x.metadata.issuer, "https://api.example", { keys: [OIDC_RSA_ONE.public_jwk] },
      options("access_token", { permitted_audiences: ["https://api.example", "https://extra.example"] })))
      .toMatchObject({ allowed: false, reason_code: "oidc-audience-invalid" });
    expect(validateProjectedJwt(access.compact, x.metadata.issuer, "registered-client", { keys: [OIDC_RSA_ONE.public_jwk] },
      options("id_token", { nonce: "oidc-vector-nonce" }))).toMatchObject({ allowed: false });
    const invalidCnf = { jkt: "Q".repeat(42) };
    expect(() => projectAccessToken({ ...x.projection,
      authorization_request: { ...x.request, cnf: invalidCnf, sender_constraint: "dpop" } }))
      .toThrow(/cnf|evidence/i);
  });

  it.each([
    ["non-canonical subject", (claims: Record<string, unknown>) => { claims.sub = "not-a-pairwise-subject"; }],
    ["short jti", (claims: Record<string, unknown>) => { claims.jti = "short"; }],
    ["duplicate unsorted scope", (claims: Record<string, unknown>) => { claims.scope = "profile openid profile"; }],
  ])("rejects a correctly re-signed JWT with %s", (_label, mutate) => {
    const access = projectAccessToken(x.projection);
    const malformed = resignJwt(access.compact, mutate);
    expect(validateProjectedJwt(malformed, x.metadata.issuer, "https://api.example",
      { keys: [OIDC_RSA_ONE.public_jwk] }, options("access_token")))
      .toMatchObject({ allowed: false, reason_code: "oidc-token-type-invalid" });
  });
});

describe("authored OIDC corpus", () => {
  it("keeps the exact 13 vector IDs and replays every mutation table", async () => {
    const vectors = await buildOidcVectors(fixtures);
    expect(vectors.map(({ relativePath }) => relativePath)).toEqual([
      "oidc/001-discovery-exact-issuer.json", "oidc/002-issuer-mismatch-rejected.json",
      "oidc/003-authorization-code-pkce.json", "oidc/004-device-authorization.json",
      "oidc/005-prohibited-grants.json", "oidc/006-pairwise-subject.json",
      "oidc/007-stable-key-consent-gated.json", "oidc/008-id-token-valid.json",
      "oidc/009-rfc9068-access-token-valid.json", "oidc/010-token-type-confusion-rejected.json",
      "oidc/011-dpop-confirmation-bound.json", "oidc/012-registered-jwt-assertion.json",
      "oidc/013-mtls-confirmation-bound.json",
    ]);
    for (const { vector } of vectors) {
      expect(replayOidcVector(vector.input)).toEqual(vector.expected_output);
      expect(JSON.stringify(vector)).not.toContain('"d":"');
    }
  });
});
