import { createHash, createPrivateKey, sign, type JsonWebKey } from "node:crypto";
import { nip19 } from "nostr-tools";
import { beforeAll, describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import {
  authorizeAuthorizationRequestEffect,
  decideDeviceAuthorization,
  derivePairwiseSubject,
  discoveryPaths,
  issueAuthorizationCode,
  issueDeviceAuthorization,
  issuerMetadata,
  issuerUrl,
  projectAccessToken,
  projectIdToken,
  projectJwtAssertion,
  purgeOidcTransactionsForCredentialReset,
  redeemAuthorizationCode,
  redeemDeviceCode,
  validateAuthorizationRequest,
  validateIssuerMetadata,
  validatePersonaBinding,
  validateProjectedJwt,
  type OidcAuthorizedRelease,
  type JwtValidationOptions,
  type OidcAuthorizationRequest,
} from "./oidc.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import { buildLiveOidcScenario } from "./oidc-test-support.js";
import { inspectVerifiedClaim } from "./claims.js";
import { buildLedgerRepositoryEvidence, mergeClaimLedger } from "./claim-ledger.js";
import { jcsCanonicalize } from "./jcs.js";
import type { ClaimAuthorizationAuthority } from "./claim-authorization.js";

const fixtures = buildFixtures();
let x: Awaited<ReturnType<typeof buildLiveOidcScenario>>;

beforeAll(async () => { x = await buildLiveOidcScenario(fixtures); });

const options = (token_use: JwtValidationOptions["token_use"], extra: Partial<JwtValidationOptions> = {}): JwtValidationOptions => ({
  now: x.issuance.issued_at, token_use, client_id: "registered-client", sender_constraint: "none",
  permitted_audiences: ["https://api.example"],
  credential_ledger: x.issuedState.credential_ledger,
  ...extra,
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

async function durableAuthorization(
  request: OidcAuthorizationRequest,
  idempotencyKey: string,
  purpose: "authorization_code" | "device_authorization" | "jwt_projection" =
    request.flow === "device_authorization" ? "device_authorization" : "authorization_code",
): Promise<OidcAuthorizedRelease> {
  const harness = x.s.makeClaimAuthorizationHarness({
    load_state: () => x.preMintState,
    trusted_now: () => x.s.now + 69,
  });
  const result = await authorizeAuthorizationRequestEffect(harness.authority, {
    request,
    idempotency_key: idempotencyKey,
    purpose,
    projection_subtype: purpose === "jwt_projection" ? "access_token" : null,
    assertion_profile: null,
    authorization_validity_seconds: 300,
    effect: () => ({ status: "completed", result: { executed: true } }),
  });
  if (result.verdict !== "accept") throw new Error(`synthetic OIDC authorization failed: ${result.reason_code}`);
  return result.authorization;
}

async function durableAuthorizationRecord(
  request: OidcAuthorizationRequest,
  idempotencyKey: string,
  purpose: "authorization_code" | "device_authorization" | "jwt_projection" =
    request.flow === "device_authorization" ? "device_authorization" : "authorization_code",
): Promise<Readonly<{
  authorization: OidcAuthorizedRelease;
  authority: ClaimAuthorizationAuthority;
}>> {
  const harness = x.s.makeClaimAuthorizationHarness({
    load_state: () => x.preMintState,
    trusted_now: () => x.s.now + 69,
  });
  const result = await authorizeAuthorizationRequestEffect(harness.authority, {
    request,
    idempotency_key: idempotencyKey,
    purpose,
    projection_subtype: purpose === "jwt_projection" ? "access_token" : null,
    assertion_profile: null,
    authorization_validity_seconds: 300,
    effect: () => ({ status: "completed", result: { executed: true } }),
  });
  if (result.verdict !== "accept") throw new Error(`synthetic OIDC authorization failed: ${result.reason_code}`);
  return Object.freeze({ authorization: result.authorization, authority: harness.authority });
}

describe("active-persona issuer and exact origin identity", () => {
  it("requires the authenticated active persona at every issuer constructor", () => {
    expect(issuerUrl("https://node.example", x.personaNpub, x.identity)).toBe(x.metadata.issuer);
    expect(discoveryPaths("https://node.example", x.personaNpub, x.identity).issuer)
      .toBe(x.metadata.issuer);
    expect(issuerMetadata("https://node.example", x.personaNpub, x.identity)).toEqual(x.metadata);
    expect(validateIssuerMetadata(x.metadata, x.metadata.issuer, x.metadata.jwks_uri)).toMatchObject({ allowed: true });
    const unrelatedNpub = nip19.npubEncode(
      fixtures.personas.carol.epoch_keys.epoch_1.pubkey,
    );
    expect(() => issuerUrl("https://node.example", unrelatedNpub, x.identity))
      .toThrow(/active persona|issuer/i);
    expect(validatePersonaBinding(unrelatedNpub, x.identity)).toMatchObject({ allowed: false });
    const legacyIdentity = {
      ...x.identity,
      cold_root_npub: unrelatedNpub,
      epoch_npubs: [x.personaNpub],
      persona_kel_head: { id: "00".repeat(32), seq: 0 },
    };
    expect(validatePersonaBinding(x.personaNpub, legacyIdentity as never))
      .toMatchObject({ allowed: false, reason_code: "oidc-issuer-mismatch" });
    expect(() => issuerUrl("https://node.example", x.personaNpub, legacyIdentity as never))
      .toThrow(/active persona|issuer/i);
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
    expect(() => issuerUrl(origin, x.personaNpub, x.identity)).toThrow(/origin|issuer/i);
  });
});

describe("evidence-bound release and OAuth state machines", () => {
  it("executes an ordinary captured async effect through durable authorization", async () => {
    const harness = x.s.makeClaimAuthorizationHarness({
      trusted_now: () => x.s.now + 69,
      load_state: () => x.preMintState,
    });
    await expect(authorizeAuthorizationRequestEffect(harness.authority, {
      request: x.request,
      idempotency_key: "synthetic-local-oidc-async-effect-0001",
      purpose: "jwt_projection",
      projection_subtype: "access_token",
      assertion_profile: null,
      authorization_validity_seconds: 300,
      effect: async (release) => ({
        status: "completed",
        result: { release_digest: release.release_digest },
      }),
    })).resolves.toMatchObject({
      verdict: "accept",
      allowed: true,
      result: { release_digest: x.release.release_digest },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local executes an active OIDC release once and rejects writer removal before acquire", async () => {
    // BLUE TEAM VALIDATION: synthetic/local uses deterministic opaque claims, one in-memory CAS store, and bounded effect counters only.
    expect(x.releaseAuthorization).toMatchObject({
      verdict: "accept",
      allowed: true,
      disposition: "executed",
    });
    expect(x.releaseHarness.calls.acquire).toBe(1);
    expect(x.releaseEffects).toBe(1);

    let loads = 0;
    let effects = 0;
    const harness = x.s.makeClaimAuthorizationHarness({
      trusted_now: () => x.s.now + 69,
      load_state: () => {
        loads += 1;
        if (loads === 2) {
          x.s.setCurrentWriterPolicy({
            ...x.s.activeWriterPolicy(),
            writers: x.s.activeWriterPolicy().writers.map((writer) => ({
              ...writer,
              state: "revoked" as const,
            })),
          });
        }
        return x.preMintState;
      },
    });
    try {
      await expect(authorizeAuthorizationRequestEffect(harness.authority, {
        request: x.request,
        idempotency_key: "synthetic-local-oidc-writer-removed-0001",
        purpose: "jwt_projection",
        projection_subtype: "access_token",
        assertion_profile: null,
        authorization_validity_seconds: 300,
        effect: () => {
          effects += 1;
          return { status: "completed", result: { release: "unexpected" } };
        },
      })).resolves.toMatchObject({
        verdict: "reject",
        allowed: false,
        reason_code: "claim-ledger-writer-unauthorized",
      });
      expect(harness.calls.acquire).toBe(0);
      expect(effects).toBe(0);
    } finally {
      x.s.resetCurrentWriterPolicy();
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a release when an effect-time source claim disappears", async () => {
    // BLUE TEAM VALIDATION: synthetic/local removes one deterministic opaque claim from an in-memory current view and invokes no external effect.
    let loads = 0;
    let effects = 0;
    const harness = x.s.makeClaimAuthorizationHarness({
      trusted_now: () => x.s.now + 69,
      load_state: () => x.preMintState,
      transform_view: (view) => {
        loads += 1;
        return loads === 1 ? view : Object.freeze({
          ...view,
          claims: Object.freeze(view.claims.filter((artifact) =>
            inspectVerifiedClaim(artifact).claim_id !== x.dataClaim.artifact.semantic.claim_id)),
        });
      },
    });
    await expect(authorizeAuthorizationRequestEffect(harness.authority, {
      request: x.request,
      idempotency_key: "synthetic-local-oidc-source-removed-0001",
      purpose: "jwt_projection",
      projection_subtype: "access_token",
      assertion_profile: null,
      authorization_validity_seconds: 300,
      effect: () => {
        effects += 1;
        return { status: "completed", result: { release: "unexpected" } };
      },
    })).resolves.toMatchObject({ verdict: "reject", allowed: false });
    expect(harness.calls.acquire).toBe(0);
    expect(effects).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects accessor/proxy effect inputs without trap invocation", async () => {
    // BLUE TEAM VALIDATION: synthetic/local trap counters are bounded inert fixtures and never access a live identity, repository, or client.
    const harness = x.s.makeClaimAuthorizationHarness({
      load_state: () => x.preMintState,
      trusted_now: () => x.s.now + 69,
    });
    let reads = 0;
    const hostile = {
      request: x.request,
      idempotency_key: "synthetic-local-oidc-accessor-0001",
      purpose: "jwt_projection",
      projection_subtype: "access_token",
      assertion_profile: null,
      authorization_validity_seconds: 300,
    } as Record<string, unknown>;
    Object.defineProperty(hostile, "effect", {
      enumerable: true,
      get() {
        reads += 1;
        return () => ({ status: "completed", result: {} });
      },
    });
    await expect(authorizeAuthorizationRequestEffect(
      harness.authority,
      hostile as never,
    )).resolves.toMatchObject({ verdict: "reject", allowed: false });
    expect(reads).toBe(0);

    let calls = 0;
    const proxy = new Proxy({
      request: x.request,
      idempotency_key: "synthetic-local-oidc-proxy-0001",
      purpose: "jwt_projection" as const,
      projection_subtype: "access_token" as const,
      assertion_profile: null,
      authorization_validity_seconds: 300,
      effect: () => ({ status: "completed" as const, result: {} }),
    }, {
      get(target, property, receiver) {
        calls += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    await expect(authorizeAuthorizationRequestEffect(
      harness.authority,
      proxy,
    )).resolves.toMatchObject({ verdict: "reject", allowed: false });
    expect(calls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures nested request data before loaders can mutate it", async () => {
    // BLUE TEAM VALIDATION: synthetic/local mutates only detached in-memory arrays and counts inert proxy traps; no external target or deployable payload is used.
    const request: OidcAuthorizationRequest = {
      ...x.request,
      requested_claims: [...x.request.requested_claims],
      source_claims: [...x.request.source_claims],
    };
    let loads = 0;
    const harness = x.s.makeClaimAuthorizationHarness({
      load_state: () => x.preMintState,
      trusted_now: () => x.s.now + 69,
      transform_view: (view) => {
        loads += 1;
        if (loads === 1) {
          request.requested_claims.length = 0;
          request.source_claims.length = 0;
        }
        return view;
      },
    });
    await expect(authorizeAuthorizationRequestEffect(harness.authority, {
      request,
      idempotency_key: "synthetic-local-oidc-request-mutation-0001",
      purpose: "jwt_projection",
      projection_subtype: "access_token",
      assertion_profile: null,
      authorization_validity_seconds: 300,
      effect: (release) => ({
        status: "completed",
        result: { name: release.released_claims?.name },
      }),
    })).resolves.toMatchObject({
      verdict: "accept",
      allowed: true,
      result: { name: "Alice" },
    });

    let traps = 0;
    const proxiedClaims = new Proxy([...x.request.requested_claims], {
      get(target, property, receiver) {
        traps += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    await expect(authorizeAuthorizationRequestEffect(harness.authority, {
      request: { ...x.request, requested_claims: proxiedClaims },
      idempotency_key: "synthetic-local-oidc-request-proxy-0001",
      purpose: "jwt_projection",
      projection_subtype: "access_token",
      assertion_profile: null,
      authorization_validity_seconds: 300,
      effect: () => ({ status: "completed", result: {} }),
    })).resolves.toMatchObject({ verdict: "reject", allowed: false });
    expect(traps).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local public issuance and projection reject inspection-only requests", () => {
    // BLUE TEAM VALIDATION: synthetic/local uses one deterministic request object and performs no code delivery, token delivery, or external transaction.
    expect(() => issueAuthorizationCode(
      x.releaseHarness.authority,
      x.request as never,
    )).toThrow(/durable|authorization|grant/i);
    expect(() => issueDeviceAuthorization(
      x.releaseHarness.authority,
      x.request as never,
    )).toThrow(/durable|authorization|grant/i);
    expect(() => projectAccessToken({
      ...x.projection("access_token"),
      authorization: x.request as never,
    })).toThrow(/durable|authorization|grant/i);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects direct and simultaneous reuse of one durable artifact", async () => {
    // BLUE TEAM VALIDATION: synthetic/local invokes only deterministic in-memory issuance functions and never delivers a code or contacts an external client.
    const authorization = await durableAuthorizationRecord(
      x.request,
      "synthetic-local-oidc-artifact-reuse-0001",
    );
    issueAuthorizationCode(authorization.authority, authorization.authorization);
    expect(() => issueAuthorizationCode(
      authorization.authority,
      authorization.authorization,
    )).toThrow(/consumed|replay|authorization/i);

    const simultaneous = await durableAuthorizationRecord(
      x.request,
      "synthetic-local-oidc-artifact-simultaneous-0001",
    );
    const results = await Promise.allSettled([
      Promise.resolve().then(() => issueAuthorizationCode(simultaneous.authority, simultaneous.authorization)),
      Promise.resolve().then(() => issueAuthorizationCode(simultaneous.authority, simultaneous.authorization)),
    ]);
    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    expect(results.filter(({ status }) => status === "rejected")).toHaveLength(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cross-purpose and later-time durable artifact use", async () => {
    // BLUE TEAM VALIDATION: synthetic/local varies only an in-memory purpose and safe-integer fixture time; it contains no live credential, target, or reusable payload.
    const codeAuthorization = await durableAuthorizationRecord(
      x.request,
      "synthetic-local-oidc-artifact-purpose-0001",
    );
    expect(() => issueDeviceAuthorization(
      codeAuthorization.authority,
      codeAuthorization.authorization,
    )).toThrow(/purpose|authorization|grant/i);
    const jwtSubstitution = await durableAuthorizationRecord(
      x.request,
      "synthetic-local-oidc-artifact-jwt-purpose-0001",
    );
    expect(() => projectAccessToken({
      ...x.projection("access_token"),
      authorization_authority: jwtSubstitution.authority,
      authorization: jwtSubstitution.authorization,
    })).toThrow(/purpose|authorization|grant/i);

    let trustedNow = x.s.now + 69;
    const harness = x.s.makeClaimAuthorizationHarness({
      load_state: () => x.preMintState,
      trusted_now: () => trustedNow,
    });
    const result = await authorizeAuthorizationRequestEffect(harness.authority, {
      request: x.request,
      idempotency_key: "synthetic-local-oidc-artifact-later-time-0001",
      purpose: "authorization_code",
      projection_subtype: null,
      assertion_profile: null,
      authorization_validity_seconds: 2,
      effect: () => ({ status: "completed", result: { executed: true } }),
    });
    if (result.verdict !== "accept") throw new Error(result.reason_code);
    trustedNow += 2;
    expect(() => issueAuthorizationCode(
      harness.authority,
      result.authorization,
    )).toThrow(/stale|expired|replay|authorization|grant/i);
  });

  it("BLUE TEAM VALIDATION: synthetic/local binds artifacts to one authority and current view", async () => {
    // BLUE TEAM VALIDATION: synthetic/local swaps only in-memory authority objects and writer-policy fixtures; no live repository or credential is accessed.
    const authorized = await durableAuthorizationRecord(
      x.request,
      "synthetic-local-oidc-artifact-authority-0001",
    );
    const other = x.s.makeClaimAuthorizationHarness({
      load_state: () => x.preMintState,
      trusted_now: () => x.s.now + 69,
    });
    expect(() => issueAuthorizationCode(
      other.authority,
      authorized.authorization,
    )).toThrow(/authority|authorization|grant/i);

    const bindingHarness = x.s.makeClaimAuthorizationHarness({
      load_state: () => x.preMintState,
      trusted_now: () => x.s.now + 69,
    });
    const bindingInput = {
      request: x.request,
      idempotency_key: "synthetic-local-oidc-artifact-binding-0001",
      authorization_validity_seconds: 300,
      effect: () => ({ status: "completed" as const, result: { executed: true } }),
    };
    await expect(authorizeAuthorizationRequestEffect(bindingHarness.authority, {
      ...bindingInput,
      purpose: "authorization_code",
      projection_subtype: null,
      assertion_profile: null,
    })).resolves.toMatchObject({ verdict: "accept", allowed: true });
    await expect(authorizeAuthorizationRequestEffect(bindingHarness.authority, {
      ...bindingInput,
      purpose: "jwt_projection",
      projection_subtype: "access_token",
      assertion_profile: null,
    })).resolves.toMatchObject({ verdict: "reject", allowed: false });

    const current = await durableAuthorizationRecord(
      x.request,
      "synthetic-local-oidc-artifact-current-view-0001",
    );
    x.s.setCurrentWriterPolicy({
      ...x.s.activeWriterPolicy(),
      writers: x.s.activeWriterPolicy().writers.map((writer) => ({
        ...writer,
        state: "revoked" as const,
      })),
    });
    try {
      expect(() => issueAuthorizationCode(
        current.authority,
        current.authorization,
      )).toThrow(/stale|writer|authorization|grant/i);
    } finally {
      x.s.resetCurrentWriterPolicy();
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local cached retry returns the same issued grant without minting twice", async () => {
    // BLUE TEAM VALIDATION: synthetic/local replays one exact in-memory idempotency key through a process-local CAS store and performs no external delivery.
    let trustedNow = x.s.now + 69;
    const harness = x.s.makeClaimAuthorizationHarness({
      load_state: () => x.preMintState,
      trusted_now: () => trustedNow,
    });
    const effect = () => ({ status: "completed" as const, result: { executed: true } });
    const input = {
      request: x.request,
      idempotency_key: "synthetic-local-oidc-artifact-cached-retry-0001",
      purpose: "authorization_code" as const,
      projection_subtype: null,
      assertion_profile: null,
      authorization_validity_seconds: 300,
      effect,
    };
    const first = await authorizeAuthorizationRequestEffect(harness.authority, input);
    trustedNow += 1;
    const second = await authorizeAuthorizationRequestEffect(harness.authority, input);
    if (first.verdict !== "accept" || second.verdict !== "accept") {
      throw new Error("synthetic cached OIDC authorization failed");
    }
    expect(first.disposition).toBe("executed");
    expect(second.disposition).toBe("cached");
    const firstCode = issueAuthorizationCode(harness.authority, first.authorization);
    const secondCode = issueAuthorizationCode(harness.authority, second.authorization);
    expect(secondCode).toEqual(firstCode);
    expect(() => issueAuthorizationCode(
      harness.authority,
      second.authorization,
    )).toThrow(/consumed|replay|authorization/i);
  });

  it("BLUE TEAM VALIDATION: synthetic/local cached JWT retry cannot select a second projection subtype", async () => {
    // BLUE TEAM VALIDATION: synthetic/local signs only deterministic fixture JWTs with repository test keys and performs no token delivery or external request.
    const harness = x.s.makeClaimAuthorizationHarness({
      load_state: () => x.preMintState,
      trusted_now: () => x.s.now + 69,
    });
    const input = {
      request: x.request,
      idempotency_key: "synthetic-local-oidc-jwt-cached-retry-0001",
      purpose: "jwt_projection" as const,
      projection_subtype: "id_token" as const,
      assertion_profile: null,
      authorization_validity_seconds: 300,
      effect: () => ({ status: "completed" as const, result: { executed: true } }),
    };
    const first = await authorizeAuthorizationRequestEffect(harness.authority, input);
    const second = await authorizeAuthorizationRequestEffect(harness.authority, input);
    const third = await authorizeAuthorizationRequestEffect(harness.authority, input);
    if (first.verdict !== "accept" || second.verdict !== "accept" || third.verdict !== "accept") {
      throw new Error("synthetic cached JWT authorization failed");
    }
    const projection = { ...x.projectionContext, authorization_authority: harness.authority };
    const idToken = projectIdToken({ ...projection, authorization: first.authorization });
    expect(() => projectAccessToken({
      ...projection,
      authorization: second.authorization,
    })).toThrow(/subtype|purpose|authorization|grant/i);
    const retryIdToken = projectIdToken({ ...projection, authorization: third.authorization });
    expect(retryIdToken.compact).toBe(idToken.compact);
    expect(retryIdToken).toBe(idToken);
    expect(Object.isFrozen(retryIdToken)).toBe(true);
    expect(Object.isFrozen(retryIdToken.claims)).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local cached JWT retry rejects changed projection input and signing authority", async () => {
    // BLUE TEAM VALIDATION: synthetic/local varies only closed fixture time, mirror, and test-key bytes; it never signs for or contacts an external target.
    const harness = x.s.makeClaimAuthorizationHarness({
      load_state: () => x.preMintState,
      trusted_now: () => x.s.now + 69,
    });
    const input = {
      request: x.request,
      idempotency_key: "synthetic-local-oidc-jwt-input-binding-0001",
      purpose: "jwt_projection" as const,
      projection_subtype: "access_token" as const,
      assertion_profile: null,
      authorization_validity_seconds: 300,
      effect: () => ({ status: "completed" as const, result: { executed: true } }),
    };
    const results = [];
    for (let index = 0; index < 4; index += 1) {
      results.push(await authorizeAuthorizationRequestEffect(harness.authority, input));
    }
    if (results.some((result) => result.verdict !== "accept")) {
      throw new Error("synthetic cached JWT input authorization failed");
    }
    const [first, mirrorChanged, timeChanged, signerChanged] = results as Array<
      Extract<(typeof results)[number], { verdict: "accept" }>
    >;
    const projection = { ...x.projectionContext, authorization_authority: harness.authority };
    projectAccessToken({ ...projection, authorization: first.authorization });
    expect(() => projectAccessToken({
      ...projection,
      authorization: mirrorChanged.authorization,
      status_mirror: { ...projection.status_mirror, sha256: "44".repeat(32) },
    })).toThrow(/input|authorization|grant/i);
    expect(() => projectAccessToken({
      ...projection,
      authorization: timeChanged.authorization,
      now: projection.now + 1,
    })).toThrow(/projection|token|authorization|grant/i);
    expect(() => projectAccessToken({
      ...projection,
      authorization: signerChanged.authorization,
      issuer_audience_key: Uint8Array.from(projection.issuer_audience_key, (byte, index) =>
        index === 0 ? byte ^ 1 : byte),
    })).toThrow(/signing|key|authority|authorization|grant/i);
  });

  it("derives pairwise subjects only from the exact lowercase typed-subject JCS digest", () => {
    const typedSubject = { type: "radicle-ed25519-nid", value: x.s.writerOne.did_key };
    const localSubject = createHash("sha256").update(jcsCanonicalize(typedSubject)).digest("hex");
    expect(localSubject).toMatch(/^[0-9a-f]{64}$/);
    expect(derivePairwiseSubject(localSubject, "https://client.example", x.pairwiseSecret))
      .toBe(x.release.pairwise_sub);
    for (const invalid of ["abc", "A".repeat(64), "_".repeat(64), "a".repeat(63), "a".repeat(65)]) {
      expect(() => derivePairwiseSubject(invalid, "https://client.example", x.pairwiseSecret), invalid)
        .toThrow(/pairwise subject derivation input/);
    }
  });

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

  it("requires a nonempty nonce on every authorization request", () => {
    expect(validateAuthorizationRequest({
      ...x.request,
      nonce: "",
    })).toMatchObject({ allowed: false, reason_code: "oidc-claim-release-denied" });
    expect(validateAuthorizationRequest({
      ...x.request,
      nonce: undefined,
    } as never)).toMatchObject({ allowed: false, reason_code: "oidc-claim-release-denied" });
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
      x.allClaims.set(alternate.artifact.semantic.claim_id, alternate.verified_artifact);
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

  it("enforces S256, client, redirect, expiry and one-time authorization-code redemption", async () => {
    const authorization = await durableAuthorizationRecord(
      x.request,
      "synthetic-local-authorization-code-redemption-0001",
    );
    const code = issueAuthorizationCode(authorization.authority, authorization.authorization);
    expect(code).toMatchObject(x.preMintState.credential_ledger);
    const consumed = new Set<string>();
    const redeem = (overrides = {}) => redeemAuthorizationCode(code, {
      code: code.code, client_id: x.request.client_id, redirect_uri: x.request.redirect_uri!,
      code_verifier: x.codeVerifier, now: x.issuance.issued_at + 1,
      credential_ledger: x.preMintState.credential_ledger, ...overrides,
    }, consumed);
    expect(redeem()).toMatchObject({ allowed: true });
    expect(redeem()).toMatchObject({ allowed: false });
    expect(redeemAuthorizationCode(code, { code: code.code, client_id: "wrong", redirect_uri: x.request.redirect_uri!,
      code_verifier: x.codeVerifier, now: x.issuance.issued_at + 1,
      credential_ledger: x.preMintState.credential_ledger }, new Set())).toMatchObject({ allowed: false });
    expect(redeemAuthorizationCode(code, { code: code.code, client_id: x.request.client_id, redirect_uri: "https://client.example/wrong",
      code_verifier: x.codeVerifier, now: x.issuance.issued_at + 1,
      credential_ledger: x.preMintState.credential_ledger }, new Set())).toMatchObject({ allowed: false });
    expect(redeemAuthorizationCode(code, { code: code.code, client_id: x.request.client_id, redirect_uri: x.request.redirect_uri!,
      code_verifier: `${x.codeVerifier}x`, now: x.issuance.issued_at + 1,
      credential_ledger: x.preMintState.credential_ledger }, new Set())).toMatchObject({ allowed: false });
    expect(redeem({ credential_ledger: {
      ...x.preMintState.credential_ledger,
      credential_ledger_generation: x.preMintState.credential_ledger.credential_ledger_generation + 1,
    } })).toMatchObject({ allowed: false });
    expect(() => issueAuthorizationCode(authorization.authority, {} as never))
      .toThrow(/durable|authorization|grant/i);
  });

  it("executes RFC 8628 pending, slow_down, denial, expiry and success states", async () => {
    const request = { ...x.request, flow: "device_authorization", grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      response_type: undefined, redirect_uri: undefined, code_challenge: undefined, code_challenge_method: undefined } as OidcAuthorizationRequest;
    const authorization = await durableAuthorizationRecord(request, "synthetic-local-device-authorization-0001");
    let record = issueDeviceAuthorization(authorization.authority, authorization.authorization);
    expect(record).toMatchObject(x.preMintState.credential_ledger);
    const current = x.preMintState.credential_ledger;
    const pending = redeemDeviceCode(record, { device_code: record.device_code, client_id: record.client_id,
      now: x.issuance.issued_at + 1, credential_ledger: current });
    expect(pending.result).toBe("authorization_pending");
    const slow = redeemDeviceCode(pending.record, { device_code: record.device_code, client_id: record.client_id,
      now: x.issuance.issued_at + 2, credential_ledger: current });
    expect(slow.result).toBe("slow_down");
    record = decideDeviceAuthorization(slow.record, "approve", x.issuance.issued_at + 3, current);
    const success = redeemDeviceCode(record, { device_code: record.device_code, client_id: record.client_id,
      now: x.issuance.issued_at + 20, credential_ledger: current });
    expect(success.result).toBe("success");
    expect(redeemDeviceCode(success.record, { device_code: record.device_code, client_id: record.client_id,
      now: x.issuance.issued_at + 21, credential_ledger: current }).result).toBe("expired_token");
    const deniedAuthorization = await durableAuthorizationRecord(request, "synthetic-local-device-denied-0001");
    const denied = decideDeviceAuthorization(issueDeviceAuthorization(
      deniedAuthorization.authority,
      deniedAuthorization.authorization,
    ), "deny",
      x.issuance.issued_at + 1, current);
    expect(redeemDeviceCode(denied, { device_code: denied.device_code, client_id: denied.client_id,
      now: x.issuance.issued_at + 2, credential_ledger: current }).result).toBe("access_denied");
    const stale = { ...current, credential_ledger_generation: current.credential_ledger_generation + 1 };
    const staleAuthorization = await durableAuthorizationRecord(request, "synthetic-local-device-stale-0001");
    expect(() => decideDeviceAuthorization(issueDeviceAuthorization(
      staleAuthorization.authority,
      staleAuthorization.authorization,
    ), "approve",
      x.issuance.issued_at + 1, stale)).toThrow(/credential_generation_stale/);
  });

  it("purges every prior-generation OAuth transaction when credential authority resets", async () => {
    const deviceRequest = {
      ...x.request,
      flow: "device_authorization",
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      response_type: undefined,
      redirect_uri: undefined,
      code_challenge: undefined,
      code_challenge_method: undefined,
    } as OidcAuthorizationRequest;
    const pendingAuthorization = await durableAuthorizationRecord(
      deviceRequest,
      "synthetic-local-device-authorization-reset-pending-0001",
    );
    const approvedAuthorization = await durableAuthorizationRecord(
      deviceRequest,
      "synthetic-local-device-authorization-reset-approved-0001",
    );
    const deniedAuthorization = await durableAuthorizationRecord(
      deviceRequest,
      "synthetic-local-device-authorization-reset-denied-0001",
    );
    const codeAuthorization = await durableAuthorizationRecord(
      x.request,
      "synthetic-local-code-authorization-reset-0001",
    );
    const current = x.preMintState.credential_ledger;
    const pending = issueDeviceAuthorization(
      pendingAuthorization.authority,
      pendingAuthorization.authorization,
    );
    const approved = decideDeviceAuthorization(
      issueDeviceAuthorization(approvedAuthorization.authority, approvedAuthorization.authorization),
      "approve",
      x.issuance.issued_at + 2,
      current,
    );
    const denied = decideDeviceAuthorization(
      issueDeviceAuthorization(deniedAuthorization.authority, deniedAuthorization.authorization),
      "deny",
      x.issuance.issued_at + 3,
      current,
    );
    const result = purgeOidcTransactionsForCredentialReset(
      [issueAuthorizationCode(codeAuthorization.authority, codeAuthorization.authorization)],
      [pending, approved, denied],
      { ...current, credential_ledger_generation: current.credential_ledger_generation + 1 },
    );
    expect(result).toMatchObject({
      retained_authorization_codes: [],
      retained_device_authorizations: [],
      requires_authority_reissue: true,
      requires_status_reissue: true,
    });
    expect(result.purged_authorization_codes).toHaveLength(1);
    expect(result.purged_device_codes).toHaveLength(3);
  });
});

describe("evidence-derived strict JOSE projection", () => {
  it("unwraps the exact Task5 key and projects a strict ID Token", () => {
    const token = projectIdToken(x.projection("id_token"));
    expect(token.protected_header).toEqual({ alg: "RS256", kid: OIDC_RSA_ONE.key_id, typ: "JWT" });
    expect(token.claims.aud).toEqual(["registered-client"]);
    expect(token.claims).toMatchObject(x.issuedState.credential_ledger);
    expect(validateProjectedJwt(token.compact, x.metadata.issuer, "registered-client", { keys: [OIDC_RSA_ONE.public_jwk] },
      options("id_token", { nonce: "oidc-vector-nonce" }))).toMatchObject({ allowed: true });
  });

  it("rejects an empty expected or presented ID Token nonce even when they match", () => {
    const token = projectIdToken(x.projection("id_token"));
    const emptyNonce = resignJwt(token.compact, (claims) => {
      claims.nonce = "";
    });
    expect(validateProjectedJwt(
      emptyNonce,
      x.metadata.issuer,
      "registered-client",
      { keys: [OIDC_RSA_ONE.public_jwk] },
      options("id_token", { nonce: "" }),
    )).toMatchObject({ allowed: false, reason_code: "oidc-token-type-invalid" });
  });

  it("requires the exact current credential-ledger binding in every projected JWT", () => {
    const access = projectAccessToken(x.projection("access_token"));
    const missing = resignJwt(access.compact, (claims) => {
      delete claims.credential_ledger_generation;
    });
    expect(validateProjectedJwt(missing, x.metadata.issuer, "https://api.example",
      { keys: [OIDC_RSA_ONE.public_jwk] }, options("access_token")))
      .toMatchObject({ allowed: false, reason_code: "credential_generation_missing" });
    const stale = resignJwt(access.compact, (claims) => {
      claims.credential_ledger_generation =
        x.issuedState.credential_ledger.credential_ledger_generation + 1;
    });
    expect(validateProjectedJwt(stale, x.metadata.issuer, "https://api.example",
      { keys: [OIDC_RSA_ONE.public_jwk] }, options("access_token")))
      .toMatchObject({ allowed: false, reason_code: "credential_generation_stale" });
  });

  it("recomputes release, mint eligibility, returnability and full checkpoint", () => {
    expect(() => projectIdToken({ ...x.projection("id_token"), client_id: "caller-substitution" })).toThrow(/projection|token/i);
    expect(() => projectIdToken({ ...x.projection("id_token"), issuance_record_id: x.registrationRecord.record_id })).toThrow(/issuance/i);
    expect(() => projectIdToken({ ...x.projection("id_token"),
      authorization: { ...x.request, requested_claims: [] } as never })).toThrow(/projection|authorization|grant/i);
    expect(() => projectIdToken({ ...x.projection("id_token"),
      authorization: { ...x.request, nonce: "substituted-nonce" } as never })).toThrow(/projection|token|authorization|grant/i);
    const otherKey = fixtures.personas.carol.epoch_keys.epoch_1.pubkey;
    const otherIdentity = {
      persona_key: otherKey,
      persona_npub: nip19.npubEncode(otherKey),
    };
    expect(() => projectIdToken({ ...x.projection("id_token"), identity: otherIdentity,
      issuer: `https://node.example/oidc/${otherIdentity.persona_npub}` })).toThrow(/issuer/i);
    expect(() => projectJwtAssertion({ ...x.projection("jwt_assertion"),
      authorization: { ...x.request, registration: x.request.consent } as never }, "urn:example:jwt-assertion:v1"))
      .toThrow(/registered|authorization|token|grant/i);
  });

  it("requires closed JWKS and exact RSA public-key metadata", () => {
    const token = projectIdToken(x.projection("id_token"));
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
    const access = projectAccessToken(x.projection("access_token"));
    expect(validateProjectedJwt(access.compact, x.metadata.issuer, "https://api.example", { keys: [OIDC_RSA_ONE.public_jwk] },
      options("access_token"))).toMatchObject({ allowed: true });
    expect(validateProjectedJwt(access.compact, x.metadata.issuer, "https://api.example", { keys: [OIDC_RSA_ONE.public_jwk] },
      options("access_token", { permitted_audiences: ["https://api.example", "https://extra.example"] })))
      .toMatchObject({ allowed: false, reason_code: "oidc-audience-invalid" });
    expect(validateProjectedJwt(access.compact, x.metadata.issuer, "registered-client", { keys: [OIDC_RSA_ONE.public_jwk] },
      options("id_token", { nonce: "oidc-vector-nonce" }))).toMatchObject({ allowed: false });
    const invalidCnf = { jkt: "Q".repeat(42) };
    expect(() => projectAccessToken({ ...x.projection("access_token"),
      authorization: { ...x.request, cnf: invalidCnf, sender_constraint: "dpop" } as never }))
      .toThrow(/cnf|evidence|authorization|grant/i);
  });

  it.each([
    ["non-canonical subject", (claims: Record<string, unknown>) => { claims.sub = "not-a-pairwise-subject"; }],
    ["short jti", (claims: Record<string, unknown>) => { claims.jti = "short"; }],
    ["duplicate unsorted scope", (claims: Record<string, unknown>) => { claims.scope = "profile openid profile"; }],
  ])("rejects a correctly re-signed JWT with %s", (_label, mutate) => {
    const access = projectAccessToken(x.projection("access_token"));
    const malformed = resignJwt(access.compact, mutate);
    expect(validateProjectedJwt(malformed, x.metadata.issuer, "https://api.example",
      { keys: [OIDC_RSA_ONE.public_jwk] }, options("access_token")))
      .toMatchObject({ allowed: false, reason_code: "oidc-token-type-invalid" });
  });
});
