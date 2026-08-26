import { createHash, createPrivateKey, sign, type JsonWebKey } from "node:crypto";
import { deflateSync, inflateSync } from "node:zlib";
import { beforeAll, describe, expect, it } from "vitest";
import { buildFixtures } from "./fixtures.js";
import { utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE, OIDC_RSA_TWO } from "./oidc-rsa-fixtures.js";
import { buildLiveOidcScenario } from "./oidc-test-support.js";
import { buildLedgerRepositoryEvidence, mergeClaimLedger } from "./claim-ledger.js";
import {
  createValidatedProjectedJwtContext,
  projectAccessToken,
  type JwtValidationOptions,
} from "./oidc.js";
import {
  MAX_STATUS_LIST_BYTES,
  STATUS_LIST_MEDIA_TYPE,
  buildContinuityTree,
  continuityManifestDigest,
  continuitySuccessorDigest,
  createContinuityAuthorityProof,
  createPersonaSuccessionProof,
  encodeStatusList,
  generateStatusListToken,
  resolveIssuerContinuity,
  validateIssuerContinuityChain,
  validateTokenStatus,
  type ContinuityManifest,
  type ContinuityManifestBody,
  type ContinuityValidationContext,
} from "./token-status.js";

const fixtures = buildFixtures();
let x: Awaited<ReturnType<typeof buildLiveOidcScenario>>;

beforeAll(async () => {
  x = await buildLiveOidcScenario(fixtures);
});

const sha256 = (value: Uint8Array | string): string =>
  createHash("sha256").update(value).digest("hex");
const statusIat = (): number => x.issuedState.checkpoint.observed_at;
const statusUri = (): string => `${x.metadata.issuer}/${x.issuance.reservation.uri}`;
const jwksBytes = (): Uint8Array =>
  Buffer.from(JSON.stringify({ keys: [OIDC_RSA_ONE.public_jwk] }));

function resignStatusToken(
  token: ReturnType<typeof generateStatusListToken>,
  lst: string,
  overrides: Partial<ReturnType<typeof generateStatusListToken>["claims"]> = {},
) {
  const claims = {
    ...token.claims,
    ...overrides,
    status_list: { bits: 1 as const, lst },
  };
  const header = Buffer.from(JSON.stringify(token.protected_header)).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${header}.${payload}`;
  const key = createPrivateKey({
    key: OIDC_RSA_ONE.private_jwk as JsonWebKey,
    format: "jwk",
  });
  return {
    ...token,
    claims,
    compact: `${input}.${sign("RSA-SHA256", Buffer.from(input), key).toString("base64url")}`,
  };
}

function resignReferencedJwt(
  compact: string,
  mutate: (claims: Record<string, any>) => void,
): string {
  const [header, payload] = compact.split(".");
  const claims = JSON.parse(
    Buffer.from(payload, "base64url").toString("utf8"),
  ) as Record<string, any>;
  mutate(claims);
  const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${header}.${encoded}`;
  const key = createPrivateKey({
    key: OIDC_RSA_ONE.private_jwk as JsonWebKey,
    format: "jwk",
  });
  return `${input}.${sign("RSA-SHA256", Buffer.from(input), key).toString("base64url")}`;
}

function generateToken(ttl = 30) {
  return generateStatusListToken({
    state: x.issuedState,
    uri: statusUri(),
    private_jwk: OIDC_RSA_ONE.private_jwk,
    iat: statusIat(),
    exp: statusIat() + 60,
    ttl,
  });
}

function manifestBodyFor(
  token: ReturnType<typeof generateStatusListToken>,
): ContinuityManifestBody {
  return {
    profile: "heterodyne-oidc-continuity-v1",
    repository_rid: x.s.rid,
    branch: "main",
    persona_npub: x.personaNpub,
    persona_key: x.personaKey,
    issuer: x.metadata.issuer,
    sequence: 0,
    predecessor_digest: null,
    max_checkpoint_age_seconds: 300,
    current_jwks_sha256: sha256(jwksBytes()),
    current_signing_key_id: OIDC_RSA_ONE.key_id,
    current_signing_jwk_sha256: sha256(utf8Bytes(jcsCanonicalize(OIDC_RSA_ONE.public_jwk))),
    retiring_signing_key_ids: [],
    retiring_jwks_sha256: [],
    status_lists: [{
      path: x.projection.status_mirror.path,
      sha256: sha256(token.compact),
      issuer: x.metadata.issuer,
      uri: token.claims.sub,
    }],
    successor: null,
    authority: {
      writer_nid: x.s.writerOne.did_key,
      issued_at: x.issuedState.checkpoint.observed_at,
      checkpoint: x.issuedState.checkpoint,
    },
  };
}

function signedManifest(
  body: ContinuityManifestBody,
  writerSecret = x.s.writerOne.private_key,
): ContinuityManifest {
  return {
    ...body,
    authority_proof: createContinuityAuthorityProof(body, writerSecret),
  };
}

function continuityContext(
  overrides: Partial<ContinuityValidationContext> = {},
): ContinuityValidationContext {
  return {
    identity: x.identity,
    repository_rid: x.s.rid,
    canonical_branch: "main",
    writer_nid: x.s.writerOne.did_key,
    now: statusIat(),
    ledger_state: x.issuedState,
    succession_authority: null,
    active_persona_authority: null,
    ...overrides,
  };
}

function continuityChain(token: ReturnType<typeof generateStatusListToken>) {
  const manifest = signedManifest(manifestBodyFor(token));
  return validateIssuerContinuityChain([{
    manifest,
    context: continuityContext(),
  }]);
}

function validatedAccessContext(token: ReturnType<typeof generateStatusListToken>) {
  const manifest = signedManifest(manifestBodyFor(token));
  const projection = {
    ...x.projection,
    status_mirror: {
      ...x.projection.status_mirror,
      sha256: continuityManifestDigest(manifest),
    },
  };
  const projected = projectAccessToken(projection);
  return createValidatedProjectedJwtContext(
    projected.compact,
    x.metadata.issuer,
    "https://api.example",
    { keys: [OIDC_RSA_ONE.public_jwk] },
    {
      now: x.issuance.issued_at,
      token_use: "access_token",
      client_id: "registered-client",
      sender_constraint: "none",
      permitted_audiences: ["https://api.example"],
      credential_ledger: x.issuedState.credential_ledger,
    },
  );
}

describe("live one-bit status-list semantics", () => {
  it("packs LSB to MSB in canonical unpadded base64url", () => {
    expect(encodeStatusList([1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]))
      .toEqual({ bits: 1, lst: "eNrbuRgAAhcBXQ" });
    expect(encodeStatusList([1, 0, 0, 0, 0, 0, 0, 0]).lst).not.toContain("=");
    expect(STATUS_LIST_MEDIA_TYPE).toBe("application/statuslist+jwt");
  });

  it("accepts a valid alternative ZLIB-wrapped DEFLATE representation", () => {
    const canonical = generateToken();
    const raw = inflateSync(Buffer.from(canonical.claims.status_list.lst, "base64url"));
    const alternative = resignStatusToken(
      canonical,
      deflateSync(raw, { level: 1 }).toString("base64url"),
    );
    expect(validateTokenStatus(
      validatedAccessContext(alternative),
      alternative,
      jwksBytes(),
      statusIat(),
      statusIat(),
      continuityChain(alternative),
    )).toMatchObject({ allowed: true });
  });

  it("rejects authenticated decompression above the output bound", () => {
    const canonical = generateToken();
    const oversized = resignStatusToken(
      canonical,
      deflateSync(Buffer.alloc(MAX_STATUS_LIST_BYTES + 1)).toString("base64url"),
    );
    expect(validateTokenStatus(
      validatedAccessContext(oversized),
      oversized,
      jwksBytes(),
      statusIat(),
      statusIat(),
      continuityChain(oversized),
    )).toMatchObject({ allowed: false, reason_code: "oidc-status-invalid" });
  });

  it("generates a deterministic active-persona-bound status token", () => {
    const token = generateToken();
    expect(token.protected_header).toEqual({
      alg: "RS256",
      kid: OIDC_RSA_ONE.key_id,
      typ: "statuslist+jwt",
    });
    expect(token.claims).toMatchObject({
      sub: statusUri(),
      ...x.issuedState.credential_ledger,
    });
    expect(generateToken().compact).toBe(token.compact);
  });

  it("rejects another credential-ledger generation", () => {
    const token = generateToken();
    const stale = resignStatusToken(token, token.claims.status_list.lst, {
      credential_ledger_generation:
        x.issuedState.credential_ledger.credential_ledger_generation + 1,
    });
    expect(validateTokenStatus(
      validatedAccessContext(stale),
      stale,
      jwksBytes(),
      statusIat(),
      statusIat(),
      continuityChain(stale),
    )).toMatchObject({ allowed: false });
  });

  it("requires the branded validated referenced JWT context", () => {
    const token = generateToken();
    const validated = validatedAccessContext(token);
    expect(validateTokenStatus(
      validated,
      token,
      jwksBytes(),
      statusIat(),
      statusIat(),
      continuityChain(token),
    )).toMatchObject({ allowed: true });
    expect(validateTokenStatus(
      { ...validated } as never,
      token,
      jwksBytes(),
      statusIat(),
      statusIat(),
      continuityChain(token),
    )).toMatchObject({ allowed: false });
  });

  it("binds raw JWKS bytes and fractional TTL to trusted resolution time", () => {
    const token = generateToken(0.5);
    const referenced = validatedAccessContext(token);
    const chain = continuityChain(token);
    expect(validateTokenStatus(
      referenced,
      token,
      jwksBytes(),
      statusIat() + 1,
      statusIat() + 0.5,
      chain,
    )).toMatchObject({ allowed: true });
    expect(validateTokenStatus(
      referenced,
      token,
      Buffer.concat([jwksBytes(), Buffer.from("\n")]),
      statusIat(),
      statusIat(),
      chain,
    )).toMatchObject({ allowed: false });
  });

  it("fails closed for invalid, malformed, and unauthenticated status", () => {
    const valid = generateToken();
    const invalid = resignStatusToken(valid, encodeStatusList([1]).lst);
    expect(validateTokenStatus(
      validatedAccessContext(invalid),
      invalid,
      jwksBytes(),
      statusIat(),
      statusIat(),
      continuityChain(invalid),
    )).toMatchObject({ allowed: false, reason_code: "oidc-status-invalid" });
    const malformed = resignStatusToken(valid, "eA");
    expect(validateTokenStatus(
      validatedAccessContext(malformed),
      malformed,
      jwksBytes(),
      statusIat(),
      statusIat(),
      continuityChain(malformed),
    )).toMatchObject({ allowed: false });
    const [header, payload, signature] = valid.compact.split(".");
    const badSignature = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
    expect(validateTokenStatus(
      validatedAccessContext(valid),
      { ...valid, compact: `${header}.${payload}.${badSignature}` },
      jwksBytes(),
      statusIat(),
      statusIat(),
      continuityChain(valid),
    )).toMatchObject({ allowed: false, reason_code: "oidc-status-invalid" });
  });

  it("rejects an authenticated referenced index outside the status bytes", () => {
    const token = generateToken();
    const manifest = signedManifest(manifestBodyFor(token));
    const projected = projectAccessToken({
      ...x.projection,
      status_mirror: {
        ...x.projection.status_mirror,
        sha256: continuityManifestDigest(manifest),
      },
    });
    const outOfRange = resignReferencedJwt(projected.compact, (claims) => {
      claims.status.status_list.idx = 8;
    });
    const options: JwtValidationOptions = {
      now: x.issuance.issued_at,
      token_use: "access_token",
      client_id: "registered-client",
      sender_constraint: "none",
      permitted_audiences: ["https://api.example"],
      credential_ledger: x.issuedState.credential_ledger,
    };
    const context = createValidatedProjectedJwtContext(
      outOfRange,
      x.metadata.issuer,
      "https://api.example",
      { keys: [OIDC_RSA_ONE.public_jwk] },
      options,
    );
    expect(validateTokenStatus(
      context,
      token,
      jwksBytes(),
      statusIat(),
      statusIat(),
      validateIssuerContinuityChain([{ manifest, context: continuityContext() }]),
    )).toMatchObject({ allowed: false, reason_code: "oidc-status-invalid" });
  });
});

describe("live active-persona issuer continuity", () => {
  it("materializes the closed public tree under the active persona npub", () => {
    const token = generateToken();
    const manifest = signedManifest(manifestBodyFor(token));
    const tree = buildContinuityTree(
      manifest,
      { issuer: manifest.issuer },
      jwksBytes(),
      new Map([[manifest.status_lists[0].path, Buffer.from(token.compact)]]),
    );
    expect([...tree.keys()].sort()).toEqual([
      `.well-known/${x.personaNpub}/issuer.json`,
      `.well-known/${x.personaNpub}/jwks.json`,
      `.well-known/${x.personaNpub}/manifest.json`,
      `.well-known/${x.personaNpub}/openid-configuration`,
      manifest.status_lists[0].path,
    ].sort());
  });

  it("accepts exact active persona fields and rejects legacy authority members", () => {
    const manifest = signedManifest(manifestBodyFor(generateToken()));
    expect(resolveIssuerContinuity(null, manifest, continuityContext()))
      .toMatchObject({ allowed: true, standard_oidc_action: "retain-exact-issuer" });
    const legacy = {
      ...manifest,
      cold_root_npub: x.personaNpub,
      cold_root_hex: x.personaKey,
      persona_kel_head: { id: "00".repeat(32), seq: 0 },
    };
    expect(resolveIssuerContinuity(null, legacy as never, continuityContext()))
      .toMatchObject({ allowed: false });
  });

  it("validates a same-persona refresh and rejects a broken predecessor", () => {
    const initial = signedManifest(manifestBodyFor(generateToken()));
    const body = {
      ...manifestBodyFor(generateToken()),
      sequence: 1,
      predecessor_digest: continuityManifestDigest(initial),
    };
    const refreshed = signedManifest(body);
    expect(validateIssuerContinuityChain([
      { manifest: initial, context: continuityContext() },
      { manifest: refreshed, context: continuityContext() },
    ]).current.sequence).toBe(1);
    const broken = signedManifest({ ...body, predecessor_digest: "00".repeat(32) });
    expect(() => validateIssuerContinuityChain([
      { manifest: initial, context: continuityContext() },
      { manifest: broken, context: continuityContext() },
    ])).toThrow(/status|chain/i);
  });

  it("binds successor proof to the current active persona and candidate", () => {
    const token = generateToken();
    const base = manifestBodyFor(token);
    const successorIssuer = base.issuer.replace("node.example", "successor.example");
    const commitment = signedManifest({
      ...base,
      issuer: successorIssuer,
      sequence: 1,
      predecessor_digest: "00".repeat(32),
    });
    const previous = signedManifest({
      ...base,
      successor: {
        issuer: successorIssuer,
        manifest_sha256: continuitySuccessorDigest(commitment),
      },
    });
    const candidate = signedManifest({
      ...base,
      issuer: successorIssuer,
      sequence: 1,
      predecessor_digest: continuityManifestDigest(previous),
    });
    const context = continuityContext({
      succession_authority: createPersonaSuccessionProof(
        candidate,
        "active-persona",
        fixtures.personas.alice.epoch_keys.epoch_1.private_key,
      ),
      active_persona_authority: {
        persona_key: x.personaKey,
        valid_from: candidate.authority.issued_at,
        valid_until: candidate.authority.issued_at + 300,
      },
    });
    expect(resolveIssuerContinuity(previous, candidate, context))
      .toMatchObject({ allowed: true, standard_oidc_action: "register-successor" });
    expect(resolveIssuerContinuity(previous, candidate, {
      ...context,
      succession_authority: createPersonaSuccessionProof(
        candidate,
        "active-persona",
        fixtures.personas.carol.epoch_keys.epoch_1.private_key,
      ),
    })).toMatchObject({ allowed: false, reason_code: "oidc-issuer-authority-invalid" });
  });

  it("retains unexpired status and signing-key material and rejects duplicate paths", () => {
    const body = manifestBodyFor(generateToken());
    const duplicate = signedManifest({
      ...body,
      status_lists: [...body.status_lists, { ...body.status_lists[0] }],
    });
    expect(resolveIssuerContinuity(null, duplicate, continuityContext()))
      .toMatchObject({ allowed: false });
    expect(resolveIssuerContinuity(null, signedManifest({
      ...body,
      status_lists: [],
    }), continuityContext())).toMatchObject({
      allowed: false,
      reason_code: "oidc-status-invalid",
    });

    const records = [...x.s.issuerKeyEpochTwoState.records, x.s.reservationOne];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: x.s.rid,
      confirmed_records: records,
      observed_at: x.s.issuerKeyEpochTwoRepository.checkpoint.observed_at + 1,
      prior: x.s.issuerKeyEpochTwoRepository.repository,
    });
    const state = mergeClaimLedger(
      records,
      [],
      repository.checkpoint,
      x.s.makeTask5Context(repository.repository),
    );
    const rotatedBody: ContinuityManifestBody = {
      ...body,
      status_lists: [{
        ...body.status_lists[0],
        path: `.well-known/${x.personaNpub}/${x.s.issuanceOne.reservation.uri}`,
        uri: `${body.issuer}/${x.s.issuanceOne.reservation.uri}`,
      }],
      current_signing_key_id: OIDC_RSA_TWO.key_id,
      current_signing_jwk_sha256: sha256(
        utf8Bytes(jcsCanonicalize(OIDC_RSA_TWO.public_jwk)),
      ),
      retiring_signing_key_ids: [OIDC_RSA_ONE.key_id],
      retiring_jwks_sha256: [sha256(
        utf8Bytes(jcsCanonicalize(OIDC_RSA_ONE.public_jwk)),
      )],
      authority: {
        writer_nid: x.s.writerTwo.did_key,
        issued_at: repository.checkpoint.observed_at,
        checkpoint: repository.checkpoint,
      },
    };
    const rotatedContext = continuityContext({
      writer_nid: x.s.writerTwo.did_key,
      now: repository.checkpoint.observed_at,
      ledger_state: state,
    });
    expect(resolveIssuerContinuity(
      null,
      signedManifest(rotatedBody, x.s.writerTwo.private_key),
      rotatedContext,
    )).toMatchObject({ allowed: true });
    expect(resolveIssuerContinuity(null, signedManifest({
      ...rotatedBody,
      retiring_signing_key_ids: [],
      retiring_jwks_sha256: [],
    }, x.s.writerTwo.private_key), rotatedContext)).toMatchObject({
      allowed: false,
      reason_code: "oidc-status-invalid",
    });
  });
});
