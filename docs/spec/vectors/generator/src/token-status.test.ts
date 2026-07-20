import { createHash, createPrivateKey, sign, type JsonWebKey } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { nip19 } from "nostr-tools";
import { buildFixtures } from "./fixtures.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE, OIDC_RSA_TWO } from "./oidc-rsa-fixtures.js";
import { buildLedgerRepositoryEvidence, mergeClaimLedger } from "./claim-ledger.js";
import {
  createValidatedProjectedJwtContext,
  projectAccessToken,
  type JwtValidationOptions,
} from "./oidc.js";
import { buildOidcScenario, buildTokenStatusVectors } from "./topics-oidc.js";
import {
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
  type ContinuityValidationContext,
} from "./token-status.js";

const fixtures = buildFixtures();
let x: Awaited<ReturnType<typeof buildOidcScenario>>;

beforeAll(async () => { x = await buildOidcScenario(fixtures); });
const statusIat = () => x.issuedState.checkpoint.observed_at;

function resignStatusToken(token: ReturnType<typeof generateStatusListToken>, lst: string) {
  const claims = { ...token.claims, status_list: { bits: 1 as const, lst } };
  const header = Buffer.from(JSON.stringify(token.protected_header)).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${header}.${payload}`;
  const key = createPrivateKey({ key: OIDC_RSA_ONE.private_jwk as JsonWebKey, format: "jwk" });
  return { ...token, claims, compact: `${input}.${sign("RSA-SHA256", Buffer.from(input), key).toString("base64url")}` };
}

function resignReferencedJwt(compact: string, mutate: (claims: Record<string, any>) => void): string {
  const [header, payload] = compact.split(".");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, any>;
  mutate(claims);
  const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${header}.${encoded}`;
  const key = createPrivateKey({ key: OIDC_RSA_ONE.private_jwk as JsonWebKey, format: "jwk" });
  return `${input}.${sign("RSA-SHA256", Buffer.from(input), key).toString("base64url")}`;
}

function statusManifestFor(token: ReturnType<typeof generateStatusListToken>): ContinuityManifest {
  const rootHex = fixtures.personas.alice.cold_root.pubkey;
  const root = nip19.npubEncode(rootHex);
  const jwksBytes = Buffer.from(JSON.stringify({ keys: [OIDC_RSA_ONE.public_jwk] }));
  const body = { profile: "heterodyne-oidc-continuity-v1" as const, repository_rid: x.s.rid,
    branch: "main" as const, cold_root_npub: root, cold_root_hex: rootHex,
    persona_kel_head: fixtures.kel.alice.head, issuer: x.metadata.issuer, sequence: 0,
    predecessor_digest: null, max_checkpoint_age_seconds: 300,
    current_jwks_sha256: createHash("sha256").update(jwksBytes).digest("hex"),
    current_signing_key_id: OIDC_RSA_ONE.key_id,
    current_signing_jwk_sha256: createHash("sha256").update(jcsCanonicalize(OIDC_RSA_ONE.public_jwk)).digest("hex"),
    retiring_signing_key_ids: [], retiring_jwks_sha256: [],
    status_lists: [{ path: x.projection.status_mirror.path,
      sha256: createHash("sha256").update(token.compact).digest("hex") }],
    successor: null, authority: { writer_nid: x.s.writerOne.did_key, issued_at: x.issuance.issued_at } };
  return { ...body, authority_proof: createContinuityAuthorityProof(body, x.s.writerOne.private_key) };
}

function validationChain(token: ReturnType<typeof generateStatusListToken>) {
  const manifest = statusManifestFor(token);
  return validateIssuerContinuityChain([{ manifest, context: {
    identity: x.identity, expected_kel_head: fixtures.kel.alice.head, repository_rid: x.s.rid,
    canonical_branch: "main", writer_nid: x.s.writerOne.did_key, now: statusIat(), ledger_state: x.issuedState,
    succession_authority: null, current_epoch_authority: { npub: x.epoch, kel_head: fixtures.kel.alice.head,
      valid_from: x.issuance.issued_at, valid_until: x.issuance.expires_at + 1_000, core_kel_authority_valid: true },
  } }]);
}

function validatedAccessContext(token: ReturnType<typeof generateStatusListToken>) {
  const manifest = statusManifestFor(token);
  const projection = { ...x.projection, status_mirror: { ...x.projection.status_mirror,
    sha256: continuityManifestDigest(manifest) } };
  const projected = projectAccessToken(projection);
  return createValidatedProjectedJwtContext(projected.compact, x.metadata.issuer,
    "https://api.example", { keys: [OIDC_RSA_ONE.public_jwk] }, {
      now: x.issuance.issued_at, token_use: "access_token", client_id: "registered-client",
      sender_constraint: "none", permitted_audiences: ["https://api.example"],
    });
}

describe("draft-ietf-oauth-status-list-21 exact one-bit profile", () => {
  it("packs LSB to MSB, uses level-9 DEFLATE in a ZLIB wrapper, and canonical base64url", () => {
    expect(encodeStatusList([1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1])).toEqual({
      bits: 1,
      lst: "eNrbuRgAAhcBXQ",
    });
    expect(encodeStatusList([1, 0, 0, 0, 0, 0, 0, 0]).lst).not.toContain("=");
    expect(STATUS_LIST_MEDIA_TYPE).toBe("application/statuslist+jwt");
  });

  it("signs a strict deterministic statuslist+jwt from validated canonical ledger state", () => {
    const uri = `${x.metadata.issuer}/${x.issuance.reservation.uri}`;
    const token = generateStatusListToken({
      state: x.issuedState, uri, private_jwk: OIDC_RSA_ONE.private_jwk,
      iat: statusIat(), exp: statusIat() + 60, ttl: 30,
    });
    expect(token.protected_header).toEqual({ alg: "RS256", kid: OIDC_RSA_ONE.public_jwk.kid, typ: "statuslist+jwt" });
    expect(token.claims).toMatchObject({ sub: uri, iat: statusIat(),
      exp: statusIat() + 60, ttl: 30, status_list: { bits: 1 } });
    expect(generateStatusListToken({
      state: x.issuedState, uri, private_jwk: OIDC_RSA_ONE.private_jwk,
      iat: statusIat(), exp: statusIat() + 60, ttl: 30,
    }).compact).toBe(token.compact);
    expect(() => generateStatusListToken({
      state: x.issuedState, uri, private_jwk: OIDC_RSA_ONE.private_jwk,
      iat: x.issuedState.checkpoint.observed_at - 1, exp: statusIat() + 60, ttl: 30,
    })).toThrow(/predates|checkpoint|stale/i);
  });

  it("requires an unforgeable fully validated referenced JWT and never lets VALID override base failures", () => {
    const uri = `${x.metadata.issuer}/${x.issuance.reservation.uri}`;
    const statusToken = generateStatusListToken({
      state: x.issuedState, uri, private_jwk: OIDC_RSA_ONE.private_jwk,
      iat: statusIat(), exp: statusIat() + 60, ttl: 30,
    });
    const validated = validatedAccessContext(statusToken);
    expect(validateTokenStatus(validated, statusToken, { keys: [OIDC_RSA_ONE.public_jwk] }, statusIat(), validationChain(statusToken)))
      .toMatchObject({ allowed: true });
    expect(validateTokenStatus({ ...validated } as never, statusToken,
      { keys: [OIDC_RSA_ONE.public_jwk] }, statusIat(), validationChain(statusToken))).toMatchObject({ allowed: false });
    const projected = projectAccessToken({ ...x.projection, status_mirror: { ...x.projection.status_mirror,
      sha256: createHash("sha256").update(statusToken.compact).digest("hex") } });
    const options: JwtValidationOptions = { now: x.issuance.issued_at, token_use: "access_token",
      client_id: "registered-client", sender_constraint: "none", permitted_audiences: ["https://api.example"] };
    expect(() => createValidatedProjectedJwtContext(projected.compact, x.metadata.issuer,
      "https://wrong.example", { keys: [OIDC_RSA_ONE.public_jwk] }, options)).toThrow();
  });

  it("follows a valid refresh from an immutable manifest anchor and rejects a broken predecessor chain", () => {
    const uri = `${x.metadata.issuer}/${x.issuance.reservation.uri}`;
    const statusToken = generateStatusListToken({ state: x.issuedState, uri,
      private_jwk: OIDC_RSA_ONE.private_jwk, iat: statusIat(), exp: statusIat() + 60, ttl: 30 });
    const anchor = statusManifestFor(statusToken);
    const { authority_proof: _proof, ...anchorBody } = anchor;
    const refreshedBody = { ...anchorBody, sequence: 1, predecessor_digest: continuityManifestDigest(anchor) };
    const refreshed: ContinuityManifest = { ...refreshedBody,
      authority_proof: createContinuityAuthorityProof(refreshedBody, x.s.writerOne.private_key) };
    const context: ContinuityValidationContext = { identity: x.identity,
      expected_kel_head: fixtures.kel.alice.head, repository_rid: x.s.rid, canonical_branch: "main",
      writer_nid: x.s.writerOne.did_key, now: statusIat(), ledger_state: x.issuedState,
      succession_authority: null, current_epoch_authority: { npub: x.epoch, kel_head: fixtures.kel.alice.head,
        valid_from: x.issuance.issued_at, valid_until: x.issuance.expires_at + 1_000,
        core_kel_authority_valid: true } };
    const chain = validateIssuerContinuityChain([{ manifest: anchor, context }, { manifest: refreshed, context }]);
    expect(validateTokenStatus(validatedAccessContext(statusToken), statusToken,
      { keys: [OIDC_RSA_ONE.public_jwk] }, statusIat(), chain)).toMatchObject({ allowed: true });
    const brokenBody = { ...refreshedBody, predecessor_digest: "00".repeat(32) };
    const broken: ContinuityManifest = { ...brokenBody,
      authority_proof: createContinuityAuthorityProof(brokenBody, x.s.writerOne.private_key) };
    expect(() => validateIssuerContinuityChain([{ manifest: anchor, context }, { manifest: broken, context }]))
      .toThrow(/digest|chain/);
  });

  it("fails closed for INVALID, stale, malformed, unverifiable, and out-of-range status", () => {
    const uri = `${x.metadata.issuer}/${x.issuance.reservation.uri}`;
    const validToken = generateStatusListToken({ state: x.issuedState, uri,
      private_jwk: OIDC_RSA_ONE.private_jwk, iat: statusIat(),
      exp: statusIat() + 60, ttl: 30 });
    const statusToken = resignStatusToken(validToken, encodeStatusList([1]).lst);
    const validated = validatedAccessContext(statusToken);
    expect(validateTokenStatus(validated, statusToken, { keys: [OIDC_RSA_ONE.public_jwk] }, statusIat(), validationChain(statusToken)))
      .toMatchObject({ allowed: false, reason_code: "oidc-status-invalid" });
    expect(validateTokenStatus(validated, { ...statusToken, compact: `${statusToken.compact}x` },
      { keys: [OIDC_RSA_ONE.public_jwk] }, statusIat(), validationChain(statusToken))).toMatchObject({ allowed: false });
    const valid = generateStatusListToken({ state: x.issuedState, uri, private_jwk: OIDC_RSA_ONE.private_jwk,
      iat: statusIat(), exp: statusIat() + 60, ttl: 1 });
    const validContext = validatedAccessContext(valid);
    expect(validateTokenStatus(validContext, valid, { keys: [OIDC_RSA_ONE.public_jwk] }, statusIat() + 1, validationChain(valid)))
      .toMatchObject({ allowed: false, reason_code: "oidc-status-stale" });

    const projection = { ...x.projection, status_mirror: { ...x.projection.status_mirror,
      sha256: continuityManifestDigest(statusManifestFor(valid)) } };
    const projected = projectAccessToken(projection);
    const outOfRange = resignReferencedJwt(projected.compact, (claims) => { claims.status.status_list.idx = 8; });
    const outOfRangeContext = createValidatedProjectedJwtContext(outOfRange, x.metadata.issuer,
      "https://api.example", { keys: [OIDC_RSA_ONE.public_jwk] }, {
        now: x.issuance.issued_at, token_use: "access_token", client_id: "registered-client",
        sender_constraint: "none", permitted_audiences: ["https://api.example"],
      });
    expect(validateTokenStatus(outOfRangeContext, valid, { keys: [OIDC_RSA_ONE.public_jwk] }, statusIat(), validationChain(valid)))
      .toMatchObject({ allowed: false, reason_code: "oidc-status-index-invalid" });
    const malformed = resignStatusToken(valid, "eA");
    expect(validateTokenStatus(validatedAccessContext(malformed), malformed,
      { keys: [OIDC_RSA_ONE.public_jwk] }, statusIat(), validationChain(malformed))).toMatchObject({ allowed: false });
    expect(validateTokenStatus(validatedAccessContext(valid), { ...valid, media_type: "application/jwt" as never },
      { keys: [OIDC_RSA_ONE.public_jwk] }, statusIat(), validationChain(valid))).toMatchObject({ allowed: false });
    expect(validateTokenStatus(validatedAccessContext(valid), valid,
      { keys: [OIDC_RSA_ONE.public_jwk] }, x.issuance.expires_at, validationChain(valid))).toMatchObject({
        allowed: false, reason_code: "oidc-token-type-invalid",
      });
  });
});

describe("root-scoped Radicle issuer continuity", () => {
  function fixtureManifest(sequence = 0): { manifest: ContinuityManifest; context: ContinuityValidationContext } {
    const rootHex = fixtures.personas.alice.cold_root.pubkey;
    const root = nip19.npubEncode(rootHex);
    const jwksBytes = Buffer.from(JSON.stringify({ keys: [OIDC_RSA_ONE.public_jwk] }));
    const unsigned = {
      profile: "heterodyne-oidc-continuity-v1" as const,
      repository_rid: x.s.rid, branch: "main" as const,
      cold_root_npub: root, cold_root_hex: rootHex, persona_kel_head: fixtures.kel.alice.head,
      issuer: x.metadata.issuer, sequence, predecessor_digest: null,
      max_checkpoint_age_seconds: 300,
      current_jwks_sha256: createHash("sha256").update(jwksBytes).digest("hex"),
      current_signing_key_id: OIDC_RSA_ONE.key_id,
      current_signing_jwk_sha256: createHash("sha256").update(jcsCanonicalize(OIDC_RSA_ONE.public_jwk)).digest("hex"),
      retiring_signing_key_ids: [], retiring_jwks_sha256: [], status_lists: [], successor: null,
      authority: { writer_nid: x.s.writerOne.did_key, issued_at: x.issuance.issued_at },
    };
    const manifest = { ...unsigned, authority_proof: createContinuityAuthorityProof(unsigned, x.s.writerOne.private_key) };
    return { manifest, context: {
      identity: x.identity, expected_kel_head: fixtures.kel.alice.head,
      repository_rid: x.s.rid, canonical_branch: "main", writer_nid: x.s.writerOne.did_key,
      now: x.issuedState.checkpoint.observed_at, ledger_state: x.issuedState, succession_authority: null,
      current_epoch_authority: { npub: x.epoch, kel_head: fixtures.kel.alice.head,
        valid_from: x.issuance.issued_at, valid_until: x.issuance.expires_at + 1_000,
        core_kel_authority_valid: true as const },
    } };
  }

  it("builds the exact public tree and checks HTTPS/Radicle bytes and SHA-256 digests", () => {
    const { manifest } = fixtureManifest();
    const discovery = { issuer: manifest.issuer };
    const jwks = Buffer.from(JSON.stringify({ keys: [OIDC_RSA_ONE.public_jwk] }));
    const tree = buildContinuityTree(manifest, discovery, jwks, new Map());
    const root = `.well-known/${manifest.cold_root_npub}`;
    expect([...tree.keys()].sort()).toEqual([
      `${root}/issuer.json`, `${root}/jwks.json`, `${root}/manifest.json`, `${root}/openid-configuration`,
    ]);
    expect(Buffer.from(tree.get(`${root}/jwks.json`)!)).toEqual(jwks);
    expect(() => buildContinuityTree(manifest, discovery, Buffer.concat([jwks, Buffer.from("\n")]), new Map()))
      .toThrow(/exact JWKS bytes/);
  });

  it("requires Core persona/KEL/repository/writer/native-proof evidence", () => {
    const { manifest, context } = fixtureManifest();
    expect(resolveIssuerContinuity(null, manifest, context)).toMatchObject({ allowed: true });
    expect(resolveIssuerContinuity(null, manifest, { ...context,
      expected_kel_head: { id: "00".repeat(32), seq: context.expected_kel_head.seq } }))
      .toMatchObject({ allowed: false });
    expect(resolveIssuerContinuity(null, manifest, { ...context, writer_nid: x.s.writerTwo.did_key }))
      .toMatchObject({ allowed: false });
    const { authority_proof: _proof, ...body } = manifest;
    const wrongCurrentBody = { ...body, current_signing_key_id: OIDC_RSA_TWO.key_id };
    const wrongCurrent: ContinuityManifest = { ...wrongCurrentBody,
      authority_proof: createContinuityAuthorityProof(wrongCurrentBody, x.s.writerOne.private_key) };
    expect(resolveIssuerContinuity(null, wrongCurrent, context)).toMatchObject({ allowed: false });
  });

  it("requires persona epoch or cold-root/recovery authority for succession; the shared issuer key is insufficient", () => {
    const { manifest: previous, context } = fixtureManifest();
    const { authority_proof: _proof, ...previousBody } = previous;
    const successorIssuer = previous.issuer.replace("node.example", "successor.example");
    const candidateCommitment = { ...previous, issuer: successorIssuer, sequence: 1,
      predecessor_digest: "00".repeat(32) } as ContinuityManifest;
    const boundPreviousBody = { ...previousBody, successor: { issuer: successorIssuer,
      manifest_sha256: continuitySuccessorDigest(candidateCommitment) } };
    const boundPrevious = { ...boundPreviousBody,
      authority_proof: createContinuityAuthorityProof(boundPreviousBody, x.s.writerOne.private_key) };
    const nextUnsigned = { ...previousBody, issuer: successorIssuer, sequence: 1,
      predecessor_digest: continuityManifestDigest(boundPrevious) };
    const candidate = { ...nextUnsigned,
      authority_proof: createContinuityAuthorityProof(nextUnsigned, x.s.writerOne.private_key) } as ContinuityManifest;
    const updateContext = { ...context, now: x.issuance.expires_at, ledger_state: x.issuedState };
    expect(resolveIssuerContinuity(boundPrevious, candidate, updateContext)).toMatchObject({ allowed: false });
    const epochAuthority = createPersonaSuccessionProof(candidate, "current-persona-epoch",
      fixtures.personas.alice.epoch_keys.epoch_1.private_key);
    expect(resolveIssuerContinuity(boundPrevious, candidate, { ...updateContext,
      succession_authority: epochAuthority,
      current_epoch_authority: { ...context.current_epoch_authority!, valid_until: updateContext.now },
    })).toMatchObject({ allowed: false });
    expect(resolveIssuerContinuity(boundPrevious, candidate, { ...updateContext, succession_authority: epochAuthority }))
      .toMatchObject({ allowed: true });
  });

  it("accepts same-key byte refresh and retains status paths through maximum token expiry", () => {
    const { manifest: initial, context } = fixtureManifest();
    const statusPath = `.well-known/${initial.cold_root_npub}/${x.issuance.reservation.uri}`;
    const { authority_proof: _initialProof, ...initialBody } = initial;
    const previousBody = { ...initialBody, status_lists: [{ path: statusPath, sha256: "11".repeat(32) }] };
    const previous = { ...previousBody,
      authority_proof: createContinuityAuthorityProof(previousBody, x.s.writerOne.private_key) } as ContinuityManifest;
    const candidateBody = { ...previousBody, sequence: 1, predecessor_digest: continuityManifestDigest(previous),
      current_jwks_sha256: "22".repeat(32),
      retiring_signing_key_ids: previous.retiring_signing_key_ids,
      retiring_jwks_sha256: previous.retiring_jwks_sha256 };
    const candidate = { ...candidateBody,
      authority_proof: createContinuityAuthorityProof(candidateBody, x.s.writerOne.private_key) } as ContinuityManifest;
    expect(resolveIssuerContinuity(previous, candidate, context)).toMatchObject({ allowed: true });
    const noStatusBody = { ...candidateBody, status_lists: [] };
    const noStatus = { ...noStatusBody,
      authority_proof: createContinuityAuthorityProof(noStatusBody, x.s.writerOne.private_key) } as ContinuityManifest;
    expect(resolveIssuerContinuity(previous, noStatus, context)).toMatchObject({ allowed: false });
    const sameKeyBody = { ...previousBody, sequence: 1, predecessor_digest: continuityManifestDigest(previous) };
    const sameKey = { ...sameKeyBody,
      authority_proof: createContinuityAuthorityProof(sameKeyBody, x.s.writerOne.private_key) } as ContinuityManifest;
    expect(resolveIssuerContinuity(previous, sameKey, context)).toMatchObject({ allowed: true });
  });

  it("retains every transitively retiring key required by an unexpired issuance", () => {
    const records = [...x.s.issuerKeyEpochTwoState.records, x.s.reservationOne];
    const repository = buildLedgerRepositoryEvidence({ repository_rid: x.s.rid, confirmed_records: records,
      observed_at: x.s.issuerKeyEpochTwoRepository.checkpoint.observed_at + 1,
      prior: x.s.issuerKeyEpochTwoRepository.repository });
    const state = mergeClaimLedger(records, [], repository.checkpoint, x.s.makeTask5Context(repository.repository));
    const { manifest: base, context: baseContext } = fixtureManifest();
    const { authority_proof: _proof, ...baseBody } = base;
    const statusPath = `.well-known/${base.cold_root_npub}/${x.s.issuanceOne.reservation.uri}`;
    const previousBody = { ...baseBody, sequence: 1, predecessor_digest: "11".repeat(32),
      current_jwks_sha256: "22".repeat(32), current_signing_key_id: OIDC_RSA_TWO.key_id,
      current_signing_jwk_sha256: createHash("sha256").update(jcsCanonicalize(OIDC_RSA_TWO.public_jwk)).digest("hex"),
      retiring_signing_key_ids: [OIDC_RSA_ONE.key_id],
      retiring_jwks_sha256: [createHash("sha256").update(jcsCanonicalize(OIDC_RSA_ONE.public_jwk)).digest("hex")],
      status_lists: [{ path: statusPath, sha256: "33".repeat(32) }],
      authority: { writer_nid: x.s.writerTwo.did_key, issued_at: repository.checkpoint.observed_at } };
    const previous: ContinuityManifest = { ...previousBody,
      authority_proof: createContinuityAuthorityProof(previousBody, x.s.writerTwo.private_key) };
    const candidateBody = { ...previousBody, sequence: 2, predecessor_digest: continuityManifestDigest(previous),
      retiring_signing_key_ids: [], retiring_jwks_sha256: [] };
    const candidate: ContinuityManifest = { ...candidateBody,
      authority_proof: createContinuityAuthorityProof(candidateBody, x.s.writerTwo.private_key) };
    const context: ContinuityValidationContext = { ...baseContext, writer_nid: x.s.writerTwo.did_key,
      now: repository.checkpoint.observed_at, ledger_state: state };
    expect(resolveIssuerContinuity(previous, candidate, context)).toMatchObject({ allowed: false,
      reason_code: "oidc-status-digest-mismatch" });
  });

  it("rejects duplicate status paths", () => {
    const { manifest, context } = fixtureManifest();
    const statusPath = `.well-known/${manifest.cold_root_npub}/${x.issuance.reservation.uri}`;
    const { authority_proof: _authorityProof, ...manifestBody } = manifest;
    const duplicateBody = { ...manifestBody,
      status_lists: [{ path: statusPath, sha256: "11".repeat(32) }, { path: statusPath, sha256: "22".repeat(32) }],
    };
    const duplicate = { ...duplicateBody,
      authority_proof: createContinuityAuthorityProof(duplicateBody, x.s.writerOne.private_key) } as ContinuityManifest;
    expect(resolveIssuerContinuity(null, duplicate, context)).toMatchObject({ allowed: false });
  });

  it("replays authoritative invalidations and all compromise retention cases", async () => {
    const vectors = await buildTokenStatusVectors(fixtures);
    const invalidated = vectors.find(({ vector }) => vector.vector_id === "token-status/invalidated-token")!.vector;
    const compromise = vectors.find(({ vector }) => vector.vector_id === "token-status/signing-key-compromise")!.vector;
    expect(invalidated.expected_output).toMatchObject({ verdict: "reject", normalized: {
      regenerated_from_ledger: true,
      evidence_cases: [{ verdict: "accept" }, { verdict: "reject" }, { verdict: "reject" }],
    } });
    expect(compromise.expected_output).toMatchObject({ verdict: "reject", normalized: {
      regenerated_from_ledger: true,
      evidence_cases: [
        { verdict: "accept" }, { verdict: "reject" }, { verdict: "accept" },
      ],
    } });
  });
});
