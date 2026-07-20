import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { nip19 } from "nostr-tools";
import {
  buildLedgerRepositoryEvidence,
  mergeClaimLedger,
  reserveStatusIndex,
  type IssuanceRecord,
  type LedgerRecord,
  type LedgerRecordValidationEvidence,
  type LedgerValidationContext,
} from "./claim-ledger.js";
import { subjectProofPayload, type JsonValue } from "./claims.js";
import type { Fixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import {
  decideDeviceAuthorization,
  derivePairwiseSubject,
  discoveryPaths,
  issueAuthorizationCode,
  issueDeviceAuthorization,
  issuerMetadata,
  projectAccessToken,
  projectIdToken,
  projectJwtAssertion,
  redeemAuthorizationCode,
  redeemDeviceCode,
  validateAuthorizationRequest,
  validateIssuerMetadata,
  validateProjectedJwt,
  type JwtProjectionInput,
  type JwtValidationOptions,
  type OidcAuthorizationRequest,
  type PersonaIdentityState,
  type RegisteredClient,
} from "./oidc.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import {
  buildClaimLedgerScenario,
  decodeClaimLedgerReplayValue,
  encodeClaimLedgerReplayValue,
} from "./topics-claim-ledger.js";
import type { AuthoredVector } from "./types.js";
import { consumeVector } from "./vector-helpers.js";

const API = "https://api.example";
const CLIENT: RegisteredClient = {
  client_id: "registered-client",
  redirect_uris: ["https://client.example/cb"],
  grant_types: ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"],
  scopes: ["heterodyne:key-ref", "openid", "profile"],
  audiences: [API],
  claims: ["https://heterodyne.network/jwt/key-ref", "name"],
  assertion_profiles: ["urn:example:jwt-assertion:v1"],
  sector_identifier: "https://client.example",
};

export async function buildOidcScenario(
  fixtures: Fixtures,
  security: { sender_constraint: "none" | "dpop" | "mtls"; cnf?: Record<string, JsonValue> } = { sender_constraint: "none" },
) {
  const s = await buildClaimLedgerScenario(fixtures);
  const root = nip19.npubEncode(fixtures.personas.alice.cold_root.pubkey);
  const epoch = nip19.npubEncode(fixtures.personas.alice.epoch_keys.epoch_1.pubkey);
  const identity: PersonaIdentityState = { cold_root_npub: root, epoch_npubs: [epoch] };
  const metadata = issuerMetadata("https://node.example", root, identity);
  const registrationClaim = await s.makeClaim(s.writerOne, {
    namespace: "heterodyne.oidc", name: "client-registration", value: CLIENT as unknown as JsonValue,
    resources: [`${s.rid}#oidc-registration`],
  });
  const dataClaim = await s.makeClaim(s.writerOne, {
    namespace: "profile", name: "name", value: "Alice", resources: [API],
  });
  const keyClaim = await s.makeClaim(s.writerOne, {
    namespace: "heterodyne.device", name: "key-ref",
    value: { type: "nostr-secp256k1", value: fixtures.personas.alice.epoch_keys.epoch_1.pubkey },
    resources: [API],
  });
  const consentClaim = await s.makeClaim(s.writerOne, {
    namespace: "heterodyne.oidc", name: "consent", resources: [`${s.rid}#oidc-consent`],
    value: {
      client_id: CLIENT.client_id, scopes: ["heterodyne:key-ref", "openid", "profile"], audiences: [API],
      claims: ["https://heterodyne.network/jwt/key-ref", "name"],
      source_claim_ids: [dataClaim.artifact.semantic.claim_id, keyClaim.artifact.semantic.claim_id],
    },
  });
  const registrationRecord = s.signRecord("claim", { claim_artifact: registrationClaim.artifact });
  const consentRecord = s.signRecord("claim", { claim_artifact: consentClaim.artifact });
  const dataRecord = s.signRecord("claim", { claim_artifact: dataClaim.artifact });
  const keyRecord = s.signRecord("claim", { claim_artifact: keyClaim.artifact });
  const authorityRecords = [
    s.claimRecordOne, s.claimRecordTwo, s.issuerClaimRecordOne, s.issuerClaimRecordTwo,
    s.issuerAuthorityRecordOne, s.issuerAuthorityRecordTwo, s.issuerKeyEpochRecordOne,
  ];
  const preMintRecords = [...authorityRecords, registrationRecord, consentRecord, dataRecord, keyRecord];
  const preMintRepository = buildLedgerRepositoryEvidence({
    repository_rid: s.rid, confirmed_records: preMintRecords, observed_at: s.now + 68,
    prior: s.issuerKeyEpochOneRepository.repository,
  });
  const allClaims = new Map([
    ...s.allClaims,
    [registrationClaim.artifact.semantic.claim_id, registrationClaim.artifact.semantic] as const,
    [consentClaim.artifact.semantic.claim_id, consentClaim.artifact.semantic] as const,
    [dataClaim.artifact.semantic.claim_id, dataClaim.artifact.semantic] as const,
    [keyClaim.artifact.semantic.claim_id, keyClaim.artifact.semantic] as const,
  ]);
  const verificationFor = (claim: typeof dataClaim, resource: string) => {
    const verification = s.makeVerification(claim);
    const challenge = {
      ...verification.subject_proof!.challenge, resource, issued_at: s.now + 68, expires_at: s.now + 128,
    };
    const signature = bytesToHex(ed25519.sign(
      utf8Bytes(subjectProofPayload(challenge)), hexToBytes(claim.reader.private_key),
    ));
    return {
      ...verification, now: s.now + 69, resource, requested_namespace: claim.artifact.semantic.namespace,
      repository_confirmed: new Set(allClaims.keys()), expected_nonce: challenge.nonce,
      subject_proof: {
        ...verification.subject_proof!, challenge,
        proof: { ...verification.subject_proof!.proof, signature },
      },
    };
  };
  const evidenceFor = (record: LedgerRecord, claim: typeof dataClaim): LedgerRecordValidationEvidence => ({
    record_id: record.record_id, payload_digest: record.payload_digest,
    claim_envelope_context: { issuer_authorized: true, registry_revision: 2 },
    claims_by_id: new Map(allClaims),
    claim_verification_context: verificationFor(claim, claim.artifact.semantic.resources![0]),
  });
  const preMintContext = s.makeTask5Context(preMintRepository.repository);
  for (const [record, claim] of [
    [registrationRecord, registrationClaim], [consentRecord, consentClaim], [dataRecord, dataClaim], [keyRecord, keyClaim],
  ] as const) preMintContext.record_evidence.set(record.record_id, evidenceFor(record, claim));
  const preMintState = mergeClaimLedger(preMintRecords, [], preMintRepository.checkpoint, preMintContext);
  const pairwiseSecret = "aa".repeat(32);
  const codeVerifier = "heterodyne-code-verifier-000000000000000000000000000000000000000000000000";
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  const evidence = (record: LedgerRecord, claim: typeof dataClaim) => ({
    claim_record_id: record.record_id,
    verification_context: verificationFor(claim, claim.artifact.semantic.resources![0]),
  });
  const request: OidcAuthorizationRequest = {
    flow: "authorization_code", grant_type: "authorization_code", response_type: "code",
    client_id: CLIENT.client_id, redirect_uri: CLIENT.redirect_uris[0],
    code_challenge: codeChallenge, code_challenge_method: "S256",
    requested_scopes: ["openid", "profile", "heterodyne:key-ref"],
    requested_audiences: [API], requested_claims: ["name", "https://heterodyne.network/jwt/key-ref"],
    pairwise_secret: pairwiseSecret, state: preMintState,
    nonce: "oidc-vector-nonce", sender_constraint: security.sender_constraint,
    ...(security.cnf === undefined ? {} : { cnf: security.cnf }),
    registration: evidence(registrationRecord, registrationClaim),
    consent: evidence(consentRecord, consentClaim),
    source_claims: [evidence(dataRecord, dataClaim), evidence(keyRecord, keyClaim)],
  };
  const release = validateAuthorizationRequest(request);
  if (!release.allowed || release.request_digest === undefined || release.release_digest === undefined) {
    throw new Error(`OIDC scenario release failed: ${release.reason_code}`);
  }
  const sourceClaimIds = [
    registrationClaim.artifact.semantic.claim_id,
    consentClaim.artifact.semantic.claim_id,
    dataClaim.artifact.semantic.claim_id,
    keyClaim.artifact.semantic.claim_id,
  ].sort();
  const now = s.now + 69;
  const issuance: IssuanceRecord = {
    jti: "oidc-evidence-jti-0001",
    reservation: reserveStatusIndex(s.writerOne.did_key, now + 600, 0, []),
    checkpoint: preMintRepository.checkpoint,
    manifest_max_age_seconds: 300,
    signing_key_id: s.issuerKeyEnvelopeOne.signing_key_id,
    client_id: CLIENT.client_id,
    authorization_request_digest: release.request_digest,
    release_digest: release.release_digest,
    source_claim_ids: sourceClaimIds,
    issued_at: now,
    expires_at: now + 600,
  };
  const issuanceRecord = s.signRecord(
    "issuance-reservation", issuance as unknown as JsonValue, s.writerOne,
    [registrationRecord.record_id, consentRecord.record_id, dataRecord.record_id, keyRecord.record_id].sort(), s.now + 70,
  );
  const issuedRecords = [...preMintRecords, issuanceRecord];
  const issuedRepository = buildLedgerRepositoryEvidence({
    repository_rid: s.rid, confirmed_records: issuedRecords, observed_at: s.now + 71,
    prior: preMintRepository.repository,
  });
  const issuedContext = s.makeTask5Context(issuedRepository.repository);
  for (const [record, claim] of [
    [registrationRecord, registrationClaim], [consentRecord, consentClaim], [dataRecord, dataClaim], [keyRecord, keyClaim],
  ] as const) issuedContext.record_evidence.set(record.record_id, evidenceFor(record, claim));
  issuedContext.record_evidence.set(issuanceRecord.record_id, {
    record_id: issuanceRecord.record_id, payload_digest: issuanceRecord.payload_digest,
  });
  const issuedState = mergeClaimLedger(issuedRecords, [], issuedRepository.checkpoint, issuedContext);
  const projection: JwtProjectionInput = {
    issuer: metadata.issuer, client_id: CLIENT.client_id, audience: release.audience!,
    pairwise_sub: release.pairwise_sub!, scopes: release.scopes!, now, expires_at: issuance.expires_at,
    issuance_record_id: issuanceRecord.record_id,
    state: issuedState, authorization_request: request, issuer_envelope: s.issuerKeyEnvelopeOne,
    issuer_audience_key: s.issuerAudienceKeyOne, issuer_writer_nid: s.writerOne.did_key,
    identity, status_mirror: {
      repository_rid: s.rid, branch: "main", path: `.well-known/${root}/${issuance.reservation.uri}`,
      sha256: "33".repeat(32),
    },
  };
  return {
    s, root, epoch, identity, metadata, registrationRecord, consentRecord, dataRecord, keyRecord,
    preMintRecords, preMintRepository, preMintContext, preMintState, issuedRecords, issuedRepository,
    issuedContext, issuedState, issuance, issuanceRecord, request, release, projection,
    codeVerifier, codeChallenge, pairwiseSecret,
  };
}

type ReplayInput = Record<string, JsonValue>;

export function replayOidcVector(input: unknown): unknown {
  const spec = input as ReplayInput;
  const operation = String(spec.operation);
  if (operation === "discovery") {
    const identity = spec.identity as unknown as PersonaIdentityState;
    const metadata = issuerMetadata(String(spec.origin), String(spec.cold_root_npub), identity);
    return { verdict: "accept", normalized: { paths: discoveryPaths(String(spec.origin), String(spec.cold_root_npub), identity), metadata } };
  }
  if (operation === "authorization") {
    const replay = decodeClaimLedgerReplayValue(spec.replay);
    const state = mergeClaimLedger(replay.records, [], replay.checkpoint, replay.context);
    const decision = validateAuthorizationRequest({ ...replay.request, state });
    return decision.allowed ? { verdict: "accept", normalized: decision } :
      { verdict: "reject", reason_code: decision.reason_code, normalized: decision };
  }
  if (operation === "oauth-flows") {
    const replay = decodeClaimLedgerReplayValue(spec.replay);
    const state = mergeClaimLedger(replay.records, [], replay.checkpoint, replay.context);
    const request = { ...replay.request, state } as OidcAuthorizationRequest;
    const code = issueAuthorizationCode(request, replay.now);
    const consumed = new Set<string>();
    const first = redeemAuthorizationCode(code, { code: code.code, client_id: request.client_id,
      redirect_uri: request.redirect_uri!, code_verifier: replay.code_verifier, now: replay.now + 1 }, consumed);
    const second = redeemAuthorizationCode(code, { code: code.code, client_id: request.client_id,
      redirect_uri: request.redirect_uri!, code_verifier: replay.code_verifier, now: replay.now + 2 }, consumed);
    const codeMutations = {
      wrong_client: redeemAuthorizationCode(code, { code: code.code, client_id: "wrong-client",
        redirect_uri: request.redirect_uri!, code_verifier: replay.code_verifier, now: replay.now + 1 }, new Set()),
      wrong_redirect: redeemAuthorizationCode(code, { code: code.code, client_id: request.client_id,
        redirect_uri: "https://client.example/wrong", code_verifier: replay.code_verifier, now: replay.now + 1 }, new Set()),
      wrong_verifier: redeemAuthorizationCode(code, { code: code.code, client_id: request.client_id,
        redirect_uri: request.redirect_uri!, code_verifier: `${replay.code_verifier}x`, now: replay.now + 1 }, new Set()),
      expired: redeemAuthorizationCode(code, { code: code.code, client_id: request.client_id,
        redirect_uri: request.redirect_uri!, code_verifier: replay.code_verifier, now: code.expires_at }, new Set()),
    };
    const deviceRequest = { ...request, flow: "device_authorization", grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      response_type: undefined, redirect_uri: undefined, code_challenge: undefined, code_challenge_method: undefined } as OidcAuthorizationRequest;
    let device = issueDeviceAuthorization(deviceRequest, replay.now);
    const pending = redeemDeviceCode(device, { device_code: device.device_code, client_id: device.client_id, now: replay.now + 1 });
    const slow = redeemDeviceCode(pending.record, { device_code: device.device_code, client_id: device.client_id, now: replay.now + 2 });
    device = decideDeviceAuthorization(slow.record, "approve", replay.now + 3);
    const success = redeemDeviceCode(device, { device_code: device.device_code, client_id: device.client_id, now: replay.now + 20 });
    const deniedRecord = decideDeviceAuthorization(issueDeviceAuthorization(deviceRequest, replay.now), "deny", replay.now + 1);
    const denied = redeemDeviceCode(deniedRecord, { device_code: deniedRecord.device_code, client_id: deniedRecord.client_id, now: replay.now + 2 });
    const expiring = issueDeviceAuthorization(deviceRequest, replay.now, 1);
    const expired = redeemDeviceCode(expiring, { device_code: expiring.device_code, client_id: expiring.client_id, now: replay.now + 1 });
    return spec.mode === "authorization-code"
      ? { verdict: "accept", normalized: { code_first: first, code_reuse: second, code_mutations: codeMutations } }
      : { verdict: "accept", normalized: { device: [pending.result, slow.result, denied.result, expired.result, success.result] } };
  }
  if (operation === "authorization-cases") {
    const replay = decodeClaimLedgerReplayValue(spec.replay);
    const state = mergeClaimLedger(replay.records, [], replay.checkpoint, replay.context);
    const decisions = (spec.grant_types as JsonValue[]).map((grant_type) =>
      validateAuthorizationRequest({ ...replay.request, state, grant_type } as OidcAuthorizationRequest));
    return { verdict: "reject", reason_code: "oidc-grant-prohibited", normalized: { decisions } };
  }
  if (operation === "pairwise-sectors") {
    return { verdict: "accept", normalized: {
      first: derivePairwiseSubject(String(spec.local_subject), String(spec.first_sector), String(spec.secret)),
      second: derivePairwiseSubject(String(spec.local_subject), String(spec.second_sector), String(spec.secret)),
    } };
  }
  if (operation === "key-gating") {
    const replay = decodeClaimLedgerReplayValue(spec.replay);
    const state = mergeClaimLedger(replay.records, [], replay.checkpoint, replay.context);
    const request = { ...replay.request, state } as OidcAuthorizationRequest;
    const accepted = validateAuthorizationRequest(request);
    const noScope = validateAuthorizationRequest({ ...request,
      requested_scopes: request.requested_scopes.filter((scope) => scope !== "heterodyne:key-ref") });
    const noClaim = validateAuthorizationRequest({ ...request,
      requested_claims: request.requested_claims.filter((claim) => claim !== "https://heterodyne.network/jwt/key-ref") });
    const missingSource = validateAuthorizationRequest({ ...request, source_claims: request.source_claims.slice(0, 1) });
    return { verdict: "accept", normalized: { accepted, no_scope: noScope, no_claim: noClaim, missing_source: missingSource } };
  }
  if (operation === "jwt-validation") {
    const metadata = spec.metadata as unknown as ReturnType<typeof issuerMetadata>;
    const options = spec.options as unknown as JwtValidationOptions;
    const metadataDecision = validateIssuerMetadata(metadata, String(spec.expected_issuer), String(spec.expected_jwks_uri));
    const decision = metadataDecision.allowed ? validateProjectedJwt(
      String(spec.compact), metadata.issuer, String(spec.expected_audience), spec.jwks!, options,
    ) : metadataDecision;
    return decision.allowed ? { verdict: "accept", normalized: decision } :
      { verdict: "reject", reason_code: decision.reason_code, normalized: decision };
  }
  if (operation === "jwt-validation-cases") {
    const metadata = spec.metadata as unknown as ReturnType<typeof issuerMetadata>;
    const decisions = (spec.cases as JsonValue[]).map((candidate) => {
      const value = candidate as Record<string, JsonValue>;
      return validateProjectedJwt(String(spec.compact), metadata.issuer, String(value.expected_audience),
        spec.jwks!, value.options as unknown as JwtValidationOptions);
    });
    return { verdict: "accept", normalized: { decisions } };
  }
  throw new Error(`unknown OIDC replay operation: ${operation}`);
}

export async function buildOidcVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const dpopCnf = { jkt: createHash("sha256").update("dpop-public-key").digest("base64url") };
  const mtlsCnf = { "x5t#S256": createHash("sha256").update("mtls-certificate").digest("base64url") };
  const x = await buildOidcScenario(fixtures);
  const dpopScenario = await buildOidcScenario(fixtures, { sender_constraint: "dpop", cnf: dpopCnf });
  const mtlsScenario = await buildOidcScenario(fixtures, { sender_constraint: "mtls", cnf: mtlsCnf });
  const authorizationReplay = encodeClaimLedgerReplayValue({
    records: x.preMintRecords, checkpoint: x.preMintRepository.checkpoint, context: x.preMintContext,
    request: { ...x.request, state: undefined }, now: x.issuance.issued_at, code_verifier: x.codeVerifier,
  });
  const id = projectIdToken(x.projection);
  const access = projectAccessToken(x.projection);
  const dpop = projectAccessToken(dpopScenario.projection);
  const mtls = projectAccessToken(mtlsScenario.projection);
  const assertion = projectJwtAssertion(x.projection, "urn:example:jwt-assertion:v1");
  const jwks = { keys: [OIDC_RSA_ONE.public_jwk] };
  const jwtInput = (token: typeof id, options: JwtValidationOptions): ReplayInput => ({
    operation: "jwt-validation", metadata: x.metadata as unknown as JsonValue, jwks: jwks as unknown as JsonValue,
    compact: token.compact, expected_audience: options.token_use === "id_token" ? CLIENT.client_id : API,
    expected_issuer: x.metadata.issuer, expected_jwks_uri: x.metadata.jwks_uri, options: options as unknown as JsonValue,
  });
  const authored = (path: string, id: string, description: string, input: ReplayInput): AuthoredVector =>
    consumeVector(`oidc/${path}`, { vector_id: `oidc/${id}`, spec_refs: ["heterodyne:comms/0.5.0#comms-conformance"],
      description, input, expected_output: replayOidcVector(input) as Record<string, unknown> });
  const common = { now: x.issuance.issued_at, client_id: CLIENT.client_id, permitted_audiences: [API] };
  const accessAsId = jwtInput(access, { ...common, token_use: "id_token", nonce: "oidc-vector-nonce", sender_constraint: "none" });
  const jwtCases = (token: typeof id, cases: Array<{ expected_audience: string; options: JwtValidationOptions }>): ReplayInput => ({
    operation: "jwt-validation-cases", metadata: x.metadata as unknown as JsonValue,
    jwks: jwks as unknown as JsonValue, compact: token.compact, cases: cases as unknown as JsonValue,
  });
  const wrongDpop = { jkt: createHash("sha256").update("wrong-dpop-key").digest("base64url") };
  const wrongMtls = { "x5t#S256": createHash("sha256").update("wrong-mtls-cert").digest("base64url") };
  return [
    authored("001-discovery-exact-issuer.json", "discovery-exact-issuer", "Exact cold-root-bound issuer discovery.", { operation: "discovery", origin: "https://node.example", cold_root_npub: x.root, identity: x.identity as unknown as JsonValue }),
    authored("002-issuer-mismatch-rejected.json", "issuer-mismatch-rejected", "A valid epoch npub is rejected as an issuer.", { operation: "jwt-validation", ...jwtInput(id, { ...common, token_use: "id_token", nonce: "oidc-vector-nonce", sender_constraint: "none" }), expected_issuer: `https://node.example/oidc/${x.epoch}` }),
    authored("003-authorization-code-pkce.json", "authorization-code-pkce", "Signed registration, consent, source replay, S256 and single-use code redemption.", { operation: "oauth-flows", mode: "authorization-code", replay: authorizationReplay }),
    authored("004-device-authorization.json", "device-authorization", "RFC 8628 pending, slow_down, denial, expiry, and successful redemption transitions.", { operation: "oauth-flows", mode: "device-authorization", replay: authorizationReplay }),
    authored("005-prohibited-grants.json", "prohibited-grants", "Implicit, password, and client-credentials grants are rejected from canonical evidence.", {
      operation: "authorization-cases", replay: authorizationReplay,
      grant_types: ["implicit", "password", "client_credentials"],
    }),
    authored("006-pairwise-subject.json", "pairwise-subject", "The same authenticated local subject derives distinct pairwise subjects for distinct sectors.", {
      operation: "pairwise-sectors", local_subject: createHash("sha256").update(x.s.writerOne.did_key).digest("hex"),
      first_sector: "https://client.example", second_sector: "https://other-client.example", secret: x.pairwiseSecret,
    }),
    authored("007-stable-key-consent-gated.json", "stable-key-consent-gated", "Key-ref release is removed without scope or claim consent and fails when the signed source is omitted.", { operation: "key-gating", replay: authorizationReplay }),
    authored("008-id-token-valid.json", "id-token-valid", "Strict RS256 ID Token validation.", jwtInput(id, { ...common, token_use: "id_token", nonce: "oidc-vector-nonce", sender_constraint: "none" })),
    authored("009-rfc9068-access-token-valid.json", "rfc9068-access-token-valid", "Strict RFC 9068 access-token validation.", jwtInput(access, { ...common, token_use: "access_token", sender_constraint: "none" })),
    authored("010-token-type-confusion-rejected.json", "token-type-confusion-rejected", "Access token rejected as ID Token.", accessAsId),
    authored("011-dpop-confirmation-bound.json", "dpop-confirmation-bound", "DPoP accepts only the exact canonical thumbprint and rejects wrong, mixed, and method-confused confirmation.", jwtCases(dpop, [
      { expected_audience: API, options: { ...common, token_use: "access_token", cnf: dpopCnf, sender_constraint: "dpop" } },
      { expected_audience: API, options: { ...common, token_use: "access_token", cnf: wrongDpop, sender_constraint: "dpop" } },
      { expected_audience: API, options: { ...common, token_use: "access_token", cnf: { ...dpopCnf, "x5t#S256": mtlsCnf["x5t#S256"] }, sender_constraint: "dpop" } },
      { expected_audience: API, options: { ...common, token_use: "access_token", cnf: mtlsCnf, sender_constraint: "mtls" } },
    ])),
    authored("012-registered-jwt-assertion.json", "registered-jwt-assertion", "Assertion validation rejects an unregistered profile despite a valid signature.", jwtCases(assertion, [
      { expected_audience: API, options: { ...common, token_use: "jwt_assertion", assertion_profile: "urn:example:jwt-assertion:v1", sender_constraint: "none" } },
      { expected_audience: API, options: { ...common, token_use: "jwt_assertion", assertion_profile: "urn:unregistered", sender_constraint: "none" } },
    ])),
    authored("013-mtls-confirmation-bound.json", "mtls-confirmation-bound", "mTLS accepts only the exact canonical certificate thumbprint and rejects wrong or method-confused confirmation.", jwtCases(mtls, [
      { expected_audience: API, options: { ...common, token_use: "access_token", cnf: mtlsCnf, sender_constraint: "mtls" } },
      { expected_audience: API, options: { ...common, token_use: "access_token", cnf: wrongMtls, sender_constraint: "mtls" } },
      { expected_audience: API, options: { ...common, token_use: "access_token", cnf: dpopCnf, sender_constraint: "dpop" } },
    ])),
  ];
}
