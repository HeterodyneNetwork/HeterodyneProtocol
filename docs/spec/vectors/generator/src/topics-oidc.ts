import { createHash, createPrivateKey, sign, type JsonWebKey } from "node:crypto";
import { inflateSync } from "node:zlib";
import { ed25519 } from "@noble/curves/ed25519";
import { nip19 } from "nostr-tools";
import {
  buildLedgerRepositoryEvidence,
  createIssuerKeyEnvelope,
  createIssuerKeyEpochPayload,
  createStatusInvalidationRecords,
  mergeClaimLedger,
  reserveStatusIndex,
  type IssuanceRecord,
  type LedgerRecord,
  type LedgerRecordValidationEvidence,
  type LedgerMergeResult,
  type LedgerValidationContext,
  type RevocationArtifact,
} from "./claim-ledger.js";
import { subjectProofPayload, type ClaimRevocation, type JsonValue } from "./claims.js";
import type { Fixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { signEvent } from "./nostr.js";
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
  createValidatedProjectedJwtContext,
  type JwtProjectionInput,
  type JwtValidationOptions,
  type OidcAuthorizationRequest,
  type PersonaIdentityState,
  type RegisteredClient,
} from "./oidc.js";
import { OIDC_RSA_ONE, OIDC_RSA_TWO } from "./oidc-rsa-fixtures.js";
import {
  buildClaimLedgerScenario,
  decodeClaimLedgerReplayValue,
  encodeClaimLedgerReplayValue,
} from "./topics-claim-ledger.js";
import type { AuthoredVector } from "./types.js";
import { consumeVector } from "./vector-helpers.js";
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
  type StatusListToken,
} from "./token-status.js";

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
    dataClaim, allClaims, evidenceFor,
    codeVerifier, codeChallenge, pairwiseSecret,
  };
}

type ReplayInput = Record<string, JsonValue>;
const REPLAY_LEDGER_STATES = new Map<string, LedgerMergeResult>();

function ledgerStateFromReplay(value: JsonValue | undefined): LedgerMergeResult {
  if (value === undefined) throw new Error("ledger replay absent");
  const key = createHash("sha256").update(jcsCanonicalize(value)).digest("hex");
  const cached = REPLAY_LEDGER_STATES.get(key);
  if (cached !== undefined) return cached;
  const replay = decodeClaimLedgerReplayValue(value);
  const state = mergeClaimLedger(replay.records, [], replay.checkpoint, replay.context);
  REPLAY_LEDGER_STATES.set(key, state);
  return state;
}

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
    let decision = metadataDecision.allowed ? validateProjectedJwt(
      String(spec.compact), metadata.issuer, String(spec.expected_audience), spec.jwks!, options,
    ) : metadataDecision;
    if (decision.allowed && spec.status_token !== undefined) {
      try {
        const referenced = createValidatedProjectedJwtContext(
          String(spec.compact), metadata.issuer, String(spec.expected_audience), spec.jwks!, options,
        );
        const continuity = validatedContinuityChainFromReplay(spec.continuity_chain, spec.ledger_replay);
        decision = validateTokenStatus(referenced, spec.status_token as unknown as StatusListToken,
          Buffer.from(String(spec.status_jwks_hex), "hex"), options.now,
          Number(spec.status_resolved_at), continuity);
      } catch {
        decision = { allowed: false, state: "invalid", reason_code: "oidc-status-invalid" };
      }
    }
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
  const legacyId = projectIdToken(x.projection);
  const statusUri = `${x.metadata.issuer}/${x.issuance.reservation.uri}`;
  const statusToken = generateStatusListToken({ state: x.issuedState, uri: statusUri,
    private_jwk: OIDC_RSA_ONE.private_jwk, iat: x.issuedState.checkpoint.observed_at,
    exp: x.issuance.expires_at, ttl: 120 });
  const jwks = { keys: [OIDC_RSA_ONE.public_jwk] };
  const jwksBytes = Buffer.from(JSON.stringify(jwks));
  const statusDigest = createHash("sha256").update(statusToken.compact).digest("hex");
  const statusManifestBody = {
    profile: "heterodyne-oidc-continuity-v1" as const, repository_rid: x.s.rid, branch: "main" as const,
    cold_root_npub: x.root, cold_root_hex: fixtures.personas.alice.cold_root.pubkey,
    persona_kel_head: fixtures.kel.alice.head, issuer: x.metadata.issuer, sequence: 0,
    predecessor_digest: null, max_checkpoint_age_seconds: 300,
    current_jwks_sha256: createHash("sha256").update(jwksBytes).digest("hex"),
    current_signing_key_id: OIDC_RSA_ONE.key_id,
    current_signing_jwk_sha256: createHash("sha256").update(jcsCanonicalize(OIDC_RSA_ONE.public_jwk)).digest("hex"),
    retiring_signing_key_ids: [], retiring_jwks_sha256: [],
    status_lists: [{ path: x.projection.status_mirror.path, sha256: statusDigest,
      issuer: x.metadata.issuer, uri: statusUri }], successor: null,
    authority: { writer_nid: x.s.writerOne.did_key, issued_at: x.issuedState.checkpoint.observed_at,
      checkpoint: x.issuedState.checkpoint },
  };
  const statusManifest: ContinuityManifest = { ...statusManifestBody,
    authority_proof: createContinuityAuthorityProof(statusManifestBody, x.s.writerOne.private_key) };
  const statusLedgerReplay = encodeClaimLedgerReplayValue({ records: x.issuedRecords,
    checkpoint: x.issuedRepository.checkpoint, context: x.issuedContext });
  const statusContinuityContext = {
    identity: x.identity, expected_kel_head: fixtures.kel.alice.head, repository_rid: x.s.rid,
    canonical_branch: "main", writer_nid: x.s.writerOne.did_key, now: x.issuedState.checkpoint.observed_at,
    succession_authority: null, kel_transition: { persona_root_npub: x.root, previous_head: null,
      current_head: fixtures.kel.alice.head, valid_from: x.issuedState.checkpoint.observed_at,
      valid_until: x.issuance.expires_at + 1_000, core_kel_authority_valid: true },
    current_epoch_authority: { npub: x.epoch, kel_head: fixtures.kel.alice.head,
      valid_from: x.issuance.issued_at, valid_until: x.issuance.expires_at + 1_000, core_kel_authority_valid: true },
  };
  const statusContinuityChain = [{ manifest: statusManifest as unknown as JsonValue,
    ledger_replay: statusLedgerReplay, context: statusContinuityContext as unknown as JsonValue }];
  const statusProjection = { ...x.projection,
    status_mirror: { ...x.projection.status_mirror, sha256: continuityManifestDigest(statusManifest) } };
  const id = projectIdToken(statusProjection);
  const access = projectAccessToken(statusProjection);
  const legacyAccess = projectAccessToken(x.projection);
  const dpop = projectAccessToken(dpopScenario.projection);
  const mtls = projectAccessToken(mtlsScenario.projection);
  const assertion = projectJwtAssertion(x.projection, "urn:example:jwt-assertion:v1");
  const jwtInput = (token: typeof id, options: JwtValidationOptions, withStatus = false): ReplayInput => ({
    operation: "jwt-validation", metadata: x.metadata as unknown as JsonValue, jwks: jwks as unknown as JsonValue,
    compact: token.compact, expected_audience: options.token_use === "id_token" ? CLIENT.client_id : API,
    expected_issuer: x.metadata.issuer, expected_jwks_uri: x.metadata.jwks_uri, options: options as unknown as JsonValue,
    ...(withStatus ? { status_token: statusToken as unknown as JsonValue,
      status_jwks_hex: jwksBytes.toString("hex"), status_resolved_at: statusToken.claims.iat,
      status_media_type: STATUS_LIST_MEDIA_TYPE,
      continuity_chain: statusContinuityChain as unknown as JsonValue } : {}),
  });
  const authored = (path: string, id: string, description: string, input: ReplayInput): AuthoredVector =>
    consumeVector(`oidc/${path}`, { vector_id: `oidc/${id}`, spec_refs: [
      /^discovery|^issuer-mismatch/.test(id)
        ? "heterodyne:comms/0.5.0#comms-oidc-endpoints"
        : /authorization|grant|pairwise|consent/.test(id)
          ? "heterodyne:comms/0.5.0#comms-oidc-authorization"
          : "heterodyne:comms/0.5.0#comms-jwt-projection",
    ],
      description, input, expected_output: replayOidcVector(input) as Record<string, unknown> });
  const common = { now: x.issuance.issued_at, client_id: CLIENT.client_id, permitted_audiences: [API] };
  const statusCommon = { ...common, now: statusToken.claims.iat };
  const accessAsId = jwtInput(legacyAccess, { ...common, token_use: "id_token", nonce: "oidc-vector-nonce", sender_constraint: "none" });
  const jwtCases = (token: typeof id, cases: Array<{ expected_audience: string; options: JwtValidationOptions }>): ReplayInput => ({
    operation: "jwt-validation-cases", metadata: x.metadata as unknown as JsonValue,
    jwks: jwks as unknown as JsonValue, compact: token.compact, cases: cases as unknown as JsonValue,
  });
  const wrongDpop = { jkt: createHash("sha256").update("wrong-dpop-key").digest("base64url") };
  const wrongMtls = { "x5t#S256": createHash("sha256").update("wrong-mtls-cert").digest("base64url") };
  return [
    authored("001-discovery-exact-issuer.json", "discovery-exact-issuer", "Exact cold-root-bound issuer discovery.", { operation: "discovery", origin: "https://node.example", cold_root_npub: x.root, identity: x.identity as unknown as JsonValue }),
    authored("002-issuer-mismatch-rejected.json", "issuer-mismatch-rejected", "A valid epoch npub is rejected as an issuer.", { operation: "jwt-validation", ...jwtInput(legacyId, { ...common, token_use: "id_token", nonce: "oidc-vector-nonce", sender_constraint: "none" }), expected_issuer: `https://node.example/oidc/${x.epoch}` }),
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
    authored("008-id-token-valid.json", "id-token-valid", "Strict RS256 ID Token and pinned draft-21 status validation.", jwtInput(id, { ...statusCommon, token_use: "id_token", nonce: "oidc-vector-nonce", sender_constraint: "none" }, true)),
    authored("009-rfc9068-access-token-valid.json", "rfc9068-access-token-valid", "Strict RFC 9068 access-token and pinned draft-21 status validation.", jwtInput(access, { ...statusCommon, token_use: "access_token", sender_constraint: "none" }, true)),
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

type MutationObservation =
  | { kind: "decision"; verdict: "accept" | "reject"; reason_code: string | null }
  | { kind: "status-bytes"; bytes_hex: string };
type MutationOutcome = {
  expected: MutationObservation;
  actual: MutationObservation;
  matched: boolean;
};
type TokenStatusMutationName =
  | "bit_0" | "bit_7" | "bit_8" | "padding"
  | "valid_to_invalid" | "invalid_to_valid_without_resign"
  | "ttl_boundary" | "expired" | "bad_signature" | "malformed_zlib" | "out_of_range"
  | "same_writer_same_index" | "distinct_writer_namespace" | "noncontiguous_prefix"
  | "jwks_byte" | "status_byte" | "path_case" | "branch_not_main"
  | "digest_nibble" | "byte_mismatch" | "extra_status_path"
  | "https_outage" | "stale_kel_head" | "unauthorized_writer" | "standard_oidc"
  | "missing_persona_proof" | "predecessor_nibble" | "wrong_successor_url" | "old_https_issuer"
  | "compromised_key_bit" | "shared_key_only_successor" | "retain_compromised_key" | "drop_status_before_expiry";
const TOKEN_STATUS_MUTATION_NAMES = new Set<TokenStatusMutationName>([
  "bit_0", "bit_7", "bit_8", "padding", "valid_to_invalid", "invalid_to_valid_without_resign",
  "ttl_boundary", "expired", "bad_signature", "malformed_zlib", "out_of_range", "same_writer_same_index",
  "distinct_writer_namespace", "noncontiguous_prefix", "jwks_byte", "status_byte", "path_case", "branch_not_main",
  "digest_nibble", "byte_mismatch", "extra_status_path", "https_outage", "stale_kel_head", "unauthorized_writer",
  "standard_oidc", "missing_persona_proof", "predecessor_nibble", "wrong_successor_url", "old_https_issuer",
  "compromised_key_bit", "shared_key_only_successor", "retain_compromised_key", "drop_status_before_expiry",
]);

function mutationTable(value: Partial<Record<TokenStatusMutationName, MutationObservation>>): JsonValue {
  return value as unknown as JsonValue;
}

export function replayTokenStatusVector(input: unknown): unknown {
  const result = replayTokenStatusVectorCore(input) as Record<string, unknown>;
  const mutationResults = replayTokenStatusMutationTable(input);
  if (Object.keys(mutationResults).length === 0) return result;
  const matched = Object.values(mutationResults).every((outcome) => outcome.matched);
  return { ...result, ...(matched ? {} : { verdict: "reject", reason_code: "mutation-expectation-mismatch" }),
    normalized: { ...((result.normalized as Record<string, unknown> | undefined) ?? {}),
      mutation_results: mutationResults } };
}

export function replayTokenStatusMutationTable(input: unknown): Record<string, MutationOutcome> {
  const spec = structuredClone(input) as ReplayInput;
  const table = spec.mutation_table;
  if (table === undefined || table === null || typeof table !== "object" || Array.isArray(table)) return {};
  delete spec.mutation_table;
  const results: Record<string, MutationOutcome> = {};
  for (const [name, declaration] of Object.entries(table as Record<string, JsonValue>)) {
    if (!TOKEN_STATUS_MUTATION_NAMES.has(name as TokenStatusMutationName)) {
      throw new Error(`unknown token-status mutation expectation: ${name}`);
    }
    const expected = parseMutationExpectation(declaration);
    const actual = replayNamedTokenStatusMutation(name as TokenStatusMutationName, spec);
    results[name] = { expected, actual, matched: jcsCanonicalize(expected) === jcsCanonicalize(actual) };
  }
  return results;
}

function parseMutationExpectation(value: JsonValue): MutationObservation {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("mutation expectation must be a closed object");
  }
  const keys = Object.keys(value).sort();
  if (value.kind === "decision" && jcsCanonicalize(keys) === jcsCanonicalize(["kind", "reason_code", "verdict"]) &&
      (value.verdict === "accept" || value.verdict === "reject") &&
      (value.reason_code === null || typeof value.reason_code === "string")) {
    return { kind: "decision", verdict: value.verdict, reason_code: value.reason_code };
  }
  if (value.kind === "status-bytes" && jcsCanonicalize(keys) === jcsCanonicalize(["bytes_hex", "kind"]) &&
      typeof value.bytes_hex === "string" && /^(?:[0-9a-f]{2})+$/.test(value.bytes_hex)) {
    return { kind: "status-bytes", bytes_hex: value.bytes_hex };
  }
  throw new Error("mutation expectation is not a closed typed result");
}

function replayTokenStatusVectorCore(input: unknown): unknown {
  const spec = input as ReplayInput;
  try {
    if (spec.operation === "status-encoding") {
      const signedValidation = spec.signed_validation === undefined ? undefined : replayTokenStatusVector(spec.signed_validation);
      return { verdict: "accept", normalized: { encoded: encodeStatusList(spec.statuses as unknown as Array<0 | 1>),
        ...(signedValidation === undefined ? {} : { signed_validation: signedValidation }) } };
    }
    if (spec.operation === "status-validation") {
      const context = createValidatedProjectedJwtContext(String(spec.referenced_compact), String(spec.issuer),
        String(spec.audience), spec.referenced_jwks!, spec.options as unknown as JwtValidationOptions);
      const continuity = validatedContinuityChainFromReplay(spec.continuity_chain, spec.ledger_replay);
      const decision = validateTokenStatus(context, spec.status_token as unknown as StatusListToken,
        Buffer.from(String(spec.status_jwks_hex), "hex"), Number(spec.now),
        Number(spec.status_resolved_at), continuity);
      const sharedKeyAttempt = spec.shared_key_succession_attempt === undefined ? undefined :
        replayTokenStatusVector(spec.shared_key_succession_attempt);
      const normalized = { status: decision,
        ...(sharedKeyAttempt === undefined ? {} : { shared_key_succession_attempt: sharedKeyAttempt }) };
      return decision.allowed ? { verdict: "accept", normalized } :
        { verdict: "reject", reason_code: decision.reason_code, normalized };
    }
    if (spec.operation === "status-generation") {
      const state = ledgerStateFromReplay(spec.ledger_replay);
      const expected = spec.status_token as unknown as StatusListToken;
      const signingFixture = expected.protected_header.kid === OIDC_RSA_TWO.key_id ? OIDC_RSA_TWO : OIDC_RSA_ONE;
      const generated = generateStatusListToken({ state, uri: String(spec.uri),
        private_jwk: signingFixture.private_jwk, iat: Number(spec.iat), exp: Number(spec.exp), ttl: Number(spec.ttl) });
      const matches = generated.compact === expected.compact &&
        jcsCanonicalize(generated.claims) === jcsCanonicalize(expected.claims);
      if (!matches) return { verdict: "reject", reason_code: "claim-repository-conflict",
        normalized: { regenerated_from_ledger: false } };
      const statusResult = replayTokenStatusVector({ ...spec, operation: "status-validation", status_token: generated });
      const evidenceCases = Array.isArray(spec.evidence_cases)
        ? spec.evidence_cases.map((candidate) => {
          const candidateSpec = candidate as unknown as ReplayInput;
          return replayTokenStatusVector(candidateSpec.ledger_replay_ref === "current"
            ? { ...candidateSpec, ledger_replay: spec.ledger_replay } : candidateSpec);
        }) : [];
      const result = statusResult as Record<string, unknown>;
      return { ...result, normalized: { ...(result.normalized as Record<string, unknown>),
        regenerated_from_ledger: true, evidence_cases: evidenceCases } };
    }
    if (spec.operation === "allocation-collision") {
      reserveStatusIndex(String(spec.writer_nid), Number(spec.expires_at), Number(spec.list_sequence),
        spec.existing as unknown as IssuanceRecord[]);
      return { verdict: "accept" };
    }
    if (spec.operation === "mirror") {
      const statuses = new Map((spec.status_tokens as unknown as Array<{ path: string; hex: string }>).map(({ path, hex }) =>
        [path, Buffer.from(hex, "hex")]));
      const tree = buildContinuityTree(spec.manifest as unknown as ContinuityManifest, spec.discovery!,
        Buffer.from(String(spec.jwks_hex), "hex"), statuses);
      const expected = new Map((spec.https_bytes as unknown as Array<{ path: string; hex: string }>).map(({ path, hex }) => [path, hex]));
      const identical = [...tree].every(([path, bytes]) => expected.get(path) === Buffer.from(bytes).toString("hex")) && tree.size === expected.size;
      return identical ? { verdict: "accept", normalized: { byte_identical: true,
        paths: [...tree.keys()].sort() } } : { verdict: "reject", reason_code: "oidc-status-digest-mismatch" };
    }
    if (spec.operation === "continuity") {
      const state = ledgerStateFromReplay(spec.ledger_replay);
      const decision = resolveIssuerContinuity(
        spec.previous === null ? null : spec.previous as unknown as ContinuityManifest,
        spec.candidate as unknown as ContinuityManifest,
        { ...(spec.context as unknown as Record<string, unknown>), ledger_state: state } as never,
      );
      return decision.allowed ? { verdict: "accept", normalized: decision } :
        { verdict: "reject", reason_code: decision.reason_code, normalized: decision };
    }
    throw new Error("unknown token-status operation");
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    const reason = message.includes("claim-repository-conflict") || message.includes("collision") || message.includes("duplicate") ? "claim-repository-conflict" :
      message.includes("digest") ? "oidc-status-digest-mismatch" : "oidc-status-invalid";
    return { verdict: "reject", reason_code: reason };
  }
}

function replayNamedTokenStatusMutation(name: TokenStatusMutationName, base: ReplayInput): MutationObservation {
  const replay = (candidate: ReplayInput): MutationObservation => {
    const output = replayTokenStatusVectorCore(candidate) as Record<string, unknown>;
    return { kind: "decision", verdict: output.verdict === "accept" ? "accept" : "reject",
      reason_code: typeof output.reason_code === "string" ? output.reason_code : null };
  };
  const encoded = (statuses: Array<0 | 1>): MutationObservation => ({ kind: "status-bytes",
    bytes_hex: inflateSync(Buffer.from(encodeStatusList(statuses).lst, "base64url")).toString("hex") });
  const clone = <T>(value: T): T => structuredClone(value);
  const flippedHex = (value: JsonValue): string => {
    const source = String(value);
    return `${source.slice(0, -1)}${source.endsWith("0") ? "1" : "0"}`;
  };
  const status = () => clone(base.status_token as unknown as StatusListToken);
  const manifest = () => clone(base.manifest as unknown as ContinuityManifest);
  const context = () => clone(base.context as unknown as Record<string, JsonValue>);
  const material = (caseName: string): Record<string, JsonValue> => {
    const all = base.mutation_material as unknown as Record<string, JsonValue>;
    const selected = all?.[caseName];
    if (selected === null || typeof selected !== "object" || Array.isArray(selected)) {
      throw new Error(`mutation material is absent for ${caseName}`);
    }
    return selected as Record<string, JsonValue>;
  };
  const replayAuthenticatedStatusMaterial = (caseName: string): MutationObservation => {
    const selected = material(caseName);
    const chain = clone(base.continuity_chain as unknown as ReplayInput[]);
    chain[0].manifest = selected.manifest;
    return replay({ ...base, status_token: selected.status_token,
      referenced_compact: selected.referenced_compact, continuity_chain: chain as unknown as JsonValue });
  };
  switch (name) {
    case "bit_0": return encoded([1, 0, 0, 0, 0, 0, 0, 0]);
    case "bit_7": return encoded([0, 0, 0, 0, 0, 0, 0, 1]);
    case "bit_8": return encoded([0, 0, 0, 0, 0, 0, 0, 0, 1]);
    case "padding": return encoded([1]);
    case "valid_to_invalid": return replay(base);
    case "invalid_to_valid_without_resign": {
      const token = status(); token.claims.status_list = encodeStatusList([0]);
      return replay({ ...base, operation: "status-validation", status_token: token as unknown as JsonValue });
    }
    case "ttl_boundary": return replay(base);
    case "expired": return replay({ ...base, now: (base.status_token as unknown as StatusListToken).claims.exp });
    case "bad_signature": {
      return replayAuthenticatedStatusMaterial(name);
    }
    case "malformed_zlib": {
      return replayAuthenticatedStatusMaterial(name);
    }
    case "out_of_range": {
      const compact = mutateAndResignCompact(String(base.referenced_compact), (claims) => {
        const statusClaim = claims.status as Record<string, JsonValue>;
        const reference = statusClaim.status_list as Record<string, JsonValue>;
        reference.idx = 8;
      }, OIDC_RSA_ONE.private_jwk);
      return replay({ ...base, referenced_compact: compact });
    }
    case "same_writer_same_index": return replay(base);
    case "distinct_writer_namespace": return replay({ ...base, list_sequence: Number(base.list_sequence) + 1,
      existing: clone(base.existing as unknown as IssuanceRecord[]).slice(0, 1) as unknown as JsonValue });
    case "noncontiguous_prefix": {
      const existing = clone(base.existing as unknown as IssuanceRecord[]);
      existing.splice(1); existing[0].reservation.idx = 1;
      return replay({ ...base, existing: existing as unknown as JsonValue });
    }
    case "jwks_byte": return replay({ ...base, jwks_hex: flippedHex(base.jwks_hex) });
    case "status_byte": {
      const tokens = clone(base.status_tokens as unknown as Array<{ path: string; hex: string }>);
      tokens[0].hex = flippedHex(tokens[0].hex);
      return replay({ ...base, status_tokens: tokens as unknown as JsonValue });
    }
    case "path_case": {
      const tokens = clone(base.status_tokens as unknown as Array<{ path: string; hex: string }>);
      tokens[0].path = tokens[0].path.replace(".well-known", ".WELL-known");
      return replay({ ...base, status_tokens: tokens as unknown as JsonValue });
    }
    case "branch_not_main": {
      const changed = manifest(); changed.branch = "dev" as never;
      return replay({ ...base, manifest: changed as unknown as JsonValue });
    }
    case "digest_nibble": return replay(base);
    case "byte_mismatch": return replay({ ...base, jwks_hex: flippedHex(base.jwks_hex) });
    case "extra_status_path": {
      const tokens = clone(base.status_tokens as unknown as Array<{ path: string; hex: string }>);
      tokens.push({ path: `${tokens[0].path}.extra`, hex: tokens[0].hex });
      return replay({ ...base, status_tokens: tokens as unknown as JsonValue });
    }
    case "https_outage": return replay(base);
    case "stale_kel_head": {
      const changed = context(); changed.expected_kel_head = { id: "00".repeat(32), seq: 0 };
      return replay({ ...base, context: changed as unknown as JsonValue });
    }
    case "unauthorized_writer": {
      const changed = context(); changed.writer_nid = "did:key:z6MkiTBz1yYdFZKmU8w4ASzQmY9vVgrJ8q8YwP9QZV5jB9aa";
      return replay({ ...base, context: changed as unknown as JsonValue });
    }
    case "standard_oidc": return replay(base);
    case "missing_persona_proof": {
      const changed = context(); changed.succession_authority = null;
      return replay({ ...base, context: changed as unknown as JsonValue });
    }
    case "predecessor_nibble": {
      const changed = material(name).candidate as unknown as ContinuityManifest;
      return replay({ ...base, candidate: changed as unknown as JsonValue });
    }
    case "wrong_successor_url": {
      const selected = material(name);
      const changedContext = context(); changedContext.succession_authority = selected.succession_authority;
      return replay({ ...base, candidate: selected.candidate, context: changedContext as unknown as JsonValue });
    }
    case "old_https_issuer": {
      const changed = material(name).candidate as unknown as ContinuityManifest;
      return replay({ ...base, candidate: changed as unknown as JsonValue });
    }
    case "compromised_key_bit": return replay(base);
    case "shared_key_only_successor": {
      const attempt = clone(base.shared_key_succession_attempt as unknown as ReplayInput);
      if (attempt.ledger_replay_ref === "current") attempt.ledger_replay = base.ledger_replay;
      return replay(attempt);
    }
    case "retain_compromised_key": {
      const evidence = clone(base.evidence_cases as unknown as ReplayInput[])[1];
      if (evidence.ledger_replay_ref === "current") evidence.ledger_replay = base.ledger_replay;
      return replay(evidence);
    }
    case "drop_status_before_expiry": {
      const evidence = clone(base.evidence_cases as unknown as ReplayInput[])[0];
      if (evidence.ledger_replay_ref === "current") evidence.ledger_replay = base.ledger_replay;
      const changed = material(name).candidate as unknown as ContinuityManifest;
      return replay({ ...evidence, candidate: changed as unknown as JsonValue });
    }
    default: throw new Error(`unimplemented token-status mutation case: ${name}`);
  }
}

function resignCompact(compact: string, claims: JsonValue, kid: string): string {
  const fixture = kid === OIDC_RSA_TWO.key_id ? OIDC_RSA_TWO : OIDC_RSA_ONE;
  const [header] = compact.split(".");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signingInput = `${header}.${payload}`;
  const key = createPrivateKey({ key: fixture.private_jwk as JsonWebKey, format: "jwk" });
  return `${signingInput}.${sign("RSA-SHA256", Buffer.from(signingInput), key).toString("base64url")}`;
}

function mutateAndResignCompact(
  compact: string,
  mutate: (claims: Record<string, JsonValue>) => void,
  privateJwk: JsonValue,
): string {
  const [header, payload] = compact.split(".");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, JsonValue>;
  mutate(claims);
  const encoded = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signingInput = `${header}.${encoded}`;
  const key = createPrivateKey({ key: privateJwk as JsonWebKey, format: "jwk" });
  return `${signingInput}.${sign("RSA-SHA256", Buffer.from(signingInput), key).toString("base64url")}`;
}

function validatedContinuityChainFromReplay(value: JsonValue | undefined, currentLedgerReplay?: JsonValue) {
  if (!Array.isArray(value)) throw new Error("continuity chain absent");
  return validateIssuerContinuityChain(value.map((raw) => {
    const entry = raw as unknown as ReplayInput;
    const replayValue = entry.ledger_replay_ref === "current" ? currentLedgerReplay : entry.ledger_replay;
    const state = ledgerStateFromReplay(replayValue);
    return { manifest: entry.manifest as unknown as ContinuityManifest,
      context: { ...(entry.context as unknown as Record<string, unknown>), ledger_state: state } as never };
  }));
}

export async function buildTokenStatusVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const x = await buildOidcScenario(fixtures);
  const jwks = { keys: [OIDC_RSA_ONE.public_jwk] };
  const uri = `${x.metadata.issuer}/${x.issuance.reservation.uri}`;
  const validStatus = generateStatusListToken({ state: x.issuedState, uri,
    private_jwk: OIDC_RSA_ONE.private_jwk, iat: x.issuedState.checkpoint.observed_at,
    exp: x.issuedState.checkpoint.observed_at + 300, ttl: 120 });
  const revocationSemantic: ClaimRevocation = { claim_id: x.dataClaim.artifact.semantic.claim_id,
    revoked_at: x.issuedState.checkpoint.observed_at + 1, reason_code: "claim-revoked",
    revoker: x.dataClaim.artifact.semantic.issuer };
  const revocationEvent = await signEvent({ secretKey: x.s.issuer.private_key, auxRand: "00".repeat(32),
    created_at: revocationSemantic.revoked_at, kind: 31014, tags: [["d", revocationSemantic.claim_id]],
    content: jcsCanonicalize(revocationSemantic) });
  const revocationArtifact: RevocationArtifact = { event: revocationEvent,
    semantic: revocationSemantic as unknown as JsonValue };
  const revocationRecord = x.s.signRecord("revocation", { revocation_artifact: revocationArtifact },
    x.s.writerOne, [x.dataRecord.record_id], revocationSemantic.revoked_at);
  const revokedRecords = [...x.issuedRecords, revocationRecord];
  const revokedRepository = buildLedgerRepositoryEvidence({ repository_rid: x.s.rid,
    confirmed_records: revokedRecords, observed_at: revocationSemantic.revoked_at,
    prior: x.issuedRepository.repository });
  const revokedContext: LedgerValidationContext = { ...x.issuedContext, repository: revokedRepository.repository,
    record_evidence: new Map(x.issuedContext.record_evidence),
    issuer_key_material_by_record_id: new Map(x.issuedContext.issuer_key_material_by_record_id ?? []) };
  const revocationEvidence = x.evidenceFor(x.dataRecord, x.dataClaim);
  revocationEvidence.claim_verification_context!.now = revocationSemantic.revoked_at;
  revokedContext.record_evidence.set(revocationRecord.record_id, { ...revocationEvidence,
    record_id: revocationRecord.record_id, payload_digest: revocationRecord.payload_digest });
  const revokedState = mergeClaimLedger(revokedRecords, [], revokedRepository.checkpoint, revokedContext);
  const generatedInvalidations = createStatusInvalidationRecords({ state: revokedState,
    writer_nid: x.s.writerOne.did_key, writer_secret_key: x.s.writerOne.private_key,
    created_at: revokedState.checkpoint.observed_at + 1, compromised_signing_key_ids: [] });
  const invalidatedRecords = [...revokedRecords, ...generatedInvalidations];
  const invalidatedRepository = buildLedgerRepositoryEvidence({ repository_rid: x.s.rid,
    confirmed_records: invalidatedRecords, observed_at: revokedState.checkpoint.observed_at + 2,
    prior: revokedRepository.repository });
  const invalidatedContext: LedgerValidationContext = { ...revokedContext,
    repository: invalidatedRepository.repository,
    record_evidence: new Map(revokedContext.record_evidence),
    issuer_key_material_by_record_id: new Map(revokedContext.issuer_key_material_by_record_id ?? []) };
  for (const record of generatedInvalidations) invalidatedContext.record_evidence.set(record.record_id, {
    ...revocationEvidence, record_id: record.record_id, payload_digest: record.payload_digest,
  });
  const invalidatedState = mergeClaimLedger(invalidatedRecords, [], invalidatedRepository.checkpoint, invalidatedContext);
  const invalidStatus = generateStatusListToken({ state: invalidatedState, uri,
    private_jwk: OIDC_RSA_ONE.private_jwk, iat: invalidatedState.checkpoint.observed_at,
    exp: x.issuance.expires_at, ttl: 120 });
  const compromiseInvalidations = createStatusInvalidationRecords({ state: x.issuedState,
    writer_nid: x.s.writerTwo.did_key, writer_secret_key: x.s.writerTwo.private_key,
    created_at: x.issuedState.checkpoint.observed_at + 1,
    compromised_signing_key_ids: [x.issuance.signing_key_id] });
  const compromisedRecords = [...x.issuedRecords, ...compromiseInvalidations];
  const compromisedRepository = buildLedgerRepositoryEvidence({ repository_rid: x.s.rid,
    confirmed_records: compromisedRecords, observed_at: x.issuedState.checkpoint.observed_at + 2,
    prior: x.issuedRepository.repository });
  const compromisedContext: LedgerValidationContext = { ...x.issuedContext,
    repository: compromisedRepository.repository, record_evidence: new Map(x.issuedContext.record_evidence),
    issuer_key_material_by_record_id: new Map(x.issuedContext.issuer_key_material_by_record_id ?? []) };
  for (const record of compromiseInvalidations) compromisedContext.record_evidence.set(record.record_id, {
    record_id: record.record_id, payload_digest: record.payload_digest });
  const compromisedState = mergeClaimLedger(compromisedRecords, [], compromisedRepository.checkpoint, compromisedContext);
  const removedRecords = [...compromisedRecords, x.s.issuerRemovalRecord];
  const removedRepository = buildLedgerRepositoryEvidence({ repository_rid: x.s.rid,
    confirmed_records: removedRecords, observed_at: x.s.issuerRemovalRecord.created_at,
    prior: compromisedRepository.repository });
  const removedContext: LedgerValidationContext = { ...compromisedContext,
    repository: removedRepository.repository, record_evidence: new Map(compromisedContext.record_evidence),
    issuer_key_material_by_record_id: new Map(compromisedContext.issuer_key_material_by_record_id ?? []) };
  const removalEvidence = x.s.makeTask5Context(removedRepository.repository)
    .record_evidence.get(x.s.issuerRemovalRecord.record_id)!;
  removedContext.record_evidence.set(x.s.issuerRemovalRecord.record_id, removalEvidence);
  const removedState = mergeClaimLedger(removedRecords, [], removedRepository.checkpoint, removedContext);
  const rotatedEnvelope = createIssuerKeyEnvelope({ persona: x.s.persona, repository_rid: x.s.rid, epoch: 2,
    audience_key: x.s.issuerAudienceKeyTwo, signing_jwk: OIDC_RSA_TWO.private_jwk,
    authority_state: removedState, recipient_nids: [x.s.writerTwo.did_key],
    previous: { envelope: x.s.issuerKeyEnvelopeOne, audience_key: x.s.issuerAudienceKeyOne } });
  const rotatedEpochPayload = createIssuerKeyEpochPayload({ authority_state: removedState,
    envelope: rotatedEnvelope, previous_record: x.s.issuerKeyEpochRecordOne });
  const rotatedEpochRecord = x.s.signRecord("audience-key-epoch", rotatedEpochPayload as unknown as JsonValue,
    x.s.writerTwo, [x.s.issuerKeyEpochRecordOne.record_id, x.s.issuerRemovalRecord.record_id].sort(),
    x.s.issuerRemovalRecord.created_at + 1);
  const rotatedRecords = [...removedRecords, rotatedEpochRecord];
  const rotatedRepository = buildLedgerRepositoryEvidence({ repository_rid: x.s.rid,
    confirmed_records: rotatedRecords, observed_at: rotatedEpochRecord.created_at + 1,
    prior: removedRepository.repository });
  const rotatedContext: LedgerValidationContext = { ...removedContext,
    repository: rotatedRepository.repository, record_evidence: new Map(removedContext.record_evidence),
    issuer_key_material_by_record_id: new Map(removedContext.issuer_key_material_by_record_id ?? []) };
  rotatedContext.record_evidence.set(rotatedEpochRecord.record_id, { record_id: rotatedEpochRecord.record_id,
    payload_digest: rotatedEpochRecord.payload_digest });
  rotatedContext.issuer_key_material_by_record_id!.set(rotatedEpochRecord.record_id,
    { envelope: rotatedEnvelope, audience_key: x.s.issuerAudienceKeyTwo });
  const rotatedState = mergeClaimLedger(rotatedRecords, [], rotatedRepository.checkpoint, rotatedContext);
  const compromiseStatus = generateStatusListToken({ state: rotatedState, uri,
    private_jwk: OIDC_RSA_TWO.private_jwk, iat: rotatedState.checkpoint.observed_at,
    exp: x.issuance.expires_at, ttl: 120 });
  const options: JwtValidationOptions = { now: x.issuance.issued_at, token_use: "access_token",
    client_id: CLIENT.client_id, sender_constraint: "none", permitted_audiences: [API] };
  const expectedDecision = (verdict: "accept" | "reject", reason_code: string | null): MutationObservation =>
    ({ kind: "decision", verdict, reason_code });
  const expectedBytes = (bytes_hex: string): MutationObservation => ({ kind: "status-bytes", bytes_hex });
  const authored = (path: string, vectorId: string, description: string, input: ReplayInput): AuthoredVector =>
    consumeVector(`token-status/${path}`, { vector_id: `token-status/${vectorId}`,
      spec_refs: [/https-outage|issuer-successor/.test(vectorId)
        ? "heterodyne:comms/0.5.0#comms-issuer-continuity"
        : "heterodyne:comms/0.5.0#comms-token-status"], description, input,
      expected_output: replayTokenStatusVector(input) as Record<string, unknown> });

  const root = x.root;
  const rootPath = `.well-known/${root}`;
  const jwksBytes = Buffer.from(JSON.stringify(jwks));
  const currentSigningJwkDigest = createHash("sha256")
    .update(jcsCanonicalize(OIDC_RSA_ONE.public_jwk)).digest("hex");
  const statusPath = `${rootPath}/${x.issuance.reservation.uri}`;
  const manifestBody = {
    profile: "heterodyne-oidc-continuity-v1" as const, repository_rid: x.s.rid, branch: "main" as const,
    cold_root_npub: root, cold_root_hex: fixtures.personas.alice.cold_root.pubkey,
    persona_kel_head: fixtures.kel.alice.head, issuer: x.metadata.issuer, sequence: 0,
    predecessor_digest: null, max_checkpoint_age_seconds: 300,
    current_jwks_sha256: createHash("sha256").update(jwksBytes).digest("hex"),
    current_signing_key_id: OIDC_RSA_ONE.key_id,
    current_signing_jwk_sha256: currentSigningJwkDigest,
    retiring_signing_key_ids: [], retiring_jwks_sha256: [],
    status_lists: [{ path: statusPath, sha256: createHash("sha256").update(validStatus.compact).digest("hex"),
      issuer: x.metadata.issuer, uri }],
    successor: null, authority: { writer_nid: x.s.writerOne.did_key,
      issued_at: x.issuedState.checkpoint.observed_at, checkpoint: x.issuedState.checkpoint },
  };
  const manifest: ContinuityManifest = { ...manifestBody,
    authority_proof: createContinuityAuthorityProof(manifestBody, x.s.writerOne.private_key) };
  const discovery = x.metadata as unknown as JsonValue;
  const statusMap = new Map([[statusPath, Buffer.from(validStatus.compact)]]);
  const tree = buildContinuityTree(manifest, discovery, jwksBytes, statusMap);
  const treeBytes = [...tree].map(([path, bytes]) => ({ path, hex: Buffer.from(bytes).toString("hex") }));
  const ledgerReplay = encodeClaimLedgerReplayValue({ records: x.issuedRecords,
    checkpoint: x.issuedRepository.checkpoint, context: x.issuedContext });
  const invalidatedReplay = encodeClaimLedgerReplayValue({ records: invalidatedRecords,
    checkpoint: invalidatedRepository.checkpoint, context: invalidatedContext });
  const rotatedReplay = encodeClaimLedgerReplayValue({ records: rotatedRecords,
    checkpoint: rotatedRepository.checkpoint, context: rotatedContext });
  const continuityContext = {
    identity: x.identity, expected_kel_head: fixtures.kel.alice.head, repository_rid: x.s.rid,
    canonical_branch: "main", writer_nid: x.s.writerOne.did_key,
    now: x.issuedState.checkpoint.observed_at, succession_authority: null,
    kel_transition: { persona_root_npub: root, previous_head: null, current_head: fixtures.kel.alice.head,
      valid_from: x.issuedState.checkpoint.observed_at, valid_until: x.issuance.expires_at + 1_000,
      core_kel_authority_valid: true },
    current_epoch_authority: { npub: x.epoch, kel_head: fixtures.kel.alice.head,
      valid_from: x.issuance.issued_at, valid_until: x.issuance.expires_at + 1_000,
      core_kel_authority_valid: true },
  };
  const outageInput: ReplayInput = { operation: "continuity", previous: null,
    candidate: manifest as unknown as JsonValue, ledger_replay: ledgerReplay,
    context: continuityContext as unknown as JsonValue, https_available: false,
    standard_oidc_behavior: "does-not-follow-radicle", heterodyne_behavior: "validated-radicle-fallback" };

  const successorIssuer = x.metadata.issuer.replace("node.example", "successor.example");
  const rotatedSigningJwkDigest = createHash("sha256")
    .update(jcsCanonicalize(OIDC_RSA_TWO.public_jwk)).digest("hex");
  const rotatedJwksBytes = Buffer.from(JSON.stringify({ keys: [OIDC_RSA_TWO.public_jwk] }));
  const rotatedJwksDigest = createHash("sha256")
    .update(rotatedJwksBytes).digest("hex");
  const candidateCommitment = { ...manifest, issuer: successorIssuer, sequence: 1,
    predecessor_digest: "00".repeat(32) } as ContinuityManifest;
  const boundPreviousBody = { ...manifestBody, successor: { issuer: successorIssuer,
    manifest_sha256: continuitySuccessorDigest(candidateCommitment) } };
  const boundPrevious: ContinuityManifest = { ...boundPreviousBody,
    authority_proof: createContinuityAuthorityProof(boundPreviousBody, x.s.writerOne.private_key) };
  const successorBody = { ...manifestBody, issuer: successorIssuer, sequence: 1,
    predecessor_digest: continuityManifestDigest(boundPrevious) };
  const successor: ContinuityManifest = { ...successorBody,
    authority_proof: createContinuityAuthorityProof(successorBody, x.s.writerOne.private_key) };
  const successionProof = createPersonaSuccessionProof(successor, "current-persona-epoch",
    fixtures.personas.alice.epoch_keys.epoch_1.private_key);
  const successionContext = { ...continuityContext, now: x.issuance.expires_at,
    succession_authority: successionProof,
    kel_transition: { ...continuityContext.kel_transition, previous_head: boundPrevious.persona_kel_head,
      current_head: successor.persona_kel_head, valid_from: successor.authority.issued_at } };
  const successionInput: ReplayInput = { operation: "continuity", previous: boundPrevious as unknown as JsonValue,
    candidate: successor as unknown as JsonValue, ledger_replay: ledgerReplay,
    context: successionContext as unknown as JsonValue, standard_oidc_action: "register-successor" };
  const predecessorNibbleBody = { ...successorBody,
    predecessor_digest: `${successorBody.predecessor_digest.slice(0, -1)}${successorBody.predecessor_digest.endsWith("0") ? "1" : "0"}` };
  const predecessorNibbleCandidate: ContinuityManifest = { ...predecessorNibbleBody,
    authority_proof: createContinuityAuthorityProof(predecessorNibbleBody, x.s.writerOne.private_key) };
  const wrongSuccessorBody = { ...successorBody,
    issuer: successorBody.issuer.replace("successor.example", "wrong.example") };
  const wrongSuccessorCandidate: ContinuityManifest = { ...wrongSuccessorBody,
    authority_proof: createContinuityAuthorityProof(wrongSuccessorBody, x.s.writerOne.private_key) };
  const wrongSuccessorProof = createPersonaSuccessionProof(wrongSuccessorCandidate, "current-persona-epoch",
    fixtures.personas.alice.epoch_keys.epoch_1.private_key);
  const oldIssuerBody = { ...successorBody, issuer: boundPrevious.issuer };
  const oldIssuerCandidate: ContinuityManifest = { ...oldIssuerBody,
    authority_proof: createContinuityAuthorityProof(oldIssuerBody, x.s.writerOne.private_key) };
  const successionMutationMaterial = {
    predecessor_nibble: { candidate: predecessorNibbleCandidate as unknown as JsonValue },
    wrong_successor_url: { candidate: wrongSuccessorCandidate as unknown as JsonValue,
      succession_authority: wrongSuccessorProof as unknown as JsonValue },
    old_https_issuer: { candidate: oldIssuerCandidate as unknown as JsonValue },
  } as unknown as JsonValue;
  const sharedKeyInsufficient: ReplayInput = { ...successionInput,
    context: { ...successionContext, succession_authority: null } as unknown as JsonValue };

  const refreshedBody = { ...manifestBody, sequence: 1, predecessor_digest: continuityManifestDigest(manifest),
    status_lists: [{ path: statusPath, sha256: createHash("sha256").update(invalidStatus.compact).digest("hex"),
      issuer: x.metadata.issuer, uri }],
    authority: { writer_nid: x.s.writerOne.did_key, issued_at: invalidatedState.checkpoint.observed_at,
      checkpoint: invalidatedState.checkpoint } };
  const refreshedManifest: ContinuityManifest = { ...refreshedBody,
    authority_proof: createContinuityAuthorityProof(refreshedBody, x.s.writerOne.private_key) };
  const refreshedContext = { ...continuityContext, now: invalidatedState.checkpoint.observed_at,
    kel_transition: { ...continuityContext.kel_transition, previous_head: manifest.persona_kel_head,
      current_head: refreshedManifest.persona_kel_head, valid_from: refreshedManifest.authority.issued_at } };
  const refreshAccepted: ReplayInput = { operation: "continuity", previous: manifest as unknown as JsonValue,
    candidate: refreshedManifest as unknown as JsonValue, ledger_replay: invalidatedReplay,
    context: refreshedContext as unknown as JsonValue };
  const noStatusBody = { ...refreshedBody, status_lists: [] };
  const noStatusManifest: ContinuityManifest = { ...noStatusBody,
    authority_proof: createContinuityAuthorityProof(noStatusBody, x.s.writerOne.private_key) };
  const refreshMissingStatus: ReplayInput = { ...refreshAccepted, candidate: noStatusManifest as unknown as JsonValue };
  const { ledger_replay: _refreshReplay, ...refreshAcceptedWithoutReplay } = refreshAccepted;
  const refreshAcceptedRef: ReplayInput = { ...refreshAcceptedWithoutReplay, ledger_replay_ref: "current" };
  const refreshMissingStatusRef: ReplayInput = { ...refreshAcceptedRef,
    candidate: noStatusManifest as unknown as JsonValue };
  const brokenRefreshBody = { ...refreshedBody, predecessor_digest: "00".repeat(32) };
  const brokenRefreshManifest: ContinuityManifest = { ...brokenRefreshBody,
    authority_proof: createContinuityAuthorityProof(brokenRefreshBody, x.s.writerOne.private_key) };
  const brokenRefreshRef: ReplayInput = { ...refreshAcceptedRef,
    candidate: brokenRefreshManifest as unknown as JsonValue };
  const baseChainEntry = { manifest: manifest as unknown as JsonValue, ledger_replay: ledgerReplay,
    context: continuityContext as unknown as JsonValue };
  const refreshChainEntry = { manifest: refreshedManifest as unknown as JsonValue, ledger_replay_ref: "current",
    context: refreshedContext as unknown as JsonValue };
  const validChain = [baseChainEntry] as unknown as JsonValue;
  const refreshedChain = [baseChainEntry, refreshChainEntry] as unknown as JsonValue;
  const anchoredProjection = { ...x.projection,
    status_mirror: { ...x.projection.status_mirror, sha256: continuityManifestDigest(manifest) } };
  const validReferenced = projectAccessToken(anchoredProjection);
  const invalidReferenced = validReferenced;
  const authenticatedStatusMutation = (token: StatusListToken): JsonValue => {
    const body = { ...manifestBody, status_lists: [{ path: statusPath,
      sha256: createHash("sha256").update(token.compact).digest("hex"), issuer: x.metadata.issuer, uri }] };
    const authenticatedManifest: ContinuityManifest = { ...body,
      authority_proof: createContinuityAuthorityProof(body, x.s.writerOne.private_key) };
    const projection = { ...x.projection, status_mirror: { ...x.projection.status_mirror,
      sha256: continuityManifestDigest(authenticatedManifest) } };
    return { status_token: token as unknown as JsonValue,
      manifest: authenticatedManifest as unknown as JsonValue,
      referenced_compact: projectAccessToken(projection).compact };
  };
  const badSignatureStatus = structuredClone(validStatus);
  const signatureSegments = badSignatureStatus.compact.split(".");
  const signature = signatureSegments[2];
  signatureSegments[2] = `${signature.slice(0, -1)}${signature.endsWith("A") ? "B" : "A"}`;
  badSignatureStatus.compact = signatureSegments.join(".");
  const malformedStatus = structuredClone(validStatus);
  malformedStatus.claims.status_list = { bits: 1, lst: "eA" };
  malformedStatus.compact = resignCompact(malformedStatus.compact, malformedStatus.claims,
    malformedStatus.protected_header.kid);
  const staleMutationMaterial = {
    bad_signature: authenticatedStatusMutation(badSignatureStatus),
    malformed_zlib: authenticatedStatusMutation(malformedStatus),
  } as unknown as JsonValue;
  const statusInput = (status: StatusListToken, referenced: typeof validReferenced,
    chain: JsonValue, now = status.claims.iat, statusJwksBytes: Uint8Array = jwksBytes,
    statusResolvedAt = status.claims.iat): ReplayInput => ({
    operation: "status-validation", referenced_compact: referenced.compact, issuer: x.metadata.issuer,
    audience: API, referenced_jwks: jwks as unknown as JsonValue, options: options as unknown as JsonValue,
    status_token: status as unknown as JsonValue,
    status_jwks_hex: Buffer.from(statusJwksBytes).toString("hex"), status_resolved_at: statusResolvedAt,
    continuity_chain: chain, media_type: STATUS_LIST_MEDIA_TYPE, now,
  });
  const rotatedBody = { ...manifestBody, sequence: 1, predecessor_digest: continuityManifestDigest(manifest),
    status_lists: [{ path: statusPath, sha256: createHash("sha256").update(compromiseStatus.compact).digest("hex"),
      issuer: x.metadata.issuer, uri }],
    authority: { writer_nid: x.s.writerTwo.did_key, issued_at: rotatedState.checkpoint.observed_at,
      checkpoint: rotatedState.checkpoint },
    current_jwks_sha256: rotatedJwksDigest,
    current_signing_key_id: OIDC_RSA_TWO.key_id,
    current_signing_jwk_sha256: rotatedSigningJwkDigest,
    retiring_signing_key_ids: [], retiring_jwks_sha256: [] };
  const rotatedManifest: ContinuityManifest = { ...rotatedBody,
    authority_proof: createContinuityAuthorityProof(rotatedBody, x.s.writerTwo.private_key) };
  const rotatedNoStatusBody = { ...rotatedBody, status_lists: [] };
  const rotatedNoStatusManifest: ContinuityManifest = { ...rotatedNoStatusBody,
    authority_proof: createContinuityAuthorityProof(rotatedNoStatusBody, x.s.writerTwo.private_key) };
  const rotatedContinuityContext = { ...continuityContext, writer_nid: x.s.writerTwo.did_key,
    now: rotatedState.checkpoint.observed_at,
    kel_transition: { ...continuityContext.kel_transition, previous_head: manifest.persona_kel_head,
      current_head: rotatedManifest.persona_kel_head, valid_from: rotatedManifest.authority.issued_at } };
  const rotatedContinuity: ReplayInput = { operation: "continuity", previous: manifest as unknown as JsonValue,
    candidate: rotatedManifest as unknown as JsonValue, ledger_replay_ref: "current",
    context: rotatedContinuityContext as unknown as JsonValue };
  const rotatedChainEntry = { manifest: rotatedManifest as unknown as JsonValue, ledger_replay_ref: "current",
    context: rotatedContinuityContext as unknown as JsonValue };
  const compromiseChain = [baseChainEntry, rotatedChainEntry] as unknown as JsonValue;
  const rotatedStatusMap = new Map([[statusPath, Buffer.from(compromiseStatus.compact)]]);
  const rotatedTree = buildContinuityTree(rotatedManifest, discovery, rotatedJwksBytes, rotatedStatusMap);
  const rotatedMirror: ReplayInput = { operation: "mirror", manifest: rotatedManifest as unknown as JsonValue,
    discovery, jwks_hex: rotatedJwksBytes.toString("hex"),
    status_tokens: [{ path: statusPath, hex: Buffer.from(compromiseStatus.compact).toString("hex") }],
    https_bytes: [...rotatedTree].map(([path, bytes]) => ({ path, hex: Buffer.from(bytes).toString("hex") })) as unknown as JsonValue };
  const compromisedRetainedBytes = Buffer.from(JSON.stringify({ keys: [OIDC_RSA_TWO.public_jwk, OIDC_RSA_ONE.public_jwk] }));
  const compromisedRetainedBody = { ...rotatedBody,
    current_jwks_sha256: createHash("sha256").update(compromisedRetainedBytes).digest("hex"),
    retiring_signing_key_ids: [OIDC_RSA_ONE.key_id],
    retiring_jwks_sha256: [manifest.current_signing_jwk_sha256] };
  const compromisedRetainedManifest: ContinuityManifest = { ...compromisedRetainedBody,
    authority_proof: createContinuityAuthorityProof(compromisedRetainedBody, x.s.writerTwo.private_key) };
  const compromisedRetained: ReplayInput = { ...rotatedContinuity,
    candidate: compromisedRetainedManifest as unknown as JsonValue };

  const corruptedManifestBody = { ...manifestBody, current_jwks_sha256: "00".repeat(32) };
  const corruptedManifest: ContinuityManifest = { ...corruptedManifestBody,
    authority_proof: createContinuityAuthorityProof(corruptedManifestBody, x.s.writerOne.private_key) };
  const collisionInput: ReplayInput = { operation: "allocation-collision", writer_nid: x.s.writerOne.did_key,
    expires_at: x.issuance.expires_at, list_sequence: 0,
    existing: [x.issuance, structuredClone(x.issuance)] as unknown as JsonValue };
  return [
    authored("001-valid-status-list.json", "valid-status-list", "Draft-21 one-bit LSB-first ZLIB level-9 bytes and a valid signed status decision.", {
      operation: "status-encoding", statuses: [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1],
      signed_validation: statusInput(validStatus, validReferenced, validChain) as unknown as JsonValue,
      mutation_table: mutationTable({ bit_0: expectedBytes("01"), bit_7: expectedBytes("80"),
        bit_8: expectedBytes("0001"), padding: expectedBytes("01") }),
    }),
    authored("002-invalidated-token.json", "invalidated-token", "A signed INVALID bit fails closed and cannot be overridden by the otherwise valid referenced JWT.", {
      ...statusInput(invalidStatus, invalidReferenced, refreshedChain), operation: "status-generation",
      ledger_replay: invalidatedReplay, uri, iat: invalidStatus.claims.iat,
      exp: invalidStatus.claims.exp, ttl: invalidStatus.claims.ttl,
      evidence_cases: [refreshAcceptedRef, refreshMissingStatusRef, brokenRefreshRef] as unknown as JsonValue,
      authoritative_source: { issuance_record: x.issuance as unknown as JsonValue,
        invalidation_records: generatedInvalidations as unknown as JsonValue,
        invalidated_jti: x.issuance.jti, convergence: "revocation-wins" },
      mutation_table: mutationTable({ valid_to_invalid: expectedDecision("reject", "oidc-status-invalid"),
        invalid_to_valid_without_resign: expectedDecision("reject", "oidc-status-invalid") }),
    }),
    authored("003-stale-status-list-rejected.json", "stale-status-list-rejected", "TTL equality, expiration, bad signature, malformed ZLIB, and out-of-range indexes fail closed.", {
      ...statusInput(validStatus, validReferenced, validChain, validStatus.claims.iat + validStatus.claims.ttl),
      mutation_material: staleMutationMaterial,
      mutation_table: mutationTable({ ttl_boundary: expectedDecision("accept", null),
        expired: expectedDecision("reject", "oidc-status-stale"),
        bad_signature: expectedDecision("reject", "oidc-status-invalid"),
        malformed_zlib: expectedDecision("reject", "oidc-status-invalid"),
        out_of_range: expectedDecision("reject", "oidc-status-index-invalid") }),
    }),
    authored("004-writer-index-collision-rejected.json", "writer-index-collision-rejected", "Duplicate writer-namespaced URI/index allocation is rejected before token return.", {
      ...collisionInput, mutation_table: mutationTable({
        same_writer_same_index: expectedDecision("reject", "claim-repository-conflict"),
        distinct_writer_namespace: expectedDecision("accept", null),
        noncontiguous_prefix: expectedDecision("reject", "claim-repository-conflict") }),
    }),
    authored("005-https-radicle-byte-identity.json", "https-radicle-byte-identity", "Canonical-main discovery, JWKS, status and manifest tree is byte-identical to supplied HTTPS entities.", {
      operation: "mirror", manifest: manifest as unknown as JsonValue, discovery,
      jwks_hex: jwksBytes.toString("hex"), status_tokens: [{ path: statusPath, hex: Buffer.from(validStatus.compact).toString("hex") }],
      https_bytes: treeBytes, mutation_table: mutationTable({
        jwks_byte: expectedDecision("reject", "oidc-status-digest-mismatch"),
        status_byte: expectedDecision("reject", "oidc-status-digest-mismatch"),
        path_case: expectedDecision("reject", "oidc-status-digest-mismatch"),
        branch_not_main: expectedDecision("reject", "oidc-status-invalid") }),
    }),
    authored("006-radicle-digest-mismatch.json", "radicle-digest-mismatch", "A manifest/JWKS SHA-256 mismatch fails closed even when the public key itself is usable.", {
      operation: "mirror", manifest: corruptedManifest as unknown as JsonValue, discovery,
      jwks_hex: jwksBytes.toString("hex"), status_tokens: [{ path: statusPath, hex: Buffer.from(validStatus.compact).toString("hex") }],
      https_bytes: treeBytes, mutation_table: mutationTable({
        digest_nibble: expectedDecision("reject", "oidc-status-digest-mismatch"),
        byte_mismatch: expectedDecision("reject", "oidc-status-digest-mismatch"),
        extra_status_path: expectedDecision("reject", "oidc-status-digest-mismatch") }),
    }),
    authored("007-https-outage-radicle-fallback.json", "https-outage-radicle-fallback", "A Heterodyne verifier may use validated canonical-main continuity during HTTPS outage; ordinary OIDC does not auto-follow it.", {
      ...outageInput, mutation_table: mutationTable({ https_outage: expectedDecision("accept", null),
        stale_kel_head: expectedDecision("reject", "oidc-issuer-authority-invalid"),
        unauthorized_writer: expectedDecision("reject", "oidc-issuer-authority-invalid"),
        standard_oidc: expectedDecision("accept", null) }),
    }),
    authored("008-issuer-successor.json", "issuer-successor", "Issuer succession binds predecessor and successor commitments and separately proves persona authority.", {
      ...successionInput, mutation_material: successionMutationMaterial, mutation_table: mutationTable({
        missing_persona_proof: expectedDecision("reject", "oidc-issuer-authority-invalid"),
        predecessor_nibble: expectedDecision("reject", "oidc-status-digest-mismatch"),
        wrong_successor_url: expectedDecision("reject", "oidc-issuer-authority-invalid"),
        old_https_issuer: expectedDecision("reject", "oidc-issuer-authority-invalid") }),
    }),
    authored("009-signing-key-compromise.json", "signing-key-compromise", "Signing-key compromise invalidates the referenced token; shared-key possession cannot authorize issuer succession.", {
      ...statusInput(compromiseStatus, invalidReferenced, compromiseChain, compromiseStatus.claims.iat,
        rotatedJwksBytes), operation: "status-generation",
      ledger_replay: rotatedReplay, uri, iat: compromiseStatus.claims.iat,
      exp: compromiseStatus.claims.exp, ttl: compromiseStatus.claims.ttl,
      shared_key_succession_attempt: sharedKeyInsufficient as unknown as JsonValue,
      evidence_cases: [rotatedContinuity, compromisedRetained, rotatedMirror] as unknown as JsonValue,
      retention: { retiring_jwks_sha256: rotatedManifest.retiring_jwks_sha256,
        status_paths: rotatedManifest.status_lists.map(({ path }) => path),
        retain_through: x.issuance.expires_at },
      mutation_material: { drop_status_before_expiry: {
        candidate: rotatedNoStatusManifest as unknown as JsonValue,
      } } as unknown as JsonValue,
      mutation_table: mutationTable({
        compromised_key_bit: expectedDecision("reject", "oidc-status-invalid"),
        shared_key_only_successor: expectedDecision("reject", "oidc-issuer-authority-invalid"),
        retain_compromised_key: expectedDecision("reject", "oidc-issuer-authority-invalid"),
        drop_status_before_expiry: expectedDecision("reject", "oidc-status-digest-mismatch") }),
    }),
  ];
}
