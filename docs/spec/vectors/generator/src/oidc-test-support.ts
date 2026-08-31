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
} from "./claim-ledger.js";
import { subjectProofPayload, type JsonValue } from "./claims.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import type { Fixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  authorizeAuthorizationRequestEffect,
  inspectOidcAuthorizedRelease,
  issuerMetadata,
  type JwtProjectionInput,
  type JwtProjectionRequest,
  type OidcAuthorizationRequest,
  type OidcProjectionSubtype,
  type PersonaIdentityState,
  type RegisteredClient,
} from "./oidc.js";

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

/** Current-only OIDC fixture assembled from the live claim-ledger semantics. */
export async function buildLiveOidcScenario(
  fixtures: Fixtures,
  security: {
    sender_constraint: "none" | "dpop" | "mtls";
    cnf?: Record<string, JsonValue>;
  } = { sender_constraint: "none" },
) {
  const s = await buildClaimLedgerScenario(fixtures);
  const personaKey = fixtures.personas.alice.epoch_keys.epoch_1.pubkey;
  const personaNpub = nip19.npubEncode(personaKey);
  const identity: PersonaIdentityState = {
    persona_key: personaKey,
    persona_npub: personaNpub,
  };
  const metadata = issuerMetadata("https://node.example", personaNpub, identity);
  const registrationClaim = await s.makeClaim(s.writerOne, {
    namespace: "heterodyne.oidc",
    name: "client-registration",
    value: CLIENT as unknown as JsonValue,
    resources: [`${s.rid}#oidc-registration`],
  });
  const dataClaim = await s.makeClaim(s.writerOne, {
    namespace: "profile",
    name: "name",
    value: "Alice",
    resources: [API],
  });
  const keyClaim = await s.makeClaim(s.writerOne, {
    namespace: "heterodyne.device",
    name: "key-ref",
    value: { type: "nostr-secp256k1", value: personaKey },
    resources: [API],
  });
  const consentClaim = await s.makeClaim(s.writerOne, {
    namespace: "heterodyne.oidc",
    name: "consent",
    resources: [`${s.rid}#oidc-consent`],
    value: {
      client_id: CLIENT.client_id,
      scopes: ["heterodyne:key-ref", "openid", "profile"],
      audiences: [API],
      claims: ["https://heterodyne.network/jwt/key-ref", "name"],
      source_claim_ids: [
        dataClaim.artifact.semantic.claim_id,
        keyClaim.artifact.semantic.claim_id,
      ],
    },
  });
  const registrationRecord = s.signRecord("claim", {
    claim_artifact: registrationClaim.artifact,
  });
  const consentRecord = s.signRecord("claim", { claim_artifact: consentClaim.artifact });
  const dataRecord = s.signRecord("claim", { claim_artifact: dataClaim.artifact });
  const keyRecord = s.signRecord("claim", { claim_artifact: keyClaim.artifact });
  const authorityRecords = [
    s.claimRecordOne,
    s.claimRecordTwo,
    s.issuerClaimRecordOne,
    s.issuerClaimRecordTwo,
    s.issuerAuthorityRecordOne,
    s.issuerAuthorityRecordTwo,
    s.issuerKeyEpochRecordOne,
  ];
  const preMintRecords = [
    ...authorityRecords,
    registrationRecord,
    consentRecord,
    dataRecord,
    keyRecord,
  ];
  const preMintRepository = buildLedgerRepositoryEvidence({
    repository_rid: s.rid,
    confirmed_records: preMintRecords,
    observed_at: s.now + 68,
    prior: s.issuerKeyEpochOneRepository.repository,
  });
  const allClaims = new Map([
    ...s.allClaims,
    [registrationClaim.artifact.semantic.claim_id, registrationClaim.verified_artifact] as const,
    [consentClaim.artifact.semantic.claim_id, consentClaim.verified_artifact] as const,
    [dataClaim.artifact.semantic.claim_id, dataClaim.verified_artifact] as const,
    [keyClaim.artifact.semantic.claim_id, keyClaim.verified_artifact] as const,
  ]);
  const verificationFor = (claim: typeof dataClaim, resource: string) => {
    const verification = s.makeVerification(claim);
    const challenge = {
      ...verification.subject_proof!.challenge,
      resource,
      issued_at: s.now + 68,
      expires_at: s.now + 128,
    };
    const signature = bytesToHex(ed25519.sign(
      subjectProofPayload(challenge),
      hexToBytes(claim.reader.private_key),
    ));
    return {
      ...verification,
      now: s.now + 69,
      resource,
      requested_namespace: claim.artifact.semantic.namespace,
      repository_confirmed: new Set(allClaims.keys()),
      expected_nonce: challenge.nonce,
      subject_proof: {
        ...verification.subject_proof!,
        challenge,
        proof: { ...verification.subject_proof!.proof, signature },
      },
    };
  };
  const evidenceFor = (
    record: LedgerRecord,
    claim: typeof dataClaim,
  ): LedgerRecordValidationEvidence => ({
    record_id: record.record_id,
    payload_digest: record.payload_digest,
    claim_envelope_context: {
      profile_revision: 2,
      credential_ledger: {
        credential_ledger_persona: s.persona,
        credential_ledger_generation: 0,
      },
    },
    claims_by_id: new Map(),
    claim_verification_context: verificationFor(
      claim,
      claim.artifact.semantic.resources![0],
    ),
  });
  const preMintContext = s.makeTask5Context(preMintRepository.repository);
  for (const [record, claim] of [
    [registrationRecord, registrationClaim],
    [consentRecord, consentClaim],
    [dataRecord, dataClaim],
    [keyRecord, keyClaim],
  ] as const) {
    preMintContext.record_evidence.set(record.record_id, evidenceFor(record, claim));
  }
  const preMintState = mergeClaimLedger(
    preMintRecords,
    [],
    preMintRepository.checkpoint,
    preMintContext,
  );
  const pairwiseSecret = "aa".repeat(32);
  const codeVerifier =
    "heterodyne-code-verifier-000000000000000000000000000000000000000000000000";
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  const evidence = (record: LedgerRecord, claim: typeof dataClaim) => ({
    claim_record_id: record.record_id,
    verification_context: verificationFor(
      claim,
      claim.artifact.semantic.resources![0],
    ),
  });
  const request: OidcAuthorizationRequest = {
    flow: "authorization_code",
    grant_type: "authorization_code",
    response_type: "code",
    client_id: CLIENT.client_id,
    redirect_uri: CLIENT.redirect_uris[0],
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    requested_scopes: ["openid", "profile", "heterodyne:key-ref"],
    requested_audiences: [API],
    requested_claims: ["name", "https://heterodyne.network/jwt/key-ref"],
    pairwise_secret: pairwiseSecret,
    state: preMintState,
    nonce: "oidc-vector-nonce",
    sender_constraint: security.sender_constraint,
    ...(security.cnf === undefined ? {} : { cnf: security.cnf }),
    registration: evidence(registrationRecord, registrationClaim),
    consent: evidence(consentRecord, consentClaim),
    source_claims: [evidence(dataRecord, dataClaim), evidence(keyRecord, keyClaim)],
  };
  const releaseHarness = s.makeClaimAuthorizationHarness({
    load_state: () => preMintState,
    trusted_now: () => s.now + 69,
  });
  let releaseEffects = 0;
  const releaseAuthorization = await authorizeAuthorizationRequestEffect(
    releaseHarness.authority,
    {
      request,
      idempotency_key: "synthetic-local-oidc-release-0001",
      purpose: "authorization_code",
      projection_subtype: null,
      assertion_profile: null,
      projection_request: null,
      authorization_validity_seconds: 300,
      effect: () => {
        releaseEffects += 1;
        return { status: "completed", result: { executed: true } };
      },
    },
  );
  if (releaseAuthorization.verdict !== "accept") {
    throw new Error(`OIDC scenario release failed: ${releaseAuthorization.reason_code}`);
  }
  const release = inspectOidcAuthorizedRelease(releaseAuthorization.authorization);
  const sourceClaimIds = [
    registrationClaim.artifact.semantic.claim_id,
    consentClaim.artifact.semantic.claim_id,
    dataClaim.artifact.semantic.claim_id,
    keyClaim.artifact.semantic.claim_id,
  ].sort();
  const now = s.now + 69;
  const issuance: IssuanceRecord = {
    credential_ledger_generation: 0,
    jti: "oidc-evidence-jti-0001",
    reservation: reserveStatusIndex(s.writerOne.did_key, now + 600, 0, []),
    checkpoint: preMintRepository.checkpoint,
    manifest_max_age_seconds: 300,
    signing_key_id: s.issuerKeyEnvelopeOne.signing_key_id,
    client_id: CLIENT.client_id,
    authorization_request_digest: release.request_digest!,
    release_digest: release.release_digest!,
    source_claim_ids: sourceClaimIds,
    issued_at: now,
    expires_at: now + 600,
  };
  const issuanceRecord = s.signRecord(
    "issuance-reservation",
    issuance as unknown as JsonValue,
    s.writerOne,
    [
      registrationRecord.record_id,
      consentRecord.record_id,
      dataRecord.record_id,
      keyRecord.record_id,
    ].sort(),
    s.now + 70,
  );
  const issuedRecords = [...preMintRecords, issuanceRecord];
  const issuedRepository = buildLedgerRepositoryEvidence({
    repository_rid: s.rid,
    confirmed_records: issuedRecords,
    observed_at: s.now + 71,
    prior: preMintRepository.repository,
  });
  const issuedContext = s.makeTask5Context(issuedRepository.repository);
  for (const [record, claim] of [
    [registrationRecord, registrationClaim],
    [consentRecord, consentClaim],
    [dataRecord, dataClaim],
    [keyRecord, keyClaim],
  ] as const) {
    issuedContext.record_evidence.set(record.record_id, evidenceFor(record, claim));
  }
  issuedContext.record_evidence.set(issuanceRecord.record_id, {
    record_id: issuanceRecord.record_id,
    payload_digest: issuanceRecord.payload_digest,
  });
  const issuedState = mergeClaimLedger(
    issuedRecords,
    [],
    issuedRepository.checkpoint,
    issuedContext,
  );
  const projectionContext: JwtProjectionRequest = Object.freeze({
    issuer: metadata.issuer,
    client_id: CLIENT.client_id,
    audience: release.audience!,
    pairwise_sub: release.pairwise_sub!,
    scopes: release.scopes!,
    now,
    expires_at: issuance.expires_at,
    issuance_record_id: issuanceRecord.record_id,
    state: issuedState,
    issuer_envelope: s.issuerKeyEnvelopeOne,
    issuer_audience_key: s.issuerAudienceKeyOne,
    issuer_writer_nid: s.writerOne.did_key,
    identity,
    status_mirror: {
      repository_rid: s.rid,
      branch: "main" as const,
      path: `.well-known/${personaNpub}/${issuance.reservation.uri}`,
      sha256: "33".repeat(32),
    },
  });
  const projectionAuthorizations: Array<Readonly<{
    authority: typeof releaseHarness.authority;
    authorization: typeof releaseAuthorization.authorization;
    projection_subtype: OidcProjectionSubtype;
    assertion_profile: string | null;
  }>> = [];
  const projectionProfiles = Array.from({ length: 16 }, () => [
    { projection_subtype: "id_token" as const, assertion_profile: null },
    { projection_subtype: "access_token" as const, assertion_profile: null },
    {
      projection_subtype: "jwt_assertion" as const,
      assertion_profile: "urn:example:jwt-assertion:v1",
    },
  ]).flat();
  for (const [index, profile] of projectionProfiles.entries()) {
    const harness = s.makeClaimAuthorizationHarness({
      load_state: () => preMintState,
      trusted_now: () => s.now + 69,
    });
    const authorized = await authorizeAuthorizationRequestEffect(harness.authority, {
      request,
      idempotency_key: `synthetic-local-oidc-projection-${String(index).padStart(4, "0")}`,
      purpose: "jwt_projection",
      projection_subtype: profile.projection_subtype,
      assertion_profile: profile.assertion_profile,
      projection_request: projectionContext,
      authorization_validity_seconds: 300,
      effect: () => ({ status: "completed", result: { executed: true } }),
    });
    if (authorized.verdict !== "accept") {
      throw new Error(`OIDC projection authorization failed: ${authorized.reason_code}`);
    }
    projectionAuthorizations.push(Object.freeze({
      authority: harness.authority,
      authorization: authorized.authorization,
      ...profile,
    }));
  }
  const projection = (
    projectionSubtype: OidcProjectionSubtype,
    assertionProfile: string | null = projectionSubtype === "jwt_assertion"
      ? "urn:example:jwt-assertion:v1"
      : null,
  ): JwtProjectionInput => {
    const selectedIndex = projectionAuthorizations.findIndex((entry) =>
      entry.projection_subtype === projectionSubtype &&
      entry.assertion_profile === assertionProfile);
    if (selectedIndex < 0) {
      throw new Error("synthetic OIDC projection authorization pool exhausted");
    }
    const [selected] = projectionAuthorizations.splice(selectedIndex, 1);
    return {
      authorization_authority: selected.authority,
      authorization: selected.authorization,
    };
  };
  let customProjectionIndex = 0;
  const authorizeProjection = async (
    projectionSubtype: OidcProjectionSubtype,
    projectionRequest: JwtProjectionRequest,
    assertionProfile: string | null = projectionSubtype === "jwt_assertion"
      ? "urn:example:jwt-assertion:v1"
      : null,
  ): Promise<JwtProjectionInput> => {
    const harness = s.makeClaimAuthorizationHarness({
      load_state: () => preMintState,
      trusted_now: () => s.now + 69,
    });
    const authorized = await authorizeAuthorizationRequestEffect(harness.authority, {
      request,
      idempotency_key: `synthetic-local-oidc-custom-projection-${String(customProjectionIndex).padStart(4, "0")}`,
      purpose: "jwt_projection",
      projection_subtype: projectionSubtype,
      assertion_profile: assertionProfile,
      projection_request: projectionRequest,
      authorization_validity_seconds: 300,
      effect: () => ({ status: "completed", result: { executed: true } }),
    });
    customProjectionIndex += 1;
    if (authorized.verdict !== "accept") {
      throw new Error(`OIDC custom projection authorization failed: ${authorized.reason_code}`);
    }
    return Object.freeze({
      authorization_authority: harness.authority,
      authorization: authorized.authorization,
    });
  };
  return {
    s,
    personaKey,
    personaNpub,
    identity,
    metadata,
    registrationRecord,
    consentRecord,
    dataRecord,
    keyRecord,
    preMintRecords,
    preMintRepository,
    preMintContext,
    preMintState,
    issuedRecords,
    issuedRepository,
    issuedContext,
    issuedState,
    issuance,
    issuanceRecord,
    request,
    release,
    releaseAuthorization,
    releaseHarness,
    releaseEffects,
    projection,
    authorizeProjection,
    projectionContext,
    dataClaim,
    allClaims,
    evidenceFor,
    codeVerifier,
    codeChallenge,
    pairwiseSecret,
  };
}
