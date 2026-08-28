import { nip44 } from "nostr-tools";
import { schnorr } from "@noble/curves/secp256k1";
import {
  injectAgentAttribution,
  validateAgentAccessToken,
  validateWorkloadRegistration,
  type AgentTokenValidationInput,
} from "../agent-authorship.js";
import { buildAuthorizationFreshnessTestSupport } from "../authorization-freshness-test-support.js";
import { evaluateAuthorizationFreshness } from "../authorization-freshness.js";
import {
  canMint,
  evaluateReaderAccess,
  ledgerErrorReason,
  mergeClaimLedger,
  validateLedgerRecordOrThrow,
} from "../claim-ledger.js";
import { buildClaimLedgerScenario } from "../claim-ledger-test-support.js";
import {
  authorizeWithClaim,
  validateClaimEnvelope,
  validateClaimId,
  validateClaimRevocationEnvelope,
  validateKeyRef,
} from "../claims.js";
import {
  classifyRelayWriteFailure,
  evaluateMarmotInboxBootstrap,
  evaluateOneTimeInvite,
  evaluatePrivateMarmotRoute,
  validateDmInviteDevice,
  validatePrivateBroadcast,
  validatePublicReaderRendering,
} from "../comms-policy.js";
import { QUALIFIED_VERSION } from "../family.js";
import { buildFixtures } from "../fixtures.js";
import { resolveTier3Recipients } from "../follow-up-hardening.js";
import { bytesToHex, hexToBytes } from "../hex.js";
import { ordinaryConversationAdmission } from "../marmot-admission.js";
import {
  evaluateMarmotDurability,
  evaluateMarmotRetention,
  evaluateMarmotRoutingBinding,
} from "../marmot-routing-policy.js";
import { signEvent } from "../nostr.js";
import { buildLiveOidcScenario } from "../oidc-test-support.js";
import {
  projectAccessToken,
  validateAuthorizationRequest,
  validateIssuerMetadata,
  validateProjectedJwt,
} from "../oidc.js";
import { OIDC_RSA_ONE } from "../oidc-rsa-fixtures.js";
import { deriveConfigPostKey, deriveTier3IndexKey } from "../privacy-crypto.js";
import {
  parseLauncherFragment,
  resolvePublicAsset,
  validateBootstrapRelay,
} from "../public-reader.js";
import { validateOidcContinuityManifestSchemaOrThrow } from "../schema.js";
import {
  createTrustedSeedAdmissionAuthority,
  evaluateTrustedSeedAdmission,
  trustedSeedAclProofBytes,
} from "../trusted-seed.js";
import { encodeStatusList } from "../token-status.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const decisionOutput = (
  decision: ReturnType<typeof evaluateAuthorizationFreshness>,
): Record<string, unknown> => decision.verdict === "accept"
  ? { verdict: "accept", current_authorization_view: "opaque" }
  : { verdict: "reject", reason_code: decision.reason };

const thrownDecision = (evaluate: () => unknown): Record<string, unknown> => {
  try {
    evaluate();
    return { verdict: "accept" };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const reason = message.match(/^([a-z][a-z0-9_-]*)(?::|$)/)?.[1];
    if (reason === undefined) throw error;
    return { verdict: "reject", reason_code: reason };
  }
};

function executedCommsRejection(options: {
  id: string;
  boundary: string;
  anchor: string;
  invariant: string;
  reason: string;
  description: string;
  input: Readonly<Record<string, unknown>>;
  decision: Readonly<Record<string, unknown>>;
}): CurrentVectorCase {
  if (options.decision.reason_code !== options.reason) {
    throw new Error(
      `current Comms evaluator mismatch for ${options.id}: ${String(options.decision.reason_code)}`,
    );
  }
  const expectedOutput = options.decision.verdict === "reject"
    ? options.decision
    : {
        verdict: "reject",
        reason_code: options.reason,
        evaluator_output: options.decision,
      };
  return {
    relativePath: `comms/${options.id}.json`,
    semantic_boundary: options.boundary,
    vector_id: `comms/${options.id}`,
    owner_document: "comms",
    spec_refs: [currentSpecRef(options.anchor)],
    invariants: [options.invariant],
    reason_codes: [options.reason],
    description: options.description,
    direction: "consume",
    input: options.input,
    expected_output: expectedOutput,
  };
}

export async function buildCommsCases(): Promise<CurrentVectorCase[]> {
  const support = await buildAuthorizationFreshnessTestSupport();
  const state = support.scenario.issuerKeyEpochOneState;
  const observedAt = state.checkpoint.observed_at;

  const checkpointBoundary = support.signedManifest(state, {
    checkpoint_age: 300,
    authorization_view_max_age: 300,
  });
  const checkpointBoundaryDecision = evaluateAuthorizationFreshness(
    support.authorityFor(checkpointBoundary, state, { now: observedAt + 300 }),
    checkpointBoundary,
  );
  const checkpointStale = support.signedManifest(state, {
    checkpoint_age: 301,
    authorization_view_max_age: 300,
  });
  const checkpointStaleDecision = evaluateAuthorizationFreshness(
    support.authorityFor(checkpointStale, state, { now: observedAt + 301 }),
    checkpointStale,
  );
  const view300 = support.signedManifest(state, { authorization_view_max_age: 300 });
  const view300Decision = evaluateAuthorizationFreshness(
    support.authorityFor(view300, state, { now: observedAt + 300 }),
    view300,
  );
  const view86400 = support.signedManifest(state, { authorization_view_max_age: 86_400 });
  const view86400Decision = evaluateAuthorizationFreshness(
    support.authorityFor(view86400, state, { now: observedAt + 86_400 }),
    view86400,
  );
  const malformed = support.signedManifest(state, { authorization_view_max_age: 86_401 });
  let malformedRejected = false;
  try {
    validateOidcContinuityManifestSchemaOrThrow(malformed);
  } catch {
    malformedRejected = true;
  }
  const persona = "11".repeat(32);
  const activeDevice = "22".repeat(32);
  const inactiveDevice = "33".repeat(32);
  const tier3Input = {
    memberPersonas: [persona],
    devices: [
      { persona, pubkey: activeDevice, active: true, role: "human-device" as const },
      { persona, pubkey: inactiveDevice, active: false, role: "human-device" as const },
    ],
    selected: [inactiveDevice],
  };
  const tier3Decision = resolveTier3Recipients(tier3Input);

  const fixtures = buildFixtures();
  const ledger = await buildClaimLedgerScenario(fixtures);
  const claim = ledger.claimOne.artifact.semantic;
  const claimContext = ledger.makeVerification(ledger.claimOne);
  const activeClaimDecision = authorizeWithClaim(claim, [claim], claimContext);
  const unconfirmedClaimDecision = authorizeWithClaim(claim, [claim], {
    ...claimContext,
    repository_confirmed: new Set(),
  });
  const baseLedgerState = mergeClaimLedger(
    [ledger.claimRecordOne, ledger.claimRecordTwo],
    [],
    ledger.baseRepository.checkpoint,
    ledger.makeContext(ledger.baseRepository.repository),
  );
  const authorizedReaderRequest = ledger.requestFor(
    ledger.claimRecordOne,
    ledger.claimOne,
  );
  authorizedReaderRequest.verification_context.now =
    ledger.baseRepository.checkpoint.observed_at;
  const authorizedReader = evaluateReaderAccess(
    ledger.writerOne.did_key,
    baseLedgerState,
    authorizedReaderRequest,
  );
  const unauthorizedReader = evaluateReaderAccess(
    ledger.writerTwo.did_key,
    baseLedgerState,
    ledger.requestFor(ledger.claimRecordOne, ledger.claimOne),
  );
  const invalidClaimId = { ...claim, claim_id: "00".repeat(32) };
  const invalidClaimIdDecision = thrownDecision(() => validateClaimId(invalidClaimId));
  const invalidClaimKey = { type: "nostr-secp256k1" as const, value: "00".repeat(32) };
  const invalidClaimKeyDecision = thrownDecision(() => validateKeyRef(invalidClaimKey));
  const invalidClaimEvent = { ...ledger.claimOne.artifact.event, sig: "00".repeat(64) };
  const claimEnvelopeContext = ledger.requestFor(
    ledger.claimRecordOne,
    ledger.claimOne,
  ).envelope_context;
  const invalidClaimEventDecision = thrownDecision(() =>
    validateClaimEnvelope(invalidClaimEvent, claimEnvelopeContext)
  );
  const missingAuthorityContext = {
    ...claimContext,
    claim_authority_evidence: new Map(),
  };
  const missingAuthorityDecision = authorizeWithClaim(
    claim,
    [claim],
    missingAuthorityContext,
  );
  const attenuationContext = { ...claimContext, requested_namespace: "other.namespace" };
  const attenuationDecision = authorizeWithClaim(claim, [claim], attenuationContext);
  const expiredAuthority = new Map(claimContext.claim_authority_evidence);
  const activeEvidence = expiredAuthority.get(claim.claim_id)!;
  expiredAuthority.set(claim.claim_id, {
    ...activeEvidence,
    valid_until: claim.expires_at! + 60,
  });
  const expiredContext = {
    ...claimContext,
    now: claim.expires_at!,
    claim_authority_evidence: expiredAuthority,
  };
  const expiredClaimDecision = authorizeWithClaim(claim, [claim], expiredContext);
  const repositoryConflictDecision = authorizeWithClaim(claim, [claim], {
    ...claimContext,
    repository_conflicted: new Set([claim.claim_id]),
  });
  const subjectRequiredDecision = authorizeWithClaim(claim, [claim], {
    ...claimContext,
    subject_proof: null,
  });
  const subjectInvalidContext = structuredClone(claimContext);
  if (subjectInvalidContext.subject_proof === null) {
    throw new Error("claim subject-proof fixture missing");
  }
  subjectInvalidContext.subject_proof.challenge.nonce = "ff".repeat(16);
  const subjectInvalidDecision = authorizeWithClaim(claim, [claim], subjectInvalidContext);
  const untrustedClaimDecision = authorizeWithClaim(claim, [claim], {
    ...claimContext,
    trusted_issuers: [],
  });
  const revocationArtifact = (ledger.revocationRecord.payload as unknown as {
    revocation_artifact: { event: Parameters<typeof validateClaimRevocationEnvelope>[0] };
  }).revocation_artifact;
  const verifiedRevocation = validateClaimRevocationEnvelope(revocationArtifact.event);
  const revokedClaimDecision = authorizeWithClaim(claim, [claim], {
    ...claimContext,
    now: verifiedRevocation.revoked_at,
    revocations: [verifiedRevocation],
  });
  const chainCycleDecision = authorizeWithClaim(claim, [claim, claim], claimContext);
  const chainDepthDecision = authorizeWithClaim(
    claim,
    Array.from({ length: 10 }, () => claim),
    claimContext,
  );
  const delegationDecision = authorizeWithClaim(
    ledger.claimTwo.artifact.semantic,
    [claim],
    claimContext,
  );
  const rollbackCheckpoint = { ...ledger.baseRepository.checkpoint, branch: "dev" };
  const rollbackDecision = (() => {
    try {
      mergeClaimLedger(
        [ledger.claimRecordOne],
        [],
        rollbackCheckpoint as never,
        ledger.makeContext(ledger.baseRepository.repository),
      );
      return { verdict: "accept" };
    } catch (error) {
      return { verdict: "reject", reason_code: ledgerErrorReason(error) };
    }
  })();
  const unauthorizedRevocationEvidence = {
    record_id: ledger.removalRecord.record_id,
    payload_digest: ledger.removalRecord.payload_digest,
  };
  const unauthorizedRevocationDecision = (() => {
    try {
      validateLedgerRecordOrThrow(
        ledger.removalRecord,
        new Map([
          [ledger.claimRecordOne.record_id, ledger.claimRecordOne],
          [ledger.removalRecord.record_id, ledger.removalRecord],
        ]),
        unauthorizedRevocationEvidence,
        {
          credential_ledger_persona: ledger.persona,
          credential_ledger_generation: 0,
        },
      );
      return { verdict: "accept" };
    } catch (error) {
      return { verdict: "reject", reason_code: ledgerErrorReason(error) };
    }
  })();

  const oidc = await buildLiveOidcScenario(fixtures);
  const oidcRelease = validateAuthorizationRequest(oidc.request);
  const accessToken = projectAccessToken(oidc.projection);
  const accessValidation = validateProjectedJwt(
    accessToken.compact,
    oidc.metadata.issuer,
    "https://api.example",
    { keys: [OIDC_RSA_ONE.public_jwk] },
    {
      now: oidc.projection.now,
      token_use: "access_token",
      client_id: oidc.request.client_id,
      sender_constraint: "none",
      permitted_audiences: ["https://api.example"],
      credential_ledger: oidc.issuedState.credential_ledger,
    },
  );
  const issuerMetadataDecision = validateIssuerMetadata(
    oidc.metadata,
    oidc.metadata.issuer,
    oidc.metadata.jwks_uri,
  );
  const unregisteredClientDecision = validateAuthorizationRequest({
    ...oidc.request,
    client_id: "unregistered-client",
  });
  const prohibitedGrantDecision = validateAuthorizationRequest({
    ...oidc.request,
    grant_type: "client_credentials",
  } as never);
  const consentRequiredDecision = validateAuthorizationRequest({
    ...oidc.request,
    requested_scopes: ["profile"],
  });
  const releaseDeniedDecision = validateAuthorizationRequest({
    ...oidc.request,
    nonce: "",
  });
  const issuerMismatchDecision = validateIssuerMetadata(
    oidc.metadata,
    "https://other.example/oidc/npub1other",
    oidc.metadata.jwks_uri,
  );
  const tokenTypeDecision = validateProjectedJwt(
    accessToken.compact,
    oidc.metadata.issuer,
    "registered-client",
    { keys: [OIDC_RSA_ONE.public_jwk] },
    {
      now: oidc.projection.now,
      token_use: "id_token",
      client_id: oidc.request.client_id,
      nonce: oidc.request.nonce,
      sender_constraint: "none",
      permitted_audiences: ["registered-client"],
      credential_ledger: oidc.issuedState.credential_ledger,
    },
  );
  const audienceInvalidDecision = validateProjectedJwt(
    accessToken.compact,
    oidc.metadata.issuer,
    "https://api.example",
    { keys: [OIDC_RSA_ONE.public_jwk] },
    {
      now: oidc.projection.now,
      token_use: "access_token",
      client_id: oidc.request.client_id,
      sender_constraint: "none",
      permitted_audiences: ["https://api.example", "https://extra.example"],
      credential_ledger: oidc.issuedState.credential_ledger,
    },
  );
  const issuerAuthorityDecision = canMint(
    ledger.baseRepository.checkpoint.observed_at,
    ledger.baseRepository.checkpoint,
    300,
    "revoked",
    true,
  );
  const signingKeyDecision = canMint(
    ledger.baseRepository.checkpoint.observed_at,
    ledger.baseRepository.checkpoint,
    300,
    "active",
    false,
  );
  const statusInvalidDecision = thrownDecision(() => encodeStatusList([]));

  const configKey = deriveConfigPostKey("42".repeat(32), "current-config-key");
  const configPlaintext = JSON.stringify({ blob: "synthetic-private-config" });
  const configCiphertext = nip44.v2.encrypt(
    configPlaintext,
    configKey,
    hexToBytes("60".repeat(32)),
  );
  const configRecovered = nip44.v2.decrypt(configCiphertext, configKey);
  const tier3Key = deriveTier3IndexKey("40".repeat(32), "current-tier3-key");
  const tier3Plaintext = JSON.stringify({ audience: "opaque", payload: "protected" });
  const tier3Ciphertext = nip44.v2.encrypt(
    tier3Plaintext,
    tier3Key,
    hexToBytes("61".repeat(32)),
  );
  const tier3Recovered = nip44.v2.decrypt(tier3Ciphertext, tier3Key);

  const publicPrivateDecision = resolvePublicAsset({
    tier: 2,
    available: true,
    signature_valid: true,
    complete_fetch: true,
    nip65_refreshed: true,
    canonical_feed_reachable: true,
    indexed: true,
    repo_confirmed: true,
    conflict: false,
  });
  const invalidLauncher = parseLauncherFragment("#/v1/unknown");
  const invalidRelay = validateBootstrapRelay("ws://127.0.0.1/private");

  const agentPersona = "11".repeat(32);
  const signer = "33".repeat(32);
  const issuer = "https://issuer.example/oidc/npub1persona";
  const audience = "https://node.example/control/agent-publication";
  const subjectJkt = "A".repeat(43);
  const registration = {
    persona_key: agentPersona,
    client_id: "current-agent-client",
    subject_jkt: subjectJkt,
    subject_proof: { method: "dpop" as const, jkt: subjectJkt },
    agent_class: "ai" as const,
    selected_signer: signer,
    signer_key_class: "agent" as const,
    agent_association: { kind: "key" as const, value: signer },
    audience,
    scopes: ["heterodyne:agent:publish"],
    allowed_kinds: [1],
    allowed_feeds: ["main"],
    allowed_resources: ["feed:main"],
    max_content_bytes: 4096,
    rate_limit: { window_seconds: 60, count: 20, burst: 5 },
    not_before: 1_000,
    expires_at: 1_300,
  };
  const validatedRegistration = validateWorkloadRegistration(registration);
  const tokenInput: AgentTokenValidationInput = {
    typ: "at+jwt",
    credential_ledger_persona: agentPersona,
    credential_ledger_generation: 0,
    expected_credential_ledger_persona: agentPersona,
    expected_credential_ledger_generation: 0,
    iss: issuer,
    sub: "stable-pairwise-sub",
    aud: [audience],
    exp: 1_250,
    iat: 1_000,
    jti: "current-token-1",
    client_id: registration.client_id,
    scope: "heterodyne:agent:publish",
    cnf_jkt: subjectJkt,
    sender_proof_jkt: subjectJkt,
    sender_proof_valid: true,
    signer_key: signer,
    signer_key_class: "agent",
    agent_association: registration.agent_association,
    expected_issuer: issuer,
    expected_subject: "stable-pairwise-sub",
    expected_audience: audience,
    expected_client_id: registration.client_id,
    expected_scope: "heterodyne:agent:publish",
    expected_signer_key: signer,
    expected_signer_key_class: "agent",
    expected_agent_association: registration.agent_association,
    now: 1_100,
    status: "VALID",
    ledger_active: true,
    ledger_binding_valid: true,
    status_binding_valid: true,
    session_expires_at: 1_300,
    delegation_expires_at: 1_300,
    registration_expires_at: 1_300,
    consent_expires_at: 1_300,
    source_authorization_expires_at: 1_300,
  };
  const tokenDecision = validateAgentAccessToken(tokenInput);
  const invalidRegistrationInput = { ...registration, max_content_bytes: 0 };
  const invalidRegistrationDecision = thrownDecision(() =>
    validateWorkloadRegistration(invalidRegistrationInput)
  );
  const invalidAgentTokenInput = { ...tokenInput, typ: "JWT" };
  const invalidAgentTokenDecision = validateAgentAccessToken(invalidAgentTokenInput);
  const invalidSenderProofInput = { ...tokenInput, sender_proof_valid: false };
  const invalidSenderProofDecision = validateAgentAccessToken(invalidSenderProofInput);
  const signerMismatchInput = { ...tokenInput, signer_key: "44".repeat(32) };
  const signerMismatchDecision = validateAgentAccessToken(signerMismatchInput);
  const attributionInput = {
    kind: 1,
    tags: [["client", "heterodyne"]],
    agent_class: "ai" as const,
    persona: agentPersona,
    issuer,
    subject: tokenInput.sub,
    client_id: registration.client_id,
    signer,
    expected_signer: signer,
    signer_key_class: "agent" as const,
    oidc_scopes: ["heterodyne:agent:publish"],
    agent_association: registration.agent_association,
    expected_agent_association: registration.agent_association,
    tier: 3 as const,
  };
  const attributionDecision = injectAgentAttribution(attributionInput);
  const personaScopeInput = {
    ...attributionInput,
    signer: agentPersona,
    expected_signer: agentPersona,
    signer_key_class: "persona" as const,
  };
  const personaScopeDecision = injectAgentAttribution(personaScopeInput);
  const invalidAttributionInput = { ...attributionInput, id: "00".repeat(32) };
  const invalidAttributionDecision = injectAgentAttribution(invalidAttributionInput);
  const unavailableAttributionInput = { ...attributionInput, kind: 2 };
  const unavailableAttributionDecision = injectAgentAttribution(unavailableAttributionInput);

  const ordinaryMarmotInput = {
    cryptographic_valid: true,
    inviter_account: persona,
    recipient_account: "22".repeat(32),
    group_id: "44".repeat(32),
    key_package_ref: "55".repeat(32),
    member_count: 2,
    supported_capabilities: true,
    prior_local_acceptance: false,
    one_time_dm_invite_valid: false,
    explicit_local_decision: "none" as const,
  };
  const ordinaryMarmotDecision = ordinaryConversationAdmission(ordinaryMarmotInput);
  const rejectedConversationInput = {
    ...ordinaryMarmotInput,
    explicit_local_decision: "reject" as const,
  };
  const rejectedConversationDecision = ordinaryConversationAdmission(rejectedConversationInput);

  const privateBroadcastInput = { transport: "nip59" as const, wrap_profile: "room_key.v1" as const };
  const relayAuthInput = { authenticated: true, response_prefix: "auth-required:" };
  const unboundDmInput = { delegation_present: false, delegation_revoked: false };
  const revokedDmInput = { delegation_present: true, delegation_revoked: true };
  const inviteBase = {
    now: 100,
    expires_at: 200,
    signed_purpose: "dm" as const,
    requested_purpose: "dm" as const,
    descriptor_signature_valid: true,
    responder_binding_valid: true,
    secret_proof_valid: true,
    capability_binding_valid: true,
    reserved_account: null,
    responder_account: "11".repeat(32),
    reserved_response_digest: null,
    response_digest: "22".repeat(32),
  };
  const inviteExpiredInput = { ...inviteBase, now: 200 };
  const invitePurposeInput = { ...inviteBase, requested_purpose: "control-enrollment" as const };
  const inviteAuthInput = { ...inviteBase, secret_proof_valid: false };
  const inviteReservedInput = { ...inviteBase, reserved_account: "33".repeat(32) };
  const privateReaderInput = { tier: 2 as const, render_as_public: true };
  const privateRouteInput = { private_group: true, requested_route: "rad:zAbsent", authorized_routes: [] as string[] };
  const inboxNidInput = { sender_nid_authorized: false, keypackage_already_consumed: false, automated_scope_valid: true };
  const inboxReplayInput = { sender_nid_authorized: true, keypackage_already_consumed: true, automated_scope_valid: true };
  const marmotScopeInput = { sender_nid_authorized: true, keypackage_already_consumed: false, automated_scope_valid: false };

  const routingBindingInput = {
    active_administrator: agentPersona,
    commit_author: agentPersona,
    canonical_h: "routing-generation-current",
    binding_h: "routing-generation-current",
    canonical_rid: "rad:zCurrentMarmotRoute",
    binding_rid: "rad:zCurrentMarmotRoute",
    canonical_genesis_digest: "22".repeat(32),
    binding_genesis_digest: "22".repeat(32),
    binding_digests: ["33".repeat(32)],
    requested_writer_ref: "refs/xyz.heterodyne.marmot/writers/current",
    authorized_writer_refs: ["refs/xyz.heterodyne.marmot/writers/current"],
  };
  const routingBindingDecision = evaluateMarmotRoutingBinding(routingBindingInput);
  const routingMismatchInput = {
    ...routingBindingInput,
    binding_genesis_digest: "44".repeat(32),
  };
  const routingMismatchDecision = evaluateMarmotRoutingBinding(routingMismatchInput);
  const routingEquivocationInput = {
    ...routingBindingInput,
    binding_digests: ["33".repeat(32), "44".repeat(32)],
  };
  const routingEquivocationDecision = evaluateMarmotRoutingBinding(routingEquivocationInput);
  const unauthorizedRefInput = {
    ...routingBindingInput,
    requested_writer_ref: "refs/xyz.heterodyne.marmot/writers/other",
  };
  const unauthorizedRefDecision = evaluateMarmotRoutingBinding(unauthorizedRefInput);
  const durabilityInput = {
    signed_event_bytes_preserved: true,
    encrypted_media_bytes_preserved: true,
    durable_local: true,
    configured_host_acceptances: 1,
    acknowledgement_requested: true,
  };
  const durabilityDecision = evaluateMarmotDurability(durabilityInput);
  const prematureAckInput = {
    ...durabilityInput,
    durable_local: false,
    configured_host_acceptances: 0,
  };
  const prematureAckDecision = evaluateMarmotDurability(prematureAckInput);
  const retentionInput = {
    retention_expired: true,
    independent_git_objects_possible: true,
  };
  const retentionDecision = evaluateMarmotRetention(retentionInput);

  const seedAdminSecret = "12".repeat(32);
  const seedAdministrator = bytesToHex(schnorr.getPublicKey(seedAdminSecret));
  const seedNid = "did:key:z6MkwQp8f8Y11L3WJYJ4hXa1";
  const seedWriterRef = "refs/xyz.heterodyne.marmot/relays/current-seed";
  const seedTransition = {
    generation: 7,
    marmot_routing_event_id: "45".repeat(32),
    routing_binding_sha256: "46".repeat(32),
  };
  const unsignedSeedAcl = {
    profile: "heterodyne.trusted-seed-acl.v1" as const,
    spec_version: QUALIFIED_VERSION,
    administrator_account: seedAdministrator,
    accounts: [{ account_key: agentPersona, roles: ["read", "write"] as const }],
    h: routingBindingInput.canonical_h,
    private_rid: routingBindingInput.canonical_rid,
    seed_grants: [{
      seed_nid: seedNid,
      relay_endpoint: "wss://seed.example/group",
      radicle_endpoint: routingBindingInput.canonical_rid,
      writer_ref: seedWriterRef,
      roles: ["read", "write"] as const,
      state: "active" as const,
    }],
    sequence: 0,
    predecessor: null,
    group_transition: seedTransition,
    issued_at: 1_799_999_900,
    expires_at: 1_800_001_000,
  };
  const seedAcl = {
    ...unsignedSeedAcl,
    accounts: unsignedSeedAcl.accounts.map(({ account_key, roles }) => ({
      account_key,
      roles: [...roles],
    })),
    seed_grants: unsignedSeedAcl.seed_grants.map((grant) => ({
      ...grant,
      roles: [...grant.roles],
    })),
    signature: bytesToHex(schnorr.sign(
      trustedSeedAclProofBytes(unsignedSeedAcl),
      seedAdminSecret,
      "00".repeat(32),
    )),
  };
  const seedMarmotEvent = await signEvent({
    secretKey: "17".repeat(32),
    created_at: 1_799_999_999,
    kind: 445,
    tags: [["h", routingBindingInput.canonical_h]],
    content: tier3Ciphertext,
    auxRand: "18".repeat(32),
  });
  const seedRaw = JSON.stringify(seedMarmotEvent);
  const seedAuthority = createTrustedSeedAdmissionAuthority({
    seed_nid: seedNid,
    administrator_account: seedAdministrator,
    trusted_now: () => ({ now: 1_800_000_000 }),
    authenticate_nip42: () => ({
      verdict: "accept",
      account_key: agentPersona,
      connection_id: "current-seed-connection",
      challenge_id: "current-seed-challenge",
      request_id: "current-seed-request",
      authenticated_at: 1_799_999_999,
      expires_at: 1_800_000_060,
    }),
    load_current_state: () => ({
      administrator_account: seedAdministrator,
      acl_candidates: [seedAcl],
      previous_acl: null,
      group_transition: seedTransition,
      revision: 1,
    }),
    consume_once: () => ({ verdict: "accept" }),
  });
  if (seedAuthority === null) throw new Error("current trusted-seed authority rejected");
  const seedRequest = {
    operation: "write" as const,
    h: routingBindingInput.canonical_h,
    private_rid: routingBindingInput.canonical_rid,
    writer_ref: seedWriterRef,
    nip01_raw: seedRaw,
  };
  const seedCapability = seedAuthority.mintRequestCapability({}, seedRequest);
  if (seedCapability === null) throw new Error("current trusted-seed request rejected");
  const seedDecision = evaluateTrustedSeedAdmission(seedAuthority.authority, seedCapability);
  const seedReplayDecision = evaluateTrustedSeedAdmission(seedAuthority.authority, seedCapability);
  const signSeedAcl = (patch: Record<string, unknown> = {}) => {
    const { signature: _signature, ...base } = seedAcl;
    const candidate = { ...structuredClone(base), ...structuredClone(patch) };
    return {
      ...candidate,
      signature: bytesToHex(schnorr.sign(
        trustedSeedAclProofBytes(candidate),
        seedAdminSecret,
        "00".repeat(32),
      )),
    } as typeof seedAcl;
  };
  const seedState = (
    candidates: typeof seedAcl[],
    previous: typeof seedAcl | null = null,
  ) => ({
    administrator_account: seedAdministrator,
    acl_candidates: candidates,
    previous_acl: previous,
    group_transition: seedTransition,
    revision: 2,
  });
  const evaluateSeedScenario = (options: {
    state: ReturnType<typeof seedState>;
    request?: typeof seedRequest;
    evaluation_now?: number;
  }) => {
    let clockCalls = 0;
    const bundle = createTrustedSeedAdmissionAuthority({
      seed_nid: seedNid,
      administrator_account: seedAdministrator,
      trusted_now: () => ({
        now: clockCalls++ === 0
          ? 1_800_000_000
          : (options.evaluation_now ?? 1_800_000_000),
      }),
      authenticate_nip42: () => ({
        verdict: "accept",
        account_key: agentPersona,
        connection_id: "scenario-connection",
        challenge_id: "scenario-challenge",
        request_id: "scenario-request",
        authenticated_at: 1_799_999_999,
        expires_at: 1_800_000_060,
      }),
      load_current_state: () => options.state,
      consume_once: () => ({ verdict: "accept" }),
    });
    if (bundle === null) throw new Error("trusted-seed scenario authority rejected");
    const capability = bundle.mintRequestCapability({}, options.request ?? seedRequest);
    if (capability === null) throw new Error("trusted-seed scenario capability rejected");
    return evaluateTrustedSeedAdmission(bundle.authority, capability);
  };
  const seedMissingDecision = evaluateSeedScenario({ state: seedState([]) });
  const seedInvalidDecision = evaluateSeedScenario({
    state: seedState([{ ...seedAcl, signature: "00".repeat(64) }]),
  });
  const seedExpiredDecision = evaluateSeedScenario({
    state: seedState([signSeedAcl({ expires_at: 1_800_000_000 })]),
  });
  const seedStaleDecision = evaluateSeedScenario({ state: seedState([seedAcl], seedAcl) });
  const seedConflictDecision = evaluateSeedScenario({
    state: seedState([seedAcl, signSeedAcl({ expires_at: seedAcl.expires_at + 1 })]),
  });
  const seedAmbiguousDecision = evaluateSeedScenario({
    state: seedState([signSeedAcl({ sequence: 1 })]),
  });
  const seedUnauthorizedDecision = evaluateSeedScenario({
    state: seedState([signSeedAcl({
      accounts: [{ account_key: "99".repeat(32), roles: ["read", "write"] }],
    })]),
  });
  const seedRevokedDecision = evaluateSeedScenario({
    state: seedState([signSeedAcl({
      seed_grants: seedAcl.seed_grants.map((grant) => ({ ...grant, state: "revoked" })),
    })]),
  });
  const seedNip42Decision = evaluateSeedScenario({
    state: seedState([seedAcl]),
    evaluation_now: 1_800_000_060,
  });
  const seedRouteDecision = evaluateSeedScenario({
    state: seedState([seedAcl]),
    request: { ...seedRequest, h: "other-routing-generation" },
  });
  const seedEventDecision = evaluateSeedScenario({
    state: seedState([seedAcl]),
    request: { ...seedRequest, nip01_raw: "{}" },
  });
  const seedRequestInvalidDecision = evaluateTrustedSeedAdmission(seedAuthority.authority, {});

  const reasonCases: CurrentVectorCase[] = [
    executedCommsRejection({
      id: "claim-id-mismatch", boundary: "claims.validateClaimId", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-AUTHENTICITY", reason: "claim-id-mismatch",
      description: "A claim identifier must equal the lowercase SHA-256 digest of its canonical semantic body.",
      input: { claim: invalidClaimId }, decision: invalidClaimIdDecision,
    }),
    executedCommsRejection({
      id: "claim-key-reference-invalid", boundary: "claims.validateKeyRef", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-AUTHENTICITY", reason: "claim-key-reference-invalid",
      description: "A claim key reference must be a registered type with its exact canonical encoding.",
      input: { key_reference: invalidClaimKey }, decision: invalidClaimKeyDecision,
    }),
    executedCommsRejection({
      id: "claim-event-signature-invalid", boundary: "claims.validateClaimEnvelope", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-AUTHENTICITY", reason: "claim-event-signature-invalid",
      description: "A substituted outer claim-event signature is rejected before claim semantics are trusted.",
      input: { event: invalidClaimEvent }, decision: invalidClaimEventDecision,
    }),
    executedCommsRejection({
      id: "claim-issuer-authority-invalid", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-AUTHENTICITY", reason: "claim-issuer-authority-invalid",
      description: "A claim without current claim-bound issuer authority evidence cannot authorize.",
      input: { claim_id: claim.claim_id, authority_evidence: [] }, decision: missingAuthorityDecision,
    }),
    executedCommsRejection({
      id: "claim-attenuation-violation", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-ATTENUATION", reason: "claim-attenuation-violation",
      description: "A requested namespace outside the exact claim scope is rejected as widening.",
      input: { claim_id: claim.claim_id, requested_namespace: attenuationContext.requested_namespace }, decision: attenuationDecision,
    }),
    executedCommsRejection({
      id: "claim-expired", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-AUTHENTICITY", reason: "claim-expired",
      description: "A claim expires at its exact exclusive expiry boundary.",
      input: { claim_id: claim.claim_id, now: expiredContext.now }, decision: expiredClaimDecision,
    }),
    executedCommsRejection({
      id: "claim-repository-conflict", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-REPOSITORY-AUTHORITY", reason: "claim-repository-conflict",
      description: "Concurrent non-monotonic canonical claim state grants no authority.",
      input: { claim_id: claim.claim_id, repository_conflicted_claim_ids: [claim.claim_id] }, decision: repositoryConflictDecision,
    }),
    executedCommsRejection({
      id: "claim-subject-proof-required", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-AUTHENTICITY", reason: "claim-subject-proof-required",
      description: "Authorization use without the subject's fresh proof of possession fails closed.",
      input: { claim_id: claim.claim_id, subject_proof: null }, decision: subjectRequiredDecision,
    }),
    executedCommsRejection({
      id: "claim-subject-proof-invalid", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-AUTHENTICITY", reason: "claim-subject-proof-invalid",
      description: "A subject proof over a different nonce does not prove this authorization use.",
      input: { claim_id: claim.claim_id, nonce: subjectInvalidContext.subject_proof.challenge.nonce }, decision: subjectInvalidDecision,
    }),
    executedCommsRejection({
      id: "claim-issuer-untrusted", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-AUTHENTICITY", reason: "claim-issuer-untrusted",
      description: "A cryptographically valid claim outside local issuer trust policy remains untrusted.",
      input: { claim_id: claim.claim_id, trusted_issuers: [] }, decision: untrustedClaimDecision,
    }),
    executedCommsRejection({
      id: "claim-revoked", boundary: "claims.validateClaimRevocationEnvelope+authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-REVOCATION", reason: "claim-revoked",
      description: "An authenticated direct-issuer revocation irreversibly removes claim authority.",
      input: { claim_id: claim.claim_id, revocation_event: revocationArtifact.event }, decision: revokedClaimDecision,
    }),
    executedCommsRejection({
      id: "claim-chain-cycle", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-ATTENUATION", reason: "claim-chain-cycle",
      description: "A repeated claim identifier in one issuance chain is rejected as a cycle.",
      input: { chain_claim_ids: [claim.claim_id, claim.claim_id] }, decision: chainCycleDecision,
    }),
    executedCommsRejection({
      id: "claim-chain-depth-exceeded", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-ATTENUATION", reason: "claim-chain-depth-exceeded",
      description: "An issuance chain longer than eight edges is rejected before authority use.",
      input: { chain_claim_ids: Array.from({ length: 10 }, () => claim.claim_id) }, decision: chainDepthDecision,
    }),
    executedCommsRejection({
      id: "claim-delegation-not-authorized", boundary: "claims.authorizeWithClaim", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-ATTENUATION", reason: "claim-delegation-not-authorized",
      description: "A supplied chain that does not terminate at the requested leaf cannot delegate authority.",
      input: { leaf_claim_id: ledger.claimTwo.artifact.semantic.claim_id, chain_claim_ids: [claim.claim_id] }, decision: delegationDecision,
    }),
    executedCommsRejection({
      id: "claim-ledger-rollback", boundary: "claim-ledger.mergeClaimLedger", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-REPOSITORY-AUTHORITY", reason: "claim-ledger-rollback",
      description: "A checkpoint outside canonical main cannot replace finalized claim-ledger history.",
      input: { checkpoint: rollbackCheckpoint }, decision: rollbackDecision,
    }),
    executedCommsRejection({
      id: "claim-revoker-unauthorized", boundary: "claim-ledger.validateLedgerRecordOrThrow", anchor: "comms-conformance",
      invariant: "COMMS-I-CLAIM-REVOCATION", reason: "claim-revoker-unauthorized",
      description: "A revocation ledger record without claim-bound revoker authority evidence cannot reduce authority.",
      input: { record_id: ledger.removalRecord.record_id, evidence: unauthorizedRevocationEvidence }, decision: unauthorizedRevocationDecision,
    }),
    ...[
      ["oidc-client-unregistered", "oidc-client-unregistered", "oidc.validateAuthorizationRequest", "comms-authorization-clients-consent-and-release", "COMMS-I-CLAIM-RELEASE", { client_id: "unregistered-client" }, unregisteredClientDecision],
      ["oidc-grant-prohibited", "oidc-grant-prohibited", "oidc.validateAuthorizationRequest", "comms-authorization-clients-consent-and-release", "COMMS-I-CLAIM-RELEASE", { grant_type: "client_credentials" }, prohibitedGrantDecision],
      ["oidc-consent-required", "oidc-consent-required", "oidc.validateAuthorizationRequest", "comms-authorization-clients-consent-and-release", "COMMS-I-CLAIM-RELEASE", { requested_scopes: ["profile"] }, consentRequiredDecision],
      ["oidc-claim-release-denied", "oidc-claim-release-denied", "oidc.validateAuthorizationRequest", "comms-authorization-clients-consent-and-release", "COMMS-I-CLAIM-RELEASE", { nonce: "" }, releaseDeniedDecision],
      ["oidc-issuer-mismatch", "oidc-issuer-mismatch", "oidc.validateIssuerMetadata", "comms-radicle-issuer-continuity", "COMMS-I-ISSUER-CONTINUITY", { expected_issuer: "https://other.example/oidc/npub1other" }, issuerMismatchDecision],
      ["oidc-token-type-invalid", "oidc-token-type-invalid", "oidc.validateProjectedJwt", "comms-interoperable-jwt-projection", "COMMS-I-JWT-TYPE-AUDIENCE", { compact: accessToken.compact, expected_token_use: "id_token" }, tokenTypeDecision],
      ["oidc-audience-invalid", "oidc-audience-invalid", "oidc.validateProjectedJwt", "comms-interoperable-jwt-projection", "COMMS-I-JWT-TYPE-AUDIENCE", { compact: accessToken.compact, permitted_audiences: ["https://api.example", "https://extra.example"] }, audienceInvalidDecision],
      ["oidc-issuer-authority-invalid", "oidc-issuer-authority-invalid", "claim-ledger.canMint", "comms-conformance", "COMMS-I-ISSUER-KEY-CONFINEMENT", { issuer_authority_state: "revoked" }, issuerAuthorityDecision],
      ["oidc-signing-key-unavailable", "oidc-signing-key-unavailable", "claim-ledger.canMint", "comms-conformance", "COMMS-I-ISSUER-KEY-CONFINEMENT", { issuer_authority_state: "active", signing_key_available: false }, signingKeyDecision],
      ["oidc-status-invalid", "oidc-status-invalid", "token-status.encodeStatusList", "comms-conformance", "COMMS-I-STATUS-INTEGRITY", { statuses: [] }, statusInvalidDecision],
    ].map(([id, reason, boundary, anchor, invariant, input, decision]) =>
      executedCommsRejection({
        id: String(id), reason: String(reason), boundary: String(boundary), anchor: String(anchor), invariant: String(invariant),
        description: `The live OIDC boundary rejects ${String(id).replaceAll("-", " ")}.`,
        input: input as Record<string, unknown>, decision: decision as Record<string, unknown>,
      })
    ),
    ...[
      ["agent-workload-registration-invalid", "agent-workload-registration-invalid", "agent-authorship.validateWorkloadRegistration", invalidRegistrationInput, invalidRegistrationDecision],
      ["agent-token-invalid", "agent-token-invalid", "agent-authorship.validateAgentAccessToken", invalidAgentTokenInput, invalidAgentTokenDecision],
      ["agent-sender-proof-invalid", "agent-sender-proof-invalid", "agent-authorship.validateAgentAccessToken", invalidSenderProofInput, invalidSenderProofDecision],
      ["agent-signer-mismatch", "agent-signer-mismatch", "agent-authorship.validateAgentAccessToken", signerMismatchInput, signerMismatchDecision],
      ["agent-persona-scope-required", "agent-persona-scope-required", "agent-authorship.injectAgentAttribution", personaScopeInput, personaScopeDecision],
      ["agent-attribution-invalid", "agent-attribution-invalid", "agent-authorship.injectAgentAttribution", invalidAttributionInput, invalidAttributionDecision],
      ["agent-attribution-profile-unavailable", "agent-attribution-profile-unavailable", "agent-authorship.injectAgentAttribution", unavailableAttributionInput, unavailableAttributionDecision],
    ].map(([id, reason, boundary, input, decision]) => executedCommsRejection({
      id: String(id), reason: String(reason), boundary: String(boundary), anchor: "comms-agent-authorship",
      invariant: String(reason).includes("attribution") || String(reason).includes("persona")
        ? "COMMS-I-AGENT-ATTRIBUTION"
        : "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT",
      description: `The current workload boundary rejects ${String(id).replaceAll("-", " ")}.`,
      input: input as Record<string, unknown>, decision: decision as Record<string, unknown>,
    })),
    ...[
      ["nip59-broadcast-rejected", "nip59_broadcast_rejected", "comms-policy.validatePrivateBroadcast", privateBroadcastInput, validatePrivateBroadcast(privateBroadcastInput), "comms-encrypted-audience-posts"],
      ["auth-rejected-permanent", "auth_rejected_permanent", "comms-policy.classifyRelayWriteFailure", relayAuthInput, classifyRelayWriteFailure(relayAuthInput), "comms-publishing"],
      ["dm-invite-unbound-device", "dm_invite_unbound_device", "comms-policy.validateDmInviteDevice", unboundDmInput, validateDmInviteDevice(unboundDmInput), "comms-direct-messages"],
      ["dm-invite-revoked-device", "dm_invite_revoked_device", "comms-policy.validateDmInviteDevice", revokedDmInput, validateDmInviteDevice(revokedDmInput), "comms-direct-messages"],
      ["invite-expired", "invite-expired", "comms-policy.evaluateOneTimeInvite", inviteExpiredInput, evaluateOneTimeInvite(inviteExpiredInput), "comms-one-time-invites"],
      ["invite-purpose-mismatch", "invite-purpose-mismatch", "comms-policy.evaluateOneTimeInvite", invitePurposeInput, evaluateOneTimeInvite(invitePurposeInput), "comms-one-time-invites"],
      ["invite-authentication-invalid", "invite-authentication-invalid", "comms-policy.evaluateOneTimeInvite", inviteAuthInput, evaluateOneTimeInvite(inviteAuthInput), "comms-one-time-invites"],
      ["invite-already-reserved", "invite-already-reserved", "comms-policy.evaluateOneTimeInvite", inviteReservedInput, evaluateOneTimeInvite(inviteReservedInput), "comms-one-time-invites"],
      ["public-reader-private-content", "public-reader-private-content", "comms-policy.validatePublicReaderRendering", privateReaderInput, validatePublicReaderRendering(privateReaderInput), "comms-public-reader-feature"],
      ["marmot-private-route-required", "marmot-private-route-required", "comms-policy.evaluatePrivateMarmotRoute", privateRouteInput, evaluatePrivateMarmotRoute(privateRouteInput), "comms-marmot-groups"],
      ["marmot-private-inbox-nid-required", "marmot-private-inbox-nid-required", "comms-policy.evaluateMarmotInboxBootstrap", inboxNidInput, evaluateMarmotInboxBootstrap(inboxNidInput), "comms-marmot-persona-inbox"],
      ["marmot-keypackage-replayed", "marmot-keypackage-replayed", "comms-policy.evaluateMarmotInboxBootstrap", inboxReplayInput, evaluateMarmotInboxBootstrap(inboxReplayInput), "comms-marmot-persona-inbox"],
      ["marmot-agent-scope-denied", "marmot-agent-scope-denied", "comms-policy.evaluateMarmotInboxBootstrap", marmotScopeInput, evaluateMarmotInboxBootstrap(marmotScopeInput), "comms-agent-authorship"],
      ["conversation-rejected", "conversation-rejected", "marmot-admission.ordinaryConversationAdmission", rejectedConversationInput, rejectedConversationDecision, "comms-ordinary-conversation-admission"],
      ["marmot-routing-equivocation", "marmot-routing-equivocation", "marmot-routing-policy.evaluateMarmotRoutingBinding", routingEquivocationInput, routingEquivocationDecision, "comms-marmot-host-authority"],
      ["marmot-unauthorized-ref", "marmot-unauthorized-ref", "marmot-routing-policy.evaluateMarmotRoutingBinding", unauthorizedRefInput, unauthorizedRefDecision, "comms-marmot-event-repository"],
    ].map(([id, reason, boundary, input, decision, anchor]) => executedCommsRejection({
      id: String(id), reason: String(reason), boundary: String(boundary), anchor: String(anchor),
      invariant: String(id).startsWith("marmot-routing") || String(id).startsWith("marmot-unauthorized")
        ? "COMMS-I-RADICLE-ROUTING-AUTHORITY"
        : String(id).startsWith("public-reader")
          ? "COMMS-I-PUBLIC-READER-TIER1-ONLY"
          : "COMMS-I-MARMOT-UPSTREAM-AUTHORITY",
      description: `The current Comms policy boundary rejects ${String(id).replaceAll("-", " ")}.`,
      input: input as Record<string, unknown>, decision: decision as Record<string, unknown>,
    })),
    ...[
      ["trusted-seed-acl-missing", "trusted-seed-acl-missing", { acl_candidates: [] }, seedMissingDecision],
      ["trusted-seed-acl-invalid", "trusted-seed-acl-invalid", { acl_candidates: [{ ...seedAcl, signature: "00".repeat(64) }] }, seedInvalidDecision],
      ["trusted-seed-acl-expired", "trusted-seed-acl-expired", { expires_at: 1_800_000_000 }, seedExpiredDecision],
      ["trusted-seed-acl-stale", "trusted-seed-acl-stale", { sequence: seedAcl.sequence, previous_sequence: seedAcl.sequence }, seedStaleDecision],
      ["trusted-seed-acl-conflict", "trusted-seed-acl-conflict", { greatest_sequence_candidates: 2 }, seedConflictDecision],
      ["trusted-seed-acl-ambiguous", "trusted-seed-acl-ambiguous", { sequence: 1, predecessor: null }, seedAmbiguousDecision],
      ["trusted-seed-unauthorized", "trusted-seed-unauthorized", { authenticated_account: agentPersona, authorized_accounts: ["99".repeat(32)] }, seedUnauthorizedDecision],
      ["trusted-seed-revoked", "trusted-seed-revoked", { seed_nid: seedNid, state: "revoked" }, seedRevokedDecision],
      ["trusted-seed-nip42-required", "trusted-seed-nip42-required", { authenticated_at: 1_799_999_999, expires_at: 1_800_000_060, now: 1_800_000_060 }, seedNip42Decision],
      ["trusted-seed-route-mismatch", "trusted-seed-route-mismatch", { request_h: "other-routing-generation", acl_h: seedAcl.h }, seedRouteDecision],
      ["trusted-seed-event-invalid", "trusted-seed-event-invalid", { nip01_raw: "{}" }, seedEventDecision],
      ["trusted-seed-request-invalid", "trusted-seed-request-invalid", { capability: {} }, seedRequestInvalidDecision],
      ["trusted-seed-request-replay", "trusted-seed-request-replay", { capability_used: true }, seedReplayDecision],
    ].map(([id, reason, input, decision]) => executedCommsRejection({
      id: String(id), reason: String(reason),
      boundary: "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
      anchor: "comms-trusted-seed-private-relay",
      invariant: "COMMS-I-TRUSTED-SEED-CONFINEMENT",
      description: `The trusted-seed authority rejects ${String(id).replaceAll("-", " ")} from authenticated current state.`,
      input: input as Record<string, unknown>, decision: decision as Record<string, unknown>,
    })),
  ];

  return [
    ...reasonCases,
    {
      relativePath: "comms/checkpoint-exact-boundary.json",
      semantic_boundary: "authorization-freshness.evaluateAuthorizationFreshness",
      vector_id: "comms/checkpoint-exact-boundary",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: [],
      description: "A signed ledger checkpoint exactly 300 seconds old remains eligible independently of authorization-view age.",
      direction: "consume",
      input: { trusted_now: observedAt + 300, manifest: checkpointBoundary, ledger_state: state },
      expected_output: decisionOutput(checkpointBoundaryDecision),
    },
    {
      relativePath: "comms/checkpoint-stale-independent.json",
      semantic_boundary: "authorization-freshness.evaluateAuthorizationFreshness",
      vector_id: "comms/checkpoint-stale-independent",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: ["oidc-checkpoint-stale"],
      description: "Checkpoint age above 300 seconds rejects even while the authorization view itself is fresh.",
      direction: "consume",
      input: { trusted_now: observedAt + 301, manifest: checkpointStale, ledger_state: state },
      expected_output: decisionOutput(checkpointStaleDecision),
    },
    {
      relativePath: "comms/authorization-view-300-boundary.json",
      semantic_boundary: "authorization-freshness.evaluateAuthorizationFreshness",
      vector_id: "comms/authorization-view-300-boundary",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: [],
      description: "A 300-second authorization view is accepted at its exact declared boundary.",
      direction: "consume",
      input: { trusted_now: observedAt + 300, manifest: view300, ledger_state: state },
      expected_output: decisionOutput(view300Decision),
    },
    {
      relativePath: "comms/authorization-view-86400-boundary.json",
      semantic_boundary: "authorization-freshness.evaluateAuthorizationFreshness",
      vector_id: "comms/authorization-view-86400-boundary",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: [],
      description: "The maximum 86400-second authorization-view bound is accepted exactly at its boundary.",
      direction: "consume",
      input: { trusted_now: observedAt + 86_400, manifest: view86400, ledger_state: state },
      expected_output: decisionOutput(view86400Decision),
    },
    {
      relativePath: "comms/authorization-view-maximum-malformed.json",
      semantic_boundary: "schema.validateOidcContinuityManifestSchemaOrThrow",
      vector_id: "comms/authorization-view-maximum-malformed",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: ["claim-schema-invalid"],
      description: "An authorization-view maximum above 86400 seconds fails the registered manifest schema.",
      direction: "consume",
      input: { manifest: malformed },
      expected_output: malformedRejected
        ? { verdict: "reject", reason_code: "claim-schema-invalid" }
        : { verdict: "accept" },
    },
    {
      relativePath: "comms/tier3-recipient-confined.json",
      semantic_boundary: "follow-up-hardening.resolveTier3Recipients",
      vector_id: "comms/tier3-recipient-confined",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-tier3-confinement")],
      invariants: ["COMMS-I-TIER3-CONFINED"],
      reason_codes: ["tier3-recipient-not-active-device"],
      description: "Tier-3 delivery rejects a selected inactive device even when its persona remains a member.",
      direction: "produce",
      input: tier3Input,
      expected_output: tier3Decision,
    },
    {
      relativePath: "comms/config-private-state-encrypted.json",
      semantic_boundary: "privacy-crypto.deriveConfigPostKey+nostr-tools.nip44",
      vector_id: "comms/config-private-state-encrypted",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-config-repository-protection-profile")],
      invariants: ["COMMS-I-CONFIG-AT-REST", "COMMS-I-TIER2-HONESTY"],
      reason_codes: [],
      description: "A Comms configuration post is encrypted under the derived repository key and round-trips only at the client boundary.",
      direction: "round-trip",
      input: {
        config_audience_key: "42".repeat(32),
        key_id: "current-config-key",
        plaintext: configPlaintext,
      },
      expected_output: {
        verdict: configRecovered === configPlaintext ? "accept" : "mismatch",
        derived_key: bytesToHex(configKey),
        ciphertext: configCiphertext,
        recovered_plaintext: configRecovered,
      },
    },
    {
      relativePath: "comms/tier3-client-side-encryption.json",
      semantic_boundary: "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44",
      vector_id: "comms/tier3-client-side-encryption",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-audience-encryption-profile-tiers-2-and-3")],
      invariants: [
        "COMMS-I-CLIENT-SIDE-DELIVERY",
        "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
        "COMMS-I-TIER3-BLIND-CARRIER",
      ],
      reason_codes: [],
      description: "A Tier-3 audience object is encrypted and recovered locally from an audience-derived key without a delivery-directory lookup.",
      direction: "round-trip",
      input: {
        audience_key: "40".repeat(32),
        key_id: "current-tier3-key",
        plaintext: tier3Plaintext,
      },
      expected_output: {
        verdict: tier3Recovered === tier3Plaintext ? "accept" : "mismatch",
        derived_key: bytesToHex(tier3Key),
        ciphertext: tier3Ciphertext,
        recovered_plaintext: tier3Recovered,
      },
    },
    {
      relativePath: "comms/claim-active-authenticated.json",
      semantic_boundary: "claims.authorizeWithClaim",
      vector_id: "comms/claim-active-authenticated",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-verification-trust-proof-of-possession-and-state")],
      invariants: ["COMMS-I-CLAIM-ATTENUATION", "COMMS-I-CLAIM-AUTHENTICITY"],
      reason_codes: [],
      description: "An exact signed, authority-bound, attenuated claim with fresh subject proof authorizes its requested repository operation.",
      direction: "consume",
      input: {
        claim: ledger.claimOne.artifact,
        requested_namespace: claimContext.requested_namespace,
        requested_operation: claimContext.requested_operation,
      },
      expected_output: { verdict: activeClaimDecision.allowed ? "accept" : "reject", authorization: activeClaimDecision },
    },
    {
      relativePath: "comms/claim-repository-unconfirmed.json",
      semantic_boundary: "claims.authorizeWithClaim",
      vector_id: "comms/claim-repository-unconfirmed",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authoritative-private-persona-claim-ledger")],
      invariants: ["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],
      reason_codes: ["claim-repository-unconfirmed"],
      description: "A valid persona authorization remains provisional until canonical private claim-repository state confirms it.",
      direction: "consume",
      input: { claim: ledger.claimOne.artifact, repository_confirmed_claim_ids: [] },
      expected_output: {
        verdict: unconfirmedClaimDecision.allowed ? "accept" : "reject",
        reason_code: unconfirmedClaimDecision.reason_code,
        state: unconfirmedClaimDecision.state,
      },
    },
    {
      relativePath: "comms/ledger-reader-authorized.json",
      semantic_boundary: "claim-ledger.mergeClaimLedger+evaluateReaderAccess",
      vector_id: "comms/ledger-reader-authorized",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authoritative-private-persona-claim-ledger")],
      invariants: ["COMMS-I-CLAIM-REVOCATION", "COMMS-I-LEDGER-CONFINEMENT"],
      reason_codes: [],
      description: "Canonical merge state exposes the private ledger only to the exact active durable NID-bearing reader.",
      direction: "consume",
      input: {
        reader_nid: ledger.writerOne.did_key,
        checkpoint: ledger.baseRepository.checkpoint,
        record_ids: baseLedgerState.records.map(({ record_id }) => record_id),
      },
      expected_output: { verdict: authorizedReader.allowed ? "accept" : "reject", authorization: authorizedReader },
    },
    {
      relativePath: "comms/ledger-reader-unauthorized.json",
      semantic_boundary: "claim-ledger.evaluateReaderAccess",
      vector_id: "comms/ledger-reader-unauthorized",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authoritative-private-persona-claim-ledger")],
      invariants: ["COMMS-I-LEDGER-CONFINEMENT"],
      reason_codes: ["claim-ledger-reader-unauthorized"],
      description: "A reader presenting another device's claim record cannot cross the private ledger boundary.",
      direction: "consume",
      input: { reader_nid: ledger.writerTwo.did_key, claim_record_id: ledger.claimRecordOne.record_id },
      expected_output: {
        verdict: unauthorizedReader.allowed ? "accept" : "reject",
        reason_code: unauthorizedReader.reason_code,
        state: unauthorizedReader.state,
      },
    },
    {
      relativePath: "comms/oidc-claim-release.json",
      semantic_boundary: "oidc.validateAuthorizationRequest",
      vector_id: "comms/oidc-claim-release",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-clients-consent-and-release")],
      invariants: ["COMMS-I-CLAIM-RELEASE", "COMMS-I-ISSUER-KEY-CONFINEMENT"],
      reason_codes: [],
      description: "The live OIDC release boundary intersects registered client, consent, scope, audience, and canonical source-claim state.",
      direction: "produce",
      input: {
        client_id: oidc.request.client_id,
        requested_scopes: oidc.request.requested_scopes,
        requested_audiences: oidc.request.requested_audiences,
        requested_claims: oidc.request.requested_claims,
        checkpoint: oidc.preMintState.checkpoint,
      },
      expected_output: {
        verdict: oidcRelease.allowed ? "accept" : "reject",
        released_claims: oidcRelease.released_claims,
        source_claim_ids: oidcRelease.source_claim_ids,
      },
    },
    {
      relativePath: "comms/oidc-access-token-validated.json",
      semantic_boundary: "oidc.projectAccessToken+validateProjectedJwt",
      vector_id: "comms/oidc-access-token-validated",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-interoperable-jwt-projection")],
      invariants: ["COMMS-I-JWT-TYPE-AUDIENCE", "COMMS-I-STATUS-INTEGRITY"],
      reason_codes: [],
      description: "A projected access token verifies its RS256 signature, at+jwt type, exact resource audience, ledger generation, and bound status locator.",
      direction: "round-trip",
      input: {
        compact: accessToken.compact,
        expected_issuer: oidc.metadata.issuer,
        expected_audience: "https://api.example",
      },
      expected_output: { verdict: accessValidation.allowed ? "accept" : "reject", authorization: accessValidation },
    },
    {
      relativePath: "comms/oidc-issuer-persona-continuity.json",
      semantic_boundary: "oidc.validateIssuerMetadata",
      vector_id: "comms/oidc-issuer-persona-continuity",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-radicle-issuer-continuity")],
      invariants: ["COMMS-I-ISSUER-CONTINUITY"],
      reason_codes: [],
      description: "Issuer metadata resolves to the exact active persona scoped HTTPS issuer before continuity state is consumed.",
      direction: "consume",
      input: { metadata: oidc.metadata, persona_npub: oidc.personaNpub },
      expected_output: {
        verdict: issuerMetadataDecision.allowed ? "accept" : "reject",
        authorization: issuerMetadataDecision,
      },
    },
    {
      relativePath: "comms/public-reader-private-tier.json",
      semantic_boundary: "public-reader.resolvePublicAsset",
      vector_id: "comms/public-reader-private-tier",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-public-reader-feature")],
      invariants: ["COMMS-I-PUBLIC-READER-TIER1-ONLY"],
      reason_codes: [],
      description: "The public resolver classifies otherwise available Tier-2 material as private instead of rendering it.",
      direction: "consume",
      input: { tier: 2, available: true, signature_valid: true },
      expected_output: { verdict: "accept", resolution: publicPrivateDecision },
    },
    {
      relativePath: "comms/public-reader-route-invalid.json",
      semantic_boundary: "public-reader.parseLauncherFragment",
      vector_id: "comms/public-reader-route-invalid",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-universal-public-launcher")],
      invariants: ["COMMS-I-PUBLIC-READER-TIER1-ONLY"],
      reason_codes: ["public-reader-route-invalid"],
      description: "An unknown launcher fragment is rejected before any network activity.",
      direction: "consume",
      input: { fragment: "#/v1/unknown" },
      expected_output: invalidLauncher,
    },
    {
      relativePath: "comms/public-reader-relay-hint-invalid.json",
      semantic_boundary: "public-reader.validateBootstrapRelay",
      vector_id: "comms/public-reader-relay-hint-invalid",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-launcher-and-content-security")],
      invariants: ["COMMS-I-PUBLIC-READER-TIER1-ONLY"],
      reason_codes: ["public-reader-relay-hint-invalid"],
      description: "A cleartext loopback relay hint is rejected by the normalized bootstrap boundary.",
      direction: "consume",
      input: { relay_hint: "ws://127.0.0.1/private" },
      expected_output: invalidRelay,
    },
    {
      relativePath: "comms/agent-workload-token-accepted.json",
      semantic_boundary: "agent-authorship.validateWorkloadRegistration+validateAgentAccessToken",
      vector_id: "comms/agent-workload-token-accepted",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-fail-closed-authorization-and-privacy")],
      invariants: ["COMMS-I-AGENT-SIGNER-BINDING", "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],
      reason_codes: [],
      description: "A closed finite workload registration and exact sender-constrained token resolve one registered automated signer without exposing private claims.",
      direction: "consume",
      input: {
        registration: validatedRegistration,
        token: tokenInput,
      },
      expected_output: { verdict: tokenDecision.verdict, identity: tokenDecision.verdict === "accept" ? tokenDecision.identity : null },
    },
    {
      relativePath: "comms/agent-attribution-encrypted-inner.json",
      semantic_boundary: "agent-authorship.injectAgentAttribution",
      vector_id: "comms/agent-attribution-encrypted-inner",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-mandatory-pre-sign-attribution")],
      invariants: ["COMMS-I-AGENT-ATTRIBUTION", "COMMS-I-AGENT-SIGNER-BINDING"],
      reason_codes: [],
      description: "Tier-3 automation attribution is canonicalized before signing and remains only inside the encrypted logical event.",
      direction: "produce",
      input: attributionInput,
      expected_output: attributionDecision,
    },
    {
      relativePath: "comms/marmot-ordinary-welcome-held.json",
      semantic_boundary: "marmot-admission.ordinaryConversationAdmission",
      vector_id: "comms/marmot-ordinary-welcome-held",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-ordinary-conversation-hook")],
      invariants: [
        "COMMS-I-MARMOT-ACCOUNT-IDENTITY",
        "COMMS-I-MARMOT-SECRET-CONFINEMENT",
        "COMMS-I-MARMOT-UPSTREAM-AUTHORITY",
      ],
      reason_codes: [],
      description: "A cryptographically valid upstream Marmot Welcome from an unrecognized account is held for local policy without any sender-observable signal or secret disclosure.",
      direction: "consume",
      input: ordinaryMarmotInput,
      expected_output: { verdict: "accept", admission: ordinaryMarmotDecision },
    },
    {
      relativePath: "comms/marmot-routing-binding-valid.json",
      semantic_boundary: "marmot-routing-policy.evaluateMarmotRoutingBinding",
      vector_id: "comms/marmot-routing-binding-valid",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-routing-generations-and-bindings")],
      invariants: ["COMMS-I-RADICLE-ROUTING-AUTHORITY"],
      reason_codes: [],
      description: "One canonical active-account administrator commit binds the same routing generation, private RID, repository genesis, and authorized writer ref.",
      direction: "consume",
      input: routingBindingInput,
      expected_output: routingBindingDecision,
    },
    {
      relativePath: "comms/marmot-routing-genesis-mismatch.json",
      semantic_boundary: "marmot-routing-policy.evaluateMarmotRoutingBinding",
      vector_id: "comms/marmot-routing-genesis-mismatch",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-routing-generations-and-bindings")],
      invariants: ["COMMS-I-RADICLE-ROUTING-AUTHORITY"],
      reason_codes: ["marmot-routing-binding-invalid"],
      description: "A routing binding whose repository genesis digest differs from canonical Marmot routing state fails closed.",
      direction: "consume",
      input: routingMismatchInput,
      expected_output: routingMismatchDecision,
    },
    {
      relativePath: "comms/marmot-exact-bytes-durable.json",
      semantic_boundary: "marmot-routing-policy.evaluateMarmotDurability",
      vector_id: "comms/marmot-exact-bytes-durable",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-exact-event-and-media-bytes")],
      invariants: ["COMMS-I-MARMOT-EXACT-BYTES"],
      reason_codes: [],
      description: "A publisher acknowledges only after exact signed-event and encrypted-media bytes are durable locally and on a configured host.",
      direction: "round-trip",
      input: durabilityInput,
      expected_output: durabilityDecision,
    },
    {
      relativePath: "comms/marmot-premature-ack.json",
      semantic_boundary: "marmot-routing-policy.evaluateMarmotDurability",
      vector_id: "comms/marmot-premature-ack",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-rotation-transaction-and-durable-acknowledgement")],
      invariants: ["COMMS-I-MARMOT-EXACT-BYTES"],
      reason_codes: ["marmot-premature-ack"],
      description: "A requested publisher acknowledgement is rejected until its exact bytes cross the configured durability boundary.",
      direction: "produce",
      input: prematureAckInput,
      expected_output: prematureAckDecision,
    },
    {
      relativePath: "comms/marmot-expiration-not-erasure.json",
      semantic_boundary: "marmot-routing-policy.evaluateMarmotRetention",
      vector_id: "comms/marmot-expiration-not-erasure",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-retention-and-non-erasure")],
      invariants: ["COMMS-I-RADICLE-NON-ERASURE"],
      reason_codes: [],
      description: "Retention expiry stops conforming advertisement and replication without claiming deletion of independently retained Git objects.",
      direction: "consume",
      input: retentionInput,
      expected_output: retentionDecision,
    },
    {
      relativePath: "comms/trusted-seed-exact-write.json",
      semantic_boundary: "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
      vector_id: "comms/trusted-seed-exact-write",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-trusted-seed-private-relay")],
      invariants: [
        "COMMS-I-MARMOT-EXACT-BYTES",
        "COMMS-I-PRIVATE-RELAY-ACL",
        "COMMS-I-TRUSTED-SEED-CONFINEMENT",
      ],
      reason_codes: [],
      description: "A one-use NIP-42-authenticated capability admits one exact signed Marmot event under the unique current administrator ACL and configured seed writer ref.",
      direction: "consume",
      input: {
        request: seedRequest,
        acl: seedAcl,
        transition: seedTransition,
      },
      expected_output: seedDecision,
    },
  ];
}
