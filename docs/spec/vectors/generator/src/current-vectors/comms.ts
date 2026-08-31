import { nip44 } from "nostr-tools";
import { schnorr } from "@noble/curves/secp256k1";
import { injectAgentAttribution, validateAgentAccessToken, validateWorkloadRegistration, type AgentTokenValidationInput, } from "../agent-authorship.js";
import { buildAuthorizationFreshnessTestSupport } from "../authorization-freshness-test-support.js";
import { evaluateAuthorizationFreshness } from "../authorization-freshness.js";
import { createClaimAuthorizationAuthority, type ClaimAuthorizationEffectInput, type ClaimEffectRecord, type ClaimEffectStore, type CurrentClaimAuthorizationView, } from "../claim-authorization.js";
import { canMint, evaluateReaderAccess, ledgerErrorReason, mergeClaimLedger, validateLedgerRecordOrThrow, } from "../claim-ledger.js";
import { buildClaimLedgerScenario } from "../claim-ledger-test-support.js";
import { inspectVerifiedClaim, inspectVerifiedClaimRevocation, validateClaimId, validateKeyRef, verifyClaimEnvelope, verifyClaimRevocationEnvelope, type ClaimVerificationContext, type VerifiedClaimArtifact, } from "../claims.js";
import { classifyRelayWriteFailure, evaluateMarmotInboxBootstrap, evaluateOneTimeInvite, validateDmInviteDevice, validatePrivateBroadcast, validatePublicReaderRendering, } from "../comms-policy.js";
import { QUALIFIED_VERSION } from "../family.js";
import { buildFixtures } from "../fixtures.js";
import { resolveTier3Recipients } from "../follow-up-hardening.js";
import { bytesToHex, hexToBytes } from "../hex.js";
import { ordinaryConversationAdmission } from "../marmot-admission.js";
import { evaluateMarmotDurability, evaluateMarmotRetention, evaluateMarmotRoutingBinding, } from "../marmot-routing-policy.js";
import { signEvent } from "../nostr.js";
import { buildLiveOidcScenario } from "../oidc-test-support.js";
import { projectAccessToken, validateAuthorizationRequest, validateIssuerMetadata, validateProjectedJwt, } from "../oidc.js";
import { OIDC_RSA_ONE } from "../oidc-rsa-fixtures.js";
import { deriveConfigPostKey, deriveTier3IndexKey } from "../privacy-crypto.js";
import { parseLauncherFragment, resolvePublicAsset, validateBootstrapRelay, } from "../public-reader.js";
import { validateOidcContinuityManifestSchemaOrThrow } from "../schema.js";
import { createTrustedSeedAdmissionAuthority, evaluateTrustedSeedAdmission, trustedSeedAclProofBytes, } from "../trusted-seed.js";
import { encodeStatusList } from "../token-status.js";
import { currentSpecRef, type CurrentCaseFixture } from "./types.js";
const decisionOutput = (decision: ReturnType<typeof evaluateAuthorizationFreshness>): Record<string, unknown> => decision.verdict === "accept"
    ? { verdict: "accept", current_authorization_view: "opaque" }
    : { verdict: "reject", reason_code: decision.reason };
const thrownDecision = (evaluate: () => unknown): Record<string, unknown> => {
    try {
        evaluate();
        return { verdict: "accept" };
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const reason = message.match(/^([a-z][a-z0-9_-]*)(?::|$)/)?.[1];
        if (reason === undefined)
            throw error;
        return { verdict: "reject", reason_code: reason };
    }
};
const currentClaimStore = (): ClaimEffectStore => {
    const records = new Map<string, ClaimEffectRecord>();
    return {
        load(singleUseKey) {
            const record = records.get(singleUseKey);
            return record === undefined ? null : structuredClone(record);
        },
        acquire(singleUseKey, bindingDigest, executionToken) {
            const existing = records.get(singleUseKey);
            if (existing !== undefined)
                return existing.binding_digest === bindingDigest ? "replay" : "conflict";
            records.set(singleUseKey, {
                state: "executing",
                binding_digest: bindingDigest,
                execution_token: executionToken,
            });
            return "acquired";
        },
        commit(executionToken, resultDigest, cachedResult) {
            for (const [key, existing] of records) {
                if (existing.state !== "executing" || existing.execution_token !== executionToken)
                    continue;
                records.set(key, {
                    state: "committed",
                    binding_digest: existing.binding_digest,
                    execution_token: executionToken,
                    result_digest: resultDigest,
                    cached_result: structuredClone(cachedResult),
                });
                return "committed";
            }
            return "conflict";
        },
        markIndeterminate(executionToken, reconciliationDigest) {
            for (const [key, existing] of records) {
                if (existing.state !== "executing" || existing.execution_token !== executionToken)
                    continue;
                records.set(key, {
                    state: "indeterminate",
                    binding_digest: existing.binding_digest,
                    execution_token: executionToken,
                    reconciliation_digest: reconciliationDigest,
                });
                return "indeterminate";
            }
            return "conflict";
        },
    };
};
const currentClaimBoundary = (options: {
    authority_id: string;
    leaf: VerifiedClaimArtifact;
    chain: readonly VerifiedClaimArtifact[];
    context: ClaimVerificationContext;
    view: CurrentClaimAuthorizationView;
}) => {
    const authority = createClaimAuthorizationAuthority({
        authority_id: options.authority_id,
        trusted_now: () => options.context.now,
        trusted_issuers: options.context.trusted_issuers,
        load_current_view: () => options.view,
        store: currentClaimStore(),
    });
    const input: ClaimAuthorizationEffectInput<{ operation: string }> = {
        leaf: options.leaf,
        chain: options.chain,
        audience: options.context.audience,
        resource: options.context.resource,
        requested_namespace: options.context.requested_namespace,
        operation: options.context.requested_operation,
        nonce: options.context.expected_nonce,
        subject_proof: options.context.subject_proof,
        idempotency_key: `${options.authority_id}:current-vector`,
        effect_digest: "e6".repeat(32),
        effect: () => ({ status: "completed", result: { operation: "claim-authorized" } }),
    };
    return { authority, input };
};
export async function buildCommsCases(): Promise<CurrentCaseFixture[]> {
    const support = await buildAuthorizationFreshnessTestSupport();
    const state = support.scenario.issuerKeyEpochOneState;
    const observedAt = state.checkpoint.observed_at;
    const checkpointBoundary = support.signedManifest(state, {
        checkpoint_age: 300,
        authorization_view_max_age: 300,
    });
    const checkpointBoundaryDecision = evaluateAuthorizationFreshness(support.authorityFor(checkpointBoundary, state, { now: observedAt + 300 }), checkpointBoundary);
    const checkpointStale = support.signedManifest(state, {
        checkpoint_age: 301,
        authorization_view_max_age: 300,
    });
    const checkpointStaleDecision = evaluateAuthorizationFreshness(support.authorityFor(checkpointStale, state, { now: observedAt + 301 }), checkpointStale);
    const view300 = support.signedManifest(state, { authorization_view_max_age: 300 });
    const view300Decision = evaluateAuthorizationFreshness(support.authorityFor(view300, state, { now: observedAt + 300 }), view300);
    const view86400 = support.signedManifest(state, { authorization_view_max_age: 86400 });
    const view86400Decision = evaluateAuthorizationFreshness(support.authorityFor(view86400, state, { now: observedAt + 86400 }), view86400);
    const malformed = support.signedManifest(state, { authorization_view_max_age: 86401 });
    let malformedRejected = false;
    try {
        validateOidcContinuityManifestSchemaOrThrow(malformed);
    }
    catch {
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
    const claimArtifact = ledger.claimOne.verified_artifact;
    const claim = inspectVerifiedClaim(claimArtifact);
    const claimContext = ledger.makeVerification(ledger.claimOne);
    const baseLedgerState = mergeClaimLedger([ledger.claimRecordOne, ledger.claimRecordTwo], [], ledger.baseRepository.checkpoint, ledger.makeContext(ledger.baseRepository.repository));
    const authorizedReaderRequest = ledger.requestFor(ledger.claimRecordOne, ledger.claimOne);
    authorizedReaderRequest.verification_context.now =
        ledger.baseRepository.checkpoint.observed_at;
    const authorizedReader = evaluateReaderAccess(ledger.writerOne.did_key, baseLedgerState, authorizedReaderRequest);
    const unauthorizedReader = evaluateReaderAccess(ledger.writerTwo.did_key, baseLedgerState, ledger.requestFor(ledger.claimRecordOne, ledger.claimOne));
    const invalidClaimId = { ...claim, claim_id: "00".repeat(32) };
    const invalidClaimIdDecision = thrownDecision(() => validateClaimId(invalidClaimId));
    const invalidClaimKey = { type: "nostr-secp256k1" as const, value: "00".repeat(32) };
    const invalidClaimKeyDecision = thrownDecision(() => validateKeyRef(invalidClaimKey));
    const invalidClaimEvent = { ...ledger.claimOne.artifact.event, sig: "00".repeat(64) };
    const claimEnvelopeContext = ledger.requestFor(ledger.claimRecordOne, ledger.claimOne).envelope_context;
    const invalidClaimEventDecision = thrownDecision(() => verifyClaimEnvelope(invalidClaimEvent, claimEnvelopeContext));
    const missingAuthorityArtifact = Object.freeze({}) as VerifiedClaimArtifact;
    const attenuationContext = { ...claimContext, requested_namespace: "other.namespace" };
    const expiredContext = {
        ...claimContext,
        now: claim.expires_at!,
    };
    const subjectInvalidContext = structuredClone(claimContext);
    if (subjectInvalidContext.subject_proof === null) {
        throw new Error("claim subject-proof fixture missing");
    }
    subjectInvalidContext.subject_proof.challenge.nonce = "ff".repeat(16);
    const revocationArtifact = (ledger.revocationRecord.payload as unknown as {
        revocation_artifact: {
            event: Parameters<typeof verifyClaimRevocationEnvelope>[0];
        };
    }).revocation_artifact;
    const verifiedRevocation = verifyClaimRevocationEnvelope(revocationArtifact.event);
    const inspectedRevocation = inspectVerifiedClaimRevocation(verifiedRevocation);
    const claimView = (overrides: Partial<CurrentClaimAuthorizationView> = {}): CurrentClaimAuthorizationView => ({
        credential_ledger: claimContext.credential_ledger,
        checkpoint_digest: "c6".repeat(32),
        repository_revision: 7,
        claims: [claimArtifact],
        revocations: [],
        conflicted_claim_ids: [],
        ...overrides,
    });
    const claimBoundary = (id: string, options: {
        leaf?: VerifiedClaimArtifact;
        chain?: readonly VerifiedClaimArtifact[];
        context?: typeof claimContext;
        view?: CurrentClaimAuthorizationView;
    } = {}) => currentClaimBoundary({
        authority_id: `current-${id}`,
        leaf: options.leaf ?? claimArtifact,
        chain: options.chain ?? [claimArtifact],
        context: options.context ?? claimContext,
        view: options.view ?? claimView(),
    });
    const activeClaimBoundary = claimBoundary("claim-active-authenticated");
    const unconfirmedClaimBoundary = claimBoundary("claim-repository-unconfirmed", {
        view: claimView({ claims: [] }),
    });
    const missingAuthorityBoundary = claimBoundary("claim-issuer-authority-invalid", {
        leaf: missingAuthorityArtifact,
        chain: [missingAuthorityArtifact],
    });
    const attenuationBoundary = claimBoundary("claim-attenuation-violation", {
        context: attenuationContext,
    });
    const expiredClaimBoundary = claimBoundary("claim-expired", { context: expiredContext });
    const repositoryConflictBoundary = claimBoundary("claim-repository-conflict", {
        view: claimView({ conflicted_claim_ids: [claim.claim_id] }),
    });
    const subjectRequiredBoundary = claimBoundary("claim-subject-proof-required", {
        context: { ...claimContext, subject_proof: null },
    });
    const subjectInvalidBoundary = claimBoundary("claim-subject-proof-invalid", {
        context: subjectInvalidContext,
    });
    const untrustedClaimBoundary = claimBoundary("claim-issuer-untrusted", {
        context: { ...claimContext, trusted_issuers: [] },
    });
    const revokedClaimBoundary = claimBoundary("claim-revoked", {
        context: { ...claimContext, now: inspectedRevocation.revoked_at },
        view: claimView({ revocations: [verifiedRevocation] }),
    });
    const chainCycleBoundary = claimBoundary("claim-chain-cycle", {
        chain: [claimArtifact, claimArtifact],
    });
    const chainDepthBoundary = claimBoundary("claim-chain-depth-exceeded", {
        chain: Array.from({ length: 10 }, () => claimArtifact),
    });
    const delegationBoundary = claimBoundary("claim-delegation-not-authorized", {
        leaf: ledger.claimTwo.verified_artifact,
        chain: [claimArtifact],
        view: claimView({ claims: [claimArtifact, ledger.claimTwo.verified_artifact] }),
    });
    const rollbackCheckpoint = { ...ledger.baseRepository.checkpoint, branch: "dev" };
    const rollbackDecision = (() => {
        try {
            mergeClaimLedger([ledger.claimRecordOne], [], rollbackCheckpoint as never, ledger.makeContext(ledger.baseRepository.repository));
            return { verdict: "accept" };
        }
        catch (error) {
            return { verdict: "reject", reason_code: ledgerErrorReason(error) };
        }
    })();
    const unauthorizedRevocationEvidence = {
        record_id: ledger.removalRecord.record_id,
        payload_digest: ledger.removalRecord.payload_digest,
    };
    const unauthorizedRevocationDecision = (() => {
        try {
            validateLedgerRecordOrThrow(ledger.removalRecord, new Map([
                [ledger.claimRecordOne.record_id, ledger.claimRecordOne],
                [ledger.removalRecord.record_id, ledger.removalRecord],
            ]), unauthorizedRevocationEvidence, {
                credential_ledger_persona: ledger.persona,
                credential_ledger_generation: 0,
            });
            return { verdict: "accept" };
        }
        catch (error) {
            return { verdict: "reject", reason_code: ledgerErrorReason(error) };
        }
    })();
    const oidc = await buildLiveOidcScenario(fixtures);
    const oidcRelease = validateAuthorizationRequest(oidc.request);
    const accessToken = projectAccessToken(oidc.projection);
    const accessValidation = validateProjectedJwt(accessToken.compact, oidc.metadata.issuer, "https://api.example", { keys: [OIDC_RSA_ONE.public_jwk] }, {
        now: oidc.projection.now,
        token_use: "access_token",
        client_id: oidc.request.client_id,
        sender_constraint: "none",
        permitted_audiences: ["https://api.example"],
        credential_ledger: oidc.issuedState.credential_ledger,
    });
    const issuerMetadataDecision = validateIssuerMetadata(oidc.metadata, oidc.metadata.issuer, oidc.metadata.jwks_uri);
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
    const issuerMismatchDecision = validateIssuerMetadata(oidc.metadata, "https://other.example/oidc/npub1other", oidc.metadata.jwks_uri);
    const tokenTypeDecision = validateProjectedJwt(accessToken.compact, oidc.metadata.issuer, "registered-client", { keys: [OIDC_RSA_ONE.public_jwk] }, {
        now: oidc.projection.now,
        token_use: "id_token",
        client_id: oidc.request.client_id,
        nonce: oidc.request.nonce,
        sender_constraint: "none",
        permitted_audiences: ["registered-client"],
        credential_ledger: oidc.issuedState.credential_ledger,
    });
    const audienceInvalidDecision = validateProjectedJwt(accessToken.compact, oidc.metadata.issuer, "https://api.example", { keys: [OIDC_RSA_ONE.public_jwk] }, {
        now: oidc.projection.now,
        token_use: "access_token",
        client_id: oidc.request.client_id,
        sender_constraint: "none",
        permitted_audiences: ["https://api.example", "https://extra.example"],
        credential_ledger: oidc.issuedState.credential_ledger,
    });
    const issuerAuthorityDecision = canMint(ledger.baseRepository.checkpoint.observed_at, ledger.baseRepository.checkpoint, 300, "revoked", true);
    const signingKeyDecision = canMint(ledger.baseRepository.checkpoint.observed_at, ledger.baseRepository.checkpoint, 300, "active", false);
    const statusInvalidDecision = thrownDecision(() => encodeStatusList([]));
    const configKey = deriveConfigPostKey("42".repeat(32), "current-config-key");
    const configPlaintext = JSON.stringify({ blob: "synthetic-private-config" });
    const configCiphertext = nip44.v2.encrypt(configPlaintext, configKey, hexToBytes("60".repeat(32)));
    const configRecovered = nip44.v2.decrypt(configCiphertext, configKey);
    const tier3Key = deriveTier3IndexKey("40".repeat(32), "current-tier3-key");
    const tier3Plaintext = JSON.stringify({ audience: "opaque", payload: "protected" });
    const tier3Ciphertext = nip44.v2.encrypt(tier3Plaintext, tier3Key, hexToBytes("61".repeat(32)));
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
        not_before: 1000,
        expires_at: 1300,
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
        exp: 1250,
        iat: 1000,
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
        now: 1100,
        status: "VALID",
        ledger_active: true,
        ledger_binding_valid: true,
        status_binding_valid: true,
        session_expires_at: 1300,
        delegation_expires_at: 1300,
        registration_expires_at: 1300,
        consent_expires_at: 1300,
        source_authorization_expires_at: 1300,
    };
    const tokenDecision = validateAgentAccessToken(tokenInput);
    const invalidRegistrationInput = { ...registration, max_content_bytes: 0 };
    const invalidRegistrationDecision = thrownDecision(() => validateWorkloadRegistration(invalidRegistrationInput));
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
    const privateRouteInput = {
        requested_repository_rid: "rad:z3CurrentPrivateRepository",
        requested_interface_id: "radicle-native-private",
        requested_route: "rad:zAbsent",
    };
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
        issued_at: 1799999900,
        expires_at: 1800001000,
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
        signature: bytesToHex(schnorr.sign(trustedSeedAclProofBytes(unsignedSeedAcl), seedAdminSecret, "00".repeat(32))),
    };
    const seedMarmotEvent = await signEvent({
        secretKey: "17".repeat(32),
        created_at: 1799999999,
        kind: 445,
        tags: [["h", routingBindingInput.canonical_h]],
        content: tier3Ciphertext,
        auxRand: "18".repeat(32),
    });
    const seedRaw = JSON.stringify(seedMarmotEvent);
    const seedAuthority = createTrustedSeedAdmissionAuthority({
        seed_nid: seedNid,
        administrator_account: seedAdministrator,
        trusted_now: () => ({ now: 1800000000 }),
        authenticate_nip42: () => ({
            verdict: "accept",
            account_key: agentPersona,
            connection_id: "current-seed-connection",
            challenge_id: "current-seed-challenge",
            request_id: "current-seed-request",
            authenticated_at: 1799999999,
            expires_at: 1800000060,
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
    if (seedAuthority === null)
        throw new Error("current trusted-seed authority rejected");
    const seedRequest = {
        operation: "write" as const,
        h: routingBindingInput.canonical_h,
        private_rid: routingBindingInput.canonical_rid,
        writer_ref: seedWriterRef,
        nip01_raw: seedRaw,
    };
    const seedCapability = seedAuthority.mintRequestCapability({}, seedRequest);
    if (seedCapability === null)
        throw new Error("current trusted-seed request rejected");
    const seedDecision = evaluateTrustedSeedAdmission(seedAuthority.authority, seedCapability);
    const seedReplayDecision = evaluateTrustedSeedAdmission(seedAuthority.authority, seedCapability);
    const signSeedAcl = (patch: Record<string, unknown> = {}) => {
        const { signature: _signature, ...base } = seedAcl;
        const candidate = { ...structuredClone(base), ...structuredClone(patch) };
        return {
            ...candidate,
            signature: bytesToHex(schnorr.sign(trustedSeedAclProofBytes(candidate), seedAdminSecret, "00".repeat(32))),
        } as typeof seedAcl;
    };
    const seedState = (candidates: typeof seedAcl[], previous: typeof seedAcl | null = null) => ({
        administrator_account: seedAdministrator,
        acl_candidates: candidates,
        previous_acl: previous,
        group_transition: seedTransition,
        revision: 2,
    });
    const createSeedScenario = (options: {
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
                    ? 1800000000
                    : (options.evaluation_now ?? 1800000000),
            }),
            authenticate_nip42: () => ({
                verdict: "accept",
                account_key: agentPersona,
                connection_id: "scenario-connection",
                challenge_id: "scenario-challenge",
                request_id: "scenario-request",
                authenticated_at: 1799999999,
                expires_at: 1800000060,
            }),
            load_current_state: () => options.state,
            consume_once: () => ({ verdict: "accept" }),
        });
        if (bundle === null)
            throw new Error("trusted-seed scenario authority rejected");
        const capability = bundle.mintRequestCapability({}, options.request ?? seedRequest);
        if (capability === null)
            throw new Error("trusted-seed scenario capability rejected");
        return { authority: bundle.authority, capability };
    };
    const evaluateSeedScenario = (options: Parameters<typeof createSeedScenario>[0]) => {
        const scenario = createSeedScenario(options);
        return evaluateTrustedSeedAdmission(scenario.authority, scenario.capability);
    };
    const seedMissingDecision = evaluateSeedScenario({ state: seedState([]) });
    const seedInvalidDecision = evaluateSeedScenario({
        state: seedState([{ ...seedAcl, signature: "00".repeat(64) }]),
    });
    const seedExpiredDecision = evaluateSeedScenario({
        state: seedState([signSeedAcl({ expires_at: 1800000000 })]),
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
        evaluation_now: 1800000060,
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
    const reasonCases: CurrentCaseFixture[] = [
        {
            vector_id: "comms/" + String("claim-id-mismatch"),
            description: "A claim identifier must equal the lowercase SHA-256 digest of its canonical semantic body.",
            direction: "consume" as const,
            input: { claim: invalidClaimId }
        },
        {
            vector_id: "comms/" + String("claim-key-reference-invalid"),
            description: "A claim key reference must be a registered type with its exact canonical encoding.",
            direction: "consume" as const,
            input: { key_reference: invalidClaimKey }
        },
        {
            vector_id: "comms/" + String("claim-event-signature-invalid"),
            description: "A substituted outer claim-event signature is rejected before claim semantics are trusted.",
            direction: "consume" as const,
            input: { event: invalidClaimEvent }
        },
        {
            vector_id: "comms/" + String("claim-issuer-authority-invalid"),
            description: "A claim without current claim-bound issuer authority evidence cannot authorize.",
            direction: "consume" as const,
            input: { claim_id: claim.claim_id, authority_evidence: [] }
        },
        {
            vector_id: "comms/" + String("claim-attenuation-violation"),
            description: "A requested namespace outside the exact claim scope is rejected as widening.",
            direction: "consume" as const,
            input: { claim_id: claim.claim_id, requested_namespace: attenuationContext.requested_namespace }
        },
        {
            vector_id: "comms/" + String("claim-expired"),
            description: "A claim expires at its exact exclusive expiry boundary.",
            direction: "consume" as const,
            input: { claim_id: claim.claim_id, now: expiredContext.now }
        },
        {
            vector_id: "comms/" + String("claim-repository-conflict"),
            description: "Concurrent non-monotonic canonical claim state grants no authority.",
            direction: "consume" as const,
            input: { claim_id: claim.claim_id, repository_conflicted_claim_ids: [claim.claim_id] }
        },
        {
            vector_id: "comms/" + String("claim-subject-proof-required"),
            description: "Authorization use without the subject's fresh proof of possession fails closed.",
            direction: "consume" as const,
            input: { claim_id: claim.claim_id, subject_proof: null }
        },
        {
            vector_id: "comms/" + String("claim-subject-proof-invalid"),
            description: "A subject proof over a different nonce does not prove this authorization use.",
            direction: "consume" as const,
            input: { claim_id: claim.claim_id, nonce: subjectInvalidContext.subject_proof.challenge.nonce }
        },
        {
            vector_id: "comms/" + String("claim-issuer-untrusted"),
            description: "A cryptographically valid claim outside local issuer trust policy remains untrusted.",
            direction: "consume" as const,
            input: { claim_id: claim.claim_id, trusted_issuers: [] }
        },
        {
            vector_id: "comms/" + String("claim-revoked"),
            description: "An authenticated direct-issuer revocation irreversibly removes claim authority.",
            direction: "consume" as const,
            input: { claim_id: claim.claim_id, revocation_event: revocationArtifact.event }
        },
        {
            vector_id: "comms/" + String("claim-chain-cycle"),
            description: "A repeated claim identifier in one issuance chain is rejected as a cycle.",
            direction: "consume" as const,
            input: { chain_claim_ids: [claim.claim_id, claim.claim_id] }
        },
        {
            vector_id: "comms/" + String("claim-chain-depth-exceeded"),
            description: "An issuance chain longer than eight edges is rejected before authority use.",
            direction: "consume" as const,
            input: { chain_claim_ids: Array.from({ length: 10 }, () => claim.claim_id) }
        },
        {
            vector_id: "comms/" + String("claim-delegation-not-authorized"),
            description: "A supplied chain that does not terminate at the requested leaf cannot delegate authority.",
            direction: "consume" as const,
            input: { leaf_claim_id: ledger.claimTwo.artifact.semantic.claim_id, chain_claim_ids: [claim.claim_id] }
        },
        {
            vector_id: "comms/" + String("claim-ledger-rollback"),
            description: "A checkpoint outside canonical main cannot replace finalized claim-ledger history.",
            direction: "consume" as const,
            input: { checkpoint: rollbackCheckpoint }
        },
        {
            vector_id: "comms/" + String("claim-revoker-unauthorized"),
            description: "A revocation ledger record without claim-bound revoker authority evidence cannot reduce authority.",
            direction: "consume" as const,
            input: { record_id: ledger.removalRecord.record_id, evidence: unauthorizedRevocationEvidence }
        },
        ...[
            ["oidc-client-unregistered", { client_id: "unregistered-client" }],
            ["oidc-grant-prohibited", { grant_type: "client_credentials" }],
            ["oidc-consent-required", { requested_scopes: ["profile"] }],
            ["oidc-claim-release-denied", { nonce: "" }],
            ["oidc-issuer-mismatch", { expected_issuer: "https://other.example/oidc/npub1other" }],
            ["oidc-token-type-invalid", { compact: accessToken.compact, expected_token_use: "id_token" }],
            ["oidc-audience-invalid", { compact: accessToken.compact, permitted_audiences: ["https://api.example", "https://extra.example"] }],
            ["oidc-issuer-authority-invalid", { issuer_authority_state: "revoked" }],
            ["oidc-signing-key-unavailable", { issuer_authority_state: "active", signing_key_available: false }],
            ["oidc-status-invalid", { statuses: [] }]
        ].map(([id, input]) => ({
            vector_id: "comms/" + String(String(id)),
            description: `The live OIDC boundary rejects ${String(id).replaceAll("-", " ")}.`,
            direction: "consume" as const,
            input: input as Record<string, unknown>
        })),
        ...[
            ["agent-workload-registration-invalid", invalidRegistrationInput],
            ["agent-token-invalid", invalidAgentTokenInput],
            ["agent-sender-proof-invalid", invalidSenderProofInput],
            ["agent-signer-mismatch", signerMismatchInput],
            ["agent-persona-scope-required", personaScopeInput],
            ["agent-attribution-invalid", invalidAttributionInput],
            ["agent-attribution-profile-unavailable", unavailableAttributionInput]
        ].map(([id, input]) => ({
            vector_id: "comms/" + String(String(id)),
            description: `The current workload boundary rejects ${String(id).replaceAll("-", " ")}.`,
            direction: "consume" as const,
            input: input as Record<string, unknown>
        })),
        ...[
            ["nip59-broadcast-rejected", privateBroadcastInput],
            ["auth-rejected-permanent", relayAuthInput],
            ["dm-invite-unbound-device", unboundDmInput],
            ["dm-invite-revoked-device", revokedDmInput],
            ["invite-expired", inviteExpiredInput],
            ["invite-purpose-mismatch", invitePurposeInput],
            ["invite-authentication-invalid", inviteAuthInput],
            ["invite-already-reserved", inviteReservedInput],
            ["public-reader-private-content", privateReaderInput],
            ["marmot-private-route-required", privateRouteInput],
            ["marmot-private-inbox-nid-required", inboxNidInput],
            ["marmot-keypackage-replayed", inboxReplayInput],
            ["marmot-agent-scope-denied", marmotScopeInput],
            ["conversation-rejected", rejectedConversationInput],
            ["marmot-routing-equivocation", routingEquivocationInput],
            ["marmot-unauthorized-ref", unauthorizedRefInput]
        ].map(([id, input]) => ({
            vector_id: "comms/" + String(String(id)),
            description: `The current Comms policy boundary rejects ${String(id).replaceAll("-", " ")}.`,
            direction: "consume" as const,
            input: input as Record<string, unknown>
        })),
        ...[
            ["trusted-seed-acl-missing", { acl_candidates: [] }],
            ["trusted-seed-acl-invalid", { acl_candidates: [{ ...seedAcl, signature: "00".repeat(64) }] }],
            ["trusted-seed-acl-expired", { expires_at: 1800000000 }],
            ["trusted-seed-acl-stale", { sequence: seedAcl.sequence, previous_sequence: seedAcl.sequence }],
            ["trusted-seed-acl-conflict", { greatest_sequence_candidates: 2 }],
            ["trusted-seed-acl-ambiguous", { sequence: 1, predecessor: null }],
            ["trusted-seed-unauthorized", { authenticated_account: agentPersona, authorized_accounts: ["99".repeat(32)] }],
            ["trusted-seed-revoked", { seed_nid: seedNid, state: "revoked" }],
            ["trusted-seed-nip42-required", { authenticated_at: 1799999999, expires_at: 1800000060, now: 1800000060 }],
            ["trusted-seed-route-mismatch", { request_h: "other-routing-generation", acl_h: seedAcl.h }],
            ["trusted-seed-event-invalid", { nip01_raw: "{}" }],
            ["trusted-seed-request-invalid", { capability: {} }],
            ["trusted-seed-request-replay", { capability_used: true }]
        ].map(([id, input]) => ({
            vector_id: "comms/" + String(String(id)),
            description: `The trusted-seed authority rejects ${String(id).replaceAll("-", " ")} from authenticated current state.`,
            direction: "consume" as const,
            input: input as Record<string, unknown>
        })),
    ];
    const boundaryArgs = new Map<string, readonly unknown[]>([
        ["comms/claim-event-signature-invalid", [invalidClaimEvent, claimEnvelopeContext]],
        ["comms/claim-issuer-authority-invalid", [missingAuthorityBoundary.authority, missingAuthorityBoundary.input]],
        ["comms/claim-attenuation-violation", [attenuationBoundary.authority, attenuationBoundary.input]],
        ["comms/claim-expired", [expiredClaimBoundary.authority, expiredClaimBoundary.input]],
        ["comms/claim-repository-conflict", [repositoryConflictBoundary.authority, repositoryConflictBoundary.input]],
        ["comms/claim-subject-proof-required", [subjectRequiredBoundary.authority, subjectRequiredBoundary.input]],
        ["comms/claim-subject-proof-invalid", [subjectInvalidBoundary.authority, subjectInvalidBoundary.input]],
        ["comms/claim-issuer-untrusted", [untrustedClaimBoundary.authority, untrustedClaimBoundary.input]],
        ["comms/claim-revoked", [revocationArtifact.event, revokedClaimBoundary.authority, revokedClaimBoundary.input]],
        ["comms/claim-chain-cycle", [chainCycleBoundary.authority, chainCycleBoundary.input]],
        ["comms/claim-chain-depth-exceeded", [chainDepthBoundary.authority, chainDepthBoundary.input]],
        ["comms/claim-delegation-not-authorized", [delegationBoundary.authority, delegationBoundary.input]],
        ["comms/claim-ledger-rollback", [
                [ledger.claimRecordOne],
                [],
                rollbackCheckpoint,
                ledger.makeContext(ledger.baseRepository.repository),
            ]],
        ["comms/claim-revoker-unauthorized", [
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
            ]],
        ["comms/claim-active-authenticated", [activeClaimBoundary.authority, activeClaimBoundary.input]],
        ["comms/claim-repository-unconfirmed", [unconfirmedClaimBoundary.authority, unconfirmedClaimBoundary.input]],
        ["comms/ledger-reader-authorized", [
                [ledger.claimRecordOne, ledger.claimRecordTwo],
                [],
                ledger.baseRepository.checkpoint,
                ledger.makeContext(ledger.baseRepository.repository),
                ledger.writerOne.did_key,
                authorizedReaderRequest,
            ]],
        ["comms/ledger-reader-unauthorized", [
                ledger.writerTwo.did_key,
                baseLedgerState,
                ledger.requestFor(ledger.claimRecordOne, ledger.claimOne),
            ]],
        ["comms/oidc-client-unregistered", [{
                    ...oidc.request,
                    client_id: "unregistered-client",
                }]],
        ["comms/oidc-grant-prohibited", [{
                    ...oidc.request,
                    grant_type: "client_credentials",
                }]],
        ["comms/oidc-consent-required", [{
                    ...oidc.request,
                    requested_scopes: ["profile"],
                }]],
        ["comms/oidc-claim-release-denied", [{
                    ...oidc.request,
                    nonce: "",
                }]],
        ["comms/oidc-issuer-mismatch", [
                oidc.metadata,
                "https://other.example/oidc/npub1other",
                oidc.metadata.jwks_uri,
            ]],
        ["comms/oidc-token-type-invalid", [
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
            ]],
        ["comms/oidc-audience-invalid", [
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
            ]],
        ["comms/oidc-issuer-authority-invalid", [
                ledger.baseRepository.checkpoint.observed_at,
                ledger.baseRepository.checkpoint,
                300,
                "revoked",
                true,
            ]],
        ["comms/oidc-signing-key-unavailable", [
                ledger.baseRepository.checkpoint.observed_at,
                ledger.baseRepository.checkpoint,
                300,
                "active",
                false,
            ]],
        ["comms/oidc-status-invalid", [[]]],
        ...[
            ["comms/trusted-seed-acl-missing", createSeedScenario({ state: seedState([]) })],
            ["comms/trusted-seed-acl-invalid", createSeedScenario({
                    state: seedState([{ ...seedAcl, signature: "00".repeat(64) }]),
                })],
            ["comms/trusted-seed-acl-expired", createSeedScenario({
                    state: seedState([signSeedAcl({ expires_at: 1800000000 })]),
                })],
            ["comms/trusted-seed-acl-stale", createSeedScenario({
                    state: seedState([seedAcl], seedAcl),
                })],
            ["comms/trusted-seed-acl-conflict", createSeedScenario({
                    state: seedState([
                        seedAcl,
                        signSeedAcl({ expires_at: seedAcl.expires_at + 1 }),
                    ]),
                })],
            ["comms/trusted-seed-acl-ambiguous", createSeedScenario({
                    state: seedState([signSeedAcl({ sequence: 1 })]),
                })],
            ["comms/trusted-seed-unauthorized", createSeedScenario({
                    state: seedState([signSeedAcl({
                            accounts: [{ account_key: "99".repeat(32), roles: ["read", "write"] }],
                        })]),
                })],
            ["comms/trusted-seed-revoked", createSeedScenario({
                    state: seedState([signSeedAcl({
                            seed_grants: seedAcl.seed_grants.map((grant) => ({
                                ...grant,
                                state: "revoked",
                            })),
                        })]),
                })],
            ["comms/trusted-seed-nip42-required", createSeedScenario({
                    state: seedState([seedAcl]),
                    evaluation_now: 1800000060,
                })],
            ["comms/trusted-seed-route-mismatch", createSeedScenario({
                    state: seedState([seedAcl]),
                    request: { ...seedRequest, h: "other-routing-generation" },
                })],
            ["comms/trusted-seed-event-invalid", createSeedScenario({
                    state: seedState([seedAcl]),
                    request: { ...seedRequest, nip01_raw: "{}" },
                })],
        ].map((entry): readonly [
            string,
            readonly unknown[]
        ] => {
            const scenario = entry[1] as ReturnType<typeof createSeedScenario>;
            return [String(entry[0]), [scenario.authority, scenario.capability]];
        }),
        ["comms/trusted-seed-request-invalid", [seedAuthority.authority, {}]],
        ...(() => {
            const replay = createSeedScenario({ state: seedState([seedAcl]) });
            return [["comms/trusted-seed-request-replay", [
                        replay.authority,
                        replay.capability,
                        "replay",
                    ]] as const];
        })(),
        ["comms/checkpoint-exact-boundary", [
                support.authorityFor(checkpointBoundary, state, { now: observedAt + 300 }),
                checkpointBoundary,
            ]],
        ["comms/checkpoint-stale-independent", [
                support.authorityFor(checkpointStale, state, { now: observedAt + 301 }),
                checkpointStale,
            ]],
        ["comms/authorization-view-300-boundary", [
                support.authorityFor(view300, state, { now: observedAt + 300 }),
                view300,
            ]],
        ["comms/authorization-view-86400-boundary", [
                support.authorityFor(view86400, state, { now: observedAt + 86400 }),
                view86400,
            ]],
        ["comms/oidc-claim-release", [oidc.request]],
        ["comms/oidc-access-token-validated", [
                oidc.projection,
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
            ]],
        ["comms/oidc-issuer-persona-continuity", [
                oidc.metadata,
                oidc.metadata.issuer,
                oidc.metadata.jwks_uri,
            ]],
        ["comms/public-reader-private-tier", [{
                    tier: 2,
                    available: true,
                    signature_valid: true,
                    complete_fetch: true,
                    nip65_refreshed: true,
                    canonical_feed_reachable: true,
                    indexed: true,
                    repo_confirmed: true,
                    conflict: false,
                }]],
        ["comms/public-reader-route-invalid", ["#/v1/unknown"]],
        ["comms/public-reader-relay-hint-invalid", ["ws://127.0.0.1/private"]],
        ["comms/agent-workload-token-accepted", [registration, tokenInput]],
        ...(() => {
            const exact = createSeedScenario({ state: seedState([seedAcl]) });
            return [["comms/trusted-seed-exact-write", [
                        exact.authority,
                        exact.capability,
                    ]] as const];
        })(),
    ]);
    const cases: CurrentCaseFixture[] = [
        ...reasonCases,
        {
            vector_id: "comms/checkpoint-exact-boundary",
            description: "A signed ledger checkpoint exactly 300 seconds old remains eligible independently of authorization-view age.",
            direction: "consume",
            input: { trusted_now: observedAt + 300, manifest: checkpointBoundary, ledger_state: state },
        },
        {
            vector_id: "comms/checkpoint-stale-independent",
            description: "Checkpoint age above 300 seconds rejects even while the authorization view itself is fresh.",
            direction: "consume",
            input: { trusted_now: observedAt + 301, manifest: checkpointStale, ledger_state: state },
        },
        {
            vector_id: "comms/authorization-view-300-boundary",
            description: "A 300-second authorization view is accepted at its exact declared boundary.",
            direction: "consume",
            input: { trusted_now: observedAt + 300, manifest: view300, ledger_state: state },
        },
        {
            vector_id: "comms/authorization-view-86400-boundary",
            description: "The maximum 86400-second authorization-view bound is accepted exactly at its boundary.",
            direction: "consume",
            input: { trusted_now: observedAt + 86400, manifest: view86400, ledger_state: state },
        },
        {
            vector_id: "comms/authorization-view-maximum-malformed",
            description: "An authorization-view maximum above 86400 seconds fails the registered manifest schema.",
            direction: "consume",
            input: { manifest: malformed }
        },
        {
            vector_id: "comms/tier3-recipient-confined",
            description: "Tier-3 delivery rejects a selected inactive device even when its persona remains a member.",
            direction: "produce",
            input: tier3Input
        },
        {
            vector_id: "comms/config-private-state-encrypted",
            description: "A Comms configuration post is encrypted under the derived repository key and round-trips only at the client boundary.",
            direction: "round-trip",
            input: {
                config_audience_key: "42".repeat(32),
                key_id: "current-config-key",
                plaintext: configPlaintext,
            }
        },
        {
            vector_id: "comms/tier3-client-side-encryption",
            description: "A Tier-3 audience object is encrypted and recovered locally from an audience-derived key without a delivery-directory lookup.",
            direction: "round-trip",
            input: {
                audience_key: "40".repeat(32),
                key_id: "current-tier3-key",
                plaintext: tier3Plaintext,
            }
        },
        {
            vector_id: "comms/claim-active-authenticated",
            description: "An exact signed, authority-bound, attenuated claim with fresh subject proof authorizes its requested repository operation.",
            direction: "consume",
            input: {
                claim: ledger.claimOne.artifact,
                requested_namespace: claimContext.requested_namespace,
                requested_operation: claimContext.requested_operation,
            }
        },
        {
            vector_id: "comms/claim-repository-unconfirmed",
            description: "A valid persona authorization remains provisional until canonical private claim-repository state confirms it.",
            direction: "consume",
            input: { claim: ledger.claimOne.artifact, repository_confirmed_claim_ids: [] }
        },
        {
            vector_id: "comms/ledger-reader-authorized",
            description: "Canonical merge state exposes the private ledger only to the exact active durable NID-bearing reader.",
            direction: "consume",
            input: {
                reader_nid: ledger.writerOne.did_key,
                checkpoint: ledger.baseRepository.checkpoint,
                record_ids: baseLedgerState.records.map(({ record_id }) => record_id),
            }
        },
        {
            vector_id: "comms/ledger-reader-unauthorized",
            description: "A reader presenting another device's claim record cannot cross the private ledger boundary.",
            direction: "consume",
            input: { reader_nid: ledger.writerTwo.did_key, claim_record_id: ledger.claimRecordOne.record_id }
        },
        {
            vector_id: "comms/oidc-claim-release",
            description: "The live OIDC release boundary intersects registered client, consent, scope, audience, and canonical source-claim state.",
            direction: "produce",
            input: {
                client_id: oidc.request.client_id,
                requested_scopes: oidc.request.requested_scopes,
                requested_audiences: oidc.request.requested_audiences,
                requested_claims: oidc.request.requested_claims,
                checkpoint: oidc.preMintState.checkpoint,
            },
        },
        {
            vector_id: "comms/oidc-access-token-validated",
            description: "A projected access token verifies its RS256 signature, at+jwt type, exact resource audience, ledger generation, and bound status locator.",
            direction: "round-trip",
            input: {
                compact: accessToken.compact,
                expected_issuer: oidc.metadata.issuer,
                expected_audience: "https://api.example",
            },
        },
        {
            vector_id: "comms/oidc-issuer-persona-continuity",
            description: "Issuer metadata resolves to the exact active persona scoped HTTPS issuer before continuity state is consumed.",
            direction: "consume",
            input: { metadata: oidc.metadata, persona_npub: oidc.personaNpub },
        },
        {
            vector_id: "comms/public-reader-private-tier",
            description: "The public resolver classifies otherwise available Tier-2 material as private instead of rendering it.",
            direction: "consume",
            input: { tier: 2, available: true, signature_valid: true }
        },
        {
            vector_id: "comms/public-reader-route-invalid",
            description: "An unknown launcher fragment is rejected before any network activity.",
            direction: "consume",
            input: { fragment: "#/v1/unknown" }
        },
        {
            vector_id: "comms/public-reader-relay-hint-invalid",
            description: "A cleartext loopback relay hint is rejected by the normalized bootstrap boundary.",
            direction: "consume",
            input: { relay_hint: "ws://127.0.0.1/private" }
        },
        {
            vector_id: "comms/agent-workload-token-accepted",
            description: "A closed finite workload registration and exact sender-constrained token resolve one registered automated signer without exposing private claims.",
            direction: "consume",
            input: {
                registration: validatedRegistration,
                token: tokenInput,
            }
        },
        {
            vector_id: "comms/agent-attribution-encrypted-inner",
            description: "Tier-3 automation attribution is canonicalized before signing and remains only inside the encrypted logical event.",
            direction: "produce",
            input: attributionInput
        },
        {
            vector_id: "comms/marmot-ordinary-welcome-held",
            description: "A cryptographically valid upstream Marmot Welcome from an unrecognized account is held for local policy without any sender-observable signal or secret disclosure.",
            direction: "consume",
            input: ordinaryMarmotInput
        },
        {
            vector_id: "comms/marmot-routing-binding-valid",
            description: "One canonical active-account administrator commit binds the same routing generation, private RID, repository genesis, and authorized writer ref.",
            direction: "consume",
            input: routingBindingInput
        },
        {
            vector_id: "comms/marmot-routing-genesis-mismatch",
            description: "A routing binding whose repository genesis digest differs from canonical Marmot routing state fails closed.",
            direction: "consume",
            input: routingMismatchInput
        },
        {
            vector_id: "comms/marmot-exact-bytes-durable",
            description: "A publisher acknowledges only after exact signed-event and encrypted-media bytes are durable locally and on a configured host.",
            direction: "round-trip",
            input: durabilityInput
        },
        {
            vector_id: "comms/marmot-premature-ack",
            description: "A requested publisher acknowledgement is rejected until its exact bytes cross the configured durability boundary.",
            direction: "produce",
            input: prematureAckInput
        },
        {
            vector_id: "comms/marmot-expiration-not-erasure",
            description: "Retention expiry stops conforming advertisement and replication without claiming deletion of independently retained Git objects.",
            direction: "consume",
            input: retentionInput
        },
        {
            vector_id: "comms/trusted-seed-exact-write",
            description: "A one-use NIP-42-authenticated capability admits one exact signed Marmot event under the unique current administrator ACL and configured seed writer ref.",
            direction: "consume",
            input: {
                request: seedRequest,
                acl: seedAcl,
                transition: seedTransition,
            },
        },
    ];
    return cases.map((fixture) => ({
        ...fixture,
        ...(boundaryArgs.has(fixture.vector_id)
            ? { boundary_args: boundaryArgs.get(fixture.vector_id) }
            : {}),
    }));
}
