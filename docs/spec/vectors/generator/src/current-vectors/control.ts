import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { buildAuthorizationFreshnessTestSupport } from "../authorization-freshness-test-support.js";
import { evaluateAuthorizationFreshness, revalidateAuthorizationViewAtEffect, type AuthorizationFreshnessAuthority, } from "../authorization-freshness.js";
import { authorizeNip46Signing, consumeNip46ConnectionSecret, executePersistedAutomatedSigning, prepareAutomatedSigning, signerGrantProofBytes, signerGrantStateDigest, validateCompromiseReset, type AutomatedPublication, type SigningGrant, } from "../control-signing.js";
import { evaluateAutomatedControlGrant, evaluateCompromiseResetBoundary, evaluateControlEnrollmentBoundary, evaluateControlOperationRequest, evaluateDeviceCodeBoundary, validateControlFrameBoundary, validateControlSignedEffect, validateInvitePreauthorizationBoundary, } from "../control-policy.js";
import { injectAgentAttribution } from "../agent-authorship.js";
import { QUALIFIED_VERSION } from "../family.js";
import { bytesToHex, hexToBytes } from "../hex.js";
import { jcsCanonicalize } from "../jcs.js";
import { getPublicKey } from "../nostr.js";
import { currentSpecRef, type CurrentCaseFixture } from "./types.js";
const normalizeReason = <T extends Record<string, unknown>>(value: T): Record<string, unknown> => "reason" in value ? (() => {
    const { reason, ...decision } = value;
    return { ...decision, reason_code: reason };
})() : value;
export async function buildControlCases(): Promise<CurrentCaseFixture[]> {
    const support = await buildAuthorizationFreshnessTestSupport();
    const state = support.scenario.issuerKeyEpochOneState;
    const manifest = support.signedManifest(state);
    const clock = { now: state.checkpoint.observed_at + 300 };
    const authority = support.authorityFor(manifest, state, clock);
    const prepared = evaluateAuthorizationFreshness(authority, manifest);
    if (prepared.verdict !== "accept") {
        throw new Error(`current authorization fixture rejected: ${prepared.reason}`);
    }
    const acceptedAtEffect = revalidateAuthorizationViewAtEffect(prepared.view);
    const acceptedEffectClock = { now: state.checkpoint.observed_at + 300 };
    const acceptedEffectPrepared = evaluateAuthorizationFreshness(support.authorityFor(manifest, state, acceptedEffectClock), manifest);
    if (acceptedEffectPrepared.verdict !== "accept") {
        throw new Error(`current effect fixture rejected: ${acceptedEffectPrepared.reason}`);
    }
    const callerDecision = evaluateAuthorizationFreshness({
        now: clock.now,
        checkpoint_fresh: true,
        authorization_view_authenticated: true,
    } as unknown as AuthorizationFreshnessAuthority, manifest);
    clock.now += 1;
    const staleAtEffect = revalidateAuthorizationViewAtEffect(prepared.view);
    const personaSecret = "01".repeat(32);
    const persona = getPublicKey(personaSecret);
    const agentSigner = getPublicKey("04".repeat(32));
    const client = "33".repeat(32);
    const vaultId = "66".repeat(32);
    const audience = "https://node.example/nip46/current-persona";
    const connectionSecret = "09".repeat(32);
    const unsignedGrant: Omit<SigningGrant, "signature"> = {
        profile: "heterodyne.control.signer-grant.v1",
        spec_version: QUALIFIED_VERSION,
        grant_id: "77".repeat(32),
        vault_id: vaultId,
        persona_active_key: persona,
        nip46_client_pubkey: client,
        signer_audience: audience,
        selected_signing_pubkey: agentSigner,
        key_class: "agent",
        persona_signing_authorized: false,
        allowed_methods: ["sign_event"],
        allowed_event_kinds: [1],
        limits: {
            request_window_seconds: 60,
            request_count: 20,
            max_event_bytes: 4096,
            max_value_msats: 0,
        },
        oidc_authorization_id: "88".repeat(32),
        connection_secret_sha256: createHash("sha256")
            .update(hexToBytes(connectionSecret))
            .digest("hex"),
        issued_at: 100,
        expires_at: 200,
        predecessor: null,
        state: "active",
        revoked_at: null,
        authorizing_pubkey: persona,
    };
    const signingGrant: SigningGrant = {
        ...unsignedGrant,
        signature: bytesToHex(schnorr.sign(signerGrantProofBytes(unsignedGrant), hexToBytes(personaSecret), "00".repeat(32))),
    };
    const usageState = {
        grant_id: signingGrant.grant_id,
        grant_digest: signerGrantStateDigest(signingGrant),
        authority: {
            vault_id: signingGrant.vault_id,
            persona_active_key: signingGrant.persona_active_key,
            nip46_client_pubkey: signingGrant.nip46_client_pubkey,
            signer_audience: signingGrant.signer_audience,
            selected_signing_pubkey: signingGrant.selected_signing_pubkey,
            key_class: signingGrant.key_class,
        },
        window_started_at: 100,
        consumed_request_count: 0,
        revision: 4,
        reservations: [],
    };
    const rpcTemplate = {
        created_at: 111,
        kind: 1,
        tags: [] as string[][],
        content: "current canonical NIP-46 payload",
    };
    const signingRequest = {
        grant_id: signingGrant.grant_id,
        vault_id: vaultId,
        persona_active_key: persona,
        nip46_client_pubkey: client,
        signer_audience: audience,
        selected_signing_pubkey: agentSigner,
        key_class: "agent" as const,
        rpc_request: {
            id: "dd".repeat(32),
            method: "sign_event",
            params: [jcsCanonicalize(rpcTemplate)],
        },
        value_msats: 0,
        now: 110,
    };
    const signerAuthorization = authorizeNip46Signing({
        grant_candidates: [signingGrant],
        usage_state: usageState,
        presented_grant: structuredClone(signingGrant),
        vaults: [{
                vault_id: vaultId,
                persona_active_key: persona,
                signers: [{
                        public_key: agentSigner,
                        key_class: "agent" as const,
                        custody: "local" as const,
                    }],
            }],
        request: signingRequest,
        client_metadata: {
            requested_methods: ["sign_event"],
            requested_event_kinds: [1],
            requested_signer_audiences: [audience],
        },
    });
    const automationPolicy = {
        workload_id: "aa".repeat(32),
        agent_class: "ai" as const,
        agent_association: { kind: "key" as const, value: agentSigner },
        tier: 1 as const,
        oidc_scopes: [] as string[],
    };
    const automationGrantUnsigned: Omit<SigningGrant, "signature"> = {
        ...unsignedGrant,
        automation_policy: automationPolicy,
    };
    const automationGrant: SigningGrant = {
        ...automationGrantUnsigned,
        signature: bytesToHex(schnorr.sign(signerGrantProofBytes(automationGrantUnsigned), hexToBytes(personaSecret), "00".repeat(32))),
    };
    const automatedPublication: AutomatedPublication = {
        profile: "heterodyne.control.agent-publish-intent.v1" as const,
        spec_version: QUALIFIED_VERSION as AutomatedPublication["spec_version"],
        grant_id: automationGrant.grant_id,
        vault_id: automationGrant.vault_id,
        persona_active_key: automationGrant.persona_active_key,
        nip46_client_pubkey: automationGrant.nip46_client_pubkey,
        signer_audience: automationGrant.signer_audience,
        selected_signing_pubkey: automationGrant.selected_signing_pubkey,
        key_class: automationGrant.key_class,
        created_at: 111,
        kind: 1,
        tags: [["t", "heterodyne"]],
        content: "current bounded automated publication",
        value_msats: 0,
        agent_class: automationPolicy.agent_class,
        agent_association: automationPolicy.agent_association,
        tier: automationPolicy.tier,
    };
    const automatedAttribution = injectAgentAttribution({
        kind: automatedPublication.kind,
        tags: automatedPublication.tags,
        agent_class: automationPolicy.agent_class,
        persona: automationGrant.persona_active_key,
        signer: automationGrant.selected_signing_pubkey,
        expected_signer: automationGrant.selected_signing_pubkey,
        signer_key_class: automationGrant.key_class,
        oidc_scopes: automationPolicy.oidc_scopes,
        agent_association: automationPolicy.agent_association,
        expected_agent_association: automationPolicy.agent_association,
        tier: automationPolicy.tier,
    });
    if (automatedAttribution.verdict !== "accept") {
        throw new Error(`current automation attribution rejected: ${automatedAttribution.reason_code}`);
    }
    const automationRequest = {
        ...signingRequest,
        grant_id: automationGrant.grant_id,
        rpc_request: {
            ...signingRequest.rpc_request,
            params: [jcsCanonicalize({
                    created_at: automatedPublication.created_at,
                    kind: automatedPublication.kind,
                    tags: automatedAttribution.tags,
                    content: automatedPublication.content,
                })],
        },
    };
    const automationUsage = {
        ...usageState,
        grant_digest: signerGrantStateDigest(automationGrant),
    };
    const automationAuthorizationInput = {
        grant_candidates: [automationGrant],
        usage_state: automationUsage,
        presented_grant: structuredClone(automationGrant),
        vaults: [{
                vault_id: vaultId,
                persona_active_key: persona,
                signers: [{
                        public_key: agentSigner,
                        key_class: "agent" as const,
                        custody: "local" as const,
                    }],
            }],
        request: automationRequest,
        client_metadata: {
            requested_methods: ["sign_event"],
            requested_event_kinds: [1],
            requested_signer_audiences: [audience],
        },
    };
    const automationReservation = authorizeNip46Signing(automationAuthorizationInput);
    if (automationReservation.verdict !== "accept") {
        throw new Error(`current automation reservation rejected: ${"reason_code" in automationReservation
            ? automationReservation.reason_code
            : automationReservation.verdict}`);
    }
    const reserved = automationReservation.usage_transition;
    const persistedAutomationUsage = {
        ...automationUsage,
        window_started_at: reserved.window_started_at,
        consumed_request_count: reserved.consumed_request_count,
        revision: reserved.next_revision,
        reservations: [{
                operation_id: reserved.operation_id,
                request_id: reserved.request_id,
                request_digest: reserved.request_digest,
                rpc_request: reserved.rpc_request,
                value_msats: reserved.value_msats,
                window_started_at: reserved.window_started_at,
                reserved_at: reserved.reserved_at,
                claimed_at: null,
                executing_at: null,
                completed_at: null,
                state: "reserved" as const,
                execution_token: null,
                result_event_id: null,
                failure_digest: null,
            }],
    };
    const automatedSigningInput = {
        authorization: {
            ...automationAuthorizationInput,
            usage_state: persistedAutomationUsage,
        },
        publication: automatedPublication,
    };
    const automatedSigningDecision = prepareAutomatedSigning(automatedSigningInput);
    const incompleteResetInput = {
        grant: {},
        completion: {},
        authoritative_inventory: {},
        authoritative_evidence: {},
        pinned_assurance_authority: null,
        now: 130,
    };
    const incompleteResetDecision = validateCompromiseReset(incompleteResetInput as never);
    const authorizationInput = (patch: Record<string, unknown>) => ({
        ...{
            grant_candidates: [signingGrant],
            usage_state: usageState,
            presented_grant: structuredClone(signingGrant),
            vaults: [{
                    vault_id: vaultId,
                    persona_active_key: persona,
                    signers: [{ public_key: agentSigner, key_class: "agent" as const, custody: "local" as const }],
                }],
            request: signingRequest,
            client_metadata: {
                requested_methods: ["sign_event"],
                requested_event_kinds: [1],
                requested_signer_audiences: [audience],
            },
        },
        ...patch,
    } as Parameters<typeof authorizeNip46Signing>[0]);
    const authorize = (patch: Record<string, unknown>) => authorizeNip46Signing(authorizationInput(patch));
    const unauthenticatedGrant = { ...signingGrant, signature: "00".repeat(64) };
    const invalidGrantDecision = authorize({ grant_candidates: [] });
    const unauthenticatedGrantDecision = authorize({
        grant_candidates: [unauthenticatedGrant],
        presented_grant: unauthenticatedGrant,
    });
    const staleGrantDecision = authorize({ grant_candidates: [signingGrant, signingGrant] });
    const inactiveGrantDecision = authorize({ request: { ...signingRequest, now: signingGrant.expires_at } });
    const vaultIsolationDecision = authorize({ vaults: [] });
    const signerBindingDecision = authorize({
        request: { ...signingRequest, selected_signing_pubkey: "55".repeat(32) },
    });
    const signerUnavailableDecision = authorize({
        vaults: [{ vault_id: vaultId, persona_active_key: persona, signers: [] }],
    });
    const metadataWideningDecision = authorize({
        client_metadata: {
            requested_methods: ["sign_event", "get_public_key"],
            requested_event_kinds: [1],
            requested_signer_audiences: [audience],
        },
    });
    const invalidNip46Decision = authorize({
        request: {
            ...signingRequest,
            rpc_request: { ...signingRequest.rpc_request, id: "invalid\nrequest" },
        },
    });
    const usageMismatchDecision = authorize({
        usage_state: { ...usageState, grant_digest: "00".repeat(32) },
    });
    const personaGrantUnsigned: Omit<SigningGrant, "signature"> = {
        ...unsignedGrant,
        selected_signing_pubkey: persona,
        key_class: "persona",
        persona_signing_authorized: true,
        automation_policy: {
            workload_id: "aa".repeat(32),
            agent_class: "ai",
            agent_association: null,
            tier: 1,
            oidc_scopes: [],
        },
    };
    const personaGrant: SigningGrant = {
        ...personaGrantUnsigned,
        signature: bytesToHex(schnorr.sign(signerGrantProofBytes(personaGrantUnsigned), hexToBytes(personaSecret), "00".repeat(32))),
    };
    const personaAuthorityInput: Parameters<typeof prepareAutomatedSigning>[0] = {
        authorization: {
            grant_candidates: [personaGrant],
            usage_state: {
                ...usageState,
                grant_digest: signerGrantStateDigest(personaGrant),
                authority: {
                    ...usageState.authority,
                    selected_signing_pubkey: persona,
                    key_class: "persona",
                },
            },
            presented_grant: structuredClone(personaGrant),
            vaults: [{
                    vault_id: vaultId,
                    persona_active_key: persona,
                    signers: [{ public_key: persona, key_class: "persona", custody: "local" }],
                }],
            request: {
                ...signingRequest,
                selected_signing_pubkey: persona,
                key_class: "persona",
            },
            client_metadata: {
                requested_methods: ["sign_event"],
                requested_event_kinds: [1],
                requested_signer_audiences: [audience],
            },
        },
        publication: {
            ...automatedPublication,
            grant_id: personaGrant.grant_id,
            selected_signing_pubkey: persona,
            key_class: "persona",
            agent_association: null,
        },
    };
    const personaAuthorityDecision = prepareAutomatedSigning(personaAuthorityInput);
    const operationIndeterminateInput = {
        ...automationAuthorizationInput,
        usage_state: persistedAutomationUsage,
    };
    const operationIndeterminateDecision = authorizeNip46Signing(operationIndeterminateInput);
    const operationConflictRequest = {
        ...automationRequest,
        rpc_request: {
            ...automationRequest.rpc_request,
            params: [jcsCanonicalize({
                    created_at: automatedPublication.created_at,
                    kind: automatedPublication.kind,
                    tags: automatedAttribution.tags,
                    content: "different canonical request bytes",
                })],
        },
    };
    const operationConflictInput = {
        ...automationAuthorizationInput,
        usage_state: persistedAutomationUsage,
        request: operationConflictRequest,
    };
    const operationConflictDecision = authorizeNip46Signing(operationConflictInput);
    const oneRequestUnsigned: Omit<SigningGrant, "signature"> = {
        ...unsignedGrant,
        limits: { ...unsignedGrant.limits, request_count: 1 },
    };
    const oneRequestGrant: SigningGrant = {
        ...oneRequestUnsigned,
        signature: bytesToHex(schnorr.sign(signerGrantProofBytes(oneRequestUnsigned), hexToBytes(personaSecret), "00".repeat(32))),
    };
    const oneRequestUsage = {
        ...usageState,
        grant_digest: signerGrantStateDigest(oneRequestGrant),
    };
    const oneRequestInput = {
        grant_candidates: [oneRequestGrant],
        usage_state: oneRequestUsage,
        presented_grant: structuredClone(oneRequestGrant),
        vaults: [{
                vault_id: vaultId,
                persona_active_key: persona,
                signers: [{ public_key: agentSigner, key_class: "agent" as const, custody: "local" as const }],
            }],
        request: signingRequest,
        client_metadata: {
            requested_methods: ["sign_event"],
            requested_event_kinds: [1],
            requested_signer_audiences: [audience],
        },
    };
    const oneReservation = authorizeNip46Signing(oneRequestInput);
    if (oneReservation.verdict !== "accept")
        throw new Error("one-request rate fixture rejected");
    const oneTransition = oneReservation.usage_transition;
    const saturatedUsage = {
        ...oneRequestUsage,
        window_started_at: oneTransition.window_started_at,
        consumed_request_count: oneTransition.consumed_request_count,
        revision: oneTransition.next_revision,
        reservations: [{
                operation_id: oneTransition.operation_id,
                request_id: oneTransition.request_id,
                request_digest: oneTransition.request_digest,
                rpc_request: oneTransition.rpc_request,
                value_msats: oneTransition.value_msats,
                window_started_at: oneTransition.window_started_at,
                reserved_at: oneTransition.reserved_at,
                claimed_at: null,
                executing_at: null,
                completed_at: null,
                state: "reserved" as const,
                execution_token: null,
                result_event_id: null,
                failure_digest: null,
            }],
    };
    const rateLimitedRequest = {
        ...signingRequest,
        now: signingRequest.now + 1,
        rpc_request: { ...signingRequest.rpc_request, id: "ee".repeat(32) },
    };
    const signingRateInput = {
        ...oneRequestInput,
        usage_state: saturatedUsage,
        request: rateLimitedRequest,
    };
    const signingRateDecision = authorizeNip46Signing(signingRateInput);
    const missingReservationInput = {
        authorization: automationAuthorizationInput,
        publication: automatedPublication,
    };
    const missingReservationDecision = prepareAutomatedSigning(missingReservationInput);
    const invalidIntentInput = {
        authorization: { ...automationAuthorizationInput, usage_state: persistedAutomationUsage },
        publication: { ...automatedPublication, extra: true } as never,
    };
    const invalidIntentDecision = prepareAutomatedSigning(invalidIntentInput);
    const missingAttributionInput = {
        authorization: {
            grant_candidates: [signingGrant],
            usage_state: usageState,
            presented_grant: structuredClone(signingGrant),
            vaults: oneRequestInput.vaults,
            request: signingRequest,
            client_metadata: oneRequestInput.client_metadata,
        },
        publication: automatedPublication,
    };
    const missingAttributionDecision = prepareAutomatedSigning(missingAttributionInput);
    const attributionBindingInput: Parameters<typeof prepareAutomatedSigning>[0] = {
        authorization: { ...automationAuthorizationInput, usage_state: persistedAutomationUsage },
        publication: { ...automatedPublication, agent_class: "programmatic" },
    };
    const attributionBindingDecision = prepareAutomatedSigning(attributionBindingInput);
    const executionFenceInput = {
        authorization: { ...automationAuthorizationInput, usage_state: persistedAutomationUsage },
        publication: automatedPublication,
        signer_execution: {
            executeOnce: () => ({ verdict: "conflict" as const }),
        },
    };
    const executionFenceDecision = executePersistedAutomatedSigning(executionFenceInput);
    const connectionState = {
        profile: "heterodyne.control.device-authorization-state.v1" as const,
        spec_version: QUALIFIED_VERSION as typeof QUALIFIED_VERSION,
        transaction_id: "10".repeat(32),
        grant_id: signingGrant.grant_id,
        oidc_authorization_id: signingGrant.oidc_authorization_id,
        persona_active_key: signingGrant.persona_active_key,
        nip46_client_pubkey: signingGrant.nip46_client_pubkey,
        signer_audience: signingGrant.signer_audience,
        selected_signing_pubkey: signingGrant.selected_signing_pubkey,
        key_class: signingGrant.key_class,
        requested_methods: [...signingGrant.allowed_methods],
        requested_event_kinds: [...signingGrant.allowed_event_kinds],
        requested_limits: { ...signingGrant.limits },
        connection_secret_sha256: signingGrant.connection_secret_sha256,
        connection_secret_state: "pending" as const,
        device_code_sha256: "11".repeat(32),
        device_code_entropy_bits: 128,
        user_code_sha256: "12".repeat(32),
        user_code_entropy_bits: 35,
        normalization: "uppercase-ascii-remove-hyphen" as const,
        client_fingerprint: "current-client-fingerprint",
        failed_guesses: 0,
        max_failed_guesses: 5 as const,
        interval_seconds: 5,
        issued_at: 100,
        expires_at: 200,
        state: "approved" as const,
        revision: 1,
    };
    const activation = {
        transaction_id: connectionState.transaction_id,
        grant_id: signingGrant.grant_id,
        oidc_authorization_id: signingGrant.oidc_authorization_id,
        persona_active_key: signingGrant.persona_active_key,
        nip46_client_pubkey: signingGrant.nip46_client_pubkey,
        signer_audience: signingGrant.signer_audience,
        selected_signing_pubkey: signingGrant.selected_signing_pubkey,
        key_class: signingGrant.key_class,
        presented_connection_secret: connectionSecret,
    };
    const invalidConnectionInput = {
        current_state: connectionState,
        grant_candidates: [signingGrant],
        activation: { ...activation, presented_connection_secret: "08".repeat(32) },
        now: 110,
    };
    const invalidConnectionDecision = consumeNip46ConnectionSecret(invalidConnectionInput);
    const activationMismatchInput = {
        current_state: connectionState,
        grant_candidates: [signingGrant],
        activation: { ...activation, transaction_id: "13".repeat(32) },
        now: 110,
    };
    const activationMismatchDecision = consumeNip46ConnectionSecret(activationMismatchInput);
    const reusedConnectionInput: Parameters<typeof consumeNip46ConnectionSecret>[0] = {
        current_state: {
            ...connectionState,
            connection_secret_state: "consumed",
            state: "consumed",
        },
        grant_candidates: [signingGrant],
        activation,
        now: 110,
    };
    const reusedConnectionDecision = consumeNip46ConnectionSecret(reusedConnectionInput);
    const enrollmentBase = {
        keypackage_valid: true,
        member_count: 2,
        node_account_matches: true,
        entitlement_state: "none" as const,
        resource_available: true,
        welcome_rate_remaining: 1,
        replenishment_requested: false,
        replenishment_rate_remaining: 1,
        pending_at_cap: false,
        method: "control.enrollment.start",
    };
    const deviceBase = { entropy_valid: true, failed_guesses: 0, rate_allowed: true, display_binding_matches: true };
    const automatedBase = {
        method_allowed: true,
        private_key_requested: false,
        human_key_profile_selected: false,
        attribution_canonical: true,
        resource_allowed: true,
        event_bytes: 100,
        max_event_bytes: 200,
        rate_remaining: 1,
    };
    const resetBase = {
        authority_signature_valid: true,
        inventory_digest_matches: true,
        transition_evidence_valid: true,
        subordinate_reauthorized: true,
    };
    const reasonCases: CurrentCaseFixture[] = [
        ...[
            ["signing-grant-invalid", { grant_candidates: [] }],
            ["signing-grant-unauthenticated", { grant: unauthenticatedGrant }],
            ["signing-grant-stale", { grant_ids: [signingGrant.grant_id, signingGrant.grant_id] }],
            ["signing-grant-inactive", { now: signingGrant.expires_at }],
            ["vault-isolation-failed", { vaults: [] }],
            ["signer-binding-mismatch", { selected_signing_pubkey: "55".repeat(32) }],
            ["persona-authority-required", { grant: personaGrant }],
            ["signer-unavailable", { signers: [] }],
            ["client-metadata-widening", { requested_methods: ["sign_event", "get_public_key"] }],
            ["nip46-request-invalid", { request_id: "invalid\\nrequest" }],
            ["usage-binding-mismatch", { grant_digest: "00".repeat(32) }],
            ["operation-conflict", { request: operationConflictRequest }],
            ["operation-indeterminate", { reservation_state: "reserved" }],
            ["signing-rate-limited", { request_count: 1, consumed_request_count: 1 }],
            ["operation-reservation-required", { reservations: [] }],
            ["agent-intent-invalid", { publication_extra_member: true }],
            ["attribution-required", { automation_policy: null }],
            ["attribution-binding-mismatch", { agent_class: "programmatic" }],
            ["operation-execution-fence-required", { reservation_state: "reserved" }],
            ["connection-secret-invalid", { presented_connection_secret: "08".repeat(32) }],
            ["activation-binding-mismatch", { transaction_id: "13".repeat(32) }],
            ["connection-secret-reused", { connection_secret_state: "consumed" }]
        ].map(([id, input]) => ({
            vector_id: "control/" + String(String(id)),
            description: `The live Control authorization boundary rejects ${String(id).replaceAll("-", " ")}.`,
            direction: "consume" as const,
            input: input as Record<string, unknown>
        })),
        ...[
            ["keypackage-invalid", { ...enrollmentBase, keypackage_valid: false }],
            ["entitlement-conflict", { ...enrollmentBase, entitlement_state: "revoked" as const }],
            ["enrollment-unavailable", { ...enrollmentBase, resource_available: false }],
            ["keypackage-replenishment-paused", { ...enrollmentBase, replenishment_requested: true, pending_at_cap: true }],
            ["enrollment-rate-limited", { ...enrollmentBase, welcome_rate_remaining: 0 }],
            ["enrollment-required", { ...enrollmentBase, method: "sign_event" }],
            ["device-code-invalid", { ...deviceBase, entropy_valid: false }],
            ["device-code-rate-limited", { ...deviceBase, rate_allowed: false }],
            ["device-code-display-mismatch", { ...deviceBase, display_binding_matches: false }],
            ["invite-preauthorization-invalid", { purpose_bound: false, finite_template: true, client_bound: true }],
            ["frame-invalid", { closed_schema_valid: false, token_valid: true, refresh_requested: false }],
            ["refresh-prohibited", { closed_schema_valid: true, token_valid: true, refresh_requested: true }],
            ["token-invalid", { closed_schema_valid: true, token_valid: false, refresh_requested: false }],
            ["request-expired", { now: 100, expires_at: 100, request_id_reused: false, request_digest_matches: true }],
            ["request-id-conflict", { now: 100, expires_at: 101, request_id_reused: true, request_digest_matches: false }],
            ["agent-method-prohibited", { ...automatedBase, method_allowed: false }],
            ["agent-key-access-prohibited", { ...automatedBase, private_key_requested: true }],
            ["agent-human-profile-prohibited", { ...automatedBase, human_key_profile_selected: true }],
            ["agent-attribution-bypass-prohibited", { ...automatedBase, attribution_canonical: false }],
            ["agent-resource-denied", { ...automatedBase, resource_allowed: false }],
            ["agent-size-exceeded", { ...automatedBase, event_bytes: 201 }],
            ["agent-rate-limited", { ...automatedBase, rate_remaining: 0 }],
            ["signed-event-invalid", { canonical_event_valid: false, fields_exact: true, effect_certain: true }],
            ["signer-effect-indeterminate", { canonical_event_valid: true, fields_exact: true, effect_certain: false }],
            ["compromise-reset-unauthenticated", { ...resetBase, authority_signature_valid: false }],
            ["compromise-reset-inventory-mismatch", { ...resetBase, inventory_digest_matches: false }],
            ["compromise-reset-evidence-invalid", { ...resetBase, transition_evidence_valid: false }],
            ["subordinate-reauthorization-required", { ...resetBase, subordinate_reauthorized: false }]
        ].map(([id, input]) => ({
            vector_id: "control/" + String(String(id)),
            description: `The current Control policy boundary rejects ${String(id).replaceAll("-", " ")}.`,
            direction: "consume" as const,
            input: input as Record<string, unknown>
        })),
    ];
    const boundaryArgs = new Map<string, readonly unknown[]>([
        ["control/signing-grant-invalid", [authorizationInput({ grant_candidates: [] })]],
        ["control/signing-grant-unauthenticated", [authorizationInput({
                    grant_candidates: [unauthenticatedGrant],
                    presented_grant: unauthenticatedGrant,
                })]],
        ["control/signing-grant-stale", [authorizationInput({
                    grant_candidates: [signingGrant, signingGrant],
                })]],
        ["control/signing-grant-inactive", [authorizationInput({
                    request: { ...signingRequest, now: signingGrant.expires_at },
                })]],
        ["control/vault-isolation-failed", [authorizationInput({ vaults: [] })]],
        ["control/signer-binding-mismatch", [authorizationInput({
                    request: { ...signingRequest, selected_signing_pubkey: "55".repeat(32) },
                })]],
        ["control/persona-authority-required", [personaAuthorityInput]],
        ["control/signer-unavailable", [authorizationInput({
                    vaults: [{ vault_id: vaultId, persona_active_key: persona, signers: [] }],
                })]],
        ["control/client-metadata-widening", [authorizationInput({
                    client_metadata: {
                        requested_methods: ["sign_event", "get_public_key"],
                        requested_event_kinds: [1],
                        requested_signer_audiences: [audience],
                    },
                })]],
        ["control/nip46-request-invalid", [authorizationInput({
                    request: {
                        ...signingRequest,
                        rpc_request: { ...signingRequest.rpc_request, id: "invalid\nrequest" },
                    },
                })]],
        ["control/usage-binding-mismatch", [authorizationInput({
                    usage_state: { ...usageState, grant_digest: "00".repeat(32) },
                })]],
        ["control/operation-conflict", [operationConflictInput]],
        ["control/operation-indeterminate", [operationIndeterminateInput]],
        ["control/signing-rate-limited", [signingRateInput]],
        ["control/operation-reservation-required", [missingReservationInput]],
        ["control/agent-intent-invalid", [invalidIntentInput]],
        ["control/attribution-required", [missingAttributionInput]],
        ["control/attribution-binding-mismatch", [attributionBindingInput]],
        ["control/operation-execution-fence-required", [executionFenceInput]],
        ["control/connection-secret-invalid", [invalidConnectionInput]],
        ["control/activation-binding-mismatch", [activationMismatchInput]],
        ["control/connection-secret-reused", [reusedConnectionInput]],
        ["control/opaque-authorization-view-accepted", [acceptedEffectPrepared.view]],
        ["control/caller-freshness-booleans-rejected", [{
                    now: state.checkpoint.observed_at + 300,
                    checkpoint_fresh: true,
                    authorization_view_authenticated: true,
                }, manifest]],
        ["control/authorization-view-stale-at-effect", [prepared.view]],
        ["control/exact-signer-grant-reserved", [authorizationInput({})]],
        ["control/automation-attributed-before-signing", [automatedSigningInput]],
    ]);
    const cases: CurrentCaseFixture[] = [
        ...reasonCases,
        {
            vector_id: "control/opaque-authorization-view-accepted",
            description: "An opaque view issued by the trusted freshness authority is accepted at mutation effect.",
            direction: "consume",
            input: {
                manifest,
                ledger_state: state,
                trusted_now: state.checkpoint.observed_at + 300,
                current_authorization_view: "opaque",
            }
        },
        {
            vector_id: "control/caller-freshness-booleans-rejected",
            description: "Caller-authored freshness booleans cannot substitute for an opaque authorization view.",
            direction: "consume",
            input: {
                manifest,
                now: state.checkpoint.observed_at + 300,
                checkpoint_fresh: true,
                authorization_view_authenticated: true,
            }
        },
        {
            vector_id: "control/authorization-view-stale-at-effect",
            description: "A view prepared at its boundary is rejected when it becomes stale before mutation effect.",
            direction: "consume",
            input: {
                manifest,
                prepared_at: state.checkpoint.observed_at + 300,
                effected_at: state.checkpoint.observed_at + 301,
                current_authorization_view: "opaque",
            }
        },
        {
            vector_id: "control/exact-signer-grant-reserved",
            description: "A domain-separated active-key grant resolves exactly one persona vault and signer, then durably reserves the canonical NIP-46 request before any key effect.",
            direction: "consume",
            input: {
                grant: signingGrant,
                usage_state: usageState,
                request: signingRequest,
            }
        },
        {
            vector_id: "control/automation-attributed-before-signing",
            description: "A reserved automated intent is exact-grant bound, receives canonical Comms attribution, and advances to a durable claim transition before signer execution.",
            direction: "produce",
            input: {
                publication: automatedPublication,
                grant: automationGrant,
                usage_state: persistedAutomationUsage,
            }
        },
        {
            vector_id: "control/compromise-reset-closure-required",
            description: "A reset without a signed authoritative inventory, successor completion, leaf removals, group advances, and fresh KeyPackages is rejected before state changes.",
            direction: "consume",
            input: incompleteResetInput
        },
    ];
    return cases.map((fixture) => ({
        ...fixture,
        ...(boundaryArgs.has(fixture.vector_id)
            ? { boundary_args: boundaryArgs.get(fixture.vector_id) }
            : {}),
    }));
}
