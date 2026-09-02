import { createHash, createPrivateKey, sign, type JsonWebKey } from "node:crypto";
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
import {
    registerPrivateCurrentFixture,
} from "./boundary-runners.js";
import { definePrivateCurrentFixtureSpecification } from "./private-fixture-specification.js";
import { controlFrameContext, controlResetEvidenceFixtures, controlSignerEvidenceFixture, reconstructControlSignerEvidenceFixture, controlSignerInvocationCount, signedControlFrameBytes } from "../control-security-evidence.js";
import { createControlDeviceAuthorizationAuthority, type ControlDeviceTransactionRequest } from "../control-device-authorization.js";
import { createControlEnrollmentAdmissionAuthority, type ControlEnrollmentAdmissionRequest, type ControlEnrollmentReservationStore } from "../control-enrollment-admission.js";
import { createControlInvitePreauthorizationAuthority, type ControlInviteTemplate, type ControlInviteRequest } from "../control-invite-preauthorization.js";
import { descriptorDigest, responseProof, secretCommitment, type InviteDescriptor, type InviteEnvelope, type InviteResponseInput } from "../one-time-invite.js";
import type { DurableAuthorityRecord, DurableAuthorityStore } from "../security-authority-support.js";
import { buildFixtures } from "../fixtures.js";
import { buildLiveOidcScenario } from "../oidc-test-support.js";
import { CHECKPOINT_CLAIM, createValidatedProjectedJwtContext, projectAccessToken } from "../oidc.js";
import { OIDC_RSA_ONE } from "../oidc-rsa-fixtures.js";
import { continuityManifestDigest, createContinuityAuthorityProof, createCurrentControlGrantResolver, createCurrentControlGrantView, generateStatusListToken, resolveCurrentControlGrant, validateIssuerContinuityChain, type ContinuityManifestBody } from "../token-status.js";
import { createAuthorizationFreshnessAuthority } from "../authorization-freshness.js";
import { proofBytes } from "../proof-bytes.js";
import type { ControlAuthorizationObject, ControlAuthorizationRecord } from "../control-profile.js";
import { currentControlFrameRequestDigest } from "../profile-negotiation.js";
import { createControlTokenVerifier, type ControlTokenOperation, type ControlTokenUse } from "../control-token-verifier.js";
import { utf8Bytes } from "../hex.js";
const CONTROL_PRIVATE_FIXTURES = definePrivateCurrentFixtureSpecification([
    ...controlResetEvidenceFixtures().map(({ expected_reason }) =>
        expected_reason.replace(/^control-/u, "control/")
    ),
    "control/signer-effect-indeterminate",
    "control/frame-invalid",
    "control/device-code-invalid",
    "control/device-code-rate-limited",
    "control/device-code-display-mismatch",
    "control/keypackage-invalid",
    "control/enrollment-unavailable",
    "control/keypackage-replenishment-paused",
    "control/invite-preauthorization-invalid",
    "control/token-invalid",
]);
const normalizeReason = <T extends Record<string, unknown>>(value: T): Record<string, unknown> => "reason" in value ? (() => {
    const { reason, ...decision } = value;
    return { ...decision, reason_code: reason };
})() : value;

type DevicePublicState = Readonly<{ transaction_id: string; state: "pending" | "approved" | "denied" | "expired" }>;
class CurrentDeviceStore implements DurableAuthorityStore<DevicePublicState> {
    readonly records = new Map<string, DurableAuthorityRecord<DevicePublicState>>();
    async load(key: string) { return this.records.get(key) ?? null; }
    async compareAndSwap(input: { key: string; expected_revision: number | null; next: DurableAuthorityRecord<DevicePublicState> }) {
        if ((this.records.get(input.key)?.revision ?? null) !== input.expected_revision) return "conflict" as const;
        this.records.set(input.key, input.next); return "committed" as const;
    }
    async acquire(input: { key: string; expected_revision: number | null; binding_digest: string; execution_token: string }) {
        const current = this.records.get(input.key);
        if (current?.state !== "available" || current.revision !== input.expected_revision || current.binding_digest !== input.binding_digest) return "conflict" as const;
        this.records.set(input.key, Object.freeze({ state: "executing" as const, revision: current.revision + 1, binding_digest: input.binding_digest, execution_token: input.execution_token }));
        return "acquired" as const;
    }
    async commit(input: { key: string; binding_digest: string; execution_token: string; output_digest: string; output: DevicePublicState }) {
        const current = this.records.get(input.key);
        if (current?.state !== "executing" || current.binding_digest !== input.binding_digest || current.execution_token !== input.execution_token) return "conflict" as const;
        this.records.set(input.key, Object.freeze({ state: "committed" as const, revision: current.revision + 1, binding_digest: input.binding_digest, execution_token: input.execution_token, output_digest: input.output_digest, output: input.output })); return "committed" as const;
    }
    async markIndeterminate(input: { key: string; binding_digest: string; execution_token: string; reconciliation_digest: string }) {
        const current = this.records.get(input.key);
        if (current?.state !== "executing") return "conflict" as const;
        this.records.set(input.key, Object.freeze({ state: "indeterminate" as const, revision: current.revision + 1, binding_digest: input.binding_digest, execution_token: input.execution_token, reconciliation_digest: input.reconciliation_digest }));
        return "indeterminate" as const;
    }
}

function buildCurrentDeviceFixture() {
    const clock = { now: 1_900_000_000 };
    let seed = 1;
    const store = new CurrentDeviceStore();
    const authority = createControlDeviceAuthorizationAuthority({
        authority_id: "synthetic-local-current-device-authority",
        trusted_now: () => clock.now,
        random_bytes: (length) => Uint8Array.from({ length }, (_, index) => (seed + index) & 0xff, seed++),
        store,
    });
    const request: ControlDeviceTransactionRequest = Object.freeze({
        client_id: "synthetic-local-current-client", persona: "synthetic-local-current-persona",
        verification_uri: "https://device.invalid/activate", display_fingerprint: "SYNTHETIC-CURRENT-FINGERPRINT",
        polling_interval_seconds: 5, expires_in_seconds: 600, failure_budget: 5,
    });
    return Object.freeze({ authority, request, clock, store });
}

type CurrentInventory = Awaited<ReturnType<Parameters<typeof createControlEnrollmentAdmissionAuthority>[0]["load_inventory"]>>;
type CurrentInvite = Awaited<ReturnType<Parameters<typeof createControlEnrollmentAdmissionAuthority>[0]["load_invite_state"]>>;
class CurrentEnrollmentStore implements ControlEnrollmentReservationStore {
    reserveCalls = 0;
    async load() { return null; }
    async reserve() { this.reserveCalls += 1; return "unavailable" as const; }
    async commit() { return "conflict" as const; }
    async markIndeterminate() { return "conflict" as const; }
}
function buildCurrentEnrollmentFixture(kind: "invalid" | "unavailable" | "paused") {
    const inventory: CurrentInventory = Object.freeze({
        revision: 7, pending_for_account: kind === "unavailable" ? 1 : 0,
        global_pending: kind === "unavailable" ? 2 : 0, global_pending_cap: 2,
        reserved_slots: Object.freeze(["synthetic-local-slot-A"]), replenishment_state: kind === "paused" ? "paused" : "ready",
        current_clients: Object.freeze([]), enrolled_accounts: Object.freeze([]), enrolled_devices: Object.freeze([]),
        rate_window_started_at: 900, attempts_in_window: 0, attempt_budget: 5,
    });
    const invite: CurrentInvite = Object.freeze({ revision: 3, purpose: "control-enrollment", state: "active", account: "synthetic-local-account-A", client_key: "synthetic-local-client-key-A", expires_at: 1_100 });
    const store = new CurrentEnrollmentStore();
    const authority = createControlEnrollmentAdmissionAuthority({
        authority_id: `synthetic-local-current-enrollment-${kind}`, trusted_now: () => 1_000,
        store, load_inventory: async () => inventory,
        load_invite_state: async () => invite,
        verify_key_package: (bytes) => kind === "invalid" || Buffer.from(bytes).toString("hex") !== "01020304" ? null : Object.freeze({ account: invite.account, reference: "synthetic-local-keypackage-ref-A", expires_at: 1_100 }),
    });
    const request: ControlEnrollmentAdmissionRequest = Object.freeze({
        persona: "synthetic-local-persona-A", account: invite.account, device_id: "synthetic-local-device-A",
        client_key: invite.client_key, group_id: "synthetic-local-group-A", invite_id: "synthetic-local-invite-A",
        invite_purpose: "control-enrollment", key_package_bytes: Uint8Array.from([1, 2, 3, 4]),
        expected_key_package_ref: "synthetic-local-keypackage-ref-A", reserved_slot: "synthetic-local-slot-A",
    });
    return Object.freeze({ authority, request, store, evidence: Object.freeze({ inventory, invite }) });
}

function buildCurrentInvalidInviteFixture() {
    const inviterSecret = "01".padStart(64, "0");
    const inviter = bytesToHex(schnorr.getPublicKey(inviterSecret));
    const template: ControlInviteTemplate = Object.freeze({ persona: "persona:alice", audience: "nip46://signer.invalid", client_key: "22".repeat(32), client_class: "human-light", methods: Object.freeze(["sign_event"]), event_kinds: Object.freeze([1]), limits: Object.freeze({ requests_per_hour: 10, max_content_bytes: 4096 }), signer: inviter, expires_at: 1_600 });
    const descriptor: InviteDescriptor = Object.freeze({ version: 1, purpose: "control-enrollment", inviter_account: inviter, invite_id: "11".repeat(32), rendezvous_pubkey: "44".repeat(32), relay_hints: ["wss://relay.invalid"], issued_at: 1_000, expires_at: template.expires_at, secret_sha256: secretCommitment("33".repeat(32)), approval_mode: "preauthorized", preauthorization: template as unknown as Record<string, unknown>, expected_client_pubkey: template.client_key });
    const envelope: InviteEnvelope = Object.freeze({ descriptor, signature: bytesToHex(schnorr.sign(descriptorDigest(descriptor), inviterSecret, new Uint8Array(32))), secret: "33".repeat(32) });
    const response: InviteResponseInput = Object.freeze({ now: 0, expires_at: 1_600, expected_purpose: "control-enrollment", response_purpose: "control-enrollment", descriptor_valid: false, secret_commitment_valid: false, seal_valid: false, seal_pubkey: template.client_key, rumor_pubkey: template.client_key, proof_valid: false, keypackage_valid: false, capabilities_compatible: false, response_digest: "55".repeat(32), group_established: false });
    const requestWithoutProof = { purpose: "control-enrollment" as const, persona: template.persona, audience: "nip46://different.invalid", client_key: template.client_key, client_class: template.client_class, response };
    const secretProof = responseProof(envelope.secret, { invite_id: descriptor.invite_id, descriptor_digest: bytesToHex(descriptorDigest(descriptor)), template_digest: createHash("sha256").update(jcsCanonicalize(template)).digest("hex"), purpose: requestWithoutProof.purpose, persona: requestWithoutProof.persona, audience: requestWithoutProof.audience, client_key: requestWithoutProof.client_key, client_class: requestWithoutProof.client_class, response_now: response.now, response_expires_at: response.expires_at, response_expected_purpose: response.expected_purpose, response_purpose: response.response_purpose, response_seal_pubkey: response.seal_pubkey, response_rumor_pubkey: response.rumor_pubkey, response_digest: response.response_digest });
    const request: ControlInviteRequest = Object.freeze({ ...requestWithoutProof, secret_proof: secretProof });
    const authority = createControlInvitePreauthorizationAuthority({ authority_id: "synthetic-local-current-control-invite", trusted_now: () => 1_200, load_revocation: async () => Object.freeze({ revision: 7, state: "active" as const }) });
    return Object.freeze({ authority, envelope, template, request });
}

async function buildCurrentControlTokenEvidence() {
    const fixtures = buildFixtures();
    const sender = "2JF8vg9etJzjFwZwmkvhBLLZ0bfMVVOPivYR5lFtcec";
    const group = "33".repeat(32), authorizationId = "44".repeat(32), grantSecret = "17".repeat(32);
    const grantSigner = bytesToHex(schnorr.getPublicKey(hexToBytes(grantSecret)));
    const object = Object.freeze({ class: "config_namespace", id: "ui" }) as ControlAuthorizationObject;
    const live = await buildLiveOidcScenario(fixtures, { sender_constraint: "dpop", cnf: { jkt: sender } });
    const state = live.issuedState, now = state.checkpoint.observed_at;
    const statusUri = `${live.metadata.issuer}/${live.issuance.reservation.uri}`;
    const statusList = generateStatusListToken({ state, uri: statusUri, private_jwk: OIDC_RSA_ONE.private_jwk, iat: now, exp: now + 600, ttl: 300 });
    const jwksBytes = utf8Bytes(jcsCanonicalize({ keys: [OIDC_RSA_ONE.public_jwk] }));
    const digest = (value: Uint8Array | string) => createHash("sha256").update(value).digest("hex");
    const body: ContinuityManifestBody = { profile: "heterodyne-oidc-continuity-v1", repository_rid: live.s.rid, branch: "main", persona_npub: live.personaNpub, persona_key: live.personaKey, issuer: live.metadata.issuer, sequence: 0, predecessor_digest: null, max_checkpoint_age_seconds: 300, authorization_view_max_age: 300, current_jwks_sha256: digest(jwksBytes), current_signing_key_id: OIDC_RSA_ONE.key_id, current_signing_jwk_sha256: digest(utf8Bytes(jcsCanonicalize(OIDC_RSA_ONE.public_jwk))), retiring_signing_key_ids: [], retiring_jwks_sha256: [], status_lists: [{ path: live.projectionContext.status_mirror.path, sha256: digest(statusList.compact), issuer: live.metadata.issuer, uri: statusUri }], successor: null, authority: { writer_nid: live.s.writerOne.did_key, issued_at: now, checkpoint: state.checkpoint } };
    const manifest = { ...body, authority_proof: createContinuityAuthorityProof(body, live.s.writerOne.private_key) };
    const projected = projectAccessToken(await live.authorizeProjection("access_token", { ...live.projectionContext, status_mirror: { ...live.projectionContext.status_mirror, sha256: continuityManifestDigest(manifest) } }));
    const [encodedHeader, encodedClaims] = projected.compact.split(".");
    const claims = JSON.parse(Buffer.from(encodedClaims!, "base64url").toString("utf8")) as Record<string, unknown>;
    Object.assign(claims, { scope: "control", group_id: group, authorization_id: authorizationId, grant_generation: state.credential_ledger.credential_ledger_generation, client_class: "automated", methods: ["config.get"], objects: [object], registry_checkpoint: state.checkpoint.commit_oid, [CHECKPOINT_CLAIM]: state.checkpoint });
    const nextClaims = Buffer.from(JSON.stringify(claims)).toString("base64url"), signingInput = `${encodedHeader}.${nextClaims}`;
    const compact = `${signingInput}.${sign("RSA-SHA256", Buffer.from(signingInput), createPrivateKey({ key: OIDC_RSA_ONE.private_jwk as JsonWebKey, format: "jwk" })).toString("base64url")}`;
    const validatedJwt = createValidatedProjectedJwtContext(compact, live.metadata.issuer, "https://api.example", { keys: [OIDC_RSA_ONE.public_jwk] }, { now, token_use: "access_token", client_id: "registered-client", cnf: { jkt: sender }, sender_constraint: "dpop", permitted_audiences: ["https://api.example"], credential_ledger: state.credential_ledger });
    const continuity = validateIssuerContinuityChain([{ manifest, context: { identity: live.identity, repository_rid: live.s.rid, canonical_branch: "main", writer_nid: live.s.writerOne.did_key, now, ledger_state: state, succession_authority: null, active_persona_authority: null } }]);
    const freshnessAuthority = createAuthorizationFreshnessAuthority({ repository_rid: live.s.rid, persona_key: live.personaKey, manifest_digest: continuityManifestDigest(manifest) }, { trusted_now: () => now, load_current_view: () => ({ manifest, ledger_state: state }) });
    const prepared = evaluateAuthorizationFreshness(freshnessAuthority, manifest);
    if (prepared.verdict !== "accept") throw new Error(`current token freshness rejected: ${prepared.reason}`);
    const unsignedGrant = { record_id: authorizationId, persona: state.credential_ledger.credential_ledger_persona, client_key: sender, client_class: "automated" as const, approving_node: grantSigner, approving_authority: "interactive-oidc", methods: ["config.get"], objects: [object], limits: { calls: 5 }, capabilities: [] as ControlAuthorizationRecord["capabilities"], token_lifetime_default_seconds: 300 as const, token_lifetime_max_seconds: 3600, inbound_execution: false, predecessor: null, state: "active" as const, created_at: Number(validatedJwt.claims.iat), expires_at: Number(validatedJwt.claims.exp), signer: grantSigner };
    const grant: ControlAuthorizationRecord = { ...unsignedGrant, signature: bytesToHex(schnorr.sign(proofBytes("heterodyne-control-authorization-record-v1", unsignedGrant), hexToBytes(grantSecret), "00".repeat(32))) };
    const resolver = createCurrentControlGrantResolver({ authority_id: "synthetic-local-current-control-token", trusted_now: () => now, expected_signer: grantSigner, load_current_grant: async (id) => id === authorizationId ? grant : null });
    const resolved = await resolveCurrentControlGrant(resolver, authorizationId);
    if (resolved.verdict !== "accept") throw new Error("current token grant rejected");
    const view = createCurrentControlGrantView({ authorization_view: prepared.view, grant: resolved.output, validated_jwt: validatedJwt, status_list: statusList, status_jwks_bytes: jwksBytes, status_resolved_at: now, continuity });
    const store = new CurrentDeviceStore() as unknown as DurableAuthorityStore<Readonly<{ operation_id: string }>>;
    let effectCalls = 0;
    const verifier = createControlTokenVerifier({ authority_id: "synthetic-local-current-control-token", trusted_now: () => now, expected_issuer: live.metadata.issuer, expected_audience: "https://api.example", jwks: { keys: [OIDC_RSA_ONE.public_jwk] }, load_grant_view: async () => view, consume_proof: async () => null, store, execute_operation: async (_token, operation) => { effectCalls += 1; return Object.freeze({ operation_id: operation.operation_id }); } });
    const use: ControlTokenUse = Object.freeze({ sender_key: sender, marmot_group_id: group, authorization_id: authorizationId, grant_generation: 0, required_scope: "control", method: "config.get", object, compact_proof: "synthetic-local-current-invalid-proof" });
    const operationId = "synthetic-local-current-operation";
    const payload = { id: operationId, method: "config.get", params: { object, namespace: "ui", value: "dark" }, expires_at: now + 60 };
    const operation: ControlTokenOperation = Object.freeze({ operation_id: operationId, request_digest: currentControlFrameRequestDigest({ profile: "human-jsonrpc", version: QUALIFIED_VERSION, group_id: group, sender, request_id: operationId, expires_at: payload.expires_at, body: payload }), payload });
    return Object.freeze({ verifier, compact, use, operation, store, effectCalls: () => effectCalls });
}
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
    const resetEvidenceByReason = new Map(controlResetEvidenceFixtures().map((fixture) => [
        fixture.expected_reason.replace(/^control-/u, "control/"),
        fixture.input,
    ]));
    const signerEvidence = controlSignerEvidenceFixture();
    const signerRetryEvidence = reconstructControlSignerEvidenceFixture(signerEvidence);
    const invalidFrameBytes = signedControlFrameBytes({ request_digest: "00".repeat(32) });
    const invalidFrameContext = controlFrameContext();
    const deviceInvalidEvidence = buildCurrentDeviceFixture();
    const deviceRateLimitedEvidence = buildCurrentDeviceFixture();
    const deviceDisplayMismatchEvidence = buildCurrentDeviceFixture();
    const enrollmentInvalidEvidence = buildCurrentEnrollmentFixture("invalid");
    const enrollmentUnavailableEvidence = buildCurrentEnrollmentFixture("unavailable");
    const enrollmentPausedEvidence = buildCurrentEnrollmentFixture("paused");
    const inviteEvidence = buildCurrentInvalidInviteFixture();
    const tokenEvidence = await buildCurrentControlTokenEvidence();
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
            ["keypackage-invalid", { evidence: "authenticated KeyPackage verification rejects" }],
            ["entitlement-conflict", { ...enrollmentBase, entitlement_state: "revoked" as const }],
            ["enrollment-unavailable", { evidence: "authenticated current capacity forbids reservation" }],
            ["keypackage-replenishment-paused", { evidence: "authoritative inventory has paused replenishment" }],
            ["enrollment-rate-limited", { ...enrollmentBase, welcome_rate_remaining: 0 }],
            ["enrollment-required", { ...enrollmentBase, method: "sign_event" }],
            ["device-code-invalid", { evidence: "genuine private transaction receives invalid normalized user code" }],
            ["device-code-rate-limited", { evidence: "genuine private transaction is polled before its authoritative interval" }],
            ["device-code-display-mismatch", { evidence: "genuine private transaction receives mismatched authenticated display fingerprint" }],
            ["invite-preauthorization-invalid", { evidence: "signed invite template does not bind the current request audience" }],
            ["frame-invalid", { evidence: "captured signed Control frame fails current profile validation" }],
            ["refresh-prohibited", { closed_schema_valid: true, token_valid: true, refresh_requested: true }],
            ["token-invalid", { evidence: "verified current JWT and grant reject the exact per-use proof before operation" }],
            ["request-expired", { now: 100, expires_at: 100, request_id_reused: false, request_digest_matches: true }],
            ["agent-size-exceeded", { ...automatedBase, event_bytes: 201 }],
            ["agent-rate-limited", { ...automatedBase, rate_remaining: 0 }],
            ["signer-effect-indeterminate", { evidence: "persisted signer execution has an absorbing indeterminate completion fence" }],
            ["compromise-reset-unauthenticated", { evidence: "signed reset grant or completion fails current Assurance binding" }],
            ["compromise-reset-inventory-mismatch", { evidence: "authenticated required-reset inventory differs from signed completion" }],
            ["compromise-reset-evidence-invalid", { evidence: "signed grant and completion carry invalid consecutive transition evidence" }],
            ["subordinate-reauthorization-required", { evidence: "required subordinate fresh authorization is absent" }]
        ].map(([id, input]) => ({
            vector_id: "control/" + String(String(id)),
            description: `The current Control policy boundary rejects ${String(id).replaceAll("-", " ")}.`,
            direction: "consume" as const,
            input: input as Record<string, unknown>
        })),
    ];
    const privateBoundaryArgs = new Map<string, readonly unknown[]>([
        ...[...resetEvidenceByReason].map(([vectorId, input]) => [
            vectorId,
            [input],
        ] as const),
        ["control/signer-effect-indeterminate", [
            signerEvidence.input,
            signerRetryEvidence.input,
            () => controlSignerInvocationCount(signerRetryEvidence),
        ]],
        ["control/frame-invalid", [invalidFrameBytes, invalidFrameContext]],
        ["control/device-code-invalid", [deviceInvalidEvidence.authority, deviceInvalidEvidence.request, deviceInvalidEvidence.clock, "control/device-code-invalid", deviceInvalidEvidence.store]],
        ["control/device-code-rate-limited", [deviceRateLimitedEvidence.authority, deviceRateLimitedEvidence.request, deviceRateLimitedEvidence.clock, "control/device-code-rate-limited", deviceRateLimitedEvidence.store]],
        ["control/device-code-display-mismatch", [deviceDisplayMismatchEvidence.authority, deviceDisplayMismatchEvidence.request, deviceDisplayMismatchEvidence.clock, "control/device-code-display-mismatch", deviceDisplayMismatchEvidence.store]],
        ["control/keypackage-invalid", [enrollmentInvalidEvidence.authority, enrollmentInvalidEvidence.request, enrollmentInvalidEvidence.store, enrollmentInvalidEvidence.evidence]],
        ["control/enrollment-unavailable", [enrollmentUnavailableEvidence.authority, enrollmentUnavailableEvidence.request, enrollmentUnavailableEvidence.store, enrollmentUnavailableEvidence.evidence]],
        ["control/keypackage-replenishment-paused", [enrollmentPausedEvidence.authority, enrollmentPausedEvidence.request, enrollmentPausedEvidence.store, enrollmentPausedEvidence.evidence]],
        ["control/invite-preauthorization-invalid", [inviteEvidence.authority, inviteEvidence.envelope, inviteEvidence.template, inviteEvidence.request]],
        ["control/token-invalid", [tokenEvidence.verifier, tokenEvidence.compact, tokenEvidence.use, tokenEvidence.operation, tokenEvidence.store, tokenEvidence.effectCalls]],
    ]);
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
    return cases.map((fixture) => {
        const privateArgs = privateBoundaryArgs.get(fixture.vector_id);
        if (privateArgs !== undefined) {
            registerPrivateCurrentFixture(CONTROL_PRIVATE_FIXTURES, fixture, privateArgs);
            return fixture;
        }
        const args = boundaryArgs.get(fixture.vector_id);
        return args === undefined ? fixture : { ...fixture, boundary_args: args };
    });
}
