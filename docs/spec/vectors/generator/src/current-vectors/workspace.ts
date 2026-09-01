import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "../hex.js";
import { proofBytes } from "../proof-bytes.js";
import { QUALIFIED_VERSION } from "../family.js";
import { createWorkspaceAssuranceAuthority, evaluateWorkspaceAssuranceTransition, verifyWorkspaceAssuranceAuthorization, type WorkspaceAssuranceAttestationInput, type WorkspaceAssuranceConfig, } from "../workspace-assurance.js";
import { authenticateWorkspaceRepositoryView, evaluateFreshness, evaluatePrivateProjection, evaluateRoleLeafChange, evaluateWorkspaceObject, resolveEffectiveHosts, signWorkspaceObject, workspaceObjectId, } from "../workspace.js";
import { evaluateWorkspaceAffiliationBoundary, evaluateWorkspaceCapabilityBoundary, evaluateWorkspaceResourceDeliveryBoundary, evaluateWorkspaceResourceKeySeparation, evaluateWorkspaceStateTransitionBoundary, } from "../workspace-policy.js";
import { currentSpecRef, type CurrentCaseFixture } from "./types.js";
import {
    registerPrivateCurrentFixture,
} from "./boundary-runners.js";
import { definePrivateCurrentFixtureSpecification } from "./private-fixture-specification.js";
const WORKSPACE_PRIVATE_FIXTURES = definePrivateCurrentFixtureSpecification([
    "workspace/carrier-not-ambient-authority",
    "workspace/current-capability-intersection",
    "workspace/inheritance-escalation-rejected",
    "workspace/invitation-replay",
    "workspace/revocation-blocks-future-effect",
]);
import { buildWorkspaceSecurityFixture, type WorkspaceSecurityFixture } from "../workspace-security-evidence.js";
const WORKSPACE_KEY = "11".repeat(32);
const INCEPTION_EVENT_ID = "22".repeat(32);
const PREVIOUS_POLICY_HEAD = "33".repeat(32);
const NEXT_POLICY_HEAD = "44".repeat(32);
const EVALUATED_AT = 1720000400;
const AUTHORIZATION_SECRET = "55".repeat(32);
const WORKSPACE_SIGNATURE_SECRET = "5a".repeat(32);
const AUX_RAND = "00".repeat(32);
const AUTHORIZATION_KEY = bytesToHex(schnorr.getPublicKey(AUTHORIZATION_SECRET));
const ASSURANCE = Object.freeze({
    profile: "heterodyne.workspace.assurance.v1" as const,
    inception_event_id: INCEPTION_EVENT_ID,
    required_state: "verified" as const,
});
type AssuranceProfile = typeof ASSURANCE;
type Transition = Readonly<{
    workspace_key: string;
    previous_policy_head: string | null;
    next_policy_head: string;
    previous_assurance: AssuranceProfile | null;
    next_assurance: AssuranceProfile | null;
}>;
const transition = (previous_assurance: AssuranceProfile | null, next_assurance: AssuranceProfile | null): Transition => ({
    workspace_key: WORKSPACE_KEY,
    previous_policy_head: PREVIOUS_POLICY_HEAD,
    next_policy_head: NEXT_POLICY_HEAD,
    previous_assurance,
    next_assurance,
});
function signedAuthorization(input: WorkspaceAssuranceAttestationInput) {
    const unsigned = {
        profile: "heterodyne.workspace.assurance-authorization.v1" as const,
        suite: "bip340" as const,
        verification_key: AUTHORIZATION_KEY,
        ...input,
    };
    return {
        ...unsigned,
        signature: bytesToHex(schnorr.sign(proofBytes("heterodyne-workspace-assurance-authorization-v1", unsigned), hexToBytes(AUTHORIZATION_SECRET), hexToBytes(AUX_RAND))),
    };
}
function authority(options: {
    pending?: boolean;
    removal?: boolean;
} = {}) {
    const config: WorkspaceAssuranceConfig = {
        trusted_now: () => EVALUATED_AT,
        resolve_verified_enrollment: ({ workspace_key, inception_event_id, evaluated_at }) => ({
            state: options.pending ? "pending" : "verified",
            active_key: workspace_key,
            inception_event_id,
            evaluated_at,
        }),
        authorize_removal: ({ transition_digest, evaluated_at }) => options.removal
            ? { authorized: true, transition_digest, evaluated_at }
            : undefined,
        attest_transition: signedAuthorization,
    };
    return createWorkspaceAssuranceAuthority(config);
}
export function buildWorkspaceCases(): CurrentCaseFixture[] {
    const bareTransition = transition(null, null);
    const activation = transition(null, ASSURANCE);
    const removal = transition(ASSURANCE, null);
    const bareDecision = evaluateWorkspaceAssuranceTransition(null, bareTransition);
    const verifiedDecision = evaluateWorkspaceAssuranceTransition(authority(), activation);
    const pendingDecision = evaluateWorkspaceAssuranceTransition(authority({ pending: true }), activation);
    const unilateralDecision = evaluateWorkspaceAssuranceTransition(authority(), removal);
    const dualDecision = evaluateWorkspaceAssuranceTransition(authority({ removal: true }), removal);
    if (dualDecision.verdict !== "accept" || dualDecision.authorization === null) {
        throw new Error("Workspace Assurance history fixture did not produce authorization");
    }
    const mutatedTransition = { ...removal, next_policy_head: "66".repeat(32) };
    const mutationDecision = verifyWorkspaceAssuranceAuthorization([{ suite: "bip340", public_key: AUTHORIZATION_KEY }], mutatedTransition, dualDecision.authorization);
    const capabilityInput = {
        authenticated_current_state: true,
        explicit_grant: true,
        carrier_only_evidence: false,
        requested_capabilities: ["read"],
        workspace_ceiling: ["read", "write"],
        role_path_ceilings: [["read", "write"], ["read"]],
        grant_capabilities: ["read"],
        revoked_effective: false,
    };
    const capabilityDecision = evaluateWorkspaceCapabilityBoundary(capabilityInput);
    const ambientAuthorityInput = {
        ...capabilityInput,
        explicit_grant: false,
        carrier_only_evidence: true,
    };
    const ambientAuthorityDecision = evaluateWorkspaceCapabilityBoundary(ambientAuthorityInput);
    const escalatedCapabilityInput = {
        ...capabilityInput,
        requested_capabilities: ["write"],
    };
    const escalatedCapabilityDecision = evaluateWorkspaceCapabilityBoundary(escalatedCapabilityInput);
    const revokedCapabilityInput = { ...capabilityInput, revoked_effective: true };
    const revokedCapabilityDecision = evaluateWorkspaceCapabilityBoundary(revokedCapabilityInput);
    const resourceKeyInput = {
        role_epoch_key_id: "role-epoch-7",
        resources: [
            { resource_id: "resource-a", content_key_id: "resource-a-4" },
            { resource_id: "resource-b", content_key_id: "resource-b-2" },
        ],
    };
    const resourceKeyDecision = evaluateWorkspaceResourceKeySeparation(resourceKeyInput);
    const projectionInput = {
        private_identifiers: [] as string[],
        private_counts: 0,
        encrypted_placeholders: 0,
    };
    const projectionDecision = evaluatePrivateProjection(projectionInput);
    const disclosureInput = {
        ...projectionInput,
        private_identifiers: [WORKSPACE_KEY],
    };
    const disclosureDecision = evaluatePrivateProjection(disclosureInput);
    const hostsInput = {
        inherited: [
            {
                host_id: WORKSPACE_KEY,
                priority: 20,
                radicle_locators: ["rad:zWorkspaceHostA"],
                radicle_backed_relay: true,
            },
            {
                host_id: INCEPTION_EVENT_ID,
                priority: 10,
                radicle_locators: ["rad:zWorkspaceHostB"],
                radicle_backed_relay: true,
            },
        ],
        mode: "default" as const,
        configured: [] as never[],
        last_responsive: WORKSPACE_KEY,
    };
    const hostsDecision = resolveEffectiveHosts(hostsInput);
    const leafInput = {
        account_removed: false,
        removed_device: WORKSPACE_KEY,
        active_devices: [WORKSPACE_KEY, INCEPTION_EVENT_ID],
        current_epoch: 7,
    };
    const leafDecision = evaluateRoleLeafChange(leafInput);
    const freshnessInput = {
        operation_class: "authority" as const,
        checkpoint_age: 300,
        policy_max_age: 300,
    };
    const freshnessDecision = evaluateFreshness(freshnessInput);
    const staleInput = { ...freshnessInput, checkpoint_age: 301 };
    const staleDecision = evaluateFreshness(staleInput);
    const invalidSchemaInput = { ...freshnessInput, checkpoint_age: -1 };
    const invalidSchemaDecision = evaluateFreshness(invalidSchemaInput);
    const signedManifest = signWorkspaceObject({
        spec_version: QUALIFIED_VERSION,
        object_type: "workspace-manifest-v1",
        workspace_key: "00".repeat(32),
        policy_head: PREVIOUS_POLICY_HEAD,
        predecessor: null,
        authority_checkpoint: INCEPTION_EVENT_ID,
        repository_rid: "rad:zWorkspaceHostA",
        repository_head: "aa".repeat(20),
        issued_at: EVALUATED_AT,
        root_policy_rid: "rad:zWorkspacePolicy",
        root_policy_head: PREVIOUS_POLICY_HEAD,
        visibility: "private",
        public_roles: [],
    }, WORKSPACE_SIGNATURE_SECRET, AUX_RAND);
    const originalSignature = String(signedManifest.signature);
    const signatureWorkspaceKey = String(signedManifest.workspace_key);
    const invalidSignedManifest = {
        ...signedManifest,
        signature: `${originalSignature.startsWith("00") ? "01" : "00"}${originalSignature.slice(2)}`,
    };
    const signatureInput = {
        object: invalidSignedManifest,
        expected_object_id: workspaceObjectId(invalidSignedManifest),
        current: {
            workspace_key: signatureWorkspaceKey,
            policy_head: PREVIOUS_POLICY_HEAD,
            predecessor: null,
            authority_checkpoint: INCEPTION_EVENT_ID,
            repository_rid: "rad:zWorkspaceHostA",
            repository_head: "aa".repeat(20),
            repository_ancestry: ["aa".repeat(20)],
            authority_checkpoint_candidates: [INCEPTION_EVENT_ID],
            competing_repository_heads: [],
        },
    };
    const signatureDecision = evaluateWorkspaceObject(signatureInput);
    const repositoryInput = { authority: {}, evidence: {}, objects: [] };
    const repositoryDecision = authenticateWorkspaceRepositoryView(repositoryInput);
    const conflictingState = {
        workspace_key: WORKSPACE_KEY,
        policy_head: PREVIOUS_POLICY_HEAD,
        predecessor: null,
        authority_checkpoint: INCEPTION_EVENT_ID,
        repository_rid: "rad:zWorkspaceHostA",
        repository_head: "aa".repeat(20),
        repository_ancestry: ["aa".repeat(20)],
        authority_checkpoint_candidates: [INCEPTION_EVENT_ID, "77".repeat(32)],
        competing_repository_heads: [],
    };
    const authorityConflictInput = {
        object: {},
        expected_object_id: "88".repeat(32),
        current: conflictingState,
    };
    const authorityConflictDecision = evaluateWorkspaceObject(authorityConflictInput);
    const affiliationInput = {
        now: 1000,
        observed_at: 699,
        expires_at: 1100,
        maximum_age: 300,
    };
    const affiliationDecision = evaluateWorkspaceAffiliationBoundary(affiliationInput);
    const revokedDeviceInput = {
        ...leafInput,
        removed_device: "99".repeat(32),
    };
    const revokedDeviceDecision = evaluateRoleLeafChange(revokedDeviceInput);
    const replayInput = {
        prior_head: "policy-head-a",
        asserted_predecessor: "policy-head-a",
        device_active: true,
        invitation_nonce_unused: false,
    };
    const replayDecision = evaluateWorkspaceStateTransitionBoundary(replayInput);
    const securityFixture = buildWorkspaceSecurityFixture({
        root_capabilities: ["invite", "read", "write"],
        ancestor_capabilities: [["invite", "read"]],
        grant_capabilities: ["invite", "read"],
        revoked: false,
    });
    const revokedSecurityFixture = buildWorkspaceSecurityFixture({
        root_capabilities: ["invite", "read"],
        ancestor_capabilities: [],
        grant_capabilities: ["invite", "read"],
        revoked: true,
    });
    const securityView = securityFixture.signed_repository_view as Readonly<{
        evidence: Readonly<Record<string, unknown>>;
        objects: readonly Readonly<Record<string, unknown>>[];
    }>;
    const securityGrant = securityView.objects.find((object) =>
        object.object_type === "role-grant-v1"
    );
    if (securityGrant === undefined) throw new Error("Workspace security fixture grant missing");
    const grantOperation = { ...securityGrant };
    delete grantOperation.signature;
    delete grantOperation.approval_ids;
    const grantOperationDigest = bytesToHex(sha256(proofBytes(
        "heterodyne-workspace-grant-operation-v1",
        grantOperation,
    )));
    const workspaceDevice = "81".repeat(32);
    const workspaceLeaf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const approvalUnsigned = {
        profile: "heterodyne.workspace-grant-approval.v1",
        spec_version: QUALIFIED_VERSION,
        workspace_key: securityGrant.workspace_key,
        policy_head: securityGrant.policy_head,
        predecessor: securityGrant.predecessor,
        authority_checkpoint: securityGrant.authority_checkpoint,
        operation_digest: grantOperationDigest,
        approver_key: bytesToHex(schnorr.getPublicKey("01".repeat(32))),
        issued_at: 1_720_000_200,
        expires_at: 1_720_000_650,
    };
    const securityApproval = {
        ...approvalUnsigned,
        signature: bytesToHex(schnorr.sign(
            proofBytes("heterodyne-workspace-grant-approval-v1", approvalUnsigned),
            "01".repeat(32),
            AUX_RAND,
        )),
    };
    const makeAcceptance = (issued_at: number) => {
        const invitation = securityGrant.invitation as Readonly<Record<string, unknown>>;
        const unsigned = {
            profile: "heterodyne.workspace-invitation-acceptance.v1",
            spec_version: QUALIFIED_VERSION,
            grant_id: securityFixture.grant_id,
            grant_operation_digest: grantOperationDigest,
            workspace_key: securityGrant.workspace_key,
            subject_account: securityFixture.subject,
            target_device: workspaceDevice,
            target_leaf: workspaceLeaf,
            policy_head: securityGrant.policy_head,
            predecessor: securityGrant.predecessor,
            authority_checkpoint: securityGrant.authority_checkpoint,
            repository_view_id: workspaceObjectId(securityView.evidence),
            nonce_opening: "b1".repeat(32),
            nonce_commitment: invitation.nonce_commitment,
            issued_at,
            expires_at: 1_720_000_600,
        };
        return {
            ...unsigned,
            signature: bytesToHex(schnorr.sign(
                proofBytes("heterodyne-workspace-invitation-acceptance-v1", unsigned),
                "02".repeat(32),
                AUX_RAND,
            )),
        };
    };
    const securityAcceptance = makeAcceptance(1_720_000_200);
    const mismatchedSecurityAcceptance = makeAcceptance(1_720_000_201);
    const deliveryInput = {
        resource_id: "resource-a",
        known_resource_ids: ["resource-a"],
        custody_host_id: "host-a",
        authorized_custody_host_ids: ["host-a"],
        requested_epoch: 4,
        current_epoch: 4,
        admission_epoch: 3,
        history_mode: "from-admission" as const,
    };
    const unknownResourceInput = { ...deliveryInput, resource_id: "resource-b" };
    const unknownResourceDecision = evaluateWorkspaceResourceDeliveryBoundary(unknownResourceInput);
    const unauthorizedHostInput = { ...deliveryInput, custody_host_id: "host-b" };
    const unauthorizedHostDecision = evaluateWorkspaceResourceDeliveryBoundary(unauthorizedHostInput);
    const historyDeniedInput = { ...deliveryInput, requested_epoch: 2 };
    const historyDeniedDecision = evaluateWorkspaceResourceDeliveryBoundary(historyDeniedInput);
    const reasonCases = [
        ["schema-invalid", invalidSchemaInput],
        ["signature-invalid", signatureInput],
        ["repository-invalid", { evidence: {}, objects: [] }],
        ["authority-conflict", authorityConflictInput],
        ["affiliation-stale", affiliationInput],
        ["device-revoked", revokedDeviceInput],
        ["history-denied", historyDeniedInput],
        ["resource-unknown", unknownResourceInput],
        ["host-unauthorized", unauthorizedHostInput],
        ["invitation-replay", { evidence: "genuine first consume and activation followed by mismatched second acceptance" }]
    ].map(([id, input]) => ({
        vector_id: "workspace/" + String(String(id)),
        description: `The current Workspace semantic boundary rejects ${String(id).replaceAll("-", " ")}.`,
        direction: "consume" as const,
            input: input as Record<string, unknown>
    }));
    const privateBoundaryArgs = new Map<string, readonly unknown[]>([
        ...(["workspace/carrier-not-ambient-authority", "workspace/current-capability-intersection",
            "workspace/inheritance-escalation-rejected", "workspace/invitation-replay"] as const)
            .map((vectorId) => [vectorId, [
                securityFixture,
                grantOperationDigest,
                securityApproval,
                securityAcceptance,
                mismatchedSecurityAcceptance,
                workspaceDevice,
                workspaceLeaf,
            ]] as const),
        ["workspace/revocation-blocks-future-effect",
            [revokedSecurityFixture, grantOperationDigest, securityApproval, securityAcceptance,
                mismatchedSecurityAcceptance, workspaceDevice, workspaceLeaf],
        ],
    ]);
    const boundaryArgs = new Map<string, readonly unknown[]>([
        ["workspace/repository-invalid", [repositoryInput]],
        ["workspace/bare-key-baseline", [null, bareTransition]],
        ["workspace/assurance-verified-activation", [authority(), activation]],
        ["workspace/assurance-pending-activation", [
                authority({ pending: true }),
                activation,
            ]],
        ["workspace/assurance-unilateral-removal", [authority(), removal]],
        ["workspace/assurance-dual-removal", [authority({ removal: true }), removal]],
        ["workspace/assurance-history-mutation-revalidated", [
                [{ suite: "bip340", public_key: AUTHORIZATION_KEY }],
                mutatedTransition,
                dualDecision.authorization,
            ]],
    ]);
    const cases: CurrentCaseFixture[] = [
        ...reasonCases,
        {
            vector_id: "workspace/bare-key-baseline",
            description: "The baseline Workspace remains valid under a bare active key without Assurance.",
            direction: "consume",
            input: { transition: bareTransition, assurance_authority: null }
        },
        {
            vector_id: "workspace/assurance-verified-activation",
            description: "A current verified enrollment activates optional Workspace Assurance with a durable signed authorization.",
            direction: "consume",
            input: {
                transition: activation,
                enrollment_resolution: {
                    state: "verified",
                    active_key: WORKSPACE_KEY,
                    inception_event_id: INCEPTION_EVENT_ID,
                    evaluated_at: EVALUATED_AT,
                },
            }
        },
        {
            vector_id: "workspace/assurance-pending-activation",
            description: "A pending enrollment cannot activate optional Workspace Assurance.",
            direction: "consume",
            input: {
                transition: activation,
                enrollment_resolution: {
                    state: "pending",
                    active_key: WORKSPACE_KEY,
                    inception_event_id: INCEPTION_EVENT_ID,
                    evaluated_at: EVALUATED_AT,
                },
            }
        },
        {
            vector_id: "workspace/assurance-unilateral-removal",
            description: "Active-key governance alone cannot remove an activated Workspace Assurance profile.",
            direction: "consume",
            input: { transition: removal, assurance_removal_receipt: null }
        },
        {
            vector_id: "workspace/assurance-dual-removal",
            description: "Matching active-key and Assurance authorization permits a profile removal and records its signed receipt.",
            direction: "round-trip",
            input: {
                transition: removal,
                assurance_removal_receipt: {
                    authorized: true,
                    evaluated_at: EVALUATED_AT,
                },
            }
        },
        {
            vector_id: "workspace/assurance-history-mutation-revalidated",
            description: "Historical authorization is revalidated against exact transition bytes and rejects a mutated policy head.",
            direction: "consume",
            input: {
                transition: mutatedTransition,
                historical_authorization: dualDecision.authorization,
                trust_anchors: [{ suite: "bip340", public_key: AUTHORIZATION_KEY }],
            }
        },
        {
            vector_id: "workspace/current-capability-intersection",
            description: "Authenticated current Workspace state and one explicit grant intersect the workspace, every role path, and grant ceiling before authorizing read.",
            direction: "consume",
            input: { actor_account: securityFixture.subject, requested_capabilities: ["invite", "read"], requested_resources: [securityFixture.resource], current_state: "authenticated-private" }
        },
        {
            vector_id: "workspace/carrier-not-ambient-authority",
            description: "Carrier-only evidence cannot replace an explicit current Workspace grant.",
            direction: "consume",
            input: { actor_account: "a2".repeat(32), actor_source: "carrier", current_state: "authenticated-private" }
        },
        {
            vector_id: "workspace/inheritance-escalation-rejected",
            description: "A request outside one inherited role-path ceiling is rejected even when a wider workspace ceiling contains it.",
            direction: "consume",
            input: { actor_account: securityFixture.subject, requested_capabilities: ["write"], current_state: "authenticated-private" }
        },
        {
            vector_id: "workspace/revocation-blocks-future-effect",
            description: "An effective current revocation blocks the next authority effect without asserting deletion of previously delivered material.",
            direction: "consume",
            input: { actor_account: revokedSecurityFixture.subject, grant_id: revokedSecurityFixture.grant_id, current_state: "authenticated-private-revoked" }
        },
        {
            vector_id: "workspace/independent-resource-content-keys",
            description: "Each resource uses a distinct content-key identifier and the role MLS epoch key is not reused as a universal content key.",
            direction: "consume",
            input: resourceKeyInput
        },
        {
            vector_id: "workspace/private-topology-clean",
            description: "A public Workspace projection contains no concealed identifiers, counts, or stable encrypted placeholders.",
            direction: "produce",
            input: projectionInput
        },
        {
            vector_id: "workspace/private-topology-disclosed",
            description: "A stable public identifier correlating a concealed Workspace is rejected.",
            direction: "produce",
            input: disclosureInput
        },
        {
            vector_id: "workspace/radicle-backed-hosts",
            description: "Deterministic host failover retains an eligible Radicle-backed relay while projecting no governance authority from host status.",
            direction: "consume",
            input: hostsInput
        },
        {
            vector_id: "workspace/independent-device-leaf-removal",
            description: "Removing one device advances the role epoch and preserves its sibling device's independent leaf.",
            direction: "consume",
            input: leafInput
        },
        {
            vector_id: "workspace/authority-freshness-boundary",
            description: "An authority mutation is accepted at the exact 300-second policy boundary.",
            direction: "consume",
            input: freshnessInput
        },
        {
            vector_id: "workspace/authority-checkpoint-stale",
            description: "An authority checkpoint one second beyond its maximum age is rejected before effect.",
            direction: "consume",
            input: staleInput
        },
    ];
    return cases.map((fixture) => {
        const privateArgs = privateBoundaryArgs.get(fixture.vector_id);
        if (privateArgs !== undefined) {
            registerPrivateCurrentFixture(WORKSPACE_PRIVATE_FIXTURES, fixture, privateArgs);
            return fixture;
        }
        const args = boundaryArgs.get(fixture.vector_id);
        return args === undefined ? fixture : { ...fixture, boundary_args: args };
    });
}
