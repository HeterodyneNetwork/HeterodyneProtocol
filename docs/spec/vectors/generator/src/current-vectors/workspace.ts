import { schnorr } from "@noble/curves/secp256k1";
import { bytesToHex, hexToBytes } from "../hex.js";
import { proofBytes } from "../proof-bytes.js";
import {
  createWorkspaceAssuranceAuthority,
  evaluateWorkspaceAssuranceTransition,
  verifyWorkspaceAssuranceAuthorization,
  type WorkspaceAssuranceAttestationInput,
  type WorkspaceAssuranceConfig,
} from "../workspace-assurance.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const WORKSPACE_KEY = "11".repeat(32);
const INCEPTION_EVENT_ID = "22".repeat(32);
const PREVIOUS_POLICY_HEAD = "33".repeat(32);
const NEXT_POLICY_HEAD = "44".repeat(32);
const EVALUATED_AT = 1_720_000_400;
const AUTHORIZATION_SECRET = "55".repeat(32);
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

const transition = (
  previous_assurance: AssuranceProfile | null,
  next_assurance: AssuranceProfile | null,
): Transition => ({
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
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-assurance-authorization-v1", unsigned),
      hexToBytes(AUTHORIZATION_SECRET),
      hexToBytes(AUX_RAND),
    )),
  };
}

function authority(options: { pending?: boolean; removal?: boolean } = {}) {
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

export function buildWorkspaceCases(): CurrentVectorCase[] {
  const bareTransition = transition(null, null);
  const activation = transition(null, ASSURANCE);
  const removal = transition(ASSURANCE, null);
  const bareDecision = evaluateWorkspaceAssuranceTransition(null, bareTransition);
  const verifiedDecision = evaluateWorkspaceAssuranceTransition(authority(), activation);
  const pendingDecision = evaluateWorkspaceAssuranceTransition(
    authority({ pending: true }),
    activation,
  );
  const unilateralDecision = evaluateWorkspaceAssuranceTransition(authority(), removal);
  const dualDecision = evaluateWorkspaceAssuranceTransition(
    authority({ removal: true }),
    removal,
  );
  if (dualDecision.verdict !== "accept" || dualDecision.authorization === null) {
    throw new Error("Workspace Assurance history fixture did not produce authorization");
  }
  const mutatedTransition = { ...removal, next_policy_head: "66".repeat(32) };
  const mutationDecision = verifyWorkspaceAssuranceAuthorization(
    [{ suite: "bip340", public_key: AUTHORIZATION_KEY }],
    mutatedTransition,
    dualDecision.authorization,
  );

  return [
    {
      relativePath: "workspace/bare-key-baseline.json",
      vector_id: "workspace/bare-key-baseline",
      owner_document: "workspace",
      spec_refs: [currentSpecRef("workspace-optional-assurance")],
      invariants: ["WORKSPACE-I-OPTIONAL-ASSURANCE"],
      reason_codes: [],
      description: "The baseline Workspace remains valid under a bare active key without Assurance.",
      direction: "consume",
      input: { transition: bareTransition, assurance_authority: null },
      expected_output: bareDecision,
    },
    {
      relativePath: "workspace/assurance-verified-activation.json",
      vector_id: "workspace/assurance-verified-activation",
      owner_document: "workspace",
      spec_refs: [currentSpecRef("workspace-optional-assurance")],
      invariants: ["WORKSPACE-I-OPTIONAL-ASSURANCE"],
      reason_codes: [],
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
      },
      expected_output: verifiedDecision,
    },
    {
      relativePath: "workspace/assurance-pending-activation.json",
      vector_id: "workspace/assurance-pending-activation",
      owner_document: "workspace",
      spec_refs: [currentSpecRef("workspace-optional-assurance")],
      invariants: ["WORKSPACE-I-OPTIONAL-ASSURANCE"],
      reason_codes: ["workspace-assurance-state-required"],
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
      },
      expected_output: pendingDecision,
    },
    {
      relativePath: "workspace/assurance-unilateral-removal.json",
      vector_id: "workspace/assurance-unilateral-removal",
      owner_document: "workspace",
      spec_refs: [currentSpecRef("workspace-optional-assurance")],
      invariants: ["WORKSPACE-I-OPTIONAL-ASSURANCE"],
      reason_codes: ["workspace-assurance-state-required"],
      description: "Active-key governance alone cannot remove an activated Workspace Assurance profile.",
      direction: "consume",
      input: { transition: removal, assurance_removal_receipt: null },
      expected_output: unilateralDecision,
    },
    {
      relativePath: "workspace/assurance-dual-removal.json",
      vector_id: "workspace/assurance-dual-removal",
      owner_document: "workspace",
      spec_refs: [currentSpecRef("workspace-optional-assurance")],
      invariants: ["WORKSPACE-I-OPTIONAL-ASSURANCE"],
      reason_codes: [],
      description: "Matching active-key and Assurance authorization permits a profile removal and records its signed receipt.",
      direction: "round-trip",
      input: {
        transition: removal,
        assurance_removal_receipt: {
          authorized: true,
          evaluated_at: EVALUATED_AT,
        },
      },
      expected_output: dualDecision,
    },
    {
      relativePath: "workspace/assurance-history-mutation-revalidated.json",
      vector_id: "workspace/assurance-history-mutation-revalidated",
      owner_document: "workspace",
      spec_refs: [currentSpecRef("workspace-optional-assurance")],
      invariants: ["WORKSPACE-I-OPTIONAL-ASSURANCE"],
      reason_codes: ["workspace-assurance-state-required"],
      description: "Historical authorization is revalidated against exact transition bytes and rejects a mutated policy head.",
      direction: "consume",
      input: {
        transition: mutatedTransition,
        historical_authorization: dualDecision.authorization,
        trust_anchors: [{ suite: "bip340", public_key: AUTHORIZATION_KEY }],
      },
      expected_output: mutationDecision,
    },
  ];
}
