import {
  applySocialAdmission,
  controlGroupAdmission,
  ordinaryConversationAdmission,
  type ControlAdmissionInput,
  type OrdinaryAdmissionInput,
} from "./marmot-admission.js";
import { baseVector } from "./vector-helpers.js";
import type { AuthoredVector, DocumentId } from "./types.js";

const ordinary: OrdinaryAdmissionInput = {
  cryptographic_valid: true,
  inviter_account: "11".repeat(32),
  recipient_account: "22".repeat(32),
  group_id: "33".repeat(32),
  key_package_ref: "44".repeat(32),
  member_count: 2,
  supported_capabilities: true,
  prior_local_acceptance: false,
  one_time_dm_invite_valid: false,
  explicit_local_decision: "none",
};

const control: ControlAdmissionInput = {
  cryptographic_valid: true,
  member_count: 2,
  node_account_matches: true,
  supported_control_profile: true,
  invitation_mode: "off",
  temporary_mode_unexpired: false,
  resource_available: true,
  entitlement_state: "none",
  purpose_bound_invite_valid: false,
  explicit_local_decision: "none",
};

export function buildMarmotAdmissionVectors(): AuthoredVector[] {
  const vectors: AuthoredVector[] = [];
  const add = (
    number: string,
    id: string,
    owner: DocumentId,
    description: string,
    input: Record<string, unknown>,
    expected_output: Record<string, unknown>,
  ) => vectors.push({
    relativePath: `acceptance-gating/${number}-${id}.json`,
    vector: baseVector({
      vector_id: `acceptance-gating/${id}`,
      spec_refs: [],
      description,
      direction: "consume",
      input,
      expected_output,
    }),
  });

  const ordinaryCases: Array<[string, string, string, OrdinaryAdmissionInput]> = [
    ["001", "authentication-before-policy", "Invalid cryptography rejects before ordinary conversation policy.", { ...ordinary, cryptographic_valid: false }],
    ["002", "message-request-no-receipt", "An unknown valid Marmot Welcome is held without sender-observable signals.", ordinary],
    ["005", "established-ordinary-accept", "A previously accepted two-member Marmot conversation remains accepted.", { ...ordinary, prior_local_acceptance: true }],
    ["006", "new-ordinary-hold", "A new valid ordinary conversation defaults to a message request.", ordinary],
    ["007", "authentication-reject", "An unauthenticated Marmot Welcome is rejected before policy.", { ...ordinary, cryptographic_valid: false }],
    ["008", "dm-invite-accept", "A valid purpose-bound one-time DM invite accepts its issuer's standard Marmot conversation.", { ...ordinary, one_time_dm_invite_valid: true }],
    ["009", "ordinary-explicit-reject", "An explicit local rejection rejects an otherwise valid conversation.", { ...ordinary, explicit_local_decision: "reject" }],
  ];
  for (const [number, id, description, input] of ordinaryCases) {
    const result = ordinaryConversationAdmission(input);
    add(number, id, "comms", description, input, {
      verdict: result.outcome === "reject" ? "reject" : "accept",
      ...(result.outcome === "reject" ? { reason_code: result.reason_code ?? "conversation-rejected" } : {}),
      normalized: result,
    });
  }

  const controlCases: Array<[string, string, string, ControlAdmissionInput]> = [
    ["010", "control-default-off-reject", "A full node defaults unsolicited Control invitation admission to off.", control],
    ["011", "control-permanent-enrollment-only", "Permanent open mode admits a bounded enrollment-only Control group.", { ...control, invitation_mode: "permanent" }],
    ["012", "control-entitled-authorized", "Active private entitlement authorizes the authenticated pairwise Control group.", { ...control, entitlement_state: "active" }],
    ["013", "control-entitlement-conflict-reject", "Conflicted private entitlement rejects Control authorization.", { ...control, entitlement_state: "conflicted" }],
    ["016", "control-capacity-reject", "Resource exhaustion rejects a Control Welcome before durable group state even for an entitled account.", { ...control, entitlement_state: "active", resource_available: false }],
    ["017", "control-explicit-reject-absorbing", "An explicit local rejection remains absorbing even when private entitlement is active.", { ...control, entitlement_state: "active", explicit_local_decision: "reject" }],
  ];
  for (const [number, id, description, input] of controlCases) {
    const result = controlGroupAdmission(input);
    add(number, id, "comms", description, input, {
      verdict: result.outcome === "reject" ? "reject" : "accept",
      ...(result.reason_code === undefined ? {} : { reason_code: result.reason_code }),
      normalized: result,
    });
  }

  for (const [number, id, description, input, outcome] of [
    ["003", "social-mute-tightens", "A local Social mute tightens Comms acceptance to rejection.", { comms_outcome: "accept", requested_social_outcome: "accept", muted: true, blocked: false }, applySocialAdmission("accept", "accept", true, false)],
    ["004", "social-policy-cannot-loosen", "Social cannot loosen an absorbing Comms rejection.", { comms_outcome: "reject", requested_social_outcome: "accept", muted: false, blocked: false }, applySocialAdmission("reject", "accept", false, false)],
    ["014", "social-wot-tightens-only", "Web-of-trust policy may tighten acceptance to a message request.", { comms_outcome: "accept", requested_social_outcome: "hold-as-message-request", muted: false, blocked: false }, applySocialAdmission("accept", "hold-as-message-request", false, false)],
    ["015", "social-wot-cannot-loosen", "Web-of-trust policy cannot loosen a message request into acceptance.", { comms_outcome: "hold-as-message-request", requested_social_outcome: "accept", muted: false, blocked: false }, applySocialAdmission("hold-as-message-request", "accept", false, false)],
  ] as const) {
    add(number, id, "social", description, input, {
      verdict: "accept",
      normalized: { composed_outcome: outcome, loosened_comms_result: false },
    });
  }
  return vectors;
}
