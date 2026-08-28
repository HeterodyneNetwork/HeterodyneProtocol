import {
  validateAgentPolicyList,
  validateAgentPolicyReceipt,
} from "../agent-moderation.js";
import { getPublicKey, signEvent } from "../nostr.js";
import { createReplaceableSelectionAuthority } from "../replaceable-selection.js";
import {
  evaluateAgentModerationEvidence,
  evaluateModeratorAsOfDeclaration,
} from "../social-policy.js";
import {
  selectCurrentSocialEvent,
  validateSocialAuthorship,
  validateSocialReplaceableCandidate,
} from "../social-events.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const SECRET = "29".repeat(32);
const AUX_RAND = "00".repeat(32);
const NOW = 1_800_100_000;

function captureSocialPolicyException(evaluate: () => unknown): Record<string, unknown> {
  try {
    evaluate();
  } catch (error) {
    return {
      verdict: "reject",
      reason_code: error instanceof Error ? error.message : String(error),
    };
  }
  throw new Error("current Social exception boundary unexpectedly accepted");
}

function executedSocialRejection(options: {
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
    throw new Error(`current Social evaluator mismatch for ${options.id}: ${String(options.decision.reason_code)}`);
  }
  return {
    relativePath: `social/${options.id}.json`,
    semantic_boundary: options.boundary,
    vector_id: `social/${options.id}`,
    owner_document: "social",
    spec_refs: [currentSpecRef(options.anchor)],
    invariants: [options.invariant],
    reason_codes: [options.reason],
    description: options.description,
    direction: "consume",
    input: options.input,
    expected_output: options.decision,
  };
}

export async function buildSocialCases(): Promise<CurrentVectorCase[]> {
  const eligible = await signEvent({
    secretKey: SECRET,
    created_at: NOW,
    kind: 30_000,
    tags: [["d", "source-neutral"]],
    content: "eligible relay state",
    auxRand: AUX_RAND,
  });
  const premature = await signEvent({
    secretKey: SECRET,
    created_at: NOW + 901,
    kind: 30_000,
    tags: [["d", "source-neutral"]],
    content: "premature repository state",
    auxRand: AUX_RAND,
  });
  const coordinate = {
    pubkey: getPublicKey(SECRET),
    kind: 30_000,
    d: "source-neutral",
  };
  const candidates = [
    { carrier: "repository" as const, event: premature },
    { carrier: "relay" as const, event: eligible },
  ];
  const selected = selectCurrentSocialEvent({
    selection_authority: createReplaceableSelectionAuthority({ trusted_now: () => NOW }),
    coordinate,
    candidates,
  });

  const note = await signEvent({
    secretKey: SECRET,
    created_at: NOW,
    kind: 1,
    tags: [],
    content: "ordinary vanilla Nostr authorship",
    auxRand: AUX_RAND,
  });
  const authorship = validateSocialAuthorship({ event: note });
  const invalidEvent = { ...note, sig: "00".repeat(64) };
  const invalidEventDecision = validateSocialAuthorship({ event: invalidEvent });
  const otherPersona = getPublicKey("2a".repeat(32));
  const authorBindingDecision = validateSocialAuthorship({
    event: note,
    persona_active_key: otherPersona,
  });
  const coordinateMismatchDecision = validateSocialReplaceableCandidate({
    coordinate: { ...coordinate, d: "other-coordinate" },
    event: eligible,
  });

  const moderatorDeclaration = await signEvent({
    secretKey: SECRET,
    created_at: NOW,
    kind: 34_550,
    tags: [
      ["d", "current-community"],
      ["p", getPublicKey(SECRET), "", "moderator"],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
  const outsideApproval = await signEvent({
    secretKey: "2b".repeat(32),
    created_at: NOW + 1,
    kind: 4_550,
    tags: [],
    content: "",
    auxRand: AUX_RAND,
  });
  const moderatorDecision = evaluateModeratorAsOfDeclaration({
    declaration: moderatorDeclaration,
    approval: outsideApproval,
  });

  const agentAssociation = { kind: "key" as const, value: getPublicKey(SECRET) };
  const attributedEvent = await signEvent({
    secretKey: SECRET,
    created_at: NOW,
    kind: 1,
    tags: [
      ["L", "network.heterodyne.agent"],
      ["l", "ai", "network.heterodyne.agent"],
      ["heterodyne_agent", "v1", agentAssociation.kind, agentAssociation.value],
      ["agent_action", "publish"],
    ],
    content: "bounded automated publication",
    auxRand: AUX_RAND,
  });
  const missingAttributionDecision = evaluateAgentModerationEvidence({
    event: note,
    automated: true,
    publication_path: "comms-authorized",
    expected_agent_association: agentAssociation,
  });
  const falsifiedAttributionDecision = evaluateAgentModerationEvidence({
    event: attributedEvent,
    automated: true,
    publication_path: "comms-authorized",
    expected_agent_association: { kind: "key", value: otherPersona },
  });
  const publicationBypassDecision = evaluateAgentModerationEvidence({
    event: attributedEvent,
    automated: true,
    publication_path: "direct",
    expected_agent_association: agentAssociation,
  });
  const receiptDecision = captureSocialPolicyException(() => validateAgentPolicyReceipt(
    note,
    { event: note, verified_agent_association: null },
  ));
  const policyBindingDecision = captureSocialPolicyException(() =>
    validateAgentPolicyList(note, new Map()));

  const reasonCases = [
    ["event-invalid", "social-event-invalid", "social-events.validateSocialAuthorship", "social-interactions", "SOCIAL-I-NIP01-AUTHORSHIP", { event: invalidEvent }, invalidEventDecision],
    ["author-binding-invalid", "social-author-binding-invalid", "social-events.validateSocialAuthorship", "social-interactions", "SOCIAL-I-NIP01-AUTHORSHIP", { event: note, persona_active_key: otherPersona }, authorBindingDecision],
    ["replaceable-coordinate-mismatch", "social-replaceable-coordinate-mismatch", "social-events.validateSocialReplaceableCandidate", "social-interactions", "SOCIAL-I-SOURCE-NEUTRAL-SELECTION", { coordinate: { ...coordinate, d: "other-coordinate" }, event: eligible }, coordinateMismatchDecision],
    ["moderator-not-in-asof-declaration", "moderator_not_in_asof_declaration", "social-policy.evaluateModeratorAsOfDeclaration", "social-moderation", "SOCIAL-I-AGENT-POLICY-LOCAL", { declaration: moderatorDeclaration, approval: outsideApproval }, moderatorDecision],
    ["agent-attribution-missing", "agent-attribution-missing", "social-policy.evaluateAgentModerationEvidence", "social-agent-policy", "SOCIAL-I-AGENT-AUTHORSHIP-EXACT", { event: note, automated: true, publication_path: "comms-authorized", expected_agent_association: agentAssociation }, missingAttributionDecision],
    ["agent-attribution-falsified", "agent-attribution-falsified", "social-policy.evaluateAgentModerationEvidence", "social-agent-policy", "SOCIAL-I-AGENT-AUTHORSHIP-EXACT", { event: attributedEvent, expected_agent_association: { kind: "key", value: otherPersona } }, falsifiedAttributionDecision],
    ["agent-publication-bypass", "agent-publication-bypass", "social-policy.evaluateAgentModerationEvidence", "social-agent-policy", "SOCIAL-I-AGENT-AUTHORSHIP-EXACT", { event: attributedEvent, publication_path: "direct" }, publicationBypassDecision],
    ["agent-policy-receipt-invalid", "agent-policy-receipt-invalid", "agent-moderation.validateAgentPolicyReceipt", "social-agent-policy", "SOCIAL-I-AGENT-POLICY-LOCAL", { event: note, target: note.id }, receiptDecision],
    ["agent-policy-binding-invalid", "agent-policy-binding-invalid", "agent-moderation.validateAgentPolicyList", "social-agent-policy", "SOCIAL-I-AGENT-POLICY-LOCAL", { event: note, receipts: [] }, policyBindingDecision],
  ].map(([id, reason, boundary, anchor, invariant, input, decision]) => executedSocialRejection({
    id: String(id),
    reason: String(reason),
    boundary: String(boundary),
    anchor: String(anchor),
    invariant: String(invariant),
    description: `The current Social semantic boundary rejects ${String(id).replaceAll("-", " ")}.`,
    input: input as Record<string, unknown>,
    decision: decision as Record<string, unknown>,
  }));

  return [
    ...reasonCases,
    {
      relativePath: "social/source-neutral-core-quarantine.json",
      semantic_boundary: "social-events.selectCurrentSocialEvent",
      vector_id: "social/source-neutral-core-quarantine",
      owner_document: "social",
      spec_refs: [currentSpecRef("social-scope")],
      invariants: [
        "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
        "SOCIAL-I-SOURCE-NEUTRAL-SELECTION",
      ],
      reason_codes: [],
      description: "Source-neutral Social selection inherits Core quarantine without giving repository transport priority.",
      direction: "consume",
      input: { trusted_now: NOW, coordinate, candidates },
      expected_output: { verdict: "accept", selected_event_id: selected?.id ?? null },
    },
    {
      relativePath: "social/source-neutral-vanilla-authorship.json",
      semantic_boundary: "social-events.validateSocialAuthorship",
      vector_id: "social/source-neutral-vanilla-authorship",
      owner_document: "social",
      spec_refs: [currentSpecRef("social-interactions")],
      invariants: ["SOCIAL-I-NIP01-AUTHORSHIP"],
      reason_codes: [],
      description: "A directly signed vanilla Nostr event preserves its NIP-01 author without requiring a Heterodyne persona.",
      direction: "consume",
      input: { event: note },
      expected_output: authorship,
    },
  ];
}
