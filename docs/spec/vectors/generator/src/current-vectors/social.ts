import { validateAgentPolicyList, validateAgentPolicyReceipt, } from "../agent-moderation.js";
import { getPublicKey, signEvent } from "../nostr.js";
import { createReplaceableSelectionAuthority } from "../replaceable-selection.js";
import { evaluateAgentModerationEvidence, evaluateModeratorAsOfDeclaration, } from "../social-policy.js";
import { selectCurrentSocialEvent, validateSocialAuthorship, validateSocialReplaceableCandidate, } from "../social-events.js";
import { currentSpecRef, type CurrentCaseFixture } from "./types.js";
const SECRET = "29".repeat(32);
const AUX_RAND = "00".repeat(32);
const NOW = 1800100000;
function captureSocialPolicyException(evaluate: () => unknown): Record<string, unknown> {
    try {
        evaluate();
    }
    catch (error) {
        return {
            verdict: "reject",
            reason_code: error instanceof Error ? error.message : String(error),
        };
    }
    throw new Error("current Social exception boundary unexpectedly accepted");
}
export async function buildSocialCases(): Promise<CurrentCaseFixture[]> {
    const eligible = await signEvent({
        secretKey: SECRET,
        created_at: NOW,
        kind: 30000,
        tags: [["d", "source-neutral"]],
        content: "eligible relay state",
        auxRand: AUX_RAND,
    });
    const premature = await signEvent({
        secretKey: SECRET,
        created_at: NOW + 901,
        kind: 30000,
        tags: [["d", "source-neutral"]],
        content: "premature repository state",
        auxRand: AUX_RAND,
    });
    const coordinate = {
        pubkey: getPublicKey(SECRET),
        kind: 30000,
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
        kind: 34550,
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
        kind: 4550,
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
    const receiptDecision = captureSocialPolicyException(() => validateAgentPolicyReceipt(note, { event: note, verified_agent_association: null }));
    const policyBindingDecision = captureSocialPolicyException(() => validateAgentPolicyList(note, new Map()));
    const reasonCases = [
        ["event-invalid", { event: invalidEvent }],
        ["author-binding-invalid", { event: note, persona_active_key: otherPersona }],
        ["replaceable-coordinate-mismatch", { coordinate: { ...coordinate, d: "other-coordinate" }, event: eligible }],
        ["moderator-not-in-asof-declaration", { declaration: moderatorDeclaration, approval: outsideApproval }],
        ["agent-attribution-missing", { event: note, automated: true, publication_path: "comms-authorized", expected_agent_association: agentAssociation }],
        ["agent-attribution-falsified", { event: attributedEvent, expected_agent_association: { kind: "key", value: otherPersona } }],
        ["agent-publication-bypass", { event: attributedEvent, publication_path: "direct" }],
        ["agent-policy-receipt-invalid", { event: note, target: note.id }],
        ["agent-policy-binding-invalid", { event: note, receipts: [] }]
    ].map(([id, input]) => ({
        vector_id: "social/" + String(String(id)),
        description: `The current Social semantic boundary rejects ${String(id).replaceAll("-", " ")}.`,
        direction: "consume" as const,
            input: input as Record<string, unknown>
    }));
    const boundaryArgs = new Map<string, readonly unknown[]>([
        ["social/agent-attribution-falsified", [{
                    event: attributedEvent,
                    automated: true,
                    publication_path: "comms-authorized",
                    expected_agent_association: { kind: "key", value: otherPersona },
                }]],
        ["social/agent-publication-bypass", [{
                    event: attributedEvent,
                    automated: true,
                    publication_path: "direct",
                    expected_agent_association: agentAssociation,
                }]],
        ["social/agent-policy-receipt-invalid", [
                note,
                { event: note, verified_agent_association: null },
            ]],
        ["social/agent-policy-binding-invalid", [note, new Map()]],
        ["social/source-neutral-core-quarantine", [{
                    selection_authority: createReplaceableSelectionAuthority({ trusted_now: () => NOW }),
                    coordinate,
                    candidates,
                }]],
    ]);
    const cases: CurrentCaseFixture[] = [
        ...reasonCases,
        {
            vector_id: "social/source-neutral-core-quarantine",
            description: "Source-neutral Social selection inherits Core quarantine without giving repository transport priority.",
            direction: "consume",
            input: { trusted_now: NOW, coordinate, candidates }
        },
        {
            vector_id: "social/source-neutral-vanilla-authorship",
            description: "A directly signed vanilla Nostr event preserves its NIP-01 author without requiring a Heterodyne persona.",
            direction: "consume",
            input: { event: note }
        },
    ];
    return cases.map((fixture) => ({
        ...fixture,
        ...(boundaryArgs.has(fixture.vector_id)
            ? { boundary_args: boundaryArgs.get(fixture.vector_id) }
            : {}),
    }));
}
