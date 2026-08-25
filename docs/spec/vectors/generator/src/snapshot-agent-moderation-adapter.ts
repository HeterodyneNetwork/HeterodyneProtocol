// Snapshot-only compatibility surface for the frozen pre-redesign Social topic.
// Live callers import agent-moderation.ts and cannot reach these legacy forms.
export {
  applyLegacyAgentPolicyCorrection as applyAgentPolicyCorrection,
  applyLegacySubscribedAgentPolicy as applySubscribedAgentPolicy,
  validateLegacyAgentPolicyCorrection as validateAgentPolicyCorrection,
  validateLegacyAgentPolicyList as validateAgentPolicyList,
  validateLegacyAgentPolicyReceipt as validateAgentPolicyReceipt,
} from "./legacy-agent-moderation.js";
