const HEX_KEY = /^[0-9a-f]{64}$/;

export {
  createCanonicalProfileSelectionAuthority,
  selectCanonicalProfile,
  type CanonicalProfileSelectionAuthority,
  type CanonicalProfileSelectionAuthorityConfig,
  type CanonicalProfileSelectionInput,
  type CanonicalProfileView,
} from "./canonical-profile-selection-authority.js";

type Device = {
  persona: string;
  pubkey: string;
  active: boolean;
  role: "human-device" | "full-node" | "agent";
};

export function resolveTier3Recipients(input: {
  memberPersonas: readonly string[];
  devices: readonly Device[];
  selected?: readonly string[];
}): { verdict: "accept"; recipients: string[] } | {
  verdict: "reject";
  reason_code: "tier3-recipient-not-active-device";
} {
  const members = new Set(input.memberPersonas);
  const eligible = input.devices
    .filter((device) => device.active && device.role === "human-device" && members.has(device.persona))
    .map((device) => device.pubkey)
    .filter((key) => HEX_KEY.test(key));
  const eligibleSet = new Set(eligible);
  const recipients = input.selected === undefined ? eligible : [...input.selected];
  if (recipients.some((key) => !eligibleSet.has(key))) {
    return { verdict: "reject", reason_code: "tier3-recipient-not-active-device" };
  }
  return { verdict: "accept", recipients: [...new Set(recipients)].sort() };
}

/**
 * @deprecated Task-15 current-vector projection only. Canonical profile state
 * is selected from captured signed candidates by selectCanonicalProfile; a
 * caller assertion cannot establish repository authority.
 */
export function validateCanonicalProfile(input: {
  canonicalRepoSelected: boolean;
  publisher: string;
  delegatedPublisher: string;
  nip05Present: boolean;
  nip05ResolvedKey?: string;
}): { verdict: "accept" } | {
  verdict: "reject";
  reason_code:
    | "profile-repository-selection-required"
    | "profile-publisher-delegation-invalid"
    | "profile-nip05-key-mismatch";
} {
  if (!input.canonicalRepoSelected) {
    return { verdict: "reject", reason_code: "profile-repository-selection-required" };
  }
  if (!HEX_KEY.test(input.publisher) || input.publisher !== input.delegatedPublisher) {
    return { verdict: "reject", reason_code: "profile-publisher-delegation-invalid" };
  }
  if (input.nip05Present && input.nip05ResolvedKey !== input.publisher) {
    return { verdict: "reject", reason_code: "profile-nip05-key-mismatch" };
  }
  return { verdict: "accept" };
}

export function classifyRetiredKeyObservation(input: {
  signatureValid: boolean;
  createdAtInAuthorityWindow: boolean;
  compromiseSince: number | null;
  eventCreatedAt?: number;
  repoCommitAncestorOfRetirementCheckpoint: boolean;
  trustedLocalReceiptBeforeRetirement: boolean;
}):
  | { verdict: "accept"; state: "repo-confirmed-pre-retirement" | "locally-confirmed-pre-retirement" }
  | { verdict: "provisional"; state: "provisional-retired-key" }
  | { verdict: "reject"; reason_code: "bad_signature" | "retired-key-authority-window-invalid" | "revoked_key_post_compromise" } {
  if (!input.signatureValid) return { verdict: "reject", reason_code: "bad_signature" };
  if (!input.createdAtInAuthorityWindow) {
    return { verdict: "reject", reason_code: "retired-key-authority-window-invalid" };
  }
  if (
    input.compromiseSince !== null
    && input.eventCreatedAt !== undefined
    && input.eventCreatedAt >= input.compromiseSince
  ) {
    return { verdict: "reject", reason_code: "revoked_key_post_compromise" };
  }
  if (input.repoCommitAncestorOfRetirementCheckpoint) {
    return { verdict: "accept", state: "repo-confirmed-pre-retirement" };
  }
  if (input.trustedLocalReceiptBeforeRetirement) {
    return { verdict: "accept", state: "locally-confirmed-pre-retirement" };
  }
  return { verdict: "provisional", state: "provisional-retired-key" };
}

type NodeAdvertisementTimeInput = {
  createdAt: number;
  expiry: number;
  now: number;
  clockUncertainty: number;
  priorAcceptanceEvidence?: boolean;
};

export function validateNodeAdvertisementTime(input: NodeAdvertisementTimeInput):
  | { verdict: "accept"; refresh_by: number }
  | { verdict: "reject"; reason_code: string } {
  if (input.expiry <= input.createdAt) {
    return { verdict: "reject", reason_code: "node-advert-expiry-invalid" };
  }
  if (input.expiry - input.createdAt > 86_400) {
    return { verdict: "reject", reason_code: "node-advert-lifetime-exceeded" };
  }
  if (input.now >= input.expiry) {
    return { verdict: "reject", reason_code: "node_advert_expired" };
  }
  const hasPriorAcceptance = input.priorAcceptanceEvidence === true;
  if (!hasPriorAcceptance && input.clockUncertainty > 300) {
    return { verdict: "reject", reason_code: "node-advert-clock-uncertain" };
  }
  if (!hasPriorAcceptance && Math.abs(input.createdAt - input.now) > 300) {
    return { verdict: "reject", reason_code: "node-advert-clock-skew" };
  }
  return { verdict: "accept", refresh_by: input.createdAt + 43_200 };
}
