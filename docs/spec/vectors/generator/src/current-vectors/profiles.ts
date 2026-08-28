import {
  validateRegisteredKindProfile,
  type Registry,
  type RegisteredKindProfile,
} from "../registry.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

function profileInvariants(profileId: string): string[] {
  if (profileId.startsWith("heterodyne-core-")) {
    return ["CORE-I-IDENTITY-INTEGRITY"];
  }
  if (profileId.includes("assurance-associated-key")) {
    return ["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"];
  }
  if (profileId.includes("assurance-succession")) {
    return ["ASSURANCE-I-TRANSITION-PROOF-BINDING"];
  }
  if (profileId.includes("assurance-enrollment-contest")) {
    return ["ASSURANCE-I-ENROLLMENT-WINDOWED"];
  }
  if (profileId.startsWith("heterodyne-assurance-")) {
    return ["ASSURANCE-I-RECIPROCAL-ENROLLMENT"];
  }
  if (profileId.includes("comms-tier3")) {
    return ["COMMS-I-TIER3-BLIND-CARRIER", "COMMS-I-TIER3-CONFINED"];
  }
  if (profileId.includes("comms-agent-attribution")) {
    return ["COMMS-I-AGENT-ATTRIBUTION", "COMMS-I-AGENT-SIGNER-BINDING"];
  }
  if (profileId.includes("comms-key-claim")) {
    return ["COMMS-I-CLAIM-AUTHENTICITY"];
  }
  if (profileId.includes("comms-claim-revocation")) {
    return ["COMMS-I-CLAIM-REVOCATION"];
  }
  if (profileId.includes("social-mute-list")) {
    return ["SOCIAL-I-PRIVATE-STATE-AT-REST"];
  }
  if (profileId.startsWith("heterodyne-social-")) {
    return ["SOCIAL-I-AGENT-AUTHORSHIP-EXACT", "SOCIAL-I-AGENT-POLICY-LOCAL"];
  }
  if (profileId.startsWith("heterodyne-control-")) {
    return ["CONTROL-I-MARMOT-GRANT-CONFINEMENT"];
  }
  throw new Error(`current profile has no semantic invariant mapping: ${profileId}`);
}

export function buildProfileCases(registry: Registry): CurrentVectorCase[] {
  return registry.kinds.flatMap(({ kind, profiles }) => profiles.map((profile) => {
    const candidate: RegisteredKindProfile = { kind, ...profile };
    const decision = validateRegisteredKindProfile(registry, candidate);
    if (decision.verdict !== "accept") {
      throw new Error(`registered profile did not validate: ${profile.profile_id}`);
    }
    return {
      relativePath: `${profile.owner}/profile-${profile.profile_id}.json`,
      semantic_boundary: "registry.validateRegisteredKindProfile",
      vector_id: `${profile.owner}/profile-${profile.profile_id}`,
      owner_document: profile.owner,
      profile: profile.profile_id,
      spec_refs: [currentSpecRef(`${profile.owner}-security`)],
      invariants: profileInvariants(profile.profile_id),
      reason_codes: [],
      description: `The complete kind/profile allocation tuple for ${profile.profile_id} validates without inference.`,
      direction: "consume" as const,
      input: candidate,
      expected_output: decision,
    };
  }));
}
