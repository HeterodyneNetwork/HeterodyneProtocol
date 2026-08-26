import type { Registry } from "./registry.js";

export type StampInput = {
  kind: number;
  profile_id?: string;
  content_is_heterodyne_json: boolean;
  is_dr_outer: boolean;
};

export function stampOwner(
  input: StampInput,
  registry: Registry,
): "core" | "assurance" | "comms" | "social" | "workspace" | null {
  if (input.is_dr_outer) return null;

  const kind = registry.kinds.find((entry) => entry.kind === input.kind);
  if (kind === undefined) return null;

  if (input.profile_id !== undefined) {
    const profile = kind.profiles.find(
      (candidate) => candidate.profile_id === input.profile_id,
    );
    if (profile === undefined) return null;
    if (profile.stamping) {
      return profile.owner === "control" ? null : profile.owner;
    }
  }

  if (kind.allocation_authority !== "heterodyne") return null;
  if (kind.base_schema_owner === "nostr" || kind.base_schema_owner === "control") {
    return null;
  }
  return kind.base_schema_owner;
}
