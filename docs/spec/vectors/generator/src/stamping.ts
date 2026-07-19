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
): "core" | "comms" | "social" | null {
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

const LEGACY_MONOLITH_KINDS = new Set([
  31000, 31001, 31002, 31003, 31005, 31010,
  31007, 31011, 31012,
  31004, 31008, 31009,
]);

export function inferLegacyOwner(input: {
  kind: number;
  stamp?: string;
  adopted_upstream: boolean;
}): "monolith/0.4.0" {
  if (
    input.adopted_upstream ||
    !LEGACY_MONOLITH_KINDS.has(input.kind) ||
    (input.stamp !== undefined && input.stamp !== "0.4.0")
  ) {
    throw new Error("legacy owner is not inferable");
  }
  return "monolith/0.4.0";
}
