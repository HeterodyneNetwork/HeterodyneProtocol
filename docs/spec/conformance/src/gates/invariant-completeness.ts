import type { ArtifactCorpus } from "../types.js";

type StrictProfile = {
  profileId: string;
  owner: string;
  conformanceOwners: ReadonlySet<string>;
  requiresProfiles: readonly string[];
  addsInvariants: readonly string[];
};

type Invariant = ArtifactCorpus["registry"]["security_invariants"][number];

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function parseStrictProfile(value: unknown): StrictProfile | undefined {
  const owner = isRecord(value) && typeof value.profile_id === "string"
    ? /^heterodyne-(core|comms|control|social|workspace)-/u.exec(value.profile_id)?.[1]
    : undefined;
  if (
    !isRecord(value)
    || typeof value.profile_id !== "string"
    || value.profile_id.length === 0
    || owner === undefined
    || typeof value.conformance_class !== "string"
    || value.state !== "active"
    || !isStringArray(value.requires_profiles)
    || !isStringArray(value.adds_invariants)
  ) {
    return undefined;
  }
  const knownOwners = new Set(["core", "comms", "control", "social", "workspace"]);
  const conformanceOwners = new Set(value.conformance_class
    .split(/[^A-Za-z]+/u)
    .map((part) => part.toLowerCase())
    .filter((part) => knownOwners.has(part)));
  return {
    profileId: value.profile_id,
    owner,
    conformanceOwners,
    requiresProfiles: value.requires_profiles,
    addsInvariants: value.adds_invariants,
  };
}

function readStrictProfiles(specifications: ReadonlyMap<string, string>): ReadonlyMap<string, StrictProfile> {
  const profiles = new Map<string, StrictProfile>();
  const conflicting = new Set<string>();
  const fixturePattern = /<!--\s*fixture:[^>]*strict-profile[^>]*-->\s*```json[ \t]*\r?\n([\s\S]*?)\r?\n```/giu;

  for (const specification of specifications.values()) {
    for (const match of specification.matchAll(fixturePattern)) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(match[1]) as unknown;
      } catch {
        continue;
      }
      const profile = parseStrictProfile(parsed);
      if (profile === undefined || conflicting.has(profile.profileId)) {
        continue;
      }
      const prior = profiles.get(profile.profileId);
      if (prior === undefined) {
        profiles.set(profile.profileId, profile);
      } else if (
        prior.owner !== profile.owner
        || JSON.stringify([...prior.conformanceOwners]) !== JSON.stringify([...profile.conformanceOwners])
        || JSON.stringify(prior.requiresProfiles) !== JSON.stringify(profile.requiresProfiles)
        || JSON.stringify(prior.addsInvariants) !== JSON.stringify(profile.addsInvariants)
      ) {
        profiles.delete(profile.profileId);
        conflicting.add(profile.profileId);
      }
    }
  }
  return profiles;
}

function collectInvariantClosures(
  profiles: ReadonlyMap<string, StrictProfile>,
  registered: ReadonlyMap<string, Invariant>,
): ReadonlyMap<string, ReadonlySet<string>> {
  const closures = new Map<string, ReadonlySet<string>>();
  const invalid = new Set<string>();
  const visiting = new Set<string>();

  function closureOf(profileId: string): ReadonlySet<string> | undefined {
    const cached = closures.get(profileId);
    if (cached !== undefined) {
      return cached;
    }
    if (invalid.has(profileId) || visiting.has(profileId)) {
      return undefined;
    }

    const profile = profiles.get(profileId);
    if (profile === undefined) {
      return undefined;
    }
    visiting.add(profileId);
    const closure = new Set<string>();
    for (const prerequisite of profile.requiresProfiles) {
      const prerequisiteClosure = closureOf(prerequisite);
      if (prerequisiteClosure === undefined) {
        visiting.delete(profileId);
        invalid.add(profileId);
        return undefined;
      }
      for (const invariant of prerequisiteClosure) {
        closure.add(invariant);
      }
    }
    for (const invariant of profile.addsInvariants) {
      const entry = registered.get(invariant);
      if (entry === undefined || entry.owner !== profile.owner || entry.feature !== undefined) {
        visiting.delete(profileId);
        invalid.add(profileId);
        return undefined;
      }
      closure.add(invariant);
    }
    visiting.delete(profileId);
    closures.set(profileId, closure);
    return closure;
  }

  for (const profileId of profiles.keys()) {
    closureOf(profileId);
  }
  return closures;
}

export function findInvariantCompletenessFailures(corpus: ArtifactCorpus): string[] {
  const profiles = readStrictProfiles(corpus.specifications);
  const registered = new Map(corpus.registry.security_invariants.map((entry) => [entry.id, entry]));
  const closures = collectInvariantClosures(profiles, registered);
  return corpus.registry.security_invariants
    .filter(({ id, owner, feature }) => feature === undefined && ![...closures].some(
      ([profileId, closure]) => profiles.get(profileId)?.conformanceOwners.has(owner)
        && closure.has(id),
    ))
    .map(({ id }) => id)
    .filter((id, index, ids) => ids.indexOf(id) === index)
    .sort(compareText);
}
