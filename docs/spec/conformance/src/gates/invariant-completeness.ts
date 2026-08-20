import type { ArtifactCorpus } from "../types.js";

type StrictProfile = {
  profileId: string;
  requiresProfiles: readonly string[];
  addsInvariants: readonly string[];
};

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
  if (
    !isRecord(value)
    || typeof value.profile_id !== "string"
    || value.profile_id.length === 0
    || !isStringArray(value.requires_profiles)
    || !isStringArray(value.adds_invariants)
  ) {
    return undefined;
  }
  return {
    profileId: value.profile_id,
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
        JSON.stringify(prior.requiresProfiles) !== JSON.stringify(profile.requiresProfiles)
        || JSON.stringify(prior.addsInvariants) !== JSON.stringify(profile.addsInvariants)
      ) {
        profiles.delete(profile.profileId);
        conflicting.add(profile.profileId);
      }
    }
  }
  return profiles;
}

function collectInvariantClosures(profiles: ReadonlyMap<string, StrictProfile>): ReadonlySet<string> {
  const closures = new Map<string, ReadonlySet<string>>();

  function closureOf(profileId: string, ancestors: ReadonlySet<string>): ReadonlySet<string> {
    const cached = closures.get(profileId);
    if (cached !== undefined) {
      return cached;
    }
    if (ancestors.has(profileId)) {
      return new Set();
    }

    const profile = profiles.get(profileId);
    if (profile === undefined) {
      return new Set();
    }
    const nextAncestors = new Set(ancestors);
    nextAncestors.add(profileId);
    const closure = new Set<string>();
    for (const prerequisite of profile.requiresProfiles) {
      for (const invariant of closureOf(prerequisite, nextAncestors)) {
        closure.add(invariant);
      }
    }
    for (const invariant of profile.addsInvariants) {
      closure.add(invariant);
    }
    closures.set(profileId, closure);
    return closure;
  }

  const allClosures = new Set<string>();
  for (const profileId of profiles.keys()) {
    for (const invariant of closureOf(profileId, new Set())) {
      allClosures.add(invariant);
    }
  }
  return allClosures;
}

export function findInvariantCompletenessFailures(corpus: ArtifactCorpus): string[] {
  const claimed = collectInvariantClosures(readStrictProfiles(corpus.specifications));
  return corpus.registry.security_invariants
    .filter(({ id, feature }) => feature === undefined && !claimed.has(id))
    .map(({ id }) => id)
    .filter((id, index, ids) => ids.indexOf(id) === index)
    .sort(compareText);
}
