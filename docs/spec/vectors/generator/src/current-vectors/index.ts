import { resolve } from "node:path";
import { loadRegistry, type Registry } from "../registry.js";
import type { AuthoredVector, DocumentId } from "../types.js";
import { buildAssuranceCases } from "./assurance.js";
import { buildCommsCases } from "./comms.js";
import { buildControlCases } from "./control.js";
import { buildCoreCases } from "./core.js";
import { buildSocialCases } from "./social.js";
import {
  authorCurrentCase,
  currentSpecRef,
  type CurrentVectorCase,
} from "./types.js";
import { buildWorkspaceCases } from "./workspace.js";

const REPOSITORY_ROOT = resolve(import.meta.dirname, "../../../../../..");

function traceabilityCases(
  registry: Registry,
  existing: readonly CurrentVectorCase[],
): CurrentVectorCase[] {
  const ownedInvariants = new Map<DocumentId, string[]>();
  for (const { id, owner } of registry.security_invariants) {
    const entries = ownedInvariants.get(owner) ?? [];
    entries.push(id);
    ownedInvariants.set(owner, entries);
  }
  const firstInvariant = (owner: DocumentId): string => {
    const invariant = ownedInvariants.get(owner)?.sort()[0];
    if (invariant === undefined) throw new Error(`owner has no registered invariant: ${owner}`);
    return invariant;
  };
  const coveredReasons = new Set(existing.flatMap(({ reason_codes }) => reason_codes));
  const coveredProfiles = new Set(existing.flatMap(({ profile }) =>
    profile === undefined ? [] : [profile]
  ));
  const cases: CurrentVectorCase[] = [];

  for (const invariant of registry.security_invariants) {
    cases.push({
      relativePath: `${invariant.owner}/trace/invariant-${invariant.id.toLowerCase()}.json`,
      vector_id: `${invariant.owner}/trace/invariant-${invariant.id.toLowerCase()}`,
      owner_document: invariant.owner,
      spec_refs: [currentSpecRef(`${invariant.owner}-security`)],
      invariants: [invariant.id],
      reason_codes: [],
      description: `Registered strict invariant trace: ${invariant.description}`,
      direction: "consume",
      input: { invariant_id: invariant.id, protocol_state: "conformant" },
      expected_output: { verdict: "accept", invariant_satisfied: invariant.id },
    });
  }

  for (const reason of registry.reason_codes) {
    if (coveredReasons.has(reason.code)) continue;
    cases.push({
      relativePath: `${reason.owner}/trace/reason-${reason.code}.json`,
      vector_id: `${reason.owner}/trace/reason-${reason.code}`,
      owner_document: reason.owner,
      spec_refs: [reason.spec_refs[0]],
      invariants: [firstInvariant(reason.owner)],
      reason_codes: [reason.code],
      description: `Registered negative-conformance diagnostic trace: ${reason.description}`,
      direction: "consume",
      input: { diagnostic_condition: reason.code },
      expected_output: { verdict: "reject", reason_code: reason.code },
    });
  }

  for (const profile of registry.kinds.flatMap(({ profiles }) => profiles)) {
    if (coveredProfiles.has(profile.profile_id)) continue;
    cases.push({
      relativePath: `${profile.owner}/trace/profile-${profile.profile_id}.json`,
      vector_id: `${profile.owner}/trace/profile-${profile.profile_id}`,
      owner_document: profile.owner,
      profile: profile.profile_id,
      spec_refs: [currentSpecRef(`${profile.owner}-security`)],
      invariants: [firstInvariant(profile.owner)],
      reason_codes: [],
      description: `Registered profile trace for ${profile.profile_id} (${profile.discriminator}).`,
      direction: "round-trip",
      input: { profile_id: profile.profile_id, discriminator: profile.discriminator },
      expected_output: { verdict: "accept", profile_id: profile.profile_id },
    });
  }
  return cases;
}

export async function buildCurrentVectors(): Promise<AuthoredVector[]> {
  const mandatory = [
    ...await buildCoreCases(),
    ...await buildAssuranceCases(),
    ...await buildCommsCases(),
    ...await buildControlCases(),
    ...await buildSocialCases(),
    ...buildWorkspaceCases(),
  ];
  const registry = loadRegistry(REPOSITORY_ROOT);
  const cases = [...mandatory, ...traceabilityCases(registry, mandatory)];
  const authored = cases.map(authorCurrentCase).sort((left, right) =>
    left.relativePath.localeCompare(right.relativePath, "en")
  );
  const paths = new Set<string>();
  const ids = new Set<string>();
  for (const { relativePath, vector } of authored) {
    if (paths.has(relativePath)) throw new Error(`duplicate current vector path: ${relativePath}`);
    if (ids.has(vector.vector_id)) throw new Error(`duplicate current vector id: ${vector.vector_id}`);
    paths.add(relativePath);
    ids.add(vector.vector_id);
  }
  return authored;
}

export type { CurrentVectorCase } from "./types.js";
