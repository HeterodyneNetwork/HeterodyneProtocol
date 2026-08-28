import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { DOCUMENTS } from "./family.js";
import type { Registry } from "./registry.js";
import type { DocumentId } from "./types.js";
import {
  semanticEvidenceForCase,
  type CurrentVectorCase,
} from "./current-vectors/index.js";

/** Registry allocations awaiting current-draft vectors. */
export const PENDING_PROFILE_IDS = [] as const;

/** Registered profiles intentionally excluded from conformance. */
export const INACTIVE_PROFILE_IDS = [] as const;

/**
 * Current registered diagnostics intentionally omitted only when no protocol
 * consumer or producer can exercise them. Each entry identifies retained
 * administrative vocabulary rather than current wire behavior.
 */
export const NON_WIRE_REASON_EXCLUSIONS: readonly Readonly<{
  code: string;
  justification: string;
}>[] = [
  {
    code: "compromise_rotation_breadcrumb_forbidden",
    justification: "Retained only to classify pre-redesign rotation breadcrumbs; current Assurance succession never authors that retired wire profile.",
  },
  {
    code: "equivocation_flagged",
    justification: "Retained as a historical KEL security-warning label; current Assurance duplicity is evaluated as assurance-duplicity without importing a KEL graph.",
  },
  {
    code: "expired_delegation",
    justification: "Retained only for pre-redesign epoch delegation reports; current associated-key expiry is evaluated as assurance-associated-key-expired.",
  },
  {
    code: "informal_vouch_not_counted",
    justification: "Retained as historical KERI vocabulary; current witness evaluation counts only registered cryptographic receipts and emits assurance-witness-threshold-unsatisfied.",
  },
  {
    code: "kel_head_forbidden",
    justification: "Retained to classify a forbidden legacy kel_head tag; current Assurance records never consume or author the retired tag graph.",
  },
  {
    code: "kel_head_mismatch",
    justification: "Retained to classify historical kel_head material; current Assurance chain validation binds predecessor and head directly in closed records.",
  },
  {
    code: "kel_head_missing",
    justification: "Retained to classify historical kel_head material; no current event class requires the retired tag and the current catalog cannot manufacture it.",
  },
  {
    code: "kel_revoked_nid",
    justification: "Retained for historical KEL-delegate reconciliation; current writer-NID and associated-key authorization use live direct proof boundaries.",
  },
  {
    code: "nid_binding_missing_signature",
    justification: "Retained for the historical kind-31001 dual-proof profile; current writer-NID authorization is covered by the Core direct proof boundary.",
  },
  {
    code: "provisional_not_final",
    justification: "Retained as a historical KEL reconciliation state label; current Assurance enrollment exposes its own executable pending-window result.",
  },
  {
    code: "repo_head_regression",
    justification: "Retained for historical KEL repository reconciliation; current Assurance records do not materialize or select a legacy repository head graph.",
  },
  {
    code: "retiring_key_nip05_invalid",
    justification: "Retained only to classify pre-redesign retiring-profile breadcrumbs; current profile publication uses the Core delegated publisher validator.",
  },
  {
    code: "revoked_key_post_revoked_at",
    justification: "Retained for retired epoch-key events; current Assurance compromise cutoff and associated-key revocation have distinct executable reasons.",
  },
  {
    code: "signing_key_compromised_at_created_at",
    justification: "Retained for historical epoch-key retroactivity reports; current Assurance evaluates the accepted inclusive compromise cutoff directly.",
  },
  {
    code: "successor_persona_mismatch",
    justification: "Retained only to classify pre-redesign rotation breadcrumbs; current succession explicitly creates a distinct successor identity.",
  },
  {
    code: "withdrawn_on_reconcile",
    justification: "Retained as a historical relay-to-KEL reconciliation label; current Assurance decisions do not import the retired reconciliation graph.",
  },
];

export type CoverageEntry = {
  vector_id: string;
  owner_document: DocumentId;
  profile?: string;
  spec_refs: string[];
  invariants: string[];
  reason_codes: string[];
};

export type SemanticCoverageEntry = CoverageEntry & {
  semantic_boundary: string;
};

type CoverageVector = {
  vector_id: string;
  owner_document: DocumentId;
  profile?: string;
  spec_refs: readonly string[];
  invariants: readonly string[];
  reason_codes: readonly string[];
};

type HistoricalCoverageVector = Omit<CoverageVector, "invariants" | "reason_codes">;
type HistoricalCoverageEntry = Omit<CoverageEntry, "invariants" | "reason_codes">;
type ProjectionCoverageEntry = CoverageEntry | HistoricalCoverageEntry;

export function buildCoverage(vectors: readonly CoverageVector[]): CoverageEntry[] {
  const seen = new Set<string>();
  return vectors
    .map((vector) => {
      if (seen.has(vector.vector_id)) {
        throw new Error(`duplicate coverage vector_id: ${vector.vector_id}`);
      }
      seen.add(vector.vector_id);
      return {
        vector_id: vector.vector_id,
        owner_document: vector.owner_document,
        ...(vector.profile === undefined ? {} : { profile: vector.profile }),
        spec_refs: [...vector.spec_refs],
        invariants: [...vector.invariants],
        reason_codes: [...vector.reason_codes],
      };
    })
    .sort((left, right) =>
      left.vector_id < right.vector_id ? -1 : left.vector_id > right.vector_id ? 1 : 0,
    );
}

/**
 * Semantic closure is deliberately computed from executed authoring cases,
 * never from the serialized administrative coverage projection. This keeps a
 * registry label (or a hand-written vector envelope) from becoming evidence
 * merely by repeating an invariant, reason, or profile identifier.
 */
export function buildSemanticCoverage(
  cases: readonly CurrentVectorCase[],
): SemanticCoverageEntry[] {
  const seen = new Set<string>();
  return cases.map((entry) => {
    if (seen.has(entry.vector_id)) {
      throw new Error(`duplicate semantic coverage vector_id: ${entry.vector_id}`);
    }
    seen.add(entry.vector_id);
    const evidence = semanticEvidenceForCase(entry);
    if (
      entry.vector_id.includes("/trace/")
      || Object.hasOwn(entry.input, "diagnostic_condition")
      || Object.hasOwn(entry.input, "protocol_state")
      || Object.hasOwn(entry.expected_output, "invariant_satisfied")
    ) {
      throw new Error(`registry-label vector is not semantic evidence: ${entry.vector_id}`);
    }
    return {
      vector_id: entry.vector_id,
      owner_document: evidence.owner_document,
      ...(evidence.profile === undefined ? {} : { profile: evidence.profile }),
      spec_refs: [...evidence.spec_refs],
      invariants: [...evidence.invariants],
      reason_codes: [...evidence.reason_codes],
      semantic_boundary: evidence.boundary_id,
    };
  }).sort((left, right) => left.vector_id.localeCompare(right.vector_id, "en"));
}

function hasExecutableBoundary(entry: CoverageEntry): entry is SemanticCoverageEntry {
  return "semantic_boundary" in entry
    && typeof entry.semantic_boundary === "string"
    && entry.semantic_boundary.trim().length > 0;
}

export function findInvariantCoverageIssues(
  registry: Pick<Registry, "security_invariants">,
  coverage: readonly CoverageEntry[],
): string[] {
  const registered = new Map(registry.security_invariants.map((entry) => [entry.id, entry]));
  const covered = new Set<string>();
  const issues: string[] = [];
  for (const entry of coverage) {
    if (!hasExecutableBoundary(entry)) {
      issues.push(`coverage entry lacks executable boundary: ${entry.vector_id}`);
      continue;
    }
    for (const id of entry.invariants) {
      const invariant = registered.get(id);
      if (invariant === undefined) issues.push(`unregistered invariant: ${id}`);
      else if (invariant.owner !== entry.owner_document) {
        issues.push(`invariant owner mismatch: ${entry.vector_id} -> ${id}`);
      } else {
        covered.add(id);
      }
    }
  }
  for (const { id } of registry.security_invariants) {
    if (!covered.has(id)) issues.push(`uncovered invariant: ${id}`);
  }
  return [...new Set(issues)].sort();
}

export function findReasonCoverageIssues(
  registry: Pick<Registry, "reason_codes">,
  coverage: readonly CoverageEntry[],
): string[] {
  const registered = new Map(registry.reason_codes.map((entry) => [entry.code, entry]));
  const excluded = new Set<string>();
  const covered = new Set<string>();
  const issues: string[] = [];
  for (const { code, justification } of NON_WIRE_REASON_EXCLUSIONS) {
    if (excluded.has(code)) issues.push(`duplicate reason exclusion: ${code}`);
    excluded.add(code);
    if (!registered.has(code)) issues.push(`reason exclusion not registered: ${code}`);
    if (justification.trim().length < 24) issues.push(`reason exclusion lacks justification: ${code}`);
  }
  for (const entry of coverage) {
    if (!hasExecutableBoundary(entry)) {
      issues.push(`coverage entry lacks executable boundary: ${entry.vector_id}`);
      continue;
    }
    for (const code of entry.reason_codes) {
      const reason = registered.get(code);
      if (reason === undefined) issues.push(`unregistered reason code: ${code}`);
      else if (reason.owner !== entry.owner_document) {
        issues.push(`reason owner mismatch: ${entry.vector_id} -> ${code}`);
      } else {
        covered.add(code);
      }
    }
  }
  for (const { code } of registry.reason_codes) {
    if (!covered.has(code) && !excluded.has(code)) issues.push(`uncovered reason code: ${code}`);
  }
  for (const code of excluded) {
    if (covered.has(code)) issues.push(`stale reason exclusion: ${code}`);
  }
  return [...new Set(issues)].sort();
}

export function findProfileCoverageIssues(
  registry: Pick<Registry, "kinds">,
  coverage: readonly CoverageEntry[],
): string[] {
  const profiles = registry.kinds.flatMap(({ profiles }) => profiles);
  const registered = new Map(profiles.map((profile) => [profile.profile_id, profile]));
  const covered = new Set<string>();
  const issues: string[] = [];
  for (const entry of coverage) {
    if (!hasExecutableBoundary(entry)) {
      issues.push(`coverage entry lacks executable boundary: ${entry.vector_id}`);
      continue;
    }
    if (entry.profile === undefined) continue;
    const profile = registered.get(entry.profile);
    if (profile === undefined) issues.push(`unregistered profile: ${entry.vector_id} -> ${entry.profile}`);
    else if (profile.owner !== entry.owner_document) {
      issues.push(`profile owner mismatch: ${entry.vector_id} -> ${entry.profile}`);
    } else {
      covered.add(entry.profile);
    }
  }
  const pending = new Set<string>(PENDING_PROFILE_IDS);
  const inactive = new Set<string>(INACTIVE_PROFILE_IDS);

  for (const profileId of pending) {
    if (covered.has(profileId)) {
      issues.push(`stale pending profile: ${profileId}`);
    }
  }

  for (const profile of profiles) {
    if (covered.has(profile.profile_id) || pending.has(profile.profile_id)) continue;
    if (inactive.has(profile.profile_id)) {
      continue;
    }
    issues.push(`uncovered profile: ${profile.profile_id}`);
  }

  for (const profileId of inactive) {
    const profile = profiles.find((candidate) => candidate.profile_id === profileId);
    if (profile === undefined) issues.push(`inactive profile not registered: ${profileId}`);
    else if (profile.owner !== "control") {
      issues.push(`inactive profile owner mismatch: ${profileId}`);
    }
  }
  for (const profileId of pending) {
    if (!profiles.some((profile) => profile.profile_id === profileId)) {
      issues.push(`pending profile not registered: ${profileId}`);
    }
  }
  return issues.sort();
}

export async function writeCoverage(vectorRoot: string): Promise<void> {
  const { buildIsolatedCurrentCatalog } = await import("./current-authoring-runtime.js");
  await writeCoverageFromVectors(
    vectorRoot,
    (await buildIsolatedCurrentCatalog()).vectors.map(({ vector }) => vector),
  );
}

export async function writeCoverageFromVectors(
  vectorRoot: string,
  vectors: readonly CoverageVector[],
): Promise<void> {
  await writeCoverageEntries(vectorRoot, buildCoverage(vectors));
}

/** Historical schema-2 packaging projects only fields present in that corpus. */
export async function writeHistoricalCoverageFromVectors(
  vectorRoot: string,
  vectors: readonly HistoricalCoverageVector[],
): Promise<void> {
  const seen = new Set<string>();
  const entries: HistoricalCoverageEntry[] = vectors.map((vector) => {
    if (seen.has(vector.vector_id)) {
      throw new Error(`duplicate coverage vector_id: ${vector.vector_id}`);
    }
    seen.add(vector.vector_id);
    return {
      vector_id: vector.vector_id,
      owner_document: vector.owner_document,
      ...(vector.profile === undefined ? {} : { profile: vector.profile }),
      spec_refs: [...vector.spec_refs],
    };
  }).sort((left, right) => left.vector_id.localeCompare(right.vector_id, "en"));
  await writeCoverageEntries(vectorRoot, entries);
}

async function writeCoverageEntries(
  vectorRoot: string,
  entries: ProjectionCoverageEntry[],
): Promise<void> {
  const coverageRoot = join(vectorRoot, "coverage");
  await mkdir(coverageRoot, { recursive: true });
  const manifestPath = join(coverageRoot, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(entries, null, 2)}\n`, "utf8");

  // The serialized manifest is the sole source for every human-readable view.
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ProjectionCoverageEntry[];
  const documents = DOCUMENTS.filter((document) =>
    document !== "assurance"
      || manifest.some((entry) => entry.owner_document === "assurance")
  );
  if (!documents.includes("assurance")) {
    await rm(join(coverageRoot, "assurance.md"), { force: true });
  }
  for (const document of documents) {
    const filtered = manifest.filter((entry) => entry.owner_document === document);
    await writeFile(
      join(coverageRoot, `${document}.md`),
      renderDocumentView(document, filtered),
      "utf8",
    );
  }
  await writeFile(join(coverageRoot, "family.md"), renderFamilyView(manifest), "utf8");
}

function renderDocumentView(document: DocumentId, entries: ProjectionCoverageEntry[]): string {
  const title = document[0].toUpperCase() + document.slice(1);
  if (document === "control") {
    return `# ${title} vector coverage\n\nStatus: \`conformant\`.\n\nThese vectors cover baseline Marmot Control plus separately advertised optional recovery profiles. Baseline conformance does not require a recovery feature.\n\nGenerated from [manifest.json](manifest.json); do not edit by hand.\n\n${renderTable(entries)}`;
  }
  return `# ${title} vector coverage\n\nGenerated from [manifest.json](manifest.json); do not edit by hand.\n\n${renderTable(entries)}`;
}

function renderFamilyView(entries: ProjectionCoverageEntry[]): string {
  const counts = DOCUMENTS
    .filter((document) =>
      document !== "assurance"
        || entries.some((entry) => entry.owner_document === "assurance")
    )
    .map((document) => `- ${document}: ${entries.filter((entry) => entry.owner_document === document).length}`)
    .join("\n");
  return `# Protocol-family vector coverage\n\nGenerated from [manifest.json](manifest.json); do not edit by hand.\n\n${counts}\n\n${renderTable(entries)}`;
}

function renderTable(entries: ProjectionCoverageEntry[]): string {
  const rows = entries
    .map((entry) =>
      `| \`${entry.vector_id}\` | ${entry.owner_document} | ${entry.profile === undefined ? "—" : `\`${entry.profile}\``} | ${"invariants" in entry ? entry.invariants.map((id) => `\`${id}\``).join("<br>") : "—"} | ${"reason_codes" in entry && entry.reason_codes.length > 0 ? entry.reason_codes.map((code) => `\`${code}\``).join("<br>") : "—"} | ${entry.spec_refs.map((ref) => `\`${ref}\``).join("<br>")} |`,
    )
    .join("\n");
  return `| Vector | Owner | Profile | Invariants | Reason codes | Spec references |\n|---|---|---|---|---|---|\n${rows}${rows.length === 0 ? "| — | — | — | — | — | — |" : ""}\n`;
}
