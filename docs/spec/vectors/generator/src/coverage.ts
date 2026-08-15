import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Registry } from "./registry.js";
import type { DocumentId, Vector } from "./types.js";

/** Registry allocations awaiting normative vectors. */
export const PENDING_PROFILE_IDS = [] as const;

/** Registered profiles intentionally excluded from conformance. */
export const INACTIVE_PROFILE_IDS = [] as const;

export type CoverageEntry = {
  vector_id: string;
  owner_document: DocumentId;
  spec_version: string;
  profile?: string;
  spec_refs: string[];
};

export function buildCoverage(vectors: Vector[]): CoverageEntry[] {
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
        spec_version: vector.spec_version,
        ...(vector.profile === undefined ? {} : { profile: vector.profile }),
        spec_refs: vector.spec_refs,
      };
    })
    .sort((left, right) =>
      left.vector_id < right.vector_id ? -1 : left.vector_id > right.vector_id ? 1 : 0,
    );
}

export function findProfileCoverageIssues(
  registry: Pick<Registry, "kinds">,
  coverage: readonly CoverageEntry[],
): string[] {
  const covered = new Set(
    coverage.flatMap(({ profile }) => profile === undefined ? [] : [profile]),
  );
  const pending = new Set<string>(PENDING_PROFILE_IDS);
  const inactive = new Set<string>(INACTIVE_PROFILE_IDS);
  const profiles = registry.kinds.flatMap(({ profiles }) => profiles);
  const issues: string[] = [];

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
  const { buildAllVectors } = await import("./topics.js");
  const { buildFixtures } = await import("./fixtures.js");
  const entries = buildCoverage(
    (await buildAllVectors(buildFixtures())).map(({ vector }) => vector),
  );
  const coverageRoot = join(vectorRoot, "coverage");
  await mkdir(coverageRoot, { recursive: true });
  const manifestPath = join(coverageRoot, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(entries, null, 2)}\n`, "utf8");

  // The serialized manifest is the sole source for every human-readable view.
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as CoverageEntry[];
  for (const document of ["core", "comms", "control", "social", "workspace"] as const) {
    const filtered = manifest.filter((entry) => entry.owner_document === document);
    await writeFile(
      join(coverageRoot, `${document}.md`),
      renderDocumentView(document, filtered),
      "utf8",
    );
  }
  await writeFile(join(coverageRoot, "family.md"), renderFamilyView(manifest), "utf8");
}

function renderDocumentView(document: DocumentId, entries: CoverageEntry[]): string {
  const title = document[0].toUpperCase() + document.slice(1);
  if (document === "control") {
    return `# ${title} vector coverage\n\nStatus: \`conformant\`.\n\nThese vectors cover baseline Marmot Control plus separately advertised optional recovery profiles. Baseline conformance does not require a recovery feature.\n\nGenerated from [manifest.json](manifest.json); do not edit by hand.\n\n${renderTable(entries)}`;
  }
  return `# ${title} vector coverage\n\nGenerated from [manifest.json](manifest.json); do not edit by hand.\n\n${renderTable(entries)}`;
}

function renderFamilyView(entries: CoverageEntry[]): string {
  const counts = (["core", "comms", "control", "social", "workspace"] as const)
    .map((document) => `- ${document}: ${entries.filter((entry) => entry.owner_document === document).length}`)
    .join("\n");
  return `# Protocol-family vector coverage\n\nGenerated from [manifest.json](manifest.json); do not edit by hand.\n\n${counts}\n\n${renderTable(entries)}`;
}

function renderTable(entries: CoverageEntry[]): string {
  const rows = entries
    .map((entry) =>
      `| \`${entry.vector_id}\` | ${entry.owner_document} | ${entry.profile === undefined ? "—" : `\`${entry.profile}\``} | ${entry.spec_refs.map((ref) => `\`${ref}\``).join("<br>")} |`,
    )
    .join("\n");
  return `| Vector | Owner | Profile | Spec references |\n|---|---|---|---|\n${rows}${rows.length === 0 ? "| — | — | — | — |" : ""}\n`;
}
