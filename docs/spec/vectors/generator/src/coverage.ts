import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { DocumentId, Vector } from "./types.js";

export type CoverageEntry = {
  vector_id: string;
  owner_document: DocumentId;
  owner_version: string;
  dependency_versions: Partial<Record<DocumentId, string>>;
  registry_revision: number;
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
        owner_version: vector.owner_version,
        dependency_versions: vector.dependency_versions,
        registry_revision: vector.registry_revision,
        ...(vector.profile === undefined ? {} : { profile: vector.profile }),
        spec_refs: vector.spec_refs,
      };
    })
    .sort((left, right) =>
      left.vector_id < right.vector_id ? -1 : left.vector_id > right.vector_id ? 1 : 0,
    );
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
  for (const document of ["core", "comms", "control", "social"] as const) {
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
    return `# ${title} vector coverage\n\nStatus: \`incomplete-draft\`.\n\nNo Control conformance corpus is published. The Control profile remains non-claimable until the ADR-030 minimum corpus exists.\n`;
  }
  return `# ${title} vector coverage\n\nGenerated from [manifest.json](manifest.json); do not edit by hand.\n\n${renderTable(entries)}`;
}

function renderFamilyView(entries: CoverageEntry[]): string {
  const counts = (["core", "comms", "control", "social"] as const)
    .map((document) => `- ${document}: ${entries.filter((entry) => entry.owner_document === document).length}`)
    .join("\n");
  return `# Protocol-family vector coverage\n\nGenerated from [manifest.json](manifest.json); do not edit by hand.\n\n${counts}\n\n${renderTable(entries)}`;
}

function renderTable(entries: CoverageEntry[]): string {
  const rows = entries
    .map((entry) => {
      const dependencies = Object.entries(entry.dependency_versions)
        .map(([document, version]) => `${document}=${version}`)
        .join(", ") || "—";
      return `| \`${entry.vector_id}\` | ${entry.owner_document} | \`${entry.owner_version}\` | ${dependencies} | ${entry.registry_revision} | ${entry.profile === undefined ? "—" : `\`${entry.profile}\``} | ${entry.spec_refs.map((ref) => `\`${ref}\``).join("<br>")} |`;
    })
    .join("\n");
  return `| Vector | Owner | Version | Dependencies | Registry | Profile | Spec references |\n|---|---|---|---|---:|---|---|\n${rows}${rows.length === 0 ? "| — | — | — | — | — | — | — |" : ""}\n`;
}
