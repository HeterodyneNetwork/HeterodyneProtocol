import type { ArtifactCorpus } from "../types.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function extractRepositoryPathTokens(specifications: ReadonlyMap<string, string>): ReadonlySet<string> {
  const paths = new Set<string>();
  const pathPattern = /(?<![A-Za-z0-9_./-])[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+/gu;
  for (const specification of specifications.values()) {
    for (const match of specification.matchAll(pathPattern)) {
      paths.add(match[0].replace(/\.+$/u, ""));
    }
  }
  return paths;
}

function hasExactStringValue(value: unknown, target: string): boolean {
  if (value === target) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.some((item) => hasExactStringValue(item, target));
  }
  if (value !== null && typeof value === "object") {
    return Object.values(value).some((item) => hasExactStringValue(item, target));
  }
  return false;
}

export function findOrphanSchemaFailures(corpus: ArtifactCorpus): string[] {
  const prosePaths = extractRepositoryPathTokens(corpus.specifications);
  return [...corpus.schemas.keys()]
    .filter((schemaPath) =>
      !prosePaths.has(schemaPath)
      && !corpus.vectors.some(({ value }) => hasExactStringValue(value, schemaPath)))
    .sort(compareText);
}
