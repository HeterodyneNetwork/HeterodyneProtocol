import type { ArtifactCorpus } from "../types.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
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
  return [...corpus.schemas.keys()]
    .filter((schemaPath) =>
      ![...corpus.specifications.values()].some((specification) => specification.includes(schemaPath))
      && !corpus.vectors.some(({ value }) => hasExactStringValue(value, schemaPath)))
    .sort(compareText);
}
