import { loadFamilyAnchorInventory } from "./docs-lint.js";
import { FAMILY_VERSION } from "./family.js";
import type { AuthoredVector } from "./types.js";

const CURRENT_SPECIFICATION_REFERENCE = new RegExp(
  `^heterodyne:${FAMILY_VERSION.replaceAll(".", "\\.")}#([a-z0-9][a-z0-9-]*)$`,
  "u",
);

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function findCurrentSpecReferenceFailures(
  vectors: readonly AuthoredVector[],
  repositoryRoot: string,
): string[] {
  const anchorsByOwner = loadFamilyAnchorInventory(repositoryRoot);
  const failures = new Set<string>();
  for (const { vector } of vectors) {
    const ownerAnchors = anchorsByOwner.get(vector.owner_document);
    for (const reference of vector.spec_refs) {
      const match = CURRENT_SPECIFICATION_REFERENCE.exec(reference);
      if (match === null || !ownerAnchors?.has(match[1])) {
        failures.add(`${vector.vector_id} :: ${reference}`);
      }
    }
  }
  return [...failures].sort(compareText);
}

export function assertCurrentSpecReferencesResolve(
  vectors: readonly AuthoredVector[],
  repositoryRoot: string,
): void {
  const failures = findCurrentSpecReferenceFailures(vectors, repositoryRoot);
  if (failures.length > 0) {
    throw new Error(
      ["unresolved current vector specification references:", ...failures].join("\n"),
    );
  }
}
