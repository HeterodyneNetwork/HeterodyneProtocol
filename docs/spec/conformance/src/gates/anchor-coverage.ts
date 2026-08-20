import type { ArtifactCorpus } from "../types.js";
import { extractExplicitAnchors, ownerForSpecificationPath } from "./anchors.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function findAnchorCoverageFailures(corpus: ArtifactCorpus): string[] {
  const referenced = new Set(corpus.vectors.flatMap(({ value }) => value.spec_refs));
  const referencePrefix = `${corpus.familyVersion.replace("/", ":")}#`;
  const failures = new Set<string>();

  for (const [path, specification] of corpus.specifications) {
    if (ownerForSpecificationPath(path) === undefined) {
      continue;
    }
    for (const anchor of extractExplicitAnchors(specification)) {
      const reference = `${referencePrefix}${anchor}`;
      if (!referenced.has(reference)) {
        failures.add(reference);
      }
    }
  }

  return [...failures].sort(compareText);
}
