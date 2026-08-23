import type { ArtifactCorpus } from "../types.js";
import {
  extractExplicitAnchors,
  formatSpecificationReference,
  ownerForSpecificationPath,
} from "./anchors.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function findAnchorCoverageFailures(corpus: ArtifactCorpus): string[] {
  const referenced = new Set(corpus.vectors.flatMap(({ value }) => value.spec_refs));
  const failures = new Set<string>();

  for (const [path, specification] of corpus.specifications) {
    const owner = ownerForSpecificationPath(path);
    if (owner === undefined) continue;
    for (const anchor of extractExplicitAnchors(specification)) {
      const reference = formatSpecificationReference(owner, anchor);
      if (!referenced.has(reference)) {
        failures.add(reference);
      }
    }
  }

  return [...failures].sort(compareText);
}
