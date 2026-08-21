import type { ArtifactCorpus } from "../types.js";
import {
  extractExplicitAnchors,
  ownerForSpecificationPath,
  parseSpecificationReference,
  type SpecificationOwner,
} from "./anchors.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function anchorsByOwner(corpus: ArtifactCorpus): ReadonlyMap<SpecificationOwner, ReadonlySet<string>> {
  const result = new Map<SpecificationOwner, ReadonlySet<string>>();
  for (const [path, specification] of corpus.specifications) {
    const owner = ownerForSpecificationPath(path);
    if (owner !== undefined) {
      result.set(owner, extractExplicitAnchors(specification));
    }
  }
  return result;
}

export function findAnchorResolutionFailures(corpus: ArtifactCorpus): string[] {
  const failures = new Set<string>();
  const availableAnchors = anchorsByOwner(corpus);
  for (const { value: vector } of corpus.vectors) {
    for (const specRef of vector.spec_refs) {
      const parsed = parseSpecificationReference(specRef);
      if (
        parsed === undefined
        || !availableAnchors.get(parsed.owner)?.has(parsed.anchor)
      ) {
        failures.add(`${vector.vector_id} :: ${specRef}`);
      }
    }
  }

  return [...failures].sort(compareText);
}
