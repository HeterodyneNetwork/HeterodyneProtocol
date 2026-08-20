import type { ArtifactCorpus } from "../types.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function findReasonCodeClosureFailures(corpus: ArtifactCorpus): string[] {
  const registered = new Set(corpus.registry.reason_codes.map(({ code }) => code));
  const failures = new Set<string>();

  for (const { value: vector } of corpus.vectors) {
    if (vector.expected_output.verdict !== "reject") {
      continue;
    }
    const value = vector.expected_output.reason_code;
    const reasonCode = typeof value === "string" && value.length > 0 ? value : "<missing>";
    if (!registered.has(reasonCode)) {
      failures.add(`${vector.vector_id} :: ${reasonCode}`);
    }
  }

  return [...failures].sort(compareText);
}
