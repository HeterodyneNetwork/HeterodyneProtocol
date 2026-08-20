import type { ArtifactCorpus } from "../types.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function findDeadVocabularyFailures(corpus: ArtifactCorpus): string[] {
  const usedReasons = new Set<string>();
  for (const { value: vector } of corpus.vectors) {
    const reasonCode = vector.expected_output.reason_code;
    if (vector.expected_output.verdict === "reject" && typeof reasonCode === "string") {
      usedReasons.add(reasonCode);
    }
  }

  return [...new Set(corpus.registry.reason_codes.map(({ code }) => code))]
    .filter((code) => !usedReasons.has(code))
    .sort(compareText);
}
