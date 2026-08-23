import { checkCoreSignedEvent } from "../subjects/reference-checker.js";
import type { ArtifactCorpus } from "../types.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function findNegativeHygieneFailures(corpus: ArtifactCorpus): string[] {
  const failures = new Set<string>();

  for (const { value: vector } of corpus.vectors) {
    for (const check of vector.conformance_checks ?? []) {
      const result = checkCoreSignedEvent(vector, check);
      const expectedVerdict = vector.expected_output.verdict;
      const expectedReason = vector.expected_output.reason_code;
      if (
        result.terminalStage !== check.expected_terminal_stage
        || result.verdict !== expectedVerdict
        || (result.verdict === "reject"
          && typeof expectedReason === "string"
          && result.reasonCode !== expectedReason)
      ) {
        failures.add(`${vector.vector_id} :: ${check.event_pointer}`);
      }
    }
  }

  return [...failures].sort(compareText);
}
