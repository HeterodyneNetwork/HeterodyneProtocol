import { checkCoreSignedEvent } from "../subjects/reference-checker.js";
import type { ArtifactCorpus } from "../types.js";

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function findIdentifierIntegrityFailures(corpus: ArtifactCorpus): string[] {
  const failures = new Set<string>();

  for (const { value: vector } of corpus.vectors) {
    for (const check of vector.conformance_checks ?? []) {
      if (
        check.expected_terminal_stage !== "identifier"
        && checkCoreSignedEvent(vector, check).terminalStage === "identifier"
      ) {
        failures.add(`${vector.vector_id} :: ${check.event_pointer}`);
      }
    }
  }

  return [...failures].sort(compareText);
}
