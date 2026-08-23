import { loadCorpus, type LoadCorpusOptions } from "./artifacts.js";
import { ALL_GATES, type GateResult } from "./gates/index.js";
import type { CorpusIssue } from "./types.js";

export type ConformanceRun = {
  sourceCommit: string;
  snapshotCommit: string;
  artifactSetSha256: string;
  vectorCount: number;
  executedDeclarationCount: number;
  results: GateResult[];
  issues: CorpusIssue[];
};

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function runConformance(options: LoadCorpusOptions): ConformanceRun {
  const loaded = loadCorpus(options);
  if (loaded.corpus === undefined) {
    return {
      sourceCommit: options.sourceCommit,
      snapshotCommit: options.snapshotCommit,
      artifactSetSha256: "",
      vectorCount: 0,
      executedDeclarationCount: 0,
      results: [],
      issues: loaded.issues,
    };
  }

  const { corpus } = loaded;
  return {
    sourceCommit: corpus.sourceCommit,
    snapshotCommit: corpus.snapshotCommit,
    artifactSetSha256: loaded.artifactSetSha256,
    vectorCount: loaded.vectorCount,
    executedDeclarationCount: corpus.vectors.reduce(
      (count, { value }) => count + (value.conformance_checks?.length ?? 0),
      0,
    ),
    results: ALL_GATES.map(({ id, name, evaluate }) => ({
      id,
      name,
      failures: [...new Set(evaluate(corpus))].sort(compareText),
    })),
    issues: loaded.issues,
  };
}
