import { loadCorpus } from "./artifacts.js";
import { ALL_GATES, type GateResult } from "./gates/index.js";
import type { CorpusIssue } from "./types.js";

export type ConformanceRun = {
  familyVersion: string;
  registryRevision: number;
  registryDigest: string;
  results: GateResult[];
  issues: CorpusIssue[];
};

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function runConformance(repositoryRoot: string): ConformanceRun {
  const loaded = loadCorpus(repositoryRoot);
  if (loaded.corpus === undefined) {
    return {
      familyVersion: "",
      registryRevision: 0,
      registryDigest: "",
      results: [],
      issues: loaded.issues,
    };
  }

  const { corpus } = loaded;
  return {
    familyVersion: corpus.familyVersion,
    registryRevision: corpus.registryRevision,
    registryDigest: corpus.registryDigest,
    results: ALL_GATES.map(({ id, name, evaluate }) => ({
      id,
      name,
      failures: [...new Set(evaluate(corpus))].sort(compareText),
    })),
    issues: loaded.issues,
  };
}
