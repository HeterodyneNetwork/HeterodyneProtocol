import type { GateId } from "./gates/index.js";

export type Baseline = {
  gate: GateId;
  failures: string[];
};

export type BaselineComparison = {
  newFailures: string[];
  staleFailures: string[];
};

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareText);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function compareBaseline(
  actual: readonly string[],
  baseline: readonly string[],
): BaselineComparison {
  const actualSet = new Set(actual);
  const baselineSet = new Set(baseline);
  return {
    newFailures: sortedUnique(actual.filter((failure) => !baselineSet.has(failure))),
    staleFailures: sortedUnique(baseline.filter((failure) => !actualSet.has(failure))),
  };
}

export function serializeBaseline(gate: GateId, failures: readonly string[]): string {
  return `${JSON.stringify({ gate, failures: sortedUnique(failures) }, null, 2)}\n`;
}

export function parseBaseline(source: string, expectedGate: GateId): Baseline {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error("baseline must be valid JSON");
  }
  if (
    !isRecord(value)
    || Object.keys(value).sort(compareText).join(",") !== "failures,gate"
  ) {
    throw new Error("baseline must contain exactly gate and failures");
  }
  if (value.gate !== expectedGate) {
    throw new Error(`baseline must identify ${expectedGate}`);
  }
  if (!Array.isArray(value.failures) || !value.failures.every((item) => typeof item === "string")) {
    throw new Error("baseline failures must be sorted unique strings");
  }
  const failures = value.failures as string[];
  if (failures.some((failure, index) => index > 0 && failures[index - 1]! >= failure)) {
    throw new Error("baseline failures must be sorted unique strings");
  }
  return { gate: expectedGate, failures: [...failures] };
}
