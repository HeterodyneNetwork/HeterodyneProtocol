import { describe, expect, it } from "vitest";
import type { GateResult } from "./gates/index.js";
import {
  buildReport,
  renderDebtMarkdown,
  renderReportJson,
} from "./report.js";
import type { ConformanceRun } from "./run.js";

const gateNames = [
  "anchor-resolution",
  "reason-code-closure",
  "invariant-completeness",
  "anchor-coverage",
  "fixtures-consistency",
  "dead-vocabulary",
  "orphan-schemas",
  "identifier-integrity",
  "signature-integrity",
  "nip01-raw",
  "negative-hygiene",
] as const;

function fixtureRun(): ConformanceRun {
  const results = gateNames.map((name, index): GateResult => ({
    id: `G${index + 1}` as GateResult["id"],
    name,
    failures: index === 0 ? ["a", "b"] : [],
  }));
  return {
    familyVersion: "heterodyne/0.5.0",
    registryRevision: 13,
    registryDigest: "aa".repeat(32),
    results,
    issues: [],
  };
}

describe("report projections", () => {
  it("records registry identity, every measured key, and aggregate totals", () => {
    expect(buildReport(fixtureRun())).toEqual({
      family_version: "heterodyne/0.5.0",
      registry_revision: 13,
      registry_digest: "aa".repeat(32),
      gates: gateNames.map((name, index) => ({
        gate: `G${index + 1}`,
        name,
        count: index === 0 ? 2 : 0,
        failures: index === 0 ? ["a", "b"] : [],
      })),
      totals: {
        gates: 11,
        gates_with_failures: 1,
        failures: 2,
      },
    });
  });

  it("uses canonical two-space JSON with exactly one final LF", () => {
    const expected = buildReport(fixtureRun());
    const rendered = renderReportJson(fixtureRun());

    expect(rendered).toBe(`${JSON.stringify(expected, null, 2)}\n`);
    expect(rendered).toContain('\n  "family_version"');
    expect(rendered.endsWith("\n")).toBe(true);
    expect(rendered.endsWith("\n\n")).toBe(false);
  });

  it("renders exactly one deterministic table row for each G1 through G11", () => {
    const rendered = renderDebtMarkdown(fixtureRun());
    const gateRows = rendered.split("\n").filter((line) => /^\| G(?:[1-9]|1[01]) \|/u.test(line));

    expect(gateRows).toEqual(gateNames.map((name, index) =>
      index === 0
        ? `| G1 | ${name} | 2 | <code>a</code><br><code>b</code> |`
        : `| G${index + 1} | ${name} | 0 | — |`,
    ));
    expect(rendered).toContain("Total failures: **2** across **1** gate.");
    expect(rendered.endsWith("\n")).toBe(true);
    expect(rendered.endsWith("\n\n")).toBe(false);
  });
});
