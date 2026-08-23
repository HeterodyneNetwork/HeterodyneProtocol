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
    sourceCommit: "1".repeat(40),
    snapshotCommit: "2".repeat(40),
    artifactSetSha256: "a".repeat(64),
    vectorCount: 23,
    executedDeclarationCount: 0,
    results,
    issues: [],
  };
}

describe("report projections", () => {
  it("records snapshot artifact identity, counts, every measured key, and aggregate totals", () => {
    expect(buildReport(fixtureRun())).toEqual({
      source_commit: "1".repeat(40),
      artifact_set_sha256: "a".repeat(64),
      vector_count: 23,
      executed_declaration_count: 0,
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
    expect(rendered).not.toContain("snapshot_commit");
    expect(Object.keys(JSON.parse(rendered) as Record<string, unknown>)).toEqual([
      "source_commit",
      "artifact_set_sha256",
      "vector_count",
      "executed_declaration_count",
      "gates",
      "totals",
    ]);
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
    expect(rendered).toContain(`Source commit: \`${"1".repeat(40)}\``);
    expect(rendered).toContain(`Artifact set SHA-256: \`${"a".repeat(64)}\``);
    expect(rendered).toContain("Vector count: **23**");
    expect(rendered).toContain("Executed declaration count: **0**");
    expect(rendered).not.toContain("snapshot_commit");
    expect(rendered.endsWith("\n")).toBe(true);
    expect(rendered.endsWith("\n\n")).toBe(false);
  });

  it("encodes pipe, CR, and LF content without injecting Markdown table structure", () => {
    const run = fixtureRun();
    run.results[0] = {
      id: "G1",
      name: "anchor|resolution\r\nname",
      failures: ["key|pipe", "line\rbreak", "line\nbreak"],
    };

    const rendered = renderDebtMarkdown(run);
    const gateRows = rendered.split("\n").filter((line) => /^\| G(?:[1-9]|1[01]) \|/u.test(line));

    expect(gateRows).toHaveLength(11);
    expect(gateRows[0]).toBe(
      "| G1 | anchor&#124;resolution&#13;&#10;name | 3 | "
      + "<code>key&#124;pipe</code><br><code>line&#13;break</code>"
      + "<br><code>line&#10;break</code> |",
    );
    expect(gateRows.every((row) => row.split("|").length === 6)).toBe(true);
    expect(rendered).not.toContain("\r");
  });
});
