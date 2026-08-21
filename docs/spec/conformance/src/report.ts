import type { GateId } from "./gates/index.js";
import type { ConformanceRun } from "./run.js";

export type ReportGate = {
  gate: GateId;
  name: string;
  count: number;
  failures: string[];
};

export type ReportDocument = {
  source_commit: string;
  artifact_set_sha256: string;
  vector_count: number;
  executed_declaration_count: number;
  gates: ReportGate[];
  totals: {
    gates: number;
    gates_with_failures: number;
    failures: number;
  };
};

export function buildReport(run: ConformanceRun): ReportDocument {
  const gates = run.results.map(({ id, name, failures }) => ({
    gate: id,
    name,
    count: failures.length,
    failures: [...failures],
  }));
  return {
    source_commit: run.sourceCommit,
    artifact_set_sha256: run.artifactSetSha256,
    vector_count: run.vectorCount,
    executed_declaration_count: run.executedDeclarationCount,
    gates,
    totals: {
      gates: gates.length,
      gates_with_failures: gates.filter(({ count }) => count > 0).length,
      failures: gates.reduce((total, { count }) => total + count, 0),
    },
  };
}

export function renderReportJson(run: ConformanceRun): string {
  return `${JSON.stringify(buildReport(run), null, 2)}\n`;
}

function encodeTableCell(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")
    .replaceAll("|", "&#124;")
    .replaceAll("\r", "&#13;")
    .replaceAll("\n", "&#10;");
}

export function renderDebtMarkdown(run: ConformanceRun): string {
  const report = buildReport(run);
  const rows = report.gates.map(({ gate, name, count, failures }) => {
    const keys = failures.length === 0
      ? "—"
      : failures.map((failure) => `<code>${encodeTableCell(failure)}</code>`).join("<br>");
    return `| ${encodeTableCell(gate)} | ${encodeTableCell(name)} | ${count} | ${keys} |`;
  });
  const gateWord = report.totals.gates_with_failures === 1 ? "gate" : "gates";
  return [
    "# Conformance debt",
    "",
    `Source commit: \`${report.source_commit}\``,
    `Artifact set SHA-256: \`${report.artifact_set_sha256}\``,
    `Vector count: **${report.vector_count}**`,
    `Executed declaration count: **${report.executed_declaration_count}**`,
    "",
    "| Gate | Name | Count | Failure keys |",
    "| --- | --- | ---: | --- |",
    ...rows,
    "",
    `Total failures: **${report.totals.failures}** across **${report.totals.gates_with_failures}** ${gateWord}.`,
    "",
  ].join("\n");
}
