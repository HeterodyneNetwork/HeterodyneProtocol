import type { GateId } from "./gates/index.js";
import type { ConformanceRun } from "./run.js";

export type ReportGate = {
  gate: GateId;
  name: string;
  count: number;
  failures: string[];
};

export type ReportDocument = {
  family_version: string;
  registry_revision: number;
  registry_digest: string;
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
    family_version: run.familyVersion,
    registry_revision: run.registryRevision,
    registry_digest: run.registryDigest,
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

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function renderDebtMarkdown(run: ConformanceRun): string {
  const report = buildReport(run);
  const rows = report.gates.map(({ gate, name, count, failures }) => {
    const keys = failures.length === 0
      ? "—"
      : failures.map((failure) => `<code>${escapeHtml(failure)}</code>`).join("<br>");
    return `| ${gate} | ${name} | ${count} | ${keys} |`;
  });
  const gateWord = report.totals.gates_with_failures === 1 ? "gate" : "gates";
  return [
    "# Conformance debt",
    "",
    `Family: \`${report.family_version}\``,
    `Registry: revision **${report.registry_revision}**, digest \`${report.registry_digest}\``,
    "",
    "| Gate | Name | Count | Failure keys |",
    "| --- | --- | ---: | --- |",
    ...rows,
    "",
    `Total failures: **${report.totals.failures}** across **${report.totals.gates_with_failures}** ${gateWord}.`,
    "",
  ].join("\n");
}
