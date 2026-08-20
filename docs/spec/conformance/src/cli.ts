import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ALL_GATES, type GateId } from "./gates/index.js";
import {
  compareBaseline,
  parseBaseline,
  serializeBaseline,
} from "./ratchet.js";
import { renderDebtMarkdown, renderReportJson } from "./report.js";
import { runConformance, type ConformanceRun } from "./run.js";

const CONFORMANCE_DIRECTORY = "docs/spec/conformance";
const FAMILY_MANIFEST = "docs/spec/releases/family/0.5.0.json";
const REPORT_PATH = `${CONFORMANCE_DIRECTORY}/report.json`;
const DEBT_PATH = `${CONFORMANCE_DIRECTORY}/DEBT.md`;
const USAGE = "usage: cli.ts <check|baseline-author|report-author> [repository-root]";

export const BASELINE_FILES: readonly {
  gate: GateId;
  name: string;
  path: string;
}[] = ALL_GATES.map(({ id, name }) => ({
  gate: id,
  name,
  path: `${CONFORMANCE_DIRECTORY}/baselines/${id}-${name}.json`,
}));

export type CommandResult = {
  exitCode: 0 | 1;
  messages: string[];
};

type CliOptions = {
  cwd?: string;
  writeLine?: (line: string) => void;
};

function corpusIssueMessages(run: ConformanceRun): string[] {
  return run.issues.map(({ code, path, message }) =>
    `corpus issue :: ${code} :: ${path} :: ${message}`);
}

function failed(messages: string[]): CommandResult {
  return { exitCode: 1, messages };
}

function writeProjection(repositoryRoot: string, path: string, contents: string): string | undefined {
  try {
    const target = join(repositoryRoot, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, contents, "utf8");
    return undefined;
  } catch {
    return `authoring failure :: ${path}`;
  }
}

export function authorBaselines(repositoryRoot: string): CommandResult {
  const run = runConformance(repositoryRoot);
  if (run.issues.length > 0) {
    return failed(corpusIssueMessages(run));
  }

  const messages: string[] = [];
  for (const baselineFile of BASELINE_FILES) {
    const result = run.results.find(({ id }) => id === baselineFile.gate);
    if (result === undefined) {
      messages.push(`authoring failure :: missing result for ${baselineFile.gate}`);
      continue;
    }
    const error = writeProjection(
      repositoryRoot,
      baselineFile.path,
      serializeBaseline(result.id, result.failures),
    );
    if (error !== undefined) {
      messages.push(error);
    }
  }
  return messages.length === 0 ? { exitCode: 0, messages } : failed(messages);
}

export function authorReport(repositoryRoot: string): CommandResult {
  const run = runConformance(repositoryRoot);
  if (run.issues.length > 0) {
    return failed(corpusIssueMessages(run));
  }

  const messages = [
    writeProjection(repositoryRoot, REPORT_PATH, renderReportJson(run)),
    writeProjection(repositoryRoot, DEBT_PATH, renderDebtMarkdown(run)),
  ].filter((message): message is string => message !== undefined);
  return messages.length === 0 ? { exitCode: 0, messages } : failed(messages);
}

function readProjection(repositoryRoot: string, path: string): string | undefined {
  try {
    return readFileSync(join(repositoryRoot, path), "utf8");
  } catch {
    return undefined;
  }
}

export function checkRepository(repositoryRoot: string): CommandResult {
  const run = runConformance(repositoryRoot);
  if (run.issues.length > 0) {
    return failed(corpusIssueMessages(run));
  }

  const messages: string[] = [];
  for (const baselineFile of BASELINE_FILES) {
    const source = readProjection(repositoryRoot, baselineFile.path);
    if (source === undefined) {
      messages.push(`${baselineFile.gate} ${baselineFile.name} baseline missing :: ${baselineFile.path}`);
      continue;
    }

    let failures: string[];
    try {
      const baseline = parseBaseline(source, baselineFile.gate);
      failures = baseline.failures;
      if (source !== serializeBaseline(baseline.gate, baseline.failures)) {
        messages.push(
          `${baselineFile.gate} ${baselineFile.name} baseline is not canonical :: ${baselineFile.path}`,
        );
        continue;
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : "invalid baseline";
      messages.push(`${baselineFile.gate} ${baselineFile.name} baseline invalid :: ${detail}`);
      continue;
    }

    const result = run.results.find(({ id }) => id === baselineFile.gate);
    if (result === undefined) {
      messages.push(`${baselineFile.gate} ${baselineFile.name} result missing`);
      continue;
    }
    const comparison = compareBaseline(result.failures, failures);
    messages.push(...comparison.newFailures.map((failure) =>
      `${result.id} ${result.name} new debt :: ${failure}`));
    messages.push(...comparison.staleFailures.map((failure) =>
      `${result.id} ${result.name} stale debt :: ${failure}`));
  }

  const expectedReport = renderReportJson(run);
  if (readProjection(repositoryRoot, REPORT_PATH) !== expectedReport) {
    messages.push(`projection drift :: ${REPORT_PATH}`);
  }
  const expectedDebt = renderDebtMarkdown(run);
  if (readProjection(repositoryRoot, DEBT_PATH) !== expectedDebt) {
    messages.push(`projection drift :: ${DEBT_PATH}`);
  }

  return messages.length === 0 ? { exitCode: 0, messages } : failed(messages);
}

function findRepositoryRoot(start: string): string | undefined {
  let candidate = resolve(start);
  while (true) {
    if (existsSync(join(candidate, FAMILY_MANIFEST))) {
      return candidate;
    }
    const parent = dirname(candidate);
    if (parent === candidate) {
      return undefined;
    }
    candidate = parent;
  }
}

export function runCli(args: readonly string[], options: CliOptions = {}): 0 | 1 | 2 {
  const writeLine = options.writeLine ?? ((line: string) => console.error(line));
  const [command, explicitRoot] = args;
  if (
    args.length < 1
    || args.length > 2
    || (command !== "check" && command !== "baseline-author" && command !== "report-author")
  ) {
    writeLine(USAGE);
    return 2;
  }

  const repositoryRoot = explicitRoot ?? findRepositoryRoot(options.cwd ?? process.cwd());
  if (repositoryRoot === undefined) {
    writeLine("corpus issue :: missing-required-root :: . :: repository root not found");
    return 1;
  }

  const result = command === "check"
    ? checkRepository(repositoryRoot)
    : command === "baseline-author"
      ? authorBaselines(repositoryRoot)
      : authorReport(repositoryRoot);
  for (const message of result.messages) {
    writeLine(message);
  }
  return result.exitCode;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  process.exitCode = runCli(process.argv.slice(2));
}
