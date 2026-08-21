import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import type { Dirent } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { LoadCorpusOptions } from "./artifacts.js";
import { ALL_GATES, type GateId } from "./gates/index.js";
import {
  compareBaseline,
  parseBaseline,
  serializeBaseline,
} from "./ratchet.js";
import { renderDebtMarkdown, renderReportJson } from "./report.js";
import { runConformance, type ConformanceRun } from "./run.js";

const CONFORMANCE_DIRECTORY = "docs/spec/conformance";
const SNAPSHOT_MANIFEST = "docs/spec/vectors/snapshot.json";
const REPORT_PATH = `${CONFORMANCE_DIRECTORY}/report.json`;
const DEBT_PATH = `${CONFORMANCE_DIRECTORY}/DEBT.md`;
const USAGE = "usage: cli.ts check --source-root <path> --snapshot-root <path> --source-commit <sha> --snapshot-commit <sha>";

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

function canonicalRepositoryRoot(repositoryRoot: string): string | undefined {
  try {
    const canonicalRoot = realpathSync(repositoryRoot);
    return lstatSync(canonicalRoot).isDirectory()
      && existsSync(join(canonicalRoot, SNAPSHOT_MANIFEST))
      ? canonicalRoot
      : undefined;
  } catch {
    return undefined;
  }
}

function firstUnsafeProjectionComponent(
  repositoryRoot: string,
  repositoryPath: string,
): string | undefined {
  const segments = repositoryPath.split("/");
  if (
    segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")
    || resolve(repositoryRoot, repositoryPath) !== join(repositoryRoot, repositoryPath)
  ) {
    return repositoryPath;
  }

  let absolutePath = repositoryRoot;
  let relativePath = "";
  for (const [index, segment] of segments.entries()) {
    absolutePath = join(absolutePath, segment);
    relativePath = relativePath.length === 0 ? segment : `${relativePath}/${segment}`;
    try {
      const entry = lstatSync(absolutePath);
      if (
        entry.isSymbolicLink()
        || (index < segments.length - 1 && !entry.isDirectory())
        || (index === segments.length - 1 && !entry.isFile())
      ) {
        return relativePath;
      }
    } catch (error) {
      const code = error !== null && typeof error === "object" && "code" in error
        ? error.code
        : undefined;
      return code === "ENOENT" ? undefined : relativePath;
    }
  }
  return undefined;
}

function authoringPreflightMessages(
  repositoryRoot: string,
  paths: readonly string[],
): string[] {
  const unsafe = new Set(paths.flatMap((path) => {
    const component = firstUnsafeProjectionComponent(repositoryRoot, path);
    return component === undefined ? [] : [component];
  }));
  return [...unsafe]
    .sort()
    .map((path) => `authoring failure :: unsafe projection path :: ${path}`);
}

function baselineDirectoryMessages(repositoryRoot: string): string[] {
  const directoryPath = `${CONFORMANCE_DIRECTORY}/baselines`;
  let entries: Dirent[];
  try {
    entries = readdirSync(join(repositoryRoot, directoryPath), { withFileTypes: true })
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  } catch (error) {
    const code = error !== null && typeof error === "object" && "code" in error
      ? error.code
      : undefined;
    return code === "ENOENT"
      ? []
      : [`baseline directory unreadable :: ${directoryPath}`];
  }
  const expectedNames = new Set(BASELINE_FILES.map(({ path }) => basename(path)));
  return entries.flatMap((entry) => {
    const path = `${directoryPath}/${entry.name}`;
    if (!expectedNames.has(entry.name)) {
      return [`baseline directory unexpected entry :: ${path}`];
    }
    return entry.isFile() ? [] : [`baseline directory invalid entry :: ${path}`];
  });
}

export function authorBaselines(options: LoadCorpusOptions): CommandResult {
  const run = runConformance(options);
  const canonicalRoot = canonicalRepositoryRoot(options.snapshotRoot);
  if (canonicalRoot === undefined) {
    return failed([
      ...corpusIssueMessages(run),
      "authoring failure :: repository root is not canonical",
    ]);
  }
  const pathMessages = authoringPreflightMessages(
    canonicalRoot,
    BASELINE_FILES.map(({ path }) => path),
  );
  const preflightMessages = [
    ...corpusIssueMessages(run),
    ...pathMessages,
    ...(pathMessages.length > 0 ? [] : baselineDirectoryMessages(canonicalRoot)),
  ];
  if (preflightMessages.length > 0) {
    return failed(preflightMessages);
  }

  const messages: string[] = [];
  for (const baselineFile of BASELINE_FILES) {
    const result = run.results.find(({ id }) => id === baselineFile.gate);
    if (result === undefined) {
      messages.push(`authoring failure :: missing result for ${baselineFile.gate}`);
      continue;
    }
    const error = writeProjection(
      canonicalRoot,
      baselineFile.path,
      serializeBaseline(result.id, result.failures),
    );
    if (error !== undefined) {
      messages.push(error);
    }
  }
  return messages.length === 0 ? { exitCode: 0, messages } : failed(messages);
}

export function authorReport(options: LoadCorpusOptions): CommandResult {
  const run = runConformance(options);
  const canonicalRoot = canonicalRepositoryRoot(options.snapshotRoot);
  if (canonicalRoot === undefined) {
    return failed([
      ...corpusIssueMessages(run),
      "authoring failure :: repository root is not canonical",
    ]);
  }
  const preflightMessages = [
    ...corpusIssueMessages(run),
    ...authoringPreflightMessages(canonicalRoot, [REPORT_PATH, DEBT_PATH]),
  ];
  if (preflightMessages.length > 0) {
    return failed(preflightMessages);
  }

  const messages = [
    writeProjection(canonicalRoot, REPORT_PATH, renderReportJson(run)),
    writeProjection(canonicalRoot, DEBT_PATH, renderDebtMarkdown(run)),
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join(",") === [...keys].sort().join(",");
}

function isSortedUniqueStrings(value: unknown): value is string[] {
  return Array.isArray(value)
    && value.every((item) => typeof item === "string")
    && value.every((item, index) => index === 0 || value[index - 1]! < item);
}

function isReportProjection(value: unknown): boolean {
  if (
    !isRecord(value)
    || !hasExactKeys(value, [
      "family_version",
      "registry_revision",
      "registry_digest",
      "gates",
      "totals",
    ])
    || typeof value.family_version !== "string"
    || value.family_version.length === 0
    || !Number.isSafeInteger(value.registry_revision)
    || (value.registry_revision as number) < 0
    || typeof value.registry_digest !== "string"
    || !/^[0-9a-f]{64}$/u.test(value.registry_digest)
    || !Array.isArray(value.gates)
    || value.gates.length !== BASELINE_FILES.length
  ) {
    return false;
  }

  let failureTotal = 0;
  let gatesWithFailures = 0;
  for (const [index, gate] of value.gates.entries()) {
    const expected = BASELINE_FILES[index]!;
    if (
      !isRecord(gate)
      || !hasExactKeys(gate, ["gate", "name", "count", "failures"])
      || gate.gate !== expected.gate
      || gate.name !== expected.name
      || !Number.isSafeInteger(gate.count)
      || (gate.count as number) < 0
      || !isSortedUniqueStrings(gate.failures)
      || gate.count !== gate.failures.length
    ) {
      return false;
    }
    failureTotal += gate.failures.length;
    gatesWithFailures += gate.failures.length === 0 ? 0 : 1;
  }

  return isRecord(value.totals)
    && hasExactKeys(value.totals, ["gates", "gates_with_failures", "failures"])
    && value.totals.gates === BASELINE_FILES.length
    && value.totals.gates_with_failures === gatesWithFailures
    && value.totals.failures === failureTotal;
}

function reportProjectionMessages(source: string, path: string): string[] {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    return [`projection invalid :: ${path} :: must be valid JSON`];
  }
  const messages: string[] = [];
  if (!isReportProjection(value)) {
    messages.push(`projection invalid :: ${path} :: invalid report shape`);
  }
  if (source !== `${JSON.stringify(value, null, 2)}\n`) {
    messages.push(`projection is not canonical :: ${path}`);
  }
  return messages;
}

function debtProjectionMessages(source: string, path: string): string[] {
  const messages: string[] = [];
  if (!source.endsWith("\n") || source.endsWith("\n\n")) {
    messages.push(`projection is not canonical :: ${path}`);
  }
  const gates = source
    .split("\n")
    .flatMap((line) => {
      const match = /^\| (G(?:[1-9]|1[01])) \|/u.exec(line);
      return match === null ? [] : [match[1]!];
    });
  if (gates.join(",") !== BASELINE_FILES.map(({ gate }) => gate).join(",")) {
    messages.push(`projection invalid :: ${path} :: must contain exactly one G1-G11 row`);
  }
  return messages;
}

export function checkRepository(options: LoadCorpusOptions): CommandResult {
  const run = runConformance(options);
  const repositoryRoot = options.snapshotRoot;
  const messages = [
    ...corpusIssueMessages(run),
    ...baselineDirectoryMessages(repositoryRoot),
  ];
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
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : "invalid baseline";
      messages.push(`${baselineFile.gate} ${baselineFile.name} baseline invalid :: ${detail}`);
      continue;
    }

    const result = run.results.find(({ id }) => id === baselineFile.gate);
    if (result === undefined) {
      if (run.issues.length === 0) {
        messages.push(`${baselineFile.gate} ${baselineFile.name} result missing`);
      }
      continue;
    }
    const comparison = compareBaseline(result.failures, failures);
    messages.push(...comparison.newFailures.map((failure) =>
      `${result.id} ${result.name} new debt :: ${failure}`));
    messages.push(...comparison.staleFailures.map((failure) =>
      `${result.id} ${result.name} stale debt :: ${failure}`));
  }

  const reportSource = readProjection(repositoryRoot, REPORT_PATH);
  if (reportSource === undefined) {
    messages.push(`projection missing :: ${REPORT_PATH}`);
  } else {
    messages.push(...reportProjectionMessages(reportSource, REPORT_PATH));
    if (run.results.length > 0 && reportSource !== renderReportJson(run)) {
      messages.push(`projection drift :: ${REPORT_PATH}`);
    }
  }
  const debtSource = readProjection(repositoryRoot, DEBT_PATH);
  if (debtSource === undefined) {
    messages.push(`projection missing :: ${DEBT_PATH}`);
  } else {
    messages.push(...debtProjectionMessages(debtSource, DEBT_PATH));
    if (run.results.length > 0 && debtSource !== renderDebtMarkdown(run)) {
      messages.push(`projection drift :: ${DEBT_PATH}`);
    }
  }

  return messages.length === 0 ? { exitCode: 0, messages } : failed(messages);
}

function parseCorpusOptions(args: readonly string[]): {
  command: "check" | "baseline-author" | "report-author";
  options: LoadCorpusOptions;
} | undefined {
  const command = args[0];
  if (command !== "check" && command !== "baseline-author" && command !== "report-author") {
    return undefined;
  }
  if (args.length !== 9) return undefined;
  const values = new Map<string, string>();
  for (let index = 1; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (
      flag === undefined
      || value === undefined
      || values.has(flag)
      || !["--source-root", "--snapshot-root", "--source-commit", "--snapshot-commit"].includes(flag)
    ) return undefined;
    values.set(flag, value);
  }
  const sourceRoot = values.get("--source-root");
  const snapshotRoot = values.get("--snapshot-root");
  const sourceCommit = values.get("--source-commit");
  const snapshotCommit = values.get("--snapshot-commit");
  if (
    sourceRoot === undefined
    || snapshotRoot === undefined
    || sourceCommit === undefined
    || snapshotCommit === undefined
  ) return undefined;
  return { command, options: { sourceRoot, snapshotRoot, sourceCommit, snapshotCommit } };
}

export function runCli(args: readonly string[], options: CliOptions = {}): 0 | 1 | 2 {
  const writeLine = options.writeLine ?? ((line: string) => console.error(line));
  const parsed = parseCorpusOptions(args);
  if (parsed === undefined) {
    writeLine(USAGE);
    return 2;
  }
  const result = parsed.command === "check"
    ? checkRepository(parsed.options)
    : parsed.command === "baseline-author"
      ? authorBaselines(parsed.options)
      : authorReport(parsed.options);
  for (const message of result.messages) {
    writeLine(message);
  }
  return result.exitCode;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  process.exitCode = runCli(process.argv.slice(2));
}
