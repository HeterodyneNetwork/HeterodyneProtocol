import {
  createHash,
} from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  authorBaselines,
  authorReport,
  BASELINE_FILES,
  checkRepository,
  runCli,
} from "./cli.js";
import { loadCorpus } from "./artifacts.js";
import { ALL_GATES, STATIC_GATES } from "./gates/index.js";
import { runConformance } from "./run.js";
import {
  createTestCorpus,
  readTestManifest,
  vectorPath,
  vectorSchemaPath,
  writeText,
  type TestCorpus,
} from "./test-support.js";

const temps: string[] = [];

afterEach(() => {
  for (const path of temps.splice(0)) rmSync(path, { recursive: true, force: true });
});

function corpus(options: { withVector?: boolean } = {}): TestCorpus {
  const value = createTestCorpus(options);
  temps.push(value.root);
  return value;
}

function projectedCorpus(): TestCorpus {
  const input = corpus();
  expect(authorBaselines(input)).toEqual({ exitCode: 0, messages: [] });
  expect(authorReport(input)).toEqual({ exitCode: 0, messages: [] });
  return input;
}

function temporaryDirectory(): string {
  const root = mkdtempSync(join(tmpdir(), "heterodyne-author-outside-"));
  temps.push(root);
  return root;
}

function projectionSnapshot(input: TestCorpus): Record<string, unknown> {
  const paths = [
    ...BASELINE_FILES.map(({ path }) => path),
    "docs/spec/conformance/report.json",
    "docs/spec/conformance/DEBT.md",
  ];
  return Object.fromEntries(paths.map((path) => {
    const target = join(input.snapshotRoot, path);
    const stat = statSync(target);
    return [path, {
      bytes: readFileSync(target).toString("base64"),
      mode: stat.mode,
      mtimeMs: stat.mtimeMs,
      size: stat.size,
    }];
  }));
}

function cliArguments(input: TestCorpus): string[] {
  return [
    "check",
    "--source-root", input.sourceRoot,
    "--snapshot-root", input.snapshotRoot,
    "--source-commit", input.sourceCommit,
    "--snapshot-commit", input.snapshotCommit,
  ];
}

describe("split-root conformance integration", () => {
  it("keeps current specification edits outside pinned source interpretation", () => {
    const input = corpus();
    const before = runConformance(input);
    writeText(
      input.snapshotRoot,
      "docs/spec/heterodyne-core.md",
      '# current HEAD\n<a id="core-current-only"></a>\n',
    );

    expect(runConformance(input)).toEqual(before);
    expect(before.issues).toEqual([]);
  });

  it("hashes only the sorted snapshot artifact array for projection identity", () => {
    const input = corpus();
    const artifacts = readTestManifest(input.snapshotRoot).artifacts;
    const expected = createHash("sha256")
      .update(`${JSON.stringify(artifacts, null, 2)}\n`, "utf8")
      .digest("hex");
    const before = runConformance(input);

    writeText(input.sourceRoot, "docs/spec/heterodyne-core.md", "changed current draft bytes\n");
    const after = runConformance(input);

    expect(before.artifactSetSha256).toBe(expected);
    expect(after.artifactSetSha256).toBe(expected);
  });

  it("rejects current snapshot vector and packaged-schema edits by exact digest", () => {
    const input = corpus();
    writeText(input.snapshotRoot, vectorPath, `${readFileSync(join(
      input.snapshotRoot,
      vectorPath,
    ), "utf8")}\n`);
    writeText(input.snapshotRoot, vectorSchemaPath, `${readFileSync(join(
      input.snapshotRoot,
      vectorSchemaPath,
    ), "utf8")}\n`);

    expect(runConformance(input).issues).toEqual(expect.arrayContaining([
      {
        code: "artifact-digest-mismatch",
        path: vectorPath,
        message: "snapshot artifact sha256 does not match exact file bytes",
      },
      {
        code: "artifact-digest-mismatch",
        path: vectorSchemaPath,
        message: "snapshot artifact sha256 does not match exact file bytes",
      },
    ]));
  });

  it("runs every static and subject gate with zero executable declarations", () => {
    const input = corpus();
    const loaded = loadCorpus(input);
    const run = runConformance(input);

    expect(loaded.corpus?.vectors).toHaveLength(1);
    expect(loaded.corpus?.vectors.flatMap(({ value }) => value.conformance_checks ?? []))
      .toEqual([]);
    expect(run.issues).toEqual([]);
    expect(run.results.map(({ id }) => id)).toEqual(ALL_GATES.map(({ id }) => id));
    expect(run.results.slice(0, STATIC_GATES.length).map(({ id }) => id))
      .toEqual(STATIC_GATES.map(({ id }) => id));
    expect(run.results.slice(STATIC_GATES.length)).toHaveLength(4);
    expect(run.results.slice(STATIC_GATES.length).every(({ failures }) => failures.length === 0))
      .toBe(true);
    expect(run.vectorCount).toBe(1);
    expect(run.executedDeclarationCount).toBe(0);
  });

  it("fails before conformance when history inputs are absent instead of substituting HEAD", () => {
    const output: string[] = [];

    expect(runCli(["check"], { cwd: process.cwd(), writeLine: (line) => output.push(line) }))
      .toBe(2);
    expect(output).toEqual([
      "usage: cli.ts check --source-root <path> --snapshot-root <path> --source-commit <sha> --snapshot-commit <sha>",
    ]);
  });

  it("keeps explicit-root checks read-only", () => {
    const input = projectedCorpus();
    const before = projectionSnapshot(input);
    const output: string[] = [];

    expect(runCli(cliArguments(input), { writeLine: (line) => output.push(line) })).toBe(0);
    expect(output).toEqual([]);
    expect(projectionSnapshot(input)).toEqual(before);
  });

  it("accumulates corpus, baseline, and projection diagnostics through the CLI", () => {
    const input = projectedCorpus();
    writeText(input.snapshotRoot, vectorPath, "{ malformed vector\n");
    writeText(
      input.snapshotRoot,
      "docs/spec/conformance/baselines/G1-anchor-resolution.json",
      "{ malformed baseline\n",
    );
    writeText(input.snapshotRoot, "docs/spec/conformance/report.json", "{}\n");
    rmSync(join(input.snapshotRoot, "docs/spec/conformance/DEBT.md"));
    const output: string[] = [];

    expect(runCli(cliArguments(input), { writeLine: (line) => output.push(line) })).toBe(1);
    expect(output).toEqual(expect.arrayContaining([
      `corpus issue :: artifact-digest-mismatch :: ${vectorPath} :: snapshot artifact sha256 does not match exact file bytes`,
      "G1 anchor-resolution baseline invalid :: baseline must be valid JSON",
      "projection invalid :: docs/spec/conformance/report.json :: invalid report shape",
      "projection missing :: docs/spec/conformance/DEBT.md",
    ]));
  });

  it("rejects stale baseline identity and snapshot commits in committed projections", () => {
    const input = projectedCorpus();
    const baselinePath = "docs/spec/conformance/baselines/G1-anchor-resolution.json";
    const baseline = JSON.parse(
      readFileSync(join(input.snapshotRoot, baselinePath), "utf8"),
    ) as Record<string, unknown>;
    baseline.source_commit = "3".repeat(40);
    baseline.artifact_set_sha256 = "b".repeat(64);
    writeText(input.snapshotRoot, baselinePath, `${JSON.stringify(baseline, null, 2)}\n`);
    const debtPath = "docs/spec/conformance/DEBT.md";
    writeText(
      input.snapshotRoot,
      debtPath,
      readFileSync(join(input.snapshotRoot, debtPath), "utf8")
        .replace("# Conformance debt\n", `# Conformance debt\n\nsnapshot_commit: ${input.snapshotCommit}\n`),
    );

    expect(checkRepository(input).messages).toEqual(expect.arrayContaining([
      "G1 anchor-resolution baseline source commit drift",
      "G1 anchor-resolution baseline artifact set drift",
      `projection invalid :: ${debtPath} :: snapshot_commit is runtime-only`,
    ]));
  });

  it("rejects a symlinked baseline parent before authoring outside the snapshot root", () => {
    const input = corpus();
    const outside = temporaryDirectory();
    mkdirSync(join(input.snapshotRoot, "docs/spec/conformance"), { recursive: true });
    symlinkSync(outside, join(input.snapshotRoot, "docs/spec/conformance/baselines"));

    expect(authorBaselines(input)).toEqual({
      exitCode: 1,
      messages: [
        "authoring failure :: unsafe projection path :: docs/spec/conformance/baselines",
      ],
    });
    expect(readdirSync(outside)).toEqual([]);
  });

  it("rejects a symlinked report target before writing either report projection", () => {
    const input = corpus();
    const outside = temporaryDirectory();
    const conformanceDirectory = join(input.snapshotRoot, "docs/spec/conformance");
    mkdirSync(conformanceDirectory, { recursive: true });
    writeText(outside, "report-target.json", "outside sentinel\n");
    symlinkSync(
      join(outside, "report-target.json"),
      join(conformanceDirectory, "report.json"),
    );

    expect(authorReport(input)).toEqual({
      exitCode: 1,
      messages: [
        "authoring failure :: unsafe projection path :: docs/spec/conformance/report.json",
      ],
    });
    expect(readFileSync(join(outside, "report-target.json"), "utf8"))
      .toBe("outside sentinel\n");
    expect(existsSync(join(conformanceDirectory, "DEBT.md"))).toBe(false);
  });
});
