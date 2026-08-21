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
import {
  createTestRepository,
  refreshReleaseDigests,
  vectorPath,
  vectorSchemaPath,
  writeJson,
  writeText,
} from "./test-support.js";

const temps: string[] = [];

afterEach(() => {
  for (const path of temps.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function repository(): string {
  const root = unprojectedRepository();
  expect(authorBaselines(root)).toEqual({ exitCode: 0, messages: [] });
  expect(authorReport(root)).toEqual({ exitCode: 0, messages: [] });
  return root;
}

function unprojectedRepository(): string {
  const root = createTestRepository();
  temps.push(root);
  return root;
}

function temporaryDirectory(): string {
  const root = mkdtempSync(join(tmpdir(), "heterodyne-author-outside-"));
  temps.push(root);
  return root;
}

function projectionSnapshot(root: string): Record<string, unknown> {
  const paths = [
    ...BASELINE_FILES.map(({ path }) => path),
    "docs/spec/conformance/report.json",
    "docs/spec/conformance/DEBT.md",
  ];
  return Object.fromEntries(paths.map((path) => {
    const target = join(root, path);
    const stat = statSync(target);
    return [path, {
      bytes: readFileSync(target).toString("base64"),
      mode: stat.mode,
      mtimeMs: stat.mtimeMs,
      size: stat.size,
    }];
  }));
}

describe("ratcheted conformance integration", () => {
  it("rejects an unexpected file in the closed baseline directory", () => {
    const root = repository();
    const extraPath = "docs/spec/conformance/baselines/G12-extra.json";
    writeJson(root, extraPath, { gate: "G1", failures: [] });

    expect(checkRepository(root)).toMatchObject({
      exitCode: 1,
      messages: expect.arrayContaining([
        `baseline directory unexpected entry :: ${extraPath}`,
      ]),
    });
  });

  it("fails baseline authoring safely when the closed directory has an extra file", () => {
    const root = repository();
    const extraPath = "docs/spec/conformance/baselines/G12-extra.json";
    writeJson(root, extraPath, { gate: "G1", failures: [] });
    const before = projectionSnapshot(root);

    expect(authorBaselines(root)).toEqual({
      exitCode: 1,
      messages: [`baseline directory unexpected entry :: ${extraPath}`],
    });
    expect(existsSync(join(root, extraPath))).toBe(true);
    expect(projectionSnapshot(root)).toEqual(before);
  });

  it("rejects an expected baseline name that is not a regular directory entry", () => {
    const root = repository();
    const outside = temporaryDirectory();
    const baselinePath = "docs/spec/conformance/baselines/G1-anchor-resolution.json";
    const baselineSource = readFileSync(join(root, baselinePath), "utf8");
    writeText(outside, "G1-anchor-resolution.json", baselineSource);
    rmSync(join(root, baselinePath));
    symlinkSync(join(outside, "G1-anchor-resolution.json"), join(root, baselinePath));

    expect(checkRepository(root)).toMatchObject({
      exitCode: 1,
      messages: expect.arrayContaining([
        `baseline directory invalid entry :: ${baselinePath}`,
      ]),
    });
  });

  it("accumulates corpus, baseline, and projection diagnostics through the public CLI", () => {
    const root = repository();
    writeText(root, vectorPath, "{ malformed vector\n");
    writeText(
      root,
      "docs/spec/conformance/baselines/G1-anchor-resolution.json",
      "{ malformed baseline\n",
    );
    writeText(root, "docs/spec/conformance/report.json", "{}\n");
    rmSync(join(root, "docs/spec/conformance/DEBT.md"));
    const output: string[] = [];

    expect(runCli(["check", root], { writeLine: (line) => output.push(line) })).toBe(1);
    expect(output).toHaveLength(5);
    expect(output[0]).toBe(
      `corpus issue :: artifact-digest-mismatch :: ${vectorPath} :: release artifact sha256 does not match exact file bytes`,
    );
    expect(output[1]).toContain(`corpus issue :: invalid-json :: ${vectorPath} ::`);
    expect(output.slice(2)).toEqual([
      "G1 anchor-resolution baseline invalid :: baseline must be valid JSON",
      "projection invalid :: docs/spec/conformance/report.json :: invalid report shape",
      "projection missing :: docs/spec/conformance/DEBT.md",
    ]);
  });

  it("reports noncanonical bytes plus simultaneous new and stale ratchet debt", () => {
    const root = repository();
    writeText(
      root,
      "docs/spec/conformance/baselines/G1-anchor-resolution.json",
      '{"gate":"G1","failures":["stale-only"]}\n',
    );

    expect(checkRepository(root)).toEqual({
      exitCode: 1,
      messages: [
        "G1 anchor-resolution baseline is not canonical :: docs/spec/conformance/baselines/G1-anchor-resolution.json",
        "G1 anchor-resolution new debt :: core.valid :: heterodyne:0.5.0#core-conformance",
        "G1 anchor-resolution stale debt :: stale-only",
      ],
    });
  });

  it("rejects a symlinked baseline parent before writing any file outside the repository", () => {
    const root = unprojectedRepository();
    const outside = temporaryDirectory();
    mkdirSync(join(root, "docs/spec/conformance"), { recursive: true });
    symlinkSync(outside, join(root, "docs/spec/conformance/baselines"));

    expect(authorBaselines(root)).toEqual({
      exitCode: 1,
      messages: [
        "authoring failure :: unsafe projection path :: docs/spec/conformance/baselines",
      ],
    });
    expect(readdirSync(outside)).toEqual([]);
  });

  it("rejects a symlinked report target before writing it or the sibling DEBT projection", () => {
    const root = unprojectedRepository();
    const outside = temporaryDirectory();
    const conformanceDirectory = join(root, "docs/spec/conformance");
    mkdirSync(conformanceDirectory, { recursive: true });
    writeText(outside, "report-target.json", "outside sentinel\n");
    symlinkSync(
      join(outside, "report-target.json"),
      join(conformanceDirectory, "report.json"),
    );

    expect(authorReport(root)).toEqual({
      exitCode: 1,
      messages: [
        "authoring failure :: unsafe projection path :: docs/spec/conformance/report.json",
      ],
    });
    expect(readFileSync(join(outside, "report-target.json"), "utf8"))
      .toBe("outside sentinel\n");
    expect(existsSync(join(conformanceDirectory, "DEBT.md"))).toBe(false);
  });

  it("detects a newly introduced unregistered G2 reason without mutating the real corpus", () => {
    const root = repository();
    const vector = JSON.parse(readFileSync(join(root, vectorPath), "utf8")) as Record<string, unknown>;
    vector.expected_output = {
      verdict: "reject",
      reason_code: "unregistered-test-reason",
    };
    writeJson(root, vectorPath, vector);
    const vectorSchema = JSON.parse(
      readFileSync(join(root, vectorSchemaPath), "utf8"),
    ) as Record<string, unknown>;
    const rejectionRule = (vectorSchema.allOf as Array<Record<string, unknown>>)[0]!;
    const thenProperties = (rejectionRule.then as Record<string, unknown>)
      .properties as Record<string, unknown>;
    const outputProperties = (thenProperties.expected_output as Record<string, unknown>)
      .properties as Record<string, unknown>;
    const reasonSchema = outputProperties.reason_code as Record<string, unknown>;
    (reasonSchema.enum as string[]).push("unregistered-test-reason");
    writeJson(root, vectorSchemaPath, vectorSchema);
    refreshReleaseDigests(root);

    expect(checkRepository(root)).toMatchObject({
      exitCode: 1,
      messages: expect.arrayContaining([
        "G2 reason-code-closure new debt :: core.valid :: unregistered-test-reason",
      ]),
    });
  });

  it("detects a measured G1 failure removed from the corpus as stale debt", () => {
    const root = repository();
    writeText(
      root,
      "docs/spec/heterodyne-core.md",
      '# core\n<a id="core-conformance"></a>\n',
    );
    refreshReleaseDigests(root);

    expect(checkRepository(root)).toMatchObject({
      exitCode: 1,
      messages: expect.arrayContaining([
        "G1 anchor-resolution stale debt :: core.valid :: heterodyne:0.5.0#core-conformance",
      ]),
    });
  });

  it("keeps check read-only with explicit and package-directory root resolution", () => {
    const root = repository();
    const before = projectionSnapshot(root);
    const explicitOutput: string[] = [];
    const automaticOutput: string[] = [];

    expect(runCli(["check", root], {
      cwd: join(root, "docs/spec/conformance"),
      writeLine: (line) => explicitOutput.push(line),
    })).toBe(0);
    expect(runCli(["check"], {
      cwd: join(root, "docs/spec/conformance"),
      writeLine: (line) => automaticOutput.push(line),
    })).toBe(0);

    expect(explicitOutput).toEqual([]);
    expect(automaticOutput).toEqual([]);
    expect(projectionSnapshot(root)).toEqual(before);
  });

  it("returns exit 2 and a deterministic usage line for invalid invocation", () => {
    const output: string[] = [];

    expect(runCli(["unknown"], { cwd: "/", writeLine: (line) => output.push(line) }))
      .toBe(2);
    expect(output).toEqual([
      "usage: cli.ts <check|baseline-author|report-author> [repository-root]",
    ]);
  });
});
