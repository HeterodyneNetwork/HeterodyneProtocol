import {
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
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
  vectorPath,
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
  const root = createTestRepository();
  temps.push(root);
  expect(authorBaselines(root)).toEqual({ exitCode: 0, messages: [] });
  expect(authorReport(root)).toEqual({ exitCode: 0, messages: [] });
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
  it("detects a newly introduced unregistered G2 reason without mutating the real corpus", () => {
    const root = repository();
    const vector = JSON.parse(readFileSync(join(root, vectorPath), "utf8")) as Record<string, unknown>;
    vector.expected_output = {
      verdict: "reject",
      reason_code: "unregistered-test-reason",
    };
    writeJson(root, vectorPath, vector);

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
