import { rmSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { authorBaselines, authorReport, runCli } from "./cli.js";
import {
  createTestCorpus,
  sourceCommit,
  snapshotCommit,
  type TestCorpus,
} from "./test-support.js";

const temps: string[] = [];

afterEach(() => {
  for (const path of temps.splice(0)) rmSync(path, { recursive: true, force: true });
});

function corpus(): TestCorpus {
  const value = createTestCorpus({ withVector: false });
  temps.push(value.root);
  return value;
}

describe("conformance CLI split-root boundary", () => {
  it("checks caller-owned source and snapshot roots with explicit commit identities", () => {
    const input = corpus();
    const output: string[] = [];

    const exitCode = runCli([
      "check",
      "--source-root", input.sourceRoot,
      "--snapshot-root", input.snapshotRoot,
      "--source-commit", sourceCommit,
      "--snapshot-commit", snapshotCommit,
    ], { writeLine: (line) => output.push(line) });

    expect(exitCode).toBe(1);
    expect(output).not.toContain(expect.stringContaining("missing-required-root"));
    expect(output).not.toContain(expect.stringContaining("usage:"));
  });

  it("prints the derived snapshot commit only to runtime stdout", () => {
    const input = corpus();
    const stderr: string[] = [];
    const stdout: string[] = [];
    expect(authorBaselines(input)).toEqual({ exitCode: 0, messages: [] });
    expect(authorReport(input)).toEqual({ exitCode: 0, messages: [] });

    const exitCode = runCli([
      "check",
      "--source-root", input.sourceRoot,
      "--snapshot-root", input.snapshotRoot,
      "--source-commit", sourceCommit,
      "--snapshot-commit", snapshotCommit,
    ], {
      writeLine: (line) => stderr.push(line),
      writeOutput: (line) => stdout.push(line),
    });

    expect(exitCode).toBe(0);
    expect(stderr).toEqual([]);
    expect(stdout).toEqual([`snapshot_commit: ${snapshotCommit}`]);
  });

  it("does not discover roots or substitute current HEAD when explicit history is absent", () => {
    const output: string[] = [];

    expect(runCli(["check"], { cwd: process.cwd(), writeLine: (line) => output.push(line) }))
      .toBe(2);
    expect(output).toEqual([
      "usage: cli.ts check --source-root <path> --snapshot-root <path> --source-commit <sha> --snapshot-commit <sha>",
    ]);
  });
});
