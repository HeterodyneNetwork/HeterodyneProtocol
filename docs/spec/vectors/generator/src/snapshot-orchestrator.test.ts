import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildSnapshotManifest } from "./snapshot-manifest.js";
import {
  assertSourceCommitAncestor,
  authorSnapshot,
  checkSnapshot,
  deriveSnapshotCommit,
  formatSnapshotCheckSuccess,
  generateSourceVectors,
  runHistoricalPackageCheck,
  runConformanceCommand,
  resolveSnapshotHistory,
  withMaterializedCommit,
} from "./snapshot-orchestrator.js";

const SNAPSHOT_PATH = "docs/spec/vectors/snapshot.json";
const temps: string[] = [];

afterEach(() => {
  for (const path of temps.splice(0)) rmSync(path, { recursive: true, force: true });
});

function git(root: string, args: string[], options: { env?: NodeJS.ProcessEnv } = {}): string {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: options.env === undefined ? process.env : { ...process.env, ...options.env },
  }).trim();
}

function write(root: string, path: string, bytes: string): void {
  const absolute = join(root, path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, bytes, "utf8");
}

function commit(root: string, message: string): string {
  git(root, ["add", "--all", "--"]);
  git(root, ["commit", "--quiet", "-m", message, "--"]);
  return git(root, ["rev-parse", "HEAD"]);
}

function repository(): { root: string; sourceCommit: string } {
  const root = mkdtempSync(join(tmpdir(), "heterodyne-snapshot-history-test-"));
  temps.push(root);
  git(root, ["init", "--quiet"]);
  git(root, ["config", "user.email", "snapshot@example.invalid"]);
  git(root, ["config", "user.name", "Snapshot Test"]);
  write(root, "source.txt", "source bytes\n");
  return { root, sourceCommit: commit(root, "source") };
}

function writeSnapshot(root: string, sourceCommit: string, marker = "one"): void {
  const vectorRoot = "docs/spec/vectors";
  write(root, `${vectorRoot}/fixtures.json`, `${marker} fixtures\n`);
  write(root, `${vectorRoot}/schema/vector.schema.json`, `${JSON.stringify({
    properties: { vector_schema_version: { const: "2.0.0" } },
  }, null, 2)}\n`);
  for (const path of [
    "schema/reason-codes.json",
    "schema/reason-codes.md",
    "coverage/manifest.json",
    "coverage/core.md",
    "coverage/comms.md",
    "coverage/control.md",
    "coverage/social.md",
    "coverage/workspace.md",
    "coverage/family.md",
  ]) write(root, `${vectorRoot}/${path}`, `${marker} ${path}\n`);
  write(root, `${vectorRoot}/core/001-vector.json`, `${JSON.stringify({
    vector_id: `${marker}-vector`,
    vector_schema_version: "2.0.0",
  }, null, 2)}\n`);
  const manifest = buildSnapshotManifest(root, sourceCommit);
  write(root, SNAPSHOT_PATH, `${JSON.stringify(manifest, null, 2)}\n`);
}

describe("snapshot history", () => {
  it("reports the pinned source commit in snapshot-check success output", () => {
    expect(formatSnapshotCheckSuccess({
      manifest: { vector_count: 482 } as never,
      sourceCommit: "1".repeat(40),
      snapshotCommit: "2".repeat(40),
    })).toBe(
      `verified 482 vectors from source ${"1".repeat(40)} at snapshot ${"2".repeat(40)}`,
    );
  });

  it("accepts first-snapshot authoring from an ancestor without deriving a snapshot commit", () => {
    const { root, sourceCommit } = repository();

    expect(() => assertSourceCommitAncestor(root, sourceCommit)).not.toThrow();
    expect(() => deriveSnapshotCommit(root)).toThrow(/no committed snapshot manifest/);
  });

  it("runs current conformance against the explicit staging snapshot root", async () => {
    const commands: Array<{ cwd: string; args: string[] }> = [];
    await runConformanceCommand(
      "/working/repository",
      "baseline-author",
      "/materialized/source",
      "/owned/staging",
      "1".repeat(40),
      "0".repeat(40),
      async (_command, args, options) => {
        commands.push({ cwd: options.cwd, args });
      },
    );

    expect(commands).toEqual([{
      cwd: "/working/repository/docs/spec/conformance",
      args: [
        "run", "baseline-author", "--",
        "--source-root", "/materialized/source",
        "--snapshot-root", "/owned/staging",
        "--source-commit", "1".repeat(40),
        "--snapshot-commit", "0".repeat(40),
      ],
    }]);
  });

  it("runs the explicit-root conformance CLI without entering its repository-bound test suite", async () => {
    const commands: Array<{ command: string; cwd: string; args: string[] }> = [];
    await runConformanceCommand(
      "/working/repository",
      "check",
      "/materialized/source",
      "/owned/staging",
      "1".repeat(40),
      "0".repeat(40),
      async (command, args, options) => {
        commands.push({ command, cwd: options.cwd, args });
      },
    );

    expect(commands).toEqual([expect.objectContaining({
      command: "/working/repository/docs/spec/conformance/node_modules/.bin/tsx",
      cwd: "/working/repository/docs/spec/conformance",
      args: expect.arrayContaining([
        "src/cli.ts", "check", "--source-root", "/materialized/source",
        "--snapshot-root", "/owned/staging",
      ]),
    })]);
    expect(commands[0]?.args).not.toContain("test");
  });

  it("authors projections in staging before one snapshot replacement", async () => {
    const { root, sourceCommit } = repository();
    const commands: string[] = [];
    let packagedRoot = "";
    let replacementRoot = "";

    await authorSnapshot(root, sourceCommit, {
      run: async (_command, args) => {
        commands.push(args.slice(0, 2).join(" "));
      },
      packageSnapshot: async (_rawRoot, stagingRoot) => {
        packagedRoot = stagingRoot;
      },
      replaceSnapshotData: async (_repositoryRoot, stagingRoot) => {
        replacementRoot = stagingRoot;
      },
    });

    expect(packagedRoot).not.toBe(root);
    expect(replacementRoot).toBe(packagedRoot);
    expect(commands).toEqual([
      "ci --ignore-scripts",
      "run author",
      "run baseline-author",
      "run report-author",
      "src/cli.ts check",
    ]);
  });

  it("checks with the historical packager and current conformance without recursion", async () => {
    const { root, sourceCommit } = repository();
    writeSnapshot(root, sourceCommit);
    commit(root, "snapshot");
    const commands: Array<{ cwd: string; args: string[] }> = [];

    await checkSnapshot(root, {
      run: async (_command, args, options) => {
        commands.push({ cwd: options.cwd, args });
      },
    });

    expect(commands.filter(({ args }) => args[0] === "ci")).toHaveLength(2);
    const historical = commands.find(({ args }) => args.includes("snapshot-package-check"));
    expect(historical?.cwd).not.toContain(root);
    expect(commands.flatMap(({ args }) => args)).not.toContain("snapshot-check");
    expect(commands.at(-1)).toMatchObject({
      cwd: join(root, "docs/spec/conformance"),
      args: expect.arrayContaining([
        "check", "--source-root", expect.stringContaining("heterodyne-snapshot-commit-"),
      ]),
    });
  });

  it("installs source and historical snapshot lockfiles in separate materialized roots", async () => {
    const commands: Array<{ cwd: string; args: string[] }> = [];
    const run = async (_command: string, args: string[], options: { cwd: string }) => {
      commands.push({ cwd: options.cwd, args });
    };

    await generateSourceVectors("/materialized/source", "/owned/raw", run);
    await runHistoricalPackageCheck(
      "/materialized/snapshot",
      "/owned/raw",
      "/working/repository",
      run,
    );

    expect(commands).toEqual([
      {
        cwd: "/materialized/source/docs/spec/vectors/generator",
        args: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
      },
      {
        cwd: "/materialized/source/docs/spec/vectors/generator",
        args: ["run", "author", "--", "/owned/raw"],
      },
      {
        cwd: "/materialized/snapshot/docs/spec/vectors/generator",
        args: ["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
      },
      {
        cwd: "/materialized/snapshot/docs/spec/vectors/generator",
        args: [
          "run", "snapshot-package-check", "--",
          "--raw-root", "/owned/raw",
          "--snapshot-root", "/working/repository",
        ],
      },
    ]);
    expect(commands.flatMap(({ args }) => args)).not.toContain("snapshot-check");
  });

  it("rejects missing source objects without substituting HEAD", () => {
    const { root } = repository();
    const missing = "f".repeat(40);
    writeSnapshot(root, missing);
    commit(root, "snapshot with unavailable source");

    expect(() => resolveSnapshotHistory(root)).toThrow(
      "snapshot source commit unavailable; fetch full history",
    );
  });

  it("rejects non-ancestor source commits", () => {
    const { root, sourceCommit: base } = repository();
    git(root, ["switch", "--quiet", "-c", "source-side"]);
    write(root, "side.txt", "side\n");
    const sourceCommit = commit(root, "source side");
    git(root, ["switch", "--quiet", "master"]);
    expect(git(root, ["rev-parse", "HEAD"])).toBe(base);
    writeSnapshot(root, sourceCommit);
    commit(root, "snapshot on other side");

    expect(() => resolveSnapshotHistory(root)).toThrow(/not an ancestor/);
  });

  it("derives the first snapshot commit after it is committed", () => {
    const { root, sourceCommit } = repository();
    writeSnapshot(root, sourceCommit);
    const snapshotCommit = commit(root, "first snapshot");
    write(root, "later.txt", "later\n");
    commit(root, "later unrelated change");

    expect(deriveSnapshotCommit(root)).toBe(snapshotCommit);
    expect(resolveSnapshotHistory(root)).toMatchObject({ sourceCommit, snapshotCommit });
  });

  it("derives a replacement snapshot commit", () => {
    const { root, sourceCommit } = repository();
    writeSnapshot(root, sourceCommit, "first");
    commit(root, "first snapshot");
    writeSnapshot(root, sourceCommit, "replacement");
    const replacementCommit = commit(root, "replacement snapshot");

    expect(deriveSnapshotCommit(root)).toBe(replacementCommit);
    expect(resolveSnapshotHistory(root).snapshotCommit).toBe(replacementCommit);
  });

  it("rejects manifest-byte mismatch with the derived commit", () => {
    const { root, sourceCommit } = repository();
    writeSnapshot(root, sourceCommit);
    commit(root, "snapshot");
    const bytes = readFileSync(join(root, SNAPSHOT_PATH), "utf8");
    write(root, SNAPSHOT_PATH, bytes.replace("\n", "\r\n"));

    expect(() => resolveSnapshotHistory(root)).toThrow(/manifest bytes differ/);
  });

  it("derives the snapshot from a squash-shaped final tree", () => {
    const { root, sourceCommit } = repository();
    writeSnapshot(root, sourceCommit);
    git(root, ["add", "--all", "--"]);
    const tree = git(root, ["write-tree"]);
    const squashCommit = git(root, ["commit-tree", tree, "-p", sourceCommit], {
      env: {
        GIT_AUTHOR_NAME: "Snapshot Test",
        GIT_AUTHOR_EMAIL: "snapshot@example.invalid",
        GIT_COMMITTER_NAME: "Snapshot Test",
        GIT_COMMITTER_EMAIL: "snapshot@example.invalid",
      },
    });
    git(root, ["reset", "--quiet", "--hard", squashCommit, "--"]);

    expect(deriveSnapshotCommit(root)).toBe(squashCommit);
    expect(resolveSnapshotHistory(root)).toMatchObject({ sourceCommit, snapshotCommit: squashCommit });
  });

  it("validates a full lowercase commit before invoking Git", async () => {
    await expect(withMaterializedCommit(
      "/path/that/does/not/exist",
      "HEAD",
      () => undefined,
    )).rejects.toThrow(/40-lowercase-hex/);
  });

  it("rejects symlink and submodule tree entries before extraction", async () => {
    const symlinkRepo = repository();
    symlinkSync("source.txt", join(symlinkRepo.root, "link"));
    const symlinkCommit = commit(symlinkRepo.root, "symlink");
    await expect(withMaterializedCommit(
      symlinkRepo.root,
      symlinkCommit,
      () => undefined,
    )).rejects.toThrow(/unsupported Git tree entry/);

    const submoduleRepo = repository();
    git(submoduleRepo.root, [
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${submoduleRepo.sourceCommit},dependency`,
      "--",
    ]);
    const tree = git(submoduleRepo.root, ["write-tree"]);
    const submoduleCommit = git(submoduleRepo.root, ["commit-tree", tree, "-p", submoduleRepo.sourceCommit], {
      env: {
        GIT_AUTHOR_NAME: "Snapshot Test",
        GIT_AUTHOR_EMAIL: "snapshot@example.invalid",
        GIT_COMMITTER_NAME: "Snapshot Test",
        GIT_COMMITTER_EMAIL: "snapshot@example.invalid",
      },
    });
    await expect(withMaterializedCommit(
      submoduleRepo.root,
      submoduleCommit,
      () => undefined,
    )).rejects.toThrow(/unsupported Git tree entry/);
  });

  it("materializes exact committed bytes and cleans its owned directory in finally", async () => {
    const { root, sourceCommit: committed } = repository();
    write(root, "source.txt", "working tree drift\n");
    let materializedRoot = "";

    await expect(withMaterializedCommit(root, committed, (ownedRoot) => {
      materializedRoot = ownedRoot;
      expect(readFileSync(join(ownedRoot, "source.txt"), "utf8")).toBe("source bytes\n");
      throw new Error("callback failed");
    })).rejects.toThrow("callback failed");
    expect(materializedRoot).not.toBe("");
    expect(existsSync(materializedRoot)).toBe(false);
    expect(existsSync(root)).toBe(true);
  });

  it("materializes exact tree blobs despite archive attributes", async () => {
    const { root } = repository();
    write(root, ".gitattributes", "retained.txt export-ignore\nsubstituted.txt export-subst\n");
    write(root, "retained.txt", "retained exact bytes\n");
    write(root, "substituted.txt", "$Format:%H$\n");
    const committed = commit(root, "archive attributes");

    await withMaterializedCommit(root, committed, (ownedRoot) => {
      expect(readFileSync(join(ownedRoot, "retained.txt"), "utf8")).toBe("retained exact bytes\n");
      expect(readFileSync(join(ownedRoot, "substituted.txt"), "utf8")).toBe("$Format:%H$\n");
    });
  });

  it("materializes the exact original commit and blobs despite replacement refs", async () => {
    const { root, sourceCommit } = repository();
    const originalBlob = git(root, ["rev-parse", `${sourceCommit}:source.txt`]);
    write(root, "source.txt", "replacement commit bytes\n");
    write(root, "replacement-only.txt", "must not materialize\n");
    const replacementCommit = commit(root, "replacement commit");
    const replacementBlob = git(root, ["rev-parse", `${replacementCommit}:source.txt`]);
    git(root, ["replace", originalBlob, replacementBlob]);
    git(root, ["replace", sourceCommit, replacementCommit]);

    await withMaterializedCommit(root, sourceCommit, (ownedRoot) => {
      expect(readFileSync(join(ownedRoot, "source.txt"), "utf8")).toBe("source bytes\n");
      expect(existsSync(join(ownedRoot, "replacement-only.txt"))).toBe(false);
    });
  });
});
