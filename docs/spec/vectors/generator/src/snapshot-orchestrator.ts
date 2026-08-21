import { spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  packageSnapshot as packageSnapshotData,
  replaceSnapshotData as replaceSnapshotDataTransaction,
} from "./author.js";
import {
  loadSnapshotManifest,
  SNAPSHOT_MANIFEST_PATH,
  type SnapshotManifest,
} from "./snapshot-manifest.js";

const FULL_COMMIT = /^[0-9a-f]{40}$/;
const SAFE_TREE_PATH = /^[A-Za-z0-9._/-]+$/;
const ALLOWED_BLOB_MODES = new Set(["100644", "100755"]);
const MAX_GIT_OUTPUT = 64 * 1024 * 1024;

export type SnapshotHistory = {
  manifest: SnapshotManifest;
  sourceCommit: string;
  snapshotCommit: string;
};

export type CommandRunner = (
  command: string,
  args: string[],
  options: { cwd: string },
) => Promise<void>;

type SnapshotWorkflowDependencies = {
  run?: CommandRunner;
  packageSnapshot?: (
    rawRoot: string,
    snapshotRoot: string,
    sourceCommit: string,
  ) => Promise<unknown>;
  replaceSnapshotData?: typeof replaceSnapshotDataTransaction;
};

export function assertSourceCommitAncestor(repoRoot: string, sourceCommit: string): void {
  const repositoryRoot = resolve(repoRoot);
  assertCommitAvailable(repositoryRoot, sourceCommit);
  preflightCommitTree(repositoryRoot, sourceCommit);
  const result = git(repositoryRoot, [
    "merge-base",
    "--is-ancestor",
    sourceCommit,
    "HEAD",
    "--",
  ]);
  if (result.status === 1) throw new Error("snapshot source commit is not an ancestor of HEAD");
  if (result.status !== 0) throw gitError("unable to validate source ancestry", result);
}

export async function runConformanceCommand(
  repositoryRoot: string,
  command: "baseline-author" | "report-author" | "check",
  sourceRoot: string,
  snapshotRoot: string,
  sourceCommit: string,
  snapshotCommit: string,
  run: CommandRunner = runCommand,
): Promise<void> {
  const conformanceRoot = resolve(repositoryRoot, "docs/spec/conformance");
  const explicitArguments = [
    "--source-root",
    resolve(sourceRoot),
    "--snapshot-root",
    resolve(snapshotRoot),
    "--source-commit",
    sourceCommit,
    "--snapshot-commit",
    snapshotCommit,
  ];
  if (command === "check") {
    await run(
      resolve(conformanceRoot, "node_modules/.bin/tsx"),
      ["src/cli.ts", command, ...explicitArguments],
      { cwd: conformanceRoot },
    );
  } else {
    await run("npm", ["run", command, "--", ...explicitArguments], { cwd: conformanceRoot });
  }
}

export async function authorSnapshot(
  repoRoot: string,
  sourceCommit: string,
  dependencies: SnapshotWorkflowDependencies = {},
): Promise<void> {
  const repositoryRoot = resolve(repoRoot);
  const run = dependencies.run ?? runCommand;
  const packageSnapshot = dependencies.packageSnapshot ?? packageSnapshotData;
  const replaceSnapshotData = dependencies.replaceSnapshotData ?? replaceSnapshotDataTransaction;
  assertSourceCommitAncestor(repositoryRoot, sourceCommit);

  const rawRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-raw-"));
  const stagingRoot = await mkdtemp(join(dirname(repositoryRoot), ".heterodyne-snapshot-stage-"));
  try {
    await withMaterializedCommit(repositoryRoot, sourceCommit, async (sourceRoot) => {
      await generateSourceVectors(sourceRoot, rawRoot, run);
      await packageSnapshot(rawRoot, stagingRoot, sourceCommit);
      const authoringSnapshotIdentity = "0".repeat(40);
      await runConformanceCommand(
        repositoryRoot,
        "baseline-author",
        sourceRoot,
        stagingRoot,
        sourceCommit,
        authoringSnapshotIdentity,
        run,
      );
      await runConformanceCommand(
        repositoryRoot,
        "report-author",
        sourceRoot,
        stagingRoot,
        sourceCommit,
        authoringSnapshotIdentity,
        run,
      );
      await runConformanceCommand(
        repositoryRoot,
        "check",
        sourceRoot,
        stagingRoot,
        sourceCommit,
        authoringSnapshotIdentity,
        run,
      );
      await replaceSnapshotData(repositoryRoot, stagingRoot);
    });
  } finally {
    await Promise.all([
      rm(rawRoot, { recursive: true, force: true }),
      rm(stagingRoot, { recursive: true, force: true }),
    ]);
  }
}

export async function checkSnapshot(
  repoRoot: string,
  dependencies: Pick<SnapshotWorkflowDependencies, "run"> = {},
): Promise<SnapshotHistory> {
  const repositoryRoot = resolve(repoRoot);
  const history = resolveSnapshotHistory(repositoryRoot);
  const run = dependencies.run ?? runCommand;
  const rawRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-raw-"));
  try {
    await withMaterializedCommit(repositoryRoot, history.sourceCommit, async (sourceRoot) => {
      await generateSourceVectors(sourceRoot, rawRoot, run);
      await withMaterializedCommit(repositoryRoot, history.snapshotCommit, async (snapshotRoot) => {
        await runHistoricalPackageCheck(snapshotRoot, rawRoot, repositoryRoot, run);
      });
      await runConformanceCommand(
        repositoryRoot,
        "check",
        sourceRoot,
        repositoryRoot,
        history.sourceCommit,
        history.snapshotCommit,
        run,
      );
    });
  } finally {
    await rm(rawRoot, { recursive: true, force: true });
  }
  return history;
}

export async function generateSourceVectors(
  sourceRoot: string,
  rawRoot: string,
  run: CommandRunner = runCommand,
): Promise<void> {
  const generatorRoot = resolve(sourceRoot, "docs/spec/vectors/generator");
  await run("npm", ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], {
    cwd: generatorRoot,
  });
  await run("npm", ["run", "author", "--", resolve(rawRoot)], { cwd: generatorRoot });
}

export async function runHistoricalPackageCheck(
  snapshotRoot: string,
  rawRoot: string,
  repositoryRoot: string,
  run: CommandRunner = runCommand,
): Promise<void> {
  const generatorRoot = resolve(snapshotRoot, "docs/spec/vectors/generator");
  await run("npm", ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], {
    cwd: generatorRoot,
  });
  await run("npm", [
    "run",
    "snapshot-package-check",
    "--",
    "--raw-root",
    resolve(rawRoot),
    "--snapshot-root",
    resolve(repositoryRoot),
  ], { cwd: generatorRoot });
}

async function runCommand(
  command: string,
  args: string[],
  options: { cwd: string },
): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      stdio: "inherit",
      env: process.env,
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolvePromise();
      else reject(new Error(
        `${command} ${args.join(" ")} failed (${signal ?? `exit ${String(code)}`})`,
      ));
    });
  });
}

export function deriveSnapshotCommit(repoRoot: string): string {
  const result = git(repoRoot, [
    "log",
    "-1",
    "--format=%H",
    "--",
    SNAPSHOT_MANIFEST_PATH,
  ]);
  if (result.status !== 0) throw gitError("unable to inspect snapshot history", result);
  const commit = result.stdout.toString("utf8").trim();
  if (commit === "") throw new Error("no committed snapshot manifest");
  assertFullCommit(commit, "derived snapshot commit");
  return commit;
}

export function resolveSnapshotHistory(repoRoot: string): SnapshotHistory {
  const repositoryRoot = resolve(repoRoot);
  const snapshotCommit = deriveSnapshotCommit(repositoryRoot);
  const workingBytes = readFileSync(resolve(repositoryRoot, SNAPSHOT_MANIFEST_PATH));
  const committedBytes = git(repositoryRoot, [
    "show",
    `${snapshotCommit}:${SNAPSHOT_MANIFEST_PATH}`,
    "--",
  ]);
  if (committedBytes.status !== 0) {
    throw gitError("unable to read committed snapshot manifest", committedBytes);
  }
  if (!workingBytes.equals(committedBytes.stdout)) {
    throw new Error("working snapshot manifest bytes differ from the derived snapshot commit");
  }

  const manifest = loadSnapshotManifest(repositoryRoot);
  const sourceCommit = manifest.source_commit;
  assertCommitAvailable(repositoryRoot, sourceCommit);
  preflightCommitTree(repositoryRoot, sourceCommit);
  preflightCommitTree(repositoryRoot, snapshotCommit);
  const ancestry = git(repositoryRoot, [
    "merge-base",
    "--is-ancestor",
    sourceCommit,
    snapshotCommit,
    "--",
  ]);
  if (ancestry.status === 1) {
    throw new Error("snapshot source commit is not an ancestor of the snapshot commit");
  }
  if (ancestry.status !== 0) throw gitError("unable to validate snapshot ancestry", ancestry);
  return { manifest, sourceCommit, snapshotCommit };
}

export async function withMaterializedCommit<T>(
  repoRoot: string,
  fullCommit: string,
  callback: (materializedRoot: string) => T | Promise<T>,
): Promise<T> {
  assertFullCommit(fullCommit, "materialized commit");
  const repositoryRoot = resolve(repoRoot);
  assertCommitAvailable(repositoryRoot, fullCommit);
  const entries = preflightCommitTree(repositoryRoot, fullCommit);

  const ownedRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-commit-"));
  try {
    await materializeTreeEntries(repositoryRoot, entries, ownedRoot);
    return await callback(ownedRoot);
  } finally {
    await rm(ownedRoot, { recursive: true, force: true });
  }
}

type GitResult = {
  status: number | null;
  stdout: Buffer;
  stderr: Buffer;
  error?: Error;
};

function git(repoRoot: string, args: string[]): GitResult {
  const result = spawnSync("git", ["--no-replace-objects", "-C", resolve(repoRoot), ...args], {
    encoding: "buffer",
    maxBuffer: MAX_GIT_OUTPUT,
  });
  return {
    status: result.status,
    stdout: result.stdout ?? Buffer.alloc(0),
    stderr: result.stderr ?? Buffer.alloc(0),
    error: result.error,
  };
}

function assertCommitAvailable(repoRoot: string, fullCommit: string): void {
  assertFullCommit(fullCommit, "snapshot source commit");
  const result = git(repoRoot, ["rev-parse", "--verify", `${fullCommit}^{commit}`, "--"]);
  if (result.status !== 0 || result.stdout.toString("utf8").trim() !== fullCommit) {
    throw new Error("snapshot source commit unavailable; fetch full history");
  }
}

type TreeEntry = {
  mode: "100644" | "100755";
  objectId: string;
  path: string;
};

function preflightCommitTree(repoRoot: string, fullCommit: string): TreeEntry[] {
  assertFullCommit(fullCommit, "materialized commit");
  const result = git(repoRoot, ["ls-tree", "-rz", "--full-tree", fullCommit, "--"]);
  if (result.status !== 0) throw gitError("unable to inspect commit tree", result);
  const records = result.stdout.toString("utf8").split("\0");
  records.pop();
  return records.map((record): TreeEntry => {
    const match = /^([0-7]{6}) (blob|commit) ([0-9a-f]{40})\t(.+)$/.exec(record);
    if (match === null) throw new Error("malformed Git tree entry");
    const [, mode, type, objectId, path] = match;
    if (type !== "blob" || !ALLOWED_BLOB_MODES.has(mode!)) {
      throw new Error(`unsupported Git tree entry: ${path}`);
    }
    if (!isSafeTreePath(path!)) throw new Error(`unsafe Git tree path: ${path}`);
    return { mode: mode as TreeEntry["mode"], objectId: objectId!, path: path! };
  });
}

function isSafeTreePath(path: string): boolean {
  if (!SAFE_TREE_PATH.test(path) || path.startsWith("/") || path.includes("//")) return false;
  return path.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

async function materializeTreeEntries(
  repoRoot: string,
  entries: TreeEntry[],
  destination: string,
): Promise<void> {
  for (const entry of entries) {
    const blob = git(repoRoot, ["show", entry.objectId, "--"]);
    if (blob.status !== 0) throw gitError(`unable to read Git blob ${entry.objectId}`, blob);
    const target = resolve(destination, entry.path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, blob.stdout);
    await chmod(target, entry.mode === "100755" ? 0o755 : 0o644);
  }
}

function assertFullCommit(value: string, label: string): void {
  if (!FULL_COMMIT.test(value)) throw new Error(`${label} must be 40-lowercase-hex`);
}

function gitError(label: string, result: GitResult): Error {
  const detail = (result.error?.message ?? result.stderr.toString("utf8").trim())
    || `Git exited ${String(result.status)}`;
  return new Error(`${label}: ${detail}`);
}
