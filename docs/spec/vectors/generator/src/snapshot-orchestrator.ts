import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
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
  const result = spawnSync("git", ["-C", resolve(repoRoot), ...args], {
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
