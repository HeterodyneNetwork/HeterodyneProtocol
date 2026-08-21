import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

export type SnapshotArtifact = {
  path: string;
  sha256: string;
};

export type SnapshotManifest = {
  snapshot_schema: "1";
  source_commit: string;
  vector_schema_version: string;
  vector_count: number;
  artifacts: SnapshotArtifact[];
};

export const SNAPSHOT_MANIFEST_PATH = "docs/spec/vectors/snapshot.json";
const VECTOR_ROOT = "docs/spec/vectors";
const FULL_COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SEMVER = /^\d+\.\d+\.\d+$/;
const SAFE_PATH = /^[A-Za-z0-9._/-]+$/;
const SUPPORT_PATHS = [
  "fixtures.json",
  "schema/vector.schema.json",
  "schema/reason-codes.json",
  "schema/reason-codes.md",
  "coverage/manifest.json",
  "coverage/core.md",
  "coverage/comms.md",
  "coverage/control.md",
  "coverage/social.md",
  "coverage/workspace.md",
  "coverage/family.md",
] as const;
const EXCLUDED_TOP_LEVEL_DIRECTORIES = new Set(["coverage", "generator", "schema"]);
const EXCLUDED_TOP_LEVEL_FILES = new Set([
  "fixtures.json",
  "snapshot.json",
  "snapshot.schema.json",
]);

export function loadSnapshotManifest(repoRoot: string): SnapshotManifest {
  const repositoryRoot = resolve(repoRoot);
  const bytes = readFileSync(resolve(repositoryRoot, SNAPSHOT_MANIFEST_PATH), "utf8");
  let raw: unknown;
  try {
    raw = JSON.parse(bytes) as unknown;
  } catch (error) {
    throw new Error(
      `invalid snapshot manifest JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const manifest = parseSnapshotManifest(raw);
  if (bytes !== serializeSnapshotManifest(manifest)) {
    throw new Error("snapshot manifest is not canonical two-space JSON with one trailing LF");
  }

  const expected = buildSnapshotManifest(repositoryRoot, manifest.source_commit);
  if (manifest.vector_schema_version !== expected.vector_schema_version) {
    throw new Error(
      `snapshot schema version disagreement: manifest ${manifest.vector_schema_version}, packaged schema ${expected.vector_schema_version}`,
    );
  }
  if (manifest.vector_count !== expected.vector_count) {
    throw new Error(
      `snapshot vector count mismatch: expected ${expected.vector_count}, found ${manifest.vector_count}`,
    );
  }
  compareArtifacts(manifest.artifacts, expected.artifacts);
  return manifest;
}

export function buildSnapshotManifest(
  repoRoot: string,
  sourceCommit: string,
): SnapshotManifest {
  if (!FULL_COMMIT.test(sourceCommit)) {
    throw new Error("snapshot source commit must be 40-lowercase-hex");
  }
  const repositoryRoot = resolve(repoRoot);
  const vectorRoot = resolve(repositoryRoot, VECTOR_ROOT);
  const vectorPaths = listVectorPaths(vectorRoot);
  const vectorSchemaVersion = readPackagedVectorSchemaVersion(repositoryRoot);
  for (const path of vectorPaths) {
    const value = readJson(resolve(repositoryRoot, path), `snapshot vector ${path}`);
    if (!isRecord(value) || value.vector_schema_version !== vectorSchemaVersion) {
      throw new Error(
        `snapshot schema version disagreement: ${path} does not use ${vectorSchemaVersion}`,
      );
    }
  }

  const paths = [
    ...vectorPaths,
    ...SUPPORT_PATHS.map((path) => `${VECTOR_ROOT}/${path}`),
  ].sort(compareStrings);
  const artifacts = paths.map((path) => ({
    path,
    sha256: digest(readFileSync(resolve(repositoryRoot, path))),
  }));
  return {
    snapshot_schema: "1",
    source_commit: sourceCommit,
    vector_schema_version: vectorSchemaVersion,
    vector_count: vectorPaths.length,
    artifacts,
  };
}

export function serializeSnapshotManifest(manifest: SnapshotManifest): string {
  const canonical: SnapshotManifest = {
    snapshot_schema: manifest.snapshot_schema,
    source_commit: manifest.source_commit,
    vector_schema_version: manifest.vector_schema_version,
    vector_count: manifest.vector_count,
    artifacts: manifest.artifacts.map(({ path, sha256 }) => ({ path, sha256 })),
  };
  return `${JSON.stringify(canonical, null, 2)}\n`;
}

function parseSnapshotManifest(value: unknown): SnapshotManifest {
  if (!isRecord(value)) throw new Error("snapshot manifest must be an object");
  assertExactKeys(
    value,
    ["snapshot_schema", "source_commit", "vector_schema_version", "vector_count", "artifacts"],
    "snapshot manifest",
  );
  if (value.snapshot_schema !== "1") throw new Error("snapshot schema must be 1");
  if (typeof value.source_commit !== "string" || !FULL_COMMIT.test(value.source_commit)) {
    throw new Error("snapshot source commit must be 40-lowercase-hex");
  }
  if (typeof value.vector_schema_version !== "string" || !SEMVER.test(value.vector_schema_version)) {
    throw new Error("snapshot vector schema version must be semantic version syntax");
  }
  if (!Number.isSafeInteger(value.vector_count) || (value.vector_count as number) < 0) {
    throw new Error("snapshot vector count must be a non-negative safe integer");
  }
  if (!Array.isArray(value.artifacts)) throw new Error("snapshot artifacts must be an array");

  const seen = new Set<string>();
  const artifacts = value.artifacts.map((entry, index): SnapshotArtifact => {
    if (!isRecord(entry)) throw new Error(`snapshot artifact ${index} must be an object`);
    assertExactKeys(entry, ["path", "sha256"], `snapshot artifact ${index}`);
    if (typeof entry.path !== "string" || !isSafeArtifactPath(entry.path)) {
      throw new Error(`unsafe artifact path: ${String(entry.path)}`);
    }
    if (seen.has(entry.path)) throw new Error(`duplicate artifact path: ${entry.path}`);
    seen.add(entry.path);
    if (typeof entry.sha256 !== "string" || !SHA256.test(entry.sha256)) {
      throw new Error(`invalid artifact digest: ${entry.path}`);
    }
    return { path: entry.path, sha256: entry.sha256 };
  });
  if (artifacts.some((entry, index) => index > 0 && artifacts[index - 1]!.path >= entry.path)) {
    throw new Error("snapshot artifact paths must be unique and strictly sorted");
  }
  return {
    snapshot_schema: "1",
    source_commit: value.source_commit,
    vector_schema_version: value.vector_schema_version,
    vector_count: value.vector_count as number,
    artifacts,
  };
}

function listVectorPaths(vectorRoot: string): string[] {
  return readdirSync(vectorRoot, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) {
      if (EXCLUDED_TOP_LEVEL_DIRECTORIES.has(entry.name)) return [];
      return listJsonFiles(vectorRoot, join(vectorRoot, entry.name));
    }
    if (entry.isSymbolicLink()) {
      if (entry.name.endsWith(".json") && !EXCLUDED_TOP_LEVEL_FILES.has(entry.name)) {
        throw new Error(`unsupported snapshot vector entry: ${entry.name}`);
      }
      return [];
    }
    if (!entry.isFile() || EXCLUDED_TOP_LEVEL_FILES.has(entry.name) || !entry.name.endsWith(".json")) {
      return [];
    }
    return [`${VECTOR_ROOT}/${entry.name}`];
  }).sort(compareStrings);
}

function listJsonFiles(root: string, current: string): string[] {
  return readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
    const absolute = join(current, entry.name);
    if (entry.isDirectory()) return listJsonFiles(root, absolute);
    if (entry.isSymbolicLink()) {
      if (entry.name.endsWith(".json")) {
        throw new Error(
          `unsupported snapshot vector entry: ${relative(root, absolute).split(sep).join("/")}`,
        );
      }
      return [];
    }
    if (!entry.isFile() || !entry.name.endsWith(".json")) return [];
    const relativePath = relative(root, absolute).split(sep).join("/");
    return [`${VECTOR_ROOT}/${relativePath}`];
  });
}

function readPackagedVectorSchemaVersion(repositoryRoot: string): string {
  const schemaPath = `${VECTOR_ROOT}/schema/vector.schema.json`;
  const schema = readJson(resolve(repositoryRoot, schemaPath), "packaged vector schema");
  if (!isRecord(schema) || !isRecord(schema.properties)) {
    throw new Error("packaged vector schema has no properties object");
  }
  const vectorVersion = schema.properties.vector_schema_version;
  if (!isRecord(vectorVersion) || typeof vectorVersion.const !== "string" || !SEMVER.test(vectorVersion.const)) {
    throw new Error("packaged vector schema has no exact vector_schema_version const");
  }
  return vectorVersion.const;
}

function compareArtifacts(actual: SnapshotArtifact[], expected: SnapshotArtifact[]): void {
  const actualByPath = new Map(actual.map((entry) => [entry.path, entry] as const));
  const expectedByPath = new Map(expected.map((entry) => [entry.path, entry] as const));
  for (const { path } of actual) {
    if (!expectedByPath.has(path)) throw new Error(`unexpected artifact in snapshot manifest: ${path}`);
  }
  for (const { path } of expected) {
    const entry = actualByPath.get(path);
    if (entry === undefined) throw new Error(`missing artifact from snapshot manifest: ${path}`);
    if (entry.sha256 !== expectedByPath.get(path)!.sha256) {
      throw new Error(`artifact digest mismatch: ${path}`);
    }
  }
}

function assertExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  for (const key of keys) {
    if (!Object.hasOwn(value, key)) throw new Error(`${label} missing property: ${key}`);
  }
  for (const key of Object.keys(value)) {
    if (!keys.includes(key)) throw new Error(`${label} has unexpected property: ${key}`);
  }
}

function isSafeArtifactPath(path: string): boolean {
  if (!SAFE_PATH.test(path) || !path.startsWith(`${VECTOR_ROOT}/`) || path.includes("//")) return false;
  return path.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

function readJson(path: string, label: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function digest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
