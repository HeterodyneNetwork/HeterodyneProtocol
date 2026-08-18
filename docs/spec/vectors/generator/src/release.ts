import { createHash } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

export type FamilyReleaseArtifactRole =
  | "specification"
  | "registry"
  | "schema"
  | "vector"
  | "normative-support";

export type FamilyReleaseArtifact = {
  path: string;
  role: FamilyReleaseArtifactRole;
  sha256: string;
};

export type FamilyReleaseManifest = {
  schema_version: "1.0.0";
  family_version: "heterodyne/0.5.0";
  status: "unreleased";
  registry: {
    path: "docs/spec/registry/manifest.json";
    sha256: string;
  };
  artifacts: FamilyReleaseArtifact[];
};

const RELEASE_PATH = "docs/spec/releases/family/0.5.0.json";
const REGISTRY_MANIFEST_PATH = "docs/spec/registry/manifest.json";
const SPECIFICATION_PATHS = [
  "docs/spec/heterodyne-comms.md",
  "docs/spec/heterodyne-control.md",
  "docs/spec/heterodyne-core.md",
  "docs/spec/heterodyne-social.md",
  "docs/spec/heterodyne-workspace.md",
] as const;
const ROLES = new Set<FamilyReleaseArtifactRole>([
  "specification",
  "registry",
  "schema",
  "vector",
  "normative-support",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const PATH_CHARACTERS = /^[A-Za-z0-9._/-]+$/;

function sha256(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function filesUnder(root: string, current = root): string[] {
  return readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
    const path = join(current, entry.name);
    if (entry.isDirectory()) return filesUnder(root, path);
    return entry.isFile() ? [relative(root, path).replaceAll("\\", "/")] : [];
  }).sort();
}

function pathsUnder(repositoryRoot: string, directory: string): string[] {
  const absolute = resolve(repositoryRoot, directory);
  return filesUnder(absolute).map((path) => `${directory}/${path}`);
}

function artifact(repositoryRoot: string, path: string, role: FamilyReleaseArtifactRole): FamilyReleaseArtifact {
  return { path, role, sha256: sha256(readFileSync(resolve(repositoryRoot, path))) };
}

function registryPaths(repositoryRoot: string): string[] {
  return pathsUnder(repositoryRoot, "docs/spec/registry")
    .filter((path) => path.endsWith(".json"))
    .filter((path) => !path.startsWith("docs/spec/registry/history/"));
}

function schemaPaths(repositoryRoot: string): string[] {
  return pathsUnder(repositoryRoot, "docs/spec/schemas")
    .filter((path) => path.endsWith(".json"));
}

function vectorPaths(repositoryRoot: string): string[] {
  return pathsUnder(repositoryRoot, "docs/spec/vectors")
    .filter((path) => path.endsWith(".json"))
    .filter((path) => path !== "docs/spec/vectors/fixtures.json")
    .filter((path) => path !== "docs/spec/vectors/manifest.json")
    .filter((path) => !path.startsWith("docs/spec/vectors/coverage/"))
    .filter((path) => !path.startsWith("docs/spec/vectors/generator/"))
    .filter((path) => !path.startsWith("docs/spec/vectors/schema/"));
}

export function buildFamilyReleaseManifest(repoRoot: string): FamilyReleaseManifest {
  const repositoryRoot = resolve(repoRoot);
  const artifacts = [
    ...SPECIFICATION_PATHS.map((path) => artifact(repositoryRoot, path, "specification")),
    ...registryPaths(repositoryRoot).map((path) => artifact(repositoryRoot, path, "registry")),
    ...schemaPaths(repositoryRoot).map((path) => artifact(repositoryRoot, path, "schema")),
    artifact(repositoryRoot, "docs/spec/vectors/schema/vector.schema.json", "schema"),
    ...vectorPaths(repositoryRoot).map((path) => artifact(repositoryRoot, path, "vector")),
    artifact(repositoryRoot, "docs/spec/external/marmot/manifest.json", "normative-support"),
  ].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  const registry = artifacts.find(({ path }) => path === REGISTRY_MANIFEST_PATH);
  if (registry === undefined) throw new Error(`missing registry manifest: ${REGISTRY_MANIFEST_PATH}`);

  return {
    schema_version: "1.0.0",
    family_version: "heterodyne/0.5.0",
    status: "unreleased",
    registry: { path: REGISTRY_MANIFEST_PATH, sha256: registry.sha256 },
    artifacts,
  };
}

export function writeFamilyReleaseManifest(repoRoot: string): string {
  const repositoryRoot = resolve(repoRoot);
  const path = resolve(repositoryRoot, RELEASE_PATH);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(buildFamilyReleaseManifest(repositoryRoot), null, 2)}\n`, "utf8");
  return path;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function reportObjectShape(
  issues: string[],
  value: Record<string, unknown>,
  required: readonly string[],
  label: string,
): void {
  for (const key of required) {
    if (!(key in value)) issues.push(`${label} missing property: ${key}`);
  }
  for (const key of Object.keys(value)) {
    if (!required.includes(key)) issues.push(`${label} has unexpected property: ${key}`);
  }
}

function isSafePath(path: string): boolean {
  if (!PATH_CHARACTERS.test(path) || path.startsWith("/") || path.includes("//")) return false;
  const segments = path.split("/");
  return segments.every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

export function validateFamilyReleaseManifest(repoRoot: string): string[] {
  const repositoryRoot = resolve(repoRoot);
  const issues: string[] = [];
  let expected: FamilyReleaseManifest | undefined;
  try {
    expected = buildFamilyReleaseManifest(repositoryRoot);
  } catch (error) {
    issues.push(`unable to build expected family release manifest: ${error instanceof Error ? error.message : String(error)}`);
  }

  let value: unknown;
  try {
    value = JSON.parse(readFileSync(resolve(repositoryRoot, RELEASE_PATH), "utf8")) as unknown;
  } catch (error) {
    issues.push(`missing or invalid family release manifest: ${error instanceof Error ? error.message : String(error)}`);
    return issues.sort();
  }
  if (!isObject(value)) {
    issues.push("family release manifest must be an object");
    return issues.sort();
  }

  reportObjectShape(
    issues,
    value,
    ["schema_version", "family_version", "status", "registry", "artifacts"],
    "family release manifest",
  );
  if (value.schema_version !== "1.0.0") issues.push("schema version mismatch");
  if (value.family_version !== "heterodyne/0.5.0") issues.push("family version mismatch");
  if (value.status !== "unreleased") issues.push("release status mismatch");

  if (!isObject(value.registry)) {
    issues.push("registry pin must be an object");
  } else {
    reportObjectShape(issues, value.registry, ["path", "sha256"], "registry pin");
    if (typeof value.registry.path !== "string" || !isSafePath(value.registry.path)) {
      issues.push(`unsafe registry path: ${String(value.registry.path)}`);
    } else if (value.registry.path !== REGISTRY_MANIFEST_PATH) {
      issues.push(`registry path mismatch: ${value.registry.path}`);
    }
    if (expected !== undefined && value.registry.sha256 !== expected.registry.sha256) {
      issues.push("registry digest mismatch");
    }
    if (typeof value.registry.sha256 !== "string" || !SHA256_PATTERN.test(value.registry.sha256)) {
      issues.push("registry digest must be lowercase 64-hex SHA-256");
    }
  }

  if (!Array.isArray(value.artifacts)) {
    issues.push("artifacts must be an array");
    return issues.sort();
  }

  const expectedByPath = new Map(
    expected?.artifacts.map((entry) => [entry.path, entry] as const) ?? [],
  );
  const safeManifestPaths: string[] = [];
  const seen = new Set<string>();
  for (const [index, item] of value.artifacts.entries()) {
    const label = `artifact ${index}`;
    if (!isObject(item)) {
      issues.push(`${label} must be an object`);
      continue;
    }
    reportObjectShape(issues, item, ["path", "role", "sha256"], label);
    if (typeof item.role !== "string" || !ROLES.has(item.role as FamilyReleaseArtifactRole)) {
      issues.push(`invalid artifact role: ${String(item.role)}`);
    }
    if (typeof item.sha256 !== "string" || !SHA256_PATTERN.test(item.sha256)) {
      issues.push(`invalid artifact digest: ${String(item.path)}`);
    }
    if (typeof item.path !== "string" || !isSafePath(item.path)) {
      issues.push(`unsafe artifact path: ${String(item.path)}`);
      continue;
    }
    safeManifestPaths.push(item.path);
    if (seen.has(item.path)) issues.push(`duplicate artifact path: ${item.path}`);
    seen.add(item.path);

    const expectedArtifact = expectedByPath.get(item.path);
    if (expected !== undefined && expectedArtifact === undefined) {
      issues.push(`unexpected artifact in manifest: ${item.path}`);
      continue;
    }
    if (expectedArtifact !== undefined) {
      if (item.role !== expectedArtifact.role) issues.push(`artifact role mismatch: ${item.path}`);
      if (item.sha256 !== expectedArtifact.sha256) issues.push(`artifact digest mismatch: ${item.path}`);
    }
  }

  if (safeManifestPaths.some((path, index) => index > 0 && safeManifestPaths[index - 1]! >= path)) {
    issues.push("artifact paths must be strictly increasing");
  }
  if (expected !== undefined) {
    for (const path of expectedByPath.keys()) {
      if (!seen.has(path)) issues.push(`missing artifact from manifest: ${path}`);
    }
  }
  return issues.sort();
}
