import { createHash } from "node:crypto";
import {
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import {
  isAbsolute,
  posix,
  relative,
  resolve,
  sep,
} from "node:path";
import { Ajv, type AnySchema } from "ajv";
import { parseJsonPointer, resolveJsonPointer } from "./json-pointer.js";
import type {
  ArtifactCorpus,
  ConformanceCheckDocument,
  CorpusIssue,
  ExpectedTerminalStage,
  RegistryDocument,
  VectorDocument,
} from "./types.js";

export type LoadCorpusOptions = {
  sourceRoot: string;
  snapshotRoot: string;
  sourceCommit: string;
  snapshotCommit: string;
};

export type LoadCorpusResult =
  | {
    corpus?: undefined;
    artifactSetSha256?: undefined;
    vectorCount?: undefined;
    issues: CorpusIssue[];
  }
  | {
    corpus: ArtifactCorpus;
    artifactSetSha256: string;
    vectorCount: number;
    issues: CorpusIssue[];
  };

type SnapshotReadBoundary = Readonly<{
  readFile(path: string): Buffer;
  afterCapture?(): void;
}>;

type SnapshotArtifact = { path: string; sha256?: string };
type SnapshotManifest = {
  sourceCommit?: string;
  vectorSchemaVersion?: string;
  vectorCount?: number;
  artifacts: SnapshotArtifact[];
};

const snapshotManifestPath = "docs/spec/vectors/snapshot.json";
const fixturesPath = "docs/spec/vectors/fixtures.json";
const registryManifestPath = "docs/spec/registry/manifest.json";
const featuresPath = "docs/spec/registry/features.json";
const kindsPath = "docs/spec/registry/kinds.json";
const objectsPath = "docs/spec/registry/objects.json";
const proofDomainsPath = "docs/spec/registry/proof-domains.json";
const reasonCodesPath = "docs/spec/registry/reason-codes.json";
const registrySchemaPath = "docs/spec/registry/registry.schema.json";
const securityInvariantsPath = "docs/spec/registry/security-invariants.json";
const vectorSchemaPath = "docs/spec/vectors/schema/vector.schema.json";
const specificationPaths = [
  "docs/spec/heterodyne-comms.md",
  "docs/spec/heterodyne-control.md",
  "docs/spec/heterodyne-core.md",
  "docs/spec/heterodyne-social.md",
  "docs/spec/heterodyne-workspace.md",
] as const;
const snapshotSupportPaths = [
  fixturesPath,
  vectorSchemaPath,
  "docs/spec/vectors/schema/reason-codes.json",
  "docs/spec/vectors/schema/reason-codes.md",
  "docs/spec/vectors/coverage/manifest.json",
  "docs/spec/vectors/coverage/core.md",
  "docs/spec/vectors/coverage/comms.md",
  "docs/spec/vectors/coverage/control.md",
  "docs/spec/vectors/coverage/social.md",
  "docs/spec/vectors/coverage/workspace.md",
  "docs/spec/vectors/coverage/family.md",
] as const;
const requiredRegistryPaths = [
  featuresPath,
  kindsPath,
  registryManifestPath,
  objectsPath,
  proofDomainsPath,
  reasonCodesPath,
  registrySchemaPath,
  securityInvariantsPath,
] as const;

const ownerDocuments = new Set(["core", "comms", "control", "social", "workspace"]);
const directions = new Set(["consume", "produce", "round-trip"]);
const fullCommitPattern = /^[0-9a-f]{40}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const semverPattern = /^\d+\.\d+\.\d+$/u;
const snapshotReferencePattern =
  /^heterodyne:(core|comms|control|social|workspace)#[a-z0-9][a-z0-9-]*$/u;
const terminalStages = new Set<ExpectedTerminalStage>([
  "event_structure",
  "nip01_raw",
  "identifier",
  "signature",
  "persona_resolution",
  "version_stamp",
  "kel_head",
  "epoch_authority",
  "subtype_nid",
  "accept",
]);
const contextRequiredStages = new Set<ExpectedTerminalStage>([
  "persona_resolution",
  "version_stamp",
  "kel_head",
  "epoch_authority",
  "subtype_nid",
  "accept",
]);
const declarationMembers = new Set([
  "profile",
  "event_pointer",
  "nip01_raw_pointer",
  "context_pointer",
  "expected_terminal_stage",
]);

class UnsafeRepositoryPathError extends Error {}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortIssues(issues: CorpusIssue[]): CorpusIssue[] {
  return issues.sort((left, right) =>
    compareText(left.code, right.code)
      || compareText(left.path, right.path)
      || compareText(left.message, right.message));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isMissingFileError(error: unknown): boolean {
  return isRecord(error) && error.code === "ENOENT";
}

function shapeIssue(issues: CorpusIssue[], path: string, message: string): void {
  issues.push({ code: "invalid-document-shape", path, message });
}

function reportUnexpectedMembers(
  value: Record<string, unknown>,
  allowed: readonly string[],
  issues: CorpusIssue[],
  path: string,
  label: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) shapeIssue(issues, path, `${label} has unexpected member: ${key}`);
  }
}

function isContained(root: string, target: string): boolean {
  const fromRoot = relative(root, target);
  return fromRoot === ""
    || (!isAbsolute(fromRoot) && fromRoot !== ".." && !fromRoot.startsWith(`..${sep}`));
}

export function safeRepositoryPath(repositoryRoot: string, repositoryPath: string): string {
  if (
    repositoryPath.length === 0
    || repositoryPath.includes("\\")
    || repositoryPath.includes("\0")
    || isAbsolute(repositoryPath)
    || /^[A-Za-z]:[\\/]/u.test(repositoryPath)
  ) {
    throw new UnsafeRepositoryPathError(`unsafe repository path: ${repositoryPath}`);
  }
  const segments = repositoryPath.split("/");
  if (
    segments.some((segment) => segment === "" || segment === "." || segment === "..")
    || posix.normalize(repositoryPath) !== repositoryPath
  ) {
    throw new UnsafeRepositoryPathError(`non-normalized repository path: ${repositoryPath}`);
  }
  const root = realpathSync(repositoryRoot);
  let current = root;
  for (const segment of segments) {
    current = resolve(current, segment);
    if (lstatSync(current).isSymbolicLink()) {
      throw new UnsafeRepositoryPathError(`repository path contains symbolic link: ${repositoryPath}`);
    }
  }
  const lexicalTarget = resolve(root, repositoryPath);
  if (!isContained(root, lexicalTarget)) {
    throw new UnsafeRepositoryPathError(`repository path escapes root: ${repositoryPath}`);
  }
  const resolvedTarget = realpathSync(lexicalTarget);
  if (!isContained(root, resolvedTarget)) {
    throw new UnsafeRepositoryPathError(`repository path resolves outside root: ${repositoryPath}`);
  }
  return resolvedTarget;
}

function canonicalRoot(
  value: string,
  label: "source" | "snapshot",
  issues: CorpusIssue[],
): string | undefined {
  try {
    const status = lstatSync(value);
    if (status.isSymbolicLink()) throw new Error(`${label} root is a symbolic link`);
    const root = realpathSync(value);
    if (!statSync(root).isDirectory()) throw new Error(`${label} root is not a directory`);
    return root;
  } catch (error) {
    issues.push({
      code: "missing-required-root",
      path: `${label}:.`,
      message: errorMessage(error),
    });
    return undefined;
  }
}

function filesUnder(
  root: string,
  directory: string,
  issues: CorpusIssue[],
  excludedDirectories: ReadonlySet<string> = new Set(),
): string[] {
  const absoluteRoot = resolve(root, directory);
  const visit = (current: string): string[] => readdirSync(current, { withFileTypes: true })
    .flatMap((entry) => {
      const target = resolve(current, entry.name);
      const path = relative(root, target).replaceAll("\\", "/");
      if (excludedDirectories.has(path)) return [];
      if (entry.isDirectory()) return visit(target);
      if (!entry.isFile()) {
        issues.push({
          code: "unsafe-artifact-path",
          path,
          message: entry.isSymbolicLink()
            ? "normative inventory entry is a symbolic link"
            : "normative inventory entry is not a regular file or directory",
        });
        return [];
      }
      return [path];
    });
  try {
    return visit(absoluteRoot).sort(compareText);
  } catch (error) {
    const code = isRecord(error) && typeof error.code === "string" ? error.code : undefined;
    const message = code === "ENOENT"
      ? "required corpus root is missing"
      : code === "ENOTDIR"
        ? "required corpus root is not a directory"
        : code === "EACCES" || code === "EPERM"
          ? "required corpus root is unreadable"
          : undefined;
    if (message === undefined) throw error;
    issues.push({ code: "missing-required-root", path: directory, message });
    return [];
  }
}

function readText(
  root: string,
  path: string,
  issues: CorpusIssue[],
  requiredRoot = false,
): string | undefined {
  let target: string;
  try {
    target = safeRepositoryPath(root, path);
  } catch (error) {
    if (error instanceof UnsafeRepositoryPathError) {
      issues.push({ code: "unsafe-artifact-path", path, message: error.message });
    } else if (isMissingFileError(error)) {
      issues.push({
        code: requiredRoot ? "missing-required-root" : "missing-artifact",
        path,
        message: requiredRoot ? "required corpus root is missing" : "snapshot artifact is missing",
      });
    } else {
      issues.push({ code: "artifact-read-error", path, message: errorMessage(error) });
    }
    return undefined;
  }
  try {
    if (!statSync(target).isFile()) {
      issues.push({ code: "artifact-read-error", path, message: "artifact is not a regular file" });
      return undefined;
    }
    return readFileSync(target, "utf8");
  } catch (error) {
    issues.push({ code: "artifact-read-error", path, message: errorMessage(error) });
    return undefined;
  }
}

function readJson(
  root: string,
  path: string,
  issues: CorpusIssue[],
  requiredRoot = false,
): unknown | undefined {
  const text = readText(root, path, issues, requiredRoot);
  if (text === undefined) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    issues.push({ code: "invalid-json", path, message: errorMessage(error) });
    return undefined;
  }
}

const nodeSnapshotReadBoundary: SnapshotReadBoundary = {
  readFile: (path) => readFileSync(path),
};

function readSnapshotBytes(
  root: string,
  path: string,
  issues: CorpusIssue[],
  boundary: SnapshotReadBoundary,
): Buffer | undefined {
  try {
    const target = safeRepositoryPath(root, path);
    if (!statSync(target).isFile()) {
      issues.push({ code: "artifact-read-error", path, message: "artifact is not a regular file" });
      return undefined;
    }
    return Buffer.from(boundary.readFile(target));
  } catch (error) {
    if (error instanceof UnsafeRepositoryPathError) {
      issues.push({ code: "unsafe-artifact-path", path, message: error.message });
    } else if (isMissingFileError(error)) {
      issues.push({ code: "missing-artifact", path, message: "snapshot artifact is missing" });
    } else {
      issues.push({ code: "artifact-read-error", path, message: errorMessage(error) });
    }
    return undefined;
  }
}

function captureSnapshotArtifacts(
  root: string,
  paths: readonly string[],
  issues: CorpusIssue[],
  boundary: SnapshotReadBoundary,
): ReadonlyMap<string, Buffer> {
  const captured = new Map<string, Buffer>();
  for (const path of paths) {
    const bytes = readSnapshotBytes(root, path, issues, boundary);
    if (bytes !== undefined) captured.set(path, bytes);
  }
  return captured;
}

function parseCapturedJson(
  captured: ReadonlyMap<string, Buffer>,
  path: string,
  issues: CorpusIssue[],
): unknown | undefined {
  const bytes = captured.get(path);
  if (bytes === undefined) return undefined;
  try {
    return JSON.parse(bytes.toString("utf8")) as unknown;
  } catch (error) {
    issues.push({ code: "invalid-json", path, message: errorMessage(error) });
    return undefined;
  }
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number is not valid JCS");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new Error(`unsupported JCS value: ${typeof value}`);
}

function parseSnapshotManifest(
  value: unknown,
  source: string | undefined,
  issues: CorpusIssue[],
): SnapshotManifest | undefined {
  if (!isRecord(value)) {
    shapeIssue(issues, snapshotManifestPath, "snapshot manifest must be an object");
    return undefined;
  }
  reportUnexpectedMembers(
    value,
    ["snapshot_schema", "source_commit", "vector_schema_version", "vector_count", "artifacts"],
    issues,
    snapshotManifestPath,
    "snapshot manifest",
  );
  if (value.snapshot_schema !== "1") shapeIssue(issues, snapshotManifestPath, "snapshot_schema must be 1");
  const sourceCommit = typeof value.source_commit === "string" && fullCommitPattern.test(value.source_commit)
    ? value.source_commit
    : undefined;
  if (sourceCommit === undefined) {
    shapeIssue(issues, snapshotManifestPath, "source_commit must be 40-lowercase-hex");
  }
  const vectorSchemaVersion = typeof value.vector_schema_version === "string"
    && semverPattern.test(value.vector_schema_version)
    ? value.vector_schema_version
    : undefined;
  if (vectorSchemaVersion === undefined) {
    shapeIssue(issues, snapshotManifestPath, "vector_schema_version must use semantic version syntax");
  }
  const vectorCount = Number.isSafeInteger(value.vector_count) && (value.vector_count as number) >= 0
    ? value.vector_count as number
    : undefined;
  if (vectorCount === undefined) {
    shapeIssue(issues, snapshotManifestPath, "vector_count must be a non-negative safe integer");
  }
  if (!Array.isArray(value.artifacts)) {
    shapeIssue(issues, snapshotManifestPath, "artifacts must be an array");
    return { sourceCommit, vectorSchemaVersion, vectorCount, artifacts: [] };
  }
  const artifacts: SnapshotArtifact[] = [];
  const seen = new Set<string>();
  for (const [index, artifact] of value.artifacts.entries()) {
    if (!isRecord(artifact)) {
      shapeIssue(issues, snapshotManifestPath, `snapshot artifact ${index} must be an object`);
      continue;
    }
    reportUnexpectedMembers(artifact, ["path", "sha256"], issues, snapshotManifestPath, "snapshot artifact");
    if (typeof artifact.path !== "string") {
      shapeIssue(issues, snapshotManifestPath, `snapshot artifact ${index} path must be a string`);
      continue;
    }
    const path = artifact.path;
    if (!path.startsWith("docs/spec/vectors/") || !isSafeRepositoryPathSyntax(path)) {
      issues.push({ code: "unsafe-artifact-path", path, message: `unsafe snapshot artifact path: ${path}` });
    }
    if (seen.has(path)) {
      issues.push({ code: "duplicate-artifact-path", path, message: "snapshot manifest repeats an artifact path" });
    }
    seen.add(path);
    const sha256 = typeof artifact.sha256 === "string" && sha256Pattern.test(artifact.sha256)
      ? artifact.sha256
      : undefined;
    if (sha256 === undefined) shapeIssue(issues, path, "artifact sha256 must be lowercase SHA-256 hex");
    artifacts.push({ path, sha256 });
  }
  if (artifacts.some((artifact, index) => index > 0 && artifacts[index - 1]!.path >= artifact.path)) {
    shapeIssue(issues, snapshotManifestPath, "artifacts must be unique and strictly sorted by path");
  }
  if (source !== undefined && sourceCommit !== undefined) {
    const canonical = `${JSON.stringify({
      snapshot_schema: "1",
      source_commit: sourceCommit,
      vector_schema_version: vectorSchemaVersion,
      vector_count: vectorCount,
      artifacts: artifacts.map(({ path, sha256 }) => ({ path, sha256 })),
    }, null, 2)}\n`;
    if (canonical !== source) {
      shapeIssue(issues, snapshotManifestPath, "snapshot manifest must be canonical two-space JSON with one trailing LF");
    }
  }
  return { sourceCommit, vectorSchemaVersion, vectorCount, artifacts };
}

function isSafeRepositoryPathSyntax(path: string): boolean {
  return path.length > 0
    && /^[A-Za-z0-9._/-]+$/u.test(path)
    && !path.startsWith("/")
    && !path.endsWith("/")
    && !path.includes("//")
    && path.split("/").every((segment) => segment !== "." && segment !== "..");
}

function snapshotVectorPaths(snapshotRoot: string, issues: CorpusIssue[]): string[] {
  return filesUnder(
    snapshotRoot,
    "docs/spec/vectors",
    issues,
    new Set([
      "docs/spec/vectors/coverage",
      "docs/spec/vectors/generator",
      "docs/spec/vectors/schema",
    ]),
  ).filter((path) =>
    path.endsWith(".json")
      && path !== fixturesPath
      && path !== snapshotManifestPath
      && path !== "docs/spec/vectors/snapshot.meta.schema.json"
      && path !== "docs/spec/vectors/snapshot.schema.json"
      && path !== "docs/spec/vectors/snapshot-unique-by-path.meta.schema.json");
}

function parseConformanceCheck(
  value: unknown,
  vector: Record<string, unknown>,
): ConformanceCheckDocument | undefined {
  if (
    !isRecord(value)
    || Object.keys(value).some((key) => !declarationMembers.has(key))
    || value.profile !== "core-signed-event-v1"
    || typeof value.event_pointer !== "string"
    || typeof value.nip01_raw_pointer !== "string"
    || (value.context_pointer !== undefined && typeof value.context_pointer !== "string")
    || typeof value.expected_terminal_stage !== "string"
    || !terminalStages.has(value.expected_terminal_stage as ExpectedTerminalStage)
  ) return undefined;
  const stage = value.expected_terminal_stage as ExpectedTerminalStage;
  if (contextRequiredStages.has(stage) && value.context_pointer === undefined) return undefined;
  try {
    parseJsonPointer(value.event_pointer);
    parseJsonPointer(value.nip01_raw_pointer);
    if (value.context_pointer !== undefined) parseJsonPointer(value.context_pointer);
  } catch {
    return undefined;
  }
  if (!resolveJsonPointer(vector, value.event_pointer).found) return undefined;
  if (value.context_pointer !== undefined && !resolveJsonPointer(vector, value.context_pointer).found) {
    return undefined;
  }
  return value as ConformanceCheckDocument;
}

function parseVector(value: unknown): VectorDocument | undefined {
  if (
    !isRecord(value)
    || Object.hasOwn(value, "spec_version")
    || typeof value.vector_id !== "string"
    || value.vector_id.length === 0
    || value.vector_schema_version !== "2.0.0"
    || typeof value.owner_document !== "string"
    || !ownerDocuments.has(value.owner_document)
    || !isStringArray(value.spec_refs)
    || !value.spec_refs.every((reference) => snapshotReferencePattern.test(reference))
    || typeof value.description !== "string"
    || value.description.length === 0
    || typeof value.direction !== "string"
    || !directions.has(value.direction)
    || !isRecord(value.input)
    || !isRecord(value.expected_output)
    || (value.conformance_checks !== undefined
      && (!Array.isArray(value.conformance_checks)
        || !value.conformance_checks.every((check) => parseConformanceCheck(check, value) !== undefined)
        || new Set(value.conformance_checks.map(canonicalize)).size !== value.conformance_checks.length))
  ) return undefined;
  return value as VectorDocument;
}

function parseRegistryManifest(value: unknown): RegistryDocument["manifest"] | undefined {
  if (
    !isRecord(value)
    || !Number.isSafeInteger(value.revision)
    || (value.revision as number) < 0
    || typeof value.schema_version !== "string"
    || !semverPattern.test(value.schema_version)
    || typeof value.entry_set_sha256 !== "string"
    || !sha256Pattern.test(value.entry_set_sha256)
  ) return undefined;
  return value as RegistryDocument["manifest"];
}

type ParsedRegistryEntries<T> = { entries: T[]; valid: boolean };

function parseReasonCodes(value: unknown): ParsedRegistryEntries<{ code: string }> {
  if (!isRecord(value) || !Array.isArray(value.reason_codes)) return { entries: [], valid: false };
  const entries = value.reason_codes.filter(
    (entry): entry is { code: string } => isRecord(entry) && typeof entry.code === "string",
  );
  return { entries, valid: entries.length === value.reason_codes.length };
}

function parseSecurityInvariants(
  value: unknown,
): ParsedRegistryEntries<{ id: string; owner: string; feature?: string }> {
  if (!isRecord(value) || !Array.isArray(value.security_invariants)) {
    return { entries: [], valid: false };
  }
  const entries = value.security_invariants.filter(
    (entry): entry is { id: string; owner: string; feature?: string } =>
      isRecord(entry)
      && typeof entry.id === "string"
      && typeof entry.owner === "string"
      && (entry.feature === undefined || typeof entry.feature === "string"),
  );
  return { entries, valid: entries.length === value.security_invariants.length };
}

function reportDuplicates(
  values: readonly string[],
  path: string,
  kind: string,
  issues: CorpusIssue[],
): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) {
      issues.push({ code: "duplicate-registry-entry", path, message: `duplicate ${kind}: ${value}` });
    }
    seen.add(value);
  }
}

function registryEntrySet(parsedJson: ReadonlyMap<string, unknown>): Record<string, unknown> | undefined {
  const documents = [
    [kindsPath, "kinds"],
    [reasonCodesPath, "reason_codes"],
    [securityInvariantsPath, "security_invariants"],
    [featuresPath, "features"],
    [objectsPath, "objects"],
    [proofDomainsPath, "proof_domains"],
  ] as const;
  const entrySet: Record<string, unknown> = {};
  for (const [path, member] of documents) {
    const document = parsedJson.get(path);
    if (!isRecord(document) || !Array.isArray(document[member])) return undefined;
    entrySet[member] = document[member];
  }
  return entrySet;
}

export function loadCorpus(
  options: LoadCorpusOptions,
  snapshotReadBoundary: SnapshotReadBoundary = nodeSnapshotReadBoundary,
): LoadCorpusResult {
  const issues: CorpusIssue[] = [];
  const { sourceCommit, snapshotCommit } = options;
  if (!fullCommitPattern.test(sourceCommit)) {
    shapeIssue(issues, "source_commit", "source commit must be 40-lowercase-hex");
  }
  if (!fullCommitPattern.test(snapshotCommit)) {
    shapeIssue(issues, "snapshot_commit", "snapshot commit must be 40-lowercase-hex");
  }
  const sourceRoot = canonicalRoot(options.sourceRoot, "source", issues);
  const snapshotRoot = canonicalRoot(options.snapshotRoot, "snapshot", issues);
  if (sourceRoot === undefined || snapshotRoot === undefined) return { issues: sortIssues(issues) };

  const specifications = new Map<string, string>();
  for (const path of specificationPaths) {
    const source = readText(sourceRoot, path, issues, true);
    if (source !== undefined) specifications.set(path, source);
  }

  const registryPaths = filesUnder(
    sourceRoot,
    "docs/spec/registry",
    issues,
    new Set(["docs/spec/registry/history"]),
  ).filter((path) => path.endsWith(".json"));
  const schemaPaths = filesUnder(sourceRoot, "docs/spec/schemas", issues)
    .filter((path) => path.endsWith(".json"));
  for (const path of requiredRegistryPaths) {
    if (!registryPaths.includes(path)) {
      issues.push({ code: "missing-required-root", path, message: "required registry artifact is absent" });
    }
  }
  const sourceJson = new Map<string, unknown>();
  for (const path of [...registryPaths, ...schemaPaths]) {
    const value = readJson(sourceRoot, path, issues);
    if (value !== undefined) sourceJson.set(path, value);
  }

  const manifestBytes = readSnapshotBytes(
    snapshotRoot,
    snapshotManifestPath,
    issues,
    snapshotReadBoundary,
  );
  const manifestSource = manifestBytes?.toString("utf8");
  let manifestValue: unknown | undefined;
  if (manifestSource !== undefined) {
    try {
      manifestValue = JSON.parse(manifestSource) as unknown;
    } catch (error) {
      issues.push({ code: "invalid-json", path: snapshotManifestPath, message: errorMessage(error) });
    }
  }
  const manifest = manifestValue === undefined
    ? undefined
    : parseSnapshotManifest(manifestValue, manifestSource, issues);
  const vectorPaths = snapshotVectorPaths(snapshotRoot, issues);
  const expectedPaths = [...vectorPaths, ...snapshotSupportPaths].sort(compareText);
  const snapshotPaths = [...new Set([
    ...expectedPaths,
    ...(manifest?.artifacts.map(({ path }) => path) ?? []),
  ])].sort(compareText);
  const snapshotArtifacts = captureSnapshotArtifacts(
    snapshotRoot,
    snapshotPaths,
    issues,
    snapshotReadBoundary,
  );
  snapshotReadBoundary.afterCapture?.();
  if (manifest !== undefined) {
    const declared = new Set(manifest.artifacts.map(({ path }) => path));
    for (const path of expectedPaths) {
      if (!declared.has(path)) {
        issues.push({
          code: "missing-snapshot-artifact",
          path,
          message: "snapshot datum is absent from the closed manifest",
        });
      }
    }
    const expected = new Set(expectedPaths);
    for (const artifact of manifest.artifacts) {
      if (!expected.has(artifact.path)) {
        issues.push({
          code: "unexpected-snapshot-artifact",
          path: artifact.path,
          message: "manifest entry is not part of the closed snapshot artifact set",
        });
      }
      const bytes = snapshotArtifacts.get(artifact.path);
      const digest = bytes === undefined
        ? undefined
        : createHash("sha256").update(bytes).digest("hex");
      if (digest !== undefined && artifact.sha256 !== undefined && digest !== artifact.sha256) {
        issues.push({
          code: "artifact-digest-mismatch",
          path: artifact.path,
          message: "snapshot artifact sha256 does not match exact file bytes",
        });
      }
    }
    if (manifest.sourceCommit !== undefined && manifest.sourceCommit !== sourceCommit) {
      issues.push({
        code: "source-commit-mismatch",
        path: snapshotManifestPath,
        message: `snapshot manifest pins ${manifest.sourceCommit} instead of ${sourceCommit}`,
      });
    }
    const actualVectorCount = expectedPaths.filter((path) => !snapshotSupportPaths.includes(
      path as (typeof snapshotSupportPaths)[number],
    )).length;
    if (manifest.vectorCount !== undefined && manifest.vectorCount !== actualVectorCount) {
      shapeIssue(
        issues,
        snapshotManifestPath,
        `vector_count must be ${actualVectorCount}, found ${manifest.vectorCount}`,
      );
    }
  }

  const fixturesValue = parseCapturedJson(snapshotArtifacts, fixturesPath, issues);
  const fixtures = isRecord(fixturesValue) ? fixturesValue : undefined;
  if (fixturesValue !== undefined && fixtures === undefined) {
    shapeIssue(issues, fixturesPath, "fixtures must be an object");
  }
  const vectorSchemaValue = parseCapturedJson(snapshotArtifacts, vectorSchemaPath, issues);
  const vectorSchema = isRecord(vectorSchemaValue) ? vectorSchemaValue : undefined;
  if (vectorSchemaValue !== undefined && vectorSchema === undefined) {
    shapeIssue(issues, vectorSchemaPath, "vector schema must be a JSON object");
  }
  let validateVectorSchema: ReturnType<Ajv["compile"]> | undefined;
  if (vectorSchema !== undefined) {
    try {
      validateVectorSchema = new Ajv({ allErrors: true, strict: false }).compile(vectorSchema as AnySchema);
    } catch {
      shapeIssue(issues, vectorSchemaPath, "vector schema is not a compilable JSON Schema");
    }
  }
  const schemaProperties = vectorSchema === undefined || !isRecord(vectorSchema.properties)
    ? undefined
    : vectorSchema.properties;
  const schemaVersionMember = schemaProperties === undefined
    || !isRecord(schemaProperties.vector_schema_version)
    ? undefined
    : schemaProperties.vector_schema_version.const;
  if (
    manifest?.vectorSchemaVersion !== undefined
    && schemaVersionMember !== manifest.vectorSchemaVersion
  ) {
    shapeIssue(issues, vectorSchemaPath, "packaged vector schema version disagrees with snapshot manifest");
  }

  const vectors: Array<{ path: string; value: VectorDocument }> = [];
  const vectorIds = new Map<string, string>();
  for (const path of vectorPaths) {
    const value = parseCapturedJson(snapshotArtifacts, path, issues);
    if (value === undefined || validateVectorSchema === undefined) continue;
    if (!validateVectorSchema(value)) {
      shapeIssue(issues, path, "vector does not match vector.schema.json");
      continue;
    }
    const vector = parseVector(value);
    if (vector === undefined) {
      shapeIssue(issues, path, "vector does not match the 2.0.0 snapshot corpus shape");
      continue;
    }
    const firstPath = vectorIds.get(vector.vector_id);
    if (firstPath !== undefined) {
      issues.push({
        code: "duplicate-vector-id",
        path,
        message: `vector_id ${vector.vector_id} was first declared at ${firstPath}`,
      });
    } else {
      vectorIds.set(vector.vector_id, path);
    }
    vectors.push({ path, value: vector });
  }
  vectors.sort((left, right) => compareText(left.path, right.path));

  const registryManifest = parseRegistryManifest(sourceJson.get(registryManifestPath));
  if (registryManifest === undefined && sourceJson.has(registryManifestPath)) {
    shapeIssue(issues, registryManifestPath, "registry manifest has an invalid shape");
  }
  const reasonCodes = parseReasonCodes(sourceJson.get(reasonCodesPath));
  const securityInvariants = parseSecurityInvariants(sourceJson.get(securityInvariantsPath));
  if (!reasonCodes.valid && sourceJson.has(reasonCodesPath)) {
    shapeIssue(issues, reasonCodesPath, "reason code registry has an invalid shape");
  }
  if (!securityInvariants.valid && sourceJson.has(securityInvariantsPath)) {
    shapeIssue(issues, securityInvariantsPath, "security invariant registry has an invalid shape");
  }
  reportDuplicates(reasonCodes.entries.map(({ code }) => code), reasonCodesPath, "reason code", issues);
  reportDuplicates(
    securityInvariants.entries.map(({ id }) => id),
    securityInvariantsPath,
    "security invariant",
    issues,
  );
  const registrySchema = sourceJson.get(registrySchemaPath);
  if (registrySchema !== undefined && !isRecord(registrySchema)) {
    shapeIssue(issues, registrySchemaPath, "registry schema must be a JSON object");
  }
  const entrySet = registryEntrySet(sourceJson);
  if (entrySet === undefined) {
    shapeIssue(issues, registryManifestPath, "complete registry entry documents are required");
  } else {
    const digest = createHash("sha256").update(canonicalize(entrySet), "utf8").digest("hex");
    if (registryManifest !== undefined && digest !== registryManifest.entry_set_sha256) {
      issues.push({
        code: "registry-entry-set-digest-mismatch",
        path: registryManifestPath,
        message: "registry entry_set_sha256 does not match the complete pinned entry set",
      });
    }
    if (isRecord(registrySchema) && registryManifest !== undefined) {
      try {
        const validateRegistry = new Ajv({ allErrors: true, strict: false })
          .compile(registrySchema as AnySchema);
        if (!validateRegistry({ manifest: registryManifest, ...entrySet })) {
          shapeIssue(issues, registryManifestPath, "registry documents do not match registry.schema.json");
        }
      } catch {
        shapeIssue(issues, registrySchemaPath, "registry schema is not a compilable JSON Schema");
      }
    }
  }

  sortIssues(issues);
  if (
    issues.length > 0
    || manifest === undefined
    || manifest.sourceCommit === undefined
    || manifest?.vectorSchemaVersion === undefined
    || manifest.vectorCount === undefined
    || manifest.artifacts.some(({ sha256 }) => sha256 === undefined)
    || registryManifest === undefined
    || !reasonCodes.valid
    || !securityInvariants.valid
    || fixtures === undefined
    || vectorSchema === undefined
  ) return { issues };

  const artifactSetSha256 = createHash("sha256")
    .update(`${JSON.stringify(manifest.artifacts, null, 2)}\n`, "utf8")
    .digest("hex");

  const schemas = new Map<string, unknown>();
  for (const path of schemaPaths) {
    if (sourceJson.has(path)) schemas.set(path, sourceJson.get(path));
  }
  return {
    artifactSetSha256,
    vectorCount: manifest.vectorCount,
    corpus: {
      sourceRoot,
      snapshotRoot,
      sourceCommit,
      snapshotCommit,
      vectorSchemaVersion: manifest.vectorSchemaVersion,
      specifications,
      schemas,
      vectorSchema,
      vectors,
      fixtures,
      registry: {
        manifest: registryManifest,
        reason_codes: reasonCodes.entries,
        security_invariants: securityInvariants.entries,
      },
    },
    issues,
  };
}
