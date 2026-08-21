import { createHash } from "node:crypto";
import {
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

const familyManifestPath = "docs/spec/releases/family/0.5.0.json";
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
const marmotManifestPath = "docs/spec/external/marmot/manifest.json";
const specificationPaths = [
  "docs/spec/heterodyne-comms.md",
  "docs/spec/heterodyne-control.md",
  "docs/spec/heterodyne-core.md",
  "docs/spec/heterodyne-social.md",
  "docs/spec/heterodyne-workspace.md",
] as const;
const requiredArtifactRoles = new Map<string, string>([
  ...specificationPaths.map((path) => [path, "specification"] as const),
  [featuresPath, "registry"],
  [kindsPath, "registry"],
  [registryManifestPath, "registry"],
  [objectsPath, "registry"],
  [proofDomainsPath, "registry"],
  [reasonCodesPath, "registry"],
  [registrySchemaPath, "registry"],
  [securityInvariantsPath, "registry"],
  [vectorSchemaPath, "schema"],
  [marmotManifestPath, "normative-support"],
]);

const ownerDocuments = new Set(["core", "comms", "control", "social", "workspace"]);
const directions = new Set(["consume", "produce", "round-trip"]);
const artifactRoles = new Set(["normative-support", "registry", "schema", "specification", "vector"]);
const sha256Pattern = /^[0-9a-f]{64}$/u;
const releasePathCharacters = /^[A-Za-z0-9._/-]+$/u;
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

type FamilyArtifact = { path: string; role: string; sha256?: string };

type FamilyManifest = {
  family_version: "heterodyne/0.5.0";
  registry: { path?: string; sha256?: string };
  artifacts: FamilyArtifact[];
};

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortIssues(issues: CorpusIssue[]): CorpusIssue[] {
  return issues.sort((left, right) =>
    compareText(left.code, right.code)
      || compareText(left.path, right.path)
      || compareText(left.message, right.message));
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isReleasePath(value: string): boolean {
  return releasePathCharacters.test(value)
    && !value.startsWith("/")
    && !value.endsWith("/")
    && !value.includes("//")
    && value.split("/").every((segment) => segment !== "." && segment !== "..");
}

function reportUnexpectedMembers(
  value: Record<string, unknown>,
  allowed: readonly string[],
  issues: CorpusIssue[],
  path: string,
  label: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      shapeIssue(issues, path, `${label} has unexpected member: ${key}`);
    }
  }
}

function shapeIssue(issues: CorpusIssue[], path: string, message: string): void {
  issues.push({ code: "invalid-document-shape", path, message });
}

function isNormativeVectorPath(path: string): boolean {
  return path.startsWith("docs/spec/vectors/")
    && path.endsWith(".json")
    && path !== "docs/spec/vectors/fixtures.json"
    && path !== "docs/spec/vectors/manifest.json"
    && !path.startsWith("docs/spec/vectors/coverage/")
    && !path.startsWith("docs/spec/vectors/generator/")
    && !path.startsWith("docs/spec/vectors/schema/");
}

function filesUnder(
  repositoryRoot: string,
  directory: string,
  issues: CorpusIssue[],
): string[] {
  const root = resolve(repositoryRoot, directory);
  const visit = (current: string): string[] => readdirSync(current, { withFileTypes: true })
    .flatMap((entry) => {
      const target = resolve(current, entry.name);
      if (entry.isDirectory()) {
        return visit(target);
      }
      if (!entry.isFile()) {
        return [];
      }
      return [relative(repositoryRoot, target).replaceAll("\\", "/")];
    });
  try {
    return visit(root).sort(compareText);
  } catch (error) {
    const code = isRecord(error) && typeof error.code === "string" ? error.code : undefined;
    const message = code === "ENOENT"
      ? "required corpus root is missing"
      : code === "ENOTDIR"
        ? "required corpus root is not a directory"
        : code === "EACCES" || code === "EPERM"
          ? "required corpus root is unreadable"
          : undefined;
    if (message === undefined) {
      throw error;
    }
    issues.push({ code: "missing-required-root", path: directory, message });
    return [];
  }
}

function expectedReleaseArtifacts(
  repositoryRoot: string,
  issues: CorpusIssue[],
): ReadonlyMap<string, string> {
  const entries: Array<readonly [string, string]> = [
    ...specificationPaths.map((path) => [path, "specification"] as const),
    ...filesUnder(repositoryRoot, "docs/spec/registry", issues)
      .filter((path) => path.endsWith(".json"))
      .filter((path) => !path.startsWith("docs/spec/registry/history/"))
      .map((path) => [path, "registry"] as const),
    ...filesUnder(repositoryRoot, "docs/spec/schemas", issues)
      .filter((path) => path.endsWith(".json"))
      .map((path) => [path, "schema"] as const),
    [vectorSchemaPath, "schema"],
    ...filesUnder(repositoryRoot, "docs/spec/vectors", issues)
      .filter(isNormativeVectorPath)
      .map((path) => [path, "vector"] as const),
    [marmotManifestPath, "normative-support"],
  ];
  return new Map(entries.sort(([left], [right]) => compareText(left, right)));
}

function sha256File(repositoryRoot: string, path: string): string | undefined {
  try {
    const target = safeRepositoryPath(repositoryRoot, path);
    if (!statSync(target).isFile()) return undefined;
    return createHash("sha256").update(readFileSync(target)).digest("hex");
  } catch {
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
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new Error(`unsupported JCS value: ${typeof value}`);
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

function readText(
  repositoryRoot: string,
  path: string,
  issues: CorpusIssue[],
  requiredRoot = false,
): string | undefined {
  let target: string;
  try {
    target = safeRepositoryPath(repositoryRoot, path);
  } catch (error) {
    if (error instanceof UnsafeRepositoryPathError) {
      issues.push({ code: "unsafe-artifact-path", path, message: error.message });
    } else if (isMissingFileError(error)) {
      issues.push({
        code: requiredRoot ? "missing-required-root" : "missing-artifact",
        path,
        message: requiredRoot ? "required corpus root is missing" : "release artifact is missing",
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
  repositoryRoot: string,
  path: string,
  issues: CorpusIssue[],
  requiredRoot = false,
): unknown | undefined {
  const text = readText(repositoryRoot, path, issues, requiredRoot);
  if (text === undefined) {
    return undefined;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    issues.push({ code: "invalid-json", path, message: errorMessage(error) });
    return undefined;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isMissingFileError(error: unknown): boolean {
  return isRecord(error) && error.code === "ENOENT";
}

function parseFamilyManifest(value: unknown, issues: CorpusIssue[]): FamilyManifest | undefined {
  if (!isRecord(value)) {
    shapeIssue(issues, familyManifestPath, "family release manifest must be an object");
    return undefined;
  }
  reportUnexpectedMembers(
    value,
    ["schema_version", "family_version", "status", "registry", "artifacts"],
    issues,
    familyManifestPath,
    "family release manifest",
  );
  if (value.schema_version !== "1.0.0") {
    shapeIssue(issues, familyManifestPath, "schema_version must be 1.0.0");
  }
  if (value.family_version !== "heterodyne/0.5.0") {
    shapeIssue(issues, familyManifestPath, "family_version must be heterodyne/0.5.0");
  }
  if (value.status !== "unreleased") {
    shapeIssue(issues, familyManifestPath, "status must be unreleased");
  }
  const registryPath = isRecord(value.registry) && typeof value.registry.path === "string"
    ? value.registry.path
    : undefined;
  const registrySha256 = isRecord(value.registry) && typeof value.registry.sha256 === "string"
    && sha256Pattern.test(value.registry.sha256)
    ? value.registry.sha256
    : undefined;
  if (isRecord(value.registry)) {
    reportUnexpectedMembers(
      value.registry,
      ["path", "sha256"],
      issues,
      familyManifestPath,
      "registry pin",
    );
  }
  if (registryPath === undefined) {
    shapeIssue(issues, familyManifestPath, "registry.path must be a string");
  } else if (!isReleasePath(registryPath)) {
    shapeIssue(issues, familyManifestPath, "registry.path must match the release path syntax");
  }
  if (registrySha256 === undefined) {
    shapeIssue(issues, familyManifestPath, "registry.sha256 must be lowercase SHA-256 hex");
  }
  if (!Array.isArray(value.artifacts)) {
    shapeIssue(issues, familyManifestPath, "artifacts must be an array");
    return undefined;
  }

  const artifacts: FamilyArtifact[] = [];
  for (const artifact of value.artifacts) {
    if (!isRecord(artifact) || typeof artifact.path !== "string" || typeof artifact.role !== "string") {
      shapeIssue(issues, familyManifestPath, "each artifact must have string path and role members");
      continue;
    }
    reportUnexpectedMembers(
      artifact,
      ["path", "role", "sha256"],
      issues,
      artifact.path,
      "release artifact",
    );
    if (!isReleasePath(artifact.path)) {
      shapeIssue(issues, artifact.path, "artifact path must match the release path syntax");
    }
    if (!artifactRoles.has(artifact.role)) {
      shapeIssue(issues, artifact.path, `unknown artifact role: ${artifact.role}`);
    }
    const artifactSha256 = typeof artifact.sha256 === "string"
      && sha256Pattern.test(artifact.sha256)
      ? artifact.sha256
      : undefined;
    if (artifactSha256 === undefined) {
      shapeIssue(issues, artifact.path, "artifact sha256 must be lowercase SHA-256 hex");
    }
    artifacts.push({ path: artifact.path, role: artifact.role, sha256: artifactSha256 });
  }
  return {
    family_version: "heterodyne/0.5.0",
    registry: { path: registryPath, sha256: registrySha256 },
    artifacts,
  };
}

function validateStandaloneManifestPath(
  repositoryRoot: string,
  path: string,
  issues: CorpusIssue[],
): void {
  try {
    safeRepositoryPath(repositoryRoot, path);
  } catch (error) {
    if (error instanceof UnsafeRepositoryPathError) {
      issues.push({ code: "unsafe-artifact-path", path, message: error.message });
    }
  }
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
  ) {
    return undefined;
  }
  const stage = value.expected_terminal_stage as ExpectedTerminalStage;
  if (contextRequiredStages.has(stage) && value.context_pointer === undefined) {
    return undefined;
  }
  try {
    parseJsonPointer(value.event_pointer);
    parseJsonPointer(value.nip01_raw_pointer);
    if (value.context_pointer !== undefined) {
      parseJsonPointer(value.context_pointer);
    }
  } catch {
    return undefined;
  }
  if (!resolveJsonPointer(vector, value.event_pointer).found) return undefined;
  if (value.context_pointer !== undefined
    && !resolveJsonPointer(vector, value.context_pointer).found) {
    return undefined;
  }
  return value as ConformanceCheckDocument;
}

function parseVector(value: unknown): VectorDocument | undefined {
  if (
    !isRecord(value)
    || typeof value.vector_id !== "string"
    || value.vector_id.length === 0
    || value.vector_schema_version !== "1.1.0"
    || typeof value.owner_document !== "string"
    || !ownerDocuments.has(value.owner_document)
    || value.spec_version !== "heterodyne/0.5.0"
    || !isStringArray(value.spec_refs)
    || typeof value.description !== "string"
    || value.description.length === 0
    || typeof value.direction !== "string"
    || !directions.has(value.direction)
    || !isRecord(value.input)
    || !isRecord(value.expected_output)
    || (value.conformance_checks !== undefined
      && (!Array.isArray(value.conformance_checks)
        || !value.conformance_checks.every((check) => parseConformanceCheck(check, value) !== undefined)
        || new Set(value.conformance_checks.map((check) => canonicalize(check))).size
          !== value.conformance_checks.length))
  ) {
    return undefined;
  }
  return value as VectorDocument;
}

function parseRegistryManifest(value: unknown): RegistryDocument["manifest"] | undefined {
  if (
    !isRecord(value)
    || value.revision !== 13
    || value.schema_version !== "3.0.0"
    || typeof value.entry_set_sha256 !== "string"
  ) {
    return undefined;
  }
  return value as RegistryDocument["manifest"];
}

type ParsedRegistryEntries<T> = { entries: T[]; valid: boolean };

function parseReasonCodes(
  value: unknown,
): ParsedRegistryEntries<{ code: string }> {
  if (!isRecord(value) || !Array.isArray(value.reason_codes)) {
    return { entries: [], valid: false };
  }
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
      issues.push({
        code: "duplicate-registry-entry",
        path,
        message: `duplicate ${kind}: ${value}`,
      });
    }
    seen.add(value);
  }
}

export function loadCorpus(repositoryRoot: string): {
  corpus?: ArtifactCorpus;
  issues: CorpusIssue[];
} {
  const issues: CorpusIssue[] = [];
  let canonicalRoot: string;
  try {
    canonicalRoot = realpathSync(repositoryRoot);
    if (!statSync(canonicalRoot).isDirectory()) {
      throw new Error("repository root is not a directory");
    }
  } catch (error) {
    issues.push({ code: "missing-required-root", path: ".", message: errorMessage(error) });
    return { issues: sortIssues(issues) };
  }

  const fixturesValue = readJson(canonicalRoot, fixturesPath, issues, true);
  let fixtures: Record<string, unknown> | undefined;
  if (fixturesValue !== undefined) {
    if (isRecord(fixturesValue)) {
      fixtures = fixturesValue;
    } else {
      shapeIssue(issues, fixturesPath, "fixtures must be an object");
    }
  }

  const manifestValue = readJson(canonicalRoot, familyManifestPath, issues, true);
  if (manifestValue === undefined) {
    return { issues: sortIssues(issues) };
  }
  const manifest = parseFamilyManifest(manifestValue, issues);
  if (manifest === undefined) {
    return { issues: sortIssues(issues) };
  }

  const artifactPaths = new Set<string>();
  for (const artifact of manifest.artifacts) {
    if (artifactPaths.has(artifact.path)) {
      issues.push({
        code: "duplicate-artifact-path",
        path: artifact.path,
        message: "family release manifest repeats an artifact path",
      });
    }
    artifactPaths.add(artifact.path);
  }

  const expectedArtifacts = expectedReleaseArtifacts(canonicalRoot, issues);
  for (const [path, role] of expectedArtifacts) {
    const artifact = manifest.artifacts.find((candidate) => candidate.path === path);
    if (artifact === undefined) {
      issues.push({
        code: "missing-release-artifact",
        path,
        message: "normative file is absent from the family release manifest",
      });
    } else if (artifact.role !== role) {
      shapeIssue(issues, path, `normative artifact role must be ${role}`);
    }
  }
  for (const artifact of manifest.artifacts) {
    let safe = true;
    try {
      safeRepositoryPath(canonicalRoot, artifact.path);
    } catch {
      safe = false;
    }
    if (safe && !expectedArtifacts.has(artifact.path)) {
      issues.push({
        code: "unexpected-release-artifact",
        path: artifact.path,
        message: "file is not part of the closed normative release artifact set",
      });
    }
    const digest = sha256File(canonicalRoot, artifact.path);
    if (digest !== undefined && artifact.sha256 !== undefined && digest !== artifact.sha256) {
      issues.push({
        code: "artifact-digest-mismatch",
        path: artifact.path,
        message: "release artifact sha256 does not match exact file bytes",
      });
    }
  }
  for (let index = 1; index < manifest.artifacts.length; index += 1) {
    if (compareText(manifest.artifacts[index - 1]!.path, manifest.artifacts[index]!.path) > 0) {
      shapeIssue(issues, familyManifestPath, "artifacts must be strictly sorted by path");
      break;
    }
  }

  for (const [path] of requiredArtifactRoles) {
    const artifact = manifest.artifacts.find((candidate) => candidate.path === path);
    if (artifact === undefined) {
      issues.push({ code: "missing-required-root", path, message: "required release artifact is absent" });
    }
  }
  if (manifest.registry.path !== undefined && !artifactPaths.has(manifest.registry.path)) {
    validateStandaloneManifestPath(canonicalRoot, manifest.registry.path, issues);
  }
  if (manifest.registry.path !== registryManifestPath) {
    issues.push({
      code: "missing-required-root",
      path: registryManifestPath,
      message: `family registry path is ${manifest.registry.path ?? "missing"}`,
    });
  }
  if (manifest.registry.path !== undefined && manifest.registry.sha256 !== undefined) {
    const registryDigest = sha256File(canonicalRoot, manifest.registry.path);
    if (registryDigest !== undefined && registryDigest !== manifest.registry.sha256) {
      issues.push({
        code: "registry-digest-mismatch",
        path: manifest.registry.path,
        message: "registry pin sha256 does not match exact registry manifest bytes",
      });
    }
  }

  const parsedJson = new Map<string, unknown>();
  const textArtifacts = new Map<string, string>();
  for (const artifact of manifest.artifacts) {
    const jsonArtifact = artifact.role === "registry"
      || artifact.role === "schema"
      || artifact.role === "vector"
      || (artifact.role !== "specification" && artifact.path.endsWith(".json"));
    if (jsonArtifact) {
      const value = readJson(canonicalRoot, artifact.path, issues);
      if (value !== undefined && !parsedJson.has(artifact.path)) {
        parsedJson.set(artifact.path, value);
      }
    } else {
      const value = readText(canonicalRoot, artifact.path, issues);
      if (value !== undefined && !textArtifacts.has(artifact.path)) {
        textArtifacts.set(artifact.path, value);
      }
    }
  }

  const specifications = new Map<string, string>();
  const schemas = new Map<string, unknown>();
  const vectors: { path: string; value: VectorDocument }[] = [];
  const vectorIds = new Map<string, string>();
  for (const artifact of manifest.artifacts) {
    if (artifact.role === "specification") {
      const value = textArtifacts.get(artifact.path);
      if (value !== undefined) {
        specifications.set(artifact.path, value);
      }
    } else if (artifact.role === "schema") {
      if (parsedJson.has(artifact.path)) {
        schemas.set(artifact.path, parsedJson.get(artifact.path));
      }
    } else if (artifact.role === "vector") {
      const value = parsedJson.get(artifact.path);
      if (value === undefined) {
        continue;
      }
      const vector = parseVector(value);
      if (vector === undefined) {
        shapeIssue(issues, artifact.path, "vector does not match the 1.1.0 corpus shape");
        continue;
      }
      const firstPath = vectorIds.get(vector.vector_id);
      if (firstPath !== undefined) {
        issues.push({
          code: "duplicate-vector-id",
          path: artifact.path,
          message: `vector_id ${vector.vector_id} was first declared at ${firstPath}`,
        });
      } else {
        vectorIds.set(vector.vector_id, artifact.path);
      }
      vectors.push({ path: artifact.path, value: vector });
    }
  }
  vectors.sort((left, right) => compareText(left.path, right.path));

  const registryManifest = parseRegistryManifest(parsedJson.get(registryManifestPath));
  if (registryManifest === undefined && parsedJson.has(registryManifestPath)) {
    shapeIssue(issues, registryManifestPath, "registry manifest must pin revision 13 and schema 3.0.0");
  }
  const reasonCodes = parseReasonCodes(parsedJson.get(reasonCodesPath));
  const securityInvariants = parseSecurityInvariants(parsedJson.get(securityInvariantsPath));
  reportDuplicates(reasonCodes.entries.map(({ code }) => code), reasonCodesPath, "reason code", issues);
  reportDuplicates(
    securityInvariants.entries.map(({ id }) => id),
    securityInvariantsPath,
    "security invariant",
    issues,
  );

  const schema = parsedJson.get(registrySchemaPath);
  if (schema !== undefined && !isRecord(schema)) {
    shapeIssue(issues, registrySchemaPath, "registry schema must be a JSON object");
  }

  const entrySet = registryEntrySet(parsedJson);
  if (entrySet === undefined) {
    shapeIssue(issues, registryManifestPath, "complete registry entry documents are required");
  } else {
    const digest = createHash("sha256").update(canonicalize(entrySet), "utf8").digest("hex");
    if (registryManifest !== undefined && digest !== registryManifest.entry_set_sha256) {
      issues.push({
        code: "registry-entry-set-digest-mismatch",
        path: registryManifestPath,
        message: "registry entry_set_sha256 does not match the complete current entry set",
      });
    }
    if (isRecord(schema) && registryManifest !== undefined) {
      const validate = new Ajv({ allErrors: true, strict: false }).compile(schema as AnySchema);
      if (!validate({ manifest: registryManifest, ...entrySet })) {
        shapeIssue(issues, registryManifestPath, "registry documents do not match registry.schema.json");
      }
    }
  }

  sortIssues(issues);
  if (
    issues.length > 0
    || registryManifest === undefined
    || !reasonCodes.valid
    || !securityInvariants.valid
    || fixtures === undefined
  ) {
    return { issues };
  }

  const registry: RegistryDocument = {
    manifest: registryManifest,
    reason_codes: reasonCodes.entries,
    security_invariants: securityInvariants.entries,
  };
  return {
    corpus: {
      repositoryRoot: canonicalRoot,
      familyVersion: "heterodyne/0.5.0",
      registryRevision: 13,
      registryDigest: registryManifest.entry_set_sha256,
      specifications,
      schemas,
      vectors,
      fixtures,
      registry,
    },
    issues,
  };
}
