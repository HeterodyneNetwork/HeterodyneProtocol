import {
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
import { parseJsonPointer } from "./json-pointer.js";
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
const reasonCodesPath = "docs/spec/registry/reason-codes.json";
const securityInvariantsPath = "docs/spec/registry/security-invariants.json";
const specificationPaths = [
  "docs/spec/heterodyne-comms.md",
  "docs/spec/heterodyne-control.md",
  "docs/spec/heterodyne-core.md",
  "docs/spec/heterodyne-social.md",
  "docs/spec/heterodyne-workspace.md",
] as const;
const requiredArtifactRoles = new Map<string, string>([
  ...specificationPaths.map((path) => [path, "specification"] as const),
  [registryManifestPath, "registry"],
  [reasonCodesPath, "registry"],
  [securityInvariantsPath, "registry"],
]);

const ownerDocuments = new Set(["core", "comms", "control", "social", "workspace"]);
const directions = new Set(["consume", "produce", "round-trip"]);
const artifactRoles = new Set(["normative-support", "registry", "schema", "specification", "vector"]);
const sha256Pattern = /^[0-9a-f]{64}$/u;
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

class UnsafeRepositoryPathError extends Error {}

type FamilyArtifact = { path: string; role: string };

type FamilyManifest = {
  family_version: "heterodyne/0.5.0";
  registry: { path?: string };
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

function shapeIssue(issues: CorpusIssue[], path: string, message: string): void {
  issues.push({ code: "invalid-document-shape", path, message });
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
  if (registryPath === undefined) {
    shapeIssue(issues, familyManifestPath, "registry.path must be a string");
  }
  if (!isRecord(value.registry) || typeof value.registry.sha256 !== "string"
    || !sha256Pattern.test(value.registry.sha256)) {
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
    if (!artifactRoles.has(artifact.role)) {
      shapeIssue(issues, artifact.path, `unknown artifact role: ${artifact.role}`);
    }
    if (typeof artifact.sha256 !== "string" || !sha256Pattern.test(artifact.sha256)) {
      shapeIssue(issues, artifact.path, "artifact sha256 must be lowercase SHA-256 hex");
    }
    artifacts.push({ path: artifact.path, role: artifact.role });
  }
  return {
    family_version: "heterodyne/0.5.0",
    registry: { path: registryPath },
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

function parseConformanceCheck(value: unknown): ConformanceCheckDocument | undefined {
  if (
    !isRecord(value)
    || value.profile !== "core-signed-event-v1"
    || typeof value.event_pointer !== "string"
    || typeof value.nip01_raw_pointer !== "string"
    || (value.context_pointer !== undefined && typeof value.context_pointer !== "string")
    || typeof value.expected_terminal_stage !== "string"
    || !terminalStages.has(value.expected_terminal_stage as ExpectedTerminalStage)
  ) {
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
    || typeof value.direction !== "string"
    || !directions.has(value.direction)
    || !isRecord(value.input)
    || !isRecord(value.expected_output)
    || (value.conformance_checks !== undefined
      && (!Array.isArray(value.conformance_checks)
        || !value.conformance_checks.every((check) => parseConformanceCheck(check) !== undefined)))
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

  for (const [path, requiredRole] of requiredArtifactRoles) {
    const artifact = manifest.artifacts.find((candidate) => candidate.path === path);
    if (artifact === undefined) {
      issues.push({ code: "missing-required-root", path, message: "required release artifact is absent" });
    } else if (artifact.role !== requiredRole) {
      shapeIssue(issues, path, `required artifact role must be ${requiredRole}`);
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
  if (!reasonCodes.valid && parsedJson.has(reasonCodesPath)) {
    shapeIssue(issues, reasonCodesPath, "reason_codes must contain entries with string codes");
  }
  const securityInvariants = parseSecurityInvariants(parsedJson.get(securityInvariantsPath));
  if (!securityInvariants.valid && parsedJson.has(securityInvariantsPath)) {
    shapeIssue(
      issues,
      securityInvariantsPath,
      "security_invariants must contain id and owner strings with optional feature strings",
    );
  }
  reportDuplicates(reasonCodes.entries.map(({ code }) => code), reasonCodesPath, "reason code", issues);
  reportDuplicates(
    securityInvariants.entries.map(({ id }) => id),
    securityInvariantsPath,
    "security invariant",
    issues,
  );

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
