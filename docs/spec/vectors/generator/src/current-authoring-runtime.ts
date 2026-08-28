import {
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readdirSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { spawn } from "node:child_process";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import ts from "typescript";
import type { SemanticCoverageEntry } from "./coverage.js";
import {
  currentCompilerOptions,
  currentModuleDependencies,
} from "./current-import-graph.js";
import { validateVectorOrThrow } from "./schema.js";
import type { AuthoredVector, DocumentId, Vector } from "./types.js";
import { loadRegistry } from "./registry.js";

export const CURRENT_RUNTIME_TIMEOUT_MS = 180_000;
export const CURRENT_RUNTIME_STDOUT_LIMIT = 32 * 1024 * 1024;
export const CURRENT_RUNTIME_STDERR_LIMIT = 64 * 1024;

const GENERATOR_ROOT = resolve(import.meta.dirname, "..");
const REPOSITORY_ROOT = resolve(GENERATOR_ROOT, "../../../..");
const NODE_MODULES_ROOT = realpathSync(resolve(GENERATOR_ROOT, "node_modules"));
const CHILD_SOURCE = resolve(import.meta.dirname, "current-authoring-child.ts");
const RUNTIME_PREFIX = ".heterodyne-current-runtime-";
const RUNTIME_FORMAT = "heterodyne-current-authoring-1";

export const CURRENT_RUNTIME_ASSET_PATHS = Object.freeze([
  "docs/spec/registry/features.json",
  "docs/spec/registry/kinds.json",
  "docs/spec/registry/manifest.json",
  "docs/spec/registry/objects.json",
  "docs/spec/registry/proof-domains.json",
  "docs/spec/registry/reason-codes.json",
  "docs/spec/registry/registry.schema.json",
  "docs/spec/registry/security-invariants.json",
  "docs/spec/schemas/assurance/active-key-acceptance-v1.schema.json",
  "docs/spec/schemas/assurance/associated-key-v1.schema.json",
  "docs/spec/schemas/assurance/enrollment-contest-v1.schema.json",
  "docs/spec/schemas/assurance/enrollment-inception-v1.schema.json",
  "docs/spec/schemas/assurance/enrollment-observation-receipt-v1.schema.json",
  "docs/spec/schemas/assurance/succession-v1.schema.json",
  "docs/spec/schemas/comms/agent-workload-registration-v1.schema.json",
  "docs/spec/schemas/comms/claim-ledger-record-v1.schema.json",
  "docs/spec/schemas/comms/config-repository-git-structure-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-candidate-abandonment-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-checkpoint-receipt-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-checkpoint-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-config-key-bootstrap-recipient-array-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-emergency-reset-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-lost-generation-path-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-removal-observation-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-reset-recipient-array-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-secret-transition-v1.schema.json",
  "docs/spec/schemas/comms/credential-ledger-staging-ref-cleanup-v1.schema.json",
  "docs/spec/schemas/comms/governed-decrypt-key-binding-v1.schema.json",
  "docs/spec/schemas/comms/historical-decrypt-obligation-v1.schema.json",
  "docs/spec/schemas/comms/key-claim-revocation-v1.schema.json",
  "docs/spec/schemas/comms/key-claim-v1.schema.json",
  "docs/spec/schemas/comms/node-secret-exposure-v1.schema.json",
  "docs/spec/schemas/comms/node-secret-source-v1.schema.json",
  "docs/spec/schemas/comms/node-secret-transition-action-v1.schema.json",
  "docs/spec/schemas/comms/oidc-continuity-manifest-v1.schema.json",
  "docs/spec/schemas/comms/oidc-issuance-record-v1.schema.json",
  "docs/spec/schemas/comms/oidc-issuer-metadata-v1.schema.json",
  "docs/spec/schemas/comms/one-time-invite-response-v1.schema.json",
  "docs/spec/schemas/comms/one-time-invite-v1.schema.json",
  "docs/spec/schemas/comms/repository-retention-inventory-v1.schema.json",
  "docs/spec/schemas/comms/trusted-seed-acl-v1.schema.json",
  "docs/spec/schemas/control/control-agent-publish-v1.schema.json",
  "docs/spec/schemas/control/control-capability-set-v1.schema.json",
  "docs/spec/schemas/control/control-client-authorization-v1.schema.json",
  "docs/spec/schemas/control/control-device-authorization-state-v1.schema.json",
  "docs/spec/schemas/control/control-epoch-registration-v1.schema.json",
  "docs/spec/schemas/control/control-frame-v1.schema.json",
  "docs/spec/schemas/control/control-invitation-policy-v1.schema.json",
  "docs/spec/schemas/control/control-mcp-frame-v1.schema.json",
  "docs/spec/schemas/control/control-operation-record-v1.schema.json",
  "docs/spec/schemas/control/control-prepared-activation-v1.schema.json",
  "docs/spec/schemas/control/control-recovery-completion-v1.schema.json",
  "docs/spec/schemas/control/control-recovery-grant-v1.schema.json",
  "docs/spec/schemas/control/control-rpc-request-v1.schema.json",
  "docs/spec/schemas/control/control-rpc-response-v1.schema.json",
  "docs/spec/schemas/control/control-sftp-grant-v1.schema.json",
  "docs/spec/schemas/social/agent-policy-correction-v1.schema.json",
  "docs/spec/schemas/social/agent-policy-receipt-v1.schema.json",
] as const);

type GuardedRuntimeOptions = Readonly<{
  runtimeRoot: string;
  entryPath: string;
  arguments?: readonly string[];
  timeoutMs?: number;
  stdoutLimit?: number;
  stderrLimit?: number;
}>;

export type GuardedRuntimeResult = Readonly<{
  stdout: string;
  stderr: string;
}>;

function isInside(candidate: string, root: string): boolean {
  const rel = relative(root, candidate);
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

function canonicalRegularFile(path: string, root: string): string {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`current runtime entry must be a regular file: ${path}`);
  }
  const canonical = realpathSync(path);
  if (!isInside(canonical, root)) {
    throw new Error(`current runtime entry escapes its root: ${path}`);
  }
  return canonical;
}

export function copyRegularCurrentRuntimeAsset(
  sourceRootPath: string,
  runtimeRootPath: string,
  relativePath: string,
): void {
  if (isAbsolute(relativePath)) {
    throw new Error(`current runtime asset escapes its root: ${relativePath}`);
  }
  const sourceRoot = realpathSync(sourceRootPath);
  const runtimeRoot = realpathSync(runtimeRootPath);
  const source = resolve(sourceRoot, relativePath);
  const destination = resolve(runtimeRoot, relativePath);
  if (!isInside(source, sourceRoot) || !isInside(destination, runtimeRoot)) {
    throw new Error(`current runtime asset escapes its root: ${relativePath}`);
  }
  const stat = lstatSync(source);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`current runtime asset must be a regular file: ${relativePath}`);
  }
  if (!isInside(realpathSync(source), sourceRoot)) {
    throw new Error(`current runtime asset escapes its source root: ${relativePath}`);
  }
  if (existsSync(destination)) {
    throw new Error(`current runtime asset destination already exists: ${relativePath}`);
  }
  mkdirSync(dirname(destination), { recursive: true });
  const destinationParent = realpathSync(dirname(destination));
  if (!isInside(destinationParent, runtimeRoot)) {
    throw new Error(`current runtime asset destination escapes its root: ${relativePath}`);
  }
  copyFileSync(source, destination, constants.COPYFILE_EXCL);
  const copied = lstatSync(destination);
  if (!copied.isFile() || copied.isSymbolicLink()) {
    throw new Error(`current runtime copied asset is not regular: ${relativePath}`);
  }
}

function assertSafeLockedNodeModulesTree(path = NODE_MODULES_ROOT): void {
  for (const name of readdirSync(path)) {
    const entry = join(path, name);
    const stat = lstatSync(entry);
    if (stat.isSymbolicLink()) {
      const target = realpathSync(entry);
      if (!isInside(target, NODE_MODULES_ROOT)) {
        throw new Error(`current runtime dependency symlink escapes node_modules: ${entry}`);
      }
      continue;
    }
    if (stat.isDirectory()) {
      assertSafeLockedNodeModulesTree(entry);
      continue;
    }
    if (!stat.isFile()) {
      throw new Error(`current runtime dependency is not a regular file: ${entry}`);
    }
  }
}

function formatDiagnostics(diagnostics: readonly ts.Diagnostic[]): string {
  return ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCanonicalFileName: (path) => path,
    getCurrentDirectory: () => REPOSITORY_ROOT,
    getNewLine: () => "\n",
  });
}

function emitCurrentRuntime(runtimeRoot: string): string {
  const graph = currentModuleDependencies(CHILD_SOURCE);
  const graphJson = graph
    .filter((path) => path.endsWith(".json"))
    .map((path) => relative(REPOSITORY_ROOT, path));
  const manifest = new Set<string>(CURRENT_RUNTIME_ASSET_PATHS);
  const omittedAssets = graphJson.filter((path) => !manifest.has(path));
  if (omittedAssets.length > 0) {
    throw new Error(`current runtime asset manifest incomplete: ${omittedAssets.join(",")}`);
  }
  const sources = graph.filter((path) => path.endsWith(".ts") && !path.endsWith(".d.ts"));
  for (const source of sources) {
    if (!isInside(source, REPOSITORY_ROOT)) {
      throw new Error(`current runtime source escapes repository: ${source}`);
    }
  }
  const options: ts.CompilerOptions = {
    ...currentCompilerOptions(CHILD_SOURCE),
    rootDir: REPOSITORY_ROOT,
    outDir: runtimeRoot,
    noEmit: false,
    noEmitOnError: true,
    declaration: false,
    declarationMap: false,
    emitDeclarationOnly: false,
    incremental: false,
    sourceMap: false,
    inlineSourceMap: false,
  };
  const program = ts.createProgram({ rootNames: sources, options });
  const preflight = ts.getPreEmitDiagnostics(program);
  if (preflight.length > 0) {
    throw new Error(`current runtime TypeScript diagnostics:\n${formatDiagnostics(preflight)}`);
  }
  const expectedOutputs = new Set(sources.map((source) => resolve(
    runtimeRoot,
    relative(REPOSITORY_ROOT, source).replace(/\.ts$/u, ".js"),
  )));
  const emitted = new Set<string>();
  const writeEmittedFile = (outputPath: string, data: string): void => {
    if (outputPath.endsWith(".json")) return;
    if (!outputPath.endsWith(".js")) {
      throw new Error(`unexpected current runtime compiler output: ${outputPath}`);
    }
    const destination = resolve(outputPath);
    if (!isInside(destination, runtimeRoot)) {
      throw new Error(`current runtime compiler output escapes root: ${destination}`);
    }
    if (!expectedOutputs.has(destination)) {
      throw new Error(`current runtime compiler emitted a non-graph source: ${destination}`);
    }
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, data, { encoding: "utf8", flag: "wx" });
    emitted.add(destination);
  };
  const emitDiagnostics: ts.Diagnostic[] = [];
  for (const sourcePath of sources) {
    const source = program.getSourceFile(sourcePath);
    if (source === undefined) {
      throw new Error(`current runtime graph source absent from Program: ${sourcePath}`);
    }
    const result = program.emit(source, writeEmittedFile);
    emitDiagnostics.push(...result.diagnostics);
    if (result.emitSkipped) {
      throw new Error(`current runtime TypeScript emit skipped: ${sourcePath}`);
    }
  }
  if (emitDiagnostics.length > 0) {
    throw new Error(`current runtime TypeScript emit failed:\n${formatDiagnostics(emitDiagnostics)}`);
  }
  for (const expected of expectedOutputs) {
    if (!emitted.has(expected)) {
      throw new Error(`current runtime source was not emitted: ${expected}`);
    }
  }
  return resolve(
    runtimeRoot,
    relative(REPOSITORY_ROOT, CHILD_SOURCE).replace(/\.ts$/u, ".js"),
  );
}

function assertRegularRuntimeTree(path: string): void {
  for (const name of readdirSync(path)) {
    const entry = join(path, name);
    const stat = lstatSync(entry);
    if (stat.isDirectory()) {
      assertRegularRuntimeTree(entry);
      continue;
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`current runtime tree contains a non-regular file: ${entry}`);
    }
  }
}

function materializeCurrentRuntime(runtimeRoot: string): string {
  writeFileSync(
    join(runtimeRoot, "package.json"),
    '{"private":true,"type":"module"}\n',
    { encoding: "utf8", flag: "wx" },
  );
  const entryPath = emitCurrentRuntime(runtimeRoot);
  for (const asset of CURRENT_RUNTIME_ASSET_PATHS) {
    copyRegularCurrentRuntimeAsset(REPOSITORY_ROOT, runtimeRoot, asset);
  }
  assertRegularRuntimeTree(runtimeRoot);
  assertSafeLockedNodeModulesTree();
  return entryPath;
}

function cleanupCurrentRuntime(path: string): void {
  const parent = realpathSync(dirname(path));
  if (
    parent !== realpathSync(GENERATOR_ROOT)
    || !/^\.heterodyne-current-runtime-[A-Za-z0-9]{6}$/u.test(basename(path))
  ) {
    throw new Error(`refusing to remove unguarded current runtime path: ${path}`);
  }
  if (!existsSync(path)) return;
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) {
    unlinkSync(path);
    return;
  }
  if (!stat.isDirectory()) {
    throw new Error(`refusing to recursively remove non-directory current runtime: ${path}`);
  }
  rmSync(path, { recursive: true, force: true });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const expected = [...required].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} must contain exactly: ${expected.join(",")}`);
  }
}

function stringArray(value: unknown, label: string, allowEmpty: boolean): string[] {
  if (
    !Array.isArray(value)
    || (!allowEmpty && value.length === 0)
    || !value.every((entry) => typeof entry === "string" && entry.length > 0)
  ) throw new Error(`${label} must be a ${allowEmpty ? "" : "nonempty "}string array`);
  if (new Set(value).size !== value.length) throw new Error(`${label} must be unique`);
  return [...value];
}

function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
  const sortedRight = [...right].sort();
  return left.length === right.length
    && [...left].sort().every((entry, index) => entry === sortedRight[index]);
}

function isSafeRelativeVectorPath(path: string): boolean {
  return !isAbsolute(path)
    && !path.includes("\\")
    && !path.includes("\0")
    && path.endsWith(".json")
    && path.split("/").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

function parseSemanticCoverage(value: unknown): SemanticCoverageEntry {
  if (!isRecord(value)) throw new Error("current runtime semantic coverage entry must be an object");
  const allowed = [
    "vector_id",
    "owner_document",
    ...(Object.hasOwn(value, "profile") ? ["profile"] : []),
    "spec_refs",
    "invariants",
    "reason_codes",
    "semantic_boundary",
  ];
  assertExactKeys(value, allowed, "current runtime semantic coverage entry");
  if (
    typeof value.vector_id !== "string"
    || typeof value.owner_document !== "string"
    || typeof value.semantic_boundary !== "string"
    || value.semantic_boundary.length === 0
    || (Object.hasOwn(value, "profile") && typeof value.profile !== "string")
  ) throw new Error("current runtime semantic coverage entry has invalid scalar fields");
  return {
    vector_id: value.vector_id,
    owner_document: value.owner_document as DocumentId,
    ...(typeof value.profile === "string" ? { profile: value.profile } : {}),
    spec_refs: stringArray(value.spec_refs, "semantic spec_refs", false),
    invariants: stringArray(value.invariants, "semantic invariants", false),
    reason_codes: stringArray(value.reason_codes, "semantic reason_codes", true),
    semantic_boundary: value.semantic_boundary,
  };
}

function freezeDeep<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value as object)) return value;
  seen.add(value as object);
  for (const key of Reflect.ownKeys(value as object)) {
    freezeDeep((value as Record<PropertyKey, unknown>)[key], seen);
  }
  if (!ArrayBuffer.isView(value as object)) Object.freeze(value);
  return value;
}

export type IsolatedCurrentCatalog = Readonly<{
  vectors: readonly AuthoredVector[];
  semantic_coverage: readonly SemanticCoverageEntry[];
}>;

export function parseCurrentRuntimeEnvelope(text: string): IsolatedCurrentCatalog {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new Error("current authoring child emitted malformed JSON", { cause: error });
  }
  if (!isRecord(raw)) throw new Error("current authoring child envelope must be an object");
  assertExactKeys(raw, ["format", "vectors", "semantic_coverage"], "current authoring child envelope");
  if (raw.format !== RUNTIME_FORMAT) throw new Error("current authoring child envelope format mismatch");
  if (!Array.isArray(raw.vectors) || !Array.isArray(raw.semantic_coverage)) {
    throw new Error("current authoring child envelope collections must be arrays");
  }
  const paths = new Set<string>();
  const ids = new Set<string>();
  const vectors = raw.vectors.map((entry, index): AuthoredVector => {
    if (!isRecord(entry)) throw new Error(`current runtime vector ${index} must be an object`);
    assertExactKeys(entry, ["relativePath", "vector"], `current runtime vector ${index}`);
    if (typeof entry.relativePath !== "string" || !isRecord(entry.vector)) {
      throw new Error(`current runtime vector ${index} has invalid fields`);
    }
    if (!isSafeRelativeVectorPath(entry.relativePath)) {
      throw new Error(`current authoring child emitted unsafe vector path: ${entry.relativePath}`);
    }
    try {
      validateVectorOrThrow(entry.vector);
    } catch (error) {
      throw new Error(
        `current authoring child emitted schema-invalid vector ${index}`,
        { cause: error },
      );
    }
    const vector = entry.vector as Vector;
    if (entry.relativePath !== `${vector.vector_id}.json`) {
      throw new Error(`current runtime vector path/id mismatch: ${entry.relativePath}`);
    }
    if (paths.has(entry.relativePath) || ids.has(vector.vector_id)) {
      throw new Error(`duplicate current runtime vector: ${vector.vector_id}`);
    }
    paths.add(entry.relativePath);
    ids.add(vector.vector_id);
    return { relativePath: entry.relativePath, vector };
  });
  const semanticCoverage = raw.semantic_coverage.map(parseSemanticCoverage);
  if (semanticCoverage.length !== vectors.length) {
    throw new Error("current authoring child vector/coverage count mismatch");
  }
  const coverageIds = new Set<string>();
  for (const entry of semanticCoverage) {
    if (coverageIds.has(entry.vector_id)) {
      throw new Error(`duplicate current runtime semantic coverage: ${entry.vector_id}`);
    }
    coverageIds.add(entry.vector_id);
    const vector = vectors.find((candidate) => candidate.vector.vector_id === entry.vector_id)?.vector;
    if (vector === undefined) {
      throw new Error(`orphan current runtime semantic coverage: ${entry.vector_id}`);
    }
    if (
      entry.owner_document !== vector.owner_document
      || entry.profile !== vector.profile
      || !sameStringSet(entry.spec_refs, vector.spec_refs)
      || !sameStringSet(entry.invariants, vector.invariants)
    ) throw new Error(`current runtime semantic coverage/vector mismatch: ${entry.vector_id}`);
  }
  const sorted = [...vectors].sort((left, right) =>
    left.relativePath.localeCompare(right.relativePath, "en")
  );
  if (vectors.some((value, index) => value.relativePath !== sorted[index]?.relativePath)) {
    throw new Error("current authoring child vectors are not sorted");
  }
  return freezeDeep({ vectors, semantic_coverage: semanticCoverage });
}

export async function withDisposableCurrentRuntime<T>(
  operation: (runtimeRoot: string) => Promise<T>,
): Promise<T> {
  let runtimeRoot: string | undefined;
  try {
    runtimeRoot = mkdtempSync(join(GENERATOR_ROOT, RUNTIME_PREFIX));
    return await operation(runtimeRoot);
  } finally {
    if (runtimeRoot !== undefined) cleanupCurrentRuntime(runtimeRoot);
  }
}

export async function buildIsolatedCurrentCatalog(): Promise<IsolatedCurrentCatalog> {
  return await withDisposableCurrentRuntime(async (runtimeRoot) => {
    const entryPath = materializeCurrentRuntime(runtimeRoot);
    const result = await runGuardedCurrentRuntimeEntry({ runtimeRoot, entryPath });
    const catalog = parseCurrentRuntimeEnvelope(result.stdout);
    const {
      findInvariantCoverageIssues,
      findProfileCoverageIssues,
      findReasonCoverageIssues,
    } = await import("./coverage.js");
    const registry = loadRegistry(REPOSITORY_ROOT);
    const issues = [
      ...findInvariantCoverageIssues(registry, catalog.semantic_coverage),
      ...findReasonCoverageIssues(registry, catalog.semantic_coverage),
      ...findProfileCoverageIssues(registry, catalog.semantic_coverage),
    ];
    if (issues.length > 0) {
      throw new Error(`current authoring child semantic closure failed: ${issues.join("; ")}`);
    }
    return catalog;
  });
}

/**
 * Trusted-parent primitive used by the current authoring materializer. The
 * child receives only explicit read roots and the three standard streams.
 */
export async function runGuardedCurrentRuntimeEntry(
  options: GuardedRuntimeOptions,
): Promise<GuardedRuntimeResult> {
  const runtimeRoot = realpathSync(options.runtimeRoot);
  const entryPath = canonicalRegularFile(options.entryPath, runtimeRoot);
  const timeoutMs = options.timeoutMs ?? CURRENT_RUNTIME_TIMEOUT_MS;
  const stdoutLimit = options.stdoutLimit ?? CURRENT_RUNTIME_STDOUT_LIMIT;
  const stderrLimit = options.stderrLimit ?? CURRENT_RUNTIME_STDERR_LIMIT;
  for (const [name, value] of [
    ["timeout", timeoutMs],
    ["stdout limit", stdoutLimit],
    ["stderr limit", stderrLimit],
  ] as const) {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw new Error(`invalid current runtime ${name}: ${value}`);
    }
  }

  const executable = realpathSync(process.execPath);
  const child = spawn(executable, [
    "--permission",
    "--no-addons",
    "--no-global-search-paths",
    "--no-expose-wasm",
    "--max-old-space-size=512",
    `--allow-fs-read=${runtimeRoot}`,
    `--allow-fs-read=${NODE_MODULES_ROOT}`,
    entryPath,
    ...(options.arguments ?? []),
  ], {
    cwd: runtimeRoot,
    env: { LANG: "C", LC_ALL: "C", TZ: "UTC" },
    stdio: ["ignore", "pipe", "pipe"],
  });

  return await new Promise<GuardedRuntimeResult>((accept, reject) => {
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let failure: Error | undefined;
    let settled = false;
    const fail = (error: Error): void => {
      failure ??= error;
      child.kill("SIGKILL");
    };
    const timer = setTimeout(
      () => fail(new Error(`current authoring child timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
    const finish = (operation: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      operation();
    };

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes > stdoutLimit) {
        fail(new Error(`current authoring child stdout exceeded ${stdoutLimit} bytes`));
        return;
      }
      stdout.push(Buffer.from(chunk));
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.byteLength;
      if (stderrBytes > stderrLimit) {
        fail(new Error(`current authoring child stderr exceeded ${stderrLimit} bytes`));
        return;
      }
      stderr.push(Buffer.from(chunk));
    });
    child.once("error", (error) => finish(() => reject(error)));
    child.once("close", (code, signal) => finish(() => {
      if (failure !== undefined) {
        reject(failure);
        return;
      }
      const errorOutput = Buffer.concat(stderr).toString("utf8");
      if (code !== 0) {
        reject(new Error(
          `current authoring child failed (${code ?? signal ?? "unknown"}): ${errorOutput}`,
        ));
        return;
      }
      accept({
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: errorOutput,
      });
    }));
  });
}
