import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { buildFixtures } from "./fixtures.js";
import { REASON_CODES } from "./reason-codes.js";
import { VECTOR_SCHEMA, validateVectorOrThrow } from "./schema.js";
import {
  buildSnapshotManifest,
  isSnapshotTopLevelVectorFile,
  serializeSnapshotManifest,
  type SnapshotManifest,
} from "./snapshot-manifest.js";
import {
  normalizeSnapshotFixtures,
  normalizeSnapshotVector,
  buildSnapshotVectorSchema,
  preservesVectorBehavior,
  snapshotVectorValidator,
  validateRawVector,
} from "./snapshot-envelope.js";
import { buildAllVectors } from "./topics.js";
import type { RawVector, SnapshotVector } from "./types.js";
import { writeCoverageFromVectors } from "./coverage.js";

export async function authorAllVectors(outputDir: string): Promise<string[]> {
  const fixtures = buildFixtures();
  const vectors = await buildAllVectors(fixtures);
  const written: string[] = [];

  await removeRetiredVectors(
    outputDir,
    new Set(vectors.map(({ relativePath }) => relativePath)),
  );

  await writeJson(join(outputDir, "fixtures.json"), fixtures);
  await writeJson(join(outputDir, "schema", "vector.schema.json"), VECTOR_SCHEMA);
  await writeJson(join(outputDir, "schema", "reason-codes.json"), { reason_codes: REASON_CODES });
  await writeReasonCodesMarkdown(join(outputDir, "schema", "reason-codes.md"));

  for (const { relativePath, vector } of vectors) {
    try {
      validateVectorOrThrow(vector);
    } catch (error) {
      throw new Error(
        `invalid authored vector ${vector.vector_id}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    await writeJson(join(outputDir, relativePath), vector);
    written.push(relativePath);
  }

  return written.sort();
}

const SNAPSHOT_VECTOR_ROOT = "docs/spec/vectors";
const SNAPSHOT_PROJECTION_PATHS = [
  `${SNAPSHOT_VECTOR_ROOT}/fixtures.json`,
  `${SNAPSHOT_VECTOR_ROOT}/snapshot.json`,
  `${SNAPSHOT_VECTOR_ROOT}/coverage`,
  `${SNAPSHOT_VECTOR_ROOT}/schema/vector.schema.json`,
  `${SNAPSHOT_VECTOR_ROOT}/schema/reason-codes.json`,
  `${SNAPSHOT_VECTOR_ROOT}/schema/reason-codes.md`,
  "docs/spec/conformance/baselines",
  "docs/spec/conformance/report.json",
  "docs/spec/conformance/DEBT.md",
] as const;

export async function packageSnapshot(
  rawRoot: string,
  snapshotRoot: string,
  sourceCommit: string,
): Promise<SnapshotManifest> {
  const rawSchema = JSON.parse(await readFile(join(rawRoot, "schema/vector.schema.json"), "utf8"));
  const packagedSchema = buildSnapshotVectorSchema(rawSchema);
  const validatePackagedVector = snapshotVectorValidator(packagedSchema);
  const rawFixtures = JSON.parse(await readFile(join(rawRoot, "fixtures.json"), "utf8"));
  const destinationVectorRoot = join(snapshotRoot, SNAPSHOT_VECTOR_ROOT);
  const snapshotVectors: SnapshotVector[] = [];

  await mkdir(destinationVectorRoot, { recursive: true });
  await writeJson(
    join(destinationVectorRoot, "fixtures.json"),
    normalizeSnapshotFixtures(rawFixtures),
  );
  await writeJson(join(destinationVectorRoot, "schema/vector.schema.json"), packagedSchema);
  const rawReasonCodes = JSON.parse(
    await readFile(join(rawRoot, "schema/reason-codes.json"), "utf8"),
  ) as unknown;
  const { projection: reasonCodes, replacements: reasonRefReplacements } =
    normalizeReasonCodeProjection(rawReasonCodes);
  await writeJson(join(destinationVectorRoot, "schema/reason-codes.json"), reasonCodes);
  let reasonMarkdown = await readFile(join(rawRoot, "schema/reason-codes.md"), "utf8");
  for (const [legacy, qualified] of reasonRefReplacements) {
    reasonMarkdown = reasonMarkdown.replaceAll(legacy, qualified);
  }
  await writeFile(
    join(destinationVectorRoot, "schema/reason-codes.md"),
    reasonMarkdown,
    "utf8",
  );

  for (const relativePath of await listRawVectorFiles(rawRoot)) {
    const raw = JSON.parse(await readFile(join(rawRoot, ...relativePath.split("/")), "utf8")) as unknown;
    let packaged: SnapshotVector;
    try {
      validateRawVector(raw, rawSchema);
      packaged = normalizeSnapshotVector(raw);
      validatePackagedVector(packaged);
      if (!preservesVectorBehavior(raw as RawVector, packaged)) {
        throw new Error(`snapshot-vector-behavior-changed: ${packaged.vector_id}`);
      }
    } catch (error) {
      throw new Error(
        `${relativePath}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    await writeJson(
      join(destinationVectorRoot, ...relativePath.split("/")),
      packaged,
    );
    snapshotVectors.push(packaged);
  }
  await writeCoverageFromVectors(destinationVectorRoot, snapshotVectors);

  const manifest = buildSnapshotManifest(snapshotRoot, sourceCommit);
  await writeFile(
    join(destinationVectorRoot, "snapshot.json"),
    serializeSnapshotManifest(manifest),
    "utf8",
  );
  return manifest;
}

export type ReplacementOperations = {
  rename?: (from: string, to: string) => Promise<void>;
};

export class SnapshotReplacementRecoveryError extends AggregateError {
  readonly recoveryPath: string;

  constructor(
    originalError: unknown,
    rollbackErrors: readonly Error[],
    recoveryPath: string,
  ) {
    super(
      [asError(originalError), ...rollbackErrors],
      `snapshot replacement failed and rollback was incomplete; recover prior bytes from ${recoveryPath}`,
    );
    this.name = "SnapshotReplacementRecoveryError";
    this.recoveryPath = recoveryPath;
  }
}

export async function replaceSnapshotData(
  repositoryRoot: string,
  stagedRoot: string,
  operations: ReplacementOperations = {},
): Promise<void> {
  const repository = resolve(repositoryRoot);
  const staging = resolve(stagedRoot);
  if (repository === staging || staging.startsWith(`${repository}${sep}`)) {
    throw new Error("snapshot staging root must be outside the repository");
  }
  const move = operations.rename ?? rename;
  const paths = await replacementPaths(repository, staging);
  const targetParents = [...new Set(paths.map((path) =>
    dirname(join(repository, ...path.split("/")))
  ))];
  // Inspect the complete destination set before creating a directory or moving
  // a byte. Otherwise an early valid target can be installed before a later
  // symlinked parent is discovered.
  for (const parent of targetParents) {
    await assertSafeDestinationParent(repository, parent, true);
  }
  for (const parent of targetParents) {
    await ensureSafeDestinationParent(repository, parent);
  }
  const backupRoot = await mkdtemp(join(dirname(repository), ".heterodyne-snapshot-backup-"));
  const applied: Array<{ path: string; oldMoved: boolean; newMoved: boolean }> = [];
  let retainBackup = false;
  try {
    for (const path of paths) {
      const target = join(repository, ...path.split("/"));
      const staged = join(staging, ...path.split("/"));
      const backup = join(backupRoot, ...path.split("/"));
      const state = { path, oldMoved: false, newMoved: false };
      applied.push(state);
      await assertSafeDestinationParent(repository, dirname(target));
      if (await pathExists(target)) {
        await mkdir(dirname(backup), { recursive: true });
        await move(target, backup);
        state.oldMoved = true;
      }
      if (await pathExists(staged)) {
        await assertSafeDestinationParent(repository, dirname(target));
        await move(staged, target);
        state.newMoved = true;
      }
    }
  } catch (error) {
    const rollbackErrors: Error[] = [];
    for (const state of [...applied].reverse()) {
      const target = join(repository, ...state.path.split("/"));
      const staged = join(staging, ...state.path.split("/"));
      const backup = join(backupRoot, ...state.path.split("/"));
      let installedBytesRecovered = true;
      if (state.newMoved) {
        try {
          if (!await pathExists(target)) {
            throw new Error(`installed snapshot bytes missing during rollback: ${state.path}`);
          }
          await mkdir(dirname(staged), { recursive: true });
          await assertSafeDestinationParent(repository, dirname(target));
          await rename(target, staged);
        } catch (rollbackError) {
          installedBytesRecovered = false;
          rollbackErrors.push(new Error(
            `rollback failed while recovering installed bytes: ${state.path}`,
            { cause: rollbackError },
          ));
        }
      }
      if (state.oldMoved && installedBytesRecovered) {
        try {
          if (!await pathExists(backup)) {
            throw new Error(`prior snapshot backup missing during rollback: ${state.path}`);
          }
          await assertSafeDestinationParent(repository, dirname(target));
          await rename(backup, target);
        } catch (rollbackError) {
          rollbackErrors.push(new Error(
            `rollback failed while restoring prior bytes: ${state.path}`,
            { cause: rollbackError },
          ));
        }
      }
    }
    if (rollbackErrors.length > 0) {
      retainBackup = true;
      throw new SnapshotReplacementRecoveryError(error, rollbackErrors, backupRoot);
    }
    throw error;
  } finally {
    if (!retainBackup) await rm(backupRoot, { recursive: true, force: true });
  }
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

async function assertSafeDestinationParent(
  repositoryRoot: string,
  parent: string,
  allowMissing = false,
): Promise<void> {
  const relativeParent = relative(repositoryRoot, parent);
  if (
    relativeParent === ".."
    || relativeParent.startsWith(`..${sep}`)
    || resolve(repositoryRoot, relativeParent) !== resolve(parent)
  ) {
    throw new Error(`unsafe snapshot destination parent escapes repository: ${parent}`);
  }

  const components = relativeParent === "" ? [] : relativeParent.split(sep);
  let current = repositoryRoot;
  for (const component of ["", ...components]) {
    if (component !== "") current = join(current, component);
    let entry;
    try {
      entry = await lstat(current);
    } catch (error) {
      if (
        allowMissing
        && error !== null
        && typeof error === "object"
        && "code" in error
        && error.code === "ENOENT"
      ) {
        return;
      }
      throw error;
    }
    if (entry.isSymbolicLink()) {
      throw new Error(`unsafe snapshot destination parent is a symbolic link: ${current}`);
    }
    if (!entry.isDirectory()) {
      throw new Error(`unsafe snapshot destination parent is not a directory: ${current}`);
    }
  }
}

async function ensureSafeDestinationParent(
  repositoryRoot: string,
  parent: string,
): Promise<void> {
  const relativeParent = relative(repositoryRoot, parent);
  const components = relativeParent === "" ? [] : relativeParent.split(sep);
  let current = repositoryRoot;
  await assertSafeDestinationParent(repositoryRoot, current);
  for (const component of components) {
    current = join(current, component);
    try {
      await mkdir(current);
    } catch (error) {
      if (
        error === null
        || typeof error !== "object"
        || !("code" in error)
        || error.code !== "EEXIST"
      ) {
        throw error;
      }
    }
    await assertSafeDestinationParent(repositoryRoot, current);
  }
}

async function replacementPaths(repositoryRoot: string, stagedRoot: string): Promise<string[]> {
  const paths = new Set<string>(SNAPSHOT_PROJECTION_PATHS);
  for (const root of [repositoryRoot, stagedRoot]) {
    const vectorRoot = join(root, SNAPSHOT_VECTOR_ROOT);
    let entries;
    try {
      entries = await readdir(vectorRoot, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (
        entry.isDirectory()
        && entry.name !== "coverage"
        && entry.name !== "generator"
        && entry.name !== "schema"
      ) {
        paths.add(`${SNAPSHOT_VECTOR_ROOT}/${entry.name}`);
      } else if (entry.isFile() && isSnapshotTopLevelVectorFile(entry.name)) {
        paths.add(`${SNAPSHOT_VECTOR_ROOT}/${entry.name}`);
      }
    }
  }
  return [...paths].sort();
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    return error !== null && typeof error === "object" && "code" in error && error.code === "ENOENT"
      ? false
      : Promise.reject(error);
  }
}

async function listRawVectorFiles(root: string): Promise<string[]> {
  return (await jsonFiles(root))
    .map((path) => relative(root, path).split(sep).join("/"))
    .filter((path) => path !== "fixtures.json")
    .filter((path) => !path.startsWith("schema/"))
    .filter((path) => !path.startsWith("coverage/"))
    .filter((path) => !path.startsWith("generator/"))
    .sort();
}

function normalizeReasonCodeProjection(raw: unknown): {
  projection: Record<string, unknown>;
  replacements: Array<[string, string]>;
} {
  if (
    typeof raw !== "object"
    || raw === null
    || !Object.hasOwn(raw, "reason_codes")
    || !Array.isArray((raw as Record<string, unknown>).reason_codes)
  ) {
    throw new Error("raw-reason-codes-invalid: reason_codes must be an array");
  }
  const projection = structuredClone(raw) as Record<string, unknown>;
  const entries = projection.reason_codes as unknown[];
  const replacements: Array<[string, string]> = [];
  for (const [index, value] of entries.entries()) {
    if (
      typeof value !== "object"
      || value === null
      || typeof (value as Record<string, unknown>).owner !== "string"
      || !Array.isArray((value as Record<string, unknown>).spec_refs)
    ) {
      throw new Error(`raw-reason-codes-invalid: reason_codes/${index}`);
    }
    const entry = value as Record<string, unknown>;
    const owner = entry.owner as string;
    entry.spec_refs = (entry.spec_refs as unknown[]).map((ref) => {
      const match = typeof ref === "string"
        ? /^heterodyne:[^#]+#([a-z0-9][a-z0-9-]*)$/u.exec(ref)
        : null;
      if (match === null || !["core", "comms", "control", "social", "workspace"].includes(owner)) {
        throw new Error(`raw-reason-codes-invalid: reason_codes/${index}/spec_refs`);
      }
      const qualified = `heterodyne:${owner}#${match[1]}`;
      replacements.push([ref as string, qualified]);
      return qualified;
    });
  }
  return { projection, replacements };
}

async function removeRetiredVectors(
  outputDir: string,
  expected: ReadonlySet<string>,
): Promise<void> {
  for (const path of await jsonFiles(outputDir)) {
    const relativePath = relative(outputDir, path);
    if (relativePath === "fixtures.json"
      || relativePath.startsWith("schema/")
      || relativePath.startsWith("coverage/")
      || expected.has(relativePath)) {
      continue;
    }
    let value: unknown;
    try {
      value = JSON.parse(await readFile(path, "utf8"));
    } catch {
      continue;
    }
    if (typeof value === "object" && value !== null && "vector_id" in value) {
      await unlink(path);
    }
  }
}

async function jsonFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return files;
  }
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) files.push(...await jsonFiles(path));
    else if (entry.isFile() && entry.name.endsWith(".json")) files.push(path);
  }
  return files;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeReasonCodesMarkdown(path: string): Promise<void> {
  const rows = REASON_CODES.map(
    (reason) => `| \`${reason.code}\` | ${reason.owner} | ${reason.status} | \`${reason.first_version}\` | ${reason.spec_refs.join(", ")} | ${reason.description} |`,
  ).join("\n");
  await mkdir(dirname(path), { recursive: true });
  await writeFile(
    path,
    `# Reason codes\n\n` +
      "Generated compatibility projection. The authoritative allocation container is `docs/spec/registry/reason-codes.json`; do not edit this file by hand. `reason_code` values are conformance-test vocabulary and implementations do not need to emit these strings on the wire.\n\n" +
      "| Code | Owner | Status | First version | Spec refs | Meaning |\n" +
      "|---|---|---|---|---|---|\n" +
      `${rows}\n`,
    "utf8",
  );
}
