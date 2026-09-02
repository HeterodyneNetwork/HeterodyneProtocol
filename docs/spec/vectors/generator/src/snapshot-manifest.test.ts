import { createHash } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import snapshotManifestSchema from "../../snapshot.schema.json" with { type: "json" };
import {
  findInvariantCoverageIssues,
  findProfileCoverageIssues,
  findReasonCoverageIssues,
} from "./coverage.js";
import {
  currentCaseContract,
  currentCaseIds,
} from "./current-vectors/case-contracts.js";
import { loadRegistry } from "./registry.js";
import {
  buildSnapshotManifest,
  loadSnapshotManifest,
  validateSnapshotManifestSchema,
  type SnapshotManifest,
} from "./snapshot-manifest.js";

const VECTOR_ROOT = "docs/spec/vectors";
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
const VECTOR_PATHS = [
  "top-level.json",
  "core/001-first.json",
  "workspace/001-second.json",
] as const;
const SOURCE_COMMIT = "1".repeat(40);
const RECONCILIATION_SOURCE_COMMIT = "c72f5ccdf855069550511d8e3e837dae55ed299c";
const RECONCILIATION_VECTOR_COUNT = 267;
const SNAPSHOT_OWNERS = [
  "assurance",
  "comms",
  "control",
  "core",
  "social",
  "workspace",
] as const;
const RETIRED_CASE_IDS = [
  "core/org-member-add-unauthorized",
  "core/role-delegation-address-invalid",
  "core/role-delegation-key-proof-invalid",
] as const;
const HETERODYNE_SCHEMA_ORIGIN = "https://" + ["heterodyne", "network"].join(".");
const JSON_SCHEMA_ORIGIN = "https://" + ["json-schema", "org"].join(".");
const SNAPSHOT_META_SCHEMA_ID =
  `${HETERODYNE_SCHEMA_ORIGIN}/schemas/vector-snapshot-manifest-meta-v1.schema.json`;
const DRAFT_2020_12_CORE_VOCABULARY_ID =
  `${JSON_SCHEMA_ORIGIN}/draft/2020-12/vocab/core`;
const UNIQUE_BY_PATH_VOCABULARY_ID =
  `${HETERODYNE_SCHEMA_ORIGIN}/vocab/unique-by-path-v1`;
const repositoryRoot = resolve(import.meta.dirname, "../../../../../");
const temps: string[] = [];

function compareText(left: string, right: string): number {
  return left.localeCompare(right, "en");
}

type PublishedVector = Readonly<{
  vector_id: string;
  owner_document: (typeof SNAPSHOT_OWNERS)[number];
  profile?: string;
  spec_refs: readonly string[];
  invariants: readonly string[];
  reason_codes: readonly string[];
  expected_output: Readonly<Record<string, unknown>>;
}>;

afterEach(() => {
  for (const path of temps.splice(0)) rmSync(path, { recursive: true, force: true });
});

function write(root: string, path: string, bytes: string): void {
  const absolute = join(root, VECTOR_ROOT, path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, bytes, "utf8");
}

function canonical(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(bytes: string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function readRepositoryJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(repositoryRoot, path), "utf8")) as Record<string, unknown>;
}

function publishedVectors(manifest: SnapshotManifest): PublishedVector[] {
  const ownerPattern = SNAPSHOT_OWNERS.join("|");
  const vectorPath = new RegExp(`^docs/spec/vectors/(${ownerPattern})/.+\\.json$`, "u");
  return manifest.artifacts
    .filter(({ path }) => vectorPath.test(path))
    .map(({ path }) => JSON.parse(
      readFileSync(resolve(repositoryRoot, path), "utf8"),
    ) as PublishedVector);
}

function repository(): string {
  const root = mkdtempSync(join(tmpdir(), "heterodyne-snapshot-manifest-test-"));
  temps.push(root);
  for (const path of SUPPORT_PATHS) {
    const value = path === "schema/vector.schema.json"
      ? canonical({ properties: { vector_schema_version: { const: "2.0.0" } } })
      : `${path}\n`;
    write(root, path, value);
  }
  for (const path of VECTOR_PATHS) {
    write(root, path, canonical({
      vector_id: path,
      vector_schema_version: "2.0.0",
      input: {},
      expected_output: {},
    }));
  }
  write(root, "README.md", "not snapshot data\n");
  write(root, "generator/package.json", "{}\n");
  write(root, "snapshot.meta.schema.json", "{}\n");
  write(root, "snapshot.schema.json", "{}\n");
  write(root, "snapshot-unique-by-path.meta.schema.json", "{}\n");
  return root;
}

function writeManifest(root: string, manifest: SnapshotManifest, bytes = canonical(manifest)): void {
  write(root, "snapshot.json", bytes);
}

describe("snapshot manifest", () => {
  it("pins the complete schema-3 reconciliation to the exact stable source catalog", () => {
    const manifest = loadSnapshotManifest(repositoryRoot);
    expect(currentCaseIds()).toHaveLength(RECONCILIATION_VECTOR_COUNT);
    expect(manifest).toMatchObject({
      source_commit: RECONCILIATION_SOURCE_COMMIT,
      vector_schema_version: "3.0.0",
      vector_count: currentCaseIds().length,
    });
  });

  it("publishes sorted unique six-owner IDs with retired cases absent", () => {
    const vectors = publishedVectors(loadSnapshotManifest(repositoryRoot));
    const vectorIds = vectors.map(({ vector_id }) => vector_id);
    const coverage = JSON.parse(readFileSync(
      resolve(repositoryRoot, "docs/spec/vectors/coverage/manifest.json"),
      "utf8",
    )) as Array<{ vector_id: string }>;
    const coverageIds = coverage.map(({ vector_id }) => vector_id);
    expect(coverageIds).toEqual([...coverageIds].sort(compareText));
    expect(new Set(coverageIds).size).toBe(coverageIds.length);
    expect([...vectorIds].sort(compareText)).toEqual([...currentCaseIds()].sort(compareText));
    expect(coverageIds).toEqual([...vectorIds].sort(compareText));
    expect([...new Set(vectors.map(({ owner_document }) => owner_document))].sort())
      .toEqual([...SNAPSHOT_OWNERS]);
    expect(vectorIds.filter((id) => RETIRED_CASE_IDS.includes(
      id as (typeof RETIRED_CASE_IDS)[number],
    ))).toEqual([]);
  });

  it("preserves complete certificate-derived invariant, reason, and profile closure", () => {
    const vectors = publishedVectors(loadSnapshotManifest(repositoryRoot));
    expect(vectors.map(({ vector_id }) => vector_id).sort(compareText))
      .toEqual([...currentCaseIds()].sort(compareText));

    const semanticCoverage = vectors.map((vector) => {
      const contract = currentCaseContract(vector.vector_id);
      expect(vector.owner_document).toBe(contract.owner_document);
      expect(vector.profile).toBe(contract.profile);
      expect(vector.invariants).toEqual(
        [...(contract.terminal_vector_invariants ?? contract.invariants)].sort(),
      );
      expect(vector.reason_codes).toEqual([...contract.reason_codes].sort());
      return {
        vector_id: vector.vector_id,
        owner_document: contract.owner_document,
        ...(contract.profile === undefined ? {} : { profile: contract.profile }),
        spec_refs: vector.spec_refs,
        invariants: contract.invariants,
        reason_codes: contract.semantic_reason_codes ?? contract.reason_codes,
        semantic_boundary: contract.boundary_id,
      };
    });
    const registry = loadRegistry(repositoryRoot);
    expect(findInvariantCoverageIssues(registry, semanticCoverage)).toEqual([]);
    expect(findReasonCoverageIssues(registry, semanticCoverage)).toEqual([]);
    expect(findProfileCoverageIssues(registry, semanticCoverage)).toEqual([]);
  });

  it("gives every rejecting vector exactly one registered reason", () => {
    const vectors = publishedVectors(loadSnapshotManifest(repositoryRoot));
    const registeredReasons = new Set(
      loadRegistry(repositoryRoot).reason_codes.map(({ code }) => code),
    );
    for (const vector of vectors) {
      if (vector.expected_output.verdict !== "reject") continue;
      expect(vector.reason_codes, vector.vector_id).toHaveLength(1);
      expect(vector.expected_output.reason_code, vector.vector_id).toBe(vector.reason_codes[0]);
      expect(registeredReasons.has(vector.reason_codes[0]!), vector.vector_id).toBe(true);
    }
  });

  it("rejects non-canonical snapshot manifests", () => {
    const root = repository();
    const manifest = buildSnapshotManifest(root, SOURCE_COMMIT);
    writeManifest(root, manifest, `${JSON.stringify(manifest)}\n`);
    expect(() => loadSnapshotManifest(root)).toThrow(/canonical/);

    writeManifest(root, { ...manifest, unexpected: true } as SnapshotManifest);
    expect(() => loadSnapshotManifest(root)).toThrow(/unexpected property/);
  });

  it("inventories every consumed snapshot datum", () => {
    const root = repository();
    const manifest = buildSnapshotManifest(root, SOURCE_COMMIT);
    const expectedPaths = [...VECTOR_PATHS, ...SUPPORT_PATHS]
      .map((path) => `${VECTOR_ROOT}/${path}`)
      .sort();

    expect(manifest).toEqual({
      snapshot_schema: "1",
      source_commit: SOURCE_COMMIT,
      vector_schema_version: "2.0.0",
      vector_count: 3,
      artifacts: expectedPaths.map((path) => ({
        path,
        sha256: sha256(readFileSync(join(root, path), "utf8")),
      })),
    });
    expect(manifest.artifacts.map(({ path }) => path)).not.toEqual(expect.arrayContaining([
      `${VECTOR_ROOT}/README.md`,
      `${VECTOR_ROOT}/generator/package.json`,
      `${VECTOR_ROOT}/snapshot.json`,
      `${VECTOR_ROOT}/snapshot.meta.schema.json`,
      `${VECTOR_ROOT}/snapshot.schema.json`,
      `${VECTOR_ROOT}/snapshot-unique-by-path.meta.schema.json`,
    ]));
  });

  it("rejects unsafe and duplicate artifact paths", () => {
    const root = repository();
    const manifest = buildSnapshotManifest(root, SOURCE_COMMIT);
    manifest.artifacts[0] = { ...manifest.artifacts[0]!, path: "../outside.json" };
    writeManifest(root, manifest);
    expect(() => loadSnapshotManifest(root)).toThrow(/unsafe artifact path/);

    const duplicate = buildSnapshotManifest(root, SOURCE_COMMIT);
    duplicate.artifacts[1] = { ...duplicate.artifacts[0]! };
    writeManifest(root, duplicate);
    expect(() => loadSnapshotManifest(root)).toThrow(/duplicate artifact path/);
  });

  it("rejects schema-version disagreement", () => {
    const root = repository();
    const manifest = buildSnapshotManifest(root, SOURCE_COMMIT);
    writeManifest(root, { ...manifest, vector_schema_version: "9.0.0" } as SnapshotManifest);
    expect(() => loadSnapshotManifest(root)).toThrow(/schema version disagreement/);

    write(root, VECTOR_PATHS[0], canonical({
      vector_id: "wrong-version",
      vector_schema_version: "1.0.0",
      input: {},
      expected_output: {},
    }));
    expect(() => buildSnapshotManifest(root, SOURCE_COMMIT)).toThrow(/schema version disagreement/);
  });

  it("detects exact-byte drift", () => {
    const root = repository();
    const manifest = buildSnapshotManifest(root, SOURCE_COMMIT);
    writeManifest(root, manifest);
    expect(loadSnapshotManifest(root)).toEqual(manifest);

    write(root, "fixtures.json", "fixtures.json\n\n");
    expect(() => loadSnapshotManifest(root)).toThrow(
      `artifact digest mismatch: ${VECTOR_ROOT}/fixtures.json`,
    );
  });

  it("keeps schema and runtime path and uniqueness rules aligned", () => {
    for (const unsafePath of [
      "docs/spec/vectors/core/../outside.json",
      "docs/spec/vectors/",
      "docs/spec/vectors/core//vector.json",
      "docs/spec/vectors/core/./vector.json",
    ]) {
      const root = repository();
      const manifest = buildSnapshotManifest(root, SOURCE_COMMIT);
      manifest.artifacts[0] = { ...manifest.artifacts[0]!, path: unsafePath };
      expect(validateSnapshotManifestSchema(manifest), unsafePath).toBe(false);
      writeManifest(root, manifest);
      expect(() => loadSnapshotManifest(root), unsafePath).toThrow(/unsafe artifact path/);
    }

    const root = repository();
    const duplicate = buildSnapshotManifest(root, SOURCE_COMMIT);
    duplicate.artifacts[1] = {
      path: duplicate.artifacts[0]!.path,
      sha256: "0".repeat(64),
    };
    expect(duplicate.artifacts[1]!.sha256).not.toBe(duplicate.artifacts[0]!.sha256);
    expect(validateSnapshotManifestSchema(duplicate)).toBe(false);
    writeManifest(root, duplicate);
    expect(() => loadSnapshotManifest(root)).toThrow(/duplicate artifact path/);
  });

  it("rejects support artifacts reached through escaping and in-root symlinks", () => {
    const escapingRoot = repository();
    const outside = mkdtempSync(join(tmpdir(), "heterodyne-snapshot-outside-test-"));
    temps.push(outside);
    const outsideFile = join(outside, "fixtures.json");
    writeFileSync(outsideFile, "outside bytes\n", "utf8");
    rmSync(join(escapingRoot, VECTOR_ROOT, "fixtures.json"));
    symlinkSync(outsideFile, join(escapingRoot, VECTOR_ROOT, "fixtures.json"));
    expect(() => buildSnapshotManifest(escapingRoot, SOURCE_COMMIT)).toThrow(/symbolic link/);

    const inRoot = repository();
    const inRootFile = join(inRoot, "fixtures-target.json");
    writeFileSync(inRootFile, "in-root bytes\n", "utf8");
    rmSync(join(inRoot, VECTOR_ROOT, "fixtures.json"));
    symlinkSync(inRootFile, join(inRoot, VECTOR_ROOT, "fixtures.json"));
    expect(() => buildSnapshotManifest(inRoot, SOURCE_COMMIT)).toThrow(/symbolic link/);

    const directoryRoot = repository();
    const coverageTarget = join(directoryRoot, "coverage-target");
    mkdirSync(coverageTarget);
    rmSync(join(directoryRoot, VECTOR_ROOT, "coverage"), { recursive: true });
    symlinkSync(coverageTarget, join(directoryRoot, VECTOR_ROOT, "coverage"), "dir");
    expect(() => buildSnapshotManifest(directoryRoot, SOURCE_COMMIT)).toThrow(/symbolic link/);

    const rootTarget = repository();
    const aliasParent = mkdtempSync(join(tmpdir(), "heterodyne-snapshot-root-alias-test-"));
    temps.push(aliasParent);
    const rootAlias = join(aliasParent, "repository");
    symlinkSync(rootTarget, rootAlias, "dir");
    expect(() => buildSnapshotManifest(rootAlias, SOURCE_COMMIT)).toThrow(/symbolic link/);
  });

  it("publishes valid and closed snapshot dialect and unique-by-path vocabulary meta-schemas", () => {
    const vocabularyMeta = readRepositoryJson(
      "docs/spec/vectors/snapshot-unique-by-path.meta.schema.json",
    );
    const dialectMeta = readRepositoryJson("docs/spec/vectors/snapshot.meta.schema.json");
    const stock = new Ajv2020({ allErrors: true, strict: true });

    expect(stock.validateSchema(vocabularyMeta)).toBe(true);
    expect(stock.validateSchema(dialectMeta)).toBe(true);
    expect((dialectMeta.$vocabulary as Record<string, unknown>)[UNIQUE_BY_PATH_VOCABULARY_ID])
      .toBe(true);
    stock.addMetaSchema(vocabularyMeta);
    const validateVocabularySchema = stock.getSchema(String(vocabularyMeta.$id));
    if (validateVocabularySchema === undefined) throw new Error("vocabulary meta-schema not registered");
    expect(validateVocabularySchema({ "x-unique-by": "path" })).toBe(true);
    expect(validateVocabularySchema({ "x-unique-by": "sha256" })).toBe(false);
    expect(validateVocabularySchema({ "x-undeclared": true })).toBe(false);
  });

  it("requires Core in every published vocabulary declaration", () => {
    const metaSchemas = [
      readRepositoryJson("docs/spec/vectors/snapshot-unique-by-path.meta.schema.json"),
      readRepositoryJson("docs/spec/vectors/snapshot.meta.schema.json"),
    ];

    for (const metaSchema of metaSchemas) {
      if (metaSchema.$vocabulary === undefined) continue;
      expect(metaSchema.$vocabulary).toEqual(expect.objectContaining({
        [DRAFT_2020_12_CORE_VOCABULARY_ID]: true,
      }));
    }
  });

  it("fails closed when a validator lacks the required unique-by-path vocabulary", () => {
    expect(snapshotManifestSchema.$schema).toBe(SNAPSHOT_META_SCHEMA_ID);
    const unsupported = new Ajv2020({ allErrors: true, strict: true });
    expect(() => unsupported.compile(snapshotManifestSchema)).toThrow(SNAPSHOT_META_SCHEMA_ID);

    const vocabularyMeta = readRepositoryJson(
      "docs/spec/vectors/snapshot-unique-by-path.meta.schema.json",
    );
    const dialectMeta = readRepositoryJson("docs/spec/vectors/snapshot.meta.schema.json");
    unsupported.addMetaSchema(vocabularyMeta);
    unsupported.addMetaSchema(dialectMeta);
    expect(() => unsupported.compile(snapshotManifestSchema)).toThrow(/unknown keyword.*x-unique-by/);
  });

  it("compiles the supported strict snapshot schema validation path", () => {
    const root = repository();
    expect(validateSnapshotManifestSchema(buildSnapshotManifest(root, SOURCE_COMMIT))).toBe(true);
  });
});
