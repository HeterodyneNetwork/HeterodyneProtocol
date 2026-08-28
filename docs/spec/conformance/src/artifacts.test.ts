import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadCorpus } from "./artifacts.js";
import {
  createTestCorpus,
  fixturesPath,
  protocolSchemaPath,
  readJson,
  readTestManifest,
  reasonCodesPath,
  refreshSnapshotManifest,
  registryManifestPath,
  snapshotManifestPath,
  sourceCommit,
  type TestCorpus,
  vectorPath,
  vectorSchemaPath,
  writeJson,
  writeText,
} from "./test-support.js";

const temps: string[] = [];

afterEach(() => {
  for (const path of temps.splice(0)) rmSync(path, { recursive: true, force: true });
});

function corpus(options: { withVector?: boolean; withAssurance?: boolean } = {}): TestCorpus {
  const value = createTestCorpus(options);
  temps.push(value.root);
  return value;
}

function upgradeSnapshotToSchema3(input: TestCorpus): void {
  const schema = readJson(input.snapshotRoot, vectorSchemaPath);
  const properties = schema.properties as Record<string, unknown>;
  const required = schema.required as string[];
  properties.vector_schema_version = { const: "3.0.0" };
  properties.invariants = {
    type: "array",
    minItems: 1,
    uniqueItems: true,
    items: { type: "string" },
  };
  properties.reason_codes = {
    type: "array",
    uniqueItems: true,
    items: { type: "string" },
  };
  required.push("invariants", "reason_codes");
  writeJson(input.snapshotRoot, vectorSchemaPath, schema);
  const vector = readJson(input.snapshotRoot, vectorPath);
  vector.vector_schema_version = "3.0.0";
  vector.invariants = ["CORE-I-VERIFY-BEFORE-USE"];
  vector.reason_codes = [];
  writeJson(input.snapshotRoot, vectorPath, vector);
  writeText(input.snapshotRoot, "docs/spec/vectors/coverage/assurance.md", "# assurance\n");
  refreshSnapshotManifest(input.snapshotRoot);
}

describe("loadCorpus split roots", () => {
  it("copies the exact complete historical schema-2 contract", () => {
    const input = corpus();
    const schemaBytes = readFileSync(resolve(input.snapshotRoot, vectorSchemaPath));
    const schema = readJson(input.snapshotRoot, vectorSchemaPath);
    const schemaVersion = (schema.properties as Record<string, Record<string, unknown>>)
      .vector_schema_version?.const;

    expect(createHash("sha256").update(schemaBytes).digest("hex"))
      .toBe("4331e2c8ae53d89bfdec913bd43c85d9f0ebeadcc3ad42950e08050a6284a1d6");
    expect(schema.allOf).toBeDefined();
    expect(schemaVersion).toBe("2.0.0");
    expect(readTestManifest(input.snapshotRoot)).toMatchObject({
      vector_schema_version: "2.0.0",
      vector_count: 1,
    });
    expect(readJson(input.snapshotRoot, vectorPath)).toMatchObject({
      vector_id: "core.valid",
      vector_schema_version: "2.0.0",
    });
    expect(existsSync(resolve(
      input.snapshotRoot,
      "docs/spec/vectors/coverage/assurance.md",
    ))).toBe(false);
  });

  it("constructs schema-3 fixtures with the complete six-owner coverage projection", () => {
    const input = corpus({ withAssurance: true });
    const assuranceCoveragePath = "docs/spec/vectors/coverage/assurance.md";
    upgradeSnapshotToSchema3(input);

    expect(existsSync(resolve(input.snapshotRoot, assuranceCoveragePath))).toBe(true);
    expect((readTestManifest(input.snapshotRoot).artifacts as Array<{ path: string }>)
      .map(({ path }) => path)).toContain(assuranceCoveragePath);
  });

  it("loads the live six-document source family", () => {
    const input = corpus({ withAssurance: true });

    const loaded = loadCorpus(input);

    expect(loaded.issues).toEqual([]);
    expect([...loaded.corpus!.specifications.keys()]).toEqual([
      "docs/spec/heterodyne-core.md",
      "docs/spec/heterodyne-assurance.md",
      "docs/spec/heterodyne-comms.md",
      "docs/spec/heterodyne-control.md",
      "docs/spec/heterodyne-social.md",
      "docs/spec/heterodyne-workspace.md",
    ]);
  });

  it("reads source-owned and snapshot-owned artifacts from their authoritative roots", () => {
    const input = corpus();
    writeText(input.snapshotRoot, "docs/spec/heterodyne-core.md", "current-head-conflict\n");
    writeJson(input.snapshotRoot, reasonCodesPath, { reason_codes: [{ code: "wrong-root" }] });
    writeJson(input.snapshotRoot, protocolSchemaPath, { title: "wrong-root" });
    writeJson(input.sourceRoot, vectorSchemaPath, { title: "wrong-root" });
    writeJson(input.sourceRoot, fixturesPath, { wrong_root: true });

    const loaded = loadCorpus(input);

    expect(loaded.issues).toEqual([]);
    expect(loaded.corpus?.sourceRoot).toBe(realpathSync(input.sourceRoot));
    expect(loaded.corpus?.snapshotRoot).toBe(realpathSync(input.snapshotRoot));
    expect(loaded.corpus?.sourceCommit).toBe(input.sourceCommit);
    expect(loaded.corpus?.snapshotCommit).toBe(input.snapshotCommit);
    expect(loaded.corpus?.specifications.get("docs/spec/heterodyne-core.md"))
      .toContain("core-conformance");
    expect(loaded.corpus?.registry.reason_codes.map(({ code }) => code)).toEqual(["bad_signature"]);
    expect(loaded.corpus?.schemas.get(protocolSchemaPath)).toEqual({
      type: "object",
      title: "pinned-source-schema",
    });
    expect(loaded.corpus?.vectorSchema).toEqual(readJson(input.snapshotRoot, vectorSchemaPath));
    expect(loaded.corpus?.fixtures).toEqual(readJson(input.snapshotRoot, fixturesPath));
  });

  it("loads a schema-2 snapshot without family release authority", () => {
    const input = corpus();
    const loaded = loadCorpus(input);

    expect(loaded.issues).toEqual([]);
    expect(loaded.corpus).not.toHaveProperty("familyVersion");
    expect(loaded.corpus).not.toHaveProperty("registryRevision");
    expect(loaded.corpus).not.toHaveProperty("registryDigest");
    expect(loaded.corpus?.vectorSchemaVersion).toBe("2.0.0");
    expect(loaded.corpus?.vectors.map(({ value }) => value.vector_id)).toEqual(["core.valid"]);
    expect(loaded.corpus?.vectors[0]?.value).not.toHaveProperty("invariants");
    expect(loaded.corpus?.vectors[0]?.value).not.toHaveProperty("reason_codes");
  });

  it("rejects a historical consume rejection without its required reason code", () => {
    const input = corpus();
    const vector = readJson(input.snapshotRoot, vectorPath);
    vector.expected_output = { verdict: "reject" };
    writeJson(input.snapshotRoot, vectorPath, vector);
    refreshSnapshotManifest(input.snapshotRoot);

    expect(loadCorpus(input).issues).toContainEqual({
      code: "invalid-document-shape",
      path: vectorPath,
      message: "vector does not match vector.schema.json",
    });
  });

  it("loads schema-3 traceability without backfilling historical vectors", () => {
    const input = corpus({ withAssurance: true });
    upgradeSnapshotToSchema3(input);

    const loaded = loadCorpus(input);

    expect(loaded.issues).toEqual([]);
    expect(loaded.corpus?.vectorSchemaVersion).toBe("3.0.0");
    expect(loaded.corpus?.vectors[0]?.value).toMatchObject({
      vector_schema_version: "3.0.0",
      invariants: ["CORE-I-VERIFY-BEFORE-USE"],
      reason_codes: [],
    });
  });

  it("rejects schema-3 vectors without sorted exact traceability even under a permissive schema", () => {
    const input = corpus({ withAssurance: true });
    upgradeSnapshotToSchema3(input);
    const schema = readJson(input.snapshotRoot, vectorSchemaPath);
    schema.required = (schema.required as string[]).filter((member) =>
      member !== "invariants" && member !== "reason_codes"
    );
    writeJson(input.snapshotRoot, vectorSchemaPath, schema);
    const vector = readJson(input.snapshotRoot, vectorPath);
    delete vector.invariants;
    delete vector.reason_codes;
    writeJson(input.snapshotRoot, vectorPath, vector);
    refreshSnapshotManifest(input.snapshotRoot);

    expect(loadCorpus(input).issues).toContainEqual({
      code: "invalid-document-shape",
      path: vectorPath,
      message: "vector does not match the 3.0.0 snapshot corpus shape",
    });
  });

  it("rejects a legacy version reference even when a permissive snapshot schema allows it", () => {
    const input = corpus();
    const schema = readJson(input.snapshotRoot, vectorSchemaPath);
    const properties = schema.properties as Record<string, Record<string, unknown>>;
    properties.spec_refs = { type: "array", minItems: 1, items: { type: "string" } };
    writeJson(input.snapshotRoot, vectorSchemaPath, schema);
    const vector = readJson(input.snapshotRoot, vectorPath);
    vector.spec_refs = ["heterodyne:0.6.0#core-conformance"];
    writeJson(input.snapshotRoot, vectorPath, vector);
    refreshSnapshotManifest(input.snapshotRoot);

    expect(loadCorpus(input).issues).toContainEqual({
      code: "invalid-document-shape",
      path: vectorPath,
      message: "vector does not match the 2.0.0 snapshot corpus shape",
    });
  });

  it("rejects an unknown seventh owner even when the packaged schema allows it", () => {
    const input = corpus();
    const schema = readJson(input.snapshotRoot, vectorSchemaPath);
    const properties = schema.properties as Record<string, Record<string, unknown>>;
    properties.owner_document = { type: "string" };
    writeJson(input.snapshotRoot, vectorSchemaPath, schema);
    const vector = readJson(input.snapshotRoot, vectorPath);
    vector.owner_document = "unknown";
    writeJson(input.snapshotRoot, vectorPath, vector);
    refreshSnapshotManifest(input.snapshotRoot);

    expect(loadCorpus(input).issues).toContainEqual({
      code: "invalid-document-shape",
      path: vectorPath,
      message: "vector does not match the 2.0.0 snapshot corpus shape",
    });
  });

  it("accumulates snapshot digest, malformed vector, and source registry diagnostics", () => {
    const input = corpus();
    const manifest = readTestManifest(input.snapshotRoot);
    const artifact = (manifest.artifacts as Array<Record<string, unknown>>)
      .find(({ path }) => path === fixturesPath)!;
    artifact.sha256 = "0".repeat(64);
    writeJson(input.snapshotRoot, snapshotManifestPath, manifest);
    writeText(input.snapshotRoot, vectorPath, "{ malformed\n");
    writeJson(input.sourceRoot, registryManifestPath, { malformed: true });

    expect(loadCorpus(input).issues.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: "artifact-digest-mismatch", path: vectorPath },
      { code: "artifact-digest-mismatch", path: fixturesPath },
      { code: "invalid-document-shape", path: registryManifestPath },
      { code: "invalid-json", path: vectorPath },
    ]);
  });

  it("rejects snapshot source identity disagreement", () => {
    const input = corpus();
    input.sourceCommit = "3".repeat(40);

    expect(loadCorpus(input).issues).toContainEqual({
      code: "source-commit-mismatch",
      path: snapshotManifestPath,
      message: `snapshot manifest pins ${sourceCommit} instead of ${input.sourceCommit}`,
    });
  });

  it("rejects a missing, extra, duplicated, and unsorted snapshot inventory", () => {
    const input = corpus();
    const manifest = readTestManifest(input.snapshotRoot);
    const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
    artifacts.pop();
    artifacts.push({ path: "docs/spec/vectors/extra.json", sha256: "a".repeat(64) });
    artifacts.push({ ...artifacts[0] });
    writeJson(input.snapshotRoot, snapshotManifestPath, manifest);

    const codes = loadCorpus(input).issues.map(({ code }) => code);
    expect(codes).toEqual(expect.arrayContaining([
      "duplicate-artifact-path",
      "invalid-document-shape",
      "missing-snapshot-artifact",
      "unexpected-snapshot-artifact",
    ]));
  });

  it("rejects exact-byte drift in a current snapshot artifact", () => {
    const input = corpus();
    writeText(input.snapshotRoot, fixturesPath, `${readFileSync(
      resolve(input.snapshotRoot, fixturesPath),
      "utf8",
    )}\n`);

    expect(loadCorpus(input).issues).toContainEqual({
      code: "artifact-digest-mismatch",
      path: fixturesPath,
      message: "snapshot artifact sha256 does not match exact file bytes",
    });
  });

  it("binds evaluation to the snapshot inventory and bytes captured for authentication", () => {
    const input = corpus();
    const changedVector = readJson(input.snapshotRoot, vectorPath);
    changedVector.vector_id = "core.changed-after-capture";
    const addedVectorPath = "docs/spec/vectors/core/002-added-after-capture.json";
    const addedVector = { ...changedVector, vector_id: "core.added-after-capture" };
    const absoluteSchemaPath = realpathSync(resolve(input.snapshotRoot, vectorSchemaPath));
    let schemaReads = 0;
    let captures = 0;
    const loaded = loadCorpus(input, {
      readFile(path: string): Buffer {
        if (path === absoluteSchemaPath) schemaReads += 1;
        return readFileSync(path);
      },
      afterCapture(): void {
        captures += 1;
        if (captures === 1) {
          writeJson(input.snapshotRoot, vectorPath, changedVector);
          rmSync(resolve(input.snapshotRoot, fixturesPath));
          writeJson(input.snapshotRoot, addedVectorPath, addedVector);
        }
      },
    });

    expect(captures).toBe(1);
    expect(schemaReads).toBe(1);
    expect(loaded.issues).toEqual([]);
    expect(loaded.corpus?.vectors.map(({ value }) => value.vector_id)).toEqual(["core.valid"]);
    expect(readJson(input.snapshotRoot, vectorPath).vector_id).toBe("core.changed-after-capture");
    expect(readJson(input.snapshotRoot, addedVectorPath).vector_id).toBe("core.added-after-capture");
    expect(existsSync(resolve(input.snapshotRoot, fixturesPath))).toBe(false);
  });

  it("reports vectors present in the captured inventory but absent from the manifest", () => {
    const input = corpus();
    const addedVectorPath = "docs/spec/vectors/core/002-present-at-capture.json";
    const addedVector = readJson(input.snapshotRoot, vectorPath);
    addedVector.vector_id = "core.present-at-capture";
    writeJson(input.snapshotRoot, addedVectorPath, addedVector);

    expect(loadCorpus(input).issues).toContainEqual({
      code: "missing-snapshot-artifact",
      path: addedVectorPath,
      message: "snapshot datum is absent from the closed manifest",
    });
  });

  it("applies the packaged vector schema from the snapshot root", () => {
    const input = corpus();
    const vector = readJson(input.snapshotRoot, vectorPath);
    vector.unregistered = true;
    writeJson(input.snapshotRoot, vectorPath, vector);
    refreshSnapshotManifest(input.snapshotRoot);

    expect(loadCorpus(input).issues).toContainEqual({
      code: "invalid-document-shape",
      path: vectorPath,
      message: "vector does not match vector.schema.json",
    });
  });

  it("reports duplicate vector and registry identifiers", () => {
    const input = corpus();
    const duplicateVectorPath = "docs/spec/vectors/core/002-duplicate.json";
    writeText(
      input.snapshotRoot,
      duplicateVectorPath,
      readFileSync(resolve(input.snapshotRoot, vectorPath), "utf8"),
    );
    refreshSnapshotManifest(input.snapshotRoot);
    const reasons = readJson(input.sourceRoot, reasonCodesPath);
    const entry = (reasons.reason_codes as unknown[])[0]!;
    writeJson(input.sourceRoot, reasonCodesPath, { reason_codes: [entry, entry] });

    expect(loadCorpus(input).issues.map(({ code }) => code)).toEqual([
      "duplicate-registry-entry",
      "duplicate-vector-id",
      "registry-entry-set-digest-mismatch",
    ]);
  });

  it("rejects special entries in source and snapshot-owned inventories", () => {
    const input = corpus();
    symlinkSync("manifest.json", resolve(input.sourceRoot, "docs/spec/registry/manifest-link.json"));
    symlinkSync(
      "001-valid.json",
      resolve(input.snapshotRoot, "docs/spec/vectors/core/002-link.json"),
    );
    const specificationPath = "docs/spec/heterodyne-core.md";
    rmSync(resolve(input.sourceRoot, specificationPath));
    symlinkSync("heterodyne-comms.md", resolve(input.sourceRoot, specificationPath));
    const supportPath = "docs/spec/vectors/coverage/core.md";
    rmSync(resolve(input.snapshotRoot, supportPath));
    symlinkSync("family.md", resolve(input.snapshotRoot, supportPath));

    expect(loadCorpus(input).issues).toEqual(expect.arrayContaining([
      {
        code: "unsafe-artifact-path",
        path: "docs/spec/registry/manifest-link.json",
        message: "normative inventory entry is a symbolic link",
      },
      {
        code: "unsafe-artifact-path",
        path: "docs/spec/vectors/core/002-link.json",
        message: "normative inventory entry is a symbolic link",
      },
      {
        code: "unsafe-artifact-path",
        path: specificationPath,
        message: expect.stringContaining("symbolic link"),
      },
      {
        code: "unsafe-artifact-path",
        path: supportPath,
        message: expect.stringContaining("symbolic link"),
      },
    ]));
  });

  it("loads the historical five-document source family with a zero-vector snapshot", () => {
    const input = corpus({ withVector: false });
    const loaded = loadCorpus(input);

    expect(loaded.issues).toEqual([]);
    expect(loaded.corpus?.vectors).toEqual([]);
    expect(loaded.corpus?.specifications).toHaveLength(5);
    expect(loaded.corpus?.schemas).toHaveLength(1);
  });
});
