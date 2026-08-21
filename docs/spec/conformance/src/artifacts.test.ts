import { readFileSync, realpathSync, rmSync, symlinkSync } from "node:fs";
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

function corpus(options: { withVector?: boolean } = {}): TestCorpus {
  const value = createTestCorpus(options);
  temps.push(value.root);
  return value;
}

describe("loadCorpus split roots", () => {
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
  });

  it("rejects a legacy version reference even when a permissive snapshot schema allows it", () => {
    const input = corpus();
    const schema = readJson(input.snapshotRoot, vectorSchemaPath);
    const properties = schema.properties as Record<string, Record<string, unknown>>;
    properties.spec_refs = { type: "array", minItems: 1, items: { type: "string" } };
    writeJson(input.snapshotRoot, vectorSchemaPath, schema);
    const vector = readJson(input.snapshotRoot, vectorPath);
    vector.spec_refs = ["heterodyne:0.5.0#core-conformance"];
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

  it("accepts a zero-vector snapshot while retaining the full static corpus", () => {
    const input = corpus({ withVector: false });
    const loaded = loadCorpus(input);

    expect(loaded.issues).toEqual([]);
    expect(loaded.corpus?.vectors).toEqual([]);
    expect(loaded.corpus?.specifications).toHaveLength(5);
    expect(loaded.corpus?.schemas).toHaveLength(1);
  });
});
