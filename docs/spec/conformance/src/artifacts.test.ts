import { rmSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { loadCorpus } from "./artifacts.js";
import {
  createTestRepository,
  familyManifestPath,
  readTestManifest,
  reasonCodesPath,
  vectorPath,
  writeJson,
  writeText,
} from "./test-support.js";

const temps: string[] = [];

afterEach(() => {
  for (const path of temps.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function repository(): string {
  const root = createTestRepository();
  temps.push(root);
  return root;
}

describe("loadCorpus", () => {
  it("loads a valid synthetic corpus from its family manifest", () => {
    const result = loadCorpus(repository());

    expect(result.issues).toEqual([]);
    expect(result.corpus).toMatchObject({
      familyVersion: "heterodyne/0.5.0",
      registryRevision: 13,
      registryDigest: "aa".repeat(32),
    });
    expect(result.corpus?.specifications).toHaveLength(5);
    expect(result.corpus?.schemas).toHaveLength(1);
    expect(result.corpus?.vectors.map(({ value }) => value.vector_id)).toEqual(["core.valid"]);
  });

  it("accumulates an unsafe manifest path and malformed vector deterministically", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    (manifest.artifacts as unknown[]).push({
      path: "../escape.json",
      role: "schema",
      sha256: "aa".repeat(32),
    });
    writeJson(root, familyManifestPath, manifest);
    writeText(root, vectorPath, "{ malformed\n");

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual([
      "invalid-json",
      "unsafe-artifact-path",
    ]);
  });

  it("keeps parsing artifacts after a top-level manifest shape issue", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    manifest.family_version = "heterodyne/9.9.9";
    writeJson(root, familyManifestPath, manifest);
    writeText(root, vectorPath, "{ malformed\n");

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual([
      "invalid-document-shape",
      "invalid-json",
    ]);
  });

  it("rejects malformed release metadata while continuing artifact parsing", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    manifest.schema_version = "9.9.9";
    manifest.status = "published";
    const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
    const vector = artifacts.find((artifact) => artifact.path === vectorPath);
    if (vector === undefined) {
      throw new Error("test vector is absent from synthetic manifest");
    }
    vector.role = "executable";
    vector.sha256 = "invalid";
    writeJson(root, familyManifestPath, manifest);
    writeText(root, vectorPath, "{ malformed\n");

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual([
      "invalid-document-shape",
      "invalid-document-shape",
      "invalid-document-shape",
      "invalid-document-shape",
      "invalid-json",
    ]);
  });

  it("validates the standalone registry manifest path for escape", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    manifest.registry = { path: "../registry.json", sha256: "aa".repeat(32) };
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual([
      "missing-required-root",
      "unsafe-artifact-path",
    ]);
  });

  it("reports duplicate vector IDs instead of silently overwriting them", () => {
    const root = repository();
    const duplicatePath = "docs/spec/vectors/core/002-duplicate.json";
    const manifest = readTestManifest(root);
    writeJson(root, duplicatePath, {
      vector_id: "core.valid",
      vector_schema_version: "1.1.0",
      owner_document: "core",
      spec_version: "heterodyne/0.5.0",
      spec_refs: ["heterodyne:0.5.0#core-conformance"],
      direction: "consume",
      input: {},
      expected_output: { verdict: "accept" },
    });
    (manifest.artifacts as unknown[]).push({
      path: duplicatePath,
      role: "vector",
      sha256: "aa".repeat(32),
    });
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual(["duplicate-vector-id"]);
  });

  it("reports duplicate registry entries", () => {
    const root = repository();
    writeJson(root, reasonCodesPath, {
      reason_codes: [{ code: "bad_signature" }, { code: "bad_signature" }],
    });

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual([
      "duplicate-registry-entry",
    ]);
  });

  it("reports a missing family manifest as a required root issue", () => {
    const root = repository();
    rmSync(`${root}/${familyManifestPath}`);

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual([
      "missing-required-root",
    ]);
    expect(loadCorpus(root).corpus).toBeUndefined();
  });
});
