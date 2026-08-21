import { readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadCorpus } from "./artifacts.js";
import {
  createTestRepository,
  familyManifestPath,
  fixturesPath,
  refreshReleaseDigests,
  refreshRegistryEntrySetDigest,
  readTestManifest,
  registryEntrySetDigest,
  registryManifestPath,
  registrySchemaPath,
  reasonCodesPath,
  sha256File,
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

function readJson(root: string, path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(root, path), "utf8")) as Record<string, unknown>;
}

function writeVector(root: string, value: Record<string, unknown>): void {
  writeJson(root, vectorPath, value);
  refreshReleaseDigests(root);
}

function declaredVector(): Record<string, unknown> {
  return {
    vector_id: "core.declared",
    vector_schema_version: "1.1.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: ["heterodyne:0.5.0#core-conformance"],
    description: "synthetic independently loaded declaration",
    direction: "consume",
    input: { event: {}, context: {} },
    expected_output: { verdict: "accept" },
    conformance_checks: [{
      profile: "core-signed-event-v1",
      event_pointer: "/input/event",
      nip01_raw_pointer: "/input/nip01_raw",
      context_pointer: "/input/context",
      expected_terminal_stage: "accept",
    }],
  };
}

describe("loadCorpus", () => {
  it("loads a valid synthetic corpus from its family manifest", () => {
    const result = loadCorpus(repository());

    expect(result.issues).toEqual([]);
    expect(result.corpus).toMatchObject({
      familyVersion: "heterodyne/0.5.0",
      registryRevision: 13,
      registryDigest: registryEntrySetDigest,
    });
    expect(result.corpus?.specifications).toHaveLength(5);
    expect(result.corpus?.schemas).toHaveLength(2);
    expect(result.corpus?.vectors.map(({ value }) => value.vector_id)).toEqual(["core.valid"]);
  });

  it("hashes exact artifact bytes and rejects a changed file", () => {
    const root = repository();
    const corePath = "docs/spec/heterodyne-core.md";
    writeText(root, corePath, "# core changed by one byte\n");

    expect(loadCorpus(root).issues).toContainEqual({
      code: "artifact-digest-mismatch",
      path: corePath,
      message: "release artifact sha256 does not match exact file bytes",
    });
  });

  it("rejects a stale syntactically valid artifact digest in the release manifest", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
    const vector = artifacts.find((artifact) => artifact.path === vectorPath)!;
    vector.sha256 = "00".repeat(32);
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues).toContainEqual({
      code: "artifact-digest-mismatch",
      path: vectorPath,
      message: "release artifact sha256 does not match exact file bytes",
    });
  });

  it("rejects a stale registry-file hash even when its artifact entry is current", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    (manifest.registry as Record<string, unknown>).sha256 = "00".repeat(32);
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues).toContainEqual({
      code: "registry-digest-mismatch",
      path: registryManifestPath,
      message: "registry pin sha256 does not match exact registry manifest bytes",
    });
  });

  it("recomputes the complete registry entry-set digest independently", () => {
    const root = repository();
    const reasons = readJson(root, reasonCodesPath);
    (reasons.reason_codes as unknown[]).push({
      code: "second_reason",
      owner: "core",
      status: "draft",
      first_version: "heterodyne/0.5.0",
      description: "A second valid synthetic reason.",
      spec_refs: ["heterodyne:0.5.0#core-conformance"],
    });
    writeJson(root, reasonCodesPath, reasons);
    refreshReleaseDigests(root);

    expect(loadCorpus(root).issues).toContainEqual({
      code: "registry-entry-set-digest-mismatch",
      path: registryManifestPath,
      message: "registry entry_set_sha256 does not match the complete current entry set",
    });
  });

  it("rejects a non-object registry schema instead of returning a clean corpus", () => {
    const root = repository();
    writeJson(root, registrySchemaPath, []);
    refreshReleaseDigests(root);

    expect(loadCorpus(root)).toEqual({
      issues: [{
        code: "invalid-document-shape",
        path: registrySchemaPath,
        message: "registry schema must be a JSON object",
      }],
    });
  });

  it("accumulates a non-object registry schema with incomplete entry documents", () => {
    const root = repository();
    writeJson(root, reasonCodesPath, {});
    writeJson(root, registrySchemaPath, null);
    refreshReleaseDigests(root);

    expect(loadCorpus(root).issues).toEqual([
      {
        code: "invalid-document-shape",
        path: registryManifestPath,
        message: "complete registry entry documents are required",
      },
      {
        code: "invalid-document-shape",
        path: registrySchemaPath,
        message: "registry schema must be a JSON object",
      },
    ]);
  });

  it("enforces closed release, registry-pin, and artifact member shapes", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    manifest.unexpected = true;
    (manifest.registry as Record<string, unknown>).unexpected = true;
    ((manifest.artifacts as Array<Record<string, unknown>>)[0]!).unexpected = true;
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues.filter(({ code }) => code === "invalid-document-shape"))
      .toHaveLength(3);
  });

  it("enforces the release schema's exact repository-path syntax", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    const artifact = (manifest.artifacts as Array<Record<string, unknown>>)[0]!;
    const invalidPath = "docs/spec/bad name.json";
    artifact.path = invalidPath;
    writeText(root, invalidPath, "{}\n");
    artifact.sha256 = sha256File(root, invalidPath);
    (manifest.artifacts as Array<Record<string, unknown>>)
      .sort((left, right) => String(left.path).localeCompare(String(right.path)));
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues).toContainEqual(expect.objectContaining({
      code: "invalid-document-shape",
      path: invalidPath,
    }));
  });

  it("rejects an incomplete release artifact set instead of trusting omissions", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    manifest.artifacts = (manifest.artifacts as Array<Record<string, unknown>>)
      .filter((artifact) => artifact.path !== vectorPath);
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues).toContainEqual({
      code: "missing-release-artifact",
      path: vectorPath,
      message: "normative file is absent from the family release manifest",
    });
  });

  it("rejects extra declaration members and duplicate declarations", () => {
    const root = repository();
    const vector = declaredVector();
    const check = (vector.conformance_checks as Array<Record<string, unknown>>)[0]!;
    check.inferred = true;
    writeVector(root, vector);
    expect(loadCorpus(root).issues).toContainEqual(expect.objectContaining({
      code: "invalid-document-shape",
      path: vectorPath,
    }));

    delete check.inferred;
    vector.conformance_checks = [check, { ...check }];
    writeVector(root, vector);
    expect(loadCorpus(root).issues).toContainEqual(expect.objectContaining({
      code: "invalid-document-shape",
      path: vectorPath,
    }));
  });

  it("requires context_pointer for persona resolution and later stages", () => {
    const root = repository();
    const vector = declaredVector();
    const check = (vector.conformance_checks as Array<Record<string, unknown>>)[0]!;
    check.expected_terminal_stage = "persona_resolution";
    delete check.context_pointer;
    writeVector(root, vector);

    expect(loadCorpus(root).issues).toContainEqual(expect.objectContaining({
      code: "invalid-document-shape",
      path: vectorPath,
    }));
  });

  it("requires declared event and context targets to exist", () => {
    const root = repository();
    const vector = declaredVector();
    const check = (vector.conformance_checks as Array<Record<string, unknown>>)[0]!;
    check.event_pointer = "/input/missing_event";
    writeVector(root, vector);
    expect(loadCorpus(root).issues).toContainEqual(expect.objectContaining({
      code: "invalid-document-shape",
      path: vectorPath,
    }));

    check.event_pointer = "/input/event";
    check.context_pointer = "/input/missing_context";
    writeVector(root, vector);
    expect(loadCorpus(root).issues).toContainEqual(expect.objectContaining({
      code: "invalid-document-shape",
      path: vectorPath,
    }));
  });

  it("leaves an absent raw target for G10 discovery debt", () => {
    const root = repository();
    writeVector(root, declaredVector());

    expect(loadCorpus(root).issues).toEqual([]);
  });

  it("accumulates an unsafe manifest path and malformed vector deterministically", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    (manifest.artifacts as unknown[]).push({
      path: "../escape.json",
      role: "schema",
      sha256: "aa".repeat(32),
    });
    writeText(root, vectorPath, "{ malformed\n");
    const vector = (manifest.artifacts as Array<Record<string, unknown>>)
      .find((artifact) => artifact.path === vectorPath)!;
    vector.sha256 = sha256File(root, vectorPath);
    (manifest.artifacts as Array<Record<string, unknown>>)
      .sort((left, right) => String(left.path).localeCompare(String(right.path)));
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual([
      "invalid-document-shape",
      "invalid-json",
      "unsafe-artifact-path",
    ]);
  });

  it("reports malformed fixtures when the family manifest is also malformed", () => {
    const root = repository();
    writeText(root, familyManifestPath, "{ malformed manifest\n");
    writeText(root, fixturesPath, "{ malformed fixtures\n");

    expect(loadCorpus(root).issues.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: "invalid-json", path: familyManifestPath },
      { code: "invalid-json", path: fixturesPath },
    ]);
  });

  it("keeps parsing artifacts after a top-level manifest shape issue", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    manifest.family_version = "heterodyne/9.9.9";
    writeText(root, vectorPath, "{ malformed\n");
    const vector = (manifest.artifacts as Array<Record<string, unknown>>)
      .find((artifact) => artifact.path === vectorPath)!;
    vector.sha256 = sha256File(root, vectorPath);
    writeJson(root, familyManifestPath, manifest);

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
      "invalid-document-shape",
      "missing-required-root",
      "unsafe-artifact-path",
    ]);
  });

  it("rejects a required specification declared with the schema role", () => {
    const root = repository();
    const corePath = "docs/spec/heterodyne-core.md";
    const manifest = readTestManifest(root);
    const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
    const core = artifacts.find((artifact) => artifact.path === corePath);
    if (core === undefined) {
      throw new Error("Core specification is absent from synthetic manifest");
    }
    core.role = "schema";
    writeText(root, corePath, "{}\n");
    writeJson(root, familyManifestPath, manifest);
    refreshReleaseDigests(root);

    expect(loadCorpus(root).issues.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: "invalid-document-shape", path: corePath },
    ]);
    expect(loadCorpus(root).corpus).toBeUndefined();
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
      description: "duplicate synthetic vector identifier",
      direction: "consume",
      input: {},
      expected_output: { verdict: "accept" },
    });
    (manifest.artifacts as unknown[]).push({
      path: duplicatePath,
      role: "vector",
      sha256: sha256File(root, duplicatePath),
    });
    (manifest.artifacts as Array<Record<string, unknown>>)
      .sort((left, right) => String(left.path).localeCompare(String(right.path)));
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual(["duplicate-vector-id"]);
  });

  it("rejects a normative vector declared as normative support", () => {
    const root = repository();
    const manifest = readTestManifest(root);
    const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
    const vector = artifacts.find((artifact) => artifact.path === vectorPath);
    if (vector === undefined) {
      throw new Error("test vector is absent from synthetic manifest");
    }
    vector.role = "normative-support";
    writeJson(root, familyManifestPath, manifest);

    expect(loadCorpus(root).issues.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: "invalid-document-shape", path: vectorPath },
    ]);
    expect(loadCorpus(root).corpus).toBeUndefined();
  });

  it("reports duplicate registry entries", () => {
    const root = repository();
    const reasons = readJson(root, reasonCodesPath);
    const entry = (reasons.reason_codes as unknown[])[0]!;
    writeJson(root, reasonCodesPath, { reason_codes: [entry, entry] });
    refreshRegistryEntrySetDigest(root);
    refreshReleaseDigests(root);

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual([
      "duplicate-registry-entry",
    ]);
  });

  it("reports duplicate reason codes even when another entry is malformed", () => {
    const root = repository();
    const reasons = readJson(root, reasonCodesPath);
    const entry = (reasons.reason_codes as unknown[])[0]!;
    writeJson(root, reasonCodesPath, {
      reason_codes: [
        entry,
        { malformed: true },
        entry,
      ],
    });
    refreshRegistryEntrySetDigest(root);
    refreshReleaseDigests(root);

    expect(loadCorpus(root).issues.map(({ code }) => code)).toEqual([
      "duplicate-registry-entry",
      "invalid-document-shape",
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

  it.each([
    "docs/spec/registry",
    "docs/spec/schemas",
    "docs/spec/vectors",
  ])("reports a missing required inventory root without throwing: %s", (requiredRoot) => {
    const root = repository();
    rmSync(resolve(root, requiredRoot), { recursive: true, force: true });

    const result = loadCorpus(root);

    expect(result.issues).toContainEqual({
      code: "missing-required-root",
      path: requiredRoot,
      message: "required corpus root is missing",
    });
    expect(result.corpus).toBeUndefined();
  });

  it("reports a required inventory root that is not a readable directory", () => {
    const root = repository();
    const requiredRoot = "docs/spec/schemas";
    rmSync(resolve(root, requiredRoot), { recursive: true, force: true });
    writeText(root, requiredRoot, "not a directory\n");

    const result = loadCorpus(root);

    expect(result.issues).toContainEqual({
      code: "missing-required-root",
      path: requiredRoot,
      message: "required corpus root is not a directory",
    });
    expect(result.corpus).toBeUndefined();
  });
});
