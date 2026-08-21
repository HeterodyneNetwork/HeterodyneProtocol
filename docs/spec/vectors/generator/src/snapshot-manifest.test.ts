import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildSnapshotManifest,
  loadSnapshotManifest,
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
  "core/001-first.json",
  "workspace/001-second.json",
] as const;
const SOURCE_COMMIT = "1".repeat(40);
const temps: string[] = [];

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
  write(root, "snapshot.schema.json", "{}\n");
  return root;
}

function writeManifest(root: string, manifest: SnapshotManifest, bytes = canonical(manifest)): void {
  write(root, "snapshot.json", bytes);
}

describe("snapshot manifest", () => {
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
      vector_count: 2,
      artifacts: expectedPaths.map((path) => ({
        path,
        sha256: sha256(readFileSync(join(root, path), "utf8")),
      })),
    });
    expect(manifest.artifacts.map(({ path }) => path)).not.toEqual(expect.arrayContaining([
      `${VECTOR_ROOT}/README.md`,
      `${VECTOR_ROOT}/generator/package.json`,
      `${VECTOR_ROOT}/snapshot.json`,
      `${VECTOR_ROOT}/snapshot.schema.json`,
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
});
