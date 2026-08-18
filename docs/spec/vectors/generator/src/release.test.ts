import { Ajv } from "ajv";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildFamilyReleaseManifest,
  validateFamilyReleaseManifest,
  writeFamilyReleaseManifest,
} from "./release.js";

const repositoryRoot = resolve(import.meta.dirname, "../../../../../");
const manifestPath = "docs/spec/releases/family/0.5.0.json";
const schemaPath = "docs/spec/releases/family-release-manifest.schema.json";
const specificationPaths = [
  "docs/spec/heterodyne-comms.md",
  "docs/spec/heterodyne-control.md",
  "docs/spec/heterodyne-core.md",
  "docs/spec/heterodyne-social.md",
  "docs/spec/heterodyne-workspace.md",
];
const changedSpecification = "docs/spec/heterodyne-core.md";
const missingVector = "docs/spec/vectors/versioning/008-exact-family-version-negotiation.json";
const temps: string[] = [];

afterEach(() => {
  for (const path of temps.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function sha256(bytes: Buffer | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function copyFile(sourceRoot: string, targetRoot: string, path: string): void {
  const target = resolve(targetRoot, path);
  mkdirSync(dirname(target), { recursive: true });
  copyFileSync(resolve(sourceRoot, path), target);
}

function copyRepository(): string {
  const targetRoot = mkdtempSync(join(tmpdir(), "heterodyne-release-"));
  temps.push(targetRoot);
  for (const path of [...specificationPaths, manifestPath, schemaPath]) {
    copyFile(repositoryRoot, targetRoot, path);
  }
  for (const path of ["docs/spec/registry", "docs/spec/schemas"]) {
    cpSync(resolve(repositoryRoot, path), resolve(targetRoot, path), { recursive: true });
  }
  cpSync(
    resolve(repositoryRoot, "docs/spec/vectors"),
    resolve(targetRoot, "docs/spec/vectors"),
    {
      recursive: true,
      filter: (source) => !source.startsWith(resolve(repositoryRoot, "docs/spec/vectors/generator")),
    },
  );
  copyFile(repositoryRoot, targetRoot, "docs/spec/external/marmot/manifest.json");
  return targetRoot;
}

function readManifest(root: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(root, manifestPath), "utf8")) as Record<string, unknown>;
}

function writeManifest(root: string, manifest: Record<string, unknown>): void {
  writeFileSync(resolve(root, manifestPath), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

describe("family release manifest", () => {
  it("schema rejects a trailing empty path segment", () => {
    const schema = JSON.parse(readFileSync(resolve(repositoryRoot, schemaPath), "utf8")) as object;
    const validate = new Ajv({ allErrors: true }).compile(schema);
    const manifest = readManifest(repositoryRoot);
    const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
    artifacts[0] = { ...artifacts[0], path: "a/" };

    expect(validate(manifest)).toBe(false);
  });

  it("builds the complete path-sorted normative family corpus", () => {
    const manifest = buildFamilyReleaseManifest(repositoryRoot);

    expect(manifest.schema_version).toBe("1.0.0");
    expect(manifest.family_version).toBe("heterodyne/0.5.0");
    expect(manifest.status).toBe("unreleased");
    expect(manifest.registry.path).toBe("docs/spec/registry/manifest.json");
    expect(manifest.registry.sha256).toBe(
      sha256(readFileSync(resolve(repositoryRoot, "docs/spec/registry/manifest.json"))),
    );
    expect(manifest.artifacts.filter((artifact) => artifact.role === "specification")).toHaveLength(5);
    expect(manifest.artifacts.filter((artifact) => artifact.role === "vector")).toHaveLength(495);
    expect(manifest.artifacts.filter((artifact) => artifact.role === "schema")).toHaveLength(63);
    expect(manifest.artifacts.map((artifact) => artifact.path)).toEqual(
      [...manifest.artifacts.map((artifact) => artifact.path)].sort(),
    );
    expect(manifest.artifacts.map((artifact) => artifact.path)).not.toContain(manifestPath);
    expect(manifest.artifacts.map((artifact) => artifact.path)).not.toContain(schemaPath);
    expect(manifest.artifacts.map((artifact) => artifact.path)).not.toContain("docs/spec/vectors/fixtures.json");
    expect(manifest.artifacts.map((artifact) => artifact.path)).not.toContain("docs/spec/vectors/coverage/manifest.json");
    expect(manifest.artifacts.map((artifact) => artifact.path)).not.toContain("docs/spec/vectors/schema/reason-codes.json");
    expect(manifest.artifacts).toContainEqual({
      path: "docs/spec/vectors/schema/vector.schema.json",
      role: "schema",
      sha256: sha256(readFileSync(resolve(repositoryRoot, "docs/spec/vectors/schema/vector.schema.json"))),
    });
    expect(validateFamilyReleaseManifest(repositoryRoot)).toEqual([]);
  });

  it("writes stable two-space JSON followed by one LF", () => {
    const root = copyRepository();
    writeFileSync(resolve(root, manifestPath), "{}\n", "utf8");
    const expected = `${JSON.stringify(buildFamilyReleaseManifest(root), null, 2)}\n`;

    expect(writeFamilyReleaseManifest(root)).toBe(resolve(root, manifestPath));
    expect(readFileSync(resolve(root, manifestPath), "utf8")).toBe(expected);
    expect(writeFamilyReleaseManifest(root)).toBe(resolve(root, manifestPath));
    expect(readFileSync(resolve(root, manifestPath), "utf8")).toBe(expected);
  });

  it("detects a changed normative file", () => {
    const root = copyRepository();
    writeFileSync(resolve(root, changedSpecification), "mutated bytes\n", "utf8");

    expect(validateFamilyReleaseManifest(root).join("\n")).toContain(
      `artifact digest mismatch: ${changedSpecification}`,
    );
  });

  it("detects a missing normative artifact", () => {
    const root = copyRepository();
    unlinkSync(resolve(root, missingVector));

    expect(validateFamilyReleaseManifest(root).join("\n")).toContain(
      `unexpected artifact in manifest: ${missingVector}`,
    );
  });

  it("detects an extra manifest entry", () => {
    const root = copyRepository();
    const manifest = readManifest(root);
    const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
    artifacts.push({ path: "README.md", role: "normative-support", sha256: "00".repeat(32) });
    writeManifest(root, manifest);

    expect(validateFamilyReleaseManifest(root).join("\n")).toContain(
      "unexpected artifact in manifest: README.md",
    );
  });

  it("detects a wrong registry digest", () => {
    const root = copyRepository();
    const manifest = readManifest(root);
    manifest.registry = {
      ...(manifest.registry as Record<string, unknown>),
      sha256: "00".repeat(32),
    };
    writeManifest(root, manifest);

    expect(validateFamilyReleaseManifest(root).join("\n")).toContain("registry digest mismatch");
  });

  it("rejects an unsafe path before attempting to read it", () => {
    const root = copyRepository();
    const manifest = readManifest(root);
    const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
    artifacts[0] = { ...artifacts[0], path: "../outside.json" };
    mkdirSync(resolve(root, "../outside.json"), { recursive: true });
    writeManifest(root, manifest);

    expect(() => validateFamilyReleaseManifest(root)).not.toThrow();
    expect(validateFamilyReleaseManifest(root).join("\n")).toContain(
      "unsafe artifact path: ../outside.json",
    );
  });

  it("reports corpus, shape, path, role, and digest failures together", () => {
    const root = copyRepository();
    unlinkSync(resolve(root, changedSpecification));
    const manifest = readManifest(root);
    manifest.extra = true;
    const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
    artifacts[0] = {
      ...artifacts[0],
      path: "../outside.json",
      role: "invalid",
      sha256: "invalid",
    };
    mkdirSync(resolve(root, "../outside.json"), { recursive: true });
    writeManifest(root, manifest);

    const issues = validateFamilyReleaseManifest(root);
    expect(issues).toEqual(expect.arrayContaining([
      expect.stringContaining("unable to build expected family release manifest"),
      "family release manifest has unexpected property: extra",
      "unsafe artifact path: ../outside.json",
      "invalid artifact role: invalid",
      "invalid artifact digest: ../outside.json",
    ]));
  });
});
