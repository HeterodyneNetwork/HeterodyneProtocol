import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

export const familyManifestPath = "docs/spec/releases/family/0.5.0.json";
export const fixturesPath = "docs/spec/vectors/fixtures.json";
export const registryManifestPath = "docs/spec/registry/manifest.json";
export const reasonCodesPath = "docs/spec/registry/reason-codes.json";
export const securityInvariantsPath = "docs/spec/registry/security-invariants.json";
export const vectorPath = "docs/spec/vectors/core/001-valid.json";

export type TestArtifact = {
  path: string;
  role: "specification" | "registry" | "schema" | "vector" | "normative-support";
  sha256: string;
};

export function writeText(root: string, path: string, value: string): void {
  const target = resolve(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, value, "utf8");
}

export function writeJson(root: string, path: string, value: unknown): void {
  writeText(root, path, `${JSON.stringify(value, null, 2)}\n`);
}

export function readTestManifest(root: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(root, familyManifestPath), "utf8")) as Record<string, unknown>;
}

export function createTestRepository(): string {
  const root = mkdtempSync(join(tmpdir(), "heterodyne-conformance-"));
  const digest = "aa".repeat(32);
  const artifacts: TestArtifact[] = [];

  for (const name of ["comms", "control", "core", "social", "workspace"]) {
    const path = `docs/spec/heterodyne-${name}.md`;
    writeText(root, path, `# ${name}\n`);
    artifacts.push({ path, role: "specification", sha256: digest });
  }

  writeJson(root, registryManifestPath, {
    revision: 13,
    schema_version: "3.0.0",
    entry_set_sha256: digest,
  });
  writeJson(root, reasonCodesPath, { reason_codes: [{ code: "bad_signature" }] });
  writeJson(root, securityInvariantsPath, {
    security_invariants: [{ id: "CORE-I-VERIFY-BEFORE-USE", owner: "core" }],
  });
  artifacts.push(
    { path: registryManifestPath, role: "registry", sha256: digest },
    { path: reasonCodesPath, role: "registry", sha256: digest },
    { path: securityInvariantsPath, role: "registry", sha256: digest },
  );

  const schemaPath = "docs/spec/schemas/core/example-v1.schema.json";
  writeJson(root, schemaPath, { type: "object" });
  artifacts.push({ path: schemaPath, role: "schema", sha256: digest });

  writeJson(root, vectorPath, {
    vector_id: "core.valid",
    vector_schema_version: "1.1.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: ["heterodyne:0.5.0#core-conformance"],
    direction: "consume",
    input: {},
    expected_output: { verdict: "accept" },
  });
  artifacts.push({ path: vectorPath, role: "vector", sha256: digest });

  writeJson(root, fixturesPath, {
    vector_schema_version: "1.1.0",
    spec_version: "heterodyne/0.5.0",
    registry_sha256: digest,
  });
  writeJson(root, familyManifestPath, {
    schema_version: "1.0.0",
    family_version: "heterodyne/0.5.0",
    status: "unreleased",
    registry: { path: registryManifestPath, sha256: digest },
    artifacts: artifacts.sort((left, right) => left.path.localeCompare(right.path)),
  });

  return root;
}
