import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

export const familyManifestPath = "docs/spec/releases/family/0.5.0.json";
export const fixturesPath = "docs/spec/vectors/fixtures.json";
export const registryManifestPath = "docs/spec/registry/manifest.json";
export const kindsPath = "docs/spec/registry/kinds.json";
export const reasonCodesPath = "docs/spec/registry/reason-codes.json";
export const securityInvariantsPath = "docs/spec/registry/security-invariants.json";
export const featuresPath = "docs/spec/registry/features.json";
export const objectsPath = "docs/spec/registry/objects.json";
export const proofDomainsPath = "docs/spec/registry/proof-domains.json";
export const registrySchemaPath = "docs/spec/registry/registry.schema.json";
export const vectorSchemaPath = "docs/spec/vectors/schema/vector.schema.json";
export const vectorPath = "docs/spec/vectors/core/001-valid.json";
export const registryEntrySetDigest =
  "32579526a345b75cf11b3892b01928794c57c0318b8ae5194208f1d76c13df69";

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

export function sha256File(root: string, path: string): string {
  return createHash("sha256").update(readFileSync(resolve(root, path))).digest("hex");
}

export function refreshReleaseDigests(root: string): void {
  const manifest = readTestManifest(root);
  const artifacts = manifest.artifacts as Array<Record<string, unknown>>;
  for (const artifact of artifacts) {
    artifact.sha256 = sha256File(root, artifact.path as string);
  }
  const registry = manifest.registry as Record<string, unknown>;
  registry.sha256 = sha256File(root, registry.path as string);
  writeJson(root, familyManifestPath, manifest);
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string"
    || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
}

export function refreshRegistryEntrySetDigest(root: string): void {
  const entrySet = {
    kinds: JSON.parse(readFileSync(resolve(root, kindsPath), "utf8")).kinds,
    reason_codes: JSON.parse(readFileSync(resolve(root, reasonCodesPath), "utf8")).reason_codes,
    security_invariants:
      JSON.parse(readFileSync(resolve(root, securityInvariantsPath), "utf8")).security_invariants,
    features: JSON.parse(readFileSync(resolve(root, featuresPath), "utf8")).features,
    objects: JSON.parse(readFileSync(resolve(root, objectsPath), "utf8")).objects,
    proof_domains: JSON.parse(readFileSync(resolve(root, proofDomainsPath), "utf8")).proof_domains,
  };
  const manifest = JSON.parse(readFileSync(resolve(root, registryManifestPath), "utf8"));
  manifest.entry_set_sha256 = createHash("sha256")
    .update(canonicalize(entrySet), "utf8")
    .digest("hex");
  writeJson(root, registryManifestPath, manifest);
}

export function createTestRepository(): string {
  const root = mkdtempSync(join(tmpdir(), "heterodyne-conformance-"));
  const artifacts: TestArtifact[] = [];

  const addArtifact = (path: string, role: TestArtifact["role"]): void => {
    artifacts.push({ path, role, sha256: sha256File(root, path) });
  };

  for (const name of ["comms", "control", "core", "social", "workspace"]) {
    const path = `docs/spec/heterodyne-${name}.md`;
    writeText(root, path, `# ${name}\n`);
    addArtifact(path, "specification");
  }

  writeJson(root, registryManifestPath, {
    revision: 13,
    schema_version: "3.0.0",
    entry_set_sha256: registryEntrySetDigest,
  });
  writeJson(root, kindsPath, { kinds: [] });
  writeJson(root, featuresPath, { features: [] });
  writeJson(root, objectsPath, { objects: [] });
  writeJson(root, proofDomainsPath, { proof_domains: [] });
  writeJson(root, reasonCodesPath, {
    reason_codes: [{
      code: "bad_signature",
      owner: "core",
      status: "draft",
      first_version: "heterodyne/0.5.0",
      description: "Nostr event id or BIP-340 signature verification failed.",
      spec_refs: ["heterodyne:0.5.0#core-conformance"],
    }],
  });
  writeJson(root, securityInvariantsPath, {
    security_invariants: [{
      id: "CORE-I-VERIFY-BEFORE-USE",
      owner: "core",
      status: "draft",
      first_version: "heterodyne/0.5.0",
      description: "Verify signed input before use.",
    }],
  });
  const repositoryRoot = resolve(import.meta.dirname, "../../../..");
  writeText(
    root,
    registrySchemaPath,
    readFileSync(resolve(repositoryRoot, registrySchemaPath), "utf8"),
  );
  for (const path of [
    featuresPath,
    kindsPath,
    registryManifestPath,
    objectsPath,
    proofDomainsPath,
    reasonCodesPath,
    registrySchemaPath,
    securityInvariantsPath,
  ]) {
    addArtifact(path, "registry");
  }

  const schemaPath = "docs/spec/schemas/core/example-v1.schema.json";
  writeJson(root, schemaPath, { type: "object" });
  addArtifact(schemaPath, "schema");
  writeText(
    root,
    vectorSchemaPath,
    readFileSync(resolve(repositoryRoot, vectorSchemaPath), "utf8"),
  );
  addArtifact(vectorSchemaPath, "schema");

  writeJson(root, vectorPath, {
    vector_id: "core.valid",
    vector_schema_version: "1.1.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: ["heterodyne:0.5.0#core-conformance"],
    description: "valid synthetic vector",
    direction: "consume",
    input: {},
    expected_output: { verdict: "accept" },
  });
  addArtifact(vectorPath, "vector");

  const marmotManifestPath = "docs/spec/external/marmot/manifest.json";
  writeJson(root, marmotManifestPath, { version: "synthetic" });
  addArtifact(marmotManifestPath, "normative-support");

  writeJson(root, fixturesPath, {
    vector_schema_version: "1.1.0",
    spec_version: "heterodyne/0.5.0",
    registry_sha256: registryEntrySetDigest,
  });
  writeJson(root, familyManifestPath, {
    schema_version: "1.0.0",
    family_version: "heterodyne/0.5.0",
    status: "unreleased",
    registry: { path: registryManifestPath, sha256: sha256File(root, registryManifestPath) },
    artifacts: artifacts.sort((left, right) => left.path.localeCompare(right.path)),
  });

  return root;
}
