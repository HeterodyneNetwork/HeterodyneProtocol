import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import type { LoadCorpusOptions } from "./artifacts.js";

export const snapshotManifestPath = "docs/spec/vectors/snapshot.json";
export const fixturesPath = "docs/spec/vectors/fixtures.json";
export const registryManifestPath = "docs/spec/registry/manifest.json";
export const kindsPath = "docs/spec/registry/kinds.json";
export const reasonCodesPath = "docs/spec/registry/reason-codes.json";
export const securityInvariantsPath = "docs/spec/registry/security-invariants.json";
export const featuresPath = "docs/spec/registry/features.json";
export const objectsPath = "docs/spec/registry/objects.json";
export const proofDomainsPath = "docs/spec/registry/proof-domains.json";
export const registrySchemaPath = "docs/spec/registry/registry.schema.json";
export const protocolSchemaPath = "docs/spec/schemas/core/example-v1.schema.json";
export const vectorSchemaPath = "docs/spec/vectors/schema/vector.schema.json";
export const vectorPath = "docs/spec/vectors/core/001-valid.json";
export const sourceCommit = "1".repeat(40);
export const snapshotCommit = "2".repeat(40);
export const registryEntrySetDigest =
  "0250925c750aa782924c6ebc6eebd4d085f7c16dc72175077b9e5188b251ace9";

const snapshotSupportPaths = [
  fixturesPath,
  vectorSchemaPath,
  "docs/spec/vectors/schema/reason-codes.json",
  "docs/spec/vectors/schema/reason-codes.md",
  "docs/spec/vectors/coverage/manifest.json",
  "docs/spec/vectors/coverage/core.md",
  "docs/spec/vectors/coverage/comms.md",
  "docs/spec/vectors/coverage/control.md",
  "docs/spec/vectors/coverage/social.md",
  "docs/spec/vectors/coverage/workspace.md",
  "docs/spec/vectors/coverage/family.md",
] as const;

export type TestCorpus = LoadCorpusOptions & { root: string };

export function writeText(root: string, path: string, value: string): void {
  const target = resolve(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, value, "utf8");
}

export function writeJson(root: string, path: string, value: unknown): void {
  writeText(root, path, `${JSON.stringify(value, null, 2)}\n`);
}

export function readJson(root: string, path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(root, path), "utf8")) as Record<string, unknown>;
}

export function readTestManifest(root: string): Record<string, unknown> {
  return readJson(root, snapshotManifestPath);
}

export function sha256File(root: string, path: string): string {
  return createHash("sha256").update(readFileSync(resolve(root, path))).digest("hex");
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
    kinds: readJson(root, kindsPath).kinds,
    reason_codes: readJson(root, reasonCodesPath).reason_codes,
    security_invariants: readJson(root, securityInvariantsPath).security_invariants,
    features: readJson(root, featuresPath).features,
    objects: readJson(root, objectsPath).objects,
    proof_domains: readJson(root, proofDomainsPath).proof_domains,
  };
  const manifest = readJson(root, registryManifestPath);
  manifest.entry_set_sha256 = createHash("sha256")
    .update(canonicalize(entrySet), "utf8")
    .digest("hex");
  writeJson(root, registryManifestPath, manifest);
}

function vectorPaths(root: string): string[] {
  const vectorRoot = resolve(root, "docs/spec/vectors");
  const excluded = new Set(["coverage", "generator", "schema"]);
  const visit = (directory: string): string[] => readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const target = resolve(directory, entry.name);
      if (entry.isDirectory()) {
        if (directory === vectorRoot && excluded.has(entry.name)) return [];
        return visit(target);
      }
      const path = relative(root, target).replaceAll("\\", "/");
      return entry.isFile()
        && entry.name.endsWith(".json")
        && path !== fixturesPath
        && path !== snapshotManifestPath
        ? [path]
        : [];
    });
  return visit(vectorRoot).sort();
}

export function refreshSnapshotManifest(
  root: string,
  pinnedSourceCommit = sourceCommit,
): void {
  const vectors = vectorPaths(root);
  const schema = readJson(root, vectorSchemaPath);
  const properties = schema.properties as Record<string, Record<string, unknown>>;
  const vectorSchemaVersion = properties.vector_schema_version?.const;
  if (typeof vectorSchemaVersion !== "string") {
    throw new Error("synthetic packaged vector schema has no version const");
  }
  const paths = [...vectors, ...snapshotSupportPaths].sort();
  writeJson(root, snapshotManifestPath, {
    snapshot_schema: "1",
    source_commit: pinnedSourceCommit,
    vector_schema_version: vectorSchemaVersion,
    vector_count: vectors.length,
    artifacts: paths.map((path) => ({ path, sha256: sha256File(root, path) })),
  });
}

function writeSource(root: string, withAssurance: boolean): void {
  const documents = withAssurance
    ? ["core", "assurance", "comms", "control", "social", "workspace"]
    : ["core", "comms", "control", "social", "workspace"];
  for (const name of documents) {
    const schemaReference = name === "core"
      ? "\nProtocol schema: docs/spec/schemas/core/example-v1.schema.json."
      : "";
    writeText(
      root,
      `docs/spec/heterodyne-${name}.md`,
      `# ${name}\n<a id="${name}-conformance"></a>${schemaReference}\n`,
    );
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
      first_version: "heterodyne/0.6.0",
      description: "Nostr event id or BIP-340 signature verification failed.",
      spec_refs: ["heterodyne:0.6.0#core-conformance"],
    }],
  });
  writeJson(root, securityInvariantsPath, {
    security_invariants: [{
      id: "CORE-I-VERIFY-BEFORE-USE",
      owner: "core",
      status: "draft",
      first_version: "heterodyne/0.6.0",
      description: "Verify signed input before use.",
    }],
  });
  const repositoryRoot = resolve(import.meta.dirname, "../../../..");
  writeText(
    root,
    registrySchemaPath,
    readFileSync(resolve(repositoryRoot, registrySchemaPath), "utf8"),
  );
  writeJson(root, protocolSchemaPath, { type: "object", title: "pinned-source-schema" });
}

function writeSnapshot(root: string, withVector: boolean): void {
  const repositoryRoot = resolve(import.meta.dirname, "../../../..");
  writeText(
    root,
    vectorSchemaPath,
    readFileSync(resolve(repositoryRoot, vectorSchemaPath), "utf8"),
  );
  writeJson(root, fixturesPath, {
    audience_keys: {},
    category_keysets: {},
    device_publishing_keys: {},
    ed25519_nids: {},
    kel: {},
    personas: {},
    pinned_randomness: {},
    radicle_rids: {},
    registry_sha256: registryEntrySetDigest,
    test_epoch: 0,
    vector_schema_version: "2.0.0",
  });
  writeJson(root, "docs/spec/vectors/schema/reason-codes.json", { reason_codes: [] });
  writeText(root, "docs/spec/vectors/schema/reason-codes.md", "# Reasons\n");
  writeJson(root, "docs/spec/vectors/coverage/manifest.json", { vectors: [] });
  for (const owner of ["core", "comms", "control", "social", "workspace", "family"]) {
    writeText(root, `docs/spec/vectors/coverage/${owner}.md`, `# ${owner}\n`);
  }
  if (withVector) {
    writeJson(root, vectorPath, {
      vector_id: "core.valid",
      vector_schema_version: "2.0.0",
      owner_document: "core",
      spec_refs: ["heterodyne:core#core-conformance"],
      description: "valid synthetic snapshot vector",
      direction: "consume",
      input: {},
      expected_output: { verdict: "accept" },
    });
  }
  refreshSnapshotManifest(root);
}

export function createTestCorpus(
  options: { withVector?: boolean; withAssurance?: boolean } = {},
): TestCorpus {
  const root = mkdtempSync(join(tmpdir(), "heterodyne-conformance-"));
  const sourceRoot = resolve(root, "source");
  const snapshotRoot = resolve(root, "snapshot");
  mkdirSync(sourceRoot);
  mkdirSync(snapshotRoot);
  writeSource(sourceRoot, options.withAssurance ?? false);
  writeSnapshot(snapshotRoot, options.withVector ?? true);
  return { root, sourceRoot, snapshotRoot, sourceCommit, snapshotCommit };
}
