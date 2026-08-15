import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv, type AnySchema, type ErrorObject } from "ajv";
import { assertCurrentFamilyVersion, FAMILY_VERSION } from "./family.js";
import type { DocumentId } from "./types.js";

export type RegistryStatus = "draft" | "stable" | "frozen";

export type RegistryManifest = {
  revision: number;
  schema_version: string;
  entry_set_sha256: string;
};

export type KindProfile = {
  profile_id: string;
  owner: DocumentId;
  discriminator: string;
  /** True only when the profile overrides the base/upstream stamp owner. */
  stamping: boolean;
  first_version: string;
  status: RegistryStatus;
};

export type KindEntry = {
  kind: number;
  allocation_authority: "heterodyne" | "nostr";
  base_schema_owner: DocumentId | "nostr";
  status: RegistryStatus;
  first_version: string;
  profiles: KindProfile[];
};

export type ReasonCodeEntry = {
  code: string;
  owner: DocumentId;
  status: RegistryStatus;
  first_version: string;
  description: string;
  spec_refs: string[];
};

export type InvariantEntry = {
  id: string;
  owner: DocumentId;
  status: RegistryStatus;
  first_version: string;
  description: string;
};

export type FeatureEntry = {
  id: string;
  owner: DocumentId;
  first_version: string;
  status: RegistryStatus;
  description: string;
  spec_ref: string;
  prerequisites: string[];
};

export type ObjectEntry = {
  id: string;
  owner: DocumentId;
  first_version: string;
  status: RegistryStatus;
  schema: string;
  carriers: Array<"radicle-authority-file" | "marmot-application-data">;
};

export type RegistryEntrySet = {
  kinds: KindEntry[];
  reason_codes: ReasonCodeEntry[];
  security_invariants: InvariantEntry[];
  features: FeatureEntry[];
  objects: ObjectEntry[];
};

export type Registry = RegistryEntrySet & {
  features: FeatureEntry[];
  objects: ObjectEntry[];
  manifest: RegistryManifest;
};

const STATUS_ORDER: Record<RegistryStatus, number> = {
  draft: 0,
  stable: 1,
  frozen: 2,
};

const QUALIFIED_REFERENCE = new RegExp(
  `^heterodyne:${FAMILY_VERSION.replaceAll(".", "\\.")}#[a-z0-9]+(?:-[a-z0-9]+)*$`,
);

const DEFAULT_REGISTRY_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../registry",
);

export function loadRegistry(root: string): Registry {
  const registryRoot = resolveRegistryRoot(root);
  const manifest = readJson<RegistryManifest>(join(registryRoot, "manifest.json"));
  const kinds = readJson<{ kinds: KindEntry[] }>(join(registryRoot, "kinds.json")).kinds;
  const reason_codes = readJson<{ reason_codes: ReasonCodeEntry[] }>(
    join(registryRoot, "reason-codes.json"),
  ).reason_codes;
  const security_invariants = readJson<{ security_invariants: InvariantEntry[] }>(
    join(registryRoot, "security-invariants.json"),
  ).security_invariants;
  const features = readJson<{ features: FeatureEntry[] }>(
    join(registryRoot, "features.json"),
  ).features;
  const objects = readJson<{ objects: ObjectEntry[] }>(
    join(registryRoot, "objects.json"),
  ).objects;
  const registry = { manifest, kinds, reason_codes, security_invariants, features, objects };
  validateRegistry(registry, registryRoot);
  return registry;
}

export function computeRegistryDigest(registry: RegistryEntrySet): string {
  const entrySet: RegistryEntrySet = {
    kinds: registry.kinds,
    reason_codes: registry.reason_codes,
    security_invariants: registry.security_invariants,
    features: registry.features,
    objects: registry.objects,
  };
  return createHash("sha256").update(canonicalize(entrySet), "utf8").digest("hex");
}

export function authorRegistryRevision(
  repositoryRoot: string,
  revision: number,
  schemaVersion = "3.0.0",
): string {
  const registryRoot = resolveRegistryRoot(repositoryRoot);
  const entrySet: RegistryEntrySet = {
    kinds: readJson<{ kinds: KindEntry[] }>(join(registryRoot, "kinds.json")).kinds,
    reason_codes: readJson<{ reason_codes: ReasonCodeEntry[] }>(
      join(registryRoot, "reason-codes.json"),
    ).reason_codes,
    security_invariants: readJson<{ security_invariants: InvariantEntry[] }>(
      join(registryRoot, "security-invariants.json"),
    ).security_invariants,
    features: readJson<{ features: FeatureEntry[] }>(
      join(registryRoot, "features.json"),
    ).features,
    objects: readJson<{ objects: ObjectEntry[] }>(
      join(registryRoot, "objects.json"),
    ).objects,
  };
  validateUniqueEntries(entrySet);
  validateEntryMetadata(entrySet);
  const digest = computeRegistryDigest(entrySet);
  writeFileSync(
    join(registryRoot, "manifest.json"),
    `${JSON.stringify({ revision, schema_version: schemaVersion, entry_set_sha256: digest }, null, 2)}\n`,
    "utf8",
  );
  return digest;
}

export function validateRegistry(
  registry: Registry,
  registryRoot = DEFAULT_REGISTRY_ROOT,
): void {
  validateUniqueEntries(registry);
  validateEntryMetadata(registry);
  validateAgainstSchema(registry, registryRoot);
  if (registry.manifest.entry_set_sha256 !== computeRegistryDigest(registry)) {
    throw new Error("registry manifest digest does not match current entry set");
  }
}

export function assertRegistryStatusTransition(
  previous: RegistryStatus,
  current: RegistryStatus,
): void {
  const delta = STATUS_ORDER[current] - STATUS_ORDER[previous];
  if (delta < 0 || delta > 1) {
    throw new Error(`invalid registry status transition: ${previous} -> ${current}`);
  }
}

export function assertRegistryDownrefs(
  familyVersion: string,
  requiredStatuses: readonly RegistryStatus[],
): void {
  const major = Number.parseInt(familyVersion.split("/").pop()!.split(".", 1)[0], 10);
  if (major >= 1 && requiredStatuses.some((status) => status !== "frozen")) {
    throw new Error("1.0 specification requires frozen registry entries");
  }
}

export function resolveStampingProfile(
  registry: Registry,
  kind: number,
  discriminator: string,
): KindProfile | null {
  const matches =
    registry.kinds
      .find((entry) => entry.kind === kind)
      ?.profiles.filter(
        (profile) =>
          profile.stamping && profile.discriminator === discriminator,
      ) ?? [];
  return matches.length === 1 ? matches[0] : null;
}

function validateUniqueEntries(registry: RegistryEntrySet): void {
  assertUnique(registry.kinds.map((entry) => entry.kind), "duplicate kind");
  assertUnique(registry.reason_codes.map((entry) => entry.code), "duplicate reason code");
  assertUnique(
    registry.security_invariants.map((entry) => entry.id),
    "duplicate security invariant",
  );
  assertUnique((registry.features ?? []).map((entry) => entry.id), "duplicate feature");
  assertUnique((registry.objects ?? []).map((entry) => entry.id), "duplicate object type");

  const profileIds: string[] = [];
  for (const entry of registry.kinds) {
    assertUnique(
      entry.profiles.map((profile) => profile.discriminator),
      `duplicate profile discriminator for kind ${entry.kind}`,
    );
    profileIds.push(...entry.profiles.map((profile) => profile.profile_id));
  }
  assertUnique(profileIds, "duplicate profile identifier");
}

function validateEntryMetadata(registry: RegistryEntrySet): void {
  for (const entry of registry.kinds) {
    assertCurrentFamilyVersion(entry.first_version);
    for (const profile of entry.profiles) {
      assertCurrentFamilyVersion(profile.first_version);
    }
  }
  for (const entry of registry.reason_codes) {
    assertCurrentFamilyVersion(entry.first_version);
    for (const ref of entry.spec_refs) {
      if (!QUALIFIED_REFERENCE.test(ref)) {
        throw new Error(`unqualified registry spec reference: ${ref}`);
      }
    }
  }
  for (const entry of registry.security_invariants) {
    assertCurrentFamilyVersion(entry.first_version);
    const prefix = `${entry.owner.toUpperCase()}-I-`;
    if (!entry.id.startsWith(prefix)) {
      throw new Error(`security invariant owner mismatch: ${entry.id}`);
    }
  }
  validateFeatures(registry.features);
  for (const entry of registry.objects) {
    assertCurrentFamilyVersion(entry.first_version);
    assertUnique(entry.carriers, `duplicate object carrier: ${entry.id}`);
  }
}

function validateFeatures(features: FeatureEntry[]): void {
  const byId = new Map(features.map((entry) => [entry.id, entry]));
  for (const entry of features) {
    if (!entry.id.startsWith(`${entry.owner}.`)) {
      throw new Error(`feature owner mismatch: ${entry.id}`);
    }
    assertCurrentFamilyVersion(entry.first_version);
    if (!QUALIFIED_REFERENCE.test(entry.spec_ref)) {
      throw new Error(`unqualified feature spec reference: ${entry.spec_ref}`);
    }
    assertUnique(entry.prerequisites, `duplicate feature prerequisite: ${entry.id}`);
    for (const prerequisite of entry.prerequisites) {
      if (!byId.has(prerequisite)) {
        throw new Error(`unknown feature prerequisite: ${entry.id} -> ${prerequisite}`);
      }
    }
  }
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (id: string): void => {
    if (visiting.has(id)) throw new Error(`feature prerequisite cycle: ${id}`);
    if (visited.has(id)) return;
    visiting.add(id);
    for (const prerequisite of byId.get(id)?.prerequisites ?? []) visit(prerequisite);
    visiting.delete(id);
    visited.add(id);
  };
  for (const id of byId.keys()) visit(id);
}

function validateAgainstSchema(registry: Registry, registryRoot: string): void {
  const schema = readJson<AnySchema>(join(registryRoot, "registry.schema.json"));
  const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);
  const value = {
    manifest: registry.manifest,
    kinds: registry.kinds,
    reason_codes: registry.reason_codes,
    security_invariants: registry.security_invariants,
    features: registry.features,
    objects: registry.objects,
  };
  if (!validate(value)) {
    throw new Error(formatErrors(validate.errors ?? []));
  }
}



function assertUnique<T>(values: T[], message: string): void {
  if (new Set(values).size !== values.length) throw new Error(message);
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number is not valid JCS");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`)
      .join(",")}}`;
  }
  throw new Error(`unsupported JCS value: ${typeof value}`);
}

function resolveRegistryRoot(root: string): string {
  if (existsSync(join(root, "manifest.json"))) return root;
  return join(root, "docs", "spec", "registry");
}

function readJson<T = unknown>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function formatErrors(errors: ErrorObject[]): string {
  return errors
    .map((error) => `${error.instancePath || "/"} ${error.message ?? "failed validation"}`)
    .join("; ");
}
