import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv, type AnySchema, type ErrorObject } from "ajv";
import { parseQualifiedVersion } from "./family.js";
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
  /** Absent only from historical snapshots created before revision 6. */
  features?: FeatureEntry[];
  /** Absent from historical snapshots created before revision 8. */
  objects?: ObjectEntry[];
};

export type Registry = RegistryEntrySet & {
  features: FeatureEntry[];
  objects: ObjectEntry[];
  manifest: RegistryManifest;
  history: Map<number, RegistryEntrySet>;
  currentEntrySet: RegistryEntrySet;
};

const STATUS_ORDER: Record<RegistryStatus, number> = {
  draft: 0,
  stable: 1,
  frozen: 2,
};

const QUALIFIED_REFERENCE =
  /^heterodyne:(core|comms|control|social|workspace)\/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?#[a-z0-9]+(?:-[a-z0-9]+)*$/;

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
  const history = new Map<number, RegistryEntrySet>();
  const historyRoot = join(registryRoot, "history");
  for (const name of readdirSync(historyRoot).sort((left, right) =>
    left.localeCompare(right, "en"),
  )) {
    if (!/^[1-9][0-9]*\.json$/.test(name)) continue;
    history.set(Number.parseInt(basename(name, ".json"), 10), readJson(join(historyRoot, name)));
  }

  const currentEntrySet = { kinds, reason_codes, security_invariants, features, objects };
  const registry = { manifest, ...currentEntrySet, history, currentEntrySet };
  validateRegistry(registry, registryRoot);
  return registry;
}

export function computeRegistryDigest(
  registry: Pick<RegistryEntrySet, "kinds" | "reason_codes" | "security_invariants" | "features" | "objects">,
): string {
  const entrySet: RegistryEntrySet = {
    kinds: registry.kinds,
    reason_codes: registry.reason_codes,
    security_invariants: registry.security_invariants,
    ...(registry.features === undefined ? {} : { features: registry.features }),
    ...(registry.objects === undefined ? {} : { objects: registry.objects }),
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
    join(registryRoot, "history", `${revision}.json`),
    `${JSON.stringify(entrySet, null, 2)}\n`,
    "utf8",
  );
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
  validateRegistryHistory(registry.history);
  validateEntryMetadata(registry);

  validateAgainstSchema(registry, registryRoot);
  if (registry.manifest.entry_set_sha256 !== computeRegistryDigest(registry)) {
    throw new Error("registry manifest digest does not match current entry set");
  }

  const snapshot = registry.history.get(registry.manifest.revision);
  if (snapshot === undefined) {
    throw new Error(`missing registry history revision ${registry.manifest.revision}`);
  }
  if (canonicalize(snapshot) !== canonicalize(registry.currentEntrySet)) {
    throw new Error("current registry entry set differs from history snapshot");
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

export function assertDocumentRegistryDownrefs(
  documentVersion: string,
  requiredStatuses: readonly RegistryStatus[],
): void {
  const parsed = parseQualifiedVersion(documentVersion);
  const major = Number.parseInt(parsed.semver.split(".", 1)[0], 10);
  if (major >= 1 && requiredStatuses.some((status) => status !== "frozen")) {
    throw new Error("1.0 document requires frozen registry entries");
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

export function assertCommsReleaseGate(
  documentVersion: string,
  _registry: Registry,
): void {
  const parsed = parseQualifiedVersion(documentVersion);
  if (parsed.document !== "comms") {
    throw new Error("Comms release gate requires a comms qualified version");
  }
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
    assertQualifiedFirstVersion(entry.first_version, entry.base_schema_owner);
    for (const profile of entry.profiles) {
      assertQualifiedFirstVersion(profile.first_version, profile.owner);
    }
  }
  for (const entry of registry.reason_codes) {
    assertQualifiedFirstVersion(entry.first_version, entry.owner);
    for (const ref of entry.spec_refs) {
      if (!QUALIFIED_REFERENCE.test(ref)) {
        throw new Error(`unqualified registry spec reference: ${ref}`);
      }
    }
  }
  for (const entry of registry.security_invariants) {
    assertQualifiedFirstVersion(entry.first_version, entry.owner);
    const prefix = `${entry.owner.toUpperCase()}-I-`;
    if (!entry.id.startsWith(prefix)) {
      throw new Error(`security invariant owner mismatch: ${entry.id}`);
    }
  }
  validateFeatures(registry.features ?? []);
  for (const entry of registry.objects ?? []) {
    assertQualifiedFirstVersion(entry.first_version, entry.owner);
    assertUnique(entry.carriers, `duplicate object carrier: ${entry.id}`);
  }
}

function validateFeatures(features: FeatureEntry[]): void {
  const byId = new Map(features.map((entry) => [entry.id, entry]));
  for (const entry of features) {
    if (!entry.id.startsWith(`${entry.owner}.`)) {
      throw new Error(`feature owner mismatch: ${entry.id}`);
    }
    assertQualifiedFirstVersion(entry.first_version, entry.owner);
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

export function validateRegistryHistory(
  history: ReadonlyMap<number, RegistryEntrySet>,
): void {
  const revisions = [...history.keys()].sort((left, right) => left - right);
  const historicalProfiles = new Map<
    string,
    { kind: number; owner: DocumentId; discriminator: string; last: KindProfile }
  >();
  const historicalKinds = new Map<string, { last: KindEntry }>();
  const historicalReasonCodes = new Map<string, { last: ReasonCodeEntry }>();
  const historicalInvariants = new Map<string, { last: InvariantEntry }>();
  const historicalFeatures = new Map<string, { last: FeatureEntry }>();
  const historicalObjects = new Map<string, { last: ObjectEntry }>();
  for (let index = 0; index < revisions.length; index += 1) {
    if (revisions[index] !== index + 1) {
      throw new Error("registry history revisions must be contiguous from 1");
    }
    const current = history.get(revisions[index])!;
    validateUniqueEntries(current);
    validateHistoricalCollection(
      current.kinds,
      historicalKinds,
      (entry) => String(entry.kind),
    );
    validateHistoricalCollection(
      current.reason_codes,
      historicalReasonCodes,
      (entry) => entry.code,
    );
    validateHistoricalCollection(
      current.security_invariants,
      historicalInvariants,
      (entry) => entry.id,
    );
    validateFeatures(current.features ?? []);
    validateHistoricalCollection(
      current.features ?? [],
      historicalFeatures,
      (entry) => entry.id,
    );
    validateHistoricalCollection(
      current.objects ?? [],
      historicalObjects,
      (entry) => entry.id,
    );
    validateHistoricalProfiles(current, historicalProfiles);
  }
}

function validateHistoricalProfiles(
  current: RegistryEntrySet,
  historical: Map<
    string,
    { kind: number; owner: DocumentId; discriminator: string; last: KindProfile }
  >,
): void {
  const present = new Set<string>();
  for (const kind of current.kinds) {
    for (const profile of kind.profiles) {
      present.add(profile.profile_id);
      const prior = historical.get(profile.profile_id);
      if (prior === undefined) {
        historical.set(profile.profile_id, {
          kind: kind.kind,
          owner: profile.owner,
          discriminator: profile.discriminator,
          last: profile,
        });
        continue;
      }
      assertRegistryStatusTransition(prior.last.status, profile.status);
      if (
        prior.last.status === "frozen" &&
        (prior.kind !== kind.kind
          || prior.owner !== profile.owner
          || prior.discriminator !== profile.discriminator
          || canonicalize(prior.last) !== canonicalize(profile))
      ) {
        throw new Error("frozen entry changed");
      }
      prior.kind = kind.kind;
      prior.owner = profile.owner;
      prior.discriminator = profile.discriminator;
      prior.last = profile;
    }
  }

  for (const [profileId, prior] of historical) {
    if (prior.last.status === "frozen" && !present.has(profileId)) {
      throw new Error("frozen entry removed");
    }
  }
}

function validateHistoricalCollection<T extends { status: RegistryStatus }>(
  current: T[],
  historical: Map<string, { last: T }>,
  key: (entry: T) => string,
): void {
  const present = new Set<string>();
  for (const entry of current) {
    const entryKey = key(entry);
    present.add(entryKey);
    const prior = historical.get(entryKey);
    if (prior === undefined) {
      historical.set(entryKey, { last: entry });
      continue;
    }
    assertRegistryStatusTransition(prior.last.status, entry.status);
    if (
      prior.last.status === "frozen" &&
      canonicalize(prior.last) !== canonicalize(entry)
    ) {
      throw new Error("frozen entry changed");
    }
    prior.last = entry;
  }

  for (const [entryKey, prior] of historical) {
    if (prior.last.status === "frozen" && !present.has(entryKey)) {
      throw new Error("frozen entry removed");
    }
  }
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

function assertQualifiedFirstVersion(
  value: string,
  expectedOwner: DocumentId | "nostr",
): void {
  const parsed = parseQualifiedVersion(value);
  if (expectedOwner !== "nostr" && parsed.document !== expectedOwner) {
    throw new Error(`first version owner mismatch: ${value}`);
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
