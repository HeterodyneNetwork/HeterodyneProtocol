import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
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

export type RegistryEntrySet = {
  kinds: KindEntry[];
  reason_codes: ReasonCodeEntry[];
  security_invariants: InvariantEntry[];
};

export type Registry = RegistryEntrySet & {
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
  /^heterodyne:(core|comms|control|social)\/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?#[a-z0-9]+(?:-[a-z0-9]+)*$/;

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
  const history = new Map<number, RegistryEntrySet>();
  const historyRoot = join(registryRoot, "history");
  for (const name of readdirSync(historyRoot).sort((left, right) =>
    left.localeCompare(right, "en"),
  )) {
    if (!/^[1-9][0-9]*\.json$/.test(name)) continue;
    history.set(Number.parseInt(basename(name, ".json"), 10), readJson(join(historyRoot, name)));
  }

  const currentEntrySet = { kinds, reason_codes, security_invariants };
  const registry = { manifest, ...currentEntrySet, history, currentEntrySet };
  validateRegistry(registry, registryRoot);
  return registry;
}

export function computeRegistryDigest(
  registry: Pick<Registry, "kinds" | "reason_codes" | "security_invariants">,
): string {
  const entrySet: RegistryEntrySet = {
    kinds: registry.kinds,
    reason_codes: registry.reason_codes,
    security_invariants: registry.security_invariants,
  };
  return createHash("sha256").update(canonicalize(entrySet), "utf8").digest("hex");
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

export function assertCommsReleaseGate(
  documentVersion: string,
  registry: Registry,
): void {
  const parsed = parseQualifiedVersion(documentVersion);
  if (parsed.document !== "comms") {
    throw new Error("Comms release gate requires a comms qualified version");
  }
  const major = Number.parseInt(parsed.semver.split(".", 1)[0], 10);
  if (major < 1) return;

  const requiredProfiles = [
    [1059, "heterodyne-comms-double-ratchet-invite-response-v1"],
    [1060, "heterodyne-comms-double-ratchet-message-v1"],
  ] as const;
  const allFrozen = requiredProfiles.every(([kindNumber, profileId]) =>
    registry.kinds
      .find((entry) => entry.kind === kindNumber)
      ?.profiles.some(
        (profile) => profile.profile_id === profileId && profile.status === "frozen",
      ),
  );
  if (!allFrozen) {
    throw new Error("double-ratchet wire profiles must be frozen before Comms 1.0");
  }
}

function validateUniqueEntries(registry: RegistryEntrySet): void {
  assertUnique(registry.kinds.map((entry) => entry.kind), "duplicate kind");
  assertUnique(registry.reason_codes.map((entry) => entry.code), "duplicate reason code");
  assertUnique(
    registry.security_invariants.map((entry) => entry.id),
    "duplicate security invariant",
  );

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
      if (prior.kind !== kind.kind) {
        throw new Error("profile kind is immutable");
      }
      if (prior.owner !== profile.owner) {
        throw new Error("profile owner is immutable");
      }
      if (prior.discriminator !== profile.discriminator) {
        throw new Error("profile discriminator is immutable");
      }
      assertRegistryStatusTransition(prior.last.status, profile.status);
      if (
        prior.last.status === "frozen" &&
        canonicalize(prior.last) !== canonicalize(profile)
      ) {
        throw new Error("frozen entry changed");
      }
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
