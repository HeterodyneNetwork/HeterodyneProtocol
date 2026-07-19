import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  assertCommsReleaseGate,
  assertDocumentRegistryDownrefs,
  assertRegistryStatusTransition,
  computeRegistryDigest,
  loadRegistry,
  type Registry,
  type RegistryEntrySet,
  validateRegistry,
} from "./registry.js";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, "../../../../../");

function cloneRegistry(registry: Registry): Registry {
  return structuredClone(registry);
}

function currentEntrySet(registry: Registry): RegistryEntrySet {
  return structuredClone(registry.currentEntrySet);
}

function registryWithHistory(
  registry: Registry,
  previous: RegistryEntrySet,
  current: RegistryEntrySet,
): Registry {
  const changed = cloneRegistry(registry);
  changed.manifest.revision = 2;
  changed.manifest.entry_set_sha256 = computeRegistryDigest(current);
  changed.kinds = current.kinds;
  changed.reason_codes = current.reason_codes;
  changed.security_invariants = current.security_invariants;
  changed.currentEntrySet = current;
  changed.history = new Map([
    [1, previous],
    [2, structuredClone(current)],
  ]);
  return changed;
}

describe("revisioned protocol registry", () => {
  const registry = loadRegistry(repositoryRoot);

  it("loads revision 1 and its immutable current snapshot", () => {
    expect(registry.manifest.revision).toBe(1);
    expect(registry.history.get(1)).toEqual(registry.currentEntrySet);
    expect(
      registry.kinds.find((entry) => entry.kind === 31001)
        ?.base_schema_owner,
    ).toBe("core");
    expect(
      registry.kinds.find((entry) => entry.kind === 31007)
        ?.base_schema_owner,
    ).toBe("comms");
    expect(
      registry.kinds.find((entry) => entry.kind === 10000)
        ?.allocation_authority,
    ).toBe("nostr");
    expect(registry.kinds.some((entry) => entry.kind === 31013)).toBe(false);
    expect(registry.kinds.some((entry) => entry.kind === 31014)).toBe(false);
    expect(registry.kinds.find((entry) => entry.kind === 31015)).toMatchObject({
      base_schema_owner: "comms",
      first_version: "comms/0.5.0",
    });
    expect(registry.kinds.find((entry) => entry.kind === 31016)).toMatchObject({
      base_schema_owner: "comms",
      first_version: "comms/0.5.0",
    });
  });

  it("commits the canonical digest of the current entry set", () => {
    expect(computeRegistryDigest(registry)).toMatch(/^[0-9a-f]{64}$/);
    expect(registry.manifest.entry_set_sha256).toBe(
      computeRegistryDigest(registry),
    );
    expect(() => validateRegistry(registry)).not.toThrow();
  });

  it("validates the manifest against the registry schema", () => {
    const changed = cloneRegistry(registry);
    changed.manifest.schema_version = "2.0.0";
    expect(() => validateRegistry(changed)).toThrow(/schema_version/);
  });

  it("rejects duplicate profile discriminators on one kind", () => {
    const changed = cloneRegistry(registry);
    const kind = changed.kinds.find((entry) => entry.profiles.length > 0);
    if (kind === undefined) {
      throw new Error("test fixture requires a profiled kind");
    }
    kind.profiles.push({ ...kind.profiles[0], profile_id: "duplicate-test" });
    expect(() => validateRegistry(changed)).toThrow(
      "duplicate profile discriminator",
    );
  });

  it("allows only adjacent monotonic status transitions", () => {
    expect(() => assertRegistryStatusTransition("draft", "stable")).not.toThrow();
    expect(() => assertRegistryStatusTransition("stable", "frozen")).not.toThrow();
    expect(() => assertRegistryStatusTransition("draft", "draft")).not.toThrow();
    expect(() => assertRegistryStatusTransition("stable", "draft")).toThrow(
      "invalid registry status transition",
    );
    expect(() => assertRegistryStatusTransition("draft", "frozen")).toThrow(
      "invalid registry status transition",
    );
  });

  it("keeps an allocated profile discriminator immutable", () => {
    const previous = currentEntrySet(registry);
    const current = structuredClone(previous);
    const kind = current.kinds.find((entry) => entry.profiles.length > 0);
    if (kind === undefined) {
      throw new Error("test fixture requires a profiled kind");
    }
    kind.profiles[0].discriminator = "changed-discriminator";
    expect(() =>
      validateRegistry(registryWithHistory(registry, previous, current)),
    ).toThrow("profile discriminator is immutable");
  });

  it("rejects mutation, reassignment, and removal of frozen entries", () => {
    const previous = currentEntrySet(registry);
    previous.kinds[0].status = "frozen";

    const mutated = structuredClone(previous);
    mutated.kinds[0].first_version = "core/0.5.1";
    expect(() =>
      validateRegistry(registryWithHistory(registry, previous, mutated)),
    ).toThrow("frozen entry");

    const reassigned = structuredClone(previous);
    reassigned.kinds[0].base_schema_owner = "social";
    expect(() =>
      validateRegistry(registryWithHistory(registry, previous, reassigned)),
    ).toThrow("frozen entry");

    const removed = structuredClone(previous);
    removed.kinds.shift();
    expect(() =>
      validateRegistry(registryWithHistory(registry, previous, removed)),
    ).toThrow("frozen entry");
  });

  it("requires frozen registry downrefs for 1.0 documents", () => {
    expect(() =>
      assertDocumentRegistryDownrefs("core/0.9.0", ["draft", "stable"]),
    ).not.toThrow();
    expect(() =>
      assertDocumentRegistryDownrefs("core/1.0.0", ["frozen"]),
    ).not.toThrow();
    expect(() =>
      assertDocumentRegistryDownrefs("core/1.0.0", ["stable"]),
    ).toThrow("1.0 document requires frozen registry entries");
  });

  it("blocks Comms 1.0 until the double-ratchet wire is frozen", () => {
    expect(() => assertCommsReleaseGate("comms/0.9.0", "draft")).not.toThrow();
    expect(() => assertCommsReleaseGate("comms/1.0.0", "stable")).toThrow(
      "double-ratchet wire profile must be frozen",
    );
    expect(() => assertCommsReleaseGate("comms/1.0.0", "frozen")).not.toThrow();
  });
});
