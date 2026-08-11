import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  assertCommsReleaseGate,
  assertDocumentRegistryDownrefs,
  assertRegistryStatusTransition,
  computeRegistryDigest,
  loadRegistry,
  resolveStampingProfile,
  type Registry,
  type RegistryEntrySet,
  validateRegistry,
  validateRegistryHistory,
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

  it("loads revision 5 while retaining historical revision 1 through 4 snapshots", () => {
    expect(registry.manifest.revision).toBe(5);
    expect(registry.history.get(5)).toEqual(registry.currentEntrySet);
    expect(registry.history.has(1)).toBe(true);
    expect(registry.history.has(2)).toBe(true);
    expect(registry.history.has(3)).toBe(true);
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
    expect(registry.kinds.find((entry) => entry.kind === 31013)).toMatchObject({
      allocation_authority: "heterodyne",
      base_schema_owner: "comms",
      status: "draft",
      first_version: "comms/0.5.0",
    });
    expect(registry.kinds.find((entry) => entry.kind === 31014)).toMatchObject({
      allocation_authority: "heterodyne",
      base_schema_owner: "comms",
      status: "draft",
      first_version: "comms/0.5.0",
    });
    expect(registry.kinds.find((entry) => entry.kind === 31017)).toMatchObject({
      base_schema_owner: "control",
      first_version: "control/0.5.0",
      profiles: [expect.objectContaining({
        profile_id: "heterodyne-control-marmot-frame-v1",
        discriminator: "marmot-inner-only;content=control-frame-v1",
        owner: "control",
        stamping: false,
      })],
    });
    expect(registry.kinds.find((entry) => entry.kind === 1059)).toBeUndefined();
    expect(registry.kinds.find((entry) => entry.kind === 1060)).toBeUndefined();
    expect(registry.kinds.find((entry) => entry.kind === 31015)).toBeUndefined();
    expect(registry.kinds.find((entry) => entry.kind === 31016)).toBeUndefined();
    expect(registry.kinds.find((entry) => entry.kind === 30078)).toBeUndefined();
  });

  it("registers upstream Marmot transport kinds without Heterodyne stamping", () => {
    for (const kind of [444, 445, 30443]) {
      expect(registry.kinds.find((entry) => entry.kind === kind)).toMatchObject({
        allocation_authority: "nostr",
        profiles: [],
      });
    }
  });

  it("allocates the revision 3 agent delegation, attribution, receipt, and policy-list profiles", () => {
    const expected = [
      [31001, "heterodyne-comms-agent-signing-delegation-v1", "comms", false],
      [1, "heterodyne-comms-agent-attribution-kind-1-v1", "comms", false],
      [6, "heterodyne-comms-agent-attribution-kind-6-v1", "comms", false],
      [7, "heterodyne-comms-agent-attribution-kind-7-v1", "comms", false],
      [16, "heterodyne-comms-agent-attribution-kind-16-v1", "comms", false],
      [1063, "heterodyne-comms-agent-attribution-kind-1063-v1", "comms", false],
      [1985, "heterodyne-comms-agent-attribution-kind-1985-v1", "comms", false],
      [4550, "heterodyne-comms-agent-attribution-kind-4550-v1", "comms", false],
      [30023, "heterodyne-comms-agent-attribution-kind-30023-v1", "comms", false],
      [1985, "heterodyne-social-agent-policy-receipt-v1", "social", true],
      [10000, "heterodyne-social-agent-policy-list-v1", "social", true],
    ] as const;

    for (const [kind, profileId, owner, stamping] of expected) {
      expect(
        registry.kinds.find((entry) => entry.kind === kind)?.profiles
          .find((profile) => profile.profile_id === profileId),
      ).toMatchObject({
        owner,
        stamping,
        status: "draft",
        first_version: `${owner}/0.5.0`,
      });
    }
  });

  it("allocates distinct immutable native-proof discriminators for claims and revocations", () => {
    const expectedProfileIds = new Map([
      [31013, [
        "heterodyne-comms-key-claim-nostr-bip340-v1",
        "heterodyne-comms-key-claim-radicle-ed25519-v1",
        "heterodyne-comms-key-claim-jwk-jws-v1",
      ]],
      [31014, [
        "heterodyne-comms-claim-revocation-nostr-bip340-v1",
        "heterodyne-comms-claim-revocation-radicle-ed25519-v1",
        "heterodyne-comms-claim-revocation-jwk-jws-v1",
      ]],
    ]);
    for (const kindNumber of [31013, 31014]) {
      const profiles = registry.kinds.find((entry) => entry.kind === kindNumber)?.profiles;
      expect(profiles?.map((profile) => profile.profile_id)).toEqual(
        expectedProfileIds.get(kindNumber),
      );
      expect(profiles?.map((profile) => profile.discriminator)).toEqual(
        kindNumber === 31013
          ? [
              "production-rule:claim-subject-pop;proof=nostr-bip340-v1",
              "production-rule:claim-subject-pop;proof=radicle-ed25519-v1",
              "production-rule:claim-subject-pop;proof=jwk-jws-v1",
            ]
          : [
              "production-rule:claim-revoker;proof=nostr-bip340-v1",
              "production-rule:claim-revoker;proof=radicle-ed25519-v1",
              "production-rule:claim-revoker;proof=jwk-jws-v1",
            ],
      );
      expect(profiles?.every((profile) =>
        profile.owner === "comms" &&
        profile.first_version === "comms/0.5.0" &&
        profile.status === "draft" &&
        profile.stamping === false,
      )).toBe(true);
      expect(new Set(profiles?.map((profile) => profile.discriminator)).size).toBe(3);
    }
    const profileIds = registry.kinds.flatMap((entry) =>
      entry.profiles.map((profile) => profile.profile_id),
    );
    expect(new Set(profileIds).size).toBe(profileIds.length);
  });

  it("allocates every claims, ledger, OIDC, and status reason code and invariant", () => {
    const reasonCodes = registry.reason_codes.map((entry) => entry.code);
    expect(reasonCodes).toEqual(expect.arrayContaining([
      "claim-schema-invalid",
      "claim-id-mismatch",
      "claim-key-reference-invalid",
      "claim-event-signature-invalid",
      "claim-issuer-authority-invalid",
      "claim-issuer-untrusted",
      "claim-chain-cycle",
      "claim-chain-depth-exceeded",
      "claim-delegation-not-authorized",
      "claim-attenuation-violation",
      "claim-subject-proof-required",
      "claim-subject-proof-invalid",
      "claim-repository-unconfirmed",
      "claim-repository-conflict",
      "claim-expired",
      "claim-revoked",
      "claim-revoker-unauthorized",
      "claim-ledger-reader-unauthorized",
      "claim-ledger-rollback",
      "oidc-issuer-authority-invalid",
      "oidc-signing-key-unavailable",
      "oidc-checkpoint-stale",
      "oidc-client-unregistered",
      "oidc-grant-prohibited",
      "oidc-consent-required",
      "oidc-claim-release-denied",
      "oidc-issuer-mismatch",
      "oidc-token-type-invalid",
      "oidc-audience-invalid",
      "oidc-status-stale",
      "oidc-status-digest-mismatch",
      "oidc-status-index-invalid",
      "oidc-status-invalid",
    ]));

    const invariantIds = registry.security_invariants.map((entry) => entry.id);
    expect(invariantIds).toEqual(expect.arrayContaining([
      "COMMS-I-CLAIM-AUTHENTICITY",
      "COMMS-I-CLAIM-ATTENUATION",
      "COMMS-I-CLAIM-REPOSITORY-AUTHORITY",
      "COMMS-I-CLAIM-REVOCATION",
      "COMMS-I-LEDGER-CONFINEMENT",
      "COMMS-I-ISSUER-KEY-CONFINEMENT",
      "COMMS-I-MINT-FRESHNESS",
      "COMMS-I-ISSUER-CONTINUITY",
      "COMMS-I-CLAIM-RELEASE",
      "COMMS-I-JWT-TYPE-AUDIENCE",
      "COMMS-I-STATUS-INTEGRITY",
    ]));
  });

  it("preserves historical snapshots and snapshots revision 5", () => {
    const history1 = JSON.parse(readFileSync(
      resolve(repositoryRoot, "docs/spec/registry/history/1.json"),
      "utf8",
    )) as RegistryEntrySet;
    const history2 = JSON.parse(readFileSync(
      resolve(repositoryRoot, "docs/spec/registry/history/2.json"),
      "utf8",
    )) as RegistryEntrySet;
    const history3 = JSON.parse(readFileSync(
      resolve(repositoryRoot, "docs/spec/registry/history/3.json"),
      "utf8",
    )) as RegistryEntrySet;
    const history4 = JSON.parse(readFileSync(
      resolve(repositoryRoot, "docs/spec/registry/history/4.json"),
      "utf8",
    )) as RegistryEntrySet;
    const history5 = JSON.parse(readFileSync(
      resolve(repositoryRoot, "docs/spec/registry/history/5.json"),
      "utf8",
    )) as RegistryEntrySet;

    for (const previous of history1.kinds) {
      const current = history2.kinds.find((entry) => entry.kind === previous.kind);
      expect(JSON.stringify(current)).toBe(JSON.stringify(previous));
    }
    for (const previous of history1.reason_codes) {
      const current = history2.reason_codes.find((entry) => entry.code === previous.code);
      expect(JSON.stringify(current)).toBe(JSON.stringify(previous));
    }
    for (const previous of history1.security_invariants) {
      const current = history2.security_invariants.find((entry) => entry.id === previous.id);
      expect(JSON.stringify(current)).toBe(JSON.stringify(previous));
    }

    for (const previous of history2.kinds) {
      const current = history3.kinds.find((entry) => entry.kind === previous.kind);
      expect(current).toBeDefined();
      const { profiles: previousProfiles, ...previousBase } = previous;
      const { profiles: currentProfiles, ...currentBase } = current!;
      expect(currentBase).toEqual(previousBase);
      for (const previousProfile of previousProfiles) {
        expect(
          currentProfiles.find((profile) => profile.profile_id === previousProfile.profile_id),
        ).toEqual(previousProfile);
      }
    }
    for (const previous of history2.reason_codes) {
      const current = history3.reason_codes.find((entry) => entry.code === previous.code);
      expect(current).toEqual(previous);
    }
    for (const previous of history2.security_invariants) {
      const current = history3.security_invariants.find((entry) => entry.id === previous.id);
      expect(current).toEqual(previous);
    }

    expect(history4).not.toEqual(registry.currentEntrySet);
    expect(history5).toEqual(registry.currentEntrySet);
    expect(registry.manifest.entry_set_sha256).toBe(computeRegistryDigest(history5));
  });

  it("commits the canonical digest of the current entry set", () => {
    expect(computeRegistryDigest(registry)).toMatch(/^[0-9a-f]{64}$/);
    expect(registry.manifest.entry_set_sha256).toBe(
      computeRegistryDigest(registry),
    );
    expect(() => validateRegistry(registry)).not.toThrow();
  });

  it("registers the closed Tier-3 wrapped-content stamping profile set", () => {
    const allocations = [
      [1, "heterodyne-comms-tier3-wrapped-content-kind-1-v1"],
      [6, "heterodyne-comms-tier3-wrapped-content-kind-6-v1"],
      [16, "heterodyne-comms-tier3-wrapped-content-kind-16-v1"],
      [1063, "heterodyne-comms-tier3-wrapped-content-kind-1063-v1"],
      [30023, "heterodyne-comms-tier3-wrapped-content-kind-30023-v1"],
      [30402, "heterodyne-comms-tier3-wrapped-content-kind-30402-v1"],
    ] as const;
    const profileIds = new Set<string>();

    for (const [kindNumber, profileId] of allocations) {
      const profile = registry.kinds
        .find((entry) => entry.kind === kindNumber)
        ?.profiles.find((entry) => entry.profile_id === profileId);
      expect(profile, `missing Tier-3 profile for kind ${kindNumber}`).toMatchObject({
        profile_id: profileId,
        discriminator: "tag:heterodyne_wrap=room_key.v2",
        owner: "comms",
        stamping: true,
        first_version: "comms/0.5.0",
        status: "draft",
      });
      expect(
        resolveStampingProfile(
          registry,
          kindNumber,
          "tag:heterodyne_wrap=room_key.v2",
        )?.owner,
      ).toBe("comms");
      profileIds.add(profileId);
    }

    expect(profileIds.size).toBe(allocations.length);
    expect(
      registry.kinds
        .find((entry) => entry.kind === 1)
        ?.profiles.map((profile) => profile.profile_id),
    ).toEqual(
      expect.arrayContaining([
        "heterodyne-core-rotation-breadcrumb-note-v1",
        "heterodyne-comms-tier3-wrapped-content-kind-1-v1",
      ]),
    );
  });

  it("does not resolve unregistered or Heterodyne-base Tier-3 profiles", () => {
    expect(
      resolveStampingProfile(
        registry,
        7,
        "tag:heterodyne_wrap=room_key.v2",
      ),
    ).toBeNull();
    expect(
      resolveStampingProfile(
        registry,
        31007,
        "tag:heterodyne_wrap=room_key.v2",
      ),
    ).toBeNull();
    expect(
      registry.kinds.find((entry) => entry.kind === 31007)?.base_schema_owner,
    ).toBe("comms");
  });

  it("validates the manifest against the registry schema", () => {
    const changed = cloneRegistry(registry);
    changed.manifest.schema_version = "2.0.0";
    expect(() => validateRegistry(changed)).toThrow(/schema_version/);
  });

  it("keeps hyphenated and underscored reason codes structurally strict", () => {
    for (const invalidCode of [
      "-leading",
      "trailing-",
      "double--separator",
      "double__separator",
      "mixed-_separator",
      "Uppercase",
      "white space",
    ]) {
      const changed = cloneRegistry(registry);
      changed.reason_codes[0].code = invalidCode;
      expect(() => validateRegistry(changed), invalidCode).toThrow();
    }
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

  it("rejects stable kind downgrade after an absent revision", () => {
    const first = currentEntrySet(registry);
    const entry = first.kinds.find((kind) => kind.kind === 3);
    if (entry === undefined) throw new Error("missing kind 3 fixture");
    entry.status = "stable";
    const second = structuredClone(first);
    second.kinds = second.kinds.filter((kind) => kind.kind !== entry.kind);
    const third = structuredClone(second);
    third.kinds.push({ ...entry, status: "draft" });

    expect(() =>
      validateRegistryHistory(
        new Map([
          [1, first],
          [2, second],
          [3, third],
        ]),
      ),
    ).toThrow("invalid registry status transition");
  });

  it("rejects reason-code state skipping after an absent revision", () => {
    const first = currentEntrySet(registry);
    const entry = first.reason_codes[0];
    const second = structuredClone(first);
    second.reason_codes = second.reason_codes.filter(
      (reason) => reason.code !== entry.code,
    );
    const third = structuredClone(second);
    third.reason_codes.push({ ...entry, status: "frozen" });

    expect(() =>
      validateRegistryHistory(
        new Map([
          [1, first],
          [2, second],
          [3, third],
        ]),
      ),
    ).toThrow("invalid registry status transition");
  });

  it("rejects invariant downgrade after an absent revision", () => {
    const first = currentEntrySet(registry);
    const entry = first.security_invariants[0];
    entry.status = "stable";
    const second = structuredClone(first);
    second.security_invariants = second.security_invariants.filter(
      (invariant) => invariant.id !== entry.id,
    );
    const third = structuredClone(second);
    third.security_invariants.push({ ...entry, status: "draft" });

    expect(() =>
      validateRegistryHistory(
        new Map([
          [1, first],
          [2, second],
          [3, third],
        ]),
      ),
    ).toThrow("invalid registry status transition");
  });

  it("allows an adjacent top-level progression after an absent revision", () => {
    const first = currentEntrySet(registry);
    const entry = first.reason_codes[0];
    const second = structuredClone(first);
    second.reason_codes = second.reason_codes.filter(
      (reason) => reason.code !== entry.code,
    );
    const third = structuredClone(second);
    third.reason_codes.push({ ...entry, status: "stable" });

    expect(() =>
      validateRegistryHistory(
        new Map([
          [1, first],
          [2, second],
          [3, third],
        ]),
      ),
    ).not.toThrow();
  });

  it("permits draft profile discriminator changes before 1.0", () => {
    const previous = currentEntrySet(registry);
    const current = structuredClone(previous);
    const kind = current.kinds.find((entry) => entry.profiles.length > 0);
    if (kind === undefined) {
      throw new Error("test fixture requires a profiled kind");
    }
    kind.profiles[0].discriminator = "changed-discriminator";
    expect(() =>
      validateRegistry(registryWithHistory(registry, previous, current)),
    ).not.toThrow();
  });

  it("rejects removal of a frozen profile with its draft parent kind", () => {
    const previous = currentEntrySet(registry);
    const kind = previous.kinds.find((entry) => entry.kind === 31017);
    const profile = kind?.profiles.find((entry) =>
      entry.profile_id === "heterodyne-control-marmot-frame-v1");
    if (kind === undefined || profile === undefined) {
      throw new Error("missing kind 31017 profile fixture");
    }
    expect(kind.status).toBe("draft");
    profile.status = "frozen";
    const current = structuredClone(previous);
    current.kinds = current.kinds.filter((entry) => entry.kind !== 31017);

    expect(() =>
      validateRegistryHistory(
        new Map([
          [1, previous],
          [2, current],
        ]),
      ),
    ).toThrow("frozen entry");
  });

  it("permits moving a draft profile before 1.0", () => {
    const previous = currentEntrySet(registry);
    const current = structuredClone(previous);
    const source = current.kinds.find((entry) => entry.kind === 31017);
    const target = current.kinds.find((entry) => entry.kind === 31014);
    const profile = source?.profiles.shift();
    if (target === undefined || profile === undefined) {
      throw new Error("missing Control profile fixtures");
    }
    target.profiles.push(profile);

    expect(() =>
      validateRegistryHistory(
        new Map([
          [1, previous],
          [2, current],
        ]),
      ),
    ).not.toThrow();
  });

  it("permits changing a draft profile owner before 1.0", () => {
    const previous = currentEntrySet(registry);
    const current = structuredClone(previous);
    const profile = current.kinds
      .find((entry) => entry.kind === 31017)
      ?.profiles.find((entry) => entry.profile_id === "heterodyne-control-marmot-frame-v1");
    if (profile === undefined) throw new Error("missing kind 31017 profile fixture");
    profile.owner = "social";
    profile.first_version = "social/0.5.0";

    expect(() =>
      validateRegistryHistory(
        new Map([
          [1, previous],
          [2, current],
        ]),
      ),
    ).not.toThrow();
  });

  it("permits changed draft discriminator after removal and reintroduction", () => {
    const first = currentEntrySet(registry);
    const profile = first.kinds
      .find((entry) => entry.kind === 31017)
      ?.profiles.find((entry) => entry.profile_id === "heterodyne-control-marmot-frame-v1");
    if (profile === undefined) throw new Error("missing kind 31017 profile fixture");
    const second = structuredClone(first);
    second.kinds.find((entry) => entry.kind === 31017)!.profiles = [];
    const third = structuredClone(second);
    third.kinds
      .find((entry) => entry.kind === 31017)!
      .profiles.push({ ...profile, discriminator: "changed-after-gap" });

    expect(() =>
      validateRegistryHistory(
        new Map([
          [1, first],
          [2, second],
          [3, third],
        ]),
      ),
    ).not.toThrow();
  });

  it("allows matching non-frozen profile reintroduction", () => {
    const first = currentEntrySet(registry);
    const profile = first.kinds
      .find((entry) => entry.kind === 31017)
      ?.profiles.find((entry) => entry.profile_id === "heterodyne-control-marmot-frame-v1");
    if (profile === undefined) throw new Error("missing kind 31017 profile fixture");
    const second = structuredClone(first);
    second.kinds.find((entry) => entry.kind === 31017)!.profiles = [];
    const third = structuredClone(second);
    third.kinds.find((entry) => entry.kind === 31017)!.profiles.push(profile);

    expect(() =>
      validateRegistryHistory(
        new Map([
          [1, first],
          [2, second],
          [3, third],
        ]),
      ),
    ).not.toThrow();
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

  it("has no Comms-specific release gate beyond the family registry rule", () => {
    expect(() => assertCommsReleaseGate("comms/0.9.0", registry)).not.toThrow();
    expect(() => assertCommsReleaseGate("comms/1.0.0", registry)).not.toThrow();
    expect(() => assertCommsReleaseGate("core/1.0.0", registry)).toThrow(
      "Comms release gate requires a comms qualified version",
    );
  });
});
