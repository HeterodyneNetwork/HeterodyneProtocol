import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  assertRegistryDownrefs,
  assertRegistryStatusTransition,
  computeRegistryDigest,
  loadRegistry,
  resolveStampingProfile,
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
  return structuredClone({
    kinds: registry.kinds,
    reason_codes: registry.reason_codes,
    security_invariants: registry.security_invariants,
    features: registry.features,
    objects: registry.objects,
    proof_domains: registry.proof_domains,
  });
}

describe("revisioned protocol registry", () => {
  const registry = loadRegistry(repositoryRoot);

  it("allocates objects with unique features and acyclic prerequisites", () => {
    expect(registry.manifest.revision).toBeGreaterThan(0);
    expect(registry.features.length).toBeGreaterThan(0);
    expect(new Set(registry.features.map((entry) => entry.id)).size)
      .toBe(registry.features.length);
    expect(registry.features.map((entry) => entry.id)).toEqual(
      expect.arrayContaining([
        "comms.key-claims.v1",
        "comms.private-claim-ledger.v1",
        "comms.oidc-jwt-projection.v1",
        "comms.token-status-list-draft-21.v1",
        "comms.marmot-conversations.v1",
        "comms.radicle-marmot-storage.v1",
        "comms.agent-authorship.v1",
        "workspace.role-authorization.v1",
        "workspace.private-role-control.v1",
        "workspace.radicle-transport-backstop.v1",
        "workspace.resource-key-delivery.v1",
        "workspace.bilateral-allowance.v1",
        "workspace.joint-governance.v1",
      ]),
    );
    expect(registry.objects.map((entry) => entry.id)).toEqual([
      "workspace-manifest-v1",
      "workspace-policy-v1",
      "role-manifest-v1",
      "role-grant-v1",
      "role-revocation-v1",
      "role-checkpoint-v1",
      "resource-advertisement-v1",
      "host-advertisement-v1",
      "service-advertisement-v1",
      "workspace-relationship-v1",
      "joint-workspace-relationship-v1",
      "resource-key-envelope-v1",
    ]);
    expect(() => validateRegistry(registry)).not.toThrow();
  });

  it("allocates the current kind and profile set", () => {
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
      first_version: "heterodyne/0.5.0",
    });
    expect(registry.kinds.find((entry) => entry.kind === 31014)).toMatchObject({
      allocation_authority: "heterodyne",
      base_schema_owner: "comms",
      status: "draft",
      first_version: "heterodyne/0.5.0",
    });
    expect(registry.kinds.find((entry) => entry.kind === 31017)).toMatchObject({
      base_schema_owner: "control",
      first_version: "heterodyne/0.5.0",
      profiles: [expect.objectContaining({
        profile_id: "heterodyne-control-marmot-frame-v1",
        discriminator: "marmot-inner-only;content=control-frame-v1",
        owner: "control",
        stamping: false,
      })],
    });
    expect(registry.kinds.find((entry) => entry.kind === 1059)).toMatchObject({ allocation_authority: "nostr", profiles: [] });
    expect(registry.kinds.find((entry) => entry.kind === 22242)).toMatchObject({ allocation_authority: "nostr", profiles: [] });
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

  it("allocates the agent delegation, attribution, receipt, and policy-list profiles", () => {
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
        first_version: "heterodyne/0.5.0",
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
        profile.first_version === "heterodyne/0.5.0" &&
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
        first_version: "heterodyne/0.5.0",
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
    changed.manifest.schema_version = "1.0.0";
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

  it("requires frozen registry downrefs at 1.0", () => {
    expect(() =>
      assertRegistryDownrefs("heterodyne/0.9.0", ["draft", "stable"]),
    ).not.toThrow();
    expect(() =>
      assertRegistryDownrefs("heterodyne/1.0.0", ["frozen"]),
    ).not.toThrow();
    expect(() =>
      assertRegistryDownrefs("heterodyne/1.0.0", ["stable"]),
    ).toThrow("1.0 specification requires frozen registry entries");
  });
});
