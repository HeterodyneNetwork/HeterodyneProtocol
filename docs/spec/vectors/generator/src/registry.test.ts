import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { matchesAgentAttributionProfile } from "./agent-authorship.js";
import {
  assertRegistryDownrefs,
  assertRegistryStatusTransition,
  computeRegistryDigest,
  loadRegistry,
  validateRegisteredKindProfile,
  resolveStampingProfile,
  type ObjectEntry,
  type Registry,
  type RegistryEntrySet,
  validateRegistry,
} from "./registry.js";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, "../../../../../");

const REVISION_15_IDENTITY_FIRST_VERSION_SHA256 =
  "679e0bfd5b7f020f0c53153e6f8c2dadfe425fcf83b165c22aa5a7068ba8edef";

const REVISION_16_ENTRY_SET_SHA256 =
  "5ff98ff2af3bcbb413918dc207dcfc5da7035e9751e9836680df9b56a2b2230f";

const REVISION_16_IDENTITY_TUPLES_SHA256 =
  "852355247956e80edfc1e987d5e46c6f1c15b47c635d2f176d69450967806a26";

const REVISION_17_REASON_REFINEMENTS = [
  ["agent-attribution-bypass-prohibited", "Retained non-wire history for the retired diagnostic that classified omitted, altered, or falsified canonical agent attribution; current attribution-before-signing is governed by live publication authority.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-human-profile-prohibited", "Retained non-wire history for the retired diagnostic that classified bypass of the selected persona vault, signer, or key class; current signer selection is governed by live publication authority.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-key-access-prohibited", "Retained non-wire history for the retired diagnostic that classified requests for private key material or raw signing authority; current key confinement is governed by live signer boundaries.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-method-prohibited", "Retained non-wire history for the retired diagnostic that classified methods outside the closed agentic Control surface; current method authorization is governed by exact grants.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-resource-denied", "Retained non-wire history for the retired diagnostic that classified operations outside an exact active signer grant; current resource authorization is governed by exact grants.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-sender-proof-invalid", "The required per-use DPoP/JWK proof is missing, replayed, malformed, or mismatched with the verified token, registered sender key, method, target, or nonce.", "heterodyne:0.6.0#comms-agent-token"],
  ["auth_rejected_permanent", "Local relay-write diagnostic for a repeated post-NIP-42 AUTH rejection; it is diagnostic-only and non-wire for semantic coverage and proves no cryptographic or upstream authority.", "heterodyne:0.6.0#comms-retired-semantics"],
  ["control-keypackage-replenishment-paused", "Authenticated current enrollment state marks public Control KeyPackage replenishment as paused.", "heterodyne:0.6.0#control-invitation-policy"],
  ["control-request-id-conflict", "Retained non-wire history for the retired diagnostic that classified request-identifier reuse with different canonical bound bytes; current at-most-once execution is governed by the durable signer fence.", "heterodyne:0.6.0#control-retired-semantics"],
  ["control-signed-event-invalid", "Retained non-wire history for the retired diagnostic that classified altered or invalid signer output; current signer-output verification is governed by publication and signer-fence boundaries.", "heterodyne:0.6.0#control-retired-semantics"],
  ["dm_invite_revoked_device", "Retained non-wire history for the retired kind:30078 device-revocation diagnostic; current invitation authentication and revocation boundaries do not emit this code.", "heterodyne:0.6.0#comms-retired-semantics"],
  ["dm_invite_unbound_device", "Retained non-wire history for the retired kind:30078 device-delegation diagnostic; current invitation authentication and account-binding boundaries do not emit this code.", "heterodyne:0.6.0#comms-retired-semantics"],
  ["invite-preauthorization-invalid", "The signed Control invite, exact preauthorization template, client binding, purpose, expiry, or current revocation state does not authorize the captured request.", "heterodyne:0.6.0#control-one-time-invites"],
  ["marmot-agent-scope-denied", "The authenticated current persona-inbox authorization does not permit the captured agent sender, request, or required first-contact scope.", "heterodyne:0.6.0#comms-marmot-persona-inbox"],
  ["marmot-keypackage-replayed", "The selected Marmot KeyPackage is already durably consumed by authenticated inbox state or a closed available or committed reservation.", "heterodyne:0.6.0#comms-marmot-persona-inbox"],
  ["marmot-private-inbox-nid-required", "The authenticated current recipient repository authorization lacks the NID binding required for private persona-inbox admission.", "heterodyne:0.6.0#comms-marmot-persona-inbox"],
  ["profile-repository-selection-required", "The selected canonical profile requires authenticated repository state, but no current writer-authenticated repository candidate supplies it.", "heterodyne:0.6.0#core-persona-profile"],
  ["relay_profile_mutation", "The retained raw profile-event bytes do not exactly match a valid NIP-01 event identifier, signature, or exposed event fields.", "heterodyne:0.6.0#core-operational-authority-views"],
  ["retired-key-authority-window-invalid", "Retained non-wire history for retired-key content outside a former key-authority window; current Core verification and source-neutral selection do not emit this code.", "heterodyne:0.6.0#core-retired-semantics"],
  ["revoked_key_post_compromise", "Retained non-wire history for the retired duplicate classification at or after an accepted compromise_since cutoff; current Assurance uses evaluateAssuranceAuthorityAt.", "heterodyne:0.6.0#assurance-retired-semantics"],
  ["strict_mode_tor_disabled", "The captured client role claims the strict profile while the current transport route is not Tor.", "heterodyne:0.6.0#core-operational-authority-views"],
  ["unauthorized_cache_content", "A friend-cache candidate lacks an exact valid NIP-01 signature by the expected persona author.", "heterodyne:0.6.0#core-operational-authority-views"],
  ["workspace_replay", "A Workspace invitation or other consuming authority input was reused with mismatched bindings or before its exact committed terminal was established.", "heterodyne:0.6.0#workspace-errors"],
] as const;

const TASK_9_NEW_FIRST_VERSION_ROWS = new Set([
  "object:repository-writer-binding-v1:heterodyne/0.6.0",
  "proof-domain:heterodyne-core-repository-writer-binding-v1:heterodyne/0.6.0",
  "reason-code:repository-writer-binding-invalid:heterodyne/0.6.0",
  "reason-code:claim-ledger-writer-unauthorized:heterodyne/0.6.0",
  "reason-code:claim-subject-proof-replayed:heterodyne/0.6.0",
  "reason-code:claim-authorization-effect-indeterminate:heterodyne/0.6.0",
]);

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

function firstVersionRows(registry: Registry): string[] {
  return [
    ...registry.features.map(({ id, first_version }) =>
      `feature:${id}:${first_version}`),
    ...registry.kinds.map(({ kind, first_version }) =>
      `kind:${kind}:${first_version}`),
    ...registry.kinds.flatMap(({ kind, profiles }) =>
      profiles.map(({ profile_id, first_version }) =>
        `kind-profile:${kind}:${profile_id}:${first_version}`)),
    ...registry.objects.map(({ id, first_version }) =>
      `object:${id}:${first_version}`),
    ...registry.proof_domains.map(({ id, first_version }) =>
      `proof-domain:${id}:${first_version}`),
    ...registry.reason_codes.map(({ code, first_version }) =>
      `reason-code:${code}:${first_version}`),
    ...registry.security_invariants.map(({ id, first_version }) =>
      `security-invariant:${id}:${first_version}`),
  ].sort();
}

function identityTuples(registry: Registry): Array<[string, string, string, string, string]> {
  return [
    ...registry.features.map(({ id, owner, status, first_version }) =>
      ["feature", id, owner, status, first_version] as [string, string, string, string, string]),
    ...registry.kinds.map(({ kind, allocation_authority, status, first_version }) =>
      ["kind", String(kind), allocation_authority, status, first_version] as [string, string, string, string, string]),
    ...registry.kinds.flatMap(({ kind, profiles }) => profiles.map(
      ({ profile_id, owner, status, first_version }) =>
        ["kind-profile", `${kind}:${profile_id}`, owner, status, first_version] as [string, string, string, string, string],
    )),
    ...registry.objects.map(({ id, owner, status, first_version }) =>
      ["object", id, owner, status, first_version] as [string, string, string, string, string]),
    ...registry.proof_domains.map(({ id, owner, status, first_version }) =>
      ["proof-domain", id, owner, status, first_version] as [string, string, string, string, string]),
    ...registry.reason_codes.map(({ code, owner, status, first_version }) =>
      ["reason-code", code, owner, status, first_version] as [string, string, string, string, string]),
    ...registry.security_invariants.map(({ id, owner, status, first_version }) =>
      ["security-invariant", id, owner, status, first_version] as [string, string, string, string, string]),
  ].sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

const NEW_0_6_REGISTRY_IDS = {
  features: [],
  kinds: [1040, 31006],
  kind_profiles: ["heterodyne-assurance-enrollment-contest-profile-v1"],
  objects: [
    "enrollment-observation-receipt-v1",
    "repository-writer-binding-v1",
  ],
  proof_domains: [
    "heterodyne-assurance-enrollment-observation-v1",
    "heterodyne-workspace-assurance-authorization-v1",
    "heterodyne-core-repository-writer-binding-v1",
  ],
  reason_codes: [
    "repository-writer-binding-invalid",
    "claim-subject-proof-replayed",
    "claim-authorization-effect-indeterminate",
    "claim-ledger-writer-unauthorized",
    "core-created-at-premature",
    "workspace-assurance-state-required",
    "assurance-enrollment-pending-window",
    "assurance-enrollment-contested",
  ],
  security_invariants: [
    "WORKSPACE-I-OPTIONAL-ASSURANCE",
    "ASSURANCE-I-ENROLLMENT-WINDOWED",
    "COMMS-I-TIER3-CONFINED",
  ],
} as const;

describe("revisioned protocol registry", () => {
  const registry = loadRegistry(repositoryRoot);

  it("BLUE TEAM VALIDATION: synthetic/local preserves revision 16 identities in immutable revision 17", () => {
    expect(registry.manifest.revision).toBe(17);
    expect(REVISION_16_ENTRY_SET_SHA256).toBe(
      "5ff98ff2af3bcbb413918dc207dcfc5da7035e9751e9836680df9b56a2b2230f",
    );
    const rows = identityTuples(registry);
    expect(rows).toHaveLength(458);
    expect(createHash("sha256").update(JSON.stringify(rows)).digest("hex"))
      .toBe(REVISION_16_IDENTITY_TUPLES_SHA256);
  });

  it("BLUE TEAM VALIDATION: synthetic/local revision 17 retargets retired security diagnostics and live authority reasons", () => {
    const reasonByCode = new Map(registry.reason_codes.map((entry) => [entry.code, entry]));
    for (const [code, description, specRef] of REVISION_17_REASON_REFINEMENTS) {
      expect(reasonByCode.get(code)).toMatchObject({
        description,
        spec_refs: [specRef],
      });
    }
  });

  it("preserves the complete Task 2-8 authority set through immutable revision 17", () => {
    expect(registry.manifest.revision).toBe(17);

    expect(registry.objects.find(
      ({ id }) => id === "repository-writer-binding-v1",
    )).toEqual({
      id: "repository-writer-binding-v1",
      owner: "core",
      first_version: "heterodyne/0.6.0",
      status: "draft",
      schema: "https://heterodyne.network/schemas/core/repository-writer-binding-v1.schema.json",
      carriers: ["radicle-authority-file"],
    });

    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-core-repository-writer-binding-v1",
    )).toEqual({
      id: "heterodyne-core-repository-writer-binding-v1",
      owner: "core",
      first_version: "heterodyne/0.6.0",
      status: "draft",
      bound_members: [
        "expires_at",
        "issued_at",
        "operations",
        "owner_active_key",
        "profile",
        "ref_namespace",
        "repository_rid",
        "spec_version",
        "writer_nid",
      ],
      suites: ["bip340", "ed25519"],
      description: "Repository owner BIP-340 and writer NID Ed25519 proofs bind the identical closed repository-writer authority body.",
    });

    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-assurance-enrollment-observation-v1",
    )?.bound_members).toEqual([
      "accepted_head",
      "active_key",
      "cold_root",
      "conflict_free",
      "first_observed_at",
      "inception_event_id",
      "last_observed_at",
      "profile",
      "spec_version",
      "witness_key",
    ]);

    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-assurance-downgrade-v1",
    )?.bound_members).toEqual([
      "active_key",
      "assurance_head",
      "created_at",
      "inception_event_id",
      "predecessor",
    ]);
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-claim-pop-v1",
    )?.bound_members).toEqual([
      "audience",
      "claim_id",
      "expires_at",
      "issued_at",
      "nonce",
      "operation",
      "resource",
    ]);

    const reason = (code: string) =>
      registry.reason_codes.find((entry) => entry.code === code);
    expect(reason("repository-writer-binding-invalid")).toEqual({
      code: "repository-writer-binding-invalid",
      owner: "core",
      status: "draft",
      first_version: "heterodyne/0.6.0",
      description: "The closed repository-writer binding or its current owner-policy authorization is invalid.",
      spec_refs: ["heterodyne:0.6.0#core-nid-delegation"],
      intentionally_coarse: true,
    });
    expect(reason("claim-ledger-writer-unauthorized")).toEqual({
      code: "claim-ledger-writer-unauthorized",
      owner: "comms",
      status: "draft",
      first_version: "heterodyne/0.6.0",
      description: "A claim-ledger record or prepared claim view lacks current Core repository-writer authorization.",
      spec_refs: ["heterodyne:0.6.0#comms-claim-ledger"],
      intentionally_coarse: true,
    });
    expect(reason("claim-subject-proof-replayed")).toEqual({
      code: "claim-subject-proof-replayed",
      owner: "comms",
      status: "draft",
      first_version: "heterodyne/0.6.0",
      description: "The claim subject proof single-use key was already acquired or conflicts with a different authorization-effect binding.",
      spec_refs: ["heterodyne:0.6.0#comms-claim-verification"],
    });
    expect(reason("claim-authorization-effect-indeterminate")).toEqual({
      code: "claim-authorization-effect-indeterminate",
      owner: "comms",
      status: "draft",
      first_version: "heterodyne/0.6.0",
      description: "The acquired claim authorization effect has no safely confirmed terminal result and requires reconciliation.",
      spec_refs: ["heterodyne:0.6.0#comms-claim-verification"],
    });
    expect(reason("claim-issuer-authority-invalid")).toMatchObject({
      first_version: "heterodyne/0.5.0",
      description: "The exact verified outer issuer or explicit verified claim-chain authority required at the edge was not established.",
    });

    for (const code of [
      "org_member_add_unauthorized",
      "role-delegation-address-invalid",
      "role-delegation-key-proof-invalid",
    ]) {
      expect(reason(code)).toMatchObject({
        first_version: "heterodyne/0.5.0",
        spec_refs: [
          "heterodyne:0.6.0#core-retired-member-kel-and-role-delegation",
        ],
      });
    }
  });

  it("preserves every revision-15 entry identity and first_version exactly", () => {
    const historicalRows = firstVersionRows(registry)
      .filter((row) => !TASK_9_NEW_FIRST_VERSION_ROWS.has(row));
    expect(historicalRows).toHaveLength(452);
    expect(createHash("sha256").update(JSON.stringify(historicalRows)).digest("hex"))
      .toBe(REVISION_15_IDENTITY_FIRST_VERSION_SHA256);
  });

  it("preserves historical first versions and closes the new 0.6 ID set", () => {
    const at06 = {
      features: registry.features
        .filter(({ first_version }) => first_version === "heterodyne/0.6.0")
        .map(({ id }) => id),
      kinds: registry.kinds
        .filter(({ first_version }) => first_version === "heterodyne/0.6.0")
        .map(({ kind }) => kind),
      kind_profiles: registry.kinds
        .flatMap(({ profiles }) => profiles)
        .filter(({ first_version }) => first_version === "heterodyne/0.6.0")
        .map(({ profile_id }) => profile_id),
      objects: registry.objects
        .filter(({ first_version }) => first_version === "heterodyne/0.6.0")
        .map(({ id }) => id),
      proof_domains: registry.proof_domains
        .filter(({ first_version }) => first_version === "heterodyne/0.6.0")
        .map(({ id }) => id),
      reason_codes: registry.reason_codes
        .filter(({ first_version }) => first_version === "heterodyne/0.6.0")
        .map(({ code }) => code),
      security_invariants: registry.security_invariants
        .filter(({ first_version }) => first_version === "heterodyne/0.6.0")
        .map(({ id }) => id),
    };

    expect(at06).toEqual(NEW_0_6_REGISTRY_IDS);
    expect(registry.kinds
      .flatMap(({ profiles }) => profiles)
      .find(({ profile_id }) =>
        profile_id === "heterodyne-assurance-enrollment-inception-v1"
      )?.first_version).toBe("heterodyne/0.5.0");
    expect(registry.kinds
      .flatMap(({ profiles }) => profiles)
      .find(({ profile_id }) =>
        profile_id === "heterodyne-assurance-enrollment-contest-profile-v1"
      )?.first_version).toBe("heterodyne/0.6.0");
  });

  it("assigns node-scoped JWT ownership only to Control", () => {
    const featureIds = registry.features.map(({ id }) => id);
    const feature = (id: string) => {
      const entry = registry.features.find((candidate) => candidate.id === id);
      if (entry === undefined) throw new Error(`missing feature: ${id}`);
      return entry;
    };
    const invariant = (id: string) => {
      const entry = registry.security_invariants.find((candidate) => candidate.id === id);
      if (entry === undefined) throw new Error(`missing invariant: ${id}`);
      return entry;
    };

    expect(featureIds).not.toContain("comms.node-scoped-jwt.v1");
    expect(feature("comms.oidc-jwt-projection.v1").prerequisites)
      .toEqual(["comms.private-claim-ledger.v1"]);
    expect(feature("control.node-scoped-token.v1").prerequisites)
      .toEqual(["control.nip46-oidc-signing.v1"]);
    expect(featureIds).not.toContain("control.oauth-device-enrollment.v1");
    expect(invariant("COMMS-I-JWT-TYPE-AUDIENCE").feature)
      .toBe("comms.oidc-jwt-projection.v1");
    expect(invariant("COMMS-I-ISSUER-CONTINUITY").description)
      .toContain("active-persona-key-scoped Radicle continuity tree");
    expect(invariant("COMMS-I-ISSUER-CONTINUITY").description)
      .not.toContain("root-key-scoped");
  });

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
      "enrollment-inception-v1",
      "active-key-acceptance-v1",
      "succession-v1",
      "associated-key-v1",
      "enrollment-observation-receipt-v1",
      "repository-writer-binding-v1",
      "trusted-seed-acl-v1",
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
      "workspace-relationship-receipt-v1",
      "joint-workspace-relationship-v1",
      "resource-key-envelope-v1",
    ]);
    expect(() => validateRegistry(registry)).not.toThrow();
  });

  it("allocates the current kind and profile set", () => {
    expect(
      registry.kinds.find((entry) => entry.kind === 31001)
        ?.base_schema_owner,
    ).toBe("assurance");
    expect(registry.kinds.find((entry) => entry.kind === 31007)).toBeUndefined();
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

  it("validates an exact registered kind-profile tuple", () => {
    const profile = registry.kinds
      .flatMap(({ kind, profiles }) => profiles.map((entry) => ({ kind, ...entry })))
      .find(({ profile_id }) => profile_id === "heterodyne-core-rotation-breadcrumb-profile-v1")!;
    expect(validateRegisteredKindProfile(registry, profile)).toEqual({
      verdict: "accept",
      normalized: profile,
    });
    expect(validateRegisteredKindProfile(registry, {
      ...profile,
      discriminator: `${profile.discriminator}:substituted`,
    })).toEqual({ verdict: "reject", reason: "profile-metadata-mismatch" });
    expect(validateRegisteredKindProfile(registry, {
      ...profile,
      profile_id: "unregistered-profile",
    })).toEqual({ verdict: "reject", reason: "profile-not-registered" });
  });

  it("allocates the optional Assurance records without reviving retired discovery kinds", () => {
    const allocations = [
      [31002, "heterodyne-assurance-enrollment-inception-v1"],
      [31000, "heterodyne-assurance-active-key-acceptance-v1"],
      [31003, "heterodyne-assurance-succession-v1"],
      [31001, "heterodyne-assurance-associated-key-v1"],
    ] as const;

    for (const [kindNumber, profileId] of allocations) {
      const kind = registry.kinds.find((entry) => entry.kind === kindNumber);
      expect(kind).toMatchObject({
        allocation_authority: "heterodyne",
        base_schema_owner: "assurance",
        status: "draft",
        first_version: "heterodyne/0.5.0",
      });
      expect(kind?.profiles).toContainEqual(expect.objectContaining({
        profile_id: profileId,
        owner: "assurance",
        stamping: false,
      }));
    }

    for (const retiredKind of [31005]) {
      expect(registry.kinds.find((entry) => entry.kind === retiredKind)).toMatchObject({
        allocation_authority: "heterodyne",
        profiles: [],
      });
    }

    expect(registry.kinds.find((entry) => entry.kind === 31006)).toMatchObject({
      allocation_authority: "heterodyne",
      base_schema_owner: "assurance",
      status: "draft",
      first_version: "heterodyne/0.6.0",
      profiles: [{
        profile_id: "heterodyne-assurance-enrollment-contest-profile-v1",
        owner: "assurance",
        discriminator: "content.profile=heterodyne.assurance.enrollment-contest.v1",
        stamping: false,
        first_version: "heterodyne/0.6.0",
        status: "draft",
      }],
    });
  });

  it("registers Social as a vanilla-Nostr extension without feed-index or KEL prerequisites", () => {
    const socialFeatures = registry.features.filter(({ owner }) => owner === "social");
    expect(socialFeatures).toEqual([expect.objectContaining({
      id: "social.agent-policy-moderation.v1",
      prerequisites: ["comms.agent-authorship.v1"],
    })]);
    expect(socialFeatures.flatMap(({ prerequisites }) => prerequisites)
      .some((id) => id.startsWith("assurance."))).toBe(false);
    expect(registry.kinds.find((entry) => entry.kind === 31007)).toBeUndefined();

    const socialReasons = registry.reason_codes
      .filter(({ owner }) => owner === "social")
      .map(({ code }) => code);
    expect(socialReasons).toEqual(expect.arrayContaining([
      "social-event-invalid",
      "social-author-binding-invalid",
      "social-replaceable-coordinate-mismatch",
      "agent-policy-receipt-invalid",
      "agent-policy-binding-invalid",
    ]));
    expect(socialReasons).not.toEqual(expect.arrayContaining([
      "stale_list_rollback",
      "agent-role-key-rotation-required",
    ]));
    expect(registry.reason_codes.map(({ code }) => code)).not.toEqual(
      expect.arrayContaining([
        "not_canonical_branch_reachable",
        "page_chain_broken",
      ]),
    );

    const socialInvariants = registry.security_invariants
      .filter(({ owner }) => owner === "social")
      .map(({ id }) => id);
    expect(socialInvariants).toEqual(expect.arrayContaining([
      "SOCIAL-I-NIP01-AUTHORSHIP",
      "SOCIAL-I-SOURCE-NEUTRAL-SELECTION",
      "SOCIAL-I-AGENT-POLICY-LOCAL",
      "SOCIAL-I-AGENT-AUTHORSHIP-EXACT",
    ]));
  });

  it("registers active-key Workspace authority and trusted-seed confinement", () => {
    const workspaceFeatures = registry.features.filter(({ owner }) => owner === "workspace");
    expect(workspaceFeatures.flatMap(({ prerequisites }) => prerequisites)
      .some((id) => id.startsWith("assurance."))).toBe(false);
    expect(registry.features.find(({ id }) => id === "workspace.private-role-control.v1")
      ?.prerequisites).toEqual([
        "workspace.role-authorization.v1",
        "comms.marmot-conversations.v1",
        "comms.radicle-marmot-storage.v1",
        "comms.trusted-seed-private-relay.v1",
      ]);
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-workspace-object-v1",
    )?.bound_members).toEqual([
      "authority_checkpoint",
      "body",
      "issued_at",
      "object_type",
      "policy_head",
      "predecessor",
      "repository_head",
      "repository_rid",
      "spec_version",
      "workspace_key",
    ]);
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-workspace-grant-approval-v1",
    )).toMatchObject({
      owner: "workspace",
      suites: ["bip340"],
      bound_members: [
        "approver_key",
        "authority_checkpoint",
        "expires_at",
        "issued_at",
        "operation_digest",
        "policy_head",
        "predecessor",
        "profile",
        "spec_version",
        "workspace_key",
      ],
    });
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-workspace-grant-operation-v1",
    )).toMatchObject({
      owner: "workspace",
      suites: ["bip340"],
      bound_members: [
        "activates_at",
        "activation",
        "authority_checkpoint",
        "capabilities",
        "delegable",
        "evidence_ids",
        "expires_at",
        "grant_id",
        "invitation",
        "issued_at",
        "object_type",
        "policy_head",
        "predecessor",
        "recipient",
        "repository_head",
        "repository_rid",
        "resource_scope",
        "role_id",
        "spec_version",
        "subject_account",
        "target_device",
        "workspace_key",
      ],
    });
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-workspace-affiliation-evidence-v1",
    )).toMatchObject({
      owner: "workspace",
      suites: ["bip340"],
      bound_members: [
        "authority_checkpoint",
        "expires_at",
        "observed_at",
        "policy_head",
        "predecessor",
        "profile",
        "relationship_id",
        "repository_head",
        "repository_rid",
        "source_account",
        "source_role_id",
        "source_workspace_key",
        "spec_version",
      ],
    });
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-workspace-joint-delegate-v1",
    )).toMatchObject({
      owner: "workspace",
      suites: ["bip340"],
      bound_members: [
        "authority_checkpoint",
        "delegate_key",
        "expires_at",
        "issued_at",
        "joint_workspace_key",
        "operation_digest",
        "policy_head",
        "predecessor",
        "profile",
        "relationship_id",
        "resource_scope",
        "spec_version",
      ],
    });
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-workspace-joint-operation-v1",
    )).toMatchObject({
      owner: "workspace",
      suites: ["bip340"],
      bound_members: [
        "authority_checkpoint",
        "policy_head",
        "predecessor",
        "relationship_id",
        "resource_scope",
        "workspace_key",
      ],
    });
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-workspace-assurance-authorization-v1",
    )).toMatchObject({
      owner: "workspace",
      first_version: "heterodyne/0.6.0",
      suites: ["bip340"],
      bound_members: [
        "evaluated_at",
        "next_assurance",
        "next_policy_head",
        "previous_assurance",
        "previous_policy_head",
        "profile",
        "suite",
        "transition_digest",
        "verification_key",
        "workspace_key",
      ],
    });
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-workspace-successor-reauthorization-v1",
    )).toMatchObject({
      owner: "workspace",
      suites: ["bip340"],
      bound_members: expect.arrayContaining([
        "new_account",
        "new_device",
        "new_leaf",
        "pending_checkpoint_id",
        "pending_custody_host_id",
        "pending_envelope_id",
        "pending_grant_id",
        "pending_key_epoch",
        "prior_account",
        "prior_device",
        "prior_grant_id",
        "prior_leaf",
      ]),
    });
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-workspace-key-request-v1",
    )).toMatchObject({
      owner: "workspace",
      suites: ["bip340"],
      bound_members: [
        "authenticated_account",
        "custody_host_id",
        "recipient",
        "requested_epoch",
        "requested_snapshot_id",
        "resource_id",
        "target_account",
        "target_device",
      ],
    });

    expect(registry.reason_codes.find(({ code }) => code === "workspace_signature_invalid")
      ?.description).not.toMatch(/KEL|cold root|epoch/i);
    expect(registry.reason_codes.find(({ code }) => code === "checkpoint_stale")
      ?.description).toMatch(/latest|superseded/i);
    expect(registry.security_invariants.find(
      ({ id }) => id === "WORKSPACE-I-CARRIER-NOT-AUTHORITY",
    )?.description).toMatch(/seed|repository writer/i);
    expect(registry.security_invariants.find(
      ({ id }) => id === "WORKSPACE-I-DEVICE-LEAF-SEPARATION",
    )?.description).toMatch(/active account/i);
    expect(registry.security_invariants.find(
      ({ id }) => id === "WORKSPACE-I-AUTHENTICATED-CURRENT-STATE",
    )?.description).toMatch(/latest.*effect|effect.*latest/i);
  });

  it("registers Assurance-owned features, objects, proofs, reasons, and invariants", () => {
    const assuranceFeatures = registry.features
      .filter(({ owner }) => owner === "assurance")
      .map(({ id }) => id);
    expect(assuranceFeatures).toEqual([
      "assurance.continuity.v1",
      "assurance.associated-keys.v1",
      "assurance.keri-export.v1",
    ]);

    const assuranceObjects = registry.objects.filter(({ owner }) => owner === "assurance");
    expect(assuranceObjects.map(({ id }) => id)).toEqual([
      "enrollment-inception-v1",
      "active-key-acceptance-v1",
      "succession-v1",
      "associated-key-v1",
      "enrollment-observation-receipt-v1",
    ]);
    expect(assuranceObjects.map(({ carriers }) => carriers)).toEqual([
      ["nostr-event"],
      ["nostr-event"],
      ["nostr-event"],
      ["nostr-event"],
      ["radicle-authority-file"],
    ]);

    const assuranceCarrier: ObjectEntry["carriers"][number] = "nostr-event";
    expect(assuranceCarrier).toBe("nostr-event");

    const assuranceProofs = registry.proof_domains
      .filter(({ owner }) => owner === "assurance")
      .map(({ id }) => id);
    expect(assuranceProofs).toEqual(expect.arrayContaining([
      "heterodyne-assurance-succession-transition-v1",
      "heterodyne-assurance-associated-key-record-v1",
      "heterodyne-assurance-downgrade-v1",
      "heterodyne-assurance-enrollment-observation-v1",
    ]));
    expect(assuranceProofs).not.toContain("heterodyne-assurance-succession-v1");
    expect(assuranceProofs).not.toContain("heterodyne-assurance-associated-key-subject-v1");
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-assurance-succession-transition-v1",
    )?.bound_members).toEqual([
      "active_key",
      "authorizing_evidence.authority_class",
      "authorizing_evidence.authority_proofs[].authority_key",
      "authorizing_evidence.witness_receipts[].witness_key",
      "class",
      "compromise_time",
      "created_at",
      "new_active_key",
      "new_key_acceptance.key",
      "next_associated_key_policy",
      "next_epoch_policy",
      "next_succession_authority",
      "predecessor",
      "previous_active_key",
      "previous_head",
      "profile",
      "spec_version",
      "subordinate_reauthorizations",
      "thresholds",
      "witnesses",
    ]);
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-assurance-associated-key-record-v1",
    )?.bound_members).toEqual([
      "active_key",
      "assurance_head",
      "created_at",
      "expires_at",
      "issuer",
      "issuer_authority.authority_proofs[].authority_key",
      "issuer_authority.class",
      "predecessor",
      "profile",
      "revocation",
      "role",
      "scope",
      "spec_version",
      "state",
      "subject_key",
      "visibility",
    ]);
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-assurance-enrollment-observation-v1",
    )).toMatchObject({
      owner: "assurance",
      suites: ["bip340"],
      bound_members: [
        "accepted_head",
        "active_key",
        "cold_root",
        "conflict_free",
        "first_observed_at",
        "inception_event_id",
        "last_observed_at",
        "profile",
        "spec_version",
        "witness_key",
      ],
    });

    const assuranceReasons = registry.reason_codes
      .filter(({ owner }) => owner === "assurance")
      .map(({ code }) => code);
    expect(assuranceReasons).toEqual(expect.arrayContaining([
      "assurance-reciprocal-proof-invalid",
      "assurance-predecessor-mismatch",
      "assurance-head-mismatch",
      "assurance-compromise-cutoff",
      "assurance-subordinate-continuation-forbidden",
      "assurance-associated-key-subject-proof-required",
      "assurance-associated-key-expired",
      "assurance-associated-key-revoked",
      "assurance-downgrade-consent-required",
      "assurance-pin-conflict",
      "assurance-enrollment-pending-window",
      "assurance-enrollment-contested",
    ]));

    const assuranceInvariants = registry.security_invariants
      .filter(({ owner }) => owner === "assurance");
    expect(assuranceInvariants.length).toBeGreaterThan(0);
    expect(assuranceInvariants.every(({ id }) => id.startsWith("ASSURANCE-I-")))
      .toBe(true);
    expect(assuranceInvariants.map(({ id }) => id)).toEqual(expect.arrayContaining([
      "ASSURANCE-I-RECIPROCAL-ENROLLMENT",
      "ASSURANCE-I-TRANSITION-PROOF-BINDING",
      "ASSURANCE-I-PIN-DOWNGRADE",
      "ASSURANCE-I-SUCCESSION-NON-ALIASING",
      "ASSURANCE-I-COMPROMISE-CUTOFF",
      "ASSURANCE-I-NO-IMPLICIT-CONTINUATION",
      "ASSURANCE-I-ASSOCIATED-KEY-BOUNDS",
      "ASSURANCE-I-ENROLLMENT-WINDOWED",
    ]));
    expect(registry.security_invariants.find(
      ({ id }) => id === "ASSURANCE-I-ENROLLMENT-WINDOWED",
    )?.description).toMatch(/observation.*604800|604800.*observation/i);
    expect(registry.security_invariants.find(
      ({ id }) => id === "ASSURANCE-I-ENROLLMENT-WINDOWED",
    )?.description).not.toMatch(/OpenTimestamp|OTS|tiebreak|materially earlier/i);
  });

  it("composes public Comms and Marmot from Core Nostr and repository primitives", () => {
    const feature = (id: string) => {
      const entry = registry.features.find((candidate) => candidate.id === id);
      if (entry === undefined) throw new Error(`missing feature: ${id}`);
      return entry;
    };
    const invariant = (id: string) => {
      const entry = registry.security_invariants.find((candidate) => candidate.id === id);
      if (entry === undefined) throw new Error(`missing invariant: ${id}`);
      return entry;
    };

    expect(feature("comms.public-reader.v1").prerequisites)
      .toEqual(["core.nostr-relay-read.v1"]);
    expect(feature("comms.marmot-conversations.v1").prerequisites)
      .toEqual(["core.nostr-relay-read.v1"]);
    expect(feature("comms.radicle-marmot-storage.v1").prerequisites)
      .toEqual(["core.repo-relay-client.v1", "comms.marmot-conversations.v1"]);
    expect(registry.features.flatMap(({ prerequisites }) => prerequisites))
      .not.toContain("core.marmot-role-attribution.v1");
    expect(invariant("COMMS-I-MARMOT-ACCOUNT-IDENTITY").feature)
      .toBe("comms.marmot-conversations.v1");
    expect(invariant("COMMS-I-RADICLE-ROUTING-AUTHORITY").feature)
      .toBe("comms.radicle-marmot-storage.v1");
  });

  it("registers trusted private seeds and flexible automated signers", () => {
    const feature = (id: string) => {
      const entry = registry.features.find((candidate) => candidate.id === id);
      if (entry === undefined) throw new Error(`missing feature: ${id}`);
      return entry;
    };

    expect(feature("comms.trusted-seed-private-relay.v1")).toMatchObject({
      owner: "comms",
      prerequisites: [
        "core.repo-relay-client.v1",
        "comms.radicle-backed-marmot-relay.v1",
      ],
      spec_ref: "heterodyne:0.6.0#comms-trusted-seed-private-relay",
    });
    expect(feature("comms.agent-authorship.v1").prerequisites)
      .toEqual(["comms.oidc-jwt-projection.v1"]);

    expect(registry.objects.find(({ id }) => id === "trusted-seed-acl-v1"))
      .toMatchObject({
        owner: "comms",
        schema: "https://heterodyne.network/schemas/comms/trusted-seed-acl-v1.schema.json",
        carriers: ["radicle-authority-file"],
      });
    expect(registry.proof_domains.find(
      ({ id }) => id === "heterodyne-trusted-seed-acl-v1",
    )).toMatchObject({
      owner: "comms",
      suites: ["bip340"],
      bound_members: [
        "accounts[].account_key",
        "accounts[].roles",
        "administrator_account",
        "expires_at",
        "group_transition.generation",
        "group_transition.marmot_routing_event_id",
        "group_transition.routing_binding_sha256",
        "h",
        "issued_at",
        "predecessor",
        "private_rid",
        "profile",
        "seed_grants[].radicle_endpoint",
        "seed_grants[].relay_endpoint",
        "seed_grants[].roles",
        "seed_grants[].seed_nid",
        "seed_grants[].state",
        "seed_grants[].writer_ref",
        "sequence",
        "spec_version",
      ],
    });
    expect(registry.proof_domains.map(({ id }) => id))
      .not.toContain("heterodyne-agent-signing-binding-v1");

    expect(registry.reason_codes.map(({ code }) => code)).toEqual(
      expect.arrayContaining([
        "trusted-seed-acl-missing",
        "trusted-seed-acl-invalid",
        "trusted-seed-acl-expired",
        "trusted-seed-acl-stale",
        "trusted-seed-acl-conflict",
        "trusted-seed-acl-ambiguous",
        "trusted-seed-unauthorized",
        "trusted-seed-revoked",
        "trusted-seed-nip42-required",
        "trusted-seed-route-mismatch",
        "trusted-seed-event-invalid",
        "trusted-seed-request-invalid",
        "trusted-seed-request-replay",
        "agent-signer-mismatch",
        "agent-persona-scope-required",
      ]),
    );
    expect(registry.reason_codes.map(({ code }) => code))
      .not.toContain("trusted-seed-secret-material-forbidden");
    expect(registry.security_invariants.map(({ id }) => id)).toEqual(
      expect.arrayContaining([
        "COMMS-I-TRUSTED-SEED-CONFINEMENT",
        "COMMS-I-PRIVATE-RELAY-ACL",
        "COMMS-I-AGENT-SIGNER-BINDING",
      ]),
    );
    expect(registry.security_invariants.map(({ id }) => id))
      .not.toContain("COMMS-I-AGENT-ROLE-BINDING");
  });

  it("registers isolated persona vaults, exact NIP-46 grants, and complete compromise reset", () => {
    const feature = (id: string) => {
      const entry = registry.features.find((candidate) => candidate.id === id);
      if (entry === undefined) throw new Error(`missing feature: ${id}`);
      return entry;
    };
    expect(feature("control.multi-persona-vaults.v1")).toMatchObject({
      owner: "control",
      prerequisites: ["comms.marmot-conversations.v1"],
      spec_ref: "heterodyne:0.6.0#control-persona-vaults",
    });
    expect(feature("control.nip46-oidc-signing.v1")).toMatchObject({
      prerequisites: [
        "comms.oidc-jwt-projection.v1",
        "control.multi-persona-vaults.v1",
      ],
      spec_ref: "heterodyne:0.6.0#control-nip46-signing",
    });
    expect(feature("control.agent-workload-publication.v1").prerequisites)
      .toEqual([
        "comms.agent-authorship.v1",
        "control.nip46-oidc-signing.v1",
      ]);
    expect(feature("control.trusted-seed-provisioning.v1").prerequisites)
      .toEqual([
        "comms.trusted-seed-private-relay.v1",
        "control.multi-persona-vaults.v1",
      ]);
    expect(feature("control.compromise-reset.v1").prerequisites)
      .toEqual([
        "comms.marmot-conversations.v1",
        "control.multi-persona-vaults.v1",
      ]);
    expect(registry.features.filter(({ owner }) => owner === "control")
      .flatMap(({ prerequisites }) => prerequisites)
      .filter((id) => id.startsWith("assurance."))).toEqual([]);
    expect(registry.features.map(({ id }) => id)).not.toEqual(expect.arrayContaining([
      "control.private-entitlement.v1",
      "control.recovery.epoch-inbox.v1",
    ]));

    const reasons = registry.reason_codes.map(({ code }) => code);
    expect(reasons).toEqual(expect.arrayContaining([
      "control-vault-isolation-failed",
      "control-signer-unavailable",
      "control-signer-binding-mismatch",
      "control-signing-grant-invalid",
      "control-signing-grant-inactive",
      "control-signing-grant-unauthenticated",
      "control-signing-grant-stale",
      "control-signing-rate-limited",
      "control-operation-reservation-required",
      "control-client-metadata-widening",
      "control-persona-authority-required",
      "control-connection-secret-invalid",
      "control-connection-secret-reused",
      "control-activation-binding-mismatch",
      "control-attribution-required",
      "control-attribution-binding-mismatch",
      "control-agent-intent-invalid",
      "control-signed-event-invalid",
      "control-compromise-reset-incomplete",
      "control-compromise-reset-unauthenticated",
      "control-compromise-reset-inventory-mismatch",
      "control-compromise-reset-evidence-invalid",
      "control-subordinate-reauthorization-required",
    ]));
    expect(reasons).not.toEqual(expect.arrayContaining([
      "control-recovery-locked",
      "control-registration-invalid",
      "control-activation-mismatch",
      "control-recovery-grant-invalid",
      "control-recovery-completion-mismatch",
      "control-sftp-denied",
    ]));

    const invariants = registry.security_invariants
      .filter(({ owner }) => owner === "control");
    expect(invariants.map(({ id }) => id)).toEqual(expect.arrayContaining([
      "CONTROL-I-PERSONA-VAULT-ISOLATION",
      "CONTROL-I-EXACT-SIGNER-GRANT",
      "CONTROL-I-NIP46-OIDC-ACTIVATION",
      "CONTROL-I-NO-SIGNER-FALLBACK",
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING",
      "CONTROL-I-BASELINE-ACTIVE-KEY",
      "CONTROL-I-MARMOT-LEAF-COMPROMISE",
      "CONTROL-I-COMPROMISE-RESET",
    ]));
    expect(invariants.map(({ id }) => id)).not.toEqual(expect.arrayContaining([
      "CONTROL-I-EPOCH-LOCKED-DURING-TRANSFER",
      "CONTROL-I-SFTP-PROCESS-SEPARATION",
    ]));
  });

  it("registers upstream Marmot transport kinds without Heterodyne stamping", () => {
    for (const kind of [444, 445, 30443]) {
      expect(registry.kinds.find((entry) => entry.kind === kind)).toMatchObject({
        allocation_authority: "nostr",
        profiles: [],
      });
    }
  });

  it("allocates the agent attribution, receipt, and policy-list profiles", () => {
    const expected = [
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

  it("admits association-free and associated agent attribution through one canonical rule", () => {
    const attributionProfiles = registry.kinds.flatMap(({ profiles }) =>
      profiles.filter(({ profile_id }) =>
        profile_id.startsWith("heterodyne-comms-agent-attribution-kind-"),
      ),
    );
    expect(attributionProfiles).toHaveLength(8);
    for (const profile of attributionProfiles) {
      expect(profile.discriminator).toBe("production-rule:agent-attribution-v1");
    }

    const associationFree = [
      ["L", "network.heterodyne.agent"],
      ["l", "ai", "network.heterodyne.agent"],
      ["agent_action", "publish"],
    ];
    const associated = [
      ["L", "network.heterodyne.agent"],
      ["l", "ai", "network.heterodyne.agent"],
      ["heterodyne_agent", "v1", "key", "33".repeat(32)],
      ["agent_action", "publish"],
    ];
    for (const tags of [associationFree, associated]) {
      expect(matchesAgentAttributionProfile(tags)).toBe(true);
    }
    expect(matchesAgentAttributionProfile([
      associationFree[0],
      associationFree[1],
      ["heterodyne_agent", "v1", "key", "not-a-key"],
      associationFree[2],
    ])).toBe(false);
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
      "oidc-status-invalid",
    ]));

    // A refusal a caller is not entitled to distinguish gets exactly one code;
    // the specific condition lives only in the encrypted audit.
    for (const collapsed of [
      "agent-token-expired", "agent-token-revoked", "agent-token-stale",
      "agent-token-audience-invalid", "agent-token-scope-invalid",
      "control-token-expired", "control-token-audience-invalid",
      "control-token-sender-invalid", "control-token-group-invalid",
      "control-token-scope-invalid",
      "oidc-status-stale", "oidc-status-digest-mismatch", "oidc-status-index-invalid",
      "control-sftp-auth-invalid", "control-sftp-resource-denied", "control-sftp-expired",
      "control-invitation-disabled", "control-enrollment-capacity",
      "control-enrollment-expired", "control-device-code-exhausted",
    ]) {
      expect(reasonCodes).not.toContain(collapsed);
    }
    expect(reasonCodes).toEqual(expect.arrayContaining([
      "agent-token-invalid",
      "control-token-invalid",
      "control-enrollment-unavailable",
      "control-device-code-invalid",
      // Backoff and the user-visible code comparison stay separable: they tell
      // a caller nothing it is not already entitled to know.
      "control-enrollment-rate-limited",
      "control-device-code-display-mismatch",
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

  it("keeps baseline and historical reason ownership through revision 17", () => {
    expect(registry.manifest.revision).toBe(17);
    const reasons = new Map(
      registry.reason_codes.map((entry) => [entry.code, entry]),
    );
    expect(reasons.get("nip01_raw_mismatch")).toMatchObject({
      owner: "core",
      status: "draft",
      first_version: "heterodyne/0.5.0",
    });
    for (const code of [
      "successor_persona_mismatch",
      "retiring_key_nip05_invalid",
      "compromise_rotation_breadcrumb_forbidden",
    ]) {
      expect(reasons.get(code)).toMatchObject({
        owner: "assurance",
        status: "draft",
        first_version: "heterodyne/0.5.0",
      });
    }
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
    expect(registry.kinds.find((entry) => entry.kind === 31007)).toBeUndefined();
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
