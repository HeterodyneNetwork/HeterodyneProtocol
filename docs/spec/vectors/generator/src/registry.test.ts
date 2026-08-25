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
  resolveStampingProfile,
  type ObjectEntry,
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
      ({ id }) => id === "heterodyne-workspace-successor-reauthorization-v1",
    )).toMatchObject({
      owner: "workspace",
      suites: ["bip340"],
      bound_members: expect.arrayContaining([
        "new_account",
        "new_device",
        "new_leaf",
        "pending_envelope_id",
        "pending_grant_id",
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
    ]);
    expect(assuranceObjects.map(({ carriers }) => carriers)).toEqual([
      ["nostr-event"],
      ["nostr-event"],
      ["nostr-event"],
      ["nostr-event"],
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
    ]));
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
      spec_ref: "heterodyne:0.5.0#comms-trusted-seed-private-relay",
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
      spec_ref: "heterodyne:0.5.0#control-persona-vaults",
    });
    expect(feature("control.nip46-oidc-signing.v1")).toMatchObject({
      prerequisites: [
        "comms.oidc-jwt-projection.v1",
        "control.multi-persona-vaults.v1",
      ],
      spec_ref: "heterodyne:0.5.0#control-nip46-signing",
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

  it("keeps baseline and historical reason ownership at revision 14", () => {
    expect(registry.manifest.revision).toBe(14);
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
