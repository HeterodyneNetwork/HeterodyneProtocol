import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Ajv, type ErrorObject } from "ajv";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../../../schemas/workspace");
const H64 = "11".repeat(32);
const H64_B = "22".repeat(32);
const H40 = "33".repeat(20);
const SIG = "44".repeat(64);

const base = (object_type: string) => ({
  spec_version: "heterodyne/0.5.0",
  object_type,
  workspace_id: H64,
  actor: H64_B,
  kel_head: H64,
  authority_sequence: 4,
  repository_rid: "rad:zWorkspace",
  repository_head: H40,
  issued_at: 1_720_000_000,
  signature: SIG,
});

const values: Record<string, Record<string, unknown>> = {
  "workspace-manifest-v1": {
    ...base("workspace-manifest-v1"),
    root_policy_rid: "rad:zPolicy",
    root_policy_head: H64,
    visibility: "public",
    public_roles: [{ role_id: H64_B, repository_rid: "rad:zPublicRole" }],
  },
  "workspace-policy-v1": {
    ...base("workspace-policy-v1"),
    policy_id: H64_B,
    sequence: 2,
    governance: { threshold: 2, controllers: [H64, H64_B] },
    visibility_ceiling: "public",
    allowed_role_types: ["public", "member", "guest"],
    allow_public_resources: true,
    allow_bilateral_relationships: true,
    default_host_ids: [H64],
    ordinary_write_max_age: 86_400,
    authority_mutation_max_age: 300,
  },
  "role-manifest-v1": {
    ...base("role-manifest-v1"),
    role_id: H64_B,
    parent_role_id: null,
    role_type: "member",
    visibility: "private",
    allowed_capabilities: ["read", "write", "invite"],
    history_mode: "full",
    selected_snapshots: [],
    policy_head: H64,
    mls_group_id: H64_B,
    active_event_repository: { repository_rid: "rad:zEvents", mls_epoch: 7 },
    overlap_event_repository: null,
    archived_event_repositories: [],
  },
  "role-grant-v1": {
    ...base("role-grant-v1"),
    grant_id: H64_B,
    subject: H64,
    role_id: H64_B,
    capabilities: ["read", "write"],
    resource_scope: [],
    delegable: false,
    activation: "immediate",
    activates_at: 1_720_000_000,
    expires_at: null,
    approval_ids: [],
    invitation: null,
    evidence_ids: [],
  },
  "role-revocation-v1": {
    ...base("role-revocation-v1"),
    revocation_id: H64_B,
    target_type: "grant",
    target_id: H64,
    effective_at: 1_720_000_010,
    reason: "access removed",
  },
  "role-checkpoint-v1": {
    ...base("role-checkpoint-v1"),
    checkpoint_id: H64_B,
    role_id: H64,
    sequence: 9,
    materialized_at: 1_720_000_000,
    workspace_policy_head: H64,
    role_policy_heads: [H64_B],
    active_grant_ids: [H64],
    revocation_ids: [],
    relationship_ids: [],
    host_ids: [H64],
    resource_ids: [H64_B],
    previous_checkpoint: null,
  },
  "resource-advertisement-v1": {
    ...base("resource-advertisement-v1"),
    resource_id: H64_B,
    role_id: H64,
    resource_type: "project",
    visibility: "private",
    locators: ["rad:zProject"],
    policy_head: H64,
    required_capabilities: ["read", "write"],
    key_epoch: 3,
    history_mode: "full",
    selected_snapshots: [],
    retention_seconds: null,
    host_ids: [H64],
    key_custody_host_ids: [H64],
  },
  "host-advertisement-v1": {
    ...base("host-advertisement-v1"),
    host_id: H64_B,
    nid: H64,
    radicle_locators: ["rad:zHost"],
    onion_endpoints: ["http://exampleexampleexampleexampleexampleexampleexampleexample.onion"],
    clearnet_endpoints: [],
    supported_features: ["comms.radicle-backed-marmot-relay.v1"],
    inheritance: "default",
    key_custody_resource_ids: [H64],
    priority: 10,
    expires_at: 1_720_003_600,
  },
  "service-advertisement-v1": {
    ...base("service-advertisement-v1"),
    service_id: H64_B,
    role_id: H64,
    service_type: "forge",
    profile_id: "example.forge.v1",
    endpoints: ["https://service.example"],
    policy_head: H64,
    audience_role_id: H64,
    expires_at: 1_720_003_600,
  },
  "workspace-relationship-v1": {
    ...base("workspace-relationship-v1"),
    relationship_id: H64_B,
    source_workspace_id: H64,
    receiving_workspace_id: H64_B,
    source_role_id: H64,
    receiving_role_id: H64_B,
    capability_ceiling: ["read", "triage"],
    proof_max_age: 300,
    grace_period: 600,
    expires_at: 1_720_086_400,
    independently_revocable: true,
    source_signature: SIG,
    receiving_signature: SIG,
  },
  "joint-workspace-relationship-v1": {
    ...base("joint-workspace-relationship-v1"),
    relationship_id: H64_B,
    joint_workspace_id: H64,
    participant_workspace_ids: [H64, H64_B],
    delegate_keys: [H64, H64_B],
    threshold: 2,
    resource_scope: [H64],
    effective_at: 1_720_000_000,
    expires_at: null,
  },
  "resource-key-envelope-v1": {
    ...base("resource-key-envelope-v1"),
    envelope_id: H64_B,
    resource_id: H64,
    key_epoch: 3,
    target_persona: H64,
    target_device: H64_B,
    role_id: H64,
    checkpoint_id: H64_B,
    host_id: H64,
    wrapping_profile: "marmot-mls-application-v1",
    nonce: "AAECAwQFBgcICQoLDA0ODw",
    ciphertext: "AQIDBAUGBwgJCgsMDQ4PEA",
    ciphertext_sha256: H64,
    created_at: 1_720_000_000,
  },
};

const schemaFor = (name: string) => JSON.parse(
  readFileSync(resolve(root, `${name}.schema.json`), "utf8"),
) as object;

const validate = (name: string, value: unknown): ErrorObject[] | null => {
  const validator = new Ajv({ allErrors: true, strict: false }).compile(schemaFor(name));
  return validator(value) ? null : validator.errors ?? [];
};

describe("Workspace authority object schemas", () => {
  for (const [name, value] of Object.entries(values)) {
    it(`accepts the exact ${name} shape`, () => {
      expect(validate(name, value)).toBeNull();
      expect(schemaFor(name)).toMatchObject({
        $schema: "http://json-schema.org/draft-07/schema#",
        $id: `https://heterodyne.network/schemas/workspace/${name}.schema.json`,
        additionalProperties: false,
      });
    });

    it(`rejects unknown, missing, and mistyped identity members for ${name}`, () => {
      expect(validate(name, { ...value, unknown: true })).not.toBeNull();
      const missing = { ...value };
      delete missing.signature;
      expect(validate(name, missing)).not.toBeNull();
      expect(validate(name, { ...value, object_type: "wrong-v1" })).not.toBeNull();
      expect(validate(name, { ...value, workspace_id: "npub1invalid" })).not.toBeNull();
    });
  }

  it("enforces visibility, capability, history, and freshness boundaries", () => {
    expect(validate("workspace-manifest-v1", {
      ...values["workspace-manifest-v1"], visibility: "secret",
    })).not.toBeNull();
    expect(validate("role-grant-v1", {
      ...values["role-grant-v1"], capabilities: ["superuser"],
    })).not.toBeNull();
    expect(validate("role-manifest-v1", {
      ...values["role-manifest-v1"], history_mode: "everything",
    })).not.toBeNull();
    expect(validate("workspace-policy-v1", {
      ...values["workspace-policy-v1"], authority_mutation_max_age: 301,
    })).not.toBeNull();
    expect(validate("workspace-policy-v1", {
      ...values["workspace-policy-v1"], ordinary_write_max_age: 86_401,
    })).not.toBeNull();
  });
});
