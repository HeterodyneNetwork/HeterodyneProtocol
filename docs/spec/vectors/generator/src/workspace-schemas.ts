import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

type Schema = Record<string, unknown>;

const h64 = { type: "string", pattern: "^[0-9a-f]{64}$" };
const h40 = { type: "string", pattern: "^[0-9a-f]{40}$" };
const signature = { type: "string", pattern: "^[0-9a-f]{128}$" };
const nonNegativeInteger = { type: "integer", minimum: 0, maximum: Number.MAX_SAFE_INTEGER };
const timestamp = { type: "integer", minimum: 0, maximum: Number.MAX_SAFE_INTEGER };
const radicleRid = { type: "string", pattern: "^rad:[A-Za-z0-9]+$" };
const radicleNid = { type: "string", pattern: "^did:key:z[1-9A-HJ-NP-Za-km-z]+$" };
const marmotLeaf = { type: "string", pattern: "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$" };
const nullableH64 = { anyOf: [h64, { type: "null" }] };
const nullableTimestamp = { anyOf: [timestamp, { type: "null" }] };
const identifierArray = { type: "array", items: h64, uniqueItems: true };
const visibility = { enum: ["public", "selective", "private"] };
const historyMode = { enum: ["full", "from-admission", "selected-snapshots"] };
const capability = {
  enum: [
    "read", "write", "triage", "moderate", "admin", "invite",
    "govern-policy", "govern-subroles", "govern-thresholds",
    "govern-publicize", "govern-federation", "govern-delegation",
    "govern-lifecycle",
  ],
};
const capabilities = { type: "array", items: capability, uniqueItems: true };

const closed = (
  required: string[],
  properties: Record<string, unknown>,
): Schema => ({
  type: "object",
  additionalProperties: false,
  required,
  properties,
});

const baseProperties = (objectType: string): Record<string, unknown> => ({
  spec_version: { const: "heterodyne/0.5.0" },
  object_type: { const: objectType },
  workspace_key: h64,
  policy_head: h64,
  predecessor: nullableH64,
  authority_checkpoint: h64,
  repository_rid: radicleRid,
  repository_head: h40,
  issued_at: timestamp,
  signature,
});

const BASE_REQUIRED = [
  "spec_version", "object_type", "workspace_key", "policy_head",
  "predecessor", "authority_checkpoint", "repository_rid",
  "repository_head", "issued_at", "signature",
];

const workspaceSchema = (
  objectType: string,
  required: string[],
  properties: Record<string, unknown>,
): Schema => ({
  $schema: "http://json-schema.org/draft-07/schema#",
  $id: `https://heterodyne.network/schemas/workspace/${objectType}.schema.json`,
  title: objectType,
  ...closed([...BASE_REQUIRED, ...required], {
    ...baseProperties(objectType),
    ...properties,
  }),
});

const roleLocator = closed(
  ["role_id", "repository_rid"],
  { role_id: h64, repository_rid: radicleRid },
);
const eventRepository = closed(
  ["repository_rid", "mls_epoch"],
  { repository_rid: radicleRid, mls_epoch: nonNegativeInteger },
);

export const WORKSPACE_SCHEMAS: Record<string, Schema> = {
  "workspace-manifest-v1": workspaceSchema(
    "workspace-manifest-v1",
    ["root_policy_rid", "root_policy_head", "visibility", "public_roles"],
    {
      root_policy_rid: radicleRid,
      root_policy_head: h64,
      visibility,
      public_roles: { type: "array", items: roleLocator, uniqueItems: true },
    },
  ),
  "workspace-policy-v1": workspaceSchema(
    "workspace-policy-v1",
    [
      "policy_id", "sequence", "governance", "visibility_ceiling",
      "allowed_role_types", "allow_public_resources",
      "allow_bilateral_relationships", "default_host_ids",
      "ordinary_write_max_age", "authority_mutation_max_age",
    ],
    {
      policy_id: h64,
      sequence: nonNegativeInteger,
      governance: closed(
        ["threshold", "controllers"],
        {
          threshold: { type: "integer", minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
          controllers: { type: "array", minItems: 1, uniqueItems: true, items: h64 },
        },
      ),
      visibility_ceiling: visibility,
      allowed_role_types: {
        type: "array",
        minItems: 1,
        uniqueItems: true,
        items: { enum: ["public", "member", "guest", "project", "service", "moderation"] },
      },
      allow_public_resources: { type: "boolean" },
      allow_bilateral_relationships: { type: "boolean" },
      default_host_ids: { ...identifierArray, minItems: 1 },
      ordinary_write_max_age: { type: "integer", minimum: 0, maximum: 86_400 },
      authority_mutation_max_age: { type: "integer", minimum: 0, maximum: 300 },
    },
  ),
  "role-manifest-v1": workspaceSchema(
    "role-manifest-v1",
    [
      "role_id", "parent_role_id", "role_type", "visibility",
      "allowed_capabilities", "history_mode", "selected_snapshots",
      "administrator_account", "marmot_h", "active_event_repository",
      "overlap_event_repository", "archived_event_repositories",
    ],
    {
      role_id: h64,
      parent_role_id: nullableH64,
      role_type: { enum: ["public", "member", "guest", "project", "service", "moderation"] },
      visibility,
      allowed_capabilities: capabilities,
      history_mode: historyMode,
      selected_snapshots: identifierArray,
      administrator_account: h64,
      marmot_h: { anyOf: [{ type: "string", minLength: 1, maxLength: 128 }, { type: "null" }] },
      active_event_repository: eventRepository,
      overlap_event_repository: { anyOf: [eventRepository, { type: "null" }] },
      archived_event_repositories: { type: "array", items: eventRepository, uniqueItems: true },
    },
  ),
  "role-grant-v1": {
    ...workspaceSchema(
    "role-grant-v1",
    [
      "grant_id", "subject_account", "target_device", "recipient", "role_id",
      "capabilities", "resource_scope",
      "delegable", "activation", "activates_at", "expires_at",
      "approval_ids", "invitation", "evidence_ids",
    ],
    {
      grant_id: h64,
      subject_account: h64,
      target_device: h64,
      recipient: closed(
        ["type", "value"],
        { type: { const: "marmot-mls-leaf" }, value: marmotLeaf },
      ),
      role_id: h64,
      capabilities,
      resource_scope: identifierArray,
      delegable: { type: "boolean" },
      activation: { enum: ["immediate", "subject-acceptance", "approval-threshold", "waiting-period"] },
      activates_at: timestamp,
      expires_at: nullableTimestamp,
      approval_ids: identifierArray,
      invitation: {
        anyOf: [
          { type: "null" },
          closed(
            ["nonce_commitment", "expires_at", "history_mode"],
            {
              nonce_commitment: h64,
              expires_at: timestamp,
              history_mode: historyMode,
            },
          ),
        ],
      },
      evidence_ids: identifierArray,
      },
    ),
    allOf: [{
      if: { properties: { activation: { const: "subject-acceptance" } } },
      then: { properties: { invitation: { type: "object" } } },
      else: { properties: { invitation: { type: "null" } } },
    }],
  },
  "role-revocation-v1": workspaceSchema(
    "role-revocation-v1",
    ["revocation_id", "target_type", "target_id", "effective_at", "reason"],
    {
      revocation_id: h64,
      target_type: { enum: ["grant", "account", "device", "relationship", "host", "resource"] },
      target_id: h64,
      effective_at: timestamp,
      reason: { type: "string", minLength: 1, maxLength: 512 },
    },
  ),
  "role-checkpoint-v1": workspaceSchema(
    "role-checkpoint-v1",
    [
      "checkpoint_id", "role_id", "sequence", "materialized_at",
      "workspace_policy_head", "role_policy_heads", "active_grant_ids",
      "revocation_ids", "relationship_ids", "host_ids", "resource_ids",
      "seed_nids", "previous_checkpoint",
    ],
    {
      checkpoint_id: h64,
      role_id: h64,
      sequence: nonNegativeInteger,
      materialized_at: timestamp,
      workspace_policy_head: h64,
      role_policy_heads: { ...identifierArray, minItems: 1 },
      active_grant_ids: identifierArray,
      revocation_ids: identifierArray,
      relationship_ids: identifierArray,
      host_ids: identifierArray,
      seed_nids: { type: "array", items: radicleNid, uniqueItems: true },
      resource_ids: identifierArray,
      previous_checkpoint: nullableH64,
    },
  ),
  "resource-advertisement-v1": workspaceSchema(
    "resource-advertisement-v1",
    [
      "resource_id", "role_id", "resource_type", "visibility", "locators",
      "required_capabilities", "key_epoch", "history_mode",
      "selected_snapshots", "retention_seconds", "host_ids",
      "key_custody_host_ids", "repository_owner_key",
      "repository_writer_nids", "trusted_seed_nids",
    ],
    {
      resource_id: h64,
      role_id: h64,
      resource_type: { enum: ["project", "group", "artifact", "service", "repository"] },
      visibility,
      locators: { type: "array", minItems: 1, uniqueItems: true, items: { type: "string", minLength: 1, maxLength: 2048 } },
      required_capabilities: capabilities,
      key_epoch: nonNegativeInteger,
      history_mode: historyMode,
      selected_snapshots: identifierArray,
      retention_seconds: { anyOf: [nonNegativeInteger, { type: "null" }] },
      host_ids: { ...identifierArray, minItems: 1 },
      key_custody_host_ids: identifierArray,
      repository_owner_key: h64,
      repository_writer_nids: { type: "array", items: radicleNid, uniqueItems: true },
      trusted_seed_nids: { type: "array", items: radicleNid, uniqueItems: true },
    },
  ),
  "host-advertisement-v1": workspaceSchema(
    "host-advertisement-v1",
    [
      "host_id", "host_nid", "trusted_seed_nids", "radicle_locators", "onion_endpoints",
      "clearnet_endpoints", "supported_features", "inheritance",
      "key_custody_resource_ids", "priority", "expires_at",
    ],
    {
      host_id: h64,
      host_nid: radicleNid,
      trusted_seed_nids: { type: "array", items: radicleNid, uniqueItems: true },
      radicle_locators: { type: "array", minItems: 1, uniqueItems: true, items: radicleRid },
      onion_endpoints: { type: "array", uniqueItems: true, items: { type: "string", pattern: "^https?://[a-z2-7]{56}\\.onion(?::[0-9]{1,5})?$" } },
      clearnet_endpoints: { type: "array", uniqueItems: true, items: { type: "string", pattern: "^https://" } },
      supported_features: { type: "array", minItems: 1, uniqueItems: true, items: { type: "string", pattern: "^[a-z][a-z0-9.-]+\\.v[0-9]+$" } },
      inheritance: { enum: ["default", "supplement", "replace"] },
      key_custody_resource_ids: identifierArray,
      priority: { type: "integer", minimum: 0, maximum: 65_535 },
      expires_at: timestamp,
    },
  ),
  "service-advertisement-v1": workspaceSchema(
    "service-advertisement-v1",
    ["service_id", "role_id", "service_type", "profile_id", "endpoints", "audience_role_id", "operator_account", "expires_at"],
    {
      service_id: h64,
      role_id: h64,
      service_type: { type: "string", pattern: "^[a-z][a-z0-9-]{0,63}$" },
      profile_id: { type: "string", pattern: "^[a-z][a-z0-9.-]+\\.v[0-9]+$" },
      endpoints: { type: "array", minItems: 1, uniqueItems: true, items: { type: "string", minLength: 1, maxLength: 2048 } },
      audience_role_id: h64,
      operator_account: h64,
      expires_at: timestamp,
    },
  ),
  "workspace-relationship-v1": workspaceSchema(
    "workspace-relationship-v1",
    [
      "relationship_id", "source_workspace_key", "receiving_workspace_key",
      "source_role_id", "receiving_role_id", "capability_ceiling",
      "proof_max_age", "grace_period", "expires_at",
      "independently_revocable", "receiving_policy_head",
      "receiving_predecessor", "receiving_authority_checkpoint",
      "receiving_signature",
    ],
    {
      relationship_id: h64,
      source_workspace_key: h64,
      receiving_workspace_key: h64,
      source_role_id: h64,
      receiving_role_id: h64,
      capability_ceiling: capabilities,
      proof_max_age: { type: "integer", minimum: 0, maximum: 86_400 },
      grace_period: { type: "integer", minimum: 0, maximum: 86_400 },
      expires_at: timestamp,
      independently_revocable: { const: true },
      receiving_policy_head: h64,
      receiving_predecessor: nullableH64,
      receiving_authority_checkpoint: h64,
      receiving_signature: signature,
    },
  ),
  "workspace-relationship-receipt-v1": workspaceSchema(
    "workspace-relationship-receipt-v1",
    [
      "receipt_id", "relationship_id", "receiving_role_id",
      "source_workspace_key", "source_relationship_object_id",
      "source_policy_head", "source_predecessor", "source_authority_checkpoint",
      "source_repository_rid", "source_repository_head", "received_at",
    ],
    {
      receipt_id: h64,
      relationship_id: h64,
      receiving_role_id: h64,
      source_workspace_key: h64,
      source_relationship_object_id: h64,
      source_policy_head: h64,
      source_predecessor: nullableH64,
      source_authority_checkpoint: h64,
      source_repository_rid: radicleRid,
      source_repository_head: h40,
      received_at: timestamp,
    },
  ),
  "joint-workspace-relationship-v1": workspaceSchema(
    "joint-workspace-relationship-v1",
    [
      "relationship_id", "joint_workspace_key", "participant_workspace_keys",
      "delegate_keys", "threshold", "resource_scope", "effective_at",
      "expires_at",
    ],
    {
      relationship_id: h64,
      joint_workspace_key: h64,
      participant_workspace_keys: { type: "array", minItems: 2, uniqueItems: true, items: h64 },
      delegate_keys: { type: "array", minItems: 2, uniqueItems: true, items: h64 },
      threshold: { type: "integer", minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
      resource_scope: { ...identifierArray, minItems: 1 },
      effective_at: timestamp,
      expires_at: nullableTimestamp,
    },
  ),
  "resource-key-envelope-v1": workspaceSchema(
    "resource-key-envelope-v1",
    [
      "envelope_id", "resource_id", "grant_id", "key_epoch", "admission_epoch", "target_account",
      "target_device", "recipient", "role_id", "checkpoint_id", "custody_host_id",
      "wrapping_profile", "nonce", "ciphertext", "ciphertext_sha256",
      "created_at",
    ],
    {
      envelope_id: h64,
      resource_id: h64,
      grant_id: h64,
      key_epoch: nonNegativeInteger,
      admission_epoch: nonNegativeInteger,
      target_account: h64,
      target_device: h64,
      recipient: {
        type: "object",
        additionalProperties: false,
        required: ["type", "value"],
        properties: {
          type: { const: "marmot-mls-leaf" },
          value: marmotLeaf,
        },
      },
      role_id: h64,
      checkpoint_id: h64,
      custody_host_id: h64,
      wrapping_profile: { const: "marmot-mls-application-v1" },
      nonce: { type: "string", pattern: "^[A-Za-z0-9_-]{16,128}$" },
      ciphertext: { type: "string", pattern: "^[A-Za-z0-9_-]+$" },
      ciphertext_sha256: h64,
      created_at: timestamp,
    },
  ),
};

export function writeWorkspaceSchemas(repositoryRoot: string): string[] {
  const directory = resolve(repositoryRoot, "docs/spec/schemas/workspace");
  mkdirSync(directory, { recursive: true });
  const written: string[] = [];
  for (const [name, schema] of Object.entries(WORKSPACE_SCHEMAS)) {
    const path = resolve(directory, `${name}.schema.json`);
    writeFileSync(path, `${JSON.stringify(schema, null, 2)}\n`, "utf8");
    written.push(path);
  }
  return written;
}
