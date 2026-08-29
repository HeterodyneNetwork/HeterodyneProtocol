import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv, type AnySchema } from "ajv";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_CONTINUITY_SCHEMA_FILES,
  CREDENTIAL_CONTINUITY_SCHEMAS,
  KEY_CLAIM_REVOCATION_SCHEMA,
  KEY_CLAIM_SCHEMA,
  VECTOR_SCHEMA,
  validateClaimRevocationSchemaOrThrow,
  validateCredentialContinuitySchemaOrThrow,
  validateKeyClaimSchemaOrThrow,
  validateOneTimeInviteResponseSchemaOrThrow,
  validateOneTimeInviteSchemaOrThrow,
  validateVectorOrThrow,
} from "./schema.js";

const assuranceSchemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/assurance",
);

const commsSchemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/comms",
);

const controlSchemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/control",
);

const socialSchemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/social",
);

const marmotSchemaNames = [
  "marmot-group-directory-v1.schema.json",
  "marmot-persona-inbox-bundle-v1.schema.json",
  "marmot-persona-inbox-manifest-v1.schema.json",
  "marmot-routing-binding-v1.schema.json",
  "marmot-event-repository-genesis-v1.schema.json",
] as const;

const marmotSchemas = new Ajv({ allErrors: true, strict: false });
for (const name of marmotSchemaNames) {
  marmotSchemas.addSchema(JSON.parse(
    readFileSync(resolve(commsSchemasRoot, name), "utf8"),
  ) as AnySchema);
}

function validateMarmotSchema(name: typeof marmotSchemaNames[number], value: unknown): string | null {
  const id = `https://heterodyne.network/schemas/comms/${name}`;
  const validate = marmotSchemas.getSchema(id);
  if (validate === undefined) throw new Error(`missing Marmot schema: ${id}`);
  return validate(value) ? null : JSON.stringify(validate.errors);
}

function validateAssuranceSchema(name: string, value: unknown): string | null {
  const schema = JSON.parse(
    readFileSync(resolve(assuranceSchemasRoot, name), "utf8"),
  ) as AnySchema;
  const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);
  return validate(value) ? null : JSON.stringify(validate.errors);
}

function validateCommsSchema(
  name: string,
  value: unknown,
  draft: "draft-07" | "2020-12" = "draft-07",
): string | null {
  const schema = JSON.parse(
    readFileSync(resolve(commsSchemasRoot, name), "utf8"),
  ) as AnySchema;
  const validate = draft === "2020-12"
    ? new Ajv2020({ allErrors: true, strict: false }).compile(schema)
    : new Ajv({ allErrors: true, strict: false }).compile(schema);
  return validate(value) ? null : JSON.stringify(validate.errors);
}

function validateControlSchema(name: string, value: unknown): string | null {
  const schema = JSON.parse(
    readFileSync(resolve(controlSchemasRoot, name), "utf8"),
  ) as AnySchema & { $schema?: string };
  const validate = schema.$schema?.includes("2020-12")
    ? new Ajv2020({ allErrors: true, strict: false }).compile(schema)
    : new Ajv({ allErrors: true, strict: false }).compile(schema);
  return validate(value) ? null : JSON.stringify(validate.errors);
}

function validateSocialSchema(name: string, value: unknown): string | null {
  const schema = JSON.parse(
    readFileSync(resolve(socialSchemasRoot, name), "utf8"),
  ) as AnySchema;
  const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema);
  return validate(value) ? null : JSON.stringify(validate.errors);
}

const h = (byte: string) => byte.repeat(64);
const sig = (byte: string) => byte.repeat(128);

describe("Social active-author policy schemas", () => {
  const author = h("a");
  const association = { kind: "key", value: author };
  const policy = { id: "network.heterodyne.agent-policy", version: "1.0.0" };
  const receipt = {
    profile: "heterodyne.social.agent-policy-receipt.v1",
    spec_version: "heterodyne/0.6.0",
    event_id: h("b"),
    event_author: author,
    agent_association: association,
    policy,
    decision: "advisory-violation",
    reason: "agent-attribution-missing",
    observed_at: 1_000,
    evidence: ["sha256:abcd"],
    explanation: "Automated publication omitted mandatory attribution.",
    remediation: "replace-signing-key",
  };
  const correction = {
    profile: "heterodyne.social.agent-policy-correction.v1",
    spec_version: "heterodyne/0.6.0",
    corrects_receipt_id: h("c"),
    event_id: receipt.event_id,
    event_author: author,
    agent_association: association,
    policy,
    decision: "retract",
    corrected_at: 1_100,
    evidence: ["sha256:dcba"],
    explanation: "The original evidence was misclassified.",
  };

  it("accepts closed receipt and correction objects bound to the active event author", () => {
    expect(validateSocialSchema("agent-policy-receipt-v1.schema.json", receipt)).toBeNull();
    expect(validateSocialSchema("agent-policy-correction-v1.schema.json", correction)).toBeNull();
  });

  it("rejects root, KEL, epoch, and device-authority aliases", () => {
    for (const legacy of [
      { cold_root: h("d") },
      { kel_head: h("e") },
      { epoch_key: h("f") },
      { device_key: h("0") },
    ]) {
      expect(validateSocialSchema(
        "agent-policy-receipt-v1.schema.json",
        { ...receipt, ...legacy },
      )).toMatch(/additionalProperties/);
      expect(validateSocialSchema(
        "agent-policy-correction-v1.schema.json",
        { ...correction, ...legacy },
      )).toMatch(/additionalProperties/);
    }
    expect(validateSocialSchema(
      "agent-policy-correction-v1.schema.json",
      { ...correction, reason: receipt.reason },
    )).toMatch(/additionalProperties/);
  });

  it("requires the author, association, policy, decision, evidence, and correction relationship", () => {
    for (const member of [
      "event_author",
      "agent_association",
      "policy",
      "decision",
      "evidence",
    ]) {
      const invalid = { ...receipt } as Record<string, unknown>;
      delete invalid[member];
      expect(validateSocialSchema("agent-policy-receipt-v1.schema.json", invalid))
        .toMatch(new RegExp(`${member}|required`));
    }
    for (const member of [
      "corrects_receipt_id",
      "event_id",
      "event_author",
      "agent_association",
      "policy",
      "decision",
      "evidence",
    ]) {
      const invalid = { ...correction } as Record<string, unknown>;
      delete invalid[member];
      expect(validateSocialSchema("agent-policy-correction-v1.schema.json", invalid))
        .toMatch(new RegExp(`${member}|required`));
    }
  });
});

describe("multi-persona Control schemas", () => {
  const persona = h("1");
  const successor = h("2");
  const client = h("3");
  const signer = h("4");
  const vaultId = h("5");
  const grantId = h("6");
  const audience = "https://node.example/nip46/persona-1";
  const grant = {
    profile: "heterodyne.control.signer-grant.v1",
    spec_version: "heterodyne/0.6.0",
    grant_id: grantId,
    vault_id: vaultId,
    persona_active_key: persona,
    nip46_client_pubkey: client,
    signer_audience: audience,
    selected_signing_pubkey: signer,
    key_class: "agent",
    persona_signing_authorized: false,
    allowed_methods: ["sign_event"],
    allowed_event_kinds: [1, 30023],
    limits: {
      request_window_seconds: 60,
      request_count: 20,
      max_event_bytes: 4096,
      max_value_msats: 0,
    },
    oidc_authorization_id: h("7"),
    connection_secret_sha256: h("8"),
    issued_at: 100,
    expires_at: 200,
    predecessor: null,
    state: "active",
    revoked_at: null,
    authorizing_pubkey: persona,
    signature: sig("9"),
  };
  const requiredReset = {
    nip46_oidc_grant_ids: [grantId],
    client_ids: [client],
    repository_ids: [h("6")],
    delegate_ids: [h("a")],
    node_ids: [h("b")],
    agent_ids: [signer],
    trusted_seed_nids: ["did:key:z6MkwQp8f8Y11L3WJYJ4hXa1"],
    marmot_leaf_ids: [h("c")],
    reachable_groups: [{ group_id: h("d"), epoch: 7 }],
    unreachable_group_ids: [h("0")],
    subordinate_authority_ids: [h("a"), h("b"), signer],
  };
  const recoveryGrant = {
    profile: "heterodyne.control.compromise-reset-grant.v1",
    spec_version: "heterodyne/0.6.0",
    recovery_id: h("e"),
    persona_active_key: persona,
    successor_active_key: successor,
    authorization_class: "active-account",
    authorizing_pubkey: persona,
    assurance_head: null,
    inventory_id: h("f"),
    inventory_revision: 12,
    inventory_digest: h("0"),
    compromise_at: 120,
    required_reset: requiredReset,
    issued_at: 121,
    expires_at: 180,
    state: "active",
    revoked_at: null,
    signature: sig("f"),
  };
  const recoveryCompletion = {
    profile: "heterodyne.control.compromise-reset-completion.v1",
    spec_version: "heterodyne/0.6.0",
    recovery_id: recoveryGrant.recovery_id,
    persona_active_key: persona,
    successor_active_key: successor,
    inventory_id: recoveryGrant.inventory_id,
    inventory_revision: recoveryGrant.inventory_revision,
    inventory_digest: recoveryGrant.inventory_digest,
    evidence_revision: 13,
    revoked_nip46_oidc_grant_ids: [grantId],
    invalidated_client_ids: [client],
    invalidated_repository_ids: [h("6")],
    invalidated_delegate_ids: [h("a")],
    invalidated_node_ids: [h("b")],
    invalidated_agent_ids: [signer],
    invalidated_trusted_seed_nids: requiredReset.trusted_seed_nids,
    removed_marmot_leaf_ids: [h("c")],
    advanced_group_ids: [h("d")],
    stalled_group_ids: [h("0")],
    fresh_keypackages: [{
      keypackage_id: h("7"), account_key: successor, group_id: h("d"), event_id: h("8"),
      event: {
        id: h("8"), pubkey: successor, created_at: 125, kind: 30443,
        tags: [["d", h("1")], ["i", h("7")]], content: "YWJj", sig: sig("8"),
      },
      content_sha256: h("9"), mls_verifier_pubkey: h("a"), verification_signature: sig("a"),
    }],
    subordinate_reauthorizations: [
      {
        prior_authority_id: h("a"), authorization_id: h("1"), authority_class: "delegate",
        successor_active_key: successor, issued_at: 130, expires_at: 180,
        permissions_digest: h("4"), contract_digest: h("5"),
      },
      {
        prior_authority_id: h("b"), authorization_id: h("2"), authority_class: "node",
        successor_active_key: successor, issued_at: 130, expires_at: 180,
        permissions_digest: h("5"), contract_digest: h("6"),
      },
      {
        prior_authority_id: signer, authorization_id: h("3"), authority_class: "agent",
        successor_active_key: successor, issued_at: 130, expires_at: 180,
        permissions_digest: h("6"), contract_digest: h("7"),
      },
    ],
    transition_evidence: {
      nip46_oidc_grants: [{ subject_id: grantId, evidence_id: h("1") }],
      clients: [{ subject_id: client, evidence_id: h("2") }],
      repositories: [{ subject_id: h("6"), evidence_id: h("0") }],
      delegates: [{ subject_id: h("a"), evidence_id: h("3") }],
      nodes: [{ subject_id: h("b"), evidence_id: h("4") }],
      agents: [{ subject_id: signer, evidence_id: h("5") }],
      trusted_seeds: [{ subject_nid: requiredReset.trusted_seed_nids[0], evidence_id: h("6") }],
      marmot_leaves: [{ subject_id: h("c"), evidence_id: h("7") }],
      groups: [{ group_id: h("d"), prior_epoch: 7, next_epoch: 8, evidence_id: h("8") }],
      stalled_groups: [{ subject_id: h("0"), evidence_id: h("9") }],
    },
    evidence_bundle_digest: h("a"),
    completed_at: 130,
    signer: successor,
    signature: sig("4"),
  };
  const fixtures = [
    ["control-client-authorization-v1.schema.json", grant],
    ["control-agent-publish-v1.schema.json", {
      profile: "heterodyne.control.agent-publish-intent.v1",
      spec_version: "heterodyne/0.6.0",
      grant_id: grantId,
      vault_id: vaultId,
      persona_active_key: persona,
      nip46_client_pubkey: client,
      signer_audience: audience,
      selected_signing_pubkey: signer,
      key_class: "agent",
      created_at: 125,
      kind: 1,
      tags: [["t", "heterodyne"]],
      content: "bounded publication intent",
      value_msats: 0,
      agent_class: "ai",
      agent_association: { kind: "key", value: signer },
      tier: 1,
    }],
    ["control-audit-record-v1.schema.json", {
      profile: "heterodyne.control.audit-record.v1",
      spec_version: "heterodyne/0.6.0",
      grant_id: grantId,
      vault_id: vaultId,
      persona_active_key: persona,
      nip46_client_pubkey: client,
      signer_audience: audience,
      selected_signing_pubkey: signer,
      key_class: "agent",
      request_id: h("5"),
      method: "sign_event",
      event_kind: 1,
      payload_digest: h("6"),
      attribution_state: "applied",
      decision: "accept",
      reason_code: null,
      event_id: h("7"),
      created_at: 126,
    }],
    ["control-capability-set-v1.schema.json", {
      profile: "heterodyne.control.capability-set.v1",
      spec_version: "heterodyne/0.6.0",
      node_mode: "full",
      max_persona_vaults: 16,
      custody_modes: ["local", "nip46"],
      nip46_methods: ["sign_event", "nip44_decrypt"],
      oidc_activation: true,
      one_use_connection_secrets: true,
      automation_attribution: true,
      compromise_reset: true,
    }],
    ["control-device-authorization-state-v1.schema.json", {
      profile: "heterodyne.control.device-authorization-state.v1",
      spec_version: "heterodyne/0.6.0",
      transaction_id: h("8"),
      grant_id: grantId,
      oidc_authorization_id: grant.oidc_authorization_id,
      revision: 0,
      persona_active_key: persona,
      nip46_client_pubkey: client,
      signer_audience: audience,
      selected_signing_pubkey: signer,
      key_class: "agent",
      requested_methods: ["sign_event"],
      requested_event_kinds: [1],
      requested_limits: grant.limits,
      connection_secret_sha256: grant.connection_secret_sha256,
      connection_secret_state: "pending",
      device_code_sha256: h("9"),
      device_code_entropy_bits: 128,
      user_code_sha256: h("a"),
      user_code_entropy_bits: 34.5,
      normalization: "uppercase-ascii-remove-hyphen",
      client_fingerprint: "NIP-46 client 33333333",
      failed_guesses: 0,
      max_failed_guesses: 5,
      interval_seconds: 5,
      issued_at: 100,
      expires_at: 200,
      state: "approved",
    }],
    ["control-operation-record-v1.schema.json", {
      profile: "heterodyne.control.signing-operation.v1",
      spec_version: "heterodyne/0.6.0",
      operation_id: h("b"),
      request_id: "nostr-tools-1",
      grant_id: grantId,
      grant_digest: h("f"),
      vault_id: vaultId,
      persona_active_key: persona,
      nip46_client_pubkey: client,
      signer_audience: audience,
      selected_signing_pubkey: signer,
      key_class: "agent",
      rpc_request: { id: "nostr-tools-1", method: "sign_event", params: ["{}"] },
      event_kind: 1,
      value_msats: 0,
      request_digest: h("d"),
      execution_token: h("c"),
      window_started_at: 100,
      attribution_state: "applied",
      signature_state: "produced",
      event_id: h("e"),
      state: "committed",
      result_digest: h("e"),
      failure_digest: null,
      commit_evidence: {
        expected_revision: 5,
        next_revision: 6,
        prior_state: "executing",
        state: "committed",
        persisted_at: 126,
      },
      created_at: 125,
      updated_at: 126,
    }],
    ["control-recovery-grant-v1.schema.json", recoveryGrant],
    ["control-recovery-completion-v1.schema.json", recoveryCompletion],
  ] as const;

  it.each(fixtures)("accepts the exact closed %s contract", (name, value) => {
    expect(validateControlSchema(name, value)).toBeNull();
    expect(validateControlSchema(name, { ...value, kel_head: h("f") }))
      .toMatch(/additionalProperties/);
  });

  it("requires every authority-bearing signer grant binding", () => {
    for (const member of [
      "persona_active_key",
      "nip46_client_pubkey",
      "signer_audience",
      "selected_signing_pubkey",
      "key_class",
      "allowed_methods",
      "allowed_event_kinds",
      "limits",
      "issued_at",
      "expires_at",
      "state",
    ]) {
      const missing = structuredClone(grant) as Record<string, unknown>;
      delete missing[member];
      expect(
        validateControlSchema("control-client-authorization-v1.schema.json", missing),
        member,
      ).toMatch(/required/);
    }
  });

  it("makes persona authority explicit and revocation state closed", () => {
    expect(validateControlSchema("control-client-authorization-v1.schema.json", {
      ...grant,
      selected_signing_pubkey: persona,
      key_class: "persona",
      persona_signing_authorized: true,
    })).toBeNull();
    expect(validateControlSchema("control-client-authorization-v1.schema.json", {
      ...grant,
      selected_signing_pubkey: persona,
      key_class: "persona",
      persona_signing_authorized: false,
    })).toMatch(/persona_signing_authorized|const/);
    expect(validateControlSchema("control-client-authorization-v1.schema.json", {
      ...grant,
      state: "revoked",
      revoked_at: null,
    })).toMatch(/revoked_at|type/);
  });

  it("preserves hardened device authorization and operation ordering", () => {
    const device = structuredClone(fixtures[4][1]) as Record<string, unknown>;
    delete device.client_fingerprint;
    expect(validateControlSchema(
      "control-device-authorization-state-v1.schema.json",
      device,
    )).toMatch(/client_fingerprint|required/);

    const operation = fixtures[5][1];
    expect(validateControlSchema("control-operation-record-v1.schema.json", {
      ...operation,
      attribution_state: "required",
      signature_state: "produced",
    })).toMatch(/attribution_state|not|const/);

    expect(validateControlSchema("control-operation-record-v1.schema.json", {
      ...operation,
      state: "claimed",
      signature_state: "produced",
      event_id: h("e"),
      result_digest: null,
      failure_digest: null,
      commit_evidence: {
        expected_revision: 4,
        next_revision: 5,
        prior_state: "reserved",
        state: "claimed",
        persisted_at: 125,
      },
    })).toMatch(/signature_state|event_id|const|pending/);

    expect(validateControlSchema("control-operation-record-v1.schema.json", {
      ...operation,
      state: "executing",
      attribution_state: "required",
      signature_state: "pending",
      event_id: null,
      result_digest: null,
      failure_digest: null,
      commit_evidence: {
        expected_revision: 5,
        next_revision: 6,
        prior_state: "claimed",
        state: "executing",
        persisted_at: 126,
      },
    })).toMatch(/attribution_state|not-applicable|applied/);

    expect(validateControlSchema("control-operation-record-v1.schema.json", {
      ...operation,
      state: "indeterminate",
      attribution_state: "required",
      signature_state: "indeterminate",
      event_id: null,
      result_digest: null,
      failure_digest: h("f"),
      commit_evidence: {
        expected_revision: 6,
        next_revision: 7,
        prior_state: "executing",
        state: "indeterminate",
        persisted_at: 127,
      },
    })).toMatch(/attribution_state|not-applicable|applied/);

    expect(validateControlSchema("control-operation-record-v1.schema.json", {
      ...operation,
      request_id: "🔐-1",
      rpc_request: { ...operation.rpc_request, id: "🔐-1" },
    })).toMatch(/request_id|pattern|rpc_request/);
  });

  it("requires the closed automated attribution contract and permits explicit null association", () => {
    const publication = structuredClone(fixtures[1][1]) as Record<string, unknown>;
    publication.agent_association = null;
    expect(validateControlSchema(
      "control-agent-publish-v1.schema.json",
      publication,
    )).toBeNull();

    delete publication.agent_association;
    expect(validateControlSchema(
      "control-agent-publish-v1.schema.json",
      publication,
    )).toMatch(/agent_association|required/);

    expect(validateControlSchema("control-agent-publish-v1.schema.json", {
      ...fixtures[1][1],
      tier: 0,
    })).toMatch(/tier|enum/);
    expect(validateControlSchema("control-agent-publish-v1.schema.json", {
      ...fixtures[1][1],
      kind: 2,
    })).toMatch(/kind|enum/);
  });
});

describe("trusted private seed and flexible agent schemas", () => {
  const administratorAccount = h("1");
  const personaKey = h("2");
  const agentKey = h("3");
  const seedNid = "did:key:z6MkwQp8f8Y11L3WJYJ4hXa1";
  const privateRid = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
  const acl = {
    profile: "heterodyne.trusted-seed-acl.v1",
    spec_version: "heterodyne/0.6.0",
    administrator_account: administratorAccount,
    accounts: [{ account_key: personaKey, roles: ["read", "write"] }],
    h: "private-routing-id",
    private_rid: privateRid,
    seed_grants: [{
      seed_nid: seedNid,
      relay_endpoint: "wss://seed.example/group",
      radicle_endpoint: privateRid,
      writer_ref: "refs/xyz.heterodyne.marmot/relays/seed-a",
      roles: ["read", "write"],
      state: "active",
    }],
    sequence: 0,
    predecessor: null,
    group_transition: {
      generation: 7,
      marmot_routing_event_id: h("4"),
      routing_binding_sha256: h("5"),
    },
    issued_at: 1_785_000_000,
    expires_at: 1_785_003_600,
    signature: sig("6"),
  };

  const workload = {
    persona_key: personaKey,
    client_id: "agent-client",
    subject_jkt: "A".repeat(43),
    subject_proof: { method: "dpop", jkt: "A".repeat(43) },
    agent_class: "ai",
    selected_signer: agentKey,
    signer_key_class: "agent",
    agent_association: { kind: "key", value: agentKey },
    audience: "https://node.example/control/agent-publication",
    scopes: ["heterodyne:agent:publish"],
    allowed_kinds: [1, 30023],
    allowed_feeds: ["main"],
    allowed_resources: ["feed:main"],
    max_content_bytes: 4096,
    rate_limit: { window_seconds: 60, count: 20, burst: 5 },
    not_before: 1_785_000_000,
    expires_at: 1_785_003_600,
  };

  const continuity = {
    profile: "heterodyne-oidc-continuity-v1",
    repository_rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
    branch: "main",
    persona_npub: `npub1${"q".repeat(58)}`,
    persona_key: personaKey,
    issuer: `https://issuer.example/oidc/npub1${"q".repeat(58)}`,
    sequence: 0,
    predecessor_digest: null,
    max_checkpoint_age_seconds: 300,
    authorization_view_max_age: 300,
    current_jwks_sha256: h("7"),
    current_signing_key_id: "B".repeat(43),
    current_signing_jwk_sha256: h("8"),
    retiring_signing_key_ids: [],
    retiring_jwks_sha256: [],
    status_lists: [],
    successor: null,
    authority: {
      writer_nid: seedNid,
      issued_at: 1_785_000_000,
      checkpoint: {
        repository_rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
        branch: "main",
        commit_oid: h("9"),
        observed_at: 1_785_000_000,
      },
    },
    authority_proof: {
      type: "radicle-ed25519",
      public_key: h("a"),
      signature: sig("b"),
    },
  };

  it("accepts the exact closed trusted-seed ACL projection", () => {
    expect(validateCommsSchema("trusted-seed-acl-v1.schema.json", acl)).toBeNull();
    for (const member of [
      "profile", "accounts", "h", "private_rid", "seed_grants", "sequence",
      "predecessor", "group_transition", "issued_at", "expires_at", "signature",
    ]) {
      const missing = structuredClone(acl) as Record<string, unknown>;
      delete missing[member];
      expect(
        validateCommsSchema("trusted-seed-acl-v1.schema.json", missing),
        member,
      ).toMatch(/required/);
    }
    expect(validateCommsSchema(
      "trusted-seed-acl-v1.schema.json",
      { ...acl, mls_leaf_secret: h("c") },
    )).toMatch(/additionalProperties/);
  });

  it("binds workload registration to persona, signer class, public association, kinds, expiry, and subject proof", () => {
    expect(validateCommsSchema(
      "agent-workload-registration-v1.schema.json",
      workload,
      "2020-12",
    )).toBeNull();
    for (const member of [
      "persona_key", "selected_signer", "signer_key_class", "allowed_kinds",
      "expires_at", "subject_proof",
    ]) {
      const missing = structuredClone(workload) as Record<string, unknown>;
      delete missing[member];
      expect(validateCommsSchema(
        "agent-workload-registration-v1.schema.json",
        missing,
        "2020-12",
      ), member).toMatch(/required/);
    }

    const personaSigner = {
      ...workload,
      selected_signer: personaKey,
      signer_key_class: "persona",
      scopes: ["heterodyne:agent:publish", "heterodyne:agent:sign:persona"],
    };
    expect(validateCommsSchema(
      "agent-workload-registration-v1.schema.json",
      personaSigner,
      "2020-12",
    )).toBeNull();
    expect(validateCommsSchema(
      "agent-workload-registration-v1.schema.json",
      {
        ...personaSigner,
        agent_association: { kind: "role", value: "newsletter" },
      },
      "2020-12",
    )).toBeNull();
    expect(validateCommsSchema(
      "agent-workload-registration-v1.schema.json",
      { ...personaSigner, scopes: ["heterodyne:agent:publish"] },
      "2020-12",
    )).toMatch(/contains/);
  });

  it("binds OIDC continuity to the active persona key without a cold-root or KEL prerequisite", () => {
    expect(validateCommsSchema(
      "oidc-continuity-manifest-v1.schema.json",
      continuity,
    )).toBeNull();
    expect(validateCommsSchema(
      "oidc-continuity-manifest-v1.schema.json",
      { ...continuity, cold_root_hex: h("c") },
    )).toMatch(/additionalProperties/);
    const { persona_key: _persona, ...missingPersona } = continuity;
    expect(validateCommsSchema(
      "oidc-continuity-manifest-v1.schema.json",
      missingPersona,
    )).toMatch(/persona_key|required/);
  });

  it("requires independent closed checkpoint and authorization-view freshness bounds", () => {
    expect(validateCommsSchema(
      "oidc-continuity-manifest-v1.schema.json",
      { ...continuity, authorization_view_max_age: 86_400 },
    )).toBeNull();

    for (const authorizationViewMaxAge of [0, 86_401, 300.5]) {
      expect(validateCommsSchema(
        "oidc-continuity-manifest-v1.schema.json",
        { ...continuity, authorization_view_max_age: authorizationViewMaxAge },
      ), String(authorizationViewMaxAge)).not.toBeNull();
    }

    const missing = { ...continuity } as Record<string, unknown>;
    delete missing.authorization_view_max_age;
    expect(validateCommsSchema(
      "oidc-continuity-manifest-v1.schema.json",
      missing,
    )).toMatch(/authorization_view_max_age|required/);
    expect(validateCommsSchema(
      "oidc-continuity-manifest-v1.schema.json",
      { ...continuity, authorization_view_fresh: true },
    )).toMatch(/additionalProperties/);
    expect(validateCommsSchema(
      "oidc-continuity-manifest-v1.schema.json",
      { ...continuity, max_checkpoint_age_seconds: 301 },
    )).toMatch(/maximum/);
  });
});

const assuranceInception = {
  profile: "heterodyne.assurance.enrollment-inception.v1",
  spec_version: "heterodyne/0.6.0",
  active_key: h("1"),
  created_at: 1_785_000_000,
  predecessor: null,
  cold_root: h("2"),
  succession_authority: h("3"),
  epoch_policy: {
    mode: "pre-rotation",
    current_keys: [h("4")],
    next_key_commitments: [h("5")],
  },
  witnesses: [{ key: h("6"), weight: 1 }],
  thresholds: { epoch: 1, witness: 1 },
  associated_key_policy: {
    active_key: [{
      role: "agent",
      scope: ["nostr:kind:1", "nostr:kind:6"],
    }],
    epoch_threshold: [{
      role: "agent",
      scope: ["nostr:kind:1"],
    }],
  },
};

const assuranceAcceptance = {
  profile: "heterodyne.assurance.active-key-acceptance.v1",
  spec_version: "heterodyne/0.6.0",
  active_key: assuranceInception.active_key,
  created_at: assuranceInception.created_at + 1,
  predecessor: h("7"),
  inception_event_id: h("7"),
  cold_root: assuranceInception.cold_root,
  cold_root_signature: sig("8"),
  assurance_head: h("7"),
  state: "assured",
};

const assuranceSuccession = {
  profile: "heterodyne.assurance.succession.v1",
  spec_version: "heterodyne/0.6.0",
  active_key: assuranceInception.active_key,
  created_at: assuranceInception.created_at + 2,
  predecessor: h("7"),
  previous_active_key: assuranceInception.active_key,
  previous_head: h("7"),
  new_active_key: h("9"),
  authorizing_evidence: {
    authority_class: "succession",
    authority_proofs: [{
      authority_key: assuranceInception.succession_authority,
      signature: sig("a"),
    }],
    witness_receipts: [{ witness_key: h("6"), signature: sig("b") }],
  },
  new_key_acceptance: { key: h("9"), signature: sig("c") },
  class: "routine",
  next_succession_authority: h("b"),
  next_epoch_policy: {
    mode: "pre-rotation",
    current_keys: [h("9")],
    next_key_commitments: [h("a")],
  },
  witnesses: [{ key: h("6"), weight: 1 }],
  thresholds: { epoch: 1, witness: 1 },
  next_associated_key_policy: assuranceInception.associated_key_policy,
  subordinate_reauthorizations: [{
    role: "agent",
    subject_key: h("d"),
    scope: ["nostr:kind:1"],
    expires_at: assuranceInception.created_at + 3_600,
  }],
};

const assuranceAssociatedKey = {
  profile: "heterodyne.assurance.associated-key.v1",
  spec_version: "heterodyne/0.6.0",
  active_key: assuranceInception.active_key,
  created_at: assuranceInception.created_at + 3,
  predecessor: h("e"),
  assurance_head: h("7"),
  role: "agent",
  scope: ["nostr:kind:1"],
  issuer: assuranceInception.active_key,
  issuer_authority: {
    class: "active-key",
    authority_proofs: [],
  },
  subject_key: h("f"),
  expires_at: assuranceInception.created_at + 3_600,
  visibility: "public",
  subject_proof: sig("0"),
  state: "active",
};

describe("Assurance record schemas", () => {
  const fixtures = [
    ["enrollment-inception-v1.schema.json", assuranceInception],
    ["active-key-acceptance-v1.schema.json", assuranceAcceptance],
    ["succession-v1.schema.json", assuranceSuccession],
    ["associated-key-v1.schema.json", assuranceAssociatedKey],
  ] as const;

  it.each(fixtures)("accepts the exact closed %s record", (name, value) => {
    expect(validateAssuranceSchema(name, value)).toBeNull();
    expect(validateAssuranceSchema(name, { ...value, unbound_authority: true }))
      .toMatch(/additionalProperties/);
  });

  it("requires reciprocal enrollment and recovery-authority downgrade consent", () => {
    const { associated_key_policy: _policy, ...withoutIssuancePolicy } = assuranceInception;
    expect(validateAssuranceSchema(
      "enrollment-inception-v1.schema.json",
      withoutIssuancePolicy,
    )).toMatch(/associated_key_policy|required/);
    expect(validateAssuranceSchema(
      "enrollment-inception-v1.schema.json",
      { ...assuranceInception, predecessor: h("7") },
    )).toMatch(/predecessor|type/);
    const { cold_root_signature: _signature, ...withoutColdRootSignature } = assuranceAcceptance;
    expect(validateAssuranceSchema(
      "active-key-acceptance-v1.schema.json",
      withoutColdRootSignature,
    )).toMatch(/cold_root_signature|required/);
    expect(validateAssuranceSchema(
      "active-key-acceptance-v1.schema.json",
      { ...assuranceAcceptance, state: "downgraded" },
    )).toMatch(/downgrade_consent|required/);
    expect(validateAssuranceSchema(
      "active-key-acceptance-v1.schema.json",
      {
        ...assuranceAcceptance,
        state: "downgraded",
        downgrade_consent: {
          recovery_authority: assuranceInception.cold_root,
          signature: sig("1"),
        },
      },
    )).toBeNull();
  });

  it("binds succession to the prior head and closes compromise continuations", () => {
    const {
      next_associated_key_policy: _policy,
      ...withoutNextIssuancePolicy
    } = assuranceSuccession;
    expect(validateAssuranceSchema(
      "succession-v1.schema.json",
      withoutNextIssuancePolicy,
    )).toMatch(/next_associated_key_policy|required/);
    const {
      next_succession_authority: _authority,
      ...withoutNextSuccessionAuthority
    } = assuranceSuccession;
    expect(validateAssuranceSchema(
      "succession-v1.schema.json",
      withoutNextSuccessionAuthority,
    )).toMatch(/next_succession_authority|required/);
    const { previous_head: _head, ...withoutHead } = assuranceSuccession;
    expect(validateAssuranceSchema("succession-v1.schema.json", withoutHead))
      .toMatch(/previous_head|required/);
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      class: "routine",
      compromise_time: assuranceSuccession.created_at - 60,
    })).toMatch(/compromise_time|not/);
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      class: "compromise",
      subordinate_reauthorizations: [],
    })).toMatch(/compromise_time|required/);
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      class: "compromise",
      compromise_time: assuranceSuccession.created_at - 60,
    })).toMatch(/subordinate_reauthorizations|maxItems/);
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      class: "compromise",
      compromise_time: assuranceSuccession.created_at - 60,
      subordinate_reauthorizations: [],
      authorizing_evidence: {
        ...assuranceSuccession.authorizing_evidence,
        authority_class: "recovery",
      },
    })).toBeNull();
    expect(validateAssuranceSchema("succession-v1.schema.json", {
      ...assuranceSuccession,
      authorizing_evidence: {
        ...assuranceSuccession.authorizing_evidence,
        authority_class: "recovery",
      },
    })).toMatch(/authority_class|enum/);
  });

  it("requires subject proof only for active public-agent grants", () => {
    const { subject_proof: _proof, ...withoutSubjectProof } = assuranceAssociatedKey;
    expect(validateAssuranceSchema("associated-key-v1.schema.json", withoutSubjectProof))
      .toMatch(/subject_proof|required/);
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...withoutSubjectProof,
      visibility: "private",
    })).toBeNull();
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...assuranceAssociatedKey,
      state: "revoked",
    })).toMatch(/revocation|required/);
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...withoutSubjectProof,
      state: "revoked",
      revocation: {
        revoked_at: assuranceAssociatedKey.created_at + 1,
        reason: "compromise",
      },
    })).toBeNull();
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...assuranceAssociatedKey,
      state: "revoked",
      revocation: {
        revoked_at: assuranceAssociatedKey.created_at + 1,
        reason: "compromise",
      },
    })).toMatch(/subject_proof|not/);
    expect(validateAssuranceSchema("associated-key-v1.schema.json", {
      ...assuranceAssociatedKey,
      state: "revoked",
      revocation: {
        revoked_at: assuranceAssociatedKey.created_at + 1,
        reason: "compromise",
        continue_authority: true,
      },
    })).toMatch(/additionalProperties/);
  });

  it("accepts only the exact closed enrollment contest body", () => {
    const contestBody = {
      profile: "heterodyne.assurance.enrollment-contest.v1",
      spec_version: "heterodyne/0.6.0",
      inception_event_id: h("7"),
      cold_root: assuranceInception.cold_root,
    };

    expect(validateAssuranceSchema(
      "enrollment-contest-v1.schema.json",
      contestBody,
    )).toBeNull();
    expect(validateAssuranceSchema(
      "enrollment-contest-v1.schema.json",
      { ...contestBody, reason: "generic stamping is not content authority" },
    )).toMatch(/additionalProperties/);
    const { cold_root: _coldRoot, ...missingColdRoot } = contestBody;
    expect(validateAssuranceSchema(
      "enrollment-contest-v1.schema.json",
      missingColdRoot,
    )).toMatch(/cold_root|required/);
  });

  it("accepts only closed signed enrollment observation receipts", () => {
    const receipt = {
      profile: "heterodyne.assurance.enrollment-observation-receipt.v1",
      spec_version: "heterodyne/0.6.0",
      inception_event_id: h("7"),
      active_key: assuranceInception.active_key,
      cold_root: assuranceInception.cold_root,
      accepted_head: h("8"),
      first_observed_at: 1_784_000_000,
      last_observed_at: 1_784_604_800,
      conflict_free: true,
      witness_key: h("6"),
      signature: sig("a"),
    };

    expect(validateAssuranceSchema(
      "enrollment-observation-receipt-v1.schema.json",
      receipt,
    )).toBeNull();
    for (const invalid of [
      { ...receipt, conflict_free: false },
      { ...receipt, unsigned_hint: true },
    ]) {
      expect(validateAssuranceSchema(
        "enrollment-observation-receipt-v1.schema.json",
        invalid,
      )).not.toBeNull();
    }
    const { signature: _signature, ...unsigned } = receipt;
    expect(validateAssuranceSchema(
      "enrollment-observation-receipt-v1.schema.json",
      unsigned,
    )).toMatch(/signature|required/);
  });
});

describe("claim profile revision schema documentation", () => {
  it("names the frozen profile revision without registry-revision or duplicated terminology", () => {
    for (const schema of [KEY_CLAIM_SCHEMA, KEY_CLAIM_REVOCATION_SCHEMA]) {
      const description = (schema as {
        properties: { profile_revision: { description: string } };
      }).properties.profile_revision.description;
      expect(description).toMatch(/profile revision/i);
      expect(description).not.toMatch(/profile_profile_revision|profile registry revision/i);
    }
  });
});

describe("one-time invite schemas", () => {
  const descriptor = {
    version: 1,
    purpose: "dm",
    inviter_account: "11".repeat(32),
    invite_id: "22".repeat(32),
    rendezvous_pubkey: "33".repeat(32),
    relay_hints: ["wss://relay.example"],
    issued_at: 1_000,
    expires_at: 2_000,
    secret_sha256: "44".repeat(32),
    approval_mode: "interactive",
  };

  it("accepts closed invite and response shapes", () => {
    expect(() => validateOneTimeInviteSchemaOrThrow({
      descriptor,
      signature: "55".repeat(64),
      secret: "66".repeat(32),
    })).not.toThrow();
    expect(() => validateOneTimeInviteResponseSchemaOrThrow({
      spec_version: "heterodyne/0.6.0",
      purpose: "dm",
      descriptor_digest: "77".repeat(32),
      responder_account: "88".repeat(32),
      mls_key_package: "AQID",
      requested_class: "conversation-peer",
      capabilities: ["chat"],
      proof: "99".repeat(32),
    })).not.toThrow();
  });

  it("rejects extra authority and private-key members", () => {
    expect(() => validateOneTimeInviteSchemaOrThrow({
      descriptor,
      signature: "55".repeat(64),
      secret: "66".repeat(32),
      device_private_key: "77".repeat(32),
    })).toThrow(/additional/);
    expect(() => validateOneTimeInviteResponseSchemaOrThrow({
      spec_version: "heterodyne/0.6.0",
      purpose: "dm",
      descriptor_digest: "77".repeat(32),
      responder_account: "88".repeat(32),
      mls_key_package: "AQID",
      requested_class: "conversation-peer",
      capabilities: [],
      proof: "99".repeat(32),
      mls_leaf_private_key: "aa".repeat(32),
    })).toThrow(/additional/);
  });

  it("accepts active-account-only device enrollment and rejects legacy authority members", () => {
    expect(() => validateOneTimeInviteSchemaOrThrow({
      descriptor: { ...descriptor, purpose: "device-enrollment" },
      signature: "55".repeat(64),
      secret: "66".repeat(32),
    })).not.toThrow();
    for (const authority of [
      { inviter_authority: { persona: "11".repeat(32), kel_head: "22".repeat(32), epoch_key: "33".repeat(32), authority_event_id: "44".repeat(32) } },
      { kel_head: "22".repeat(32) },
      { epoch_key: "33".repeat(32) },
      { cold_root: "44".repeat(32) },
    ]) {
      expect(() => validateOneTimeInviteSchemaOrThrow({
        descriptor: { ...descriptor, purpose: "device-enrollment", ...authority },
        signature: "55".repeat(64),
        secret: "66".repeat(32),
      })).toThrow(/additional/);
    }
  });

  it("enforces purpose-specific preauthorization", () => {
    expect(() => validateOneTimeInviteSchemaOrThrow({
      descriptor: { ...descriptor, approval_mode: "preauthorized" },
      signature: "55".repeat(64),
      secret: "66".repeat(32),
    })).toThrow();
    expect(() => validateOneTimeInviteResponseSchemaOrThrow({
      spec_version: "heterodyne/0.6.0",
      purpose: "device-enrollment",
      descriptor_digest: "77".repeat(32),
      responder_account: "88".repeat(32),
      mls_key_package: "AQID",
      requested_class: "conversation-peer",
      capabilities: [],
      proof: "99".repeat(32),
    })).toThrow();
  });
});

describe("active-account Marmot repository schemas", () => {
  const accountKey = h("a");
  const writerNid = "did:key:z6MkwQp8f8Y11L3WJYJ4hXa1";
  const eventRid = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5";
  const routingEventId = h("b");
  const routingBindingDigest = h("c");
  const writerRefs = [
    {
      nid: writerNid,
      ref: "refs/xyz.heterodyne.marmot/writers/native-1",
    },
    {
      nid: "did:key:z6Mkq7ZBA1Vh9fVhKo2H2iW4",
      ref: "refs/xyz.heterodyne.marmot/relays/ingest-1",
    },
  ];
  const exactEvent = (kind: number, byte: string) => ({
    nip01_raw: `[0,"${byte}"]`,
    event: {
      id: h(byte),
      pubkey: h("d"),
      created_at: 1_785_000_100,
      kind,
      tags: [["h", "marmot-routing-id"]],
      content: "ciphertext",
      sig: sig("e"),
    },
  });

  const directory = {
    spec_version: "heterodyne/0.6.0",
    profile: "standard-compatible",
    stable_group_id: "stable-group-1",
    account_key: accountKey,
    current_routing: {
      generation: 3,
      h: "marmot-routing-id",
      event_rid: eventRid,
      marmot_routing_event_id: routingEventId,
      routing_binding_sha256: routingBindingDigest,
    },
    authorized_writer_refs: writerRefs,
    visibility: "public-directory",
    public_profile: { name: "Group", description: "", policy: {} },
    encrypted_records: [],
    host_announcements: [],
    routing_binding_digests: [routingBindingDigest],
  };

  const manifest = {
    spec_version: "heterodyne/0.6.0",
    account_key: accountKey,
    writer_nid: writerNid,
    consumed_keypackage_id: "keypackage-1",
    welcome_event_id: h("1"),
    first_group_event_id: h("2"),
    objects: [
      { object_id: "welcome", media_type: "application/nostr+json", encoded_bytes: 128, sha256: h("3") },
      { object_id: "first-event", media_type: "application/nostr+json", encoded_bytes: 256, sha256: h("4") },
    ],
    automation: { automated: false },
  };

  const bundle = {
    spec_version: "heterodyne/0.6.0",
    account_key: accountKey,
    writer_nid: writerNid,
    manifest,
    welcome: exactEvent(444, "1"),
    first_group_event: exactEvent(445, "2"),
    atomic_commit: true,
  };

  const routingBinding = {
    spec_version: "heterodyne/0.6.0",
    stable_group_id: "stable-group-1",
    generation: 3,
    h: "marmot-routing-id",
    event_rid: eventRid,
    genesis_manifest_sha256: h("5"),
    previous_generation: null,
    authorized_writer_refs: writerRefs,
    authorized_hosts: [writerNid],
    interfaces: [{ type: "radicle", endpoint: eventRid }],
    retention: { retain_until: 1_785_086_400, non_erasure_acknowledged: true },
    account_key: accountKey,
    marmot_routing_event_id: routingEventId,
    signature: sig("6"),
  };

  const genesis = {
    spec_version: "heterodyne/0.6.0",
    stable_group_id_digest: h("7"),
    generation: 3,
    h: "marmot-routing-id",
    event_rid: eventRid,
    account_key: accountKey,
    marmot_routing_event_id: routingEventId,
    authorized_writer_refs: writerRefs,
    created_at: 1_785_000_000,
    logical_soft_cap_bytes: 5_368_709_120,
    event_index: "events/by-id/<event-id>.json",
    media_index: "media/by-ciphertext-sha256/<sha256>",
    writer_ref_prefix: "refs/xyz.heterodyne.marmot/writers/",
    relay_ref_prefix: "refs/xyz.heterodyne.marmot/relays/",
  };

  it("accepts closed account, routing, RID, h, and authorized-writer bindings", () => {
    for (const [name, value] of [
      ["marmot-group-directory-v1.schema.json", directory],
      ["marmot-persona-inbox-manifest-v1.schema.json", manifest],
      ["marmot-persona-inbox-bundle-v1.schema.json", bundle],
      ["marmot-routing-binding-v1.schema.json", routingBinding],
      ["marmot-event-repository-genesis-v1.schema.json", genesis],
    ] as const) {
      expect(validateMarmotSchema(name, value), name).toBeNull();
    }
  });

  it("rejects missing active-account, routing-commit, and writer-ref authority", () => {
    const { account_key: _directoryAccount, ...directoryWithoutAccount } = directory;
    const { marmot_routing_event_id: _routingEvent, ...bindingWithoutRoutingEvent } = routingBinding;
    const { authorized_writer_refs: _writerRefs, ...genesisWithoutWriters } = genesis;

    expect(validateMarmotSchema(
      "marmot-group-directory-v1.schema.json",
      directoryWithoutAccount,
    )).toMatch(/account_key|required/);
    expect(validateMarmotSchema(
      "marmot-routing-binding-v1.schema.json",
      bindingWithoutRoutingEvent,
    )).toMatch(/marmot_routing_event_id|required/);
    expect(validateMarmotSchema(
      "marmot-event-repository-genesis-v1.schema.json",
      genesisWithoutWriters,
    )).toMatch(/authorized_writer_refs|required/);
  });

  it("keeps Radicle writer provenance separate from the Marmot account", () => {
    const { account_key: _accountKey, ...manifestWithoutAccount } = manifest;
    const { writer_nid: _writerNid, ...bundleWithoutWriter } = bundle;

    expect(validateMarmotSchema(
      "marmot-persona-inbox-manifest-v1.schema.json",
      manifestWithoutAccount,
    )).toMatch(/account_key|required/);
    expect(validateMarmotSchema(
      "marmot-persona-inbox-bundle-v1.schema.json",
      bundleWithoutWriter,
    )).toMatch(/writer_nid|required/);
  });

  it("rejects legacy identity and discovery authority members", () => {
    for (const [name, value] of [
      ["marmot-group-directory-v1.schema.json", { ...directory, cold_root: h("8") }],
      ["marmot-routing-binding-v1.schema.json", { ...routingBinding, kel_head: h("9") }],
      ["marmot-event-repository-genesis-v1.schema.json", { ...genesis, epoch_pubkey: h("0") }],
      ["marmot-persona-inbox-manifest-v1.schema.json", { ...manifest, identity_pointer_kind: 31_005 }],
      ["marmot-persona-inbox-bundle-v1.schema.json", { ...bundle, feed_index_kind: 31_007 }],
    ] as const) {
      expect(validateMarmotSchema(name, value), name).toMatch(/additionalProperties/);
    }
  });
});

describe("vector schema", () => {
  const invariantFor = {
    core: "CORE-I-VERIFY-BEFORE-USE",
    assurance: "ASSURANCE-I-CORE-OPTIONALITY",
    comms: "COMMS-I-TIER3-BLIND-CARRIER",
    control: "CONTROL-I-AUDIT-AT-REST",
    social: "SOCIAL-I-NIP01-AUTHORSHIP",
    workspace: "WORKSPACE-I-NO-AMBIENT-AUTHORITY",
  } as const;
  const valid = (owner: keyof typeof invariantFor) => ({
    vector_id: `versioning/${owner}-metadata`,
    vector_schema_version: "3.0.0",
    owner_document: owner,
    spec_version: "heterodyne/0.6.0",
    spec_refs: [`heterodyne:0.6.0#${owner}-conformance`],
    invariants: [invariantFor[owner]],
    reason_codes: [],
    description: "exact family metadata",
    direction: "consume",
    input: {},
    expected_output: { verdict: "accept" },
  });

  it("accepts only the closed Core signed-event checker declaration", () => {
    const check = {
      profile: "core-signed-event-v1",
      event_pointer: "/input/event",
      nip01_raw_pointer: "/input/nip01_raw",
      expected_terminal_stage: "signature",
    };
    expect(() => validateVectorOrThrow({
      ...valid("core"), conformance_checks: [check],
    })).not.toThrow();
    for (const invalid of [
      { ...check, profile: "generator-v1" },
      { ...check, event_pointer: "input/event" },
      { ...check, inferred: true },
    ]) {
      expect(() => validateVectorOrThrow({
        ...valid("core"), conformance_checks: [invalid],
      })).toThrow();
    }
    expect(() => validateVectorOrThrow({
      ...valid("core"), conformance_checks: [check, check],
    })).toThrow();
  });

  it("requires context for persona resolution and every later terminal stage", () => {
    const baseCheck = {
      profile: "core-signed-event-v1",
      event_pointer: "/input/event",
      nip01_raw_pointer: "/input/nip01_raw",
    };
    for (const expected_terminal_stage of [
      "persona_resolution",
      "version_stamp",
      "kel_head",
      "epoch_authority",
      "subtype_nid",
      "accept",
    ]) {
      expect(() => validateVectorOrThrow({
        ...valid("core"),
        conformance_checks: [{ ...baseCheck, expected_terminal_stage }],
      })).toThrow(/context_pointer|required/);
      expect(() => validateVectorOrThrow({
        ...valid("core"),
        conformance_checks: [{
          ...baseCheck,
          context_pointer: "/input/context",
          expected_terminal_stage,
        }],
      })).not.toThrow();
    }
  });

  it("accepts the qualified family vector envelope", () => {
    expect(() =>
      validateVectorOrThrow({
        vector_id: "identity/root-attestation-valid",
        vector_schema_version: "3.0.0",
        owner_document: "core",
        spec_version: "heterodyne/0.6.0",
        spec_refs: ["heterodyne:0.6.0#core-root-attestation"],
        invariants: ["CORE-I-IDENTITY-INTEGRITY"],
        reason_codes: [],
        description: "root attestation is reproduced byte-identically",
        direction: "produce",
        input: { hello: "world" },
        expected_output: {
          canonical_wire: "[0,...]",
          decoded: {},
        },
      }),
    ).not.toThrow();
  });

  it("keeps the generator schema as the draft raw-authoring contract", () => {
    expect(VECTOR_SCHEMA.required).toContain("spec_version");
    expect(VECTOR_SCHEMA.required).toEqual(expect.arrayContaining([
      "invariants",
      "reason_codes",
    ]));
    expect(VECTOR_SCHEMA.properties.vector_schema_version).toEqual({ const: "3.0.0" });
  });

  it("rejects an unqualified version and a bare section reference", () => {
    expect(() => validateVectorOrThrow({ ...valid("core"), spec_version: "0.5.0" }))
      .toThrow();
    expect(() => validateVectorOrThrow({ ...valid("core"), spec_refs: ["§3"] }))
      .toThrow();
  });

  it.each(["core", "assurance", "comms", "control", "social", "workspace"] as const)(
    "accepts the exact %s runtime metadata",
    (owner) => expect(() => validateVectorOrThrow(valid(owner))).not.toThrow(),
  );

  it("rejects a version other than the current family release", () => {
    expect(() => validateVectorOrThrow({ ...valid("core"), spec_version: "heterodyne/0.5.1" }))
      .toThrow();
    expect(() => validateVectorOrThrow({
      ...valid("core"), spec_refs: ["heterodyne:0.4.0#core-conformance"],
    })).toThrow();
  });

  it("rejects references above the owner in the layering", () => {
    expect(() => validateVectorOrThrow({
      ...valid("social"), spec_refs: ["heterodyne:0.6.0#control-conformance"],
    })).toThrow(/spec_ref/);
    expect(() => validateVectorOrThrow({
      ...valid("comms"), spec_refs: ["heterodyne:0.6.0#social-conformance"],
    })).toThrow(/spec_ref/);
    expect(() => validateVectorOrThrow({
      ...valid("core"), spec_refs: ["heterodyne:0.6.0#comms-conformance"],
    })).toThrow(/spec_ref/);
  });

  it("requires exactly one qualified permanent spec reference", () => {
    expect(() => validateVectorOrThrow({
      ...valid("core"),
      spec_refs: [
        "heterodyne:0.6.0#core-versioning",
        "heterodyne:0.6.0#core-conformance",
      ],
    })).toThrow(/spec_refs|one|item/i);
  });

  it("allows one Control reference to either document beneath it", () => {
    for (const specRef of [
      "heterodyne:0.6.0#core-version-stamps",
      "heterodyne:0.6.0#comms-subprotocol-negotiation",
    ]) {
      expect(() => validateVectorOrThrow({
        ...valid("control"),
        spec_refs: [specRef],
      })).not.toThrow();
    }
  });

  it("rejects null for the optional profile field", () => {
    expect(() =>
      validateVectorOrThrow({
        vector_id: "stamping/null-profile",
        vector_schema_version: "3.0.0",
        owner_document: "core",
        owner_version: "heterodyne/0.6.0",
        dependency_versions: {},
        profile_revision: 1,
        profile: null,
        spec_refs: ["heterodyne:0.6.0#core-version-stamps"],
        invariants: ["CORE-I-VERIFY-BEFORE-USE"],
        reason_codes: [],
        description: "optional means absent, not null",
        direction: "round-trip",
        input: {},
        expected_output: {},
      }),
    ).toThrow();
  });

  it.each(["consume", "produce", "round-trip"] as const)(
    "requires reason_code on %s rejects",
    (direction) => expect(() => validateVectorOrThrow({
      ...valid("core"),
      direction,
      reason_codes: ["bad_signature"],
      expected_output: { verdict: "reject" },
    })).toThrow(/reason_code/),
  );

  it("requires nonempty sorted unique registered invariants owned by the vector document", () => {
    for (const invariants of [
      [],
      ["CORE-I-VERIFY-BEFORE-USE", "CORE-I-IDENTITY-INTEGRITY"],
      ["CORE-I-VERIFY-BEFORE-USE", "CORE-I-VERIFY-BEFORE-USE"],
      ["NOT-REGISTERED"],
      ["COMMS-I-TIER3-BLIND-CARRIER"],
    ]) {
      expect(() => validateVectorOrThrow({ ...valid("core"), invariants }), invariants.join(","))
        .toThrow(/invariant/i);
    }
  });

  it("binds reject traceability to the exact registered expected reason", () => {
    expect(() => validateVectorOrThrow({
      ...valid("core"),
      reason_codes: ["bad_signature"],
      expected_output: { verdict: "reject", reason_code: "bad_signature" },
    })).not.toThrow();
    for (const reason_codes of [
      [],
      ["nip01_raw_mismatch", "bad_signature"],
      ["bad_signature", "bad_signature"],
      ["nip01_raw_mismatch"],
      ["not-registered"],
    ]) {
      expect(() => validateVectorOrThrow({
        ...valid("core"),
        reason_codes,
        expected_output: { verdict: "reject", reason_code: "bad_signature" },
      }), reason_codes.join(",")).toThrow(/reason/i);
    }
  });

  it("requires accept vectors to carry an empty reason trace", () => {
    expect(() => validateVectorOrThrow({
      ...valid("core"),
      reason_codes: ["bad_signature"],
    })).toThrow(/reason/i);
  });
});

describe("credential-continuity schema registry", () => {
  it("loads the seventeen transport-independent Comms schemas", () => {
    expect(CREDENTIAL_CONTINUITY_SCHEMA_FILES).toHaveLength(17);
    for (const file of CREDENTIAL_CONTINUITY_SCHEMA_FILES) {
      expect(CREDENTIAL_CONTINUITY_SCHEMAS[file]).toMatchObject({
        $schema: "http://json-schema.org/draft-07/schema#",
        $id: `https://heterodyne.network/schemas/comms/${file}`,
      });
      expect(() =>
        validateCredentialContinuitySchemaOrThrow(file, {}),
      ).toThrow(/credential-continuity-schema-invalid/);
    }
  });
});

describe("Comms claim schemas", () => {
  const key = { type: "nostr-secp256k1", value: "12".repeat(32) };
  const base = {
    claim_id: "ab".repeat(32),
    issuer: key,
    subject: { type: "radicle-ed25519-nid", value: "did:key:z6MkhM7qBMzbpZbpQeMVQW1H4KAKz7GgzGzHwGKYvEyt84qC" },
    claim_class: "authorization",
    namespace: "heterodyne.device",
    name: "claim-ledger-reader",
    value: true,
    issued_at: 1784390400,
    not_before: 1784390400,
    expires_at: 1784476800,
    visibility: "repository-private",
    spec_version: "heterodyne/0.6.0",
    profile_revision: 2,
    credential_ledger_persona: "34".repeat(32),
    credential_ledger_generation: 0,
  };

  it("accepts exact claims and rejects extra properties", () => {
    expect(() => validateKeyClaimSchemaOrThrow(base)).not.toThrow();
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, extra: true })).toThrow(/additional/);
    const { spec_version: _version, ...missingVersion } = base;
    expect(() => validateKeyClaimSchemaOrThrow(missingVersion)).toThrow(/spec_version|required/);
    expect(() => validateKeyClaimSchemaOrThrow({
      ...missingVersion,
      comms_version: "heterodyne/0.6.0",
    })).toThrow(/spec_version|required|additional/);
    expect(() => validateKeyClaimSchemaOrThrow({
      ...base,
      spec_version: "heterodyne/0.5.1",
    })).toThrow(/spec_version|const/);
  });

  it("requires bounded authorization expiry and caps delegation depth at eight", () => {
    const { expires_at: _, ...withoutExpiry } = base;
    expect(() => validateKeyClaimSchemaOrThrow(withoutExpiry)).toThrow(/expires_at/);
    expect(() => validateKeyClaimSchemaOrThrow({
      ...base,
      constraints: { namespaces: [], audiences: [], resources: [], remaining_depth: 9 },
    })).toThrow(/remaining_depth|8/);
  });

  it("enforces time ordering beyond structural JSON Schema", () => {
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, not_before: base.issued_at - 1 })).toThrow(/not_before/);
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, expires_at: base.not_before - 1 })).toThrow(/expires_at/);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    "rejects non-finite numeric fields through the direct claim API: %s",
    (value) => expect(() => validateKeyClaimSchemaOrThrow({ ...base, issued_at: value })).toThrow(),
  );

  it("rejects non-finite values recursively through the direct claim API", () => {
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, value: { nested: [Number.NaN] } })).toThrow(/finite|JCS|number/);
    expect(() => validateKeyClaimSchemaOrThrow({ ...base, value: [Number.POSITIVE_INFINITY] })).toThrow(/finite|JCS|number/);
  });

  it("accepts exact revocations and rejects unregistered reasons and extras", () => {
    const revocation = {
      claim_id: base.claim_id,
      revoked_at: 1784390500,
      reason_code: "claim-revoked",
      revoker: key,
      spec_version: "heterodyne/0.6.0",
      profile_revision: 2,
    };
    expect(() => validateClaimRevocationSchemaOrThrow(revocation)).not.toThrow();
    const { spec_version: _version, ...missingVersion } = revocation;
    const { profile_revision: _revision, ...missingRevision } = revocation;
    expect(() => validateClaimRevocationSchemaOrThrow(missingVersion)).toThrow(/spec_version|required/);
    expect(() => validateClaimRevocationSchemaOrThrow({
      ...missingVersion,
      comms_version: "heterodyne/0.6.0",
    })).toThrow(/spec_version|required|additional/);
    expect(() => validateClaimRevocationSchemaOrThrow(missingRevision)).toThrow(/profile_revision|required/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, spec_version: "heterodyne/0.5.1" })).toThrow(/spec_version|const/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, profile_revision: 1 })).toThrow(/profile_revision|const/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, reason_code: "not-registered" })).toThrow(/reason_code/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, extra: true })).toThrow(/additional/);
    expect(() => validateClaimRevocationSchemaOrThrow({ ...revocation, revoked_at: Number.NEGATIVE_INFINITY })).toThrow();
  });

  it("closes embedded public JWK profiles at the revocation schema boundary", () => {
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: "A".repeat(43),
      alg: "EdDSA",
      use: "sig",
      key_ops: ["verify"],
      kid: "B".repeat(43),
    };
    const revocation = {
      claim_id: base.claim_id,
      revoked_at: 1784390500,
      reason_code: "claim-revoked",
      revoker: { type: "jwk-thumbprint", value: "B".repeat(43) },
      spec_version: "heterodyne/0.6.0",
      profile_revision: 2,
      proof: {
        type: "jwk-jws",
        jwk,
        protected: "AA",
        signature: "AA",
      },
    };
    expect(() => validateClaimRevocationSchemaOrThrow(revocation)).not.toThrow();
    expect(() => validateClaimRevocationSchemaOrThrow({
      ...revocation,
      proof: { ...revocation.proof, jwk: { ...jwk, arbitrary: true } },
    })).toThrow(/additional|oneOf/);
    expect(() => validateClaimRevocationSchemaOrThrow({
      ...revocation,
      proof: { ...revocation.proof, jwk: { ...jwk, alg: "RS256" } },
    })).toThrow(/alg|const|oneOf/);
    expect(() => validateClaimRevocationSchemaOrThrow({
      ...revocation,
      proof: { ...revocation.proof, jwk: { ...jwk, d: "A".repeat(43) } },
    })).toThrow(/additional|oneOf/);
  });
});
