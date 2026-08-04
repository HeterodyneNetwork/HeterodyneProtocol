import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv, type ValidateFunction } from "ajv";
import { describe, expect, it } from "vitest";

const schemasRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/comms",
);

const H32 = "11".repeat(16);
const H40 = "22".repeat(20);
const H64 = "33".repeat(32);
const H128 = "44".repeat(64);
const B64URL_32 = "A".repeat(43);
const B64URL_64 = `${"B".repeat(85)}Q`;
const NID = "did:key:z6MkhM7qBMzbpZbpQeMVQW1H4KAKz7GgzGzHwGKYvEyt84qC";
const TYPE_GIT_SHA256 = { object_format: "sha256", oid: H64 };
const KEL_HEAD = { event_id: H64, seq: 7 };
const AUTHORITY = { signer_type: "epoch", signer: H64, kel_head: KEL_HEAD };
const ARTIFACT_REF = { profile_id: "core.nid-delegation.v1", record_digest: H64 };

const PEER_TOMBSTONE = {
  type: "heterodyne.double-ratchet-peer-tombstone.v1",
  spec_version: "comms/0.5.0",
  persona: H64,
  transition_id: H32,
  old_session_id: H64,
  local_nid: NID,
  remote_persona: H64,
  remote_nid: NID,
  local_delivery_pubkey: H64,
  local_delivery_delegation_event_id: H64,
  remote_delivery_pubkey: H64,
  remote_delivery_delegation_event_id: H64,
  invalidated_at: 1784390400,
  successor_session_ids: [H64],
  reason: "candidate_material_retired",
  epoch_pubkey: H64,
  kel_head: KEL_HEAD,
  epoch_signature: H128,
};

const RUMOR_EVENT = {
  id: H64,
  pubkey: H64,
  created_at: PEER_TOMBSTONE.invalidated_at,
  kind: 1061,
  tags: [
    ["p", H64],
    ["heterodyne", "dr_peer_tombstone"],
  ],
  content: JSON.stringify(PEER_TOMBSTONE),
};

const RUMOR_CARRIER = {
  event: RUMOR_EVENT,
  nip01_raw: `[0,"${H64}",${PEER_TOMBSTONE.invalidated_at},1061,[],""]`,
};

const SIGNED_SEAL = {
  id: H64,
  pubkey: H64,
  created_at: 1784390401,
  kind: 13,
  tags: [],
  content: "AQ",
  sig: H128,
};

const SIGNED_WRAP = {
  id: H64,
  pubkey: H64,
  created_at: 1784390402,
  kind: 1059,
  tags: [["p", H64]],
  content: "Ag",
  sig: H128,
};

const GIFT_WRAP_CARRIER = {
  event: SIGNED_WRAP,
  nip01_raw: `[0,"${H64}",1784390402,1059,[],""]`,
  seal: {
    event: SIGNED_SEAL,
    nip01_raw: `[0,"${H64}",1784390401,13,[],""]`,
  },
  rumor: RUMOR_CARRIER,
};

interface SchemaCase {
  name: string;
  id: string;
  valid: unknown;
  wrong: readonly unknown[];
}

function validatorFor(name: string): ValidateFunction {
  const schema = JSON.parse(
    readFileSync(resolve(schemasRoot, name), "utf8"),
  ) as Record<string, unknown>;
  return new Ajv({ allErrors: true, strict: false }).compile(schema);
}

function cloneWithUnknownAt(
  value: unknown,
  path: readonly (string | number)[],
): unknown {
  const clone = structuredClone(value);
  let cursor = clone as Record<string | number, unknown>;
  for (const part of path) cursor = cursor[part] as Record<string | number, unknown>;
  cursor.unexpected = true;
  return clone;
}

function cloneWithoutAt(
  value: unknown,
  path: readonly (string | number)[],
  key: string,
): unknown {
  const clone = structuredClone(value);
  let cursor = clone as Record<string | number, unknown>;
  for (const part of path) cursor = cursor[part] as Record<string | number, unknown>;
  delete cursor[key];
  return clone;
}

function objectPaths(value: unknown, path: readonly (string | number)[] = []): (string | number)[][] {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => objectPaths(item, [...path, index]));
  }
  if (value === null || typeof value !== "object") return [];
  const record = value as Record<string, unknown>;
  return [
    [...path],
    ...Object.entries(record).flatMap(([key, item]) => objectPaths(item, [...path, key])),
  ];
}

function requiredMemberMutations(value: unknown): unknown[] {
  return objectPaths(value).flatMap((path) => {
    let cursor = value as unknown;
    for (const part of path) cursor = (cursor as Record<string | number, unknown>)[part];
    return Object.keys(cursor as Record<string, unknown>)
      .map((key) => cloneWithoutAt(value, path, key));
  });
}

const resetRecipients = [{
  nid: NID,
  delegation_event_id: H64,
  recovery_key: { algorithm: "X25519", public_key: B64URL_32 },
  nid_proof: B64URL_64,
  enc: B64URL_32,
  ciphertext: "AQ",
}];

const secretSource = {
  type: "heterodyne.node-secret-source.v1",
  persona: H64,
  secret_class: "device-signing",
  secret_id: H64,
  instance_commitment: H64,
  holder_nid: NID,
  commitment_kind: "capability-jcs",
  source_kind: "canonical-artifact",
  artifact_refs: [ARTIFACT_REF],
  issued_at: 1784390400,
  epoch_pubkey: H64,
  kel_head: KEL_HEAD,
  epoch_signature: H128,
};

const secretExposure = {
  type: "heterodyne.node-secret-exposure.v1",
  persona: H64,
  assignment_id: H32,
  action: "assign",
  holder_nid: NID,
  secret_class: "config-audience",
  secret_id: H32,
  secret_commitment: H64,
  source_profile: "comms.node-secret-source.v1",
  source_record_digest: H64,
  transition_id: null,
  supersedes: null,
  issued_at: 1784390400,
  authority: AUTHORITY,
  signature: H128,
};

const candidateAudit = {
  predecessor_checkpoint: H64,
  candidate_checkpoint_digest: H64,
  accepted_basis_head: TYPE_GIT_SHA256,
  candidate_head: TYPE_GIT_SHA256,
  candidate_exposure_records: [
    { record_type: "secret-source", record_digest: H64 },
  ],
  candidate_governed_decrypt_key_bindings_sha256: H64,
  candidate_historical_decrypt_obligations_sha256: H64,
  opaque_object_manifest: [{
    object_type: "blob",
    object_id: TYPE_GIT_SHA256,
    raw_sha256: H64,
    paths: ["config-data/" + H64 + ".bin"],
    disposition: "opaque-copy",
    audit_path: "credential-sync/reset-candidate-audit/" + H32 + "/" + H64 + "/objects/blob/sha256-" + H64 + ".bin",
    audit_sha256: H64,
    inherited_audit_set_digests: [],
  }],
  opaque_object_manifest_sha256: H64,
  safe_record_copies: [{
    profile_id: "comms.node-secret-source.v1",
    record_digest: H64,
    source_path: "credential-sync/secret-sources/" + H64 + "/" + H64 + ".json",
    audit_path: "credential-sync/reset-candidate-audit/" + H32 + "/" + H64 + "/safe/" + H64 + ".json",
    audit_sha256: H64,
  }],
  safe_record_set_sha256: H64,
};

const secretTransition = {
  type: "heterodyne.credential-ledger.secret-transition.v1",
  transition_id: H32,
  persona: H64,
  mode: "routine-key-rotation",
  prior_checkpoint: H64,
  added_nids: [],
  removed_nids: [],
  target: {
    generation: 0,
    sequence: 1,
    new_roster: [NID],
    config_key_id: H32,
    config_key_sha256: H64,
    pairwise_secret_sha256: H64,
    exposure_set_sha256: H64,
    governed_decrypt_key_bindings_sha256: H64,
    historical_decrypt_obligations_sha256: H64,
    epoch_pubkey: H64,
    kel_head: KEL_HEAD,
    reset_id: null,
    epoch_rotation_event_id: null,
  },
  inventory_basis: {
    config_head: TYPE_GIT_SHA256,
    source_ref_head: TYPE_GIT_SHA256,
    staging_heads: [],
    recovered_heads: [],
    offline_recovery_pre_unseal_intents: [],
    offline_recovery_pre_unseal_intent_collisions: [],
    offline_recovery_activations: [],
    offline_recovery_activation_collisions: [],
    same_key_candidate_audit: null,
    signed_ref_map: [{ ref: "refs/heads/enc/" + H32, head: TYPE_GIT_SHA256 }],
    signed_ref_map_sha256: H64,
    exposure_set_sha256: H64,
    governed_decrypt_key_bindings_sha256: H64,
    historical_decrypt_obligations_sha256: H64,
  },
  result_basis: {
    config_head: TYPE_GIT_SHA256,
    exposure_set_sha256: H64,
    governed_decrypt_key_bindings_sha256: H64,
    historical_decrypt_obligations_sha256: H64,
  },
  exposures: [{
    secret_class: "config-audience",
    secret_id: H32,
    secret_commitment: H64,
    holder_nids: [NID],
    assignment_record_digests: [H64],
    pre_unseal_intent_items: [],
  }],
  outcomes: [{
    secret_class: "config-audience",
    secret_id: H32,
    old_commitment: H64,
    disposition: "rotate",
    successor_id: H32,
    proof_digests: [H64],
  }],
  created_at: 1784390400,
  authority: AUTHORITY,
  signature: H128,
};

const transitionAction = {
  type: "heterodyne.node-secret-transition-action.v1",
  persona: H64,
  transition_id: H32,
  action_kind: "audience-key-rotation",
  secret_class: "config-audience",
  secret_id: H32,
  old_commitment: H64,
  disposition: "rotate",
  successor_id: H32,
  successor_commitment: H64,
  excluded_nids: [],
  authorized_nids: [NID],
  source_assignment_digests: [H64],
  pre_unseal_intent_items: [],
  retirement_record_digests: [H64],
  successor_assignment_digests: [H64],
  historical_decrypt_nids: [],
  historical_assignment_digests: [],
  artifact_refs: [ARTIFACT_REF],
  created_at: 1784390400,
  authority: AUTHORITY,
  signature: H128,
};

const drTermination = {
  type: "heterodyne.double-ratchet-session-termination.v1",
  persona: H64,
  transition_id: H32,
  old_session_id: H64,
  local_nid: NID,
  remote_persona: H64,
  remote_nid: NID,
  local_delivery_pubkey: H64,
  local_delivery_delegation_event_id: H64,
  remote_delivery_pubkey: H64,
  remote_delivery_delegation_event_id: H64,
  source_assignment_digests: [H64],
  removed_holder_nids: [],
  retained_holder_nids: [NID],
  invalidated_at: 1784390400,
  successor_session_ids: [H64],
  nid_revocation_digests: [],
  retained_receipts: [{
    termination_base_digest: H64,
    nid: NID,
    observed_at: 1784390400,
    signature: B64URL_64,
  }],
  peer_tombstone: PEER_TOMBSTONE,
  peer_delivery_event: GIFT_WRAP_CARRIER,
  authority: AUTHORITY,
  signature: H128,
};

const lostGenerationPath = {
  type: "heterodyne.credential-ledger.lost-generation-path.v1",
  persona: H64,
  prior_generation: 0,
  path_sha256: H64,
  logical_path: "config-data/" + H64 + ".bin",
  variants: [{
    origin_heads: [TYPE_GIT_SHA256],
    state: "present",
    storage_object_id: TYPE_GIT_SHA256,
    content_sha256: H64,
    content_path: "credential-sync/lost-generation-data/0/" + H64 + "/sha256-" + H64 + ".bin",
  }],
};

const configGit = {
  type: "heterodyne.config-repository-git-structure.v1",
  object_format: "sha1",
  commit_oid: H40,
  commit_raw_base64url: "AQ",
  tree_objects: [{ oid: H40, raw_base64url: "Ag" }],
};

const cases: readonly SchemaCase[] = [
  {
    name: "credential-ledger-reset-recipient-array-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/credential-ledger-reset-recipient-array-v1.schema.json",
    valid: resetRecipients,
    wrong: [[{ ...resetRecipients[0], enc: "A" }]],
  },
  {
    name: "node-secret-source-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/node-secret-source-v1.schema.json",
    valid: secretSource,
    wrong: [
      { ...secretSource, secret_id: H32 },
      { ...secretSource, commitment_kind: "secret-bytes" },
    ],
  },
  {
    name: "node-secret-exposure-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/node-secret-exposure-v1.schema.json",
    valid: secretExposure,
    wrong: [{ ...secretExposure, action: "retire" }],
  },
  {
    name: "credential-ledger-secret-transition-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/credential-ledger-secret-transition-v1.schema.json",
    valid: secretTransition,
    wrong: [{
      ...secretTransition,
      target: { ...secretTransition.target, reset_id: H32 },
    }],
  },
  {
    name: "node-secret-transition-action-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/node-secret-transition-action-v1.schema.json",
    valid: transitionAction,
    wrong: [{ ...transitionAction, action_kind: "ratchet-termination" }],
  },
  {
    name: "double-ratchet-session-termination-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/double-ratchet-session-termination-v1.schema.json",
    valid: drTermination,
    wrong: [{ ...drTermination, invalidated_at: Number.MAX_SAFE_INTEGER + 1 }],
  },
  {
    name: "credential-ledger-lost-generation-path-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/credential-ledger-lost-generation-path-v1.schema.json",
    valid: lostGenerationPath,
    wrong: [{
      ...lostGenerationPath,
      variants: [{
        ...lostGenerationPath.variants[0],
        state: "deleted",
      }],
    }],
  },
  {
    name: "config-repository-git-structure-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/config-repository-git-structure-v1.schema.json",
    valid: configGit,
    wrong: [{ ...configGit, commit_oid: H64 }],
  },
  {
    name: "double-ratchet-peer-tombstone-rumor-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/double-ratchet-peer-tombstone-rumor-v1.schema.json",
    valid: RUMOR_CARRIER,
    wrong: [{ ...RUMOR_CARRIER, event: { ...RUMOR_EVENT, kind: 1060 } }],
  },
  {
    name: "double-ratchet-peer-tombstone-gift-wrap-v1.schema.json",
    id: "https://heterodyne.network/schemas/comms/double-ratchet-peer-tombstone-gift-wrap-v1.schema.json",
    valid: GIFT_WRAP_CARRIER,
    wrong: [{
      ...GIFT_WRAP_CARRIER,
      seal: { ...GIFT_WRAP_CARRIER.seal, event: { ...SIGNED_SEAL, tags: [["p", H64]] } },
    }],
  },
];

describe("ADR-037 Decision 7 schema group B", () => {
  it.each(cases)("$name accepts its exact carrier and rejects unknown members", ({ name, id, valid }) => {
    const validate = validatorFor(name);
    expect(validate.schema).toMatchObject({ $schema: "http://json-schema.org/draft-07/schema#", $id: id });
    expect(validate(valid), JSON.stringify(validate.errors)).toBe(true);
    for (const path of objectPaths(valid)) {
      const mutated = cloneWithUnknownAt(valid, path);
      expect(validate(mutated), `${name} left ${path.join(".") || "<root>"} open`).toBe(false);
    }
  });

  it.each(cases)("$name requires every exposed member", ({ name, valid }) => {
    const validate = validatorFor(name);
    for (const mutated of requiredMemberMutations(valid)) {
      expect(validate(mutated), JSON.stringify(validate.errors)).toBe(false);
    }
  });

  it.each(cases)("$name rejects wrong shapes and encodings", ({ name, wrong }) => {
    const validate = validatorFor(name);
    for (const mutated of wrong) {
      expect(validate(mutated), JSON.stringify(validate.errors)).toBe(false);
    }
  });

  it("keeps the selected config Git carrier closed and format-dependent", () => {
    const validate = validatorFor("config-repository-git-structure-v1.schema.json");
    expect(validate({
      ...configGit,
      object_format: "sha256",
      commit_oid: H64,
      tree_objects: [{ oid: H64, raw_base64url: "Aw" }],
    }), JSON.stringify(validate.errors)).toBe(true);
    expect(validate({
      ...configGit,
      tree_objects: [{ oid: H64, raw_base64url: "Aw" }],
    })).toBe(false);
    expect(validate({ ...configGit, commit_raw_base64url: "AQ==" })).toBe(false);
  });

  it("keeps the unused same-key candidate audit shape closed when present", () => {
    const validate = validatorFor("credential-ledger-secret-transition-v1.schema.json");
    const withAudit = {
      ...secretTransition,
      mode: "emergency-reset",
      target: {
        ...secretTransition.target,
        sequence: 0,
        reset_id: H32,
        epoch_rotation_event_id: H64,
      },
      inventory_basis: {
        ...secretTransition.inventory_basis,
        same_key_candidate_audit: candidateAudit,
      },
    };
    expect(validate(withAudit), JSON.stringify(validate.errors)).toBe(true);
    expect(validate({
      ...withAudit,
      inventory_basis: {
        ...withAudit.inventory_basis,
        same_key_candidate_audit: { ...candidateAudit, unexpected: true },
      },
    })).toBe(false);
  });
});
