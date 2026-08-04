import { Ajv, type ValidateFunction } from "ajv";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * These tests cover the structural draft-07 boundary only. Signature checks,
 * canonical ordering, digest recomputation, ancestry, repository scans,
 * roster/delegation completeness, and every cross-record continuity rule
 * belong to the credential-continuity evaluator.
 */

const SCHEMAS_ROOT = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../schemas/comms",
);

const ID_16 = "11".repeat(16);
const ID_16_B = "22".repeat(16);
const SHA1 = "33".repeat(20);
const SHA1_B = "44".repeat(20);
const SHA256 = "55".repeat(32);
const SHA256_B = "66".repeat(32);
const SHA256_C = "77".repeat(32);
const SHA256_D = "88".repeat(32);
const BIP340_SIGNATURE = "99".repeat(64);
const BASE64URL_32_BYTES = "A".repeat(43);
const BASE64URL_64_BYTES = "A".repeat(86);
const BASE64URL_CIPHERTEXT = "A".repeat(64);
const NID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";
const NID_B = "did:key:z6Mkgd9vC5PoQn4fiePDTQAsha3eT6LgF6tUPzf28iwXLgde";
const RID = "rad:z2kYoeXzQMmpmmf4HWWZuYqT4rdQj";

const gitSha1 = () => ({ object_format: "sha1", oid: SHA1 });
const gitSha1B = () => ({ object_format: "sha1", oid: SHA1_B });
const kelHead = () => ({ event_id: SHA256_B, seq: 1 });
const authority = () => ({
  signer_type: "epoch",
  signer: SHA256,
  kel_head: kelHead(),
});

const retainedCiphertext = () => ({
  storage_class: "git-blob",
  owner: "comms",
  repository_rid: RID,
  repository_head: gitSha1(),
  ref_name: `refs/heads/enc/${ID_16}`,
  path: `config-data/${SHA256}.bin`,
  git_blob_oid: gitSha1B(),
  object_id: null,
  ciphertext_sha256: SHA256_C,
  ciphertext_length: 48,
});

const candidateExposure = () => ({
  record_type: "secret-assignment",
  record_digest: SHA256_D,
});

const opaqueObject = () => ({
  object_type: "commit",
  object_id: SHA1,
  raw_sha256: SHA256,
  paths: [],
  disposition: "opaque-copy",
  audit_path: `credential-sync/staging-ref-audit/${ID_16}/sha1-${SHA1}/objects/commit/${SHA1}.bin`,
  audit_sha256: SHA256_B,
  inherited_audit_set_digests: [],
});

const safeRecordCopy = () => ({
  profile_id: "comms.credential-ledger-checkpoint.v1",
  record_digest: SHA256,
  source_path: `credential-sync/checkpoints/0/0-${SHA256}.json`,
  audit_path: `credential-sync/staging-ref-audit/${ID_16}/sha1-${SHA1}/records/${SHA256}.json`,
  audit_sha256: SHA256_B,
});

const repositoryInventory = () => ({
  type: "heterodyne.repository-retention-inventory.v1",
  persona: SHA256,
  inventory_sequence: 0,
  previous_records: [],
  basis_checkpoint_digest: null,
  target_generation: 0,
  target_sequence: 0,
  repository_refs: [
    {
      repository_ref_id: SHA256_B,
      repository_class: "config",
      repository_rid: RID,
      ref_name: `refs/heads/enc/${ID_16}`,
      object_format: "sha1",
      retired: false,
      scan_head: gitSha1(),
    },
  ],
  issued_at: 1,
  epoch_pubkey: SHA256_C,
  kel_head: kelHead(),
  epoch_signature: BIP340_SIGNATURE,
});

const governedBinding = () => ({
  type: "heterodyne.governed-decrypt-key-binding.v1",
  persona: SHA256,
  binding_id: SHA256_B,
  retained_ciphertext: retainedCiphertext(),
  secret_class: "config-audience",
  secret_id: ID_16,
  instance_commitment: SHA256_C,
  issued_at: 2,
  authority: authority(),
  signature: BIP340_SIGNATURE,
});

const historicalObligation = () => ({
  type: "heterodyne.historical-decrypt-obligation.v1",
  persona: SHA256,
  obligation_id: ID_16,
  lineage_sequence: 0,
  previous_record: null,
  action: "retain",
  secret_class: "config-audience",
  secret_id: ID_16_B,
  instance_commitment: SHA256_C,
  retained_ciphertexts: [retainedCiphertext()],
  retired_provenance_lineages: [
    {
      holder_nid: NID,
      assignment_id: ID_16,
      source_record_digest: SHA256,
      assignment_record_digest: SHA256_B,
      retirement_record_digest: SHA256_C,
    },
  ],
  transition_id: ID_16_B,
  issued_at: 3,
  authority: authority(),
  signature: BIP340_SIGNATURE,
});

const checkpoint = () => ({
  type: "heterodyne.credential-ledger.checkpoint.v1",
  persona: SHA256,
  generation: 0,
  sequence: 0,
  previous_checkpoint: null,
  record_set_digest: SHA256_B,
  node_roster: [NID],
  config_head: gitSha1(),
  config_key_id: ID_16,
  config_key_sha256: SHA256_C,
  pairwise_secret_sha256: SHA256_D,
  exposure_set_sha256: SHA256,
  config_bootstrap_recipients_digest: SHA256_B,
  governed_decrypt_key_bindings_sha256: SHA256_C,
  historical_decrypt_obligations_sha256: SHA256_D,
  secret_transition_digest: null,
  generation_transition: null,
  epoch_pubkey: SHA256_C,
  kel_head: kelHead(),
  created_at: 4,
  epoch_signature: BIP340_SIGNATURE,
});

const checkpointReceipt = () => ({
  type: "heterodyne.credential-ledger.checkpoint-receipt.v1",
  checkpoint_digest: SHA256,
  node_nid: NID,
  observed_at: 5,
  signature: BASE64URL_64_BYTES,
});

const removalObservation = () => ({
  type: "heterodyne.credential-ledger.removal-observation.v1",
  persona: SHA256,
  transition_id: ID_16,
  transition_digest: SHA256_B,
  checkpoint_digest: SHA256_C,
  source_ref_head: gitSha1(),
  staged_ref: `refs/heads/enc/${ID_16_B}`,
  staged_head: gitSha1B(),
  node_nid: NID,
  observed_at: 6,
  signature: BASE64URL_64_BYTES,
});

const candidateAbandonment = () => ({
  type: "heterodyne.credential-ledger.candidate-abandonment.v1",
  persona: SHA256,
  predecessor_checkpoint: SHA256_B,
  candidate_checkpoint_digest: SHA256_C,
  candidate_transition_id: ID_16,
  candidate_transition_digest: SHA256_D,
  candidate_ref: `refs/heads/enc/${ID_16_B}`,
  candidate_head: gitSha1B(),
  abandonment_ref: `refs/heads/enc/${ID_16}`,
  abandonment_basis_head: gitSha1(),
  partial_acceptance_record_set_sha256: SHA256,
  candidate_exposure_records: [candidateExposure()],
  candidate_governed_decrypt_key_bindings_sha256: SHA256_B,
  candidate_historical_decrypt_obligations_sha256: SHA256_C,
  abandoned_at: 7,
  epoch_pubkey: SHA256_D,
  kel_head: kelHead(),
  epoch_signature: BIP340_SIGNATURE,
});

const stagingCleanup = () => ({
  type: "heterodyne.credential-ledger.staging-ref-cleanup.v1",
  persona: SHA256,
  staging_config_key_id: ID_16_B,
  staging_ref: `refs/heads/enc/${ID_16_B}`,
  staging_head: gitSha1B(),
  staging_transition_id: ID_16,
  staging_transition_digest: SHA256_B,
  staging_baseline_head: gitSha1(),
  terminalization: {
    kind: "candidate-abandonment",
    record_digest: SHA256_C,
    acceptance_head: gitSha1(),
  },
  accepted_transition_id: ID_16_B,
  accepted_transition_digest: SHA256_D,
  accepted_checkpoint_digest: SHA256,
  active_ref: `refs/heads/enc/${ID_16}`,
  active_basis_head: gitSha1(),
  staging_storage_object_set_sha256: SHA256_B,
  inherited_audit_set_digests: [],
  opaque_object_manifest: [opaqueObject()],
  opaque_object_manifest_sha256: SHA256_C,
  safe_record_copies: [safeRecordCopy()],
  safe_record_set_sha256: SHA256_D,
  assignment_record_digests: [SHA256],
  adopted_epoch_assignment_digests: [],
  retirement_record_digests: [SHA256_B],
  cleaned_at: 8,
  epoch_pubkey: SHA256_C,
  kel_head: kelHead(),
  epoch_signature: BIP340_SIGNATURE,
});

const bootstrapRecipients = () => [
  {
    nid: NID,
    delegation_event_id: SHA256,
    recovery_key: {
      algorithm: "X25519",
      public_key: BASE64URL_32_BYTES,
    },
    nid_proof: BASE64URL_64_BYTES,
    enc: BASE64URL_32_BYTES,
    ciphertext: BASE64URL_CIPHERTEXT,
  },
];

const emergencyReset = () => ({
  type: "heterodyne.credential-ledger.emergency-reset.v1",
  reset_id: ID_16,
  persona: SHA256,
  prior_generation: 0,
  new_generation: 1,
  last_common_checkpoint: SHA256_B,
  old_roster: [NID],
  new_roster: [NID_B],
  unavailable_nodes: [NID],
  prior_config_key_id: ID_16,
  new_config_key_id: ID_16_B,
  new_config_key_sha256: SHA256_C,
  prior_pairwise_secret_sha256: SHA256,
  new_pairwise_secret_sha256: SHA256_D,
  lost_audit_set_digest: SHA256_B,
  same_key_candidate_audit: null,
  offline_recovery_pre_unseal_intents: [],
  offline_recovery_pre_unseal_intent_collisions: [],
  offline_recovery_activations: [],
  offline_recovery_activation_collisions: [],
  exposure_set_sha256: SHA256,
  governed_decrypt_key_bindings_sha256: SHA256_B,
  historical_decrypt_obligations_sha256: SHA256_C,
  secret_transition_digest: SHA256_D,
  epoch_rotation_event_id: SHA256,
  new_epoch_pubkey: SHA256_B,
  new_kel_head: kelHead(),
  compromise_since: 9,
  bootstrap_recipients_digest: SHA256_C,
  created_at: 10,
  reason: "credential_ledger_reset_node_loss",
  cold_root_signature: BIP340_SIGNATURE,
});

type StructuralCase = {
  name: string;
  file: string;
  value: () => unknown;
  missingKey: string;
  malformed: (value: unknown) => void;
};

const cases: StructuralCase[] = [
  {
    name: "repository retention inventory",
    file: "repository-retention-inventory-v1.schema.json",
    value: repositoryInventory,
    missingKey: "repository_refs",
    malformed: (value) => {
      (value as ReturnType<typeof repositoryInventory>).persona = "AA".repeat(32);
    },
  },
  {
    name: "governed decrypt key binding",
    file: "governed-decrypt-key-binding-v1.schema.json",
    value: governedBinding,
    missingKey: "binding_id",
    malformed: (value) => {
      (value as ReturnType<typeof governedBinding>).signature = `${BIP340_SIGNATURE}=`;
    },
  },
  {
    name: "historical decrypt obligation",
    file: "historical-decrypt-obligation-v1.schema.json",
    value: historicalObligation,
    missingKey: "retained_ciphertexts",
    malformed: (value) => {
      const row = (value as ReturnType<typeof historicalObligation>).retained_ciphertexts[0];
      row.repository_head.oid = SHA256;
    },
  },
  {
    name: "credential ledger checkpoint",
    file: "credential-ledger-checkpoint-v1.schema.json",
    value: checkpoint,
    missingKey: "node_roster",
    malformed: (value) => {
      (value as ReturnType<typeof checkpoint>).config_key_id = SHA256;
    },
  },
  {
    name: "checkpoint receipt",
    file: "credential-ledger-checkpoint-receipt-v1.schema.json",
    value: checkpointReceipt,
    missingKey: "node_nid",
    malformed: (value) => {
      (value as ReturnType<typeof checkpointReceipt>).signature = BIP340_SIGNATURE;
    },
  },
  {
    name: "removal observation",
    file: "credential-ledger-removal-observation-v1.schema.json",
    value: removalObservation,
    missingKey: "staged_head",
    malformed: (value) => {
      (value as ReturnType<typeof removalObservation>).staged_head.oid = SHA256;
    },
  },
  {
    name: "candidate abandonment",
    file: "credential-ledger-candidate-abandonment-v1.schema.json",
    value: candidateAbandonment,
    missingKey: "candidate_checkpoint_digest",
    malformed: (value) => {
      (value as ReturnType<typeof candidateAbandonment>).candidate_transition_id =
        "AA".repeat(16);
    },
  },
  {
    name: "staging ref cleanup",
    file: "credential-ledger-staging-ref-cleanup-v1.schema.json",
    value: stagingCleanup,
    missingKey: "terminalization",
    malformed: (value) => {
      (value as ReturnType<typeof stagingCleanup>).staging_config_key_id = SHA256;
    },
  },
  {
    name: "config-key bootstrap recipient array",
    file: "credential-ledger-config-key-bootstrap-recipient-array-v1.schema.json",
    value: bootstrapRecipients,
    missingKey: "recovery_key",
    malformed: (value) => {
      (value as ReturnType<typeof bootstrapRecipients>)[0].recovery_key.public_key =
        `${BASE64URL_32_BYTES}=`;
    },
  },
  {
    name: "emergency reset",
    file: "credential-ledger-emergency-reset-v1.schema.json",
    value: emergencyReset,
    missingKey: "reset_id",
    malformed: (value) => {
      (value as ReturnType<typeof emergencyReset>).reset_id = SHA256;
    },
  },
];

const validators = new Map<string, ValidateFunction>();
const schemas = new Map<string, Record<string, unknown>>();

function loadSchema(file: string): Record<string, unknown> {
  const cached = schemas.get(file);
  if (cached !== undefined) return cached;
  const path = resolve(SCHEMAS_ROOT, file);
  expect(existsSync(path), `${file} must exist`).toBe(true);
  const schema = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  schemas.set(file, schema);
  return schema;
}

function validate(file: string, value: unknown): {
  valid: boolean;
  errors: ValidateFunction["errors"];
} {
  let validator = validators.get(file);
  if (validator === undefined) {
    const compiled = new Ajv({ allErrors: true, strict: false }).compile(
      loadSchema(file),
    );
    validators.set(file, compiled);
    validator = compiled;
  }
  return { valid: Boolean(validator(value)), errors: validator.errors };
}

function addUnknownMember(value: unknown): unknown {
  const copy = structuredClone(value);
  if (Array.isArray(copy)) {
    (copy[0] as Record<string, unknown>).unknown_member = true;
  } else {
    (copy as Record<string, unknown>).unknown_member = true;
  }
  return copy;
}

function removeRequiredMember(value: unknown, key: string): unknown {
  const copy = structuredClone(value);
  if (Array.isArray(copy)) {
    delete (copy[0] as Record<string, unknown>)[key];
  } else {
    delete (copy as Record<string, unknown>)[key];
  }
  return copy;
}

describe.each(cases)("$name schema", ({ file, value, missingKey, malformed }) => {
  it("accepts the exact positive structural shape and canonical schema metadata", () => {
    const schema = loadSchema(file);
    expect(schema.$schema).toBe("http://json-schema.org/draft-07/schema#");
    expect(schema.$id).toBe(`https://heterodyne.network/schemas/comms/${file}`);
    const result = validate(file, value());
    expect(result.valid, JSON.stringify(result.errors)).toBe(true);
  });

  it("rejects an unknown member at its record boundary", () => {
    expect(validate(file, addUnknownMember(value())).valid).toBe(false);
  });

  it("rejects a missing required member", () => {
    expect(validate(file, removeRequiredMember(value(), missingKey)).valid).toBe(false);
  });

  it("rejects a noncanonical or wrong-length encoding", () => {
    const candidate = structuredClone(value());
    malformed(candidate);
    expect(validate(file, candidate).valid).toBe(false);
  });
});

describe("schema-expressible credential-continuity branches", () => {
  it("rejects a sequence-zero repository inventory with parents", () => {
    const value = repositoryInventory() as unknown as {
      previous_records: Array<{ inventory_sequence: number; record_digest: string }>;
    };
    value.previous_records = [{ inventory_sequence: 0, record_digest: SHA256 }];
    expect(validate("repository-retention-inventory-v1.schema.json", value).valid).toBe(
      false,
    );
  });

  it("selects the secret-ID width from the secret class", () => {
    const value = governedBinding();
    value.secret_class = "oauth-pairwise";
    expect(validate("governed-decrypt-key-binding-v1.schema.json", value).valid).toBe(
      false,
    );
  });

  it("requires retain to be nonempty and close to be empty", () => {
    const close = historicalObligation() as unknown as {
      lineage_sequence: number;
      previous_record: string | null;
      action: string;
      retained_ciphertexts: unknown[];
    };
    close.lineage_sequence = 1;
    close.previous_record = SHA256;
    close.action = "close";
    expect(validate("historical-decrypt-obligation-v1.schema.json", close).valid).toBe(
      false,
    );

    const emptyRetain = historicalObligation() as unknown as {
      retained_ciphertexts: unknown[];
    };
    emptyRetain.retained_ciphertexts = [];
    expect(
      validate("historical-decrypt-obligation-v1.schema.json", emptyRetain).valid,
    ).toBe(false);
  });

  it("admits only a structurally legal checkpoint continuity form", () => {
    const value = checkpoint();
    value.generation = 1;
    expect(validate("credential-ledger-checkpoint-v1.schema.json", value).valid).toBe(
      false,
    );
  });

  it("requires both candidate transition references or neither", () => {
    const value = candidateAbandonment();
    value.candidate_transition_id = null as unknown as string;
    expect(
      validate("credential-ledger-candidate-abandonment-v1.schema.json", value).valid,
    ).toBe(false);
  });

  it("closes inherited-reference and opaque-copy manifest alternatives", () => {
    const value = stagingCleanup() as unknown as {
      opaque_object_manifest: Array<Record<string, unknown>>;
    };
    value.opaque_object_manifest[0] = {
      ...value.opaque_object_manifest[0],
      disposition: "inherited-reference",
      inherited_audit_set_digests: [SHA256],
    };
    expect(
      validate("credential-ledger-staging-ref-cleanup-v1.schema.json", value).valid,
    ).toBe(false);
  });

  it("requires at least one bootstrap recipient", () => {
    expect(
      validate("credential-ledger-config-key-bootstrap-recipient-array-v1.schema.json", [])
        .valid,
    ).toBe(false);
  });

  it("requires collision evidence for the collision-only reset reason", () => {
    const value = emergencyReset();
    value.reason = "credential_ledger_reset_offline_activation_id_collision";
    value.unavailable_nodes = [];
    expect(validate("credential-ledger-emergency-reset-v1.schema.json", value).valid).toBe(
      false,
    );
  });
});
