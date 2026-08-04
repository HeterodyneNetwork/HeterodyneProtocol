import {
  advanceCandidate,
  domainSeparatedJcsDigest,
  evaluateCheckpointCandidate,
  evaluateHistoricalObligations,
  evaluateRetentionInventory,
  evaluateSecretTransition,
  replayExposureSet,
  selectDrTombstoneReason,
  validateConfigGitProjection,
  type CredentialCheckpoint,
} from "./credential-continuity.js";
import { CREDENTIAL_CONTINUITY_SCHEMA_FILES } from "./schema.js";
import { baseVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

const H16 = "11".repeat(16);
const H32 = "22".repeat(32);
const PERSONA = "33".repeat(32);
const EPOCH = "44".repeat(32);
const KEL_EVENT = "55".repeat(32);
const NID_A =
  "did:key:z6MkhM7qBMzbpZbpQeMVQW1H4KAKz7GgzGzHwGKYvEyt84qC";
const NID_B =
  "did:key:z6MkjUu8rZKs11amYJzwRyJyyuGHcAfWjjjqbTncCjB7FAsF";

export function buildCredentialContinuityVectors(): AuthoredVector[] {
  const vectors: AuthoredVector[] = [];
  const checkpoint: CredentialCheckpoint = {
    persona: PERSONA,
    generation: 0,
    sequence: 0,
    previous_checkpoint: null,
    generation_transition: null,
    node_roster: [NID_A],
    config_key_id: H16,
    config_key_sha256: "61".repeat(32),
    pairwise_secret_sha256: "62".repeat(32),
    exposure_set_sha256: "63".repeat(32),
    governed_decrypt_key_bindings_sha256: "64".repeat(32),
    historical_decrypt_obligations_sha256: "65".repeat(32),
    epoch_pubkey: EPOCH,
    kel_head: { event_id: KEL_EVENT, seq: 7 },
  };
  const epochCommitment = domainSeparatedJcsDigest(
    "heterodyne-node-secret-instance-v1",
    {
      epoch_pubkey: EPOCH,
      kel_head: checkpoint.kel_head,
    },
  );
  const checkpointInput = {
    candidate: checkpoint,
    candidate_digest: "66".repeat(32),
    predecessor: null,
    predecessor_digest: null,
    expected_persona: PERSONA,
    current_generation: 0,
    current_epoch: {
      epoch_pubkey: EPOCH,
      kel_head: checkpoint.kel_head,
    },
    active_delegation_nids: [NID_A],
    receipt_nids: [NID_A],
    recomputed: {
      exposure_set_sha256: checkpoint.exposure_set_sha256,
      governed_decrypt_key_bindings_sha256:
        checkpoint.governed_decrypt_key_bindings_sha256,
      historical_decrypt_obligations_sha256:
        checkpoint.historical_decrypt_obligations_sha256,
    },
    operational_pairwise_tuples: [
      {
        secret_id: "67".repeat(32),
        instance_commitment: checkpoint.pairwise_secret_sha256,
      },
    ],
    operational_epoch_tuples: [
      {
        secret_id: EPOCH,
        instance_commitment: epochCommitment,
      },
    ],
    mutation_after_basis: false,
  };

  vectors.push(
    draft(
      "credential-continuity/001-checkpoint-genesis.json",
      "credential-continuity/checkpoint-genesis",
      "The draft credential checkpoint accepts only after exact generation, KEL, singleton, delegation, and receipt replay.",
      checkpointInput,
      evaluateCheckpointCandidate(checkpointInput),
    ),
  );
  vectors.push(
    draft(
      "credential-continuity/002-stale-generation.json",
      "credential-continuity/stale-generation",
      "A structurally recognizable prior-generation checkpoint is a draft rejection and never inferred as generation zero.",
      { ...checkpointInput, current_generation: 1 },
      evaluateCheckpointCandidate({
        ...checkpointInput,
        current_generation: 1,
      }),
    ),
  );

  const source = {
    record_digest: "71".repeat(32),
    persona: PERSONA,
    holder_nid: NID_A,
    secret_class: "config-audience" as const,
    secret_id: H16,
    instance_commitment: checkpoint.config_key_sha256,
  };
  const assign = {
    record_digest: "72".repeat(32),
    assignment_id: "73".repeat(16),
    action: "assign" as const,
    holder_nid: NID_A,
    secret_class: "config-audience" as const,
    secret_id: H16,
    secret_commitment: checkpoint.config_key_sha256,
    source_record_digest: source.record_digest,
    transition_id: null,
    supersedes: null,
  };
  const pendingRetire = {
    ...assign,
    record_digest: "74".repeat(32),
    action: "retire" as const,
    transition_id: "75".repeat(16),
    supersedes: assign.record_digest,
  };
  const exposureInput = {
    sources: [source],
    assignments: [assign, pendingRetire],
    accepted_transition_ids: [] as string[],
  };
  vectors.push(
    draft(
      "credential-continuity/003-pending-retirement-conservative.json",
      "credential-continuity/pending-retirement-conservative",
      "A pending retirement removes no assignment from the conservative exposure projection.",
      exposureInput,
      replayExposureSet(exposureInput),
    ),
  );

  const repositoryRef = {
    repository_ref_id: "76".repeat(32),
    repository_class: "config" as const,
    repository_rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
    ref_name: `refs/heads/enc/${H16}`,
    object_format: "sha1" as const,
    retired: false,
    scan_head: { object_format: "sha1" as const, oid: "77".repeat(20) },
  };
  const inventory = {
    record_digest: "78".repeat(32),
    inventory_sequence: 0,
    previous_records: [],
    basis_checkpoint_digest: null,
    target_generation: 0,
    target_sequence: 0,
    repository_refs: [repositoryRef],
  };
  const inventoryInput = {
    parents: [],
    candidate: inventory,
    activated_generation: 0,
    activated_sequence: 0,
    is_descendant_or_equal: () => true,
  };
  vectors.push(
    draft(
      "credential-continuity/004-retention-inventory-genesis.json",
      "credential-continuity/retention-inventory-genesis",
      "The draft signed retention inventory activates only at its exact target and complete parent frontier.",
      {
        parents: [],
        candidate: inventory,
        activated_generation: 0,
        activated_sequence: 0,
        ancestry_projection: "equal",
      },
      evaluateRetentionInventory(inventoryInput),
    ),
  );

  const locator = {
    storage_class: "git-blob",
    owner: "comms.config-repository.v1",
    repository_rid: repositoryRef.repository_rid,
    repository_head: repositoryRef.scan_head,
    ref_name: repositoryRef.ref_name,
    path: `config-data/${"79".repeat(32)}.bin`,
    git_blob_oid: { object_format: "sha1" as const, oid: "7a".repeat(20) },
    object_id: null,
    ciphertext_sha256: "7b".repeat(32),
    ciphertext_length: 256,
  };
  const tuple = {
    secret_class: "config-audience" as const,
    secret_id: H16,
    instance_commitment: checkpoint.config_key_sha256,
  };
  const obligation = {
    record_digest: "7c".repeat(32),
    obligation_id: "7d".repeat(16),
    lineage_sequence: 0,
    previous_record: null,
    action: "retain" as const,
    ...tuple,
    retained_ciphertexts: [locator],
    retired_provenance_lineages: [],
  };
  const obligationInput = {
    records: [obligation],
    governed_dependencies: [{ locator, tuple }],
    ordinary_acceptance: true,
  };
  vectors.push(
    draft(
      "credential-continuity/005-governed-obligation-equation.json",
      "credential-continuity/governed-obligation-equation",
      "The independently derived governed-dependency set equals the active historical-obligation projection exactly.",
      obligationInput,
      evaluateHistoricalObligations(obligationInput),
    ),
  );

  const removalInput = {
    mode: "routine-removal" as const,
    old_roster: [NID_A, NID_B],
    new_roster: [NID_A],
    added_nids: [],
    removed_nids: [NID_B],
    exposure_classes: [
      "config-audience",
      "oauth-pairwise",
      "double-ratchet",
    ] as const,
    action_classes: [
      "config-audience",
      "oauth-pairwise",
      "double-ratchet",
    ] as const,
    removal_observation_nids: [NID_B],
    transition_authority: "epoch" as const,
  };
  vectors.push(
    draft(
      "credential-continuity/006-routine-removal-complete.json",
      "credential-continuity/routine-removal-complete",
      "Routine removal requires exact roster delta, observations, mandatory rotations, and a class-complete action set.",
      removalInput,
      evaluateSecretTransition({
        ...removalInput,
        exposure_classes: [...removalInput.exposure_classes],
        action_classes: [...removalInput.action_classes],
      }),
    ),
  );

  const migrationInput = {
    mode: "emergency-reset" as const,
    old_roster: [NID_A],
    new_roster: [NID_A],
    added_nids: [],
    removed_nids: [],
    exposure_classes: ["cold-root"] as const,
    action_classes: ["cold-root"] as const,
    removal_observation_nids: [],
    transition_authority: "cold-root" as const,
  };
  vectors.push(
    draft(
      "credential-continuity/007-cold-root-exposure-migrates.json",
      "credential-continuity/cold-root-exposure-migrates",
      "Cold-root exposure is terminal persona migration, never an acceptable same-persona reset.",
      migrationInput,
      evaluateSecretTransition({
        ...migrationInput,
        exposure_classes: [...migrationInput.exposure_classes],
        action_classes: [...migrationInput.action_classes],
      }),
    ),
  );

  const pending = {
    status: "pending" as const,
    tip: "81".repeat(20),
    partial_record_digests: [] as string[],
  };
  const append = {
    kind: "append" as const,
    expected_tip: pending.tip,
    new_tip: "82".repeat(20),
    record_digests: ["83".repeat(32)],
  };
  vectors.push(
    draft(
      "credential-continuity/008-candidate-exact-tip-append.json",
      "credential-continuity/candidate-exact-tip-append",
      "Candidate receipt append is an exact-tip CAS that preserves prior bytes and adds new records.",
      { state: pending, operation: append },
      advanceCandidate(pending, append),
    ),
  );

  const tombstoneInput = {
    old_holder_nids: [NID_A, NID_B],
    removed_nids: [NID_B],
  };
  vectors.push(
    draft(
      "credential-continuity/009-dr-persona-node-removed.json",
      "credential-continuity/dr-persona-node-removed",
      "The DR tombstone uses persona_node_removed only for an actual removed-roster holder.",
      tombstoneInput,
      { reason: selectDrTombstoneReason(tombstoneInput) },
    ),
  );

  const commitRaw = Buffer.from(
    "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
      "author Heterodyne <protocol@heterodyne.network> 0 +0000\n" +
      "committer Heterodyne <protocol@heterodyne.network> 0 +0000\n\n" +
      "heterodyne-config-v1\n",
    "utf8",
  );
  const gitProjection = {
    type: "heterodyne.config-repository-git-structure.v1" as const,
    object_format: "sha1" as const,
    commit_oid: "3f3ddb82263fa2e7552e33977206122bfd19e564",
    commit_raw_base64url: commitRaw.toString("base64url"),
    tree_objects: [
      {
        oid: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        raw_base64url: "",
      },
    ],
  };
  vectors.push(
    draft(
      "credential-continuity/010-config-git-raw-projection.json",
      "credential-continuity/config-git-raw-projection",
      "The closed draft config-Git carrier authenticates exact raw commit/tree bytes without activating the profile.",
      gitProjection,
      validateConfigGitProjection(gitProjection),
    ),
  );

  vectors.push(
    draft(
      "credential-continuity/011-twenty-schemas-gated.json",
      "credential-continuity/twenty-schemas-gated",
      "All twenty Comms schemas are present as draft definitions while revision-4 profiles and reasons remain unavailable.",
      {
        selected_registry_revision: 3,
        schema_files: [...CREDENTIAL_CONTINUITY_SCHEMA_FILES],
        adr038_core_recovery_schemas_active: false,
        governed_source_profile_catalog_active: false,
      },
      {
        schema_count: CREDENTIAL_CONTINUITY_SCHEMA_FILES.length,
        profile_active: false,
        revision_4_claimable: false,
        offline_recovery_conformance_complete: false,
      },
    ),
  );

  return vectors;
}

function draft(
  relativePath: string,
  vectorId: string,
  description: string,
  input: Record<string, unknown>,
  decision: unknown,
): AuthoredVector {
  return {
    relativePath,
    vector: baseVector({
      vector_id: vectorId,
      spec_refs: ["metadata-selects-comms-subset-anchor"],
      description,
      direction: "consume",
      input,
      expected_output: {
        verdict: "accept",
        normalized: {
          draft_credential_continuity_decision: decision,
          selected_registry_revision: 3,
          conformance_claimable: false,
        },
      },
    }),
  };
}
