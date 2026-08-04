import { describe, expect, it } from "vitest";
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
  validateSecretInstance,
  type CheckpointCandidateInput,
  type CredentialCheckpoint,
  type SecretAssignment,
  type SecretSource,
} from "./credential-continuity.js";

const H32 = "11".repeat(32);
const H32_B = "22".repeat(32);
const H32_C = "33".repeat(32);
const H16 = "44".repeat(16);
const NID_A = "did:key:z6MkhM7qBMzbpZbpQeMVQW1H4KAKz7GgzGzHwGKYvEyt84qC";
const NID_B = "did:key:z6MkjUu8rZKs11amYJzwRyJyyuGHcAfWjjjqbTncCjB7FAsF";
const ZERO_DIGEST = "00".repeat(32);

const source = (overrides: Partial<SecretSource> = {}): SecretSource => ({
  record_digest: "a1".repeat(32),
  persona: H32,
  holder_nid: NID_A,
  secret_class: "oauth-pairwise",
  secret_id: H32_B,
  instance_commitment: "b1".repeat(32),
  ...overrides,
});

const assignment = (
  overrides: Partial<SecretAssignment> = {},
): SecretAssignment => ({
  record_digest: "c1".repeat(32),
  assignment_id: H16,
  action: "assign",
  holder_nid: NID_A,
  secret_class: "oauth-pairwise",
  secret_id: H32_B,
  secret_commitment: "b1".repeat(32),
  source_record_digest: "a1".repeat(32),
  transition_id: null,
  supersedes: null,
  ...overrides,
});

const checkpoint = (
  overrides: Partial<CredentialCheckpoint> = {},
): CredentialCheckpoint => ({
  persona: H32,
  generation: 0,
  sequence: 0,
  previous_checkpoint: null,
  generation_transition: null,
  node_roster: [NID_A],
  config_key_id: H16,
  config_key_sha256: "71".repeat(32),
  pairwise_secret_sha256: "72".repeat(32),
  exposure_set_sha256: "73".repeat(32),
  governed_decrypt_key_bindings_sha256: "74".repeat(32),
  historical_decrypt_obligations_sha256: "75".repeat(32),
  epoch_pubkey: H32_B,
  kel_head: { event_id: H32_C, seq: 4 },
  ...overrides,
});

const checkpointInput = (
  candidate: CredentialCheckpoint,
  overrides: Partial<CheckpointCandidateInput> = {},
): CheckpointCandidateInput => ({
  candidate,
  candidate_digest: "81".repeat(32),
  predecessor: null,
  predecessor_digest: null,
  expected_persona: H32,
  current_generation: 0,
  current_epoch: {
    epoch_pubkey: H32_B,
    kel_head: { event_id: H32_C, seq: 4 },
  },
  active_delegation_nids: [NID_A],
  receipt_nids: [NID_A],
  recomputed: {
    exposure_set_sha256: candidate.exposure_set_sha256,
    governed_decrypt_key_bindings_sha256:
      candidate.governed_decrypt_key_bindings_sha256,
    historical_decrypt_obligations_sha256:
      candidate.historical_decrypt_obligations_sha256,
  },
  operational_pairwise_tuples: [
    {
      secret_id: "91".repeat(32),
      instance_commitment: candidate.pairwise_secret_sha256,
    },
  ],
  operational_epoch_tuples: [
    {
      secret_id: candidate.epoch_pubkey,
      instance_commitment: domainSeparatedJcsDigest(
        "heterodyne-node-secret-instance-v1",
        {
          epoch_pubkey: candidate.epoch_pubkey,
          kel_head: candidate.kel_head,
        },
      ),
    },
  ],
  mutation_after_basis: false,
  ...overrides,
});

describe("credential continuity primitives", () => {
  it("uses exact zero-separated JCS digest domains", () => {
    expect(
      domainSeparatedJcsDigest("heterodyne-test-v1", { z: 2, a: 1 }),
    ).toBe("abc757f28e4d86fd387d1fd60ba3976480037040450d3ce0fd38a10fbef46c6a");
  });

  it("enforces class-selected IDs and commitments", () => {
    const config = validateSecretInstance({
      secret_class: "config-audience",
      secret_id: H16,
      secret_bytes: Uint8Array.from([1, 2, 3]),
    });
    expect(config.instance_commitment).toMatch(/^[0-9a-f]{64}$/);
    expect(() =>
      validateSecretInstance({
        secret_class: "config-audience",
        secret_id: H32,
        secret_bytes: Uint8Array.from([1]),
      }),
    ).toThrow(/config-audience.*32 lowercase hexadecimal/i);
    expect(() =>
      validateSecretInstance({
        secret_class: "oauth-pairwise",
        secret_id: H16,
        secret_bytes: Uint8Array.from([1]),
      }),
    ).toThrow(/64 lowercase hexadecimal/i);
  });
});

describe("conservative secret exposure replay", () => {
  it("keeps staged assignments and removes only accepted exact retirements", () => {
    const staged = assignment({ transition_id: H16 });
    const pendingRetirement = assignment({
      record_digest: "c2".repeat(32),
      action: "retire",
      supersedes: staged.record_digest,
      source_record_digest: staged.source_record_digest,
      transition_id: H16,
    });
    const pending = replayExposureSet({
      sources: [source()],
      assignments: [staged, pendingRetirement],
      accepted_transition_ids: [],
    });
    expect(pending.items).toHaveLength(1);
    expect(pending.items[0]?.assignment_record_digests).toEqual([
      staged.record_digest,
    ]);

    const accepted = replayExposureSet({
      sources: [source()],
      assignments: [staged, pendingRetirement],
      accepted_transition_ids: [H16],
    });
    expect(accepted.items).toEqual([]);
  });

  it("preserves competing assignment variants and quarantines operational use", () => {
    const conflicting = assignment({
      record_digest: "c3".repeat(32),
      secret_id: "92".repeat(32),
      secret_commitment: "93".repeat(32),
    });
    const result = replayExposureSet({
      sources: [
        source(),
        source({
          record_digest: "a2".repeat(32),
          secret_id: conflicting.secret_id,
          instance_commitment: conflicting.secret_commitment,
        }),
      ],
      assignments: [
        assignment(),
        { ...conflicting, source_record_digest: "a2".repeat(32) },
      ],
      accepted_transition_ids: [],
    });
    expect(result.conflicted_assignment_ids).toEqual([H16]);
    expect(result.items).toHaveLength(2);
    expect(result.operational_assignment_ids).toEqual([]);
  });

  it("rejects source and assignment tuple substitution", () => {
    expect(() =>
      replayExposureSet({
        sources: [source()],
        assignments: [
          assignment({ secret_commitment: "ff".repeat(32) }),
        ],
        accepted_transition_ids: [],
      }),
    ).toThrow(/source.*tuple|tuple.*source/i);
  });
});

describe("checkpoint continuity and acceptance", () => {
  it("accepts genesis, same-generation successor, and reset successor", () => {
    expect(evaluateCheckpointCandidate(checkpointInput(checkpoint()))).toEqual({
      verdict: "accept",
      continuity: "genesis",
    });

    const prior = checkpoint();
    const same = checkpoint({
      sequence: 1,
      previous_checkpoint: "82".repeat(32),
    });
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(same, {
          predecessor: prior,
          predecessor_digest: same.previous_checkpoint,
        }),
      ),
    ).toEqual({ verdict: "accept", continuity: "same-generation" });

    const reset = checkpoint({
      generation: 1,
      sequence: 0,
      generation_transition: "83".repeat(32),
    });
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(reset, {
          predecessor: prior,
          predecessor_digest: "82".repeat(32),
          current_generation: 1,
        }),
      ),
    ).toEqual({ verdict: "accept", continuity: "reset" });
  });

  it("reports reset validation only after a structurally valid reset checkpoint", () => {
    const prior = checkpoint();
    const reset = checkpoint({
      generation: 1,
      sequence: 0,
      generation_transition: "83".repeat(32),
    });
    const resetInput = {
      ...checkpointInput(reset, {
        predecessor: prior,
        predecessor_digest: "82".repeat(32),
        current_generation: 1,
      }),
      reset_valid: false,
    };
    expect(
      evaluateCheckpointCandidate(resetInput),
    ).toEqual({
      verdict: "reject",
      reason: "credential_reset_invalid",
    });
  });

  it("applies missing generation, empty roster, persona, generation, KEL, then checkpoint precedence", () => {
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(checkpoint({ generation: undefined }), {
          active_delegation_nids: [],
          receipt_nids: [],
        }),
      ),
    ).toEqual({
      verdict: "reject",
      reason: "credential_generation_missing",
    });
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(checkpoint({ node_roster: [] }), {
          active_delegation_nids: [],
          receipt_nids: [],
        }),
      ),
    ).toEqual({ verdict: "reject", reason: "credential_roster_empty" });
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(checkpoint({ persona: H32_C })),
      ),
    ).toEqual({
      verdict: "reject",
      reason: "credential_ledger_persona_mismatch",
    });
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(checkpoint(), { current_generation: 2 }),
      ),
    ).toEqual({
      verdict: "reject",
      reason: "credential_generation_stale",
    });
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(checkpoint(), {
          current_epoch: {
            epoch_pubkey: H32_B,
            kel_head: { event_id: ZERO_DIGEST, seq: 4 },
          },
        }),
      ),
    ).toEqual({
      verdict: "reject",
      reason: "credential_checkpoint_stale_kel",
    });
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(checkpoint(), { receipt_nids: [] }),
      ),
    ).toEqual({
      verdict: "reject",
      reason: "credential_checkpoint_invalid",
    });
  });

  it("keeps wrong-typed generation, non-array roster, and malformed checkpoints in structural failure", () => {
    const wrongGeneration = {
      ...checkpoint(),
      generation: "0",
    } as unknown as CredentialCheckpoint;
    expect(
      evaluateCheckpointCandidate(checkpointInput(wrongGeneration)),
    ).toEqual({
      verdict: "reject",
      reason: "credential_checkpoint_invalid",
    });

    const nonArrayRoster = {
      ...checkpoint(),
      node_roster: "not-an-array",
    } as unknown as CredentialCheckpoint;
    expect(
      evaluateCheckpointCandidate(checkpointInput(nonArrayRoster)),
    ).toEqual({
      verdict: "reject",
      reason: "credential_checkpoint_invalid",
    });

    expect(
      evaluateCheckpointCandidate(
        checkpointInput(checkpoint({
          persona: H32_C,
          config_key_id: "AA".repeat(16),
        })),
      ),
    ).toEqual({
      verdict: "reject",
      reason: "credential_checkpoint_invalid",
    });
  });

  it("requires exact singleton identities and invalidates basis mutation", () => {
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(checkpoint(), {
          operational_pairwise_tuples: [],
        }),
      ),
    ).toEqual({
      verdict: "reject",
      reason: "credential_checkpoint_invalid",
    });
    expect(
      evaluateCheckpointCandidate(
        checkpointInput(checkpoint(), { mutation_after_basis: true }),
      ),
    ).toEqual({
      verdict: "reject",
      reason: "credential_checkpoint_invalid",
    });
  });
});

describe("repository retention and historical obligation replay", () => {
  const ref = {
    repository_ref_id: "41".repeat(32),
    repository_class: "config" as const,
    repository_rid: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
    ref_name: `refs/heads/enc/${H16}`,
    object_format: "sha1" as const,
    retired: false,
    scan_head: { object_format: "sha1" as const, oid: "42".repeat(20) },
  };

  it("requires the complete maximal parent frontier and monotonic cuts", () => {
    const genesis = {
      record_digest: "51".repeat(32),
      inventory_sequence: 0,
      previous_records: [],
      basis_checkpoint_digest: null,
      target_generation: 0,
      target_sequence: 0,
      repository_refs: [ref],
    };
    const first = evaluateRetentionInventory({
      parents: [],
      candidate: genesis,
      activated_generation: 0,
      activated_sequence: 0,
      is_descendant_or_equal: () => true,
    });
    expect(first.verdict).toBe("accept");
    const successor = {
      ...genesis,
      record_digest: "52".repeat(32),
      inventory_sequence: 1,
      previous_records: [
        {
          inventory_sequence: 0,
          record_digest: genesis.record_digest,
        },
      ],
      basis_checkpoint_digest: "53".repeat(32),
      target_sequence: 1,
    };
    expect(
      evaluateRetentionInventory({
        parents: [genesis],
        candidate: successor,
        activated_generation: 0,
        activated_sequence: 1,
        is_descendant_or_equal: () => true,
      }).verdict,
    ).toBe("accept");
    expect(
      evaluateRetentionInventory({
        parents: [genesis],
        candidate: {
          ...successor,
          previous_records: [],
        },
        activated_generation: 0,
        activated_sequence: 1,
        is_descendant_or_equal: () => true,
      }),
    ).toMatchObject({ verdict: "reject" });
  });

  it("allows emergency convergence to remove the complete old config-ref variant set", () => {
    const oldVariantA = {
      ...ref,
      repository_ref_id: "61".repeat(32),
      scan_head: { object_format: "sha1" as const, oid: "62".repeat(20) },
    };
    const oldVariantB = {
      ...ref,
      repository_ref_id: "63".repeat(32),
      scan_head: { object_format: "sha1" as const, oid: "64".repeat(20) },
    };
    const parentA = {
      record_digest: "65".repeat(32),
      inventory_sequence: 0,
      previous_records: [],
      basis_checkpoint_digest: null,
      target_generation: 0,
      target_sequence: 0,
      repository_refs: [oldVariantA],
    };
    const parentB = {
      ...parentA,
      record_digest: "66".repeat(32),
      repository_refs: [oldVariantB],
    };
    const newRef = {
      ...ref,
      repository_ref_id: "67".repeat(32),
      ref_name: `refs/heads/enc/${"68".repeat(16)}`,
      scan_head: { object_format: "sha1" as const, oid: "69".repeat(20) },
    };
    const candidate = {
      record_digest: "6a".repeat(32),
      inventory_sequence: 1,
      previous_records: [
        { inventory_sequence: 0, record_digest: parentA.record_digest },
        { inventory_sequence: 0, record_digest: parentB.record_digest },
      ],
      basis_checkpoint_digest: "6b".repeat(32),
      target_generation: 1,
      target_sequence: 0,
      repository_refs: [newRef],
    };
    const input = {
      parents: [parentA, parentB],
      candidate,
      activated_generation: 1,
      activated_sequence: 0,
      is_descendant_or_equal: () => true,
      config_deregistration: {
        old_repository_ref_ids: [
          oldVariantA.repository_ref_id,
          oldVariantB.repository_ref_id,
        ],
        new_repository_ref_id: newRef.repository_ref_id,
      },
    } as unknown as Parameters<typeof evaluateRetentionInventory>[0];
    expect(evaluateRetentionInventory(input)).toMatchObject({
      verdict: "accept",
    });
  });

  it("derives the complete obligation frontier and exact G(C)=O(C)", () => {
    const locator = {
      storage_class: "git-blob",
      owner: "comms.config-repository.v1",
      repository_rid: ref.repository_rid,
      repository_head: ref.scan_head,
      ref_name: ref.ref_name,
      path: "config-data/" + "61".repeat(32) + ".bin",
      git_blob_oid: { object_format: "sha1" as const, oid: "62".repeat(20) },
      object_id: null,
      ciphertext_sha256: "63".repeat(32),
      ciphertext_length: 128,
    };
    const tuple = {
      secret_class: "config-audience" as const,
      secret_id: H16,
      instance_commitment: "64".repeat(32),
    };
    const root = {
      record_digest: "65".repeat(32),
      obligation_id: H16,
      lineage_sequence: 0,
      previous_record: null,
      action: "retain" as const,
      ...tuple,
      retained_ciphertexts: [locator],
      retired_provenance_lineages: [],
    };
    expect(
      evaluateHistoricalObligations({
        records: [root],
        governed_dependencies: [{ locator, tuple }],
        ordinary_acceptance: true,
      }),
    ).toMatchObject({ verdict: "accept", active_obligations: [root.record_digest] });
    expect(
      evaluateHistoricalObligations({
        records: [root],
        governed_dependencies: [],
        ordinary_acceptance: true,
      }),
    ).toMatchObject({ verdict: "reject" });
    expect(
      evaluateHistoricalObligations({
        records: [
          root,
          { ...root, record_digest: "66".repeat(32) },
        ],
        governed_dependencies: [{ locator, tuple }],
        ordinary_acceptance: true,
      }),
    ).toMatchObject({ verdict: "reject", reason: "fork" });
  });
});

describe("transition, candidate, and DR terminalization", () => {
  it("enforces roster deltas, action completeness, and selected authority", () => {
    const result = evaluateSecretTransition({
      mode: "routine-removal",
      old_roster: [NID_A, NID_B],
      new_roster: [NID_A],
      added_nids: [],
      removed_nids: [NID_B],
      exposure_classes: ["config-audience", "oauth-pairwise", "double-ratchet"],
      action_classes: ["config-audience", "oauth-pairwise", "double-ratchet"],
      removal_observation_nids: [NID_B],
      transition_authority: "epoch",
    });
    expect(result).toEqual({
      verdict: "accept",
      required_authority: "epoch",
    });
    expect(
      evaluateSecretTransition({
        mode: "routine-removal",
        old_roster: [NID_A, NID_B],
        new_roster: [NID_A],
        added_nids: [],
        removed_nids: [NID_B],
        exposure_classes: ["config-audience", "epoch"],
        action_classes: ["config-audience", "epoch"],
        removal_observation_nids: [NID_B],
        transition_authority: "epoch",
      }),
    ).toMatchObject({ verdict: "reject", required_authority: "cold-root" });
  });

  it("makes cold-root exposure a persona migration terminal condition", () => {
    expect(
      evaluateSecretTransition({
        mode: "emergency-reset",
        old_roster: [NID_A],
        new_roster: [NID_A],
        added_nids: [],
        removed_nids: [],
        exposure_classes: ["cold-root"],
        action_classes: ["cold-root"],
        removal_observation_nids: [],
        transition_authority: "cold-root",
      }),
    ).toEqual({
      verdict: "reject",
      reason: "persona-migration-required",
      required_authority: "cold-root",
    });
  });

  it("orders append, acceptance, abandonment, and reset by exact-tip CAS", () => {
    const started = {
      status: "pending" as const,
      tip: "a".repeat(40),
      partial_record_digests: [] as string[],
    };
    const appended = advanceCandidate(started, {
      kind: "append",
      expected_tip: started.tip,
      new_tip: "b".repeat(40),
      record_digests: ["d1".repeat(32)],
    });
    expect(appended.status).toBe("pending");
    expect(() =>
      advanceCandidate(appended, {
        kind: "abandon",
        expected_tip: started.tip,
        new_tip: "c".repeat(40),
      }),
    ).toThrow(/stale.*tip/i);
    const accepted = advanceCandidate(appended, {
      kind: "accept",
      expected_tip: appended.tip,
      new_tip: "d".repeat(40),
    });
    expect(accepted.status).toBe("accepted");
    expect(() =>
      advanceCandidate(accepted, {
        kind: "append",
        expected_tip: accepted.tip,
        new_tip: "e".repeat(40),
        record_digests: ["d2".repeat(32)],
      }),
    ).toThrow(/terminal/i);
  });

  it("selects the DR tombstone reason only from actual roster removal", () => {
    expect(
      selectDrTombstoneReason({
        old_holder_nids: [NID_A, NID_B],
        removed_nids: [NID_B],
      }),
    ).toBe("persona_node_removed");
    expect(
      selectDrTombstoneReason({
        old_holder_nids: [NID_A],
        removed_nids: [NID_B],
      }),
    ).toBe("candidate_material_retired");
  });
});

describe("config Git authenticated raw projection", () => {
  it("accepts canonical raw base64url and recomputed SHA-1 objects", () => {
    const commitRaw = Buffer.from(
      "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
        "author Heterodyne <protocol@heterodyne.network> 0 +0000\n" +
        "committer Heterodyne <protocol@heterodyne.network> 0 +0000\n\n" +
        "heterodyne-config-v1\n",
      "utf8",
    );
    const projection = {
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
    expect(validateConfigGitProjection(projection)).toMatchObject({
      kind: "ordinary",
      parent_oids: [],
    });
  });

  it("rejects noncanonical base64url and mismatched object IDs", () => {
    const base = {
      type: "heterodyne.config-repository-git-structure.v1" as const,
      object_format: "sha1" as const,
      commit_oid: "00".repeat(20),
      commit_raw_base64url: "YQ==",
      tree_objects: [],
    };
    expect(() => validateConfigGitProjection(base)).toThrow(/base64url/i);
    expect(() =>
      validateConfigGitProjection({
        ...base,
        commit_raw_base64url: Buffer.from("bad").toString("base64url"),
      }),
    ).toThrow(/object id|oid/i);
  });
});
