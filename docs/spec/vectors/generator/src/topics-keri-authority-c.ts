import { deriveMaterializedRefs, type KelEntry, type MaterializedState } from "./keri-materialized.js";
import { inceptionTemplate } from "./kel.js";
import { canonicalNip01, getPublicKey, signEvent } from "./nostr.js";
import { AUX_RAND, consumeVector, produceAuthored } from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector } from "./types.js";

const STATE_SCHEMA_REF = "§10.1.2";

// keri-authority/ materialized-KEL derivation (OID-level, §10.1.2) and
// did:webs export (§11.8) vectors (ADR-032). The materialized vectors pin
// byte-identical git blob/tree/commit OIDs (validated against real git in
// keri-materialized.test.ts) for a two-event accepted KEL, plus the empty-KEL
// deletion and atomic-rebuild ref-transaction rules. The export vectors cover
// the origin-independent package, the degraded-vs-fail taxonomy, and the
// export-AID-substituted-for-npub rejection.
export async function buildKeriAuthorityMaterializedVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const alice = fixtures.personas.alice;
  const cold = alice.cold_root;
  const e1 = alice.epoch_keys.epoch_1.pubkey;
  const e2 = getPublicKey("22".padStart(64, "0"));
  const T = fixtures.test_epoch;

  const inception = await signEvent({
    secretKey: cold.private_key,
    created_at: T,
    kind: 31002,
    tags: inceptionTemplate(cold.pubkey, e1, T).tags,
    content: "",
    auxRand: AUX_RAND,
  });
  const rotation = await signEvent({
    secretKey: cold.private_key,
    created_at: T + 3600,
    kind: 31003,
    tags: [
      ["d", "1"],
      ["heterodyne", "keri_rotation"],
      ["p", cold.pubkey],
      ["s", "1"],
      ["prior_digest", inception.id],
      ["strategy", "committed"],
      ["epoch_key", e2],
    ],
    content: "[]",
    auxRand: AUX_RAND,
  });

  const state0: MaterializedState = { cold_root: cold.pubkey, s: 0, epoch_key: e1, witnesses: [], threshold: 0, producing_event_id: inception.id };
  const state1: MaterializedState = { cold_root: cold.pubkey, s: 1, epoch_key: e2, witnesses: [], threshold: 0, producing_event_id: rotation.id };
  const kel: KelEntry[] = [
    { event_id: inception.id, created_at: T, nip01_raw: canonicalNip01(inception), state: state0 },
    { event_id: rotation.id, created_at: T + 3600, nip01_raw: canonicalNip01(rotation), state: state1 },
  ];
  const refs = deriveMaterializedRefs(kel);

  const exportDigestMap = { [String(0)]: inception.id, [String(1)]: rotation.id };

  return [
    produceAuthored("keri-authority/024-materialized-log-derivation.json", {
      vector_id: "keri-authority/materialized-log-derivation",
      spec_refs: [STATE_SCHEMA_REF, "§3.0.1", "§14.3"],
      description: "refs/xyz.heterodyne.keri/log derivation: one commit per accepted KEL event in s order, sole parent the prior event's commit (inception parentless). Each tree holds one entry mode 100644 path event.nip01 whose content is the event's exact nip01_raw bytes. Git object OIDs (sha1) are byte-identical to git hash-object / mktree / commit-tree.",
      input: {
        fixture_persona: "alice",
        kel: kel.map((entry) => ({ event_id: entry.event_id, s: entry.state.s, created_at: entry.created_at, nip01_raw: entry.nip01_raw })),
        git_actor: "Heterodyne KERI <keri@heterodyne.invalid>",
        commit_message_rule: "lowercase-64-hex event id + one LF",
      },
      expected_output: {
        canonical_wire: refs.log_tip,
        decoded: {
          ref: "refs/xyz.heterodyne.keri/log",
          log_tip: refs.log_tip,
          commits: refs.log.map((commit, index) => ({
            s: index,
            event_id: kel[index].event_id,
            path: "event.nip01",
            mode: "100644",
            blob_oid: commit.blob,
            tree_oid: commit.tree,
            commit_oid: commit.commit,
            parents: commit.parents,
          })),
        },
      },
      notes: "OID-level only (no packfiles). blob = sha1(\"blob \"+len+\"\\0\"+content); tree = sha1(\"tree \"+len+\"\\0\"+\"100644 <path>\\0\"+20-byte-raw-blob-oid); commit = sha1(\"commit \"+len+\"\\0\"+text) with author==committer==git_actor, both timestamps <created_at> +0000, no encoding/gpgsig headers.",
    }),
    produceAuthored("keri-authority/025-materialized-state-derivation.json", {
      vector_id: "keri-authority/materialized-state-derivation",
      spec_refs: [STATE_SCHEMA_REF, "§14.3"],
      description: "refs/xyz.heterodyne.keri/state derivation: each state commit's tree holds one entry mode 100644 path state.json, the key state after applying the log event, canonicalized per RFC 8785 (JCS) against the §10.1.2 schema. Parents are, in order, the prior state commit then the producing log commit; the first state commit has the inception log commit as sole parent.",
      input: {
        fixture_persona: "alice",
        states: kel.map((entry) => entry.state),
        jcs: "RFC 8785: keys sorted by UTF-16 code units; s/threshold/weight are JSON integers; hex lowercase; empty witness set is [].",
      },
      expected_output: {
        canonical_wire: refs.state_tip,
        decoded: {
          ref: "refs/xyz.heterodyne.keri/state",
          state_tip: refs.state_tip,
          log_tip: refs.log_tip,
          commits: refs.state.map((commit, index) => ({
            s: index,
            producing_event_id: kel[index].event_id,
            path: "state.json",
            mode: "100644",
            state_json: commit.state_json,
            blob_oid: commit.blob,
            tree_oid: commit.tree,
            commit_oid: commit.commit,
            parents: commit.parents,
          })),
        },
      },
      notes: "The two-parent ordering (prior state commit, then producing log commit) appears at s=1; the s=0 state commit has the inception log commit as its sole parent. Readers MUST check both tips derive from the same accepted KEL head before using either as a cache.",
    }),
    consumeVector("keri-authority/026-materialized-empty-kel-deletion.json", {
      vector_id: "keri-authority/materialized-empty-kel-deletion",
      spec_refs: [STATE_SCHEMA_REF, "§14.3"],
      description: "An empty accepted KEL deletes BOTH refs (log and state) in one atomic multi-ref transaction. There is no log_tip or state_tip.",
      input: { accepted_kel: [], profile: "materialized-kel" },
      expected_output: {
        verdict: "accept",
        normalized: { log_ref_deleted: true, state_ref_deleted: true, atomic_multi_ref_transaction: true, log_tip: null, state_tip: null },
      },
      decision_trace: ["observe_empty_accepted_kel", "delete_log_and_state_refs", "single_atomic_transaction"],
    }),
    consumeVector("keri-authority/027-materialized-atomic-rebuild.json", {
      vector_id: "keri-authority/materialized-atomic-rebuild",
      spec_refs: [STATE_SCHEMA_REF, "§3.9.10.1", "§14.3"],
      description: "On divergence the materialized refs are re-derived by a FULL atomic rebuild (compare-and-swap on both refs together), never an incremental patch; the repo-carried KEL events win and the node re-derives. A backend without multi-ref atomicity MUST NOT claim the profile.",
      input: {
        divergence_detected: true,
        repo_carried_kel_head_seq: 1,
        stale_refs: ["refs/xyz.heterodyne.keri/log", "refs/xyz.heterodyne.keri/state"],
      },
      expected_output: {
        verdict: "accept",
        normalized: { rebuild: "full_atomic", incremental_patch: false, multi_ref_compare_and_swap: true, derived_from: "repo_carried_kel" },
      },
      decision_trace: ["detect_divergence", "re_derive_from_accepted_kel", "compare_and_swap_both_refs", "reject_incremental_patch"],
    }),
    consumeVector("keri-authority/028-export-aid-digest-anchoring.json", {
      vector_id: "keri-authority/export-aid-digest-anchoring",
      spec_refs: ["§11.8", "§14.3"],
      description: "The derived export AID's KEL anchors digests of the persona's accepted Heterodyne KEL events in order, and its DID document names the persona npub as the canonical Heterodyne subject. Persona authority remains solely the Heterodyne KEL; the export AID/DID is never an alternate authoritative identity.",
      input: {
        accepted_kel_event_ids: [inception.id, rotation.id],
        export_aid_present: true,
        operator_consent: true,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          anchored_digests_in_order: exportDigestMap,
          canonical_subject_npub: cold.pubkey,
          export_identity_authoritative: false,
        },
      },
      decision_trace: ["require_operator_consent", "anchor_kel_event_digests_in_order", "name_npub_as_subject", "export_not_authoritative"],
    }),
    consumeVector("keri-authority/029-export-origin-absent-not-failure.json", {
      vector_id: "keri-authority/export-origin-absent-not-failure",
      spec_refs: ["§11.8", "§14.3"],
      description: "With no operator web origin configured, a full node still produces the origin-independent export package (the export AID's CESR stream plus the anchored-digest map). The absence of did:webs artifacts (did.json, keri.cesr, the did:webs identifier) is NOT an export failure.",
      input: {
        operator_origin_configured: false,
        origin_independent_package_produced: true,
        didwebs_artifacts_present: false,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          package_produced: true,
          didwebs_artifacts: "absent",
          status: "complete",
          is_failure: false,
        },
      },
      decision_trace: ["produce_origin_independent_package", "no_operator_origin", "skip_didwebs_artifacts", "not_a_failure"],
    }),
    consumeVector("keri-authority/030-export-degraded-metadata.json", {
      vector_id: "keri-authority/export-degraded-metadata",
      spec_refs: ["§11.8", "§14.3"],
      description: "A non-security metadata omission is emitted with status degraded plus an explicit warning code and MUST NOT be labeled complete; security-relevant state is intact.",
      input: {
        omitted_field: "non_security_display_metadata",
        security_relevant_state_intact: true,
      },
      expected_output: {
        verdict: "accept",
        normalized: { status: "degraded", labeled_complete: false, security_state_omitted: false },
        warnings: ["export_degraded_metadata"],
      },
      decision_trace: ["export_security_state", "omit_non_security_metadata", "mark_status_degraded"],
    }),
    consumeVector("keri-authority/031-export-unmappable-feature.json", {
      vector_id: "keri-authority/export-unmappable-feature",
      spec_refs: ["§11.8", "§14.3"],
      description: "did:webs export fails when security-relevant KEL state uses a construct with no semantics-preserving canonical-KERI mapping (UNMAPPABLE_FEATURE). Security-relevant state MUST NOT be silently omitted or altered.",
      input: { security_relevant_feature: "unmappable_construct", mapping_exists: false },
      expected_output: { verdict: "reject", reason_code: "export_unmappable_feature" },
      decision_trace: ["scan_security_relevant_state", "no_semantics_preserving_mapping", "fail_unmappable_feature"],
    }),
    consumeVector("keri-authority/032-export-unsupported-crypto-suite.json", {
      vector_id: "keri-authority/export-unsupported-crypto-suite",
      spec_refs: ["§11.8", "§14.3"],
      description: "did:webs export fails when a mapping exists but the target crypto suite is unavailable locally (UNSUPPORTED_CRYPTO_SUITE).",
      input: { mapping_exists: true, crypto_suite_available_locally: false },
      expected_output: { verdict: "reject", reason_code: "export_unsupported_crypto_suite" },
      decision_trace: ["resolve_mapping", "crypto_suite_unavailable", "fail_unsupported_crypto_suite"],
    }),
    consumeVector("keri-authority/033-export-incomplete.json", {
      vector_id: "keri-authority/export-incomplete",
      spec_refs: ["§11.8", "§14.3"],
      description: "did:webs export fails when required source KEL events or attachments are unavailable (INCOMPLETE_EXPORT).",
      input: { required_source_events_available: false, missing: ["kel_event_s_1"] },
      expected_output: { verdict: "reject", reason_code: "export_incomplete" },
      decision_trace: ["collect_required_source_events", "detect_missing_events", "fail_incomplete_export"],
    }),
    consumeVector("keri-authority/034-export-aid-substituted-for-npub-rejected.json", {
      vector_id: "keri-authority/export-aid-substituted-for-npub-rejected",
      spec_refs: ["§11.8", "§14.3"],
      description: "A consumer that substitutes the derived export AID (or its did:webs DID) for the persona npub where the spec requires the npub is rejected: the export identity confers no identifier status and is never an alternate authoritative identity.",
      input: {
        required_identifier: "persona_npub",
        presented_identifier: "export_aid",
        context: "identity_resolution_requiring_npub",
      },
      expected_output: { verdict: "reject", reason_code: "export_aid_substituted_for_npub" },
      decision_trace: ["expect_persona_npub", "observe_export_aid_substitution", "reject_substitution"],
    }),
  ];
}
