import { consumeVector } from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector } from "./types.js";

// keri-authority/ behavioral vectors (ADR-032): the §4.5.1 accelerator
// decision-equivalence conditions, §4.5.2 provisional acceptance and
// convergence-gated withdrawal, the (pubkey,31001,d) conflict rule,
// §3.9.10.1 rollback resistance, and the "materialized refs are never
// verification authority" rule. Scenario state is encoded in input and the
// verdict in expected_output, following the light-node/ and identity-doc/ style.
export function buildKeriAuthorityBehavioralVectors(fixtures: Fixtures): AuthoredVector[] {
  const alice = fixtures.personas.alice;
  const epoch = alice.epoch_keys.epoch_1;
  const head = fixtures.kel.alice.head;
  const nid1 = fixtures.ed25519_nids.alice_device_1;
  const T = fixtures.test_epoch;

  return [
    consumeVector("keri-authority/014-accelerator-decision-equivalent.json", {
      vector_id: "keri-authority/accelerator-decision-equivalent",
      spec_refs: ["§4.5.1", "§3.5.3", "§14.3"],
      description: "The §4.5.1 accelerator accepts when all of (a)-(d) hold: the referenced head is on the accepted KEL, created_at is inside its authority window, no later event retroactively invalidates the signing key, and no pending KEL refresh exists. The result is decision-equivalent to a full §3.5.3 replay.",
      input: {
        signing_epoch_key: epoch.pubkey,
        kel_head: { id: head.id, seq: 0 },
        condition_a_referenced_event_on_accepted_kel: true,
        condition_b_created_at_in_authority_window: true,
        condition_c_no_retroactive_compromise: true,
        condition_d_no_pending_refresh: true,
      },
      expected_output: {
        verdict: "accept",
        normalized: { path: "accelerator", decision_equivalent_to_replay: true },
      },
      decision_trace: ["check_referenced_on_kel_a", "check_authority_window_b", "check_no_retroactive_compromise_c", "check_no_pending_refresh_d", "accelerator_accept"],
    }),
    consumeVector("keri-authority/015-accelerator-backdated-compromise.json", {
      vector_id: "keri-authority/accelerator-backdated-compromise",
      spec_refs: ["§3.5.2", "§4.5.1", "§14.3"],
      description: "A backdated event signed by a superseded epoch key is caught by effective_compromise_since. With compromise_since=T+200 and rotation created_at=T+500, effective_compromise_since=min(200,500)=T+200; the -300s skew makes the key non-authoritative for any created_at >= T-100, so the event at T+100 is rejected under both replay and the accelerator.",
      input: {
        signing_epoch_key: epoch.pubkey,
        event_created_at: T + 100,
        compromise_declaration: { compromise_since: T + 200, rotation_created_at: T + 500 },
        skew_seconds: 300,
      },
      expected_output: {
        verdict: "reject",
        reason_code: "signing_key_compromised_at_created_at",
        normalized: { effective_compromise_since: T + 200, non_authoritative_cutoff: T - 100 },
      },
      decision_trace: ["accept_compromise_rotation", "compute_effective_compromise_since", "apply_300s_skew", "created_at_at_or_after_cutoff", "reject"],
    }),
    consumeVector("keri-authority/016-refresh-failed-not-condition-d.json", {
      vector_id: "keri-authority/refresh-failed-not-condition-d",
      spec_refs: ["§4.5.1", "§4.5.2", "§14.3"],
      description: "A kel_head seq ahead of the verifier's accepted head triggers a KEL refresh that FAILS. An attempted-but-failed refresh does not satisfy condition (d), so the accelerator MUST NOT be used; under provisional-accept the event is held provisional and MUST NOT be reported final.",
      input: {
        kel_head_seq: 1,
        verifier_accepted_head_seq: 0,
        refresh_attempted: true,
        refresh_succeeded: false,
        policy: "provisional-accept",
      },
      expected_output: {
        verdict: "accept_provisional",
        normalized: { accelerator_used: false, condition_d_satisfied: false, report_final: false },
        warnings: ["provisional_not_final"],
      },
      decision_trace: ["kel_head_ahead_of_accepted", "attempt_refresh", "refresh_failed", "condition_d_unsatisfied", "hold_provisional"],
    }),
    consumeVector("keri-authority/017-provisional-not-hardened-repo-unreachable.json", {
      vector_id: "keri-authority/provisional-not-hardened-repo-unreachable",
      spec_refs: ["§4.5.2", "§3.7", "§14.3"],
      description: "A relay-only key-material event under provisional-accept never hardens to final while the repo is unreachable; a light node without repo access operates in permanently reduced-assurance provisional mode.",
      input: {
        key_material_event: { kind: 31003, s: 1, seen_on: ["nostr_relay"] },
        repo_reachable: false,
        policy: "provisional-accept",
        node_role: "light",
      },
      expected_output: {
        verdict: "accept_provisional",
        normalized: { hardened: false, reason: "repo_unreachable", reduced_assurance: true },
        warnings: ["provisional_not_final"],
      },
      decision_trace: ["classify_key_material", "seen_relay_only", "repo_unreachable", "cannot_harden", "remain_provisional"],
    }),
    consumeVector("keri-authority/018-withdrawal-causally-behind-no-withdraw.json", {
      vector_id: "keri-authority/withdrawal-causally-behind-no-withdraw",
      spec_refs: ["§4.5.2", "§14.3"],
      description: "Convergence-gated withdrawal: a provisional KEL event at seq 2 is not withdrawn when the reachable repo-carried head is only at seq 1. A reachable but causally behind replica leaves provisional status unchanged (absence is not convergence).",
      input: {
        provisional_kel_event_seq: 2,
        repo_carried_head_seq: 1,
        repo_reachable: true,
        event_present_in_repo: false,
      },
      expected_output: {
        verdict: "accept_provisional",
        normalized: { withdrawn: false, convergence_reached: false, reason: "repo_causally_behind" },
      },
      decision_trace: ["provisional_event_seq_2", "repo_head_seq_1", "seq_below_event_seq", "not_converged", "no_withdrawal"],
    }),
    consumeVector("keri-authority/019-withdrawal-converged-head.json", {
      vector_id: "keri-authority/withdrawal-converged-head",
      spec_refs: ["§4.5.2", "§13", "§14.3"],
      description: "Convergence-gated withdrawal: a provisional KEL event at seq 2 is withdrawn once the verified repo-carried head reaches seq 3 (>= 2) and the event at seq 2 differs from the provisional one. The hash chain makes seq a true causality marker.",
      input: {
        provisional_kel_event_seq: 2,
        provisional_event_id: "aa".repeat(32),
        repo_carried_head_seq: 3,
        repo_event_at_seq_2_id: "bb".repeat(32),
      },
      expected_output: {
        verdict: "reject",
        reason_code: "withdrawn_on_reconcile",
        normalized: { convergence_reached: true, repo_event_differs: true, flagged_per_section_13: true },
      },
      decision_trace: ["provisional_event_seq_2", "repo_head_seq_3_ge_2", "event_at_seq_differs", "convergence_gate_satisfied", "withdraw_acceptance"],
    }),
    consumeVector("keri-authority/020-delegation-conflict-repo-wins.json", {
      vector_id: "keri-authority/delegation-conflict-repo-wins",
      spec_refs: ["§3.9.10.1", "§4.5.2", "§14.3"],
      description: "Two kind:31001 delegations occupy the same replaceable address (pubkey, 31001, d). The repo-carried copy is canonical for acceptance; the relay-only conflicting copy stays provisional and MUST NOT displace it.",
      input: {
        replaceable_address: { pubkey: epoch.pubkey, kind: 31001, d: `nid:${nid1.did_key}` },
        repo_carried: { event_id: "aa".repeat(32), valid_until: T + 7200 },
        relay_only: { event_id: "bb".repeat(32), valid_until: T + 3600 },
      },
      expected_output: {
        verdict: "accept",
        normalized: { canonical: "repo_carried", canonical_event_id: "aa".repeat(32), relay_only_status: "provisional" },
      },
      decision_trace: ["collect_conflicting_31001_at_address", "identify_repo_carried", "repo_carried_wins", "mark_relay_only_provisional"],
    }),
    consumeVector("keri-authority/021-dependent-events-unresolved.json", {
      vector_id: "keri-authority/dependent-events-unresolved",
      spec_refs: ["§4.5.2", "§13", "§14.3"],
      description: "When a key-material acceptance is withdrawn (per §4.5.2), the verifier withdraws the acceptance signal, flags per §13, and marks dependent events (posts verified under that key state) unresolved until reverified.",
      input: {
        withdrawn_key_material: { kind: 31003, seq: 2, event_id: "aa".repeat(32) },
        dependent_events: [
          { event_id: "cc".repeat(32), kind: 1 },
          { event_id: "dd".repeat(32), kind: 31007 },
        ],
      },
      expected_output: {
        verdict: "reject",
        reason_code: "withdrawn_on_reconcile",
        normalized: {
          dependent_events_marked_unresolved: ["cc".repeat(32), "dd".repeat(32)],
          dependents_status: "unresolved_until_reverified",
        },
      },
      decision_trace: ["withdraw_key_material", "identify_dependent_events", "mark_dependents_unresolved", "await_reverification"],
    }),
    consumeVector("keri-authority/022-repo-head-regression-rejected.json", {
      vector_id: "keri-authority/repo-head-regression-rejected",
      spec_refs: ["§3.9.10.1", "§14.3"],
      description: "A repo presenting a key-material head that regresses below a previously finalized canonical head, with no authenticated re-anchor, is rejected: key state must never silently regress.",
      input: {
        previously_finalized_head_seq: 5,
        presented_repo_head_seq: 3,
        authenticated_reanchor: false,
      },
      expected_output: {
        verdict: "reject",
        reason_code: "repo_head_regression",
        normalized: { regressed_from_seq: 5, presented_seq: 3, reanchor_present: false },
      },
      decision_trace: ["load_finalized_canonical_head", "observe_presented_head", "no_authenticated_reanchor", "reject_regression"],
    }),
    consumeVector("keri-authority/023-materialized-refs-not-authority.json", {
      vector_id: "keri-authority/materialized-refs-not-authority",
      spec_refs: ["§4.5.1", "§10.1.2", "§14.3"],
      description: "The refs/xyz.heterodyne.keri/state ref is derived, never authoritative: it MUST NOT establish acceptance. The verifier replays the accepted KEL and only populates its cache from the ref after independently matching it to that replay.",
      input: {
        presented_ref: "refs/xyz.heterodyne.keri/state",
        claim: "verification_authority",
        accepted_kel_events_available: true,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          materialized_ref_as_authority: false,
          authority_source: "replayed_accepted_kel",
          refs_used_as: "cache_after_independent_match",
        },
      },
      decision_trace: ["receive_state_ref_claim", "reject_ref_as_authority", "replay_accepted_kel", "populate_cache_only_after_match"],
    }),
  ];
}
