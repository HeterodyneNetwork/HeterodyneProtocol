import { withKelHead } from "./kel.js";
import { canonicalNip01, getPublicKey, signEvent } from "./nostr.js";
import { buildKeriAuthorityWireVectors } from "./topics-keri-authority.js";
import { buildKeriAuthorityBehavioralVectors } from "./topics-keri-authority-b.js";
import { buildKeriAuthorityMaterializedVectors } from "./topics-keri-authority-c.js";
import { buildV04Vectors } from "./topics-v04.js";
import { buildV04bVectors } from "./topics-v04b.js";
import { buildSplitVectors } from "./topics-split.js";
import { buildClaimVectors } from "./topics-claims.js";
import { buildClaimLedgerVectors } from "./topics-claim-ledger.js";
import { buildOidcVectors, buildTokenStatusVectors } from "./topics-oidc.js";
import { buildRoleCapabilityVectors } from "./topics-role-capabilities.js";
import { buildPublicReaderVectors } from "./topics-public-reader.js";
import { buildAgentAuthorshipVectors } from "./topics-agent-authorship.js";
import { buildControlVectors } from "./topics-control.js";
import { buildAgentModerationVectors } from "./topics-agent-moderation.js";
import { buildCredentialContinuityVectors } from "./topics-credential-continuity.js";
import { buildMarmotRadicleVectors } from "./topics-marmot-radicle.js";
import { buildMarmotAdmissionVectors } from "./topics-marmot-admission.js";
import { buildOneTimeInviteVectors } from "./topics-one-time-invite.js";
import { buildFollowUpHardeningVectors } from "./topics-follow-up-hardening.js";
import { buildWorkspaceVectors } from "./topics-workspace.js";
import {
  AUX_RAND,
  baseVector,
  consume,
  produceVector,
  withoutSig,
  type VectorFactory,
  type VectorBody,
} from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { Vector, AuthoredVector } from "./types.js";

export const TOPIC_SPECS = {
  identity: "§3",
  keri: "§3.5",
  verification: "§4.5",
  index: "§6.7",
  outbox: "§7",
  moderation: "§8",
  "relay-interop": "§10.5",
  transport: "§7.7",
  "social-recovery": "§3.12",
  "relay-profile": "§10.6",
  interop: "§11",
  versioning: "§12",
  "repo-relay": "§10.1.2",
  "routing-node": "§7.0",
  "node-advert": "§7.0",
  "light-node": "§7.3",
  "nid-binding": "§3.3.1",
  "identity-doc": "§3.9.10",
  org: "§6.7.0",
  "privacy-tiers": "§9.0",
  lists: "§8.5",
  "config-backup": "§3.8.6",
  "keri-authority": "§4.5.1",
  "core-redundancy": "heterodyne:0.5.0#core-multi-host-seeding",
  "acceptance-gating": "heterodyne:0.5.0#comms-acceptance-hook",
  atproto: "heterodyne:0.5.0#social-atproto-resolution",
  "credential-continuity": "heterodyne:0.5.0#comms-credential-continuity",
  stamping: "heterodyne:0.5.0#core-version-stamps",
  registry: "heterodyne:0.5.0#core-registry",
  "marmot-radicle": "heterodyne:0.5.0#comms-marmot",
  "workspace-object": "heterodyne:0.5.0#workspace-object-types",
  "workspace-policy": "heterodyne:0.5.0#workspace-role-policy",
  "workspace-grant": "heterodyne:0.5.0#workspace-grants",
  "workspace-relationship": "heterodyne:0.5.0#workspace-relationships",
  "workspace-privacy": "heterodyne:0.5.0#workspace-privacy",
  "workspace-host": "heterodyne:0.5.0#workspace-advertisements",
  "workspace-device": "heterodyne:0.5.0#workspace-role-control",
  "workspace-key": "heterodyne:0.5.0#workspace-key-delivery",
  "workspace-freshness": "heterodyne:0.5.0#workspace-freshness",
  "workspace-joint": "heterodyne:0.5.0#workspace-relationships",
  "workspace-events": "heterodyne:0.5.0#workspace-role-repositories",
} as const;

export async function buildAllVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const vectors: AuthoredVector[] = [];
  for (const factory of VECTOR_FACTORIES) {
    vectors.push(await factory(fixtures));
  }
  vectors.push(...(await buildV04Vectors(fixtures)));
  vectors.push(...(await buildV04bVectors(fixtures)));
  vectors.push(...(await buildKeriAuthorityWireVectors(fixtures)));
  vectors.push(...buildKeriAuthorityBehavioralVectors(fixtures));
  vectors.push(...(await buildKeriAuthorityMaterializedVectors(fixtures)));
  vectors.push(...(await buildSplitVectors(fixtures)));
  vectors.push(...(await buildClaimVectors(fixtures)));
  vectors.push(...(await buildClaimLedgerVectors(fixtures)));
  vectors.push(...(await buildOidcVectors(fixtures)));
  vectors.push(...(await buildTokenStatusVectors(fixtures)));
  vectors.push(...buildRoleCapabilityVectors());
  vectors.push(...buildPublicReaderVectors());
  vectors.push(...(await buildAgentAuthorshipVectors(fixtures)));
  vectors.push(...buildControlVectors());
  vectors.push(...(await buildAgentModerationVectors()));
  vectors.push(...buildCredentialContinuityVectors());
  vectors.push(...(await buildMarmotRadicleVectors(fixtures)));
  vectors.push(...buildMarmotAdmissionVectors());
  vectors.push(...buildOneTimeInviteVectors());
  vectors.push(...buildFollowUpHardeningVectors(fixtures));
  vectors.push(...buildWorkspaceVectors());
  return vectors;
}

const VECTOR_FACTORIES: VectorFactory[] = [
  async (fixtures) => {
    const persona = fixtures.personas.alice;
    const rootEvent = await signEvent({
      secretKey: persona.epoch_keys.epoch_1.private_key,
      created_at: fixtures.test_epoch,
      kind: 31000,
      tags: [
        ...withKelHead(
          [
            ["d", ""],
            ["heterodyne", "root"],
            ["cold_root", persona.cold_root.pubkey],
          ],
          fixtures.kel.alice.head,
        ),
        ["spec_version", "heterodyne/0.5.0"],
      ],
      content: "",
      auxRand: AUX_RAND,
    });
    return {
      relativePath: "identity/001-root-attestation-valid.json",
      vector: produceVector({
        vector_id: "identity/root-attestation-valid",
        spec_refs: ["§3.2.1", "§14.1", "§14.5"],
        description: "Root attestation: kind:31000 signed by the current epoch key, cold_root tag binds the npub.",
        input: {
          fixture_persona: "alice",
          signer: "epoch_1",
          aux_rand: AUX_RAND,
          event_template: withoutSig(rootEvent),
        },
        expected_output: {
          canonical_wire: canonicalNip01(rootEvent),
          decoded: { event: rootEvent },
          id: rootEvent.id,
          sig: rootEvent.sig,
        },
        notes: "Per §3.2.1 the root attestation is epoch-key-signed (the cold root is never brought online for it).",
      }),
    };
  },
  consume("keri/001-informal-vouch-not-counted.json", {
    vector_id: "keri/informal-vouch-not-counted",
    spec_refs: ["§3.5", "§3.12", "§14.3"],
    description: "A rotation that reaches threshold only by counting kind:31008 informal vouches is rejected.",
    input: {
      evidence_classification: "non-wire-behavioral-scenario",
      kel: [
        { type: "inception", sequence: 0, witness_threshold: 2, witnesses: ["did:key:z6Mkp1", "did:key:z6Mkp2"] },
        { type: "rotation", sequence: 1, witness_receipts: ["did:key:z6Mkp1"], informal_vouches: ["kind:31008:z6Mkp2"] },
      ],
    },
    expected_output: {
      verdict: "reject",
      reason_code: "informal_vouch_not_counted",
    },
  }),
  consume("verification/001-bad-signature-rejects.json", {
    vector_id: "verification/bad-signature-rejects",
    spec_refs: ["§4.5", "§14.2"],
    description: "A Nostr event with a mismatched signature is rejected before delegation checks.",
    input: {
      event: {
        id: "00".repeat(32),
        pubkey: "11".repeat(32),
        created_at: 1767225600,
        kind: 1,
        tags: [],
        content: "tampered",
        sig: "22".repeat(64),
      },
    },
    expected_output: {
      verdict: "reject",
      reason_code: "bad_signature",
    },
    decision_trace: ["validate_nip01_id", "verify_bip340_signature"],
  }),
  consume("outbox/001-scoped-outbox.json", {
    vector_id: "outbox/scoped-outbox",
    spec_refs: ["§7", "§14.3"],
    description: "Scoped outbox returns relays for the requested category without leaking private room descriptors.",
    input: {
      outbox: {
        public_relays: ["wss://relay.example.org"],
        scoped: { articles: ["wss://articles.example.org"] },
        private_descriptors: [{ d: "opaque-private-feed" }],
      },
      request_scope: "articles",
    },
    expected_output: {
      verdict: "accept",
      normalized: { relays: ["wss://articles.example.org"], private_descriptor_count: 0 },
    },
  }),
  consume("moderation/001-contributor-implicit-rejection-window.json", {
    vector_id: "moderation/contributor-implicit-rejection-window",
    spec_refs: ["§8", "§14.3"],
    description: "A contributor submission remains pending until the seven-day implicit-rejection window elapses.",
    input: {
      submitted_at: 1767225600,
      simulated_clock: 1767830400,
      approval_events: [],
      implicit_rejection_seconds: 604800,
    },
    expected_output: {
      verdict: "accept",
      normalized: {
        moderation_state: "implicitly-rejected",
        outcome: {
          class: "moderation-approval-window-expired",
          candidate_id: "candidate-fixture",
          community_id: "34550:community:fixture",
          attempted_at: 1767225600,
          deadline_at: 1767830400,
          last_attempt_at: 1767826800,
          retry_state: "terminal",
          terminal_cause: "approval-window-expired",
          allowed_actions: ["abandon", "edited-republication", "unchanged-republication"],
        },
      },
    },
    simulated_clock: 1767830400,
  }),
  consume("moderation/strict-mode/001-invalid-event-signature.json", {
    vector_id: "moderation/strict-mode-invalid-event-signature",
    spec_refs: ["§11.7", "§14.3", "§14.5"],
    description: "Strict mode rejects an invalid signed Social event that base mode may retain only as explicitly invalid external content.",
    input: {
      same_input_id: "invalid-signed-social-event-fixture",
      mode: "strict",
    },
    expected_output: {
      verdict: "reject",
      reason_code: "bad_signature",
    },
    notes: "Base-mode companion outcome is warnings:[\"invalid_event_signature\"] for the same external input.",
  }),
  async (fixtures) => {
    const epoch = fixtures.personas.alice.epoch_keys.epoch_1;
    const auth = await signEvent({
      secretKey: epoch.private_key,
      created_at: fixtures.test_epoch + 20,
      kind: 22242,
      tags: [
        ["relay", "wss://relay.example.org"],
        ["challenge", "auth-challenge-001"],
      ],
      content: "",
      auxRand: AUX_RAND,
    });
    return {
      relativePath: "relay-interop/001-nip42-auth-current-epoch-key.json",
      vector: produceVector({
        vector_id: "relay-interop/nip42-auth-current-epoch-key",
        spec_refs: ["§10.5", "§3.5", "§14.3"],
        description: "NIP-42 AUTH response is signed by the current epoch key, not the cold root.",
        input: {
          challenge: "auth-challenge-001",
          relay: "wss://relay.example.org",
          fixture_persona: "alice",
          signer: "epoch_1",
          aux_rand: AUX_RAND,
        },
        expected_output: {
          canonical_wire: canonicalNip01(auth),
          decoded: { event: auth },
          id: auth.id,
          sig: auth.sig,
        },
      }),
    };
  },
  consume("transport/001-onion-no-clearnet-dns-leak.json", {
    vector_id: "transport/onion-no-clearnet-dns-leak",
    spec_refs: ["§7.7", "§14.3"],
    description: ".onion relay discovery must not send the host to a clearnet resolver.",
    input: {
      target: "wss://examplehiddenservice.onion",
      resolver_calls: [{ resolver: "system_dns", host: "examplehiddenservice.onion" }],
    },
    expected_output: {
      verdict: "reject",
      reason_code: "onion_dns_leak",
    },
  }),
  consume("transport/strict-mode/001-egress-tor-default-on.json", {
    vector_id: "transport/strict-mode-egress-tor-default-on",
    spec_refs: ["§7.7", "§11.7", "§14.3"],
    description: "Strict mode rejects startup with Tor egress disabled unless the user explicitly disabled it.",
    input: {
      mode: "strict",
      egress_over_tor: false,
      user_explicitly_disabled: false,
    },
    expected_output: {
      verdict: "reject",
      reason_code: "strict_mode_tor_disabled",
    },
  }),
  consume("relay-profile/001-vanilla-nip01-unaffected.json", {
    vector_id: "relay-profile/vanilla-nip01-unaffected",
    spec_refs: ["§10.6", "§14.3"],
    description: "Heterodyne-aware relay profile must not mutate vanilla NIP-01 read/write behavior.",
    input: {
      relay_profile_enabled: true,
      vanilla_nip01_event_before: { id: "bb".repeat(32), content: "hello" },
      vanilla_nip01_event_after: { id: "bb".repeat(32), content: "hello" },
    },
    expected_output: {
      verdict: "accept",
      normalized: { vanilla_nip01_unaffected: true },
    },
  }),
  consume("versioning/001-unknown-major-placeholder.json", {
    vector_id: "versioning/unknown-major-placeholder",
    spec_refs: ["§12", "§14.3"],
    description: "Future incompatible major versions render as placeholders rather than being misinterpreted.",
    input: {
      receiver_supported_major: 0,
      sender_version: "1.0.0",
      event_kind: 31007,
    },
    expected_output: {
      verdict: "reject",
      reason_code: "unknown_major_version",
      normalized: { placeholder_required: true },
    },
  }),
];

type ConsumeCase = {
  relativePath: string;
  vector: VectorBody;
};

const ADDITIONAL_COVERAGE_CASES: ConsumeCase[] = [
  {
    relativePath: "identity/005-revocation-post-window.json",
    vector: {
      vector_id: "identity/revocation-post-window",
      spec_refs: ["§3.3", "§4.5", "§14.3"],
      description: "Post-revocation events are rejected after the revocation window.",
      input: { revoked_at: 1767225600, event_created_at: 1767225901, revocation_grace_seconds: 300 },
      expected_output: { verdict: "reject", reason_code: "revoked_key_post_revoked_at" },
      simulated_clock: 1767226000,
    },
  },
  {
    relativePath: "identity/006-identity-room-full-state.json",
    vector: {
      vector_id: "identity/identity-room-full-state",
      spec_refs: ["§3", "§14.3"],
      description: "Identity room full state exposes root, delegation, KERI, and pointer facts.",
      input: { room_id: "!alice-identity:example.org", state_types: ["root", "delegation", "kel", "pointer"] },
      expected_output: { verdict: "accept", normalized: { complete_identity_state: true } },
    },
  },
  {
    relativePath: "keri/002-inception-event.json",
    vector: {
      vector_id: "keri/inception-event",
      spec_refs: ["§3.5", "§14.3"],
      description: "KERI inception establishes sequence 0 and the initial witness threshold.",
      input: { evidence_classification: "non-wire-behavioral-scenario", event_type: "inception", sequence: 0, witness_threshold: 1, witnesses: ["did:key:z6Mkwitness"] },
      expected_output: { verdict: "accept", normalized: { kel_sequence: 0, witness_threshold: 1 } },
    },
  },
  {
    relativePath: "keri/003-rotation-committed-strategy.json",
    vector: {
      vector_id: "keri/rotation-committed-strategy",
      spec_refs: ["§3.5", "§14.3"],
      description: "Committed-strategy rotation is accepted when it advances sequence and satisfies witnesses.",
      input: { evidence_classification: "non-wire-behavioral-scenario", event_type: "rotation", sequence: 1, strategy: "committed", witness_receipts: 2, threshold: 2 },
      expected_output: { verdict: "accept", normalized: { current_epoch_sequence: 1 } },
    },
  },
  {
    relativePath: "keri/004-rotation-none-witness-threshold.json",
    vector: {
      vector_id: "keri/rotation-none-witness-threshold",
      spec_refs: ["§3.5", "§14.3"],
      description: "None-strategy rotation is accepted only with the configured witness threshold.",
      input: { evidence_classification: "non-wire-behavioral-scenario", event_type: "rotation", sequence: 1, strategy: "none", witness_receipts: 3, threshold: 3 },
      expected_output: { verdict: "accept", normalized: { witness_threshold_satisfied: true } },
    },
  },
  {
    relativePath: "keri/005-first-seen-ordering.json",
    vector: {
      vector_id: "keri/first-seen-ordering",
      spec_refs: ["§3.5", "§14.3"],
      description: "First-seen ordering picks the rotation first observed by each witness.",
      input: { evidence_classification: "non-wire-behavioral-scenario", witness_observations: [{ witness: "w1", first_seen: "rotation-a" }, { witness: "w2", first_seen: "rotation-a" }] },
      expected_output: { verdict: "accept", normalized: { accepted_rotation: "rotation-a" } },
    },
  },
  {
    relativePath: "keri/006-fork-resolution-conflicting-rotations.json",
    vector: {
      vector_id: "keri/fork-resolution-conflicting-rotations",
      spec_refs: ["§3.5", "§14.3"],
      description: "Conflicting rotations resolve according to witness first-seen evidence.",
      input: { evidence_classification: "non-wire-behavioral-scenario", rotations: ["rotation-a", "rotation-b"], first_seen_winner: "rotation-b" },
      expected_output: { verdict: "accept", normalized: { accepted_rotation: "rotation-b", rejected_rotation: "rotation-a" } },
    },
  },
  {
    relativePath: "keri/007-didkey-witness-no-network.json",
    vector: {
      vector_id: "keri/didkey-witness-no-network",
      spec_refs: ["§3.5", "§14.3"],
      description: "did:key witness verification uses the embedded key and performs no network resolution.",
      input: { evidence_classification: "non-wire-behavioral-scenario", witness: "did:key:z6Mkwitness", network_resolution_attempts: 0 },
      expected_output: { verdict: "accept", normalized: { didkey_verified_locally: true } },
    },
  },
  {
    relativePath: "verification/003-revoked-key-rejects.json",
    vector: {
      vector_id: "verification/revoked-key-rejects",
      spec_refs: ["§4.5", "§14.3"],
      description: "Events created after epoch-key revocation are rejected.",
      input: { revoked_at: 1767225600, event_created_at: 1767225700 },
      expected_output: { verdict: "reject", reason_code: "revoked_key_post_revoked_at" },
    },
  },
  {
    relativePath: "verification/004-backdated-event-suspicion-window.json",
    vector: {
      vector_id: "verification/backdated-event-suspicion-window",
      spec_refs: ["§4.5", "§14.3"],
      description: "Backdated event inside the suspicion window is accepted with a warning.",
      input: { event_created_at: 1767225000, received_at: 1767225600, suspicion_window_seconds: 900 },
      expected_output: { verdict: "accept", normalized: { backdated: true }, warnings: ["backdated_event_suspicion_window"] },
      simulated_clock: 1767225600,
    },
  },
  {
    relativePath: "index/002-prev-page-hash.json",
    vector: {
      vector_id: "index/prev-page-hash",
      spec_refs: ["§6.7", "§14.3"],
      description: "prev_page_hash links each feed-index page to the canonical bytes of the previous page.",
      input: { page: 2, prev_page_hash: "12".repeat(32), previous_page_canonical_hash: "12".repeat(32) },
      expected_output: { verdict: "accept", normalized: { page_chain_valid: true } },
    },
  },
  {
    relativePath: "index/003-complete-fetch-attempt.json",
    vector: {
      vector_id: "index/complete-fetch-attempt",
      spec_refs: ["§6.7", "§14.3"],
      description: "A complete fetch attempt queries the full configured relay set before declaring a page missing.",
      input: { relay_set: ["wss://a", "wss://b"], queried_relays: ["wss://a", "wss://b"] },
      expected_output: { verdict: "accept", normalized: { complete_fetch_attempt: true } },
    },
  },
  {
    relativePath: "index/004-missing-predecessor-structured-outcome.json",
    vector: {
      vector_id: "index/missing-predecessor-structured-outcome",
      spec_refs: ["heterodyne:0.5.0#comms-feed-paging"],
      description: "An unresolved predecessor produces a structured localizable outcome with durable retry state.",
      input: {
        referring_page: {
          event_id: "ab".repeat(32),
          created_at: 1767225600,
          d: "feed:page-2",
        },
        missing_predecessor_event_id: "cd".repeat(32),
        attempted_at: 1767225610,
        deadline_at: 1767225640,
        last_attempt_at: 1767225640,
        retry_state: "retrying",
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          outcome_class: "missing-predecessor",
          registered_reason_code: null,
          terminal_cause: null,
          allowed_actions: ["retry", "continue-incomplete"],
          localizable: true,
        },
      },
    },
  },
  {
    relativePath: "privacy-tiers/015-tier3-membership-metadata-disclosed.json",
    vector: {
      vector_id: "privacy-tiers/tier3-membership-metadata-disclosed",
      spec_refs: ["heterodyne:0.5.0#comms-privacy-tiers"],
      description: "Tier 3 protects content but discloses recipient, roster, generation-linkage, timing, and volume metadata.",
      input: {
        tier: 3,
        pre_use_disclosure_presented: true,
        observed_distribution_graph: ["kind:31011", "kind:31012"],
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          content_confidentiality: true,
          membership_private: false,
          residual_metadata: [
            "recipient-tags",
            "roster-events",
            "key-id-linkage",
            "timing",
            "volume",
          ],
        },
      },
    },
  },
  {
    relativePath: "discussion/001-reaction-reply-bare-not-indexed.json",
    vector: {
      vector_id: "discussion/reaction-reply-bare-not-indexed",
      spec_refs: ["heterodyne:0.5.0#social-discussion-rooms"],
      description: "Reaction/reply remains bare in-room and is not added to the relay feed index.",
      input: { event_kind: 7, relation: "reaction", candidate_for_index: true },
      expected_output: { verdict: "accept", normalized: { indexed: false, in_room_bare: true } },
    },
  },
  {
    relativePath: "outbox/002-full-public-outbox.json",
    vector: {
      vector_id: "outbox/full-public-outbox",
      spec_refs: ["§7", "§14.3"],
      description: "Full public outbox lists all public relay endpoints.",
      input: { relays: ["wss://relay-a", "wss://relay-b"], scope: "all_public" },
      expected_output: { verdict: "accept", normalized: { relay_count: 2 } },
    },
  },
  {
    relativePath: "outbox/003-transitive-discovery-walk.json",
    vector: {
      vector_id: "outbox/transitive-discovery-walk",
      spec_refs: ["§7", "§14.3"],
      description: "Transitive discovery walk follows declared relay hints without entering private descriptors.",
      input: { start: "alice", follows: ["bob"], private_descriptor_seen: true },
      expected_output: { verdict: "accept", normalized: { visited_personas: ["alice", "bob"], private_descriptor_followed: false } },
    },
  },
  {
    relativePath: "outbox/004-cross-persona-attestation-valid.json",
    vector: {
      vector_id: "outbox/cross-persona-attestation-valid",
      spec_refs: ["§7", "§14.3"],
      description: "A same_holder relationship requires an exact dual-authorized kind:31004 pair plus explicit post-warning confirmation.",
      input: {
        relation: "same_holder",
        left: { signer: "alice", other_npub: "alice-work", signature_valid: true },
        right: { signer: "alice-work", other_npub: "alice", signature_valid: true },
        cross_binding_exact: true,
        permanent_linkability_warning_presented: true,
        explicit_confirmation: true,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          cross_persona_attested: true,
          authorization: "dual",
          permanently_linkable: true,
          deletion_erases_prior_observations: false,
        },
      },
    },
  },
  {
    relativePath: "outbox/005-cross-persona-attestation-invalid.json",
    vector: {
      vector_id: "outbox/cross-persona-attestation-invalid",
      spec_refs: ["§7", "§14.3"],
      description: "A one-sided or unconfirmed cross-persona relationship is rejected.",
      input: {
        relation: "same_holder",
        left: { signer: "alice", other_npub: "alice-work", signature_valid: true },
        right: null,
        permanent_linkability_warning_presented: false,
        explicit_confirmation: false,
      },
      expected_output: { verdict: "reject", reason_code: "bad_signature" },
    },
  },
  {
    relativePath: "moderation/002-nip72-approval.json",
    vector: {
      vector_id: "moderation/nip72-approval",
      spec_refs: ["§8", "§14.3"],
      description: "NIP-72 approval event makes a candidate community post visible.",
      input: { candidate_id: "post-1", approvals: [{ moderator: "mod-a", valid: true }] },
      expected_output: { verdict: "accept", normalized: { moderation_state: "approved" } },
    },
  },
  {
    relativePath: "moderation/003-multi-mod-requirement.json",
    vector: {
      vector_id: "moderation/multi-mod-requirement",
      spec_refs: ["§8", "§14.3"],
      description: "Multi-moderator community requires the configured approval threshold.",
      input: { threshold: 2, approvals: ["mod-a", "mod-b"] },
      expected_output: { verdict: "accept", normalized: { threshold_satisfied: true } },
    },
  },
  {
    relativePath: "moderation/004-moderator-rotation-through-kel.json",
    vector: {
      vector_id: "moderation/moderator-rotation-through-kel",
      spec_refs: ["§8", "§14.3"],
      description: "Moderator rotation follows the moderator persona's KERI key event log.",
      input: { moderator: "mod-a", old_epoch: 1, new_epoch: 2, kel_rotation_valid: true },
      expected_output: { verdict: "accept", normalized: { active_moderator_epoch: 2 } },
    },
  },
  {
    relativePath: "moderation/005-redaction-of-approved-post.json",
    vector: {
      vector_id: "moderation/redaction-of-approved-post",
      spec_refs: ["§8", "§14.3"],
      description: "Redaction of an approved post makes it no longer visible in the moderated room view.",
      input: { approved: true, redacted: true },
      expected_output: { verdict: "accept", normalized: { visible: false } },
    },
  },
  {
    relativePath: "moderation/strict-mode/002-bare-not-hidden.json",
    vector: {
      vector_id: "moderation/strict-mode-bare-not-hidden",
      spec_refs: ["§11.7", "§14.3"],
      description: "Strict mode does not hide bare discussion messages solely because they are bare.",
      input: { mode: "strict", room_kind: "public_discussion", bare_message: true },
      expected_output: { verdict: "accept", normalized: { hidden: false } },
    },
  },
  {
    relativePath: "moderation/strict-mode/003-kind5-deletion-30s.json",
    vector: {
      vector_id: "moderation/strict-mode-kind5-deletion-30s",
      spec_refs: ["§11.7", "§14.3"],
      description: "Strict mode initiates kind:5 subscription or polling within 30 seconds and records retry availability separately from observation.",
      input: {
        deletion_kind: 5,
        source_activated_at: 1767225600,
        initiated_at: 1767225625,
        deadline_at: 1767225630,
        retry_state: "retrying-source-partitioned",
        observed: false,
        terminal_condition: null,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          monitoring_initiated_within_deadline: true,
          carrier_success_guaranteed: false,
        },
      },
    },
  },
  {
    relativePath: "moderation/strict-mode/004-state-downgrade-warning.json",
    vector: {
      vector_id: "moderation/strict-mode-state-downgrade-warning",
      spec_refs: ["§11.7", "§14.3"],
      description: "Strict mode renders a warning when state downgrades below strict requirements.",
      input: { state_downgrade_detected: true, mode: "strict" },
      expected_output: { verdict: "accept", normalized: { warning_rendered: true }, warnings: ["state_downgrade"] },
    },
  },
  {
    relativePath: "relay-interop/002-auth-rejection-permanent.json",
    vector: {
      vector_id: "relay-interop/auth-rejection-permanent",
      spec_refs: ["§6.4", "§10.5", "§14.3"],
      description: "Post-AUTH relay rejection is classified as permanent.",
      input: { auth_attempted: true, relay_notice: "restricted: policy" },
      expected_output: { verdict: "reject", reason_code: "auth_rejected_permanent" },
    },
  },
  {
    relativePath: "relay-interop/003-keri-rotation-auth-new-key.json",
    vector: {
      vector_id: "relay-interop/keri-rotation-auth-new-key",
      spec_refs: ["§3.5", "§10.5", "§14.3"],
      description: "After KERI rotation, AUTH events are signed under the new epoch key.",
      input: { old_epoch_pubkey: "old", new_epoch_pubkey: "new", auth_pubkey: "new" },
      expected_output: { verdict: "accept", normalized: { auth_signed_by_current_epoch: true } },
    },
  },
  {
    relativePath: "transport/002-onion-reachable-via-tor.json",
    vector: {
      vector_id: "transport/onion-reachable-via-tor",
      spec_refs: ["§7.7", "§14.3"],
      description: ".onion relay is reachable through embedded Tor.",
      input: { target: "wss://relayhidden.onion", tor_bootstrapped: true },
      expected_output: { verdict: "accept", normalized: { reached_via_tor: true } },
    },
  },
  {
    relativePath: "transport/003-wasm-bridge-no-bridge-indicator.json",
    vector: {
      vector_id: "transport/wasm-bridge-no-bridge-indicator",
      spec_refs: ["§7.7", "§14.3"],
      description: "Browser/WASM client surfaces no-bridge-available when no Tor WebSocket bridge exists.",
      input: { runtime: "browser-wasm", websocket_bridge_available: false },
      expected_output: { verdict: "accept", normalized: { no_bridge_indicator: true } },
    },
  },
  {
    relativePath: "transport/004-egress-tor-off-default-indicator.json",
    vector: {
      vector_id: "transport/egress-tor-off-default-indicator",
      spec_refs: ["§7.7", "§14.3"],
      description: "Base mode defaults egress-over-Tor off and shows active-state indicator when enabled.",
      input: { mode: "base", default_egress_over_tor: false, enabled_now: true },
      expected_output: { verdict: "accept", normalized: { active_state_indicator: true } },
    },
  },
  {
    relativePath: "social-recovery/002-three-tier-caching.json",
    vector: {
      vector_id: "social-recovery/three-tier-caching",
      spec_refs: ["§3.12", "§14.3"],
      description: "Follower MAY, mutual SHOULD, and witness MUST cache identity-room state.",
      input: { relationships: ["follower", "mutual", "witness"] },
      expected_output: { verdict: "accept", normalized: { cache_policy: { follower: "may", mutual: "should", witness: "must" } } },
    },
  },
  {
    relativePath: "social-recovery/003-retention-30-days.json",
    vector: {
      vector_id: "social-recovery/retention-30-days",
      spec_refs: ["§3.12", "§14.3"],
      description: "Friend-cache retention keeps cache-sourced state for 30 days.",
      input: { retained_days: 30 },
      expected_output: { verdict: "accept", normalized: { retention_days: 30 } },
    },
  },
  {
    relativePath: "social-recovery/004-cold-root-reanchor-authoritative.json",
    vector: {
      vector_id: "social-recovery/cold-root-reanchor-authoritative",
      spec_refs: ["§3.12", "§14.3"],
      description: "An uncompromised available cold root authoritatively re-anchors after serving-infrastructure loss, but does not recover cold-root compromise.",
      input: {
        recovery_cause: "infrastructure-loss",
        cold_root_available: true,
        cold_root_compromised: false,
        cold_root_pointer: "!new:example.org",
        cache_pointer: "!old:example.org",
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          authoritative_pointer: "!new:example.org",
          recovery_scope: "infrastructure-loss",
          cold_root_compromise_recovered: false,
        },
      },
    },
  },
  {
    relativePath: "social-recovery/005-cache-sourced-marked-stale.json",
    vector: {
      vector_id: "social-recovery/cache-sourced-marked-stale",
      spec_refs: ["§3.12", "§14.3"],
      description: "Cache-sourced identity-room state is marked stale.",
      input: { source: "friend_cache", live_room_reachable: false },
      expected_output: { verdict: "accept", normalized: { stale: true } },
    },
  },
  {
    relativePath: "relay-profile/002-nip11-capability-advert.json",
    vector: {
      vector_id: "relay-profile/nip11-capability-advert",
      spec_refs: ["§10.6", "§14.3"],
      description: "Heterodyne-aware relay advertises capabilities through NIP-11.",
      input: { nip11: { supported_nips: [1, 11], heterodyne: { kel_reputation: true } } },
      expected_output: { verdict: "accept", normalized: { heterodyne_capability_advertised: true } },
    },
  },
  {
    relativePath: "relay-profile/003-kel-aware-reputation-continuity.json",
    vector: {
      vector_id: "relay-profile/kel-aware-reputation-continuity",
      spec_refs: ["§10.6", "§14.3"],
      description: "KEL-aware relay preserves reputation continuity across epoch rotation.",
      input: { old_epoch_reputation: 10, new_epoch_reputation: 10, kel_rotation_valid: true },
      expected_output: { verdict: "accept", normalized: { reputation_continues: true } },
    },
  },
  {
    relativePath: "relay-profile/004-passive-witness-store-signs-nothing.json",
    vector: {
      vector_id: "relay-profile/passive-witness-store-signs-nothing",
      spec_refs: ["§10.6", "§14.3"],
      description: "Passive witness-receipt store stores receipts but signs no Heterodyne state.",
      input: { stored_receipts: 3, signatures_emitted: 0 },
      expected_output: { verdict: "accept", normalized: { passive_store: true } },
    },
  },
  {
    relativePath: "interop/003-vanilla-nostr-only-follow.json",
    vector: {
      vector_id: "interop/vanilla-nostr-only-follow",
      spec_refs: ["§11", "§14.3"],
      description: "A valid vanilla Nostr author is a first-class manual follow target through NIP-65, with external-identity and reduced-assurance DM presentation.",
      input: {
        author_pubkey: getPublicKey("04".padStart(64, "0")),
        nip01_signature_valid: true,
        nip65_write_relays: ["wss://relay.example"],
        follow_change_requested_by_user: true,
        breadcrumb_claimed_successor: null,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          follow_target: "vanilla-nostr-author",
          authority: "nip01-signature-only",
          presentation: "external-reduced-assurance",
          subscription_source: "nip65",
          dm_fallback: "nip17-reduced-assurance",
          automatic_refollow: false,
        },
      },
    },
  },
  {
    relativePath: "versioning/002-older-receiver-newer-sender.json",
    vector: {
      vector_id: "versioning/older-receiver-newer-sender",
      spec_refs: ["§12", "§14.3"],
      description: "Older receiver tolerates a newer compatible 0.x sender with unknown optional fields.",
      input: { receiver_version: "0.3.0", sender_version: "0.4.0", unknown_optional_fields: ["x-new"] },
      expected_output: { verdict: "accept", normalized: { ignored_unknown_optional_fields: ["x-new"] } },
    },
  },
  {
    relativePath: "versioning/003-capabilities-roundtrip.json",
    vector: {
      vector_id: "versioning/capabilities-roundtrip",
      spec_refs: ["§12", "§14.3"],
      description: "Capabilities event round-trips supported feature flags.",
      input: { capabilities: ["baseline", "tor", "strict-mode"] },
      expected_output: { verdict: "accept", normalized: { capabilities: ["baseline", "tor", "strict-mode"] } },
    },
  },
  {
    relativePath: "versioning/004-unknown-room-kind-tolerance.json",
    vector: {
      vector_id: "versioning/unknown-room-kind-tolerance",
      spec_refs: ["§12", "§14.3"],
      description: "Unknown room kind from a compatible sender is tolerated with placeholder rendering.",
      input: { room_kind: "future_kind", sender_version: "0.4.0" },
      expected_output: { verdict: "accept", normalized: { placeholder_required: true } },
    },
  },
];

VECTOR_FACTORIES.push(...ADDITIONAL_COVERAGE_CASES.map((testCase) => consume(testCase.relativePath, testCase.vector)));
