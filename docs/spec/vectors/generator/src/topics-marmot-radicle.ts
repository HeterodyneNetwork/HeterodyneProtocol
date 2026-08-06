import { canonicalNip01, signEvent } from "./nostr.js";
import {
  AUX_RAND,
  baseVector,
  type VectorBody,
} from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector, VectorDirection } from "./types.js";

type Case = {
  file: string;
  id: string;
  description: string;
  input: Record<string, unknown>;
  expected: Record<string, unknown>;
  direction?: VectorDirection;
};

export async function buildMarmotRadicleVectors(
  fixtures: Fixtures,
): Promise<AuthoredVector[]> {
  const ephemeral = fixtures.personas.alice.epoch_keys.epoch_1;
  const event = await signEvent({
    secretKey: ephemeral.private_key,
    created_at: fixtures.test_epoch + 900,
    kind: 445,
    tags: [
      ["h", "routing-generation-a"],
      ["expiration", String(fixtures.test_epoch + 86_400)],
    ],
    content: "marmot-ciphertext",
    auxRand: AUX_RAND,
  });
  const exact = JSON.stringify(event);
  const raw = canonicalNip01(event);

  const cases: Case[] = [
    {
      file: "001-kind445-exact-bytes.json",
      id: "kind445-exact-bytes",
      description: "Native Radicle, onion NIP-01, and clearnet NIP-01 expose one signed kind:445 without reconstruction.",
      input: { event, nip01_raw: raw },
      expected: {
        verdict: "accept",
        normalized: {
          radicle_object: exact,
          onion_nip01: exact,
          clearnet_nip01: exact,
          byte_identical: true,
        },
      },
      direction: "round-trip",
    },
    {
      file: "002-media-exact-bytes.json",
      id: "media-exact-bytes",
      description: "Every advertised media interface returns the same encrypted-media v2 ciphertext.",
      input: {
        ciphertext_sha256: "11".repeat(32),
        radicle: "encrypted-media-bytes",
        onion: "encrypted-media-bytes",
        clearnet: "encrypted-media-bytes",
      },
      expected: { verdict: "accept", normalized: { byte_identical: true } },
    },
    {
      file: "003-standard-marmot-interop.json",
      id: "standard-marmot-interop",
      description: "A standard-compatible group presents unmodified Marmot envelopes to an ordinary Marmot implementation.",
      input: { profile: "standard-compatible", upstream_marmot_accepts: true, heterodyne_component_required: false },
      expected: { verdict: "accept", normalized: { interoperable: true } },
    },
    {
      file: "004-private-group-radicle-required.json",
      id: "private-group-radicle-required",
      description: "A Heterodyne-private group with no authorized Radicle route fails closed.",
      input: { profile: "heterodyne-private", authorized_radicle_routes: [] },
      expected: { verdict: "reject", reason_code: "marmot-private-route-required" },
    },
    {
      file: "005-directory-sensitive-fields-encrypted.json",
      id: "directory-sensitive-fields-encrypted",
      description: "A discoverable directory keeps public profile fields clear and routing, membership, and administration encrypted.",
      input: {
        visibility: "public-directory",
        public_fields: ["name", "description", "policy"],
        encrypted_fields: ["routing-binding", "membership", "administration"],
      },
      expected: { verdict: "accept", normalized: { sensitive_plaintext: [] } },
    },
    {
      file: "006-invites-individually-sealed.json",
      id: "invites-individually-sealed",
      description: "Directory invitations are individually sealed rather than encrypted to a public group-wide audience.",
      input: { invitation_count: 2, recipient_ciphertexts: 2, shared_plaintext_invite: false },
      expected: { verdict: "accept", normalized: { individually_sealed: true } },
    },
    {
      file: "007-routing-binding-valid.json",
      id: "routing-binding-valid",
      description: "A routing binding is accepted when the active administrator authored the canonical matching routing commit and genesis matches.",
      input: {
        active_admin: true,
        routing_commit_author_matches: true,
        h_matches: true,
        genesis_digest_matches: true,
      },
      expected: { verdict: "accept", normalized: { binding_authoritative: true } },
    },
    {
      file: "008-routing-genesis-mismatch.json",
      id: "routing-genesis-mismatch",
      description: "A binding whose repository genesis does not match its digest is rejected.",
      input: { active_admin: true, routing_commit_author_matches: true, h_matches: true, genesis_digest_matches: false },
      expected: { verdict: "reject", reason_code: "marmot-routing-binding-invalid" },
    },
    {
      file: "009-writer-ref-union-dedup.json",
      id: "writer-ref-union-dedup",
      description: "The logical event repository is the deduplicated union of authorized writer and relay refs.",
      input: {
        refs: {
          "did:key:zWriterA": ["event-a", "event-shared"],
          "did:key:zWriterB": ["event-b", "event-shared"],
          relay: ["event-c"],
        },
      },
      expected: { verdict: "accept", normalized: { event_ids: ["event-a", "event-b", "event-c", "event-shared"] } },
    },
    {
      file: "010-unauthorized-ref-rejected.json",
      id: "unauthorized-ref-rejected",
      description: "Objects reachable only from an unauthorized writer ref do not enter the logical union.",
      input: { ref_authorized: false, event_signature_valid: true },
      expected: { verdict: "reject", reason_code: "marmot-unauthorized-ref" },
    },
    {
      file: "011-relay-routes-by-h-only.json",
      id: "relay-routes-by-h-only",
      description: "A Radicle-backed relay routes by h without group identity, membership, static repository, or MLS epoch knowledge.",
      input: { h: "routing-generation-a", relay_known_fields: ["h", "event_rid"] },
      expected: { verdict: "accept", normalized: { group_metadata_required: false } },
    },
    {
      file: "012-concurrent-routing-marmot-wins.json",
      id: "concurrent-routing-marmot-wins",
      description: "Marmot convergence selects the canonical routing commit and the losing prepared repository is abandoned.",
      input: { candidates: ["commit-a", "commit-b"], marmot_winner: "commit-b" },
      expected: { verdict: "accept", normalized: { active: "commit-b", abandoned: ["commit-a"] } },
    },
    {
      file: "013-canonical-h-equivocation.json",
      id: "canonical-h-equivocation",
      description: "Two different bindings for the canonical h fail the Radicle transition closed.",
      input: { canonical_h: "routing-generation-a", binding_digests: ["11".repeat(32), "22".repeat(32)] },
      expected: { verdict: "reject", reason_code: "marmot-routing-equivocation" },
    },
    {
      file: "014-removal-before-routing-rotation.json",
      id: "removal-before-routing-rotation",
      description: "Member removal becomes canonical before a remaining administrator publishes the replacement routing state.",
      input: { sequence: ["removal-commit", "post-removal-routing-commit"] },
      expected: { verdict: "accept", normalized: { removed_member_received_new_h: false } },
    },
    {
      file: "015-logical-size-cap-control-open.json",
      id: "logical-size-cap-control-open",
      description: "At the 5 GiB logical cap application and media admission stop while bounded rotation control remains open.",
      input: { logical_unique_bytes: 5_368_709_120, operation: ["application", "media", "routing-control"] },
      expected: {
        verdict: "accept",
        normalized: { application: "reject", media: "reject", routing_control: "accept", rotate: true },
      },
    },
    {
      file: "016-radicle-durable-ack.json",
      id: "radicle-durable-ack",
      description: "Native publication acknowledges only after local durability and one configured host accepts the writer ref announcement.",
      input: { exact_objects_committed: true, durable_local: true, configured_host_acceptances: 1 },
      expected: { verdict: "accept", normalized: { durable_ack: true } },
    },
    {
      file: "017-relay-ack-before-durable-rejected.json",
      id: "relay-ack-before-durable-rejected",
      description: "A relay cannot return NIP-01 OK before exact bytes are durable on its relay ref.",
      input: { envelope_valid: true, durable_relay_ref: false, returned_ok: true },
      expected: { verdict: "reject", reason_code: "marmot-premature-ack" },
    },
    {
      file: "018-failover-delivery.json",
      id: "failover-delivery",
      description: "Failover submits the same signed event to the next authorized target after the preferred target fails.",
      input: { event_id: event.id, attempts: [{ target: "preferred", result: "timeout" }, { target: "fallback", result: "durable-ok" }] },
      expected: { verdict: "accept", normalized: { applied_after: "fallback", logical_messages: 1 } },
    },
    {
      file: "019-redundant-delivery-dedup.json",
      id: "redundant-delivery-dedup",
      description: "Redundant delivery carries one event ID through multiple targets and applies it once.",
      input: { event_id: event.id, durable_targets: ["radicle", "nostr"] },
      expected: { verdict: "accept", normalized: { first_ack_applies: true, logical_messages: 1 } },
    },
    {
      file: "020-retained-routing-overlap.json",
      id: "retained-routing-overlap",
      description: "Clients retain the current generation and every prior routing ID required by the Marmot rollback horizon.",
      input: { current: 7, rollback_required: [6], optional_archives: [1, 2, 3, 4, 5] },
      expected: { verdict: "accept", normalized: { required_generations: [6, 7] } },
    },
    {
      file: "021-expiration-is-not-erasure.json",
      id: "expiration-is-not-erasure",
      description: "Archive expiry removes active advertisements and refs without claiming independently replicated Git data is erased.",
      input: { retention_expired: true, independent_clones_possible: true },
      expected: { verdict: "accept", normalized: { stop_seeding: true, erasure_guarantee: false } },
    },
    {
      file: "022-persona-inbox-atomic-bootstrap.json",
      id: "persona-inbox-atomic-bootstrap",
      description: "First contact atomically commits one consumed KeyPackage, exact Welcome, and first exact kind:445 on the sender ref.",
      input: { keypackage_consumed: true, welcome_exact: true, first_event_exact: true, one_commit: true },
      expected: { verdict: "accept", normalized: { two_member_group_created: true } },
    },
    {
      file: "023-private-inbox-nid-required.json",
      id: "private-inbox-nid-required",
      description: "An unknown NID cannot write a first-contact bundle to a private persona repository.",
      input: { persona_repository: "private", sender_nid_authorized: false },
      expected: { verdict: "reject", reason_code: "marmot-private-inbox-nid-required" },
    },
    {
      file: "024-keypackage-replay-rejected.json",
      id: "keypackage-replay-rejected",
      description: "A public-inbox bundle that reuses a consumed KeyPackage is discarded in quarantine.",
      input: { keypackage_id: "kp-1", prior_consumption_seen: true },
      expected: { verdict: "reject", reason_code: "marmot-keypackage-replayed" },
    },
    {
      file: "025-public-inbox-lazy-media.json",
      id: "public-inbox-lazy-media",
      description: "Public-inbox quarantine fetches the bounded manifest but does not automatically retrieve unknown media.",
      input: { manifest_bytes: 2048, media_objects: 4, user_accepted_media: false },
      expected: { verdict: "accept", normalized: { fetched: ["manifest"], deferred_media_objects: 4 } },
    },
    {
      file: "026-agent-group-attribution.json",
      id: "agent-group-attribution",
      description: "An agent group message binds token group scope, Marmot sender account, KERI role, and protected automation attribution.",
      input: {
        group_scope_matches: true,
        mls_sender_matches_role: true,
        keri_role_current: true,
        automation_attribution_present: true,
      },
      expected: { verdict: "accept", normalized: { automated: true, node_mediated: true } },
    },
    {
      file: "027-agent-group-scope-denied.json",
      id: "agent-group-scope-denied",
      description: "A token for another group cannot authorize an automated Marmot message.",
      input: { token_group: "group-a", requested_group: "group-b" },
      expected: { verdict: "reject", reason_code: "marmot-agent-scope-denied" },
    },
    {
      file: "028-repeated-media-locators.json",
      id: "repeated-media-locators",
      description: "A message may carry radicle-v1 and standard media locators; an unsupported locator is skipped without invalidating the message.",
      input: { locators: ["radicle-v1", "blossom"], supported: ["blossom"] },
      expected: { verdict: "accept", normalized: { selected: "blossom", skipped: ["radicle-v1"] } },
    },
    {
      file: "029-direct-member-history-boundary.json",
      id: "direct-member-history-boundary",
      description: "A new independent direct-member leaf receives ordinary retained history from its join epoch only.",
      input: { join_epoch: 12, requested_epochs: [10, 11, 12, 13] },
      expected: { verdict: "accept", normalized: { available_epochs: [12, 13] } },
    },
    {
      file: "030-node-mediated-secret-confinement.json",
      id: "node-mediated-secret-confinement",
      description: "A node-mediated light client receives grant-filtered content and no MLS, account, leaf, or repository secret.",
      input: { mode: "node-mediated", requested_view: "group-a" },
      expected: {
        verdict: "accept",
        normalized: { content_filtered: true, released_secrets: [] },
      },
    },
  ];

  return cases.map(({ file, id, description, input, expected, direction = "consume" }) => ({
    relativePath: `marmot-radicle/${file}`,
    vector: baseVector({
      vector_id: `marmot-radicle/${id}`,
      spec_refs: [],
      description,
      direction,
      input,
      expected_output: expected,
    } satisfies VectorBody & { direction: VectorDirection }),
  }));
}
