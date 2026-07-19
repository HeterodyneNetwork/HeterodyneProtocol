import { baseVector, consumeVector, produceAuthored } from "./vector-helpers.js";
import type { AuthoredVector, VectorDirection } from "./types.js";

type Case = {
  path: string;
  vector_id: string;
  description: string;
  direction?: VectorDirection;
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
};

export function buildSplitVectors(): AuthoredVector[] {
  return CASES.map((testCase) => ({
    relativePath: testCase.path,
    vector: baseVector({
      vector_id: testCase.vector_id,
      spec_refs: ["split-metadata-selects-the-qualified-reference"],
      description: testCase.description,
      direction: testCase.direction ?? "consume",
      input: testCase.input,
      expected_output: testCase.expected_output,
    }),
  }));
}

const CASES: Case[] = [
  {
    path: "comms-envelope/001-nostr-native-event-valid.json",
    vector_id: "comms-envelope/nostr-native-event-valid",
    description: "A NIP-01 signed event is the Comms-native envelope on both ordinary and repo relays.",
    direction: "round-trip",
    input: { event_id: "11".repeat(32), carriers: ["nostr_relay", "repo_relay"] },
    expected_output: { verdict: "accept", normalized: { deduplication_key: "11".repeat(32), carrier_bytes_equal: true } },
  },
  {
    path: "comms-envelope/002-owner-stamp-valid.json",
    vector_id: "comms-envelope/owner-stamp-valid",
    description: "A Comms-allocated JSON kind carries the Comms qualified owner stamp in content.",
    input: { kind: 31007, content: { spec_version: "comms/0.5.0", page: 0 } },
    expected_output: { verdict: "accept", normalized: { owner: "comms", stamp_location: "content.spec_version" } },
  },
  {
    path: "core-redundancy/001-radicle-multihost-replication.json",
    vector_id: "core-redundancy/radicle-multihost-replication",
    description: "Two independent Radicle seeds replicate the same signed canonical repository head.",
    input: { rid: "rad:zFixture", hosts: ["node-a", "node-b"], canonical_head: "22".repeat(20) },
    expected_output: { verdict: "accept", normalized: { independent_host_count: 2, canonical_head_agrees: true } },
  },
  {
    path: "core-redundancy/002-stale-seed-rejected.json",
    vector_id: "core-redundancy/stale-seed-rejected",
    description: "A stale seed cannot replace the locally accepted canonical repository head.",
    input: { accepted_seq: 9, offered_seq: 8, offered_host: "node-stale" },
    expected_output: { verdict: "reject", reason_code: "repo_head_regression" },
  },
  {
    path: "acceptance-gating/001-authentication-before-policy.json",
    vector_id: "acceptance-gating/authentication-before-policy",
    description: "Cryptographic authentication rejects invalid input before the Comms policy hook runs.",
    input: { signature_valid: false, policy_would_accept: true },
    expected_output: { verdict: "reject", reason_code: "bad_signature", normalized: { policy_hook_invoked: false } },
  },
  {
    path: "acceptance-gating/002-message-request-no-receipt.json",
    vector_id: "acceptance-gating/message-request-no-receipt",
    description: "A new authenticated DM is held as a message request without sender-observable signals.",
    input: { context: "ordinary-dm", established_locally_accepted_session: false, authenticated: true },
    expected_output: { verdict: "accept", normalized: { outcome: "hold-as-message-request", receipts: 0, typing_signals: 0, retry_hints: 0 } },
  },
  {
    path: "acceptance-gating/003-social-mute-tightens.json",
    vector_id: "acceptance-gating/social-mute-tightens",
    description: "Social mute state may tighten an authenticated Comms acceptance into rejection.",
    input: { comms_outcome: "accept", authenticated_peer_muted: true },
    expected_output: { verdict: "accept", normalized: { composed_outcome: "reject", loosened_comms_result: false } },
  },
  {
    path: "acceptance-gating/004-social-policy-cannot-loosen.json",
    vector_id: "acceptance-gating/social-policy-cannot-loosen",
    description: "Social policy cannot turn a Comms rejection into hold or accept.",
    input: { comms_outcome: "reject", social_policy_outcome: "accept" },
    expected_output: { verdict: "accept", normalized: { composed_outcome: "reject", loosened_comms_result: false } },
  },
  {
    path: "versioning/005-qualified-version-valid.json",
    vector_id: "versioning/qualified-version-valid",
    description: "A qualified family version parses into its document and semver suffix.",
    direction: "round-trip",
    input: { value: "comms/0.5.0" },
    expected_output: { valid: true, document: "comms", semver: "0.5.0" },
  },
  {
    path: "versioning/006-qualified-version-unqualified-rejected.json",
    vector_id: "versioning/qualified-version-unqualified-rejected",
    description: "An unqualified scalar semver is not a protocol-family document version.",
    direction: "round-trip",
    input: { value: "0.5.0" },
    expected_output: { valid: false, error: "invalid_qualified_version" },
  },
  {
    path: "versioning/007-core-capability-bootstrap.json",
    vector_id: "versioning/core-capability-bootstrap",
    description: "The Core capability descriptor is discoverable without a higher-document carrier.",
    input: { descriptor: "heterodyne-capabilities-v1", bootstrap_version: "core/0.5.0", registry_revision: 1 },
    expected_output: { verdict: "accept", normalized: { bootstrap_owner: "core", higher_carrier_required: false } },
  },
  {
    path: "versioning/008-per-document-negotiation.json",
    vector_id: "versioning/per-document-negotiation",
    description: "Peers negotiate each document version independently before using its stamp.",
    input: { local: { core: ["core/0.5.0"], comms: ["comms/0.5.0"] }, remote: { core: ["core/0.5.0"], comms: [] } },
    expected_output: { verdict: "accept", normalized: { core: "core/0.5.0", comms: null, may_stamp_comms: false } },
  },
  {
    path: "versioning/009-unknown-asynchronous-stamp-rejected.json",
    vector_id: "versioning/unknown-asynchronous-stamp-rejected",
    description: "An unsupported asynchronous owner stamp is rejected without presumed negotiation.",
    input: { received_stamp: "comms/9.0.0", negotiated_session: false, degraded_mode_declared: false },
    expected_output: { verdict: "reject", reason_code: "unknown_major_version" },
  },
  ...stampCases(),
  {
    path: "registry/001-downref-nonfrozen-rejected.json",
    vector_id: "registry/downref-nonfrozen-rejected",
    description: "A 1.0 document cannot require a non-frozen registry entry.",
    direction: "round-trip",
    input: { document_version: "core/1.0.0", required_entry_status: "stable" },
    expected_output: { valid: false, error: "requires_frozen_registry_entry" },
  },
  {
    path: "registry/002-frozen-entry-immutable.json",
    vector_id: "registry/frozen-entry-immutable",
    description: "A frozen registry entry cannot be removed or semantically reassigned in a later revision.",
    direction: "round-trip",
    input: { previous: { status: "frozen", owner: "core" }, current: { status: "frozen", owner: "comms" } },
    expected_output: { valid: false, error: "frozen_entry_changed" },
  },
];

function stampCases(): Case[] {
  const values: Array<[string, string, Record<string, unknown>, Record<string, unknown>]> = [
    ["001-heterodyne-json-content-owner", "heterodyne-json-content-owner", { kind: 31001, content_is_heterodyne_json: true }, { owner: "core", placement: "content.spec_version" }],
    ["002-heterodyne-empty-content-tag-owner", "heterodyne-empty-content-tag-owner", { kind: 31001, content_is_heterodyne_json: false }, { owner: "core", placement: "tag" }],
    ["003-upstream-unstamped", "upstream-unstamped", { kind: 10000 }, { owner: null, placement: null }],
    ["004-upstream-profile-owner", "upstream-profile-owner", { kind: 10000, profile_id: "heterodyne-social-mute-list-v1" }, { owner: "social", placement: "tag" }],
    ["005-non-stamping-profile-unchanged", "non-stamping-profile-unchanged", { kind: 0, profile_id: "heterodyne-core-rotation-breadcrumb-profile-v1" }, { owner: null, bytes_changed: false }],
    ["006-dr-outer-unstamped", "dr-outer-unstamped", { kind: 1060, is_dr_outer: true }, { owner: null, marker_count: 0 }],
    ["007-control-profile-retains-core-owner", "control-profile-retains-core-owner", { kind: 31001, profile_id: "heterodyne-control-session-device-v1" }, { owner: "core", control_stamp_count: 0 }],
    ["008-control-carrier-comms-owner", "control-carrier-comms-owner", { kind: 31016, profile_id: "comms-subprotocol-payload-v1" }, { owner: "comms", control_stamp_count: 0 }],
    ["009-legacy-monolith-explicit", "legacy-monolith-explicit", { kind: 31001, stamp: "0.4.0" }, { owner: "monolith/0.4.0" }],
    ["010-legacy-monolith-inferred", "legacy-monolith-inferred", { kind: 31007, stamp: null, archived_form_valid: true }, { owner: "monolith/0.4.0" }],
    ["011-legacy-upstream-not-inferable", "legacy-upstream-not-inferable", { kind: 1, adopted_upstream: true }, { owner: null, inferable: false }],
    ["012-no-restamp-existing-bytes", "no-restamp-existing-bytes", { historical_stamp: "0.4.0", migration_target: "core/0.5.0" }, { historical_stamp: "0.4.0", resign: false, bytes_changed: false }],
    ["013-tier3-profile-owner", "tier3-profile-owner", { kind: 1, profile_id: "heterodyne-comms-tier3-wrapped-content-kind-1-v1", content_is_heterodyne_json: false }, { owner: "comms", placement: "tag" }],
  ];
  return values.map(([file, id, input, expected_output]) => ({
    path: `stamping/${file}.json`,
    vector_id: `stamping/${id}`,
    description: `Owner-stamp conformance class: ${id.replaceAll("-", " ")}.`,
    direction: "round-trip",
    input,
    expected_output,
  }));
}
