import { schnorr } from "@noble/curves/secp256k1";
import { nip19, nip44 } from "nostr-tools";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { canonicalNip01, getEventId, getPublicKey, signEvent, verifyEventSignature, type NostrSignedEvent } from "./nostr.js";
import { AUX_RAND, baseVector } from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector, VectorDirection } from "./types.js";

type Case = {
  path: string;
  vector_id: string;
  description: string;
  direction?: VectorDirection;
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
};

export async function buildSplitVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const sender = fixtures.personas.alice.epoch_keys.epoch_1;
  const recipient = fixtures.personas.bob.epoch_keys.epoch_1;
  const successorPrivateKey = "0a".padStart(64, "0");
  const successorPublicKey = getPublicKey(successorPrivateKey);
  const successorNpub = nip19.npubEncode(successorPublicKey);
  const unrelatedNpub = nip19.npubEncode(recipient.pubkey);
  const breadcrumbWriteRelays = ["wss://relay.example"];
  const senderDevice = fixtures.device_publishing_keys.alice_device_1;
  const recipientDevice = fixtures.device_publishing_keys.bob_device_1;
  const native = await signEvent({
    secretKey: sender.private_key,
    created_at: fixtures.test_epoch + 500,
    kind: 1,
    tags: [["kel_head", fixtures.kel.alice.head.id, "0"]],
    content: "deterministic Comms-native envelope",
    auxRand: AUX_RAND,
  });
  const payloadContent = JSON.stringify({
    spec_version: "heterodyne/0.5.0",
    protocol_type: "payload",
    negotiation_id: "aa".repeat(16),
    protocol_id: "heterodyne-device-rpc",
    protocol_version: "1.0.0",
    responder_confirmation_hash: "bb".repeat(32),
    payload: { method: "claims.list", request_id: "fixture-1" },
  });
  const rumorBase = {
    pubkey: senderDevice.pubkey,
    created_at: fixtures.test_epoch + 501,
    kind: 31016,
    tags: [["p", recipientDevice.pubkey]],
    content: payloadContent,
  };
  const rumor = { id: getEventId(rumorBase), ...rumorBase };
  const negotiationContent = JSON.stringify({
    spec_version: "heterodyne/0.5.0", protocol_type: "negotiation", phase: "offer",
    negotiation_id: "cc".repeat(16), protocol_id: "heterodyne-device-rpc",
    supported_versions: ["1.0.0"], required_features: ["claims"],
  });
  const negotiationBase = { ...rumorBase, created_at: fixtures.test_epoch + 502, kind: 31015, content: negotiationContent };
  const negotiationRumor = { id: getEventId(negotiationBase), ...negotiationBase };
  const breadcrumbProfile = await signEvent({
    secretKey: sender.private_key, created_at: fixtures.test_epoch + 503, kind: 0, tags: [],
    content: JSON.stringify({
      name: "Alice (moved)",
      about: `Continues at ${successorNpub}`,
      website: `https://heterodyne.network/client/${successorNpub}`,
    }),
    auxRand: AUX_RAND,
  });
  const breadcrumbNote = await signEvent({
    secretKey: sender.private_key, created_at: fixtures.test_epoch + 504, kind: 1, tags: [],
    content: `This account continues at ${successorNpub}`, auxRand: AUX_RAND,
  });
  const unrelatedSuccessorProfile = await signEvent({
    secretKey: sender.private_key, created_at: fixtures.test_epoch + 505, kind: 0, tags: [],
    content: JSON.stringify({
      name: "Alice (moved)",
      about: `Continues at ${unrelatedNpub}`,
      website: `https://heterodyne.network/client/${unrelatedNpub}`,
    }),
    auxRand: AUX_RAND,
  });
  const repointedNip05Profile = await signEvent({
    secretKey: sender.private_key, created_at: fixtures.test_epoch + 506, kind: 0, tags: [],
    content: JSON.stringify({
      name: "Alice (moved)",
      about: `Continues at ${successorNpub}`,
      website: `https://heterodyne.network/client/${successorNpub}`,
      nip05: "alice@example.test",
    }),
    auxRand: AUX_RAND,
  });
  const ordinaryVanillaProfile = await signEvent({
    secretKey: recipient.private_key, created_at: fixtures.test_epoch + 507, kind: 0, tags: [],
    content: JSON.stringify({
      name: "Ordinary upstream author",
      about: `Human-readable continuation at ${successorNpub}`,
    }),
    auxRand: AUX_RAND,
  });
  const trustedRotationContext = {
    prior_kel_accepted: true,
    prior_kel_head: fixtures.kel.alice.head,
    routine_rotation_accepted: true,
    compromise_rotation: false,
    same_persona: true,
    persona_cold_root: fixtures.personas.alice.cold_root.pubkey,
    rotation_persona_cold_root: fixtures.personas.alice.cold_root.pubkey,
    retiring_epoch_key: sender.pubkey,
    rotation_prior_epoch_key: sender.pubkey,
    successor_epoch_key: successorPublicKey,
    rotation_successor_epoch_key: successorPublicKey,
    nip65_write_relays: breadcrumbWriteRelays,
    kel_accepted_at: fixtures.test_epoch + 500,
    retiring_secret_destroyed_at: fixtures.test_epoch + 600,
  };
  const candidatePair = {
    kind0_event_id: breadcrumbProfile.id,
    kind1_event_id: breadcrumbNote.id,
  };
  const orgFeed = await signEvent({
    secretKey: sender.private_key, created_at: fixtures.test_epoch + 505, kind: 31007,
    tags: [["d", "org-news:page-1"], ["heterodyne", "feed_index"], ["cold_root", fixtures.personas.alice.cold_root.pubkey], ["rid", fixtures.radicle_rids.org_acme], ["feed_label", "Org news"], ["e", "33".repeat(32), "wss://relay.example"], ["kel_head", fixtures.kel.alice.head.id, "0"]],
    content: "{\"profile\":\"heterodyne.social.org-feed.v1\",\"spec_version\":\"heterodyne/0.5.0\"}", auxRand: AUX_RAND,
  });
  const inviterEphemeralPrivateKey = "0c".repeat(32);
  const inviterEphemeralPublicKey = getPublicKey(inviterEphemeralPrivateKey);
  const inviteeSessionPrivateKey = "0d".repeat(32);
  const inviteeSessionPublicKey = getPublicKey(inviteeSessionPrivateKey);
  const randomSenderPrivateKey = "0e".repeat(32);
  const sharedSecret = "0f".repeat(32);
  const inviteResponsePayload = JSON.stringify({
    sessionKey: inviteeSessionPublicKey,
    ownerPublicKey: fixtures.personas.bob.cold_root.pubkey,
  });
  const dhEncrypted = nip44.v2.encrypt(
    inviteResponsePayload,
    nip44.v2.utils.getConversationKey(hexToBytes(recipientDevice.private_key), senderDevice.pubkey),
    hexToBytes("61".repeat(32)),
  );
  const innerEvent = {
    pubkey: recipientDevice.pubkey,
    content: nip44.v2.encrypt(dhEncrypted, hexToBytes(sharedSecret), hexToBytes("62".repeat(32))),
    created_at: fixtures.test_epoch + 506,
  };
  const inviteResponse = await signEvent({
    secretKey: randomSenderPrivateKey,
    created_at: fixtures.test_epoch + 507,
    kind: 1059,
    tags: [["p", inviterEphemeralPublicKey]],
    content: nip44.v2.encrypt(
      JSON.stringify(innerEvent),
      nip44.v2.utils.getConversationKey(hexToBytes(randomSenderPrivateKey), inviterEphemeralPublicKey),
      hexToBytes("63".repeat(32)),
    ),
    auxRand: AUX_RAND,
  });
  const dynamic: Case[] = [
    {
      path: "profiles/001-core-breadcrumb-kind0.json",
      vector_id: "profiles/core-breadcrumb-kind0",
      description: "A trusted routine-rotation workflow produces the exact unstamped old-key kind:0 successor profile after KEL acceptance and before retiring-secret destruction.",
      direction: "produce",
      input: {
        trusted_rotation_context: trustedRotationContext,
        candidate_pair: candidatePair,
        candidate_event: breadcrumbProfile,
        publication_relays: breadcrumbWriteRelays,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          classification_source: "trusted-local-producer-workflow",
          same_persona: true,
          emitted_after_kel_acceptance: true,
          emitted_before_secret_destruction: true,
          signature_valid: verifyEventSignature(breadcrumbProfile),
          stamp_count: 0,
          nip05_present: false,
          successor_npub: successorNpub,
        },
      },
    },
    {
      path: "profiles/002-core-breadcrumb-kind1.json",
      vector_id: "profiles/core-breadcrumb-kind1",
      description: "The same trusted routine-rotation workflow produces the exact unstamped old-key kind:1 continuation note in the permitted post-acceptance window.",
      direction: "produce",
      input: {
        trusted_rotation_context: trustedRotationContext,
        candidate_pair: candidatePair,
        candidate_event: breadcrumbNote,
        publication_relays: breadcrumbWriteRelays,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          classification_source: "trusted-local-producer-workflow",
          same_persona: true,
          emitted_after_kel_acceptance: true,
          emitted_before_secret_destruction: true,
          signature_valid: verifyEventSignature(breadcrumbNote),
          stamp_count: 0,
          successor_npub: successorNpub,
        },
      },
    },
    {
      path: "breadcrumbs/001-unrelated-successor-rejected.json",
      vector_id: "breadcrumbs/unrelated-successor-rejected",
      description: "A retiring key that points at another persona's epoch key is not a conforming v1 breadcrumb producer workflow.",
      direction: "produce",
      input: {
        trusted_rotation_context: {
          ...trustedRotationContext,
          same_persona: false,
          successor_epoch_key: recipient.pubkey,
          rotation_successor_epoch_key: successorPublicKey,
        },
        candidate_event: unrelatedSuccessorProfile,
        publication_relays: breadcrumbWriteRelays,
      },
      expected_output: { verdict: "reject", reason_code: "successor_persona_mismatch" },
    },
    {
      path: "breadcrumbs/002-compromise-rotation-not-produced.json",
      vector_id: "breadcrumbs/compromise-rotation-not-produced",
      description: "A compromise-driven rotation cannot produce a trustworthy old-key breadcrumb profile.",
      direction: "produce",
      input: {
        trusted_rotation_context: {
          ...trustedRotationContext,
          routine_rotation_accepted: false,
          compromise_rotation: true,
        },
        candidate_pair: candidatePair,
        candidate_event: breadcrumbProfile,
        publication_relays: breadcrumbWriteRelays,
      },
      expected_output: { verdict: "reject", reason_code: "compromise_rotation" },
    },
    {
      path: "breadcrumbs/003-repointed-nip05-rejected.json",
      vector_id: "breadcrumbs/repointed-nip05-rejected",
      description: "The retiring-key profile is not produced with a NIP-05 identifier already repointed to the successor.",
      direction: "produce",
      input: {
        trusted_rotation_context: trustedRotationContext,
        candidate_event: repointedNip05Profile,
        nip05_repointed_to_successor: true,
        publication_relays: breadcrumbWriteRelays,
      },
      expected_output: { verdict: "reject", reason_code: "retiring_key_nip05_invalid" },
    },
    {
      path: "breadcrumbs/004-ordinary-consumer-no-profile-inference.json",
      vector_id: "breadcrumbs/ordinary-consumer-no-profile-inference",
      description: "Relay bytes for an unstamped signed kind:0 without kel_head remain ordinary upstream Nostr and never identify either registered rotation-breadcrumb producer profile.",
      direction: "consume",
      input: { event: ordinaryVanillaProfile },
      expected_output: {
        verdict: "accept",
        normalized: {
          signature_valid: verifyEventSignature(ordinaryVanillaProfile),
          authority: "nip01-signature-only",
          inferred_heterodyne_profile: null,
          kel_succession: false,
        },
      },
    },
    { path: "profiles/010-social-org-feed-kind31007.json", vector_id: "profiles/social-org-feed-kind31007", description: "The active Social organization-feed profile is a complete signed Comms feed-index with its exact canonical content marker.", direction: "round-trip", input: { event: orgFeed, canonical_wire: canonicalNip01(orgFeed) }, expected_output: { verdict: "accept", normalized: { signature_valid: verifyEventSignature(orgFeed), owner: "social", stamp_location: "content.spec_version" } } },
  ];
  const authored = [...dynamic, ...CASES].map((testCase) => ({
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
  return authored;
}

const CASES: Case[] = [
  {
    path: "core-redundancy/001-radicle-multihost-replication.json",
    vector_id: "core-redundancy/radicle-multihost-replication",
    description: "Two independent Radicle seeds replicate the same signed canonical repository head.",
    input: { rid: "rad:zFixture", hosts: ["node-a", "node-b"], canonical_head: "22".repeat(20) },
    expected_output: { verdict: "accept", normalized: { independent_host_count: 2, canonical_head_agrees: true } },
  },
  {
    path: "core-redundancy/002-stale-seed-does-not-remove-durability.json",
    vector_id: "core-redundancy/stale-seed-does-not-remove-durability",
    description: "A stale seed remains a discoverable replica while two current independent hosts preserve durable canonical repository availability.",
    input: { canonical_head: "22".repeat(20), hosts: [{ host: "node-a", head_current: true }, { host: "node-b", head_current: true }, { host: "node-stale", head_current: false }] },
    expected_output: { verdict: "accept", normalized: { durable_current_host_count: 2, stale_host_retained: true, canonical_head_authority_changed: false } },
  },
  {
    path: "versioning/005-qualified-version-valid.json",
    vector_id: "versioning/qualified-version-valid",
    description: "A qualified family version parses into its semver suffix.",
    direction: "round-trip",
    input: { value: "heterodyne/0.5.0" },
    expected_output: { valid: true, semver: "0.5.0" },
  },
  {
    path: "versioning/006-qualified-version-unqualified-rejected.json",
    vector_id: "versioning/qualified-version-unqualified-rejected",
    description: "Bare and document-qualified values are not family versions.",
    direction: "round-trip",
    input: { values: ["0.5.0", { document: "core", semver: "0.5.0" }] },
    expected_output: { valid: false, error: "invalid_family_version" },
  },
  {
    path: "versioning/007-core-capability-bootstrap.json",
    vector_id: "versioning/core-capability-bootstrap",
    description: "The complete Core capability bootstrap object is accepted without a higher-document carrier.",
    input: { descriptor: "heterodyne-capabilities-v1", spec_version: "heterodyne/0.5.0", registry_sha256: "a2a902c616a5671bf058c1d9a0e2ed91ee15c7915593fac5fa551e3f41a805f4", implementation_role: "public-reader", supported_documents: ["core"], required_features: ["core.nostr-relay-read.v1"], strict_profiles: [] },
    expected_output: { verdict: "accept", normalized: { bootstrap_owner: "core", higher_carrier_required: false, family_version: "heterodyne/0.5.0" } },
  },
  {
    path: "versioning/008-exact-family-version-negotiation.json",
    vector_id: "versioning/exact-family-version-negotiation",
    description: "Peers select one exact family version before sending stamped events.",
    input: { local: ["heterodyne/0.5.0"], remote: ["heterodyne/0.5.0"] },
    expected_output: { verdict: "accept", normalized: { selected_version: "heterodyne/0.5.0" } },
  },
  {
    path: "versioning/009-unknown-asynchronous-stamp-rejected.json",
    vector_id: "versioning/unknown-asynchronous-stamp-rejected",
    description: "An unsupported asynchronous family stamp is rejected without presumed negotiation.",
    input: { received_stamp: "heterodyne/9.0.0", negotiated_session: false, degraded_mode_declared: false },
    expected_output: { verdict: "reject", reason_code: "unknown_major_version" },
  },
  ...profileCases(),
  ...stampCases(),
  {
    path: "registry/001-downref-nonfrozen-rejected.json",
    vector_id: "registry/downref-nonfrozen-rejected",
    description: "A 1.0 document cannot require a non-frozen registry entry.",
    direction: "round-trip",
    input: { document_version: "heterodyne/1.0.0", required_entry_status: "stable" },
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
  {
    path: "registry/003-feature-dependency-exact.json",
    vector_id: "registry/feature-dependency-exact",
    description: "A required feature resolves only through the exact declared dependency release that owns and provides it.",
    direction: "round-trip",
    input: {
      document: "heterodyne/0.5.0",
      dependency: "heterodyne/0.5.0",
      required_feature: "comms.marmot-conversations.v1",
      catalog_owner: "comms",
      dependency_provided_features: ["comms.marmot-conversations.v1"],
    },
    expected_output: { valid: true, resolved_dependency: "heterodyne/0.5.0" },
  },
  {
    path: "registry/004-feature-dependency-unprovided-rejected.json",
    vector_id: "registry/feature-dependency-unprovided-rejected",
    description: "A catalog entry does not satisfy a required feature unless the exact dependency release provides it.",
    direction: "round-trip",
    input: {
      document: "heterodyne/0.5.0",
      dependency: "heterodyne/0.5.0",
      required_feature: "comms.marmot-conversations.v1",
      catalog_owner: "comms",
      dependency_provided_features: [],
    },
    expected_output: { valid: false, error: "required_feature_not_provided" },
  },
  {
    path: "registry/005-control-strict-profile-flattened.json",
    vector_id: "registry/control-strict-profile-flattened",
    description: "The active Control strict profile contains the complete 27-invariant flattened Core, Comms, and Control membership.",
    direction: "round-trip",
    input: {
      profile_id: "heterodyne-control-strict-v1",
      prerequisite_profiles: ["heterodyne-core-strict-v1", "heterodyne-comms-strict-v1"],
      declared_invariant_count: 27,
      duplicate_invariant_ids: [],
      missing_prerequisite_invariants: [],
    },
    expected_output: { valid: true, flattened_invariant_count: 27 },
  },
];

function profileCases(): Case[] {
  const tier3Kinds = [1, 6, 16, 1063, 30023, 30402];
  const tier3 = tier3Kinds.map((kind, index): Case => ({
    path: `profiles/${String(index + 3).padStart(3, "0")}-tier3-kind-${kind}.json`,
    vector_id: `profiles/tier3-kind-${kind}`,
    description: `The active Tier-3 kind:${kind} profile uses the exact opaque carrier tags and Comms owner stamp.`,
    direction: "round-trip",
    input: { event_template: { kind, tags: [...(kind >= 30000 ? [["d", `opaque-${kind}`]] : []), ["heterodyne_wrap", "room_key.v2"], ["key_id", "aud-fixture"], ["kel_head", "11".repeat(32), "0"], ["spec_version", "heterodyne/0.5.0"]], content: "AopaqueNIP44fixture" } },
    expected_output: { verdict: "accept", normalized: { owner: "comms", stamp_location: "tag", semantic_cleartext_tags: 0 } },
  }));
  return [
    ...tier3,
  ];
}

function stampCases(): Case[] {
  const values: Array<[string, string, Record<string, unknown>, Record<string, unknown>]> = [
    ["001-heterodyne-json-content-owner", "heterodyne-json-content-owner", { kind: 31003, content_is_heterodyne_json: true, content: { spec_version: "heterodyne/0.5.0" } }, { owner: "core", placement: "content.spec_version" }],
    ["002-heterodyne-empty-content-tag-owner", "heterodyne-empty-content-tag-owner", { kind: 31001, content_is_heterodyne_json: false }, { owner: "core", placement: "tag" }],
    ["003-upstream-unstamped", "upstream-unstamped", { kind: 10000 }, { owner: null, placement: null }],
    ["004-upstream-profile-owner", "upstream-profile-owner", { kind: 10000, profile_id: "heterodyne-social-mute-list-v1" }, { owner: "social", placement: "tag" }],
    ["005-non-stamping-profile-unchanged", "non-stamping-profile-unchanged", { kind: 0, profile_id: "heterodyne-core-rotation-breadcrumb-profile-v1" }, { owner: null, bytes_changed: false }],
    ["006-tier3-profile-owner", "tier3-profile-owner", { kind: 1, profile_id: "heterodyne-comms-tier3-wrapped-content-kind-1-v1", content_is_heterodyne_json: false }, { owner: "comms", placement: "tag" }],
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
