import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
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
    spec_version: "comms/0.5.0",
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
    spec_version: "comms/0.5.0", protocol_type: "negotiation", phase: "offer",
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
  const sessionDevice = fixtures.device_publishing_keys.alice_device_2;
  const bindingNonce = "70".repeat(32);
  const validUntil = String(fixtures.test_epoch + 3600);
  const bindingPayload = [
    "heterodyne-light-binding-v1",
    fixtures.personas.alice.cold_root.pubkey,
    sessionDevice.pubkey,
    "session-device",
    bindingNonce,
  ].join("|");
  const keyProof = bytesToHex(schnorr.sign(
    sha256(utf8Bytes(bindingPayload)),
    hexToBytes(sessionDevice.private_key),
    AUX_RAND,
  ));
  const sessionTags = [
    ["d", `pubkey:${sessionDevice.pubkey}`],
    ["heterodyne", "delegation"],
    ["publishing_key", sessionDevice.pubkey],
    ["cold_root", fixtures.personas.alice.cold_root.pubkey],
    ["valid_until", validUntil],
    ["binding_nonce", bindingNonce],
    ["kel_head", fixtures.kel.alice.head.id, "0"],
    ["key_proof", keyProof],
    ["spec_version", "core/0.5.0"],
  ];
  const sessionDeviceEvent = await signEvent({
    secretKey: sender.private_key,
    created_at: fixtures.test_epoch + 509,
    kind: 31001,
    tags: sessionTags,
    content: "",
    auxRand: AUX_RAND,
  });
  const sessionWithNidFields = await signEvent({
    secretKey: sender.private_key,
    created_at: fixtures.test_epoch + 510,
    kind: 31001,
    tags: [
      ...sessionTags.slice(0, -1),
      ["radicle_nid", fixtures.ed25519_nids.alice_device_2.did_key],
      ["nid_proof", "00".repeat(64)],
      sessionTags.at(-1)!,
    ],
    content: "",
    auxRand: AUX_RAND,
  });
  const sessionWithBadProof = await signEvent({
    secretKey: sender.private_key,
    created_at: fixtures.test_epoch + 511,
    kind: 31001,
    tags: sessionTags.map((tag) => tag[0] === "key_proof"
      ? ["key_proof", "00".repeat(64)]
      : tag),
    content: "",
    auxRand: AUX_RAND,
  });
  const sessionWithoutOwnerStamp = await signEvent({
    secretKey: sender.private_key,
    created_at: fixtures.test_epoch + 512,
    kind: 31001,
    tags: sessionTags.slice(0, -1),
    content: "",
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
    content: "{\"profile\":\"heterodyne.social.org-feed.v1\",\"spec_version\":\"social/0.5.0\"}", auxRand: AUX_RAND,
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
      path: "comms-envelope/001-nostr-native-event-valid.json",
      vector_id: "comms-envelope/nostr-native-event-valid",
      description: "A complete deterministic BIP-340-signed NIP-01 event is the Comms-native envelope on ordinary and repo relays.",
      direction: "round-trip",
      input: { event: native, canonical_wire: canonicalNip01(native), carriers: ["nostr_relay", "repo_relay"] },
      expected_output: { verdict: "accept", normalized: { deduplication_key: native.id, carrier_bytes_equal: true, id_valid: true, signature_valid: verifyEventSignature(native) } },
    },
    {
      path: "comms-envelope/002-owner-stamp-valid.json",
      vector_id: "comms-envelope/owner-stamp-valid",
      description: "A complete unsigned kind:31016 Comms rumor carries its qualified stamp inside the canonical JSON content string.",
      input: { rumor, canonical_wire: canonicalNip01(rumorBase) },
      expected_output: { verdict: "accept", normalized: { owner: "comms", stamp_location: "content.spec_version", event_id: rumor.id, outer_signature_present: false } },
    },
    {
      path: "comms-envelope/003-nostr-native-signature-mutation.json",
      vector_id: "comms-envelope/nostr-native-signature-mutation",
      description: "Changing signed NIP-01 content while retaining the deterministic id and signature is rejected.",
      input: { event: { ...native, content: `${native.content} tampered` } },
      expected_output: { verdict: "reject", reason_code: "bad_signature" },
    },
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
      description: "Relay bytes for an unstamped signed kind:0 without kel_head remain ordinary upstream Nostr and never identify either ADR-031 v1 producer profile.",
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
    {
      path: "session-device/001-reserved-shape-valid-but-gated.json",
      vector_id: "session-device/reserved-shape-valid-but-gated",
      description: "The exact NID-less session-device event passes draft structural and dual-proof validation, but relay observation is provisional and revision 3 keeps the Control profile non-claimable.",
      direction: "consume",
      input: {
        event: sessionDeviceEvent,
        binding_payload: bindingPayload,
        evaluation_time: fixtures.test_epoch + 512,
        relay_valid: true,
        repository_reachable: false,
        profile_gate_open: false,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          base_owner: "core",
          profile_state: "reserved-inactive",
          schema_valid: true,
          key_proof_valid: schnorr.verify(
            keyProof,
            sha256(utf8Bytes(bindingPayload)),
            sessionDevice.pubkey,
          ),
          relay_state: "provisional",
          repository_final: false,
          control_authority: false,
          conformance_claimable: false,
        },
      },
    },
    {
      path: "session-device/002-nid-fields-forbidden.json",
      vector_id: "session-device/nid-fields-forbidden",
      description: "The reserved NID-less discriminator rejects radicle_nid and nid_proof rather than conflating session and durable-device authority.",
      direction: "consume",
      input: { event: sessionWithNidFields, binding_payload: bindingPayload },
      expected_output: {
        verdict: "reject",
        reason_code: "role-delegation-address-invalid",
        validation_error: "nid_fields_forbidden",
        conformance_claimable: false,
      },
    },
    {
      path: "session-device/003-key-proof-invalid.json",
      vector_id: "session-device/key-proof-invalid",
      description: "A valid epoch-key envelope cannot activate a session-device candidate whose publishing-key proof fails.",
      direction: "consume",
      input: { event: sessionWithBadProof, binding_payload: bindingPayload },
      expected_output: {
        verdict: "reject",
        reason_code: "bad_signature",
        validation_error: "key_proof_invalid",
        conformance_claimable: false,
      },
    },
    {
      path: "session-device/004-repository-final-gate-closed.json",
      vector_id: "session-device/repository-final-gate-closed",
      description: "Canonical repository reachability hardens the candidate delegation but cannot open the independently closed revision-3 Control profile gate.",
      direction: "consume",
      input: {
        event: sessionDeviceEvent,
        relay_valid: true,
        repository_reachable: true,
        profile_gate_open: false,
        comms_authorization_state: "active",
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          repository_final: true,
          delegation_state: "final-but-gated",
          control_authority: false,
          conformance_claimable: false,
        },
      },
    },
    {
      path: "session-device/005-owner-stamp-missing.json",
      vector_id: "session-device/owner-stamp-missing",
      description: "A producer refuses to emit the reserved candidate without the sole Core owner stamp.",
      direction: "produce",
      input: { event: sessionWithoutOwnerStamp, binding_payload: bindingPayload },
      expected_output: {
        verdict: "reject",
        reason_code: "owner_stamp_missing",
        conformance_claimable: false,
      },
    },
    {
      path: "session-device/006-live-challenge-binding-valid.json",
      vector_id: "session-device/live-challenge-binding-valid",
      description: "The publishing-key proof nonce matches a fresh challenge from the authenticated enrollment session, while the closed profile gate still grants no Control authority.",
      direction: "consume",
      input: {
        event: sessionDeviceEvent,
        enrollment_binding: {
          source: "live-challenge",
          binding_nonce: bindingNonce,
          authenticated_session: true,
          unexpired: true,
        },
        profile_gate_open: false,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          binding_valid: true,
          binding_source: "live-challenge",
          control_authority: false,
          conformance_claimable: false,
        },
      },
    },
    {
      path: "session-device/007-one-time-token-binding-valid.json",
      vector_id: "session-device/one-time-token-binding-valid",
      description: "The publishing-key proof nonce matches an issuer-bound, unexpired, unredeemed one-time enrollment token, while the closed profile gate still grants no Control authority.",
      direction: "consume",
      input: {
        event: sessionDeviceEvent,
        enrollment_binding: {
          source: "one-time-token",
          binding_nonce: bindingNonce,
          token_id: "71".repeat(16),
          authenticated_session: true,
          issuer_bound: true,
          single_use: true,
          unredeemed: true,
          unexpired: true,
        },
        profile_gate_open: false,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          binding_valid: true,
          binding_source: "one-time-token",
          control_authority: false,
          conformance_claimable: false,
        },
      },
    },
    {
      path: "session-device/008-revoked-no-authority.json",
      vector_id: "session-device/revoked-no-authority",
      description: "Revocation removes all prospective session-device authority even when the candidate was repository-final.",
      direction: "consume",
      input: {
        event: sessionDeviceEvent,
        repository_final: true,
        delegation_revoked: true,
        profile_gate_open: false,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          delegation_state: "revoked",
          control_authority: false,
          conformance_claimable: false,
        },
      },
    },
    { path: "profiles/010-social-org-feed-kind31007.json", vector_id: "profiles/social-org-feed-kind31007", description: "The active Social organization-feed profile is a complete signed Comms feed-index with its exact canonical content marker.", direction: "round-trip", input: { event: orgFeed, canonical_wire: canonicalNip01(orgFeed) }, expected_output: { verdict: "accept", normalized: { signature_valid: verifyEventSignature(orgFeed), owner: "social", stamp_location: "content.spec_version" } } },
    { path: "profiles/011-comms-negotiation-kind31015.json", vector_id: "profiles/comms-negotiation-kind31015", description: "The active Comms negotiation profile is a complete canonical unsigned rumor with one recipient tag.", direction: "round-trip", input: { rumor: negotiationRumor, canonical_wire: canonicalNip01(negotiationBase) }, expected_output: { verdict: "accept", normalized: { owner: "comms", outer_signature_present: false } } },
    { path: "profiles/012-comms-payload-kind31016.json", vector_id: "profiles/comms-payload-kind31016", description: "The active Comms payload profile is a complete canonical unsigned rumor whose string content carries the Comms stamp.", direction: "round-trip", input: { rumor, canonical_wire: canonicalNip01(rumorBase) }, expected_output: { verdict: "accept", normalized: { owner: "comms", outer_signature_present: false } } },
    { path: "profiles/009-dr-invite-response-kind1059.json", vector_id: "profiles/dr-invite-response-kind1059", description: "A complete deterministic nostr-double-ratchet 0.0.138 kind:1059 invite response is transient relay traffic and never repository storage or backfill.", direction: "round-trip", input: { wire_version: "nostr-double-ratchet/0.0.138", event: inviteResponse, canonical_wire: canonicalNip01(inviteResponse), inviter_ephemeral_private_key: inviterEphemeralPrivateKey, inviter_identity_private_key: senderDevice.private_key, shared_secret: sharedSecret, pinned_nonces: ["61".repeat(32), "62".repeat(32), "63".repeat(32)] }, expected_output: { verdict: "accept", normalized: { invitee_identity: recipientDevice.pubkey, invitee_session_public_key: inviteeSessionPublicKey, owner_public_key: fixtures.personas.bob.cold_root.pubkey, stamp_count: 0, relay_carriage: "transient", repo_storable: false, backfill: false } } },
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
  validateInviteResponseProfileFixture(authored.find(({ vector }) => vector.vector_id === "profiles/dr-invite-response-kind1059")!.vector);
  return authored;
}

export function validateInviteResponseProfileFixture(vector: {
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
}): void {
  const event = vector.input.event as Partial<NostrSignedEvent> | undefined;
  if (event === undefined || event.kind !== 1059 || typeof event.id !== "string" || typeof event.sig !== "string" ||
      typeof event.pubkey !== "string" || typeof event.created_at !== "number" || typeof event.content !== "string" ||
      !Array.isArray(event.tags) || !verifyEventSignature(event as NostrSignedEvent)) {
    throw new Error("kind:1059 fixture must be a complete signed deterministic event");
  }
  const normalized = vector.expected_output.normalized as Record<string, unknown> | undefined;
  if (normalized?.repo_storable !== false || normalized.backfill !== false || normalized.relay_carriage !== "transient") {
    throw new Error("kind:1059 fixture must declare transient relay carriage without repository storage or backfill");
  }
  if (event.tags.length !== 1 || event.tags[0]?.[0] !== "p" || event.tags[0]?.length !== 2) {
    throw new Error("kind:1059 fixture must contain exactly one ephemeral recipient p tag");
  }
  const inviterEphemeralPrivateKey = vector.input.inviter_ephemeral_private_key as string;
  const inviterIdentityPrivateKey = vector.input.inviter_identity_private_key as string;
  const sharedSecret = vector.input.shared_secret as string;
  const outerKey = nip44.v2.utils.getConversationKey(hexToBytes(inviterEphemeralPrivateKey), event.pubkey);
  const innerEvent = JSON.parse(nip44.v2.decrypt(event.content, outerKey)) as { pubkey: string; content: string; created_at: number };
  const dhEncrypted = nip44.v2.decrypt(innerEvent.content, hexToBytes(sharedSecret));
  const identityKey = nip44.v2.utils.getConversationKey(hexToBytes(inviterIdentityPrivateKey), innerEvent.pubkey);
  const payload = JSON.parse(nip44.v2.decrypt(dhEncrypted, identityKey)) as { sessionKey: string; ownerPublicKey?: string };
  if (normalized.invitee_identity !== innerEvent.pubkey || normalized.invitee_session_public_key !== payload.sessionKey || normalized.owner_public_key !== payload.ownerPublicKey) {
    throw new Error("kind:1059 fixture decoded identity/session bytes do not match expected output");
  }
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
    path: "acceptance-gating/001-authentication-before-policy.json",
    vector_id: "acceptance-gating/authentication-before-policy",
    description: "Cryptographic authentication rejects invalid input before the Comms policy hook runs.",
    input: hookInput({ context: "ordinary-dm", authenticated: false, signature_valid: false, policy_would_accept: true }),
    expected_output: { verdict: "reject", reason_code: "bad_signature", normalized: { outcome: "reject", policy_hook_invoked: false } },
  },
  {
    path: "acceptance-gating/002-message-request-no-receipt.json",
    vector_id: "acceptance-gating/message-request-no-receipt",
    description: "A new authenticated DM is held as a message request without sender-observable signals.",
    input: hookInput({ context: "ordinary-dm", established_locally_accepted_session: false, authenticated: true }),
    expected_output: { verdict: "accept", normalized: { outcome: "hold-as-message-request", receipts: 0, typing_signals: 0, retry_hints: 0 } },
  },
  {
    path: "acceptance-gating/003-social-mute-tightens.json",
    vector_id: "acceptance-gating/social-mute-tightens",
    description: "Social mute state may tighten an authenticated Comms acceptance into rejection.",
    input: hookInput({ context: "ordinary-dm", comms_outcome: "accept", authenticated_peer_muted: true }),
    expected_output: { verdict: "accept", normalized: { composed_outcome: "reject", loosened_comms_result: false } },
  },
  {
    path: "acceptance-gating/004-social-policy-cannot-loosen.json",
    vector_id: "acceptance-gating/social-policy-cannot-loosen",
    description: "Social policy cannot turn a Comms rejection into hold or accept.",
    input: hookInput({ context: "ordinary-dm", comms_outcome: "reject", social_policy_outcome: "accept" }),
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
  ...acceptanceCases(),
  ...profileCases(),
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

function acceptanceCases(): Case[] {
  const hold = { outcome: "hold-as-message-request", content_transferred: false, receipts: 0, typing_signals: 0, retry_hints: 0 };
  const epochInvite = "66".repeat(32);
  const staleInvite = "67".repeat(32);
  return [
    ["005-established-ordinary-accept", "established-ordinary-accept", hookInput({ context: "ordinary-dm", authenticated: true, established_locally_accepted_session: true }), { verdict: "accept", normalized: { outcome: "accept" } }],
    ["006-new-ordinary-hold", "new-ordinary-hold", hookInput({ context: "ordinary-dm", authenticated: true, established_locally_accepted_session: false }), { verdict: "accept", normalized: hold }],
    ["007-authentication-reject", "authentication-reject", hookInput({ context: "ordinary-dm", authenticated: false }), { verdict: "reject", reason_code: "bad_signature", normalized: { outcome: "reject" } }],
    ["008-credential-valid-accept", "credential-valid-accept", hookInput({ context: "credential-sync", authenticated: true, credential: { status: "valid", nid_bound: true, subject_matches: true } }), { verdict: "accept", normalized: { outcome: "accept" } }],
    ["009-authoritative-state-unavailable-hold", "authoritative-state-unavailable-hold", hookInput({ context: "credential-sync", authenticated: true, credential: { authoritative_state: "unavailable" } }), { verdict: "accept", normalized: hold }],
    ["010-credential-invalid-reject", "credential-invalid-reject", hookInput({ context: "credential-sync", authenticated: true, credential: { status: "invalid" } }), { verdict: "reject", reason_code: "nid_proof_invalid", normalized: { outcome: "reject" } }],
    ["011-credential-revoked-reject", "credential-revoked-reject", hookInput({ context: "credential-sync", authenticated: true, credential: { status: "revoked" } }), { verdict: "reject", reason_code: "kel_revoked_nid", normalized: { outcome: "reject" } }],
    ["012-credential-expired-reject", "credential-expired-reject", hookInput({ context: "credential-sync", authenticated: true, credential: { status: "expired" } }), { verdict: "reject", reason_code: "expired_delegation", normalized: { outcome: "reject" } }],
    ["013-credential-subject-mismatch-reject", "credential-subject-mismatch-reject", hookInput({ context: "credential-sync", authenticated: true, credential: { subject_matches: false } }), { verdict: "reject", reason_code: "delegation_mismatch", normalized: { outcome: "reject" } }],
    ["014-credential-nidless-reject", "credential-nidless-reject", hookInput({ context: "credential-sync", authenticated: true, credential: { nid_bound: false } }), { verdict: "reject", reason_code: "nid_binding_missing_signature", normalized: { outcome: "reject" } }],
    ["015-control-enrollment-default-hold", "control-enrollment-default-hold", hookInput({ context: "control-enrollment", authenticated: true, explicitly_approved: false }), { verdict: "accept", normalized: hold }],
    [
      "018-control-enrollment-active-invite-gated-hold",
      "control-enrollment-active-invite-gated-hold",
      hookInput({
        context: "control-enrollment",
        authenticated: true,
        active_delegation: false,
        peer_delegation_id: null,
        epoch_invite_event_id: epochInvite,
        current_epoch_invite_event_id: epochInvite,
        epoch_invite_signer_current: true,
        epoch_invite_kel_head_current: true,
        profile_gate_open: false,
      }),
      {
        verdict: "accept",
        normalized: {
          ...hold,
          control_interpretation_allowed: false,
          sender_visible_signals: 0,
        },
      },
    ],
    [
      "019-control-enrollment-stale-invite-reject",
      "control-enrollment-stale-invite-reject",
      hookInput({
        context: "control-enrollment",
        authenticated: true,
        active_delegation: false,
        peer_delegation_id: null,
        epoch_invite_event_id: staleInvite,
        current_epoch_invite_event_id: epochInvite,
        epoch_invite_signer_current: true,
        epoch_invite_kel_head_current: true,
        profile_gate_open: false,
      }),
      {
        verdict: "reject",
        reason_code: "dm_invite_revoked_device",
        normalized: { outcome: "reject", control_interpretation_allowed: false },
      },
    ],
    [
      "020-ordinary-undelegated-reject",
      "ordinary-undelegated-reject",
      hookInput({
        context: "ordinary-dm",
        authenticated: true,
        active_delegation: false,
        peer_delegation_id: null,
        epoch_invite_event_id: epochInvite,
        current_epoch_invite_event_id: epochInvite,
      }),
      {
        verdict: "reject",
        reason_code: "dm_invite_unbound_device",
        normalized: { outcome: "reject" },
      },
    ],
    [
      "021-control-enrollment-tombstoned-invite-reject",
      "control-enrollment-tombstoned-invite-reject",
      hookInput({
        context: "control-enrollment",
        authenticated: true,
        active_delegation: false,
        peer_delegation_id: null,
        epoch_invite_event_id: epochInvite,
        current_epoch_invite_event_id: epochInvite,
        epoch_invite_signer_current: true,
        epoch_invite_kel_head_current: true,
        epoch_invite_tombstoned: true,
        profile_gate_open: false,
      }),
      {
        verdict: "reject",
        reason_code: "dm_invite_revoked_device",
        normalized: { outcome: "reject", control_interpretation_allowed: false },
      },
    ],
    ["016-social-wot-tightens-only", "social-wot-tightens-only", hookInput({ context: "ordinary-dm", authenticated: true, comms_outcome: "accept", social: { follows: false, replied_before: false, trust_distance: 4, overmuted_ratio: 0.75 } }), { verdict: "accept", normalized: { composed_outcome: "hold-as-message-request", loosened_comms_result: false } }],
    ["017-social-wot-cannot-loosen", "social-wot-cannot-loosen", hookInput({ context: "ordinary-dm", authenticated: true, comms_outcome: "reject", social: { follows: true, replied_before: true, trust_distance: 1, overmuted_ratio: 0 } }), { verdict: "accept", normalized: { composed_outcome: "reject", loosened_comms_result: false } }],
  ].map(([file, id, input, expected_output]) => ({
    path: `acceptance-gating/${file}.json`, vector_id: `acceptance-gating/${id}`,
    description: `Closed Comms acceptance outcome: ${String(id).replaceAll("-", " ")}.`,
    input: input as Record<string, unknown>, expected_output: expected_output as Record<string, unknown>,
  }));
}

function hookInput(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    peer_persona_cold_root: "11".repeat(32),
    peer_device_publishing_key: "22".repeat(32),
    peer_delegation_id: "device:bob:1",
    local_recipient_persona: "33".repeat(32),
    target_device_nid: "did:key:z6MkFixtureTarget",
    context: "ordinary-dm",
    session_id: "44".repeat(32),
    transcript_binding: "55".repeat(32),
    protocol_id: "heterodyne-dm",
    requested_features: [],
    active_delegation: true,
    finality: "final",
    revoked: false,
    prior_session_state: "new",
    explicit_user_decision: null,
    ...overrides,
  };
}

function profileCases(): Case[] {
  const tier3Kinds = [1, 6, 16, 1063, 30023, 30402];
  const tier3 = tier3Kinds.map((kind, index): Case => ({
    path: `profiles/${String(index + 3).padStart(3, "0")}-tier3-kind-${kind}.json`,
    vector_id: `profiles/tier3-kind-${kind}`,
    description: `The active Tier-3 kind:${kind} profile uses the exact opaque carrier tags and Comms owner stamp.`,
    direction: "round-trip",
    input: { event_template: { kind, tags: [...(kind >= 30000 ? [["d", `opaque-${kind}`]] : []), ["heterodyne_wrap", "room_key.v2"], ["key_id", "aud-fixture"], ["kel_head", "11".repeat(32), "0"], ["spec_version", "comms/0.5.0"]], content: "AopaqueNIP44fixture" } },
    expected_output: { verdict: "accept", normalized: { owner: "comms", stamp_location: "tag", semantic_cleartext_tags: 0 } },
  }));
  return [
    ...tier3,
  ];
}

function stampCases(): Case[] {
  const values: Array<[string, string, Record<string, unknown>, Record<string, unknown>]> = [
    ["001-heterodyne-json-content-owner", "heterodyne-json-content-owner", { kind: 31003, content_is_heterodyne_json: true, content: { spec_version: "core/0.5.0" } }, { owner: "core", placement: "content.spec_version" }],
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
    ["014-legacy-malformed-not-inferable", "legacy-malformed-not-inferable", { kind: 31001, archived_form_valid: false }, { owner: null, inferable: false }],
    ["015-legacy-post-split-not-inferable", "legacy-post-split-not-inferable", { kind: 31001, archived_form_valid: true, post_split_discriminator: true }, { owner: null, inferable: false }],
    ["016-legacy-profile-only-not-inferable", "legacy-profile-only-not-inferable", { kind: 31001, archived_form_valid: true, profile_only: true }, { owner: null, inferable: false }],
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
