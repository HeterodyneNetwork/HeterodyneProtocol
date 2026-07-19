import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { nip44 } from "nostr-tools";
import { hexToBytes, utf8Bytes, bytesToHex } from "./hex.js";
import { buildDmTranscriptVectors } from "./dm-transcript.js";
import { withKelHead } from "./kel.js";
import { canonicalNip01, signEvent } from "./nostr.js";
import { buildKeriAuthorityWireVectors } from "./topics-keri-authority.js";
import { buildKeriAuthorityBehavioralVectors } from "./topics-keri-authority-b.js";
import { buildKeriAuthorityMaterializedVectors } from "./topics-keri-authority-c.js";
import { buildV04Vectors } from "./topics-v04.js";
import { buildV04bVectors } from "./topics-v04b.js";
import { buildSplitVectors } from "./topics-split.js";
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
  config_room: "§3.8",
  "multi-homing": "§3.9",
  envelope: "§4",
  verification: "§4.5",
  bridge: "§6.4",
  index: "§6.7",
  "room-kind": "§5",
  broadcast: "§5.3",
  outbox: "§7",
  moderation: "§8",
  encryption: "§9",
  "relay-interop": "§10.5",
  "homeserver-exit": "§3.10",
  transport: "§7.7",
  redundancy: "§3.11",
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
  dm: "§5.7",
  "config-backup": "§3.8.6",
  "keri-authority": "§4.5.1",
  "comms-envelope": "heterodyne:comms/0.5.0#comms-envelope",
  "core-redundancy": "heterodyne:core/0.5.0#core-multi-host-seeding",
  "acceptance-gating": "heterodyne:comms/0.5.0#comms-acceptance-hook",
  stamping: "heterodyne:core/0.5.0#core-version-stamps",
  registry: "heterodyne:core/0.5.0#core-registry",
} as const;

export async function buildAllVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const vectors: AuthoredVector[] = [];
  for (const factory of VECTOR_FACTORIES) {
    vectors.push(await factory(fixtures));
  }
  vectors.push(...(await buildV04Vectors(fixtures)));
  vectors.push(...(await buildV04bVectors(fixtures)));
  vectors.push(...buildDmTranscriptVectors(fixtures));
  vectors.push(...(await buildKeriAuthorityWireVectors(fixtures)));
  vectors.push(...buildKeriAuthorityBehavioralVectors(fixtures));
  vectors.push(...(await buildKeriAuthorityMaterializedVectors(fixtures)));
  vectors.push(...buildSplitVectors());
  return vectors;
}

const VECTOR_FACTORIES: VectorFactory[] = [
  async (fixtures) => {
    const persona = fixtures.personas.alice;
    const rootEvent = await signEvent({
      secretKey: persona.epoch_keys.epoch_1.private_key,
      created_at: fixtures.test_epoch,
      kind: 31000,
      tags: withKelHead(
        [
          ["d", ""],
          ["heterodyne", "root"],
          ["cold_root", persona.cold_root.pubkey],
        ],
        fixtures.kel.alice.head,
      ),
      content: "",
      auxRand: AUX_RAND,
    });
    return {
      relativePath: "identity/001-root-attestation-valid.json",
      vector: produceVector({
        vector_id: "identity/root-attestation-valid",
        spec_refs: ["§3.2.1", "§14.1", "§14.5"],
        description: "Matrix-free root attestation: kind:31000 signed by the current epoch key, cold_root tag binds the npub, no matrix_room tag.",
        input: {
          fixture_persona: "alice",
          signer: "epoch_1",
          aux_rand: AUX_RAND,
          event_template: withoutSig(rootEvent),
        },
        expected_output: {
          canonical_wire: canonicalNip01(rootEvent),
          decoded: rootEvent,
          id: rootEvent.id,
          sig: rootEvent.sig,
        },
        notes: "Per §3.2.1 the root attestation is epoch-key-signed (the cold root is never brought online for it) and the matrix_room tag is omitted for a Matrix-free persona.",
      }),
    };
  },
  consume("keri/001-informal-vouch-not-counted.json", {
    vector_id: "keri/informal-vouch-not-counted",
    spec_refs: ["§3.5", "§3.12", "§14.3"],
    description: "A rotation that reaches threshold only by counting kind:31008 informal vouches is rejected.",
    input: {
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
  consume("config_room/001-device-inventory-not-synced.json", {
    vector_id: "config_room/device-inventory-not-synced",
    spec_refs: ["§3.8", "§14.3"],
    description: "Cross-MXID config sync includes portable config but leaves device_inventory room-local.",
    input: {
      source_room: "!alice-config-a:example.org",
      target_room: "!alice-config-b:example.org",
      state_events: ["persona_config", "user_prefs", "key_backup", "device_inventory"],
    },
    expected_output: {
      verdict: "accept",
      normalized: {
        synced_types: ["persona_config", "user_prefs", "key_backup"],
        room_local_types: ["device_inventory"],
      },
    },
  }),
  consume("multi-homing/001-active-room-election.json", {
    vector_id: "multi-homing/active-room-election",
    spec_refs: ["§3.9", "§14.3"],
    description: "Active config room election uses lexicographically minimum election_id as tie-breaker.",
    input: {
      candidates: [
        { room_id: "!config-a:example.org", lease_epoch: 9, election_id: "b" },
        { room_id: "!config-b:example.org", lease_epoch: 9, election_id: "a" },
      ],
    },
    expected_output: {
      verdict: "accept",
      normalized: { active_room_id: "!config-b:example.org" },
    },
  }),
  async (fixtures) => {
    const epoch = fixtures.personas.alice.epoch_keys.epoch_1;
    const inner = await signEvent({
      secretKey: epoch.private_key,
      created_at: fixtures.test_epoch + 10,
      kind: 1,
      tags: withKelHead([["client", "heterodyne"]], fixtures.kel.alice.head),
      content: "hello from a wrapped Heterodyne post",
      auxRand: AUX_RAND,
    });
    return {
      relativePath: "envelope/001-minimal-kind1-wrapped.json",
      vector: produceVector({
        vector_id: "envelope/minimal-kind1-wrapped",
        spec_refs: ["§4", "§14.1", "§14.3"],
        description: "Minimal wrapped kind:1 carries nip01_raw matching the signed inner event.",
        input: {
          fixture_persona: "alice",
          inner_event_template: withoutSig(inner),
          aux_rand: AUX_RAND,
        },
        expected_output: {
          canonical_wire: canonicalNip01(inner),
          decoded: {
            matrix_content: {
              msgtype: "m.text",
              body: inner.content,
              "m.heterodyne.nostr": {
                id: inner.id,
                pubkey: inner.pubkey,
                sig: inner.sig,
                nip01_raw: canonicalNip01(inner),
              },
            },
            event: inner,
          },
          id: inner.id,
          sig: inner.sig,
        },
      }),
    };
  },
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
  consume("bridge/001-nostr-permanent-failure-index-not-updated.json", {
    vector_id: "bridge/nostr-permanent-failure-index-not-updated",
    spec_refs: ["§6.4", "§10.5", "§14.3"],
    description: "A permanent relay write failure prevents updating the kind:31007 feed index.",
    input: {
      nostr_write: { status: "rejected", notice_prefix: "blocked:" },
      matrix_write: { status: "ok", event_id: "$matrix-event" },
      prior_index_ids: ["nostr:prev"],
      candidate_event_id: "nostr:new",
    },
    expected_output: {
      verdict: "accept",
      normalized: {
        index_updated: false,
        partial_failure: "nostr_permanent",
      },
      warnings: ["destination_out_of_sync"],
    },
  }),
  encryptedIndexVector,
  consume("room-kind/001-retired-kind-rejected.json", {
    vector_id: "room-kind/retired-kind-rejected",
    spec_refs: ["§5", "§14.3"],
    description: "A newly-created room asserting a retired pre-ADR-017 kind is rejected.",
    input: {
      room_state: { room_kind: "private_verifiable", created_at: 1767225600, legacy: false },
    },
    expected_output: {
      verdict: "reject",
      reason_code: "retired_room_kind",
    },
  }),
  encryptedBroadcastVector,
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
    description: "A contributor submission remains pending until the implicit-rejection window elapses.",
    input: {
      submitted_at: 1767225600,
      simulated_clock: 1767227400,
      approval_events: [],
      implicit_rejection_seconds: 3600,
    },
    expected_output: {
      verdict: "accept",
      normalized: { moderation_state: "pending" },
    },
    simulated_clock: 1767227400,
  }),
  consume("moderation/strict-mode/001-invalid-broadcast-signature.json", {
    vector_id: "moderation/strict-mode-invalid-broadcast-signature",
    spec_refs: ["§11.7", "§14.3", "§14.5"],
    description: "Strict mode rejects the invalid broadcast signature that base mode only warns about.",
    input: {
      same_input_id: "broadcast-invalid-signature-fixture",
      mode: "strict",
    },
    expected_output: {
      verdict: "reject",
      reason_code: "bad_signature",
    },
    notes: "Base-mode companion outcome is warnings:[\"invalid_broadcast_signature\"] for the same input.",
  }),
  consume("encryption/001-delegation-revocation-rotation.json", {
    vector_id: "encryption/delegation-revocation-rotation",
    spec_refs: ["§9", "§14.3"],
    description: "Delegation revocation triggers the documented room-secret rotation SHOULD path.",
    input: {
      revoked_mxid: "@old-device:example.org",
      active_key_id: "room-secret-2026-05-25-a",
      next_key_id: "room-secret-2026-05-25-b",
    },
    expected_output: {
      verdict: "accept",
      normalized: { rotation_recommended: true, next_key_id: "room-secret-2026-05-25-b" },
      warnings: ["should_rotate_room_secret"],
    },
  }),
  consume("encryption/mls-migration/001-missing-ack-aborts.json", {
    vector_id: "encryption/mls-migration-missing-ack-aborts",
    spec_refs: ["§9.2", "§14.3"],
    description: "MLS migration aborts if any eligible receiver fails to ACK intent.",
    input: {
      eligible_receivers: ["@a:example.org", "@b:example.org"],
      acked_receivers: ["@a:example.org"],
    },
    expected_output: {
      verdict: "reject",
      reason_code: "mls_missing_ack",
    },
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
          decoded: auth,
          id: auth.id,
          sig: auth.sig,
        },
      }),
    };
  },
  consume("homeserver-exit/001-migration-pointer-precedence.json", {
    vector_id: "homeserver-exit/migration-pointer-precedence",
    spec_refs: ["§3.10", "§14.3"],
    description: "Identity-room migration pointer takes precedence over a stale kind:31005 pointer.",
    input: {
      stale_kind31005_room: "!old:example.org",
      migration_event: { old_room: "!old:example.org", new_room: "!new:example.org" },
    },
    expected_output: {
      verdict: "reject",
      reason_code: "homeserver_exit_stale_pointer",
      normalized: { authoritative_room: "!new:example.org" },
    },
  }),
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
    transport_context: { adapter_boundary: "matrix_to_protocol" },
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
  consume("redundancy/001-dedupe-across-replicas.json", {
    vector_id: "redundancy/dedupe-across-replicas",
    spec_refs: ["§3.11", "§14.3"],
    description: "Replica rooms deduplicate the same relay-borne private broadcast by Nostr event id.",
    input: {
      replicas: [
        { room_id: "!primary:example.org", nostr_event_id: "aa".repeat(32) },
        { room_id: "!replica:example.org", nostr_event_id: "aa".repeat(32) },
      ],
    },
    expected_output: {
      verdict: "accept",
      normalized: { unique_event_ids: ["aa".repeat(32)], duplicate_count: 1 },
    },
  }),
  consume("social-recovery/001-cache-rejects-unauthorized-content.json", {
    vector_id: "social-recovery/cache-rejects-unauthorized-content",
    spec_refs: ["§3.12", "§14.3"],
    description: "Friend cache rejects non-owner-signed non-KERI identity-room content.",
    input: {
      cached_event: { type: "m.room.topic", signed_by_owner: false, keri_event: false },
    },
    expected_output: {
      verdict: "reject",
      reason_code: "unauthorized_cache_content",
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
  async (fixtures) => {
    const epoch = fixtures.personas.alice.epoch_keys.epoch_1;
    const event = await signEvent({
      secretKey: epoch.private_key,
      created_at: fixtures.test_epoch + 30,
      kind: 1,
      tags: withKelHead([["client", "heterodyne"]], fixtures.kel.alice.head),
      content: "round trip through a vanilla relay",
      auxRand: AUX_RAND,
    });
    return {
      relativePath: "interop/001-wrapped-vanilla-roundtrip.json",
      vector: {
        ...baseVector({
          vector_id: "interop/wrapped-vanilla-roundtrip",
          spec_refs: ["§11", "§14.1", "§14.3", "§14.5"],
          description: "Wrapped event round-trips through vanilla Nostr preserving NIP-01 canonical serialization.",
          direction: "round-trip",
          input: {
            fixture_persona: "alice",
            relay_frame: ["EVENT", "subscription-1", event],
          },
          expected_output: {
            comparison_surface: "nip01_canonical_event_serialization",
            canonical_wire: canonicalNip01(event),
            decoded: event,
            id: event.id,
            sig: event.sig,
          },
        }),
      },
    };
  },
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

async function encryptedIndexVector(fixtures: Fixtures): Promise<AuthoredVector> {
  const secret = fixtures.room_secrets.alice_private_broadcast_v1;
  const roomKey = hkdf(
    sha256,
    hexToBytes(secret.secret),
    utf8Bytes(secret.matrix_room_id),
    utf8Bytes("heterodyne-index-key-v1"),
    32,
  );
  const nonce = hexToBytes("20".repeat(32));
  const plaintext = JSON.stringify({
    room_id: secret.matrix_room_id,
    key_id: secret.key_id,
    entries: [{ event_id: "cd".repeat(32), relay: "wss://relay.example.org" }],
  });
  const payload = nip44.v2.encrypt(plaintext, roomKey, nonce);
  return {
    relativePath: "index/001-room-key-wrap-encryption.json",
    vector: produceVector({
      vector_id: "index/room-key-wrap-encryption",
      spec_refs: ["§6.7", "§14.3", "§14.5"],
      description: "Private feed index content encrypts under HKDF(room_secret, room_id, heterodyne-index-key-v1).",
      input: {
        fixture_room_secret: "alice_private_broadcast_v1",
        hkdf: {
          salt: secret.matrix_room_id,
          info: "heterodyne-index-key-v1",
          output_len: 32,
        },
        nip44_nonce: bytesToHex(nonce),
        plaintext,
      },
      expected_output: {
        canonical_wire: payload,
        decoded: {
          key_id: secret.key_id,
          matrix_room_id: secret.matrix_room_id,
          room_key: bytesToHex(roomKey),
          plaintext: JSON.parse(plaintext) as unknown,
          nip44_payload: payload,
        },
      },
      notes: "Megolm transport ciphertext is intentionally out of scope; this vector starts at decrypted Matrix payload hand-off.",
    }),
  };
}

async function encryptedBroadcastVector(fixtures: Fixtures): Promise<AuthoredVector> {
  const secret = fixtures.room_secrets.alice_private_broadcast_v1;
  const epoch = fixtures.personas.alice.epoch_keys.epoch_1;
  const postKey = hkdf(
    sha256,
    hexToBytes(secret.secret),
    utf8Bytes(secret.matrix_room_id),
    utf8Bytes("heterodyne-private-broadcast-post-key-v1"),
    32,
  );
  const nonce = hexToBytes("30".repeat(32));
  const cleartext = JSON.stringify({
    body: "private broadcast body",
    matrix_room_id: secret.matrix_room_id,
    key_id: secret.key_id,
  });
  const ciphertext = nip44.v2.encrypt(cleartext, postKey, nonce);
  const event = await signEvent({
    secretKey: epoch.private_key,
    created_at: fixtures.test_epoch + 15,
    kind: 1,
    tags: withKelHead(
      [
        ["heterodyne_wrap", "room_key.v2"],
        ["key_id", secret.key_id],
        ["matrix_room_id", secret.matrix_room_id],
      ],
      fixtures.kel.alice.head,
    ),
    content: ciphertext,
    auxRand: AUX_RAND,
  });
  return {
    relativePath: "broadcast/001-private-broadcast-wrapped.json",
    vector: produceVector({
      vector_id: "broadcast/private-broadcast-wrapped",
      spec_refs: ["§5.3", "§6.10", "§6.7.4", "§14.1", "§14.3", "§14.5"],
      description: "OPTIONAL Matrix-hosted audience: a private broadcast post NIP-44-wrapped under the Matrix room-secret-derived post key, then signed. Matrix-shaped; the CORE Tier 3 wrap is in privacy-tiers/.",
      input: {
        fixture_room_secret: "alice_private_broadcast_v1",
        fixture_persona: "alice",
        signer: "epoch_1",
        hkdf: {
          salt: secret.matrix_room_id,
          info: "heterodyne-private-broadcast-post-key-v1",
          output_len: 32,
        },
        nip44_nonce: bytesToHex(nonce),
        cleartext,
      },
      expected_output: {
        canonical_wire: canonicalNip01(event),
        decoded: {
          event,
          post_key: bytesToHex(postKey),
          cleartext: JSON.parse(cleartext) as unknown,
          nip44_payload: ciphertext,
        },
        id: event.id,
        sig: event.sig,
      },
      notes: "Megolm transport is opaque; this vector validates the room-secret to NIP-44 post chain and context binding to matrix_room_id.",
    }),
  };
}

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
      input: { event_type: "inception", sequence: 0, witness_threshold: 1, witnesses: ["did:key:z6Mkwitness"] },
      expected_output: { verdict: "accept", normalized: { kel_sequence: 0, witness_threshold: 1 } },
    },
  },
  {
    relativePath: "keri/003-rotation-committed-strategy.json",
    vector: {
      vector_id: "keri/rotation-committed-strategy",
      spec_refs: ["§3.5", "§14.3"],
      description: "Committed-strategy rotation is accepted when it advances sequence and satisfies witnesses.",
      input: { event_type: "rotation", sequence: 1, strategy: "committed", witness_receipts: 2, threshold: 2 },
      expected_output: { verdict: "accept", normalized: { current_epoch_sequence: 1 } },
    },
  },
  {
    relativePath: "keri/004-rotation-none-witness-threshold.json",
    vector: {
      vector_id: "keri/rotation-none-witness-threshold",
      spec_refs: ["§3.5", "§14.3"],
      description: "None-strategy rotation is accepted only with the configured witness threshold.",
      input: { event_type: "rotation", sequence: 1, strategy: "none", witness_receipts: 3, threshold: 3 },
      expected_output: { verdict: "accept", normalized: { witness_threshold_satisfied: true } },
    },
  },
  {
    relativePath: "keri/005-first-seen-ordering.json",
    vector: {
      vector_id: "keri/first-seen-ordering",
      spec_refs: ["§3.5", "§14.3"],
      description: "First-seen ordering picks the rotation first observed by each witness.",
      input: { witness_observations: [{ witness: "w1", first_seen: "rotation-a" }, { witness: "w2", first_seen: "rotation-a" }] },
      expected_output: { verdict: "accept", normalized: { accepted_rotation: "rotation-a" } },
    },
  },
  {
    relativePath: "keri/006-fork-resolution-conflicting-rotations.json",
    vector: {
      vector_id: "keri/fork-resolution-conflicting-rotations",
      spec_refs: ["§3.5", "§14.3"],
      description: "Conflicting rotations resolve according to witness first-seen evidence.",
      input: { rotations: ["rotation-a", "rotation-b"], first_seen_winner: "rotation-b" },
      expected_output: { verdict: "accept", normalized: { accepted_rotation: "rotation-b", rejected_rotation: "rotation-a" } },
    },
  },
  {
    relativePath: "keri/007-didkey-witness-no-network.json",
    vector: {
      vector_id: "keri/didkey-witness-no-network",
      spec_refs: ["§3.5", "§14.3"],
      description: "did:key witness verification uses the embedded key and performs no network resolution.",
      input: { witness: "did:key:z6Mkwitness", network_resolution_attempts: 0 },
      expected_output: { verdict: "accept", normalized: { didkey_verified_locally: true } },
    },
  },
  {
    relativePath: "config_room/002-minimal-config-room.json",
    vector: {
      vector_id: "config_room/minimal-config-room",
      spec_refs: ["§3.8", "§14.3"],
      description: "Minimal config room contains the required persona config anchor.",
      input: { room_id: "!alice-config:example.org", state_types: ["persona_config"] },
      expected_output: { verdict: "accept", normalized: { minimal_config_room: true } },
    },
  },
  {
    relativePath: "config_room/003-private-mutes.json",
    vector: {
      vector_id: "config_room/private-mutes",
      spec_refs: ["§3.8", "§14.3"],
      description: "Persona config stores private mute entries without publishing them to relays.",
      input: { muted_npubs: ["npub-muted"], relay_publication_attempts: 0 },
      expected_output: { verdict: "accept", normalized: { private_mutes_count: 1 } },
    },
  },
  {
    relativePath: "config_room/004-key-backup-wrapping-algorithms.json",
    vector: {
      vector_id: "config_room/key-backup-wrapping-algorithms",
      spec_refs: ["§3.8", "§14.3"],
      description: "Key backup records preserve their declared wrapping algorithm.",
      input: { backups: [{ algorithm: "m.megolm_backup.v1" }, { algorithm: "heterodyne.room_secret_wrap.v1" }] },
      expected_output: { verdict: "accept", normalized: { wrapping_algorithms: ["m.megolm_backup.v1", "heterodyne.room_secret_wrap.v1"] } },
    },
  },
  {
    relativePath: "multi-homing/002-publish-lease-acquire-renew.json",
    vector: {
      vector_id: "multi-homing/publish-lease-acquire-renew",
      spec_refs: ["§3.9", "§14.3"],
      description: "Publish lease acquisition and renewal preserve a single active writer.",
      input: { holder: "@alice-a:example.org", renew_before_seconds: 30, competing_holders: [] },
      expected_output: { verdict: "accept", normalized: { lease_holder: "@alice-a:example.org", renewed: true } },
    },
  },
  {
    relativePath: "multi-homing/003-single-mxid-revocation.json",
    vector: {
      vector_id: "multi-homing/single-mxid-revocation",
      spec_refs: ["§3.9", "§14.3"],
      description: "Revoking one MXID removes only that MXID from the multi-homed persona set.",
      input: { revoked_mxid: "@alice-old:example.org", remaining_mxids: ["@alice-new:example.org"] },
      expected_output: { verdict: "accept", normalized: { active_mxids: ["@alice-new:example.org"] } },
    },
  },
  {
    relativePath: "multi-homing/004-kind31005-race-tiebreaker.json",
    vector: {
      vector_id: "multi-homing/kind31005-race-tiebreaker",
      spec_refs: ["§3.9.8", "§14.3"],
      description: "OPTIONAL Matrix corroboration of the kind:31005 tiebreaker via KERI witness counts; the CORE Matrix-free tiebreaker lives in identity/ (§3.9.8).",
      input: { candidates: [{ id: "a", witness_count: 1 }, { id: "b", witness_count: 2 }] },
      expected_output: { verdict: "accept", normalized: { accepted_pointer: "b" } },
    },
  },
  {
    relativePath: "multi-homing/005-partition-window-void-requeue.json",
    vector: {
      vector_id: "multi-homing/partition-window-void-requeue",
      spec_refs: ["§3.9", "§14.3"],
      description: "Writes made under a voided partition-window lease are requeued after partition heal.",
      input: { partition_window: true, lease_voided: true, pending_writes: ["post-1"] },
      expected_output: { verdict: "accept", normalized: { requeued_writes: ["post-1"] } },
    },
  },
  {
    relativePath: "envelope/002-bare-dm-signature-badge.json",
    vector: {
      vector_id: "envelope/bare-dm-signature-badge",
      spec_refs: ["§4", "§14.3"],
      description: "Bare DM with heterodyne_nostr_sig renders a verifiable signature badge.",
      input: { msgtype: "m.text", heterodyne_nostr_sig: "present" },
      expected_output: { verdict: "accept", normalized: { signature_badge: "verified" } },
    },
  },
  {
    relativePath: "envelope/003-fallback-rendering.json",
    vector: {
      vector_id: "envelope/fallback-rendering",
      spec_refs: ["§4", "§14.3"],
      description: "Fallback rendering exposes a usable body when Heterodyne metadata is ignored.",
      input: { body: "fallback text", heterodyne_metadata_present: true },
      expected_output: { verdict: "accept", normalized: { fallback_body: "fallback text" } },
    },
  },
  {
    relativePath: "envelope/004-cross-kind-wrapping.json",
    vector: {
      vector_id: "envelope/cross-kind-wrapping",
      spec_refs: ["§4", "§14.3"],
      description: "Wrapping rules apply consistently to kind 1, reaction kind 7, and long-form kind 30023.",
      input: { nostr_kinds: [1, 7, 30023] },
      expected_output: { verdict: "accept", normalized: { wrapped_kinds: [1, 7, 30023] } },
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
    relativePath: "bridge/002-matrix-permanent-failure-index-updated.json",
    vector: {
      vector_id: "bridge/matrix-permanent-failure-index-updated",
      spec_refs: ["§6.4", "§14.3"],
      description: "Matrix permanent failure leaves relay index updated and surfaces Matrix-out-of-sync warning.",
      input: { nostr_write: { status: "ok" }, matrix_write: { status: "permanent_failure", http_status: 403 } },
      expected_output: { verdict: "accept", normalized: { index_updated: true }, warnings: ["matrix_out_of_sync"] },
    },
  },
  {
    relativePath: "bridge/003-idempotent-republication.json",
    vector: {
      vector_id: "bridge/idempotent-republication",
      spec_refs: ["§6.4", "§14.3"],
      description: "Re-publication after a transient failure reuses the original Nostr event id.",
      input: { first_event_id: "ab".repeat(32), retry_event_id: "ab".repeat(32) },
      expected_output: { verdict: "accept", normalized: { idempotent_republish: true } },
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
    relativePath: "index/004-context-binding-mismatch.json",
    vector: {
      vector_id: "index/context-binding-mismatch",
      spec_refs: ["§6.7", "§14.5"],
      description: "Index ciphertext derived with the wrong Matrix room salt rejects.",
      input: { expected_room_id: "!room-a:example.org", derived_with_room_id: "!room-b:example.org" },
      expected_output: { verdict: "reject", reason_code: "context_binding_mismatch" },
    },
  },
  {
    relativePath: "room-kind/002-current-kinds-roundtrip.json",
    vector: {
      vector_id: "room-kind/current-kinds-roundtrip",
      spec_refs: ["§5", "§14.3"],
      description: "Four social kinds plus identity_room and config_room round-trip.",
      input: { room_kinds: ["public_broadcast", "private_broadcast", "public_discussion", "private_discussion", "identity_room", "config_room"] },
      expected_output: { verdict: "accept", normalized: { round_tripped_count: 6 } },
    },
  },
  {
    relativePath: "room-kind/003-legacy-read-back-map.json",
    vector: {
      vector_id: "room-kind/legacy-read-back-map",
      spec_refs: ["§5", "§14.3"],
      description: "Legacy room kinds map to current kinds with a legacy indicator.",
      input: { legacy_kinds: ["public_moderated", "private_verifiable", "dm_verifiable", "dm_deniable"] },
      expected_output: { verdict: "accept", normalized: { legacy_indicator: true, mapped_count: 4 } },
    },
  },
  {
    relativePath: "broadcast/002-member-decrypts.json",
    vector: {
      vector_id: "broadcast/member-decrypts",
      spec_refs: ["§5.3", "§6.10", "§14.3"],
      description: "Room member with the active room secret decrypts the private broadcast body.",
      input: { member_has_room_secret: true, key_id: "room-secret-2026-05-25-a" },
      expected_output: { verdict: "accept", normalized: { decrypted: true } },
    },
  },
  {
    relativePath: "broadcast/003-non-member-cannot-decrypt.json",
    vector: {
      vector_id: "broadcast/non-member-cannot-decrypt",
      spec_refs: ["§5.3", "§6.10", "§14.3"],
      description: "Non-member without the room secret cannot decrypt the private broadcast body.",
      input: { member_has_room_secret: false, key_id: "room-secret-2026-05-25-a" },
      expected_output: { verdict: "reject", reason_code: "context_binding_mismatch" },
    },
  },
  {
    relativePath: "broadcast/004-reaction-reply-bare-not-indexed.json",
    vector: {
      vector_id: "broadcast/reaction-reply-bare-not-indexed",
      spec_refs: ["§5.3", "§6.10", "§14.3"],
      description: "Reaction/reply remains bare in-room and is not added to the relay feed index.",
      input: { event_kind: 7, relation: "reaction", candidate_for_index: true },
      expected_output: { verdict: "accept", normalized: { indexed: false, in_room_bare: true } },
    },
  },
  {
    relativePath: "broadcast/005-nip59-rejected.json",
    vector: {
      vector_id: "broadcast/nip59-rejected",
      spec_refs: ["§5.3", "§6.10", "§14.3"],
      description: "NIP-59 gift-wrapped broadcast posts are rejected.",
      input: { event_kind: 1059, claimed_room_kind: "private_broadcast" },
      expected_output: { verdict: "reject", reason_code: "nip59_broadcast_rejected" },
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
      description: "Valid cross-persona attestation links a secondary persona to the root persona.",
      input: { attester: "alice", subject: "alice-work", signature_valid: true },
      expected_output: { verdict: "accept", normalized: { cross_persona_attested: true } },
    },
  },
  {
    relativePath: "outbox/005-cross-persona-attestation-invalid.json",
    vector: {
      vector_id: "outbox/cross-persona-attestation-invalid",
      spec_refs: ["§7", "§14.3"],
      description: "Invalid cross-persona attestation is rejected.",
      input: { attester: "alice", subject: "mallory", signature_valid: false },
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
      description: "Strict mode observes kind:5 deletion within 30 seconds.",
      input: { deletion_kind: 5, observed_after_seconds: 25 },
      expected_output: { verdict: "accept", normalized: { deletion_observed_within_30s: true } },
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
    relativePath: "encryption/002-encryption-version-event.json",
    vector: {
      vector_id: "encryption/encryption-version-event",
      spec_refs: ["§9", "§14.3"],
      description: "encryption_version event declares the active encrypted-room protocol generation.",
      input: { state_type: "m.heterodyne.encryption_version.v1", version: "megolm-v1" },
      expected_output: { verdict: "accept", normalized: { encryption_version: "megolm-v1" } },
    },
  },
  {
    relativePath: "encryption/mls-migration/002-eligibility-check.json",
    vector: {
      vector_id: "encryption/mls-migration-eligibility-check",
      spec_refs: ["§9.2", "§14.3"],
      description: "MLS migration eligibility requires all receivers to advertise MLS support.",
      input: { receivers: [{ mxid: "@a", mls: true }, { mxid: "@b", mls: true }] },
      expected_output: { verdict: "accept", normalized: { eligible: true } },
    },
  },
  {
    relativePath: "encryption/mls-migration/003-intent-and-ack.json",
    vector: {
      vector_id: "encryption/mls-migration-intent-and-ack",
      spec_refs: ["§9.2", "§14.3"],
      description: "MLS migration intent is accepted after all eligible receivers ACK.",
      input: { intent_id: "mls-intent-1", eligible: ["@a", "@b"], acked: ["@a", "@b"] },
      expected_output: { verdict: "accept", normalized: { intent_acked: true } },
    },
  },
  {
    relativePath: "encryption/mls-migration/004-receiver-verifiable-flip.json",
    vector: {
      vector_id: "encryption/mls-migration-receiver-verifiable-flip",
      spec_refs: ["§9.2", "§14.3"],
      description: "Receiver verifies the MLS flip event encrypted under the last Megolm key.",
      input: { flip_event_encrypted_with: "last_megolm_key", receiver_has_last_key: true },
      expected_output: { verdict: "accept", normalized: { flip_verified: true } },
    },
  },
  {
    relativePath: "encryption/mls-migration/005-tail-period-acceptance.json",
    vector: {
      vector_id: "encryption/mls-migration-tail-period-acceptance",
      spec_refs: ["§9.2", "§14.3"],
      description: "Pre-flip-keyed Megolm events are accepted during the 60-second tail period.",
      input: { seconds_after_flip: 45, keyed_pre_flip: true },
      expected_output: { verdict: "accept", normalized: { accepted_in_tail_period: true } },
    },
  },
  {
    relativePath: "encryption/mls-migration/006-offline-reconnect-reencrypt.json",
    vector: {
      vector_id: "encryption/mls-migration-offline-reconnect-reencrypt",
      spec_refs: ["§9.2", "§14.3"],
      description: "Offline receiver reconnect causes re-encryption while preserving Nostr event id.",
      input: { original_event_id: "de".repeat(32), reencrypted_event_id: "de".repeat(32) },
      expected_output: { verdict: "accept", normalized: { nostr_event_id_reused: true } },
    },
  },
  {
    relativePath: "encryption/mls-migration/007-non-mls-receiver-fallback.json",
    vector: {
      vector_id: "encryption/mls-migration-non-mls-receiver-fallback",
      spec_refs: ["§9.2", "§14.3"],
      description: "Non-MLS receiver falls back rather than forcing migration.",
      input: { receiver_mls_supported: false },
      expected_output: { verdict: "accept", normalized: { fallback_path: "megolm" } },
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
    relativePath: "homeserver-exit/002-identity-room-migration.json",
    vector: {
      vector_id: "homeserver-exit/identity-room-migration",
      spec_refs: ["§3.10", "§14.3"],
      description: "Identity-room migration event points followers to the replacement room.",
      input: { old_room: "!old:example.org", new_room: "!new:example.org", migration_event_valid: true },
      expected_output: { verdict: "accept", normalized: { authoritative_room: "!new:example.org" } },
    },
  },
  {
    relativePath: "homeserver-exit/003-dual-publish-during-exit.json",
    vector: {
      vector_id: "homeserver-exit/dual-publish-during-exit",
      spec_refs: ["§3.10", "§14.3"],
      description: "KERI rotation during exit window is dual-published to old and new rooms.",
      input: { exit_window_active: true, published_rooms: ["!old:example.org", "!new:example.org"] },
      expected_output: { verdict: "accept", normalized: { dual_published: true } },
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
    relativePath: "redundancy/002-mirror-group-primary-replicas.json",
    vector: {
      vector_id: "redundancy/mirror-group-primary-replicas",
      spec_refs: ["§3.11", "§14.3"],
      description: "mirror_group contains one primary and declared replicas.",
      input: { primary: "!primary:example.org", replicas: ["!replica-a:example.org", "!replica-b:example.org"] },
      expected_output: { verdict: "accept", normalized: { replica_count: 2 } },
    },
  },
  {
    relativePath: "redundancy/003-promotion-republishes-pointer.json",
    vector: {
      vector_id: "redundancy/promotion-republishes-pointer",
      spec_refs: ["§3.11", "§14.3"],
      description: "Replica promotion republishes cold-root kind:31005 and updates mirror_group.",
      input: { promoted_room: "!replica-a:example.org", kind31005_republished: true, mirror_group_updated: true },
      expected_output: { verdict: "accept", normalized: { promoted: true } },
    },
  },
  {
    relativePath: "redundancy/004-private-body-relay-borne.json",
    vector: {
      vector_id: "redundancy/private-body-relay-borne",
      spec_refs: ["§3.11", "§14.3"],
      description: "Private broadcast body remains relay-borne and is not duplicated per mirror room.",
      input: { body_storage: "relay", per_room_body_copies: 0 },
      expected_output: { verdict: "accept", normalized: { duplicated_per_room: false } },
    },
  },
  {
    relativePath: "redundancy/005-rekey-remove-not-join.json",
    vector: {
      vector_id: "redundancy/rekey-remove-not-join",
      spec_refs: ["§3.11", "§14.3"],
      description: "Mirror group rekeys on member removal but not on join.",
      input: { event: "member_removed", rekey_performed: true },
      expected_output: { verdict: "accept", normalized: { rekey_required: true } },
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
      description: "Cold-root kind:31005 re-anchor is authoritative over friend-cache fallback.",
      input: { cold_root_pointer: "!new:example.org", cache_pointer: "!old:example.org" },
      expected_output: { verdict: "accept", normalized: { authoritative_pointer: "!new:example.org" } },
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
    relativePath: "interop/002-bare-hide-pref.json",
    vector: {
      vector_id: "interop/bare-hide-pref",
      spec_refs: ["§11", "§14.3"],
      description: "Bare Matrix event respects the user's hide-bare preference.",
      input: { bare_event: true, hide_bare_preference: true },
      expected_output: { verdict: "accept", normalized: { rendered: false } },
    },
  },
  {
    relativePath: "interop/003-vanilla-nostr-only-follow.json",
    vector: {
      vector_id: "interop/vanilla-nostr-only-follow",
      spec_refs: ["§11", "§14.3"],
      description: "Vanilla-Nostr-only follow remains readable without Matrix room participation.",
      input: { follower_capabilities: ["nip01"], matrix_joined: false },
      expected_output: { verdict: "accept", normalized: { follow_readable_via_nostr: true } },
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
