import { getPublicKey } from "./nostr.js";

const TEST_EPOCH = 1767225600;

const key = (n: number) => n.toString(16).padStart(64, "0");

export function buildFixtures() {
  const personas = {
    alice: {
      cold_root: {
        private_key: key(1),
        pubkey: getPublicKey(key(1)),
      },
      epoch_keys: {
        epoch_1: {
          private_key: key(2),
          pubkey: getPublicKey(key(2)),
          valid_from: TEST_EPOCH,
        },
      },
    },
    bob: {
      cold_root: {
        private_key: key(3),
        pubkey: getPublicKey(key(3)),
      },
      epoch_keys: {
        epoch_1: {
          private_key: key(4),
          pubkey: getPublicKey(key(4)),
          valid_from: TEST_EPOCH,
        },
      },
    },
  };

  return {
    vector_schema_version: "1.0.0",
    spec_version: "0.3.0",
    test_epoch: TEST_EPOCH,
    pinned_randomness: {
      schnorr_aux_rand: "00".repeat(32),
      nip44_nonce_policy: "Each vector carries a fixed 32-byte nonce in input.",
    },
    personas,
    matrix_rooms: {
      identity_alice: "!alice-identity:example.org",
      private_broadcast_alice: "!alice-private-broadcast:example.org",
      config_alice: "!alice-config:example.org",
    },
    room_secrets: {
      alice_private_broadcast_v1: {
        matrix_room_id: "!alice-private-broadcast:example.org",
        key_id: "room-secret-2026-05-25-a",
        secret: "10".repeat(32),
      },
    },
    category_keysets: {
      identity: "alice",
      keri: "alice",
      envelope: "alice",
      verification: "alice",
      broadcast: "alice",
      index: "alice",
      relay_interop: "alice",
      config_room: "alice",
      default_peer: "bob",
    },
  };
}

export type Fixtures = ReturnType<typeof buildFixtures>;
