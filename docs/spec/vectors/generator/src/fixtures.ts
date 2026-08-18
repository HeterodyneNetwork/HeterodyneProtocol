import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { QUALIFIED_VERSION } from "./family.js";
import { inceptionTemplate } from "./kel.js";
import { getEventId, getPublicKey } from "./nostr.js";
import { didKeyFromEd25519, ed25519PublicKey, fixtureRid } from "./radicle.js";
import { loadRegistry } from "./registry.js";

const TEST_EPOCH = 1767225600;
export const CURRENT_REGISTRY_SHA256 = loadRegistry(resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../registry",
)).manifest.entry_set_sha256;

const key = (n: number) => n.toString(16).padStart(64, "0");

function nid(secret: string) {
  const publicKey = ed25519PublicKey(secret);
  return { private_key: secret, public_key: publicKey, did_key: didKeyFromEd25519(publicKey) };
}

function secp(secret: string) {
  return { private_key: secret, pubkey: getPublicKey(secret) };
}

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
    carol: {
      cold_root: {
        private_key: key(8),
        pubkey: getPublicKey(key(8)),
      },
      epoch_keys: {
        epoch_1: {
          private_key: key(9),
          pubkey: getPublicKey(key(9)),
          valid_from: TEST_EPOCH,
        },
      },
    },
  };

  // Ed25519 Radicle NIDs (Core delegation targets). Each device also
  // carries a secp256k1 publishing key; one kind:31001 binds both to a persona.
  const ed25519_nids = {
    alice_device_1: nid(key(0xa1)),
    alice_device_2: nid(key(0xa2)),
    bob_device_1: nid(key(0xb1)),
  };

  const device_publishing_keys = {
    alice_device_1: secp(key(5)),
    alice_device_2: secp(key(6)),
    bob_device_1: secp(key(7)),
  };

  // Deterministic fixture RIDs (rad:z...). Not derived from a live repo.
  const radicle_rids = {
    alice: fixtureRid("alice"),
    alice_reanchor: fixtureRid("alice-reanchor"),
    org_acme: fixtureRid("org-acme"),
  };

  // Tier 3 audience keys (32-byte HKDF ikm) and their opaque key_id
  // generations. gen_b is the post-removal rotation of gen_a.
  const audience_keys = {
    alice_tier3_gen_a: { key_id: "aud-2026-05-25-a", key: "40".repeat(32) },
    alice_tier3_gen_b: { key_id: "aud-2026-05-25-b", key: "41".repeat(32) },
  };

  // Per-persona KEL head. Each persona's KEL here is a single
  // committed inception (kind:31002, §3.5.1) with no witnesses; its id is the
  // head every epoch-key-signed event's kel_head tag references (§3.0, §4.5.1).
  // The inception_event is the unsigned NIP-01 template; its id is over that
  // serialization, so it is stable whether or not the cold-root signature is
  // attached (signatures are exercised in the keri-authority/ vectors).
  const kelFor = (coldRootPubkey: string, epochPubkey: string) => {
    const inceptionEvent = inceptionTemplate(coldRootPubkey, epochPubkey, TEST_EPOCH);
    const id = getEventId(inceptionEvent);
    return { inception_event: inceptionEvent, head: { id, seq: 0 } };
  };
  const kel = {
    alice: kelFor(personas.alice.cold_root.pubkey, personas.alice.epoch_keys.epoch_1.pubkey),
    bob: kelFor(personas.bob.cold_root.pubkey, personas.bob.epoch_keys.epoch_1.pubkey),
    carol: kelFor(personas.carol.cold_root.pubkey, personas.carol.epoch_keys.epoch_1.pubkey),
  };
  return {
    vector_schema_version: "1.0.0",
    spec_version: QUALIFIED_VERSION,
    registry_sha256: CURRENT_REGISTRY_SHA256,
    test_epoch: TEST_EPOCH,
    pinned_randomness: {
      schnorr_aux_rand: "00".repeat(32),
      nip44_nonce_policy: "Each vector carries a fixed 32-byte nonce in input.",
    },
    personas,
    kel,
    ed25519_nids,
    device_publishing_keys,
    radicle_rids,
    audience_keys,
    category_keysets: {
      identity: "alice",
      keri: "alice",
      verification: "alice",
      index: "alice",
      relay_interop: "alice",
      "nid-binding": "alice",
      "identity-doc": "alice",
      "node-advert": "alice",
      "privacy-tiers": "alice",
      org: "alice",
      default_peer: "bob",
    },
  };
}

export type Fixtures = ReturnType<typeof buildFixtures>;
