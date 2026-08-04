import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { nip44 } from "nostr-tools";
import { configKeyId, nip49EncryptDeterministic } from "./backup-crypto.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { withKelHead } from "./kel.js";
import { canonicalNip01, getPublicKey, signEvent } from "./nostr.js";
import { fixtureRid } from "./radicle.js";
import { AUX_RAND, consumeVector, produceAuthored } from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector } from "./types.js";
import type { NostrSignedEvent } from "./nostr.js";

type ProduceMeta = {
  vector_id: string;
  spec_refs: string[];
  description: string;
  input: Record<string, unknown>;
  notes?: string;
};

function producedEvent(
  relativePath: string,
  meta: ProduceMeta,
  event: NostrSignedEvent,
  extraDecoded: Record<string, unknown> = {},
): AuthoredVector {
  return produceAuthored(relativePath, {
    ...meta,
    expected_output: {
      canonical_wire: canonicalNip01(event),
      decoded: { event, ...extraDecoded },
      id: event.id,
      sig: event.sig,
    },
  });
}

// The v0.4.0 spec sections added after topics-v04.ts: NIP-51 lists/sets as a
// core carrier (§8.5-§8.6), CORE double-ratchet DMs (§5.7), core config/keys
// backups (§3.8.6-§3.8.8, §6.10.4), and the moderator-declaration / as-of
// resolution moderation additions (§8.1-§8.2.1).
export async function buildV04bVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const alice = fixtures.personas.alice;
  const bob = fixtures.personas.bob;
  const carol = fixtures.personas.carol;
  const epoch = alice.epoch_keys.epoch_1;
  const cold = alice.cold_root;
  const nid1 = fixtures.ed25519_nids.alice_device_1;
  const pub1 = fixtures.device_publishing_keys.alice_device_1;
  const pub2 = fixtures.device_publishing_keys.alice_device_2;
  const rid = fixtures.radicle_rids.alice;
  const T = fixtures.test_epoch;

  const vectors: AuthoredVector[] = [];

  // ---- lists/ NIP-51 lists and sets, core carrier (§8.5, §8.6, §3.0) -------

  const muteList = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 100,
    kind: 10000,
    tags: withKelHead(
      [
        ["p", bob.cold_root.pubkey],
        ["t", "spam"],
        ["word", "airdrop"],
        ["e", "aa".repeat(32)],
      ],
      fixtures.legacy_kel.alice.head,
    ),
    content: "",
    auxRand: AUX_RAND,
  });

  const selfConvKey = nip44.v2.utils.getConversationKey(hexToBytes(epoch.private_key), epoch.pubkey);
  const privateItemsPlaintext = JSON.stringify([
    ["p", carol.cold_root.pubkey],
    ["word", "secret-topic"],
  ]);
  const privateItemsNonce = hexToBytes("52".repeat(32));
  const privateItemsCipher = nip44.v2.encrypt(privateItemsPlaintext, selfConvKey, privateItemsNonce);
  const muteListPrivate = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 101,
    kind: 10000,
    tags: withKelHead(
      [
        ["p", bob.cold_root.pubkey],
        ["t", "spam"],
      ],
      fixtures.legacy_kel.alice.head,
    ),
    content: privateItemsCipher,
    auxRand: AUX_RAND,
  });

  const kindMuteSet = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 102,
    kind: 30007,
    tags: withKelHead(
      [
        ["d", "1"],
        ["title", "Muted authors for kind 1"],
        ["p", bob.cold_root.pubkey],
        ["p", carol.cold_root.pubkey],
      ],
      fixtures.kel.alice.head,
    ),
    content: "",
    auxRand: AUX_RAND,
  });

  const newEpochPub = getPublicKey("2e".padStart(64, "0"));

  vectors.push(
    producedEvent(
      "lists/001-mute-list-public-roundtrip.json",
      {
        vector_id: "lists/mute-list-public-roundtrip",
        spec_refs: ["§8.5", "§3.0", "§14.1", "§14.3"],
        description: "NIP-51 kind:10000 mute list: public entries as clear p/t/word/e tags, epoch-key-signed, publishable to both core backends.",
        input: { fixture_persona: "alice", signer: "epoch_1", aux_rand: AUX_RAND },
        notes: "kind:10000 is a standard NIP-51 replaceable list (10000-10102 range), replaced by (pubkey, kind) with no d tag. The identical event is publishable to ordinary Nostr relays and repo relays; a repo relay MUST accept it like any other replaceable event (§3.0, §8.5).",
      },
      muteList,
    ),
    producedEvent(
      "lists/002-mute-list-private-items-encrypted-to-self.json",
      {
        vector_id: "lists/mute-list-private-items-encrypted-to-self",
        spec_refs: ["§8.5", "§3.0", "§14.3"],
        description: "NIP-51 kind:10000 mute list carrying private items: a JSON array of tag-shaped arrays, NIP-44 v2 encrypted-to-self under the persona's current epoch key, in content alongside the public tags.",
        input: {
          fixture_persona: "alice",
          signer: "epoch_1",
          self_conversation: true,
          nip44_nonce: bytesToHex(privateItemsNonce),
          private_items_plaintext: privateItemsPlaintext,
        },
        notes: "The self-encryption conversation key is the NIP-44 v2 ECDH of the epoch private key with its own x-only epoch pubkey (getConversationKey(epoch_priv, epoch_pub)). Private items are the JSON array of tag-shaped arrays. Decryptable by any holder of the epoch key; on KERI rotation the client re-encrypts under the new epoch key (see lists/006).",
      },
      muteListPrivate,
      {
        conversation_key: bytesToHex(selfConvKey),
        nip44_nonce: bytesToHex(privateItemsNonce),
        private_items: JSON.parse(privateItemsPlaintext) as unknown,
        nip44_payload: privateItemsCipher,
      },
    ),
    producedEvent(
      "lists/003-kind-mute-set-addressing.json",
      {
        vector_id: "lists/kind-mute-set-addressing",
        spec_refs: ["§8.5", "§3.0", "§14.3"],
        description: "NIP-51 kind:30007 kind-mute set: an addressable (pubkey, kind, d) set event; one such event per (kind, d) pair forms the persona's sets file.",
        input: { fixture_persona: "alice", signer: "epoch_1", set_d: "1", aux_rand: AUX_RAND },
        notes: "Per NIP-51 the kind:30007 d tag names the muted kind (here d=\"1\": pubkeys muted for kind:1 notes); the muted authors are p tags. The persona's sets file is the collection of its NIP-51 set events keyed by (kind, d) (§3.0, §8.5).",
      },
      kindMuteSet,
    ),
    consumeVector("lists/004-stale-list-rollback-rejected.json", {
      vector_id: "lists/stale-list-rollback-rejected",
      spec_refs: ["§8.5", "§3.0", "§14.3"],
      description: "A relay serving an older kind:10000 revision than one reachable in the repo's canonical git history is a stale-list rollback; the client rejects the stale copy and prefers the newest verifiable revision.",
      input: {
        list_kind: 10000,
        served_revision: { event_id: "aa".repeat(32), created_at: T + 100 },
        repo_canonical_history_newest: {
          event_id: "bb".repeat(32),
          created_at: T + 200,
          reachable_from_canonical_history: true,
        },
      },
      expected_output: {
        verdict: "reject",
        reason_code: "stale_list_rollback",
        normalized: { preferred_revision_id: "bb".repeat(32), preferred_created_at: T + 200 },
      },
      decision_trace: [
        "read_served_revision",
        "walk_repo_revision_history",
        "detect_newer_reachable_revision",
        "reject_stale_rollback",
      ],
      notes: "Because a repo relay's event store is git, the full revision history is retained and tamper-evident; the client MUST prefer the newest verifiable revision (§8.5). Replaceable-event convergence otherwise follows latest-created_at.",
    }),
    consumeVector("lists/005-policy-list-adoption-parsed.json", {
      vector_id: "lists/policy-list-adoption-parsed",
      spec_refs: ["§8.6", "§8.5", "§14.3"],
      description: "A community's kind:34550 definition declares adopted NIP-51 policy lists via one [\"p\", <policy persona>, <relay>, \"policy\"] tag per policy persona and one [\"a\", ...] tag per adopted set; a client parses the adopted sources.",
      input: {
        community_definition: {
          kind: 34550,
          d: "acme-town-square",
          tags: [
            ["d", "acme-town-square"],
            ["p", carol.cold_root.pubkey, "wss://relay.example", "policy"],
            ["a", `30007:${bob.cold_root.pubkey}:1`, "wss://relay.example"],
          ],
        },
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          adopted_policy_personas: [carol.cold_root.pubkey],
          adopted_policy_sets: [`30007:${bob.cold_root.pubkey}:1`],
        },
      },
      decision_trace: ["read_kind34550_tags", "collect_policy_p_tags", "collect_policy_a_tags"],
      notes: "Community blocklists ride the §8.5 carrier; adoption is declared in kind:34550 (§8.6). Only p tags with the fourth element \"policy\" are policy-source tags; ordinary moderator p tags carry \"moderator\" instead.",
    }),
    consumeVector("lists/006-private-items-reencrypt-on-rotation.json", {
      vector_id: "lists/private-items-reencrypt-on-rotation",
      spec_refs: ["§8.5", "§3.5", "§14.3"],
      description: "On KERI epoch rotation the client re-encrypts a list's private items under the new epoch key when it next writes the list.",
      input: {
        list_kind: 10000,
        old_epoch_pubkey: epoch.pubkey,
        new_epoch_pubkey: newEpochPub,
        private_items_present: true,
        reencrypted_under_new_epoch: true,
      },
      expected_output: {
        verdict: "accept",
        normalized: { reencrypted_under_new_epoch: true, conversation_key_source: "new_epoch_key" },
      },
      notes: "The self-encryption conversation key is derived from the persona's current epoch key; after rotation the private items MUST be re-encrypted so the current epoch key can still read them (§8.5, §3.5).",
    }),
  );

  // ---- dm/ CORE double-ratchet direct messages (§5.7) ----------------------

  const inviteDTag = `double-ratchet/invites/${pub1.pubkey}`;
  const inviteEphemeralPub = getPublicKey("e1".padStart(64, "0"));
  const invite = await signEvent({
    secretKey: pub1.private_key,
    created_at: T + 110,
    kind: 30078,
    tags: [
      ["d", inviteDTag],
      ["heterodyne", "dm_invite"],
      ["ephemeral_key", inviteEphemeralPub],
    ],
    content: "",
    auxRand: AUX_RAND,
  });

  const unboundSecret = "99".padStart(64, "0");
  const unboundInvite = await signEvent({
    secretKey: unboundSecret,
    created_at: T + 111,
    kind: 30078,
    tags: [
      ["d", `double-ratchet/invites/${getPublicKey(unboundSecret)}`],
      ["heterodyne", "dm_invite"],
      ["ephemeral_key", getPublicKey("e2".padStart(64, "0"))],
    ],
    content: "",
    auxRand: AUX_RAND,
  });

  const revokedDeviceInvite = await signEvent({
    secretKey: pub2.private_key,
    created_at: T + 1000,
    kind: 30078,
    tags: [
      ["d", `double-ratchet/invites/${pub2.pubkey}`],
      ["heterodyne", "dm_invite"],
      ["ephemeral_key", getPublicKey("e3".padStart(64, "0"))],
    ],
    content: "",
    auxRand: AUX_RAND,
  });

  const messageKey = hexToBytes("62".repeat(32));
  const dmNonce = hexToBytes("63".repeat(32));
  const innerRumor = {
    pubkey: pub1.pubkey,
    created_at: T + 120,
    kind: 14,
    tags: [["p", bob.cold_root.pubkey]],
    content: "hi over the ratchet",
  };
  const dmCiphertext = nip44.v2.encrypt(JSON.stringify(innerRumor), messageKey, dmNonce);
  const dmHeader = bytesToHex(sha256(utf8Bytes("heterodyne-fixture-dr-header|alice-device-1|msg-1")));
  const ephemeralMessageSecret = "d1".padStart(64, "0");
  const outerMessage = await signEvent({
    secretKey: ephemeralMessageSecret,
    created_at: T + 120,
    kind: 1060,
    tags: [["header", dmHeader]],
    content: dmCiphertext,
    auxRand: AUX_RAND,
  });

  vectors.push(
    producedEvent(
      "dm/001-invite-delegated-device-valid.json",
      {
        vector_id: "dm/invite-delegated-device-valid",
        spec_refs: ["§5.7.1", "§5.7.2", "§3.3.1", "§14.1", "§14.3"],
        description: "A kind:30078 double-ratchet invite (d = double-ratchet/invites/<device>) signed by a device secp256k1 publishing key that is currently kind:31001-delegated to the persona.",
        input: {
          fixture_device: "alice_device_1",
          device_publishing_key: pub1.pubkey,
          delegated_via_kind31001: nid1.did_key,
          delegation_vector: "nid-binding/001-bidirectional-valid",
          ephemeral_key: inviteEphemeralPub,
          d_tag_device_segment: pub1.pubkey,
        },
        notes: "Signed by alice_device_1's publishing key (fixtures.device_publishing_keys.alice_device_1), which nid-binding/001 binds to alice via a valid kind:31001 delegation (§5.7.2). Byte-level choices: the <device> segment of the d tag is the device publishing pubkey, and the invite's ephemeral key / shared-secret bootstrap payload are deferred per §5.7.1 (frozen wire extracted before 1.0), so only the addressable shape and delegation binding are asserted here.",
      },
      invite,
      { ephemeral_key: inviteEphemeralPub, d_tag: inviteDTag },
    ),
    consumeVector("dm/002-invite-unbound-device-rejected.json", {
      vector_id: "dm/invite-unbound-device-rejected",
      spec_refs: ["§5.7.2", "§3.3.1", "§14.3"],
      description: "A kind:30078 invite signed by a publishing key with no valid kind:31001 delegation to the persona is rejected before a session is established.",
      input: {
        event: unboundInvite,
        signer_publishing_key: getPublicKey(unboundSecret),
        persona_delegation_set: [pub1.pubkey, pub2.pubkey],
      },
      expected_output: { verdict: "reject", reason_code: "dm_invite_unbound_device" },
      decision_trace: [
        "verify_outer_bip340_signature",
        "resolve_signer_delegation",
        "reject_no_kind31001_binding",
      ],
      notes: "The outer Nostr signature is valid, but the signer key is absent from the persona's kind:31001 delegation set, so it does not chain to the cold root (§5.7.2).",
    }),
    consumeVector("dm/003-invite-revoked-device-rejected.json", {
      vector_id: "dm/invite-revoked-device-rejected",
      spec_refs: ["§5.7.2", "§3.9.7", "§14.3"],
      description: "A kind:30078 invite signed by a device whose kind:31001 delegation has been revoked is rejected; the persona's remaining devices are unaffected.",
      input: {
        event: revokedDeviceInvite,
        signer_publishing_key: pub2.pubkey,
        revoked_at: T + 900,
        event_created_at: T + 1000,
      },
      expected_output: { verdict: "reject", reason_code: "dm_invite_revoked_device" },
      simulated_clock: T + 1100,
      decision_trace: [
        "verify_outer_bip340_signature",
        "resolve_signer_delegation",
        "check_revocation",
        "reject_revoked_device",
      ],
      notes: "Peers MUST stop accepting sessions bound to a revoked device (§5.7.2). The invite's created_at is after revoked_at.",
    }),
    producedEvent(
      "dm/004-kind1060-outer-message-shape.json",
      {
        vector_id: "dm/kind1060-outer-message-shape",
        spec_refs: ["§5.7.1", "§14.1", "§14.3"],
        description: "A kind:1060 double-ratchet outer message: signed by the sender's current ratchet key (a fresh key per DH ratchet step, NOT the sender's epoch key), carrying the encrypted ratchet header in a tag and the NIP-44 v2 ciphertext in content; the plaintext is an unsigned kind:14 NIP-17 rumor.",
        input: {
          signer: "current_ratchet_key",
          ephemeral_signer_secret: ephemeralMessageSecret,
          message_key: bytesToHex(messageKey),
          nip44_nonce: bytesToHex(dmNonce),
          header_blob: dmHeader,
          inner_rumor: innerRumor,
        },
        notes: "SHAPE/parse vector only. Byte-level choices: the message key (used directly as the NIP-44 v2 conversation key) and the ratchet header blob are fixture placeholders, and the ratchet-key signer is a fixture key. dm/006 carries the full ratchet transcript generated with the pinned upstream wire library. The inner rumor is an unsigned kind:14 (no id/sig), attributable to the peer only via the session binding (§5.7.2).",
      },
      outerMessage,
      {
        message_key: bytesToHex(messageKey),
        nip44_nonce: bytesToHex(dmNonce),
        header: dmHeader,
        inner_rumor: innerRumor,
        nip44_payload: dmCiphertext,
        signer_kind: "current_ratchet_key",
      },
    ),
    consumeVector("dm/005-repo-relay-refuses-kind1060.json", {
      vector_id: "dm/repo-relay-refuses-kind1060",
      spec_refs: ["§5.7.3", "§10.1.2", "§14.3"],
      description: "A repo relay refuses to store a kind:1060 double-ratchet message; ratchet ciphertext MUST NOT be archived in a repo.",
      input: { event_kind: 1060, submitted_to: "repo_relay" },
      expected_output: { verdict: "reject", reason_code: "dm_event_not_storable" },
      decision_trace: [
        "classify_event_kind",
        "apply_repo_relay_storage_policy",
        "reject_ratchet_ciphertext_storage",
      ],
      notes: "kind:1060 messages and kind:1059 invite responses MUST NOT be committed to any repo or accepted by a repo relay; archiving ratchet ciphertext would contradict forward secrecy (§5.7.3). Ordinary Nostr relays still carry them within their transient retention window; invites (kind:30078) MAY live on both backends.",
    }),
  );

  // ---- config-backup/ config repo, keys repo, key-ID branch (§3.8.6-§3.8.8) -

  const configAudienceKey = "42".repeat(32);
  const configKid = configKeyId(configAudienceKey);
  const rotatedAudienceKey = "43".repeat(32);
  const rotatedKid = configKeyId(rotatedAudienceKey);

  const configPostKey = hkdf(
    sha256,
    hexToBytes(configAudienceKey),
    utf8Bytes(configKid),
    utf8Bytes("heterodyne-post-key-v1"),
    32,
  );
  const configBlobNonce = hexToBytes("60".repeat(32));
  const configBlobPlaintext = JSON.stringify({
    blob: "persona_config",
    private_mutes: [["p", carol.cold_root.pubkey]],
    feed_prefs: { default_tier: 1 },
  });
  const configBlobCipher = nip44.v2.encrypt(configBlobPlaintext, configPostKey, configBlobNonce);

  const nsecPassword = "heterodyne-vector-passphrase";
  const nip49Salt = "70".repeat(16);
  const nip49Nonce = "71".repeat(24);
  const ncryptsec = nip49EncryptDeterministic(cold.private_key, nsecPassword, nip49Salt, nip49Nonce, 16, 2);

  const configRid = fixtureRid("alice-config");

  vectors.push(
    produceAuthored("config-backup/001-key-id-derivation.json", {
      vector_id: "config-backup/key-id-derivation",
      spec_refs: ["§6.10.4", "§14.3"],
      description: "The RECOMMENDED self-verifying key_id derivation: the first 16 bytes (32 hex chars) of SHA-256 over the ASCII domain separator concatenated with the raw 32-byte audience key; the ciphertext for this generation lives on refs/heads/enc/<key_id>.",
      input: {
        audience_key: configAudienceKey,
        domain_separator: "heterodyne-key-id-v1",
        derivation: "lowercase-hex(SHA-256(\"heterodyne-key-id-v1\" || audience_key))[0..32]",
      },
      expected_output: {
        canonical_wire: configKid,
        decoded: {
          audience_key: configAudienceKey,
          key_id: configKid,
          enc_branch: `refs/heads/enc/${configKid}`,
          domain_separator: "heterodyne-key-id-v1",
        },
      },
      notes: "The domain separator is concatenated as raw ASCII bytes with the raw 32-byte audience key before hashing (not the hex string). key_id remains opaque to verifiers; a publisher MAY instead use a random UUID-style id (§6.10.4).",
    }),
    produceAuthored("config-backup/002-config-blob-encrypt-decrypt.json", {
      vector_id: "config-backup/config-blob-encrypt-decrypt",
      spec_refs: ["§3.8.6", "§6.10", "§6.10.4", "§14.3"],
      description: "A config-repository blob is Tier 3 content: encrypted under post_key = HKDF-SHA256(config_audience_key, salt=key_id, info=heterodyne-post-key-v1, 32) using the NIP-44 v2 symmetric layer, committed on the enc/<key_id> branch.",
      input: {
        fixture_config_audience_key: configAudienceKey,
        key_id: configKid,
        hkdf: {
          hash: "SHA-256",
          ikm_hex: configAudienceKey,
          salt_utf8: configKid,
          info_utf8: "heterodyne-post-key-v1",
          output_len: 32,
        },
        nip44_nonce: bytesToHex(configBlobNonce),
        plaintext: configBlobPlaintext,
      },
      expected_output: {
        canonical_wire: configBlobCipher,
        decoded: {
          config_audience_key: configAudienceKey,
          key_id: configKid,
          enc_branch: `refs/heads/enc/${configKid}`,
          post_key: bytesToHex(configPostKey),
          nip44_conversation_key: bytesToHex(configPostKey),
          plaintext: JSON.parse(configBlobPlaintext) as unknown,
          nip44_payload: configBlobCipher,
        },
      },
      notes: "Byte-level choice: config blobs are treated as Tier 3 content (not index), so the post_key label heterodyne-post-key-v1 applies with the derived key_id as the HKDF salt (§6.10, §3.8.6). The NIP-44 v2 symmetric layer takes post_key directly as the conversation key (no ECDH).",
    }),
    consumeVector("config-backup/003-key-rotation-ref-delta.json", {
      vector_id: "config-backup/key-rotation-ref-delta",
      spec_refs: ["§6.10.4", "§6.7.4", "§14.3"],
      description: "On audience-key rotation the publisher creates enc/<key_id'>, force-deletes the retired enc/<key_id>, and publishes updated signed refs; the retired branch is absent from the new signed ref set.",
      input: {
        prior_key_id: configKid,
        prior_enc_branch: `refs/heads/enc/${configKid}`,
        new_key_id: rotatedKid,
        new_enc_branch: `refs/heads/enc/${rotatedKid}`,
        signed_ref_set_after_rotation: [`refs/heads/enc/${rotatedKid}`, "refs/rad/sigrefs"],
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          old_branch_in_new_signed_ref_set: false,
          new_branch_present: true,
          ref_delta: {
            added: [`refs/heads/enc/${rotatedKid}`],
            removed: [`refs/heads/enc/${configKid}`],
          },
        },
      },
      decision_trace: [
        "generate_fresh_key_and_key_id",
        "create_new_enc_branch",
        "force_delete_retired_branch",
        "publish_updated_sigrefs",
      ],
      notes: "Cooperating seeds mirror the publisher's signed ref set and converge to a tree without the retired branch. This is cooperative hygiene, not cryptographic erasure: a hostile or offline seed MAY retain the old ciphertext (§6.10.4).",
    }),
    produceAuthored("config-backup/004-nip49-nsec-wrap.json", {
      vector_id: "config-backup/nip49-nsec-wrap",
      spec_refs: ["§3.8.7", "§14.3"],
      description: "The keys repository stores the persona's nsec wrapped per NIP-49 (scrypt N=2^16, r=8, p=1; XChaCha20-Poly1305; key-security-byte 2). The resulting ncryptsec round-trips through nostr-tools nip49.decrypt.",
      input: {
        fixture_persona: "alice",
        secret_key: cold.private_key,
        password: nsecPassword,
        scrypt_logn: 16,
        scrypt_salt: nip49Salt,
        xchacha_nonce: nip49Nonce,
        key_security_byte: 2,
      },
      expected_output: {
        canonical_wire: ncryptsec,
        decoded: {
          secret_key_source: "alice.cold_root",
          scrypt: { logn: 16, n: 65536, r: 8, p: 1, dk_len: 32 },
          salt: nip49Salt,
          nonce: nip49Nonce,
          key_security_byte: 2,
          ncryptsec,
        },
      },
      notes: "NIP-49 draws the 16-byte salt and 24-byte nonce randomly; here both are pinned fixture bytes for reproducibility (never random). The nsec (alice's well-known test cold root) and password are test fixtures only. Round-trip is asserted in crypto-kat.test.ts via nostr-tools nip49.decrypt.",
    }),
    consumeVector("config-backup/005-config-rid-unadvertised-clean.json", {
      vector_id: "config-backup/config-rid-unadvertised-clean",
      spec_refs: ["§3.8.6", "§14.3"],
      description: "A negative surface scan: the config repository RID appears on none of the persona's published surfaces (kind:31005, kind:31010, kind:0 profile, NIP-65 relays, NIP-51 lists), which reference only the public RID.",
      input: {
        config_rid: configRid,
        public_rid: rid,
        published_surfaces: {
          kind31005: {
            tags: [["d", ""], ["heterodyne", "identity_pointer"], ["rid", rid], ["host_hint", "wss://node-a.example/relay"]],
          },
          kind31010: { tags: [["d", rid], ["rid", rid], ["endpoint", "wss://node-a.example/relay"]] },
          kind0_profile: { content: "{\"name\":\"alice\",\"about\":\"heterodyne persona\"}" },
          nip65_relays: ["wss://relay.example"],
          nip51_lists: [{ kind: 10000, tags: [["p", bob.cold_root.pubkey]] }],
        },
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          config_rid_absent_from_all: true,
          scanned_surfaces: ["kind:31005", "kind:31010", "kind:0", "nip65", "nip51"],
        },
      },
      decision_trace: ["collect_published_surfaces", "scan_for_config_rid", "confirm_absent"],
      notes: "The config repository RID MUST NOT appear on any published surface (§3.8.6); knowledge of it travels only through the keys repository, a §5.7 device DM, or a backup restore.",
    }),
    consumeVector("config-backup/006-config-rid-advertised-rejected.json", {
      vector_id: "config-backup/config-rid-advertised-rejected",
      spec_refs: ["§3.8.6", "§14.3"],
      description: "The same negative surface scan detects the config RID leaked into a kind:31010 advertisement and rejects it.",
      input: {
        config_rid: configRid,
        published_surfaces: {
          kind31010: { tags: [["d", configRid], ["rid", configRid], ["endpoint", "wss://node-a.example/relay"]] },
        },
      },
      expected_output: {
        verdict: "reject",
        reason_code: "config_rid_advertised",
        normalized: { leaked_on: "kind:31010" },
      },
      decision_trace: ["scan_for_config_rid", "detect_config_rid_on_published_surface", "reject"],
      notes: "Advertising the config RID would let observers associate the private config repo with the persona and let non-allowed nodes attempt to fetch it (§3.8.6).",
    }),
  );

  // ---- moderation/ additions: kind:34550 declaration + as-of resolution -----

  const communityDefinition = await signEvent({
    secretKey: epoch.private_key,
    created_at: T + 130,
    kind: 34550,
    tags: withKelHead(
      [
        ["d", "acme-town-square"],
        ["name", "Acme Town Square"],
        ["p", bob.cold_root.pubkey, "wss://relay.example", "moderator"],
        ["p", carol.cold_root.pubkey, "wss://relay.example", "moderator"],
        ["approvals_required", "2"],
      ],
      fixtures.kel.alice.head,
    ),
    content: "",
    auxRand: AUX_RAND,
  });

  const declarationHistory = [
    { commit_seq: 3, kind34550_revision: "rev-a", moderators: [bob.cold_root.pubkey, carol.cold_root.pubkey] },
    { commit_seq: 8, kind34550_revision: "rev-b", moderators: [carol.cold_root.pubkey] },
  ];

  vectors.push(
    producedEvent(
      "moderation/007-kind34550-approvals-required.json",
      {
        vector_id: "moderation/kind34550-approvals-required",
        spec_refs: ["§8.2", "§8.1", "§14.1", "§14.3"],
        description: "A NIP-72 kind:34550 community definition signed by the community persona's epoch key, listing moderators by permanent cold-root npub and carrying the Heterodyne [\"approvals_required\",\"N\"] extension tag.",
        input: { fixture_persona: "alice", signer: "epoch_1", approvals_required: 2, aux_rand: AUX_RAND },
        notes: "Moderators are listed per NIP-72 as [\"p\", <cold-root npub hex>, <relay hint>, \"moderator\"] - the permanent KERI cold root, not the epoch key that signs approvals. A vanilla NIP-72 client ignores approvals_required and sees a normal community (§8.2).",
      },
      communityDefinition,
    ),
    consumeVector("moderation/008-approvals-required-absent-default-one.json", {
      vector_id: "moderation/approvals-required-absent-default-one",
      spec_refs: ["§8.2", "§14.3"],
      description: "A kind:34550 community definition with no approvals_required tag defaults the threshold to 1.",
      input: {
        community_definition: {
          kind: 34550,
          tags: [
            ["d", "acme-town-square"],
            ["p", bob.cold_root.pubkey, "wss://relay.example", "moderator"],
          ],
        },
      },
      expected_output: {
        verdict: "accept",
        normalized: { approvals_required: 1, threshold_source: "default_absent" },
      },
      notes: "Absent approvals_required means 1, keeping vanilla-NIP-72 compatibility (§8.2).",
    }),
    consumeVector("moderation/009-repo-anchor-asof-before-removal-counts.json", {
      vector_id: "moderation/repo-anchor-asof-before-removal-counts",
      spec_refs: ["§8.1", "§8.2.1", "§14.3"],
      description: "Repo-anchored as-of resolution: an approval anchored (by its introducing commit) before a moderator's removal counts, because the newest kind:34550 revision reachable in the anchor commit's ancestor history still lists the moderator.",
      input: {
        hosting: "repo",
        approval: {
          approval_event_id: "e1".repeat(32),
          approved_post_id: "e2".repeat(32),
          moderator_cold_root: bob.cold_root.pubkey,
          anchor_commit_seq: 5,
        },
        canonical_declaration_history: declarationHistory,
      },
      expected_output: {
        verdict: "accept",
        normalized: { counted: true, asof_revision: "rev-a", moderator_in_asof_declaration: true },
      },
      decision_trace: [
        "resolve_anchor_commit",
        "walk_ancestor_history",
        "select_newest_reachable_kind34550",
        "confirm_moderator_listed",
        "count_approval",
      ],
      notes: "The approval's anchor is commit seq 5; the newest kind:34550 reachable in that commit's ancestor history (seq <= 5) is rev-a (seq 3), which lists bob. Removal at rev-b (seq 8) is later, so bob's earlier approval is not retroactively invalidated (§8.2.1).",
    }),
    consumeVector("moderation/010-repo-anchor-asof-after-removal-rejected.json", {
      vector_id: "moderation/repo-anchor-asof-after-removal-rejected",
      spec_refs: ["§8.1", "§8.2.1", "§14.3"],
      description: "Repo-anchored as-of resolution: an approval anchored after a moderator's removal does not count, because the newest kind:34550 revision reachable in the anchor commit's ancestor history no longer lists the moderator.",
      input: {
        hosting: "repo",
        approval: {
          approval_event_id: "e3".repeat(32),
          approved_post_id: "e4".repeat(32),
          moderator_cold_root: bob.cold_root.pubkey,
          anchor_commit_seq: 9,
        },
        canonical_declaration_history: declarationHistory,
      },
      expected_output: {
        verdict: "reject",
        reason_code: "moderator_not_in_asof_declaration",
        normalized: { asof_revision: "rev-b" },
      },
      decision_trace: [
        "resolve_anchor_commit",
        "walk_ancestor_history",
        "select_newest_reachable_kind34550",
        "moderator_absent",
        "reject_approval",
      ],
      notes: "The approval's anchor is commit seq 9; the newest reachable kind:34550 (seq <= 9) is rev-b (seq 8), which removed bob. A removed moderator cannot obtain a new anchor positioned before their removal because commits append to the canonical head (§8.2.1).",
    }),
    consumeVector("moderation/011-relay-only-created-at-fallback.json", {
      vector_id: "moderation/relay-only-created-at-fallback",
      spec_refs: ["§8.1", "§8.2.1", "§14.3"],
      description: "For a community with neither a repo nor a Matrix room, the as-of point falls back to the newest kind:34550 revision whose created_at is <= the approval's created_at, carrying reduced assurance.",
      input: {
        hosting: "relay_only",
        approval: { approval_event_id: "e5".repeat(32), moderator_cold_root: bob.cold_root.pubkey, created_at: T + 500 },
        kind34550_revisions: [
          { revision: "rev-a", created_at: T + 100, moderators: [bob.cold_root.pubkey] },
          { revision: "rev-b", created_at: T + 700, moderators: [carol.cold_root.pubkey] },
        ],
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          counted: true,
          asof_source: "relay_only_created_at_fallback",
          asof_revision: "rev-a",
          reduced_assurance: true,
        },
      },
      simulated_clock: T + 900,
      notes: "REDUCED ASSURANCE: created_at is author-forgeable, so a listed-then-removed moderator could backdate an approval to fall under an older revision that still lists them. Communities SHOULD host in a repo (or Matrix room) when moderation-history integrity matters (§8.1).",
    }),
  );

  return vectors;
}
