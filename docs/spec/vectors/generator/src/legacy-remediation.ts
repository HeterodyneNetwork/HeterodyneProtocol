import { nip44 } from "nostr-tools";
import { hexToBytes } from "./hex.js";
import { canonicalNip01, signEvent, type NostrSignedEvent } from "./nostr.js";
import { AUX_RAND, baseVector, produceVector, withoutSig } from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector } from "./types.js";

type Replacement = {
  newId: string;
  path: string;
  owner: "core" | "comms" | "social";
  coldRoot?: boolean;
  profile?: "mute" | "tier3";
};

const REPLACEMENTS = new Map<string, Replacement>([
  ["identity/root-attestation-valid", { newId: "identity/root-attestation-valid-v050", path: "identity/008-root-attestation-valid-v050.json", owner: "core" }],
  ["identity-doc/emergency-reanchor", { newId: "identity-doc/emergency-reanchor-v050", path: "identity-doc/004-emergency-reanchor-v050.json", owner: "core", coldRoot: true }],
  ["nid-binding/bidirectional-valid", { newId: "nid-binding/bidirectional-valid-v050", path: "nid-binding/004-bidirectional-valid-v050.json", owner: "core" }],
  ["node-advert/valid-dual-signed", { newId: "node-advert/valid-dual-signed-v050", path: "node-advert/005-valid-dual-signed-v050.json", owner: "core" }],
  ["privacy-tiers/tier1-public-plaintext-both-backends", { newId: "privacy-tiers/tier1-public-plaintext-both-backends-v050", path: "privacy-tiers/011-tier1-public-plaintext-both-backends-v050.json", owner: "comms" }],
  ["privacy-tiers/tier3-index-key-derivation-and-encryption", { newId: "privacy-tiers/tier3-index-key-derivation-and-encryption-v050", path: "privacy-tiers/012-tier3-index-key-derivation-and-encryption-v050.json", owner: "comms" }],
  ["privacy-tiers/tier3-kind31011-audience-key-wrap", { newId: "privacy-tiers/tier3-kind31011-audience-key-wrap-v050", path: "privacy-tiers/013-tier3-kind31011-audience-key-wrap-v050.json", owner: "comms" }],
  ["privacy-tiers/tier3-kind31012-audience-roster", { newId: "privacy-tiers/tier3-kind31012-audience-roster-v050", path: "privacy-tiers/014-tier3-kind31012-audience-roster-v050.json", owner: "comms" }],
  ["lists/mute-list-public-roundtrip", { newId: "lists/mute-list-public-roundtrip-v050", path: "lists/007-mute-list-public-roundtrip-v050.json", owner: "social", profile: "mute" }],
  ["lists/mute-list-private-items-encrypted-to-self", { newId: "lists/mute-list-private-items-encrypted-to-self-v050", path: "lists/008-mute-list-private-items-encrypted-to-self-v050.json", owner: "social", profile: "mute" }],
]);

export async function remediateHistoricalProduction(
  authored: AuthoredVector[],
  fixtures: Fixtures,
): Promise<AuthoredVector[]> {
  const current: AuthoredVector[] = [];
  const historical = authored.map((item) => {
    const replacement = REPLACEMENTS.get(item.vector.vector_id);
    if (replacement === undefined) return item;
    current.push({ relativePath: replacement.path, vector: produceVector({
      vector_id: replacement.newId,
      spec_refs: [],
      description: `Current 0.5 production form replacing archived ${item.vector.vector_id} bytes without relabeling them.`,
      input: {},
      expected_output: {},
    }) });
    return {
      relativePath: item.relativePath,
      vector: baseVector({
        vector_id: item.vector.vector_id,
        spec_refs: [],
        description: `Verify preserved ${item.vector.vector_id} bytes as an archived monolith/0.4.0 form; never restamp or resign them.`,
        direction: "consume",
        input: {
          source_schema: "monolith/0.4.0",
          archived_form_valid: true,
          historical_input: item.vector.input,
          historical_expected_output: item.vector.expected_output,
        },
        expected_output: {
          verdict: "accept",
          normalized: { owner: "monolith/0.4.0", direction: "verify", historical_bytes_preserved: true, restamped: false },
        },
      }),
    };
  });

  for (const item of current) {
    const replacement = [...REPLACEMENTS.values()].find(({ newId }) => newId === item.vector.vector_id)!;
    const sourceId = [...REPLACEMENTS.entries()].find(([, value]) => value === replacement)![0];
    const source = authored.find(({ vector }) => vector.vector_id === sourceId)!.vector;
    const oldEvent = findSignedEvent(source.expected_output);
    if (oldEvent === undefined) throw new Error(`historical production vector has no signed event: ${sourceId}`);
    let content = oldEvent.content;
    let currentCryptoInput: Record<string, unknown> = {};
    let currentDecoded: Record<string, unknown> = {};
    if (sourceId === "privacy-tiers/tier3-index-key-derivation-and-encryption") {
      const sourceDecoded = source.expected_output.decoded as Record<string, unknown>;
      const plaintext = {
        ...(sourceDecoded.plaintext as Record<string, unknown>),
        spec_version: "comms/0.5.0",
      };
      const indexKey = sourceDecoded.index_key as string;
      content = nip44.v2.encrypt(JSON.stringify(plaintext), hexToBytes(indexKey), hexToBytes(source.input.nip44_nonce as string));
      currentCryptoInput = {
        hkdf: {
          hash: "SHA-256",
          ikm_hex: fixtures.audience_keys.alice_tier3_gen_a.key,
          salt_utf8: source.input.key_id,
          info_utf8: (source.input.hkdf as Record<string, unknown>).info,
          output_len: 32,
        },
        nip44_nonce: source.input.nip44_nonce,
        plaintext: JSON.stringify(plaintext),
      };
      currentDecoded = {
        index_key: indexKey,
        nip44_conversation_key: indexKey,
        plaintext,
        nip44_payload: content,
      };
    }
    let tags = oldEvent.tags
      .filter((tag) => tag[0] !== "spec_version")
      .map((tag) => tag[0] === "kel_head"
        ? ["kel_head", fixtures.kel.alice.head.id, String(fixtures.kel.alice.head.seq)]
        : [...tag]);
    if (sourceId === "node-advert/valid-dual-signed") {
      const repoHead = source.input.repo_head as string;
      const endpointIndex = tags.findIndex((tag) => tag[0] === "endpoint");
      if (endpointIndex < 0) throw new Error("historical node advertisement has no endpoint tag");
      tags.splice(endpointIndex + 1, 0, ["repo_head", repoHead]);
    }
    if (sourceId === "privacy-tiers/tier3-kind31011-audience-key-wrap") {
      const recipient = fixtures.device_publishing_keys.bob_device_1;
      tags = tags.map((tag) => tag[0] === "d"
        ? ["d", `${fixtures.audience_keys.alice_tier3_gen_a.key_id}:${recipient.pubkey}`]
        : tag[0] === "p" ? ["p", recipient.pubkey] : tag);
      const conversationKey = nip44.v2.utils.getConversationKey(
        hexToBytes(fixtures.personas.alice.epoch_keys.epoch_1.private_key),
        recipient.pubkey,
      );
      const nonce = hexToBytes(source.input.nip44_nonce as string);
      content = nip44.v2.encrypt(fixtures.audience_keys.alice_tier3_gen_a.key, conversationKey, nonce);
      currentCryptoInput = {
        recipient_pubkey: recipient.pubkey,
        recipient_role: "active-delegated-human-device",
        nip44_nonce: source.input.nip44_nonce,
      };
      currentDecoded = {
        recipient_pubkey: recipient.pubkey,
        conversation_key: Buffer.from(conversationKey).toString("hex"),
        audience_key_plaintext: fixtures.audience_keys.alice_tier3_gen_a.key,
        nip44_payload: content,
      };
    }
    if (sourceId === "privacy-tiers/tier3-kind31012-audience-roster") {
      const recipients = [
        fixtures.device_publishing_keys.alice_device_1.pubkey,
        fixtures.device_publishing_keys.bob_device_1.pubkey,
      ].sort();
      tags = tags.filter((tag) => tag[0] !== "p");
      const coldRootIndex = tags.findIndex((tag) => tag[0] === "cold_root");
      tags.splice(coldRootIndex + 1, 0, ...recipients.map((recipient) => ["p", recipient]));
      currentCryptoInput = { recipients, recipient_role: "active-delegated-human-device" };
      currentDecoded = { recipients };
    }
    if (replacement.profile === "tier3") {
      tags = tags.filter((tag) => tag[0] !== "matrix_room_id");
    }
    if (replacement.profile === "mute") {
      tags.push(["heterodyne", "social-mute-list-v1"]);
    }
    const wireOwner = replacement.profile === "tier3" ? "comms" : replacement.owner;
    tags.push(["spec_version", `${wireOwner}/0.5.0`]);
    const secretKey = replacement.coldRoot
      ? fixtures.personas.alice.cold_root.private_key
      : fixtures.personas.alice.epoch_keys.epoch_1.private_key;
    const createdAt = sourceId === "node-advert/valid-dual-signed"
      ? (source.input.expiry as number) - 300
      : oldEvent.created_at;
    const event = await signEvent({ secretKey, created_at: createdAt, kind: oldEvent.kind, tags, content, auxRand: AUX_RAND });
    item.vector.input = {
      migrated_from: sourceId,
      event_template: withoutSig(event),
      aux_rand: AUX_RAND,
      ...currentCryptoInput,
      ...(sourceId === "node-advert/valid-dual-signed"
        ? {
            validation_context: {
              now: (source.input.expiry as number) - 1,
              graph_fetch: {
                status: "available",
                reachable_oids: [source.input.repo_head as string],
              },
            },
          }
        : {}),
    };
    item.vector.expected_output = {
      canonical_wire: canonicalNip01(event),
      decoded: { event, ...currentDecoded },
      id: event.id,
      sig: event.sig,
    };
  }
  return [...historical, ...current];
}

function findSignedEvent(value: unknown): NostrSignedEvent | undefined {
  if (value !== null && typeof value === "object") {
    const candidate = value as Record<string, unknown>;
    if (typeof candidate.kind === "number" && typeof candidate.id === "string" && typeof candidate.sig === "string" && Array.isArray(candidate.tags)) {
      return candidate as unknown as NostrSignedEvent;
    }
    for (const child of Object.values(candidate)) {
      const found = findSignedEvent(child);
      if (found !== undefined) return found;
    }
  }
  return undefined;
}
