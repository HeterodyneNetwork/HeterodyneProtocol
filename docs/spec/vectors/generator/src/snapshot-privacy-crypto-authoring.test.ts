import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { nip44 } from "nostr-tools";
import { describe, expect, it } from "vitest";
import { buildFixtures } from "./snapshot-fixtures-adapter.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { buildV04Vectors } from "./topics-v04.js";
import { buildV04bVectors } from "./topics-v04b.js";

type HkdfTranscript = {
  hash: "SHA-256";
  ikm_hex: string;
  salt_utf8: string;
  info_utf8: string;
  output_len: 32;
};

function replayHkdf(transcript: HkdfTranscript): Uint8Array {
  expect(transcript.hash).toBe("SHA-256");
  return hkdf(
    sha256,
    hexToBytes(transcript.ikm_hex),
    utf8Bytes(transcript.salt_utf8),
    utf8Bytes(transcript.info_utf8),
    transcript.output_len,
  );
}

describe("historical snapshot Tier 3 HKDF transcripts", () => {
  it("replays the v04 index-key vector authoring input", async () => {
    const vectors = await buildV04Vectors(buildFixtures());
    const vector = vectors.find(({ vector: candidate }) =>
      candidate.vector_id === "privacy-tiers/tier3-index-key-derivation-and-encryption")!.vector;
    const derived = replayHkdf(vector.input.hkdf as HkdfTranscript);
    const decoded = vector.expected_output.decoded as Record<string, unknown>;

    expect(bytesToHex(derived)).toBe(decoded.index_key);
    expect(bytesToHex(derived)).toBe(decoded.nip44_conversation_key);
    expect(JSON.parse(nip44.v2.decrypt(
      (decoded.event as { content: string }).content,
      derived,
    ))).toEqual(decoded.plaintext);
  });

  it("replays the v04b config-post-key vector authoring input", async () => {
    const vector = (await buildV04bVectors(buildFixtures())).find(({ vector: candidate }) =>
      candidate.vector_id === "config-backup/config-blob-encrypt-decrypt")!.vector;
    const derived = replayHkdf(vector.input.hkdf as HkdfTranscript);
    const decoded = vector.expected_output.decoded as Record<string, unknown>;

    expect(bytesToHex(derived)).toBe(decoded.post_key);
    expect(bytesToHex(derived)).toBe(decoded.nip44_conversation_key);
    expect(JSON.parse(nip44.v2.decrypt(
      vector.expected_output.canonical_wire as string,
      derived,
    ))).toEqual(decoded.plaintext);
  });
});
