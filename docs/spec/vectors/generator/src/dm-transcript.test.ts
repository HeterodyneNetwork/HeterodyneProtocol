import { describe, expect, it } from "vitest";
import { generateDmTranscript } from "./dm-transcript.js";
import { DoubleRatchetSession } from "./ndr.js";
import { buildFixtures } from "./fixtures.js";
import { hexToBytes } from "./hex.js";
import { getPublicKey, verifyEventSignature } from "./nostr.js";

const fixtures = buildFixtures();

describe("dm transcript KAT (nostr-double-ratchet@0.0.138)", () => {
  const transcript = generateDmTranscript(fixtures);

  it("is deterministic across generations", () => {
    const again = generateDmTranscript(fixtures);
    expect(JSON.stringify(again)).toEqual(JSON.stringify(transcript));
  });

  it("produces five kind:1060 outer events with valid signatures", () => {
    expect(transcript.messages).toHaveLength(5);
    for (const message of transcript.messages) {
      expect(message.outer_event.kind).toBe(1060);
      expect(verifyEventSignature(message.outer_event)).toBe(true);
    }
  });

  it("outer signer is the current ratchet key: same chain shares it, DH ratchet rotates it", () => {
    const [a1, a2, b1, a3, b2] = transcript.messages;
    expect(a1.outer_event.pubkey).toBe(a2.outer_event.pubkey);
    expect(a1.outer_event.pubkey).toBe(transcript.alice_session_pubkey);
    expect(b1.outer_event.pubkey).toBe(transcript.bob_session_pubkey);
    expect(a3.outer_event.pubkey).not.toBe(a1.outer_event.pubkey);
    expect(b2.outer_event.pubkey).not.toBe(b1.outer_event.pubkey);
    // The post-ratchet signer is exactly the nextPublicKey advertised in the
    // prior chain's headers.
    expect(a3.outer_event.pubkey).toBe(a1.header_plaintext.nextPublicKey);
    expect(b2.outer_event.pubkey).toBe(b1.header_plaintext.nextPublicKey);
  });

  it("receive-side recovers every inner rumor in delivery order", () => {
    // receiveEvent() ran inside the deterministic generation sequence; every
    // delivered outer event must decrypt back to the exact sent rumor.
    expect(transcript.received_rumors).toHaveLength(5);
    for (const message of transcript.messages) {
      const rumor = transcript.received_rumors[message.seq];
      expect(rumor, `seq ${message.seq} must decrypt`).toBeDefined();
      expect(rumor?.content).toBe(message.plaintext);
      expect(rumor?.kind).toBe(14);
      expect(JSON.stringify(rumor)).toBe(JSON.stringify(message.inner_rumor));
    }
  });

  it("pinned ratchet keys are exactly the transcript's DH ratchet keys", () => {
    const [a1, , b1, a3, b2] = transcript.messages;
    const [aliceEpoch1, aliceEpoch2] = transcript.ratchet_keys.alice;
    const [bobEpoch1, bobEpoch2] = transcript.ratchet_keys.bob;
    for (const key of [...transcript.ratchet_keys.alice, ...transcript.ratchet_keys.bob]) {
      expect(getPublicKey(key.secret_key)).toBe(key.public_key);
    }
    // Epoch-1 keys are advertised in the prior chain's headers and become the
    // post-ratchet outer signers; epoch-2 keys are advertised in the
    // post-ratchet chain's headers.
    expect(aliceEpoch1.public_key).toBe(a1.header_plaintext.nextPublicKey);
    expect(aliceEpoch1.public_key).toBe(a3.outer_event.pubkey);
    expect(bobEpoch1.public_key).toBe(b1.header_plaintext.nextPublicKey);
    expect(bobEpoch1.public_key).toBe(b2.outer_event.pubkey);
    expect(aliceEpoch2.public_key).toBe(a3.header_plaintext.nextPublicKey);
    expect(bobEpoch2.public_key).toBe(b2.header_plaintext.nextPublicKey);
  });

  it("recovers a skipped message out of order via skipped-key handling", () => {
    const bob = DoubleRatchetSession.init(
      transcript.alice_session_pubkey,
      hexToBytes(transcript.bob_session_sk),
      false,
      hexToBytes(transcript.shared_secret),
    );
    const [a1, a2] = transcript.messages;
    const second = bob.receiveEvent(a2.outer_event);
    expect(second?.content).toBe(a2.plaintext);
    const first = bob.receiveEvent(a1.outer_event);
    expect(first?.content).toBe(a1.plaintext);
  });
});
