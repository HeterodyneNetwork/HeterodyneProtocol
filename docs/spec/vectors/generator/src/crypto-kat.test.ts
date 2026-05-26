import { schnorr } from "@noble/curves/secp256k1";
import { nip44 } from "nostr-tools";
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes } from "./hex.js";

describe("external crypto known-answer vectors", () => {
  it("reproduces official BIP-340 Schnorr vector 0", () => {
    const secretKey = "0000000000000000000000000000000000000000000000000000000000000003";
    const publicKey = "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9";
    const auxRand = "0000000000000000000000000000000000000000000000000000000000000000";
    const message = "0000000000000000000000000000000000000000000000000000000000000000";
    const signature =
      "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F" +
      "66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";

    expect(bytesToHex(schnorr.getPublicKey(hexToBytes(secretKey)))).toBe(publicKey.toLowerCase());
    expect(bytesToHex(schnorr.sign(message, hexToBytes(secretKey), auxRand))).toBe(signature.toLowerCase());
    expect(schnorr.verify(signature, message, publicKey)).toBe(true);
  });

  it("reproduces official NIP-44 v2 encrypt/decrypt vector 0", () => {
    const conversationKey = hexToBytes("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
    const nonce = hexToBytes("0000000000000000000000000000000000000000000000000000000000000001");
    const plaintext = "a";
    const payload =
      "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNa" +
      "CXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";

    expect(nip44.v2.encrypt(plaintext, conversationKey, nonce)).toBe(payload);
    expect(nip44.v2.decrypt(payload, conversationKey)).toBe(plaintext);
  });
});
