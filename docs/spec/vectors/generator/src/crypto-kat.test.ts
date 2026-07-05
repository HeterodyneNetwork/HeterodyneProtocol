import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { nip44 } from "nostr-tools";
import * as nip49 from "nostr-tools/nip49";
import { describe, expect, it } from "vitest";
import { configKeyId, nip49EncryptDeterministic } from "./backup-crypto.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";

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

describe("Heterodyne backup crypto (§3.8.7, §6.10.4)", () => {
  it("derives the §6.10.4 self-verifying key_id (first 16 bytes of the domain-separated hash)", () => {
    const audienceKey = "42".repeat(32);
    const domain = utf8Bytes("heterodyne-key-id-v1");
    const key = hexToBytes(audienceKey);
    const preimage = new Uint8Array(domain.length + key.length);
    preimage.set(domain, 0);
    preimage.set(key, domain.length);

    const kid = configKeyId(audienceKey);
    expect(kid).toHaveLength(32);
    expect(kid).toBe(bytesToHex(sha256(preimage)).slice(0, 32));
  });

  it("wraps an nsec deterministically and round-trips through nostr-tools nip49.decrypt", () => {
    const nsec = "0000000000000000000000000000000000000000000000000000000000000001";
    const password = "heterodyne-vector-passphrase";
    const salt = "70".repeat(16);
    const nonce = "71".repeat(24);

    const ncryptsec = nip49EncryptDeterministic(nsec, password, salt, nonce, 16, 2);
    expect(ncryptsec.startsWith("ncryptsec1")).toBe(true);
    expect(nip49EncryptDeterministic(nsec, password, salt, nonce, 16, 2)).toBe(ncryptsec);
    expect(bytesToHex(nip49.decrypt(ncryptsec, password))).toBe(nsec);
  });
});
