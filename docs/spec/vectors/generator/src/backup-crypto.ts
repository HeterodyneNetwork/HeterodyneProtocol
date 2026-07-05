import { scrypt } from "@noble/hashes/scrypt";
import { sha256 } from "@noble/hashes/sha2";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { bech32 } from "@scure/base";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";

const BECH32_MAX_SIZE = 5000;

// §6.10.4 RECOMMENDED self-verifying key_id derivation:
//   key_id = lowercase-hex(SHA-256("heterodyne-key-id-v1" || audience_key))[0..32]
// i.e. the first 16 bytes (32 hex chars) of the domain-separated hash of the
// raw 32-byte audience key.
export function configKeyId(audienceKeyHex: string): string {
  const domain = utf8Bytes("heterodyne-key-id-v1");
  const key = hexToBytes(audienceKeyHex);
  const preimage = new Uint8Array(domain.length + key.length);
  preimage.set(domain, 0);
  preimage.set(key, domain.length);
  return bytesToHex(sha256(preimage).slice(0, 16));
}

// Deterministic NIP-49 (ncryptsec) encryption. The nostr-tools nip49.encrypt
// draws a random 16-byte salt and 24-byte nonce; this variant takes both as
// pinned fixture bytes so the vector is reproducible. The output is a standard
// ncryptsec string that nostr-tools nip49.decrypt round-trips (asserted in
// crypto-kat.test.ts).
export function nip49EncryptDeterministic(
  secretKeyHex: string,
  password: string,
  saltHex: string,
  nonceHex: string,
  logn = 16,
  ksb = 2,
): string {
  const salt = hexToBytes(saltHex);
  const nonce = hexToBytes(nonceHex);
  if (salt.length !== 16) {
    throw new Error(`nip49 salt must be 16 bytes, got ${salt.length}`);
  }
  if (nonce.length !== 24) {
    throw new Error(`nip49 nonce must be 24 bytes, got ${nonce.length}`);
  }
  const n = 2 ** logn;
  const key = scrypt(password.normalize("NFKC"), salt, { N: n, r: 8, p: 1, dkLen: 32 });
  const aad = Uint8Array.from([ksb]);
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(hexToBytes(secretKeyHex));
  const concatenated = concatBytes(Uint8Array.from([2]), Uint8Array.from([logn]), salt, nonce, aad, ciphertext);
  return bech32.encode("ncryptsec", bech32.toWords(concatenated), BECH32_MAX_SIZE);
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}
