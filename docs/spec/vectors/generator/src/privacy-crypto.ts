import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { hexToBytes, utf8Bytes } from "./hex.js";

export function deriveTier3IndexKey(
  audienceKeyHex: string,
  keyId: string,
): Uint8Array {
  return hkdf(
    sha256,
    hexToBytes(audienceKeyHex),
    utf8Bytes(keyId),
    utf8Bytes("heterodyne-index-key-v1"),
    32,
  );
}

export function deriveConfigPostKey(
  configAudienceKeyHex: string,
  keyId: string,
): Uint8Array {
  return hkdf(
    sha256,
    hexToBytes(configAudienceKeyHex),
    utf8Bytes(keyId),
    utf8Bytes("heterodyne-post-key-v1"),
    32,
  );
}
