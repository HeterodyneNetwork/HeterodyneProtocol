import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";

// Multicodec prefix for an Ed25519 public key (varint 0xed 0x01), per the
// did:key method and the multicodec table.
const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);

export function ed25519PublicKey(secretHex: string): string {
  return bytesToHex(ed25519.getPublicKey(hexToBytes(secretHex)));
}

export function ed25519Sign(message: string, secretHex: string): string {
  return bytesToHex(ed25519.sign(utf8Bytes(message), hexToBytes(secretHex)));
}

export function ed25519Verify(sigHex: string, message: string, pubHex: string): boolean {
  return ed25519.verify(hexToBytes(sigHex), utf8Bytes(message), hexToBytes(pubHex));
}

// did:key for an Ed25519 public key: multibase base58btc ("z" prefix) of the
// multicodec-prefixed raw public key.
export function didKeyFromEd25519(pubHex: string): string {
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + 32);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(hexToBytes(pubHex), ED25519_MULTICODEC.length);
  return `did:key:z${base58.encode(prefixed)}`;
}

// A deterministic fixture RID. Real Radicle RIDs are derived from a live
// repository; these are stable base58btc fixture identifiers of the shape
// `rad:z...` so vectors can reference an npub->RID binding without a repo.
export function fixtureRid(seed: string): string {
  const digest = sha256(utf8Bytes(`heterodyne-fixture-rid|${seed}`)).slice(0, 20);
  return `rad:z${base58.encode(digest)}`;
}

// Binding payload signed by BOTH the epoch key (via the outer Nostr sig over
// the tags) AND the NID's Ed25519 nid_proof for a kind:31001 NID delegation.
// The serialization is pinned by spec section 3.3.1.
export function nidBindingPayload(npubHex: string, nidDidKey: string): string {
  return `heterodyne-nid-binding-v1|${npubHex}|${nidDidKey}|radicle-nid-delegation`;
}

// Payload signed by the advertised NID's Ed25519 nid_proof for a kind:31010
// node/repo advertisement (section 7.0). The spec fixes the bound fields (RID,
// NID, endpoint, expiry, current canonical repo head) and defers the exact
// serialization to this vector; the domain-separated form below is that
// serialization.
export function nodeAdvertPayload(
  rid: string,
  nidDidKey: string,
  endpoint: string,
  expiry: number,
  repoHead: string,
): string {
  return `heterodyne-node-advert-v1|${rid}|${nidDidKey}|${endpoint}|${expiry}|${repoHead}`;
}
