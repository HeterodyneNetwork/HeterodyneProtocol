import { ed25519 } from "@noble/curves/ed25519";
import { base58 } from "@scure/base";
import { describe, expect, it } from "vitest";
import { hexToBytes, utf8Bytes } from "./hex.js";
import {
  didKeyFromEd25519,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  nidBindingPayload,
  nodeAdvertPayload,
} from "./radicle.js";

describe("Radicle / NID helpers", () => {
  it("encodes an Ed25519 did:key as multibase base58btc of the multicodec-prefixed key", () => {
    // RFC 8032 Ed25519 test-1 public key.
    const pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const didKey = didKeyFromEd25519(pub);

    expect(didKey.startsWith("did:key:z6Mk")).toBe(true);
    const decoded = base58.decode(didKey.slice("did:key:z".length));
    expect(decoded[0]).toBe(0xed);
    expect(decoded[1]).toBe(0x01);
    expect(Array.from(decoded.slice(2))).toEqual(Array.from(hexToBytes(pub)));
  });

  it("signs and verifies deterministically with Ed25519 (pure EdDSA)", () => {
    const secret = "01".padStart(64, "0");
    const pub = ed25519PublicKey(secret);
    const message = "heterodyne-nid-binding-v1|npub|nid|radicle-nid-delegation";

    const sig = ed25519Sign(message, secret);
    expect(sig).toHaveLength(128);
    expect(ed25519Sign(message, secret)).toBe(sig);
    expect(ed25519Verify(sig, message, pub)).toBe(true);
    expect(ed25519.verify(hexToBytes(sig), utf8Bytes(message), hexToBytes(pub))).toBe(true);
  });

  it("pins the domain-separated binding payloads", () => {
    expect(nidBindingPayload("aa".repeat(32), "did:key:z6MkExample")).toBe(
      "heterodyne-nid-binding-v1|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|did:key:z6MkExample|radicle-nid-delegation",
    );
    expect(nodeAdvertPayload("rad:zRID", "did:key:z6MkNid", "wss://n.example/relay", 1767312000, "abcd")).toBe(
      "heterodyne-node-advert-v1|rad:zRID|did:key:z6MkNid|wss://n.example/relay|1767312000|abcd",
    );
  });
});
