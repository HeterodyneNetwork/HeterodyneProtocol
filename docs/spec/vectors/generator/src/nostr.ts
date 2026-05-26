import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";

export type NostrUnsignedEvent = {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};

export type NostrSignedEvent = NostrUnsignedEvent & {
  id: string;
  sig: string;
};

export type SignEventInput = Omit<NostrUnsignedEvent, "pubkey"> & {
  secretKey: string;
  auxRand: string;
};

export function canonicalNip01(event: NostrUnsignedEvent): string {
  return JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
}

export function getEventId(event: NostrUnsignedEvent): string {
  return bytesToHex(sha256(utf8Bytes(canonicalNip01(event))));
}

export function getPublicKey(secretKey: string): string {
  return bytesToHex(schnorr.getPublicKey(hexToBytes(secretKey)));
}

export async function signEvent(input: SignEventInput): Promise<NostrSignedEvent> {
  const event: NostrUnsignedEvent = {
    pubkey: getPublicKey(input.secretKey),
    created_at: input.created_at,
    kind: input.kind,
    tags: input.tags,
    content: input.content,
  };
  const id = getEventId(event);
  const sig = bytesToHex(schnorr.sign(id, hexToBytes(input.secretKey), input.auxRand));
  return { ...event, id, sig };
}

export function verifyEventSignature(event: NostrSignedEvent): boolean {
  if (event.id !== getEventId(event)) {
    return false;
  }
  return schnorr.verify(event.sig, event.id, event.pubkey);
}
