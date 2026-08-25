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

export function isStrictNostrSignedEvent(value: unknown): value is NostrSignedEvent {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const event = value as Record<string, unknown>;
  if (
    Object.keys(event).sort().join("\0")
      !== ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"].join("\0")
    || typeof event.pubkey !== "string"
    || !/^[0-9a-f]{64}$/.test(event.pubkey)
    || typeof event.id !== "string"
    || !/^[0-9a-f]{64}$/.test(event.id)
    || typeof event.sig !== "string"
    || !/^[0-9a-f]{128}$/.test(event.sig)
    || !Number.isSafeInteger(event.created_at)
    || (event.created_at as number) < 0
    || !Number.isSafeInteger(event.kind)
    || (event.kind as number) < 0
    || (event.kind as number) > 65_535
    || !Array.isArray(event.tags)
    || !event.tags.every((tag) =>
      Array.isArray(tag)
      && tag.length >= 1
      && tag.every((member) => typeof member === "string"))
    || typeof event.content !== "string"
  ) {
    return false;
  }
  try {
    return verifyEventSignature(event as NostrSignedEvent);
  } catch {
    return false;
  }
}
