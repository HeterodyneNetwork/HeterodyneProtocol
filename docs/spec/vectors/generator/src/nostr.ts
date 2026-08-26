import { types as utilTypes } from "node:util";
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

declare const verifiedNostrEventBrand: unique symbol;
export type VerifiedNostrEvent = NostrSignedEvent & {
  readonly [verifiedNostrEventBrand]: true;
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
  return snapshotAndVerifyNostrEvent(event) !== null;
}

export function isStrictNostrSignedEvent(value: unknown): value is NostrSignedEvent {
  return snapshotAndVerifyNostrEvent(value) !== null;
}

const VERIFIED_NOSTR_EVENTS = new WeakSet<object>();
const SIGNED_EVENT_MEMBERS = [
  "content",
  "created_at",
  "id",
  "kind",
  "pubkey",
  "sig",
  "tags",
] as const;

export function isVerifiedNostrEvent(value: unknown): value is VerifiedNostrEvent {
  return value !== null
    && typeof value === "object"
    && VERIFIED_NOSTR_EVENTS.has(value);
}

export function snapshotAndVerifyNostrEvent(value: unknown): VerifiedNostrEvent | null {
  if (isVerifiedNostrEvent(value)) return value;
  const event = snapshotSignedEvent(value);
  if (event === null) return null;
  const raw = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
  const digest = sha256(utf8Bytes(raw));
  if (event.id !== bytesToHex(digest)) return null;
  try {
    if (!schnorr.verify(event.sig, digest, event.pubkey)) return null;
  } catch {
    return null;
  }
  for (const tag of event.tags) Object.freeze(tag);
  Object.freeze(event.tags);
  Object.freeze(event);
  VERIFIED_NOSTR_EVENTS.add(event);
  return event as VerifiedNostrEvent;
}

function snapshotSignedEvent(value: unknown): NostrSignedEvent | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  try {
    if (utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
      return null;
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.some((key) => typeof key !== "string")
      || keys.length !== SIGNED_EVENT_MEMBERS.length
      || !SIGNED_EVENT_MEMBERS.every((member) => Object.hasOwn(descriptors, member))
    ) return null;
    const read = (member: typeof SIGNED_EVENT_MEMBERS[number]): unknown => {
      const descriptor = descriptors[member];
      return descriptor !== undefined
        && "value" in descriptor
        && descriptor.enumerable === true
        ? descriptor.value
        : undefined;
    };
    const pubkey = read("pubkey");
    const createdAt = read("created_at");
    const kind = read("kind");
    const tags = snapshotTags(read("tags"));
    const content = read("content");
    const id = read("id");
    const sig = read("sig");
    if (
      typeof pubkey !== "string"
      || !/^[0-9a-f]{64}$/.test(pubkey)
      || !Number.isSafeInteger(createdAt)
      || (createdAt as number) < 0
      || !Number.isSafeInteger(kind)
      || (kind as number) < 0
      || (kind as number) > 65_535
      || tags === null
      || typeof content !== "string"
      || typeof id !== "string"
      || !/^[0-9a-f]{64}$/.test(id)
      || typeof sig !== "string"
      || !/^[0-9a-f]{128}$/.test(sig)
    ) return null;
    return {
      pubkey,
      created_at: createdAt as number,
      kind: kind as number,
      tags,
      content,
      id,
      sig,
    };
  } catch {
    return null;
  }
}

function snapshotTags(value: unknown): string[][] | null {
  if (!Array.isArray(value) || utilTypes.isProxy(value)) return null;
  if (Object.getPrototypeOf(value) !== Array.prototype) return null;
  const tags = snapshotDenseArray(value);
  if (tags === null) return null;
  const snapshot: string[][] = [];
  for (const tagValue of tags) {
    if (!Array.isArray(tagValue) || utilTypes.isProxy(tagValue)) return null;
    if (Object.getPrototypeOf(tagValue) !== Array.prototype) return null;
    const members = snapshotDenseArray(tagValue);
    if (
      members === null
      || members.length === 0
      || members.some((member) => typeof member !== "string")
    ) return null;
    snapshot.push(members as string[]);
  }
  return snapshot;
}

function snapshotDenseArray(value: unknown[]): unknown[] | null {
  const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as PropertyDescriptorMap;
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) return null;
  const lengthDescriptor = descriptors.length;
  if (
    lengthDescriptor === undefined
    || !("value" in lengthDescriptor)
    || !Number.isSafeInteger(lengthDescriptor.value)
    || lengthDescriptor.value < 0
  ) return null;
  const length = lengthDescriptor.value as number;
  if (keys.length !== length + 1) return null;
  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      descriptor === undefined
      || !("value" in descriptor)
      || descriptor.enumerable !== true
    ) return null;
    snapshot.push(descriptor.value);
  }
  return snapshot;
}
