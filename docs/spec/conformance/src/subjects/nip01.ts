import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import type { NostrSignedEvent } from "./types.js";

const HEX_32 = /^[0-9a-f]{64}$/u;
const HEX_64 = /^[0-9a-f]{128}$/u;
const EVENT_KEYS = ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"];

export type Nip01Tuple = [0, string, number, number, string[][], string];

export type BoundNip01Raw = {
  raw: string;
  bytes: Uint8Array;
  tuple: Nip01Tuple;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringTagArray(value: unknown): value is string[][] {
  return Array.isArray(value)
    && value.every((tag) => Array.isArray(tag)
      && tag.every((part) => typeof part === "string"));
}

export function isNostrSignedEvent(value: unknown): value is NostrSignedEvent {
  if (!isRecord(value) || Object.keys(value).sort().join("\0") !== EVENT_KEYS.join("\0")) {
    return false;
  }
  return typeof value.id === "string"
    && HEX_32.test(value.id)
    && typeof value.pubkey === "string"
    && HEX_32.test(value.pubkey)
    && Number.isSafeInteger(value.created_at)
    && (value.created_at as number) >= 0
    && Number.isSafeInteger(value.kind)
    && (value.kind as number) >= 0
    && (value.kind as number) <= 65_535
    && isStringTagArray(value.tags)
    && typeof value.content === "string"
    && typeof value.sig === "string"
    && HEX_64.test(value.sig);
}

function isNip01Tuple(value: unknown): value is Nip01Tuple {
  return Array.isArray(value)
    && value.length === 6
    && value[0] === 0
    && typeof value[1] === "string"
    && HEX_32.test(value[1])
    && Number.isSafeInteger(value[2])
    && value[2] >= 0
    && Number.isSafeInteger(value[3])
    && value[3] >= 0
    && value[3] <= 65_535
    && isStringTagArray(value[4])
    && typeof value[5] === "string";
}

export function bindNip01Raw(event: NostrSignedEvent, raw: unknown): BoundNip01Raw | undefined {
  if (typeof raw !== "string") {
    return undefined;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }

  if (!isNip01Tuple(parsed) || JSON.stringify(parsed) !== raw) {
    return undefined;
  }

  if (
    parsed[1] !== event.pubkey
    || parsed[2] !== event.created_at
    || parsed[3] !== event.kind
    || JSON.stringify(parsed[4]) !== JSON.stringify(event.tags)
    || parsed[5] !== event.content
  ) {
    return undefined;
  }

  return { raw, bytes: new TextEncoder().encode(raw), tuple: parsed };
}

export function computeNip01Digest(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

export function computeNip01Id(bytes: Uint8Array): string {
  return Buffer.from(computeNip01Digest(bytes)).toString("hex");
}

export function verifyNip01Signature(event: NostrSignedEvent, digest: Uint8Array): boolean {
  try {
    return schnorr.verify(event.sig, digest, event.pubkey);
  } catch {
    return false;
  }
}
