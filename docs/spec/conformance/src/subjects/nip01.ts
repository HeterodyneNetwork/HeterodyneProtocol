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

type Nip01EventFields = Pick<
  NostrSignedEvent,
  "pubkey" | "created_at" | "kind" | "tags" | "content"
>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringTagArray(value: unknown): value is string[][] {
  return Array.isArray(value)
    && value.every((tag) => Array.isArray(tag)
      && tag.every((part) => typeof part === "string"));
}

function isNip01EventFields(value: unknown): value is Nip01EventFields & Record<string, unknown> {
  return isRecord(value)
    && typeof value.pubkey === "string"
    && HEX_32.test(value.pubkey)
    && Number.isSafeInteger(value.created_at)
    && (value.created_at as number) >= 0
    && Number.isSafeInteger(value.kind)
    && (value.kind as number) >= 0
    && (value.kind as number) <= 65_535
    && isStringTagArray(value.tags)
    && typeof value.content === "string";
}

export function isNostrSignedEvent(value: unknown): value is NostrSignedEvent {
  if (!isRecord(value) || Object.keys(value).sort().join("\0") !== EVENT_KEYS.join("\0")) {
    return false;
  }
  return isNip01EventFields(value)
    && typeof value.id === "string"
    && HEX_32.test(value.id)
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

function isCompactJson(source: string): boolean {
  let inString = false;
  let escaped = false;
  for (const character of source) {
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
    } else if (character === '"') {
      inString = true;
    } else if (character === " " || character === "\t" || character === "\n" || character === "\r") {
      return false;
    }
  }
  return !inString && !escaped;
}

function equalTags(left: readonly string[][], right: readonly string[][]): boolean {
  return left.length === right.length
    && left.every((tag, index) => {
      const other = right[index];
      return other !== undefined
        && tag.length === other.length
        && tag.every((part, partIndex) => part === other[partIndex]);
    });
}

export function bindNip01Raw(event: unknown, raw: unknown): BoundNip01Raw | undefined {
  if (!isNip01EventFields(event) || typeof raw !== "string" || !isCompactJson(raw)) {
    return undefined;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }

  if (!isNip01Tuple(parsed)) {
    return undefined;
  }

  if (
    parsed[1] !== event.pubkey
    || parsed[2] !== event.created_at
    || parsed[3] !== event.kind
    || !equalTags(parsed[4], event.tags)
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
