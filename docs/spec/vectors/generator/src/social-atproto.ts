import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8Bytes } from "./hex.js";
import { isStrictNostrSignedEvent, type NostrSignedEvent } from "./nostr.js";

export type AtprotoBinding = {
  spec_version: "heterodyne/0.5.0";
  did: string;
  did_signing_key_id: string;
  pubkey: string;
  rid?: string;
  established_at: number;
  generation: number;
  nonce: string;
};

export type AtprotoRevocation = {
  spec_version: "heterodyne/0.5.0";
  record_type: "atproto_link_revocation";
  did: string;
  pubkey: string;
  generation: number;
  nonce: string;
  binding_hash: string;
  revoked_at: number;
};

export type AtprotoBindingDecision =
  | { verdict: "accept"; binding: AtprotoBinding }
  | {
      verdict: "reject";
      reason_code: "atproto-binding-invalid" | "atproto-binding-revoked";
    };

export type AtprotoRevocationDecision =
  | { verdict: "accept"; revocation: AtprotoRevocation }
  | { verdict: "reject"; reason_code: "atproto-revocation-invalid" };

const HEX_32 = /^[0-9a-f]{64}$/;

export function validateAtprotoBinding(input: {
  nostr_event: NostrSignedEvent;
  pds_value: unknown;
  did_signature_valid: boolean;
  did_signed_payload_hash: string;
  previous_binding: AtprotoBinding | null;
  durable_revocations: readonly AtprotoRevocation[];
}): AtprotoBindingDecision {
  const binding = parseBinding(input.pds_value);
  const payloadHash = digestJson(input.pds_value);
  if (
    binding === null
    || !input.did_signature_valid
    || input.did_signed_payload_hash !== payloadHash
    || !isStrictNostrSignedEvent(input.nostr_event)
    || input.nostr_event.kind !== 31009
    || input.nostr_event.pubkey !== binding.pubkey
    || input.nostr_event.created_at !== binding.established_at
    || input.nostr_event.content !== JSON.stringify(input.pds_value)
    || !hasExactSingletonTag(input.nostr_event, ["d", binding.did])
    || !hasExactSingletonTag(input.nostr_event, ["heterodyne", "atproto_link"])
    || !hasExactSingletonTag(input.nostr_event, ["pubkey", binding.pubkey])
    || !hasExactSingletonTag(input.nostr_event, ["did", binding.did])
  ) {
    return { verdict: "reject", reason_code: "atproto-binding-invalid" };
  }
  if (
    input.previous_binding === null
      ? binding.generation !== 1
      : binding.did !== input.previous_binding.did
        || binding.pubkey !== input.previous_binding.pubkey
        || binding.generation !== input.previous_binding.generation + 1
        || binding.established_at <= input.previous_binding.established_at
        || binding.nonce === input.previous_binding.nonce
  ) {
    return { verdict: "reject", reason_code: "atproto-binding-invalid" };
  }
  if (input.durable_revocations.some((revocation) =>
    revocation.did === binding.did
    && revocation.pubkey === binding.pubkey
    && (
      revocation.generation >= binding.generation
      || revocation.nonce === binding.nonce
    ))) {
    return { verdict: "reject", reason_code: "atproto-binding-revoked" };
  }
  return { verdict: "accept", binding };
}

export function validateAtprotoRevocation(input: {
  side: "nostr" | "atproto";
  value: unknown;
  signature_valid: boolean;
  signed_payload_hash: string;
  binding: AtprotoBinding;
  nostr_event?: NostrSignedEvent;
}): AtprotoRevocationDecision {
  const revocation = parseRevocation(input.value);
  if (
    revocation === null
    || !input.signature_valid
    || input.signed_payload_hash !== digestJson(input.value)
    || revocation.did !== input.binding.did
    || revocation.pubkey !== input.binding.pubkey
    || revocation.generation !== input.binding.generation
    || revocation.nonce !== input.binding.nonce
    || revocation.binding_hash !== digestJson(input.binding)
    || revocation.revoked_at < input.binding.established_at
  ) {
    return { verdict: "reject", reason_code: "atproto-revocation-invalid" };
  }
  if (input.side === "nostr") {
    const event = input.nostr_event;
    if (
      !isStrictNostrSignedEvent(event)
      || event.kind !== 31009
      || event.pubkey !== revocation.pubkey
      || event.created_at !== revocation.revoked_at
      || event.content !== JSON.stringify(input.value)
      || !hasExactSingletonTag(event, [
        "d",
        `revocation:${revocation.did}:${revocation.generation}:${revocation.nonce}`,
      ])
      || !hasExactSingletonTag(event, ["heterodyne", "atproto_link_revocation"])
      || !hasExactSingletonTag(event, ["did", revocation.did])
      || !hasExactSingletonTag(event, ["pubkey", revocation.pubkey])
    ) {
      return { verdict: "reject", reason_code: "atproto-revocation-invalid" };
    }
  } else if (input.nostr_event !== undefined) {
    return { verdict: "reject", reason_code: "atproto-revocation-invalid" };
  }
  return { verdict: "accept", revocation };
}

function parseBinding(value: unknown): AtprotoBinding | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort().join("\0");
  if (
    keys !== [
      "did", "did_signing_key_id", "established_at", "generation", "nonce",
      "pubkey", "spec_version",
    ]
      .join("\0")
    && keys !== [
      "did", "did_signing_key_id", "established_at", "generation", "nonce",
      "pubkey", "rid", "spec_version",
    ]
      .join("\0")
  ) return null;
  if (
    record.spec_version !== "heterodyne/0.5.0"
    || typeof record.did !== "string"
    || !record.did.startsWith("did:")
    || typeof record.did_signing_key_id !== "string"
    || record.did_signing_key_id.length === 0
    || typeof record.pubkey !== "string"
    || !HEX_32.test(record.pubkey)
    || !Number.isSafeInteger(record.established_at)
    || (record.established_at as number) < 0
    || !Number.isSafeInteger(record.generation)
    || (record.generation as number) < 1
    || typeof record.nonce !== "string"
    || !HEX_32.test(record.nonce)
    || record.rid !== undefined && (typeof record.rid !== "string" || record.rid.length === 0)
  ) return null;
  return record as AtprotoBinding;
}

function parseRevocation(value: unknown): AtprotoRevocation | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join("\0") !== [
      "binding_hash", "did", "generation", "nonce", "pubkey", "record_type",
      "revoked_at", "spec_version",
    ].join("\0")
    || record.spec_version !== "heterodyne/0.5.0"
    || record.record_type !== "atproto_link_revocation"
    || typeof record.did !== "string"
    || !record.did.startsWith("did:")
    || typeof record.pubkey !== "string"
    || !HEX_32.test(record.pubkey)
    || !Number.isSafeInteger(record.generation)
    || (record.generation as number) < 1
    || typeof record.nonce !== "string"
    || !HEX_32.test(record.nonce)
    || typeof record.binding_hash !== "string"
    || !HEX_32.test(record.binding_hash)
    || !Number.isSafeInteger(record.revoked_at)
    || (record.revoked_at as number) < 0
  ) return null;
  return record as AtprotoRevocation;
}

function digestJson(value: unknown): string {
  return bytesToHex(sha256(utf8Bytes(JSON.stringify(value))));
}

function hasExactSingletonTag(event: NostrSignedEvent, expected: string[]): boolean {
  const matches = event.tags.filter((tag) => tag[0] === expected[0]);
  return matches.length === 1
    && matches[0].length === expected.length
    && matches[0].every((member, index) => member === expected[index]);
}
