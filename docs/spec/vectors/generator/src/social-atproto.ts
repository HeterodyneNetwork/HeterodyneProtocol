import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import { bytesToHex, utf8Bytes } from "./hex.js";
import {
  authenticateAtprotoBindingObservation,
  authenticateAtprotoDidResolution,
  currentAtprotoDidMethod,
  verifyAtprotoDidSignature,
  type AtprotoBindingObservationEvidence,
  type AtprotoResolutionEvidence,
  type AtprotoResolverAuthority,
} from "./atproto-did-resolution.js";
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
  predecessor: null | { event_id: string; binding_hash: string };
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

export type AtprotoBindingEvidence = {
  nostr_event: NostrSignedEvent;
  pds_value: unknown;
  did_signature: string;
  resolution_evidence: AtprotoResolutionEvidence;
  observation_evidence?: AtprotoBindingObservationEvidence;
};

export type AtprotoRevocationEvidence =
  | { side: "nostr"; nostr_event: NostrSignedEvent }
  | { side: "atproto"; value: unknown; did_signature: string };

export type AtprotoBindingDecision =
  | { verdict: "accept"; binding: AtprotoBinding; selected_event_id: string }
  | {
      verdict: "reject";
      reason_code: "atproto-binding-invalid" | "atproto-binding-revoked";
    };

export type AtprotoRevocationDecision =
  | { verdict: "accept"; revocation: AtprotoRevocation }
  | { verdict: "reject"; reason_code: "atproto-revocation-invalid" };

const HEX_32 = /^[0-9a-f]{64}$/;

export function validateAtprotoBinding(input: {
  did: string;
  pubkey: string;
  candidates: readonly AtprotoBindingEvidence[];
  lineage: readonly AtprotoBindingEvidence[];
  revocations: readonly AtprotoRevocationEvidence[];
  resolver_authority: AtprotoResolverAuthority;
  current_resolution: AtprotoResolutionEvidence;
  now: number;
}): AtprotoBindingDecision {
  if (!HEX_32.test(input.pubkey)) {
    return { verdict: "reject", reason_code: "atproto-binding-invalid" };
  }
  const valid = new Map<string, { binding: AtprotoBinding; event: NostrSignedEvent }>();
  for (const candidate of input.candidates) {
    const checked = validateBindingEvidence(
      candidate,
      input.did,
      input.pubkey,
      input.now,
      input.resolver_authority,
      false,
    );
    if (checked !== null) valid.set(checked.event.id, checked);
  }
  const current = [...valid.values()].sort((left, right) =>
    right.event.created_at - left.event.created_at
    || left.event.id.localeCompare(right.event.id))[0];
  if (current === undefined) {
    return { verdict: "reject", reason_code: "atproto-binding-invalid" };
  }
  const historical = new Map<string, { binding: AtprotoBinding; event: NostrSignedEvent }>();
  for (const evidence of [...input.candidates, ...input.lineage]) {
    const checked = validateBindingEvidence(
      evidence,
      input.did,
      input.pubkey,
      evidence.nostr_event.created_at,
      input.resolver_authority,
      evidence.nostr_event.id !== current.event.id,
    );
    if (checked !== null) historical.set(checked.event.id, checked);
  }
  const chain = validateLineage(current, historical);
  if (chain === null) {
    return { verdict: "reject", reason_code: "atproto-binding-invalid" };
  }
  const universe = historical;
  const verifiedRevocations = input.revocations.flatMap((evidence) => {
    const target = [...universe.values()].find(({ binding }) =>
      revocationTargetsBinding(evidence, binding));
    if (target === undefined) return [];
    const decision = validateAtprotoRevocation({
      evidence,
      binding: target.binding,
      resolver_authority: input.resolver_authority,
      current_resolution: input.current_resolution,
      now: input.now,
    });
    return decision.verdict === "accept" ? [decision.revocation] : [];
  });
  for (const revocation of verifiedRevocations) {
    const target = chain.find(({ binding }) =>
      binding.did === revocation.did
      && binding.pubkey === revocation.pubkey
      && binding.generation === revocation.generation
      && binding.nonce === revocation.nonce
      && digestAtprotoBinding(binding) === revocation.binding_hash);
    if (target === undefined || revocation.generation === current.binding.generation) {
      return { verdict: "reject", reason_code: "atproto-binding-revoked" };
    }
    const recovery = chain.find(({ binding }) =>
      binding.generation === revocation.generation + 1);
    if (
      recovery === undefined
      || recovery.binding.established_at <= revocation.revoked_at
      || recovery.binding.nonce === revocation.nonce
    ) {
      return { verdict: "reject", reason_code: "atproto-binding-revoked" };
    }
  }
  return {
    verdict: "accept",
    binding: current.binding,
    selected_event_id: current.event.id,
  };
}

export function validateAtprotoRevocation(input: {
  evidence: AtprotoRevocationEvidence;
  binding: AtprotoBinding;
  resolver_authority: AtprotoResolverAuthority;
  current_resolution: AtprotoResolutionEvidence;
  now: number;
}): AtprotoRevocationDecision {
  const value = input.evidence.side === "nostr"
    ? parseJson(input.evidence.nostr_event.content)
    : input.evidence.value;
  const revocation = parseRevocation(value);
  const canonicalPayload = revocation === null ? null : serializeAtprotoRevocation(revocation);
  if (
    revocation === null
    || canonicalPayload === null
    || revocation.did !== input.binding.did
    || revocation.pubkey !== input.binding.pubkey
    || revocation.generation !== input.binding.generation
    || revocation.nonce !== input.binding.nonce
    || revocation.binding_hash !== digestAtprotoBinding(input.binding)
    || revocation.revoked_at < input.binding.established_at
  ) {
    return { verdict: "reject", reason_code: "atproto-revocation-invalid" };
  }
  if (input.evidence.side === "nostr") {
    const event = input.evidence.nostr_event;
    if (
      !isStrictNostrSignedEvent(event)
      || event.kind !== 31009
      || event.pubkey !== revocation.pubkey
      || event.created_at !== revocation.revoked_at
      || event.content !== canonicalPayload
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
  } else {
    const resolution = authenticateAtprotoDidResolution({
      authority: input.resolver_authority,
      evidence: input.current_resolution,
      validation_time: input.now,
    });
    if (resolution.verdict !== "accept") {
      return { verdict: "reject", reason_code: "atproto-revocation-invalid" };
    }
    const currentMethod = currentAtprotoDidMethod({
      authority: input.resolver_authority,
      resolution: resolution.resolution,
      did: input.binding.did,
      validation_time: input.now,
    });
    if (
      currentMethod === null
      || !verifyAtprotoDidSignature({
        authority: input.resolver_authority,
        resolution: resolution.resolution,
        did: input.binding.did,
        verification_method_id: currentMethod,
        payload: canonicalPayload,
        signature: input.evidence.did_signature,
        validation_time: input.now,
      })
    ) return { verdict: "reject", reason_code: "atproto-revocation-invalid" };
  }
  return { verdict: "accept", revocation };
}

function validateBindingEvidence(
  evidence: AtprotoBindingEvidence,
  expectedDid: string,
  expectedPubkey: string,
  validationTime: number,
  resolverAuthority: AtprotoResolverAuthority,
  requireObservation: boolean,
): {
  binding: AtprotoBinding;
  event: NostrSignedEvent;
} | null {
  const evidenceKeys = Object.keys(evidence).sort().join("\0");
  if (
    evidenceKeys !== "did_signature\0nostr_event\0pds_value\0resolution_evidence"
    && evidenceKeys
      !== "did_signature\0nostr_event\0observation_evidence\0pds_value\0resolution_evidence"
  ) return null;
  const binding = parseBinding(evidence.pds_value);
  if (binding === null) return null;
  const canonicalPayload = serializeAtprotoBinding(binding);
  const event = evidence.nostr_event;
  const resolution = authenticateAtprotoDidResolution({
    authority: resolverAuthority,
    evidence: evidence.resolution_evidence,
    validation_time: validationTime,
  });
  if (
    binding.did !== expectedDid
    || binding.pubkey !== expectedPubkey
    || resolution.verdict !== "accept"
    || !verifyAtprotoDidSignature({
      authority: resolverAuthority,
      resolution: resolution.verdict === "accept" ? resolution.resolution : null,
      did: binding.did,
      verification_method_id: binding.did_signing_key_id,
      payload: canonicalPayload,
      signature: evidence.did_signature,
      validation_time: validationTime,
    })
    || !isStrictNostrSignedEvent(event)
    || event.kind !== 31009
    || event.pubkey !== binding.pubkey
    || event.created_at !== binding.established_at
    || event.content !== canonicalPayload
    || !hasExactSingletonTag(event, ["d", binding.did])
    || !hasExactSingletonTag(event, ["heterodyne", "atproto_link"])
    || !hasExactSingletonTag(event, ["pubkey", binding.pubkey])
    || !hasExactSingletonTag(event, ["did", binding.did])
  ) return null;
  if (
    requireObservation
    && (
      evidence.observation_evidence === undefined
      || authenticateAtprotoBindingObservation({
        authority: resolverAuthority,
        evidence: evidence.observation_evidence,
        resolution_evidence: evidence.resolution_evidence,
        expected_binding: {
          binding_event_id: event.id,
          binding_hash: digestAtprotoBinding(binding),
          did: binding.did,
          pubkey: binding.pubkey,
          generation: binding.generation,
          event_created_at: event.created_at,
        },
      }).verdict !== "accept"
    )
  ) return null;
  return { binding, event };
}

function validateLineage(
  current: { binding: AtprotoBinding; event: NostrSignedEvent },
  historical: ReadonlyMap<string, { binding: AtprotoBinding; event: NostrSignedEvent }>,
): Array<{ binding: AtprotoBinding; event: NostrSignedEvent }> | null {
  const chain = [current];
  const used = new Set<string>();
  const nonces = new Set([current.binding.nonce]);
  let cursor = current;
  while (cursor.binding.generation > 1) {
    const predecessor = cursor.binding.predecessor;
    if (predecessor === null || used.has(predecessor.event_id)) return null;
    const previous = historical.get(predecessor.event_id);
    if (
      previous === undefined
      || previous.event.id !== predecessor.event_id
      || digestAtprotoBinding(previous.binding) !== predecessor.binding_hash
      || previous.binding.did !== cursor.binding.did
      || previous.binding.pubkey !== cursor.binding.pubkey
      || previous.binding.generation !== cursor.binding.generation - 1
      || previous.binding.established_at >= cursor.binding.established_at
      || nonces.has(previous.binding.nonce)
    ) return null;
    used.add(predecessor.event_id);
    nonces.add(previous.binding.nonce);
    chain.push(previous);
    cursor = previous;
  }
  return cursor.binding.predecessor === null ? chain : null;
}

function revocationTargetsBinding(
  evidence: AtprotoRevocationEvidence,
  binding: AtprotoBinding,
): boolean {
  const value = evidence.side === "nostr"
    ? parseJson(evidence.nostr_event.content)
    : evidence.value;
  const revocation = parseRevocation(value);
  return revocation !== null
    && revocation.did === binding.did
    && revocation.pubkey === binding.pubkey
    && revocation.generation === binding.generation
    && revocation.nonce === binding.nonce
    && revocation.binding_hash === digestAtprotoBinding(binding);
}

function parseBinding(value: unknown): AtprotoBinding | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort().join("\0");
  if (
    keys !== [
      "did", "did_signing_key_id", "established_at", "generation", "nonce",
      "predecessor", "pubkey", "spec_version",
    ]
      .join("\0")
    && keys !== [
      "did", "did_signing_key_id", "established_at", "generation", "nonce",
      "predecessor", "pubkey", "rid", "spec_version",
    ]
      .join("\0")
  ) return null;
  if (
    record.spec_version !== "heterodyne/0.5.0"
    || typeof record.did !== "string"
    || !isCanonicalDid(record.did)
    || typeof record.did_signing_key_id !== "string"
    || !record.did_signing_key_id.startsWith(`${record.did}#`)
    || !/^[A-Za-z0-9._~-]+$/u.test(record.did_signing_key_id.slice(record.did.length + 1))
    || typeof record.pubkey !== "string"
    || !HEX_32.test(record.pubkey)
    || !Number.isSafeInteger(record.established_at)
    || (record.established_at as number) < 0
    || !Number.isSafeInteger(record.generation)
    || (record.generation as number) < 1
    || typeof record.nonce !== "string"
    || !HEX_32.test(record.nonce)
    || !validPredecessor(record.predecessor, record.generation as number)
    || record.rid !== undefined
      && (typeof record.rid !== "string" || !isCanonicalRid(record.rid))
  ) return null;
  return {
    spec_version: "heterodyne/0.5.0",
    did: record.did,
    did_signing_key_id: record.did_signing_key_id,
    pubkey: record.pubkey,
    ...(record.rid === undefined ? {} : { rid: record.rid as string }),
    established_at: record.established_at as number,
    generation: record.generation as number,
    nonce: record.nonce,
    predecessor: record.predecessor as AtprotoBinding["predecessor"],
  };
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
    || !isCanonicalDid(record.did)
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
  return {
    spec_version: "heterodyne/0.5.0",
    record_type: "atproto_link_revocation",
    did: record.did,
    pubkey: record.pubkey,
    generation: record.generation as number,
    nonce: record.nonce,
    binding_hash: record.binding_hash,
    revoked_at: record.revoked_at as number,
  };
}

export function serializeAtprotoBinding(binding: AtprotoBinding): string {
  return JSON.stringify({
    spec_version: binding.spec_version,
    did: binding.did,
    did_signing_key_id: binding.did_signing_key_id,
    pubkey: binding.pubkey,
    ...(binding.rid === undefined ? {} : { rid: binding.rid }),
    established_at: binding.established_at,
    generation: binding.generation,
    nonce: binding.nonce,
    predecessor: binding.predecessor,
  });
}

export function serializeAtprotoRevocation(revocation: AtprotoRevocation): string {
  return JSON.stringify({
    spec_version: revocation.spec_version,
    record_type: revocation.record_type,
    did: revocation.did,
    pubkey: revocation.pubkey,
    generation: revocation.generation,
    nonce: revocation.nonce,
    binding_hash: revocation.binding_hash,
    revoked_at: revocation.revoked_at,
  });
}

function digestAtprotoBinding(binding: AtprotoBinding): string {
  return bytesToHex(sha256(utf8Bytes(serializeAtprotoBinding(binding))));
}

function validPredecessor(value: unknown, generation: number): boolean {
  if (generation === 1) return value === null;
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const predecessor = value as Record<string, unknown>;
  return Object.keys(predecessor).sort().join("\0") === "binding_hash\0event_id"
    && typeof predecessor.event_id === "string"
    && HEX_32.test(predecessor.event_id)
    && typeof predecessor.binding_hash === "string"
    && HEX_32.test(predecessor.binding_hash);
}

function parseJson(content: string): unknown {
  try {
    return JSON.parse(content) as unknown;
  } catch {
    return null;
  }
}

function isCanonicalDid(value: string): boolean {
  if (/^did:plc:[a-z2-7]{24}$/u.test(value)) return true;
  if (!value.startsWith("did:web:")) return false;
  const [host, ...path] = value.slice("did:web:".length).split(":");
  return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/u.test(host)
    && !host.includes("..")
    && path.every((segment) => /^[A-Za-z0-9._~-]+$/u.test(segment));
}

function isCanonicalRid(value: string): boolean {
  if (!value.startsWith("rad:z")) return false;
  const body = value.slice("rad:z".length);
  try {
    const decoded = base58.decode(body);
    return decoded.length === 20 && base58.encode(decoded) === body;
  } catch {
    return false;
  }
}

function hasExactSingletonTag(event: NostrSignedEvent, expected: string[]): boolean {
  const matches = event.tags.filter((tag) => tag[0] === expected[0]);
  return matches.length === 1
    && matches[0].length === expected.length
    && matches[0].every((member, index) => member === expected[index]);
}
