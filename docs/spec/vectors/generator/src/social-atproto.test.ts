import { beforeAll, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import {
  authenticateAtprotoDidResolution,
  type AtprotoDidResolution,
  type AtprotoResolutionEnvelope,
} from "./atproto-did-resolution.js";
import { AUX_RAND } from "./vector-helpers.js";

type Binding = {
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

type Revocation = {
  spec_version: "heterodyne/0.5.0";
  record_type: "atproto_link_revocation";
  did: string;
  pubkey: string;
  generation: number;
  nonce: string;
  binding_hash: string;
  revoked_at: number;
};

type BindingEvidence = {
  carrier: "repository-history" | "relay";
  nostr_event: NostrSignedEvent;
  pds_value: unknown;
  did_signature: string;
  resolution: AtprotoDidResolution;
};

type RevocationEvidence =
  | { side: "nostr"; nostr_event: NostrSignedEvent }
  | {
      side: "atproto";
      value: unknown;
      did_signature: string;
    };

type AtprotoModule = {
  validateAtprotoBinding?: (input: {
    did: string;
    candidates: BindingEvidence[];
    lineage: BindingEvidence[];
    revocations: RevocationEvidence[];
    current_resolution: AtprotoDidResolution;
    now: number;
  }) => { verdict: "accept"; binding: Binding; selected_event_id: string } | {
    verdict: "reject";
    reason_code: string;
  };
  validateAtprotoRevocation?: (input: {
    evidence: RevocationEvidence;
    binding: Binding;
    current_resolution: AtprotoDidResolution;
    now: number;
  }) => { verdict: "accept"; revocation: Revocation } | {
    verdict: "reject";
    reason_code: string;
  };
};

const secret = "17".repeat(32);
const pubkey = getPublicKey(secret);
const didSecret = "04".repeat(32);
const resolverSecret = "05".repeat(32);
const resolverPublicKey = bytesToHex(ed25519.getPublicKey(hexToBytes(resolverSecret)));
const binding: Binding = {
  spec_version: "heterodyne/0.5.0",
  did: "did:web:alice.example",
  did_signing_key_id: "did:web:alice.example#atproto",
  pubkey,
  rid: "rad:z2TJoDAhK5pTmLzqmK9W4FMdtjyy1",
  established_at: 1_000,
  generation: 1,
  nonce: "01".repeat(32),
  predecessor: null,
};
let bindingEvent: NostrSignedEvent;

beforeAll(async () => {
  bindingEvent = await signEvent({
    secretKey: secret,
    created_at: binding.established_at,
    kind: 31009,
    tags: [
      ["d", binding.did],
      ["heterodyne", "atproto_link"],
      ["pubkey", pubkey],
      ["did", binding.did],
    ],
    content: canonicalBinding(binding),
    auxRand: AUX_RAND,
  });
});

async function loadAtproto(): Promise<AtprotoModule> {
  return await import("./social-atproto.js").catch(() => ({}));
}

describe("ATProto active-key binding", () => {
  it("accepts only the canonical raw-pubkey binding through authenticated resolution", async () => {
    const atproto = await loadAtproto();
    expect(atproto.validateAtprotoBinding?.(bindingInput([
      bindingEvidence(binding, bindingEvent),
    ]))).toEqual({ verdict: "accept", binding, selected_event_id: bindingEvent.id });

    const legacyValue = {
      spec_version: binding.spec_version,
      did: binding.did,
      did_signing_key_id: binding.did_signing_key_id,
      npub: binding.pubkey,
      rid: binding.rid,
      established_at: binding.established_at,
      generation: binding.generation,
      nonce: binding.nonce,
    };
    const legacyEvent = await bindingNostrEvent(legacyValue, secret, binding.established_at);
    expect(atproto.validateAtprotoBinding?.(bindingInput([{
      carrier: "relay",
      nostr_event: legacyEvent,
      pds_value: legacyValue,
      did_signature: didPayloadSignature(JSON.stringify(legacyValue)),
      resolution: resolutionFor(binding),
    }]))).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
  });

  it("selects one current fork source-neutrally by time then lowest id", async () => {
    const atproto = await loadAtproto();
    const newer = { ...binding, established_at: 1_100, nonce: "02".repeat(32) };
    const newerEvent = await bindingNostrEvent(newer, secret, newer.established_at);
    const oldest = bindingEvidence(binding, bindingEvent, "repository-history");
    const newest = bindingEvidence(newer, newerEvent, "relay");
    for (const candidates of [[oldest, newest], [newest, oldest]]) {
      expect(atproto.validateAtprotoBinding?.(bindingInput(candidates)))
        .toEqual({ verdict: "accept", binding: newer, selected_event_id: newerEvent.id });
    }

    const tieA = { ...newer, nonce: "03".repeat(32) };
    const tieB = { ...newer, nonce: "04".repeat(32) };
    const eventA = await bindingNostrEvent(tieA, secret, tieA.established_at);
    const eventB = await bindingNostrEvent(tieB, secret, tieB.established_at);
    const expected = eventA.id < eventB.id
      ? { binding: tieA, event: eventA }
      : { binding: tieB, event: eventB };
    expect(atproto.validateAtprotoBinding?.(bindingInput([
      bindingEvidence(tieA, eventA, "repository-history"),
      bindingEvidence(tieB, eventB, "relay"),
    ]))).toEqual({
      verdict: "accept",
      binding: expected.binding,
      selected_event_id: expected.event.id,
    });
  });

  it("keeps a Nostr-side revocation durable and requires authenticated full lineage", async () => {
    const atproto = await loadAtproto();
    const revocation = revocationFor(binding, 1_100);
    const revocationEvent = await revocationNostrEvent(revocation);
    const evidence = { side: "nostr" as const, nostr_event: revocationEvent };
    expect(atproto.validateAtprotoRevocation?.({
      evidence,
      binding,
      current_resolution: resolutionFor(binding),
      now: 1_150,
    }))
      .toEqual({ verdict: "accept", revocation });
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([bindingEvidence(binding, bindingEvent)]),
      revocations: [evidence],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-revoked" });

    const next = {
      ...binding,
      established_at: 1_200,
      generation: 2,
      nonce: "02".repeat(32),
      predecessor: {
        event_id: bindingEvent.id,
        binding_hash: digestCanonicalBinding(binding),
      },
    };
    const nextEvent = await bindingNostrEvent(next, secret, next.established_at);
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([bindingEvidence(next, nextEvent)], [bindingEvidence(binding, bindingEvent)]),
      revocations: [evidence],
    })).toEqual({ verdict: "accept", binding: next, selected_event_id: nextEvent.id });
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([bindingEvidence(next, nextEvent)]),
      revocations: [evidence],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
  });

  it("uses the current authenticated DID method for ATProto-side revocation after rotation", async () => {
    const atproto = await loadAtproto();
    const revocation = revocationFor(binding, 1_100);
    const rotatedSecret = "08".repeat(32);
    const rotatedMethod = `${binding.did}#rotated`;
    const rotatedResolution = resolutionFor(
      binding,
      rotatedMethod,
      rotatedSecret,
    );
    const evidence: RevocationEvidence = {
      side: "atproto",
      value: revocation,
      did_signature: didPayloadSignature(
        canonicalRevocation(revocation),
        rotatedSecret,
      ),
    };
    expect(atproto.validateAtprotoRevocation?.({
      evidence,
      binding,
      current_resolution: rotatedResolution,
      now: 1_150,
    }))
      .toEqual({ verdict: "accept", revocation });
    const oldMethodEvidence: RevocationEvidence = {
      side: "atproto",
      value: revocation,
      did_signature: didPayloadSignature(canonicalRevocation(revocation)),
    };
    expect(atproto.validateAtprotoRevocation?.({
      evidence: oldMethodEvidence,
      binding,
      current_resolution: rotatedResolution,
      now: 1_150,
    })).toEqual({ verdict: "reject", reason_code: "atproto-revocation-invalid" });
  });

  it("rejects forged lineage and noncanonical DID or RID identity", async () => {
    const atproto = await loadAtproto();
    const otherSecret = "18".repeat(32);
    const changed = {
      ...binding,
      pubkey: getPublicKey(otherSecret),
      established_at: 1_200,
      generation: 2,
      nonce: "02".repeat(32),
      predecessor: {
        event_id: bindingEvent.id,
        binding_hash: digestCanonicalBinding(binding),
      },
    };
    const changedEvent = await bindingNostrEvent(changed, otherSecret, changed.established_at);
    expect(atproto.validateAtprotoBinding?.(bindingInput(
      [bindingEvidence(changed, changedEvent)],
      [bindingEvidence(binding, bindingEvent)],
    ))).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });

    for (const patch of [
      { did: "did:web:Alice.Example", did_signing_key_id: "did:web:Alice.Example#atproto" },
      { rid: "rad:z111111111111111111111" },
    ]) {
      const malformed = { ...binding, ...patch };
      const malformedEvent = await bindingNostrEvent(malformed, secret, malformed.established_at);
      expect(atproto.validateAtprotoBinding?.(bindingInput([{
        ...bindingEvidence(binding, malformedEvent),
        pds_value: malformed,
        did_signature: didPayloadSignature(canonicalBinding(malformed)),
      }]))).toMatchObject({ verdict: "reject" });
    }
  });
});

function revocationFor(value: Binding, revoked_at: number): Revocation {
  return {
    spec_version: "heterodyne/0.5.0",
    record_type: "atproto_link_revocation",
    did: value.did,
    pubkey: value.pubkey,
    generation: value.generation,
    nonce: value.nonce,
    binding_hash: digestCanonicalBinding(value),
    revoked_at,
  };
}

function canonicalBinding(value: Binding): string {
  return JSON.stringify({
    spec_version: value.spec_version,
    did: value.did,
    did_signing_key_id: value.did_signing_key_id,
    pubkey: value.pubkey,
    ...(value.rid === undefined ? {} : { rid: value.rid }),
    established_at: value.established_at,
    generation: value.generation,
    nonce: value.nonce,
    predecessor: value.predecessor,
  });
}

function canonicalRevocation(value: Revocation): string {
  return JSON.stringify({
    spec_version: value.spec_version,
    record_type: value.record_type,
    did: value.did,
    pubkey: value.pubkey,
    generation: value.generation,
    nonce: value.nonce,
    binding_hash: value.binding_hash,
    revoked_at: value.revoked_at,
  });
}

function digestCanonicalBinding(value: Binding): string {
  return bytesToHex(sha256(utf8Bytes(canonicalBinding(value))));
}

function bindingEvidence(
  value: Binding,
  event: NostrSignedEvent,
  carrier: "repository-history" | "relay" = "relay",
): BindingEvidence {
  return {
    carrier,
    nostr_event: event,
    pds_value: value,
    did_signature: didPayloadSignature(canonicalBinding(value)),
    resolution: resolutionFor(value),
  };
}

function bindingInput(
  candidates: BindingEvidence[],
  lineage: BindingEvidence[] = [],
): {
  did: string;
  candidates: BindingEvidence[];
  lineage: BindingEvidence[];
  revocations: RevocationEvidence[];
  current_resolution: AtprotoDidResolution;
  now: number;
} {
  return {
    did: binding.did,
    candidates,
    lineage,
    revocations: [],
    current_resolution: resolutionFor(binding),
    now: 1_250,
  };
}

async function bindingNostrEvent(
  value: Record<string, unknown>,
  signingSecret: string,
  createdAt: number,
): Promise<NostrSignedEvent> {
  const eventPubkey = getPublicKey(signingSecret);
  const content = Object.hasOwn(value, "predecessor")
    ? canonicalBinding(value as Binding)
    : JSON.stringify(value);
  return await signEvent({
    secretKey: signingSecret,
    created_at: createdAt,
    kind: 31009,
    tags: [
      ["d", value.did as string],
      ["heterodyne", "atproto_link"],
      ["pubkey", eventPubkey],
      ["did", value.did as string],
    ],
    content,
    auxRand: AUX_RAND,
  });
}

async function revocationNostrEvent(value: Revocation): Promise<NostrSignedEvent> {
  return await signEvent({
    secretKey: secret,
    created_at: value.revoked_at,
    kind: 31009,
    tags: [
      ["d", `revocation:${value.did}:${value.generation}:${value.nonce}`],
      ["heterodyne", "atproto_link_revocation"],
      ["did", value.did],
      ["pubkey", value.pubkey],
    ],
    content: canonicalRevocation(value),
    auxRand: AUX_RAND,
  });
}

function didPayloadSignature(payload: string, secretKey = didSecret): string {
  return bytesToHex(ed25519.sign(
    sha256(utf8Bytes(payload)),
    hexToBytes(secretKey),
  ));
}

function resolutionFor(
  value: Binding,
  selectedMethod = value.did_signing_key_id,
  selectedSecret = didSecret,
): AtprotoDidResolution {
  const selectedPublic = bytesToHex(ed25519.getPublicKey(hexToBytes(selectedSecret)));
  const document = JSON.stringify({
    id: value.did,
    verificationMethod: [{
      controller: value.did,
      id: selectedMethod,
      publicKeyHex: selectedPublic,
      type: "Ed25519VerificationKey2020",
    }],
  });
  const envelope: AtprotoResolutionEnvelope = {
    domain: "heterodyne-atproto-did-resolution-v1",
    did: value.did,
    resolution_method: "did:web",
    canonical_https_url: "https://alice.example/.well-known/did.json",
    plc_log_head: null,
    plc_log_hash: null,
    canonical_document: document,
    document_sha256: bytesToHex(sha256(utf8Bytes(document))),
    selected_verification_method_id: selectedMethod,
    resolved_at: 900,
    expires_at: 1_300,
    resolver_policy: "webpki-pinned-redirect-v1",
    resolver_version: "resolver-1.0.0",
  };
  const digest = sha256(utf8Bytes(
    `heterodyne:atproto-did-resolution:v1\0${canonicalResolutionEnvelope(envelope)}`,
  ));
  const decision = authenticateAtprotoDidResolution({
    envelope,
    signature: bytesToHex(ed25519.sign(digest, hexToBytes(resolverSecret))),
    trust_anchor: { suite: "ed25519", public_key: resolverPublicKey },
    now: 1_000,
  });
  if (decision.verdict !== "accept") throw new Error(decision.reason_code);
  return decision.resolution;
}

function canonicalResolutionEnvelope(value: AtprotoResolutionEnvelope): string {
  return JSON.stringify({
    domain: value.domain,
    did: value.did,
    resolution_method: value.resolution_method,
    canonical_https_url: value.canonical_https_url,
    plc_log_head: value.plc_log_head,
    plc_log_hash: value.plc_log_hash,
    canonical_document: value.canonical_document,
    document_sha256: value.document_sha256,
    selected_verification_method_id: value.selected_verification_method_id,
    resolved_at: value.resolved_at,
    expires_at: value.expires_at,
    resolver_policy: value.resolver_policy,
    resolver_version: value.resolver_version,
  });
}
