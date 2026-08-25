import { beforeAll, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import {
  createAtprotoResolverAuthority,
  type AtprotoBindingObservationEvidence,
  type AtprotoResolutionEvidence,
  type AtprotoResolutionEnvelope,
  type AtprotoResolverAuthority,
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
  nostr_event: NostrSignedEvent;
  pds_value: unknown;
  did_signature: string;
  resolution_evidence: AtprotoResolutionEvidence;
  observation_evidence?: AtprotoBindingObservationEvidence;
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
    pubkey: string;
    candidates: BindingEvidence[];
    lineage: BindingEvidence[];
    revocations: RevocationEvidence[];
    resolver_authority: AtprotoResolverAuthority;
    current_resolution: AtprotoResolutionEvidence;
    now: number;
  }) => { verdict: "accept"; binding: Binding; selected_event_id: string } | {
    verdict: "reject";
    reason_code: string;
  };
  validateAtprotoRevocation?: (input: {
    evidence: RevocationEvidence;
    binding: Binding;
    resolver_authority: AtprotoResolverAuthority;
    current_resolution: AtprotoResolutionEvidence;
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
const resolverAuthority = createAtprotoResolverAuthority({
  trust_anchors: [{ suite: "ed25519", public_key: resolverPublicKey }],
  allowed_policies: ["webpki-pinned-redirect-v1"],
  minimum_version: "1.0.0",
  max_ttl: 600,
});
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
      bindingEvidence(binding, bindingEvent, resolutionEvidenceFor(binding), false),
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
      nostr_event: legacyEvent,
      pds_value: legacyValue,
      did_signature: didPayloadSignature(JSON.stringify(legacyValue)),
      resolution_evidence: resolutionEvidenceFor(binding),
    }]))).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
  });

  it("selects one current fork source-neutrally by time then lowest id", async () => {
    const atproto = await loadAtproto();
    const newer = { ...binding, established_at: 1_100, nonce: "02".repeat(32) };
    const newerEvent = await bindingNostrEvent(newer, secret, newer.established_at);
    const oldest = bindingEvidence(binding, bindingEvent);
    const newest = bindingEvidence(newer, newerEvent);
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
      bindingEvidence(tieA, eventA),
      bindingEvidence(tieB, eventB),
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
      resolver_authority: resolverAuthority,
      current_resolution: resolutionEvidenceFor(binding),
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

  it("rejects a candidate that changes between selection and revocation history", async () => {
    const atproto = await loadAtproto();
    const substituted = {
      ...binding,
      established_at: 1_100,
      nonce: "22".repeat(32),
    };
    const substitutedEvent = await bindingNostrEvent(
      substituted,
      secret,
      substituted.established_at,
    );
    const first = bindingEvidence(binding, bindingEvent);
    const second = bindingEvidence(substituted, substitutedEvent);
    let eventReads = 0;
    let valueReads = 0;
    let signatureReads = 0;
    let observationReads = 0;
    const changingEvidence = {
      resolution_evidence: first.resolution_evidence,
      get nostr_event() {
        eventReads += 1;
        return eventReads === 1 ? first.nostr_event : second.nostr_event;
      },
      get pds_value() {
        valueReads += 1;
        return valueReads === 1 ? first.pds_value : second.pds_value;
      },
      get did_signature() {
        signatureReads += 1;
        return signatureReads === 1 ? first.did_signature : second.did_signature;
      },
      get observation_evidence() {
        observationReads += 1;
        return observationReads === 1
          ? first.observation_evidence
          : second.observation_evidence;
      },
    } as BindingEvidence;
    const revoked = await revocationNostrEvent(revocationFor(binding, 1_150));

    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([changingEvidence]),
      revocations: [{ side: "nostr", nostr_event: revoked }],
    })).toMatchObject({ verdict: "reject" });
  });

  it("lets a fresh verifier authenticate expired historical resolution at binding time", async () => {
    const atproto = await loadAtproto();
    const next = {
      ...binding,
      established_at: 1_200,
      generation: 2,
      nonce: "05".repeat(32),
      predecessor: {
        event_id: bindingEvent.id,
        binding_hash: digestCanonicalBinding(binding),
      },
    };
    const nextEvent = await bindingNostrEvent(next, secret, next.established_at);
    const oldAttestation = resolutionEvidenceFor(
      binding,
      binding.did_signing_key_id,
      didSecret,
      900,
      1_050,
    );
    const currentAttestation = resolutionEvidenceFor(
      next,
      next.did_signing_key_id,
      didSecret,
      1_100,
      1_300,
    );
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([
        bindingEvidence(next, nextEvent, currentAttestation),
      ], [
        bindingEvidence(binding, bindingEvent, oldAttestation),
      ]),
      current_resolution: currentAttestation,
    })).toEqual({ verdict: "accept", binding: next, selected_event_id: nextEvent.id });
  });

  it("binds the observation to one resolution and the exact DID signature", async () => {
    const atproto = await loadAtproto();
    const rotatedSecret = "28".repeat(32);
    const rotatedResolution = resolutionEvidenceFor(
      binding,
      binding.did_signing_key_id,
      rotatedSecret,
    );
    const payload = canonicalBinding(binding);
    const rotatedSignature = didPayloadSignature(payload, rotatedSecret);
    const originalSignature = didPayloadSignature(payload);
    const validEvidence: BindingEvidence = {
      nostr_event: bindingEvent,
      pds_value: binding,
      did_signature: rotatedSignature,
      resolution_evidence: rotatedResolution,
      observation_evidence: bindingObservation(
        binding,
        bindingEvent,
        rotatedResolution,
        rotatedSignature,
      ),
    };
    const next = {
      ...binding,
      established_at: 1_200,
      generation: 2,
      nonce: "29".repeat(32),
      predecessor: {
        event_id: bindingEvent.id,
        binding_hash: digestCanonicalBinding(binding),
      },
    };
    const nextEvent = await bindingNostrEvent(next, secret, next.established_at);
    const nextSignature = didPayloadSignature(canonicalBinding(next), rotatedSecret);
    const nextEvidence: BindingEvidence = {
      nostr_event: nextEvent,
      pds_value: next,
      did_signature: nextSignature,
      resolution_evidence: rotatedResolution,
    };
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([nextEvidence], [validEvidence]),
      current_resolution: rotatedResolution,
    })).toEqual({ verdict: "accept", binding: next, selected_event_id: nextEvent.id });

    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([nextEvidence], [{
        ...validEvidence,
        observation_evidence: bindingObservation(
          binding,
          bindingEvent,
          rotatedResolution,
          originalSignature,
        ),
      }]),
      current_resolution: rotatedResolution,
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });

    let resolutionReads = 0;
    const aliased = { ...validEvidence } as Record<string, unknown>;
    Object.defineProperty(aliased, "resolution_evidence", {
      enumerable: true,
      get() {
        resolutionReads += 1;
        return resolutionReads === 1
          ? resolutionEvidenceFor(binding)
          : rotatedResolution;
      },
    });
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([nextEvidence], [aliased as BindingEvidence]),
      current_resolution: rotatedResolution,
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
  });

  it("rejects expired backdated history that lacks a prior authenticated observation", async () => {
    const atproto = await loadAtproto();
    const next = {
      ...binding,
      established_at: 1_200,
      generation: 2,
      nonce: "06".repeat(32),
      predecessor: {
        event_id: bindingEvent.id,
        binding_hash: digestCanonicalBinding(binding),
      },
    };
    const nextEvent = await bindingNostrEvent(next, secret, next.established_at);
    const expiredHistoricalResolution = resolutionEvidenceFor(
      binding,
      binding.did_signing_key_id,
      didSecret,
      900,
      1_050,
    );
    const currentResolution = resolutionEvidenceFor(
      next,
      next.did_signing_key_id,
      didSecret,
      1_100,
      1_300,
    );
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([
        bindingEvidence(next, nextEvent, currentResolution),
      ], [
        bindingEvidence(
          binding,
          bindingEvent,
          expiredHistoricalResolution,
          false,
        ),
      ]),
      current_resolution: currentResolution,
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
  });

  it("uses the current authenticated DID method for ATProto-side revocation after rotation", async () => {
    const atproto = await loadAtproto();
    const revocation = revocationFor(binding, 1_100);
    const rotatedSecret = "08".repeat(32);
    const rotatedMethod = `${binding.did}#rotated`;
    const rotatedResolution = resolutionEvidenceFor(
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
      resolver_authority: resolverAuthority,
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
      resolver_authority: resolverAuthority,
      current_resolution: rotatedResolution,
      now: 1_150,
    })).toEqual({ verdict: "reject", reason_code: "atproto-revocation-invalid" });
  });

  it("fails malformed direct revocation evidence closed without throwing", async () => {
    const atproto = await loadAtproto();
    const validRevocation = revocationFor(binding, 1_100);
    const validRevocationEvidence: RevocationEvidence = {
      side: "nostr",
      nostr_event: await revocationNostrEvent(validRevocation),
    };
    const directInput = (evidence: unknown) => ({
      evidence,
      binding,
      resolver_authority: resolverAuthority,
      current_resolution: resolutionEvidenceFor(binding),
      now: 1_150,
    });
    const malformed: unknown[] = [
      null,
      1,
      [],
      { side: "nostr", nostr_event: null },
      { side: "nostr", nostr_event: [] },
      { side: "nostr", nostr_event: { ...bindingEvent, extra: true } },
      { side: "atproto", value: null, did_signature: null },
      { side: "atproto", value: [], did_signature: "00".repeat(64) },
      { side: "atproto", value: { ...validRevocation, extra: true }, did_signature: "00".repeat(64) },
    ];
    for (const evidence of malformed) {
      let result: unknown;
      expect(() => {
        result = atproto.validateAtprotoRevocation?.(directInput(evidence) as never);
      }, JSON.stringify(evidence)).not.toThrow();
      expect(result, JSON.stringify(evidence)).toEqual({
        verdict: "reject",
        reason_code: "atproto-revocation-invalid",
      });
    }
    for (const malformedBinding of [null, 1, [], { ...binding, extra: true }]) {
      let result: unknown;
      expect(() => {
        result = atproto.validateAtprotoRevocation?.({
          ...directInput(validRevocationEvidence),
          binding: malformedBinding,
        } as never);
      }, JSON.stringify(malformedBinding)).not.toThrow();
      expect(result, JSON.stringify(malformedBinding)).toEqual({
        verdict: "reject",
        reason_code: "atproto-revocation-invalid",
      });
    }
  });

  it("fails malformed nested binding evidence closed without throwing", async () => {
    const atproto = await loadAtproto();
    const valid = bindingEvidence(
      binding,
      bindingEvent,
      resolutionEvidenceFor(binding),
      false,
    );
    const malformedEvent = { ...bindingEvent, extra: true };
    const cases: unknown[] = [
      null,
      1,
      "invalid",
      [],
      { ...bindingInput([valid]), candidates: [valid, null] },
      { ...bindingInput([valid]), candidates: [valid, { ...valid, nostr_event: null }] },
      { ...bindingInput([valid]), candidates: [valid, { ...valid, pds_value: null }] },
      { ...bindingInput([valid]), candidates: [valid, { ...valid, pds_value: [] }] },
      {
        ...bindingInput([valid]),
        candidates: [valid, { ...valid, resolution_evidence: null }],
      },
      { ...bindingInput([valid]), candidates: [valid, { ...valid, extra: true }] },
      { ...bindingInput([valid]), lineage: [{ ...valid, nostr_event: null }] },
      { ...bindingInput([valid]), lineage: [{ ...valid, nostr_event: malformedEvent }] },
      { ...bindingInput([valid]), revocations: [null] },
      { ...bindingInput([valid]), revocations: [[]] },
      {
        ...bindingInput([valid]),
        revocations: [{ side: "nostr", nostr_event: null }],
      },
      { ...bindingInput([valid]), current_resolution: null },
      {
        ...bindingInput([valid]),
        current_resolution: { ...resolutionEvidenceFor(binding), envelope: null },
      },
    ];
    for (const value of cases) {
      let result: unknown;
      expect(() => {
        result = atproto.validateAtprotoBinding?.(value as never);
      }).not.toThrow();
      expect(result).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
    }
  });

  it("fails closed when durable revocations target sibling, reset, or incompatible forks", async () => {
    const atproto = await loadAtproto();
    const branchA = {
      ...binding,
      established_at: 1_100,
      generation: 2,
      nonce: "0a".repeat(32),
      predecessor: {
        event_id: bindingEvent.id,
        binding_hash: digestCanonicalBinding(binding),
      },
    };
    const branchB = {
      ...binding,
      established_at: 1_120,
      generation: 2,
      nonce: "0b".repeat(32),
      predecessor: {
        event_id: bindingEvent.id,
        binding_hash: digestCanonicalBinding(binding),
      },
    };
    const eventA = await bindingNostrEvent(branchA, secret, branchA.established_at);
    const eventB = await bindingNostrEvent(branchB, secret, branchB.established_at);
    const revokedA = await revocationNostrEvent(revocationFor(branchA, 1_130));
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput(
        [bindingEvidence(branchA, eventA), bindingEvidence(branchB, eventB)],
        [bindingEvidence(binding, bindingEvent)],
      ),
      revocations: [{ side: "nostr", nostr_event: revokedA }],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-revoked" });

    const reset = {
      ...binding,
      established_at: 1_200,
      nonce: "0c".repeat(32),
    };
    const resetEvent = await bindingNostrEvent(reset, secret, reset.established_at);
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([bindingEvidence(branchA, eventA), bindingEvidence(reset, resetEvent)]),
      revocations: [{ side: "nostr", nostr_event: revokedA }],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-revoked" });

    const branchBRevocation = await revocationNostrEvent(revocationFor(branchB, 1_140));
    const recoveredB = {
      ...binding,
      established_at: 1_200,
      generation: 3,
      nonce: "0d".repeat(32),
      predecessor: {
        event_id: eventB.id,
        binding_hash: digestCanonicalBinding(branchB),
      },
    };
    const recoveredEvent = await bindingNostrEvent(
      recoveredB,
      secret,
      recoveredB.established_at,
    );
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput(
        [bindingEvidence(branchA, eventA), bindingEvidence(recoveredB, recoveredEvent)],
        [bindingEvidence(branchB, eventB), bindingEvidence(binding, bindingEvent)],
      ),
      revocations: [
        { side: "nostr", nostr_event: revokedA },
        { side: "nostr", nostr_event: branchBRevocation },
      ],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-revoked" });
  });

  it("does not treat an unobserved non-selected sibling as historical revocation authority", async () => {
    const atproto = await loadAtproto();
    const selected = {
      ...binding,
      established_at: 1_120,
      nonce: "0e".repeat(32),
    };
    const selectedEvent = await bindingNostrEvent(
      selected,
      secret,
      selected.established_at,
    );
    const oldRevocation = await revocationNostrEvent(revocationFor(binding, 1_100));
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([
        bindingEvidence(binding, bindingEvent, resolutionEvidenceFor(binding), false),
        bindingEvidence(selected, selectedEvent),
      ]),
      revocations: [{ side: "nostr", nostr_event: oldRevocation }],
    })).toEqual({
      verdict: "accept",
      binding: selected,
      selected_event_id: selectedEvent.id,
    });
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

  it("ignores another pubkey coordinate and its revocation for the same DID", async () => {
    const atproto = await loadAtproto();
    const otherSecret = "19".repeat(32);
    const other = {
      ...binding,
      pubkey: getPublicKey(otherSecret),
      established_at: 1_240,
      nonce: "19".repeat(32),
    };
    const otherEvent = await bindingNostrEvent(other, otherSecret, other.established_at);
    const otherRevocation = revocationFor(other, 1_245);
    const otherRevocationEvent = await revocationNostrEvent(
      otherRevocation,
      otherSecret,
    );
    expect(atproto.validateAtprotoBinding?.({
      ...bindingInput([
        bindingEvidence(binding, bindingEvent),
        bindingEvidence(other, otherEvent),
      ]),
      revocations: [{ side: "nostr", nostr_event: otherRevocationEvent }],
    })).toEqual({ verdict: "accept", binding, selected_event_id: bindingEvent.id });
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
  resolutionEvidence = resolutionEvidenceFor(value),
  includeObservation = true,
): BindingEvidence {
  const didSignature = didPayloadSignature(canonicalBinding(value));
  return {
    nostr_event: event,
    pds_value: value,
    did_signature: didSignature,
    resolution_evidence: resolutionEvidence,
    ...(includeObservation
      ? {
          observation_evidence: bindingObservation(
            value,
            event,
            resolutionEvidence,
            didSignature,
          ),
        }
      : {}),
  };
}

function bindingInput(
  candidates: BindingEvidence[],
  lineage: BindingEvidence[] = [],
): {
  did: string;
  pubkey: string;
  candidates: BindingEvidence[];
  lineage: BindingEvidence[];
  revocations: RevocationEvidence[];
  resolver_authority: AtprotoResolverAuthority;
  current_resolution: AtprotoResolutionEvidence;
  now: number;
} {
  return {
    did: binding.did,
    pubkey: binding.pubkey,
    candidates,
    lineage,
    revocations: [],
    resolver_authority: resolverAuthority,
    current_resolution: resolutionEvidenceFor(binding),
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

async function revocationNostrEvent(
  value: Revocation,
  signingSecret = secret,
): Promise<NostrSignedEvent> {
  return await signEvent({
    secretKey: signingSecret,
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

function resolutionEvidenceFor(
  value: Binding,
  selectedMethod = value.did_signing_key_id,
  selectedSecret = didSecret,
  resolvedAt = 900,
  expiresAt = 1_300,
): AtprotoResolutionEvidence {
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
    resolved_at: resolvedAt,
    expires_at: expiresAt,
    resolver_policy: "webpki-pinned-redirect-v1",
    resolver_version: "1.0.0",
  };
  const digest = sha256(utf8Bytes(
    `heterodyne:atproto-did-resolution:v1\0${canonicalResolutionEnvelope(envelope)}`,
  ));
  return {
    envelope,
    signature: bytesToHex(ed25519.sign(digest, hexToBytes(resolverSecret))),
  };
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

function bindingObservation(
  value: Binding,
  event: NostrSignedEvent,
  resolutionEvidence: AtprotoResolutionEvidence,
  didSignature: string,
): AtprotoBindingObservationEvidence {
  const envelope = {
    domain: "heterodyne-atproto-binding-observation-v2" as const,
    binding_event_id: event.id,
    binding_hash: digestCanonicalBinding(value),
    did_signature_digest: bytesToHex(sha256(hexToBytes(didSignature))),
    did: value.did,
    pubkey: value.pubkey,
    generation: value.generation,
    observed_at: event.created_at + 1,
    checkpoint_reference: `nostr:event:${event.id}`,
    resolution_envelope_hash: bytesToHex(sha256(utf8Bytes(
      canonicalResolutionEnvelope(resolutionEvidence.envelope),
    ))),
    resolver_policy: resolutionEvidence.envelope.resolver_policy,
    resolver_version: resolutionEvidence.envelope.resolver_version,
  };
  const payload = JSON.stringify({
    domain: envelope.domain,
    binding_event_id: envelope.binding_event_id,
    binding_hash: envelope.binding_hash,
    did_signature_digest: envelope.did_signature_digest,
    did: envelope.did,
    pubkey: envelope.pubkey,
    generation: envelope.generation,
    observed_at: envelope.observed_at,
    checkpoint_reference: envelope.checkpoint_reference,
    resolution_envelope_hash: envelope.resolution_envelope_hash,
    resolver_policy: envelope.resolver_policy,
    resolver_version: envelope.resolver_version,
  });
  return {
    envelope,
    signature: bytesToHex(ed25519.sign(
      sha256(utf8Bytes(
        `heterodyne:atproto-binding-observation:v2\0${payload}`,
      )),
      hexToBytes(resolverSecret),
    )),
  } as AtprotoBindingObservationEvidence;
}
