import { beforeAll, describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
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

type DidEvidence = {
  did_document: {
    id: string;
    verificationMethod: Array<{
      id: string;
      controller: string;
      type: "Ed25519VerificationKey2020";
      publicKeyHex: string;
    }>;
  };
  verification_method_id: string;
  signature: string;
};

type BindingEvidence = {
  carrier: "repository-history" | "relay";
  nostr_event: NostrSignedEvent;
  pds_value: unknown;
  did_evidence: DidEvidence;
};

type RevocationEvidence =
  | { side: "nostr"; nostr_event: NostrSignedEvent }
  | { side: "atproto"; value: unknown; did_evidence: DidEvidence };

type AtprotoModule = {
  validateAtprotoBinding?: (input: {
    nostr_event: NostrSignedEvent;
    pds_value: unknown;
    did_evidence: DidEvidence;
    lineage: BindingEvidence[];
    revocations: RevocationEvidence[];
  }) => { verdict: "accept"; binding: Binding } | {
    verdict: "reject";
    reason_code: string;
  };
  validateAtprotoRevocation?: (input: {
    evidence: RevocationEvidence;
    binding: Binding;
  }) => { verdict: "accept"; revocation: Revocation } | {
    verdict: "reject";
    reason_code: string;
  };
};

const secret = "17".repeat(32);
const pubkey = getPublicKey(secret);
const didSecret = "04".repeat(32);
const didPublicKey = bytesToHex(ed25519.getPublicKey(hexToBytes(didSecret)));
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
  it("binds a raw 64-hex Nostr key as pubkey, not as a misleading npub member", async () => {
    const atproto = await loadAtproto();
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: bindingEvent,
      pds_value: binding,
      did_evidence: didEvidence(binding),
      lineage: [],
      revocations: [],
    })).toEqual({ verdict: "accept", binding });

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
    const legacyEvent = await signEvent({
      secretKey: secret,
      created_at: binding.established_at,
      kind: 31009,
      tags: [
        ["d", binding.did],
        ["heterodyne", "atproto_link"],
        ["npub", pubkey],
        ["did", binding.did],
      ],
      content: JSON.stringify(legacyValue),
      auxRand: AUX_RAND,
    });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: legacyEvent,
      pds_value: legacyValue,
      did_evidence: didEvidence(binding),
      lineage: [],
      revocations: [],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
  });

  it("keeps a Nostr-side revocation durable and requires a fresh mutually signed generation", async () => {
    const atproto = await loadAtproto();
    const revocation = revocationFor(binding, 1_100);
    const revocationEvent = await signEvent({
      secretKey: secret,
      created_at: revocation.revoked_at,
      kind: 31009,
      tags: [
        ["d", `revocation:${binding.did}:${binding.generation}:${binding.nonce}`],
        ["heterodyne", "atproto_link_revocation"],
        ["did", binding.did],
        ["pubkey", binding.pubkey],
      ],
      content: canonicalRevocation(revocation),
      auxRand: AUX_RAND,
    });
    expect(atproto.validateAtprotoRevocation?.({
      evidence: { side: "nostr", nostr_event: revocationEvent },
      binding,
    })).toEqual({ verdict: "accept", revocation });
    const nostrRevocationEvidence = {
      side: "nostr" as const,
      nostr_event: revocationEvent,
    };
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: bindingEvent,
      pds_value: binding,
      did_evidence: didEvidence(binding),
      lineage: [],
      revocations: [nostrRevocationEvidence],
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
    const nextEvent = await signEvent({
      secretKey: secret,
      created_at: next.established_at,
      kind: 31009,
      tags: [
        ["d", next.did],
        ["heterodyne", "atproto_link"],
        ["pubkey", next.pubkey],
        ["did", next.did],
      ],
      content: canonicalBinding(next),
      auxRand: AUX_RAND,
    });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: nextEvent,
      pds_value: next,
      did_evidence: didEvidence(binding),
      lineage: [bindingEvidence()],
      revocations: [nostrRevocationEvidence],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: nextEvent,
      pds_value: next,
      did_evidence: didEvidence(next),
      lineage: [],
      revocations: [nostrRevocationEvidence],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: nextEvent,
      pds_value: next,
      did_evidence: didEvidence(next),
      lineage: [{
        ...bindingEvidence(),
        pds_value: { ...binding, nonce: "ff".repeat(32) },
      }],
      revocations: [nostrRevocationEvidence],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: nextEvent,
      pds_value: next,
      did_evidence: didEvidence(next),
      lineage: [bindingEvidence()],
      revocations: [nostrRevocationEvidence],
    })).toEqual({ verdict: "accept", binding: next });
  });

  it("keeps an ATProto-side revocation durable without a Nostr replacement event", async () => {
    const atproto = await loadAtproto();
    const revocation = revocationFor(binding, 1_100);
    const evidence: RevocationEvidence = {
      side: "atproto",
      value: revocation,
      did_evidence: didEvidence(binding, canonicalRevocation(revocation)),
    };
    expect(atproto.validateAtprotoRevocation?.({
      evidence,
      binding,
    })).toEqual({ verdict: "accept", revocation });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: bindingEvent,
      pds_value: binding,
      did_evidence: didEvidence(binding),
      lineage: [],
      revocations: [evidence],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-revoked" });

    const forgedEvidence: RevocationEvidence = {
      side: "atproto",
      value: revocation,
      did_evidence: didEvidence(binding),
    };
    expect(atproto.validateAtprotoRevocation?.({
      evidence: forgedEvidence,
      binding,
    })).toMatchObject({ verdict: "reject" });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: bindingEvent,
      pds_value: binding,
      did_evidence: didEvidence(binding),
      lineage: [],
      revocations: [forgedEvidence],
    })).toEqual({ verdict: "accept", binding });
  });

  it("rejects lineage that changes the mutually bound Nostr pubkey", async () => {
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
    const changedEvent = await signEvent({
      secretKey: otherSecret,
      created_at: changed.established_at,
      kind: 31009,
      tags: [
        ["d", changed.did],
        ["heterodyne", "atproto_link"],
        ["pubkey", changed.pubkey],
        ["did", changed.did],
      ],
      content: canonicalBinding(changed),
      auxRand: AUX_RAND,
    });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: changedEvent,
      pds_value: changed,
      did_evidence: didEvidence(changed),
      lineage: [bindingEvidence()],
      revocations: [],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
  });

  it("normalizes one canonical payload and rejects noncanonical identity evidence", async () => {
    const atproto = await loadAtproto();
    const reordered = {
      nonce: binding.nonce,
      generation: binding.generation,
      established_at: binding.established_at,
      rid: binding.rid,
      pubkey: binding.pubkey,
      did_signing_key_id: binding.did_signing_key_id,
      did: binding.did,
      spec_version: binding.spec_version,
      predecessor: binding.predecessor,
    };
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: bindingEvent,
      pds_value: reordered,
      did_evidence: didEvidence(binding),
      lineage: [],
      revocations: [],
    })).toEqual({ verdict: "accept", binding });

    const unrelated = didEvidence(binding);
    unrelated.did_document.verificationMethod[0] = {
      ...unrelated.did_document.verificationMethod[0],
      id: `${binding.did}#other`,
    };
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: bindingEvent,
      pds_value: binding,
      did_evidence: unrelated,
      lineage: [],
      revocations: [],
    })).toMatchObject({ verdict: "reject" });

    for (const patch of [
      { did: "did:web:Alice.Example", did_signing_key_id: "did:web:Alice.Example#atproto" },
      { rid: "rad:z111111111111111111111" },
    ]) {
      const malformed = { ...binding, ...patch };
      const malformedEvent = await signEvent({
        secretKey: secret,
        created_at: malformed.established_at,
        kind: 31009,
        tags: [
          ["d", malformed.did],
          ["heterodyne", "atproto_link"],
          ["pubkey", malformed.pubkey],
          ["did", malformed.did],
        ],
        content: canonicalBinding(malformed),
        auxRand: AUX_RAND,
      });
      expect(atproto.validateAtprotoBinding?.({
        nostr_event: malformedEvent,
        pds_value: malformed,
        did_evidence: didEvidence(malformed),
        lineage: [],
        revocations: [],
      })).toMatchObject({ verdict: "reject" });
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

function didEvidence(value: Binding, canonical = canonicalBinding(value)): DidEvidence {
  const payloadHash = sha256(utf8Bytes(canonical));
  return {
    did_document: {
      id: value.did,
      verificationMethod: [{
        id: value.did_signing_key_id,
        controller: value.did,
        type: "Ed25519VerificationKey2020",
        publicKeyHex: didPublicKey,
      }],
    },
    verification_method_id: value.did_signing_key_id,
    signature: bytesToHex(ed25519.sign(payloadHash, hexToBytes(didSecret))),
  };
}

function bindingEvidence(): BindingEvidence {
  return {
    carrier: "repository-history",
    nostr_event: bindingEvent,
    pds_value: binding,
    did_evidence: didEvidence(binding),
  };
}
