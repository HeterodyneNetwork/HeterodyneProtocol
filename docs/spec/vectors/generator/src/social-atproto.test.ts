import { beforeAll, describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8Bytes } from "./hex.js";
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

type AtprotoModule = {
  validateAtprotoBinding?: (input: {
    nostr_event: NostrSignedEvent;
    pds_value: unknown;
    did_signature_valid: boolean;
    did_signed_payload_hash: string;
    previous_binding: Binding | null;
    durable_revocations: Revocation[];
  }) => { verdict: "accept"; binding: Binding } | {
    verdict: "reject";
    reason_code: string;
  };
  validateAtprotoRevocation?: (input: {
    side: "nostr" | "atproto";
    value: unknown;
    signature_valid: boolean;
    signed_payload_hash: string;
    binding: Binding;
    nostr_event?: NostrSignedEvent;
  }) => { verdict: "accept"; revocation: Revocation } | {
    verdict: "reject";
    reason_code: string;
  };
};

const secret = "17".repeat(32);
const pubkey = getPublicKey(secret);
const binding: Binding = {
  spec_version: "heterodyne/0.5.0",
  did: "did:web:alice.example",
  did_signing_key_id: "did:web:alice.example#atproto",
  pubkey,
  rid: "rad:zAlice",
  established_at: 1_000,
  generation: 1,
  nonce: "01".repeat(32),
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
    content: JSON.stringify(binding),
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
      did_signature_valid: true,
      did_signed_payload_hash: digest(binding),
      previous_binding: null,
      durable_revocations: [],
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
      did_signature_valid: true,
      did_signed_payload_hash: digest(legacyValue),
      previous_binding: null,
      durable_revocations: [],
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
      content: JSON.stringify(revocation),
      auxRand: AUX_RAND,
    });
    expect(atproto.validateAtprotoRevocation?.({
      side: "nostr",
      value: revocation,
      signature_valid: true,
      signed_payload_hash: digest(revocation),
      binding,
      nostr_event: revocationEvent,
    })).toEqual({ verdict: "accept", revocation });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: bindingEvent,
      pds_value: binding,
      did_signature_valid: true,
      did_signed_payload_hash: digest(binding),
      previous_binding: null,
      durable_revocations: [revocation],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-revoked" });

    const next = {
      ...binding,
      established_at: 1_200,
      generation: 2,
      nonce: "02".repeat(32),
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
      content: JSON.stringify(next),
      auxRand: AUX_RAND,
    });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: nextEvent,
      pds_value: next,
      did_signature_valid: true,
      did_signed_payload_hash: digest(binding),
      previous_binding: binding,
      durable_revocations: [revocation],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-invalid" });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: nextEvent,
      pds_value: next,
      did_signature_valid: true,
      did_signed_payload_hash: digest(next),
      previous_binding: binding,
      durable_revocations: [revocation],
    })).toEqual({ verdict: "accept", binding: next });
  });

  it("keeps an ATProto-side revocation durable without a Nostr replacement event", async () => {
    const atproto = await loadAtproto();
    const revocation = revocationFor(binding, 1_100);
    expect(atproto.validateAtprotoRevocation?.({
      side: "atproto",
      value: revocation,
      signature_valid: true,
      signed_payload_hash: digest(revocation),
      binding,
    })).toEqual({ verdict: "accept", revocation });
    expect(atproto.validateAtprotoBinding?.({
      nostr_event: bindingEvent,
      pds_value: binding,
      did_signature_valid: true,
      did_signed_payload_hash: digest(binding),
      previous_binding: null,
      durable_revocations: [revocation],
    })).toEqual({ verdict: "reject", reason_code: "atproto-binding-revoked" });
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
    binding_hash: digest(value),
    revoked_at,
  };
}

function digest(value: unknown): string {
  return bytesToHex(sha256(utf8Bytes(JSON.stringify(value))));
}
