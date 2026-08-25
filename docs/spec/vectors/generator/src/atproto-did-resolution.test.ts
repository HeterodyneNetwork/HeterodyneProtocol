import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { AUX_RAND } from "./vector-helpers.js";
import * as resolutionModule from "./atproto-did-resolution.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";

type Envelope = {
  domain: "heterodyne-atproto-did-resolution-v1";
  did: string;
  resolution_method: "did:web" | "did:plc";
  canonical_https_url: string | null;
  plc_log_head: string | null;
  plc_log_hash: string | null;
  canonical_document: string;
  document_sha256: string;
  selected_verification_method_id: string;
  resolved_at: number;
  expires_at: number;
  resolver_policy: string;
  resolver_version: string;
};

type ResolutionModule = {
  createAtprotoResolverAuthority?: (input: {
    trust_anchors: Array<{ suite: "ed25519" | "bip340"; public_key: string }>;
    allowed_policies: string[];
    minimum_version: string;
    max_ttl: number;
  }) => object;
  authenticateAtprotoDidResolution?: (input: {
    authority: object;
    evidence: { envelope: unknown; signature: string };
    validation_time: number;
  }) => { verdict: "accept"; resolution: object } | {
    verdict: "reject";
    reason_code: string;
  };
  verifyAtprotoDidSignature?: (input: {
    authority: object;
    resolution: unknown;
    did: string;
    verification_method_id: string;
    payload: string;
    signature: string;
    validation_time: number;
  }) => boolean;
  authenticateAtprotoBindingObservation?: (input: {
    authority: object;
    evidence: { envelope: unknown; signature: string };
    resolution_evidence: { envelope: unknown; signature: string };
    expected_binding: {
      binding_event_id: string;
      binding_hash: string;
      canonical_payload: string;
      did: string;
      did_signature: string;
      did_signing_key_id: string;
      pubkey: string;
      generation: number;
      event_created_at: number;
      nostr_event: NostrSignedEvent;
    };
  }) => { verdict: "accept" } | { verdict: "reject"; reason_code: string };
};

type ObservationEnvelope = {
  domain: "heterodyne-atproto-binding-observation-v2";
  binding_event_id: string;
  binding_hash: string;
  did_signature_digest: string;
  did: string;
  pubkey: string;
  generation: number;
  observed_at: number;
  checkpoint_reference: string;
  resolution_envelope_hash: string;
  resolver_policy: string;
  resolver_version: string;
};

const didSecret = "04".repeat(32);
const didPublic = bytesToHex(ed25519.getPublicKey(hexToBytes(didSecret)));
const resolverSecret = "05".repeat(32);
const resolverPublic = bytesToHex(ed25519.getPublicKey(hexToBytes(resolverSecret)));
const did = "did:web:alice.example";
const method = `${did}#atproto`;
const document = JSON.stringify({
  id: did,
  verificationMethod: [{
    controller: did,
    id: method,
    publicKeyHex: didPublic,
    type: "Ed25519VerificationKey2020",
  }],
});
const envelope: Envelope = {
  domain: "heterodyne-atproto-did-resolution-v1",
  did,
  resolution_method: "did:web",
  canonical_https_url: "https://alice.example/.well-known/did.json",
  plc_log_head: null,
  plc_log_hash: null,
  canonical_document: document,
  document_sha256: bytesToHex(sha256(utf8Bytes(document))),
  selected_verification_method_id: method,
  resolved_at: 1_000,
  expires_at: 1_300,
  resolver_policy: "webpki-pinned-redirect-v1",
  resolver_version: "1.0.0",
};

describe("authenticated ATProto DID resolution", () => {
  it("authenticates a closed durable binding observation inside the resolution interval", async () => {
    const api = await loadResolution();
    const authority = configuredAuthority(api, {
      suite: "ed25519",
      public_key: resolverPublic,
    });
    const { expected, observation } = await bindingObservationFixture();
    const resolutionEvidence = attestation(envelope, resolverSecret, "ed25519");
    expect(api.authenticateAtprotoBindingObservation?.({
      authority,
      evidence: observationAttestation(observation, resolverSecret),
      resolution_evidence: resolutionEvidence,
      expected_binding: expected,
    })).toEqual({ verdict: "accept" });

    const attackerSecret = "06".repeat(32);
    for (const evidence of [
      observationAttestation(observation, attackerSecret),
      observationAttestation({ ...observation, binding_event_id: "44".repeat(32) }, resolverSecret),
      observationAttestation({ ...observation, binding_hash: "44".repeat(32) }, resolverSecret),
      observationAttestation({
        ...observation,
        did_signature_digest: "44".repeat(32),
      }, resolverSecret),
      observationAttestation({ ...observation, pubkey: "44".repeat(32) }, resolverSecret),
      observationAttestation({ ...observation, generation: 2 }, resolverSecret),
      observationAttestation({ ...observation, resolution_envelope_hash: "44".repeat(32) }, resolverSecret),
      observationAttestation({ ...observation, observed_at: 1_049 }, resolverSecret),
      observationAttestation({ ...observation, observed_at: 1_300 }, resolverSecret),
      observationAttestation({ ...observation, resolver_policy: "unapproved-policy" }, resolverSecret),
      observationAttestation({ ...observation, resolver_version: "0.9.9" }, resolverSecret),
    ]) {
      expect(api.authenticateAtprotoBindingObservation?.({
        authority,
        evidence,
        resolution_evidence: resolutionEvidence,
        expected_binding: expected,
      })).toEqual({
        verdict: "reject",
        reason_code: "atproto-binding-observation-invalid",
      });
    }
  });

  it("rejects accessor-backed resolver and observation envelopes without invoking them", async () => {
    const api = await loadResolution();
    const authority = configuredAuthority(api, {
      suite: "ed25519",
      public_key: resolverPublic,
    });
    let resolutionGetterCalls = 0;
    const accessorResolution = { ...envelope } as Record<string, unknown>;
    Object.defineProperty(accessorResolution, "resolver_version", {
      enumerable: true,
      get() {
        resolutionGetterCalls += 1;
        return envelope.resolver_version;
      },
    });
    expect(api.authenticateAtprotoDidResolution?.({
      authority,
      evidence: {
        envelope: accessorResolution,
        signature: resolverSignature(envelope, resolverSecret, "ed25519"),
      },
      validation_time: 1_100,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    expect(resolutionGetterCalls).toBe(0);

    const { expected, observation: signedEnvelope } = await bindingObservationFixture();
    let observationGetterCalls = 0;
    const accessorObservation = { ...signedEnvelope } as Record<string, unknown>;
    Object.defineProperty(accessorObservation, "binding_event_id", {
      enumerable: true,
      get() {
        observationGetterCalls += 1;
        return observationGetterCalls === 1
          ? expected.binding_event_id
          : "44".repeat(32);
      },
    });
    expect(api.authenticateAtprotoBindingObservation?.({
      authority,
      evidence: {
        envelope: accessorObservation,
        signature: observationAttestation(signedEnvelope, resolverSecret).signature,
      },
      resolution_evidence: attestation(envelope, resolverSecret, "ed25519"),
      expected_binding: expected,
    })).toEqual({
      verdict: "reject",
      reason_code: "atproto-binding-observation-invalid",
    });
    expect(observationGetterCalls).toBe(0);
  });

  it("rejects canonical JSON hazards across public resolution and observation paths", async () => {
    const api = await loadResolution();
    const authority = configuredAuthority(api, {
      suite: "ed25519",
      public_key: resolverPublic,
    });
    const { expected, observation } = await bindingObservationFixture();
    const hazards = [
      "1e400",
      '{"nested":1e400}',
      `${"[".repeat(6_000)}null${"]".repeat(6_000)}`,
    ];
    for (const canonicalDocument of hazards) {
      const hazardousEnvelope = withCanonicalDocument(canonicalDocument);
      const resolutionEvidence = attestation(
        hazardousEnvelope,
        resolverSecret,
        "ed25519",
      );
      let resolutionResult: unknown;
      expect(() => {
        resolutionResult = api.authenticateAtprotoDidResolution?.({
          authority,
          evidence: resolutionEvidence,
          validation_time: 1_100,
        });
      }, canonicalDocument.slice(0, 40)).not.toThrow();
      expect(resolutionResult, canonicalDocument.slice(0, 40)).toEqual({
        verdict: "reject",
        reason_code: "atproto-did-resolution-invalid",
      });

      let observationResult: unknown;
      expect(() => {
        observationResult = api.authenticateAtprotoBindingObservation?.({
          authority,
          evidence: observationAttestation(observation, resolverSecret),
          resolution_evidence: resolutionEvidence,
          expected_binding: expected,
        });
      }, canonicalDocument.slice(0, 40)).not.toThrow();
      expect(observationResult, canonicalDocument.slice(0, 40)).toEqual({
        verdict: "reject",
        reason_code: "atproto-binding-observation-invalid",
      });
    }
  });

  it("mints only from a fresh exact resolver attestation and rejects a fake victim document", async () => {
    const api = await loadResolution();
    const authority = configuredAuthority(api, {
      suite: "ed25519",
      public_key: resolverPublic,
    });
    const valid = api.authenticateAtprotoDidResolution?.({
      authority,
      evidence: attestation(envelope, resolverSecret, "ed25519"),
      validation_time: 1_100,
    });
    expect(valid).toMatchObject({ verdict: "accept", resolution: expect.any(Object) });

    const attackerSecret = "06".repeat(32);
    const attackerPublic = bytesToHex(ed25519.getPublicKey(hexToBytes(attackerSecret)));
    const fakeDocument = JSON.stringify({
      id: did,
      verificationMethod: [{
        controller: did,
        id: method,
        publicKeyHex: attackerPublic,
        type: "Ed25519VerificationKey2020",
      }],
    });
    const fake = {
      ...envelope,
      canonical_document: fakeDocument,
      document_sha256: bytesToHex(sha256(utf8Bytes(fakeDocument))),
    };
    expect(api.authenticateAtprotoDidResolution?.({
      authority,
      evidence: attestation(fake, attackerSecret, "ed25519"),
      validation_time: 1_100,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    expect(api.authenticateAtprotoDidResolution?.({
      authority,
      evidence: {
        envelope,
        signature: resolverSignature(
          { ...envelope, resolver_version: "9.9.9" },
          resolverSecret,
          "ed25519",
        ),
      },
      validation_time: 1_100,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    expect(api.authenticateAtprotoDidResolution?.({
      authority,
      evidence: attestation(envelope, resolverSecret, "ed25519"),
      validation_time: 1_300,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    const wrongUrl = { ...envelope, canonical_https_url: "https://victim.example/did.json" };
    expect(api.authenticateAtprotoDidResolution?.({
      authority,
      evidence: attestation(wrongUrl, resolverSecret, "ed25519"),
      validation_time: 1_100,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    const wrongResolutionMethod: Envelope = {
      ...envelope,
      resolution_method: "did:plc",
      canonical_https_url: null,
      plc_log_head: "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
      plc_log_hash: "11".repeat(32),
    };
    expect(api.authenticateAtprotoDidResolution?.({
      authority,
      evidence: attestation(wrongResolutionMethod, resolverSecret, "ed25519"),
      validation_time: 1_100,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });

    if (valid?.verdict !== "accept") throw new Error("resolution missing");
    const payload = "binding payload";
    const didSignature = bytesToHex(ed25519.sign(
      sha256(utf8Bytes(payload)),
      hexToBytes(didSecret),
    ));
    expect(api.verifyAtprotoDidSignature?.({
      authority,
      resolution: valid.resolution,
      did,
      verification_method_id: method,
      payload,
      signature: didSignature,
      validation_time: 1_100,
    })).toBe(true);
    expect(api.verifyAtprotoDidSignature?.({
      authority,
      resolution: valid.resolution,
      did: "did:web:victim.example",
      verification_method_id: "did:web:victim.example#atproto",
      payload,
      signature: didSignature,
      validation_time: 1_100,
    })).toBe(false);
    expect(api.verifyAtprotoDidSignature?.({
      authority,
      resolution: valid.resolution,
      did,
      verification_method_id: `${did}#other`,
      payload,
      signature: didSignature,
      validation_time: 1_100,
    })).toBe(false);
    expect(api.verifyAtprotoDidSignature?.({
      authority,
      resolution: valid.resolution,
      did,
      verification_method_id: method,
      payload,
      signature: didSignature,
      validation_time: 1_300,
    })).toBe(false);
  });

  it("binds capabilities to deep-frozen configured policy authority", async () => {
    const api = await loadResolution();
    const authority = configuredAuthority(api, {
      suite: "ed25519",
      public_key: resolverPublic,
    });
    const mutableEnvelope = structuredClone(envelope);
    const valid = api.authenticateAtprotoDidResolution?.({
      authority,
      evidence: attestation(mutableEnvelope, resolverSecret, "ed25519"),
      validation_time: 1_100,
    });
    expect(valid).toMatchObject({ verdict: "accept", resolution: expect.any(Object) });
    if (valid?.verdict !== "accept") throw new Error("resolution missing");
    mutableEnvelope.canonical_document = JSON.stringify({ id: did, verificationMethod: [] });
    mutableEnvelope.document_sha256 = bytesToHex(sha256(utf8Bytes(mutableEnvelope.canonical_document)));

    const payload = "immutable resolver evidence";
    const signature = bytesToHex(ed25519.sign(
      sha256(utf8Bytes(payload)),
      hexToBytes(didSecret),
    ));
    expect(api.verifyAtprotoDidSignature?.({
      authority,
      resolution: valid.resolution,
      did,
      verification_method_id: method,
      payload,
      signature,
      validation_time: 1_100,
    })).toBe(true);

    const attackerSecret = "06".repeat(32);
    const attackerPublic = bytesToHex(ed25519.getPublicKey(hexToBytes(attackerSecret)));
    const fakeDocument = JSON.stringify({
      id: did,
      verificationMethod: [{
        controller: did,
        id: method,
        publicKeyHex: attackerPublic,
        type: "Ed25519VerificationKey2020",
      }],
    });
    const fakeEnvelope = {
      ...envelope,
      canonical_document: fakeDocument,
      document_sha256: bytesToHex(sha256(utf8Bytes(fakeDocument))),
    };
    const attackerAuthority = configuredAuthority(api, {
      suite: "ed25519",
      public_key: attackerPublic,
    });
    const fake = api.authenticateAtprotoDidResolution?.({
      authority: attackerAuthority,
      evidence: attestation(fakeEnvelope, attackerSecret, "ed25519"),
      validation_time: 1_100,
    });
    expect(fake).toMatchObject({ verdict: "accept", resolution: expect.any(Object) });
    if (fake?.verdict !== "accept") throw new Error("fake resolution missing");
    expect(api.verifyAtprotoDidSignature?.({
      authority,
      resolution: fake.resolution,
      did,
      verification_method_id: method,
      payload,
      signature: bytesToHex(ed25519.sign(
        sha256(utf8Bytes(payload)),
        hexToBytes(attackerSecret),
      )),
      validation_time: 1_100,
    })).toBe(false);

    for (const rejectedEnvelope of [
      { ...envelope, resolver_policy: "unapproved-policy" },
      { ...envelope, resolver_version: "0.9.9" },
      { ...envelope, expires_at: 1_601 },
    ]) {
      expect(api.authenticateAtprotoDidResolution?.({
        authority,
        evidence: attestation(rejectedEnvelope as Envelope, resolverSecret, "ed25519"),
        validation_time: 1_100,
      })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    }
  });

  it("accepts a BIP340 resolver trust anchor over a verified PLC log envelope", async () => {
    const api = await loadResolution();
    const secret = "07".repeat(32);
    const plcDid = "did:plc:abcdefghijklmnopqrstuvwx";
    const plcMethod = `${plcDid}#atproto`;
    const plcDocument = JSON.stringify({
      id: plcDid,
      verificationMethod: [{
        controller: plcDid,
        id: plcMethod,
        publicKeyHex: didPublic,
        type: "Ed25519VerificationKey2020",
      }],
    });
    const plc: Envelope = {
      ...envelope,
      did: plcDid,
      resolution_method: "did:plc",
      canonical_https_url: null,
      plc_log_head: "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
      plc_log_hash: "11".repeat(32),
      canonical_document: plcDocument,
      document_sha256: bytesToHex(sha256(utf8Bytes(plcDocument))),
      selected_verification_method_id: plcMethod,
    };
    const authority = configuredAuthority(api, {
        suite: "bip340",
        public_key: bytesToHex(schnorr.getPublicKey(hexToBytes(secret))),
    });
    expect(api.authenticateAtprotoDidResolution?.({
      authority,
      evidence: attestation(plc, secret, "bip340"),
      validation_time: 1_100,
    })).toMatchObject({ verdict: "accept", resolution: expect.any(Object) });
  });
});

async function loadResolution(): Promise<ResolutionModule> {
  return resolutionModule as ResolutionModule;
}

function configuredAuthority(
  api: ResolutionModule,
  anchor: { suite: "ed25519" | "bip340"; public_key: string },
): object {
  const authority = api.createAtprotoResolverAuthority?.({
    trust_anchors: [anchor],
    allowed_policies: ["webpki-pinned-redirect-v1"],
    minimum_version: "1.0.0",
    max_ttl: 600,
  });
  if (authority === undefined) throw new Error("resolver authority missing");
  return authority;
}

function attestation(
  value: Envelope,
  secret: string,
  suite: "ed25519" | "bip340",
): { envelope: Envelope; signature: string } {
  return { envelope: value, signature: resolverSignature(value, secret, suite) };
}

function withCanonicalDocument(canonicalDocument: string): Envelope {
  return {
    ...envelope,
    canonical_document: canonicalDocument,
    document_sha256: bytesToHex(sha256(utf8Bytes(canonicalDocument))),
  };
}

function resolverSignature(
  value: Envelope,
  secret: string,
  suite: "ed25519" | "bip340",
): string {
  const digest = sha256(utf8Bytes(
    `heterodyne:atproto-did-resolution:v1\0${canonicalEnvelope(value)}`,
  ));
  return suite === "ed25519"
    ? bytesToHex(ed25519.sign(digest, hexToBytes(secret)))
    : bytesToHex(schnorr.sign(digest, hexToBytes(secret), AUX_RAND));
}

function canonicalEnvelope(value: Envelope): string {
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

function observationAttestation(
  value: ObservationEnvelope,
  secret: string,
): { envelope: ObservationEnvelope; signature: string } {
  const digest = sha256(utf8Bytes(
    `heterodyne:atproto-binding-observation:v2\0${JSON.stringify({
      domain: value.domain,
      binding_event_id: value.binding_event_id,
      binding_hash: value.binding_hash,
      did_signature_digest: value.did_signature_digest,
      did: value.did,
      pubkey: value.pubkey,
      generation: value.generation,
      observed_at: value.observed_at,
      checkpoint_reference: value.checkpoint_reference,
      resolution_envelope_hash: value.resolution_envelope_hash,
      resolver_policy: value.resolver_policy,
      resolver_version: value.resolver_version,
    })}`,
  ));
  return {
    envelope: value,
    signature: bytesToHex(ed25519.sign(digest, hexToBytes(secret))),
  };
}

async function bindingObservationFixture(): Promise<{
  expected: {
    binding_event_id: string;
    binding_hash: string;
    canonical_payload: string;
    did: string;
    did_signature: string;
    did_signing_key_id: string;
    pubkey: string;
    generation: number;
    event_created_at: number;
    nostr_event: NostrSignedEvent;
  };
  observation: ObservationEnvelope;
}> {
  const nostrSecret = "17".repeat(32);
  const pubkey = getPublicKey(nostrSecret);
  const canonicalPayload = JSON.stringify({
    spec_version: "heterodyne/0.5.0",
    did,
    did_signing_key_id: method,
    pubkey,
    established_at: 1_050,
    generation: 1,
    nonce: "01".repeat(32),
    predecessor: null,
  });
  const nostrEvent = await signEvent({
    secretKey: nostrSecret,
    created_at: 1_050,
    kind: 31009,
    tags: [
      ["d", did],
      ["heterodyne", "atproto_link"],
      ["pubkey", pubkey],
      ["did", did],
    ],
    content: canonicalPayload,
    auxRand: AUX_RAND,
  });
  const didSignature = bytesToHex(ed25519.sign(
    sha256(utf8Bytes(canonicalPayload)),
    hexToBytes(didSecret),
  ));
  const expected = {
    binding_event_id: nostrEvent.id,
    binding_hash: bytesToHex(sha256(utf8Bytes(canonicalPayload))),
    canonical_payload: canonicalPayload,
    did,
    did_signature: didSignature,
    did_signing_key_id: method,
    pubkey,
    generation: 1,
    event_created_at: nostrEvent.created_at,
    nostr_event: nostrEvent,
  };
  return {
    expected,
    observation: {
      domain: "heterodyne-atproto-binding-observation-v2",
      binding_event_id: nostrEvent.id,
      binding_hash: expected.binding_hash,
      did_signature_digest: bytesToHex(sha256(hexToBytes(didSignature))),
      did,
      pubkey,
      generation: 1,
      observed_at: 1_100,
      checkpoint_reference: `nostr:event:${nostrEvent.id}`,
      resolution_envelope_hash: bytesToHex(sha256(utf8Bytes(canonicalEnvelope(envelope)))),
      resolver_policy: envelope.resolver_policy,
      resolver_version: envelope.resolver_version,
    },
  };
}
