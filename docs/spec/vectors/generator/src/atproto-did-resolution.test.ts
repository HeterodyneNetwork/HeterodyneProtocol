import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { AUX_RAND } from "./vector-helpers.js";

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
  authenticateAtprotoDidResolution?: (input: {
    envelope: unknown;
    signature: string;
    trust_anchor: { suite: "ed25519" | "bip340"; public_key: string };
    now: number;
  }) => { verdict: "accept"; resolution: object } | {
    verdict: "reject";
    reason_code: string;
  };
  verifyAtprotoDidSignature?: (input: {
    resolution: unknown;
    did: string;
    verification_method_id: string;
    payload: string;
    signature: string;
    now: number;
  }) => boolean;
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
  resolver_version: "resolver-1.0.0",
};

describe("authenticated ATProto DID resolution", () => {
  it("mints only from a fresh exact resolver attestation and rejects a fake victim document", async () => {
    const api = await loadResolution();
    const valid = api.authenticateAtprotoDidResolution?.({
      envelope,
      signature: resolverSignature(envelope, resolverSecret, "ed25519"),
      trust_anchor: { suite: "ed25519", public_key: resolverPublic },
      now: 1_100,
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
      envelope: fake,
      signature: resolverSignature(fake, attackerSecret, "ed25519"),
      trust_anchor: { suite: "ed25519", public_key: resolverPublic },
      now: 1_100,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    expect(api.authenticateAtprotoDidResolution?.({
      envelope,
      signature: resolverSignature({ ...envelope, resolver_version: "forged" }, resolverSecret, "ed25519"),
      trust_anchor: { suite: "ed25519", public_key: resolverPublic },
      now: 1_100,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    expect(api.authenticateAtprotoDidResolution?.({
      envelope,
      signature: resolverSignature(envelope, resolverSecret, "ed25519"),
      trust_anchor: { suite: "ed25519", public_key: resolverPublic },
      now: 1_300,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    const wrongUrl = { ...envelope, canonical_https_url: "https://victim.example/did.json" };
    expect(api.authenticateAtprotoDidResolution?.({
      envelope: wrongUrl,
      signature: resolverSignature(wrongUrl, resolverSecret, "ed25519"),
      trust_anchor: { suite: "ed25519", public_key: resolverPublic },
      now: 1_100,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });
    const wrongResolutionMethod: Envelope = {
      ...envelope,
      resolution_method: "did:plc",
      canonical_https_url: null,
      plc_log_head: "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
      plc_log_hash: "11".repeat(32),
    };
    expect(api.authenticateAtprotoDidResolution?.({
      envelope: wrongResolutionMethod,
      signature: resolverSignature(wrongResolutionMethod, resolverSecret, "ed25519"),
      trust_anchor: { suite: "ed25519", public_key: resolverPublic },
      now: 1_100,
    })).toEqual({ verdict: "reject", reason_code: "atproto-did-resolution-invalid" });

    if (valid?.verdict !== "accept") throw new Error("resolution missing");
    const payload = "binding payload";
    const didSignature = bytesToHex(ed25519.sign(
      sha256(utf8Bytes(payload)),
      hexToBytes(didSecret),
    ));
    expect(api.verifyAtprotoDidSignature?.({
      resolution: valid.resolution,
      did,
      verification_method_id: method,
      payload,
      signature: didSignature,
      now: 1_100,
    })).toBe(true);
    expect(api.verifyAtprotoDidSignature?.({
      resolution: valid.resolution,
      did: "did:web:victim.example",
      verification_method_id: "did:web:victim.example#atproto",
      payload,
      signature: didSignature,
      now: 1_100,
    })).toBe(false);
    expect(api.verifyAtprotoDidSignature?.({
      resolution: valid.resolution,
      did,
      verification_method_id: `${did}#other`,
      payload,
      signature: didSignature,
      now: 1_100,
    })).toBe(false);
    expect(api.verifyAtprotoDidSignature?.({
      resolution: valid.resolution,
      did,
      verification_method_id: method,
      payload,
      signature: didSignature,
      now: 1_300,
    })).toBe(false);
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
    expect(api.authenticateAtprotoDidResolution?.({
      envelope: plc,
      signature: resolverSignature(plc, secret, "bip340"),
      trust_anchor: {
        suite: "bip340",
        public_key: bytesToHex(schnorr.getPublicKey(hexToBytes(secret))),
      },
      now: 1_100,
    })).toMatchObject({ verdict: "accept", resolution: expect.any(Object) });
  });
});

async function loadResolution(): Promise<ResolutionModule> {
  return await import("./atproto-did-resolution.js").catch(() => ({}));
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
