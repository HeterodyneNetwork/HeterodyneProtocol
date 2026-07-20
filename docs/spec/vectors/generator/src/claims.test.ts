import { createHash, generateKeyPairSync, sign as signNative } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import {
  computeClaimId,
  computeJwkThumbprint,
  revocationProofPayload,
  validateClaimEnvelope,
  validateClaimId,
  validateClaimRevocationEnvelope,
  type ClaimRevocation,
  type ClaimSemanticBody,
} from "./claims.js";
import { buildFixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { signEvent } from "./nostr.js";

const fixtures = buildFixtures();
const epoch = fixtures.personas.alice.epoch_keys.epoch_1;
const device = fixtures.ed25519_nids.alice_device_1;
const auxRand = fixtures.pinned_randomness.schnorr_aux_rand;
const issuedAt = 1784390400;

const semanticWithoutId = () => ({
  issuer: { type: "nostr-secp256k1" as const, value: epoch.pubkey },
  subject: { type: "radicle-ed25519-nid" as const, value: device.did_key },
  claim_class: "authorization" as const,
  namespace: "heterodyne.device",
  name: "claim-ledger-reader",
  value: true,
  issued_at: issuedAt,
  not_before: issuedAt,
  expires_at: issuedAt + 86400,
  audience: [fixtures.personas.alice.cold_root.pubkey],
  visibility: "repository-private" as const,
  comms_version: "comms/0.5.0" as const,
  registry_revision: 2 as const,
});

function semanticBody(): ClaimSemanticBody {
  const body = semanticWithoutId();
  return { claim_id: computeClaimId(body), ...body };
}

const addressTags = (claimId: string): string[][] => [["d", claimId]];

describe("canonical key claims", () => {
  it("derives the lowercase claim ID from the complete semantic body", () => {
    const body = semanticWithoutId();
    const expected = createHash("sha256").update(jcsCanonicalize(body), "utf8").digest("hex");
    expect(computeClaimId(body)).toBe(expected);
    expect(computeClaimId(body)).toMatch(/^[0-9a-f]{64}$/);
    expect(() => validateClaimId({ claim_id: expected, ...body })).not.toThrow();
  });

  it("rejects uppercase and mismatched claim IDs", () => {
    const body = semanticWithoutId();
    expect(() => validateClaimId({ claim_id: "A".repeat(64), ...body })).toThrow(/lowercase/);
    expect(() => validateClaimId({ claim_id: "0".repeat(64), ...body })).toThrow(/mismatch/);
  });

  it("validates a canonical signed kind:31013 envelope", async () => {
    const body = semanticBody();
    const event = await signEvent({
      secretKey: epoch.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: addressTags(body.claim_id),
      content: jcsCanonicalize(body),
    });
    expect(validateClaimEnvelope(event, { issuer_authorized: true, registry_revision: 2 })).toEqual(body);
  });

  it("rejects non-canonical content, duplicate addresses, bad signatures, and failed Core authority", async () => {
    const body = semanticBody();
    const valid = await signEvent({
      secretKey: epoch.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: addressTags(body.claim_id),
      content: jcsCanonicalize(body),
    });
    const nonCanonical = await signEvent({
      secretKey: epoch.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: [...addressTags(body.claim_id), ["d", body.claim_id]],
      content: JSON.stringify(body),
    });
    const duplicate = await signEvent({
      secretKey: epoch.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: [["d", body.claim_id], ["d", body.claim_id]],
      content: jcsCanonicalize(body),
    });
    expect(() => validateClaimEnvelope(nonCanonical, { issuer_authorized: true, registry_revision: 2 })).toThrow(/canonical/);
    expect(() => validateClaimEnvelope(duplicate, { issuer_authorized: true, registry_revision: 2 })).toThrow(/single.*d/i);
    const badSignature = `${valid.sig[0] === "0" ? "1" : "0"}${valid.sig.slice(1)}`;
    expect(() => validateClaimEnvelope({ ...valid, sig: badSignature }, { issuer_authorized: true, registry_revision: 2 })).toThrow(/signature/);
    expect(() => validateClaimEnvelope(valid, { issuer_authorized: false, registry_revision: 2 })).toThrow(/authority/);
  });

  it("accepts only byte-identical semantic bodies at an existing address", async () => {
    const body = semanticBody();
    const event = await signEvent({
      secretKey: epoch.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: addressTags(body.claim_id),
      content: jcsCanonicalize(body),
    });
    expect(validateClaimEnvelope(event, {
      issuer_authorized: true,
      registry_revision: 2,
      existing_semantic_body: structuredClone(body),
    })).toEqual(body);
    expect(() => validateClaimEnvelope(event, {
      issuer_authorized: true,
      registry_revision: 2,
      existing_semantic_body: { ...body, value: false },
    })).toThrow(/identical/);
  });

  it("rejects syntactically plausible but non-Ed25519 NIDs and mismatched outer issuers", async () => {
    const invalidNidBody = { ...semanticBody(), subject: { type: "radicle-ed25519-nid" as const, value: "did:key:z1234" } };
    const invalidNid = await signEvent({
      secretKey: epoch.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: addressTags(invalidNidBody.claim_id),
      content: jcsCanonicalize(invalidNidBody),
    });
    expect(() => validateClaimEnvelope(invalidNid, { issuer_authorized: true, registry_revision: 2 })).toThrow(/NID|did:key/);

    const body = semanticBody();
    const mismatched = await signEvent({
      secretKey: fixtures.personas.bob.epoch_keys.epoch_1.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: addressTags(body.claim_id),
      content: jcsCanonicalize(body),
    });
    expect(() => validateClaimEnvelope(mismatched, { issuer_authorized: true, registry_revision: 2 })).toThrow(/signer.*issuer/);
  });
});

describe("claim revocation envelopes", () => {
  async function revocationEvent(revocation: ClaimRevocation, secretKey = epoch.private_key) {
    return signEvent({
      secretKey,
      auxRand,
      created_at: revocation.revoked_at,
      kind: 31014,
      tags: addressTags(revocation.claim_id),
      content: jcsCanonicalize(revocation),
    });
  }

  it("uses a matching outer Nostr signer as the revoker proof", async () => {
    const revocation: ClaimRevocation = {
      claim_id: semanticBody().claim_id,
      revoked_at: issuedAt + 10,
      reason_code: "claim-revoked",
      revoker: { type: "nostr-secp256k1", value: epoch.pubkey },
    };
    const event = await revocationEvent(revocation);
    expect(validateClaimRevocationEnvelope(event)).toEqual({ ...revocation, signer: revocation.revoker, event_id: event.id });
  });

  it("verifies a native Ed25519 proof and derives the named NID", async () => {
    const unsigned = {
      claim_id: semanticBody().claim_id,
      revoked_at: issuedAt + 20,
      reason_code: "claim-revoked",
    };
    const signature = bytesToHex(ed25519.sign(utf8Bytes(revocationProofPayload(unsigned)), hexToBytes(device.private_key)));
    const revocation: ClaimRevocation = {
      ...unsigned,
      revoker: { type: "radicle-ed25519-nid", value: device.did_key },
      proof: { type: "radicle-ed25519", public_key: device.public_key, signature },
    };
    const event = await revocationEvent(revocation);
    expect(validateClaimRevocationEnvelope(event).signer).toEqual(revocation.revoker);
    const wrongNid = { ...revocation, revoker: { type: "radicle-ed25519-nid" as const, value: fixtures.ed25519_nids.alice_device_2.did_key } };
    const wrongNidEvent = await revocationEvent(wrongNid);
    expect(() => validateClaimRevocationEnvelope(wrongNidEvent)).toThrow(/NID/);
  });

  it("verifies a detached JWS proof and RFC 7638 thumbprint", async () => {
    const jwk = { kty: "OKP", crv: "Ed25519", x: Buffer.from(hexToBytes(device.public_key)).toString("base64url") };
    const thumbprint = computeJwkThumbprint(jwk);
    const unsigned = {
      claim_id: semanticBody().claim_id,
      revoked_at: issuedAt + 30,
      reason_code: "claim-revoked",
    };
    const protectedHeader = Buffer.from('{"alg":"EdDSA"}', "utf8").toString("base64url");
    const signingInput = `${protectedHeader}.${Buffer.from(revocationProofPayload(unsigned), "utf8").toString("base64url")}`;
    const signature = Buffer.from(ed25519.sign(utf8Bytes(signingInput), hexToBytes(device.private_key))).toString("base64url");
    const revocation: ClaimRevocation = {
      ...unsigned,
      revoker: { type: "jwk-thumbprint", value: thumbprint },
      proof: { type: "jwk-jws", jwk, protected: protectedHeader, signature },
    };
    const event = await revocationEvent(revocation);
    expect(validateClaimRevocationEnvelope(event).signer).toEqual(revocation.revoker);
    const wrongThumbprintEvent = await revocationEvent({
      ...revocation,
      revoker: { type: "jwk-thumbprint", value: "A".repeat(43) },
    });
    expect(() => validateClaimRevocationEnvelope(wrongThumbprintEvent)).toThrow(/thumbprint/);
  });

  it("supports only the explicit EdDSA, RS256, and ES256 native JWS suites", async () => {
    const cases = [
      { alg: "RS256", keyType: "rsa" as const },
      { alg: "ES256", keyType: "ec" as const },
    ];
    for (const { alg, keyType } of cases) {
      const pair = keyType === "rsa"
        ? generateKeyPairSync("rsa", { modulusLength: 2048 })
        : generateKeyPairSync("ec", { namedCurve: "P-256" });
      const jwk = pair.publicKey.export({ format: "jwk" }) as Record<string, string>;
      const unsigned = {
        claim_id: semanticBody().claim_id,
        revoked_at: issuedAt + (alg === "RS256" ? 31 : 32),
        reason_code: "claim-revoked",
      };
      const protectedHeader = Buffer.from(jcsCanonicalize({ alg }), "utf8").toString("base64url");
      const signingInput = Buffer.from(
        `${protectedHeader}.${Buffer.from(revocationProofPayload(unsigned), "utf8").toString("base64url")}`,
        "utf8",
      );
      const signature = alg === "RS256"
        ? signNative("RSA-SHA256", signingInput, pair.privateKey)
        : signNative("sha256", signingInput, { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
      const revocation: ClaimRevocation = {
        ...unsigned,
        revoker: { type: "jwk-thumbprint", value: computeJwkThumbprint(jwk) },
        proof: {
          type: "jwk-jws",
          jwk,
          protected: protectedHeader,
          signature: signature.toString("base64url"),
        },
      };
      expect(validateClaimRevocationEnvelope(await revocationEvent(revocation)).signer).toEqual(revocation.revoker);
    }
  });

  it("rejects ambiguous JWS headers, private JWKs, unsupported algorithms, and noncanonical base64url", async () => {
    const jwk = { kty: "OKP", crv: "Ed25519", x: Buffer.from(hexToBytes(device.public_key)).toString("base64url") };
    const unsigned = { claim_id: semanticBody().claim_id, revoked_at: issuedAt + 40, reason_code: "claim-revoked" };
    const proof = { type: "jwk-jws" as const, jwk, protected: Buffer.from('{"alg":"EdDSA"}').toString("base64url"), signature: "AA" };
    const base: ClaimRevocation = { ...unsigned, revoker: { type: "jwk-thumbprint", value: computeJwkThumbprint(jwk) }, proof };

    const b64False = { ...base, proof: { ...proof, protected: Buffer.from('{"alg":"EdDSA","b64":false,"crit":["b64"]}').toString("base64url") } };
    const b64FalseEvent = await revocationEvent(b64False);
    expect(() => validateClaimRevocationEnvelope(b64FalseEvent)).toThrow(/protected|header|b64|crit/);

    const privateJwk = { ...jwk, d: Buffer.from(hexToBytes(device.private_key)).toString("base64url") };
    const privateEvent = await revocationEvent({ ...base, proof: { ...proof, jwk: privateJwk } });
    expect(() => validateClaimRevocationEnvelope(privateEvent)).toThrow(/private/);

    const unsupportedEvent = await revocationEvent({ ...base, proof: { ...proof, protected: Buffer.from('{"alg":"none"}').toString("base64url") } });
    expect(() => validateClaimRevocationEnvelope(unsupportedEvent)).toThrow(/alg|algorithm/);

    const duplicateAlg = Buffer.from('{"alg":"none","alg":"EdDSA"}').toString("base64url");
    const duplicateAlgEvent = await revocationEvent({ ...base, proof: { ...proof, protected: duplicateAlg } });
    expect(() => validateClaimRevocationEnvelope(duplicateAlgEvent)).toThrow(/ambiguous|canonical/);

    const paddedEvent = await revocationEvent({ ...base, proof: { ...proof, protected: `${proof.protected}=` } });
    expect(() => validateClaimRevocationEnvelope(paddedEvent)).toThrow(/base64url|schema/);
  });
});
