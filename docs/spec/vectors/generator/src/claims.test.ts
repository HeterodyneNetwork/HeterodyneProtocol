import { createHash, generateKeyPairSync, sign as signNative } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { nip44 } from "nostr-tools";
import { describe, expect, it } from "vitest";
import {
  authorizeWithClaim,
  CLAIM_REVOCATION_PROFILE,
  computeClaimId,
  computeJwkThumbprint,
  resolveClaimState,
  revocationProofPayload,
  subjectProofPayload,
  validateClaimEnvelope,
  validateClaimId,
  validateClaimRevocationEnvelope,
  validateKeyRef,
  verifyClaimChain,
  type ClaimVerificationContext,
  type ClaimRevocation,
  type ClaimAuthorityEvidence,
  type ClaimSemanticBody,
  type JsonValue,
  type KeyProof,
  type KeyRef,
  type SubjectProofChallenge,
  type VerifiedRevocation,
  type RevocationAuthorityEvidence,
} from "./claims.js";
import { buildFixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { getEventId, signEvent, verifyEventSignature, type NostrSignedEvent, type NostrUnsignedEvent } from "./nostr.js";
import { buildClaimVectors } from "./topics-claims.js";

const fixtures = buildFixtures();
const epoch = fixtures.personas.alice.epoch_keys.epoch_1;
const device = fixtures.ed25519_nids.alice_device_1;
const auxRand = fixtures.pinned_randomness.schnorr_aux_rand;
const issuedAt = 1784390400;
const credentialLedger = {
  credential_ledger_persona: fixtures.personas.alice.cold_root.pubkey,
  credential_ledger_generation: 0,
};

const semanticWithoutId = () => ({
  issuer: { type: "nostr-secp256k1" as const, value: epoch.pubkey },
  subject: { type: "radicle-ed25519-nid" as const, value: device.did_key },
  claim_class: "authorization" as const,
  ...credentialLedger,
  namespace: "heterodyne.device",
  name: "claim-ledger-reader",
  value: true,
  issued_at: issuedAt,
  not_before: issuedAt,
  expires_at: issuedAt + 86400,
  audience: [fixtures.personas.alice.cold_root.pubkey],
  visibility: "repository-private" as const,
  spec_version: "comms/0.5.0" as const,
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
    expect(validateClaimEnvelope(event, {
      issuer_authorized: true,
      registry_revision: 2,
      credential_ledger: credentialLedger,
    })).toEqual(body);
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
    expect(() => validateClaimEnvelope(nonCanonical, {
      issuer_authorized: true, registry_revision: 2, credential_ledger: credentialLedger,
    })).toThrow(/canonical/);
    expect(() => validateClaimEnvelope(duplicate, {
      issuer_authorized: true, registry_revision: 2, credential_ledger: credentialLedger,
    })).toThrow(/exactly.*d/i);
    const badSignature = `${valid.sig[0] === "0" ? "1" : "0"}${valid.sig.slice(1)}`;
    expect(() => validateClaimEnvelope({ ...valid, sig: badSignature }, {
      issuer_authorized: true, registry_revision: 2, credential_ledger: credentialLedger,
    })).toThrow(/signature/);
    expect(() => validateClaimEnvelope(valid, {
      issuer_authorized: false, registry_revision: 2, credential_ledger: credentialLedger,
    })).toThrow(/authority/);
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
      credential_ledger: credentialLedger,
      existing_semantic_body: structuredClone(body),
    })).toEqual(body);
    expect(() => validateClaimEnvelope(event, {
      issuer_authorized: true,
      registry_revision: 2,
      credential_ledger: credentialLedger,
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
    expect(() => validateClaimEnvelope(invalidNid, {
      issuer_authorized: true, registry_revision: 2, credential_ledger: credentialLedger,
    })).toThrow(/NID|did:key/);

    const body = semanticBody();
    const mismatched = await signEvent({
      secretKey: fixtures.personas.bob.epoch_keys.epoch_1.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: addressTags(body.claim_id),
      content: jcsCanonicalize(body),
    });
    expect(() => validateClaimEnvelope(mismatched, {
      issuer_authorized: true, registry_revision: 2, credential_ledger: credentialLedger,
    })).toThrow(/signer.*issuer/);
  });

  it("rejects noncanonical or non-SHA-256 JWK thumbprint references", () => {
    expect(() => validateKeyRef({ type: "jwk-thumbprint", value: `${"A".repeat(42)}B` })).toThrow(/thumbprint|base64url/);
    expect(() => validateKeyRef({ type: "jwk-thumbprint", value: "A".repeat(42) })).toThrow(/thumbprint|base64url/);
  });
});

describe("claim revocation envelopes", () => {
  async function revocationEvent(
    revocation: ClaimRevocation,
    secretKey = epoch.private_key,
    createdAt = revocation.revoked_at,
  ) {
    return signEvent({
      secretKey,
      auxRand,
      created_at: createdAt,
      kind: 31014,
      tags: addressTags(revocation.claim_id),
      content: jcsCanonicalize(revocation),
    });
  }

  it("requires the Comms owner stamp and binds it into native revocation proofs", async () => {
    const stamped = {
      claim_id: semanticBody().claim_id,
      revoked_at: issuedAt + 9,
      reason_code: "claim-revoked",
      revoker: { type: "nostr-secp256k1", value: epoch.pubkey },
      spec_version: "comms/0.5.0",
      registry_revision: 2,
    } as unknown as ClaimRevocation;
    expect(revocationProofPayload(stamped)).toBe(jcsCanonicalize({
      domain: "heterodyne-claim-revocation-v1",
      claim_id: stamped.claim_id,
      revoked_at: stamped.revoked_at,
      reason_code: stamped.reason_code,
      spec_version: "comms/0.5.0",
      registry_revision: 2,
    }));
    const stampedEvent = await revocationEvent(stamped);
    expect(() => validateClaimRevocationEnvelope(stampedEvent)).not.toThrow();

    const { spec_version: _version, ...missingVersion } = stamped as ClaimRevocation & { spec_version: string };
    const { registry_revision: _revision, ...missingRevision } = stamped as ClaimRevocation & { registry_revision: number };
    const missingVersionEvent = await revocationEvent(missingVersion as ClaimRevocation);
    const missingRevisionEvent = await revocationEvent(missingRevision as ClaimRevocation);
    const wrongVersionEvent = await revocationEvent({ ...stamped, spec_version: "comms/0.5.1" } as unknown as ClaimRevocation);
    const legacyVersionEvent = await revocationEvent({
      ...missingVersion,
      comms_version: "comms/0.5.0",
    } as unknown as ClaimRevocation);
    const wrongRevisionEvent = await revocationEvent({ ...stamped, registry_revision: 1 } as unknown as ClaimRevocation);
    expect(() => validateClaimRevocationEnvelope(missingVersionEvent))
      .toThrow(/spec_version|required/);
    expect(() => validateClaimRevocationEnvelope(missingRevisionEvent))
      .toThrow(/registry_revision|required/);
    expect(() => validateClaimRevocationEnvelope(wrongVersionEvent)).toThrow(/spec_version|const/);
    expect(() => validateClaimRevocationEnvelope(legacyVersionEvent)).toThrow(/spec_version|required|additional/);
    expect(() => validateClaimRevocationEnvelope(wrongRevisionEvent)).toThrow(/registry_revision|const/);
  });

  it("requires exactly one ordered d=claim_id tag and rejects every re-signed alternative", async () => {
    const claim = semanticBody();
    const revocation = {
      claim_id: claim.claim_id,
      revoked_at: issuedAt + 9,
      reason_code: "claim-revoked",
      revoker: { type: "nostr-secp256k1", value: epoch.pubkey },
      spec_version: "comms/0.5.0",
      registry_revision: 2,
    } as unknown as ClaimRevocation;
    const cases = [
      {
        kind: 31013,
        created_at: issuedAt,
        content: jcsCanonicalize(claim),
        validate: (event: NostrSignedEvent) => validateClaimEnvelope(event, {
          issuer_authorized: true, registry_revision: 2, credential_ledger: credentialLedger,
        }),
      },
      {
        kind: 31014,
        created_at: revocation.revoked_at,
        content: jcsCanonicalize(revocation),
        validate: validateClaimRevocationEnvelope,
      },
    ];
    const variants = [
      [["d", claim.claim_id], ["p", epoch.pubkey]],
      [["p", epoch.pubkey], ["d", claim.claim_id]],
      [["d", claim.claim_id], ["d", claim.claim_id]],
      [["d", claim.claim_id, "extra"]],
      [[claim.claim_id, "d"]],
    ];
    for (const fixture of cases) {
      for (const tags of variants) {
        const event = await signEvent({
          secretKey: epoch.private_key,
          auxRand,
          created_at: fixture.created_at,
          kind: fixture.kind,
          tags,
          content: fixture.content,
        });
        expect(() => fixture.validate(event)).toThrow(/exactly.*d|exact.*tag|address tag/i);
      }
    }
  });

  it("uses a matching outer Nostr signer as the revoker proof", async () => {
    const revocation: ClaimRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: semanticBody().claim_id,
      revoked_at: issuedAt + 10,
      reason_code: "claim-revoked",
      revoker: { type: "nostr-secp256k1", value: epoch.pubkey },
    };
    const event = await revocationEvent(revocation);
    expect(validateClaimRevocationEnvelope(event)).toEqual({
      ...revocation,
      signer: revocation.revoker,
      event_id: event.id,
      event_created_at: event.created_at,
    });
  });

  it("binds revocation semantic time exactly to the signed outer event", async () => {
    const revocation: ClaimRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: semanticBody().claim_id,
      revoked_at: issuedAt + 11,
      reason_code: "claim-revoked",
      revoker: { type: "nostr-secp256k1", value: epoch.pubkey },
    };
    expect(validateClaimRevocationEnvelope(await revocationEvent(revocation)).event_created_at)
      .toBe(revocation.revoked_at);
    const oneSecondLate = await revocationEvent(revocation, epoch.private_key, revocation.revoked_at + 1);
    const backdatedByTenMinutes = await revocationEvent(revocation, epoch.private_key, revocation.revoked_at + 600);
    expect(() => validateClaimRevocationEnvelope(oneSecondLate))
      .toThrow(/claim-schema-invalid.*revoked_at.*created_at/);
    expect(() => validateClaimRevocationEnvelope(backdatedByTenMinutes))
      .toThrow(/claim-schema-invalid.*revoked_at.*created_at/);
  });

  it("verifies a native Ed25519 proof and derives the named NID", async () => {
    const unsigned = {
      ...CLAIM_REVOCATION_PROFILE,
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
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(hexToBytes(device.public_key)).toString("base64url"),
      use: "sig",
      key_ops: ["verify"],
      alg: "EdDSA",
    };
    const thumbprint = computeJwkThumbprint(jwk);
    const unsigned = {
      ...CLAIM_REVOCATION_PROFILE,
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

    for (const jwkMetadata of [
      { use: "enc" },
      { use: 7 },
      { key_ops: ["verify", "encrypt"] },
      { key_ops: ["sign"] },
      { key_ops: ["verify", "verify"] },
      { key_ops: "verify" },
      { alg: 7 },
      { alg: "RS256" },
      { jku: "https://attacker.example/jwks.json" },
      { x5u: "https://attacker.example/cert.pem" },
    ] as Array<Record<string, JsonValue>>) {
      const invalidMetadata = {
        ...revocation,
        proof: { ...revocation.proof!, jwk: { ...jwk, ...jwkMetadata } },
      } as ClaimRevocation;
      const invalidMetadataEvent = await revocationEvent(invalidMetadata);
      expect(() => validateClaimRevocationEnvelope(invalidMetadataEvent)).toThrow(/JWK|metadata|use|key_ops|alg|remote/);
    }
  });

  it("rejects non-minimal, undersized, or invalid JWK public forms", () => {
    const rsa2048 = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" });
    expect(() => computeJwkThumbprint(rsa2048 as Record<string, string>)).not.toThrow();
    const leadingZeroN = Buffer.concat([Buffer.from([0]), Buffer.from(rsa2048.n!, "base64url")]).toString("base64url");
    expect(() => computeJwkThumbprint({ ...rsa2048, n: leadingZeroN } as Record<string, string>)).toThrow(/minimal|leading zero/);
    const leadingZeroE = Buffer.concat([Buffer.from([0]), Buffer.from(rsa2048.e!, "base64url")]).toString("base64url");
    expect(() => computeJwkThumbprint({ ...rsa2048, e: leadingZeroE } as Record<string, string>)).toThrow(/minimal|leading zero/);

    const rsa1024 = generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({ format: "jwk" });
    expect(() => computeJwkThumbprint(rsa1024 as Record<string, string>)).toThrow(/2048|modulus/);

    const validEd = { kty: "OKP", crv: "Ed25519", x: Buffer.from(hexToBytes(device.public_key)).toString("base64url") };
    expect(() => computeJwkThumbprint(validEd)).not.toThrow();
    expect(() => computeJwkThumbprint({ ...validEd, x: Buffer.alloc(31).toString("base64url") })).toThrow(/32/);
    expect(() => computeJwkThumbprint({ ...validEd, x: Buffer.alloc(32).toString("base64url") })).toThrow(/public|point|order/);

    const p256Jwk = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
    expect(() => computeJwkThumbprint(p256Jwk as Record<string, string>)).not.toThrow();
    expect(() => computeJwkThumbprint({ ...p256Jwk, y: Buffer.alloc(31).toString("base64url") } as Record<string, string>)).toThrow(/32/);
    expect(() => computeJwkThumbprint({ ...p256Jwk, x: Buffer.alloc(32).toString("base64url") } as Record<string, string>)).toThrow(/public|point|curve/);
  });

  it("enforces closed public JWK members and exact optional metadata", () => {
    const bare = {
      kty: "OKP",
      crv: "Ed25519",
      x: Buffer.from(hexToBytes(device.public_key)).toString("base64url"),
    };
    const thumbprint = computeJwkThumbprint(bare);
    expect(computeJwkThumbprint({
      ...bare,
      alg: "EdDSA",
      use: "sig",
      key_ops: ["verify"],
      kid: thumbprint,
    })).toBe(thumbprint);

    for (const invalid of [
      { ...bare, arbitrary: "accepted-by-open-object" },
      { ...bare, x5c: ["certificate"] },
      { ...bare, x5t: "thumbprint" },
      { ...bare, kid: "wrong-kid" },
      { ...bare, alg: "RS256" },
      { ...bare, use: "enc" },
      { ...bare, key_ops: ["sign"] },
      { kty: "oct", k: "AA" },
    ] as Array<Record<string, JsonValue>>) {
      expect(() => computeJwkThumbprint(invalid)).toThrow(/JWK|member|kid|alg|use|key_ops|public|unsupported/);
    }
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
      const jwk = {
        ...pair.publicKey.export({ format: "jwk" }),
        use: "sig",
        key_ops: ["verify"],
        alg,
      } as Record<string, JsonValue>;
      const unsigned = {
        ...CLAIM_REVOCATION_PROFILE,
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
    const unsigned = { ...CLAIM_REVOCATION_PROFILE, claim_id: semanticBody().claim_id, revoked_at: issuedAt + 40, reason_code: "claim-revoked" };
    const proof = { type: "jwk-jws" as const, jwk, protected: Buffer.from('{"alg":"EdDSA"}').toString("base64url"), signature: "AA" };
    const base: ClaimRevocation = { ...unsigned, revoker: { type: "jwk-thumbprint", value: computeJwkThumbprint(jwk) }, proof };

    const b64False = { ...base, proof: { ...proof, protected: Buffer.from('{"alg":"EdDSA","b64":false,"crit":["b64"]}').toString("base64url") } };
    const b64FalseEvent = await revocationEvent(b64False);
    expect(() => validateClaimRevocationEnvelope(b64FalseEvent)).toThrow(/protected|header|b64|crit/);

    const privateJwk = { ...jwk, d: Buffer.from(hexToBytes(device.private_key)).toString("base64url") };
    const privateEvent = await revocationEvent({ ...base, proof: { ...proof, jwk: privateJwk } });
    expect(() => validateClaimRevocationEnvelope(privateEvent)).toThrow(/private|schema|additional/);

    const unsupportedEvent = await revocationEvent({ ...base, proof: { ...proof, protected: Buffer.from('{"alg":"none"}').toString("base64url") } });
    expect(() => validateClaimRevocationEnvelope(unsupportedEvent)).toThrow(/alg|algorithm/);

    const missingAlgEvent = await revocationEvent({
      ...base,
      proof: { ...proof, protected: Buffer.from("{}").toString("base64url") },
    });
    expect(() => validateClaimRevocationEnvelope(missingAlgEvent)).toThrow(/protected|header|alg/);

    const hmacEvent = await revocationEvent({
      ...base,
      proof: { ...proof, protected: Buffer.from('{"alg":"HS256"}').toString("base64url") },
    });
    expect(() => validateClaimRevocationEnvelope(hmacEvent)).toThrow(/alg|algorithm/);

    const duplicateAlg = Buffer.from('{"alg":"none","alg":"EdDSA"}').toString("base64url");
    const duplicateAlgEvent = await revocationEvent({ ...base, proof: { ...proof, protected: duplicateAlg } });
    expect(() => validateClaimRevocationEnvelope(duplicateAlgEvent)).toThrow(/ambiguous|canonical/);

    const paddedEvent = await revocationEvent({ ...base, proof: { ...proof, protected: `${proof.protected}=` } });
    expect(() => validateClaimRevocationEnvelope(paddedEvent)).toThrow(/base64url|schema/);
  });
});

describe("closed NIP-01 claim and revocation event structure", () => {
  function signRaw(unsigned: NostrUnsignedEvent): NostrSignedEvent {
    const id = getEventId(unsigned);
    const sig = bytesToHex(schnorr.sign(id, hexToBytes(epoch.private_key), auxRand));
    return { ...unsigned, id, sig };
  }

  it("rejects malformed structure before cryptography for both allocated kinds", async () => {
    const claim = semanticBody();
    const revocation: ClaimRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: claim.claim_id,
      revoked_at: issuedAt + 90,
      reason_code: "claim-revoked",
      revoker: { type: "nostr-secp256k1", value: epoch.pubkey },
    };
    const fixturesByKind = [
      {
        kind: 31013,
        created_at: issuedAt,
        tags: [["d", claim.claim_id]],
        content: jcsCanonicalize(claim),
        validate: (event: NostrSignedEvent) => validateClaimEnvelope(event, {
          issuer_authorized: true, registry_revision: 2, credential_ledger: credentialLedger,
        }),
      },
      {
        kind: 31014,
        created_at: revocation.revoked_at,
        tags: [["d", revocation.claim_id]],
        content: jcsCanonicalize(revocation),
        validate: (event: NostrSignedEvent) => validateClaimRevocationEnvelope(event),
      },
    ];

    for (const fixture of fixturesByKind) {
      const unsigned = {
        pubkey: epoch.pubkey,
        created_at: fixture.created_at,
        kind: fixture.kind,
        tags: fixture.tags,
        content: fixture.content,
      };
      const valid = signRaw(unsigned);
      const fractional = signRaw({ ...unsigned, created_at: fixture.created_at + 0.5 });
      const uppercasePubkey = signRaw({ ...unsigned, pubkey: epoch.pubkey.toUpperCase() });
      const emptyTag = signRaw({ ...unsigned, tags: [...fixture.tags, []] });
      const numericTag = signRaw({
        ...unsigned,
        tags: [...fixture.tags, ["x", 1, null] as unknown as string[]],
      });
      const stringTimestamp = signRaw({ ...unsigned, created_at: String(fixture.created_at) as unknown as number });
      const numericContent = signRaw({ ...unsigned, content: 7 as unknown as string });
      const nullTags = signRaw({ ...unsigned, tags: null as unknown as string[][] });
      const extra = { ...valid, extra: true } as NostrSignedEvent;
      const uppercaseId = { ...valid, id: valid.id.toUpperCase() };
      const uppercaseSig = { ...valid, sig: valid.sig.toUpperCase() };

      for (const malformed of [
        fractional,
        uppercasePubkey,
        emptyTag,
        numericTag,
        stringTimestamp,
        numericContent,
        nullTags,
        extra,
        uppercaseId,
        uppercaseSig,
      ]) {
        expect(() => fixture.validate(malformed)).toThrow(/NIP-01|structure|lowercase|created_at|tag|field|encoding/);
      }
    }
  });
});

describe("claim trust, attenuation, and authorization state", () => {
  const rootIssuer: KeyRef = { type: "nostr-secp256k1", value: epoch.pubkey };
  const delegatedIssuer: KeyRef = {
    type: "nostr-secp256k1",
    value: fixtures.device_publishing_keys.alice_device_1.pubkey,
  };
  const subject: KeyRef = {
    type: "nostr-secp256k1",
    value: fixtures.device_publishing_keys.alice_device_2.pubkey,
  };
  const sameKey = (left: KeyRef, right: KeyRef) => left.type === right.type && left.value === right.value;

  function claim(overrides: Partial<Omit<ClaimSemanticBody, "claim_id">> = {}): ClaimSemanticBody {
    const bodyWithUndefined = {
      issuer: rootIssuer,
      subject,
      claim_class: "authorization",
      credential_ledger_persona:
        overrides.claim_class === "descriptive" ? null : credentialLedger.credential_ledger_persona,
      credential_ledger_generation:
        overrides.claim_class === "descriptive" ? null : credentialLedger.credential_ledger_generation,
      namespace: "heterodyne.device",
      name: "claim-ledger-reader",
      value: true,
      issued_at: issuedAt,
      not_before: issuedAt,
      expires_at: issuedAt + 600,
      audience: [fixtures.personas.alice.cold_root.pubkey, "https://rp.example"],
      resources: ["rad:claims", "rad:claims/device"],
      visibility: "repository-private",
      spec_version: "comms/0.5.0",
      registry_revision: 2,
      ...overrides,
    };
    delete (bodyWithUndefined as Partial<ClaimSemanticBody>).claim_id;
    const body = Object.fromEntries(
      Object.entries(bodyWithUndefined).filter(([, value]) => value !== undefined),
    ) as Omit<ClaimSemanticBody, "claim_id">;
    return { claim_id: computeClaimId(body), ...body };
  }

  function reissue(body: ClaimSemanticBody, overrides: Partial<Omit<ClaimSemanticBody, "claim_id">>): ClaimSemanticBody {
    const { claim_id: _claimId, ...withoutId } = body;
    return claim({ ...withoutId, ...overrides });
  }

  function challenge(forClaim: ClaimSemanticBody, overrides: Partial<SubjectProofChallenge> = {}): SubjectProofChallenge {
    return {
      domain: "heterodyne-claim-pop-v1",
      claim_id: forClaim.claim_id,
      nonce: "ab".repeat(16),
      audience: fixtures.personas.alice.cold_root.pubkey,
      resource: "rad:claims/device",
      operation: "read",
      issued_at: issuedAt + 10,
      expires_at: issuedAt + 70,
      ...overrides,
    };
  }

  function nostrProof(forClaim: ClaimSemanticBody, proofChallenge = challenge(forClaim)): KeyProof {
    return {
      type: "nostr-bip340",
      signature: bytesToHex(schnorr.sign(utf8Bytes(subjectProofPayload(proofChallenge)), hexToBytes(fixtures.device_publishing_keys.alice_device_2.private_key), auxRand)),
    };
  }

  function authorityEvidence(forClaim: ClaimSemanticBody, eventByte = "31"): ClaimAuthorityEvidence {
    return {
      claim_id: forClaim.claim_id,
      issuer: forClaim.issuer,
      event_id: eventByte.repeat(32),
      envelope_valid: true,
      core_kel_authority_valid: true,
      credential_ledger_persona: forClaim.credential_ledger_persona,
      credential_ledger_generation: forClaim.credential_ledger_generation,
      verified_at: issuedAt + 5,
      valid_until: issuedAt + 300,
    };
  }

  function context(
    forClaim: ClaimSemanticBody,
    overrides: Partial<ClaimVerificationContext> = {},
  ): ClaimVerificationContext {
    const proofChallenge = challenge(forClaim);
    const evidence = authorityEvidence(forClaim);
    return {
      now: issuedAt + 20,
      audience: fixtures.personas.alice.cold_root.pubkey,
      resource: "rad:claims/device",
      requested_namespace: forClaim.namespace,
      requested_operation: "read",
      expected_nonce: proofChallenge.nonce,
      used_nonces: new Set(),
      trusted_issuers: [rootIssuer],
      claim_authority_evidence: new Map([[forClaim.claim_id, evidence]]),
      revocation_authority_evidence: new Map(),
      repository_confirmed: new Set([forClaim.claim_id]),
      repository_conflicted: new Set(),
      revocations: [],
      subject_proof: { key: forClaim.subject, challenge: proofChallenge, proof: nostrProof(forClaim, proofChallenge) },
      ...overrides,
      credential_ledger: overrides.credential_ledger ?? credentialLedger,
    };
  }

  function delegatedPair(): { root: ClaimSemanticBody; child: ClaimSemanticBody } {
    const root = claim({
      subject: delegatedIssuer,
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [fixtures.personas.alice.cold_root.pubkey, "https://rp.example"],
        resources: ["rad:claims", "rad:claims/device"],
        remaining_depth: 2,
      },
    });
    const child = claim({
      issuer: delegatedIssuer,
      parent_claim_id: root.claim_id,
      audience: [fixtures.personas.alice.cold_root.pubkey],
      resources: ["rad:claims/device"],
      not_before: issuedAt + 1,
      expires_at: issuedAt + 300,
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [fixtures.personas.alice.cold_root.pubkey],
        resources: ["rad:claims/device"],
        remaining_depth: 1,
      },
    });
    return { root, child };
  }

  function delegatedContext(root: ClaimSemanticBody, child: ClaimSemanticBody): ClaimVerificationContext {
    return context(child, {
      claim_authority_evidence: new Map([
        [root.claim_id, authorityEvidence(root, "32")],
        [child.claim_id, authorityEvidence(child, "33")],
      ]),
      repository_confirmed: new Set([root.claim_id, child.claim_id]),
    });
  }

  it("resolves a deterministic root-to-leaf chain and rejects missing parents or cycles", () => {
    const { root, child } = delegatedPair();
    expect(verifyClaimChain(child, new Map([[root.claim_id, root], [child.claim_id, child]])))
      .toEqual([root, child]);
    expect(() => verifyClaimChain(child, new Map([[child.claim_id, child]])))
      .toThrow(/claim-delegation-not-authorized.*missing ancestor/);
    const a = claim({ parent_claim_id: "11".repeat(32) });
    const b = claim({ parent_claim_id: a.claim_id });
    const cyclicA = { ...a, parent_claim_id: b.claim_id };
    expect(() => verifyClaimChain(cyclicA, new Map([[cyclicA.claim_id, cyclicA], [b.claim_id, b]])))
      .toThrow(/claim-chain-cycle/);
  });

  it("requires current claim-bound envelope and Core/KEL authority evidence before policy", () => {
    const active = claim();
    const valid = context(active, { trusted_issuers: [] });
    expect(authorizeWithClaim(active, [active], {
      ...valid,
      claim_authority_evidence: new Map(),
    })).toEqual({ allowed: false, state: "invalid", reason_code: "claim-issuer-authority-invalid" });

    const baseEvidence = valid.claim_authority_evidence.get(active.claim_id)!;
    for (const evidence of [
      { ...baseEvidence, envelope_valid: false },
      { ...baseEvidence, core_kel_authority_valid: false },
      { ...baseEvidence, claim_id: "01".repeat(32) },
      { ...baseEvidence, issuer: subject },
      { ...baseEvidence, valid_until: valid.now },
      { ...baseEvidence, verified_at: valid.now + 1 },
    ]) {
      const decision = authorizeWithClaim(active, [active], {
        ...valid,
        claim_authority_evidence: new Map([[active.claim_id, evidence]]),
      });
      expect(decision).toEqual({ allowed: false, state: "invalid", reason_code: "claim-issuer-authority-invalid" });
    }
  });

  it("binds requested namespace, operation, expected nonce, and caller-owned replay state", () => {
    const active = claim();
    const valid = context(active);
    expect(authorizeWithClaim(active, [active], { ...valid, requested_namespace: "heterodyne.control" }).reason_code)
      .toBe("claim-attenuation-violation");
    expect(authorizeWithClaim(active, [active], { ...valid, requested_operation: "write" }).reason_code)
      .toBe("claim-subject-proof-invalid");
    expect(authorizeWithClaim(active, [active], { ...valid, expected_nonce: "cd".repeat(16) }).reason_code)
      .toBe("claim-subject-proof-invalid");
    const consumed = context(active);
    consumed.used_nonces.add(consumed.expected_nonce);
    expect(authorizeWithClaim(active, [active], consumed).reason_code).toBe("claim-subject-proof-invalid");
    const callerState = context(active);
    expect(authorizeWithClaim(active, [active], callerState).allowed).toBe(true);
    callerState.used_nonces.add(callerState.expected_nonce);
    expect(authorizeWithClaim(active, [active], callerState).reason_code).toBe("claim-subject-proof-invalid");
  });

  it("enforces the eight-edge limit and explicit depth decrement", () => {
    const chain: ClaimSemanticBody[] = [];
    let parent = claim({
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [fixtures.personas.alice.cold_root.pubkey],
        resources: ["rad:claims/device"],
        remaining_depth: 8,
      },
    });
    chain.push(parent);
    for (let edge = 1; edge <= 9; edge += 1) {
      const child = claim({
        issuer: parent.subject,
        subject: {
          type: "nostr-secp256k1",
          value: bytesToHex(schnorr.getPublicKey((20 + edge).toString(16).padStart(64, "0"))),
        },
        parent_claim_id: parent.claim_id,
        not_before: issuedAt + edge,
        expires_at: issuedAt + 600 - edge,
        audience: [fixtures.personas.alice.cold_root.pubkey],
        resources: ["rad:claims/device"],
        constraints: {
          namespaces: ["heterodyne.device"],
          audiences: [fixtures.personas.alice.cold_root.pubkey],
          resources: ["rad:claims/device"],
          remaining_depth: Math.max(0, 8 - edge),
        },
      });
      chain.push(child);
      parent = child;
    }
    const map = new Map(chain.map((entry) => [entry.claim_id, entry]));
    expect(verifyClaimChain(chain[8], map)).toHaveLength(9);
    expect(() => verifyClaimChain(chain[9], map)).toThrow(/claim-chain-depth-exceeded/);
  });

  it("rejects issuer mismatch and widening of semantic, audience, resource, validity, or delegation scope", () => {
    const { root, child } = delegatedPair();
    const invalidChildren = [
      reissue(child, { issuer: subject, parent_claim_id: root.claim_id }),
      reissue(child, { namespace: "heterodyne.control", parent_claim_id: root.claim_id }),
      reissue(child, { name: "oidc-token-issuer", parent_claim_id: root.claim_id }),
      reissue(child, { value: false, parent_claim_id: root.claim_id }),
      reissue(child, { audience: [...child.audience!, "https://other.example"], parent_claim_id: root.claim_id }),
      reissue(child, { resources: ["rad:other"], parent_claim_id: root.claim_id }),
      reissue(child, { not_before: issuedAt - 1, parent_claim_id: root.claim_id }),
      reissue(child, { expires_at: issuedAt + 601, parent_claim_id: root.claim_id }),
      reissue(child, { constraints: { ...child.constraints!, remaining_depth: 2 }, parent_claim_id: root.claim_id }),
    ];
    for (const invalid of invalidChildren) {
      expect(() => verifyClaimChain(invalid, new Map([[root.claim_id, root], [invalid.claim_id, invalid]])))
        .toThrow(/claim-(delegation-not-authorized|attenuation-violation)/);
    }
    const equalWindow = reissue(child, {
      not_before: root.not_before,
      expires_at: root.expires_at,
      parent_claim_id: root.claim_id,
    });
    expect(verifyClaimChain(
      equalWindow,
      new Map([[root.claim_id, root], [equalWindow.claim_id, equalWindow]]),
    )).toEqual([root, equalWindow]);
  });

  it("requires explicit authorization audience and resource restrictions", () => {
    const noAudience = claim({ audience: undefined });
    expect(authorizeWithClaim(noAudience, [noAudience], context(noAudience)).reason_code)
      .toBe("claim-attenuation-violation");
    const noResource = claim({ resources: undefined });
    expect(authorizeWithClaim(noResource, [noResource], context(noResource)).reason_code)
      .toBe("claim-attenuation-violation");
  });

  it("exposes all seven states while keeping trust as the final policy stage", () => {
    const active = claim();
    expect(resolveClaimState(active, [active], context(active))).toBe("active");
    expect(resolveClaimState(active, [active], context(active, { trusted_issuers: [] }))).toBe("untrusted");
    expect(resolveClaimState(active, [active], context(active, { repository_confirmed: new Set() }))).toBe("provisional");
    expect(resolveClaimState(active, [active], context(active, {
      now: active.expires_at!,
      claim_authority_evidence: new Map([[
        active.claim_id,
        { ...authorityEvidence(active), valid_until: active.expires_at! + 60 },
      ]]),
    }))).toBe("expired");
    expect(resolveClaimState(active, [active], context(active, { repository_conflicted: new Set([active.claim_id]) }))).toBe("conflicted");
    const directRevocation: VerifiedRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: active.claim_id,
      revoked_at: issuedAt + 11,
      reason_code: "claim-revoked",
      revoker: rootIssuer,
      signer: rootIssuer,
      event_id: "44".repeat(32),
      event_created_at: issuedAt + 11,
    };
    expect(resolveClaimState(active, [active], context(active, { revocations: [directRevocation] }))).toBe("revoked");
    expect(authorizeWithClaim(active, [active], context(active, {
      trusted_issuers: [],
      repository_confirmed: new Set(),
      revocations: [directRevocation],
    }))).toEqual({ allowed: false, state: "revoked", reason_code: "claim-revoked" });
    const copied = context(active, { trusted_issuers: [] });
    copied.subject_proof = { ...copied.subject_proof!, challenge: { ...copied.subject_proof!.challenge, operation: "write" } };
    expect(resolveClaimState(active, [active], copied)).toBe("invalid");
    expect(authorizeWithClaim(active, [active], copied).reason_code).toBe("claim-subject-proof-invalid");
    const malformed = { ...active, claim_id: "00".repeat(32) };
    expect(authorizeWithClaim(malformed, [malformed], context(malformed, { trusted_issuers: [] })))
      .toEqual({ allowed: false, state: "invalid", reason_code: "claim-id-mismatch" });
  });

  it("requires every authorization ancestor to remain confirmed and uncompromised", () => {
    const { root, child } = delegatedPair();
    const valid = delegatedContext(root, child);
    expect(authorizeWithClaim(child, [root, child], valid).allowed).toBe(true);
    expect(authorizeWithClaim(child, [root, child], {
      ...valid,
      repository_confirmed: new Set([child.claim_id]),
    })).toEqual({ allowed: false, state: "provisional", reason_code: "claim-repository-unconfirmed" });
    expect(authorizeWithClaim(child, [root, child], {
      ...valid,
      repository_conflicted: new Set([root.claim_id]),
    })).toEqual({ allowed: false, state: "conflicted", reason_code: "claim-repository-conflict" });
    const expiredRoot = reissue(root, { expires_at: valid.now });
    const expiredChild = reissue(child, { parent_claim_id: expiredRoot.claim_id, expires_at: valid.now - 1 });
    const expiredContext = delegatedContext(expiredRoot, expiredChild);
    expiredContext.now = valid.now;
    expect(authorizeWithClaim(expiredChild, [expiredRoot, expiredChild], expiredContext))
      .toEqual({ allowed: false, state: "expired", reason_code: "claim-expired" });

    const ancestorRevocation: VerifiedRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: root.claim_id,
      revoked_at: issuedAt + 10,
      reason_code: "claim-revoked",
      revoker: root.issuer,
      signer: root.issuer,
      event_id: "58".repeat(32),
      event_created_at: issuedAt + 10,
    };
    expect(authorizeWithClaim(child, [root, child], {
      ...valid,
      repository_confirmed: new Set([child.claim_id]),
      revocations: [ancestorRevocation],
    })).toEqual({ allowed: false, state: "revoked", reason_code: "claim-revoked" });
  });

  it("applies repository finality to authorization claims above a descriptive leaf", () => {
    const { root } = delegatedPair();
    const descriptive = claim({
      claim_class: "descriptive",
      issuer: root.subject,
      subject,
      parent_claim_id: root.claim_id,
      not_before: root.not_before + 1,
      expires_at: root.expires_at! - 1,
    });
    const chain = [root, descriptive];
    const base = context(descriptive, {
      trusted_issuers: [root.issuer],
      subject_proof: null,
      claim_authority_evidence: new Map([
        [root.claim_id, authorityEvidence(root, "72")],
        [descriptive.claim_id, authorityEvidence(descriptive, "73")],
      ]),
      repository_confirmed: new Set([descriptive.claim_id]),
    });
    expect(resolveClaimState(descriptive, chain, base)).toBe("provisional");
    expect(authorizeWithClaim(descriptive, chain, base)).toEqual({
      allowed: false,
      state: "provisional",
      reason_code: "claim-repository-unconfirmed",
    });

    const standalone = claim({
      claim_class: "descriptive",
      parent_claim_id: undefined,
      expires_at: undefined,
    });
    expect(resolveClaimState(standalone, [standalone], context(standalone, {
      subject_proof: null,
      repository_confirmed: new Set(),
    }))).toBe("active");
  });

  it("recognizes each authorization revoker and applies reduction before repository finality", () => {
    const { root, child } = delegatedPair();
    const authorities = [child.issuer, root.issuer, child.subject];
    for (const [index, authority] of authorities.entries()) {
      const revocation: VerifiedRevocation = {
        ...CLAIM_REVOCATION_PROFILE,
        claim_id: child.claim_id,
        revoked_at: issuedAt + 10,
        reason_code: "claim-revoked",
        revoker: authority,
        signer: authority,
        event_id: (50 + index).toString(16).padStart(64, "0"),
        event_created_at: issuedAt + 10,
      };
      const base = delegatedContext(root, child);
      const revocationAuthority: RevocationAuthorityEvidence | undefined = sameKey(authority, root.issuer)
        ? {
            event_id: revocation.event_id,
            claim_id: child.claim_id,
            signer: authority,
            authority: "active-ancestor-issuer",
            authority_claim_id: root.claim_id,
            valid_from: root.not_before,
            valid_until: root.expires_at!,
            core_kel_authority_valid: true,
          }
        : undefined;
      const decision = authorizeWithClaim(child, [root, child], {
        ...base,
        repository_confirmed: new Set(),
        revocations: [revocation],
        revocation_authority_evidence: revocationAuthority === undefined
          ? new Map()
          : new Map([[revocation.event_id, revocationAuthority]]),
      });
      expect(decision).toEqual({ allowed: false, state: "revoked", reason_code: "claim-revoked" });
    }
    const outsider: KeyRef = {
      type: "nostr-secp256k1",
      value: fixtures.personas.bob.epoch_keys.epoch_1.pubkey,
    };
    const unauthorized: VerifiedRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: child.claim_id,
      revoked_at: issuedAt + 10,
      reason_code: "claim-revoked",
      revoker: outsider,
      signer: outsider,
      event_id: "59".repeat(32),
      event_created_at: issuedAt + 10,
    };
    expect(authorizeWithClaim(child, [root, child], {
      ...delegatedContext(root, child),
      revocations: [unauthorized],
    }).allowed).toBe(true);
  });

  it("limits descriptive revocation to issuer, named revoker, or superior issuer", () => {
    const namedRevoker: KeyRef = { type: "radicle-ed25519-nid", value: device.did_key };
    const descriptiveRoot = claim({
      subject: delegatedIssuer,
      revokers: [namedRevoker],
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [fixtures.personas.alice.cold_root.pubkey, "https://rp.example"],
        resources: ["rad:claims", "rad:claims/device"],
        remaining_depth: 1,
      },
    });
    const descriptive = claim({
      claim_class: "descriptive",
      issuer: delegatedIssuer,
      subject,
      parent_claim_id: descriptiveRoot.claim_id,
      not_before: descriptiveRoot.not_before + 1,
      expires_at: descriptiveRoot.expires_at! - 1,
      revokers: [namedRevoker],
    });
    for (const authority of [descriptive.issuer, descriptiveRoot.issuer, namedRevoker]) {
      const revocation: VerifiedRevocation = {
        ...CLAIM_REVOCATION_PROFILE,
        claim_id: descriptive.claim_id,
        revoked_at: issuedAt + 10,
        reason_code: "claim-revoked",
        revoker: authority,
        signer: authority,
        event_id: "55".repeat(32),
        event_created_at: issuedAt + 10,
      };
      const revocationAuthority: RevocationAuthorityEvidence | undefined = sameKey(authority, descriptiveRoot.issuer)
        ? {
            event_id: revocation.event_id,
            claim_id: descriptive.claim_id,
            signer: authority,
            authority: "active-ancestor-issuer",
            authority_claim_id: descriptiveRoot.claim_id,
            valid_from: descriptiveRoot.not_before,
            valid_until: descriptiveRoot.expires_at!,
            core_kel_authority_valid: true,
          }
        : undefined;
      expect(resolveClaimState(descriptive, [descriptiveRoot, descriptive], context(descriptive, {
        trusted_issuers: [descriptiveRoot.issuer],
        claim_authority_evidence: new Map([
          [descriptiveRoot.claim_id, authorityEvidence(descriptiveRoot, "34")],
          [descriptive.claim_id, authorityEvidence(descriptive, "35")],
        ]),
        subject_proof: null,
        revocations: [revocation],
        revocation_authority_evidence: revocationAuthority === undefined
          ? new Map()
          : new Map([[revocation.event_id, revocationAuthority]]),
      }))).toBe("revoked");
    }
    const subjectRejection: VerifiedRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: descriptive.claim_id,
      revoked_at: issuedAt + 10,
      reason_code: "claim-revoked",
      revoker: descriptive.subject,
      signer: descriptive.subject,
      event_id: "56".repeat(32),
      event_created_at: issuedAt + 10,
    };
    expect(resolveClaimState(descriptive, [descriptiveRoot, descriptive], context(descriptive, {
      trusted_issuers: [descriptiveRoot.issuer],
      claim_authority_evidence: new Map([
        [descriptiveRoot.claim_id, authorityEvidence(descriptiveRoot, "34")],
        [descriptive.claim_id, authorityEvidence(descriptive, "35")],
      ]),
      repository_confirmed: new Set([descriptiveRoot.claim_id, descriptive.claim_id]),
      subject_proof: null,
      revocations: [subjectRejection],
    }))).toBe("active");
  });

  it("requires revocation-event-bound Core evidence for persona and superior authorities", () => {
    const active = claim();
    const personaColdRoot: KeyRef = {
      type: "nostr-secp256k1",
      value: fixtures.personas.alice.cold_root.pubkey,
    };
    const revocation: VerifiedRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: active.claim_id,
      revoked_at: issuedAt + 10,
      reason_code: "claim-revoked",
      revoker: personaColdRoot,
      signer: personaColdRoot,
      event_id: "61".repeat(32),
      event_created_at: issuedAt + 10,
    };
    const evidence: RevocationAuthorityEvidence = {
      event_id: revocation.event_id,
      claim_id: active.claim_id,
      signer: personaColdRoot,
      authority: "persona-cold-root",
      valid_from: issuedAt,
      valid_until: issuedAt + 600,
      core_kel_authority_valid: true,
    };
    expect(authorizeWithClaim(active, [active], context(active, {
      repository_confirmed: new Set(),
      revocations: [revocation],
      revocation_authority_evidence: new Map([[revocation.event_id, evidence]]),
    }))).toEqual({ allowed: false, state: "revoked", reason_code: "claim-revoked" });

    const backdatedRevocation: VerifiedRevocation = {
      ...revocation,
      event_created_at: evidence.valid_until + 1,
    };
    expect(authorizeWithClaim(active, [active], context(active, {
      revocations: [backdatedRevocation],
      revocation_authority_evidence: new Map([[backdatedRevocation.event_id, evidence]]),
    })).state).toBe("active");

    const personaEpoch: KeyRef = {
      type: "nostr-secp256k1",
      value: fixtures.personas.carol.epoch_keys.epoch_1.pubkey,
    };
    const epochRevocation: VerifiedRevocation = {
      ...revocation,
      revoker: personaEpoch,
      signer: personaEpoch,
      event_id: "64".repeat(32),
    };
    const epochEvidence: RevocationAuthorityEvidence = {
      ...evidence,
      event_id: epochRevocation.event_id,
      signer: personaEpoch,
      authority: "persona-epoch",
    };
    expect(authorizeWithClaim(active, [active], context(active, {
      repository_confirmed: new Set(),
      revocations: [epochRevocation],
      revocation_authority_evidence: new Map([[epochRevocation.event_id, epochEvidence]]),
    })).state).toBe("revoked");

    for (const invalid of [
      { ...evidence, event_id: "62".repeat(32) },
      { ...evidence, claim_id: "63".repeat(32) },
      { ...evidence, signer: subject },
      { ...evidence, valid_until: revocation.revoked_at },
      { ...evidence, core_kel_authority_valid: false },
      { ...evidence, authority: "active-ancestor-issuer" as const, authority_claim_id: active.claim_id },
    ]) {
      expect(authorizeWithClaim(active, [active], context(active, {
        revocations: [revocation],
        revocation_authority_evidence: new Map([[revocation.event_id, invalid]]),
      })).allowed).toBe(true);
    }
  });

  it("verifies BIP-340, Ed25519, and JWS subject possession with exact challenge binding", () => {
    const nostrClaim = claim();
    expect(authorizeWithClaim(nostrClaim, [nostrClaim], context(nostrClaim)).allowed).toBe(true);

    const edClaim = claim({ subject: { type: "radicle-ed25519-nid", value: device.did_key } });
    const edChallenge = challenge(edClaim);
    const edProof: KeyProof = {
      type: "radicle-ed25519",
      public_key: device.public_key,
      signature: bytesToHex(ed25519.sign(utf8Bytes(subjectProofPayload(edChallenge)), hexToBytes(device.private_key))),
    };
    expect(authorizeWithClaim(edClaim, [edClaim], context(edClaim, {
      subject_proof: { key: edClaim.subject, challenge: edChallenge, proof: edProof },
    })).allowed).toBe(true);

    const jwk = { kty: "OKP", crv: "Ed25519", x: Buffer.from(device.public_key, "hex").toString("base64url") };
    const jwkClaim = claim({ subject: { type: "jwk-thumbprint", value: computeJwkThumbprint(jwk) } });
    const jwkChallenge = challenge(jwkClaim);
    const protectedHeader = Buffer.from(jcsCanonicalize({ alg: "EdDSA" }), "utf8").toString("base64url");
    const signingInput = `${protectedHeader}.${Buffer.from(subjectProofPayload(jwkChallenge), "utf8").toString("base64url")}`;
    const jwkProof: KeyProof = {
      type: "jwk-jws",
      jwk,
      protected: protectedHeader,
      signature: Buffer.from(ed25519.sign(utf8Bytes(signingInput), hexToBytes(device.private_key))).toString("base64url"),
    };
    expect(authorizeWithClaim(jwkClaim, [jwkClaim], context(jwkClaim, {
      subject_proof: { key: jwkClaim.subject, challenge: jwkChallenge, proof: jwkProof },
    })).allowed).toBe(true);

    for (const { alg, pair } of [
      { alg: "RS256", pair: generateKeyPairSync("rsa", { modulusLength: 2048 }) },
      { alg: "ES256", pair: generateKeyPairSync("ec", { namedCurve: "P-256" }) },
    ]) {
      const publicJwk = pair.publicKey.export({ format: "jwk" }) as Record<string, JsonValue>;
      const algorithmClaim = claim({
        subject: { type: "jwk-thumbprint", value: computeJwkThumbprint(publicJwk) },
      });
      const algorithmChallenge = challenge(algorithmClaim);
      const algorithmProtected = Buffer.from(jcsCanonicalize({ alg }), "utf8").toString("base64url");
      const algorithmInput = Buffer.from(
        `${algorithmProtected}.${Buffer.from(subjectProofPayload(algorithmChallenge), "utf8").toString("base64url")}`,
        "utf8",
      );
      const algorithmSignature = alg === "RS256"
        ? signNative("RSA-SHA256", algorithmInput, pair.privateKey)
        : signNative("sha256", algorithmInput, { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
      const algorithmProof: KeyProof = {
        type: "jwk-jws",
        jwk: publicJwk,
        protected: algorithmProtected,
        signature: algorithmSignature.toString("base64url"),
      };
      expect(authorizeWithClaim(algorithmClaim, [algorithmClaim], context(algorithmClaim, {
        subject_proof: { key: algorithmClaim.subject, challenge: algorithmChallenge, proof: algorithmProof },
      })).allowed).toBe(true);
    }

    const copiedChallenge = { ...jwkChallenge, nonce: "cd".repeat(16) };
    expect(authorizeWithClaim(jwkClaim, [jwkClaim], context(jwkClaim, {
      subject_proof: { key: jwkClaim.subject, challenge: copiedChallenge, proof: jwkProof },
    }))).toEqual({ allowed: false, state: "invalid", reason_code: "claim-subject-proof-invalid" });
  });

  it("rejects missing, stale, overlong, or context-copied proof before trust policy", () => {
    const active = claim();
    expect(authorizeWithClaim(active, [active], context(active, { subject_proof: null })))
      .toEqual({ allowed: false, state: "invalid", reason_code: "claim-subject-proof-required" });
    const base = context(active, { trusted_issuers: [] });
    for (const changed of [
      { ...base.subject_proof!.challenge, domain: "wrong-domain" as SubjectProofChallenge["domain"] },
      { ...base.subject_proof!.challenge, audience: "https://other.example" },
      { ...base.subject_proof!.challenge, resource: "rad:other" },
      { ...base.subject_proof!.challenge, expires_at: base.subject_proof!.challenge.issued_at + 61 },
      { ...base.subject_proof!.challenge, expires_at: base.now - 1 },
    ]) {
      const decision = authorizeWithClaim(active, [active], {
        ...base,
        subject_proof: { ...base.subject_proof!, challenge: changed },
      });
      expect(decision.reason_code).toBe("claim-subject-proof-invalid");
    }
  });
});

describe("normative claim vector authoring", () => {
  it("authors exactly the 20 named Comms vectors with closed visibility carriers", async () => {
    const vectors = await buildClaimVectors(fixtures);
    expect(vectors.map(({ relativePath }) => relativePath)).toEqual([
      "claims/001-canonical-nostr-subject.json",
      "claims/002-canonical-radicle-nid-subject.json",
      "claims/003-canonical-jwk-thumbprint-subject.json",
      "claims/004-claim-id-mismatch.json",
      "claims/005-persona-issuance-active.json",
      "claims/006-delegated-issuance-active.json",
      "claims/007-third-party-issuer-untrusted.json",
      "claims/008-chain-attenuation-valid.json",
      "claims/009-chain-widening-rejected.json",
      "claims/010-chain-depth-exceeded.json",
      "claims/011-subject-proof-valid.json",
      "claims/012-copied-proof-rejected.json",
      "claims/013-provisional-authorization-denied.json",
      "claims/014-repository-confirmed-active.json",
      "claims/015-authorization-self-revocation.json",
      "claims/016-descriptive-subject-rejection.json",
      "claims/017-public-claim-publication.json",
      "claims/018-pairwise-private-marmot-delivery.json",
      "claims/019-repository-private-encryption.json",
      "claims/020-local-only-no-publication.json",
    ]);
    expect(vectors.every(({ vector }) =>
      vector.owner_document === "comms" &&
      vector.owner_version === "comms/0.5.0" &&
      vector.registry_revision === 5 &&
      vector.dependency_versions.core === "core/0.5.0" &&
      vector.spec_refs.every((ref) => ref.startsWith("heterodyne:comms/0.5.0#")),
    )).toBe(true);

    const byId = new Map(vectors.map(({ vector }) => [vector.vector_id, vector]));
    const claimMutations = byId.get("claims/canonical-nostr-subject")!
      .input.rejection_mutations as Array<{ name: string; event: NostrSignedEvent; reason_code: string }>;
    expect(claimMutations.map(({ name }) => name)).toEqual([
      "extra-tag-after", "extra-tag-before", "duplicate-d", "malformed-d", "misordered-d",
      "missing-spec-version", "legacy-comms-version", "wrong-spec-version",
    ]);
    for (const mutation of claimMutations) {
      expect(verifyEventSignature(mutation.event)).toBe(true);
      expect(mutation.reason_code).toBe("claim-schema-invalid");
      expect(() => validateClaimEnvelope(mutation.event, {
        issuer_authorized: true,
        registry_revision: 2,
        credential_ledger: credentialLedger,
      })).toThrow(/claim-schema-invalid/);
    }
    const revocationMutations = byId.get("claims/authorization-self-revocation")!
      .input.rejection_mutations as Array<{ name: string; event: NostrSignedEvent; reason_code: string }>;
    expect(revocationMutations).toHaveLength(10);
    expect(revocationMutations.map(({ name }) => name)).toEqual([
      "revocation-extra-tag-after", "revocation-extra-tag-before", "revocation-duplicate-d",
      "revocation-malformed-d", "revocation-misordered-d", "missing-spec-version",
      "legacy-comms-version", "missing-registry-revision", "wrong-spec-version",
      "wrong-registry-revision",
    ]);
    const jwkMutations = byId.get("claims/canonical-jwk-thumbprint-subject")!
      .input.jwk_rejection_mutations as Array<{
        name: string;
        event: NostrSignedEvent;
        reason_code: string;
      }>;
    expect(jwkMutations.map(({ name }) => name)).toEqual([
      "missing-protected-alg",
      "extra-protected-member",
      "none-protected-alg",
      "hmac-protected-alg",
      "extra-jwk-member",
      "wrong-jwk-alg",
      "wrong-jwk-kid",
    ]);
    for (const mutation of jwkMutations) {
      expect(verifyEventSignature(mutation.event)).toBe(true);
      expect(() => validateClaimRevocationEnvelope(mutation.event)).toThrow();
      expect(["claim-schema-invalid", "claim-key-reference-invalid", "claim-subject-proof-invalid"])
        .toContain(mutation.reason_code);
    }
    for (const mutation of revocationMutations) {
      expect(verifyEventSignature(mutation.event)).toBe(true);
      expect(mutation.reason_code).toBe("claim-schema-invalid");
      expect(() => validateClaimRevocationEnvelope(mutation.event)).toThrow(/claim-schema-invalid/);
    }
    const pairwise = byId.get("claims/pairwise-private-marmot-delivery")!;
    const marmotGroup = pairwise.input.marmot_group as {
      member_accounts: string[];
      application_event: NostrSignedEvent;
      outer_kind: number;
      outer_claim_metadata_fields: string[];
    };
    expect(marmotGroup.member_accounts).toHaveLength(2);
    expect(marmotGroup.outer_kind).toBe(445);
    expect(marmotGroup.outer_claim_metadata_fields).toEqual([]);
    const carriedClaimEvent = JSON.parse(marmotGroup.application_event.content) as NostrSignedEvent;
    expect(carriedClaimEvent.kind).toBe(31013);
    expect(verifyEventSignature(carriedClaimEvent)).toBe(true);
    const repository = byId.get("claims/repository-private-encryption")!;
    const repositoryClaimId = (repository.expected_output.normalized as { inner_claim_id: string }).inner_claim_id;
    const repositoryMetadata = JSON.stringify({
      commit: repository.input.commit,
      tree: repository.input.tree,
      rid: repository.input.rid,
      branch: repository.input.branch,
    });
    expect(repositoryMetadata).not.toContain(repositoryClaimId);
    expect(repositoryMetadata).not.toContain("heterodyne.device");
    expect(repositoryMetadata).not.toContain("claim-ledger-reader");
    expect(JSON.stringify(repository.input.blobs)).not.toContain(repositoryClaimId);
    const encryptedBlob = Object.values(repository.input.blobs as Record<string, string>)[0];
    const repositoryEvent = JSON.parse(nip44.v2.decrypt(
      encryptedBlob,
      hexToBytes(repository.input.fixture_audience_key as string),
    )) as NostrSignedEvent;
    expect(repositoryEvent.kind).toBe(31013);
    expect(verifyEventSignature(repositoryEvent)).toBe(true);
    expect((byId.get("claims/local-only-no-publication")!.expected_output.normalized as { transport_artifacts: unknown[] }).transport_artifacts).toEqual([]);
    const localInput = byId.get("claims/local-only-no-publication")!.input;
    expect(localInput).not.toHaveProperty("valid_signed_event");
    expect(localInput).not.toHaveProperty("canonical_wire");
    expect((byId.get("claims/persona-issuance-active")!.input.vector_context as { decision_trace: string[] }).decision_trace).toHaveLength(8);
    const personaVector = byId.get("claims/persona-issuance-active")!;
    expect((personaVector.input.claim_authority_evidence as ClaimAuthorityEvidence[])[0].event_id)
      .toBe((personaVector.input.event as NostrSignedEvent).id);

    const cycleVector = byId.get("claims/chain-depth-exceeded")!;
    const cycleCase = (cycleVector.input.cases as Array<{
      name: string;
      leaf_claim_id: string;
      claims_by_id: Record<string, ClaimSemanticBody>;
    }>).find(({ name }) => name === "cycle")!;
    const cycleMap = new Map(Object.entries(cycleCase.claims_by_id));
    expect(() => verifyClaimChain(cycleMap.get(cycleCase.leaf_claim_id)!, cycleMap))
      .toThrow(/claim-chain-cycle/);

    const jwkRevocation = byId.get("claims/canonical-jwk-thumbprint-subject")!
      .input.positive_native_revocation_event as NostrSignedEvent;
    expect(validateClaimRevocationEnvelope(jwkRevocation).signer.type).toBe("jwk-thumbprint");
    const authorizationRoles = byId.get("claims/authorization-self-revocation")!
      .input.role_cases as Array<{
        role: string;
        event: NostrSignedEvent;
        authority_evidence: RevocationAuthorityEvidence | null;
        persona_cold_root: string | null;
        expected_authorized: boolean;
      }>;
    expect(authorizationRoles).toHaveLength(6);
    expect(authorizationRoles.filter(({ expected_authorized }) => expected_authorized)).toHaveLength(5);
    expect(authorizationRoles.every(({ event }) => validateClaimRevocationEnvelope(event).event_id === event.id)).toBe(true);
    const personaEpochRole = authorizationRoles.find(({ role }) => role === "persona-epoch")!;
    expect(personaEpochRole.event.pubkey).toBe(fixtures.personas.alice.epoch_keys.epoch_1.pubkey);
    expect(personaEpochRole.authority_evidence).toMatchObject({
      signer: { type: "nostr-secp256k1", value: fixtures.personas.alice.epoch_keys.epoch_1.pubkey },
      authority: "persona-epoch",
    });
    expect(personaEpochRole.persona_cold_root).toBe(fixtures.personas.alice.cold_root.pubkey);
    expect(new Map([
      ["claims/canonical-nostr-subject", "heterodyne-comms-key-claim-nostr-bip340-v1"],
      ["claims/canonical-radicle-nid-subject", "heterodyne-comms-key-claim-radicle-ed25519-v1"],
      ["claims/subject-proof-valid", "heterodyne-comms-key-claim-jwk-jws-v1"],
      ["claims/canonical-jwk-thumbprint-subject", "heterodyne-comms-claim-revocation-jwk-jws-v1"],
      ["claims/authorization-self-revocation", "heterodyne-comms-claim-revocation-nostr-bip340-v1"],
      ["claims/descriptive-subject-rejection", "heterodyne-comms-claim-revocation-radicle-ed25519-v1"],
    ])).toEqual(new Map(
      [...byId.values()].filter(({ profile }) => profile !== undefined).map(({ vector_id, profile }) => [vector_id, profile!]),
    ));
  });
});
