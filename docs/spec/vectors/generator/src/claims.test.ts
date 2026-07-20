import { createHash, generateKeyPairSync, sign as signNative } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import {
  authorizeWithClaim,
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
  type ClaimSemanticBody,
  type JsonValue,
  type KeyProof,
  type KeyRef,
  type SubjectProofChallenge,
  type VerifiedRevocation,
} from "./claims.js";
import { buildFixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { getEventId, signEvent, type NostrSignedEvent, type NostrUnsignedEvent } from "./nostr.js";
import { buildClaimVectors } from "./topics-claims.js";

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

  it("rejects noncanonical or non-SHA-256 JWK thumbprint references", () => {
    expect(() => validateKeyRef({ type: "jwk-thumbprint", value: `${"A".repeat(42)}B` })).toThrow(/thumbprint|base64url/);
    expect(() => validateKeyRef({ type: "jwk-thumbprint", value: "A".repeat(42) })).toThrow(/thumbprint|base64url/);
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

describe("closed NIP-01 claim and revocation event structure", () => {
  function signRaw(unsigned: NostrUnsignedEvent): NostrSignedEvent {
    const id = getEventId(unsigned);
    const sig = bytesToHex(schnorr.sign(id, hexToBytes(epoch.private_key), auxRand));
    return { ...unsigned, id, sig };
  }

  it("rejects malformed structure before cryptography for both allocated kinds", async () => {
    const claim = semanticBody();
    const revocation: ClaimRevocation = {
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
        validate: (event: NostrSignedEvent) => validateClaimEnvelope(event, { issuer_authorized: true, registry_revision: 2 }),
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

  function claim(overrides: Partial<Omit<ClaimSemanticBody, "claim_id">> = {}): ClaimSemanticBody {
    const bodyWithUndefined = {
      issuer: rootIssuer,
      subject,
      claim_class: "authorization",
      namespace: "heterodyne.device",
      name: "claim-ledger-reader",
      value: true,
      issued_at: issuedAt,
      not_before: issuedAt,
      expires_at: issuedAt + 600,
      audience: [fixtures.personas.alice.cold_root.pubkey, "https://rp.example"],
      resources: ["rad:claims", "rad:claims/device"],
      visibility: "repository-private",
      comms_version: "comms/0.5.0",
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

  function context(
    forClaim: ClaimSemanticBody,
    overrides: Partial<ClaimVerificationContext> = {},
  ): ClaimVerificationContext {
    const proofChallenge = challenge(forClaim);
    return {
      now: issuedAt + 20,
      audience: fixtures.personas.alice.cold_root.pubkey,
      resource: "rad:claims/device",
      trusted_issuers: [rootIssuer],
      repository_confirmed: new Set([forClaim.claim_id]),
      repository_conflicted: new Set(),
      revocations: [],
      subject_proof: { key: forClaim.subject, challenge: proofChallenge, proof: nostrProof(forClaim, proofChallenge) },
      ...overrides,
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
  });

  it("exposes all seven states while keeping trust as the final policy stage", () => {
    const active = claim();
    expect(resolveClaimState(active, [active], context(active))).toBe("active");
    expect(resolveClaimState(active, [active], context(active, { trusted_issuers: [] }))).toBe("untrusted");
    expect(resolveClaimState(active, [active], context(active, { repository_confirmed: new Set() }))).toBe("provisional");
    expect(resolveClaimState(active, [active], context(active, { now: active.expires_at! }))).toBe("expired");
    expect(resolveClaimState(active, [active], context(active, { repository_conflicted: new Set([active.claim_id]) }))).toBe("conflicted");
    const directRevocation: VerifiedRevocation = {
      claim_id: active.claim_id,
      revoked_at: issuedAt + 11,
      reason_code: "claim-revoked",
      revoker: rootIssuer,
      signer: rootIssuer,
      event_id: "44".repeat(32),
    };
    expect(resolveClaimState(active, [active], context(active, { revocations: [directRevocation] }))).toBe("revoked");
    const copied = context(active, { trusted_issuers: [] });
    copied.subject_proof = { ...copied.subject_proof!, challenge: { ...copied.subject_proof!.challenge, operation: "write" } };
    expect(resolveClaimState(active, [active], copied)).toBe("invalid");
    expect(authorizeWithClaim(active, [active], copied).reason_code).toBe("claim-subject-proof-invalid");
    const malformed = { ...active, claim_id: "00".repeat(32) };
    expect(authorizeWithClaim(malformed, [malformed], context(malformed, { trusted_issuers: [] })))
      .toEqual({ allowed: false, state: "invalid", reason_code: "claim-id-mismatch" });
  });

  it("recognizes each authorization revoker and applies reduction before repository finality", () => {
    const { root, child } = delegatedPair();
    const authorities = [child.issuer, root.issuer, child.subject];
    for (const [index, authority] of authorities.entries()) {
      const revocation: VerifiedRevocation = {
        claim_id: child.claim_id,
        revoked_at: issuedAt + 10,
        reason_code: "claim-revoked",
        revoker: authority,
        signer: authority,
        event_id: (50 + index).toString(16).padStart(64, "0"),
      };
      const decision = authorizeWithClaim(child, [root, child], context(child, {
        repository_confirmed: new Set(),
        revocations: [revocation],
      }));
      expect(decision).toEqual({ allowed: false, state: "revoked", reason_code: "claim-revoked" });
    }
    const outsider: KeyRef = {
      type: "nostr-secp256k1",
      value: fixtures.personas.bob.epoch_keys.epoch_1.pubkey,
    };
    const unauthorized: VerifiedRevocation = {
      claim_id: child.claim_id,
      revoked_at: issuedAt + 10,
      reason_code: "claim-revoked",
      revoker: outsider,
      signer: outsider,
      event_id: "59".repeat(32),
    };
    expect(authorizeWithClaim(child, [root, child], context(child, {
      revocations: [unauthorized],
    })).allowed).toBe(true);
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
      revokers: [namedRevoker],
    });
    for (const authority of [descriptive.issuer, descriptiveRoot.issuer, namedRevoker]) {
      const revocation: VerifiedRevocation = {
        claim_id: descriptive.claim_id,
        revoked_at: issuedAt + 10,
        reason_code: "claim-revoked",
        revoker: authority,
        signer: authority,
        event_id: "55".repeat(32),
      };
      expect(resolveClaimState(descriptive, [descriptiveRoot, descriptive], context(descriptive, {
        trusted_issuers: [descriptiveRoot.issuer],
        subject_proof: null,
        revocations: [revocation],
      }))).toBe("revoked");
    }
    const subjectRejection: VerifiedRevocation = {
      claim_id: descriptive.claim_id,
      revoked_at: issuedAt + 10,
      reason_code: "claim-revoked",
      revoker: descriptive.subject,
      signer: descriptive.subject,
      event_id: "56".repeat(32),
    };
    expect(resolveClaimState(descriptive, [descriptiveRoot, descriptive], context(descriptive, {
      trusted_issuers: [descriptiveRoot.issuer],
      subject_proof: null,
      revocations: [subjectRejection],
    }))).toBe("active");
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
  it("authors exactly the 20 named revision-2 Comms vectors with closed visibility carriers", async () => {
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
      "claims/018-pairwise-private-dr-delivery.json",
      "claims/019-repository-private-encryption.json",
      "claims/020-local-only-no-publication.json",
    ]);
    expect(vectors.every(({ vector }) =>
      vector.owner_document === "comms" &&
      vector.owner_version === "comms/0.5.0" &&
      vector.registry_revision === 2 &&
      vector.dependency_versions.core === "core/0.5.0" &&
      vector.spec_refs.every((ref) => ref.startsWith("heterodyne:comms/0.5.0#")),
    )).toBe(true);

    const byId = new Map(vectors.map(({ vector }) => [vector.vector_id, vector]));
    const pairwise = byId.get("claims/pairwise-private-dr-delivery")!;
    const pairwiseOuter = JSON.stringify(pairwise.input.outer);
    expect(pairwiseOuter).not.toContain("claim_id");
    expect(pairwiseOuter).not.toContain("heterodyne.device");
    const repository = byId.get("claims/repository-private-encryption")!;
    expect(JSON.stringify({
      path: repository.input.keyed_path,
      rid: repository.input.rid,
      branch: repository.input.branch,
    })).not.toContain((repository.expected_output.normalized as { inner_claim_id: string }).inner_claim_id);
    expect((byId.get("claims/local-only-no-publication")!.expected_output.normalized as { transport_artifacts: unknown[] }).transport_artifacts).toEqual([]);
    expect((byId.get("claims/persona-issuance-active")!.input.vector_context as { decision_trace: string[] }).decision_trace).toHaveLength(8);
  });
});
