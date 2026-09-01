import { createHash, generateKeyPairSync, sign as signNative } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import {
  authorizeWithClaim as authorizeVerifiedClaim,
  claimArtifactBindingDigest,
  claimRevocationArtifactBindingDigest,
  CLAIM_REVOCATION_OPERATION_BUDGET,
  CLAIM_REVOCATION_PROFILE,
  computeClaimId,
  computeJwkThumbprint,
  resolveClaimState as resolveVerifiedClaimState,
  revocationProofPayload,
  subjectProofPayload,
  validateClaimEnvelope,
  validateClaimId,
  validateClaimRevocationEnvelope,
  validateKeyRef,
  verifyClaimEnvelope,
  verifyClaimRevocationEnvelope,
  inspectVerifiedClaim,
  inspectVerifiedClaimRevocation,
  inspectClaimRevocationAuthorityEvaluation,
  isClaimRevocationAuthorized,
  verifyLedgerClaimArtifact,
  verifyLedgerClaimRevocationArtifact,
  verifyClaimChain as verifyVerifiedClaimChain,
  type ClaimVerificationContext,
  type ClaimRevocation,
  type ClaimSemanticBody,
  type JsonValue,
  type KeyProof,
  type KeyRef,
  type SubjectProofChallenge,
  type VerifiedClaimArtifact,
  type VerifiedClaimRevocationArtifact,
} from "./claims.js";
import { buildFixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { getEventId, signEvent, type NostrSignedEvent, type NostrUnsignedEvent } from "./nostr.js";

const fixtures = buildFixtures();
const epoch = fixtures.personas.alice.epoch_keys.epoch_1;
const device = fixtures.ed25519_nids.alice_device_1;
const auxRand = fixtures.pinned_randomness.schnorr_aux_rand;
const issuedAt = 1784390400;
const credentialLedger = {
  credential_ledger_persona: epoch.pubkey,
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
  audience: [epoch.pubkey],
  visibility: "repository-private" as const,
  spec_version: "heterodyne/0.6.0" as const,
  profile_revision: 2 as const,
});

function semanticBody(): ClaimSemanticBody {
  const body = semanticWithoutId();
  return { claim_id: computeClaimId(body), ...body };
}

function verificationContextForArtifact(body: ClaimSemanticBody): ClaimVerificationContext {
  return {
    now: body.not_before,
    audience: body.audience?.[0] ?? epoch.pubkey,
    resource: body.resources?.[0] ?? "rad:claims/device",
    requested_namespace: body.namespace,
    requested_operation: "read",
    expected_nonce: "ab".repeat(16),
    used_nonces: new Set(),
    trusted_issuers: [body.issuer],
    credential_ledger: credentialLedger,
    repository_confirmed: new Set([body.claim_id]),
    repository_conflicted: new Set(),
    revocations: [],
    subject_proof: null,
  };
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
    const artifact = validateClaimEnvelope(event, {
      profile_revision: 2,
      credential_ledger: credentialLedger,
    });
    expect(artifact).toEqual({});
    expect(inspectVerifiedClaim(artifact)).toEqual(body);
  });

  it("BLUE TEAM VALIDATION: synthetic/local keeps semantic issuance independent from the NIP-01 audit timestamp", async () => {
    // BLUE TEAM VALIDATION: synthetic/local timing fixture is deterministic and non-deployable.
    const body = semanticBody();
    const event = await signEvent({
      secretKey: epoch.private_key,
      auxRand,
      created_at: issuedAt + 37,
      kind: 31013,
      tags: addressTags(body.claim_id),
      content: jcsCanonicalize(body),
    });
    const artifact = verifyClaimEnvelope(event, {
      profile_revision: 2,
      credential_ledger: credentialLedger,
    });
    expect(inspectVerifiedClaim(artifact)).toEqual(body);
  });

  it("BLUE TEAM VALIDATION: synthetic/local mints only opaque exact claim artifacts", async () => {
    // BLUE TEAM VALIDATION: synthetic/local fixtures exercise no live target, account, or credential.
    const body = semanticBody();
    const event = await signEvent({
      secretKey: epoch.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: addressTags(body.claim_id),
      content: jcsCanonicalize(body),
    });
    const context = { profile_revision: 2 as const, credential_ledger: credentialLedger };
    const artifact = verifyClaimEnvelope(event, context);
    expect(artifact).toEqual({});
    expect(Object.isFrozen(artifact)).toBe(true);
    expect(claimArtifactBindingDigest(artifact)).toMatch(/^[0-9a-f]{64}$/);
    const first = inspectVerifiedClaim(artifact);
    const second = inspectVerifiedClaim(artifact);
    expect(first).toEqual(body);
    expect(second).toEqual(body);
    expect(first).not.toBe(second);
    expect(Object.isFrozen(first)).toBe(true);
    expect(verifyVerifiedClaimChain(artifact, new Map([[body.claim_id, artifact]]))).toEqual([artifact]);
    expect(() => verifyVerifiedClaimChain(
      first as unknown as VerifiedClaimArtifact,
      new Map([[body.claim_id, first as unknown as VerifiedClaimArtifact]]),
    )).toThrow(/verified claim artifact/i);

    const mutableSource = structuredClone(event);
    const snapshotArtifact = verifyClaimEnvelope(mutableSource, context);
    mutableSource.id = "00".repeat(32);
    mutableSource.content = "{}";
    expect(inspectVerifiedClaim(snapshotArtifact)).toEqual(body);

    const clone = structuredClone(artifact) as VerifiedClaimArtifact;
    expect(() => inspectVerifiedClaim(clone)).toThrow(/verified claim artifact/i);
    expect(() => claimArtifactBindingDigest(clone)).toThrow(/verified claim artifact/i);
    expect(() => verifyVerifiedClaimChain(clone, new Map([[body.claim_id, clone]])))
      .toThrow(/verified claim artifact/i);
    const secondArtifact = verifyClaimEnvelope(event, context);
    expect(claimArtifactBindingDigest(secondArtifact)).toBe(claimArtifactBindingDigest(artifact));
    expect(() => verifyVerifiedClaimChain(artifact, new Map([[body.claim_id, secondArtifact]])))
      .toThrow(/identity/i);

    expect(() => verifyClaimEnvelope(event, {
      ...context,
      issuer_authorized: true,
    })).toThrow(/closed verification context/i);
    expect(() => verifyClaimEnvelope(event, {
      ...context,
      envelope_valid: true,
    })).toThrow(/closed verification context/i);
    expect(() => verifyClaimEnvelope({ ...event, id: "00".repeat(32) }, context))
      .toThrow(/signature/i);
    expect(() => verifyClaimEnvelope({ ...event, content: `${event.content} ` }, context))
      .toThrow(/signature/i);

    let getterReads = 0;
    const accessor = { ...event } as NostrSignedEvent;
    Object.defineProperty(accessor, "content", {
      enumerable: true,
      get() {
        getterReads += 1;
        return event.content;
      },
    });
    expect(() => verifyClaimEnvelope(accessor, context)).toThrow(/signature/i);
    expect(getterReads).toBe(0);
    const proxy = new Proxy(event, {
      get() {
        throw new Error("synthetic/local proxy trap must not execute");
      },
    });
    expect(() => verifyClaimEnvelope(proxy, context)).toThrow(/signature/i);

    expect(() => verifyLedgerClaimArtifact({
      event,
      semantic: { ...body, value: false },
    }, context)).toThrow(/semantic does not equal signed event content/i);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects hostile claim maps and chain containers without invoking user code", async () => {
    // BLUE TEAM VALIDATION: synthetic/local containers contain no external target or reusable payload.
    const body = semanticBody();
    const event = await signEvent({
      secretKey: epoch.private_key,
      auxRand,
      created_at: issuedAt,
      kind: 31013,
      tags: addressTags(body.claim_id),
      content: jcsCanonicalize(body),
    });
    const artifact = verifyClaimEnvelope(event, {
      profile_revision: 2,
      credential_ledger: credentialLedger,
    });

    let iteratorCalls = 0;
    const hostileMap = new Map([[body.claim_id, artifact]]) as Map<string, VerifiedClaimArtifact> & {
      [Symbol.iterator]: () => IterableIterator<[string, VerifiedClaimArtifact]>;
    };
    Object.defineProperty(hostileMap, Symbol.iterator, {
      enumerable: false,
      value() {
        iteratorCalls += 1;
        return new Map([[body.claim_id, artifact]])[Symbol.iterator]();
      },
    });
    expect(() => verifyVerifiedClaimChain(artifact, hostileMap)).toThrow(/ordinary|artifact map/i);
    expect(iteratorCalls).toBe(0);

    let proxyCalls = 0;
    const proxyMap = new Proxy(new Map([[body.claim_id, artifact]]), {
      get() {
        proxyCalls += 1;
        throw new Error("synthetic/local map proxy trap must not execute");
      },
    });
    expect(() => verifyVerifiedClaimChain(artifact, proxyMap)).toThrow(/ordinary|artifact map/i);
    expect(proxyCalls).toBe(0);

    let subclassIteratorCalls = 0;
    class HostileMap extends Map<string, VerifiedClaimArtifact> {
      override [Symbol.iterator](): MapIterator<[string, VerifiedClaimArtifact]> {
        subclassIteratorCalls += 1;
        return super[Symbol.iterator]();
      }
    }
    expect(() => verifyVerifiedClaimChain(
      artifact,
      new HostileMap([[body.claim_id, artifact]]),
    )).toThrow(/ordinary|artifact map/i);
    expect(subclassIteratorCalls).toBe(0);

    const memberMap = new Map([[body.claim_id, artifact]]) as Map<string, VerifiedClaimArtifact> & {
      extra?: boolean;
    };
    memberMap.extra = true;
    expect(() => verifyVerifiedClaimChain(artifact, memberMap)).toThrow(/ordinary|artifact map/i);
    const oversizedMap = new Map<string, VerifiedClaimArtifact>();
    for (let index = 0; index < 257; index += 1) {
      oversizedMap.set(index.toString(16).padStart(64, "0"), artifact);
    }
    expect(() => verifyVerifiedClaimChain(artifact, oversizedMap)).toThrow(/oversized/i);
    const cyclicMap = new Map<string, VerifiedClaimArtifact>();
    cyclicMap.set(body.claim_id, cyclicMap as unknown as VerifiedClaimArtifact);
    expect(() => verifyVerifiedClaimChain(artifact, cyclicMap)).toThrow(/verified claim artifact/i);

    let chainReads = 0;
    const hostileChain = [artifact];
    Object.defineProperty(hostileChain, "0", {
      enumerable: true,
      get() {
        chainReads += 1;
        return artifact;
      },
    });
    const decision = authorizeVerifiedClaim(
      artifact,
      hostileChain,
      verificationContextForArtifact(body),
    );
    expect(decision).toMatchObject({ state: "invalid" });
    expect(chainReads).toBe(0);

    let subclassMapCalls = 0;
    class HostileChain extends Array<VerifiedClaimArtifact> {
      override map<U>(): U[] {
        subclassMapCalls += 1;
        throw new Error("synthetic/local chain map must not execute");
      }
    }
    const subclassChain = new HostileChain();
    subclassChain.push(artifact);
    expect(authorizeVerifiedClaim(
      artifact,
      subclassChain,
      verificationContextForArtifact(body),
    ).state).toBe("invalid");
    expect(subclassMapCalls).toBe(0);

    const symbolChain = [artifact] as VerifiedClaimArtifact[] & { [key: symbol]: boolean };
    symbolChain[Symbol("unexpected")] = true;
    expect(authorizeVerifiedClaim(artifact, symbolChain, verificationContextForArtifact(body)).state)
      .toBe("invalid");
    const memberChain = [artifact] as VerifiedClaimArtifact[] & { extra?: boolean };
    memberChain.extra = true;
    expect(authorizeVerifiedClaim(artifact, memberChain, verificationContextForArtifact(body)).state)
      .toBe("invalid");
    const cyclicChain: unknown[] = [];
    cyclicChain.push(cyclicChain);
    expect(authorizeVerifiedClaim(
      artifact,
      cyclicChain as VerifiedClaimArtifact[],
      verificationContextForArtifact(body),
    ).state).toBe("invalid");

    const sparse = new Array<VerifiedClaimArtifact>(1);
    expect(authorizeVerifiedClaim(artifact, sparse, verificationContextForArtifact(body)).state)
      .toBe("invalid");
    const oversized = Array.from({ length: 257 }, () => artifact);
    expect(authorizeVerifiedClaim(artifact, oversized, verificationContextForArtifact(body)).state)
      .toBe("invalid");
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
      profile_revision: 2, credential_ledger: credentialLedger,
    })).toThrow(/canonical/);
    expect(() => validateClaimEnvelope(duplicate, {
      profile_revision: 2, credential_ledger: credentialLedger,
    })).toThrow(/exactly.*d/i);
    const badSignature = `${valid.sig[0] === "0" ? "1" : "0"}${valid.sig.slice(1)}`;
    expect(() => validateClaimEnvelope({ ...valid, sig: badSignature }, {
      profile_revision: 2, credential_ledger: credentialLedger,
    })).toThrow(/signature/);
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
    expect(inspectVerifiedClaim(validateClaimEnvelope(event, {
      profile_revision: 2,
      credential_ledger: credentialLedger,
      existing_semantic_body: structuredClone(body),
    }))).toEqual(body);
    expect(() => validateClaimEnvelope(event, {
      profile_revision: 2,
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
      profile_revision: 2, credential_ledger: credentialLedger,
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
      profile_revision: 2, credential_ledger: credentialLedger,
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
      spec_version: "heterodyne/0.6.0",
      profile_revision: 2,
    } as unknown as ClaimRevocation;
    expect(new TextDecoder().decode(revocationProofPayload(stamped))).toBe(
      `heterodyne-claim-revocation-v1\u0000${jcsCanonicalize({
        claim_id: stamped.claim_id,
        profile_revision: 2,
        reason_code: stamped.reason_code,
        revoked_at: stamped.revoked_at,
        spec_version: "heterodyne/0.6.0",
      })}`,
    );
    const stampedEvent = await revocationEvent(stamped);
    expect(() => validateClaimRevocationEnvelope(stampedEvent)).not.toThrow();

    const { spec_version: _version, ...missingVersion } = stamped as ClaimRevocation & { spec_version: string };
    const { profile_revision: _revision, ...missingRevision } = stamped as ClaimRevocation & { profile_revision: number };
    const missingVersionEvent = await revocationEvent(missingVersion as ClaimRevocation);
    const missingRevisionEvent = await revocationEvent(missingRevision as ClaimRevocation);
    const wrongVersionEvent = await revocationEvent({ ...stamped, spec_version: "heterodyne/0.5.1" } as unknown as ClaimRevocation);
    const legacyVersionEvent = await revocationEvent({
      ...missingVersion,
      comms_version: "heterodyne/0.6.0",
    } as unknown as ClaimRevocation);
    const wrongRevisionEvent = await revocationEvent({ ...stamped, profile_revision: 1 } as unknown as ClaimRevocation);
    expect(() => validateClaimRevocationEnvelope(missingVersionEvent))
      .toThrow(/spec_version|required/);
    expect(() => validateClaimRevocationEnvelope(missingRevisionEvent))
      .toThrow(/profile_revision|required/);
    expect(() => validateClaimRevocationEnvelope(wrongVersionEvent)).toThrow(/spec_version|const/);
    expect(() => validateClaimRevocationEnvelope(legacyVersionEvent)).toThrow(/spec_version|required|additional/);
    expect(() => validateClaimRevocationEnvelope(wrongRevisionEvent)).toThrow(/profile_revision|const/);
  });

  it("requires exactly one ordered d=claim_id tag and rejects every re-signed alternative", async () => {
    const claim = semanticBody();
    const revocation = {
      claim_id: claim.claim_id,
      revoked_at: issuedAt + 9,
      reason_code: "claim-revoked",
      revoker: { type: "nostr-secp256k1", value: epoch.pubkey },
      spec_version: "heterodyne/0.6.0",
      profile_revision: 2,
    } as unknown as ClaimRevocation;
    const cases = [
      {
        kind: 31013,
        created_at: issuedAt,
        content: jcsCanonicalize(claim),
        validate: (event: NostrSignedEvent) => validateClaimEnvelope(event, {
          profile_revision: 2, credential_ledger: credentialLedger,
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
    expect(inspectVerifiedClaimRevocation(validateClaimRevocationEnvelope(event))).toEqual({
      ...revocation,
      signer: revocation.revoker,
      event_id: event.id,
      event_created_at: event.created_at,
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects revocation artifact lookalikes and wire mismatches", async () => {
    // BLUE TEAM VALIDATION: synthetic/local revocation fixtures are minimal and non-deployable.
    const semantic: ClaimRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: semanticBody().claim_id,
      revoked_at: issuedAt + 10,
      reason_code: "claim-revoked",
      revoker: { type: "nostr-secp256k1", value: epoch.pubkey },
    };
    const event = await revocationEvent(semantic);
    const artifact = verifyClaimRevocationEnvelope(event);
    expect(artifact).toEqual({});
    expect(Object.isFrozen(artifact)).toBe(true);
    const inspected = inspectVerifiedClaimRevocation(artifact);
    expect(inspected.claim_id).toBe(semantic.claim_id);
    expect(inspected.event_id).toBe(event.id);
    expect(Object.isFrozen(inspected)).toBe(true);
    const lookalike = structuredClone(artifact) as VerifiedClaimRevocationArtifact;
    expect(() => inspectVerifiedClaimRevocation(lookalike)).toThrow(/verified claim revocation artifact/i);
    expect(() => verifyLedgerClaimRevocationArtifact({
      event,
      semantic: { ...semantic, reason_code: "claim-expired" },
    })).toThrow(/semantic does not equal signed event content/i);
  });

  it("binds revocation semantic time exactly to the signed outer event", async () => {
    const revocation: ClaimRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: semanticBody().claim_id,
      revoked_at: issuedAt + 11,
      reason_code: "claim-revoked",
      revoker: { type: "nostr-secp256k1", value: epoch.pubkey },
    };
    expect(inspectVerifiedClaimRevocation(
      validateClaimRevocationEnvelope(await revocationEvent(revocation)),
    ).event_created_at)
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
    const signature = bytesToHex(ed25519.sign(revocationProofPayload(unsigned), hexToBytes(device.private_key)));
    const revocation: ClaimRevocation = {
      ...unsigned,
      revoker: { type: "radicle-ed25519-nid", value: device.did_key },
      proof: { type: "radicle-ed25519", public_key: device.public_key, signature },
    };
    const event = await revocationEvent(revocation);
    expect(inspectVerifiedClaimRevocation(validateClaimRevocationEnvelope(event)).signer)
      .toEqual(revocation.revoker);
    const wrongNid = { ...revocation, revoker: { type: "radicle-ed25519-nid" as const, value: fixtures.ed25519_nids.alice_device_2.did_key } };
    const wrongNidEvent = await revocationEvent(wrongNid);
    expect(() => validateClaimRevocationEnvelope(wrongNidEvent)).toThrow(/NID/);
  });

  it("BLUE TEAM VALIDATION: synthetic/local — verifies a detached JWS proof and RFC 7638 thumbprint", async () => {
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
    const signingInput = `${protectedHeader}.${Buffer.from(revocationProofPayload(unsigned)).toString("base64url")}`;
    const signature = Buffer.from(ed25519.sign(utf8Bytes(signingInput), hexToBytes(device.private_key))).toString("base64url");
    const revocation: ClaimRevocation = {
      ...unsigned,
      revoker: { type: "jwk-thumbprint", value: thumbprint },
      proof: { type: "jwk-jws", jwk, protected: protectedHeader, signature },
    };
    const event = await revocationEvent(revocation);
    expect(inspectVerifiedClaimRevocation(validateClaimRevocationEnvelope(event)).signer)
      .toEqual(revocation.revoker);
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
        `${protectedHeader}.${Buffer.from(revocationProofPayload(unsigned)).toString("base64url")}`,
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
      expect(inspectVerifiedClaimRevocation(
        validateClaimRevocationEnvelope(await revocationEvent(revocation)),
      ).signer).toEqual(revocation.revoker);
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
          profile_revision: 2, credential_ledger: credentialLedger,
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
  const issuerSecrets = new Map<string, string>([
    [epoch.pubkey, epoch.private_key],
    [fixtures.device_publishing_keys.alice_device_1.pubkey,
      fixtures.device_publishing_keys.alice_device_1.private_key],
    [fixtures.device_publishing_keys.alice_device_2.pubkey,
      fixtures.device_publishing_keys.alice_device_2.private_key],
    [fixtures.personas.bob.epoch_keys.epoch_1.pubkey,
      fixtures.personas.bob.epoch_keys.epoch_1.private_key],
    [fixtures.personas.carol.epoch_keys.epoch_1.pubkey,
      fixtures.personas.carol.epoch_keys.epoch_1.private_key],
  ]);
  const artifactsBySemantic = new WeakMap<ClaimSemanticBody, VerifiedClaimArtifact>();
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
      audience: [epoch.pubkey, "https://rp.example"],
      resources: ["rad:claims", "rad:claims/device"],
      visibility: "repository-private",
      spec_version: "heterodyne/0.6.0",
      profile_revision: 2,
      ...overrides,
    };
    delete (bodyWithUndefined as Partial<ClaimSemanticBody>).claim_id;
    const body = Object.fromEntries(
      Object.entries(bodyWithUndefined).filter(([, value]) => value !== undefined),
    ) as Omit<ClaimSemanticBody, "claim_id">;
    const semantic = { claim_id: computeClaimId(body), ...body };
    if (semantic.issuer.type !== "nostr-secp256k1") {
      throw new Error("synthetic claim issuer must be Nostr");
    }
    const secretKey = issuerSecrets.get(semantic.issuer.value);
    if (secretKey === undefined) throw new Error("synthetic claim issuer key missing");
    const unsigned: NostrUnsignedEvent = {
      pubkey: semantic.issuer.value,
      created_at: semantic.issued_at,
      kind: 31013,
      tags: addressTags(semantic.claim_id),
      content: jcsCanonicalize(semantic),
    };
    const id = getEventId(unsigned);
    const event: NostrSignedEvent = {
      ...unsigned,
      id,
      sig: bytesToHex(schnorr.sign(id, hexToBytes(secretKey), auxRand)),
    };
    const artifact = verifyClaimEnvelope(event, {
      profile_revision: 2,
      credential_ledger: credentialLedger,
    });
    const inspected = inspectVerifiedClaim(artifact);
    artifactsBySemantic.set(inspected, artifact);
    return inspected;
  }

  function artifactFor(semantic: ClaimSemanticBody): VerifiedClaimArtifact {
    const artifact = artifactsBySemantic.get(semantic);
    if (artifact === undefined) throw new Error("claim-issuer-authority-invalid: verified claim artifact required");
    return artifact;
  }

  function verifyClaimChain(
    leaf: ClaimSemanticBody,
    claimsById: ReadonlyMap<string, ClaimSemanticBody>,
  ): ClaimSemanticBody[] {
    const artifacts = new Map<string, VerifiedClaimArtifact>();
    for (const [claimId, semantic] of claimsById) artifacts.set(claimId, artifactFor(semantic));
    return verifyVerifiedClaimChain(artifactFor(leaf), artifacts).map(inspectVerifiedClaim);
  }

  function resolveClaimState(
    leaf: ClaimSemanticBody,
    chain: readonly ClaimSemanticBody[],
    verification: ClaimVerificationContext,
  ) {
    return resolveVerifiedClaimState(artifactFor(leaf), chain.map(artifactFor), verification);
  }

  function authorizeWithClaim(
    leaf: ClaimSemanticBody,
    chain: readonly ClaimSemanticBody[],
    verification: ClaimVerificationContext,
  ) {
    return authorizeVerifiedClaim(artifactFor(leaf), chain.map(artifactFor), verification);
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
      audience: epoch.pubkey,
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
      signature: bytesToHex(schnorr.sign(subjectProofPayload(proofChallenge), hexToBytes(fixtures.device_publishing_keys.alice_device_2.private_key), auxRand)),
    };
  }

  function context(
    forClaim: ClaimSemanticBody,
    overrides: Partial<ClaimVerificationContext> = {},
  ): ClaimVerificationContext {
    const proofChallenge = challenge(forClaim);
    return {
      now: issuedAt + 20,
      audience: epoch.pubkey,
      resource: "rad:claims/device",
      requested_namespace: forClaim.namespace,
      requested_operation: "read",
      expected_nonce: proofChallenge.nonce,
      used_nonces: new Set(),
      trusted_issuers: [rootIssuer],
      repository_confirmed: new Set([forClaim.claim_id]),
      repository_conflicted: new Set(),
      revocations: [],
      subject_proof: { key: forClaim.subject, challenge: proofChallenge, proof: nostrProof(forClaim, proofChallenge) },
      ...overrides,
      credential_ledger: overrides.credential_ledger ?? credentialLedger,
    };
  }

  function nostrRevocation(
    target: ClaimSemanticBody,
    revoker: KeyRef,
    revokedAt = issuedAt + 10,
  ): VerifiedClaimRevocationArtifact {
    if (revoker.type !== "nostr-secp256k1") throw new Error("synthetic Nostr revoker required");
    const secretKey = issuerSecrets.get(revoker.value);
    if (secretKey === undefined) throw new Error("synthetic revoker key missing");
    const semantic: ClaimRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: target.claim_id,
      revoked_at: revokedAt,
      reason_code: "claim-revoked",
      revoker,
    };
    const unsigned: NostrUnsignedEvent = {
      pubkey: revoker.value,
      created_at: revokedAt,
      kind: 31014,
      tags: addressTags(target.claim_id),
      content: jcsCanonicalize(semantic),
    };
    const id = getEventId(unsigned);
    return verifyClaimRevocationEnvelope({
      ...unsigned,
      id,
      sig: bytesToHex(schnorr.sign(id, hexToBytes(secretKey), auxRand)),
    });
  }

  function delegatedPair(): { root: ClaimSemanticBody; child: ClaimSemanticBody } {
    const root = claim({
      subject: delegatedIssuer,
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [epoch.pubkey, "https://rp.example"],
        resources: ["rad:claims", "rad:claims/device"],
        remaining_depth: 2,
      },
    });
    const child = claim({
      issuer: delegatedIssuer,
      parent_claim_id: root.claim_id,
      audience: [epoch.pubkey],
      resources: ["rad:claims/device"],
      not_before: issuedAt + 1,
      expires_at: issuedAt + 300,
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [epoch.pubkey],
        resources: ["rad:claims/device"],
        remaining_depth: 1,
      },
    });
    return { root, child };
  }

  function delegatedContext(root: ClaimSemanticBody, child: ClaimSemanticBody): ClaimVerificationContext {
    return context(child, {
      repository_confirmed: new Set([root.claim_id, child.claim_id]),
    });
  }

  it("BLUE TEAM VALIDATION: synthetic/local rejects bare semantic and shaped public authority evidence", () => {
    // BLUE TEAM VALIDATION: synthetic/local objects exercise only this local verifier boundary.
    const formerPublicReturn = claim();
    const formerContext = context(formerPublicReturn);
    expect(authorizeVerifiedClaim(
      formerPublicReturn as unknown as VerifiedClaimArtifact,
      [formerPublicReturn as unknown as VerifiedClaimArtifact],
      formerContext,
    )).toEqual({
      allowed: false,
      state: "invalid",
      reason_code: "claim-issuer-authority-invalid",
    });
    const revocationArtifact = nostrRevocation(formerPublicReturn, formerPublicReturn.issuer);
    expect(claimRevocationArtifactBindingDigest(revocationArtifact)).toMatch(/^[0-9a-f]{64}$/);
    const formerRevocation = inspectVerifiedClaimRevocation(revocationArtifact);
    expect(authorizeVerifiedClaim(artifactFor(formerPublicReturn), [artifactFor(formerPublicReturn)], context(formerPublicReturn, {
      revocations: [formerRevocation as unknown as VerifiedClaimRevocationArtifact],
    })).state).not.toBe("revoked");

    const bare = structuredClone(formerPublicReturn);
    const shaped = context(bare);
    expect(() => verifyClaimChain(
      bare,
      new Map([[bare.claim_id, bare]]),
    )).toThrow(/verified claim artifact/i);
    expect(authorizeVerifiedClaim(
      bare as unknown as VerifiedClaimArtifact,
      [bare as unknown as VerifiedClaimArtifact],
      shaped,
    )).toEqual({
      allowed: false,
      state: "invalid",
      reason_code: "claim-issuer-authority-invalid",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects hostile revocation containers without invoking user code", () => {
    // BLUE TEAM VALIDATION: synthetic/local container has no live target, credential, or external effect.
    const active = claim();
    const revocation = nostrRevocation(active, active.issuer);
    let trapCalls = 0;
    const hostile = new Proxy([revocation], {
      get() {
        trapCalls += 1;
        throw new Error("synthetic/local revocation trap must not execute");
      },
    });
    expect(authorizeVerifiedClaim(
      artifactFor(active),
      [artifactFor(active)],
      context(active, { revocations: hostile }),
    )).toMatchObject({ allowed: false, state: "invalid" });
    expect(trapCalls).toBe(0);

    let accessorReads = 0;
    const accessor = [revocation];
    Object.defineProperty(accessor, "0", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return revocation;
      },
    });
    expect(authorizeVerifiedClaim(
      artifactFor(active),
      [artifactFor(active)],
      context(active, { revocations: accessor }),
    ).state).toBe("invalid");
    expect(accessorReads).toBe(0);

    const sparse = new Array<VerifiedClaimRevocationArtifact>(1);
    const oversized = Array.from({ length: 257 }, () => revocation);
    const cyclic: unknown[] = [];
    cyclic.push(cyclic);
    for (const revocations of [sparse, oversized, cyclic]) {
      expect(authorizeVerifiedClaim(
        artifactFor(active),
        [artifactFor(active)],
        context(active, { revocations }),
      ).state).toBe("invalid");
    }
  });

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
      .toThrow(/verified claim artifact/);
  });

  it("requires current verifier-minted artifact identity before policy", () => {
    const active = claim();
    const valid = context(active, { trusted_issuers: [] });
    expect(authorizeWithClaim(active, [active], valid)).toEqual({
      allowed: false,
      state: "untrusted",
      reason_code: "claim-issuer-untrusted",
    });
    const clone = structuredClone(active);
    expect(authorizeVerifiedClaim(
      clone as unknown as VerifiedClaimArtifact,
      [clone as unknown as VerifiedClaimArtifact],
      valid,
    )).toEqual({
      allowed: false,
      state: "invalid",
      reason_code: "claim-issuer-authority-invalid",
    });
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
    expect(authorizeWithClaim(active, [active], callerState).state).toBe("active");
    callerState.used_nonces.add(callerState.expected_nonce);
    expect(authorizeWithClaim(active, [active], callerState).reason_code).toBe("claim-subject-proof-invalid");
  });

  it("enforces the eight-edge limit and explicit depth decrement", () => {
    const chain: ClaimSemanticBody[] = [];
    let parent = claim({
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [epoch.pubkey],
        resources: ["rad:claims/device"],
        remaining_depth: 8,
      },
    });
    chain.push(parent);
    for (let edge = 1; edge <= 9; edge += 1) {
      const childSecret = (20 + edge).toString(16).padStart(64, "0");
      const childPublic = bytesToHex(schnorr.getPublicKey(childSecret));
      const child = claim({
        issuer: parent.subject,
        subject: {
          type: "nostr-secp256k1",
          value: childPublic,
        },
        parent_claim_id: parent.claim_id,
        not_before: issuedAt + edge,
        expires_at: issuedAt + 600 - edge,
        audience: [epoch.pubkey],
        resources: ["rad:claims/device"],
        constraints: {
          namespaces: ["heterodyne.device"],
          audiences: [epoch.pubkey],
          resources: ["rad:claims/device"],
          remaining_depth: Math.max(0, 8 - edge),
        },
      });
      chain.push(child);
      issuerSecrets.set(childPublic, childSecret);
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
      reissue(child, { expires_at: issuedAt + 601, parent_claim_id: root.claim_id }),
      reissue(child, { constraints: { ...child.constraints!, remaining_depth: 2 }, parent_claim_id: root.claim_id }),
    ];
    for (const invalid of invalidChildren) {
      expect(() => verifyClaimChain(invalid, new Map([[root.claim_id, root], [invalid.claim_id, invalid]])))
        .toThrow(/claim-(delegation-not-authorized|attenuation-violation)/);
    }
    expect(() => reissue(child, {
      not_before: issuedAt - 1,
      parent_claim_id: root.claim_id,
    })).toThrow(/not_before/);
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
    }))).toBe("expired");
    expect(resolveClaimState(active, [active], context(active, { repository_conflicted: new Set([active.claim_id]) }))).toBe("conflicted");
    const directRevocation = nostrRevocation(active, rootIssuer, issuedAt + 11);
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
    expect(authorizeVerifiedClaim(
      malformed as unknown as VerifiedClaimArtifact,
      [malformed as unknown as VerifiedClaimArtifact],
      context(malformed, { trusted_issuers: [] }),
    ))
      .toEqual({ allowed: false, state: "invalid", reason_code: "claim-issuer-authority-invalid" });
  });

  it("requires every authorization ancestor to remain confirmed and uncompromised", () => {
    const { root, child } = delegatedPair();
    const valid = delegatedContext(root, child);
    expect(authorizeWithClaim(child, [root, child], valid).state).toBe("active");
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

    const ancestorRevocation = nostrRevocation(root, root.issuer);
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
    for (const authority of authorities) {
      const revocation = nostrRevocation(child, authority);
      const base = delegatedContext(root, child);
      const decision = authorizeWithClaim(child, [root, child], {
        ...base,
        repository_confirmed: new Set(),
        revocations: [revocation],
      });
      expect(decision).toEqual({ allowed: false, state: "revoked", reason_code: "claim-revoked" });
    }
    const outsider: KeyRef = {
      type: "nostr-secp256k1",
      value: fixtures.personas.bob.epoch_keys.epoch_1.pubkey,
    };
    const unauthorized = nostrRevocation(child, outsider);
    expect(authorizeWithClaim(child, [root, child], {
      ...delegatedContext(root, child),
      revocations: [unauthorized],
    }).state).toBe("active");
  });

  it("BLUE TEAM VALIDATION: synthetic/local requires superior revoker authority to be active at revoked_at", () => {
    // BLUE TEAM VALIDATION: synthetic/local time windows are deterministic and non-deployable.
    const threeLevelChain = (
      middleOverrides: Partial<Omit<ClaimSemanticBody, "claim_id">> = {},
    ) => {
      const root = claim({
        subject: delegatedIssuer,
        constraints: {
          namespaces: ["heterodyne.device"],
          audiences: [epoch.pubkey, "https://rp.example"],
          resources: ["rad:claims", "rad:claims/device"],
          remaining_depth: 2,
        },
      });
      const middle = claim({
        issuer: delegatedIssuer,
        subject,
        parent_claim_id: root.claim_id,
        not_before: issuedAt + 1,
        expires_at: issuedAt + 400,
        audience: [epoch.pubkey],
        resources: ["rad:claims/device"],
        constraints: {
          namespaces: ["heterodyne.device"],
          audiences: [epoch.pubkey],
          resources: ["rad:claims/device"],
          remaining_depth: 1,
        },
        ...middleOverrides,
      });
      const leaf = claim({
        issuer: subject,
        parent_claim_id: middle.claim_id,
        not_before: middle.not_before,
        expires_at: middle.expires_at,
        audience: [epoch.pubkey],
        resources: ["rad:claims/device"],
      });
      return { root, middle, leaf };
    };

    const future = threeLevelChain({ not_before: issuedAt + 20 });
    const early = nostrRevocation(future.leaf, future.middle.issuer, issuedAt + 19);
    expect(isClaimRevocationAuthorized(
      artifactFor(future.leaf),
      [artifactFor(future.root), artifactFor(future.middle), artifactFor(future.leaf)],
      early,
      context(future.leaf, {
      now: issuedAt + 30,
      repository_confirmed: new Set([future.root.claim_id, future.middle.claim_id, future.leaf.claim_id]),
      }),
    )).toBe(false);

    const expired = threeLevelChain({
      expires_at: issuedAt + 20,
    });
    const atExpiry = nostrRevocation(expired.leaf, expired.middle.issuer, issuedAt + 20);
    expect(isClaimRevocationAuthorized(
      artifactFor(expired.leaf),
      [artifactFor(expired.root), artifactFor(expired.middle), artifactFor(expired.leaf)],
      atExpiry,
      context(expired.leaf, {
        now: issuedAt + 30,
        repository_confirmed: new Set([expired.root.claim_id, expired.middle.claim_id, expired.leaf.claim_id]),
      }),
    )).toBe(false);

    const revoked = threeLevelChain();
    const middleRevokedFirst = nostrRevocation(revoked.middle, revoked.middle.issuer, issuedAt + 9);
    const leafRevokedLater = nostrRevocation(revoked.leaf, revoked.middle.issuer, issuedAt + 10);
    expect(isClaimRevocationAuthorized(
      artifactFor(revoked.leaf),
      [artifactFor(revoked.root), artifactFor(revoked.middle), artifactFor(revoked.leaf)],
      leafRevokedLater,
      context(revoked.leaf, {
        repository_confirmed: new Set([revoked.root.claim_id, revoked.middle.claim_id, revoked.leaf.claim_id]),
        revocations: [middleRevokedFirst],
      }),
    )).toBe(false);

    const boundaryChain = threeLevelChain({
      not_before: issuedAt + 10,
    });
    const boundary = nostrRevocation(boundaryChain.leaf, boundaryChain.middle.issuer, issuedAt + 10);
    expect(isClaimRevocationAuthorized(
      artifactFor(boundaryChain.leaf),
      [artifactFor(boundaryChain.root), artifactFor(boundaryChain.middle), artifactFor(boundaryChain.leaf)],
      boundary,
      context(boundaryChain.leaf, {
        repository_confirmed: new Set([
          boundaryChain.root.claim_id,
          boundaryChain.middle.claim_id,
          boundaryChain.leaf.claim_id,
        ]),
      }),
    )).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects duplicate revocation event identities", () => {
    // BLUE TEAM VALIDATION: synthetic/local duplicates are deterministic, non-deployable signed fixtures.
    const active = claim();
    const first = nostrRevocation(active, active.issuer, issuedAt + 11);
    const duplicate = nostrRevocation(active, active.issuer, issuedAt + 11);
    expect(first).not.toBe(duplicate);
    expect(inspectVerifiedClaimRevocation(first).event_id)
      .toBe(inspectVerifiedClaimRevocation(duplicate).event_id);
    expect(resolveVerifiedClaimState(
      artifactFor(active),
      [artifactFor(active)],
      context(active, { revocations: [first, duplicate] }),
    )).toBe("invalid");
    expect(isClaimRevocationAuthorized(
      artifactFor(active),
      [artifactFor(active)],
      duplicate,
      context(active, { revocations: [first] }),
    )).toBe(false);
  });

  it("BLUE TEAM VALIDATION: synthetic/local revocation disables the full delegated superior prefix", () => {
    // BLUE TEAM VALIDATION: synthetic/local chronology is deterministic, bounded, and non-deployable.
    const root = claim({
      subject: delegatedIssuer,
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [epoch.pubkey, "https://rp.example"],
        resources: ["rad:claims", "rad:claims/device"],
        remaining_depth: 2,
      },
    });
    const middle = claim({
      issuer: delegatedIssuer,
      subject,
      parent_claim_id: root.claim_id,
      not_before: issuedAt + 1,
      expires_at: issuedAt + 400,
      audience: [epoch.pubkey],
      resources: ["rad:claims/device"],
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [epoch.pubkey],
        resources: ["rad:claims/device"],
        remaining_depth: 1,
      },
    });
    const leaf = claim({
      issuer: subject,
      parent_claim_id: middle.claim_id,
      not_before: issuedAt + 2,
      expires_at: issuedAt + 300,
      audience: [epoch.pubkey],
      resources: ["rad:claims/device"],
    });
    const chain = [artifactFor(root), artifactFor(middle), artifactFor(leaf)];
    const confirmed = new Set([root.claim_id, middle.claim_id, leaf.claim_id]);
    const rootRevokedAtNine = nostrRevocation(root, root.issuer, issuedAt + 9);
    const leafCandidateAtTen = nostrRevocation(leaf, root.subject, issuedAt + 10);

    expect(inspectClaimRevocationAuthorityEvaluation(
      artifactFor(leaf),
      chain,
      leafCandidateAtTen,
      context(leaf, {
        now: issuedAt + 10,
        repository_confirmed: confirmed,
        revocations: [rootRevokedAtNine],
      }),
    )).toMatchObject({ authorized: false, rejected: false });
    expect(resolveVerifiedClaimState(
      artifactFor(leaf),
      chain,
      context(leaf, {
        now: issuedAt + 10,
        repository_confirmed: confirmed,
        revocations: [rootRevokedAtNine, leafCandidateAtTen],
      }),
    )).toBe("revoked");

    expect(isClaimRevocationAuthorized(
      artifactFor(leaf),
      chain,
      leafCandidateAtTen,
      context(leaf, {
        now: issuedAt + 10,
        repository_confirmed: confirmed,
        revocations: [],
      }),
    )).toBe(true);
    expect(isClaimRevocationAuthorized(
      artifactFor(leaf),
      chain,
      leafCandidateAtTen,
      context(leaf, {
        now: issuedAt + 9,
        repository_confirmed: confirmed,
        revocations: [],
      }),
    )).toBe(false);
  });

  it("BLUE TEAM VALIDATION: synthetic/local bounds branching inactive superior revocation work", () => {
    // BLUE TEAM VALIDATION: synthetic/local matrix is bounded, deterministic, and has no external target.
    const root = claim({
      subject: delegatedIssuer,
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [epoch.pubkey, "https://rp.example"],
        resources: ["rad:claims", "rad:claims/device"],
        remaining_depth: 2,
      },
    });
    const middle = claim({
      issuer: delegatedIssuer,
      subject,
      parent_claim_id: root.claim_id,
      not_before: issuedAt + 200,
      expires_at: issuedAt + 400,
      audience: [epoch.pubkey],
      resources: ["rad:claims/device"],
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [epoch.pubkey],
        resources: ["rad:claims/device"],
        remaining_depth: 1,
      },
    });
    const leaf = claim({
      issuer: subject,
      parent_claim_id: middle.claim_id,
      not_before: middle.not_before,
      expires_at: middle.expires_at,
      audience: [epoch.pubkey],
      resources: ["rad:claims/device"],
    });
    const inactiveCandidates = Array.from({ length: 128 }, (_, index) =>
      nostrRevocation(leaf, middle.issuer, issuedAt + index + 1));
    const boundary = nostrRevocation(leaf, middle.issuer, middle.not_before);
    const chain = [artifactFor(root), artifactFor(middle), artifactFor(leaf)];
    const result = inspectClaimRevocationAuthorityEvaluation(
      artifactFor(leaf),
      chain,
      boundary,
      context(leaf, {
        now: issuedAt + 300,
        repository_confirmed: new Set([root.claim_id, middle.claim_id, leaf.claim_id]),
        revocations: inactiveCandidates,
      }),
    );
    expect(result).toMatchObject({ authorized: true, rejected: false });
    expect(result.operation_budget).toBe(CLAIM_REVOCATION_OPERATION_BUDGET);
    expect(result.operations).toBeLessThanOrEqual(CLAIM_REVOCATION_OPERATION_BUDGET);
  });

  it("BLUE TEAM VALIDATION: synthetic/local snapshots closed revocation authority context without traps", () => {
    // BLUE TEAM VALIDATION: synthetic/local hostile containers never contact live accounts or systems.
    const active = claim();
    const candidate = nostrRevocation(active, active.issuer, issuedAt + 11);
    const valid = context(active);
    expect(isClaimRevocationAuthorized(
      artifactFor(active), [artifactFor(active)], candidate, valid,
    )).toBe(true);

    let nowReads = 0;
    const accessorContext = { ...valid };
    Object.defineProperty(accessorContext, "now", {
      enumerable: true,
      get() {
        nowReads += 1;
        return valid.now;
      },
    });
    expect(isClaimRevocationAuthorized(
      artifactFor(active), [artifactFor(active)], candidate, accessorContext,
    )).toBe(false);
    expect(nowReads).toBe(0);

    let hasCalls = 0;
    const hostileConfirmed = new Set([active.claim_id]) as Set<string> & { has: (value: string) => boolean };
    Object.defineProperty(hostileConfirmed, "has", {
      enumerable: true,
      value(value: string) {
        hasCalls += 1;
        return Set.prototype.has.call(hostileConfirmed, value);
      },
    });
    expect(isClaimRevocationAuthorized(
      artifactFor(active), [artifactFor(active)], candidate,
      { ...valid, repository_confirmed: hostileConfirmed },
    )).toBe(false);
    expect(hasCalls).toBe(0);

    let nestedTrapCalls = 0;
    const hostileLedger = new Proxy(valid.credential_ledger, {
      get() {
        nestedTrapCalls += 1;
        throw new Error("synthetic/local nested context trap must not execute");
      },
    });
    expect(isClaimRevocationAuthorized(
      artifactFor(active), [artifactFor(active)], candidate,
      { ...valid, credential_ledger: hostileLedger },
    )).toBe(false);
    expect(nestedTrapCalls).toBe(0);

    let rootTrapCalls = 0;
    const proxyContext = new Proxy(valid, {
      get() {
        rootTrapCalls += 1;
        throw new Error("synthetic/local root context trap must not execute");
      },
    });
    expect(isClaimRevocationAuthorized(
      artifactFor(active), [artifactFor(active)], candidate, proxyContext,
    )).toBe(false);
    expect(rootTrapCalls).toBe(0);

    let issuerReads = 0;
    const mutatingIssuer = { type: active.issuer.type } as KeyRef;
    Object.defineProperty(mutatingIssuer, "value", {
      enumerable: true,
      get() {
        issuerReads += 1;
        return active.issuer.value;
      },
    });
    expect(isClaimRevocationAuthorized(
      artifactFor(active), [artifactFor(active)], candidate,
      { ...valid, trusted_issuers: [mutatingIssuer] },
    )).toBe(false);
    expect(issuerReads).toBe(0);

    const extra = { ...valid, unexpected: true };
    expect(isClaimRevocationAuthorized(
      artifactFor(active), [artifactFor(active)], candidate, extra,
    )).toBe(false);
    const symbol = { ...valid } as ClaimVerificationContext & { [key: symbol]: boolean };
    symbol[Symbol("synthetic/local unexpected")] = true;
    expect(isClaimRevocationAuthorized(
      artifactFor(active), [artifactFor(active)], candidate, symbol,
    )).toBe(false);
  });

  it("limits descriptive revocation to issuer, named revoker, or superior issuer", () => {
    const namedRevoker: KeyRef = {
      type: "nostr-secp256k1",
      value: fixtures.personas.bob.epoch_keys.epoch_1.pubkey,
    };
    const descriptiveRoot = claim({
      subject: delegatedIssuer,
      revokers: [namedRevoker],
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [epoch.pubkey, "https://rp.example"],
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
      const revocation = nostrRevocation(descriptive, authority);
      expect(resolveClaimState(descriptive, [descriptiveRoot, descriptive], context(descriptive, {
        trusted_issuers: [descriptiveRoot.issuer],
        subject_proof: null,
        repository_confirmed: new Set([descriptiveRoot.claim_id, descriptive.claim_id]),
        revocations: [revocation],
      }))).toBe("revoked");
    }
    const subjectRejection = nostrRevocation(descriptive, descriptive.subject);
    expect(resolveClaimState(descriptive, [descriptiveRoot, descriptive], context(descriptive, {
      trusted_issuers: [descriptiveRoot.issuer],
      repository_confirmed: new Set([descriptiveRoot.claim_id, descriptive.claim_id]),
      subject_proof: null,
      revocations: [subjectRejection],
    }))).toBe("active");
  });

  it("accepts only revocation-event-bound active persona authority", () => {
    const active = claim({ issuer: delegatedIssuer });
    const activePersona: KeyRef = {
      type: "nostr-secp256k1",
      value: epoch.pubkey,
    };
    const revocation = nostrRevocation(active, activePersona);
    expect(authorizeWithClaim(active, [active], context(active, {
      repository_confirmed: new Set(),
      revocations: [revocation],
    }))).toEqual({ allowed: false, state: "revoked", reason_code: "claim-revoked" });

    const backdatedRevocation = structuredClone(revocation);
    expect(authorizeWithClaim(active, [active], context(active, {
      revocations: [backdatedRevocation],
    })).state).not.toBe("revoked");

    const legacyEpoch: KeyRef = {
      type: "nostr-secp256k1",
      value: fixtures.personas.carol.epoch_keys.epoch_1.pubkey,
    };
    const epochRevocation = nostrRevocation(active, legacyEpoch);
    expect(authorizeWithClaim(active, [active], context(active, {
      repository_confirmed: new Set(),
      revocations: [epochRevocation],
    })).state).not.toBe("revoked");
  });

  it("verifies BIP-340, Ed25519, and JWS subject possession with exact challenge binding", () => {
    const nostrClaim = claim();
    expect(authorizeWithClaim(nostrClaim, [nostrClaim], context(nostrClaim)).state).toBe("active");

    const edClaim = claim({ subject: { type: "radicle-ed25519-nid", value: device.did_key } });
    const edChallenge = challenge(edClaim);
    const edProof: KeyProof = {
      type: "radicle-ed25519",
      public_key: device.public_key,
      signature: bytesToHex(ed25519.sign(subjectProofPayload(edChallenge), hexToBytes(device.private_key))),
    };
    expect(authorizeWithClaim(edClaim, [edClaim], context(edClaim, {
      subject_proof: { key: edClaim.subject, challenge: edChallenge, proof: edProof },
    }))).toMatchObject({ allowed: false, state: "active" });

    const jwk = { kty: "OKP", crv: "Ed25519", x: Buffer.from(device.public_key, "hex").toString("base64url") };
    const jwkClaim = claim({ subject: { type: "jwk-thumbprint", value: computeJwkThumbprint(jwk) } });
    const jwkChallenge = challenge(jwkClaim);
    const protectedHeader = Buffer.from(jcsCanonicalize({ alg: "EdDSA" }), "utf8").toString("base64url");
    const signingInput = `${protectedHeader}.${Buffer.from(subjectProofPayload(jwkChallenge)).toString("base64url")}`;
    const jwkProof: KeyProof = {
      type: "jwk-jws",
      jwk,
      protected: protectedHeader,
      signature: Buffer.from(ed25519.sign(utf8Bytes(signingInput), hexToBytes(device.private_key))).toString("base64url"),
    };
    expect(authorizeWithClaim(jwkClaim, [jwkClaim], context(jwkClaim, {
      subject_proof: { key: jwkClaim.subject, challenge: jwkChallenge, proof: jwkProof },
    }))).toMatchObject({ allowed: false, state: "active" });

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
        `${algorithmProtected}.${Buffer.from(subjectProofPayload(algorithmChallenge)).toString("base64url")}`,
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
      }))).toMatchObject({ allowed: false, state: "active" });
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
