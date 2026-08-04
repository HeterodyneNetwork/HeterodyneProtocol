import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { nip44 } from "nostr-tools";
import {
  authorizeWithClaim,
  CLAIM_REVOCATION_PROFILE,
  computeClaimId,
  computeJwkThumbprint,
  revocationProofPayload,
  subjectProofPayload,
  validateClaimEnvelope,
  validateClaimRevocationEnvelope,
  type ClaimRevocation,
  type ClaimAuthorityEvidence,
  type ClaimSemanticBody,
  type ClaimVerificationContext,
  type JsonValue,
  type KeyProof,
  type KeyRef,
  type SubjectProofChallenge,
  type VerifiedRevocation,
  type RevocationAuthorityEvidence,
} from "./claims.js";
import { withDeterministicEnv } from "./dm-transcript.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { DoubleRatchetSession } from "./ndr.js";
import { canonicalNip01, getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import { AUX_RAND, baseVector } from "./vector-helpers.js";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector, VectorDirection } from "./types.js";

type ClaimCase = {
  path: string;
  vector_id: string;
  description: string;
  direction?: VectorDirection;
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
  decision_trace?: string[];
  notes?: string;
};

function claimSpecRef(vectorId: string): string {
  if (/^chain-/.test(vectorId)) return "heterodyne:comms/0.5.0#comms-claim-chain";
  if (/revocation|rejection/.test(vectorId)) return "heterodyne:comms/0.5.0#comms-claim-revocation";
  if (/provisional|repository-confirmed/.test(vectorId)) return "heterodyne:comms/0.5.0#comms-claim-ledger";
  if (/proof|issuance|issuer/.test(vectorId)) return "heterodyne:comms/0.5.0#comms-claim-verification";
  return "heterodyne:comms/0.5.0#comms-key-claims";
}

export async function buildClaimVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const now = fixtures.test_epoch + 2_000;
  const epoch = fixtures.personas.alice.epoch_keys.epoch_1;
  const thirdParty = fixtures.personas.bob.epoch_keys.epoch_1;
  const deviceOne = fixtures.ed25519_nids.alice_device_1;
  const deviceOnePublishing = fixtures.device_publishing_keys.alice_device_1;
  const deviceTwoPublishing = fixtures.device_publishing_keys.alice_device_2;
  const audience = fixtures.personas.alice.cold_root.pubkey;
  const resource = `rad:${fixtures.radicle_rids.alice}:claims`;
  const rootIssuer: KeyRef = { type: "nostr-secp256k1", value: epoch.pubkey };
  const delegatedIssuer: KeyRef = { type: "nostr-secp256k1", value: deviceOnePublishing.pubkey };
  const nostrSubject: KeyRef = { type: "nostr-secp256k1", value: deviceTwoPublishing.pubkey };
  const radicleSubject: KeyRef = { type: "radicle-ed25519-nid", value: deviceOne.did_key };
  const publicJwk: Record<string, JsonValue> = {
    crv: "Ed25519",
    kty: "OKP",
    x: Buffer.from(deviceOne.public_key, "hex").toString("base64url"),
  };
  const jwkSubject: KeyRef = { type: "jwk-thumbprint", value: computeJwkThumbprint(publicJwk) };

  const makeClaim = (overrides: Partial<Omit<ClaimSemanticBody, "claim_id">> = {}): ClaimSemanticBody => {
    const complete = {
      issuer: rootIssuer,
      subject: nostrSubject,
      claim_class: "authorization" as const,
      credential_ledger_persona: overrides.claim_class === "descriptive" ? null : audience,
      credential_ledger_generation: overrides.claim_class === "descriptive" ? null : 0,
      namespace: "heterodyne.device",
      name: "claim-ledger-reader",
      value: true,
      issued_at: now,
      not_before: now,
      expires_at: now + 3_600,
      audience: [audience],
      resources: [resource],
      visibility: "repository-private" as const,
      spec_version: "comms/0.5.0" as const,
      registry_revision: 2 as const,
      ...overrides,
    };
    const body = Object.fromEntries(
      Object.entries(complete).filter(([, value]) => value !== undefined),
    ) as Omit<ClaimSemanticBody, "claim_id">;
    return { claim_id: computeClaimId(body), ...body };
  };
  const signClaim = async (claim: ClaimSemanticBody, secretKey = epoch.private_key): Promise<NostrSignedEvent> =>
    signEvent({
      secretKey,
      auxRand: AUX_RAND,
      created_at: claim.issued_at,
      kind: 31013,
      tags: [["d", claim.claim_id]],
      content: jcsCanonicalize(claim),
    });
  const challenge = (claim: ClaimSemanticBody, nonce = "71".repeat(16)): SubjectProofChallenge => ({
    domain: "heterodyne-claim-pop-v1",
    claim_id: claim.claim_id,
    nonce,
    audience,
    resource,
    operation: "read",
    issued_at: now + 10,
    expires_at: now + 70,
  });
  const nostrProof = (proofChallenge: SubjectProofChallenge, privateKey = deviceTwoPublishing.private_key): KeyProof => ({
    type: "nostr-bip340",
    signature: bytesToHex(schnorr.sign(utf8Bytes(subjectProofPayload(proofChallenge)), hexToBytes(privateKey), AUX_RAND)),
  });
  const edProof = (proofChallenge: SubjectProofChallenge): KeyProof => ({
    type: "radicle-ed25519",
    public_key: deviceOne.public_key,
    signature: bytesToHex(ed25519.sign(utf8Bytes(subjectProofPayload(proofChallenge)), hexToBytes(deviceOne.private_key))),
  });
  const jwkProof = (proofChallenge: SubjectProofChallenge): KeyProof => {
    const protectedHeader = Buffer.from(jcsCanonicalize({ alg: "EdDSA" }), "utf8").toString("base64url");
    const signingInput = `${protectedHeader}.${Buffer.from(subjectProofPayload(proofChallenge), "utf8").toString("base64url")}`;
    return {
      type: "jwk-jws",
      jwk: publicJwk,
      protected: protectedHeader,
      signature: Buffer.from(ed25519.sign(utf8Bytes(signingInput), hexToBytes(deviceOne.private_key))).toString("base64url"),
    };
  };
  const claimEventIds = new Map<string, string>();
  const activeContext = (
    claim: ClaimSemanticBody,
    proof: KeyProof,
    proofChallenge: SubjectProofChallenge,
    overrides: Partial<ClaimVerificationContext> = {},
  ): ClaimVerificationContext => {
    const authority: ClaimAuthorityEvidence = {
      claim_id: claim.claim_id,
      issuer: claim.issuer,
      event_id: claimEventIds.get(claim.claim_id) ?? "75".repeat(32),
      envelope_valid: true,
      core_kel_authority_valid: true,
      credential_ledger_persona: claim.credential_ledger_persona,
      credential_ledger_generation: claim.credential_ledger_generation,
      verified_at: now + 5,
      valid_until: now + 300,
    };
    return {
      now: now + 20,
      audience,
      resource,
      requested_namespace: claim.namespace,
      requested_operation: proofChallenge.operation,
      expected_nonce: proofChallenge.nonce,
      used_nonces: new Set(),
      trusted_issuers: [rootIssuer],
      claim_authority_evidence: new Map([[claim.claim_id, authority]]),
      revocation_authority_evidence: new Map(),
      repository_confirmed: new Set([claim.claim_id]),
      repository_conflicted: new Set(),
      revocations: [],
      subject_proof: { key: claim.subject, challenge: proofChallenge, proof },
      ...overrides,
      credential_ledger: overrides.credential_ledger ?? {
        credential_ledger_persona: audience,
        credential_ledger_generation: 0,
      },
    };
  };

  const nostrClaim = makeClaim({ subject: nostrSubject });
  const radicleClaim = makeClaim({ subject: radicleSubject });
  const jwkClaim = makeClaim({ subject: jwkSubject });
  const nostrChallenge = challenge(nostrClaim);
  const radicleChallenge = challenge(radicleClaim, "72".repeat(16));
  const jwkChallenge = challenge(jwkClaim, "73".repeat(16));
  const nostrEvent = await signClaim(nostrClaim);
  const radicleEvent = await signClaim(radicleClaim);
  const jwkEvent = await signClaim(jwkClaim);
  claimEventIds.set(nostrClaim.claim_id, nostrEvent.id);
  claimEventIds.set(radicleClaim.claim_id, radicleEvent.id);
  claimEventIds.set(jwkClaim.claim_id, jwkEvent.id);
  const tagMutationCases = [
    { name: "extra-tag-after", tags: [["d", nostrClaim.claim_id], ["p", epoch.pubkey]] },
    { name: "extra-tag-before", tags: [["p", epoch.pubkey], ["d", nostrClaim.claim_id]] },
    { name: "duplicate-d", tags: [["d", nostrClaim.claim_id], ["d", nostrClaim.claim_id]] },
    { name: "malformed-d", tags: [["d", nostrClaim.claim_id, "extra"]] },
    { name: "misordered-d", tags: [[nostrClaim.claim_id, "d"]] },
  ];
  const claimTagMutations = await Promise.all(tagMutationCases.map(async ({ name, tags }) => {
    const event = await signEvent({
      secretKey: epoch.private_key,
      auxRand: AUX_RAND,
      created_at: nostrClaim.issued_at,
      kind: 31013,
      tags,
      content: jcsCanonicalize(nostrClaim),
    });
    return {
      name,
      event,
      reason_code: rejectionReason(() => validateClaimEnvelope(event, {
        issuer_authorized: true,
        registry_revision: 2,
        credential_ledger: {
          credential_ledger_persona: audience,
          credential_ledger_generation: 0,
        },
      })),
    };
  }));
  const { spec_version: _claimSpecVersion, ...claimWithoutSpecVersion } = nostrClaim;
  const claimContentMutationCases = [
    { name: "missing-spec-version", semantic: claimWithoutSpecVersion },
    {
      name: "legacy-comms-version",
      semantic: { ...claimWithoutSpecVersion, comms_version: "comms/0.5.0" },
    },
    {
      name: "wrong-spec-version",
      semantic: { ...nostrClaim, spec_version: "comms/0.5.1" },
    },
  ];
  const claimContentMutations = await Promise.all(
    claimContentMutationCases.map(async ({ name, semantic }) => {
      const event = await signEvent({
        secretKey: epoch.private_key,
        auxRand: AUX_RAND,
        created_at: nostrClaim.issued_at,
        kind: 31013,
        tags: [["d", nostrClaim.claim_id]],
        content: jcsCanonicalize(semantic),
      });
      return {
        name,
        event,
        reason_code: rejectionReason(() => validateClaimEnvelope(event, {
          issuer_authorized: true,
          registry_revision: 2,
          credential_ledger: {
            credential_ledger_persona: audience,
            credential_ledger_generation: 0,
          },
        })),
      };
    }),
  );
  const claimMutations = [...claimTagMutations, ...claimContentMutations];

  const parent = makeClaim({
    subject: delegatedIssuer,
    constraints: {
      namespaces: ["heterodyne.device"],
      audiences: [audience],
      resources: [resource],
      remaining_depth: 2,
    },
  });
  const child = makeClaim({
    issuer: delegatedIssuer,
    parent_claim_id: parent.claim_id,
    not_before: now + 1,
    expires_at: now + 1_800,
    constraints: {
      namespaces: ["heterodyne.device"],
      audiences: [audience],
      resources: [resource],
      remaining_depth: 1,
    },
  });
  const parentEvent = await signClaim(parent);
  const childEvent = await signClaim(child, deviceOnePublishing.private_key);
  claimEventIds.set(parent.claim_id, parentEvent.id);
  claimEventIds.set(child.claim_id, childEvent.id);
  const childChallenge = challenge(child, "74".repeat(16));
  const childContext = activeContext(child, nostrProof(childChallenge), childChallenge);
  childContext.claim_authority_evidence.set(parent.claim_id, {
    claim_id: parent.claim_id,
    issuer: parent.issuer,
    event_id: parentEvent.id,
    envelope_valid: true,
    core_kel_authority_valid: true,
    credential_ledger_persona: parent.credential_ledger_persona,
    credential_ledger_generation: parent.credential_ledger_generation,
    verified_at: now + 5,
    valid_until: now + 300,
  });
  childContext.repository_confirmed.add(parent.claim_id);

  const thirdPartyClaim = makeClaim({
    issuer: { type: "nostr-secp256k1", value: thirdParty.pubkey },
    claim_class: "descriptive",
    expires_at: undefined,
    visibility: "public",
  });
  const thirdPartyEvent = await signClaim(thirdPartyClaim, thirdParty.private_key);

  const widened = makeClaim({
    issuer: delegatedIssuer,
    parent_claim_id: parent.claim_id,
    namespace: "heterodyne.control",
    not_before: now + 1,
    expires_at: now + 1_800,
  });

  const depthClaims: ClaimSemanticBody[] = [];
  let depthParent = makeClaim({
    subject: delegatedIssuer,
    constraints: { namespaces: ["heterodyne.device"], audiences: [audience], resources: [resource], remaining_depth: 8 },
  });
  depthClaims.push(depthParent);
  for (let edge = 1; edge <= 9; edge += 1) {
    const nextKey = bytesToHex(schnorr.getPublicKey((40 + edge).toString(16).padStart(64, "0")));
    const next = makeClaim({
      issuer: depthParent.subject,
      subject: { type: "nostr-secp256k1", value: nextKey },
      parent_claim_id: depthParent.claim_id,
      not_before: now + edge,
      expires_at: now + 3_600 - edge,
      constraints: {
        namespaces: ["heterodyne.device"],
        audiences: [audience],
        resources: [resource],
        remaining_depth: Math.max(0, 8 - edge),
      },
    });
    depthClaims.push(next);
    depthParent = next;
  }

  const selfRevocation: ClaimRevocation = {
    ...CLAIM_REVOCATION_PROFILE,
    claim_id: nostrClaim.claim_id,
    revoked_at: now + 15,
    reason_code: "claim-revoked",
    revoker: nostrSubject,
  };
  const selfRevocationEvent = await signEvent({
    secretKey: deviceTwoPublishing.private_key,
    auxRand: AUX_RAND,
    created_at: selfRevocation.revoked_at,
    kind: 31014,
    tags: [["d", nostrClaim.claim_id]],
    content: jcsCanonicalize(selfRevocation),
  });
  const verifiedSelfRevocation = validateClaimRevocationEnvelope(selfRevocationEvent);
  const { spec_version: _selfVersion, ...missingRevocationVersion } = selfRevocation;
  const { registry_revision: _selfRevision, ...missingRevocationRevision } = selfRevocation;
  const revocationContentMutations = [
    { name: "missing-spec-version", semantic: missingRevocationVersion },
    {
      name: "legacy-comms-version",
      semantic: { ...missingRevocationVersion, comms_version: "comms/0.5.0" },
    },
    { name: "missing-registry-revision", semantic: missingRevocationRevision },
    { name: "wrong-spec-version", semantic: { ...selfRevocation, spec_version: "comms/0.5.1" } },
    { name: "wrong-registry-revision", semantic: { ...selfRevocation, registry_revision: 1 } },
  ];
  const revocationMutations = [
    ...await Promise.all(tagMutationCases.map(async ({ name, tags }) => ({
      name: `revocation-${name}`,
      event: await signEvent({
        secretKey: deviceTwoPublishing.private_key,
        auxRand: AUX_RAND,
        created_at: selfRevocation.revoked_at,
        kind: 31014,
        tags,
        content: jcsCanonicalize(selfRevocation),
      }),
    }))),
    ...await Promise.all(revocationContentMutations.map(async ({ name, semantic }) => ({
      name,
      event: await signEvent({
        secretKey: deviceTwoPublishing.private_key,
        auxRand: AUX_RAND,
        created_at: selfRevocation.revoked_at,
        kind: 31014,
        tags: [["d", selfRevocation.claim_id]],
        content: jcsCanonicalize(semantic),
      }),
    }))),
  ].map(({ name, event }) => ({
    name,
    event,
    reason_code: rejectionReason(() => validateClaimRevocationEnvelope(event)),
  }));
  const roleSigners = [
    { role: "claim-issuer", key: child.issuer, secret: deviceOnePublishing.private_key, authorized: true },
    { role: "active-ancestor-issuer", key: parent.issuer, secret: epoch.private_key, authorized: true },
    { role: "persona-epoch", key: { type: "nostr-secp256k1" as const, value: epoch.pubkey }, secret: epoch.private_key, authorized: true },
    { role: "persona-cold-root", key: { type: "nostr-secp256k1" as const, value: fixtures.personas.alice.cold_root.pubkey }, secret: fixtures.personas.alice.cold_root.private_key, authorized: true },
    { role: "subject-self", key: child.subject, secret: deviceTwoPublishing.private_key, authorized: true },
    { role: "unrelated-signer", key: { type: "nostr-secp256k1" as const, value: thirdParty.pubkey }, secret: thirdParty.private_key, authorized: false },
  ];
  const authorizationRevocationCases = [];
  for (const [index, role] of roleSigners.entries()) {
    const semantic: ClaimRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: child.claim_id,
      revoked_at: now + 30 + index,
      reason_code: "claim-revoked",
      revoker: role.key,
    };
    const event = await signEvent({
      secretKey: role.secret,
      auxRand: AUX_RAND,
      created_at: semantic.revoked_at,
      kind: 31014,
      tags: [["d", child.claim_id]],
      content: jcsCanonicalize(semantic),
    });
    const verified = validateClaimRevocationEnvelope(event);
    let authority_evidence: RevocationAuthorityEvidence | null = null;
    if (role.role === "active-ancestor-issuer") {
      authority_evidence = {
        event_id: event.id,
        claim_id: child.claim_id,
        signer: role.key,
        authority: "active-ancestor-issuer",
        authority_claim_id: parent.claim_id,
        valid_from: parent.not_before,
        valid_until: parent.expires_at!,
        core_kel_authority_valid: true,
      };
    } else if (role.role === "persona-epoch" || role.role === "persona-cold-root") {
      authority_evidence = {
        event_id: event.id,
        claim_id: child.claim_id,
        signer: role.key,
        authority: role.role,
        valid_from: now,
        valid_until: now + 3_600,
        core_kel_authority_valid: true,
      };
    }
    authorizationRevocationCases.push({
      role: role.role,
      event,
      verified_signer: verified.signer,
      authority_evidence,
      persona_cold_root: role.role === "persona-epoch" || role.role === "persona-cold-root"
        ? audience
        : null,
      expected_authorized: role.authorized,
    });
  }

  const namedRevoker: KeyRef = radicleSubject;
  const descriptive = makeClaim({
    claim_class: "descriptive",
    expires_at: undefined,
    subject: nostrSubject,
    revokers: [namedRevoker],
  });
  const edRevocationUnsigned = {
    ...CLAIM_REVOCATION_PROFILE,
    claim_id: descriptive.claim_id,
    revoked_at: now + 16,
    reason_code: "claim-revoked",
  };
  const edRevocation: ClaimRevocation = {
    ...edRevocationUnsigned,
    revoker: namedRevoker,
    proof: {
      type: "radicle-ed25519",
      public_key: deviceOne.public_key,
      signature: bytesToHex(ed25519.sign(utf8Bytes(revocationProofPayload(edRevocationUnsigned)), hexToBytes(deviceOne.private_key))),
    },
  };
  const edRevocationEvent = await signEvent({
    secretKey: epoch.private_key,
    auxRand: AUX_RAND,
    created_at: edRevocation.revoked_at,
    kind: 31014,
    tags: [["d", descriptive.claim_id]],
    content: jcsCanonicalize(edRevocation),
  });
  const verifiedEdRevocation = validateClaimRevocationEnvelope(edRevocationEvent);
  const delegatedDescriptive = makeClaim({
    issuer: delegatedIssuer,
    subject: nostrSubject,
    claim_class: "descriptive",
    parent_claim_id: parent.claim_id,
    not_before: now + 1,
    expires_at: now + 1_800,
    revokers: [namedRevoker],
  });
  const descriptiveNostrRoles = [
    { role: "descriptive-issuer", key: delegatedDescriptive.issuer, secret: deviceOnePublishing.private_key, authorized: true },
    { role: "superior-active-issuer", key: parent.issuer, secret: epoch.private_key, authorized: true },
    { role: "descriptive-subject", key: delegatedDescriptive.subject, secret: deviceTwoPublishing.private_key, authorized: false },
  ];
  const descriptiveRevocationCases = [];
  for (const [index, role] of descriptiveNostrRoles.entries()) {
    const semantic: ClaimRevocation = {
      ...CLAIM_REVOCATION_PROFILE,
      claim_id: delegatedDescriptive.claim_id,
      revoked_at: now + 50 + index,
      reason_code: "claim-revoked",
      revoker: role.key,
    };
    const event = await signEvent({
      secretKey: role.secret,
      auxRand: AUX_RAND,
      created_at: semantic.revoked_at,
      kind: 31014,
      tags: [["d", semantic.claim_id]],
      content: jcsCanonicalize(semantic),
    });
    const verified = validateClaimRevocationEnvelope(event);
    const authority_evidence: RevocationAuthorityEvidence | null = role.role === "superior-active-issuer"
      ? {
          event_id: event.id,
          claim_id: semantic.claim_id,
          signer: role.key,
          authority: "active-ancestor-issuer",
          authority_claim_id: parent.claim_id,
          valid_from: parent.not_before,
          valid_until: parent.expires_at!,
          core_kel_authority_valid: true,
        }
      : null;
    descriptiveRevocationCases.push({
      role: role.role,
      event,
      verified_signer: verified.signer,
      authority_evidence,
      expected_authorized: role.authorized,
    });
  }
  const rejectionClaim = makeClaim({
    issuer: nostrSubject,
    subject: nostrSubject,
    claim_class: "descriptive",
    namespace: "heterodyne.claim-rejection",
    name: descriptive.claim_id,
    value: false,
    expires_at: undefined,
    audience: undefined,
    resources: undefined,
    visibility: "public",
  });
  const rejectionEvent = await signClaim(rejectionClaim, deviceTwoPublishing.private_key);

  const jwkRevocationUnsigned = {
    ...CLAIM_REVOCATION_PROFILE,
    claim_id: jwkClaim.claim_id,
    revoked_at: now + 17,
    reason_code: "claim-revoked",
  };
  const copiedProtected = Buffer.from(jcsCanonicalize({ alg: "EdDSA" }), "utf8").toString("base64url");
  const copiedInput = `${copiedProtected}.${Buffer.from(revocationProofPayload(jwkRevocationUnsigned), "utf8").toString("base64url")}`;
  const validJwkRevocation: ClaimRevocation = {
    ...jwkRevocationUnsigned,
    revoker: jwkSubject,
    proof: {
      type: "jwk-jws",
      jwk: publicJwk,
      protected: copiedProtected,
      signature: Buffer.from(ed25519.sign(utf8Bytes(copiedInput), hexToBytes(deviceOne.private_key))).toString("base64url"),
    },
  };
  const validJwkRevocationEvent = await signEvent({
    secretKey: epoch.private_key,
    auxRand: AUX_RAND,
    created_at: validJwkRevocation.revoked_at,
    kind: 31014,
    tags: [["d", validJwkRevocation.claim_id]],
    content: jcsCanonicalize(validJwkRevocation),
  });
  const verifiedJwkRevocation = validateClaimRevocationEnvelope(validJwkRevocationEvent);
  const protectedHeader = (header: Record<string, JsonValue>) =>
    Buffer.from(jcsCanonicalize(header), "utf8").toString("base64url");
  const baseJwkProof = validJwkRevocation.proof as Extract<KeyProof, { type: "jwk-jws" }>;
  const jwkMutationSemantics: Array<{ name: string; semantic: ClaimRevocation }> = [
    {
      name: "missing-protected-alg",
      semantic: {
        ...validJwkRevocation,
        proof: { ...baseJwkProof, protected: protectedHeader({}) },
      },
    },
    {
      name: "extra-protected-member",
      semantic: {
        ...validJwkRevocation,
        proof: { ...baseJwkProof, protected: protectedHeader({ alg: "EdDSA", typ: "JWT" }) },
      },
    },
    {
      name: "none-protected-alg",
      semantic: {
        ...validJwkRevocation,
        proof: { ...baseJwkProof, protected: protectedHeader({ alg: "none" }) },
      },
    },
    {
      name: "hmac-protected-alg",
      semantic: {
        ...validJwkRevocation,
        proof: { ...baseJwkProof, protected: protectedHeader({ alg: "HS256" }) },
      },
    },
    {
      name: "extra-jwk-member",
      semantic: {
        ...validJwkRevocation,
        proof: { ...baseJwkProof, jwk: { ...publicJwk, arbitrary: true } },
      },
    },
    {
      name: "wrong-jwk-alg",
      semantic: {
        ...validJwkRevocation,
        proof: { ...baseJwkProof, jwk: { ...publicJwk, alg: "RS256" } },
      },
    },
    {
      name: "wrong-jwk-kid",
      semantic: {
        ...validJwkRevocation,
        proof: { ...baseJwkProof, jwk: { ...publicJwk, kid: "A".repeat(43) } },
      },
    },
  ];
  const jwkRejectionMutations = (await Promise.all(
    jwkMutationSemantics.map(async ({ name, semantic }) => ({
      name,
      event: await signEvent({
        secretKey: epoch.private_key,
        auxRand: AUX_RAND,
        created_at: semantic.revoked_at,
        kind: 31014,
        tags: [["d", semantic.claim_id]],
        content: jcsCanonicalize(semantic),
      }),
    })),
  )).map(({ name, event }) => ({
    name,
    event,
    reason_code: rejectionReason(() => validateClaimRevocationEnvelope(event)),
  }));
  const copiedChallenge = { ...jwkChallenge, nonce: "79".repeat(16) };
  const copiedProofDecision = authorizeWithClaim(
    jwkClaim,
    [jwkClaim],
    activeContext(jwkClaim, jwkProof(jwkChallenge), copiedChallenge, {
      expected_nonce: copiedChallenge.nonce,
    }),
  );

  const publicClaim = makeClaim({
    claim_class: "descriptive",
    expires_at: undefined,
    visibility: "public",
  });
  const publicEvent = await signClaim(publicClaim);
  const pairwiseClaim = makeClaim({ visibility: "pairwise-private" });
  const pairwiseEvent = await signClaim(pairwiseClaim);
  const drAliceSecret = "a1".repeat(32);
  const drBobSecret = "b2".repeat(32);
  const drSharedSecret = "c3".repeat(32);
  const pairwiseDr = withDeterministicEnv(now + 100, () => {
    const session = DoubleRatchetSession.init(
      getPublicKey(drBobSecret),
      hexToBytes(drAliceSecret),
      true,
      hexToBytes(drSharedSecret),
      "claims-pairwise",
    );
    return session.sendEvent({
      kind: 14,
      pubkey: deviceOnePublishing.pubkey,
      tags: [["p", audience]],
      content: jcsCanonicalize(pairwiseEvent),
    });
  });
  const repositoryClaim = makeClaim({ subject: radicleSubject, visibility: "repository-private" });
  const repositoryEvent = await signClaim(repositoryClaim);
  const ledgerAudienceKey = hexToBytes("82".repeat(32));
  const repositoryCiphertext = nip44.v2.encrypt(jcsCanonicalize(repositoryEvent), ledgerAudienceKey, hexToBytes("83".repeat(32)));
  const repositoryPath = bytesToHex(hmac(sha256, ledgerAudienceKey, utf8Bytes(repositoryClaim.claim_id)));
  const repositoryBlobDigest = bytesToHex(sha256(utf8Bytes(repositoryCiphertext)));
  const repositoryTree = [{
    mode: "100644",
    path: `objects/${repositoryPath.slice(0, 2)}/${repositoryPath.slice(2)}`,
    blob_sha256: repositoryBlobDigest,
    size: Buffer.byteLength(repositoryCiphertext, "utf8"),
  }];
  const repositoryCommit = {
    tree_sha256: bytesToHex(sha256(utf8Bytes(jcsCanonicalize(repositoryTree)))),
    parent: "84".repeat(20),
    author_nid: deviceOne.did_key,
    message: "update encrypted claim ledger object",
  };

  const cases: ClaimCase[] = [
    {
      ...canonicalCase("001-canonical-nostr-subject.json", "canonical-nostr-subject", nostrClaim, nostrEvent, nostrChallenge, nostrProof(nostrChallenge), "nostr-bip340-v1"),
      input: {
        ...canonicalCase("001-canonical-nostr-subject.json", "canonical-nostr-subject", nostrClaim, nostrEvent, nostrChallenge, nostrProof(nostrChallenge), "nostr-bip340-v1").input,
        rejection_mutations: claimMutations,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          claim_id: nostrClaim.claim_id,
          subject: nostrClaim.subject,
          proof_profile: "nostr-bip340-v1",
          registry_revision: 2,
          rejection_mutations: claimMutations.map(({ name, reason_code }) => ({ name, reason_code })),
        },
      },
    },
    canonicalCase("002-canonical-radicle-nid-subject.json", "canonical-radicle-nid-subject", radicleClaim, radicleEvent, radicleChallenge, edProof(radicleChallenge), "radicle-ed25519-v1"),
    {
      ...canonicalCase("003-canonical-jwk-thumbprint-subject.json", "canonical-jwk-thumbprint-subject", jwkClaim, jwkEvent, jwkChallenge, jwkProof(jwkChallenge), "jwk-jws-v1"),
      description: "A canonical JWK-thumbprint subject claim and a positive native EdDSA JWK revocation fixture bind the embedded public JWK to the same RFC 7638 thumbprint.",
      input: {
        ...canonicalCase("003-canonical-jwk-thumbprint-subject.json", "canonical-jwk-thumbprint-subject", jwkClaim, jwkEvent, jwkChallenge, jwkProof(jwkChallenge), "jwk-jws-v1").input,
        positive_native_revocation_event: validJwkRevocationEvent,
        jwk_rejection_mutations: jwkRejectionMutations,
      },
      expected_output: {
        verdict: "accept",
        normalized: {
          claim_id: jwkClaim.claim_id,
          subject: jwkClaim.subject,
          proof_profile: "jwk-jws-v1",
          revocation_signer: verifiedJwkRevocation.signer,
          revocation_native_proof_valid: true,
          registry_revision: 2,
          jwk_rejection_mutations: jwkRejectionMutations.map(({ name, reason_code }) => ({
            name,
            reason_code,
          })),
        },
      },
    },
    {
      path: "004-claim-id-mismatch.json",
      vector_id: "claim-id-mismatch",
      description: "Changing one semantic member while retaining the old lowercase claim_id is rejected before trust policy.",
      input: { semantic_body: { ...nostrClaim, value: false }, retained_claim_id: nostrClaim.claim_id },
      expected_output: { verdict: "reject", reason_code: "claim-id-mismatch" },
      decision_trace: ["parse_canonical_bytes", "recompute_claim_id", "reject_before_policy"],
    },
    {
      path: "005-persona-issuance-active.json",
      vector_id: "persona-issuance-active",
      description: "A current persona epoch issuer, canonical repository confirmation, and fresh exact-subject proof produce active authorization.",
      input: { event: nostrEvent, claim: nostrClaim, claim_authority_evidence: [...activeContext(nostrClaim, nostrProof(nostrChallenge), nostrChallenge).claim_authority_evidence.values()], requested_namespace: nostrClaim.namespace, requested_operation: "read", expected_nonce: nostrChallenge.nonce, used_nonces: [], repository_confirmed: true, subject_proof: { challenge: nostrChallenge, proof: nostrProof(nostrChallenge) } },
      expected_output: { verdict: "accept", normalized: authorizeWithClaim(nostrClaim, [nostrClaim], activeContext(nostrClaim, nostrProof(nostrChallenge), nostrChallenge)) },
      decision_trace: eightStages(),
    },
    {
      path: "006-delegated-issuance-active.json",
      vector_id: "delegated-issuance-active",
      description: "A child signed by the parent subject preserves scope, shortens validity, decrements depth, and authorizes only after repository confirmation.",
      input: { chain_events: [parentEvent, childEvent], chain: [parent, child], claim_authority_evidence: [...childContext.claim_authority_evidence.values()], canonical_repository_claim_ids: [...childContext.repository_confirmed], requested_namespace: child.namespace, requested_operation: "read", expected_nonce: childChallenge.nonce, used_nonces: [], subject_proof: childContext.subject_proof },
      expected_output: { verdict: "accept", normalized: authorizeWithClaim(child, [parent, child], childContext) },
      decision_trace: eightStages(),
    },
    {
      path: "007-third-party-issuer-untrusted.json",
      vector_id: "third-party-issuer-untrusted",
      description: "A cryptographically valid third-party descriptive assertion remains untrusted when its issuer is outside local policy.",
      input: { event: thirdPartyEvent, canonical_wire: canonicalNip01(thirdPartyEvent), issuer_core_authority: "current", trusted_issuers: [] },
      expected_output: { verdict: "accept", normalized: { cryptographically_valid: true, state: "untrusted", reason_code: "claim-issuer-untrusted", provenance_retained: true } },
      decision_trace: [...eightStages().slice(0, 7), "apply_local_trust_policy_untrusted"],
    },
    {
      path: "008-chain-attenuation-valid.json",
      vector_id: "chain-attenuation-valid",
      description: "A two-edge-capable chain narrows time and keeps all semantic, audience, resource, and remaining-depth dimensions within the parent.",
      input: { chain: [parent, child] },
      expected_output: { verdict: "accept", normalized: { edge_count: 1, remaining_depth: 1, exact_name_value_preserved: true, validity_shortened: true } },
    },
    {
      path: "009-chain-widening-rejected.json",
      vector_id: "chain-widening-rejected",
      description: "A child that changes the atomic namespace is rejected even when its issuer equals the parent subject.",
      input: { chain: [parent, widened] },
      expected_output: { verdict: "reject", reason_code: "claim-attenuation-violation", normalized: { stale_core_kel_authority_reason_code: "claim-issuer-authority-invalid", policy_hook_invoked: false } },
      decision_trace: ["resolve_claim_issuance_chain", "prove_attenuation", "reject_before_policy"],
    },
    {
      path: "010-chain-depth-exceeded.json",
      vector_id: "chain-depth-exceeded",
      description: "Nine issuance edges exceed the strict bound; a separately modeled repeated ancestor is rejected as a cycle.",
      input: {
        cases: [
          { name: "ninth-edge", leaf_claim_id: depthClaims[9].claim_id, claims_by_id: Object.fromEntries(depthClaims.map((claim) => [claim.claim_id, claim])), expected_reason_code: "claim-chain-depth-exceeded" },
          { name: "cycle", leaf_claim_id: child.claim_id, claims_by_id: { [child.claim_id]: child, [parent.claim_id]: child }, expected_reason_code: "claim-chain-cycle", note: "Both stored claim bodies retain valid canonical IDs; the corrupted lookup binds the parent ID to the child and repeats the child's claim_id." },
        ],
      },
      expected_output: { verdict: "reject", reason_code: "claim-chain-depth-exceeded", normalized: { cycle_reason_code: "claim-chain-cycle", cycle_path: [child.claim_id, child.claim_id], maximum_edges: 8 } },
    },
    {
      path: "011-subject-proof-valid.json",
      vector_id: "subject-proof-valid",
      description: "Fresh BIP-340, Ed25519, and EdDSA JWS proofs bind exact claim, audience, resource, operation, nonce, and sixty-second window.",
      input: {
        proofs: [
          { subject: nostrClaim.subject, challenge: nostrChallenge, proof: nostrProof(nostrChallenge) },
          { subject: radicleClaim.subject, challenge: radicleChallenge, proof: edProof(radicleChallenge) },
          { subject: jwkClaim.subject, challenge: jwkChallenge, proof: jwkProof(jwkChallenge) },
        ],
      },
      expected_output: { verdict: "accept", normalized: { verified_profiles: ["nostr-bip340-v1", "radicle-ed25519-v1", "jwk-jws-v1"], maximum_window_seconds: 60 } },
    },
    {
      path: "012-copied-proof-rejected.json",
      vector_id: "copied-proof-rejected",
      description: "An actual JWK authorization subject proof copied from one verifier challenge to a challenge with a different nonce fails signature and exact expected-nonce binding before local trust.",
      input: { claim: jwkClaim, source: { challenge: jwkChallenge, proof: jwkProof(jwkChallenge) }, copied_request: { challenge: copiedChallenge, proof: jwkProof(jwkChallenge), expected_nonce: copiedChallenge.nonce }, claim_authority_evidence: [...activeContext(jwkClaim, jwkProof(jwkChallenge), jwkChallenge).claim_authority_evidence.values()] },
      expected_output: { verdict: "reject", reason_code: "claim-subject-proof-invalid", normalized: { ...copiedProofDecision, policy_hook_invoked: false, changed_binding: "nonce" } },
      decision_trace: ["verify_claim_and_core_authority", "compare_expected_nonce", "verify_subject_proof_signature", "reject_before_policy"],
    },
    {
      path: "013-provisional-authorization-denied.json",
      vector_id: "provisional-authorization-denied",
      description: "A delivered persona authorization remains provisional and cannot authorize before canonical repository reachability.",
      input: { claim: nostrClaim, delivered_over_dr: true, repository_confirmed: false },
      expected_output: { verdict: "reject", reason_code: "claim-repository-unconfirmed", normalized: { allowed: false, state: "provisional" } },
    },
    {
      path: "014-repository-confirmed-active.json",
      vector_id: "repository-confirmed-active",
      description: "The identical grant becomes active once its claim ID is reachable from canonical private repository state.",
      input: { claim: nostrClaim, canonical_repository_claim_ids: [nostrClaim.claim_id], subject_proof: { challenge: nostrChallenge, proof: nostrProof(nostrChallenge) } },
      expected_output: { verdict: "accept", normalized: authorizeWithClaim(nostrClaim, [nostrClaim], activeContext(nostrClaim, nostrProof(nostrChallenge), nostrChallenge)) },
    },
    {
      path: "015-authorization-self-revocation.json",
      vector_id: "authorization-self-revocation",
      description: "The exact authorization subject BIP-340 signer self-revokes immediately, before repository finality can leave the delivered grant provisional.",
      input: { chain: [parent, child], role_cases: authorizationRevocationCases, self_revocation_event: selfRevocationEvent, rejection_mutations: revocationMutations, repository_confirmed: false },
      expected_output: { verdict: "reject", reason_code: "claim-revoked", normalized: { allowed: false, state: "revoked", repository_final: false, signer: verifiedSelfRevocation.signer, authorized_roles: ["claim-issuer", "active-ancestor-issuer", "persona-epoch", "persona-cold-root", "subject-self"], unauthorized_roles: ["unrelated-signer"], rejection_mutations: revocationMutations.map(({ name, reason_code }) => ({ name, reason_code })) } },
      decision_trace: ["authenticate_revocation", "apply_irreversible_reduction", "skip_provisional_authorization"],
    },
    {
      path: "016-descriptive-subject-rejection.json",
      vector_id: "descriptive-subject-rejection",
      description: "A named Radicle Ed25519 revoker can revoke a descriptive assertion; the subject's separately signed rejection preserves the original provenance rather than erasing it.",
      input: { assertion_chain: [parent, delegatedDescriptive], nostr_role_cases: descriptiveRevocationCases, named_radicle_revocation_event: edRevocationEvent, subject_rejection_event: rejectionEvent },
      expected_output: { verdict: "accept", normalized: { named_revocation_authenticated: true, named_revocation_signer: verifiedEdRevocation.signer, authorized_roles: ["descriptive-issuer", "superior-active-issuer", "named-revoker"], unauthorized_revocation_roles: ["descriptive-subject"], subject_rejection_is_separate_claim: true, original_provenance_retained: true } },
    },
    {
      path: "017-public-claim-publication.json",
      vector_id: "public-claim-publication",
      description: "A public descriptive claim is a complete signed kind:31013 event suitable for ordinary and repository relays.",
      direction: "round-trip",
      input: { event: publicEvent, canonical_wire: canonicalNip01(publicEvent), carriers: ["nostr_relay", "repo_relay"] },
      expected_output: { verdict: "accept", normalized: { visibility: "public", claim_metadata_public: true, signed_event_complete: true } },
    },
    {
      path: "018-pairwise-private-dr-delivery.json",
      vector_id: "pairwise-private-dr-delivery",
      description: "A full signed claim is carried only inside pairwise DR ciphertext; outer metadata contains no claim ID, namespace, name, value, or visibility.",
      input: { wire_library: "nostr-double-ratchet@0.0.138", session_setup: { initiator_secret: drAliceSecret, responder_public: getPublicKey(drBobSecret), shared_secret: drSharedSecret }, outer_event: pairwiseDr.event, canonical_wire: canonicalNip01(pairwiseDr.event), inner_rumor: pairwiseDr.innerEvent },
      expected_output: { verdict: "accept", normalized: { visibility: "pairwise-private", inner_claim_id: pairwiseClaim.claim_id, outer_kind: 1060, outer_signer: pairwiseDr.event.pubkey, signer_is_current_ratchet_key: pairwiseDr.event.pubkey === getPublicKey(drAliceSecret), outer_claim_metadata_fields: [], repository_storable: false, backfill: false } },
    },
    {
      path: "019-repository-private-encryption.json",
      vector_id: "repository-private-encryption",
      description: "Repository-private claim bytes and keyed path are opaque under a dedicated ledger audience key.",
      input: { rid: fixtures.radicle_rids.alice, branch: "main", commit: repositoryCommit, tree: repositoryTree, blobs: { [repositoryTree[0].path]: repositoryCiphertext }, key_id: "claim-ledger-audience-v1", fixture_audience_key: bytesToHex(ledgerAudienceKey), pinned_nonce: "83".repeat(32) },
      expected_output: { verdict: "accept", normalized: { visibility: "repository-private", inner_claim_id: repositoryClaim.claim_id, plaintext_metadata_in_path: false, plaintext_metadata_in_commit: false, encrypted_before_storage: true } },
    },
    {
      path: "020-local-only-no-publication.json",
      vector_id: "local-only-no-publication",
      description: "A local-only assertion remains application state and creates no signed claim, relay, DR, repository, discovery, or OIDC protocol artifact.",
      input: { local_state: { namespace: "heterodyne.local", name: "display-preference", value: true }, requested_visibility: "local-only" },
      expected_output: { verdict: "accept", normalized: { visibility: "local-only", transport_artifacts: [], public_discovery_fields: [] } },
    },
  ];

  return cases.map((testCase) => ({
    relativePath: `claims/${testCase.path}`,
    vector: baseVector({
      vector_id: `claims/${testCase.vector_id}`,
      spec_refs: [claimSpecRef(testCase.vector_id)],
      description: testCase.description,
      direction: testCase.direction ?? "consume",
      input: testCase.input,
      expected_output: testCase.expected_output,
      ...(testCase.decision_trace === undefined ? {} : { decision_trace: testCase.decision_trace }),
      ...(testCase.notes === undefined ? {} : { notes: testCase.notes }),
    }),
  }));
}

function canonicalCase(
  path: string,
  id: string,
  claim: ClaimSemanticBody,
  event: NostrSignedEvent,
  challenge: SubjectProofChallenge,
  proof: KeyProof,
  proofProfile: string,
): ClaimCase {
  return {
    path,
    vector_id: id,
    description: `Canonical kind:31013 bytes use a typed ${claim.subject.type} subject and a fresh ${proofProfile} subject proof.`,
    direction: "round-trip",
    input: { semantic_body: claim, event, canonical_wire: canonicalNip01(event), subject_proof: { challenge, proof } },
    expected_output: { verdict: "accept", normalized: { claim_id: claim.claim_id, subject: claim.subject, proof_profile: proofProfile, registry_revision: 2 } },
  };
}

function eightStages(): string[] {
  return [
    "parse_canonical_bytes_and_recompute_claim_id",
    "verify_event_signature_and_core_kel_issuer_authority",
    "resolve_claim_issuance_chain",
    "prove_attenuation_and_depth",
    "check_time_audience_namespace_subject_resource",
    "resolve_repository_confirmation_and_revocation",
    "require_fresh_subject_proof",
    "apply_local_trust_and_release_policy",
  ];
}

function rejectionReason(validate: () => unknown): string {
  try {
    validate();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const reason = /^([a-z0-9]+(?:-[a-z0-9]+)*):/.exec(message)?.[1];
    if (reason !== undefined) return reason;
    throw error;
  }
  throw new Error("negative claim vector mutation was unexpectedly accepted");
}
