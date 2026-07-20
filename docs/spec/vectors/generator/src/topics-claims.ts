import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { nip44 } from "nostr-tools";
import {
  authorizeWithClaim,
  computeClaimId,
  computeJwkThumbprint,
  revocationProofPayload,
  subjectProofPayload,
  validateClaimRevocationEnvelope,
  type ClaimRevocation,
  type ClaimSemanticBody,
  type ClaimVerificationContext,
  type JsonValue,
  type KeyProof,
  type KeyRef,
  type SubjectProofChallenge,
  type VerifiedRevocation,
} from "./claims.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { canonicalNip01, signEvent, type NostrSignedEvent } from "./nostr.js";
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

const CLAIM_REF = "heterodyne:comms/0.5.0#comms-conformance";

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
      namespace: "heterodyne.device",
      name: "claim-ledger-reader",
      value: true,
      issued_at: now,
      not_before: now,
      expires_at: now + 3_600,
      audience: [audience],
      resources: [resource],
      visibility: "repository-private" as const,
      comms_version: "comms/0.5.0" as const,
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
  const activeContext = (
    claim: ClaimSemanticBody,
    proof: KeyProof,
    proofChallenge: SubjectProofChallenge,
    overrides: Partial<ClaimVerificationContext> = {},
  ): ClaimVerificationContext => ({
    now: now + 20,
    audience,
    resource,
    trusted_issuers: [rootIssuer],
    repository_confirmed: new Set([claim.claim_id]),
    repository_conflicted: new Set(),
    revocations: [],
    subject_proof: { key: claim.subject, challenge: proofChallenge, proof },
    ...overrides,
  });

  const nostrClaim = makeClaim({ subject: nostrSubject });
  const radicleClaim = makeClaim({ subject: radicleSubject });
  const jwkClaim = makeClaim({ subject: jwkSubject });
  const nostrChallenge = challenge(nostrClaim);
  const radicleChallenge = challenge(radicleClaim, "72".repeat(16));
  const jwkChallenge = challenge(jwkClaim, "73".repeat(16));
  const nostrEvent = await signClaim(nostrClaim);
  const radicleEvent = await signClaim(radicleClaim);
  const jwkEvent = await signClaim(jwkClaim);

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
  const childChallenge = challenge(child, "74".repeat(16));
  const childContext = activeContext(child, nostrProof(childChallenge), childChallenge);

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

  const namedRevoker: KeyRef = radicleSubject;
  const descriptive = makeClaim({
    claim_class: "descriptive",
    expires_at: undefined,
    subject: nostrSubject,
    revokers: [namedRevoker],
  });
  const edRevocationUnsigned = {
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

  const copiedJwkRevocationUnsigned = {
    claim_id: jwkClaim.claim_id,
    revoked_at: now + 17,
    reason_code: "claim-revoked",
  };
  const copiedProtected = Buffer.from(jcsCanonicalize({ alg: "EdDSA" }), "utf8").toString("base64url");
  const copiedInput = `${copiedProtected}.${Buffer.from(revocationProofPayload(copiedJwkRevocationUnsigned), "utf8").toString("base64url")}`;
  const validJwkRevocation: ClaimRevocation = {
    ...copiedJwkRevocationUnsigned,
    revoker: jwkSubject,
    proof: {
      type: "jwk-jws",
      jwk: publicJwk,
      protected: copiedProtected,
      signature: Buffer.from(ed25519.sign(utf8Bytes(copiedInput), hexToBytes(deviceOne.private_key))).toString("base64url"),
    },
  };
  const copiedTarget = "99".repeat(32);
  const copiedJwkRevocation = { ...validJwkRevocation, claim_id: copiedTarget };
  const copiedJwkEvent = await signEvent({
    secretKey: epoch.private_key,
    auxRand: AUX_RAND,
    created_at: copiedJwkRevocation.revoked_at,
    kind: 31014,
    tags: [["d", copiedTarget]],
    content: jcsCanonicalize(copiedJwkRevocation),
  });

  const publicClaim = makeClaim({
    claim_class: "descriptive",
    expires_at: undefined,
    visibility: "public",
  });
  const publicEvent = await signClaim(publicClaim);
  const pairwiseClaim = makeClaim({ visibility: "pairwise-private" });
  const pairwiseEvent = await signClaim(pairwiseClaim);
  const pairwiseCiphertext = nip44.v2.encrypt(
    canonicalNip01(pairwiseEvent),
    nip44.v2.utils.getConversationKey(hexToBytes(deviceOnePublishing.private_key), deviceTwoPublishing.pubkey),
    hexToBytes("81".repeat(32)),
  );
  const repositoryClaim = makeClaim({ subject: radicleSubject, visibility: "repository-private" });
  const repositoryEvent = await signClaim(repositoryClaim);
  const ledgerAudienceKey = hexToBytes("82".repeat(32));
  const repositoryCiphertext = nip44.v2.encrypt(canonicalNip01(repositoryEvent), ledgerAudienceKey, hexToBytes("83".repeat(32)));
  const repositoryPath = bytesToHex(hmac(sha256, ledgerAudienceKey, utf8Bytes(repositoryClaim.claim_id)));
  const localClaim = makeClaim({ claim_class: "descriptive", expires_at: undefined, visibility: "local-only" });

  const cases: ClaimCase[] = [
    canonicalCase("001-canonical-nostr-subject.json", "canonical-nostr-subject", nostrClaim, nostrEvent, nostrChallenge, nostrProof(nostrChallenge), "nostr-bip340-v1"),
    canonicalCase("002-canonical-radicle-nid-subject.json", "canonical-radicle-nid-subject", radicleClaim, radicleEvent, radicleChallenge, edProof(radicleChallenge), "radicle-ed25519-v1"),
    canonicalCase("003-canonical-jwk-thumbprint-subject.json", "canonical-jwk-thumbprint-subject", jwkClaim, jwkEvent, jwkChallenge, jwkProof(jwkChallenge), "jwk-jws-v1"),
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
      input: { claim: nostrClaim, issuer_core_authority: "current", repository_confirmed: true, subject_proof: { challenge: nostrChallenge, proof: nostrProof(nostrChallenge) } },
      expected_output: { verdict: "accept", normalized: authorizeWithClaim(nostrClaim, [nostrClaim], activeContext(nostrClaim, nostrProof(nostrChallenge), nostrChallenge)) },
      decision_trace: eightStages(),
    },
    {
      path: "006-delegated-issuance-active.json",
      vector_id: "delegated-issuance-active",
      description: "A child signed by the parent subject preserves scope, shortens validity, decrements depth, and authorizes only after repository confirmation.",
      input: { chain: [parent, child], issuer_core_authority: "current", repository_confirmed: true, subject_proof: childContext.subject_proof },
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
      input: { depth_chain: depthClaims, cycle: { leaf: child.claim_id, repeated_ancestor: parent.claim_id } },
      expected_output: { verdict: "reject", reason_code: "claim-chain-depth-exceeded", normalized: { cycle_reason_code: "claim-chain-cycle", maximum_edges: 8 } },
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
      description: "A JWK/JWS native proof copied to another claim ID fails before local trust; the same rule binds authorization challenges to nonce and operation.",
      input: { event: copiedJwkEvent, copied_from_claim_id: jwkClaim.claim_id, copied_to_claim_id: copiedTarget, copied_proof: validJwkRevocation.proof },
      expected_output: { verdict: "reject", reason_code: "claim-subject-proof-invalid", normalized: { policy_hook_invoked: false, copied_authorization_proof_also_rejected: true } },
      decision_trace: ["authenticate_jwk_revoker", "verify_exact_jcs_payload", "reject_before_policy"],
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
      input: { claim: nostrClaim, event: selfRevocationEvent, repository_confirmed: false },
      expected_output: { verdict: "reject", reason_code: "claim-revoked", normalized: { allowed: false, state: "revoked", repository_final: false, signer: verifiedSelfRevocation.signer } },
      decision_trace: ["authenticate_revocation", "apply_irreversible_reduction", "skip_provisional_authorization"],
    },
    {
      path: "016-descriptive-subject-rejection.json",
      vector_id: "descriptive-subject-rejection",
      description: "A named Radicle Ed25519 revoker can revoke a descriptive assertion; the subject's separately signed rejection preserves the original provenance rather than erasing it.",
      input: { assertion: descriptive, named_revocation_event: edRevocationEvent, subject_rejection_event: rejectionEvent },
      expected_output: { verdict: "accept", normalized: { named_revocation_authenticated: true, named_revocation_signer: verifiedEdRevocation.signer, subject_rejection_is_separate_claim: true, original_provenance_retained: true } },
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
      input: { outer: { sender_device: deviceOnePublishing.pubkey, recipient_tag: deviceTwoPublishing.pubkey, ciphertext: pairwiseCiphertext }, pinned_nonce: "81".repeat(32) },
      expected_output: { verdict: "accept", normalized: { visibility: "pairwise-private", inner_claim_id: pairwiseClaim.claim_id, outer_claim_metadata_fields: [], repository_backfill: false } },
    },
    {
      path: "019-repository-private-encryption.json",
      vector_id: "repository-private-encryption",
      description: "Repository-private claim bytes and keyed path are opaque under a dedicated ledger audience key.",
      input: { rid: fixtures.radicle_rids.alice, branch: "main", keyed_path: repositoryPath, ciphertext: repositoryCiphertext, key_id: "claim-ledger-audience-v1", pinned_nonce: "83".repeat(32) },
      expected_output: { verdict: "accept", normalized: { visibility: "repository-private", inner_claim_id: repositoryClaim.claim_id, plaintext_metadata_in_path: false, plaintext_metadata_in_commit: false, encrypted_before_storage: true } },
    },
    {
      path: "020-local-only-no-publication.json",
      vector_id: "local-only-no-publication",
      description: "A local-only descriptive claim produces no relay, DR, repository, discovery, or OIDC publication artifact.",
      input: { local_claim: localClaim, requested_visibility: "local-only" },
      expected_output: { verdict: "accept", normalized: { visibility: "local-only", transport_artifacts: [], public_discovery_fields: [] } },
    },
  ];

  return cases.map((testCase) => ({
    relativePath: `claims/${testCase.path}`,
    vector: baseVector({
      vector_id: `claims/${testCase.vector_id}`,
      spec_refs: [CLAIM_REF],
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
