import { createPublicKey, verify as verifyNativeSignature, type JsonWebKey } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/nist";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { type NostrSignedEvent, verifyEventSignature } from "./nostr.js";
import { didKeyFromEd25519 } from "./radicle.js";
import { reasonCodeValues } from "./reason-codes.js";
import {
  validateClaimRevocationSchemaOrThrow,
  validateKeyClaimSchemaOrThrow,
} from "./schema.js";
import {
  evaluateCredentialGeneration,
  type CredentialLedgerBinding,
} from "./credential-generation.js";

export type KeyRef =
  | { type: "nostr-secp256k1"; value: string }
  | { type: "radicle-ed25519-nid"; value: string }
  | { type: "jwk-thumbprint"; value: string };

export type ClaimClass = "descriptive" | "authorization";
export type ClaimVisibility = "public" | "pairwise-private" | "repository-private" | "local-only";
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export const CLAIM_REVOCATION_PROFILE = {
  spec_version: "heterodyne/0.5.0",
  profile_revision: 2,
} as const;

export type DelegationConstraints = {
  namespaces: string[];
  audiences: string[];
  resources: string[];
  remaining_depth: number;
};

export type ClaimSemanticBody = {
  claim_id: string;
  issuer: KeyRef;
  subject: KeyRef;
  claim_class: ClaimClass;
  credential_ledger_persona: string | null;
  credential_ledger_generation: number | null;
  namespace: string;
  name: string;
  value: JsonValue;
  issued_at: number;
  not_before: number;
  expires_at?: number;
  audience?: string[];
  resources?: string[];
  visibility: ClaimVisibility;
  parent_claim_id?: string;
  constraints?: DelegationConstraints;
  revokers?: KeyRef[];
  spec_version: "heterodyne/0.5.0";
  profile_revision: 2;
};

export type KeyProof =
  | { type: "nostr-bip340"; signature: string }
  | { type: "radicle-ed25519"; public_key: string; signature: string }
  | { type: "jwk-jws"; jwk: Record<string, JsonValue>; protected: string; signature: string };

export type ClaimRevocation = {
  claim_id: string;
  revoked_at: number;
  reason_code: string;
  revoker: KeyRef;
  proof?: KeyProof;
  spec_version: "heterodyne/0.5.0";
  profile_revision: 2;
};

export type VerifiedRevocation = ClaimRevocation & {
  signer: KeyRef;
  event_id: string;
  event_created_at: number;
};

export type SubjectProofChallenge = {
  domain: "heterodyne-claim-pop-v1";
  claim_id: string;
  nonce: string;
  audience: string;
  resource: string;
  operation: string;
  issued_at: number;
  expires_at: number;
};

export type ClaimEnvelopeContext = {
  issuer_authorized: boolean;
  profile_revision: 2;
  credential_ledger: CredentialLedgerBinding;
  existing_semantic_body?: ClaimSemanticBody;
};

export type ClaimState =
  | "invalid"
  | "untrusted"
  | "provisional"
  | "active"
  | "expired"
  | "revoked"
  | "conflicted";

/**
 * Task 3 needs this evidence in addition to the original plan's abbreviated
 * context shape so the approved stage-2 Core/KEL check is explicit rather
 * than being inferred from local trust policy.
 */
export type ClaimAuthorityEvidence = {
  claim_id: string;
  issuer: KeyRef;
  event_id: string;
  envelope_valid: boolean;
  core_kel_authority_valid: boolean;
  credential_ledger_persona: string | null;
  credential_ledger_generation: number | null;
  verified_at: number;
  valid_until: number;
};

export type RevocationAuthorityEvidence = {
  event_id: string;
  claim_id: string;
  signer: KeyRef;
  authority: "active-ancestor-issuer" | "persona-epoch" | "persona-cold-root";
  authority_claim_id?: string;
  valid_from: number;
  valid_until: number;
  core_kel_authority_valid: boolean;
};

export type ClaimVerificationContext = {
  now: number;
  audience: string;
  resource: string;
  requested_namespace: string;
  requested_operation: string;
  expected_nonce: string;
  used_nonces: Set<string>;
  trusted_issuers: KeyRef[];
  credential_ledger: CredentialLedgerBinding;
  claim_authority_evidence: Map<string, ClaimAuthorityEvidence>;
  revocation_authority_evidence: Map<string, RevocationAuthorityEvidence>;
  repository_confirmed: Set<string>;
  repository_conflicted: Set<string>;
  revocations: VerifiedRevocation[];
  subject_proof: { key: KeyRef; challenge: SubjectProofChallenge; proof: KeyProof } | null;
};

export type AuthorizationDecision = {
  allowed: boolean;
  state: ClaimState;
  reason_code: string | null;
};

type RevocationProofBody = Pick<
  ClaimRevocation,
  "claim_id" | "revoked_at" | "reason_code" | "spec_version" | "profile_revision"
>;

const CLAIM_KIND = 31013;
const REVOCATION_KIND = 31014;
const CLAIM_ID_PATTERN = /^[0-9a-f]{64}$/;
const LOWER_HEX_32_PATTERN = /^[0-9a-f]{64}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const REGISTERED_REASON_CODES = new Set(reasonCodeValues());
const PRIVATE_JWK_MEMBERS = new Set(["d", "k", "p", "q", "dp", "dq", "qi", "oth"]);
const REMOTE_JWK_MEMBERS = new Set(["jku", "x5u"]);
const NIP01_SIGNED_EVENT_FIELDS = ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"];

export function computeClaimId(body: Omit<ClaimSemanticBody, "claim_id">): string {
  const { claim_id: _omitted, ...semantic } = body as Omit<ClaimSemanticBody, "claim_id"> & {
    claim_id?: unknown;
  };
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize(semantic))));
}

export function validateClaimId(body: ClaimSemanticBody): void {
  if (!CLAIM_ID_PATTERN.test(body.claim_id)) {
    throw new Error("claim_id must be lowercase 64-character hexadecimal");
  }
  if (body.claim_id !== computeClaimId(body)) {
    throw new Error("claim-id-mismatch: claim_id does not match the canonical semantic body");
  }
}

export function validateClaimEnvelope(
  event: NostrSignedEvent,
  context: ClaimEnvelopeContext,
): ClaimSemanticBody {
  assertNip01EventStructure(event);
  assertAddressedCommsEvent(event, CLAIM_KIND);
  const parsed = parseCanonicalContent(event.content, "claim") as unknown;
  if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) &&
      !Object.prototype.hasOwnProperty.call(parsed, "credential_ledger_generation")) {
    throw new Error("credential_generation_missing");
  }
  validateKeyClaimSchemaOrThrow(parsed);
  const body = parsed as ClaimSemanticBody;
  validateKeyRef(body.issuer);
  validateKeyRef(body.subject);
  for (const revoker of body.revokers ?? []) validateKeyRef(revoker);
  if (body.issuer.type !== "nostr-secp256k1" || body.issuer.value !== event.pubkey) {
    throw new Error("claim-key-reference-invalid: outer Nostr signer must equal the typed claim issuer");
  }
  validateClaimId(body);
  assertSingleAddress(event, body.claim_id);
  assertOuterSignature(event);
  if (context.profile_revision !== 2 || body.profile_revision !== context.profile_revision) {
    throw new Error("claim-schema-invalid: registry revision does not match the supplied context");
  }
  if (!context.issuer_authorized) {
    throw new Error("claim-issuer-authority-invalid: Core did not authorize the issuer at issuance time");
  }
  if (body.claim_class === "authorization") {
    const generation = evaluateCredentialGeneration(body, context.credential_ledger);
    if (!generation.valid) throw new Error(generation.reason_code);
  }
  if (
    context.existing_semantic_body !== undefined &&
    jcsCanonicalize(context.existing_semantic_body) !== jcsCanonicalize(body)
  ) {
    throw new Error("claim-repository-conflict: semantic body at an existing address must be identical");
  }
  return body;
}

export function revocationProofPayload(body: RevocationProofBody): string {
  return jcsCanonicalize({
    domain: "heterodyne-claim-revocation-v1",
    claim_id: body.claim_id,
    revoked_at: body.revoked_at,
    reason_code: body.reason_code,
    spec_version: body.spec_version,
    profile_revision: body.profile_revision,
  });
}

export function validateClaimRevocationEnvelope(event: NostrSignedEvent): VerifiedRevocation {
  assertNip01EventStructure(event);
  assertAddressedCommsEvent(event, REVOCATION_KIND);
  const parsed = parseCanonicalContent(event.content, "revocation") as unknown;
  validateClaimRevocationSchemaOrThrow(parsed);
  const revocation = parsed as ClaimRevocation;
  validateKeyRef(revocation.revoker);
  assertSingleAddress(event, revocation.claim_id);
  if (!REGISTERED_REASON_CODES.has(revocation.reason_code)) {
    throw new Error(`claim-schema-invalid: unregistered reason_code ${revocation.reason_code}`);
  }
  if (revocation.revoked_at !== event.created_at) {
    throw new Error("claim-schema-invalid: revoked_at must equal signed event created_at");
  }
  assertOuterSignature(event);
  verifyRevocationProof(event, revocation);
  return {
    ...revocation,
    signer: revocation.revoker,
    event_id: event.id,
    event_created_at: event.created_at,
  };
}

export function validateKeyRef(key: KeyRef): void {
  if (key.type === "nostr-secp256k1") {
    if (!LOWER_HEX_32_PATTERN.test(key.value)) {
      throw new Error("claim-key-reference-invalid: Nostr key must be lowercase 32-byte x-only hex");
    }
    try {
      schnorr.utils.lift_x(BigInt(`0x${key.value}`));
    } catch {
      throw new Error("claim-key-reference-invalid: Nostr key is not a secp256k1 x-coordinate");
    }
    return;
  }
  if (key.type === "radicle-ed25519-nid") {
    decodeEd25519Nid(key.value);
    return;
  }
  if (key.type === "jwk-thumbprint") {
    if (!/^[A-Za-z0-9_-]{43}$/.test(key.value)) {
      throw new Error("claim-key-reference-invalid: JWK thumbprint must be a canonical SHA-256 base64url value");
    }
    const decoded = decodeCanonicalBase64url(key.value, "JWK thumbprint");
    if (decoded.length !== 32) {
      throw new Error("claim-key-reference-invalid: JWK thumbprint must decode to exactly 32 bytes");
    }
    return;
  }
  throw new Error("claim-key-reference-invalid: unsupported typed key reference");
}

/**
 * Resolves a claim chain deterministically from its leaf to its root and
 * returns the canonical root-to-leaf order used by every later decision.
 */
export function verifyClaimChain(
  leaf: ClaimSemanticBody,
  claimsById: Map<string, ClaimSemanticBody>,
): ClaimSemanticBody[] {
  const reversed: ClaimSemanticBody[] = [];
  const seen = new Set<string>();
  let current = leaf;
  let edges = 0;
  while (true) {
    if (seen.has(current.claim_id)) {
      throw new Error(`claim-chain-cycle: repeated claim ${current.claim_id}`);
    }
    seen.add(current.claim_id);
    reversed.push(current);
    if (current.parent_claim_id === undefined) break;
    edges += 1;
    if (edges > 8) {
      throw new Error("claim-chain-depth-exceeded: issuance chain exceeds eight edges");
    }
    const parent = claimsById.get(current.parent_claim_id);
    if (parent === undefined) {
      throw new Error(`claim-delegation-not-authorized: missing ancestor ${current.parent_claim_id}`);
    }
    current = parent;
  }
  const chain = reversed.reverse();
  validateResolvedChain(leaf, chain);
  return chain;
}

export function subjectProofPayload(challenge: SubjectProofChallenge): string {
  return jcsCanonicalize(challenge);
}

export function resolveClaimState(
  leaf: ClaimSemanticBody,
  chain: ClaimSemanticBody[],
  context: ClaimVerificationContext,
): ClaimState {
  return evaluateClaim(leaf, chain, context).state;
}

export function authorizeWithClaim(
  leaf: ClaimSemanticBody,
  chain: ClaimSemanticBody[],
  context: ClaimVerificationContext,
): AuthorizationDecision {
  const result = evaluateClaim(leaf, chain, context);
  return {
    allowed: result.state === "active" && leaf.claim_class === "authorization",
    state: result.state,
    reason_code: result.reason_code,
  };
}

type ClaimEvaluation = Pick<AuthorizationDecision, "state" | "reason_code">;

/** Implements the approved eight-stage authentication-before-policy order. */
function evaluateClaim(
  leaf: ClaimSemanticBody,
  chain: ClaimSemanticBody[],
  context: ClaimVerificationContext,
): ClaimEvaluation {
  for (const claim of chain) {
    if (!Object.prototype.hasOwnProperty.call(claim, "credential_ledger_generation")) {
      return { state: "invalid", reason_code: "credential_generation_missing" };
    }
    if (claim.claim_class === "authorization") {
      const generation = evaluateCredentialGeneration(claim, context.credential_ledger);
      if (!generation.valid) return { state: "invalid", reason_code: generation.reason_code };
    } else if (claim.credential_ledger_persona !== null || claim.credential_ledger_generation !== null) {
      return { state: "invalid", reason_code: "credential_schema_invalid" };
    }
  }

  // 1. Canonical semantic content and claim identifiers.
  try {
    for (const claim of chain) {
      validateClaimId(claim);
      validateKeyRef(claim.issuer);
      validateKeyRef(claim.subject);
    }
    if (chain.length === 0 || !sameClaim(chain[chain.length - 1], leaf)) {
      throw new Error("claim-delegation-not-authorized: supplied chain does not terminate at leaf");
    }
  } catch (error) {
    return invalidEvaluation(error);
  }

  // 2. Require explicit, current, claim-bound envelope and Core/KEL evidence.
  for (const claim of chain) {
    const evidence = context.claim_authority_evidence.get(claim.claim_id);
    if (!validClaimAuthorityEvidence(claim, evidence, context.now)) {
      return { state: "invalid", reason_code: "claim-issuer-authority-invalid" };
    }
  }

  // 3-4. Resolve the issuance chain, then prove attenuation/depth.
  try {
    validateResolvedChain(leaf, chain);
  } catch (error) {
    return invalidEvaluation(error);
  }

  // 5. Time, audience, namespace, resource, and subject type.
  if (chain.some((claim) => context.now < claim.not_before)) {
    return { state: "invalid", reason_code: "claim-issuer-authority-invalid" };
  }
  if (chain.some((claim) => claim.expires_at !== undefined && context.now >= claim.expires_at)) {
    return { state: "expired", reason_code: "claim-expired" };
  }
  if (context.requested_namespace !== leaf.namespace) {
    return { state: "invalid", reason_code: "claim-attenuation-violation" };
  }
  if (
    leaf.claim_class === "authorization" &&
    (
      leaf.audience === undefined || leaf.audience.length === 0 ||
      leaf.resources === undefined || leaf.resources.length === 0
    )
  ) {
    return { state: "invalid", reason_code: "claim-attenuation-violation" };
  }
  if (!matchesRestriction(leaf.audience, context.audience) || !matchesRestriction(leaf.resources, context.resource)) {
    return { state: "invalid", reason_code: "claim-attenuation-violation" };
  }
  try {
    validateKeyRef(leaf.subject);
  } catch (error) {
    return invalidEvaluation(error);
  }

  // 6. Authenticated monotonic reductions win before repository confirmation.
  if (isRevoked(chain, context)) {
    return { state: "revoked", reason_code: "claim-revoked" };
  }
  if (chain.some((claim) => context.repository_conflicted.has(claim.claim_id))) {
    return { state: "conflicted", reason_code: "claim-repository-conflict" };
  }
  if (chain.some((claim) =>
    claim.claim_class === "authorization" &&
    !context.repository_confirmed.has(claim.claim_id)
  )) {
    return { state: "provisional", reason_code: "claim-repository-unconfirmed" };
  }

  // 7. Authorization requires fresh proof by the exact subject key.
  if (leaf.claim_class === "authorization") {
    if (context.subject_proof === null) {
      return { state: "invalid", reason_code: "claim-subject-proof-required" };
    }
    try {
      verifySubjectProof(leaf, context);
    } catch {
      return { state: "invalid", reason_code: "claim-subject-proof-invalid" };
    }
  }

  // 8. Local trust/release policy is deliberately last.
  const trustAnchor = chain[0].issuer;
  if (!context.trusted_issuers.some((candidate) => sameKeyRef(candidate, trustAnchor))) {
    return { state: "untrusted", reason_code: "claim-issuer-untrusted" };
  }
  return { state: "active", reason_code: null };
}

function validateResolvedChain(leaf: ClaimSemanticBody, chain: ClaimSemanticBody[]): void {
  if (chain.length === 0 || chain.length > 9) {
    throw new Error("claim-chain-depth-exceeded: issuance chain exceeds eight edges");
  }
  if (!sameClaim(chain[chain.length - 1], leaf)) {
    throw new Error("claim-delegation-not-authorized: supplied chain does not terminate at leaf");
  }
  const ids = new Set<string>();
  for (let index = 0; index < chain.length; index += 1) {
    const claim = chain[index];
    if (ids.has(claim.claim_id)) throw new Error(`claim-chain-cycle: repeated claim ${claim.claim_id}`);
    ids.add(claim.claim_id);
    if (index === 0) {
      if (claim.parent_claim_id !== undefined) {
        throw new Error(`claim-delegation-not-authorized: missing ancestor ${claim.parent_claim_id}`);
      }
      continue;
    }
    const parent = chain[index - 1];
    if (claim.parent_claim_id !== parent.claim_id || !sameKeyRef(claim.issuer, parent.subject)) {
      throw new Error("claim-delegation-not-authorized: parent subject did not authorize the child issuer");
    }
    if (parent.claim_class !== "authorization" || parent.constraints === undefined || parent.constraints.remaining_depth < 1) {
      throw new Error("claim-delegation-not-authorized: parent lacks an explicit claim-issuance capability");
    }
    assertAttenuated(parent, claim);
  }
}

function assertAttenuated(parent: ClaimSemanticBody, child: ClaimSemanticBody): void {
  const constraints = parent.constraints!;
  if (
    (child.claim_class === "authorization" &&
      (child.credential_ledger_persona !== parent.credential_ledger_persona ||
       child.credential_ledger_generation !== parent.credential_ledger_generation)) ||
    child.namespace !== parent.namespace ||
    child.name !== parent.name ||
    jcsCanonicalize(child.value) !== jcsCanonicalize(parent.value) ||
    !constraints.namespaces.includes(child.namespace)
  ) {
    throw new Error("claim-attenuation-violation: child widened namespace, name, or atomic value scope");
  }
  if (child.issued_at < parent.issued_at || child.not_before < parent.not_before) {
    throw new Error("claim-attenuation-violation: child extended the lower validity bound");
  }
  if (
    parent.expires_at !== undefined &&
    (child.expires_at === undefined || child.expires_at > parent.expires_at)
  ) {
    throw new Error("claim-attenuation-violation: child extended the expiry bound");
  }
  if (!isSubset(child.audience, parent.audience) || !isSubset(child.audience, constraints.audiences)) {
    throw new Error("claim-attenuation-violation: child widened audience scope");
  }
  if (!isSubset(child.resources, parent.resources) || !isSubset(child.resources, constraints.resources)) {
    throw new Error("claim-attenuation-violation: child widened resource scope");
  }
  if (child.constraints !== undefined) {
    if (child.constraints.remaining_depth !== constraints.remaining_depth - 1) {
      throw new Error("claim-attenuation-violation: child did not decrement remaining depth exactly once");
    }
    if (
      !isSubset(child.constraints.namespaces, constraints.namespaces) ||
      !isSubset(child.constraints.audiences, constraints.audiences) ||
      !isSubset(child.constraints.resources, constraints.resources)
    ) {
      throw new Error("claim-attenuation-violation: child widened delegation constraints");
    }
  }
}

function verifySubjectProof(leaf: ClaimSemanticBody, context: ClaimVerificationContext): void {
  const presented = context.subject_proof!;
  const challenge = presented.challenge;
  if (
    !sameKeyRef(presented.key, leaf.subject) ||
    challenge.domain !== "heterodyne-claim-pop-v1" ||
    challenge.claim_id !== leaf.claim_id ||
    challenge.audience !== context.audience ||
    challenge.resource !== context.resource ||
    challenge.operation !== context.requested_operation ||
    challenge.nonce !== context.expected_nonce ||
    context.used_nonces.has(context.expected_nonce) ||
    typeof challenge.operation !== "string" || challenge.operation.length === 0 ||
    !/^[0-9a-f]{32,128}$/.test(challenge.nonce) ||
    !Number.isSafeInteger(challenge.issued_at) ||
    !Number.isSafeInteger(challenge.expires_at) ||
    challenge.expires_at <= challenge.issued_at ||
    challenge.expires_at - challenge.issued_at > 60 ||
    context.now < challenge.issued_at ||
    context.now >= challenge.expires_at
  ) {
    throw new Error("claim-subject-proof-invalid: challenge binding or freshness failed");
  }
  const payload = subjectProofPayload(challenge);
  if (leaf.subject.type === "nostr-secp256k1") {
    if (presented.proof.type !== "nostr-bip340") throw new Error("proof suite mismatch");
    const signature = parseLowerHex(presented.proof.signature, 64, "BIP-340 signature");
    let valid = false;
    try {
      valid = schnorr.verify(signature, utf8Bytes(payload), leaf.subject.value);
    } catch {
      valid = false;
    }
    if (!valid) throw new Error("claim-subject-proof-invalid: BIP-340 proof is invalid");
    return;
  }
  if (leaf.subject.type === "radicle-ed25519-nid") {
    if (presented.proof.type !== "radicle-ed25519") throw new Error("proof suite mismatch");
    const publicKey = parseLowerHex(presented.proof.public_key, 32, "Ed25519 public key");
    if (didKeyFromEd25519(presented.proof.public_key) !== leaf.subject.value) {
      throw new Error("claim-subject-proof-invalid: Ed25519 key does not derive subject NID");
    }
    const signature = parseLowerHex(presented.proof.signature, 64, "Ed25519 signature");
    if (!ed25519.verify(signature, utf8Bytes(payload), publicKey)) {
      throw new Error("claim-subject-proof-invalid: Ed25519 proof is invalid");
    }
    return;
  }
  if (presented.proof.type !== "jwk-jws") throw new Error("proof suite mismatch");
  if (computeJwkThumbprint(presented.proof.jwk) !== leaf.subject.value) {
    throw new Error("claim-subject-proof-invalid: JWK thumbprint does not match subject");
  }
  verifyDetachedJws(presented.proof, payload);
}

function isRevoked(chain: ClaimSemanticBody[], context: ClaimVerificationContext): boolean {
  for (let targetIndex = 0; targetIndex < chain.length; targetIndex += 1) {
    const target = chain[targetIndex];
    for (const revocation of context.revocations) {
      if (
        revocation.claim_id !== target.claim_id ||
        revocation.event_created_at !== revocation.revoked_at ||
        revocation.revoked_at > context.now ||
        revocation.revoked_at < target.issued_at ||
        !sameKeyRef(revocation.revoker, revocation.signer)
      ) continue;
      const directIssuer = sameKeyRef(target.issuer, revocation.signer);
      const superiorClaims = chain.slice(0, targetIndex);
      const superior = superiorClaims.find((claim) => sameKeyRef(claim.issuer, revocation.signer));
      const external = context.revocation_authority_evidence.get(revocation.event_id);
      const superiorAuthorized = superior !== undefined && validRevocationAuthorityEvidence(
        revocation,
        external,
        "active-ancestor-issuer",
        superior.claim_id,
      );
      const personaAuthorized = external !== undefined &&
        (external.authority === "persona-epoch" || external.authority === "persona-cold-root") &&
        validRevocationAuthorityEvidence(revocation, external, external.authority);
      if (target.claim_class === "authorization") {
        if (
          sameKeyRef(revocation.signer, target.subject) ||
          directIssuer ||
          superiorAuthorized ||
          personaAuthorized
        ) return true;
      } else if (
        directIssuer ||
        superiorAuthorized ||
        (target.revokers ?? []).some((revoker) => sameKeyRef(revoker, revocation.signer))
      ) return true;
    }
  }
  return false;
}

function validClaimAuthorityEvidence(
  claim: ClaimSemanticBody,
  evidence: ClaimAuthorityEvidence | undefined,
  now: number,
): evidence is ClaimAuthorityEvidence {
  return evidence !== undefined &&
    evidence.claim_id === claim.claim_id &&
    sameKeyRef(evidence.issuer, claim.issuer) &&
    CLAIM_ID_PATTERN.test(evidence.event_id) &&
    evidence.envelope_valid &&
    evidence.core_kel_authority_valid &&
    evidence.credential_ledger_persona === claim.credential_ledger_persona &&
    evidence.credential_ledger_generation === claim.credential_ledger_generation &&
    Number.isSafeInteger(evidence.verified_at) &&
    Number.isSafeInteger(evidence.valid_until) &&
    evidence.verified_at <= now &&
    now < evidence.valid_until;
}

function validRevocationAuthorityEvidence(
  revocation: VerifiedRevocation,
  evidence: RevocationAuthorityEvidence | undefined,
  authority: RevocationAuthorityEvidence["authority"],
  authorityClaimId?: string,
): evidence is RevocationAuthorityEvidence {
  return evidence !== undefined &&
    evidence.event_id === revocation.event_id &&
    evidence.claim_id === revocation.claim_id &&
    sameKeyRef(evidence.signer, revocation.signer) &&
    evidence.authority === authority &&
    (authorityClaimId === undefined
      ? evidence.authority_claim_id === undefined
      : evidence.authority_claim_id === authorityClaimId) &&
    evidence.core_kel_authority_valid &&
    Number.isSafeInteger(evidence.valid_from) &&
    Number.isSafeInteger(evidence.valid_until) &&
    revocation.event_created_at === revocation.revoked_at &&
    evidence.valid_from <= revocation.event_created_at &&
    revocation.event_created_at < evidence.valid_until;
}

function matchesRestriction(restriction: string[] | undefined, value: string): boolean {
  return restriction === undefined || restriction.includes(value);
}

function isSubset(child: string[] | undefined, parent: string[] | undefined): boolean {
  if (parent === undefined) return true;
  if (child === undefined) return false;
  const allowed = new Set(parent);
  return child.every((value) => allowed.has(value));
}

function sameKeyRef(left: KeyRef, right: KeyRef): boolean {
  return left.type === right.type && left.value === right.value;
}

function sameClaim(left: ClaimSemanticBody, right: ClaimSemanticBody): boolean {
  return left.claim_id === right.claim_id && jcsCanonicalize(left) === jcsCanonicalize(right);
}

function invalidEvaluation(error: unknown, fallback = "claim-schema-invalid"): ClaimEvaluation {
  const message = error instanceof Error ? error.message : "";
  const code = message.match(/\b(claim-[a-z-]+)\b/)?.[1] ?? fallback;
  return { state: "invalid", reason_code: code };
}

export function computeJwkThumbprint(jwk: Record<string, JsonValue>): string {
  return inspectPublicJwk(jwk).thumbprint;
}

function assertAddressedCommsEvent(event: NostrSignedEvent, expectedKind: number): void {
  if (event.kind !== expectedKind) {
    throw new Error(`claim-schema-invalid: expected kind:${expectedKind}`);
  }
}

function assertNip01EventStructure(event: NostrSignedEvent): void {
  if (event === null || Array.isArray(event) || typeof event !== "object") {
    throw new Error("claim-event-signature-invalid: NIP-01 event structure must be an object");
  }
  const fields = Reflect.ownKeys(event);
  if (
    fields.some((field) => typeof field !== "string") ||
    fields.length !== NIP01_SIGNED_EVENT_FIELDS.length ||
    [...(fields as string[])].sort().some((field, index) => field !== NIP01_SIGNED_EVENT_FIELDS[index])
  ) {
    throw new Error("claim-event-signature-invalid: NIP-01 signed event has unexpected or missing fields");
  }
  if (
    typeof event.id !== "string" ||
    typeof event.pubkey !== "string" ||
    !LOWER_HEX_32_PATTERN.test(event.id) ||
    !LOWER_HEX_32_PATTERN.test(event.pubkey)
  ) {
    throw new Error("claim-event-signature-invalid: NIP-01 id and pubkey require lowercase 64-hex encoding");
  }
  if (typeof event.sig !== "string" || !/^[0-9a-f]{128}$/.test(event.sig)) {
    throw new Error("claim-event-signature-invalid: NIP-01 sig requires lowercase 128-hex encoding");
  }
  if (!Number.isSafeInteger(event.created_at) || event.created_at < 0) {
    throw new Error("claim-event-signature-invalid: NIP-01 created_at must be a nonnegative safe integer");
  }
  if (!Number.isInteger(event.kind) || typeof event.content !== "string" || !Array.isArray(event.tags)) {
    throw new Error("claim-event-signature-invalid: NIP-01 kind, content, or tags has the wrong type");
  }
  for (const tag of event.tags) {
    if (!Array.isArray(tag) || tag.length === 0 || tag.some((member) => typeof member !== "string")) {
      throw new Error("claim-event-signature-invalid: every NIP-01 tag must be a non-empty string array");
    }
  }
}

function assertSingleAddress(event: NostrSignedEvent, expected: string): void {
  if (
    event.tags.length !== 1 ||
    event.tags[0].length !== 2 ||
    event.tags[0][0] !== "d" ||
    event.tags[0][1] !== expected
  ) {
    throw new Error("claim-schema-invalid: event tags must be exactly [[\"d\",claim_id]]");
  }
}

function parseCanonicalContent(content: string, label: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content) as unknown;
  } catch {
    throw new Error(`claim-schema-invalid: ${label} content is not JSON`);
  }
  let canonical: string;
  try {
    canonical = jcsCanonicalize(parsed);
  } catch (error) {
    throw new Error(`claim-schema-invalid: ${error instanceof Error ? error.message : "invalid JCS content"}`);
  }
  if (content !== canonical) {
    throw new Error(`claim-schema-invalid: ${label} content is not canonical RFC 8785 JCS`);
  }
  return parsed;
}

function assertOuterSignature(event: NostrSignedEvent): void {
  try {
    if (!verifyEventSignature(event)) throw new Error("invalid");
  } catch {
    throw new Error("claim-event-signature-invalid: invalid canonical NIP-01 id or BIP-340 signature");
  }
}

function verifyRevocationProof(event: NostrSignedEvent, revocation: ClaimRevocation): void {
  if (revocation.revoker.type === "nostr-secp256k1") {
    if (revocation.proof !== undefined) {
      throw new Error("claim-key-reference-invalid: Nostr revocation uses only the outer event signature");
    }
    if (revocation.revoker.value !== event.pubkey) {
      throw new Error("claim-key-reference-invalid: Nostr revoker does not match the outer event signer");
    }
    return;
  }

  const payload = revocationProofPayload(revocation);
  if (revocation.revoker.type === "radicle-ed25519-nid") {
    const proof = revocation.proof;
    if (proof?.type !== "radicle-ed25519") {
      throw new Error("claim-key-reference-invalid: Radicle revoker requires a radicle-ed25519 proof");
    }
    const publicKey = parseLowerHex(proof.public_key, 32, "Ed25519 public key");
    if (didKeyFromEd25519(proof.public_key) !== revocation.revoker.value) {
      throw new Error("claim-key-reference-invalid: Ed25519 public key does not derive the named NID");
    }
    const signature = parseLowerHex(proof.signature, 64, "Ed25519 signature");
    let valid = false;
    try {
      valid = ed25519.verify(signature, utf8Bytes(payload), publicKey);
    } catch {
      valid = false;
    }
    if (!valid) throw new Error("claim-subject-proof-invalid: Ed25519 revocation proof is invalid");
    return;
  }

  const proof = revocation.proof;
  if (proof?.type !== "jwk-jws") {
    throw new Error("claim-key-reference-invalid: JWK revoker requires a jwk-jws proof");
  }
  if (computeJwkThumbprint(proof.jwk) !== revocation.revoker.value) {
    throw new Error("claim-key-reference-invalid: embedded JWK does not match the named thumbprint");
  }
  verifyDetachedJws(proof, payload);
}

function decodeEd25519Nid(value: string): Uint8Array {
  if (!value.startsWith("did:key:z")) {
    throw new Error("claim-key-reference-invalid: Radicle NID must use did:key base58btc");
  }
  let decoded: Uint8Array;
  try {
    decoded = base58.decode(value.slice("did:key:z".length));
  } catch {
    throw new Error("claim-key-reference-invalid: Radicle NID has invalid base58btc");
  }
  if (
    decoded.length !== 34 ||
    decoded[0] !== 0xed ||
    decoded[1] !== 0x01 ||
    `did:key:z${base58.encode(decoded)}` !== value
  ) {
    throw new Error("claim-key-reference-invalid: Radicle NID is not a canonical Ed25519 did:key");
  }
  return decoded.slice(2);
}

function parseLowerHex(value: string, bytes: number, label: string): Uint8Array {
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) {
    throw new Error(`claim-key-reference-invalid: ${label} must be lowercase ${bytes}-byte hex`);
  }
  return hexToBytes(value);
}

function thumbprintMembers(jwk: Record<string, JsonValue>): Record<string, string> {
  const kty = requireJwkString(jwk, "kty");
  if (kty === "RSA") {
    const n = requireBase64urlUInt(jwk, "n");
    const e = requireBase64urlUInt(jwk, "e");
    const modulusBits = (n.bytes.length - 1) * 8 + (32 - Math.clz32(n.bytes[0]));
    if (modulusBits < 2048) {
      throw new Error("claim-key-reference-invalid: RSA modulus must be at least 2048 bits");
    }
    if ((n.bytes[n.bytes.length - 1] & 1) === 0) {
      throw new Error("claim-key-reference-invalid: RSA modulus is not a valid odd public modulus");
    }
    const exponent = bytesToBigInt(e.bytes);
    if (exponent < 3n || (exponent & 1n) === 0n) {
      throw new Error("claim-key-reference-invalid: RSA exponent is not a valid odd public exponent");
    }
    return { e: e.value, kty, n: n.value };
  }
  if (kty === "EC") {
    const crv = requireJwkString(jwk, "crv");
    if (crv !== "P-256") {
      throw new Error(`claim-key-reference-invalid: unsupported EC curve ${crv}`);
    }
    const x = requireExactBase64urlMember(jwk, "x", 32);
    const y = requireExactBase64urlMember(jwk, "y", 32);
    const encoded = new Uint8Array(65);
    encoded[0] = 0x04;
    encoded.set(x.bytes, 1);
    encoded.set(y.bytes, 33);
    try {
      p256.Point.fromBytes(encoded).assertValidity();
    } catch {
      throw new Error("claim-key-reference-invalid: P-256 coordinates do not encode a valid public point");
    }
    return {
      crv,
      kty,
      x: x.value,
      y: y.value,
    };
  }
  if (kty === "OKP") {
    const crv = requireJwkString(jwk, "crv");
    if (crv !== "Ed25519") {
      throw new Error(`claim-key-reference-invalid: unsupported OKP curve ${crv}`);
    }
    const x = requireExactBase64urlMember(jwk, "x", 32);
    try {
      const point = ed25519.Point.fromBytes(x.bytes, false);
      point.assertValidity();
      if (point.isSmallOrder() || !point.isTorsionFree()) throw new Error("invalid subgroup");
    } catch {
      throw new Error("claim-key-reference-invalid: Ed25519 x does not encode a valid prime-order public point");
    }
    return { crv, kty, x: x.value };
  }
  throw new Error(`claim-key-reference-invalid: unsupported public JWK kty ${kty}`);
}

type PublicJwkProfile = {
  algorithm: "EdDSA" | "RS256" | "ES256";
  thumbprint: string;
};

function inspectPublicJwk(jwk: Record<string, JsonValue>): PublicJwkProfile {
  if (jwk === null || Array.isArray(jwk) || typeof jwk !== "object") {
    throw new Error("claim-key-reference-invalid: JWK must be an object");
  }
  for (const member of PRIVATE_JWK_MEMBERS) {
    if (Object.prototype.hasOwnProperty.call(jwk, member)) {
      throw new Error(`claim-key-reference-invalid: embedded JWK contains private key member ${member}`);
    }
  }
  for (const member of REMOTE_JWK_MEMBERS) {
    if (Object.prototype.hasOwnProperty.call(jwk, member)) {
      throw new Error(`claim-key-reference-invalid: embedded JWK contains prohibited remote-key metadata ${member}`);
    }
  }
  const required = thumbprintMembers(jwk);
  const kty = required.kty;
  const algorithm = kty === "OKP" ? "EdDSA" : kty === "EC" ? "ES256" : "RS256";
  const allowed = new Set([...Object.keys(required), "alg", "use", "key_ops", "kid"]);
  for (const member of Object.keys(jwk)) {
    if (!allowed.has(member)) {
      throw new Error(`claim-key-reference-invalid: embedded JWK contains unrecognized member ${member}`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(jwk, "use") && jwk.use !== "sig") {
    throw new Error("claim-key-reference-invalid: JWK use metadata must be the string sig");
  }
  if (Object.prototype.hasOwnProperty.call(jwk, "key_ops")) {
    const operations = jwk.key_ops;
    if (
      !Array.isArray(operations) ||
      operations.some((operation) => typeof operation !== "string") ||
      new Set(operations).size !== operations.length ||
      operations.length !== 1 ||
      operations[0] !== "verify"
    ) {
      throw new Error("claim-key-reference-invalid: JWK key_ops must contain exactly one unique verify operation");
    }
  }
  if (Object.prototype.hasOwnProperty.call(jwk, "alg") && jwk.alg !== algorithm) {
    throw new Error(`claim-key-reference-invalid: JWK alg metadata must be exactly ${algorithm}`);
  }
  const thumbprint = Buffer.from(
    sha256(utf8Bytes(jcsCanonicalize(required))),
  ).toString("base64url");
  if (Object.prototype.hasOwnProperty.call(jwk, "kid") && jwk.kid !== thumbprint) {
    throw new Error("claim-key-reference-invalid: JWK kid must equal its RFC 7638 thumbprint");
  }
  return { algorithm, thumbprint };
}

function requireJwkString(jwk: Record<string, JsonValue>, member: string): string {
  const value = jwk[member];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`claim-key-reference-invalid: JWK ${member} must be a non-empty string`);
  }
  return value;
}

function requireExactBase64urlMember(
  jwk: Record<string, JsonValue>,
  member: string,
  bytes: number,
): { value: string; bytes: Buffer } {
  const value = requireJwkString(jwk, member);
  const decoded = decodeCanonicalBase64url(value, `JWK ${member}`);
  if (decoded.length !== bytes) {
    throw new Error(`claim-key-reference-invalid: JWK ${member} must decode to exactly ${bytes} bytes`);
  }
  return { value, bytes: decoded };
}

function requireBase64urlUInt(
  jwk: Record<string, JsonValue>,
  member: string,
): { value: string; bytes: Buffer } {
  const value = requireJwkString(jwk, member);
  const bytes = decodeCanonicalBase64url(value, `JWK ${member}`);
  if (bytes.length > 1 && bytes[0] === 0) {
    throw new Error(`claim-key-reference-invalid: JWK ${member} Base64urlUInt is not minimal (leading zero)`);
  }
  return { value, bytes };
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function decodeCanonicalBase64url(value: string, label: string): Buffer {
  if (!BASE64URL_PATTERN.test(value)) {
    throw new Error(`claim-key-reference-invalid: ${label} is not unpadded base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length === 0 || decoded.toString("base64url") !== value) {
    throw new Error(`claim-key-reference-invalid: ${label} is not canonical base64url`);
  }
  return decoded;
}

function verifyDetachedJws(proof: Extract<KeyProof, { type: "jwk-jws" }>, payload: string): void {
  const protectedBytes = decodeCanonicalBase64url(proof.protected, "JWS protected header");
  const signature = decodeCanonicalBase64url(proof.signature, "JWS signature");
  let header: unknown;
  try {
    header = JSON.parse(protectedBytes.toString("utf8")) as unknown;
  } catch {
    throw new Error("claim-subject-proof-invalid: JWS protected header is not JSON");
  }
  if (
    header === null ||
    Array.isArray(header) ||
    typeof header !== "object" ||
    Object.keys(header).length !== 1 ||
    typeof (header as { alg?: unknown }).alg !== "string"
  ) {
    throw new Error("claim-subject-proof-invalid: JWS protected header must contain only alg");
  }
  if (protectedBytes.toString("utf8") !== jcsCanonicalize(header)) {
    throw new Error("claim-subject-proof-invalid: JWS protected header is ambiguous or non-canonical");
  }
  const alg = (header as { alg: string }).alg;
  const expectedAlgorithm = algorithmForJwk(proof.jwk);
  if (alg !== expectedAlgorithm) {
    throw new Error(`claim-subject-proof-invalid: unsupported or mismatched JWS alg ${alg}`);
  }
  if (typeof proof.jwk.alg === "string" && proof.jwk.alg !== alg) {
    throw new Error("claim-subject-proof-invalid: JWK alg does not match protected alg");
  }
  if (Array.isArray(proof.jwk.key_ops) && !proof.jwk.key_ops.includes("verify")) {
    throw new Error("claim-subject-proof-invalid: JWK key_ops does not permit verification");
  }
  const signingInput = utf8Bytes(
    `${proof.protected}.${Buffer.from(payload, "utf8").toString("base64url")}`,
  );
  let key;
  try {
    key = createPublicKey({ key: proof.jwk as JsonWebKey, format: "jwk" });
  } catch {
    throw new Error("claim-key-reference-invalid: embedded JWK is not a valid public key");
  }
  let valid = false;
  try {
    if (alg === "EdDSA") {
      valid = verifyNativeSignature(null, signingInput, key, signature);
    } else if (alg === "RS256") {
      valid = verifyNativeSignature("RSA-SHA256", signingInput, key, signature);
    } else {
      valid = verifyNativeSignature("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature);
    }
  } catch {
    valid = false;
  }
  if (!valid) throw new Error("claim-subject-proof-invalid: detached JWS revocation proof is invalid");
}

function algorithmForJwk(jwk: Record<string, JsonValue>): "EdDSA" | "RS256" | "ES256" {
  return inspectPublicJwk(jwk).algorithm;
}
