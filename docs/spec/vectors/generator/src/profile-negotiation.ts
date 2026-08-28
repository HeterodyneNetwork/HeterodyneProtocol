import {
  validateRegisteredKindProfile,
  type Registry,
  type RegisteredKindProfile,
} from "./registry.js";
import { stampOwner } from "./stamping.js";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { hexToBytes } from "./hex.js";
import { validateControlFrameSchemaOrThrow } from "./schema.js";
import { validateControlFrameBoundary } from "./control-policy.js";
import { controlGroupAdmission } from "./marmot-admission.js";

export type CurrentProfileWireProbe = Readonly<{
  content_is_heterodyne_json: boolean;
  is_dr_outer: boolean;
  content_profile?: string;
  tags?: readonly (readonly string[])[];
  production_rule?: string;
  transport?: "marmot-inner";
  content_profile_id?: string;
}>;

export type CurrentKindProfileNegotiationInput = RegisteredKindProfile & Readonly<{
  wire_probe: CurrentProfileWireProbe;
}>;

type ProfileNegotiationDecision =
  | Readonly<{
      verdict: "accept";
      normalized: RegisteredKindProfile;
      stamp_owner: ReturnType<typeof stampOwner>;
      wire_binding: string;
    }>
  | Readonly<{
      verdict: "reject";
      reason:
        | "profile-not-registered"
        | "profile-metadata-mismatch"
        | "profile-wire-discriminator-mismatch";
    }>;

function hasTag(
  probe: CurrentProfileWireProbe,
  name: string,
  value: (candidate: string) => boolean,
): boolean {
  return probe.tags?.some((tag) =>
    tag.length === 2
    && tag[0] === name
    && typeof tag[1] === "string"
    && value(tag[1])
  ) === true;
}

function wireBindingMatches(
  discriminator: string,
  probe: CurrentProfileWireProbe,
): boolean {
  if (discriminator.startsWith("content.profile=")) {
    return probe.content_profile === discriminator.slice("content.profile=".length);
  }
  if (discriminator.startsWith("tag:")) {
    const allocation = discriminator.slice("tag:".length);
    const separator = allocation.indexOf("=");
    if (separator <= 0) return false;
    const name = allocation.slice(0, separator);
    const expected = allocation.slice(separator + 1);
    return hasTag(probe, name, (value) => value === expected);
  }
  if (discriminator.startsWith("tags:L=")) {
    const match = /^tags:L=([^,]+),l=<reason>@(.+)$/u.exec(discriminator);
    if (match === null || match[1] !== match[2]) return false;
    const namespace = match[1];
    return hasTag(probe, "L", (value) => value === namespace)
      && hasTag(probe, "l", (value) =>
        value.length > namespace.length + 1 && value.endsWith(`@${namespace}`)
      );
  }
  if (discriminator.startsWith("production-rule:")) {
    return probe.production_rule === discriminator.slice("production-rule:".length);
  }
  if (discriminator === "marmot-inner-only;content=control-frame-v1") {
    return probe.transport === "marmot-inner"
      && probe.content_profile_id === "control-frame-v1";
  }
  return false;
}

function expectedStampOwner(
  registry: Registry,
  profile: RegisteredKindProfile,
  probe: CurrentProfileWireProbe,
): ReturnType<typeof stampOwner> {
  if (probe.is_dr_outer) return null;
  if (profile.stamping) return profile.owner === "control" ? null : profile.owner;
  const kind = registry.kinds.find((candidate) => candidate.kind === profile.kind);
  if (
    kind === undefined
    || kind.allocation_authority !== "heterodyne"
    || kind.base_schema_owner === "nostr"
    || kind.base_schema_owner === "control"
  ) return null;
  return kind.base_schema_owner;
}

/**
 * Resolves one exact registered kind/profile tuple and validates the tuple's
 * declared wire discriminator before applying live stamping negotiation.
 */
export function validateCurrentKindProfileNegotiation(
  registry: Registry,
  value: unknown,
): ProfileNegotiationDecision {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { verdict: "reject", reason: "profile-metadata-mismatch" };
  }
  const { wire_probe: probe, ...candidate } = value as CurrentKindProfileNegotiationInput;
  if (probe === null || typeof probe !== "object" || Array.isArray(probe)) {
    return { verdict: "reject", reason: "profile-wire-discriminator-mismatch" };
  }
  const registered = validateRegisteredKindProfile(
    registry,
    candidate as RegisteredKindProfile,
  );
  if (registered.verdict === "reject") return registered;
  if (!wireBindingMatches(registered.normalized.discriminator, probe)) {
    return { verdict: "reject", reason: "profile-wire-discriminator-mismatch" };
  }
  const stamp = stampOwner({
    kind: registered.normalized.kind,
    profile_id: registered.normalized.profile_id,
    content_is_heterodyne_json: probe.content_is_heterodyne_json,
    is_dr_outer: probe.is_dr_outer,
  }, registry);
  const expectedStamp = expectedStampOwner(registry, registered.normalized, probe);
  if (stamp !== expectedStamp) {
    return { verdict: "reject", reason: "profile-wire-discriminator-mismatch" };
  }
  return {
    verdict: "accept",
    normalized: registered.normalized,
    stamp_owner: stamp,
    wire_binding: registered.normalized.discriminator,
  };
}

type CurrentClaimProofProbe = Readonly<{
  proof_suite: "nostr-bip340" | "radicle-ed25519" | "jwk-jws";
  proof_purpose: "claim-subject-pop" | "claim-revoker";
  message: string;
  public_key?: string;
  public_jwk?: Readonly<{ kty: string; crv: string; x: string }>;
  protected?: string;
  signature: string;
}>;

/** Verifies the native proof suite named by one fixed claim profile probe. */
export function verifyCurrentClaimProofProfile(value: unknown):
  | Readonly<{
      verdict: "accept";
      proof_suite: CurrentClaimProofProbe["proof_suite"];
      proof_purpose: CurrentClaimProofProbe["proof_purpose"];
      authenticated_message: string;
    }>
  | Readonly<{ verdict: "reject"; reason_code: "claim-subject-proof-invalid" }> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { verdict: "reject", reason_code: "claim-subject-proof-invalid" };
  }
  const probe = value as CurrentClaimProofProbe;
  if (
    !["claim-subject-pop", "claim-revoker"].includes(probe.proof_purpose)
    || !/^[0-9a-f]{64}$/u.test(probe.message)
  ) {
    return { verdict: "reject", reason_code: "claim-subject-proof-invalid" };
  }
  const message = hexToBytes(probe.message);
  let verified = false;
  try {
    if (
      probe.proof_suite === "nostr-bip340"
      && typeof probe.public_key === "string"
      && /^[0-9a-f]{64}$/u.test(probe.public_key)
      && /^[0-9a-f]{128}$/u.test(probe.signature)
    ) {
      verified = schnorr.verify(
        hexToBytes(probe.signature),
        message,
        hexToBytes(probe.public_key),
      );
    } else if (
      probe.proof_suite === "radicle-ed25519"
      && typeof probe.public_key === "string"
      && /^[0-9a-f]{64}$/u.test(probe.public_key)
      && /^[0-9a-f]{128}$/u.test(probe.signature)
    ) {
      verified = ed25519.verify(
        hexToBytes(probe.signature),
        message,
        hexToBytes(probe.public_key),
      );
    } else if (
      probe.proof_suite === "jwk-jws"
      && probe.public_jwk?.kty === "OKP"
      && probe.public_jwk.crv === "Ed25519"
      && probe.protected === Buffer.from('{"alg":"EdDSA"}', "utf8").toString("base64url")
    ) {
      const publicKey = Buffer.from(probe.public_jwk.x, "base64url");
      const signature = Buffer.from(probe.signature, "base64url");
      const encodedPayload = Buffer.from(message).toString("base64url");
      const signingInput = new TextEncoder().encode(
        `${probe.protected}.${encodedPayload}`,
      );
      verified = publicKey.length === 32
        && signature.length === 64
        && ed25519.verify(signature, signingInput, publicKey);
    }
  } catch {
    verified = false;
  }
  return verified
    ? {
        verdict: "accept",
        proof_suite: probe.proof_suite,
        proof_purpose: probe.proof_purpose,
        authenticated_message: probe.message,
      }
    : { verdict: "reject", reason_code: "claim-subject-proof-invalid" };
}

/** Applies both the closed Control schema and live frame-policy boundary. */
export function validateCurrentControlFrameProfile(value: unknown):
  | Readonly<{ verdict: "accept"; transport: "marmot-inner"; frame_type: string }>
  | Readonly<{
      verdict: "reject";
      reason_code:
        | "control-frame-invalid"
        | "control-token-invalid"
        | "control-refresh-prohibited";
    }> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { verdict: "reject", reason_code: "control-frame-invalid" };
  }
  const input = value as Readonly<{
    transport?: unknown;
    frame?: unknown;
  }>;
  if (input.transport !== "marmot-inner") {
    return { verdict: "reject", reason_code: "control-frame-invalid" };
  }
  try {
    validateControlFrameSchemaOrThrow(input.frame);
  } catch {
    return { verdict: "reject", reason_code: "control-frame-invalid" };
  }
  const policy = validateControlFrameBoundary({
    closed_schema_valid: true,
    token_valid: true,
    refresh_requested: false,
  });
  if (policy.verdict === "reject") return policy;
  const frameType = (input.frame as Readonly<{ frame_type: string }>).frame_type;
  return { verdict: "accept", transport: "marmot-inner", frame_type: frameType };
}

type CurrentControlGrantProfileInput = Readonly<{
  active_account: string;
  authenticated_account: string;
  grant_account: string;
  requested_device: string;
  grant_device: string;
  requested_leaf: string;
  grant_leaf: string;
  requested_group: string;
  grant_group: string;
  requested_grant: string;
  grant_id: string;
  requested_content_ids: readonly string[];
  granted_content_ids: readonly string[];
  requested_secret_classes: readonly string[];
}>;

function isClosedStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value)
    && value.every((member) => typeof member === "string" && member.length > 0)
    && new Set(value).size === value.length;
}

/**
 * Enforces the exact node account, device leaf, group, grant-filtered content,
 * and zero-secret result for one closed Control Marmot frame.
 */
export function validateCurrentControlGrantProfile(value: unknown):
  | Readonly<{
      verdict: "accept";
      transport: "marmot-inner";
      frame_type: string;
      active_account: string;
      device_leaf: string;
      grant_id: string;
      content_ids: readonly string[];
      released_secrets: readonly [];
    }>
  | Readonly<{
      verdict: "reject";
      reason_code: "control-frame-invalid" | "control-token-invalid";
    }> {
  const frame = validateCurrentControlFrameProfile(value);
  if (frame.verdict === "reject") {
    return {
      verdict: "reject",
      reason_code: frame.reason_code === "control-frame-invalid"
        ? "control-frame-invalid"
        : "control-token-invalid",
    };
  }
  const input = value as CurrentControlGrantProfileInput;
  const scalarFields = [
    input.active_account,
    input.authenticated_account,
    input.grant_account,
    input.requested_device,
    input.grant_device,
    input.requested_leaf,
    input.grant_leaf,
    input.requested_group,
    input.grant_group,
    input.requested_grant,
    input.grant_id,
  ];
  const accounts = [
    input.active_account,
    input.authenticated_account,
    input.grant_account,
  ];
  if (
    scalarFields.some((field) => typeof field !== "string" || field.length === 0)
    || accounts.some((account) => !/^[0-9a-f]{64}$/u.test(account))
    || !isClosedStringArray(input.requested_content_ids)
    || !isClosedStringArray(input.granted_content_ids)
    || !isClosedStringArray(input.requested_secret_classes)
  ) return { verdict: "reject", reason_code: "control-token-invalid" };

  const accountMatches = input.active_account === input.authenticated_account
    && input.active_account === input.grant_account;
  const exactGrant = input.requested_device === input.grant_device
    && input.requested_leaf === input.grant_leaf
    && input.requested_group === input.grant_group
    && input.requested_grant === input.grant_id;
  const grantedContent = new Set(input.granted_content_ids);
  const contentConfined = input.requested_content_ids.every((id) => grantedContent.has(id));
  const secretsConfined = input.requested_secret_classes.length === 0;
  const admission = controlGroupAdmission({
    cryptographic_valid: true,
    member_count: 2,
    node_account_matches: accountMatches,
    supported_control_profile: true,
    invitation_mode: "off",
    temporary_mode_unexpired: false,
    resource_available: exactGrant && contentConfined && secretsConfined,
    entitlement_state: "active",
    purpose_bound_invite_valid: false,
    explicit_local_decision: "none",
  });
  if (admission.outcome !== "accept-authorized") {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  return {
    verdict: "accept",
    transport: frame.transport,
    frame_type: frame.frame_type,
    active_account: input.active_account,
    device_leaf: input.requested_leaf,
    grant_id: input.requested_grant,
    content_ids: [...input.requested_content_ids],
    released_secrets: [],
  };
}
