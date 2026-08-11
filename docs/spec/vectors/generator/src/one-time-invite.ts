import { createHash, createHmac } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";

const DESCRIPTOR_DOMAIN = "heterodyne.one-time-invite.v1";
const RESPONSE_DOMAIN = "heterodyne.one-time-invite-response.v1";

export type InvitePurpose = "dm" | "control-enrollment" | "device-enrollment";

export type InviteDescriptor = {
  version: 1;
  purpose: InvitePurpose;
  inviter_account: string;
  inviter_authority?: Record<string, unknown>;
  invite_id: string;
  rendezvous_pubkey: string;
  relay_hints: string[];
  issued_at: number;
  expires_at: number;
  secret_sha256: string;
  approval_mode: "interactive" | "preauthorized";
  preauthorization?: Record<string, unknown>;
  expected_client_pubkey?: string;
};

export type InviteEnvelope = {
  descriptor: InviteDescriptor;
  signature: string;
  secret: string;
};

function domainInput(domain: string, payload: Uint8Array): Uint8Array {
  return Buffer.concat([Buffer.from(domain, "utf8"), Buffer.from([0]), payload]);
}

export function descriptorDigest(descriptor: InviteDescriptor): Uint8Array {
  return createHash("sha256")
    .update(domainInput(DESCRIPTOR_DOMAIN, Buffer.from(jcsCanonicalize(descriptor), "utf8")))
    .digest();
}

export function secretCommitment(secretHex: string): string {
  return createHash("sha256").update(hexToBytes(secretHex)).digest("hex");
}

export function verifyInviteSignature(
  descriptor: InviteDescriptor,
  signatureHex: string,
): boolean {
  try {
    return schnorr.verify(
      hexToBytes(signatureHex),
      descriptorDigest(descriptor),
      hexToBytes(descriptor.inviter_account),
    );
  } catch {
    return false;
  }
}

export function encodeInviteFragment(envelope: InviteEnvelope): string {
  return `#v1.${Buffer.from(jcsCanonicalize(envelope), "utf8").toString("base64url")}`;
}

export function responseProof(
  secretHex: string,
  responseWithoutProof: Record<string, unknown>,
): string {
  const responseDigest = createHash("sha256")
    .update(jcsCanonicalize(responseWithoutProof), "utf8")
    .digest();
  return createHmac("sha256", hexToBytes(secretHex))
    .update(domainInput(RESPONSE_DOMAIN, responseDigest))
    .digest("hex");
}

export type InviteState =
  | { status: "active" | "revoked" }
  | { status: "reserved"; reserved_account: string; reserved_response_digest: string }
  | { status: "spent"; reserved_account: string; reserved_response_digest: string };

export type InviteResponseInput = {
  now: number;
  expires_at: number;
  expected_purpose: InvitePurpose;
  response_purpose: InvitePurpose;
  descriptor_valid: boolean;
  secret_commitment_valid: boolean;
  seal_valid: boolean;
  seal_pubkey: string;
  rumor_pubkey: string;
  proof_valid: boolean;
  keypackage_valid: boolean;
  capabilities_compatible: boolean;
  response_digest: string;
  group_established: boolean;
};

export function evaluateInviteResponse(
  state: InviteState,
  input: InviteResponseInput,
): { verdict: "accept" | "reject"; retry: boolean; state: InviteState } {
  const valid = state.status !== "revoked"
    && input.now < input.expires_at
    && input.expected_purpose === input.response_purpose
    && input.descriptor_valid
    && input.secret_commitment_valid
    && input.seal_valid
    && input.seal_pubkey === input.rumor_pubkey
    && input.proof_valid
    && input.keypackage_valid
    && input.capabilities_compatible;
  if (!valid || state.status === "spent") return { verdict: "reject", retry: false, state };
  if (state.status === "reserved") {
    const retry = state.reserved_account === input.rumor_pubkey
      && state.reserved_response_digest === input.response_digest;
    if (!retry) return { verdict: "reject", retry: false, state };
    return {
      verdict: "accept",
      retry: true,
      state: input.group_established ? { ...state, status: "spent" } : state,
    };
  }
  const reserved: InviteState = {
    status: input.group_established ? "spent" : "reserved",
    reserved_account: input.rumor_pubkey,
    reserved_response_digest: input.response_digest,
  };
  return { verdict: "accept", retry: false, state: reserved };
}
