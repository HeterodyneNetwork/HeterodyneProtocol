import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import { getPublicKey } from "./nostr.js";
import {
  descriptorDigest,
  encodeInviteFragment,
  evaluateInviteResponse,
  responseProof,
  secretCommitment,
  verifyInviteSignature,
  type InviteDescriptor,
} from "./one-time-invite.js";

const secretKey = "01".padStart(64, "0");
const secret = "ab".repeat(32);
const descriptor: InviteDescriptor = {
  version: 1,
  purpose: "dm" as const,
  inviter_account: getPublicKey(secretKey),
  invite_id: "11".repeat(32),
  rendezvous_pubkey: "22".repeat(32),
  relay_hints: ["wss://relay.example"],
  issued_at: 1_000,
  expires_at: 1_000 + 86_400,
  secret_sha256: secretCommitment(secret),
  approval_mode: "interactive" as const,
};

describe("provider-independent one-time invites", () => {
  it("domain-separates and verifies the signed descriptor", () => {
    const digest = descriptorDigest(descriptor);
    const signature = Buffer.from(schnorr.sign(digest, secretKey, new Uint8Array(32))).toString("hex");
    expect(verifyInviteSignature(descriptor, signature)).toBe(true);
    expect(verifyInviteSignature({ ...descriptor, purpose: "control-enrollment" }, signature)).toBe(false);
  });

  it("accepts an active-account-signed device invite and rejects legacy authority members", () => {
    const deviceDescriptor: InviteDescriptor = {
      ...descriptor,
      purpose: "device-enrollment",
    };
    const signature = Buffer.from(
      schnorr.sign(descriptorDigest(deviceDescriptor), secretKey, new Uint8Array(32)),
    ).toString("hex");
    expect(verifyInviteSignature(deviceDescriptor, signature)).toBe(true);

    const legacyDescriptor = {
      ...deviceDescriptor,
      inviter_authority: {
        persona: getPublicKey(secretKey),
        kel_head: "33".repeat(32),
        epoch_key: getPublicKey(secretKey),
        authority_event_id: "44".repeat(32),
      },
    };
    const legacySignature = Buffer.from(
      schnorr.sign(descriptorDigest(legacyDescriptor), secretKey, new Uint8Array(32)),
    ).toString("hex");
    expect(verifyInviteSignature(legacyDescriptor, legacySignature)).toBe(false);
  });

  it("rejects a correctly signed descriptor missing any required member", () => {
    for (const required of [
      "version",
      "purpose",
      "inviter_account",
      "invite_id",
      "rendezvous_pubkey",
      "relay_hints",
      "issued_at",
      "expires_at",
      "secret_sha256",
      "approval_mode",
    ] as const) {
      const partial = Object.fromEntries(
        Object.entries(descriptor).filter(([member]) => member !== required),
      ) as InviteDescriptor;
      const signature = Buffer.from(
        schnorr.sign(descriptorDigest(partial), secretKey, new Uint8Array(32)),
      ).toString("hex");

      expect(verifyInviteSignature(partial, signature), required).toBe(false);
    }
  });

  it("rejects descriptor properties that are not signed JSON data members", () => {
    const missingPurpose = Object.fromEntries(
      Object.entries(descriptor).filter(([member]) => member !== "purpose"),
    ) as InviteDescriptor;
    Object.defineProperty(missingPurpose, "purpose", {
      value: "dm",
      enumerable: false,
    });

    const hiddenOptional = { ...descriptor } as InviteDescriptor;
    Object.defineProperty(hiddenOptional, "preauthorization", {
      value: { capability: "control" },
      enumerable: false,
    });

    const symbolMember = { ...descriptor } as InviteDescriptor;
    Object.defineProperty(symbolMember, Symbol("unsigned"), {
      value: "authority",
      enumerable: true,
    });

    const accessorMember = { ...descriptor } as InviteDescriptor;
    Object.defineProperty(accessorMember, "purpose", {
      get: () => "dm",
      enumerable: true,
    });

    for (const malformed of [
      missingPurpose,
      hiddenOptional,
      symbolMember,
      accessorMember,
    ]) {
      const signature = Buffer.from(
        schnorr.sign(descriptorDigest(malformed), secretKey, new Uint8Array(32)),
      ).toString("hex");
      expect(verifyInviteSignature(malformed, signature)).toBe(false);
    }
  });

  it("encodes authority only in a URL fragment", () => {
    const signature = Buffer.from(schnorr.sign(descriptorDigest(descriptor), secretKey, new Uint8Array(32))).toString("hex");
    const fragment = encodeInviteFragment({ descriptor, signature, secret });
    expect(fragment).toMatch(/^#v1\.[A-Za-z0-9_-]+$/);
    expect(new URL(`https://heterodyne.network/client/${fragment}`).hash).toBe(fragment);
  });

  it("binds the response proof to the secret and canonical response", () => {
    const response = {
      descriptor_digest: Buffer.from(descriptorDigest(descriptor)).toString("hex"),
      responder_account: "33".repeat(32),
      mls_key_package: "AQID",
      requested_class: "human-light" as const,
      capabilities: ["chat"],
    };
    expect(responseProof(secret, response)).not.toBe(responseProof("cd".repeat(32), response));
    expect(responseProof(secret, response)).not.toBe(responseProof(secret, { ...response, requested_class: "automated" }));
  });

  it("reserves for the first fully valid responder and permits only its retry", () => {
    const first = evaluateInviteResponse(
      { status: "active" },
      {
        now: 1_001,
        expires_at: 2_000,
        expected_purpose: "dm",
        response_purpose: "dm",
        descriptor_valid: true,
        secret_commitment_valid: true,
        seal_valid: true,
        seal_pubkey: "33".repeat(32),
        rumor_pubkey: "33".repeat(32),
        proof_valid: true,
        keypackage_valid: true,
        capabilities_compatible: true,
        response_digest: "44".repeat(32),
        group_established: false,
      },
    );
    expect(first).toEqual({
      verdict: "accept",
      retry: false,
      state: {
        status: "reserved",
        reserved_account: "33".repeat(32),
        reserved_response_digest: "44".repeat(32),
      },
    });
    expect(evaluateInviteResponse(first.state, {
      now: 1_002,
      expires_at: 2_000,
      expected_purpose: "dm",
      response_purpose: "dm",
      descriptor_valid: true,
      secret_commitment_valid: true,
      seal_valid: true,
      seal_pubkey: "33".repeat(32),
      rumor_pubkey: "33".repeat(32),
      proof_valid: true,
      keypackage_valid: true,
      capabilities_compatible: true,
      response_digest: "44".repeat(32),
      group_established: true,
    })).toMatchObject({ verdict: "accept", retry: true, state: { status: "spent" } });
    expect(evaluateInviteResponse(first.state, {
      now: 1_002,
      expires_at: 2_000,
      expected_purpose: "dm",
      response_purpose: "dm",
      descriptor_valid: true,
      secret_commitment_valid: true,
      seal_valid: true,
      seal_pubkey: "55".repeat(32),
      rumor_pubkey: "55".repeat(32),
      proof_valid: true,
      keypackage_valid: true,
      capabilities_compatible: true,
      response_digest: "66".repeat(32),
      group_established: false,
    })).toMatchObject({ verdict: "reject", state: first.state });
  });

  it("does not reserve invalid, expired, or purpose-mismatched traffic", () => {
    for (const change of [
      { now: 2_001 },
      { response_purpose: "device-enrollment" as const },
      { proof_valid: false },
      { seal_pubkey: "55".repeat(32) },
      { descriptor_valid: false },
      { secret_commitment_valid: false },
      { keypackage_valid: false },
    ]) {
      expect(evaluateInviteResponse({ status: "active" }, {
        now: 1_001,
        expires_at: 2_000,
        expected_purpose: "dm",
        response_purpose: "dm",
        descriptor_valid: true,
        secret_commitment_valid: true,
        seal_valid: true,
        seal_pubkey: "33".repeat(32),
        rumor_pubkey: "33".repeat(32),
        proof_valid: true,
        keypackage_valid: true,
        capabilities_compatible: true,
        response_digest: "44".repeat(32),
        group_established: false,
        ...change,
      })).toMatchObject({ verdict: "reject", state: { status: "active" } });
    }
  });
});
