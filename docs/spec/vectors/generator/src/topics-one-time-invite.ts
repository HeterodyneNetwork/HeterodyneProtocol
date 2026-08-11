import { schnorr } from "@noble/curves/secp256k1";
import { getPublicKey } from "./nostr.js";
import {
  descriptorDigest,
  encodeInviteFragment,
  evaluateInviteResponse,
  responseProof,
  secretCommitment,
  type InviteDescriptor,
  type InviteResponseInput,
} from "./one-time-invite.js";
import { baseVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

export function buildOneTimeInviteVectors(): AuthoredVector[] {
  const inviterSecretKey = "01".padStart(64, "0");
  const inviteSecret = "ab".repeat(32);
  const descriptor: InviteDescriptor = {
    version: 1,
    purpose: "dm",
    inviter_account: getPublicKey(inviterSecretKey),
    invite_id: "11".repeat(32),
    rendezvous_pubkey: "22".repeat(32),
    relay_hints: ["wss://relay.example"],
    issued_at: 1_000,
    expires_at: 87_400,
    secret_sha256: secretCommitment(inviteSecret),
    approval_mode: "interactive",
  };
  const digest = Buffer.from(descriptorDigest(descriptor)).toString("hex");
  const signature = Buffer.from(
    schnorr.sign(descriptorDigest(descriptor), inviterSecretKey, new Uint8Array(32)),
  ).toString("hex");
  const responseWithoutProof = {
    spec_version: "comms/0.5.0",
    purpose: "dm",
    descriptor_digest: digest,
    responder_account: "33".repeat(32),
    mls_key_package: "AQID",
    requested_class: "conversation-peer",
    capabilities: ["chat"],
  };
  const response = {
    ...responseWithoutProof,
    proof: responseProof(inviteSecret, responseWithoutProof),
  };
  const responseInput: InviteResponseInput = {
    now: 1_001,
    expires_at: descriptor.expires_at,
    expected_purpose: "dm",
    response_purpose: "dm",
    descriptor_valid: true,
    secret_commitment_valid: true,
    seal_valid: true,
    seal_pubkey: response.responder_account,
    rumor_pubkey: response.responder_account,
    proof_valid: true,
    keypackage_valid: true,
    capabilities_compatible: true,
    response_digest: "44".repeat(32),
    group_established: false,
  };
  const reserved = evaluateInviteResponse({ status: "active" }, responseInput);

  const vectors: AuthoredVector[] = [];
  const add = (
    number: string,
    id: string,
    description: string,
    input: Record<string, unknown>,
    expected_output: Record<string, unknown>,
  ) => vectors.push({
    relativePath: `one-time-invite/${number}-${id}.json`,
    vector: baseVector({
      vector_id: `one-time-invite/${id}`,
      spec_refs: [],
      description,
      direction: "consume",
      input,
      expected_output,
    }),
  });

  add("001", "descriptor-and-fragment", "The signed descriptor and secret form a provider-independent fragment envelope.", {
    descriptor,
    signature,
    secret: inviteSecret,
  }, {
    verdict: "accept",
    normalized: {
      descriptor_digest: digest,
      fragment: encodeInviteFragment({ descriptor, signature, secret: inviteSecret }),
      origin_is_authority: false,
    },
  });
  add("002", "response-proof", "The NIP-59 response binds its responder, KeyPackage, purpose, descriptor, capabilities, and invite secret.", {
    response,
    nip59_seal_pubkey: response.responder_account,
  }, {
    verdict: "accept",
    normalized: { proof_valid: true, seal_matches_rumor: true, private_key_members: 0 },
  });
  add("003", "purpose-mismatch", "A purpose-bound DM invite cannot be converted into device enrollment.", {
    state: { status: "active" },
    response: { ...responseInput, response_purpose: "device-enrollment" },
  }, {
    verdict: "reject",
    reason_code: "invite-purpose-mismatch",
    normalized: { state: { status: "active" } },
  });
  add("004", "expired", "An invite is invalid at its signed expiry and cannot reserve state.", {
    state: { status: "active" },
    response: { ...responseInput, now: descriptor.expires_at },
  }, {
    verdict: "reject",
    reason_code: "invite-expired",
    normalized: { state: { status: "active" } },
  });
  add("005", "first-valid-reservation", "The first completely valid authenticated response reserves the invite restart-safely.", {
    state: { status: "active" }, response: responseInput,
  }, { verdict: "accept", normalized: reserved });
  add("006", "reserved-responder-retry", "The exact reserved responder and response digest may retry and complete group establishment.", {
    state: reserved.state, response: { ...responseInput, group_established: true },
  }, { verdict: "accept", normalized: evaluateInviteResponse(reserved.state, { ...responseInput, group_established: true }) });
  add("007", "reservation-race-rejected", "A second responder cannot race an already reserved invitation.", {
    state: reserved.state,
    response: { ...responseInput, seal_pubkey: "55".repeat(32), rumor_pubkey: "55".repeat(32), response_digest: "66".repeat(32) },
  }, {
    verdict: "reject",
    reason_code: "invite-already-reserved",
    normalized: evaluateInviteResponse(reserved.state, { ...responseInput, seal_pubkey: "55".repeat(32), rumor_pubkey: "55".repeat(32), response_digest: "66".repeat(32) }),
  });
  add("008", "invalid-keypackage-no-reservation", "An invalid serialized Marmot KeyPackage cannot reserve an invitation.", {
    state: { status: "active" },
    response: { ...responseInput, keypackage_valid: false },
  }, {
    verdict: "reject",
    reason_code: "invite-authentication-invalid",
    normalized: evaluateInviteResponse({ status: "active" }, { ...responseInput, keypackage_valid: false }),
  });
  return vectors;
}
