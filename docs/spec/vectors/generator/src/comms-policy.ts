export function validatePrivateBroadcast(input: {
  transport: "nip01" | "nip59";
  wrap_profile: "room_key.v1" | "room_key.v2";
}): { verdict: "accept" } | { verdict: "reject"; reason_code: "nip59_broadcast_rejected" } {
  return input.transport === "nip59" || input.wrap_profile !== "room_key.v2"
    ? { verdict: "reject", reason_code: "nip59_broadcast_rejected" }
    : { verdict: "accept" };
}

export function classifyRelayWriteFailure(input: {
  authenticated: boolean;
  response_prefix: string;
}):
  | { verdict: "retry"; permanence: "transient" }
  | { verdict: "reject"; permanence: "permanent"; reason_code: "auth_rejected_permanent" } {
  return input.authenticated && input.response_prefix === "auth-required:"
    ? { verdict: "reject", permanence: "permanent", reason_code: "auth_rejected_permanent" }
    : { verdict: "retry", permanence: "transient" };
}

export function validateDmInviteDevice(input: {
  delegation_present: boolean;
  delegation_revoked: boolean;
}):
  | { verdict: "accept" }
  | { verdict: "reject"; reason_code: "dm_invite_unbound_device" | "dm_invite_revoked_device" } {
  if (!input.delegation_present) {
    return { verdict: "reject", reason_code: "dm_invite_unbound_device" };
  }
  return input.delegation_revoked
    ? { verdict: "reject", reason_code: "dm_invite_revoked_device" }
    : { verdict: "accept" };
}

type InvitePurpose = "dm" | "control-enrollment" | "device-enrollment";

export function evaluateOneTimeInvite(input: {
  now: number;
  expires_at: number;
  signed_purpose: InvitePurpose;
  requested_purpose: InvitePurpose;
  descriptor_signature_valid: boolean;
  responder_binding_valid: boolean;
  secret_proof_valid: boolean;
  capability_binding_valid: boolean;
  reserved_account: string | null;
  responder_account: string;
  reserved_response_digest: string | null;
  response_digest: string;
}):
  | { verdict: "accept"; reservation: "new" | "retry" }
  | { verdict: "reject"; reason_code: "invite-expired" | "invite-purpose-mismatch" | "invite-authentication-invalid" | "invite-already-reserved" } {
  if (!Number.isSafeInteger(input.now) || !Number.isSafeInteger(input.expires_at) || input.now >= input.expires_at) {
    return { verdict: "reject", reason_code: "invite-expired" };
  }
  if (input.requested_purpose !== input.signed_purpose) {
    return { verdict: "reject", reason_code: "invite-purpose-mismatch" };
  }
  if (
    !input.descriptor_signature_valid
    || !input.responder_binding_valid
    || !input.secret_proof_valid
    || !input.capability_binding_valid
    || !/^[0-9a-f]{64}$/.test(input.responder_account)
    || !/^[0-9a-f]{64}$/.test(input.response_digest)
  ) return { verdict: "reject", reason_code: "invite-authentication-invalid" };
  if (input.reserved_account !== null) {
    if (
      input.reserved_account !== input.responder_account
      || input.reserved_response_digest !== input.response_digest
    ) return { verdict: "reject", reason_code: "invite-already-reserved" };
    return { verdict: "accept", reservation: "retry" };
  }
  return { verdict: "accept", reservation: "new" };
}

export function validatePublicReaderRendering(input: {
  tier: 1 | 2 | 3;
  render_as_public: boolean;
}): { verdict: "accept" } | { verdict: "reject"; reason_code: "public-reader-private-content" } {
  return input.tier !== 1 && input.render_as_public
    ? { verdict: "reject", reason_code: "public-reader-private-content" }
    : { verdict: "accept" };
}

export function evaluateMarmotInboxBootstrap(input: {
  sender_nid_authorized: boolean;
  keypackage_already_consumed: boolean;
  automated_scope_valid: boolean;
}):
  | { verdict: "accept" }
  | { verdict: "reject"; reason_code: "marmot-private-inbox-nid-required" | "marmot-keypackage-replayed" | "marmot-agent-scope-denied" } {
  if (!input.sender_nid_authorized) {
    return { verdict: "reject", reason_code: "marmot-private-inbox-nid-required" };
  }
  if (input.keypackage_already_consumed) {
    return { verdict: "reject", reason_code: "marmot-keypackage-replayed" };
  }
  return input.automated_scope_valid
    ? { verdict: "accept" }
    : { verdict: "reject", reason_code: "marmot-agent-scope-denied" };
}
