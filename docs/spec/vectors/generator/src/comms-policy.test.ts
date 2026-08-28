import { describe, expect, it } from "vitest";
import {
  classifyRelayWriteFailure,
  evaluateMarmotInboxBootstrap,
  evaluateOneTimeInvite,
  evaluatePrivateMarmotRoute,
  validateDmInviteDevice,
  validatePrivateBroadcast,
  validatePublicReaderRendering,
} from "./comms-policy.js";

describe("current Comms semantic policy boundaries", () => {
  it("rejects withdrawn private transports and permanent post-AUTH failures", () => {
    expect(validatePrivateBroadcast({ transport: "nip59", wrap_profile: "room_key.v1" }))
      .toEqual({ verdict: "reject", reason_code: "nip59_broadcast_rejected" });
    expect(classifyRelayWriteFailure({ authenticated: true, response_prefix: "auth-required:" }))
      .toEqual({ verdict: "reject", permanence: "permanent", reason_code: "auth_rejected_permanent" });
  });

  it("validates delegated DM devices and one-time invite state", () => {
    expect(validateDmInviteDevice({ delegation_present: false, delegation_revoked: false }))
      .toEqual({ verdict: "reject", reason_code: "dm_invite_unbound_device" });
    expect(validateDmInviteDevice({ delegation_present: true, delegation_revoked: true }))
      .toEqual({ verdict: "reject", reason_code: "dm_invite_revoked_device" });
    const invite = {
      now: 100,
      expires_at: 200,
      signed_purpose: "dm" as const,
      requested_purpose: "dm" as const,
      descriptor_signature_valid: true,
      responder_binding_valid: true,
      secret_proof_valid: true,
      capability_binding_valid: true,
      reserved_account: null,
      responder_account: "11".repeat(32),
      reserved_response_digest: null,
      response_digest: "22".repeat(32),
    };
    expect(evaluateOneTimeInvite({ ...invite, now: 200 }))
      .toEqual({ verdict: "reject", reason_code: "invite-expired" });
    expect(evaluateOneTimeInvite({ ...invite, requested_purpose: "control-enrollment" }))
      .toEqual({ verdict: "reject", reason_code: "invite-purpose-mismatch" });
    expect(evaluateOneTimeInvite({ ...invite, secret_proof_valid: false }))
      .toEqual({ verdict: "reject", reason_code: "invite-authentication-invalid" });
    expect(evaluateOneTimeInvite({ ...invite, reserved_account: "33".repeat(32) }))
      .toEqual({ verdict: "reject", reason_code: "invite-already-reserved" });
  });

  it("confines public rendering, private routes, inboxes, and automation", () => {
    expect(validatePublicReaderRendering({ tier: 2, render_as_public: true }))
      .toEqual({ verdict: "reject", reason_code: "public-reader-private-content" });
    expect(evaluatePrivateMarmotRoute({ private_group: true, requested_route: "rad:zAbsent", authorized_routes: [] }))
      .toEqual({ verdict: "reject", reason_code: "marmot-private-route-required" });
    expect(evaluateMarmotInboxBootstrap({ sender_nid_authorized: false, keypackage_already_consumed: false, automated_scope_valid: true }))
      .toEqual({ verdict: "reject", reason_code: "marmot-private-inbox-nid-required" });
    expect(evaluateMarmotInboxBootstrap({ sender_nid_authorized: true, keypackage_already_consumed: true, automated_scope_valid: true }))
      .toEqual({ verdict: "reject", reason_code: "marmot-keypackage-replayed" });
    expect(evaluateMarmotInboxBootstrap({ sender_nid_authorized: true, keypackage_already_consumed: false, automated_scope_valid: false }))
      .toEqual({ verdict: "reject", reason_code: "marmot-agent-scope-denied" });
  });
});
