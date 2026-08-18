import { describe, expect, it } from "vitest";
import {
  authorizeInvitation,
  evaluateAuthorizationFreshness,
  evaluateDeviceAuthorizationAttempt,
  evaluateInvitePreauthorization,
  evaluatePendingEnrollment,
  evaluateEntitlementUpdate,
  evaluateEpochActivation,
  evaluateRecoveryAccess,
  evaluateSftpAccess,
  issueControlToken,
  processControlOperation,
  retentionDecision,
  validateControlTokenUse,
} from "./control-profile.js";

const client = "11".repeat(32);
const node = "22".repeat(32);
const group = "33".repeat(32);
const jkt = "A".repeat(43);

describe("Marmot Control invitation and entitlement", () => {
  const invitation = {
    invitation_mode: "off" as const,
    temporary_expires_at: null,
    now: 1_000,
    keypackage_valid: true,
    keypackage_last_resort: true,
    member_count: 2,
    node_account_matches: true,
    entitlement_state: "none" as const,
    method: "control.enrollment.start",
    purpose_bound_invite_valid: false,
    explicitly_approved: false,
    pending_for_account: 0,
    global_pending: 0,
    global_pending_cap: 10,
    welcome_rate_remaining: 1,
    replenishment_rate_remaining: 1,
    public_pool_replenishment_requested: false,
    reserved_slot_available: true,
  };

  it("defaults unsolicited invitations to off and admits bounded open mode enrollment", () => {
    expect(authorizeInvitation({
      ...invitation,
      invitation_mode: "permanent",
    })).toEqual({ verdict: "accept", state: "enrollment-only", authority: false });
    expect(authorizeInvitation(invitation))
      .toEqual({ verdict: "reject", reason_code: "control-enrollment-unavailable" });
  });

  it("enforces temporary expiry, one pending group per account, global cap, and rates", () => {
    expect(authorizeInvitation({ ...invitation, invitation_mode: "temporary", temporary_expires_at: 1_001 }))
      .toMatchObject({ verdict: "accept", state: "enrollment-only" });
    expect(authorizeInvitation({ ...invitation, invitation_mode: "temporary", temporary_expires_at: 1_000 }))
      .toEqual({ verdict: "reject", reason_code: "control-enrollment-unavailable" });
    expect(authorizeInvitation({ ...invitation, invitation_mode: "permanent", pending_for_account: 1 }))
      .toEqual({ verdict: "reject", reason_code: "control-enrollment-unavailable" });
    expect(authorizeInvitation({ ...invitation, invitation_mode: "permanent", global_pending: 10 }))
      .toEqual({ verdict: "reject", reason_code: "control-enrollment-unavailable" });
    expect(authorizeInvitation({ ...invitation, invitation_mode: "permanent", welcome_rate_remaining: 0 }))
      .toEqual({ verdict: "reject", reason_code: "control-enrollment-rate-limited" });
    expect(authorizeInvitation({ ...invitation, invitation_mode: "permanent", global_pending: 10, public_pool_replenishment_requested: true }))
      .toEqual({ verdict: "reject", reason_code: "control-keypackage-replenishment-paused" });
  });

  it("reserves capacity for entitled or explicitly approved clients", () => {
    expect(authorizeInvitation({
      ...invitation,
      entitlement_state: "active",
      global_pending: 10,
      explicitly_approved: true,
    })).toEqual({ verdict: "accept", state: "active", authority: true });
    expect(authorizeInvitation({
      ...invitation,
      entitlement_state: "active",
      global_pending: 10,
      explicitly_approved: true,
      reserved_slot_available: false,
    })).toEqual({ verdict: "reject", reason_code: "control-enrollment-unavailable" });
  });

  it("expires enrollment-only groups after the hard 30-minute lifetime", () => {
    expect(evaluatePendingEnrollment({ created_at: 1_000, now: 2_799 }))
      .toEqual({ verdict: "accept", state: "enrollment-only", expires_at: 2_800 });
    expect(evaluatePendingEnrollment({ created_at: 1_000, now: 2_800 }))
      .toEqual({ verdict: "reject", reason_code: "control-enrollment-unavailable" });
  });

  it("converges reductions, absorbs revocation, and rejects unconsented expansion", () => {
    const current = {
      record_id: "44".repeat(32), client_key: client, predecessor: null,
      state: "active" as const, methods: ["config.get", "config.put"],
      objects: ["config:ui", "config:feeds"], authorized_writer: true,
      explicit_consent: true,
    };
    expect(evaluateEntitlementUpdate(current, {
      ...current, record_id: "55".repeat(32), predecessor: current.record_id,
      methods: ["config.get"], objects: ["config:ui"], explicit_consent: false,
    })).toMatchObject({ verdict: "accept", state: "active", methods: ["config.get"] });
    expect(evaluateEntitlementUpdate(current, {
      ...current, record_id: "66".repeat(32), predecessor: current.record_id,
      methods: [...current.methods, "publish"], explicit_consent: false,
    })).toEqual({ verdict: "reject", reason_code: "control-entitlement-conflict" });
    expect(evaluateEntitlementUpdate(current, {
      ...current, record_id: "77".repeat(32), predecessor: current.record_id,
      state: "revoked", methods: [], objects: [], explicit_consent: false,
    })).toMatchObject({ verdict: "accept", state: "revoked", methods: [], objects: [] });
  });
});

describe("node-scoped Marmot-bound tokens", () => {
  const currentEntitlement = {
    record_id: "44".repeat(32),
    state: "active" as const,
    client_key: client,
    client_id: "agent-newsletter",
    client_class: "automated" as const,
    scopes: ["control.read"],
    methods: ["config.get"],
    objects: ["config:ui"],
    limits: { content_bytes: 1_024, requests_per_hour: 10 },
    registry_checkpoint: "55".repeat(32),
    agent_role: "newsletter",
    max_token_lifetime_seconds: 3_600,
  };
  const issuance = {
    client_jkt: jkt,
    group_id: group,
    issuer: "https://node.example/oidc/persona",
    audience: "urn:heterodyne:control:node-a",
    node_key: node,
    requested_lifetime_seconds: 300,
    node_policy_max_seconds: 3600,
    extended_capability: false,
    now: 1_000,
    authorization_view_authenticated: true,
    authorization_view_conflicted: false,
    authorization_view_age_seconds: 0,
    methods: ["config.get"],
    objects: ["config:ui"],
    entitlement: currentEntitlement,
    scopes: ["control.read"],
    limits: { content_bytes: 1_024, requests_per_hour: 10 },
    agent_role: "newsletter",
  };

  it("issues five minutes by default, permits explicit extension, and never refreshes", () => {
    expect(issueControlToken(issuance)).toMatchObject({
      verdict: "accept", lifetime_seconds: 300, refresh_token: null,
      token: {
        authorization_id: currentEntitlement.record_id,
        client_id: currentEntitlement.client_id,
        client_class: currentEntitlement.client_class,
        scope: "control.read",
        limits: currentEntitlement.limits,
        registry_checkpoint: currentEntitlement.registry_checkpoint,
        agent_role: currentEntitlement.agent_role,
      },
    });
    expect(issueControlToken({
      ...issuance, requested_lifetime_seconds: 3_600, extended_capability: true,
    })).toMatchObject({ verdict: "accept", lifetime_seconds: 3_600, refresh_token: null });
    expect(issueControlToken({ ...issuance, requested_lifetime_seconds: 301 }))
      .toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
  });

  it("rejects the wrong sender, group, node audience, and scope", () => {
    const token = issueControlToken(issuance);
    if (token.verdict !== "accept") throw new Error("fixture token failed");
    const use = {
      token: token.token,
      signature_valid: true,
      now: 1_100,
      expected_issuer: issuance.issuer,
      expected_audience: issuance.audience,
      expected_node_key: node,
      authenticated_sender_jkt: jkt,
      group_id: group,
      authorization_view_authenticated: true,
      authorization_view_conflicted: false,
      authorization_view_age_seconds: 100,
      method: "config.get",
      object: "config:ui",
      current_entitlement: currentEntitlement,
      required_scope: "control.read",
      usage: { content_bytes: 512, requests_per_hour: 1 },
      required_agent_role: "newsletter",
    };
    expect(validateControlTokenUse(use)).toEqual({ verdict: "accept" });
    expect(validateControlTokenUse({ ...use, authenticated_sender_jkt: "B".repeat(43) }))
      .toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
    expect(validateControlTokenUse({ ...use, group_id: "99".repeat(32) }))
      .toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
    expect(validateControlTokenUse({ ...use, expected_audience: "urn:heterodyne:control:node-b" }))
      .toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
    expect(validateControlTokenUse({ ...use, method: "config.put" }))
      .toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
  });

  it("revalidates every token grant against the current entitlement", () => {
    const token = issueControlToken(issuance);
    if (token.verdict !== "accept") throw new Error("fixture token failed");
    const use = {
      token: token.token,
      signature_valid: true,
      now: 1_100,
      expected_issuer: issuance.issuer,
      expected_audience: issuance.audience,
      expected_node_key: node,
      authenticated_sender_jkt: jkt,
      group_id: group,
      authorization_view_authenticated: true,
      authorization_view_conflicted: false,
      authorization_view_age_seconds: 100,
      method: "config.get",
      object: "config:ui",
      current_entitlement: currentEntitlement,
      required_scope: "control.read",
      usage: { content_bytes: 512, requests_per_hour: 1 },
      required_agent_role: "newsletter",
    };
    for (const current_entitlement of [
      { ...currentEntitlement, record_id: "66".repeat(32) },
      { ...currentEntitlement, client_id: "other-client" },
      { ...currentEntitlement, client_class: "human-light" as const },
      { ...currentEntitlement, scopes: [] },
      { ...currentEntitlement, methods: [] },
      { ...currentEntitlement, objects: [] },
      { ...currentEntitlement, limits: { content_bytes: 256, requests_per_hour: 10 } },
      { ...currentEntitlement, registry_checkpoint: "77".repeat(32) },
      { ...currentEntitlement, agent_role: "moderator" },
    ]) {
      expect(validateControlTokenUse({ ...use, current_entitlement })).toEqual({
        verdict: "reject",
        reason_code: "control-token-invalid",
      });
    }
  });

  it("caps authorization-view age at 300 seconds for minting and use", () => {
    expect(issueControlToken({ ...issuance, authorization_view_age_seconds: 301 }))
      .toEqual({ verdict: "reject", reason_code: "control-authorization-view-stale" });
    expect(evaluateAuthorizationFreshness({ authenticated: true, conflicted: false, age_seconds: 300, mutation: false, immediate_sync_succeeded: false }))
      .toEqual({ verdict: "accept" });
    expect(evaluateAuthorizationFreshness({ authenticated: true, conflicted: false, age_seconds: 100, mutation: true, immediate_sync_succeeded: false }))
      .toEqual({ verdict: "reject", reason_code: "control-authorization-view-stale" });
  });
});

describe("OAuth Device Authorization hardening", () => {
  const attempt = {
    device_code_entropy_bits: 128,
    user_code_entropy_bits: 34.5,
    failed_guesses: 0,
    per_code_rate_allowed: true,
    node_rate_allowed: true,
    normalized_constant_time_match: true,
    display_code_matches: true,
    display_fingerprint_matches: true,
    poll_interval_observed: true,
    slow_down_observed: true,
    terminal_state: "pending" as const,
  };

  it("requires entropy, throttling, display binding, and RFC polling behavior", () => {
    expect(evaluateDeviceAuthorizationAttempt(attempt)).toEqual({ verdict: "accept", state: "pending" });
    expect(evaluateDeviceAuthorizationAttempt({ ...attempt, device_code_entropy_bits: 127 }))
      .toMatchObject({ verdict: "reject" });
    expect(evaluateDeviceAuthorizationAttempt({ ...attempt, user_code_entropy_bits: 34 }))
      .toMatchObject({ verdict: "reject" });
    expect(evaluateDeviceAuthorizationAttempt({ ...attempt, failed_guesses: 5 }))
      .toEqual({ verdict: "reject", reason_code: "control-device-code-invalid", state: "invalidated" });
    expect(evaluateDeviceAuthorizationAttempt({ ...attempt, node_rate_allowed: false }))
      .toEqual({ verdict: "reject", reason_code: "control-device-code-rate-limited", state: "pending" });
    expect(evaluateDeviceAuthorizationAttempt({ ...attempt, display_fingerprint_matches: false }))
      .toEqual({ verdict: "reject", reason_code: "control-device-code-display-mismatch", state: "pending" });
  });
});

describe("purpose-bound enrollment effects", () => {
  const preauthorized = {
    purpose: "control-enrollment" as const,
    approval_mode: "preauthorized" as const,
    client_class: "automated" as const,
    expected_client_pubkey: "11".repeat(32),
    unbound_bearer_enabled: false,
    node_allows_unbound_bearer: false,
    methods: ["agent.publish"],
    objects: ["feed:main"],
    limits: { requests_per_hour: 10 },
    agent_role: "newsletter",
    token_lifetime_ceiling_seconds: 300,
    keri_authorized_device: false,
  };

  it("allows exact key-bound private Control preauthorization", () => {
    expect(evaluateInvitePreauthorization(preauthorized)).toEqual({
      verdict: "accept",
      prompt_free: true,
      risk: "normal",
    });
  });

  it("rejects prompt-free KERI devices and unbound automation by default", () => {
    expect(evaluateInvitePreauthorization({
      ...preauthorized,
      purpose: "device-enrollment",
      client_class: "full-device",
      keri_authorized_device: true,
    })).toEqual({ verdict: "reject", reason_code: "invite-preauthorization-invalid" });
    expect(evaluateInvitePreauthorization({ ...preauthorized, expected_client_pubkey: null }))
      .toEqual({ verdict: "reject", reason_code: "invite-preauthorization-invalid" });
  });

  it("reports explicitly enabled unbound bearer automation as higher risk", () => {
    expect(evaluateInvitePreauthorization({
      ...preauthorized,
      expected_client_pubkey: null,
      unbound_bearer_enabled: true,
      node_allows_unbound_bearer: true,
    })).toEqual({ verdict: "accept", prompt_free: true, risk: "higher" });
  });
});

describe("operation reservation, failover, and retention", () => {
  const request = {
    node_key: node, group_id: group, request_id: "request-1", operation_id: "op-1",
    method: "publish", object: "feed:main", payload_digest: "44".repeat(32),
    expires_at: 1_200, now: 1_000, mutation: true, inherently_idempotent: false,
    prior_result_proven: false,
  };

  it("executes first arrival, joins exact duplicate, and conflicts changed bytes", () => {
    const first = processControlOperation(request);
    expect(first).toMatchObject({ verdict: "accept", action: "execute", execute: true });
    if (first.verdict !== "accept") throw new Error("fixture reservation failed");
    expect(processControlOperation(request, first.reservation))
      .toMatchObject({ verdict: "accept", action: "join", execute: false });
    expect(processControlOperation({ ...request, payload_digest: "55".repeat(32) }, first.reservation))
      .toEqual({ verdict: "reject", reason_code: "control-operation-conflict" });
  });

  it("fails over reads and safe mutations but returns indeterminate for an unsafe mutation", () => {
    const first = processControlOperation(request);
    if (first.verdict !== "accept") throw new Error("fixture reservation failed");
    const otherNode = "88".repeat(32);
    expect(processControlOperation({ ...request, node_key: otherNode, mutation: false }, first.reservation))
      .toMatchObject({ verdict: "accept", action: "execute" });
    expect(processControlOperation({ ...request, node_key: otherNode, inherently_idempotent: true }, first.reservation))
      .toMatchObject({ verdict: "accept", action: "execute" });
    expect(processControlOperation({ ...request, node_key: otherNode }, first.reservation))
      .toEqual({ verdict: "indeterminate", reason_code: "control-operation-indeterminate" });
  });

  it("bounds delivery retention and excludes transient authority from backup", () => {
    expect(retentionDecision({ created_at: 1_000, requested_retention_seconds: 90_000, request_expires_at: 4_000 }))
      .toEqual({
        expires_at: 4_000,
        retention_seconds: 86_400,
        excluded_from_backup: ["access_tokens", "control_frames", "device_codes", "mls_state", "transcripts"],
      });
  });
});

describe("optional recovery profiles", () => {
  const expected = {
    repositories: [{ rid: "rad:z3abc", head: "aa".repeat(20) }],
    portable_manifest_id: "55".repeat(32), object_digests: ["66".repeat(32)],
  };

  it("requires unlock only for preparation, relocks before transfer, and exact completion", () => {
    expect(evaluateEpochActivation({
      epoch_unlocked: false, registration_valid: true, prepared: false,
      epoch_relocked_before_transfer: false, expected, completion: null,
    })).toEqual({ verdict: "reject", reason_code: "control-recovery-locked" });
    expect(evaluateEpochActivation({
      epoch_unlocked: true, registration_valid: true, prepared: false,
      epoch_relocked_before_transfer: false, expected, completion: null,
    })).toEqual({ verdict: "accept", action: "prepare-and-relock" });
    expect(evaluateEpochActivation({
      epoch_unlocked: false, registration_valid: true, prepared: true,
      epoch_relocked_before_transfer: true, expected, completion: expected,
    })).toEqual({ verdict: "accept", action: "activate" });
    expect(evaluateEpochActivation({
      epoch_unlocked: false, registration_valid: true, prepared: true,
      epoch_relocked_before_transfer: true, expected,
      completion: { ...expected, portable_manifest_id: "77".repeat(32) },
    })).toEqual({ verdict: "reject", reason_code: "control-activation-mismatch" });
  });

  it("confines temporary private-Radicle recovery", () => {
    const grant = {
      prospective_nid: "did:key:z6MkhProspective", repositories: ["rad:z3abc"],
      direction: "fetch" as const, byte_ceiling: 1_000, expires_at: 2_000,
    };
    expect(evaluateRecoveryAccess({ grant, nid: grant.prospective_nid, repository: "rad:z3abc", direction: "fetch", bytes: 500, now: 1_000 }))
      .toEqual({ verdict: "accept" });
    expect(evaluateRecoveryAccess({ grant, nid: grant.prospective_nid, repository: "rad:z3other", direction: "fetch", bytes: 500, now: 1_000 }))
      .toEqual({ verdict: "reject", reason_code: "control-recovery-grant-invalid" });
  });

  it("requires SFTP address/process separation, dual authentication, rooting, limits, and expiry", () => {
    const grant = {
      onion_address: `${"a".repeat(56)}.onion`, radicle_onion_address: `${"b".repeat(56)}.onion`,
      service_process_id: "sftp-1", radicle_process_id: "radicle-1",
      tor_client_key: "tor-key", ssh_client_key: "ssh-key", ssh_host_key: "host-key",
      root: "/grant", resources: [{ path: "/grant/archive.bin", direction: "read" as const, size: 1_000 }],
      byte_ceiling: 1_000, expires_at: 2_000,
      channels_disabled: true, renewal_overlap_seconds: 300, prior_endpoint_read_only: true,
    };
    const access = { grant, onion_address: grant.onion_address, tor_client_key: "tor-key", ssh_client_key: "ssh-key", ssh_host_key: "host-key", path: "/grant/archive.bin", direction: "read" as const, bytes: 1_000, now: 1_000 };
    expect(evaluateSftpAccess(access)).toEqual({ verdict: "accept" });
    expect(evaluateSftpAccess({ ...access, onion_address: grant.radicle_onion_address }))
      .toEqual({ verdict: "reject", reason_code: "control-sftp-denied" });
    expect(evaluateSftpAccess({ ...access, path: "/etc/passwd" }))
      .toEqual({ verdict: "reject", reason_code: "control-sftp-denied" });
    expect(evaluateSftpAccess({ ...access, now: 2_000 }))
      .toEqual({ verdict: "reject", reason_code: "control-sftp-denied" });
  });
});
