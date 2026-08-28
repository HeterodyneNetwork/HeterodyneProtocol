import { createHash } from "node:crypto";
import { nip19 } from "nostr-tools";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  createAuthorizationFreshnessAuthority,
  evaluateAuthorizationFreshness,
  type CurrentAuthorizationView,
} from "./authorization-freshness.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import {
  authorizeInvitation,
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
import { buildFixtures } from "./fixtures.js";
import { utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import {
  continuityManifestDigest,
  createContinuityAuthorityProof,
  type ContinuityManifest,
  type ContinuityManifestBody,
} from "./token-status.js";

const client = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const node = "22".repeat(32);
const group = "33".repeat(32);
const jkt = "2JF8vg9etJzjFwZwmkvhBLLZ0bfMVVOPivYR5lFtcec";
const fixtures = buildFixtures();
let freshnessScenario: Awaited<ReturnType<typeof buildClaimLedgerScenario>>;

beforeAll(async () => {
  freshnessScenario = await buildClaimLedgerScenario(fixtures);
});

function currentAuthorizationView(clock: { now: number }): CurrentAuthorizationView {
  const state = freshnessScenario.issuerKeyEpochOneState;
  const personaKey = freshnessScenario.persona;
  const personaNpub = nip19.npubEncode(personaKey);
  const sha256 = (value: Uint8Array): string => createHash("sha256").update(value).digest("hex");
  const body: ContinuityManifestBody = {
    profile: "heterodyne-oidc-continuity-v1",
    repository_rid: freshnessScenario.rid,
    branch: "main",
    persona_npub: personaNpub,
    persona_key: personaKey,
    issuer: `https://node.example/oidc/${personaNpub}`,
    sequence: 0,
    predecessor_digest: null,
    max_checkpoint_age_seconds: 300,
    authorization_view_max_age: 300,
    current_jwks_sha256: sha256(utf8Bytes(jcsCanonicalize({ keys: [OIDC_RSA_ONE.public_jwk] }))),
    current_signing_key_id: OIDC_RSA_ONE.key_id,
    current_signing_jwk_sha256: sha256(utf8Bytes(jcsCanonicalize(OIDC_RSA_ONE.public_jwk))),
    retiring_signing_key_ids: [],
    retiring_jwks_sha256: [],
    status_lists: [],
    successor: null,
    authority: {
      writer_nid: freshnessScenario.writerOne.did_key,
      issued_at: state.checkpoint.observed_at,
      checkpoint: state.checkpoint,
    },
  };
  const manifest: ContinuityManifest = {
    ...body,
    authority_proof: createContinuityAuthorityProof(body, freshnessScenario.writerOne.private_key),
  };
  const authority = createAuthorizationFreshnessAuthority({
    repository_rid: manifest.repository_rid,
    persona_key: manifest.persona_key,
    manifest_digest: continuityManifestDigest(manifest),
  }, {
    trusted_now: () => clock.now,
    load_current_view: () => ({ manifest, ledger_state: state }),
  });
  const result = evaluateAuthorizationFreshness(authority, manifest);
  if (result.verdict !== "accept") throw new Error(`freshness fixture rejected: ${result.reason}`);
  return result.view;
}

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
  const object = { class: "config_namespace" as const, id: "ui" };
  let currentEntitlement: {
    record_id: string;
    persona: string;
    client_key: string;
    client_class: "automated";
    approving_node: string;
    approving_authority: string;
    methods: string[];
    objects: typeof object[];
    limits: Record<string, number>;
    capabilities: Array<"control.token.extended">;
    token_lifetime_default_seconds: 300;
    token_lifetime_max_seconds: number;
    inbound_execution: boolean;
    agent_role: string;
    predecessor: null;
    state: "active";
    created_at: number;
    expires_at: null;
    signer: string;
    signature: string;
  };
  let freshnessClock: { now: number };
  let issuance: {
    group_id: string;
    audience: string;
    node_key: string;
    issuance_nonce: string;
    requested_lifetime_seconds: number;
    node_policy_max_seconds: number;
    authorization_view: CurrentAuthorizationView;
    methods: string[];
    objects: typeof object[];
    entitlement: typeof currentEntitlement;
    limits: Record<string, number>;
  };

  beforeEach(() => {
    currentEntitlement = {
    record_id: "44".repeat(32),
    persona: freshnessScenario.persona,
    client_key: client,
    client_class: "automated" as const,
    approving_node: node,
    approving_authority: "fixture-local-approval",
    methods: ["config.get", "config.put"],
    objects: [object],
    limits: {
      max_content_bytes: 1_024,
      rate_window_seconds: 3_600,
      rate_count: 10,
      burst: 2,
      max_media_bytes: 2_048,
    },
    capabilities: [] as Array<"control.token.extended">,
    token_lifetime_default_seconds: 300 as const,
    token_lifetime_max_seconds: 3_600,
    inbound_execution: false,
    agent_role: "agent:newsletter",
    predecessor: null,
    state: "active" as const,
    created_at: 900,
    expires_at: null,
    signer: node,
    signature: "66".repeat(64),
    };
    freshnessClock = { now: freshnessScenario.issuerKeyEpochOneState.checkpoint.observed_at };
    issuance = {
      group_id: group,
      audience: "urn:heterodyne:control:node-a",
      node_key: node,
      issuance_nonce: "77".repeat(32),
      requested_lifetime_seconds: 300,
      node_policy_max_seconds: 3600,
      authorization_view: currentAuthorizationView(freshnessClock),
      methods: ["config.get"],
      objects: [object],
      entitlement: currentEntitlement,
      limits: { max_content_bytes: 1_024, rate_count: 10 },
    };
  });

  it("issues five minutes by default, permits explicit extension, and never refreshes", () => {
    expect(issueControlToken(issuance)).toMatchObject({
      verdict: "accept", lifetime_seconds: 300, refresh_token: null,
      token: {
        authorization_id: currentEntitlement.record_id,
        client_id: currentEntitlement.client_key,
        client_class: currentEntitlement.client_class,
        scope: "control",
        limits: issuance.limits,
        registry_checkpoint: freshnessScenario.issuerKeyEpochOneState.checkpoint.commit_oid,
        agent_role: currentEntitlement.agent_role,
        cnf: { jkt },
      },
    });
    expect(issueControlToken({
      ...issuance,
      entitlement: {
        ...currentEntitlement,
        capabilities: ["control.token.extended" as const],
      },
      requested_lifetime_seconds: 3_600,
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
      expected_issuer: token.token.iss,
      expected_audience: issuance.audience,
      expected_node_key: node,
      authenticated_sender_jkt: jkt,
      group_id: group,
      authorization_view: issuance.authorization_view,
      method: "config.get",
      object,
      current_entitlement: currentEntitlement,
      required_scope: "control",
      usage: { max_content_bytes: 512, rate_count: 1 },
      required_agent_role: "agent:newsletter",
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
      expected_issuer: token.token.iss,
      expected_audience: issuance.audience,
      expected_node_key: node,
      authenticated_sender_jkt: jkt,
      group_id: group,
      authorization_view: issuance.authorization_view,
      method: "config.get",
      object,
      current_entitlement: currentEntitlement,
      required_scope: "control",
      usage: { max_content_bytes: 512, rate_count: 1 },
      required_agent_role: "agent:newsletter",
    };
    for (const current_entitlement of [
      { ...currentEntitlement, record_id: "66".repeat(32) },
      { ...currentEntitlement, client_key: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" },
      { ...currentEntitlement, client_class: "human-light" as const },
      { ...currentEntitlement, methods: [] },
      { ...currentEntitlement, objects: [] },
      { ...currentEntitlement, limits: { ...currentEntitlement.limits, max_content_bytes: 256 } },
      { ...currentEntitlement, capabilities: ["control.token.extended" as const] },
      { ...currentEntitlement, agent_role: "agent:moderator" },
    ]) {
      expect(validateControlTokenUse({ ...use, current_entitlement })).toEqual({
        verdict: "reject",
        reason_code: "control-token-invalid",
      });
    }
  });

  it("caps authorization-view age at 300 seconds for minting and use", () => {
    freshnessClock.now = freshnessScenario.issuerKeyEpochOneState.checkpoint.observed_at + 300;
    issuance.authorization_view = currentAuthorizationView(freshnessClock);
    expect(issueControlToken(issuance)).toMatchObject({ verdict: "accept" });
    freshnessClock.now += 1;
    expect(issueControlToken(issuance))
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
