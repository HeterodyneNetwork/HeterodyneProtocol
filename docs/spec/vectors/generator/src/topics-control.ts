import { createHash } from "node:crypto";
import {
  authorizeInvitation,
  evaluateEntitlementUpdate,
  evaluateEpochActivation,
  evaluateAuthorizationFreshness,
  evaluateDeviceAuthorizationAttempt,
  evaluateInvitePreauthorization,
  evaluatePendingEnrollment,
  evaluateRecoveryAccess,
  evaluateSftpAccess,
  issueControlToken,
  processControlOperation,
  retentionDecision,
  validateControlTokenUse,
  type ControlAuthorizationRecord,
  type ControlToken,
  type Entitlement,
  type OperationInput,
  type TokenIssuanceInput,
  type TokenUseInput,
} from "./control-profile.js";
import { jcsCanonicalize } from "./jcs.js";
import { baseVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

const client = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const otherClient = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const node = "22".repeat(32);
const group = "33".repeat(32);
const jkt = "2JF8vg9etJzjFwZwmkvhBLLZ0bfMVVOPivYR5lFtcec";
const otherJkt = "GKeBJdbiPSiSZ8qwiPH8NBmmtrLcKCZ7gYOzX0hwzlM";

function withRecomputedJti(token: ControlToken): ControlToken {
  const { jti: _jti, ...claims } = token;
  return {
    ...claims,
    jti: createHash("sha256")
      .update(`heterodyne-control-token-jti-v1\0${jcsCanonicalize(claims)}`)
      .digest("hex"),
  };
}

export function buildControlVectors(): AuthoredVector[] {
  const vectors: AuthoredVector[] = [];
  const add = (
    number: string,
    id: string,
    description: string,
    input: Record<string, unknown>,
    expected_output: Record<string, unknown>,
  ) => vectors.push({
    relativePath: `control/${number}-${id}.json`,
    vector: baseVector({
      vector_id: `control/${id}`,
      spec_refs: [],
      description,
      direction: "consume",
      input,
      expected_output,
    }),
  });

  const invitation = {
    invitation_mode: "permanent" as const,
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
  for (const [number, id, input] of [
    ["001", "invitation-enrollment-only", invitation],
    ["002", "invitation-disabled", { ...invitation, invitation_mode: "off" as const }],
    ["003", "invitation-revoked", { ...invitation, entitlement_state: "revoked" as const }],
    ["004", "invitation-nonenrollment-rejected", { ...invitation, method: "config.get" }],
    ["033", "invitation-account-cap", { ...invitation, pending_for_account: 1 }],
    ["034", "invitation-global-cap", { ...invitation, global_pending: 10 }],
    ["035", "invitation-rate-limited", { ...invitation, welcome_rate_remaining: 0 }],
    ["036", "invitation-replenishment-paused", { ...invitation, global_pending: 10, public_pool_replenishment_requested: true }],
    ["037", "invitation-reserved-slot", { ...invitation, invitation_mode: "off" as const, entitlement_state: "active" as const, explicitly_approved: true, global_pending: 10 }],
  ] as const) {
    add(number, id, `Marmot Control invitation decision: ${id}.`, input, authorizeInvitation(input));
  }

  const entitlement: Entitlement = {
    record_id: "44".repeat(32),
    client_key: client,
    predecessor: null,
    state: "active",
    methods: ["config.get", "config.put"],
    objects: ["config:feeds", "config:ui"],
    authorized_writer: true,
    explicit_consent: true,
  };
  const entitlementCases: Array<[string, string, Entitlement]> = [
    ["005", "entitlement-reduction", { ...entitlement, record_id: "45".repeat(32), predecessor: entitlement.record_id, methods: ["config.get"], explicit_consent: false }],
    ["006", "entitlement-expansion-rejected", { ...entitlement, record_id: "46".repeat(32), predecessor: entitlement.record_id, methods: [...entitlement.methods, "publish"], explicit_consent: false }],
    ["007", "entitlement-revocation-absorbing", { ...entitlement, record_id: "47".repeat(32), predecessor: entitlement.record_id, state: "revoked" as const, methods: [], objects: [], explicit_consent: false }],
  ];
  for (const [number, id, next] of entitlementCases) {
    add(number, id, `Private Control entitlement decision: ${id}.`, { current: entitlement, next }, evaluateEntitlementUpdate(entitlement, next));
  }

  const object = { class: "config_namespace" as const, id: "ui" };
  const tokenEntitlement: ControlAuthorizationRecord = {
    record_id: "44".repeat(32),
    persona: "aa".repeat(32),
    client_key: client,
    client_class: "automated",
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
    capabilities: [],
    token_lifetime_default_seconds: 300,
    token_lifetime_max_seconds: 3_600,
    inbound_execution: false,
    agent_role: "agent:newsletter",
    predecessor: null,
    state: "active",
    created_at: 900,
    expires_at: null,
    signer: node,
    signature: "66".repeat(64),
  };
  const extendedTokenEntitlement: ControlAuthorizationRecord = {
    ...tokenEntitlement,
    capabilities: ["control.token.extended"],
  };
  const { agent_role: _agentRole, ...tokenEntitlementWithoutRole } = tokenEntitlement;
  const humanTokenEntitlement: ControlAuthorizationRecord = {
    ...tokenEntitlementWithoutRole,
    client_class: "human-light",
  };
  const issuance: TokenIssuanceInput = {
    entitlement: tokenEntitlement,
    group_id: group,
    issuer: "https://node.example/oidc/persona",
    audience: "urn:heterodyne:control:node-a",
    node_key: node,
    registry_checkpoint: "55".repeat(32),
    issuance_nonce: "77".repeat(32),
    requested_lifetime_seconds: 300,
    node_policy_max_seconds: 3_600,
    now: 1_000,
    authorization_view_authenticated: true,
    authorization_view_conflicted: false,
    authorization_view_age_seconds: 0,
    methods: ["config.get"],
    objects: [object],
    limits: { max_content_bytes: 1_024, rate_count: 10 },
  };
  const issued = issueControlToken(issuance);
  if (issued.verdict !== "accept") throw new Error("Control token fixture failed");
  const issuedExtended = issueControlToken({
    ...issuance,
    entitlement: extendedTokenEntitlement,
    requested_lifetime_seconds: 3_600,
    issuance_nonce: "78".repeat(32),
  });
  if (issuedExtended.verdict !== "accept") {
    throw new Error("Extended Control token fixture failed");
  }
  const tokenIssuanceCases: Array<[string, string, TokenIssuanceInput]> = [
    ["008", "token-default-five-minutes", issuance],
    ["009", "token-explicit-sixty-minutes", {
      ...issuance,
      entitlement: extendedTokenEntitlement,
      requested_lifetime_seconds: 3_600,
      issuance_nonce: "78".repeat(32),
    }],
    ["010", "token-extension-missing-capability", { ...issuance, requested_lifetime_seconds: 301 }],
    ["064", "token-human-role-omitted", {
      ...issuance,
      entitlement: humanTokenEntitlement,
      issuance_nonce: "79".repeat(32),
    }],
  ];
  for (const [number, id, value] of tokenIssuanceCases) {
    add(number, id, `Node-scoped Control token issuance: ${id}.`, value, issueControlToken(value));
  }
  for (const [number, id, value] of [
    ["050", "pending-enrollment-live", { created_at: 1_000, now: 2_799 }],
    ["051", "pending-enrollment-expired", { created_at: 1_000, now: 2_800 }],
  ] as const) {
    add(number, id, `Enrollment-only lifetime: ${id}.`, value, evaluatePendingEnrollment(value));
  }
  const tokenUse: TokenUseInput = {
    token: issued.token,
    signature_valid: true,
    now: 1_100,
    expected_issuer: issuance.issuer,
    expected_audience: issuance.audience,
    expected_node_key: node,
    authenticated_sender_jkt: jkt,
    group_id: group,
    current_entitlement: tokenEntitlement,
    authorization_view_authenticated: true,
    authorization_view_conflicted: false,
    authorization_view_age_seconds: 100,
    current_registry_checkpoint: issuance.registry_checkpoint,
    required_scope: "control",
    method: "config.get",
    object,
    usage: { max_content_bytes: 512, rate_count: 1 },
    required_agent_role: "agent:newsletter",
  };
  const crossBoundToken = withRecomputedJti({
    ...issued.token,
    cnf: { jkt: otherJkt },
  });
  const tokenUseCases: Array<[string, string, TokenUseInput]> = [
    ["011", "token-valid", tokenUse],
    ["012", "token-wrong-sender", { ...tokenUse, authenticated_sender_jkt: otherJkt }],
    ["013", "token-wrong-group", { ...tokenUse, group_id: "99".repeat(32) }],
    ["014", "token-wrong-node", { ...tokenUse, expected_audience: "urn:heterodyne:control:node-b" }],
    ["015", "token-scope-rejected", { ...tokenUse, method: "config.put" }],
    ["038", "token-stale-authorization-view", { ...tokenUse, authorization_view_age_seconds: 301 }],
    ["052", "token-over-sixty-minutes-rejected", {
      ...tokenUse,
      token: { ...tokenUse.token, exp: tokenUse.token.iat + 3_601 },
    }],
    ["053", "token-entitlement-id-mismatch", {
      ...tokenUse,
      current_entitlement: { ...tokenEntitlement, record_id: "66".repeat(32) },
    }],
    ["054", "token-client-id-mismatch", {
      ...tokenUse,
      token: { ...tokenUse.token, client_id: otherClient },
    }],
    ["062", "token-client-key-mismatch", {
      ...tokenUse,
      current_entitlement: { ...tokenEntitlement, client_key: otherClient },
    }],
    ["055", "token-client-class-mismatch", {
      ...tokenUse,
      current_entitlement: { ...tokenEntitlement, client_class: "human-light" as const },
    }],
    ["056", "token-current-scope-mismatch", {
      ...tokenUse,
      current_entitlement: extendedTokenEntitlement,
    }],
    ["057", "token-current-method-mismatch", {
      ...tokenUse,
      current_entitlement: { ...tokenEntitlement, methods: ["config.put"] },
    }],
    ["058", "token-current-object-mismatch", {
      ...tokenUse,
      current_entitlement: {
        ...tokenEntitlement,
        objects: [{ class: "config_namespace", id: "feeds" }],
      },
    }],
    ["059", "token-current-limit-mismatch", {
      ...tokenUse,
      current_entitlement: {
        ...tokenEntitlement,
        limits: { ...tokenEntitlement.limits, max_content_bytes: 256 },
      },
    }],
    ["060", "token-registry-checkpoint-mismatch", {
      ...tokenUse,
      current_registry_checkpoint: "77".repeat(32),
    }],
    ["061", "token-agent-role-mismatch", {
      ...tokenUse,
      current_entitlement: { ...tokenEntitlement, agent_role: "agent:moderator" },
    }],
    ["063", "token-current-lifetime-mismatch", {
      ...tokenUse,
      token: issuedExtended.token,
      current_entitlement: {
        ...extendedTokenEntitlement,
        token_lifetime_max_seconds: 300,
      },
    }],
    ["065", "token-cross-bound-client-key", {
      ...tokenUse,
      token: crossBoundToken,
      authenticated_sender_jkt: otherJkt,
    }],
  ];
  for (const [number, id, value] of tokenUseCases) {
    add(number, id, `Marmot-bound Control token use: ${id}.`, value, validateControlTokenUse(value));
  }

  const differingGrantIssuance: TokenIssuanceInput = {
    ...issuance,
    methods: ["config.put"],
    issuance_nonce: "88".repeat(32),
  };
  const differingGrant = issueControlToken(differingGrantIssuance);
  if (differingGrant.verdict !== "accept") {
    throw new Error("Differing Control grant fixture failed");
  }
  add(
    "066",
    "token-same-second-differing-grant",
    "Same-second Control token grants have distinct issuance identifiers.",
    { first: issuance, second: differingGrantIssuance },
    {
      verdict: issued.token.jti === differingGrant.token.jti ? "reject" : "accept",
      distinct_jti: issued.token.jti !== differingGrant.token.jti,
    },
  );

  const deviceAuthorization = {
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
  for (const [number, id, value] of [
    ["039", "device-code-hardened", deviceAuthorization],
    ["040", "device-code-exhausted", { ...deviceAuthorization, failed_guesses: 5 }],
    ["041", "device-code-node-rate-limited", { ...deviceAuthorization, node_rate_allowed: false }],
    ["042", "device-code-display-mismatch", { ...deviceAuthorization, display_fingerprint_matches: false }],
  ] as const) {
    add(number, id, `OAuth Device Authorization decision: ${id}.`, value, evaluateDeviceAuthorizationAttempt(value));
  }

  for (const [number, id, value] of [
    ["043", "authorization-fresh-read", { authenticated: true, conflicted: false, age_seconds: 300, mutation: false, immediate_sync_succeeded: false }],
    ["044", "authorization-stale-read", { authenticated: true, conflicted: false, age_seconds: 301, mutation: false, immediate_sync_succeeded: false }],
    ["045", "authorization-mutation-sync-failed", { authenticated: true, conflicted: false, age_seconds: 10, mutation: true, immediate_sync_succeeded: false }],
  ] as const) {
    add(number, id, `Control authorization-view freshness: ${id}.`, value, evaluateAuthorizationFreshness(value));
  }

  const preauthorization = {
    purpose: "control-enrollment" as const,
    approval_mode: "preauthorized" as const,
    client_class: "automated" as const,
    expected_client_pubkey: client,
    unbound_bearer_enabled: false,
    node_allows_unbound_bearer: false,
    methods: ["agent.publish"],
    objects: ["feed:main"],
    limits: { requests_per_hour: 10 },
    agent_role: "newsletter",
    token_lifetime_ceiling_seconds: 300,
    keri_authorized_device: false,
  };
  for (const [number, id, value] of [
    ["046", "invite-preauthorization-key-bound", preauthorization],
    ["047", "invite-preauthorization-unbound-rejected", { ...preauthorization, expected_client_pubkey: null }],
    ["048", "invite-preauthorization-keri-rejected", { ...preauthorization, purpose: "device-enrollment" as const, client_class: "full-device" as const, keri_authorized_device: true }],
    ["049", "invite-preauthorization-unbound-higher-risk", { ...preauthorization, expected_client_pubkey: null, unbound_bearer_enabled: true, node_allows_unbound_bearer: true }],
  ] as const) {
    add(number, id, `Purpose-bound invite preauthorization: ${id}.`, value, evaluateInvitePreauthorization(value));
  }

  const operation: OperationInput = {
    node_key: node,
    group_id: group,
    request_id: "request-1",
    operation_id: "operation-1",
    method: "publish",
    object: "feed:main",
    payload_digest: "55".repeat(32),
    expires_at: 1_200,
    now: 1_000,
    mutation: true,
    inherently_idempotent: false,
    prior_result_proven: false,
  };
  const first = processControlOperation(operation);
  if (first.verdict !== "accept") throw new Error("Control reservation fixture failed");
  for (const [number, id, value, prior] of [
    ["016", "operation-first-reservation", operation, undefined],
    ["017", "operation-identical-join", operation, first.reservation],
    ["018", "operation-conflicting-bytes", { ...operation, payload_digest: "66".repeat(32) }, first.reservation],
    ["019", "failover-read", { ...operation, node_key: "77".repeat(32), mutation: false }, first.reservation],
    ["020", "failover-idempotent-mutation", { ...operation, node_key: "77".repeat(32), inherently_idempotent: true }, first.reservation],
    ["021", "failover-indeterminate-mutation", { ...operation, node_key: "77".repeat(32) }, first.reservation],
  ] as const) {
    add(number, id, `Control operation/failover decision: ${id}.`, { operation: value, ...(prior === undefined ? {} : { prior }) }, processControlOperation(value, prior));
  }

  const retention = { created_at: 1_000, requested_retention_seconds: 90_000, request_expires_at: 4_000 };
  add("022", "retention-ceiling-and-backup-exclusion", "Transient Control authority is bounded and excluded from backup.", retention, retentionDecision(retention));

  const expected = {
    repositories: [{ rid: "rad:z3abc", head: "aa".repeat(20) }],
    portable_manifest_id: "55".repeat(32),
    object_digests: ["66".repeat(32)],
  };
  for (const [number, id, value] of [
    ["023", "epoch-locked", { epoch_unlocked: false, registration_valid: true, prepared: false, epoch_relocked_before_transfer: false, expected, completion: null }],
    ["024", "epoch-prepare-and-relock", { epoch_unlocked: true, registration_valid: true, prepared: false, epoch_relocked_before_transfer: false, expected, completion: null }],
    ["025", "epoch-exact-activation", { epoch_unlocked: false, registration_valid: true, prepared: true, epoch_relocked_before_transfer: true, expected, completion: expected }],
    ["026", "epoch-activation-mismatch", { epoch_unlocked: false, registration_valid: true, prepared: true, epoch_relocked_before_transfer: true, expected, completion: { ...expected, portable_manifest_id: "77".repeat(32) } }],
  ] as const) {
    add(number, id, `Locked epoch bootstrap decision: ${id}.`, value, evaluateEpochActivation(value));
  }

  const recoveryGrant = { prospective_nid: "did:key:z6MkhProspective", repositories: ["rad:z3abc"], direction: "fetch" as const, byte_ceiling: 1_000, expires_at: 2_000 };
  for (const [number, id, value] of [
    ["027", "recovery-grant-accepted", { grant: recoveryGrant, nid: recoveryGrant.prospective_nid, repository: "rad:z3abc", direction: "fetch" as const, bytes: 500, now: 1_000 }],
    ["028", "recovery-grant-confined", { grant: recoveryGrant, nid: recoveryGrant.prospective_nid, repository: "rad:z3other", direction: "fetch" as const, bytes: 500, now: 1_000 }],
  ] as const) {
    add(number, id, `Private Radicle recovery decision: ${id}.`, value, evaluateRecoveryAccess(value));
  }

  const sftpGrant = {
    onion_address: `${"a".repeat(56)}.onion`,
    radicle_onion_address: `${"b".repeat(56)}.onion`,
    service_process_id: "sftp-1",
    radicle_process_id: "radicle-1",
    tor_client_key: "tor-key",
    ssh_client_key: "ssh-key",
    ssh_host_key: "host-key",
    root: "/grant",
    resources: [{ path: "/grant/archive.bin", direction: "read" as const, size: 1_000 }],
    byte_ceiling: 1_000,
    expires_at: 2_000,
    channels_disabled: true,
    renewal_overlap_seconds: 300,
    prior_endpoint_read_only: true,
  };
  const access = { grant: sftpGrant, onion_address: sftpGrant.onion_address, tor_client_key: "tor-key", ssh_client_key: "ssh-key", ssh_host_key: "host-key", path: "/grant/archive.bin", direction: "read" as const, bytes: 1_000, now: 1_000 };
  for (const [number, id, value] of [
    ["029", "sftp-grant-accepted", access],
    ["030", "sftp-address-separated", { ...access, onion_address: sftpGrant.radicle_onion_address }],
    ["031", "sftp-root-confined", { ...access, path: "/etc/passwd" }],
    ["032", "sftp-grant-expired", { ...access, now: 2_000 }],
  ] as const) {
    add(number, id, `Isolated SFTP recovery decision: ${id}.`, value, evaluateSftpAccess(value));
  }

  return vectors;
}
