import {
  authorizeInvitation,
  evaluateEntitlementUpdate,
  evaluateEpochActivation,
  evaluateRecoveryAccess,
  evaluateSftpAccess,
  issueControlToken,
  processControlOperation,
  retentionDecision,
  validateControlTokenUse,
  type Entitlement,
  type OperationInput,
} from "./control-profile.js";
import { baseVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

const client = "11".repeat(32);
const node = "22".repeat(32);
const group = "33".repeat(32);
const jkt = "A".repeat(43);

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
    invitation_enabled: true,
    keypackage_valid: true,
    member_count: 2,
    node_account_matches: true,
    entitlement_state: "none" as const,
    method: "control.enrollment.start",
  };
  for (const [number, id, input] of [
    ["001", "invitation-enrollment-only", invitation],
    ["002", "invitation-disabled", { ...invitation, invitation_enabled: false }],
    ["003", "invitation-revoked", { ...invitation, entitlement_state: "revoked" as const }],
    ["004", "invitation-nonenrollment-rejected", { ...invitation, method: "config.get" }],
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

  const issuance = {
    entitlement_state: "active" as const,
    client_key: client,
    client_jkt: jkt,
    group_id: group,
    issuer: "https://node.example/oidc/persona",
    audience: "urn:heterodyne:control:node-a",
    node_key: node,
    authorization_id: "44".repeat(32),
    requested_lifetime_seconds: 300,
    entitlement_max_seconds: 3_600,
    node_policy_max_seconds: 3_600,
    extended_capability: false,
    now: 1_000,
    methods: ["config.get"],
    objects: ["config:ui"],
  };
  const issued = issueControlToken(issuance);
  if (issued.verdict !== "accept") throw new Error("Control token fixture failed");
  for (const [number, id, value] of [
    ["008", "token-default-five-minutes", issuance],
    ["009", "token-explicit-sixty-minutes", { ...issuance, requested_lifetime_seconds: 3_600, extended_capability: true }],
    ["010", "token-extension-missing-capability", { ...issuance, requested_lifetime_seconds: 301 }],
  ] as const) {
    add(number, id, `Node-scoped Control token issuance: ${id}.`, value, issueControlToken(value));
  }
  const tokenUse = {
    token: issued.token,
    signature_valid: true,
    now: 1_100,
    expected_issuer: issuance.issuer,
    expected_audience: issuance.audience,
    authenticated_sender_jkt: jkt,
    group_id: group,
    entitlement_state: "active" as const,
    method: "config.get",
    object: "config:ui",
  };
  for (const [number, id, value] of [
    ["011", "token-valid", tokenUse],
    ["012", "token-wrong-sender", { ...tokenUse, authenticated_sender_jkt: "B".repeat(43) }],
    ["013", "token-wrong-group", { ...tokenUse, group_id: "99".repeat(32) }],
    ["014", "token-wrong-node", { ...tokenUse, expected_audience: "urn:heterodyne:control:node-b" }],
    ["015", "token-scope-rejected", { ...tokenUse, method: "config.put" }],
  ] as const) {
    add(number, id, `Marmot-bound Control token use: ${id}.`, value, validateControlTokenUse(value));
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
