import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import { bytesToHex } from "./hex.js";
import { proofBytes } from "./proof-bytes.js";
import {
  buildWorkspaceSecurityFixture,
  buildWorkspaceSecurityFixtureWithInvitationStore,
  type WorkspaceSecurityFixture,
} from
  "./workspace-security-evidence.js";
import {
  authenticateWorkspaceRepositoryView,
  consumeWorkspaceInvitationAcceptance,
  evaluateGrantActivation,
  ReferenceWorkspaceInvitationAcceptanceStore,
  resolveWorkspaceEffectiveAuthorization,
  type WorkspaceInvitationStoreRecord,
  workspaceObjectId,
} from "./workspace.js";

const WORKSPACE_SECRET = "01".repeat(32);
const SUBJECT_SECRET = "02".repeat(32);
const RESOLVER_SECRET = "07".repeat(32);
const DEVICE_ID = "81".repeat(32);
const LEAF = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

type RepositoryView = Readonly<{
  authority: object;
  evidence: Readonly<Record<string, unknown>>;
  objects: readonly Readonly<Record<string, unknown>>[];
}>;

const viewOf = (fixture: WorkspaceSecurityFixture): RepositoryView =>
  fixture.signed_repository_view as RepositoryView;

const authenticate = (fixture: WorkspaceSecurityFixture): object => {
  const result = authenticateWorkspaceRepositoryView(fixture.signed_repository_view);
  if (result.verdict !== "accept") throw new Error(`fixture rejected: ${result.reason_code}`);
  return result.state;
};

const grantOf = (fixture: WorkspaceSecurityFixture): Readonly<Record<string, unknown>> => {
  const grant = viewOf(fixture).objects.find((object) => object.object_type === "role-grant-v1");
  if (grant === undefined) throw new Error("fixture grant missing");
  return grant;
};

const grantOperationDigest = (grant: Readonly<Record<string, unknown>>): string => {
  const operation = { ...grant };
  delete operation.signature;
  delete operation.approval_ids;
  return bytesToHex(sha256(proofBytes(
    "heterodyne-workspace-grant-operation-v1",
    operation,
  )));
};

const grantApproval = (grant: Readonly<Record<string, unknown>>): Record<string, unknown> => {
  const operationDigest = grantOperationDigest(grant);
  const unsigned = {
    profile: "heterodyne.workspace-grant-approval.v1",
    spec_version: "heterodyne/0.6.0",
    workspace_key: grant.workspace_key,
    policy_head: grant.policy_head,
    predecessor: grant.predecessor,
    authority_checkpoint: grant.authority_checkpoint,
    operation_digest: operationDigest,
    approver_key: bytesToHex(schnorr.getPublicKey(WORKSPACE_SECRET)),
    issued_at: 1_720_000_200,
    expires_at: 1_720_000_650,
  };
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-grant-approval-v1", unsigned),
      WORKSPACE_SECRET,
      "00".repeat(32),
    )),
  };
};

const invitationAcceptance = (
  fixture: WorkspaceSecurityFixture,
  issuedAt = 1_720_000_200,
): Record<string, unknown> => {
  const grant = grantOf(fixture);
  const invitation = grant.invitation as Readonly<Record<string, unknown>>;
  const unsigned = {
    profile: "heterodyne.workspace-invitation-acceptance.v1",
    spec_version: "heterodyne/0.6.0",
    grant_id: fixture.grant_id,
    grant_operation_digest: grantOperationDigest(grant),
    workspace_key: grant.workspace_key,
    subject_account: fixture.subject,
    target_device: DEVICE_ID,
    target_leaf: LEAF,
    policy_head: grant.policy_head,
    predecessor: grant.predecessor,
    authority_checkpoint: grant.authority_checkpoint,
    repository_view_id: workspaceObjectId(viewOf(fixture).evidence),
    nonce_opening: "b1".repeat(32),
    nonce_commitment: invitation.nonce_commitment,
    issued_at: issuedAt,
    expires_at: 1_720_000_600,
  };
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-invitation-acceptance-v1", unsigned),
      SUBJECT_SECRET,
      "00".repeat(32),
    )),
  };
};

const activationAuthorization = (
  fixture: WorkspaceSecurityFixture,
  state: object,
): object => {
  const grant = grantOf(fixture);
  const result = resolveWorkspaceEffectiveAuthorization({
    authority: fixture.authority,
    current_state: state,
    actor_account: fixture.subject,
    actor_device: DEVICE_ID,
    actor_leaf: LEAF,
    operation_digest: grantOperationDigest(grant),
    requested_capabilities: grant.capabilities,
    requested_resources: [fixture.resource],
    requested_delegable: false,
  });
  if (result.verdict !== "accept") throw new Error(`authorization rejected: ${result.reason_code}`);
  return result.authorization;
};

const activationRequest = (
  fixture: WorkspaceSecurityFixture,
  state: object,
  authorization: object,
  acceptance: object,
): Record<string, unknown> => ({
  authority: fixture.authority,
  current_state: state,
  authorization,
  invitation_acceptance: acceptance,
  successor_reauthorization: null,
  grant_id: fixture.grant_id,
  membership: {
    authenticated_account: fixture.subject,
    accepted_device: DEVICE_ID,
    accepted_leaf: LEAF,
  },
  approvals: [grantApproval(grantOf(fixture))],
});

const supersedingRepositoryView = (
  fixture: WorkspaceSecurityFixture,
): Readonly<Record<string, unknown>> => {
  const view = viewOf(fixture);
  const unsigned = {
    ...view.evidence,
    observed_at: 1_720_000_101,
  };
  delete (unsigned as Record<string, unknown>).signature;
  return {
    authority: fixture.authority,
    evidence: {
      ...unsigned,
      signature: bytesToHex(schnorr.sign(
        proofBytes("heterodyne-workspace-repository-view-v1", unsigned),
        RESOLVER_SECRET,
        "00".repeat(32),
      )),
    },
    objects: view.objects,
  };
};

describe("Workspace signed current state security evidence", () => {
  it("BLUE TEAM VALIDATION: synthetic/local rejects a child wider than the signed root workspace-wide ceiling", () => {
    const fixture = buildWorkspaceSecurityFixture({
      root_capabilities: ["read"],
      ancestor_capabilities: [["read", "write"]],
      grant_capabilities: ["read", "write"],
      revoked: false,
    });
    const current = authenticateWorkspaceRepositoryView(fixture.signed_repository_view);
    expect(current).toEqual({ verdict: "reject", reason_code: "capability_escalation" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a signed grant wider than every ancestor", () => {
    const fixture = buildWorkspaceSecurityFixture({
      root_capabilities: ["read", "write"],
      ancestor_capabilities: [["read"]],
      grant_capabilities: ["read", "write"],
      revoked: false,
    });
    expect(authenticateWorkspaceRepositoryView(fixture.signed_repository_view)).toEqual({
      verdict: "reject",
      reason_code: "capability_escalation",
    });
  });

  it("resolves only the signed root, ancestor, and grant intersection", () => {
    const fixture = buildWorkspaceSecurityFixture({
      root_capabilities: ["read", "write"],
      ancestor_capabilities: [["read"]],
      grant_capabilities: ["read"],
      revoked: false,
    });
    const state = authenticate(fixture);
    const resolution = resolveWorkspaceEffectiveAuthorization({
      authority: fixture.authority,
      current_state: state,
      actor_account: fixture.subject,
      actor_device: DEVICE_ID,
      actor_leaf: LEAF,
      operation_digest: "d1".repeat(32),
      requested_capabilities: [fixture.action],
      requested_resources: [fixture.resource],
      requested_delegable: false,
    });
    expect(resolution).toMatchObject({
      verdict: "accept",
      normalized: { effective_capabilities: ["read"] },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local gives carrier, host, and repository writers no ambient authority", () => {
    const fixture = buildWorkspaceSecurityFixture({
      root_capabilities: ["read", "write"],
      ancestor_capabilities: [["read"]],
      grant_capabilities: ["read"],
      revoked: false,
    });
    const state = authenticate(fixture);
    for (const actor of ["a2".repeat(32), "a3".repeat(32), "a4".repeat(32)]) {
      expect(resolveWorkspaceEffectiveAuthorization({
        authority: fixture.authority,
        current_state: state,
        actor_account: actor,
        actor_device: DEVICE_ID,
        actor_leaf: LEAF,
        operation_digest: "d2".repeat(32),
        requested_capabilities: ["read"],
        requested_resources: [fixture.resource],
        requested_delegable: false,
      })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local denies a grant revoked in signed current state", () => {
    const fixture = buildWorkspaceSecurityFixture({
      root_capabilities: ["read"],
      ancestor_capabilities: [],
      grant_capabilities: ["read"],
      revoked: true,
    });
    const state = authenticate(fixture);
    expect(resolveWorkspaceEffectiveAuthorization({
      authority: fixture.authority,
      current_state: state,
      actor_account: fixture.subject,
      actor_device: DEVICE_ID,
      actor_leaf: LEAF,
      operation_digest: "d3".repeat(32),
      requested_capabilities: ["read"],
      requested_resources: [fixture.resource],
      requested_delegable: false,
    })).toEqual({ verdict: "reject", reason_code: "policy_denied" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxy, accessor, clone, and mutation inputs", () => {
    const fixture = buildWorkspaceSecurityFixture({
      root_capabilities: ["read"],
      ancestor_capabilities: [],
      grant_capabilities: ["read"],
      revoked: false,
    });
    let trapCalls = 0;
    const proxied = new Proxy(fixture.signed_repository_view, {
      get() {
        trapCalls += 1;
        throw new Error("proxy trap must not execute");
      },
    });
    expect(authenticateWorkspaceRepositoryView(proxied)).toEqual({
      verdict: "reject",
      reason_code: "workspace_schema_invalid",
    });
    expect(trapCalls).toBe(0);

    let getterCalls = 0;
    const accessor = Object.defineProperty({
      authority: fixture.authority,
      objects: viewOf(fixture).objects,
    }, "evidence", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return viewOf(fixture).evidence;
      },
    });
    expect(authenticateWorkspaceRepositoryView(accessor)).toEqual({
      verdict: "reject",
      reason_code: "workspace_schema_invalid",
    });
    expect(getterCalls).toBe(0);

    const state = authenticate(fixture);
    expect(resolveWorkspaceEffectiveAuthorization({
      authority: fixture.authority,
      current_state: structuredClone(state),
      actor_account: fixture.subject,
      actor_device: DEVICE_ID,
      actor_leaf: LEAF,
      operation_digest: "d4".repeat(32),
      requested_capabilities: ["read"],
      requested_resources: [fixture.resource],
      requested_delegable: false,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });

    const mutatedEvidence = structuredClone(viewOf(fixture).evidence) as Record<string, unknown>;
    mutatedEvidence.observed_at = 1_720_000_101;
    expect(authenticateWorkspaceRepositoryView({
      authority: fixture.authority,
      evidence: mutatedEvidence,
      objects: viewOf(fixture).objects,
    })).toEqual({ verdict: "reject", reason_code: "workspace_repository_invalid" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes invitation replay consuming and exact committed retry idempotent", () => {
    const fixture = buildWorkspaceSecurityFixture({
      root_capabilities: ["invite", "read"],
      ancestor_capabilities: [["invite", "read"]],
      grant_capabilities: ["invite", "read"],
      revoked: false,
    });
    const state = authenticate(fixture);
    const authorization = activationAuthorization(fixture, state);
    const signedAcceptance = invitationAcceptance(fixture);
    const first = consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: signedAcceptance,
    });
    expect(first).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (first.verdict !== "accept") throw new Error("first invitation acceptance rejected");
    expect(consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: signedAcceptance,
    })).toEqual({ verdict: "reject", reason_code: "workspace_replay" });

    const activated = evaluateGrantActivation(activationRequest(
      fixture,
      state,
      authorization,
      first.acceptance,
    ));
    expect(activated.verdict, JSON.stringify(activated)).toBe("accept");
    expect(activated).toMatchObject({ verdict: "accept", normalized: { active: true } });

    const retry = consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: signedAcceptance,
    });
    expect(retry).toEqual({ verdict: "accept", acceptance: first.acceptance });
    if (retry.verdict !== "accept") throw new Error("exact committed retry rejected");
    expect(evaluateGrantActivation(activationRequest(
      fixture,
      state,
      authorization,
      retry.acceptance,
    ))).toEqual(activated);
    expect(evaluateGrantActivation({
      ...activationRequest(fixture, state, authorization, retry.acceptance),
      approvals: [],
    })).toEqual({ verdict: "reject", reason_code: "workspace_replay" });
    expect(new Set([first.acceptance, retry.acceptance]).size).toBe(2);

    expect(consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: invitationAcceptance(fixture, 1_720_000_201),
    })).toEqual({ verdict: "reject", reason_code: "workspace_replay" });

    expect(authenticateWorkspaceRepositoryView(supersedingRepositoryView(fixture)))
      .toMatchObject({ verdict: "accept", state: expect.any(Object) });
    const staleViewRetry = consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: signedAcceptance,
    });
    expect(staleViewRetry).toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    expect(evaluateGrantActivation(activationRequest(
      fixture,
      state,
      authorization,
      first.acceptance,
    ))).toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rechecks signed current state at invitation activation effect time", () => {
    const fixture = buildWorkspaceSecurityFixture({
      root_capabilities: ["invite", "read"],
      ancestor_capabilities: [],
      grant_capabilities: ["invite", "read"],
      revoked: false,
    });
    const state = authenticate(fixture);
    const authorization = activationAuthorization(fixture, state);
    const reserved = consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: invitationAcceptance(fixture),
    });
    expect(reserved).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (reserved.verdict !== "accept") throw new Error("invitation reservation rejected");
    expect(authenticateWorkspaceRepositoryView(supersedingRepositoryView(fixture)))
      .toMatchObject({ verdict: "accept", state: expect.any(Object) });

    expect(evaluateGrantActivation(activationRequest(
      fixture,
      state,
      authorization,
      reserved.acceptance,
    ))).toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local fences unknown invitation activation outcomes as durable indeterminate", () => {
    const records = new Map<string, WorkspaceInvitationStoreRecord>();
    let executingTransitions = 0;
    const backend = {
      load(token: string): WorkspaceInvitationStoreRecord | null {
        const record = records.get(token);
        return record === undefined ? null : structuredClone(record);
      },
      compareAndSwap(
        token: string,
        expectedRevision: number | null,
        next: WorkspaceInvitationStoreRecord | null,
      ): "committed" | "conflict" | "unknown" {
        const existing = records.get(token);
        if ((existing?.revision ?? null) !== expectedRevision) return "conflict";
        if (next?.state === "committed") return "unknown";
        if (next === null) records.delete(token);
        else records.set(token, structuredClone(next));
        if (next?.state === "executing") {
          executingTransitions += 1;
        }
        return "committed";
      },
    };
    const invitationStore = new ReferenceWorkspaceInvitationAcceptanceStore(backend);
    backend.load = () => {
      throw new Error("replacement callback must not be observed");
    };
    backend.compareAndSwap = () => {
      throw new Error("replacement callback must not be observed");
    };
    const fixture = buildWorkspaceSecurityFixtureWithInvitationStore({
      root_capabilities: ["invite", "read"],
      ancestor_capabilities: [],
      grant_capabilities: ["invite", "read"],
      revoked: false,
    }, invitationStore);
    const state = authenticate(fixture);
    const authorization = activationAuthorization(fixture, state);
    const reserved = consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: invitationAcceptance(fixture),
    });
    expect(reserved).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (reserved.verdict !== "accept") throw new Error("invitation reservation rejected");
    const request = activationRequest(fixture, state, authorization, reserved.acceptance);
    expect(evaluateGrantActivation(request)).toEqual({
      verdict: "indeterminate",
      reason_code: "workspace_replay",
    });
    expect(evaluateGrantActivation(request)).toEqual({
      verdict: "indeterminate",
      reason_code: "workspace_replay",
    });
    expect(executingTransitions).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a store that lies about durable invitation acquire", () => {
    const records = new Map<string, WorkspaceInvitationStoreRecord>();
    let executingClaims = 0;
    let terminalClaims = 0;
    const backend = {
      load(token: string): WorkspaceInvitationStoreRecord | null {
        const record = records.get(token);
        return record === undefined ? null : structuredClone(record);
      },
      compareAndSwap(
        token: string,
        expectedRevision: number | null,
        next: WorkspaceInvitationStoreRecord | null,
      ): "committed" | "conflict" | "unknown" {
        const existing = records.get(token);
        if ((existing?.revision ?? null) !== expectedRevision) return "conflict";
        if (next?.state === "executing") {
          executingClaims += 1;
          return "committed";
        }
        if (next?.state === "committed") {
          terminalClaims += 1;
          return "committed";
        }
        if (next === null) records.delete(token);
        else records.set(token, structuredClone(next));
        return "committed";
      },
    };
    const fixture = buildWorkspaceSecurityFixtureWithInvitationStore({
      root_capabilities: ["invite", "read"],
      ancestor_capabilities: [],
      grant_capabilities: ["invite", "read"],
      revoked: false,
    }, new ReferenceWorkspaceInvitationAcceptanceStore(backend));
    const state = authenticate(fixture);
    const authorization = activationAuthorization(fixture, state);
    const reserved = consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: invitationAcceptance(fixture),
    });
    expect(reserved).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (reserved.verdict !== "accept") throw new Error("invitation reservation rejected");
    const request = activationRequest(fixture, state, authorization, reserved.acceptance);
    expect(evaluateGrantActivation(request)).toEqual({
      verdict: "indeterminate",
      reason_code: "workspace_replay",
    });
    expect(evaluateGrantActivation(request)).toEqual({
      verdict: "indeterminate",
      reason_code: "workspace_replay",
    });
    expect(executingClaims).toBe(1);
    expect(terminalClaims).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a store that lies about durable invitation terminal commit", () => {
    const records = new Map<string, WorkspaceInvitationStoreRecord>();
    let executingTransitions = 0;
    let terminalClaims = 0;
    const backend = {
      load(token: string): WorkspaceInvitationStoreRecord | null {
        const record = records.get(token);
        return record === undefined ? null : structuredClone(record);
      },
      compareAndSwap(
        token: string,
        expectedRevision: number | null,
        next: WorkspaceInvitationStoreRecord | null,
      ): "committed" | "conflict" | "unknown" {
        const existing = records.get(token);
        if ((existing?.revision ?? null) !== expectedRevision) return "conflict";
        if (next?.state === "committed") {
          terminalClaims += 1;
          return "committed";
        }
        if (next === null) records.delete(token);
        else records.set(token, structuredClone(next));
        if (next?.state === "executing") executingTransitions += 1;
        return "committed";
      },
    };
    const fixture = buildWorkspaceSecurityFixtureWithInvitationStore({
      root_capabilities: ["invite", "read"],
      ancestor_capabilities: [],
      grant_capabilities: ["invite", "read"],
      revoked: false,
    }, new ReferenceWorkspaceInvitationAcceptanceStore(backend));
    const state = authenticate(fixture);
    const authorization = activationAuthorization(fixture, state);
    const reserved = consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: invitationAcceptance(fixture),
    });
    expect(reserved).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (reserved.verdict !== "accept") throw new Error("invitation reservation rejected");
    const request = activationRequest(fixture, state, authorization, reserved.acceptance);
    expect(evaluateGrantActivation(request)).toEqual({
      verdict: "indeterminate",
      reason_code: "workspace_replay",
    });
    expect(evaluateGrantActivation(request)).toEqual({
      verdict: "indeterminate",
      reason_code: "workspace_replay",
    });
    expect(executingTransitions).toBe(1);
    expect(terminalClaims).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a self-consistent but wrong cached activation output", () => {
    const records = new Map<string, WorkspaceInvitationStoreRecord>();
    const backend = {
      load(token: string): WorkspaceInvitationStoreRecord | null {
        const record = records.get(token);
        return record === undefined ? null : structuredClone(record);
      },
      compareAndSwap(
        token: string,
        expectedRevision: number | null,
        next: WorkspaceInvitationStoreRecord | null,
      ): "committed" | "conflict" {
        const existing = records.get(token);
        if ((existing?.revision ?? null) !== expectedRevision) return "conflict";
        if (next === null) records.delete(token);
        else records.set(token, structuredClone(next));
        return "committed";
      },
    };
    const fixture = buildWorkspaceSecurityFixtureWithInvitationStore({
      root_capabilities: ["invite", "read"],
      ancestor_capabilities: [],
      grant_capabilities: ["invite", "read"],
      revoked: false,
    }, new ReferenceWorkspaceInvitationAcceptanceStore(backend));
    const state = authenticate(fixture);
    const authorization = activationAuthorization(fixture, state);
    const reserved = consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: invitationAcceptance(fixture),
    });
    expect(reserved).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (reserved.verdict !== "accept") throw new Error("invitation reservation rejected");
    const request = activationRequest(fixture, state, authorization, reserved.acceptance);
    expect(evaluateGrantActivation(request)).toMatchObject({ verdict: "accept" });
    const entry = [...records.entries()][0];
    if (entry === undefined || entry[1].activation_binding === null || entry[1].terminal === null) {
      throw new Error("committed terminal fixture missing");
    }
    const wrongOutput = { ...entry[1].terminal, active: false };
    records.set(entry[0], {
      ...entry[1],
      terminal: wrongOutput,
      terminal_digest: bytesToHex(sha256(proofBytes(
        "heterodyne-workspace-invitation-terminal-v1",
        { activation_binding: entry[1].activation_binding, output: wrongOutput },
      ))),
    });
    expect(evaluateGrantActivation(request)).toEqual({
      verdict: "reject",
      reason_code: "workspace_replay",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local revalidates current Workspace state after replay-store load", () => {
    const records = new Map<string, WorkspaceInvitationStoreRecord>();
    let activationLoads = 0;
    let executingTransitions = 0;
    let mutateOnLoad = false;
    let fixture: WorkspaceSecurityFixture | null = null;
    const backend = {
      load(token: string): WorkspaceInvitationStoreRecord | null {
        if (mutateOnLoad) {
          activationLoads += 1;
          if (activationLoads === 2 && fixture !== null) {
            expect(authenticateWorkspaceRepositoryView(supersedingRepositoryView(fixture)))
              .toMatchObject({ verdict: "accept", state: expect.any(Object) });
          }
        }
        const record = records.get(token);
        return record === undefined ? null : structuredClone(record);
      },
      compareAndSwap(
        token: string,
        expectedRevision: number | null,
        next: WorkspaceInvitationStoreRecord | null,
      ): "committed" | "conflict" | "unknown" {
        const existing = records.get(token);
        if ((existing?.revision ?? null) !== expectedRevision) return "conflict";
        if (next === null) records.delete(token);
        else records.set(token, structuredClone(next));
        if (next?.state === "executing") executingTransitions += 1;
        return "committed";
      },
    };
    fixture = buildWorkspaceSecurityFixtureWithInvitationStore({
      root_capabilities: ["invite", "read"],
      ancestor_capabilities: [],
      grant_capabilities: ["invite", "read"],
      revoked: false,
    }, new ReferenceWorkspaceInvitationAcceptanceStore(backend));
    const state = authenticate(fixture);
    const authorization = activationAuthorization(fixture, state);
    const reserved = consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: invitationAcceptance(fixture),
    });
    expect(reserved).toMatchObject({ verdict: "accept", acceptance: expect.any(Object) });
    if (reserved.verdict !== "accept") throw new Error("invitation reservation rejected");
    mutateOnLoad = true;
    expect(evaluateGrantActivation(activationRequest(
      fixture,
      state,
      authorization,
      reserved.acceptance,
    ))).toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    expect(executingTransitions).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local revalidates current Workspace state before invitation reservation CAS", () => {
    const records = new Map<string, WorkspaceInvitationStoreRecord>();
    let fixture: WorkspaceSecurityFixture | null = null;
    let mutateOnLoad = false;
    const backend = {
      load(token: string): WorkspaceInvitationStoreRecord | null {
        if (mutateOnLoad && fixture !== null) {
          mutateOnLoad = false;
          expect(authenticateWorkspaceRepositoryView(supersedingRepositoryView(fixture)))
            .toMatchObject({ verdict: "accept", state: expect.any(Object) });
        }
        const record = records.get(token);
        return record === undefined ? null : structuredClone(record);
      },
      compareAndSwap(
        token: string,
        expectedRevision: number | null,
        next: WorkspaceInvitationStoreRecord | null,
      ): "committed" | "conflict" {
        const existing = records.get(token);
        if ((existing?.revision ?? null) !== expectedRevision) return "conflict";
        if (next === null) records.delete(token);
        else records.set(token, structuredClone(next));
        return "committed";
      },
    };
    fixture = buildWorkspaceSecurityFixtureWithInvitationStore({
      root_capabilities: ["invite", "read"],
      ancestor_capabilities: [],
      grant_capabilities: ["invite", "read"],
      revoked: false,
    }, new ReferenceWorkspaceInvitationAcceptanceStore(backend));
    const state = authenticate(fixture);
    mutateOnLoad = true;
    expect(consumeWorkspaceInvitationAcceptance({
      authority: fixture.authority,
      current_state: state,
      acceptance: invitationAcceptance(fixture),
    })).toEqual({ verdict: "reject", reason_code: "checkpoint_stale" });
    expect(records.size).toBe(0);
  });
});
