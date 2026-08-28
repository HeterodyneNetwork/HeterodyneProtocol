import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import { bytesToHex } from "./hex.js";
import { proofBytes } from "./proof-bytes.js";
import {
  createWorkspaceAssuranceAuthority,
  evaluateWorkspaceAssuranceTransition,
  type WorkspaceAssuranceConfig,
} from "./workspace-assurance.js";

const WORKSPACE_KEY = "11".repeat(32);
const INCEPTION_EVENT_ID = "22".repeat(32);
const PREVIOUS_POLICY_HEAD = "33".repeat(32);
const NEXT_POLICY_HEAD = "44".repeat(32);
const EVALUATED_AT = 1_720_000_400;
const AUTHORIZATION_SECRET = "55".repeat(32);
const AUTHORIZATION_KEY = bytesToHex(schnorr.getPublicKey(AUTHORIZATION_SECRET));
type EnrollmentInput = Parameters<WorkspaceAssuranceConfig[
  "resolve_verified_enrollment"
]>[0];
type RemovalInput = Parameters<WorkspaceAssuranceConfig["authorize_removal"]>[0];

const ASSURANCE = Object.freeze({
  profile: "heterodyne.workspace.assurance.v1" as const,
  inception_event_id: INCEPTION_EVENT_ID,
  required_state: "verified" as const,
});
const REPLACEMENT_ASSURANCE = Object.freeze({
  ...ASSURANCE,
  inception_event_id: "23".repeat(32),
});

type AttestationInput = Readonly<{
  workspace_key: string;
  previous_policy_head: string | null;
  next_policy_head: string;
  previous_assurance: typeof ASSURANCE | null;
  next_assurance: typeof ASSURANCE | null;
  transition_digest: string;
  evaluated_at: number;
}>;

const signedAuthorization = (
  input: AttestationInput,
  changed: Readonly<Record<string, unknown>> = {},
) => {
  const unsigned = {
    profile: "heterodyne.workspace.assurance-authorization.v1",
    suite: "bip340",
    verification_key: AUTHORIZATION_KEY,
    ...input,
    ...changed,
  };
  return {
    ...unsigned,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-workspace-assurance-authorization-v1", unsigned),
      AUTHORIZATION_SECRET,
    )),
  };
};

const transition = (
  previousAssurance: typeof ASSURANCE | null,
  nextAssurance: typeof ASSURANCE | null,
) => ({
  workspace_key: WORKSPACE_KEY,
  previous_policy_head: PREVIOUS_POLICY_HEAD,
  next_policy_head: NEXT_POLICY_HEAD,
  previous_assurance: previousAssurance,
  next_assurance: nextAssurance,
});

const verifiedEnrollment = (evaluatedAt = EVALUATED_AT) => ({
  state: "verified" as const,
  active_key: WORKSPACE_KEY,
  inception_event_id: INCEPTION_EVENT_ID,
  evaluated_at: evaluatedAt,
});

const authority = (overrides: Partial<{
  trusted_now: () => number;
  resolve_verified_enrollment: (input: Readonly<{
    workspace_key: string;
    inception_event_id: string;
    evaluated_at: number;
  }>) => unknown;
  authorize_removal: (input: Readonly<{
    workspace_key: string;
    inception_event_id: string;
    transition_digest: string;
    evaluated_at: number;
  }>) => unknown;
  attest_transition: (input: AttestationInput) => unknown;
}> = {}) => createWorkspaceAssuranceAuthority({
  trusted_now: () => EVALUATED_AT,
  resolve_verified_enrollment: () => verifiedEnrollment(),
  authorize_removal: ({ transition_digest, evaluated_at }: RemovalInput) => ({
    authorized: true,
    transition_digest,
    evaluated_at,
  }),
  attest_transition: (input: AttestationInput) => signedAuthorization(input),
  ...overrides,
});

describe("Workspace optional Assurance authority", () => {
  it("allows a bare-to-bare transition without an Assurance authority", () => {
    expect(evaluateWorkspaceAssuranceTransition(null, transition(null, null)))
      .toEqual({ verdict: "accept", authorization: null });
    expect(evaluateWorkspaceAssuranceTransition(null, transition(null, ASSURANCE)))
      .toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });
  });

  it("activates only a callback-verified enrollment bound to the Workspace key", () => {
    const calls: unknown[] = [];
    const configured = authority({
      resolve_verified_enrollment: (input) => {
        calls.push(input);
        return verifiedEnrollment();
      },
    });

    expect(evaluateWorkspaceAssuranceTransition(
      configured,
      transition(null, ASSURANCE),
    )).toMatchObject({ verdict: "accept", authorization: expect.any(Object) });
    expect(calls).toEqual([{
      workspace_key: WORKSPACE_KEY,
      inception_event_id: INCEPTION_EVENT_ID,
      evaluated_at: EVALUATED_AT,
    }]);
  });

  it("rejects pending, stale, and mismatched enrollment results", () => {
    const pending = authority({
      resolve_verified_enrollment: () => ({
        state: "pending",
        active_key: WORKSPACE_KEY,
        inception_event_id: INCEPTION_EVENT_ID,
        evaluated_at: EVALUATED_AT,
      }),
    });
    expect(evaluateWorkspaceAssuranceTransition(pending, transition(null, ASSURANCE)))
      .toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });

    const stale = authority({
      resolve_verified_enrollment: () => verifiedEnrollment(EVALUATED_AT - 1),
    });
    expect(evaluateWorkspaceAssuranceTransition(stale, transition(ASSURANCE, ASSURANCE)))
      .toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });

    for (const resolve_verified_enrollment of [
      () => ({ ...verifiedEnrollment(), active_key: "66".repeat(32) }),
      () => ({ ...verifiedEnrollment(), inception_event_id: "77".repeat(32) }),
    ]) {
      expect(evaluateWorkspaceAssuranceTransition(
        authority({ resolve_verified_enrollment }),
        transition(null, ASSURANCE),
      )).toEqual({
        verdict: "reject",
        reason_code: "workspace-assurance-state-required",
      });
    }
  });

  it("rejects active-key-only removal and accepts matching dual authorization", () => {
    const unilateral = authority({ authorize_removal: () => undefined });
    expect(evaluateWorkspaceAssuranceTransition(unilateral, transition(ASSURANCE, null)))
      .toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });

    let removalInput: unknown;
    const dual = authority({
      authorize_removal: (input) => {
        removalInput = input;
        return {
          authorized: true,
          transition_digest: input.transition_digest,
          evaluated_at: input.evaluated_at,
        };
      },
    });
    expect(evaluateWorkspaceAssuranceTransition(dual, transition(ASSURANCE, null)))
      .toMatchObject({ verdict: "accept", authorization: expect.any(Object) });
    expect(removalInput).toEqual({
      workspace_key: WORKSPACE_KEY,
      inception_event_id: INCEPTION_EVENT_ID,
      transition_digest: "2255058e3826813a633e316c6ffdf5d3d8b0970e042a54a2686ed0792dba1367",
      evaluated_at: EVALUATED_AT,
    });
  });

  it("rejects a removal result for another digest or trusted clock sample", () => {
    for (const authorize_removal of [
      () => ({
        authorized: true,
        transition_digest: "55".repeat(32),
        evaluated_at: EVALUATED_AT,
      }),
      ({ transition_digest }: { transition_digest: string }) => ({
        authorized: true,
        transition_digest,
        evaluated_at: EVALUATED_AT - 1,
      }),
    ]) {
      expect(evaluateWorkspaceAssuranceTransition(
        authority({ authorize_removal }),
        transition(ASSURANCE, null),
      )).toEqual({
        verdict: "reject",
        reason_code: "workspace-assurance-state-required",
      });
    }
  });

  it("captures all callback identities once from own data descriptors", () => {
    const calls: string[] = [];
    const config: {
      trusted_now: () => number;
      resolve_verified_enrollment: (input: EnrollmentInput) => unknown;
      authorize_removal: (input: RemovalInput) => unknown;
      attest_transition: (input: AttestationInput) => unknown;
    } = {
      trusted_now: () => {
        calls.push("trusted-now-original");
        return EVALUATED_AT;
      },
      resolve_verified_enrollment: () => {
        calls.push("resolve-original");
        return verifiedEnrollment();
      },
      authorize_removal: ({ transition_digest, evaluated_at }: RemovalInput) => {
        calls.push("authorize-original");
        return { authorized: true, transition_digest, evaluated_at };
      },
      attest_transition: (input: AttestationInput) => {
        calls.push("attest-original");
        return signedAuthorization(input);
      },
    };
    const configured = createWorkspaceAssuranceAuthority(config);
    config.trusted_now = () => 0;
    config.resolve_verified_enrollment = () => ({ state: "pending" });
    config.authorize_removal = () => ({ authorized: false });
    config.attest_transition = () => ({ authorized: false });

    expect(evaluateWorkspaceAssuranceTransition(configured, transition(ASSURANCE, null)))
      .toMatchObject({ verdict: "accept", authorization: expect.any(Object) });
    expect(calls).toEqual([
      "trusted-now-original",
      "resolve-original",
      "authorize-original",
      "attest-original",
    ]);

    let getterCalls = 0;
    const accessorConfig = {
      resolve_verified_enrollment: () => verifiedEnrollment(),
      authorize_removal: () => undefined,
      attest_transition: () => undefined,
    } as Record<string, unknown>;
    Object.defineProperty(accessorConfig, "trusted_now", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return () => EVALUATED_AT;
      },
    });
    expect(() => createWorkspaceAssuranceAuthority(accessorConfig)).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });

  it("rejects proxy, accessor, and open callback results without reading hostile members", () => {
    let proxyTraps = 0;
    const proxied = new Proxy(verifiedEnrollment(), {
      ownKeys(target) {
        proxyTraps += 1;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, member) {
        proxyTraps += 1;
        return Object.getOwnPropertyDescriptor(target, member);
      },
      getPrototypeOf() {
        proxyTraps += 1;
        return Object.prototype;
      },
    });
    expect(evaluateWorkspaceAssuranceTransition(
      authority({ resolve_verified_enrollment: () => proxied }),
      transition(null, ASSURANCE),
    )).toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });
    expect(proxyTraps).toBe(0);

    let getterCalls = 0;
    const accessor = Object.defineProperty(
      { ...verifiedEnrollment() },
      "state",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          return "verified";
        },
      },
    );
    expect(evaluateWorkspaceAssuranceTransition(
      authority({ resolve_verified_enrollment: () => accessor }),
      transition(null, ASSURANCE),
    )).toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });
    expect(getterCalls).toBe(0);

    expect(evaluateWorkspaceAssuranceTransition(
      authority({
        resolve_verified_enrollment: () => ({ ...verifiedEnrollment(), proof: true }),
      }),
      transition(null, ASSURANCE),
    )).toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });

    let removalProxyTraps = 0;
    const removalProxyAuthority = authority({
      authorize_removal: ({ transition_digest, evaluated_at }) => new Proxy({
        authorized: true,
        transition_digest,
        evaluated_at,
      }, {
        ownKeys(target) {
          removalProxyTraps += 1;
          return Reflect.ownKeys(target);
        },
      }),
    });
    expect(evaluateWorkspaceAssuranceTransition(
      removalProxyAuthority,
      transition(ASSURANCE, null),
    )).toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });
    expect(removalProxyTraps).toBe(0);

    let removalGetterCalls = 0;
    const removalAccessorAuthority = authority({
      authorize_removal: ({ transition_digest, evaluated_at }) => Object.defineProperty({
        transition_digest,
        evaluated_at,
      }, "authorized", {
        enumerable: true,
        get() {
          removalGetterCalls += 1;
          return true;
        },
      }),
    });
    expect(evaluateWorkspaceAssuranceTransition(
      removalAccessorAuthority,
      transition(ASSURANCE, null),
    )).toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });
    expect(removalGetterCalls).toBe(0);
  });

  it("rejects caller-supplied state labels before invoking embedding callbacks", () => {
    let callbackCalls = 0;
    const configured = authority({
      trusted_now: () => {
        callbackCalls += 1;
        return EVALUATED_AT;
      },
    });
    expect(evaluateWorkspaceAssuranceTransition(configured, {
      ...transition(null, ASSURANCE),
      state: "verified",
    })).toEqual({ verdict: "reject", reason_code: "workspace-assurance-state-required" });
    expect(callbackCalls).toBe(0);
  });

  it("returns a signed durable authorization for every Assurance profile change", () => {
    const inputs: AttestationInput[] = [];
    const configured = createWorkspaceAssuranceAuthority({
      trusted_now: () => EVALUATED_AT,
      resolve_verified_enrollment: ({ workspace_key, inception_event_id, evaluated_at }:
        EnrollmentInput) => ({
        state: "verified",
        active_key: workspace_key,
        inception_event_id,
        evaluated_at,
      }),
      authorize_removal: ({ transition_digest, evaluated_at }: RemovalInput) => ({
        authorized: true,
        transition_digest,
        evaluated_at,
      }),
      attest_transition: (input: AttestationInput) => {
        inputs.push(input);
        return signedAuthorization(input);
      },
    });
    const changes = [
      transition(null, ASSURANCE),
      transition(ASSURANCE, REPLACEMENT_ASSURANCE),
      transition(ASSURANCE, null),
    ];
    const decisions = changes.map((change) =>
      evaluateWorkspaceAssuranceTransition(configured, change));
    for (const decision of decisions) {
      expect(decision).toMatchObject({
        verdict: "accept",
        authorization: {
          profile: "heterodyne.workspace.assurance-authorization.v1",
          suite: "bip340",
          verification_key: AUTHORIZATION_KEY,
          workspace_key: WORKSPACE_KEY,
          previous_policy_head: PREVIOUS_POLICY_HEAD,
          next_policy_head: NEXT_POLICY_HEAD,
          transition_digest: expect.stringMatching(/^[0-9a-f]{64}$/u),
          evaluated_at: EVALUATED_AT,
          signature: expect.stringMatching(/^[0-9a-f]{128}$/u),
        },
      });
    }
    expect(inputs).toHaveLength(3);
    expect(inputs[2]).toEqual({
      workspace_key: WORKSPACE_KEY,
      previous_policy_head: PREVIOUS_POLICY_HEAD,
      next_policy_head: NEXT_POLICY_HEAD,
      previous_assurance: ASSURANCE,
      next_assurance: null,
      transition_digest: "2255058e3826813a633e316c6ffdf5d3d8b0970e042a54a2686ed0792dba1367",
      evaluated_at: EVALUATED_AT,
    });
  });

  it("rejects stale, mismatched, open, and forged durable callback receipts", () => {
    const change = transition(ASSURANCE, null);
    const invalidAttesters = [
      (input: AttestationInput) => signedAuthorization(input, {
        evaluated_at: input.evaluated_at - 1,
      }),
      (input: AttestationInput) => signedAuthorization(input, {
        next_policy_head: "66".repeat(32),
      }),
      (input: AttestationInput) => ({ ...signedAuthorization(input), proof: true }),
      (input: AttestationInput) => ({
        ...signedAuthorization(input),
        signature: "00".repeat(64),
      }),
    ];
    for (const attest_transition of invalidAttesters) {
      const configured = createWorkspaceAssuranceAuthority({
        trusted_now: () => EVALUATED_AT,
        resolve_verified_enrollment: () => verifiedEnrollment(),
        authorize_removal: ({ transition_digest, evaluated_at }: RemovalInput) => ({
          authorized: true,
          transition_digest,
          evaluated_at,
        }),
        attest_transition,
      });
      expect(evaluateWorkspaceAssuranceTransition(configured, change)).toEqual({
        verdict: "reject",
        reason_code: "workspace-assurance-state-required",
      });
    }
  });
});
