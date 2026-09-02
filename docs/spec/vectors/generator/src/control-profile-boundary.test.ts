import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CurrentAuthorizationView } from "./authorization-freshness.js";

type EffectDecision =
  | {
    verdict: "accept";
    evaluated_at: number;
    checkpoint: { repository_rid: string; branch: "main"; commit_oid: string; observed_at: number };
    repository_rid: string;
    persona_key: string;
    manifest_digest: string;
    issuer: string;
  }
  | {
    verdict: "reject";
    reason: "oidc-checkpoint-stale" | "oidc-issuer-authority-invalid" | "control-authorization-view-stale";
  };

const effect = vi.hoisted(() => ({
  calls: 0,
  run: (_view: unknown): EffectDecision => ({
    verdict: "accept",
    evaluated_at: 1_000,
    checkpoint: {
      repository_rid: `rad:z${"1".repeat(48)}`,
      branch: "main",
      commit_oid: "aa".repeat(32),
      observed_at: 1_000,
    },
    repository_rid: `rad:z${"1".repeat(48)}`,
    persona_key: "11".repeat(32),
    manifest_digest: "bb".repeat(32),
    issuer: "https://node.example/oidc/test",
  }),
}));

vi.mock("./authorization-freshness.js", () => ({
  revalidateAuthorizationViewAtEffect: (view: unknown): EffectDecision => {
    effect.calls += 1;
    return effect.run(view);
  },
}));

import {
  commitControlEnrollment,
  issueControlToken,
  validateControlTokenUse,
  type ControlAuthorizationRecord,
  type ControlToken,
  type TokenIssuanceInput,
  type TokenUseInput,
} from "./control-profile.js";
import { jcsCanonicalize } from "./jcs.js";

const authorizationView = Object.freeze({}) as CurrentAuthorizationView;
const client = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const node = "22".repeat(32);
const group = "33".repeat(32);
const object = { class: "config_namespace" as const, id: "ui" };

const authorization: ControlAuthorizationRecord = {
  record_id: "44".repeat(32),
  persona: "11".repeat(32),
  client_key: client,
  client_class: "automated",
  approving_node: node,
  approving_authority: "fixture-local-approval",
  methods: ["config.get", "config.put"],
  objects: [object],
  limits: { calls: 5 },
  capabilities: ["control.token.extended"],
  token_lifetime_default_seconds: 300,
  token_lifetime_max_seconds: 3_600,
  inbound_execution: false,
  agent_role: "agent:test",
  predecessor: null,
  state: "active",
  created_at: 0,
  expires_at: null,
  signer: node,
  signature: "55".repeat(64),
};

function acceptedEffect(evaluatedAt = 1_000): EffectDecision {
  return {
    verdict: "accept",
    evaluated_at: evaluatedAt,
    checkpoint: {
      repository_rid: `rad:z${"1".repeat(48)}`,
      branch: "main",
      commit_oid: "aa".repeat(32),
      observed_at: evaluatedAt,
    },
    repository_rid: `rad:z${"1".repeat(48)}`,
    persona_key: authorization.persona,
    manifest_digest: "bb".repeat(32),
    issuer: "https://node.example/oidc/test",
  };
}

function issuanceInput(): TokenIssuanceInput {
  return {
    entitlement: structuredClone(authorization),
    group_id: group,
    audience: "urn:heterodyne:control:node-a",
    node_key: node,
    issuance_nonce: "66".repeat(32),
    requested_lifetime_seconds: 300,
    node_policy_max_seconds: 3_600,
    authorization_view: authorizationView,
    methods: ["config.get"],
    objects: [object],
    limits: { calls: 5 },
  };
}

function withRecomputedJti(token: ControlToken): ControlToken {
  const { jti: _jti, ...claims } = token;
  return {
    ...claims,
    jti: createHash("sha256")
      .update(`heterodyne-control-token-jti-v1\0${jcsCanonicalize(claims)}`)
      .digest("hex"),
  };
}

function acceptedToken(): ControlToken {
  const issued = issueControlToken(issuanceInput());
  if (issued.verdict !== "accept") throw new Error("fixture token failed");
  return issued.token;
}

function tokenUseInput(token: ControlToken): TokenUseInput {
  return {
    token,
    signature_valid: true,
    expected_issuer: token.iss,
    expected_audience: token.aud,
    expected_node_key: node,
    authenticated_sender_jkt: token.cnf.jkt,
    group_id: group,
    current_entitlement: structuredClone(authorization),
    authorization_view: authorizationView,
    required_scope: "control",
    method: "config.get",
    object,
    usage: { calls: 1 },
    required_agent_role: "agent:test",
  };
}

beforeEach(() => {
  effect.calls = 0;
  effect.run = () => acceptedEffect();
});

describe("Control effect input snapshots", () => {
  it("snapshots token issuance before effect-time revalidation mutates caller data", () => {
    const input = issuanceInput();
    effect.run = () => {
      input.audience = "https://attacker.invalid/substituted";
      input.requested_lifetime_seconds = 3_600;
      input.methods[0] = "config.put";
      input.entitlement.persona = "ff".repeat(32);
      return acceptedEffect();
    };
    const result = issueControlToken(input);
    expect(result).toMatchObject({
      verdict: "accept",
      lifetime_seconds: 300,
      token: {
        aud: "urn:heterodyne:control:node-a",
        methods: ["config.get"],
      },
    });
  });

  it("snapshots token use before effect-time revalidation mutates caller data", () => {
    const input = tokenUseInput(acceptedToken());
    effect.calls = 0;
    effect.run = () => {
      input.method = "config.put";
      input.current_entitlement.state = "revoked";
      input.token.methods[0] = "config.put";
      return acceptedEffect();
    };
    expect(validateControlTokenUse(input)).toEqual({ verdict: "accept" });
  });

  it("rejects accessor and proxy issuance inputs before reads or revalidation", () => {
    let reads = 0;
    const accessor = Object.defineProperty(issuanceInput(), "audience", {
      enumerable: true,
      get: () => {
        reads += 1;
        return "urn:heterodyne:control:node-a";
      },
    });
    expect(issueControlToken(accessor)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
    expect(reads).toBe(0);
    expect(effect.calls).toBe(0);

    let traps = 0;
    const proxy = new Proxy(issuanceInput(), {
      get(target, key, receiver) {
        traps += 1;
        return Reflect.get(target, key, receiver);
      },
      ownKeys(target) {
        traps += 1;
        return Reflect.ownKeys(target);
      },
    });
    expect(issueControlToken(proxy)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
    expect(traps).toBe(0);
    expect(effect.calls).toBe(0);
  });

  it("rejects accessor and proxy token-use inputs before reads or revalidation", () => {
    let reads = 0;
    const accessor = Object.defineProperty(tokenUseInput(acceptedToken()), "method", {
      enumerable: true,
      get: () => {
        reads += 1;
        return "config.get";
      },
    });
    effect.calls = 0;
    expect(validateControlTokenUse(accessor)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
    expect(reads).toBe(0);
    expect(effect.calls).toBe(0);

    let traps = 0;
    const proxy = new Proxy(tokenUseInput(acceptedToken()), {
      get(target, key, receiver) {
        traps += 1;
        return Reflect.get(target, key, receiver);
      },
      ownKeys(target) {
        traps += 1;
        return Reflect.ownKeys(target);
      },
    });
    effect.calls = 0;
    expect(validateControlTokenUse(proxy)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
    expect(traps).toBe(0);
    expect(effect.calls).toBe(0);
  });
});

describe("Control token safe-integer time boundaries", () => {
  it.each([
    { field: "requested_lifetime_seconds", value: 300.5 },
    { field: "requested_lifetime_seconds", value: -1 },
    { field: "requested_lifetime_seconds", value: Number.MAX_SAFE_INTEGER + 1 },
    { field: "node_policy_max_seconds", value: 300.5 },
    { field: "node_policy_max_seconds", value: -1 },
    { field: "node_policy_max_seconds", value: Number.MAX_SAFE_INTEGER + 1 },
  ] as const)("rejects unsafe issuance operand $field=$value", ({ field, value }) => {
    expect(issueControlToken({ ...issuanceInput(), [field]: value })).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });

  it.each([
    { created_at: -1, expires_at: null },
    { created_at: 0.5, expires_at: null },
    { created_at: Number.MAX_SAFE_INTEGER + 1, expires_at: null },
    { created_at: 0, expires_at: 1_000.5 },
    { created_at: 0, expires_at: Number.MAX_SAFE_INTEGER + 1 },
  ])("rejects unsafe authorization times", ({ created_at, expires_at }) => {
    expect(issueControlToken({
      ...issuanceInput(),
      entitlement: { ...authorization, created_at, expires_at },
    })).toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
  });

  it("accepts the exact maximum safe expiration and rejects addition overflow", () => {
    effect.run = () => acceptedEffect(Number.MAX_SAFE_INTEGER - 300);
    const exact = issueControlToken(issuanceInput());
    expect(exact).toMatchObject({
      verdict: "accept",
      token: { exp: Number.MAX_SAFE_INTEGER },
    });

    effect.run = () => acceptedEffect(Number.MAX_SAFE_INTEGER - 299);
    expect(issueControlToken(issuanceInput())).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });

  it("rejects fractional, negative, and unsafe effect time", () => {
    for (const now of [-1, 1_000.5, Number.MAX_SAFE_INTEGER + 1]) {
      effect.run = () => acceptedEffect(now);
      expect(issueControlToken(issuanceInput())).toEqual({
        verdict: "reject",
        reason_code: "control-token-invalid",
      });
    }
  });

  it("rejects non-safe token time claims even when the token identity is recomputed", () => {
    for (const overrides of [
      { iat: -1, exp: 300 },
      { iat: 1.5, exp: 300 },
      { iat: 1_000, exp: Number.MAX_SAFE_INTEGER + 1 },
    ]) {
      const token = withRecomputedJti({ ...acceptedToken(), ...overrides });
      expect(validateControlTokenUse(tokenUseInput(token))).toEqual({
        verdict: "reject",
        reason_code: "control-token-invalid",
      });
    }
  });
});

describe("durable Control enrollment effect", () => {
  const enrollmentInput = () => ({
    enrollment_id: "77".repeat(32),
    group_id: group,
    client_key: client,
    authorization_view: authorizationView,
  });

  it("commits enrollment-only state from effect-time authority", () => {
    expect(commitControlEnrollment(enrollmentInput())).toEqual({
      verdict: "accept",
      enrollment: {
        enrollment_id: "77".repeat(32),
        group_id: group,
        client_key: client,
        state: "enrollment-only",
        authority: false,
        committed_at: 1_000,
        registry_checkpoint: "aa".repeat(32),
        repository_rid: `rad:z${"1".repeat(48)}`,
        persona_key: authorization.persona,
        manifest_digest: "bb".repeat(32),
        issuer: "https://node.example/oidc/test",
      },
    });
  });

  it.each([
    "oidc-checkpoint-stale",
    "oidc-issuer-authority-invalid",
    "control-authorization-view-stale",
  ] as const)("does not commit on effect rejection %s", (reason) => {
    effect.run = () => ({ verdict: "reject", reason });
    expect(commitControlEnrollment(enrollmentInput())).toEqual({
      verdict: "reject",
      reason_code: reason,
    });
  });

  it("snapshots the enrollment request before revalidation", () => {
    const input = enrollmentInput();
    effect.run = () => {
      input.enrollment_id = "88".repeat(32);
      input.group_id = "99".repeat(32);
      input.client_key = "aa".repeat(32);
      return acceptedEffect();
    };
    expect(commitControlEnrollment(input)).toMatchObject({
      verdict: "accept",
      enrollment: {
        enrollment_id: "77".repeat(32),
        group_id: group,
        client_key: client,
      },
    });
  });

  it("rejects closed-shape violations before the authority effect", () => {
    let reads = 0;
    const accessor = Object.defineProperty(enrollmentInput(), "client_key", {
      enumerable: true,
      get: () => {
        reads += 1;
        return client;
      },
    });
    expect(commitControlEnrollment(accessor)).toEqual({
      verdict: "reject",
      reason_code: "control-enrollment-invalid",
    });
    expect(reads).toBe(0);
    expect(effect.calls).toBe(0);

    let traps = 0;
    const proxy = new Proxy(enrollmentInput(), {
      get(target, key, receiver) {
        traps += 1;
        return Reflect.get(target, key, receiver);
      },
      ownKeys(target) {
        traps += 1;
        return Reflect.ownKeys(target);
      },
    });
    expect(commitControlEnrollment(proxy)).toEqual({
      verdict: "reject",
      reason_code: "control-enrollment-invalid",
    });
    expect(traps).toBe(0);
    expect(effect.calls).toBe(0);
  });
});
