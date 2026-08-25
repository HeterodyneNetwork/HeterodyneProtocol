import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  issueControlToken,
  validateControlTokenUse,
  type ControlToken,
  type TokenIssuanceInput,
  type TokenUseInput,
} from "./control-profile.js";
import { jcsCanonicalize } from "./jcs.js";

const client = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const otherClient = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const node = "22".repeat(32);
const group = "33".repeat(32);
const checkpoint = "55".repeat(32);
const expectedJkt = "2JF8vg9etJzjFwZwmkvhBLLZ0bfMVVOPivYR5lFtcec";
const otherJkt = "GKeBJdbiPSiSZ8qwiPH8NBmmtrLcKCZ7gYOzX0hwzlM";
const object = { class: "config_namespace" as const, id: "ui" };

const authorization = {
  record_id: "44".repeat(32),
  persona: "aa".repeat(32),
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
  capabilities: ["control.token.extended"],
  token_lifetime_default_seconds: 300,
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

const issuance = {
  entitlement: authorization,
  group_id: group,
  issuer: "https://node.example/oidc/persona",
  audience: "urn:heterodyne:control:node-a",
  node_key: node,
  registry_checkpoint: checkpoint,
  issuance_nonce: "77".repeat(32),
  requested_lifetime_seconds: 300,
  node_policy_max_seconds: 3_600,
  now: 1_000,
  authorization_view_authenticated: true,
  authorization_view_conflicted: false,
  authorization_view_age_seconds: 0,
  methods: ["config.get"],
  objects: [object],
  limits: {
    max_content_bytes: 1_024,
    rate_count: 10,
  },
};

function issue(overrides: Record<string, unknown> = {}) {
  return issueControlToken({
    ...issuance,
    ...overrides,
  } as unknown as TokenIssuanceInput);
}

function acceptedToken(overrides: Record<string, unknown> = {}) {
  const result = issue(overrides);
  if (result.verdict !== "accept") throw new Error("fixture token failed");
  return result.token;
}

function useInput(token = acceptedToken()): TokenUseInput {
  return {
    token,
    signature_valid: true,
    now: 1_100,
    expected_issuer: issuance.issuer,
    expected_audience: issuance.audience,
    expected_node_key: node,
    authenticated_sender_jkt: expectedJkt,
    group_id: group,
    current_entitlement: authorization,
    current_registry_checkpoint: checkpoint,
    authorization_view_authenticated: true,
    authorization_view_conflicted: false,
    authorization_view_age_seconds: 100,
    required_scope: "control",
    method: "config.get",
    object,
    usage: { max_content_bytes: 512, rate_count: 1 },
    required_agent_role: "agent:newsletter",
  } as unknown as TokenUseInput;
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

describe("Control token authorization projection", () => {
  it("mints from the frozen compatibility authorization record", () => {
    expect(issue()).toMatchObject({
      verdict: "accept",
      token: {
        authorization_id: authorization.record_id,
        client_id: client,
        sub: client,
        client_class: "automated",
        scope: "control control.token.extended",
        methods: ["config.get"],
        objects: [object],
        registry_checkpoint: checkpoint,
        agent_role: "agent:newsletter",
      },
    });
  });

  it("derives the even-Y secp256k1 JWK thumbprint and rejects a non-point key", () => {
    expect(issue({ client_jkt: otherJkt })).toMatchObject({
      verdict: "accept",
      token: { cnf: { jkt: expectedJkt } },
    });
    expect(issue({
      entitlement: { ...authorization, client_key: "11".repeat(32) },
    })).toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
  });

  it("derives extended lifetime authority at mint and revalidates its removal at use", () => {
    const withoutExtended = {
      ...authorization,
      capabilities: [] as string[],
    };
    expect(issue({
      entitlement: withoutExtended,
      requested_lifetime_seconds: 301,
      extended_capability: true,
    })).toEqual({ verdict: "reject", reason_code: "control-token-invalid" });

    const token = acceptedToken({ requested_lifetime_seconds: 3_600 });
    expect(validateControlTokenUse({
      ...useInput(token),
      now: 1_100,
      current_entitlement: withoutExtended,
    } as unknown as TokenUseInput)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });
});

describe("Control token key and issuance-identifier binding", () => {
  it("rejects a sender JWK cross-bound to a different entitled client key", () => {
    const token = acceptedToken();
    const crossBound = withRecomputedJti({
      ...token,
      cnf: { jkt: otherJkt },
    });
    expect(validateControlTokenUse({
      ...useInput(crossBound),
      authenticated_sender_jkt: otherJkt,
    } as unknown as TokenUseInput)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });

  it("rejects a noncanonical base64url thumbprint even when its jti is recomputed", () => {
    const token = acceptedToken();
    const noncanonical = withRecomputedJti({
      ...token,
      cnf: { jkt: `${"A".repeat(42)}B` },
    });
    expect(validateControlTokenUse({
      ...useInput(noncanonical),
      authenticated_sender_jkt: noncanonical.cnf.jkt,
    } as unknown as TokenUseInput)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });

  it("gives same-second differing grants distinct identifiers", () => {
    const read = acceptedToken();
    const write = acceptedToken({ methods: ["config.put"] });
    const renewed = acceptedToken({ issuance_nonce: "88".repeat(32) });

    expect(read.iat).toBe(write.iat);
    expect(read.jti).not.toBe(write.jti);
    expect(read.jti).not.toBe(renewed.jti);
  });

  it("recomputes the issuance identifier before token use", () => {
    const token = acceptedToken();
    expect(validateControlTokenUse({
      ...useInput({ ...token, jti: "00".repeat(32) }),
    } as unknown as TokenUseInput)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });

  it("uses a second valid BIP-340 fixture for cross-binding coverage", () => {
    expect(otherClient).toMatch(/^[0-9a-f]{64}$/);
    expect(otherJkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});
