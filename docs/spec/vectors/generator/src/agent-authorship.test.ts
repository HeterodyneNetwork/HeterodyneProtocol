import { describe, expect, it } from "vitest";
import {
  agentBindingMessage,
  deriveAgentIdentity,
  injectAgentAttribution,
  validateAgentAccessToken,
  validateAgentDelegation,
  validateWorkloadRegistration,
  type AgentTokenValidationInput,
  type WorkloadRegistration,
} from "./agent-authorship.js";

const coldRoot = "11".repeat(32);
const roleId = "ab".repeat(32);
const publishingKey = "33".repeat(32);
const nid = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdgQ9T";
const issuer = "https://issuer.example/oidc/npub1persona";
const audience = "https://node.example/control/agent-publication";
const subjectJkt = "A".repeat(43);

describe("agent signing delegation", () => {
  const proof = `heterodyne-agent-signing-binding-v1|${coldRoot}|${nid}|${roleId}|${publishingKey}`;
  const valid = {
    cold_root: coldRoot,
    credential_ledger_generation: 0,
    expected_credential_ledger_persona: coldRoot,
    expected_credential_ledger_generation: 0,
    nid,
    role_id: roleId,
    publishing_key: publishingKey,
    address: `agent:${roleId}`,
    proof_bytes: proof,
    outer_epoch_signature_valid: true,
    nid_proof_valid: true,
    key_proof_valid: true,
    kel_authority_current: true,
    unexpired: true,
    repo_final: true,
  };

  it("constructs and validates the exact triple-proof binding", () => {
    expect(agentBindingMessage(coldRoot, nid, roleId, publishingKey)).toBe(proof);
    expect(validateAgentDelegation(valid)).toEqual({
      verdict: "accept",
      role_id: roleId,
      publishing_key: publishingKey,
      repo_final: true,
    });
  });

  it("fails closed on address, proof, KEL, expiry, or finality failures", () => {
    expect(validateAgentDelegation({ ...valid, address: `agent:${roleId.toUpperCase()}` }))
      .toMatchObject({ verdict: "reject", reason_code: "role-delegation-address-invalid" });
    for (const patch of [
      { outer_epoch_signature_valid: false },
      { nid_proof_valid: false },
      { key_proof_valid: false },
      { proof_bytes: `${proof}x` },
      { kel_authority_current: false },
      { unexpired: false },
    ]) {
      expect(validateAgentDelegation({ ...valid, ...patch })).toMatchObject({ verdict: "reject" });
    }
    expect(validateAgentDelegation({ ...valid, repo_final: false }))
      .toMatchObject({ verdict: "reject", reason_code: "provisional_not_final" });
    expect(validateAgentDelegation({ ...valid, expected_credential_ledger_generation: 1 }))
      .toMatchObject({ verdict: "reject", reason_code: "credential_generation_stale" });
  });
});

describe("workload registration and stable identity", () => {
  const registration: WorkloadRegistration = {
    client_id: "agent-client",
    subject_jkt: subjectJkt,
    agent_class: "ai",
    role_id: roleId,
    audience,
    scopes: ["heterodyne:agent:publish"],
    allowed_kinds: [1, 30023],
    allowed_feeds: ["main"],
    allowed_resources: ["feed:main"],
    max_content_bytes: 4096,
    rate_limit: { window_seconds: 60, count: 20, burst: 5 },
    not_before: 1_000,
    expires_at: 2_000,
  };

  it("accepts one role and finite kind, resource, size, rate, and burst bounds", () => {
    expect(validateWorkloadRegistration(registration)).toEqual(registration);
  });

  it("rejects empty, unlimited, multi-role-shaped, unknown, or inverted registrations", () => {
    for (const value of [
      { ...registration, scopes: [] },
      { ...registration, max_content_bytes: 0 },
      { ...registration, rate_limit: { ...registration.rate_limit, count: 0 } },
      { ...registration, role_id: [roleId, "44".repeat(32)] },
      { ...registration, expires_at: registration.not_before },
      { ...registration, unlimited: true },
    ]) {
      expect(() => validateWorkloadRegistration(value)).toThrow(
        /agent-workload-registration-invalid/,
      );
    }
  });

  it("keeps one persona's tuple stable across renewal and unlinkable across personas", () => {
    const first = deriveAgentIdentity(
      coldRoot,
      "https://sector.example",
      "55".repeat(32),
      issuer,
      "agent-client",
    );
    const renewed = deriveAgentIdentity(
      coldRoot,
      "https://sector.example",
      "55".repeat(32),
      issuer,
      "agent-client",
    );
    const otherPersona = deriveAgentIdentity(
      "66".repeat(32),
      "https://sector.example",
      "77".repeat(32),
      "https://other.example/oidc/npub1other",
      "agent-client",
    );
    expect(renewed).toEqual(first);
    expect(otherPersona.sub).not.toBe(first.sub);
  });
});

describe("agent workload access token", () => {
  const valid: AgentTokenValidationInput = {
    typ: "at+jwt",
    credential_ledger_persona: coldRoot,
    credential_ledger_generation: 0,
    expected_credential_ledger_persona: coldRoot,
    expected_credential_ledger_generation: 0,
    iss: issuer,
    sub: "stable-pairwise-sub",
    aud: [audience],
    exp: 1_250,
    iat: 1_000,
    jti: "token-1",
    client_id: "agent-client",
    scope: "heterodyne:agent:publish",
    cnf_jkt: subjectJkt,
    sender_proof_jkt: subjectJkt,
    sender_proof_valid: true,
    agent_role_id: roleId,
    expected_issuer: issuer,
    expected_subject: "stable-pairwise-sub",
    expected_audience: audience,
    expected_client_id: "agent-client",
    expected_scope: "heterodyne:agent:publish",
    expected_role_id: roleId,
    now: 1_100,
    status: "VALID",
    ledger_active: true,
    ledger_binding_valid: true,
    status_binding_valid: true,
    session_expires_at: 1_300,
    delegation_expires_at: 1_300,
    registration_expires_at: 1_300,
    consent_expires_at: 1_300,
    source_authorization_expires_at: 1_300,
  };

  it("accepts one exact audience, normalized scope, cnf proof, active status, and five-minute cap", () => {
    expect(validateAgentAccessToken(valid)).toEqual({
      verdict: "accept",
      identity: {
        issuer,
        sub: "stable-pairwise-sub",
        client_id: "agent-client",
        role_id: roleId,
      },
    });
  });

  it("rejects invalid type, time, status, audience, scope, sender proof, role, or ledger state", () => {
    const cases: Array<[Partial<AgentTokenValidationInput>, string]> = [
      [{ typ: "JWT" }, "agent-token-invalid"],
      [{ exp: 1_301 }, "agent-token-invalid"],
      [{ now: 1_251 }, "agent-token-expired"],
      [{ status: "INVALID" }, "agent-token-revoked"],
      [{ aud: [audience, "https://other.example"] }, "agent-token-audience-invalid"],
      [{ scope: "heterodyne:agent:publish extra" }, "agent-token-scope-invalid"],
      [{ sender_proof_valid: false }, "agent-sender-proof-invalid"],
      [{ sender_proof_jkt: "B".repeat(43) }, "agent-sender-proof-invalid"],
      [{ agent_role_id: "44".repeat(32) }, "agent-role-mismatch"],
      [{ ledger_active: false }, "agent-token-stale"],
      [{ expected_credential_ledger_generation: 1 }, "credential_generation_stale"],
    ];
    for (const [patch, reason_code] of cases) {
      expect(validateAgentAccessToken({ ...valid, ...patch })).toEqual({
        verdict: "reject",
        reason_code,
      });
    }
  });
});

describe("canonical agent attribution", () => {
  const base = {
    kind: 1,
    tags: [
      ["client", "heterodyne"],
      ["heterodyne_agent", "v1", "forged", "forged", "forged", "44".repeat(32)],
      ["agent_action", "human"],
    ],
    agent_class: "ai" as const,
    issuer,
    subject: "stable-pairwise-sub",
    client_id: "agent-client",
    role_id: roleId,
    signer: publishingKey,
    current_role_key: publishingKey,
    tier: 1 as const,
  };
  const canonicalTags = [
    ["L", "network.heterodyne.agent"],
    ["l", "ai", "network.heterodyne.agent"],
    ["heterodyne_agent", "v1", issuer, "stable-pairwise-sub", "agent-client", roleId],
    ["agent_action", "publish"],
  ];

  it("removes caller forgery and inserts the exact ordered block", () => {
    expect(injectAgentAttribution(base)).toEqual({
      verdict: "accept",
      tags: [["client", "heterodyne"], ...canonicalTags],
      placement: "public",
    });
  });

  it("keeps verified human review optional without changing agent classification", () => {
    const result = injectAgentAttribution({
      ...base,
      agent_review: "approved-by-human",
      agent_review_verified: true,
    });
    expect(result).toMatchObject({ verdict: "accept", placement: "public" });
    expect(result.verdict === "accept" && result.tags).toEqual([
      ["client", "heterodyne"],
      ...canonicalTags,
      ["agent_review", "approved-by-human"],
    ]);
  });

  it("puts Tier 3 attribution only in the encrypted logical event", () => {
    expect(injectAgentAttribution({ ...base, tier: 3 })).toMatchObject({
      verdict: "accept",
      placement: "encrypted-inner",
      clear_outer_tags: [],
    });
  });

  it("rejects unsupported kinds and signer-role mismatch without fallback", () => {
    expect(injectAgentAttribution({ ...base, kind: 31007 })).toEqual({
      verdict: "reject",
      reason_code: "agent-attribution-profile-unavailable",
    });
    expect(injectAgentAttribution({ ...base, signer: "44".repeat(32) })).toEqual({
      verdict: "reject",
      reason_code: "agent-role-mismatch",
    });
  });
});
