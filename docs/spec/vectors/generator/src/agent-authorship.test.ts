import { describe, expect, it } from "vitest";
import {
  deriveAgentIdentity,
  injectAgentAttribution,
  validateAgentAccessToken,
  validateWorkloadRegistration,
  type AgentTokenValidationInput,
} from "./agent-authorship.js";

const coldRoot = "11".repeat(32);
const roleId = "ab".repeat(32);
const publishingKey = "33".repeat(32);
const issuer = "https://issuer.example/oidc/npub1persona";
const audience = "https://node.example/control/agent-publication";
const subjectJkt = "A".repeat(43);

describe("workload registration and stable identity", () => {
  const registration = {
    persona_key: coldRoot,
    client_id: "agent-client",
    subject_jkt: subjectJkt,
    subject_proof: { method: "dpop", jkt: subjectJkt },
    agent_class: "ai",
    selected_signer: publishingKey,
    signer_key_class: "agent",
    agent_association: { kind: "key", value: publishingKey },
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

  it("accepts an agent-key signer bound to one persona, subject proof, and finite authority", () => {
    expect(validateWorkloadRegistration(registration)).toEqual(registration);
  });

  it("permits persona-key signing only under the explicit OIDC scope", () => {
    const personaSigner = {
      ...registration,
      selected_signer: coldRoot,
      signer_key_class: "persona",
      scopes: ["heterodyne:agent:publish", "heterodyne:agent:sign:persona"],
    };
    expect(validateWorkloadRegistration(personaSigner)).toEqual(personaSigner);
    expect(() => validateWorkloadRegistration({
      ...personaSigner,
      scopes: ["heterodyne:agent:publish"],
    })).toThrow(/agent-workload-registration-invalid/);
  });

  it("rejects signer, proof, authority, legacy delegation, or shape-invalid registrations", () => {
    for (const value of [
      { ...registration, scopes: [] },
      { ...registration, max_content_bytes: 0 },
      { ...registration, rate_limit: { ...registration.rate_limit, count: 0 } },
      { ...registration, selected_signer: "zz".repeat(32) },
      { ...registration, subject_proof: { method: "dpop", jkt: "B".repeat(43) } },
      { ...registration, proof_bytes: "legacy-delegation-proof" },
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
    signer_key: publishingKey,
    signer_key_class: "agent",
    agent_association: { kind: "role", value: roleId },
    expected_issuer: issuer,
    expected_subject: "stable-pairwise-sub",
    expected_audience: audience,
    expected_client_id: "agent-client",
    expected_scope: "heterodyne:agent:publish",
    expected_signer_key: publishingKey,
    expected_signer_key_class: "agent",
    expected_agent_association: { kind: "role", value: roleId },
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
        signer: publishingKey,
        key_class: "agent",
        agent_association: { kind: "role", value: roleId },
      },
    });
  });

  it("accepts an explicitly scoped persona signer without inventing an agent role", () => {
    const scope = "heterodyne:agent:publish heterodyne:agent:sign:persona";
    expect(validateAgentAccessToken({
      ...valid,
      scope,
      expected_scope: scope,
      signer_key: coldRoot,
      expected_signer_key: coldRoot,
      signer_key_class: "persona",
      expected_signer_key_class: "persona",
      agent_association: undefined,
      expected_agent_association: undefined,
    })).toEqual({
      verdict: "accept",
      identity: {
        issuer,
        sub: "stable-pairwise-sub",
        client_id: "agent-client",
        signer: coldRoot,
        key_class: "persona",
      },
    });
  });

  it("rejects invalid token state, association mismatch, or legacy delegation proof", () => {
    const cases: Array<[Partial<AgentTokenValidationInput>, string]> = [
      [{ typ: "JWT" }, "agent-token-invalid"],
      [{ exp: 1_301 }, "agent-token-invalid"],
      [{ now: 1_251 }, "agent-token-invalid"],
      [{ status: "INVALID" }, "agent-token-invalid"],
      [{ aud: [audience, "https://other.example"] }, "agent-token-invalid"],
      [{ scope: "heterodyne:agent:publish extra" }, "agent-token-invalid"],
      [{ sender_proof_valid: false }, "agent-sender-proof-invalid"],
      [{ sender_proof_jkt: "B".repeat(43) }, "agent-sender-proof-invalid"],
      [{ signer_key: "44".repeat(32) }, "agent-signer-mismatch"],
      [{ signer_key_class: "persona" }, "agent-signer-mismatch"],
      [{
        scope: "heterodyne:agent:publish heterodyne:agent:sign:persona",
        expected_scope: "heterodyne:agent:publish heterodyne:agent:sign:persona",
        signer_key: coldRoot,
        expected_signer_key: coldRoot,
        signer_key_class: "persona",
        expected_signer_key_class: "persona",
        agent_association: { kind: "key", value: publishingKey },
        expected_agent_association: { kind: "key", value: "44".repeat(32) },
      }, "agent-signer-mismatch"],
      [{ proof_bytes: "legacy-delegation-proof" } as Partial<AgentTokenValidationInput>,
        "agent-token-invalid"],
      [{ ledger_active: false }, "agent-token-invalid"],
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
    persona: coldRoot,
    issuer,
    subject: "stable-pairwise-sub",
    client_id: "agent-client",
    signer: publishingKey,
    expected_signer: publishingKey,
    signer_key_class: "agent" as const,
    oidc_scopes: ["heterodyne:agent:publish"],
    agent_association: { kind: "key" as const, value: publishingKey },
    expected_agent_association: { kind: "key" as const, value: publishingKey },
    tier: 1 as const,
  };
  const canonicalTags = [
    ["L", "network.heterodyne.agent"],
    ["l", "ai", "network.heterodyne.agent"],
    ["heterodyne_agent", "v1", "key", publishingKey],
    ["agent_action", "publish"],
  ];

  it("removes caller forgery, inserts public-safe attribution, and keeps the signer authoritative", () => {
    expect(injectAgentAttribution(base)).toEqual({
      verdict: "accept",
      tags: [["client", "heterodyne"], ...canonicalTags],
      placement: "public",
      author: publishingKey,
    });
    const result = injectAgentAttribution(base);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(issuer);
    expect(serialized).not.toContain("stable-pairwise-sub");
    expect(serialized).not.toContain("agent-client");
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

  it("allows persona-key authorship only under explicit scope and keeps automation visible", () => {
    const personaSigned = injectAgentAttribution({
      ...base,
      signer: coldRoot,
      expected_signer: coldRoot,
      signer_key_class: "persona",
      oidc_scopes: ["heterodyne:agent:publish", "heterodyne:agent:sign:persona"],
    });
    expect(personaSigned).toMatchObject({ verdict: "accept", author: coldRoot });
    expect(personaSigned.verdict === "accept" && personaSigned.tags).toContainEqual(
      ["l", "ai", "network.heterodyne.agent"],
    );
    expect(injectAgentAttribution({
      ...base,
      signer: coldRoot,
      expected_signer: coldRoot,
      signer_key_class: "persona",
    })).toEqual({ verdict: "reject", reason_code: "agent-persona-scope-required" });
  });

  it("keeps the Heterodyne association optional without weakening the NIP-32 label", () => {
    const result = injectAgentAttribution({
      ...base,
      signer: coldRoot,
      expected_signer: coldRoot,
      signer_key_class: "persona",
      oidc_scopes: ["heterodyne:agent:publish", "heterodyne:agent:sign:persona"],
      agent_association: undefined,
      expected_agent_association: undefined,
    });
    expect(result).toMatchObject({
      verdict: "accept",
      tags: [
        ["client", "heterodyne"],
        ["L", "network.heterodyne.agent"],
        ["l", "ai", "network.heterodyne.agent"],
        ["agent_action", "publish"],
      ],
    });
  });

  it("rejects unsupported kinds, mismatches, post-sign input, and legacy proof without fallback", () => {
    expect(injectAgentAttribution({ ...base, kind: 31007 })).toEqual({
      verdict: "reject",
      reason_code: "agent-attribution-profile-unavailable",
    });
    expect(injectAgentAttribution({ ...base, signer: "44".repeat(32) })).toEqual({
      verdict: "reject",
      reason_code: "agent-signer-mismatch",
    });
    expect(injectAgentAttribution({
      ...base,
      signer: coldRoot,
      expected_signer: coldRoot,
      signer_key_class: "persona",
      oidc_scopes: ["heterodyne:agent:publish", "heterodyne:agent:sign:persona"],
      agent_association: { kind: "role", value: roleId },
    })).toEqual({ verdict: "reject", reason_code: "agent-signer-mismatch" });
    expect(injectAgentAttribution({
      ...base,
      proof_bytes: "legacy-delegation-proof",
      key_proof_valid: true,
    } as typeof base)).toEqual({
      verdict: "reject",
      reason_code: "agent-attribution-invalid",
    });
    expect(injectAgentAttribution({ ...base, sig: "55".repeat(64) } as typeof base)).toEqual({
      verdict: "reject",
      reason_code: "agent-attribution-invalid",
    });
  });
});
