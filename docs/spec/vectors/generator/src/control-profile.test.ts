import { describe, expect, it } from "vitest";
import {
  acceptControlRequest,
  authorizeControlMethod,
  authorizeAgentMethod,
  controlPayloadDigest,
  evaluateControlEnrollment,
  evaluateControlSessionLifecycle,
  evaluateMcpToolCall,
  redeemEnrollmentToken,
  routeControlResponse,
  type AgentMethodInput,
  type ControlGrant,
  type ControlRequestInput,
  type EnrollmentEvaluationInput,
  type EnrollmentTokenRecord,
  type RequestReservation,
} from "./control-profile.js";
import {
  validateControlCapabilitySetSchemaOrThrow,
  validateControlEnrollmentRequestSchemaOrThrow,
  validateControlEnrollmentTokenSchemaOrThrow,
  validateControlGrantSchemaOrThrow,
  validateControlMcpFrameSchemaOrThrow,
  validateControlRpcRequestSchemaOrThrow,
  validateControlRpcResponseSchemaOrThrow,
} from "./schema.js";

const relayA = "wss://relay-a.example/";
const relayB = "wss://relay-b.example/";
const sessionId = "11".repeat(32);
const payload = { content: "hello", kind: 1 };
const payloadDigest = controlPayloadDigest(payload);

describe("restart-safe request reservation and relay affinity", () => {
  const request: ControlRequestInput = {
    authenticated: true,
    session_id: sessionId,
    request_id: "request-1",
    method: "heterodyne.agent.publish",
    payload,
    payload_digest: payloadDigest,
    ingress_relay: relayA,
    expires_at: 1_200,
    now: 1_000,
  };

  it("atomically reserves the first valid arrival and executes it at most once", () => {
    expect(acceptControlRequest(request)).toEqual({
      verdict: "accept",
      action: "execute",
      execute: true,
      response_relay: relayA,
      reservation: {
        session_id: sessionId,
        request_id: "request-1",
        method: "heterodyne.agent.publish",
        payload_digest: payloadDigest,
        expires_at: 1_200,
        first_ingress_relay: relayA,
        state: "reserved",
      },
    });
  });

  it("joins a concurrent identical arrival without a second dispatch", () => {
    const prior = acceptControlRequest(request);
    expect(prior.verdict).toBe("accept");
    const reservation = prior.verdict === "accept" ? prior.reservation : undefined;
    expect(acceptControlRequest(request, reservation)).toMatchObject({
      verdict: "accept",
      action: "join",
      execute: false,
      response_relay: relayA,
    });
  });

  it("replays one persisted final response through the retry ingress relay", () => {
    const complete: RequestReservation = {
      session_id: sessionId,
      request_id: "request-1",
      method: request.method,
      payload_digest: payloadDigest,
      expires_at: request.expires_at,
      first_ingress_relay: relayA,
      state: "complete",
      response: { status: "ok", event_id: "22".repeat(32) },
    };
    const decision = acceptControlRequest({ ...request, ingress_relay: relayB }, complete);
    expect(decision).toMatchObject({
      verdict: "accept",
      action: "replay",
      execute: false,
      response_relay: relayB,
      response: complete.response,
    });
    expect(routeControlResponse(decision)).toBe(relayB);
  });

  it("rejects changed method or payload under an existing request id", () => {
    const reservation = acceptControlRequest(request);
    if (reservation.verdict !== "accept") throw new Error("fixture failed");
    expect(acceptControlRequest({
      ...request,
      method: "heterodyne.agent.token",
    }, reservation.reservation)).toEqual({
      verdict: "reject",
      reason_code: "control-request-id-conflict",
    });
    const changedPayload = { ...payload, content: "changed" };
    expect(acceptControlRequest({
      ...request,
      payload: changedPayload,
      payload_digest: controlPayloadDigest(changedPayload),
    }, reservation.reservation)).toEqual({
      verdict: "reject",
      reason_code: "control-request-id-conflict",
    });
    expect(acceptControlRequest({
      ...request,
      expires_at: request.expires_at + 1,
    }, reservation.reservation)).toEqual({
      verdict: "reject",
      reason_code: "control-request-id-conflict",
    });
    expect(acceptControlRequest({
      ...request,
      session_id: "22".repeat(32),
    }, reservation.reservation)).toEqual({
      verdict: "reject",
      reason_code: "control-request-id-conflict",
    });
  });

  it("requires final response persistence before replay and survives restart", () => {
    const invalidComplete = {
      session_id: sessionId,
      request_id: "request-1",
      method: request.method,
      payload_digest: payloadDigest,
      expires_at: request.expires_at,
      first_ingress_relay: relayA,
      state: "complete" as const,
    };
    expect(acceptControlRequest(request, invalidComplete)).toEqual({
      verdict: "reject",
      reason_code: "control-request-id-conflict",
    });
    const restarted = { ...invalidComplete, state: "reserved" as const };
    expect(acceptControlRequest({ ...request, ingress_relay: relayB }, restarted))
      .toMatchObject({ verdict: "accept", action: "join", execute: false });
  });

  it("rejects expiry, digest mismatch, unauthenticated input, and reply_relay", () => {
    expect(acceptControlRequest({ ...request, now: request.expires_at }))
      .toMatchObject({ verdict: "reject", reason_code: "control-request-expired" });
    expect(acceptControlRequest({ ...request, payload_digest: "00".repeat(32) }))
      .toMatchObject({ verdict: "reject" });
    expect(acceptControlRequest({ ...request, authenticated: false }))
      .toMatchObject({ verdict: "reject" });
    expect(acceptControlRequest({ ...request, reply_relay: relayB }))
      .toMatchObject({ verdict: "reject", reason_code: "control-ingress-relay-invalid" });
  });
});

describe("requirements for automated agents", () => {
  const valid: AgentMethodInput = {
    method: "heterodyne.agent.publish",
    token_decision: { verdict: "accept" },
    sender_proof_valid: true,
    kind: 1,
    allowed_kinds: [1, 30023],
    resource: "feed:main",
    allowed_resources: ["feed:main"],
    content_bytes: 100,
    max_content_bytes: 4096,
    rate_count: 1,
    rate_limit: 20,
    burst_count: 1,
    burst_limit: 5,
    requests_key_access: false,
    requests_human_profile: false,
    requests_attribution_bypass: false,
  };

  it("accepts only the intent-level publication method with current authorization", () => {
    expect(authorizeAgentMethod(valid)).toEqual({
      verdict: "accept",
      method: "heterodyne.agent.publish",
    });
  });

  it("refuses raw signing, key access, human profiles, and attribution bypass", () => {
    expect(authorizeAgentMethod({ ...valid, method: "sign_event" }))
      .toMatchObject({ reason_code: "agent-method-prohibited" });
    expect(authorizeAgentMethod({ ...valid, requests_key_access: true }))
      .toMatchObject({ reason_code: "agent-key-access-prohibited" });
    expect(authorizeAgentMethod({ ...valid, requests_human_profile: true }))
      .toMatchObject({ reason_code: "agent-human-profile-prohibited" });
    expect(authorizeAgentMethod({ ...valid, requests_attribution_bypass: true }))
      .toMatchObject({ reason_code: "agent-attribution-bypass-prohibited" });
  });

  it("refuses missing or invalid tokens and sender proofs", () => {
    expect(authorizeAgentMethod({
      ...valid,
      token_decision: { verdict: "reject", reason_code: "agent-token-expired" },
    })).toEqual({ verdict: "reject", reason_code: "agent-token-expired" });
    expect(authorizeAgentMethod({ ...valid, sender_proof_valid: false }))
      .toEqual({ verdict: "reject", reason_code: "agent-sender-proof-invalid" });
  });

  it("enforces kind, resource, size, rate, and burst limits", () => {
    expect(authorizeAgentMethod({ ...valid, kind: 7 }))
      .toMatchObject({ reason_code: "agent-resource-denied" });
    expect(authorizeAgentMethod({ ...valid, resource: "feed:other" }))
      .toMatchObject({ reason_code: "agent-resource-denied" });
    expect(authorizeAgentMethod({ ...valid, content_bytes: 4097 }))
      .toMatchObject({ reason_code: "agent-size-exceeded" });
    expect(authorizeAgentMethod({ ...valid, rate_count: 21 }))
      .toMatchObject({ reason_code: "agent-rate-limited" });
    expect(authorizeAgentMethod({ ...valid, burst_count: 6 }))
      .toMatchObject({ reason_code: "agent-rate-limited" });
  });
});

describe("Control enrollment lifecycle", () => {
  const enrollment: EnrollmentEvaluationInput = {
    profile_id: "heterodyne-control-session-device-v1",
    binding_proof_valid: true,
    binding_nonce_matches_bootstrap: true,
    active_invite: true,
    bootstrap_authorized: true,
    bootstrap_mode: "challenge",
    fresh_ceremony: true,
    pending_expires_at: 1_200,
    now: 1_000,
    organization_persona: false,
    delegation_state: "repository-final",
    authorization_state: "active",
  };

  it("requires the Core binding proof and live bootstrap binding", () => {
    expect(evaluateControlEnrollment({
      ...enrollment,
      binding_proof_valid: false,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-enrollment-binding-invalid",
    });
    expect(evaluateControlEnrollment({
      ...enrollment,
      binding_nonce_matches_bootstrap: false,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-enrollment-binding-invalid",
    });
  });

  it("expires pending enrollment before ceremony or delegation issuance", () => {
    expect(evaluateControlEnrollment({
      ...enrollment,
      now: enrollment.pending_expires_at,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-request-expired",
    });
  });

  it.each(["qr", "challenge"] as const)(
    "requires a fresh ceremony for %s bootstrap",
    (bootstrap_mode) => {
      expect(evaluateControlEnrollment({
        ...enrollment,
        bootstrap_mode,
        fresh_ceremony: false,
      })).toEqual({
        verdict: "reject",
        reason_code: "control-fresh-authorization-required",
      });
    },
  );

  it("keeps relay evidence provisional and grants no authority", () => {
    expect(evaluateControlEnrollment({
      ...enrollment,
      delegation_state: "relay-provisional",
    })).toEqual({
      verdict: "hold",
      state: "provisional",
      authority: false,
    });
  });

  it("requires repository-final delegation and active Comms authority", () => {
    expect(evaluateControlEnrollment({
      ...enrollment,
      authorization_state: "provisional",
    })).toEqual({
      verdict: "hold",
      state: "authorization-pending",
      authority: false,
    });
    expect(evaluateControlEnrollment(enrollment)).toEqual({
      verdict: "accept",
      state: "active",
      authority: true,
      default_grant: "regular",
    });
  });

  it.each(["untrusted", "conflicted", "invalid", "expired", "revoked"] as const)(
    "fails closed for %s Comms authorization",
    (authorization_state) => {
      expect(evaluateControlEnrollment({
        ...enrollment,
        authorization_state,
      })).toEqual({
        verdict: "reject",
        reason_code: "control-authorization-not-active",
      });
    },
  );
});

describe("issuer-bound enrollment tokens", () => {
  const token: EnrollmentTokenRecord = {
    token_class: "control-enrollment",
    token_id: "aa".repeat(32),
    issuer_device: "bb".repeat(32),
    enrolling_key: undefined,
    expires_at: 1_200,
    grant_tier: "regular",
    state: "unspent",
    signature_valid: true,
  };

  it("spends a valid token before delegation publication", () => {
    expect(redeemEnrollmentToken({
      token,
      redeeming_device: token.issuer_device,
      enrolling_key: "cc".repeat(32),
      now: 1_000,
    })).toEqual({
      verdict: "accept",
      action: "redeem",
      grant_tier: "regular",
      next: {
        ...token,
        state: "spent",
        enrolling_key: "cc".repeat(32),
      },
    });
  });

  it("replays an idempotent same-key redemption and conflicts on another key", () => {
    const spent: EnrollmentTokenRecord = {
      ...token,
      state: "spent",
      enrolling_key: "cc".repeat(32),
    };
    expect(redeemEnrollmentToken({
      token: spent,
      redeeming_device: token.issuer_device,
      enrolling_key: "cc".repeat(32),
      now: 1_000,
    })).toMatchObject({ verdict: "accept", action: "replay" });
    expect(redeemEnrollmentToken({
      token: spent,
      redeeming_device: token.issuer_device,
      enrolling_key: "dd".repeat(32),
      now: 1_000,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-enrollment-token-conflict",
    });
  });

  it("rejects another redeemer, expiry, revocation, recovery/workload tokens, and full grants", () => {
    expect(redeemEnrollmentToken({
      token,
      redeeming_device: "ee".repeat(32),
      enrolling_key: "cc".repeat(32),
      now: 1_000,
    })).toMatchObject({ verdict: "reject" });
    expect(redeemEnrollmentToken({
      token,
      redeeming_device: token.issuer_device,
      enrolling_key: "cc".repeat(32),
      now: token.expires_at,
    })).toMatchObject({ verdict: "reject" });
    expect(redeemEnrollmentToken({
      token: { ...token, state: "revoked" },
      redeeming_device: token.issuer_device,
      enrolling_key: "cc".repeat(32),
      now: 1_000,
    })).toMatchObject({ verdict: "reject" });
    expect(redeemEnrollmentToken({
      token: { ...token, token_class: "agent-workload" },
      redeeming_device: token.issuer_device,
      enrolling_key: "cc".repeat(32),
      now: 1_000,
    })).toMatchObject({ verdict: "reject" });
    expect(redeemEnrollmentToken({
      token: { ...token, grant_tier: "full" },
      redeeming_device: token.issuer_device,
      enrolling_key: "cc".repeat(32),
      now: 1_000,
    })).toMatchObject({ verdict: "reject" });
  });
});

describe("grants, protected policy state, and session lifecycle", () => {
  const grant: ControlGrant = {
    tier: "regular",
    media_upload: false,
    repositories: ["rad:z3repo"],
    config_namespaces: ["ui"],
    sessions: [sessionId],
  };

  it("enforces object scope and refuses configuration writes to policy state", () => {
    expect(authorizeControlMethod({
      grant,
      authorization_state: "active",
      method: "config.put",
      object_type: "config_namespace",
      object_id: "ui",
      fresh_ceremony: false,
    })).toEqual({ verdict: "accept", method: "config.put" });
    expect(authorizeControlMethod({
      grant,
      authorization_state: "active",
      method: "repo.write",
      object_type: "repository",
      object_id: "rad:z-other",
      fresh_ceremony: false,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-object-not-authorized",
    });
    expect(authorizeControlMethod({
      grant,
      authorization_state: "active",
      method: "config.put",
      object_type: "security_policy",
      object_id: "grant-table",
      fresh_ceremony: false,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-policy-state-protected",
    });
  });

  it("requires an active Comms decision and fresh ceremony for full-grant activation", () => {
    expect(authorizeControlMethod({
      grant,
      authorization_state: "provisional",
      method: "config.get",
      object_type: "config_namespace",
      object_id: "ui",
      fresh_ceremony: false,
    })).toMatchObject({ verdict: "reject" });
    const full = { ...grant, tier: "full" as const };
    expect(authorizeControlMethod({
      grant: full,
      authorization_state: "active",
      method: "device.activate",
      object_type: "session",
      object_id: sessionId,
      fresh_ceremony: false,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-fresh-authorization-required",
    });
    expect(authorizeControlMethod({
      grant: full,
      authorization_state: "active",
      method: "device.activate",
      object_type: "session",
      object_id: sessionId,
      fresh_ceremony: true,
    })).toEqual({ verdict: "accept", method: "device.activate" });
  });

  it("revokes on self-revocation or logout and lapses on inactivity", () => {
    expect(evaluateControlSessionLifecycle({
      now: 1_000,
      valid_until: 1_100,
      self_revoked: true,
      logout: false,
      authorization_state: "active",
    })).toMatchObject({ state: "revoked", terminate_dr: true });
    expect(evaluateControlSessionLifecycle({
      now: 1_000,
      valid_until: 1_100,
      self_revoked: false,
      logout: true,
      authorization_state: "active",
    })).toMatchObject({ state: "revoked", terminate_dr: true });
    expect(evaluateControlSessionLifecycle({
      now: 1_100,
      valid_until: 1_100,
      self_revoked: false,
      logout: false,
      authorization_state: "active",
    })).toMatchObject({ state: "lapsed", terminate_dr: true });
  });
});

describe("MCP capability lifecycle", () => {
  const call = {
    initialized: true,
    advertised_tools: ["heterodyne.agent.publish"],
    tool: "heterodyne.agent.publish",
    direction: "light-to-full" as const,
    inbound_execution_advertised: false,
    cancellation_supported: true,
    cancel_requested: false,
    started_at: 1_000,
    timeout_ms: 1_000,
    now: 1_100,
  };

  it("requires mutual initialize and refuses unadvertised tools", () => {
    expect(evaluateMcpToolCall({ ...call, initialized: false })).toEqual({
      verdict: "reject",
      reason_code: "control-mcp-not-initialized",
    });
    expect(evaluateMcpToolCall({ ...call, tool: "unknown.tool" })).toEqual({
      verdict: "reject",
      reason_code: "control-mcp-tool-unadvertised",
    });
  });

  it("supports cancellation and enforces the negotiated timeout", () => {
    expect(evaluateMcpToolCall({ ...call, cancel_requested: true })).toEqual({
      verdict: "accept",
      action: "cancel",
      tool: call.tool,
    });
    expect(evaluateMcpToolCall({
      ...call,
      now: call.started_at + call.timeout_ms,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-mcp-tool-timeout",
    });
  });

  it("defaults full-node-to-light inbound execution to denied", () => {
    expect(evaluateMcpToolCall({
      ...call,
      direction: "full-to-light",
    })).toEqual({
      verdict: "reject",
      reason_code: "control-mcp-inbound-default-deny",
    });
  });
});

describe("closed Control payload schemas", () => {
  const grant = {
    tier: "regular",
    media_upload: false,
    repositories: ["rad:z3repo"],
    config_namespaces: ["ui"],
    sessions: [sessionId],
  };
  const enrollment = {
    invite_event_id: "aa".repeat(32),
    publishing_key: "bb".repeat(32),
    binding_nonce: "cc".repeat(32),
    key_proof: "dd".repeat(64),
    bootstrap: { mode: "challenge", credential: "challenge-response" },
    requested_grant: grant,
  };
  const token = {
    token_class: "control-enrollment",
    token_id: "aa".repeat(32),
    persona: "bb".repeat(32),
    epoch_key: "cc".repeat(32),
    minting_device: "dd".repeat(32),
    kel_head: { event_id: "ee".repeat(32), sequence: 2 },
    issued_at: 1_000,
    expires_at: 1_200,
    grant,
    signature: "ff".repeat(64),
  };
  const capabilities = {
    role: "light-client",
    inbound_execution: false,
    cancellation: true,
    tools: [{
      name: "heterodyne.agent.publish",
      input_schema: { type: "object" },
      timeout_ms: 1_000,
    }],
  };

  it("accepts each exact closed payload", () => {
    expect(() => validateControlGrantSchemaOrThrow(grant)).not.toThrow();
    expect(() => validateControlEnrollmentRequestSchemaOrThrow(enrollment)).not.toThrow();
    expect(() => validateControlEnrollmentTokenSchemaOrThrow(token)).not.toThrow();
    expect(() => validateControlCapabilitySetSchemaOrThrow(capabilities)).not.toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: "initialize-1",
      method: "initialize",
      params: { capabilities },
    })).not.toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: "tool-1",
      result: {
        content: [{ type: "text", text: "published" }],
        isError: false,
      },
    })).not.toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: "tool-2",
      error: {
        code: -32602,
        message: "invalid tool arguments",
      },
    })).not.toThrow();
    expect(() => validateControlRpcRequestSchemaOrThrow({
      id: "request-1",
      method: "config.get",
      params: { namespace: "ui" },
      expires_at: 1_200,
    })).not.toThrow();
    expect(() => validateControlRpcResponseSchemaOrThrow({
      id: "request-1",
      result: { namespace: "ui", value: {} },
    })).not.toThrow();
  });

  it("forbids unknown members, Control wire stamps, caller ingress, and unsafe integers", () => {
    expect(() => validateControlEnrollmentRequestSchemaOrThrow({
      ...enrollment,
      extra: true,
    })).toThrow(/additional/);
    expect(() => validateControlRpcRequestSchemaOrThrow({
      id: "request-1",
      method: "config.get",
      params: {},
      expires_at: 1_200,
      spec_version: "control\/0.5.0",
    })).toThrow(/additional/);
    expect(() => validateControlRpcRequestSchemaOrThrow({
      id: "request-1",
      method: "config.get",
      params: {},
      expires_at: 1_200,
      ingress_relay: relayA,
    })).toThrow(/additional/);
    expect(() => validateControlEnrollmentTokenSchemaOrThrow({
      ...token,
      expires_at: Number.MAX_SAFE_INTEGER + 1,
    })).toThrow(/9007199254740991|safe/i);
    expect(() => validateControlEnrollmentTokenSchemaOrThrow({
      ...token,
      expires_at: token.issued_at,
    })).toThrow(/greater than issued_at/i);
    expect(() => validateControlEnrollmentTokenSchemaOrThrow({
      ...token,
      grant: { ...grant, tier: "full" },
    })).toThrow(/cannot confer the full grant/i);
    expect(() => validateControlCapabilitySetSchemaOrThrow({
      ...capabilities,
      tools: [
        ...capabilities.tools,
        { ...capabilities.tools[0], timeout_ms: 2_000 },
      ],
    })).toThrow(/tool names must be unique/i);
  });
});
