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
  const binding = {
    issuer: "https://issuer.example/persona",
    pairwise_sub: "pairwise-agent-7",
    client_id: "heterodyne-agent-client",
    role_id: "44".repeat(32),
    control_session: sessionId,
    request_id: "agent-request-1",
    method: "heterodyne.agent.publish",
    payload_digest: payloadDigest,
    ledger_persona: "55".repeat(32),
    ledger_generation: 4,
    ledger_checkpoint: {
      event_id: "66".repeat(32),
      sequence: 12,
    },
    ledger_status: "active" as const,
  };
  const valid: AgentMethodInput = {
    method: "heterodyne.agent.publish",
    initialization_complete: true,
    now: 1_000,
    request_binding: binding,
    token: {
      token_class: "agent-workload",
      signature_valid: true,
      issued_at: 900,
      expires_at: 1_200,
      sender_key: "77".repeat(32),
      binding,
    },
    sender_proof: {
      signature_valid: true,
      signing_key: "77".repeat(32),
      issued_at: 995,
      expires_at: 1_005,
      nonce: "agent-proof-1",
      nonce_state: "unused",
      binding,
    },
    current_ledger: {
      persona: binding.ledger_persona,
      generation: binding.ledger_generation,
      checkpoint: binding.ledger_checkpoint,
      status: "active",
    },
    pending_issuance_generation: binding.ledger_generation,
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

  it("refuses invalid token signatures and per-use proof signatures", () => {
    expect(authorizeAgentMethod({
      ...valid,
      token: {
        ...valid.token,
        signature_valid: false,
      },
    })).toEqual({ verdict: "reject", reason_code: "agent-token-expired" });
    expect(authorizeAgentMethod({
      ...valid,
      sender_proof: {
        ...valid.sender_proof,
        signature_valid: false,
      },
    }))
      .toEqual({ verdict: "reject", reason_code: "agent-sender-proof-invalid" });
  });

  it("rejects a workload token whose lifetime exceeds five minutes", () => {
    expect(authorizeAgentMethod({
      ...valid,
      token: {
        ...valid.token,
        expires_at: valid.token.issued_at + 301,
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "agent-token-expired",
    });
  });

  it.each([
    ["issuer", { issuer: "https://substituted.example/persona" }],
    ["pairwise subject", { pairwise_sub: "pairwise-agent-substituted" }],
    ["client", { client_id: "substituted-client" }],
    ["role", { role_id: "88".repeat(32) }],
    ["Control session", { control_session: "99".repeat(32) }],
    ["request", { request_id: "agent-request-substituted" }],
    ["method", { method: "heterodyne.agent.substituted" }],
    ["payload digest", { payload_digest: "aa".repeat(32) }],
    ["ledger persona", { ledger_persona: "bb".repeat(32) }],
    ["ledger generation", { ledger_generation: 5 }],
    ["ledger checkpoint", {
      ledger_checkpoint: {
        event_id: "cc".repeat(32),
        sequence: 13,
      },
    }],
    ["ledger status", { ledger_status: "revoked" as const }],
  ] as const)(
    "rejects a workload token with a substituted %s binding",
    (_description, mutation) => {
      expect(authorizeAgentMethod({
        ...valid,
        token: {
          ...valid.token,
          binding: {
            ...binding,
            ...mutation,
          },
        },
      })).toEqual({
        verdict: "reject",
        reason_code: "agent-token-binding-mismatch",
      });
    },
  );

  it("rejects a replayed or request-substituted per-use proof", () => {
    expect(authorizeAgentMethod({
      ...valid,
      sender_proof: {
        ...valid.sender_proof,
        nonce_state: "used",
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "agent-sender-proof-invalid",
    });
    expect(authorizeAgentMethod({
      ...valid,
      sender_proof: {
        ...valid.sender_proof,
        binding: {
          ...binding,
          request_id: "agent-request-substituted",
        },
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "agent-sender-proof-invalid",
    });
  });

  it.each([
    ["generation", {
      generation: binding.ledger_generation + 1,
    }, true],
    ["checkpoint", {
      checkpoint: {
        event_id: "dd".repeat(32),
        sequence: 13,
      },
    }, false],
    ["status", {
      status: "revoked" as const,
    }, false],
  ] as const)(
    "invalidates prior authority after a ledger %s transition",
    (_description, mutation, purgesPendingIssuance) => {
      expect(authorizeAgentMethod({
        ...valid,
        current_ledger: {
          ...valid.current_ledger,
          ...mutation,
        },
      })).toEqual({
        verdict: "reject",
        reason_code: "agent-token-stale-credential",
        requires_current_generation_reissuance: true,
        ...(purgesPendingIssuance
          ? { purge_pending_issuance: true as const }
          : {}),
      });
    },
  );

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
  const identityJoin = {
    invite_event_id: "31".repeat(32),
    enrollee_key: "32".repeat(32),
    dr_transcript_hash: "33".repeat(32),
    dr_session_id: sessionId,
    delegation_address: `pubkey:${"32".repeat(32)}`,
    delegation_event_id: "34".repeat(32),
    grant_subject: "32".repeat(32),
    executor_nid: "did:key:z6MkhExecutor",
    executor_device_key: "35".repeat(32),
    negotiated_protocol: "heterodyne-control-human-v1",
    negotiated_version: "control/0.5.0",
  };
  const enrollment: EnrollmentEvaluationInput = {
    profile_id: "heterodyne-control-session-device-v1",
    binding_proof_valid: true,
    binding_nonce_matches_bootstrap: true,
    active_invite: true,
    pending_expires_at: 1_200,
    now: 1_000,
    organization_persona: false,
    delegation_state: "repository-final",
    authorization_state: "active",
    identity_join: {
      expected: identityJoin,
      presented: identityJoin,
    },
    bootstrap_evidence: {
      mode: "challenge",
      credential_valid: true,
      credential_validated_at: 900,
      ceremony_prompted_at: 910,
      ceremony_completed_at: 920,
      ceremony_authorized: true,
    },
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
        bootstrap_evidence: {
          mode: bootstrap_mode,
          credential_valid: true,
          credential_validated_at: 900,
          ceremony_prompted_at: 910,
          ceremony_completed_at: 920,
          ceremony_authorized: false,
        },
      })).toEqual({
        verdict: "reject",
        reason_code: "control-fresh-authorization-required",
      });
    },
  );

  it.each(Object.keys(identityJoin) as Array<keyof typeof identityJoin>)(
    "rejects substitution at the %s enrollment identity join",
    (field) => {
      expect(evaluateControlEnrollment({
        ...enrollment,
        identity_join: {
          expected: identityJoin,
          presented: {
            ...identityJoin,
            [field]: `${identityJoin[field]}-substituted`,
          },
        },
      })).toEqual({
        verdict: "reject",
        reason_code: "control-enrollment-identity-join-mismatch",
      });
    },
  );

  it.each(["qr", "challenge"] as const)(
    "rejects a %s ceremony prompt shown before bootstrap validation",
    (mode) => {
      expect(evaluateControlEnrollment({
        ...enrollment,
        bootstrap_evidence: {
          mode,
          credential_valid: true,
          credential_validated_at: 910,
          ceremony_prompted_at: 900,
          ceremony_completed_at: 920,
          ceremony_authorized: true,
        },
      })).toEqual({
        verdict: "reject",
        reason_code: "control-enrollment-bootstrap-invalid",
      });
    },
  );

  it("accepts only a ledger-spent token as the prior authorization ceremony", () => {
    expect(evaluateControlEnrollment({
      ...enrollment,
      bootstrap_evidence: {
        mode: "token",
        token_state: "unspent",
        token_redeemed_at: 900,
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-enrollment-bootstrap-invalid",
    });
    expect(evaluateControlEnrollment({
      ...enrollment,
      bootstrap_evidence: {
        mode: "token",
        token_state: "spent",
        token_redeemed_at: 900,
      },
    })).toEqual({
      verdict: "accept",
      state: "active",
      authority: true,
      default_grant: "regular",
    });
  });

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
    persona: "11".repeat(32),
    epoch_key: "22".repeat(32),
    minting_device: "bb".repeat(32),
    kel_head: {
      event_id: "33".repeat(32),
      sequence: 4,
    },
    issued_at: 900,
    enrolling_key: undefined,
    expires_at: 1_200,
    grant_tier: "regular",
    state: "unspent",
    signature_valid: true,
    ledger_finality: "repository-final",
    ledger_decision: "active",
  };
  const redemption = {
    redeeming_device: token.minting_device,
    enrolling_key: "cc".repeat(32),
    delegation_id: "dd".repeat(32),
    current_persona: token.persona,
    current_epoch_key: token.epoch_key,
    current_kel_head: token.kel_head,
    now: 1_000,
  };

  it("spends a valid token before delegation publication", () => {
    expect(redeemEnrollmentToken({
      token,
      ...redemption,
    })).toEqual({
      verdict: "accept",
      action: "redeem",
      grant_tier: "regular",
      delegation_id: redemption.delegation_id,
      next: {
        ...token,
        state: "spent",
        enrolling_key: redemption.enrolling_key,
        recorded_delegation_id: redemption.delegation_id,
      },
    });
  });

  it("replays an idempotent same-key redemption and conflicts on another key", () => {
    const spent: EnrollmentTokenRecord = {
      ...token,
      state: "spent",
      enrolling_key: "cc".repeat(32),
      recorded_delegation_id: redemption.delegation_id,
    };
    expect(redeemEnrollmentToken({
      token: spent,
      ...redemption,
    })).toEqual({
      verdict: "accept",
      action: "replay",
      grant_tier: "regular",
      delegation_id: redemption.delegation_id,
      next: spent,
    });
    expect(redeemEnrollmentToken({
      token: spent,
      ...redemption,
      enrolling_key: "dd".repeat(32),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-enrollment-token-conflict",
    });
  });

  it.each([
    ["relay-provisional ledger state", {
      token: { ...token, ledger_finality: "relay-provisional" as const },
    }],
    ["non-active ledger decision", {
      token: { ...token, ledger_decision: "provisional" as const },
    }],
    ["persona substitution", {
      current_persona: "44".repeat(32),
    }],
    ["epoch-key substitution", {
      current_epoch_key: "55".repeat(32),
    }],
    ["KEL-head substitution", {
      current_kel_head: {
        ...token.kel_head,
        sequence: token.kel_head.sequence + 1,
      },
    }],
  ] as const)(
    "rejects token redemption with %s",
    (_description, mutation) => {
      expect(redeemEnrollmentToken({
        token,
        ...redemption,
        ...mutation,
      })).toEqual({
        verdict: "reject",
        reason_code: "control-enrollment-token-authority-invalid",
      });
    },
  );

  it("rejects another redeemer, expiry, revocation, recovery/workload tokens, and full grants", () => {
    expect(redeemEnrollmentToken({
      token,
      ...redemption,
      redeeming_device: "ee".repeat(32),
    })).toMatchObject({ verdict: "reject" });
    expect(redeemEnrollmentToken({
      token,
      ...redemption,
      now: token.expires_at,
    })).toMatchObject({ verdict: "reject" });
    expect(redeemEnrollmentToken({
      token: { ...token, state: "revoked" },
      ...redemption,
    })).toMatchObject({ verdict: "reject" });
    expect(redeemEnrollmentToken({
      token: { ...token, token_class: "agent-workload" },
      ...redemption,
    })).toMatchObject({ verdict: "reject" });
    expect(redeemEnrollmentToken({
      token: { ...token, grant_tier: "full" },
      ...redemption,
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

  it("rejects a method whose declared object type does not match its authorization surface", () => {
    expect(authorizeControlMethod({
      grant,
      authorization_state: "active",
      method: "config.put",
      object_type: "none",
      object_id: "",
      fresh_ceremony: false,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-object-not-authorized",
    });
    expect(authorizeControlMethod({
      grant,
      authorization_state: "active",
      method: "ping",
      object_type: "session",
      object_id: sessionId,
      fresh_ceremony: false,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-object-not-authorized",
    });
    expect(authorizeControlMethod({
      grant,
      authorization_state: "active",
      method: "ping",
      object_type: "none",
      object_id: "",
      fresh_ceremony: false,
    })).toEqual({ verdict: "accept", method: "ping" });
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
    side_effect_state: "in-progress" as const,
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

  it.each(["committed", "completed"] as const)(
    "ignores cancellation after a side effect is %s",
    (side_effect_state) => {
      expect(evaluateMcpToolCall({
        ...call,
        cancel_requested: true,
        side_effect_state,
      })).toEqual({
        verdict: "accept",
        action: "ignore-cancellation",
        tool: call.tool,
      });
    },
  );

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
  const mcpCapabilities = {
    experimental: {
      "network.heterodyne.control": capabilities,
    },
  };
  const clientInfo = {
    name: "heterodyne-control-light",
    version: "0.5.0",
  };
  const serverInfo = {
    name: "heterodyne-control-full",
    version: "0.5.0",
  };

  it("accepts each exact closed payload", () => {
    expect(() => validateControlGrantSchemaOrThrow(grant)).not.toThrow();
    expect(() => validateControlEnrollmentRequestSchemaOrThrow(enrollment)).not.toThrow();
    expect(() => validateControlEnrollmentTokenSchemaOrThrow(token)).not.toThrow();
    expect(() => validateControlCapabilitySetSchemaOrThrow(capabilities)).not.toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: mcpCapabilities,
        clientInfo,
      },
    })).not.toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-11-25",
        capabilities: mcpCapabilities,
        serverInfo,
      },
    })).not.toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      method: "notifications/initialized",
    })).not.toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: "tool-call-1",
      method: "tools/call",
      params: {
        name: "heterodyne.agent.publish",
        arguments: { content: "hello" },
      },
    })).not.toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: "tool-1",
      result: {
        content: [{ type: "text", text: "published" }],
        structuredContent: { event_id: "aa".repeat(32) },
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
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: {
        requestId: "tool-call-1",
        reason: "caller no longer needs the result",
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

  it("rejects MCP lifecycle substitutions and result/error ambiguity", () => {
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        capabilities: mcpCapabilities,
        clientInfo,
      },
    })).toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: 1,
      result: {
        protocolVersion: "2025-11-25",
        capabilities: mcpCapabilities,
      },
    })).toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { request_id: "tool-call-1" },
    })).toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: {},
    })).toThrow();
    expect(() => validateControlMcpFrameSchemaOrThrow({
      jsonrpc: "2.0",
      id: "tool-call-1",
      result: {
        content: [{ type: "text", text: "published" }],
      },
      error: {
        code: -32603,
        message: "ambiguous",
      },
    })).toThrow();
  });
});
