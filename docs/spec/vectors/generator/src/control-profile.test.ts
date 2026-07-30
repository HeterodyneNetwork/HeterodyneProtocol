import { describe, expect, it } from "vitest";
import {
  acceptControlRequest,
  authorizeAgentMethod,
  controlPayloadDigest,
  routeControlResponse,
  type AgentMethodInput,
  type ControlRequestInput,
  type RequestReservation,
} from "./control-profile.js";

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
  });

  it("requires final response persistence before replay and survives restart", () => {
    const invalidComplete = {
      session_id: sessionId,
      request_id: "request-1",
      method: request.method,
      payload_digest: payloadDigest,
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
