import {
  acceptControlRequest,
  authorizeAgentMethod,
  controlPayloadDigest,
  type AgentMethodInput,
  type ControlRequestInput,
  type RequestReservation,
} from "./control-profile.js";
import { baseVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

const relayA = "wss://relay-a.example/";
const relayB = "wss://relay-b.example/";
const sessionId = "11".repeat(32);
const payload = { content: "hello", kind: 1 };
const payloadDigest = controlPayloadDigest(payload);
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
const reserved = acceptControlRequest(request);
if (reserved.verdict !== "accept") throw new Error("control fixture reservation failed");
const reservation = reserved.reservation;
const complete: RequestReservation = {
  ...reservation,
  state: "complete",
  response: { status: "ok", event_id: "22".repeat(32) },
};

const validAgentMethod: AgentMethodInput = {
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

export function buildControlVectors(): AuthoredVector[] {
  const vectors: AuthoredVector[] = [];
  for (const [number, name, input, prior] of [
    ["001", "first-arrival-reserved", request, undefined],
    ["002", "concurrent-identical-joins", request, reservation],
    ["003", "cross-relay-final-response-replay", { ...request, ingress_relay: relayB }, complete],
    ["004", "restart-reserved-operation-joins", { ...request, ingress_relay: relayB }, { ...reservation }],
    ["005", "expired-request-rejected", { ...request, now: request.expires_at }, undefined],
    ["006", "reply-relay-rejected", { ...request, reply_relay: relayB }, undefined],
    ["007", "changed-method-rejected", { ...request, method: "heterodyne.agent.token" }, reservation],
    ["008", "changed-payload-rejected", {
      ...request,
      payload: { ...payload, content: "changed" },
      payload_digest: controlPayloadDigest({ ...payload, content: "changed" }),
    }, reservation],
    ["009", "complete-without-response-rejected", request, { ...complete, response: undefined }],
  ] as const) {
    vectors.push(authored(
      `control/${number}-${name}.json`,
      `control/${name}`,
      `The relay-affine restart-safe request decision is ${name}.`,
      { request: input, ...(prior === undefined ? {} : { prior }) },
      acceptControlRequest(input, prior),
    ));
  }

  const methodCases: Array<[string, string, AgentMethodInput]> = [
    ["010", "agent-publish-authorized", validAgentMethod],
    ["011", "raw-signing-refused", { ...validAgentMethod, method: "sign_event" }],
    ["012", "key-access-refused", { ...validAgentMethod, requests_key_access: true }],
    ["013", "human-profile-refused", { ...validAgentMethod, requests_human_profile: true }],
    ["014", "attribution-bypass-refused", { ...validAgentMethod, requests_attribution_bypass: true }],
    ["015", "expired-token-refused", {
      ...validAgentMethod,
      token_decision: { verdict: "reject", reason_code: "agent-token-expired" },
    }],
    ["016", "sender-proof-refused", { ...validAgentMethod, sender_proof_valid: false }],
    ["017", "kind-resource-refused", { ...validAgentMethod, kind: 7 }],
    ["018", "content-size-refused", { ...validAgentMethod, content_bytes: 4097 }],
    ["019", "rate-refused", { ...validAgentMethod, rate_count: 21 }],
    ["020", "burst-refused", { ...validAgentMethod, burst_count: 6 }],
  ];
  for (const [number, name, input] of methodCases) {
    vectors.push(authored(
      `control/${number}-${name}.json`,
      `control/${name}`,
      `The automated-agent method boundary is ${name}.`,
      input,
      authorizeAgentMethod(input),
    ));
  }

  vectors.push(authored(
    "control/021-token-request-bounded.json",
    "control/token-request-bounded",
    "A Control/DR token request binds one session, challenge, workload proof, scope, resource, and expiry and yields no refresh token.",
    {
      spec_version: "control/0.5.0",
      session_id: sessionId,
      request_id: "token-request-1",
      challenge: "challenge-123456",
      workload_proof: "compact-jws",
      requested_scopes: ["heterodyne:agent:publish"],
      requested_resource: "feed:main",
      requested_expiry: 1_250,
    },
    {
      verdict: "accept",
      normalized: {
        access_token_issued: true,
        refresh_token_issued: false,
        expires_at: 1_250,
      },
    },
  ));
  vectors.push(authored(
    "control/022-agent-publish-schema-intent-only.json",
    "control/agent-publish-schema-intent-only",
    "The closed agent publication payload carries intent fields and rejects signature, pubkey, and authoritative attribution input.",
    {
      accepted_fields: [
        "spec_version",
        "token",
        "sender_proof",
        "content",
        "kind",
        "resource",
        "feed",
        "options",
      ],
      forbidden_fields: ["sig", "pubkey", "private_key", "attribution", "human_profile"],
    },
    {
      verdict: "accept",
      normalized: {
        caller_can_supply_signature: false,
        caller_can_supply_attribution_authority: false,
      },
    },
  ));
  vectors.push(authored(
    "control/023-audit-omits-raw-token.json",
    "control/audit-omits-raw-token",
    "The encrypted agent audit retains token jti and authorization evidence but not raw access-token bytes.",
    {
      token_jti: "token-1",
      raw_token_presented: true,
      source_claim_ids: ["claim-1"],
      payload_digest: payloadDigest,
    },
    {
      verdict: "accept",
      normalized: {
        retained_fields: ["token_jti", "source_claim_ids", "payload_digest"],
        raw_token_retained: false,
        encrypted_at_rest: true,
      },
    },
  ));
  return vectors;
}

function authored(
  relativePath: string,
  vectorId: string,
  description: string,
  input: Record<string, unknown>,
  expectedOutput: Record<string, unknown>,
): AuthoredVector {
  return {
    relativePath,
    vector: baseVector({
      vector_id: vectorId,
      spec_refs: ["metadata-selects-control-subset-anchor"],
      description,
      direction: "consume",
      input,
      expected_output: expectedOutput,
    }),
  };
}
