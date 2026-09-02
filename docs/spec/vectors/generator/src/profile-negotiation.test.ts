import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { getEventId, getPublicKey, type NostrUnsignedEvent } from "./nostr.js";
import { proofBytes } from "./proof-bytes.js";
import {
  type CurrentControlFrameVerificationContext,
  projectCurrentControlRequestBody,
  validateCurrentControlFrameProfile,
} from "./profile-negotiation.js";

const SECRET = "31".repeat(32);
const SENDER = getPublicKey(SECRET);
const GROUP = "42".repeat(32);
const NOW = 1_800_000_000;
const REQUEST_ID = "request-1";
const HUMAN_BODY = Object.freeze({
  id: REQUEST_ID,
  method: "status",
  params: {},
  expires_at: NOW + 60,
});

function requestDigest(input: Readonly<{
  profile: string;
  version: string;
  group_id: string;
  sender: string;
  request_id: string;
  expires_at: number;
  body: Readonly<Record<string, unknown>>;
}>): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-frame-request-v1", input))
    .digest("hex");
}

const REQUEST = requestDigest({
  profile: "human-jsonrpc",
  version: "heterodyne/0.6.0",
  group_id: GROUP,
  sender: SENDER,
  request_id: REQUEST_ID,
  expires_at: NOW + 60,
  body: HUMAN_BODY,
});

function context(
  overrides: Partial<CurrentControlFrameVerificationContext> = {},
): CurrentControlFrameVerificationContext {
  return {
    expected_profile: "human-jsonrpc",
    expected_version: "heterodyne/0.6.0",
    expected_group_id: GROUP,
    expected_sender: SENDER,
    expected_request_digest: REQUEST,
    trusted_now: NOW,
    ...overrides,
  };
}

function signedBytes(overrides: Readonly<{
  event?: Partial<NostrUnsignedEvent>;
  frame?: Readonly<Record<string, unknown>>;
  payload?: Readonly<Record<string, unknown>>;
}> = {}): Uint8Array {
  const profile = overrides.frame?.profile ?? "human-jsonrpc";
  const version = overrides.frame?.version ?? "heterodyne/0.6.0";
  const requestId = overrides.frame?.request_id ?? REQUEST_ID;
  const expiresAt = overrides.frame?.expires_at ?? NOW + 60;
  const body = overrides.payload?.body ?? HUMAN_BODY;
  const groupId = overrides.payload?.group_id ?? GROUP;
  const payload = {
    group_id: groupId,
    request_digest: requestDigest({
      profile: String(profile),
      version: String(version),
      group_id: String(groupId),
      sender: overrides.event?.pubkey ?? SENDER,
      request_id: String(requestId),
      expires_at: Number(expiresAt),
      body: body as Readonly<Record<string, unknown>>,
    }),
    body,
    ...overrides.payload,
  };
  const frame = {
    version,
    profile,
    frame_type: "request",
    request_id: requestId,
    expires_at: expiresAt,
    payload,
    ...overrides.frame,
  };
  const unsigned: NostrUnsignedEvent = {
    pubkey: SENDER,
    created_at: NOW,
    kind: 31017,
    tags: [],
    content: jcsCanonicalize(frame),
    ...overrides.event,
  };
  const id = getEventId(unsigned);
  const event = {
    ...unsigned,
    id,
    sig: bytesToHex(schnorr.sign(id, hexToBytes(SECRET), "00".repeat(32))),
  };
  return new TextEncoder().encode(JSON.stringify(event));
}

describe("current Control frame profile", () => {
  it("projects exact human JSON-RPC and agent MCP authorization requests", () => {
    const object = { class: "config_namespace", id: "ui" };
    expect(projectCurrentControlRequestBody("human-jsonrpc", {
      id: REQUEST_ID,
      method: "config.get",
      params: { object },
      expires_at: NOW + 60,
    })).toEqual({
      profile: "human-jsonrpc",
      request_id: REQUEST_ID,
      expires_at: NOW + 60,
      authorization_method: "config.get",
      authorization_object: object,
      body: {
        id: REQUEST_ID,
        method: "config.get",
        params: { object },
        expires_at: NOW + 60,
      },
    });
    expect(projectCurrentControlRequestBody("agent-mcp", {
      jsonrpc: "2.0",
      id: REQUEST_ID,
      method: "tools/call",
      params: { name: "config.get", arguments: { object } },
    })).toEqual({
      profile: "agent-mcp",
      request_id: REQUEST_ID,
      expires_at: null,
      authorization_method: "config.get",
      authorization_object: object,
      body: {
        jsonrpc: "2.0",
        id: REQUEST_ID,
        method: "tools/call",
        params: { name: "config.get", arguments: { object } },
      },
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects unsafe request projections before traps", () => {
    let traps = 0;
    const accessor = { ...HUMAN_BODY } as Record<string, unknown>;
    Object.defineProperty(accessor, "method", {
      enumerable: true,
      get: () => { traps += 1; return "status"; },
    });
    const proxy = new Proxy(HUMAN_BODY, {
      ownKeys: () => { traps += 1; return []; },
      get: () => { traps += 1; return undefined; },
    });
    const invalidUnicode = { ...HUMAN_BODY, method: "status\ud800" };
    expect(projectCurrentControlRequestBody("human-jsonrpc", accessor)).toBeNull();
    expect(projectCurrentControlRequestBody("human-jsonrpc", proxy)).toBeNull();
    expect(projectCurrentControlRequestBody("human-jsonrpc", invalidUnicode)).toBeNull();
    expect(traps).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects over-budget request collections before descriptor work", () => {
    const oversizedArray = Array.from({ length: 5_000 }, () => null);
    const oversizedObject = Object.fromEntries(
      Array.from({ length: 4_096 }, (_, index) => [`member-${index}`, null]),
    );
    const originalGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
    let oversizedDescriptorMaterializations = 0;
    Object.getOwnPropertyDescriptors = ((value: object) => {
      if (value === oversizedArray || value === oversizedObject) {
        oversizedDescriptorMaterializations += 1;
      }
      return originalGetOwnPropertyDescriptors(value);
    }) as typeof Object.getOwnPropertyDescriptors;
    try {
      for (const oversized of [oversizedArray, oversizedObject]) {
        expect(projectCurrentControlRequestBody("human-jsonrpc", {
          ...HUMAN_BODY,
          params: { oversized },
        })).toBeNull();
      }
    } finally {
      Object.getOwnPropertyDescriptors = originalGetOwnPropertyDescriptors;
    }
    expect(oversizedDescriptorMaterializations).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects exact typed-array metadata without traps", () => {
    const hostileBytes = signedBytes();
    let byteLengthTraps = 0;
    let iteratorTraps = 0;
    Object.defineProperty(hostileBytes, "byteLength", {
      configurable: true,
      get: () => {
        byteLengthTraps += 1;
        throw new Error("synthetic byteLength trap");
      },
    });
    Object.defineProperty(hostileBytes, Symbol.iterator, {
      configurable: true,
      get: () => {
        iteratorTraps += 1;
        throw new Error("synthetic iterator trap");
      },
    });
    expect(validateCurrentControlFrameProfile(hostileBytes, context())).toEqual({
      verdict: "reject",
      reason_code: "control-frame-invalid",
    });
    expect(byteLengthTraps).toBe(0);
    expect(iteratorTraps).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local ignores hidden JSON metadata without complete own-key work", () => {
    const params: Record<string | symbol, unknown> = {};
    for (let index = 0; index < 10_000; index += 1) {
      Object.defineProperty(params, `synthetic-hidden-${index}`, {
        value: `not-authority-${index}`,
      });
      Object.defineProperty(params, Symbol(`synthetic-symbol-${index}`), {
        value: `not-authority-${index}`,
        enumerable: true,
      });
    }
    const body = { ...HUMAN_BODY, params };
    const cleanBody = { ...HUMAN_BODY, params: {} };
    const originalOwnKeys = Reflect.ownKeys;
    let completeOwnKeyCalls = 0;
    Reflect.ownKeys = ((value: object) => {
      if (value === params) completeOwnKeyCalls += 1;
      return originalOwnKeys(value);
    }) as typeof Reflect.ownKeys;
    let projection;
    try {
      projection = projectCurrentControlRequestBody("human-jsonrpc", body);
    } finally {
      Reflect.ownKeys = originalOwnKeys;
    }
    expect(completeOwnKeyCalls).toBe(0);
    expect(projection).toEqual({
      profile: "human-jsonrpc",
      request_id: REQUEST_ID,
      expires_at: NOW + 60,
      authorization_method: "status",
      authorization_object: null,
      body: cleanBody,
    });
    expect(requestDigest({
      profile: "human-jsonrpc",
      version: "heterodyne/0.6.0",
      group_id: GROUP,
      sender: SENDER,
      request_id: REQUEST_ID,
      expires_at: NOW + 60,
      body: projection?.body ?? {},
    })).toBe(requestDigest({
      profile: "human-jsonrpc",
      version: "heterodyne/0.6.0",
      group_id: GROUP,
      sender: SENDER,
      request_id: REQUEST_ID,
      expires_at: NOW + 60,
      body: cleanBody,
    }));
    expect(JSON.stringify(projection)).not.toContain("not-authority");
  });

  it("accepts one exact signed, current, request-bound Marmot frame", () => {
    const result = validateCurrentControlFrameProfile(signedBytes(), context());
    expect(result).toEqual({
      verdict: "accept",
      output: {
        event_id: JSON.parse(new TextDecoder().decode(signedBytes())).id,
        request_id: REQUEST_ID,
        request_digest: REQUEST,
      },
    });
  });

  it.each([
    ["request digest", signedBytes({ payload: { request_digest: "64".repeat(32) } }), context()],
    ["Marmot group", signedBytes({ payload: { group_id: "65".repeat(32) } }), context()],
    ["profile", signedBytes({ frame: { profile: "agent-mcp" } }), context()],
    ["version", signedBytes({ frame: { version: "heterodyne/9.0.0" } }), context()],
    ["sender", signedBytes(), context({ expected_sender: "66".repeat(32) })],
    ["future time", signedBytes({ event: { created_at: NOW + 1 } }), context()],
    ["expiry", signedBytes({ frame: { expires_at: NOW } }), context()],
  ])("BLUE TEAM VALIDATION: synthetic/local rejects a signed frame with a mismatched %s binding", (_name, bytes, verificationContext) => {
    expect(validateCurrentControlFrameProfile(bytes, verificationContext)).toEqual({
      verdict: "reject",
      reason_code: "control-frame-invalid",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects malformed UTF-8 and closed-member violations", () => {
    const eventWithExtraMember = JSON.parse(new TextDecoder().decode(signedBytes())) as Record<string, unknown>;
    eventWithExtraMember.transport = "marmot-inner";
    const ordinaryEvent = JSON.parse(new TextDecoder().decode(signedBytes())) as {
      content: string;
    };
    const duplicateFrameMember = signedBytes({
      event: {
        content: ordinaryEvent.content.replace(
          '{"expires_at":',
          `{"expires_at":${NOW + 60},"expires_at":`,
        ),
      },
    });
    const frameWithExtraMember = signedBytes({ frame: { transport: "marmot-inner" } });
    const payloadWithExtraMember = signedBytes({ payload: { authorized: true } });
    const invalidUtf8 = Uint8Array.from([0xc3, 0x28]);

    for (const bytes of [
      invalidUtf8,
      new TextEncoder().encode(JSON.stringify(eventWithExtraMember)),
      duplicateFrameMember,
      frameWithExtraMember,
      payloadWithExtraMember,
    ]) {
      expect(validateCurrentControlFrameProfile(bytes, context())).toEqual({
        verdict: "reject",
        reason_code: "control-frame-invalid",
      });
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a valid signed same-value duplicate outer member", () => {
    const ordinary = new TextDecoder().decode(signedBytes());
    const event = JSON.parse(ordinary) as { id: string };
    const duplicate = ordinary.replace(
      `"id":"${event.id}"`,
      `"id":"${event.id}","id":"${event.id}"`,
    );

    expect(validateCurrentControlFrameProfile(
      new TextEncoder().encode(duplicate),
      context(),
    )).toEqual({ verdict: "reject", reason_code: "control-frame-invalid" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects changed or extended human requests carrying the old digest", () => {
    const changed = signedBytes({
      payload: {
        request_digest: REQUEST,
        body: { ...HUMAN_BODY, method: "delete" },
      },
    });
    const extended = signedBytes({
      payload: {
        request_digest: REQUEST,
        body: { ...HUMAN_BODY, authorized: true },
      },
    });

    for (const bytes of [changed, extended]) {
      expect(validateCurrentControlFrameProfile(bytes, context())).toEqual({
        verdict: "reject",
        reason_code: "control-frame-invalid",
      });
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a human request body under the agent MCP profile", () => {
    const profile = "agent-mcp";
    const digest = requestDigest({
      profile,
      version: "heterodyne/0.6.0",
      group_id: GROUP,
      sender: SENDER,
      request_id: REQUEST_ID,
      expires_at: NOW + 60,
      body: HUMAN_BODY,
    });
    const bytes = signedBytes({
      frame: { profile },
      payload: { body: HUMAN_BODY, request_digest: digest },
    });

    expect(validateCurrentControlFrameProfile(bytes, context({
      expected_profile: profile,
      expected_request_digest: digest,
    }))).toEqual({ verdict: "reject", reason_code: "control-frame-invalid" });
  });

  it("accepts one complete request under the agent MCP profile", () => {
    const profile = "agent-mcp";
    const body = {
      jsonrpc: "2.0",
      id: REQUEST_ID,
      method: "tools/call",
      params: { name: "status", arguments: {} },
    };
    const digest = requestDigest({
      profile,
      version: "heterodyne/0.6.0",
      group_id: GROUP,
      sender: SENDER,
      request_id: REQUEST_ID,
      expires_at: NOW + 60,
      body,
    });
    const bytes = signedBytes({
      frame: { profile },
      payload: { body, request_digest: digest },
    });

    expect(validateCurrentControlFrameProfile(bytes, context({
      expected_profile: profile,
      expected_request_digest: digest,
    }))).toMatchObject({ verdict: "accept" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a recomputed event carrying a forged signature", () => {
    const event = JSON.parse(new TextDecoder().decode(signedBytes())) as Record<string, unknown>;
    event.sig = "00".repeat(64);

    expect(validateCurrentControlFrameProfile(
      new TextEncoder().encode(JSON.stringify(event)),
      context(),
    )).toEqual({ verdict: "reject", reason_code: "control-frame-invalid" });
  });
});
