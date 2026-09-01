import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { getEventId, getPublicKey, type NostrUnsignedEvent } from "./nostr.js";
import {
  type CurrentControlFrameVerificationContext,
  validateCurrentControlFrameProfile,
} from "./profile-negotiation.js";

const SECRET = "31".repeat(32);
const SENDER = getPublicKey(SECRET);
const GROUP = "42".repeat(32);
const REQUEST = "53".repeat(32);
const NOW = 1_800_000_000;

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
  const payload = {
    group_id: GROUP,
    request_digest: REQUEST,
    body: { method: "status" },
    ...overrides.payload,
  };
  const frame = {
    version: "heterodyne/0.6.0",
    profile: "human-jsonrpc",
    frame_type: "request",
    request_id: "request-1",
    expires_at: NOW + 60,
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
  it("accepts one exact signed, current, request-bound Marmot frame", () => {
    const result = validateCurrentControlFrameProfile(signedBytes(), context());
    expect(result).toEqual({
      verdict: "accept",
      output: {
        event_id: JSON.parse(new TextDecoder().decode(signedBytes())).id,
        request_id: "request-1",
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

  it("BLUE TEAM VALIDATION: synthetic/local rejects a recomputed event carrying a forged signature", () => {
    const event = JSON.parse(new TextDecoder().decode(signedBytes())) as Record<string, unknown>;
    event.sig = "00".repeat(64);

    expect(validateCurrentControlFrameProfile(
      new TextEncoder().encode(JSON.stringify(event)),
      context(),
    )).toEqual({ verdict: "reject", reason_code: "control-frame-invalid" });
  });
});
