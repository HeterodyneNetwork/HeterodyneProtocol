import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import {
  validateRegisteredKindProfile,
  type Registry,
  type RegisteredKindProfile,
} from "./registry.js";
import { stampOwner } from "./stamping.js";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { hexToBytes } from "./hex.js";
import {
  validateControlFrameSchemaOrThrow,
  validateControlMcpFrameSchemaOrThrow,
  validateControlRpcRequestSchemaOrThrow,
} from "./schema.js";
import { controlGroupAdmission } from "./marmot-admission.js";
import { snapshotAndVerifyNostrEvent } from "./nostr.js";
import { jcsCanonicalize } from "./jcs.js";
import { proofBytes } from "./proof-bytes.js";
import type { JsonValue } from "./claims.js";

export type CurrentProfileWireProbe = Readonly<{
  content_is_heterodyne_json: boolean;
  is_dr_outer: boolean;
  content_profile?: string;
  tags?: readonly (readonly string[])[];
  production_rule?: string;
  transport?: "marmot-inner";
  content_profile_id?: string;
}>;

export type CurrentKindProfileNegotiationInput = RegisteredKindProfile & Readonly<{
  wire_probe: CurrentProfileWireProbe;
}>;

type ProfileNegotiationDecision =
  | Readonly<{
      verdict: "accept";
      normalized: RegisteredKindProfile;
      stamp_owner: ReturnType<typeof stampOwner>;
      wire_binding: string;
    }>
  | Readonly<{
      verdict: "reject";
      reason:
        | "profile-not-registered"
        | "profile-metadata-mismatch"
        | "profile-wire-discriminator-mismatch";
    }>;

function hasTag(
  probe: CurrentProfileWireProbe,
  name: string,
  value: (candidate: string) => boolean,
): boolean {
  return probe.tags?.some((tag) =>
    tag.length === 2
    && tag[0] === name
    && typeof tag[1] === "string"
    && value(tag[1])
  ) === true;
}

function wireBindingMatches(
  discriminator: string,
  probe: CurrentProfileWireProbe,
): boolean {
  if (discriminator.startsWith("content.profile=")) {
    return probe.content_profile === discriminator.slice("content.profile=".length);
  }
  if (discriminator.startsWith("tag:")) {
    const allocation = discriminator.slice("tag:".length);
    const separator = allocation.indexOf("=");
    if (separator <= 0) return false;
    const name = allocation.slice(0, separator);
    const expected = allocation.slice(separator + 1);
    return hasTag(probe, name, (value) => value === expected);
  }
  if (discriminator.startsWith("tags:L=")) {
    const match = /^tags:L=([^,]+),l=<reason>@(.+)$/u.exec(discriminator);
    if (match === null || match[1] !== match[2]) return false;
    const namespace = match[1];
    return hasTag(probe, "L", (value) => value === namespace)
      && hasTag(probe, "l", (value) =>
        value.length > namespace.length + 1 && value.endsWith(`@${namespace}`)
      );
  }
  if (discriminator.startsWith("production-rule:")) {
    return probe.production_rule === discriminator.slice("production-rule:".length);
  }
  if (discriminator === "marmot-inner-only;content=control-frame-v1") {
    return probe.transport === "marmot-inner"
      && probe.content_profile_id === "control-frame-v1";
  }
  return false;
}

function expectedStampOwner(
  registry: Registry,
  profile: RegisteredKindProfile,
  probe: CurrentProfileWireProbe,
): ReturnType<typeof stampOwner> {
  if (probe.is_dr_outer) return null;
  if (profile.stamping) return profile.owner === "control" ? null : profile.owner;
  const kind = registry.kinds.find((candidate) => candidate.kind === profile.kind);
  if (
    kind === undefined
    || kind.allocation_authority !== "heterodyne"
    || kind.base_schema_owner === "nostr"
    || kind.base_schema_owner === "control"
  ) return null;
  return kind.base_schema_owner;
}

/**
 * Resolves one exact registered kind/profile tuple and validates the tuple's
 * declared wire discriminator before applying live stamping negotiation.
 */
export function validateCurrentKindProfileNegotiation(
  registry: Registry,
  value: unknown,
): ProfileNegotiationDecision {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { verdict: "reject", reason: "profile-metadata-mismatch" };
  }
  const { wire_probe: probe, ...candidate } = value as CurrentKindProfileNegotiationInput;
  if (probe === null || typeof probe !== "object" || Array.isArray(probe)) {
    return { verdict: "reject", reason: "profile-wire-discriminator-mismatch" };
  }
  const registered = validateRegisteredKindProfile(
    registry,
    candidate as RegisteredKindProfile,
  );
  if (registered.verdict === "reject") return registered;
  if (!wireBindingMatches(registered.normalized.discriminator, probe)) {
    return { verdict: "reject", reason: "profile-wire-discriminator-mismatch" };
  }
  const stamp = stampOwner({
    kind: registered.normalized.kind,
    profile_id: registered.normalized.profile_id,
    content_is_heterodyne_json: probe.content_is_heterodyne_json,
    is_dr_outer: probe.is_dr_outer,
  }, registry);
  const expectedStamp = expectedStampOwner(registry, registered.normalized, probe);
  if (stamp !== expectedStamp) {
    return { verdict: "reject", reason: "profile-wire-discriminator-mismatch" };
  }
  return {
    verdict: "accept",
    normalized: registered.normalized,
    stamp_owner: stamp,
    wire_binding: registered.normalized.discriminator,
  };
}

type CurrentClaimProofProbe = Readonly<{
  proof_suite: "nostr-bip340" | "radicle-ed25519" | "jwk-jws";
  proof_purpose: "claim-subject-pop" | "claim-revoker";
  message: string;
  public_key?: string;
  public_jwk?: Readonly<{ kty: string; crv: string; x: string }>;
  protected?: string;
  signature: string;
}>;

/** Verifies the native proof suite named by one fixed claim profile probe. */
export function verifyCurrentClaimProofProfile(value: unknown):
  | Readonly<{
      verdict: "accept";
      proof_suite: CurrentClaimProofProbe["proof_suite"];
      proof_purpose: CurrentClaimProofProbe["proof_purpose"];
      authenticated_message: string;
    }>
  | Readonly<{ verdict: "reject"; reason_code: "claim-subject-proof-invalid" }> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { verdict: "reject", reason_code: "claim-subject-proof-invalid" };
  }
  const probe = value as CurrentClaimProofProbe;
  if (
    !["claim-subject-pop", "claim-revoker"].includes(probe.proof_purpose)
    || !/^[0-9a-f]{64}$/u.test(probe.message)
  ) {
    return { verdict: "reject", reason_code: "claim-subject-proof-invalid" };
  }
  const message = hexToBytes(probe.message);
  let verified = false;
  try {
    if (
      probe.proof_suite === "nostr-bip340"
      && typeof probe.public_key === "string"
      && /^[0-9a-f]{64}$/u.test(probe.public_key)
      && /^[0-9a-f]{128}$/u.test(probe.signature)
    ) {
      verified = schnorr.verify(
        hexToBytes(probe.signature),
        message,
        hexToBytes(probe.public_key),
      );
    } else if (
      probe.proof_suite === "radicle-ed25519"
      && typeof probe.public_key === "string"
      && /^[0-9a-f]{64}$/u.test(probe.public_key)
      && /^[0-9a-f]{128}$/u.test(probe.signature)
    ) {
      verified = ed25519.verify(
        hexToBytes(probe.signature),
        message,
        hexToBytes(probe.public_key),
      );
    } else if (
      probe.proof_suite === "jwk-jws"
      && probe.public_jwk?.kty === "OKP"
      && probe.public_jwk.crv === "Ed25519"
      && probe.protected === Buffer.from('{"alg":"EdDSA"}', "utf8").toString("base64url")
    ) {
      const publicKey = Buffer.from(probe.public_jwk.x, "base64url");
      const signature = Buffer.from(probe.signature, "base64url");
      const encodedPayload = Buffer.from(message).toString("base64url");
      const signingInput = new TextEncoder().encode(
        `${probe.protected}.${encodedPayload}`,
      );
      verified = publicKey.length === 32
        && signature.length === 64
        && ed25519.verify(signature, signingInput, publicKey);
    }
  } catch {
    verified = false;
  }
  return verified
    ? {
        verdict: "accept",
        proof_suite: probe.proof_suite,
        proof_purpose: probe.proof_purpose,
        authenticated_message: probe.message,
      }
    : { verdict: "reject", reason_code: "claim-subject-proof-invalid" };
}

// Composition dependency: after the Task 2 fix lands, delete these private
// aliases and add:
// import type { AuthorityDecision } from "./security-authority-support.js";
type IndeterminateDecision<I extends string = never> = Readonly<
  [I] extends [never]
    ? { verdict: "indeterminate"; reconciliation_digest: string }
    : { verdict: "indeterminate"; reason_code: I; reconciliation_digest: string }
>;

type AuthorityDecision<R extends string, O, I extends string = never> = Readonly<
  | { verdict: "accept"; output: O }
  | { verdict: "reject"; reason_code: R }
  | IndeterminateDecision<I>
>;

export type CurrentControlFrameVerificationContext = Readonly<{
  expected_profile: string;
  expected_version: string;
  expected_group_id: string;
  expected_sender: string;
  expected_request_digest: string;
  trusted_now: number;
}>;

export type CurrentControlFrameDecision = AuthorityDecision<
  "control-frame-invalid",
  Readonly<{
    event_id: string;
    request_id: string;
    request_digest: string;
  }>
>;

const CONTROL_FRAME_MEMBERS = [
  "expires_at",
  "frame_type",
  "payload",
  "profile",
  "request_id",
  "version",
] as const;
const CONTROL_PAYLOAD_MEMBERS = ["body", "group_id", "request_digest"] as const;
const SIGNED_EVENT_MEMBERS = [
  "content",
  "created_at",
  "id",
  "kind",
  "pubkey",
  "sig",
  "tags",
] as const;

function hasExactOwnMembers(
  value: object,
  expected: readonly string[],
): boolean {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  return keys.every((key) => typeof key === "string")
    && keys.length === expected.length
    && expected.every((member) => {
      const descriptor = descriptors[member];
      return descriptor !== undefined
        && "value" in descriptor
        && descriptor.enumerable === true;
    });
}

function rejectCurrentControlFrame(): CurrentControlFrameDecision {
  return { verdict: "reject", reason_code: "control-frame-invalid" };
}

function topLevelJsonObjectKeys(source: string): string[] | undefined {
  let index = 0;
  const skipWhitespace = () => {
    while (/\s/.test(source[index] ?? "")) index += 1;
  };
  const scanString = (): string | undefined => {
    const start = index;
    if (source[index] !== '"') return undefined;
    index += 1;
    while (index < source.length) {
      if (source[index] === "\\") index += 2;
      else if (source[index] === '"') {
        index += 1;
        try {
          return JSON.parse(source.slice(start, index)) as string;
        } catch {
          return undefined;
        }
      } else index += 1;
    }
    return undefined;
  };
  const skipValue = (): boolean => {
    let objectDepth = 0;
    let arrayDepth = 0;
    let inString = false;
    let escaped = false;
    for (; index < source.length; index += 1) {
      const character = source[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
        continue;
      }
      if (character === '"') inString = true;
      else if (character === "{") objectDepth += 1;
      else if (character === "[") arrayDepth += 1;
      else if (character === "}") {
        if (objectDepth === 0 && arrayDepth === 0) return true;
        objectDepth -= 1;
      } else if (character === "]") arrayDepth -= 1;
      else if (character === "," && objectDepth === 0 && arrayDepth === 0) return true;
      if (objectDepth < 0 || arrayDepth < 0) return false;
    }
    return true;
  };
  skipWhitespace();
  if (source[index] !== "{") return undefined;
  index += 1;
  const keys: string[] = [];
  for (;;) {
    skipWhitespace();
    if (source[index] === "}") {
      index += 1;
      skipWhitespace();
      return index === source.length ? keys : undefined;
    }
    const key = scanString();
    if (key === undefined || keys.includes(key)) return undefined;
    keys.push(key);
    skipWhitespace();
    if (source[index] !== ":") return undefined;
    index += 1;
    skipWhitespace();
    if (!skipValue()) return undefined;
    skipWhitespace();
    if (source[index] === ",") {
      index += 1;
      continue;
    }
    if (source[index] !== "}") return undefined;
  }
}

export function currentControlFrameRequestDigest(input: Readonly<{
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

export type CurrentControlRequestBodyProjection = Readonly<{
  profile: "human-jsonrpc" | "agent-mcp";
  request_id: string;
  expires_at: number | null;
  authorization_method: string;
  authorization_object: Readonly<{ class: string; id: string }> | null;
  body: Readonly<Record<string, JsonValue>>;
}>;

const REQUEST_BODY_MAX_DEPTH = 16;
const REQUEST_BODY_MAX_NODES = 8_192;
const REQUEST_BODY_MAX_STRING_BYTES = 1_048_576;
const CONTROL_OBJECT_CLASSES = new Set([
  "none", "session", "repository", "config_namespace", "marmot_group",
  "feed", "media", "device",
]);

function hasOnlyUnicodeScalars(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function preflightRequestBody(value: unknown): value is JsonValue {
  let nodes = 0;
  let stringBytes = 0;
  const active = new Set<object>();
  const visit = (current: unknown, depth: number): boolean => {
    nodes += 1;
    if (nodes > REQUEST_BODY_MAX_NODES || depth > REQUEST_BODY_MAX_DEPTH) return false;
    if (current === null || typeof current === "boolean") return true;
    if (typeof current === "number") return Number.isFinite(current);
    if (typeof current === "string") {
      if (!hasOnlyUnicodeScalars(current)) return false;
      stringBytes += Buffer.byteLength(current, "utf8");
      return stringBytes <= REQUEST_BODY_MAX_STRING_BYTES;
    }
    if (typeof current !== "object" || utilTypes.isProxy(current) || active.has(current)) return false;
    const prototype = Object.getPrototypeOf(current);
    if (prototype !== Object.prototype && prototype !== Array.prototype) return false;
    const descriptors = Object.getOwnPropertyDescriptors(current);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== "string" || !hasOnlyUnicodeScalars(key))) return false;
    active.add(current);
    try {
      if (Array.isArray(current)) {
        if (keys.length !== current.length + 1) return false;
        for (let index = 0; index < current.length; index += 1) {
          const descriptor = descriptors[String(index)];
          if (descriptor === undefined || !("value" in descriptor)
            || descriptor.enumerable !== true || !visit(descriptor.value, depth + 1)) return false;
        }
        return true;
      }
      for (const key of keys as string[]) {
        const descriptor = descriptors[key];
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true
          || !visit(key, depth + 1) || !visit(descriptor.value, depth + 1)) return false;
      }
      return true;
    } finally {
      active.delete(current);
    }
  };
  return visit(value, 0);
}

function freezeJson(value: JsonValue): JsonValue {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeJson(child);
    Object.freeze(value);
  }
  return value;
}

function projectedAuthorizationObject(
  value: unknown,
): Readonly<{ class: string; id: string }> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  if (!hasExactOwnMembers(value, ["class", "id"])) return null;
  const candidate = value as Readonly<{ class: unknown; id: unknown }>;
  return typeof candidate.class === "string" && CONTROL_OBJECT_CLASSES.has(candidate.class)
    && typeof candidate.id === "string" && candidate.id.length > 0
    ? Object.freeze({ class: candidate.class, id: candidate.id })
    : null;
}

/** Captures the exact live Control JSON-RPC/MCP request and projects its authorization tuple. */
export function projectCurrentControlRequestBody(
  profile: string,
  value: unknown,
): CurrentControlRequestBodyProjection | null {
  if ((profile !== "human-jsonrpc" && profile !== "agent-mcp")
    || !preflightRequestBody(value) || value === null || Array.isArray(value)
    || typeof value !== "object") return null;
  try {
    const body = freezeJson(structuredClone(value)) as Readonly<Record<string, JsonValue>>;
    if (profile === "human-jsonrpc") {
      validateControlRpcRequestSchemaOrThrow(body);
      if (typeof body.id !== "string" || typeof body.method !== "string"
        || !Number.isSafeInteger(body.expires_at)) return null;
      const params = body.params as Readonly<Record<string, JsonValue>>;
      return Object.freeze({
        profile,
        request_id: body.id,
        expires_at: body.expires_at as number,
        authorization_method: body.method,
        authorization_object: projectedAuthorizationObject(params.object),
        body,
      });
    }
    validateControlMcpFrameSchemaOrThrow(body);
    if (typeof body.id !== "string" || typeof body.method !== "string") return null;
    const params = body.params !== null && typeof body.params === "object" && !Array.isArray(body.params)
      ? body.params as Readonly<Record<string, JsonValue>>
      : null;
    const argumentsValue = params?.arguments;
    const argumentsObject = argumentsValue !== null && typeof argumentsValue === "object"
      && !Array.isArray(argumentsValue)
      ? argumentsValue as Readonly<Record<string, JsonValue>>
      : null;
    return Object.freeze({
      profile,
      request_id: body.id,
      expires_at: null,
      authorization_method: body.method === "tools/call" && typeof params?.name === "string"
        ? params.name
        : body.method,
      authorization_object: projectedAuthorizationObject(argumentsObject?.object),
      body,
    });
  } catch {
    return null;
  }
}

/**
 * Captures and verifies one exact signed kind-31017 Control request carried by
 * an already authenticated Marmot group.
 */
export function validateCurrentControlFrameProfile(
  frame_bytes: Uint8Array,
  context: CurrentControlFrameVerificationContext,
): CurrentControlFrameDecision {
  try {
    if (
      !(frame_bytes instanceof Uint8Array)
      || Object.getPrototypeOf(frame_bytes) !== Uint8Array.prototype
      || !Number.isSafeInteger(context.trusted_now)
      || context.trusted_now < 0
    ) return rejectCurrentControlFrame();
    const capturedBytes = frame_bytes.slice();
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(capturedBytes);
    const outerKeys = topLevelJsonObjectKeys(decoded);
    if (
      outerKeys === undefined
      || outerKeys.length !== SIGNED_EVENT_MEMBERS.length
      || !SIGNED_EVENT_MEMBERS.every((member) => outerKeys.includes(member))
    ) return rejectCurrentControlFrame();
    const parsed: unknown = JSON.parse(decoded);
    const event = snapshotAndVerifyNostrEvent(parsed);
    if (
      event === null
      || event.kind !== 31017
      || event.pubkey !== context.expected_sender
      || event.tags.length !== 0
      || event.created_at > context.trusted_now
    ) return rejectCurrentControlFrame();

    const frame: unknown = JSON.parse(event.content);
    if (frame === null || typeof frame !== "object" || Array.isArray(frame)) {
      return rejectCurrentControlFrame();
    }
    if (jcsCanonicalize(frame) !== event.content) return rejectCurrentControlFrame();
    validateControlFrameSchemaOrThrow(frame);
    if (!hasExactOwnMembers(frame, CONTROL_FRAME_MEMBERS)) {
      return rejectCurrentControlFrame();
    }
    const candidate = frame as Readonly<{
      expires_at: unknown;
      frame_type: unknown;
      payload: unknown;
      profile: unknown;
      request_id: unknown;
      version: unknown;
    }>;
    if (
      candidate.frame_type !== "request"
      || candidate.profile !== context.expected_profile
      || candidate.version !== context.expected_version
      || typeof candidate.request_id !== "string"
      || candidate.request_id.length === 0
      || !Number.isSafeInteger(candidate.expires_at)
      || (candidate.expires_at as number) <= context.trusted_now
      || candidate.payload === null
      || typeof candidate.payload !== "object"
      || Array.isArray(candidate.payload)
      || !hasExactOwnMembers(candidate.payload, CONTROL_PAYLOAD_MEMBERS)
    ) return rejectCurrentControlFrame();
    const payload = candidate.payload as Readonly<{
      body: unknown;
      group_id: unknown;
      request_digest: unknown;
    }>;
    if (
      payload.body === null
      || typeof payload.body !== "object"
      || Array.isArray(payload.body)
      || payload.group_id !== context.expected_group_id
      || payload.request_digest !== context.expected_request_digest
      || typeof payload.request_digest !== "string"
      || !/^[0-9a-f]{64}$/u.test(payload.request_digest)
    ) return rejectCurrentControlFrame();
    const projectedBody = projectCurrentControlRequestBody(
      candidate.profile as string,
      payload.body,
    );
    if (projectedBody === null || projectedBody.request_id !== candidate.request_id
      || (projectedBody.profile === "human-jsonrpc"
        && projectedBody.expires_at !== candidate.expires_at)) return rejectCurrentControlFrame();
    const body = projectedBody.body;
    const derivedRequestDigest = currentControlFrameRequestDigest({
      profile: candidate.profile,
      version: candidate.version as string,
      group_id: payload.group_id as string,
      sender: event.pubkey,
      request_id: candidate.request_id,
      expires_at: candidate.expires_at as number,
      body,
    });
    if (payload.request_digest !== derivedRequestDigest) {
      return rejectCurrentControlFrame();
    }
    return {
      verdict: "accept",
      output: {
        event_id: event.id,
        request_id: candidate.request_id,
        request_digest: payload.request_digest,
      },
    };
  } catch {
    return rejectCurrentControlFrame();
  }
}

function validateLegacyControlFrameProfile(value: unknown):
  | Readonly<{ verdict: "accept"; transport: "marmot-inner"; frame_type: string }>
  | Readonly<{ verdict: "reject"; reason_code: "control-frame-invalid" }> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { verdict: "reject", reason_code: "control-frame-invalid" };
  }
  const input = value as Readonly<{
    transport?: unknown;
    frame?: unknown;
  }>;
  if (input.transport !== "marmot-inner") {
    return { verdict: "reject", reason_code: "control-frame-invalid" };
  }
  try {
    validateControlFrameSchemaOrThrow(input.frame);
  } catch {
    return { verdict: "reject", reason_code: "control-frame-invalid" };
  }
  const frameType = (input.frame as Readonly<{ frame_type: string }>).frame_type;
  return { verdict: "accept", transport: "marmot-inner", frame_type: frameType };
}

type CurrentControlGrantProfileInput = Readonly<{
  active_account: string;
  authenticated_account: string;
  grant_account: string;
  requested_device: string;
  grant_device: string;
  requested_leaf: string;
  grant_leaf: string;
  requested_group: string;
  grant_group: string;
  requested_grant: string;
  grant_id: string;
  requested_content_ids: readonly string[];
  granted_content_ids: readonly string[];
  requested_secret_classes: readonly string[];
}>;

function isClosedStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value)
    && value.every((member) => typeof member === "string" && member.length > 0)
    && new Set(value).size === value.length;
}

/**
 * Enforces the exact node account, device leaf, group, grant-filtered content,
 * and zero-secret result for one closed Control Marmot frame.
 */
export function validateCurrentControlGrantProfile(value: unknown):
  | Readonly<{
      verdict: "accept";
      transport: "marmot-inner";
      frame_type: string;
      active_account: string;
      device_leaf: string;
      grant_id: string;
      content_ids: readonly string[];
      released_secrets: readonly [];
    }>
  | Readonly<{
      verdict: "reject";
      reason_code: "control-frame-invalid" | "control-token-invalid";
    }> {
  const frame = validateLegacyControlFrameProfile(value);
  if (frame.verdict === "reject") {
    return {
      verdict: "reject",
      reason_code: frame.reason_code === "control-frame-invalid"
        ? "control-frame-invalid"
        : "control-token-invalid",
    };
  }
  const input = value as CurrentControlGrantProfileInput;
  const scalarFields = [
    input.active_account,
    input.authenticated_account,
    input.grant_account,
    input.requested_device,
    input.grant_device,
    input.requested_leaf,
    input.grant_leaf,
    input.requested_group,
    input.grant_group,
    input.requested_grant,
    input.grant_id,
  ];
  const accounts = [
    input.active_account,
    input.authenticated_account,
    input.grant_account,
  ];
  if (
    scalarFields.some((field) => typeof field !== "string" || field.length === 0)
    || accounts.some((account) => !/^[0-9a-f]{64}$/u.test(account))
    || !isClosedStringArray(input.requested_content_ids)
    || !isClosedStringArray(input.granted_content_ids)
    || !isClosedStringArray(input.requested_secret_classes)
  ) return { verdict: "reject", reason_code: "control-token-invalid" };

  const accountMatches = input.active_account === input.authenticated_account
    && input.active_account === input.grant_account;
  const exactGrant = input.requested_device === input.grant_device
    && input.requested_leaf === input.grant_leaf
    && input.requested_group === input.grant_group
    && input.requested_grant === input.grant_id;
  const grantedContent = new Set(input.granted_content_ids);
  const contentConfined = input.requested_content_ids.every((id) => grantedContent.has(id));
  const secretsConfined = input.requested_secret_classes.length === 0;
  const admission = controlGroupAdmission({
    cryptographic_valid: true,
    member_count: 2,
    node_account_matches: accountMatches,
    supported_control_profile: true,
    invitation_mode: "off",
    temporary_mode_unexpired: false,
    resource_available: exactGrant && contentConfined && secretsConfined,
    entitlement_state: "active",
    purpose_bound_invite_valid: false,
    explicit_local_decision: "none",
  });
  if (admission.outcome !== "accept-authorized") {
    return { verdict: "reject", reason_code: "control-token-invalid" };
  }
  return {
    verdict: "accept",
    transport: frame.transport,
    frame_type: frame.frame_type,
    active_account: input.active_account,
    device_leaf: input.requested_leaf,
    grant_id: input.requested_grant,
    content_ids: [...input.requested_content_ids],
    released_secrets: [],
  };
}
