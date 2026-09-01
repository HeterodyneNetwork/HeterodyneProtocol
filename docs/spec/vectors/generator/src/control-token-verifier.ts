import { types as utilTypes } from "node:util";
import {
  revalidateAuthorizationViewAtEffect,
  type CurrentAuthorizationView,
} from "./authorization-freshness.js";
import type { JsonValue } from "./claims.js";
import type { ControlAuthorizationObject } from "./control-profile.js";
import { jcsCanonicalize } from "./jcs.js";
import { createValidatedProjectedJwtContext } from "./oidc.js";
import {
  currentControlFrameRequestDigest,
  projectCurrentControlRequestBody,
} from "./profile-negotiation.js";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type AuthorityDecision,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
} from "./security-authority-support.js";
import { assertCurrentControlGrantUse } from "./token-status.js";

type ControlTokenOutput = Readonly<{ operation_id: string }>;

export type ControlTokenVerifierConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  expected_issuer: string;
  expected_audience: string;
  jwks: JsonValue;
  load_grant_view: (authorization_id: string) => Promise<CurrentAuthorizationView>;
  consume_proof: (input: Readonly<{
    compact_proof: string;
    sender_key: string;
    operation_digest: string;
  }>) => Promise<string | null>;
  store: DurableAuthorityStore<ControlTokenOutput>;
  execute_operation: (
    execution_token: string,
    operation: Readonly<{
      operation_id: string;
      request_digest: string;
      payload: JsonValue;
    }>,
  ) => Promise<ControlTokenOutput>;
}>;

export type ControlTokenUse = Readonly<{
  sender_key: string;
  marmot_group_id: string;
  authorization_id: string;
  grant_generation: number;
  required_scope: string;
  method: string;
  object: ControlAuthorizationObject;
  compact_proof: string;
}>;

export type ControlTokenOperation = Readonly<{
  operation_id: string;
  request_digest: string;
  payload: JsonValue;
}>;

export type VerifiedControlToken = Readonly<Record<never, never>>;
export type ControlTokenVerifier = Readonly<Record<never, never>>;

type StoreCallbacks = Readonly<{
  load: DurableAuthorityStore<ControlTokenOutput>["load"];
  acquire: DurableAuthorityStore<ControlTokenOutput>["acquire"];
  compareAndSwap: DurableAuthorityStore<ControlTokenOutput>["compareAndSwap"];
  commit: DurableAuthorityStore<ControlTokenOutput>["commit"];
  markIndeterminate: DurableAuthorityStore<ControlTokenOutput>["markIndeterminate"];
}>;

type AuthorityRecord = Readonly<{
  authority_id: string;
  trusted_now: ControlTokenVerifierConfig["trusted_now"];
  expected_issuer: string;
  expected_audience: string;
  jwks: JsonValue;
  load_grant_view: ControlTokenVerifierConfig["load_grant_view"];
  consume_proof: ControlTokenVerifierConfig["consume_proof"];
  store: StoreCallbacks;
  execute_operation: ControlTokenVerifierConfig["execute_operation"];
}>;

type VerifiedRecord = {
  readonly authority: AuthorityRecord;
  readonly compact_jwt: string;
  readonly use: ControlTokenUse;
  readonly token_binding_digest: string;
  readonly issued_at: number;
  readonly expires_at: number;
  readonly mode: "effect-capable" | "replay-only";
  operation_binding_digest: string | null;
};

type DurableBinding = Readonly<{
  key: string;
  binding_digest: string;
  execution_token: string;
  output: ControlTokenOutput;
  output_digest: string;
  reconciliation_digest: string;
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const VERIFIED = new WeakMap<object, VerifiedRecord>();
const CONFIG_KEYS = [
  "authority_id",
  "consume_proof",
  "execute_operation",
  "expected_audience",
  "expected_issuer",
  "jwks",
  "load_grant_view",
  "store",
  "trusted_now",
] as const;
const STORE_KEYS = ["acquire", "commit", "compareAndSwap", "load", "markIndeterminate"] as const;
const USE_KEYS = [
  "authorization_id",
  "compact_proof",
  "grant_generation",
  "marmot_group_id",
  "method",
  "object",
  "required_scope",
  "sender_key",
] as const;
const OPERATION_KEYS = ["operation_id", "payload", "request_digest"] as const;
const OUTPUT_KEYS = ["operation_id"] as const;
const OBJECT_KEYS = ["class", "id"] as const;
const OBJECT_CLASSES = new Set([
  "none",
  "session",
  "repository",
  "config_namespace",
  "marmot_group",
  "feed",
  "media",
  "device",
]);
const RECORD_KEYS = Object.freeze({
  available: ["binding_digest", "output", "revision", "state"],
  executing: ["binding_digest", "execution_token", "revision", "state"],
  committed: [
    "binding_digest",
    "execution_token",
    "output",
    "output_digest",
    "revision",
    "state",
  ],
  indeterminate: [
    "binding_digest",
    "execution_token",
    "reconciliation_digest",
    "revision",
    "state",
  ],
} as const);
const IDENTIFIER_MAX_BYTES = 2_048;
const JWT_MAX_BYTES = 131_072;
const PROOF_MAX_BYTES = 65_536;
const JSON_MAX_DEPTH = 16;
const JSON_MAX_NODES = 8_192;
const JSON_MAX_STRING_BYTES = 1_048_576;
const CURRENT_CONTROL_VERSION = "heterodyne/0.6.0";

const REJECT = Object.freeze({
  verdict: "reject" as const,
  reason_code: "control-token-invalid" as const,
});

function exactDescriptorValues(
  value: unknown,
  keys: readonly string[],
): Readonly<Record<string, unknown>> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const ownKeys = Reflect.ownKeys(descriptors);
  if (ownKeys.length !== keys.length || ownKeys.some((key) => typeof key !== "string")
    || !keys.every((key) => Object.hasOwn(descriptors, key))) return null;
  const result: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      return null;
    }
    result[key] = descriptor.value;
  }
  return result;
}

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

function boundedString(value: unknown, maximum = IDENTIFIER_MAX_BYTES): value is string {
  return typeof value === "string" && value.length > 0
    && hasOnlyUnicodeScalars(value)
    && Buffer.byteLength(value, "utf8") <= maximum;
}

function boundMethod<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  let owner: object | null = object;
  while (owner !== null) {
    if (utilTypes.isProxy(owner)) throw new TypeError("Control token store cannot be a proxy");
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function"
        || utilTypes.isProxy(descriptor.value)) {
        throw new TypeError(`Control token store requires data method ${name}`);
      }
      return descriptor.value.bind(object) as T;
    }
    owner = Object.getPrototypeOf(owner) as object | null;
  }
  throw new TypeError(`Control token store requires method ${name}`);
}

function validObject(value: unknown): value is ControlAuthorizationObject {
  const object = exactDescriptorValues(value, OBJECT_KEYS);
  return object !== null && boundedString(object.class) && OBJECT_CLASSES.has(object.class)
    && boundedString(object.id);
}

function boundedClosedJson(value: unknown): value is JsonValue {
  let nodes = 0;
  let stringBytes = 0;
  const active = new Set<object>();
  const visit = (current: unknown, depth: number): boolean => {
    nodes += 1;
    if (nodes > JSON_MAX_NODES || depth > JSON_MAX_DEPTH) return false;
    if (current === null || typeof current === "boolean") return true;
    if (typeof current === "number") return Number.isFinite(current);
    if (typeof current === "string") {
      if (!hasOnlyUnicodeScalars(current)) return false;
      stringBytes += Buffer.byteLength(current, "utf8");
      return stringBytes <= JSON_MAX_STRING_BYTES;
    }
    if (typeof current !== "object" || utilTypes.isProxy(current) || active.has(current)) return false;
    active.add(current);
    try {
      const descriptors = Object.getOwnPropertyDescriptors(current);
      const keys = Reflect.ownKeys(descriptors);
      if (keys.some((key) => typeof key !== "string" || !hasOnlyUnicodeScalars(key))) return false;
      if (Array.isArray(current)) {
        if (Object.getPrototypeOf(current) !== Array.prototype) return false;
        const length = current.length;
        if (!Number.isSafeInteger(length) || length < 0 || keys.length !== length + 1) return false;
        for (let index = 0; index < length; index += 1) {
          const descriptor = descriptors[String(index)];
          if (descriptor === undefined || !("value" in descriptor)
            || descriptor.enumerable !== true || !visit(descriptor.value, depth + 1)) return false;
        }
        return true;
      }
      if (Object.getPrototypeOf(current) !== Object.prototype) return false;
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

function captureUse(value: ControlTokenUse): ControlTokenUse | null {
  const raw = exactDescriptorValues(value, USE_KEYS);
  if (raw === null || !boundedClosedJson(raw)) return null;
  const captured = captureAuthorityInput(raw) as unknown as ControlTokenUse;
  return boundedString(captured.sender_key)
    && boundedString(captured.marmot_group_id)
    && boundedString(captured.authorization_id)
    && Number.isSafeInteger(captured.grant_generation) && captured.grant_generation >= 0
    && boundedString(captured.required_scope)
    && boundedString(captured.method)
    && validObject(captured.object)
    && boundedString(captured.compact_proof, PROOF_MAX_BYTES)
    ? captured
    : null;
}

function captureOperation(value: ControlTokenOperation): ControlTokenOperation | null {
  const raw = exactDescriptorValues(value, OPERATION_KEYS);
  if (raw === null || !boundedClosedJson(raw)) return null;
  const captured = captureAuthorityInput(raw) as unknown as ControlTokenOperation;
  return boundedString(captured.operation_id)
    && /^[0-9a-f]{64}$/u.test(captured.request_digest)
    && boundedClosedJson(captured.payload)
    ? captured
    : null;
}

function replayValidatedToken(
  authority: AuthorityRecord,
  compactJwt: string,
  use: ControlTokenUse,
): Readonly<{ issued_at: number; expires_at: number }> | null {
  try {
    const segments = compactJwt.split(".");
    if (segments.length !== 3 || !/^[A-Za-z0-9_-]+$/u.test(segments[1])) return null;
    const decoded: unknown = JSON.parse(Buffer.from(segments[1], "base64url").toString("utf8"));
    if (!boundedClosedJson(decoded) || decoded === null || typeof decoded !== "object"
      || Array.isArray(decoded)) return null;
    const claims = decoded as Readonly<Record<string, JsonValue>>;
    if (!Number.isSafeInteger(claims.iat) || Number(claims.iat) < 0
      || !Number.isSafeInteger(claims.exp) || Number(claims.exp) <= Number(claims.iat)
      || !boundedString(claims.client_id) || !boundedString(claims.sub)
      || (claims.client_class !== "human-light" && claims.client_class !== "automated")
      || !/^[0-9a-f]{64}$/u.test(String(claims.credential_ledger_persona))
      || !Number.isSafeInteger(claims.credential_ledger_generation)
      || Number(claims.credential_ledger_generation) < 0) return null;
    const validated = createValidatedProjectedJwtContext(
      compactJwt,
      authority.expected_issuer,
      authority.expected_audience,
      authority.jwks,
      {
        now: Number(claims.iat),
        token_use: "access_token",
        client_id: claims.client_id,
        cnf: { jkt: use.sender_key },
        sender_constraint: "dpop",
        permitted_audiences: [authority.expected_audience],
        credential_ledger: {
          credential_ledger_persona: String(claims.credential_ledger_persona),
          credential_ledger_generation: Number(claims.credential_ledger_generation),
        },
      },
    );
    const presented = validated.claims;
    return presented.group_id === use.marmot_group_id
      && presented.authorization_id === use.authorization_id
      && presented.grant_generation === use.grant_generation
      && presented.credential_ledger_generation === use.grant_generation
      && typeof presented.scope === "string"
      && presented.scope.split(" ").includes(use.required_scope)
      && Array.isArray(presented.methods) && presented.methods.includes(use.method)
      && Array.isArray(presented.objects) && presented.objects.some((object) =>
        jcsCanonicalize(object) === jcsCanonicalize(use.object))
      ? Object.freeze({ issued_at: Number(presented.iat), expires_at: Number(presented.exp) })
      : null;
  } catch {
    return null;
  }
}

function captureVerifiedOperation(
  token: VerifiedRecord,
  value: ControlTokenOperation,
): Readonly<{ operation: ControlTokenOperation; expires_at: number }> | null {
  const captured = captureOperation(value);
  if (captured === null) return null;
  const projections = (["human-jsonrpc", "agent-mcp"] as const)
    .map((profile) => projectCurrentControlRequestBody(profile, captured.payload))
    .filter((projection) => projection !== null);
  if (projections.length !== 1) return null;
  const projection = projections[0];
  if (projection.request_id !== captured.operation_id
    || projection.authorization_method !== token.use.method
    || projection.authorization_object === null
    || jcsCanonicalize(projection.authorization_object) !== jcsCanonicalize(token.use.object)) return null;
  const expiresAt = projection.expires_at ?? token.expires_at;
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= token.issued_at
    || expiresAt > token.expires_at) return null;
  const derived = currentControlFrameRequestDigest({
    profile: projection.profile,
    version: CURRENT_CONTROL_VERSION,
    group_id: token.use.marmot_group_id,
    sender: token.use.sender_key,
    request_id: projection.request_id,
    expires_at: expiresAt,
    body: projection.body,
  });
  return captured.request_digest === derived
    ? Object.freeze({ operation: Object.freeze({
        operation_id: captured.operation_id,
        request_digest: derived,
        payload: projection.body,
      }), expires_at: expiresAt })
    : null;
}

function captureOutput(value: unknown): ControlTokenOutput | null {
  const raw = exactDescriptorValues(value, OUTPUT_KEYS);
  if (raw === null || !boundedString(raw.operation_id)) return null;
  return Object.freeze({ operation_id: raw.operation_id });
}

function requireAuthority(verifier: ControlTokenVerifier): AuthorityRecord | null {
  return verifier !== null && typeof verifier === "object"
    ? AUTHORITIES.get(verifier as object) ?? null
    : null;
}

function trustedNow(authority: AuthorityRecord): number | null {
  try {
    const now = authority.trusted_now();
    return Number.isSafeInteger(now) && now >= 0 ? now : null;
  } catch {
    return null;
  }
}

async function assertCurrentGrant(
  authority: AuthorityRecord,
  compactJwt: string,
  use: ControlTokenUse,
): Promise<void> {
  const now = trustedNow(authority);
  if (now === null) throw new Error("control-token-invalid");
  try {
    const view = await authority.load_grant_view(use.authorization_id);
    const current = revalidateAuthorizationViewAtEffect(view);
    if (current.verdict !== "accept" || current.evaluated_at !== now) {
      throw new Error("control-token-invalid");
    }
    await assertCurrentControlGrantUse(view, {
      authority_id: authority.authority_id,
      compact_jwt: compactJwt,
      expected_issuer: authority.expected_issuer,
      expected_audience: authority.expected_audience,
      jwks: authority.jwks,
      now,
      sender_key: use.sender_key,
      marmot_group_id: use.marmot_group_id,
      authorization_id: use.authorization_id,
      grant_generation: use.grant_generation,
      required_scope: use.required_scope,
      method: use.method,
      object: use.object,
    });
  } catch {
    throw new Error("control-token-invalid");
  }
}

function bindingFor(
  authority: AuthorityRecord,
  token: VerifiedRecord,
  operation: ControlTokenOperation,
): DurableBinding {
  const request = {
    authority_id: authority.authority_id,
    token_binding_digest: token.token_binding_digest,
    operation,
  };
  const key = authorityBindingDigest("control-token-operation-key-v1", request);
  const bindingDigest = authorityBindingDigest("control-token-operation-binding-v1", request);
  const executionToken = authorityBindingDigest("control-token-operation-execution-v1", {
    key,
    binding_digest: bindingDigest,
  });
  const output = Object.freeze({ operation_id: operation.operation_id });
  const outputDigest = authorityBindingDigest("control-token-operation-output-v1", output);
  const reconciliationDigest = authorityBindingDigest("control-token-operation-reconciliation-v1", {
    key,
    binding_digest: bindingDigest,
    execution_token: executionToken,
  });
  return {
    key,
    binding_digest: bindingDigest,
    execution_token: executionToken,
    output,
    output_digest: outputDigest,
    reconciliation_digest: reconciliationDigest,
  };
}

function captureDurableRecord(
  value: DurableAuthorityRecord<ControlTokenOutput> | null,
): DurableAuthorityRecord<ControlTokenOutput> | null | undefined {
  if (value === null) return null;
  if (value === undefined || value === null || typeof value !== "object" || utilTypes.isProxy(value)) {
    return undefined;
  }
  const stateDescriptor = Object.getOwnPropertyDescriptor(value, "state");
  if (stateDescriptor === undefined || !("value" in stateDescriptor)
    || typeof stateDescriptor.value !== "string"
    || !Object.hasOwn(RECORD_KEYS, stateDescriptor.value)) return undefined;
  const keys = RECORD_KEYS[stateDescriptor.value as keyof typeof RECORD_KEYS];
  const raw = exactDescriptorValues(value, keys);
  if (raw === null || !Number.isSafeInteger(raw.revision) || Number(raw.revision) < 0
    || !boundedString(raw.binding_digest)) return undefined;
  try {
    const captured = captureAuthorityInput(raw) as unknown as DurableAuthorityRecord<ControlTokenOutput>;
    if (captured.state === "available") {
      return captureOutput(captured.output) === null ? undefined : captured;
    }
    if (!boundedString(captured.execution_token)) return undefined;
    if (captured.state === "committed") {
      return boundedString(captured.output_digest) && captureOutput(captured.output) !== null
        ? captured
        : undefined;
    }
    if (captured.state === "indeterminate" && !boundedString(captured.reconciliation_digest)) {
      return undefined;
    }
    return captured;
  } catch {
    return undefined;
  }
}

async function loadRecord(
  authority: AuthorityRecord,
  key: string,
): Promise<DurableAuthorityRecord<ControlTokenOutput> | null | undefined> {
  try {
    return captureDurableRecord(await authority.store.load(key));
  } catch {
    return undefined;
  }
}

function exactCommitted(
  record: DurableAuthorityRecord<ControlTokenOutput>,
  binding: DurableBinding,
): boolean {
  if (record.state !== "committed") return false;
  const output = captureOutput(record.output);
  return record.binding_digest === binding.binding_digest
    && record.execution_token === binding.execution_token
    && record.output_digest === binding.output_digest
    && output !== null
    && output.operation_id === binding.output.operation_id;
}

function exactExecuting(
  record: DurableAuthorityRecord<ControlTokenOutput>,
  binding: DurableBinding,
): boolean {
  return record.state === "executing"
    && record.binding_digest === binding.binding_digest
    && record.execution_token === binding.execution_token;
}

function exactIndeterminate(
  record: DurableAuthorityRecord<ControlTokenOutput>,
  binding: DurableBinding,
): boolean {
  return record.state === "indeterminate"
    && record.binding_digest === binding.binding_digest
    && record.execution_token === binding.execution_token
    && record.reconciliation_digest === binding.reconciliation_digest;
}

function indeterminate(binding: DurableBinding): AuthorityDecision<
  "control-token-invalid",
  ControlTokenOutput
> {
  return Object.freeze({
    verdict: "indeterminate" as const,
    reconciliation_digest: binding.reconciliation_digest,
  });
}

async function markIndeterminate(
  authority: AuthorityRecord,
  binding: DurableBinding,
): Promise<void> {
  try {
    await authority.store.markIndeterminate({
      key: binding.key,
      binding_digest: binding.binding_digest,
      execution_token: binding.execution_token,
      reconciliation_digest: binding.reconciliation_digest,
    });
    await loadRecord(authority, binding.key);
  } catch {
    // The already persisted executing state remains conservative authority.
  }
}

export function createControlTokenVerifier(
  config: ControlTokenVerifierConfig,
): ControlTokenVerifier {
  const values = exactDescriptorValues(config, CONFIG_KEYS);
  if (values === null || !boundedString(values.authority_id)
    || !boundedString(values.expected_issuer) || !boundedString(values.expected_audience)
    || typeof values.trusted_now !== "function" || utilTypes.isProxy(values.trusted_now)
    || typeof values.load_grant_view !== "function" || utilTypes.isProxy(values.load_grant_view)
    || typeof values.consume_proof !== "function" || utilTypes.isProxy(values.consume_proof)
    || typeof values.execute_operation !== "function" || utilTypes.isProxy(values.execute_operation)) {
    throw new TypeError("closed Control token verifier configuration required");
  }
  if (values.store === null || typeof values.store !== "object" || utilTypes.isProxy(values.store)) {
    throw new TypeError("closed Control token durable store required");
  }
  if (!boundedClosedJson(values.jwks)) {
    throw new TypeError("closed Control token JWKS required");
  }
  const store = values.store as DurableAuthorityStore<ControlTokenOutput>;
  const authority: AuthorityRecord = Object.freeze({
    authority_id: values.authority_id,
    trusted_now: values.trusted_now as ControlTokenVerifierConfig["trusted_now"],
    expected_issuer: values.expected_issuer,
    expected_audience: values.expected_audience,
    jwks: captureAuthorityInput(values.jwks) as JsonValue,
    load_grant_view: values.load_grant_view as ControlTokenVerifierConfig["load_grant_view"],
    consume_proof: values.consume_proof as ControlTokenVerifierConfig["consume_proof"],
    store: Object.freeze({
      load: boundMethod<StoreCallbacks["load"]>(store, STORE_KEYS[3]),
      acquire: boundMethod<StoreCallbacks["acquire"]>(store, STORE_KEYS[0]),
      compareAndSwap: boundMethod<StoreCallbacks["compareAndSwap"]>(store, STORE_KEYS[2]),
      commit: boundMethod<StoreCallbacks["commit"]>(store, STORE_KEYS[1]),
      markIndeterminate: boundMethod<StoreCallbacks["markIndeterminate"]>(store, STORE_KEYS[4]),
    }),
    execute_operation: values.execute_operation as ControlTokenVerifierConfig["execute_operation"],
  });
  const verifier = Object.freeze({}) as ControlTokenVerifier;
  AUTHORITIES.set(verifier, authority);
  return verifier;
}

export async function verifyControlToken(
  verifier: ControlTokenVerifier,
  compact_jwt: string,
  use: ControlTokenUse,
): Promise<AuthorityDecision<"control-token-invalid", VerifiedControlToken>> {
  const authority = requireAuthority(verifier);
  const capturedUse = captureUse(use);
  if (authority === null || !boundedString(compact_jwt, JWT_MAX_BYTES) || capturedUse === null) {
    return REJECT;
  }
  const replay = replayValidatedToken(authority, compact_jwt, capturedUse);
  if (replay === null) return REJECT;
  let mode: VerifiedRecord["mode"] = "effect-capable";
  try {
    await assertCurrentGrant(authority, compact_jwt, capturedUse);
  } catch {
    mode = "replay-only";
  }
  const tokenBindingDigest = authorityBindingDigest("control-verified-token-v1", {
    authority_id: authority.authority_id,
    compact_jwt,
    use: capturedUse,
  });
  const token = Object.freeze({}) as VerifiedControlToken;
  VERIFIED.set(token, {
    authority,
    compact_jwt,
    use: capturedUse,
    token_binding_digest: tokenBindingDigest,
    issued_at: replay.issued_at,
    expires_at: replay.expires_at,
    mode,
    operation_binding_digest: null,
  });
  return Object.freeze({ verdict: "accept" as const, output: token });
}

export async function consumeVerifiedControlToken(
  verifier: ControlTokenVerifier,
  token: VerifiedControlToken,
  operation: ControlTokenOperation,
): Promise<AuthorityDecision<"control-token-invalid", ControlTokenOutput>> {
  const authority = requireAuthority(verifier);
  const retained = token !== null && typeof token === "object"
    ? VERIFIED.get(token as object)
    : undefined;
  const operationCapture = retained === undefined ? null : captureVerifiedOperation(retained, operation);
  const capturedOperation = operationCapture?.operation ?? null;
  if (authority === null || retained === undefined || retained.authority !== authority
    || capturedOperation === null) return REJECT;
  const binding = bindingFor(authority, retained, capturedOperation);
  if (retained.operation_binding_digest !== null
    && retained.operation_binding_digest !== binding.binding_digest) return REJECT;
  retained.operation_binding_digest = binding.binding_digest;

  const initial = await loadRecord(authority, binding.key);
  if (initial === undefined) return REJECT;
  if (initial !== null) {
    if (exactCommitted(initial, binding)) {
      return Object.freeze({ verdict: "accept" as const, output: binding.output });
    }
    if (retained.mode === "replay-only") return REJECT;
    if (exactExecuting(initial, binding) || exactIndeterminate(initial, binding)) {
      return indeterminate(binding);
    }
    return REJECT;
  }

  if (retained.mode === "replay-only") return REJECT;
  const operationNow = trustedNow(authority);
  if (operationNow === null || operationCapture === null
    || operationCapture.expires_at <= operationNow) return REJECT;

  try {
    await assertCurrentGrant(authority, retained.compact_jwt, retained.use);
  } catch {
    return REJECT;
  }

  let proofReceipt: string | null;
  try {
    proofReceipt = await authority.consume_proof(Object.freeze({
      compact_proof: retained.use.compact_proof,
      sender_key: retained.use.sender_key,
      operation_digest: capturedOperation.request_digest,
    }));
  } catch {
    return REJECT;
  }
  if (!boundedString(proofReceipt)) return REJECT;

  try {
    await assertCurrentGrant(authority, retained.compact_jwt, retained.use);
  } catch {
    return REJECT;
  }

  let acquired: "acquired" | "replay" | "conflict" | "unavailable";
  try {
    acquired = await authority.store.acquire({
      key: binding.key,
      expected_revision: null,
      binding_digest: binding.binding_digest,
      execution_token: binding.execution_token,
    });
  } catch {
    return REJECT;
  }
  if (acquired !== "acquired") {
    if (acquired !== "replay") return REJECT;
    const replay = await loadRecord(authority, binding.key);
    if (replay !== null && replay !== undefined && exactCommitted(replay, binding)) {
      return Object.freeze({ verdict: "accept" as const, output: binding.output });
    }
    if (replay !== null && replay !== undefined
      && (exactExecuting(replay, binding) || exactIndeterminate(replay, binding))) {
      return indeterminate(binding);
    }
    return REJECT;
  }

  const executing = await loadRecord(authority, binding.key);
  if (executing === null || executing === undefined || !exactExecuting(executing, binding)) {
    await markIndeterminate(authority, binding);
    return indeterminate(binding);
  }
  try {
    await assertCurrentGrant(authority, retained.compact_jwt, retained.use);
  } catch {
    await markIndeterminate(authority, binding);
    return indeterminate(binding);
  }

  let output: ControlTokenOutput;
  try {
    const effect = captureOutput(await authority.execute_operation(
      binding.execution_token,
      capturedOperation,
    ));
    if (effect === null || effect.operation_id !== binding.output.operation_id) {
      await markIndeterminate(authority, binding);
      return indeterminate(binding);
    }
    output = effect;
  } catch {
    await markIndeterminate(authority, binding);
    return indeterminate(binding);
  }

  try {
    await authority.store.commit({
      key: binding.key,
      binding_digest: binding.binding_digest,
      execution_token: binding.execution_token,
      output_digest: binding.output_digest,
      output,
    });
  } catch {
    await markIndeterminate(authority, binding);
    return indeterminate(binding);
  }
  const terminal = await loadRecord(authority, binding.key);
  if (terminal !== null && terminal !== undefined && exactCommitted(terminal, binding)) {
    return Object.freeze({ verdict: "accept" as const, output: binding.output });
  }
  await markIndeterminate(authority, binding);
  return indeterminate(binding);
}
