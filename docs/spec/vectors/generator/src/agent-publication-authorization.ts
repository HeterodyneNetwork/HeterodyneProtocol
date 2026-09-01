import { createHash, randomBytes } from "node:crypto";
import { types as utilTypes } from "node:util";
import {
  injectAgentAttribution,
  snapshotAndVerifyAgentPublication,
  validateWorkloadRegistration,
  type AgentAssociation,
  type NostrSignedEvent,
  type NostrUnsignedEvent,
  type WorkloadRegistration,
} from "./agent-authorship.js";
import type { CurrentClaimAuthorizationView } from "./claim-authorization.js";
import { revalidateLedgerWriterAuthorities } from "./claim-ledger.js";
import {
  claimArtifactBindingDigest,
  claimRevocationArtifactBindingDigest,
  inspectVerifiedClaim,
  inspectVerifiedClaimRevocation,
  type JsonValue,
  type VerifiedClaimArtifact,
  type VerifiedClaimRevocationArtifact,
} from "./claims.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  assertValidatedProjectedJwtContext,
  createValidatedProjectedJwtContext,
} from "./oidc.js";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type AuthorityDecision,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
} from "./security-authority-support.js";

export type AgentPublicationAuthorizationAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  expected_issuer: string;
  expected_audience: string;
  jwks: JsonValue;
  load_claim_view: () => Promise<CurrentClaimAuthorizationView>;
  load_status: (subject: string) => Promise<Readonly<{
    generation: number;
    state: "active" | "revoked";
    checkpoint: string;
  }>>;
  consume_dpop: (proof: Readonly<{
    compact: string;
    method: string;
    target: string;
    nonce: string;
  }>) => Promise<Readonly<{
    proof_digest: string;
    sender_key: string;
  }> | null>;
  read_mtls_peer_identity: () => string | null;
  store: DurableAuthorityStore<NostrSignedEvent>;
  sign_once: (
    execution_token: string,
    event: NostrUnsignedEvent,
  ) => Promise<NostrSignedEvent>;
}>;

export type AgentPublicationRequest = Readonly<{
  compact_jwt: string;
  represented_persona: string;
  agent_id: string;
  signer: string;
  scope: string;
  ledger_generation: number;
  publication: NostrUnsignedEvent;
  attribution_profile: "heterodyne-agent-v1";
  sender_proof:
    | Readonly<{
        kind: "dpop";
        compact: string;
        method: string;
        target: string;
        nonce: string;
      }>
    | Readonly<{ kind: "mtls" }>;
}>;

export type AgentPublicationDecision = AuthorityDecision<
  "agent-sender-proof-invalid" | "agent-signer-mismatch",
  NostrSignedEvent
>;

declare const agentPublicationAuthorizationAuthorityBrand: unique symbol;
export type AgentPublicationAuthorizationAuthority = Readonly<{
  readonly [agentPublicationAuthorizationAuthorityBrand]: true;
}>;

type StoreCallbacks = Readonly<{
  load: DurableAuthorityStore<NostrSignedEvent>["load"];
  acquire: DurableAuthorityStore<NostrSignedEvent>["acquire"];
  compareAndSwap: DurableAuthorityStore<NostrSignedEvent>["compareAndSwap"];
  commit: DurableAuthorityStore<NostrSignedEvent>["commit"];
  markIndeterminate: DurableAuthorityStore<NostrSignedEvent>["markIndeterminate"];
}>;

type AuthorityRecord = Readonly<{
  authority_id: string;
  trusted_now: AgentPublicationAuthorizationAuthorityConfig["trusted_now"];
  expected_issuer: string;
  expected_audience: string;
  jwks: JsonValue;
  load_claim_view: AgentPublicationAuthorizationAuthorityConfig["load_claim_view"];
  load_status: AgentPublicationAuthorizationAuthorityConfig["load_status"];
  consume_dpop: AgentPublicationAuthorizationAuthorityConfig["consume_dpop"];
  read_mtls_peer_identity: AgentPublicationAuthorizationAuthorityConfig["read_mtls_peer_identity"];
  store: StoreCallbacks;
  sign_once: AgentPublicationAuthorizationAuthorityConfig["sign_once"];
}>;

type CapturedClaimView = Readonly<{
  credential_ledger: Readonly<{
    credential_ledger_persona: string;
    credential_ledger_generation: number;
  }>;
  checkpoint_digest: string;
  repository_revision: number;
  fingerprint: string;
  workload_artifact: VerifiedClaimArtifact;
  workload_binding: string;
  workload_claim_id: string;
  registration: WorkloadRegistration;
}>;

type CapturedStatus = Readonly<{
  generation: number;
  state: "active" | "revoked";
  checkpoint: string;
  fingerprint: string;
}>;

type VerifiedToken = Readonly<{
  compact_digest: string;
  issuer: string;
  audience: string;
  subject: string;
  agent_id: string;
  persona: string;
  signer: string;
  signer_key_class: "agent" | "persona";
  association: AgentAssociation | null;
  scope: string;
  issued_at: number;
  expires_at: number;
  token_id: string;
  generation: number;
  sender_key: string;
  sender_kind: "dpop" | "mtls";
}>;

type PreparedAuthorization = Readonly<{
  now: number;
  view: CapturedClaimView;
  status: CapturedStatus;
  token: VerifiedToken;
  attributed_event: NostrUnsignedEvent;
  proof_digest: string;
  proof_key: string;
  durable_key: string;
  binding_digest: string;
  reconciliation_digest: string;
}>;

type VerifiedAgentPublicationAuthorization = Readonly<Record<never, never>>;

type InternalAuthorizationRecord = Readonly<{
  authority: AgentPublicationAuthorizationAuthority;
  prepared: PreparedAuthorization;
  consumed: boolean;
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const INTERNAL_AUTHORIZATIONS = new WeakMap<object, InternalAuthorizationRecord>();
const LOWER_HEX_32 = /^[0-9a-f]{64}$/u;
const SHA256_BASE64URL = /^[A-Za-z0-9_-]{43}$/u;
const MAX_STRING = 4_096;
const MAX_COMPACT = 65_536;
const MAX_CONTENT_BYTES = 16_777_216;
const MAX_TAGS = 1_024;
const MAX_TAG_MEMBERS = 64;
const SELECTED_SIGNER_CLAIM = "https://heterodyne.network/jwt/agent-selected-signer";
const SIGNER_CLASS_CLAIM = "https://heterodyne.network/jwt/agent-signer-key-class";
const ASSOCIATION_CLAIM = "https://heterodyne.network/jwt/agent-association";

const PROOF_REJECT = Object.freeze({
  verdict: "reject" as const,
  reason_code: "agent-sender-proof-invalid" as const,
});
const SIGNER_REJECT = Object.freeze({
  verdict: "reject" as const,
  reason_code: "agent-signer-mismatch" as const,
});

function exactDataDescriptors(
  value: unknown,
  expected: readonly string[],
  label: string,
): Record<string, PropertyDescriptor & { value: unknown }> {
  if (
    value === null
    || typeof value !== "object"
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) throw new TypeError(`${label} must be an ordinary object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some((key) => typeof key !== "string")
    || keys.length !== expected.length
    || !expected.every((key) => Object.hasOwn(descriptors, key))
  ) throw new TypeError(`${label} must be closed`);
  for (const key of expected) {
    const descriptor = descriptors[key];
    if (
      descriptor === undefined
      || !("value" in descriptor)
      || descriptor.enumerable !== true
    ) throw new TypeError(`${label}.${key} must be an enumerable data property`);
  }
  return descriptors as Record<string, PropertyDescriptor & { value: unknown }>;
}

function boundedString(value: unknown, maximum = MAX_STRING): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new TypeError("bounded non-empty string required");
  }
  return value;
}

function callback<T extends (...args: never[]) => unknown>(value: unknown): T {
  if (typeof value !== "function" || utilTypes.isProxy(value)) {
    throw new TypeError("ordinary callback required");
  }
  return value as T;
}

function boundMethod<T extends (...args: never[]) => unknown>(value: unknown, name: string): T {
  if (value === null || typeof value !== "object" || utilTypes.isProxy(value)) {
    throw new TypeError("ordinary durable store required");
  }
  let owner: object | null = value;
  while (owner !== null) {
    if (utilTypes.isProxy(owner)) throw new TypeError("durable store prototype cannot be a proxy");
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new TypeError(`durable store ${name} must be a data method`);
      }
      return descriptor.value.bind(value) as T;
    }
    owner = Object.getPrototypeOf(owner) as object | null;
  }
  throw new TypeError(`durable store ${name} is required`);
}

function captureConfig(config: AgentPublicationAuthorizationAuthorityConfig): AuthorityRecord {
  const descriptors = exactDataDescriptors(config, [
    "authority_id",
    "trusted_now",
    "expected_issuer",
    "expected_audience",
    "jwks",
    "load_claim_view",
    "load_status",
    "consume_dpop",
    "read_mtls_peer_identity",
    "store",
    "sign_once",
  ], "agent publication authority configuration");
  const store = descriptors.store.value;
  return Object.freeze({
    authority_id: boundedString(descriptors.authority_id.value, 256),
    trusted_now: callback<AgentPublicationAuthorizationAuthorityConfig["trusted_now"]>(
      descriptors.trusted_now.value,
    ),
    expected_issuer: boundedString(descriptors.expected_issuer.value, 2_048),
    expected_audience: boundedString(descriptors.expected_audience.value, 2_048),
    jwks: captureAuthorityInput(descriptors.jwks.value) as JsonValue,
    load_claim_view: callback<AgentPublicationAuthorizationAuthorityConfig["load_claim_view"]>(
      descriptors.load_claim_view.value,
    ),
    load_status: callback<AgentPublicationAuthorizationAuthorityConfig["load_status"]>(
      descriptors.load_status.value,
    ),
    consume_dpop: callback<AgentPublicationAuthorizationAuthorityConfig["consume_dpop"]>(
      descriptors.consume_dpop.value,
    ),
    read_mtls_peer_identity: callback<
      AgentPublicationAuthorizationAuthorityConfig["read_mtls_peer_identity"]
    >(descriptors.read_mtls_peer_identity.value),
    store: Object.freeze({
      load: boundMethod<StoreCallbacks["load"]>(store, "load"),
      acquire: boundMethod<StoreCallbacks["acquire"]>(store, "acquire"),
      compareAndSwap: boundMethod<StoreCallbacks["compareAndSwap"]>(store, "compareAndSwap"),
      commit: boundMethod<StoreCallbacks["commit"]>(store, "commit"),
      markIndeterminate: boundMethod<StoreCallbacks["markIndeterminate"]>(store, "markIndeterminate"),
    }),
    sign_once: callback<AgentPublicationAuthorizationAuthorityConfig["sign_once"]>(
      descriptors.sign_once.value,
    ),
  });
}

export function createAgentPublicationAuthorizationAuthority(
  config: AgentPublicationAuthorizationAuthorityConfig,
): AgentPublicationAuthorizationAuthority {
  const record = captureConfig(config);
  const authority = Object.freeze({}) as AgentPublicationAuthorizationAuthority;
  AUTHORITIES.set(authority, record);
  return authority;
}

function captureRequest(value: unknown): AgentPublicationRequest | null {
  try {
    const request = captureAuthorityInput(value) as AgentPublicationRequest;
    const expected = [
      "compact_jwt",
      "represented_persona",
      "agent_id",
      "signer",
      "scope",
      "ledger_generation",
      "publication",
      "attribution_profile",
      "sender_proof",
    ];
    if (!exactKeys(request as unknown as Record<string, unknown>, expected)) return null;
    if (
      boundedString(request.compact_jwt, MAX_COMPACT) !== request.compact_jwt
      || boundedString(request.represented_persona, 64) !== request.represented_persona
      || boundedString(request.agent_id, 128) !== request.agent_id
      || boundedString(request.signer, 64) !== request.signer
      || boundedString(request.scope, 4_096) !== request.scope
      || !Number.isSafeInteger(request.ledger_generation)
      || request.ledger_generation < 0
      || request.attribution_profile !== "heterodyne-agent-v1"
      || !strictUnsignedEvent(request.publication)
      || !captureSenderProof(request.sender_proof)
    ) return null;
    return request;
  } catch {
    return null;
  }
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return keys.length === sorted.length && keys.every((key, index) => key === sorted[index]);
}

function captureSenderProof(value: AgentPublicationRequest["sender_proof"]): boolean {
  if (value.kind === "mtls") {
    return exactKeys(value as unknown as Record<string, unknown>, ["kind"]);
  }
  return value.kind === "dpop"
    && exactKeys(value as unknown as Record<string, unknown>, [
      "kind", "compact", "method", "target", "nonce",
    ])
    && value.compact.length > 0
    && value.compact.length <= MAX_COMPACT
    && value.method.length > 0
    && value.method.length <= 32
    && value.target.length > 0
    && value.target.length <= 2_048
    && value.nonce.length > 0
    && value.nonce.length <= MAX_STRING;
}

function strictUnsignedEvent(event: NostrUnsignedEvent): boolean {
  return exactKeys(event as unknown as Record<string, unknown>, [
    "pubkey", "created_at", "kind", "tags", "content",
  ])
    && LOWER_HEX_32.test(event.pubkey)
    && Number.isSafeInteger(event.created_at)
    && event.created_at >= 0
    && Number.isSafeInteger(event.kind)
    && event.kind >= 0
    && event.kind <= 65_535
    && typeof event.content === "string"
    && new TextEncoder().encode(event.content).length <= MAX_CONTENT_BYTES
    && Array.isArray(event.tags)
    && event.tags.length <= MAX_TAGS
    && event.tags.every((tag) => Array.isArray(tag)
      && tag.length > 0
      && tag.length <= MAX_TAG_MEMBERS
      && tag.every((member) => typeof member === "string" && member.length <= MAX_STRING));
}

function snapshotOpaqueArray<T>(value: unknown, maximum: number): readonly T[] {
  if (!Array.isArray(value) || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw new TypeError("ordinary dense array required");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  const length = lengthDescriptor !== undefined && "value" in lengthDescriptor
    ? lengthDescriptor.value
    : undefined;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximum
    || Reflect.ownKeys(descriptors).length !== length + 1) {
    throw new TypeError("bounded dense array required");
  }
  const result: T[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new TypeError("array members must be data properties");
    }
    result.push(descriptor.value as T);
  }
  return Object.freeze(result);
}

function captureClaimView(
  value: unknown,
  now: number,
  request: AgentPublicationRequest,
): CapturedClaimView {
  const descriptors = exactDataDescriptors(value, [
    "credential_ledger",
    "checkpoint_digest",
    "repository_revision",
    "claims",
    "revocations",
    "conflicted_claim_ids",
    "ledger_state",
  ], "current claim authorization view");
  const credential = captureAuthorityInput(descriptors.credential_ledger.value) as {
    credential_ledger_persona: string;
    credential_ledger_generation: number;
  };
  if (!exactKeys(credential, ["credential_ledger_persona", "credential_ledger_generation"])
    || !LOWER_HEX_32.test(credential.credential_ledger_persona)
    || !Number.isSafeInteger(credential.credential_ledger_generation)
    || credential.credential_ledger_generation < 0
    || typeof descriptors.checkpoint_digest.value !== "string"
    || !LOWER_HEX_32.test(descriptors.checkpoint_digest.value)
    || !Number.isSafeInteger(descriptors.repository_revision.value)
    || (descriptors.repository_revision.value as number) < 0) {
    throw new TypeError("invalid current claim authorization view");
  }
  const claims = snapshotOpaqueArray<VerifiedClaimArtifact>(descriptors.claims.value, 256);
  const revocations = snapshotOpaqueArray<VerifiedClaimRevocationArtifact>(
    descriptors.revocations.value,
    256,
  );
  const conflicts = captureAuthorityInput(descriptors.conflicted_claim_ids.value) as readonly string[];
  if (!Array.isArray(conflicts) || conflicts.length > 256
    || conflicts.some((claimId) => typeof claimId !== "string" || !LOWER_HEX_32.test(claimId))
    || new Set(conflicts).size !== conflicts.length) {
    throw new TypeError("invalid current claim conflicts");
  }
  const writerState = revalidateLedgerWriterAuthorities(
    descriptors.ledger_state.value as CurrentClaimAuthorizationView["ledger_state"],
  );
  if (writerState.verdict !== "accept") throw new TypeError("current writer authority invalid");

  const claimBindings = claims.map((artifact) => Object.freeze({
    semantic: inspectVerifiedClaim(artifact),
    binding: claimArtifactBindingDigest(artifact),
    artifact,
  }));
  if (new Set(claimBindings.map(({ semantic }) => semantic.claim_id)).size !== claimBindings.length) {
    throw new TypeError("duplicate current claim ID");
  }
  const revocationBindings = revocations.map((artifact) => {
    const inspected = inspectVerifiedClaimRevocation(artifact);
    return Object.freeze({
      binding: claimRevocationArtifactBindingDigest(artifact),
      claim_id: inspected.claim_id,
      revoked_at: inspected.revoked_at,
    });
  });
  if (new Set(revocationBindings.map(({ binding }) => binding)).size !== revocationBindings.length) {
    throw new TypeError("duplicate current revocation artifact");
  }

  const workloadCandidates = claimBindings.flatMap((candidate) => {
    const { semantic } = candidate;
    if (semantic.claim_class !== "authorization"
      || semantic.namespace !== "heterodyne.agent"
      || semantic.name !== "workload-registration"
      || semantic.visibility !== "repository-private"
      || semantic.credential_ledger_persona !== credential.credential_ledger_persona
      || semantic.credential_ledger_generation !== credential.credential_ledger_generation
      || semantic.not_before > now
      || (semantic.expires_at !== undefined && now >= semantic.expires_at)
      || conflicts.includes(semantic.claim_id)
      || revocationBindings.some((revocation) =>
        revocation.claim_id === semantic.claim_id && revocation.revoked_at <= now)) return [];
    try {
      const registration = validateWorkloadRegistration(semantic.value);
      return registration.persona_key === request.represented_persona
        && registration.client_id === request.agent_id
        ? [Object.freeze({ ...candidate, registration })]
        : [];
    } catch {
      return [];
    }
  });
  if (workloadCandidates.length !== 1) throw new TypeError("one current workload claim required");
  const workload = workloadCandidates[0]!;
  const registration = workload.registration;
  if (workload.semantic.subject.type !== "jwk-thumbprint"
    || workload.semantic.subject.value !== registration.subject_jkt) {
    throw new TypeError("workload subject binding invalid");
  }
  const fingerprint = authorityBindingDigest("heterodyne-current-agent-claim-view-v1", {
    credential_ledger: credential,
    checkpoint_digest: descriptors.checkpoint_digest.value,
    repository_revision: descriptors.repository_revision.value,
    claims: claimBindings.map(({ semantic, binding }) => [semantic.claim_id, binding])
      .sort(([left], [right]) => String(left).localeCompare(String(right))),
    revocations: revocationBindings.map(({ binding }) => binding).sort(),
    conflicted_claim_ids: [...conflicts].sort(),
    writer_fingerprints: [...writerState.writer_fingerprints],
  });
  return Object.freeze({
    credential_ledger: Object.freeze({ ...credential }),
    checkpoint_digest: descriptors.checkpoint_digest.value,
    repository_revision: descriptors.repository_revision.value as number,
    fingerprint,
    workload_artifact: workload.artifact,
    workload_binding: workload.binding,
    workload_claim_id: workload.semantic.claim_id,
    registration,
  });
}

function captureStatus(value: unknown): CapturedStatus {
  const captured = captureAuthorityInput(value) as {
    generation: number;
    state: "active" | "revoked";
    checkpoint: string;
  };
  if (!exactKeys(captured, ["generation", "state", "checkpoint"])
    || !Number.isSafeInteger(captured.generation)
    || captured.generation < 0
    || (captured.state !== "active" && captured.state !== "revoked")
    || !LOWER_HEX_32.test(captured.checkpoint)) {
    throw new TypeError("invalid workload token status");
  }
  return Object.freeze({
    ...captured,
    fingerprint: authorityBindingDigest("heterodyne-agent-token-status-v1", captured),
  });
}

function parseJwtClaims(compact: string): Record<string, JsonValue> {
  const segments = compact.split(".");
  if (segments.length !== 3) throw new TypeError("compact JWT required");
  const decoded = Buffer.from(segments[1]!, "base64url");
  if (decoded.toString("base64url") !== segments[1]) throw new TypeError("canonical JWT required");
  const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decoded));
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("JWT claims object required");
  }
  return parsed as Record<string, JsonValue>;
}

function association(value: JsonValue | undefined): AgentAssociation | null {
  if (value === undefined) return null;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("invalid agent association claim");
  }
  const captured = captureAuthorityInput(value) as unknown as AgentAssociation;
  if (!exactKeys(captured as unknown as Record<string, unknown>, ["kind", "value"])
    || (captured.kind !== "key" && captured.kind !== "role")
    || typeof captured.value !== "string"
    || captured.value.length === 0
    || captured.value.length > 128
    || (captured.kind === "key" && !LOWER_HEX_32.test(captured.value))) {
    throw new TypeError("invalid agent association claim");
  }
  return captured;
}

function verifyToken(
  authority: AuthorityRecord,
  request: AgentPublicationRequest,
  view: CapturedClaimView,
  now: number,
): VerifiedToken {
  const untrusted = parseJwtClaims(request.compact_jwt);
  const confirmation = untrusted.cnf;
  if (confirmation === null || typeof confirmation !== "object" || Array.isArray(confirmation)) {
    throw new TypeError("sender-constrained token required");
  }
  const capturedConfirmation = captureAuthorityInput(confirmation) as Record<string, JsonValue>;
  const senderKind = request.sender_proof.kind;
  const senderKey = senderKind === "dpop"
    ? capturedConfirmation.jkt
    : capturedConfirmation["x5t#S256"];
  if (typeof senderKey !== "string" || !SHA256_BASE64URL.test(senderKey)) {
    throw new TypeError("sender key binding invalid");
  }
  const context = createValidatedProjectedJwtContext(
    request.compact_jwt,
    authority.expected_issuer,
    authority.expected_audience,
    authority.jwks,
    {
      now,
      token_use: "access_token",
      client_id: request.agent_id,
      cnf: capturedConfirmation,
      sender_constraint: senderKind,
      permitted_audiences: [authority.expected_audience],
      credential_ledger: view.credential_ledger,
    },
  );
  assertValidatedProjectedJwtContext(context);
  const claims = context.claims;
  const audiences = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
  const signer = claims[SELECTED_SIGNER_CLAIM];
  const signerClass = claims[SIGNER_CLASS_CLAIM];
  const tokenAssociation = association(claims[ASSOCIATION_CLAIM]);
  if (
    claims.iss !== authority.expected_issuer
    || !Array.isArray(audiences)
    || audiences.length !== 1
    || audiences[0] !== authority.expected_audience
    || typeof claims.sub !== "string"
    || !SHA256_BASE64URL.test(claims.sub)
    || claims.client_id !== request.agent_id
    || claims.credential_ledger_persona !== request.represented_persona
    || claims.credential_ledger_generation !== request.ledger_generation
    || claims.scope !== request.scope
    || typeof claims.iat !== "number"
    || typeof claims.exp !== "number"
    || !Number.isSafeInteger(claims.iat)
    || !Number.isSafeInteger(claims.exp)
    || claims.exp <= claims.iat
    || claims.exp - claims.iat > 300
    || typeof claims.jti !== "string"
    || claims.jti.length < 16
    || claims.jti.length > 128
    || typeof signer !== "string"
    || !LOWER_HEX_32.test(signer)
    || (signerClass !== "agent" && signerClass !== "persona")
  ) throw new TypeError("workload token binding invalid");
  return Object.freeze({
    compact_digest: sha256String(request.compact_jwt),
    issuer: claims.iss,
    audience: audiences[0] as string,
    subject: claims.sub,
    agent_id: claims.client_id,
    persona: claims.credential_ledger_persona,
    signer,
    signer_key_class: signerClass,
    association: tokenAssociation,
    scope: claims.scope,
    issued_at: claims.iat,
    expires_at: claims.exp,
    token_id: claims.jti,
    generation: claims.credential_ledger_generation,
    sender_key: senderKey,
    sender_kind: senderKind,
  });
}

function sameAssociation(left: AgentAssociation | null | undefined, right: AgentAssociation | null): boolean {
  return (left ?? null) === null && right === null
    || left !== null && left !== undefined && right !== null
      && left.kind === right.kind && left.value === right.value;
}

function attributedEvent(
  request: AgentPublicationRequest,
  view: CapturedClaimView,
  token: VerifiedToken,
  now: number,
): NostrUnsignedEvent {
  const registration = view.registration;
  const normalizedScopes = [...registration.scopes].sort().join(" ");
  if (
    request.publication.pubkey !== request.signer
    || token.signer !== request.signer
    || registration.selected_signer !== request.signer
    || registration.persona_key !== request.represented_persona
    || registration.client_id !== request.agent_id
    || registration.audience !== token.audience
    || registration.subject_jkt !== token.sender_key
    || registration.signer_key_class !== token.signer_key_class
    || !sameAssociation(registration.agent_association, token.association)
  ) throw SIGNER_REJECT;
  if (
    request.scope !== normalizedScopes
    || !registration.scopes.includes("heterodyne:agent:publish")
    || request.attribution_profile !== "heterodyne-agent-v1"
    || now < registration.not_before
    || now >= registration.expires_at
    || request.publication.created_at < registration.not_before
    || request.publication.created_at < token.issued_at
    || request.publication.created_at >= token.expires_at
    || request.publication.created_at > now
    || !registration.allowed_kinds.includes(request.publication.kind)
    || new TextEncoder().encode(request.publication.content).length > registration.max_content_bytes
    || (registration.signer_key_class === "persona"
      && !registration.scopes.includes("heterodyne:agent:sign:persona"))
  ) throw new TypeError("publication is outside workload authority");
  const attributed = injectAgentAttribution({
    kind: request.publication.kind,
    tags: request.publication.tags.map((tag) => [...tag]),
    agent_class: registration.agent_class,
    persona: request.represented_persona,
    signer: request.signer,
    expected_signer: token.signer,
    signer_key_class: token.signer_key_class,
    oidc_scopes: registration.scopes,
    agent_association: registration.agent_association,
    expected_agent_association: token.association ?? undefined,
    tier: 1,
  });
  if (attributed.verdict !== "accept") {
    throw attributed.reason_code === "agent-signer-mismatch" ? SIGNER_REJECT
      : new TypeError("agent attribution invalid");
  }
  if (attributed.author !== request.signer) throw SIGNER_REJECT;
  return captureAuthorityInput({
    pubkey: request.signer,
    created_at: request.publication.created_at,
    kind: request.publication.kind,
    tags: attributed.tags,
    content: request.publication.content,
  }) as NostrUnsignedEvent;
}

function proofDigest(request: AgentPublicationRequest): string {
  return request.sender_proof.kind === "dpop"
    ? sha256String(request.sender_proof.compact)
    : authorityBindingDigest("heterodyne-agent-mtls-proof-v1", {
      compact_jwt: sha256String(request.compact_jwt),
      publication: request.publication,
    });
}

function durableRequest(
  authority: AuthorityRecord,
  request: AgentPublicationRequest,
  view: CapturedClaimView,
  status: CapturedStatus,
  token: VerifiedToken,
  event: NostrUnsignedEvent,
): Omit<PreparedAuthorization, "now"> {
  const digest = proofDigest(request);
  const proofKey = request.sender_proof.kind === "dpop"
    ? digest
    : authorityBindingDigest("heterodyne-agent-mtls-operation-v1", {
      token_id: token.token_id,
      proof_digest: digest,
    });
  const durableKey = authorityBindingDigest("heterodyne-agent-publication-key-v1", {
    authority_id: authority.authority_id,
    sender_kind: request.sender_proof.kind,
    proof_key: proofKey,
  });
  const bindingDigest = authorityBindingDigest("heterodyne-agent-publication-binding-v1", {
    authority_id: authority.authority_id,
    durable_key: durableKey,
    compact_jwt_digest: token.compact_digest,
    token,
    proof: request.sender_proof,
    proof_digest: digest,
    claim_view_fingerprint: view.fingerprint,
    workload_artifact_binding: view.workload_binding,
    workload_claim_id: view.workload_claim_id,
    status_fingerprint: status.fingerprint,
    represented_persona: request.represented_persona,
    agent_id: request.agent_id,
    signer: request.signer,
    scope: request.scope,
    ledger_generation: request.ledger_generation,
    publication: request.publication,
    attributed_event: event,
    attribution_profile: request.attribution_profile,
  });
  return Object.freeze({
    view,
    status,
    token,
    attributed_event: event,
    proof_digest: digest,
    proof_key: proofKey,
    durable_key: durableKey,
    binding_digest: bindingDigest,
    reconciliation_digest: authorityBindingDigest(
      "heterodyne-agent-publication-reconciliation-v1",
      { durable_key: durableKey, binding_digest: bindingDigest },
    ),
  });
}

async function prepare(
  authority: AuthorityRecord,
  request: AgentPublicationRequest,
): Promise<PreparedAuthorization> {
  const now = authority.trusted_now();
  if (!Number.isSafeInteger(now) || now < 0) throw new TypeError("trusted time invalid");
  const view = captureClaimView(await authority.load_claim_view(), now, request);
  const token = verifyToken(authority, request, view, now);
  const status = captureStatus(await authority.load_status(token.subject));
  if (
    status.state !== "active"
    || status.generation !== request.ledger_generation
    || status.generation !== view.credential_ledger.credential_ledger_generation
    || status.checkpoint !== view.checkpoint_digest
    || token.persona !== view.credential_ledger.credential_ledger_persona
    || token.generation !== view.credential_ledger.credential_ledger_generation
  ) throw new TypeError("current workload token status invalid");
  const event = attributedEvent(request, view, token, now);
  return Object.freeze({ now, ...durableRequest(authority, request, view, status, token, event) });
}

function samePreparation(left: PreparedAuthorization, right: PreparedAuthorization): boolean {
  return left.view.fingerprint === right.view.fingerprint
    && left.status.fingerprint === right.status.fingerprint
    && left.binding_digest === right.binding_digest
    && left.durable_key === right.durable_key
    && left.token.compact_digest === right.token.compact_digest
    && left.now <= right.now;
}

async function verifySenderProof(
  authority: AuthorityRecord,
  request: AgentPublicationRequest,
  prepared: PreparedAuthorization,
): Promise<boolean> {
  if (request.sender_proof.kind === "mtls") {
    let identity: unknown;
    try {
      identity = authority.read_mtls_peer_identity();
    } catch {
      return false;
    }
    return identity === prepared.token.sender_key && SHA256_BASE64URL.test(identity);
  }
  try {
    const proof = await authority.consume_dpop(Object.freeze({
      compact: request.sender_proof.compact,
      method: request.sender_proof.method,
      target: request.sender_proof.target,
      nonce: request.sender_proof.nonce,
    }));
    if (proof === null) return false;
    const captured = captureAuthorityInput(proof) as {
      proof_digest: string;
      sender_key: string;
    };
    return exactKeys(captured, ["proof_digest", "sender_key"])
      && captured.proof_digest === prepared.proof_digest
      && captured.sender_key === prepared.token.sender_key
      && LOWER_HEX_32.test(captured.proof_digest)
      && SHA256_BASE64URL.test(captured.sender_key);
  } catch {
    return false;
  }
}

function mintInternalAuthorization(
  authority: AgentPublicationAuthorizationAuthority,
  prepared: PreparedAuthorization,
): VerifiedAgentPublicationAuthorization {
  const handle = Object.freeze({}) as VerifiedAgentPublicationAuthorization;
  INTERNAL_AUTHORIZATIONS.set(handle, Object.freeze({ authority, prepared, consumed: false }));
  return handle;
}

function consumeInternalAuthorization(
  authority: AgentPublicationAuthorizationAuthority,
  handle: VerifiedAgentPublicationAuthorization,
  bindingDigest: string,
): PreparedAuthorization | null {
  const record = INTERNAL_AUTHORIZATIONS.get(handle);
  if (record === undefined || record.authority !== authority || record.consumed
    || record.prepared.binding_digest !== bindingDigest) return null;
  INTERNAL_AUTHORIZATIONS.delete(handle);
  return record.prepared;
}

function discardInternalAuthorization(handle: VerifiedAgentPublicationAuthorization): void {
  INTERNAL_AUTHORIZATIONS.delete(handle);
}

function sha256String(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function outputDigest(value: NostrSignedEvent): string {
  return authorityBindingDigest("heterodyne-agent-publication-output-v1", value);
}

function captureDurableRecord(
  value: unknown,
): DurableAuthorityRecord<NostrSignedEvent> | null {
  try {
    const captured = captureAuthorityInput(value) as DurableAuthorityRecord<NostrSignedEvent>;
    if (!Number.isSafeInteger(captured.revision) || captured.revision < 0
      || !LOWER_HEX_32.test(captured.binding_digest)) return null;
    if (captured.state === "executing") {
      return exactKeys(captured as unknown as Record<string, unknown>, [
        "state", "revision", "binding_digest", "execution_token",
      ]) && LOWER_HEX_32.test(captured.execution_token) ? captured : null;
    }
    if (captured.state === "indeterminate") {
      return exactKeys(captured as unknown as Record<string, unknown>, [
        "state", "revision", "binding_digest", "execution_token", "reconciliation_digest",
      ]) && LOWER_HEX_32.test(captured.execution_token)
        && LOWER_HEX_32.test(captured.reconciliation_digest) ? captured : null;
    }
    if (captured.state === "committed") {
      const event = snapshotAndVerifyAgentPublication(captured.output);
      return exactKeys(captured as unknown as Record<string, unknown>, [
        "state", "revision", "binding_digest", "execution_token", "output_digest", "output",
      ]) && LOWER_HEX_32.test(captured.execution_token)
        && LOWER_HEX_32.test(captured.output_digest)
        && event !== null
        && outputDigest(event) === captured.output_digest
        ? Object.freeze({ ...captured, output: event })
        : null;
    }
    if (captured.state === "available") {
      const event = snapshotAndVerifyAgentPublication(captured.output);
      return exactKeys(captured as unknown as Record<string, unknown>, [
        "state", "revision", "binding_digest", "output",
      ]) && event !== null ? Object.freeze({ ...captured, output: event }) : null;
    }
    return null;
  } catch {
    return null;
  }
}

async function loadRecord(
  store: StoreCallbacks,
  key: string,
): Promise<DurableAuthorityRecord<NostrSignedEvent> | null | undefined> {
  try {
    const raw = await store.load(key);
    return raw === null ? null : captureDurableRecord(raw) ?? undefined;
  } catch {
    return undefined;
  }
}

function indeterminate(reconciliationDigest: string): AgentPublicationDecision {
  return Object.freeze({ verdict: "indeterminate" as const, reconciliation_digest: reconciliationDigest });
}

function cachedDecision(
  record: DurableAuthorityRecord<NostrSignedEvent>,
  prepared: PreparedAuthorization,
): AgentPublicationDecision | null {
  if (record.binding_digest !== prepared.binding_digest) return PROOF_REJECT;
  if (record.state === "committed") {
    const event = snapshotAndVerifyAgentPublication(record.output, prepared.attributed_event);
    if (event === null || record.output_digest !== outputDigest(event)
    ) return null;
    return Object.freeze({ verdict: "accept" as const, output: event });
  }
  if (record.state === "indeterminate") return indeterminate(record.reconciliation_digest);
  if (record.state === "executing") return indeterminate(prepared.reconciliation_digest);
  return null;
}

async function markIndeterminate(
  authority: AuthorityRecord,
  prepared: PreparedAuthorization,
  executionToken: string,
): Promise<AgentPublicationDecision> {
  try {
    await authority.store.markIndeterminate(Object.freeze({
      key: prepared.durable_key,
      binding_digest: prepared.binding_digest,
      execution_token: executionToken,
      reconciliation_digest: prepared.reconciliation_digest,
    }));
    const loaded = await loadRecord(authority.store, prepared.durable_key);
    if (loaded?.state === "indeterminate"
      && loaded.binding_digest === prepared.binding_digest
      && loaded.execution_token === executionToken) {
      return indeterminate(loaded.reconciliation_digest);
    }
  } catch {
    // The deterministic local digest remains the only safe terminal result.
  }
  return indeterminate(prepared.reconciliation_digest);
}

function failureReason(error: unknown): AgentPublicationDecision {
  return error === SIGNER_REJECT ? SIGNER_REJECT : PROOF_REJECT;
}

export async function authorizeAndSignAgentPublication(
  authority: AgentPublicationAuthorizationAuthority,
  request: AgentPublicationRequest,
): Promise<AgentPublicationDecision> {
  const authorityRecord = AUTHORITIES.get(authority);
  if (authorityRecord === undefined) return PROOF_REJECT;
  const captured = captureRequest(request);
  if (captured === null) return PROOF_REJECT;
  if (captured.publication.pubkey !== captured.signer || !LOWER_HEX_32.test(captured.signer)) {
    return SIGNER_REJECT;
  }

  let prepared: PreparedAuthorization;
  try {
    prepared = await prepare(authorityRecord, captured);
  } catch (error) {
    return failureReason(error);
  }

  if (captured.sender_proof.kind === "mtls"
    && !await verifySenderProof(authorityRecord, captured, prepared)) return PROOF_REJECT;

  let loaded = await loadRecord(authorityRecord.store, prepared.durable_key);
  if (loaded === undefined) return indeterminate(prepared.reconciliation_digest);
  if (loaded !== null) {
    return cachedDecision(loaded, prepared) ?? indeterminate(prepared.reconciliation_digest);
  }

  if (captured.sender_proof.kind === "dpop"
    && !await verifySenderProof(authorityRecord, captured, prepared)) return PROOF_REJECT;

  let current: PreparedAuthorization;
  try {
    current = await prepare(authorityRecord, captured);
  } catch (error) {
    return failureReason(error);
  }
  if (!samePreparation(prepared, current)) return PROOF_REJECT;
  prepared = current;

  const authorization = mintInternalAuthorization(authority, prepared);
  const executionToken = randomBytes(32).toString("hex");
  let acquired: "acquired" | "replay" | "conflict" | "unavailable";
  try {
    acquired = await authorityRecord.store.acquire(Object.freeze({
      key: prepared.durable_key,
      expected_revision: null,
      binding_digest: prepared.binding_digest,
      execution_token: executionToken,
    }));
  } catch {
    discardInternalAuthorization(authorization);
    return indeterminate(prepared.reconciliation_digest);
  }
  if (acquired !== "acquired") {
    discardInternalAuthorization(authorization);
    loaded = await loadRecord(authorityRecord.store, prepared.durable_key);
    if (loaded === undefined || loaded === null) return indeterminate(prepared.reconciliation_digest);
    return cachedDecision(loaded, prepared) ?? indeterminate(prepared.reconciliation_digest);
  }

  const executing = await loadRecord(authorityRecord.store, prepared.durable_key);
  if (executing?.state !== "executing"
    || executing.binding_digest !== prepared.binding_digest
    || executing.execution_token !== executionToken) {
    discardInternalAuthorization(authorization);
    return markIndeterminate(authorityRecord, prepared, executionToken);
  }
  const authorized = consumeInternalAuthorization(authority, authorization, prepared.binding_digest);
  if (authorized === null) return markIndeterminate(authorityRecord, prepared, executionToken);

  let signed: NostrSignedEvent | null;
  try {
    const raw = await authorityRecord.sign_once(executionToken, authorized.attributed_event);
    signed = snapshotAndVerifyAgentPublication(raw, authorized.attributed_event);
  } catch {
    signed = null;
  }
  if (signed === null) {
    return markIndeterminate(authorityRecord, prepared, executionToken);
  }

  const digest = outputDigest(signed);
  let committed: "committed" | "conflict" | "unknown";
  try {
    committed = await authorityRecord.store.commit(Object.freeze({
      key: prepared.durable_key,
      binding_digest: prepared.binding_digest,
      execution_token: executionToken,
      output_digest: digest,
      output: signed,
    }));
  } catch {
    committed = "unknown";
  }
  if (committed !== "committed") {
    if (committed === "conflict") {
      loaded = await loadRecord(authorityRecord.store, prepared.durable_key);
      const raced = loaded === undefined || loaded === null ? null : cachedDecision(loaded, prepared);
      if (raced?.verdict === "accept" && jcsCanonicalize(raced.output) === jcsCanonicalize(signed)) {
        return raced;
      }
    }
    return markIndeterminate(authorityRecord, prepared, executionToken);
  }

  const terminal = await loadRecord(authorityRecord.store, prepared.durable_key);
  if (terminal?.state !== "committed"
    || terminal.binding_digest !== prepared.binding_digest
    || terminal.execution_token !== executionToken
    || terminal.output_digest !== digest) {
    return markIndeterminate(authorityRecord, prepared, executionToken);
  }
  const decision = cachedDecision(terminal, prepared);
  return decision?.verdict === "accept"
    ? decision
    : markIndeterminate(authorityRecord, prepared, executionToken);
}
