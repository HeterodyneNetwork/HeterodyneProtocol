import { Ajv2020 } from "ajv/dist/2020.js";
import workloadRegistrationSchema from "../../../schemas/comms/agent-workload-registration-v1.schema.json" with { type: "json" };
import { derivePairwiseSubject } from "./oidc.js";
import { evaluateCredentialGeneration } from "./credential-generation.js";
import {
  getEventId,
  isStrictNostrSignedEvent,
  type NostrSignedEvent,
  type NostrUnsignedEvent,
} from "./nostr.js";

// Compatibility exports for the explicitly frozen pre-redesign vector topic.
export {
  legacyAgentBindingMessage as agentBindingMessage,
  validateLegacyAgentDelegation as validateAgentDelegation,
} from "./legacy-agent-delegation.js";
export type {
  LegacyAgentDelegationInput as AgentDelegationInput,
  LegacyAgentDelegationResult as AgentDelegationResult,
} from "./legacy-agent-delegation.js";

export type WorkloadRegistration = {
  /** Optional in this source type only so the frozen pre-redesign topic source still compiles. */
  persona_key?: string;
  client_id: string;
  subject_jkt: string;
  subject_proof?: {
    method: "dpop";
    jkt: string;
  };
  agent_class: "ai" | "programmatic";
  selected_signer?: string;
  signer_key_class?: "agent" | "persona";
  agent_association?: AgentAssociation;
  /** Retained only as a compile-time bridge for the frozen pre-redesign topic source. */
  role_id?: string;
  audience: string;
  scopes: string[];
  allowed_kinds: number[];
  allowed_feeds: string[];
  allowed_resources: string[];
  max_content_bytes: number;
  rate_limit: {
    window_seconds: number;
    count: number;
    burst: number;
  };
  not_before: number;
  expires_at: number;
  software_claim_ref?: string;
};

export type AgentAssociation = {
  kind: "key" | "role";
  value: string;
};

declare const commsSocialPublicationAuthorityBrand: unique symbol;
export type CommsSocialPublicationAuthority = {
  readonly [commsSocialPublicationAuthorityBrand]: true;
};

declare const commsSocialSignedPublicationBrand: unique symbol;
export type CommsSocialSignedPublication = {
  readonly [commsSocialSignedPublicationBrand]: true;
};

export type CommsSocialSignerExecutionOutcome =
  | { verdict: "accept"; disposition: "executed" | "cached"; event: NostrSignedEvent }
  | { verdict: "indeterminate" | "reconciliation" | "conflict" };

export interface CommsSocialSignerExecutionCapability {
  executeOnce(
    executionToken: string,
    unsignedEvent: NostrUnsignedEvent,
    requestDigest: string,
  ): CommsSocialSignerExecutionOutcome;
}

export type AgentTokenValidationInput = {
  typ: string;
  credential_ledger_persona: string;
  credential_ledger_generation: number;
  expected_credential_ledger_persona: string;
  expected_credential_ledger_generation: number;
  iss: string;
  sub: string;
  aud: string[];
  exp: number;
  iat: number;
  jti: string;
  client_id: string;
  scope: string;
  cnf_jkt: string;
  sender_proof_jkt: string;
  sender_proof_valid: boolean;
  /** Frozen topic compile bridge; current validation rejects this member. */
  agent_role_id?: string;
  signer_key?: string;
  signer_key_class?: "agent" | "persona";
  agent_association?: unknown;
  expected_issuer: string;
  expected_subject: string;
  expected_audience: string;
  expected_client_id: string;
  expected_scope: string;
  /** Frozen topic compile bridge; current validation rejects this member. */
  expected_role_id?: string;
  expected_signer_key?: string;
  expected_signer_key_class?: "agent" | "persona";
  expected_agent_association?: unknown;
  now: number;
  status: "VALID" | "INVALID" | "SUSPENDED";
  ledger_active: boolean;
  ledger_binding_valid: boolean;
  status_binding_valid: boolean;
  session_expires_at: number;
  delegation_expires_at: number;
  registration_expires_at: number;
  consent_expires_at: number;
  source_authorization_expires_at: number;
};

export type AgentTokenDecision =
  | {
      verdict: "accept";
      identity: {
        issuer: string;
        sub: string;
        client_id: string;
        signer: string;
        key_class: "agent" | "persona";
        agent_association?: AgentAssociation;
      };
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

export type AgentPublicationInput = {
  kind: number;
  tags: string[][];
  agent_class: "ai" | "programmatic";
  persona?: string;
  issuer?: string;
  subject?: string;
  client_id?: string;
  /** Frozen topic compile bridge; current validation rejects this member. */
  role_id?: string;
  signer: string;
  expected_signer?: string;
  /** Frozen topic compile bridge; current validation rejects this member. */
  current_role_key?: string;
  signer_key_class?: "agent" | "persona";
  oidc_scopes?: string[];
  agent_association?: unknown;
  expected_agent_association?: unknown;
  tier: 1 | 2 | 3;
  agent_review?: string;
  agent_review_verified?: boolean;
};

export type AgentPublicationResult =
  | {
      verdict: "accept";
      tags: string[][];
      placement: "public" | "private-repository" | "encrypted-inner";
      author: string;
      clear_outer_tags?: string[][];
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

const ajv = new Ajv2020({ allErrors: true, strict: false });
const validateRegistration = ajv.compile<WorkloadRegistration>(
  workloadRegistrationSchema,
);
const AGENT_KINDS = new Set([1, 6, 7, 16, 1063, 1985, 4550, 30023]);
const SOCIAL_PUBLICATION_AUTHORITIES = new WeakMap<object, {
  trusted_now: () => number;
  execute_once: CommsSocialSignerExecutionCapability["executeOnce"];
}>();
const SOCIAL_SIGNED_PUBLICATIONS = new WeakMap<object, {
  authority: CommsSocialPublicationAuthority;
  represented_persona: string;
  event_id: string;
  signer: string;
  kind: number;
  created_at: number;
  agent_association: AgentAssociation | null;
  requested_feed: string;
  requested_resource: string;
}>();
const LEGACY_DELEGATION_MEMBERS = new Set([
  "agent_role_id",
  "expected_role_id",
  "role_id",
  "current_role_key",
  "proof_bytes",
  "outer_epoch_signature_valid",
  "nid_proof_valid",
  "key_proof_valid",
  "kel_authority_current",
]);

export function validateWorkloadRegistration(
  value: unknown,
): WorkloadRegistration {
  if (!validateRegistration(value)) {
    throw new Error("agent-workload-registration-invalid");
  }
  const registration = value as WorkloadRegistration;
  if (
    registration.expires_at <= registration.not_before
    || registration.rate_limit.burst > registration.rate_limit.count
    || registration.subject_proof?.jkt !== registration.subject_jkt
    || registration.subject_proof?.method !== "dpop"
  ) {
    throw new Error("agent-workload-registration-invalid");
  }
  if (!/^[0-9a-f]{64}$/.test(registration.selected_signer ?? "")) {
    throw new Error("agent-workload-registration-invalid");
  }
  if (
    registration.signer_key_class === "persona"
    && (
      registration.selected_signer !== registration.persona_key
      || !registration.scopes.includes("heterodyne:agent:sign:persona")
    )
  ) {
    throw new Error("agent-workload-registration-invalid");
  }
  return registration;
}

export function deriveAgentIdentity(
  localSubject: string,
  sectorIdentifier: string,
  pairwiseSecretHex: string,
  issuer: string,
  clientId: string,
): { issuer: string; sub: string; client_id: string } {
  const parsedIssuer = new URL(issuer);
  if (
    parsedIssuer.protocol !== "https:"
    || parsedIssuer.username !== ""
    || parsedIssuer.password !== ""
    || parsedIssuer.search !== ""
    || parsedIssuer.hash !== ""
    || clientId.length === 0
  ) {
    throw new Error("agent-workload-registration-invalid");
  }
  return {
    issuer,
    sub: derivePairwiseSubject(localSubject, sectorIdentifier, pairwiseSecretHex),
    client_id: clientId,
  };
}

export function validateAgentAccessToken(
  input: AgentTokenValidationInput,
): AgentTokenDecision {
  const captured = snapshotAgentTokenValidationInput(input);
  if (captured === null) return denied("agent-token-invalid");
  return validateAgentAccessTokenSnapshot(captured);
}

function validateAgentAccessTokenSnapshot(
  input: AgentTokenValidationInput,
): AgentTokenDecision {
  if (hasAnyMember(input, LEGACY_DELEGATION_MEMBERS)) {
    return denied("agent-token-invalid");
  }
  if (!Object.prototype.hasOwnProperty.call(input, "credential_ledger_generation")) {
    return denied("credential_generation_missing");
  }
  if (
    input.typ !== "at+jwt"
    || input.iss !== input.expected_issuer
    || input.sub !== input.expected_subject
    || input.client_id !== input.expected_client_id
    || input.jti.length === 0
    || !Number.isSafeInteger(input.iat)
    || !Number.isSafeInteger(input.exp)
    || input.exp <= input.iat
    || input.exp - input.iat > 300
    || input.exp > Math.min(
      input.session_expires_at,
      input.delegation_expires_at,
      input.registration_expires_at,
      input.consent_expires_at,
      input.source_authorization_expires_at,
    )
  ) {
    return denied("agent-token-invalid");
  }
  if (input.now >= input.exp) return denied("agent-token-invalid");
  if (input.status !== "VALID") return denied("agent-token-invalid");
  if (input.aud.length !== 1 || input.aud[0] !== input.expected_audience) {
    return denied("agent-token-invalid");
  }
  if (
    input.scope.trim().split(/\s+/).join(" ") !== input.expected_scope
    || input.scope !== input.expected_scope
  ) {
    return denied("agent-token-invalid");
  }
  if (
    !input.sender_proof_valid
    || input.sender_proof_jkt !== input.cnf_jkt
    || !/^[A-Za-z0-9_-]{43}$/.test(input.cnf_jkt)
  ) {
    return denied("agent-sender-proof-invalid");
  }
  const generation = evaluateCredentialGeneration(input, {
    credential_ledger_persona: input.expected_credential_ledger_persona,
    credential_ledger_generation: input.expected_credential_ledger_generation,
  });
  if (!generation.valid) {
    return denied(generation.reason_code === "credential_schema_invalid"
      ? "agent-token-invalid"
      : generation.reason_code);
  }
  if (
    input.signer_key !== input.expected_signer_key
    || input.signer_key_class !== input.expected_signer_key_class
    || !/^[0-9a-f]{64}$/.test(input.signer_key ?? "")
  ) {
    return denied("agent-signer-mismatch");
  }
  const signerKey = input.signer_key as string;
  const signerKeyClass = input.signer_key_class as "agent" | "persona";
  if (
    input.signer_key_class === "persona"
    && !input.scope.split(" ").includes("heterodyne:agent:sign:persona")
  ) {
    return denied("agent-persona-scope-required");
  }
  if (!equalAssociation(input.agent_association, input.expected_agent_association)) {
    return denied("agent-signer-mismatch");
  }
  const agentAssociation = input.agent_association === undefined
    ? undefined
    : isAgentAssociation(input.agent_association)
      ? input.agent_association
      : undefined;
  if (
    !input.ledger_active
    || !input.ledger_binding_valid
    || !input.status_binding_valid
  ) {
    return denied("agent-token-invalid");
  }
  return {
    verdict: "accept",
    identity: {
      issuer: input.iss,
      sub: input.sub,
      client_id: input.client_id,
      signer: signerKey,
      key_class: signerKeyClass,
      ...(agentAssociation === undefined
        ? {}
        : { agent_association: agentAssociation }),
    },
  };
}

export function injectAgentAttribution(
  input: AgentPublicationInput,
): AgentPublicationResult {
  if (!AGENT_KINDS.has(input.kind)) {
    return denied("agent-attribution-profile-unavailable");
  }
  if (
    Object.prototype.hasOwnProperty.call(input, "id")
    || Object.prototype.hasOwnProperty.call(input, "sig")
    || hasAnyMember(input, LEGACY_DELEGATION_MEMBERS)
  ) {
    return denied("agent-attribution-invalid");
  }
  if (!/^[0-9a-f]{64}$/.test(input.persona ?? "")) {
    return denied("agent-signer-mismatch");
  }
  if (
    input.signer !== input.expected_signer
    || !/^[0-9a-f]{64}$/.test(input.signer)
  ) {
    return denied("agent-signer-mismatch");
  }
  if (input.signer_key_class === "agent") {
    // The exact signer was already compared with verified token identity.
  } else if (input.signer_key_class === "persona") {
    if (input.signer !== input.persona) return denied("agent-signer-mismatch");
    if (!input.oidc_scopes?.includes("heterodyne:agent:sign:persona")) {
      return denied("agent-persona-scope-required");
    }
  } else {
    return denied("agent-signer-mismatch");
  }
  if (
    !["ai", "programmatic"].includes(input.agent_class)
  ) {
    return denied("agent-attribution-invalid");
  }

  if (!equalAssociation(
    input.agent_association,
    input.expected_agent_association,
  )) {
    return denied("agent-signer-mismatch");
  }

  const association = agentAssociationTag(input.agent_association);
  if (association === null) return denied("agent-attribution-invalid");

  const preserved = input.tags.filter((tag) => !isReservedAttributionTag(tag));
  const tags = [
    ...preserved,
    ["L", "network.heterodyne.agent"],
    ["l", input.agent_class, "network.heterodyne.agent"],
    ...(association === undefined ? [] : [association]),
    ["agent_action", "publish"],
    ...(input.agent_review !== undefined && input.agent_review_verified === true
      ? [["agent_review", input.agent_review]]
      : []),
  ];
  if (input.tier === 3) {
    return {
      verdict: "accept",
      tags,
      placement: "encrypted-inner",
      author: input.signer,
      clear_outer_tags: [],
    };
  }
  return {
    verdict: "accept",
    tags,
    placement: input.tier === 1 ? "public" : "private-repository",
    author: input.signer,
  };
}

export function createCommsSocialPublicationAuthority(input: {
  trusted_now: () => number;
  signer_execution: CommsSocialSignerExecutionCapability;
}): CommsSocialPublicationAuthority {
  const authority = Object.freeze({}) as CommsSocialPublicationAuthority;
  const trustedNow = input.trusted_now;
  const executeOnce = input.signer_execution.executeOnce.bind(input.signer_execution);
  SOCIAL_PUBLICATION_AUTHORITIES.set(authority, {
    trusted_now: trustedNow,
    execute_once: executeOnce,
  });
  return authority;
}

export function signCommsSocialPublication(input: {
  authority: unknown;
  registration: unknown;
  token: AgentTokenValidationInput;
  represented_persona: string;
  event: NostrUnsignedEvent;
  requested_feed: string;
  requested_resource: string;
  execution_token: string;
  request_digest: string;
}): {
  verdict: "accept";
  event: NostrSignedEvent;
  publication: CommsSocialSignedPublication;
} | {
  verdict: "reject";
  reason_code: "agent-signer-mismatch";
} {
  const request = snapshotCommsSocialPublicationRequest(input);
  if (
    request === null
    || request.authority === null
    || typeof request.authority !== "object"
    || Array.isArray(request.authority)
  ) return denied("agent-signer-mismatch");
  const capturedAuthority = request.authority as CommsSocialPublicationAuthority;
  const authority = SOCIAL_PUBLICATION_AUTHORITIES.get(capturedAuthority);
  if (authority === undefined) return denied("agent-signer-mismatch");
  let trustedNow: number;
  try {
    trustedNow = authority.trusted_now();
  } catch {
    return denied("agent-signer-mismatch");
  }
  let context: ReturnType<typeof validateCommsSocialContext>;
  try {
    context = validateCommsSocialContext({
      registration: request.registration,
      token: request.token,
      represented_persona: request.represented_persona,
      event: request.event,
      requested_feed: request.requested_feed,
      requested_resource: request.requested_resource,
      trusted_now: trustedNow,
    });
  } catch {
    return denied("agent-signer-mismatch");
  }
  if (
    context === null
    || !/^[0-9a-f]{64}$/u.test(request.execution_token)
    || !/^[0-9a-f]{64}$/u.test(request.request_digest)
  ) return denied("agent-signer-mismatch");
  const { registration, token, association } = context;
  const attributed = injectAgentAttribution({
    kind: request.event.kind,
    tags: request.event.tags,
    agent_class: registration.agent_class,
    persona: request.represented_persona,
    signer: request.event.pubkey,
    expected_signer: token.identity.signer,
    signer_key_class: token.identity.key_class,
    oidc_scopes: registration.scopes,
    agent_association: registration.agent_association,
    expected_agent_association: token.identity.agent_association,
    tier: 1,
  });
  if (
    attributed.verdict !== "accept"
    || attributed.author !== request.event.pubkey
  ) {
    return denied("agent-signer-mismatch");
  }
  const unsignedEvent = deepFreezeJson({
    pubkey: request.event.pubkey,
    created_at: request.event.created_at,
    kind: request.event.kind,
    tags: attributed.tags,
    content: request.event.content,
  });
  let rawOutcome: unknown;
  try {
    rawOutcome = authority.execute_once(
      request.execution_token,
      unsignedEvent,
      request.request_digest,
    );
  } catch {
    return denied("agent-signer-mismatch");
  }
  const outcome = snapshotAcceptedSignerOutcome(rawOutcome);
  if (
    outcome === null
    || !isStrictNostrSignedEvent(outcome.event)
    || outcome.event.id !== getEventId(unsignedEvent)
    || outcome.event.pubkey !== unsignedEvent.pubkey
    || outcome.event.created_at !== unsignedEvent.created_at
    || outcome.event.kind !== unsignedEvent.kind
    || outcome.event.content !== unsignedEvent.content
    || stableJson(outcome.event.tags) !== stableJson(unsignedEvent.tags)
  ) return denied("agent-signer-mismatch");
  const event = outcome.event;
  const publication = Object.freeze({}) as CommsSocialSignedPublication;
  SOCIAL_SIGNED_PUBLICATIONS.set(publication, {
    authority: capturedAuthority,
    represented_persona: request.represented_persona,
    event_id: event.id,
    signer: event.pubkey,
    kind: event.kind,
    created_at: event.created_at,
    agent_association: association,
    requested_feed: request.requested_feed,
    requested_resource: request.requested_resource,
  });
  return { verdict: "accept", event, publication };
}

export type CommsSocialSignedPublicationConsumer = (input: {
  publication: unknown;
  represented_persona: string;
  event: NostrSignedEvent;
  agent_association: AgentAssociation | null;
  requested_feed: string;
  requested_resource: string;
}) => boolean;

export function createCommsSocialSignedPublicationConsumer(input: {
  authority: CommsSocialPublicationAuthority;
}): CommsSocialSignedPublicationConsumer {
  const expectedAuthority = input.authority;
  if (!SOCIAL_PUBLICATION_AUTHORITIES.has(expectedAuthority)) return () => false;
  return (publicationInput) => consumeCommsSocialSignedPublication(
    expectedAuthority,
    publicationInput,
  );
}

function consumeCommsSocialSignedPublication(
  expectedAuthority: CommsSocialPublicationAuthority,
  input: Parameters<CommsSocialSignedPublicationConsumer>[0],
): boolean {
  if (
    input.publication === null
    || typeof input.publication !== "object"
    || Array.isArray(input.publication)
  ) return false;
  const binding = SOCIAL_SIGNED_PUBLICATIONS.get(input.publication);
  if (binding === undefined || binding.authority !== expectedAuthority) return false;
  SOCIAL_SIGNED_PUBLICATIONS.delete(input.publication);
  return isStrictNostrSignedEvent(input.event)
    && binding.represented_persona === input.represented_persona
    && binding.event_id === input.event.id
    && binding.signer === input.event.pubkey
    && binding.kind === input.event.kind
    && binding.created_at === input.event.created_at
    && binding.requested_feed === input.requested_feed
    && binding.requested_resource === input.requested_resource
    && equalNullableAssociation(binding.agent_association, input.agent_association);
}

function validateCommsSocialContext(input: {
  registration: unknown;
  token: AgentTokenValidationInput;
  represented_persona: string;
  event: NostrUnsignedEvent;
  requested_feed: string;
  requested_resource: string;
  trusted_now: number;
}): {
  registration: WorkloadRegistration;
  token: Extract<AgentTokenDecision, { verdict: "accept" }>;
  association: AgentAssociation | null;
} | null {
  let registration: WorkloadRegistration;
  try {
    registration = validateWorkloadRegistration(input.registration);
  } catch {
    return null;
  }
  const currentToken = structuredClone(input.token);
  currentToken.now = input.trusted_now;
  const token = validateAgentAccessToken(deepFreeze(currentToken));
  const association = registration.agent_association ?? null;
  if (
    token.verdict !== "accept"
    || !Number.isSafeInteger(input.trusted_now)
    || input.trusted_now < 0
    || !isStrictNostrUnsignedEvent(input.event)
    || registration.persona_key !== input.represented_persona
    || registration.selected_signer !== input.event.pubkey
    || registration.selected_signer !== token.identity.signer
    || registration.signer_key_class !== token.identity.key_class
    || !equalAssociation(registration.agent_association, token.identity.agent_association)
    || registration.audience !== input.token.aud[0]
    || registration.audience !== input.token.expected_audience
    || registration.subject_jkt !== input.token.cnf_jkt
    || registration.subject_proof?.jkt !== input.token.sender_proof_jkt
    || !registration.scopes.includes("heterodyne:agent:publish")
    || input.token.scope !== registration.scopes.join(" ")
    || input.token.expected_scope !== registration.scopes.join(" ")
    || input.token.expected_client_id !== registration.client_id
    || input.token.expected_signer_key !== registration.selected_signer
    || input.token.expected_signer_key_class !== registration.signer_key_class
    || !equalAssociation(input.token.expected_agent_association, registration.agent_association)
    || input.token.registration_expires_at !== registration.expires_at
    || input.trusted_now < registration.not_before
    || input.trusted_now >= registration.expires_at
    || input.trusted_now < input.token.iat
    || input.event.created_at > input.trusted_now
    || input.event.created_at < registration.not_before
    || input.event.created_at >= registration.expires_at
    || input.event.created_at < input.token.iat
    || input.event.created_at >= input.token.exp
    || !registration.allowed_kinds.includes(input.event.kind)
    || !registration.allowed_feeds.includes(input.requested_feed)
    || !registration.allowed_resources.includes(input.requested_resource)
    || new TextEncoder().encode(input.event.content).length > registration.max_content_bytes
  ) return null;
  return { registration, token, association };
}

export function matchesAgentAttributionProfile(tags: string[][]): boolean {
  const reservedIndexes = tags.flatMap((tag, index) =>
    isAgentProfileTag(tag) ? [index] : []
  );
  const reserved = reservedIndexes.map((index) => tags[index]);
  if (reserved.length !== 3 && reserved.length !== 4) return false;
  if (reservedIndexes.some((index, offset) => index !== reservedIndexes[0] + offset)) {
    return false;
  }
  if (
    !equalTag(reserved[0], ["L", "network.heterodyne.agent"])
    || reserved[1].length !== 3
    || reserved[1][0] !== "l"
    || !["ai", "programmatic"].includes(reserved[1][1])
    || reserved[1][2] !== "network.heterodyne.agent"
    || !equalTag(reserved.at(-1) ?? [], ["agent_action", "publish"])
  ) {
    return false;
  }
  if (reserved.length === 3) return true;
  const association = reserved[2];
  return association.length === 4
    && association[0] === "heterodyne_agent"
    && association[1] === "v1"
    && isAgentAssociation({
      kind: association[2] as "key" | "role",
      value: association[3],
    });
}

function isAgentProfileTag(tag: string[]): boolean {
  return tag[0] === "heterodyne_agent"
    || tag[0] === "agent_action"
    || tag[0] === "L" && tag[1] === "network.heterodyne.agent"
    || tag[0] === "l" && tag[2] === "network.heterodyne.agent";
}

function agentAssociationTag(
  association: unknown,
): string[] | undefined | null {
  if (association === undefined) return undefined;
  return isAgentAssociation(association)
    ? ["heterodyne_agent", "v1", association.kind, association.value]
    : null;
}

function equalAssociation(
  actual: unknown,
  expected: unknown,
): boolean {
  if (actual === undefined || expected === undefined) {
    return actual === expected;
  }
  return isAgentAssociation(actual)
    && isAgentAssociation(expected)
    && actual.kind === expected.kind
    && actual.value === expected.value;
}

function equalNullableAssociation(
  actual: AgentAssociation | null,
  expected: AgentAssociation | null,
): boolean {
  return actual === null || expected === null
    ? actual === expected
    : actual.kind === expected.kind && actual.value === expected.value;
}

function isAgentAssociation(value: unknown): value is AgentAssociation {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || Object.keys(value).length !== 2
    || !Object.hasOwn(value, "kind")
    || !Object.hasOwn(value, "value")
  ) {
    return false;
  }
  const association = value as Record<string, unknown>;
  if (typeof association.value !== "string") return false;
  return association.kind === "key"
    ? /^[0-9a-f]{64}$/.test(association.value)
    : association.kind === "role"
      && association.value.length >= 1
      && association.value.length <= 128;
}

function isReservedAttributionTag(tag: string[]): boolean {
  if (tag[0] === "heterodyne_agent" || tag[0] === "agent_action" || tag[0] === "agent_review") {
    return true;
  }
  return tag[0] === "L" && tag[1] === "network.heterodyne.agent"
    || tag[0] === "l" && tag[2] === "network.heterodyne.agent";
}

function equalTag(actual: string[], expected: string[]): boolean {
  return actual.length === expected.length
    && actual.every((member, index) => member === expected[index]);
}

function hasAnyMember(value: object, members: ReadonlySet<string>): boolean {
  return Object.keys(value).some((member) => members.has(member));
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) =>
    `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

type CapturedCommsSocialPublicationRequest = {
  authority: unknown;
  registration: unknown;
  token: AgentTokenValidationInput;
  represented_persona: string;
  event: NostrUnsignedEvent;
  requested_feed: string;
  requested_resource: string;
  execution_token: string;
  request_digest: string;
};

const COMMS_SOCIAL_REQUEST_KEYS = [
  "authority", "event", "execution_token", "registration", "represented_persona",
  "request_digest", "requested_feed", "requested_resource", "token",
].join("\0");
const CURRENT_TOKEN_REQUIRED_KEYS = [
  "aud", "client_id", "cnf_jkt", "consent_expires_at",
  "credential_ledger_generation", "credential_ledger_persona",
  "delegation_expires_at", "exp", "expected_audience", "expected_client_id",
  "expected_credential_ledger_generation", "expected_credential_ledger_persona",
  "expected_issuer", "expected_scope", "expected_signer_key",
  "expected_signer_key_class", "expected_subject", "iat", "iss", "jti",
  "ledger_active", "ledger_binding_valid", "now", "registration_expires_at",
  "scope", "sender_proof_jkt", "sender_proof_valid", "session_expires_at",
  "signer_key", "signer_key_class", "source_authorization_expires_at", "status",
  "status_binding_valid", "sub", "typ",
].sort();
const CURRENT_TOKEN_OPTIONAL_KEYS = new Set([
  "agent_association",
  "expected_agent_association",
]);
const CURRENT_TOKEN_STRING_KEYS = [
  "client_id", "cnf_jkt", "credential_ledger_persona", "expected_audience",
  "expected_client_id", "expected_credential_ledger_persona", "expected_issuer",
  "expected_scope", "expected_signer_key", "expected_signer_key_class",
  "expected_subject", "iss", "jti", "scope", "sender_proof_jkt", "signer_key",
  "signer_key_class", "status", "sub", "typ",
] as const;
const CURRENT_TOKEN_INTEGER_KEYS = [
  "consent_expires_at", "credential_ledger_generation", "delegation_expires_at",
  "exp", "expected_credential_ledger_generation", "iat", "now",
  "registration_expires_at", "session_expires_at", "source_authorization_expires_at",
] as const;
const CURRENT_TOKEN_BOOLEAN_KEYS = [
  "ledger_active", "ledger_binding_valid", "sender_proof_valid", "status_binding_valid",
] as const;

function snapshotAgentTokenValidationInput(
  value: unknown,
): AgentTokenValidationInput | null {
  const captured = snapshotClosedData(value, new WeakSet());
  if (
    captured === INVALID_SNAPSHOT
    || captured === null
    || typeof captured !== "object"
    || Array.isArray(captured)
  ) return null;
  const token = captured as Record<string, unknown>;
  const keys = Object.keys(token).sort();
  if (
    CURRENT_TOKEN_REQUIRED_KEYS.some((key) => !keys.includes(key))
    || keys.some((key) =>
      !CURRENT_TOKEN_REQUIRED_KEYS.includes(key) && !CURRENT_TOKEN_OPTIONAL_KEYS.has(key))
    || !CURRENT_TOKEN_STRING_KEYS.every((key) => typeof token[key] === "string")
    || !CURRENT_TOKEN_INTEGER_KEYS.every((key) => Number.isSafeInteger(token[key]))
    || !CURRENT_TOKEN_BOOLEAN_KEYS.every((key) => typeof token[key] === "boolean")
    || !Array.isArray(token.aud)
    || token.aud.length !== 1
    || !token.aud.every((member) => typeof member === "string")
    || token.signer_key_class !== "agent" && token.signer_key_class !== "persona"
    || token.expected_signer_key_class !== "agent"
      && token.expected_signer_key_class !== "persona"
    || !["VALID", "INVALID", "SUSPENDED"].includes(token.status as string)
    || token.agent_association !== undefined && !isAgentAssociation(token.agent_association)
    || token.expected_agent_association !== undefined
      && !isAgentAssociation(token.expected_agent_association)
  ) return null;
  return deepFreeze(captured) as AgentTokenValidationInput;
}

function snapshotCommsSocialPublicationRequest(
  value: unknown,
): CapturedCommsSocialPublicationRequest | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Object.getPrototypeOf(value) as object | null;
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return null;
  }
  const keys = Reflect.ownKeys(descriptors);
  if (
    prototype !== Object.prototype
    || keys.some((key) => typeof key !== "string")
    || Object.keys(descriptors).sort().join("\0") !== COMMS_SOCIAL_REQUEST_KEYS
    || Object.values(descriptors).some((descriptor) =>
      !("value" in descriptor) || descriptor.enumerable !== true)
  ) return null;

  const captured: Record<string, unknown> = {};
  for (const key of Object.keys(descriptors)) {
    const descriptor = descriptors[key] as PropertyDescriptor & { value: unknown };
    if (key === "authority") {
      captured.authority = descriptor.value;
      continue;
    }
    const member = snapshotClosedData(descriptor.value, new WeakSet());
    if (member === INVALID_SNAPSHOT) return null;
    captured[key] = deepFreeze(member);
  }
  const token = captured.token;
  if (token === null || typeof token !== "object" || Array.isArray(token)) return null;
  const tokenKeys = Object.keys(token).sort();
  if (
    CURRENT_TOKEN_REQUIRED_KEYS.some((key) => !tokenKeys.includes(key))
    || tokenKeys.some((key) =>
      !CURRENT_TOKEN_REQUIRED_KEYS.includes(key) && !CURRENT_TOKEN_OPTIONAL_KEYS.has(key))
  ) return null;
  return Object.freeze(captured) as CapturedCommsSocialPublicationRequest;
}

const INVALID_SNAPSHOT = Symbol("invalid-signer-outcome-snapshot");

function snapshotAcceptedSignerOutcome(
  value: unknown,
): Extract<CommsSocialSignerExecutionOutcome, { verdict: "accept" }> | null {
  const snapshot = snapshotClosedData(value, new WeakSet());
  if (
    snapshot === INVALID_SNAPSHOT
    || snapshot === null
    || typeof snapshot !== "object"
    || Array.isArray(snapshot)
    || Object.keys(snapshot).sort().join("\0") !== "disposition\0event\0verdict"
  ) return null;
  const outcome = snapshot as Record<string, unknown>;
  if (
    outcome.verdict !== "accept"
    || outcome.disposition !== "executed" && outcome.disposition !== "cached"
    || outcome.event === null
    || typeof outcome.event !== "object"
    || Array.isArray(outcome.event)
    || Object.keys(outcome.event).sort().join("\0")
      !== "content\0created_at\0id\0kind\0pubkey\0sig\0tags"
  ) return null;
  return deepFreeze(snapshot) as Extract<
    CommsSocialSignerExecutionOutcome,
    { verdict: "accept" }
  >;
}

function snapshotClosedData(
  value: unknown,
  seen: WeakSet<object>,
): unknown | typeof INVALID_SNAPSHOT {
  if (
    value === null
    || value === undefined
    || typeof value === "string"
    || typeof value === "number"
    || typeof value === "boolean"
  ) return value;
  if (typeof value !== "object" || seen.has(value)) return INVALID_SNAPSHOT;
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Object.getPrototypeOf(value) as object | null;
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    return INVALID_SNAPSHOT;
  }
  const array = Array.isArray(value);
  if (
    prototype !== (array ? Array.prototype : Object.prototype)
    || Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
  ) return INVALID_SNAPSHOT;
  seen.add(value);
  try {
    if (array) {
      const lengthDescriptor = descriptors.length;
      if (
        lengthDescriptor === undefined
        || !("value" in lengthDescriptor)
        || !Number.isSafeInteger(lengthDescriptor.value)
        || lengthDescriptor.value < 0
      ) return INVALID_SNAPSHOT;
      const length = lengthDescriptor.value as number;
      const keys = Object.keys(descriptors).filter((key) => key !== "length");
      if (
        keys.length !== length
        || keys.some((key, index) => key !== String(index))
      ) return INVALID_SNAPSHOT;
      const snapshot: unknown[] = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (
          descriptor === undefined
          || !("value" in descriptor)
          || descriptor.enumerable !== true
        ) {
          return INVALID_SNAPSHOT;
        }
        const member = snapshotClosedData(descriptor.value, seen);
        if (member === INVALID_SNAPSHOT) return INVALID_SNAPSHOT;
        snapshot.push(member);
      }
      return snapshot;
    }
    const snapshot: Record<string, unknown> = {};
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key];
      if (
        descriptor === undefined
        || !("value" in descriptor)
        || descriptor.enumerable !== true
      ) {
        return INVALID_SNAPSHOT;
      }
      const member = snapshotClosedData(descriptor.value, seen);
      if (member === INVALID_SNAPSHOT) return INVALID_SNAPSHOT;
      Object.defineProperty(snapshot, key, {
        value: member,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return snapshot;
  } finally {
    seen.delete(value);
  }
}

function deepFreezeJson<T>(value: T): T {
  const clone = JSON.parse(stableJson(value)) as T;
  return deepFreeze(clone);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function isStrictNostrUnsignedEvent(value: unknown): value is NostrUnsignedEvent {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const event = value as Record<string, unknown>;
  return Object.keys(event).sort().join("\0")
      === ["content", "created_at", "kind", "pubkey", "tags"].join("\0")
    && typeof event.pubkey === "string"
    && /^[0-9a-f]{64}$/u.test(event.pubkey)
    && Number.isSafeInteger(event.created_at)
    && (event.created_at as number) >= 0
    && Number.isSafeInteger(event.kind)
    && (event.kind as number) >= 0
    && (event.kind as number) <= 65_535
    && Array.isArray(event.tags)
    && event.tags.every((tag) =>
      Array.isArray(tag)
      && tag.length >= 1
      && tag.every((member) => typeof member === "string"))
    && typeof event.content === "string";
}

function denied<const T extends string>(reason_code: T): { verdict: "reject"; reason_code: T } {
  return { verdict: "reject", reason_code };
}
