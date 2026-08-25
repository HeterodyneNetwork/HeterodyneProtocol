import { Ajv2020 } from "ajv/dist/2020.js";
import workloadRegistrationSchema from "../../../schemas/comms/agent-workload-registration-v1.schema.json" with { type: "json" };
import { derivePairwiseSubject } from "./oidc.js";
import { evaluateCredentialGeneration } from "./credential-generation.js";
import { isStrictNostrSignedEvent, type NostrSignedEvent } from "./nostr.js";

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

declare const commsSocialAuthorizationBrand: unique symbol;
export type CommsSocialAuthorization = {
  readonly [commsSocialAuthorizationBrand]: true;
};

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
const SOCIAL_AUTHORIZATIONS = new WeakMap<object, {
  represented_persona: string;
  event_id: string;
  signer: string;
  kind: number;
  created_at: number;
  agent_association: AgentAssociation | null;
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

export function authorizeCommsSocialPublication(input: {
  registration: unknown;
  token: AgentTokenValidationInput;
  represented_persona: string;
  event: NostrSignedEvent;
}): { verdict: "accept"; authorization: CommsSocialAuthorization } | {
  verdict: "reject";
  reason_code: "agent-signer-mismatch";
} {
  let registration: WorkloadRegistration;
  try {
    registration = validateWorkloadRegistration(input.registration);
  } catch {
    return denied("agent-signer-mismatch");
  }
  const token = validateAgentAccessToken(input.token);
  const association = registration.agent_association ?? null;
  if (
    token.verdict !== "accept"
    || !isStrictNostrSignedEvent(input.event)
    || registration.persona_key !== input.represented_persona
    || registration.selected_signer !== input.event.pubkey
    || registration.selected_signer !== token.identity.signer
    || registration.signer_key_class !== token.identity.key_class
    || !equalAssociation(registration.agent_association, token.identity.agent_association)
    || !registration.scopes.includes("heterodyne:agent:publish")
    || input.token.scope !== registration.scopes.join(" ")
    || input.token.expected_scope !== registration.scopes.join(" ")
    || input.token.expected_client_id !== registration.client_id
    || input.token.expected_signer_key !== registration.selected_signer
    || input.token.expected_signer_key_class !== registration.signer_key_class
    || !equalAssociation(input.token.expected_agent_association, registration.agent_association)
    || input.token.registration_expires_at !== registration.expires_at
    || input.event.created_at !== input.token.now
    || input.event.created_at < registration.not_before
    || input.event.created_at >= registration.expires_at
    || input.event.created_at < input.token.iat
    || input.event.created_at >= input.token.exp
    || !registration.allowed_kinds.includes(input.event.kind)
    || new TextEncoder().encode(input.event.content).length > registration.max_content_bytes
  ) {
    return denied("agent-signer-mismatch");
  }
  const attributed = injectAgentAttribution({
    kind: input.event.kind,
    tags: input.event.tags,
    agent_class: registration.agent_class,
    persona: input.represented_persona,
    signer: input.event.pubkey,
    expected_signer: token.identity.signer,
    signer_key_class: token.identity.key_class,
    oidc_scopes: registration.scopes,
    agent_association: registration.agent_association,
    expected_agent_association: token.identity.agent_association,
    tier: 1,
  });
  if (
    attributed.verdict !== "accept"
    || attributed.author !== input.event.pubkey
    || JSON.stringify(attributed.tags) !== JSON.stringify(input.event.tags)
  ) {
    return denied("agent-signer-mismatch");
  }
  const authorization = Object.freeze({}) as CommsSocialAuthorization;
  SOCIAL_AUTHORIZATIONS.set(authorization, {
    represented_persona: input.represented_persona,
    event_id: input.event.id,
    signer: input.event.pubkey,
    kind: input.event.kind,
    created_at: input.event.created_at,
    agent_association: association,
  });
  return { verdict: "accept", authorization };
}

export function matchesCommsSocialAuthorization(input: {
  authorization: unknown;
  represented_persona: string;
  event: NostrSignedEvent;
  agent_association: AgentAssociation | null;
}): boolean {
  if (
    input.authorization === null
    || typeof input.authorization !== "object"
    || Array.isArray(input.authorization)
  ) return false;
  const binding = SOCIAL_AUTHORIZATIONS.get(input.authorization);
  return binding !== undefined
    && binding.represented_persona === input.represented_persona
    && binding.event_id === input.event.id
    && binding.signer === input.event.pubkey
    && binding.kind === input.event.kind
    && binding.created_at === input.event.created_at
    && equalNullableAssociation(binding.agent_association, input.agent_association);
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

function denied<const T extends string>(reason_code: T): { verdict: "reject"; reason_code: T } {
  return { verdict: "reject", reason_code };
}
