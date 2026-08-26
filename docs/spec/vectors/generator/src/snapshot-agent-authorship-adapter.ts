import { Ajv2020 } from "ajv/dist/2020.js";
import workloadRegistrationSchema from "../../../schemas/comms/agent-workload-registration-v1.schema.json" with { type: "json" };
import { derivePairwiseSubject } from "./oidc.js";
import { evaluateCredentialGeneration } from "./credential-generation.js";
import { proofBytes } from "./proof-bytes.js";
import { bytesToHex } from "./hex.js";

export type AgentDelegationInput = {
  cold_root: string;
  credential_ledger_generation: number;
  expected_credential_ledger_persona: string;
  expected_credential_ledger_generation: number;
  nid: string;
  role_id: string;
  publishing_key: string;
  address: string;
  /** Hex of the Core 3.5.1 proof bytes. */
  proof_bytes: string;
  outer_epoch_signature_valid: boolean;
  nid_proof_valid: boolean;
  key_proof_valid: boolean;
  kel_authority_current: boolean;
  unexpired: boolean;
  repo_final: boolean;
};

export type AgentDelegationResult =
  | {
      verdict: "accept";
      role_id: string;
      publishing_key: string;
      repo_final: true;
    }
  | {
      verdict: "reject";
      reason_code: string;
    };

export type WorkloadRegistration = {
  client_id: string;
  subject_jkt: string;
  agent_class: "ai" | "programmatic";
  role_id: string;
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
  agent_role_id: string;
  expected_issuer: string;
  expected_subject: string;
  expected_audience: string;
  expected_client_id: string;
  expected_scope: string;
  expected_role_id: string;
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
        role_id: string;
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
  issuer: string;
  subject: string;
  client_id: string;
  role_id: string;
  signer: string;
  current_role_key: string;
  tier: 1 | 2 | 3;
  agent_review?: string;
  agent_review_verified?: boolean;
};

export type AgentPublicationResult =
  | {
      verdict: "accept";
      tags: string[][];
      placement: "public" | "private-repository" | "encrypted-inner";
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

export function agentBindingMessage(
  coldRoot: string,
  nid: string,
  roleId: string,
  publishingKey: string,
): Uint8Array {
  return proofBytes("heterodyne-agent-signing-binding-v1", {
    cold_root: coldRoot,
    nid,
    publishing_key: publishingKey,
    role_id: roleId,
  });
}

export function validateAgentDelegation(
  input: AgentDelegationInput,
): AgentDelegationResult {
  if (!Object.prototype.hasOwnProperty.call(input, "credential_ledger_generation")) {
    return denied("credential_generation_missing");
  }
  if (
    !/^[0-9a-f]{64}$/.test(input.role_id)
    || input.address !== `agent:${input.role_id}`
  ) {
    return denied("role-delegation-address-invalid");
  }
  if (
    !/^[0-9a-f]{64}$/.test(input.cold_root)
    || !/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(input.nid)
    || !/^[0-9a-f]{64}$/.test(input.publishing_key)
    || input.proof_bytes !== bytesToHex(agentBindingMessage(
      input.cold_root,
      input.nid,
      input.role_id,
      input.publishing_key,
    ))
    || !input.outer_epoch_signature_valid
    || !input.nid_proof_valid
    || !input.key_proof_valid
    || !input.kel_authority_current
  ) {
    return denied("role-delegation-key-proof-invalid");
  }
  const generation = evaluateCredentialGeneration({
    credential_ledger_persona: input.cold_root,
    credential_ledger_generation: input.credential_ledger_generation,
  }, {
    credential_ledger_persona: input.expected_credential_ledger_persona,
    credential_ledger_generation: input.expected_credential_ledger_generation,
  });
  if (!generation.valid) {
    return denied(generation.reason_code === "credential_schema_invalid"
      ? "role-delegation-key-proof-invalid"
      : generation.reason_code);
  }
  if (!input.unexpired) return denied("expired_delegation");
  if (!input.repo_final) return denied("provisional_not_final");
  return {
    verdict: "accept",
    role_id: input.role_id,
    publishing_key: input.publishing_key,
    repo_final: true,
  };
}

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
    input.agent_role_id !== input.expected_role_id
    || !/^[0-9a-f]{64}$/.test(input.agent_role_id)
  ) {
    return denied("agent-role-mismatch");
  }
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
      role_id: input.agent_role_id,
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
    input.signer !== input.current_role_key
    || !/^[0-9a-f]{64}$/.test(input.role_id)
  ) {
    return denied("agent-role-mismatch");
  }
  if (
    !["ai", "programmatic"].includes(input.agent_class)
    || input.issuer.length === 0
    || input.subject.length === 0
    || input.client_id.length === 0
  ) {
    return denied("agent-attribution-invalid");
  }

  const preserved = input.tags.filter((tag) => !isReservedAttributionTag(tag));
  const tags = [
    ...preserved,
    ["L", "network.heterodyne.agent"],
    ["l", input.agent_class, "network.heterodyne.agent"],
    [
      "heterodyne_agent",
      "v1",
      input.issuer,
      input.subject,
      input.client_id,
      input.role_id,
    ],
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
      clear_outer_tags: [],
    };
  }
  return {
    verdict: "accept",
    tags,
    placement: input.tier === 1 ? "public" : "private-repository",
  };
}

function isReservedAttributionTag(tag: string[]): boolean {
  if (tag[0] === "heterodyne_agent" || tag[0] === "agent_action" || tag[0] === "agent_review") {
    return true;
  }
  return tag[0] === "L" && tag[1] === "network.heterodyne.agent"
    || tag[0] === "l" && tag[2] === "network.heterodyne.agent";
}

function denied(reason_code: string): { verdict: "reject"; reason_code: string } {
  return { verdict: "reject", reason_code };
}
