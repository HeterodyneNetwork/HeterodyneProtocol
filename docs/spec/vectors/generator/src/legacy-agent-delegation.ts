/**
 * Frozen pre-redesign vector compatibility only.
 *
 * No current registration, token, or publication authority decision invokes
 * these functions; agent-authorship.ts only re-exports legacy names so the
 * explicitly frozen topic source continues to compile.
 */
import { evaluateCredentialGeneration } from "./credential-generation.js";
import { bytesToHex } from "./hex.js";
import { proofBytes } from "./proof-bytes.js";

export type LegacyAgentDelegationInput = {
  cold_root: string;
  credential_ledger_generation: number;
  expected_credential_ledger_persona: string;
  expected_credential_ledger_generation: number;
  nid: string;
  role_id: string;
  publishing_key: string;
  address: string;
  proof_bytes: string;
  outer_epoch_signature_valid: boolean;
  nid_proof_valid: boolean;
  key_proof_valid: boolean;
  kel_authority_current: boolean;
  unexpired: boolean;
  repo_final: boolean;
};

export type LegacyAgentDelegationResult =
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

export function legacyAgentBindingMessage(
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

export function validateLegacyAgentDelegation(
  input: LegacyAgentDelegationInput,
): LegacyAgentDelegationResult {
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
    || input.proof_bytes !== bytesToHex(legacyAgentBindingMessage(
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

function denied(reason_code: string): LegacyAgentDelegationResult {
  return { verdict: "reject", reason_code };
}
