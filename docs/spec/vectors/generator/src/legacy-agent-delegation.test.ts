import { describe, expect, it } from "vitest";
import { bytesToHex } from "./hex.js";
import {
  legacyAgentBindingMessage,
  validateLegacyAgentDelegation,
} from "./legacy-agent-delegation.js";

const coldRoot = "11".repeat(32);
const roleId = "ab".repeat(32);
const publishingKey = "33".repeat(32);
const nid = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdgQ9T";

describe("frozen pre-redesign agent delegation compatibility", () => {
  const proof = bytesToHex(
    legacyAgentBindingMessage(coldRoot, nid, roleId, publishingKey),
  );
  const valid = {
    cold_root: coldRoot,
    credential_ledger_generation: 0,
    expected_credential_ledger_persona: coldRoot,
    expected_credential_ledger_generation: 0,
    nid,
    role_id: roleId,
    publishing_key: publishingKey,
    address: `agent:${roleId}`,
    proof_bytes: proof,
    outer_epoch_signature_valid: true,
    nid_proof_valid: true,
    key_proof_valid: true,
    kel_authority_current: true,
    unexpired: true,
    repo_final: true,
  };

  it("keeps the frozen vector-only proof behavior isolated under legacy names", () => {
    expect(new TextDecoder().decode(
      legacyAgentBindingMessage(coldRoot, nid, roleId, publishingKey),
    )).toBe(
      'heterodyne-agent-signing-binding-v1\u0000'
        + `{"cold_root":"${coldRoot}","nid":"${nid}",`
        + `"publishing_key":"${publishingKey}","role_id":"${roleId}"}`,
    );
    expect(validateLegacyAgentDelegation(valid)).toEqual({
      verdict: "accept",
      role_id: roleId,
      publishing_key: publishingKey,
      repo_final: true,
    });
  });

  it("fails closed within the frozen compatibility boundary", () => {
    expect(validateLegacyAgentDelegation({
      ...valid,
      address: `agent:${roleId.toUpperCase()}`,
    })).toMatchObject({
      verdict: "reject",
      reason_code: "role-delegation-address-invalid",
    });
    for (const patch of [
      { outer_epoch_signature_valid: false },
      { nid_proof_valid: false },
      { key_proof_valid: false },
      { proof_bytes: `${proof}x` },
      { kel_authority_current: false },
      { unexpired: false },
    ]) {
      expect(validateLegacyAgentDelegation({ ...valid, ...patch }))
        .toMatchObject({ verdict: "reject" });
    }
    expect(validateLegacyAgentDelegation({ ...valid, repo_final: false }))
      .toMatchObject({ verdict: "reject", reason_code: "provisional_not_final" });
  });
});
