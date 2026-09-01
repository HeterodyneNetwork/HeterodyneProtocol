import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import {
  controlFrameContext,
  controlResetEvidenceFixtures,
  controlSignerEvidenceFixture,
  executeControlResetEvidenceFixture,
  executeControlSignerEvidenceFixture,
  isControlSecurityEvidenceTerminal,
  signedControlFrameBytes,
} from "./control-security-evidence.js";
import {
  compromiseResetCompletionProofBytes,
  compromiseResetGrantProofBytes,
  executePersistedAutomatedSigning,
  validateCompromiseReset,
} from "./control-signing.js";
import { hexToBytes } from "./hex.js";
import { validateCurrentControlFrameProfile } from "./profile-negotiation.js";

const REQUEST_A = "aa".repeat(32);
const REQUEST_B = "bb".repeat(32);

describe("real Control security evidence", () => {
  it("BLUE TEAM VALIDATION: synthetic/local rejects a signed frame rebound to another request", () => {
    const bytes = signedControlFrameBytes({ request_digest: REQUEST_A });

    expect(validateCurrentControlFrameProfile(bytes, controlFrameContext({
      expected_request_digest: REQUEST_B,
    }))).toEqual({ verdict: "reject", reason_code: "control-frame-invalid" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local invokes the real reset boundary for every retained reason", () => {
    const fixtures = controlResetEvidenceFixtures();
    expect(fixtures.map(({ expected_reason }) => expected_reason)).toEqual([
      "control-compromise-reset-evidence-invalid",
      "control-compromise-reset-inventory-mismatch",
      "control-compromise-reset-unauthenticated",
      "control-subordinate-reauthorization-required",
    ]);

    for (const fixture of fixtures) {
      const grantSignatureValid = schnorr.verify(
        hexToBytes(fixture.input.grant.signature),
        compromiseResetGrantProofBytes(fixture.input.grant),
        hexToBytes(fixture.input.grant.authorizing_pubkey),
      );
      const completionSignatureValid = schnorr.verify(
        hexToBytes(fixture.input.completion.signature),
        compromiseResetCompletionProofBytes(fixture.input.completion),
        hexToBytes(fixture.input.completion.signer),
      );
      expect(grantSignatureValid, fixture.expected_reason).toBe(true);
      expect(completionSignatureValid, fixture.expected_reason).toBe(true);

      const execution = executeControlResetEvidenceFixture(fixture);
      expect(execution.input).toBe(fixture.input);
      expect(execution.result).toEqual(validateCompromiseReset(fixture.input));
      expect(execution.result).toEqual({
        verdict: "reject",
        reason_code: fixture.expected_reason,
      });
      expect(Object.isFrozen(execution.terminal)).toBe(true);
      expect(isControlSecurityEvidenceTerminal(
        execution.terminal,
        validateCompromiseReset,
        execution.input,
        execution.result,
      )).toBe(true);
      expect(isControlSecurityEvidenceTerminal(
        Object.freeze({}),
        validateCompromiseReset,
        execution.input,
        execution.result,
      )).toBe(false);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local retains the durable indeterminate signer terminal without repeating the key effect", () => {
    const fixture = controlSignerEvidenceFixture();
    const first = executeControlSignerEvidenceFixture(fixture);
    const retry = executeControlSignerEvidenceFixture(fixture);

    expect(first.input).toBe(fixture.input);
    expect(first.result).toMatchObject({
      verdict: "indeterminate",
      reason_code: fixture.expected_reason,
      signer_execution_disposition: "executed",
      completion_transition: {
        prior_reservation_state: "executing",
        reservation_state: "indeterminate",
        failure_digest: expect.stringMatching(/^[0-9a-f]{64}$/u),
      },
    });
    expect(retry.result).toMatchObject({
      verdict: "indeterminate",
      reason_code: fixture.expected_reason,
      signer_execution_disposition: "cached",
      completion_transition: {
        failure_digest: first.result.verdict === "indeterminate"
          ? first.result.completion_transition.failure_digest
          : "unreachable",
      },
    });
    expect(retry.terminal).toBe(first.terminal);
    expect(isControlSecurityEvidenceTerminal(
      first.terminal,
      executePersistedAutomatedSigning,
      first.input,
      first.result,
    )).toBe(true);
    expect(isControlSecurityEvidenceTerminal(
      first.terminal,
      executePersistedAutomatedSigning,
      retry.input,
      retry.result,
    )).toBe(true);
  });
});
