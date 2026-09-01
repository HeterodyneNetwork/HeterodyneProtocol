import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import {
  controlFrameContext,
  controlResetEvidenceFixtures,
  controlSignerEvidenceFixture,
  controlSignerInvocationCount,
  executeControlResetEvidenceFixture,
  executeControlSignerEvidenceFixture,
  isControlSecurityEvidenceTerminal,
  reconstructControlSignerEvidenceFixture,
  signedControlFrameBytes,
  type ControlResetEvidenceFixture,
  type ControlSignerEvidenceFixture,
} from "./control-security-evidence.js";
import {
  compromiseResetCompletionProofBytes,
  compromiseResetGrantProofBytes,
  executePersistedAutomatedSigning,
  validateCompromiseReset,
} from "./control-signing.js";
import { hexToBytes } from "./hex.js";
import { validateCurrentControlFrameProfile } from "./profile-negotiation.js";

const REQUEST_B = "bb".repeat(32);

describe("real Control security evidence", () => {
  it("BLUE TEAM VALIDATION: synthetic/local rejects a signed frame rebound to another request", () => {
    const bytes = signedControlFrameBytes();

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
    expect(controlSignerInvocationCount(fixture)).toBe(0);
    const first = executeControlSignerEvidenceFixture(fixture);
    expect(controlSignerInvocationCount(fixture)).toBe(1);
    const reconstructed = reconstructControlSignerEvidenceFixture(fixture);
    const retry = executeControlSignerEvidenceFixture(reconstructed);

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
    expect(controlSignerInvocationCount(fixture)).toBe(1);
    expect(controlSignerInvocationCount(reconstructed)).toBe(1);
    expect(retry.terminal).not.toBe(first.terminal);
    expect(isControlSecurityEvidenceTerminal(
      first.terminal,
      executePersistedAutomatedSigning,
      first.input,
      first.result,
    )).toBe(true);
    expect(isControlSecurityEvidenceTerminal(
      retry.terminal,
      executePersistedAutomatedSigning,
      retry.input,
      retry.result,
    )).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects post-mint reset input and result mutation", () => {
    const inputFixture = controlResetEvidenceFixtures()[0];
    const inputExecution = executeControlResetEvidenceFixture(inputFixture);
    inputFixture.input.authoritative_evidence.evidence_revision += 1;
    expect(isControlSecurityEvidenceTerminal(
      inputExecution.terminal,
      validateCompromiseReset,
      inputExecution.input,
      inputExecution.result,
    )).toBe(false);

    const verdictFixture = controlResetEvidenceFixtures()[1];
    const verdictExecution = executeControlResetEvidenceFixture(verdictFixture);
    (verdictExecution.result as { verdict: string }).verdict = "accept";
    expect(isControlSecurityEvidenceTerminal(
      verdictExecution.terminal,
      validateCompromiseReset,
      verdictExecution.input,
      verdictExecution.result,
    )).toBe(false);

    const reasonFixture = controlResetEvidenceFixtures()[2];
    const reasonExecution = executeControlResetEvidenceFixture(reasonFixture);
    (reasonExecution.result as { reason_code: string }).reason_code =
      "control-compromise-reset-evidence-invalid";
    expect(isControlSecurityEvidenceTerminal(
      reasonExecution.terminal,
      validateCompromiseReset,
      reasonExecution.input,
      reasonExecution.result,
    )).toBe(false);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects post-mint nested signer-terminal mutation", () => {
    const fixture = controlSignerEvidenceFixture();
    const execution = executeControlSignerEvidenceFixture(fixture);
    if (execution.result.verdict !== "indeterminate") {
      throw new Error("synthetic signer fixture did not reach indeterminate");
    }
    execution.result.completion_transition.failure_digest = "ff".repeat(32);

    expect(isControlSecurityEvidenceTerminal(
      execution.terminal,
      executePersistedAutomatedSigning,
      execution.input,
      execution.result,
    )).toBe(false);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned, cross-input, and cross-boundary evidence", () => {
    const [fixture, otherFixture] = controlResetEvidenceFixtures();
    const execution = executeControlResetEvidenceFixture(fixture);
    const clonedInput = structuredClone(execution.input);
    const clonedResult = structuredClone(execution.result);

    expect(isControlSecurityEvidenceTerminal(
      execution.terminal,
      validateCompromiseReset,
      clonedInput,
      execution.result,
    )).toBe(false);
    expect(isControlSecurityEvidenceTerminal(
      execution.terminal,
      validateCompromiseReset,
      execution.input,
      clonedResult,
    )).toBe(false);
    expect(isControlSecurityEvidenceTerminal(
      execution.terminal,
      validateCompromiseReset,
      otherFixture.input,
      execution.result,
    )).toBe(false);
    expect(isControlSecurityEvidenceTerminal(
      execution.terminal,
      executePersistedAutomatedSigning,
      execution.input,
      execution.result,
    )).toBe(false);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a reset fixture accessor before reading its alternating input", () => {
    const [fixtureA, fixtureB] = controlResetEvidenceFixtures();
    let trapCount = 0;
    const inputSequence = [
      fixtureA.input,
      fixtureB.input,
      fixtureA.input,
      fixtureA.input,
    ];
    const accessorFixture = Object.defineProperties({}, {
      input: {
        enumerable: true,
        get: () => inputSequence[Math.min(trapCount++, inputSequence.length - 1)],
      },
      expected_reason: {
        enumerable: true,
        value: fixtureA.expected_reason,
      },
    }) as ControlResetEvidenceFixture;
    let rejected = false;

    try {
      executeControlResetEvidenceFixture(accessorFixture);
    } catch {
      rejected = true;
    }

    expect(trapCount).toBe(0);
    expect(rejected).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local closes every signer fixture adapter without invoking accessors", () => {
    for (const operation of [
      executeControlSignerEvidenceFixture,
      reconstructControlSignerEvidenceFixture,
      controlSignerInvocationCount,
    ]) {
      const fixtureA = controlSignerEvidenceFixture();
      const fixtureB = controlSignerEvidenceFixture();
      let trapCount = 0;
      const inputSequence = [
        fixtureA.input,
        fixtureB.input,
        fixtureA.input,
        fixtureA.input,
      ];
      const accessorFixture = Object.defineProperties({}, {
        input: {
          enumerable: true,
          get: () => inputSequence[Math.min(trapCount++, inputSequence.length - 1)],
        },
        expected_reason: {
          enumerable: true,
          value: fixtureA.expected_reason,
        },
      }) as ControlSignerEvidenceFixture;
      let rejected = false;

      try {
        operation(accessorFixture);
      } catch {
        rejected = true;
      }

      expect(trapCount).toBe(0);
      expect(rejected).toBe(true);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxy, extra, and symbol fixture members", () => {
    const fixture = controlResetEvidenceFixtures()[0];
    const candidates = [
      new Proxy(fixture, {}),
      { ...fixture, extra: true },
      { ...fixture, [Symbol("synthetic-local")]: true },
    ];

    for (const candidate of candidates) {
      expect(() => executeControlResetEvidenceFixture(
        candidate as ControlResetEvidenceFixture,
      )).toThrow(/exact ordinary data object/u);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local closes signer input descriptors in non-executing fixture adapters", () => {
    for (const operation of [
      reconstructControlSignerEvidenceFixture,
      controlSignerInvocationCount,
    ]) {
      const fixture = controlSignerEvidenceFixture();
      const authorization = fixture.input.authorization;
      let trapCount = 0;
      Object.defineProperty(fixture.input, "authorization", {
        enumerable: true,
        configurable: true,
        get: () => {
          trapCount += 1;
          return authorization;
        },
      });
      let rejected = false;

      try {
        operation(fixture);
      } catch {
        rejected = true;
      }

      expect(trapCount).toBe(0);
      expect(rejected).toBe(true);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects substituted signer capabilities without invoking proxy traps", () => {
    for (const operation of [
      executeControlSignerEvidenceFixture,
      reconstructControlSignerEvidenceFixture,
      controlSignerInvocationCount,
    ]) {
      const fixture = controlSignerEvidenceFixture();
      let trapCount = 0;
      const signerProxy = new Proxy(fixture.input.signer_execution, {
        get: (target, property, receiver) => {
          trapCount += 1;
          return Reflect.get(target, property, receiver);
        },
      });
      Object.defineProperty(fixture.input, "signer_execution", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: signerProxy,
      });
      let rejected = false;

      try {
        operation(fixture);
      } catch {
        rejected = true;
      }

      expect(trapCount).toBe(0);
      expect(rejected).toBe(true);
    }
  });
});
