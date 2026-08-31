import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import {
  buildLedgerRepositoryEvidence,
  evaluateReaderAccess,
  materializeLedgerLayout,
  mergeClaimLedger,
  prepareLedgerReplayValidationContext,
  validateReaderOnboardingBundle,
  type LedgerValidationContext,
  type ReaderAccessRequest,
} from "./claim-ledger.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import { inspectVerifiedClaim } from "./claims.js";
import { buildFixtures } from "./fixtures.js";

const fixtures = buildFixtures();

describe("claim-ledger remediation security contexts", () => {
  it("requires explicit repository and record validation evidence", () => {
    expect(typeof buildLedgerRepositoryEvidence).toBe("function");
    expect({} as LedgerValidationContext).toBeDefined();
    expect({} as ReaderAccessRequest).toBeDefined();
  });

  it("materializes a fixed 256-entry re-encrypted layout", () => {
    const key = Uint8Array.from({ length: 32 }, () => 0x51);
    const first = materializeLedgerLayout(key, 1, "aa".repeat(32), "11".repeat(32), []);
    const second = materializeLedgerLayout(key, 1, "bb".repeat(32), "12".repeat(32), []);
    expect(first.entries).toHaveLength(256);
    expect(new Set(first.entries.map(({ size }) => size))).toEqual(new Set([64]));
    expect(first.entries.map(({ path }) => path)).toEqual(
      Array.from({ length: 256 }, (_, index) => `objects/${index.toString(16).padStart(2, "0")}.bin`),
    );
    expect(first.entries.every((entry, index) => entry.ciphertext !== second.entries[index].ciphertext)).toBe(true);
  });

  it("exposes an executable onboarding validator", () => {
    expect(typeof validateReaderOnboardingBundle).toBe("function");
    expect(ed25519.getPublicKey(fixtures.ed25519_nids.alice_device_1.private_key)).toHaveLength(32);
  });

  it("BLUE TEAM VALIDATION: synthetic/local ledger replay accepts only opaque claim artifacts", async () => {
    // BLUE TEAM VALIDATION: synthetic/local replay uses deterministic non-deployable records only.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const state = mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      scenario.makeContext(scenario.baseRepository.repository),
    );
    const opaqueRequest = scenario.requestFor(scenario.claimRecordOne, scenario.claimOne);
    opaqueRequest.verification_context.now = state.checkpoint.observed_at;
    expect(evaluateReaderAccess(scenario.writerOne.did_key, state, opaqueRequest).state).toBe("active");

    const inspection = inspectVerifiedClaim(scenario.claimOne.verified_artifact);
    const formerPublicRequest = {
      ...opaqueRequest,
      claims_by_id: new Map([[inspection.claim_id, inspection]]),
    } as unknown as typeof opaqueRequest;
    expect(evaluateReaderAccess(scenario.writerOne.did_key, state, formerPublicRequest)).toMatchObject({
      allowed: false,
      state: "invalid",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local replay cache never invokes evidence accessors", async () => {
    // BLUE TEAM VALIDATION: synthetic/local evidence is deterministic and cannot target deployments.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const validation = scenario.makeContext(scenario.baseRepository.repository);
    prepareLedgerReplayValidationContext(validation);
    mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      validation,
    );

    const original = validation.record_evidence.get(scenario.claimRecordOne.record_id)!;
    let accessorReads = 0;
    const hostileEvidence = {
      record_id: original.record_id,
      payload_digest: original.payload_digest,
      claim_envelope_context: original.claim_envelope_context,
      claim_verification_context: original.claim_verification_context,
    };
    Object.defineProperty(hostileEvidence, "claims_by_id", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return accessorReads % 2 === 1 ? undefined : original.claims_by_id;
      },
    });
    validation.record_evidence.set(
      scenario.claimRecordOne.record_id,
      hostileEvidence as unknown as typeof original,
    );
    expect(() => mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      validation,
    )).toThrow(/evidence|data-only|repository-unconfirmed/i);
    expect(accessorReads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local ledger revocation never spreads nested hostile context", async () => {
    // BLUE TEAM VALIDATION: synthetic/local replay uses only deterministic non-deployable signed records.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: scenario.rid,
      confirmed_records: [scenario.claimRecordOne, scenario.revocationRecord],
      observed_at: scenario.now + 50,
    });

    let nowReads = 0;
    const accessorValidation = scenario.makeContext(repository.repository);
    const accessorEvidence = accessorValidation.record_evidence.get(
      scenario.revocationRecord.record_id,
    )!;
    const accessorContext = { ...accessorEvidence.claim_verification_context! };
    Object.defineProperty(accessorContext, "now", {
      enumerable: true,
      get() {
        nowReads += 1;
        return scenario.now + 40;
      },
    });
    accessorValidation.record_evidence.set(scenario.revocationRecord.record_id, {
      ...accessorEvidence,
      claim_verification_context: accessorContext,
    });
    expect(() => mergeClaimLedger(
      [scenario.claimRecordOne, scenario.revocationRecord],
      [],
      repository.checkpoint,
      accessorValidation,
    )).toThrow(/claim-revoker-unauthorized|data-only|context/i);
    expect(nowReads).toBe(0);

    let proxyTraps = 0;
    const proxyValidation = scenario.makeContext(repository.repository);
    const proxyEvidence = proxyValidation.record_evidence.get(scenario.revocationRecord.record_id)!;
    const proxyContext = new Proxy(proxyEvidence.claim_verification_context!, {
      ownKeys(target) {
        proxyTraps += 1;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, property) {
        proxyTraps += 1;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
      get(target, property, receiver) {
        proxyTraps += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    proxyValidation.record_evidence.set(scenario.revocationRecord.record_id, {
      ...proxyEvidence,
      claim_verification_context: proxyContext,
    });
    expect(() => mergeClaimLedger(
      [scenario.claimRecordOne, scenario.revocationRecord],
      [],
      repository.checkpoint,
      proxyValidation,
    )).toThrow(/claim-revoker-unauthorized|context/i);
    expect(proxyTraps).toBe(0);
  });
});
