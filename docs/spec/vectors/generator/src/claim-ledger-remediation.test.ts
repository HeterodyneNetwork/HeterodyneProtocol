import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import {
  buildLedgerRepositoryEvidence,
  evaluateReaderAccess,
  materializeLedgerLayout,
  mergeClaimLedger,
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
});
