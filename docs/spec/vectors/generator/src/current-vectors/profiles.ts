import { buildClaimLedgerScenario } from "../claim-ledger-test-support.js";
import { buildFixtures } from "../fixtures.js";
import { buildAssuranceProfileBoundaryFixtures } from "./assurance.js";
import { buildCurrentProfileOracleFixture, CURRENT_PROFILE_ORACLES } from "./profile-oracles.js";
import { buildCurrentRevocationProfileFixtures } from "./revocation-profile-fixtures.js";
import type { CurrentCaseFixture } from "./types.js";

/** Builds only fixtures from the independent, fixed current-profile oracle. */
export async function buildProfileCases(): Promise<CurrentCaseFixture[]> {
  const assurance = await buildAssuranceProfileBoundaryFixtures();
  const ledger = await buildClaimLedgerScenario(buildFixtures());
  const revocations = await buildCurrentRevocationProfileFixtures(ledger);
  return CURRENT_PROFILE_ORACLES.map((oracle) => {
    const proofExpectation = oracle.claim_proof_expectation;
    const revocation = proofExpectation?.purpose === "claim-revoker"
      ? revocations.get(proofExpectation.suite)
      : undefined;
    const fixtureName = oracle.semantic_input.assurance_profile_fixture;
    const semanticInput = typeof fixtureName === "string"
      ? assurance[fixtureName as keyof typeof assurance]
      : revocation === undefined
        ? oracle.semantic_input
        : { revocation_artifact: revocation.artifact };
    const input = {
      ...structuredClone(oracle.tuple),
      wire_probe: structuredClone(oracle.wire_probe),
      ...(revocation === undefined
        ? structuredClone(semanticInput)
        : semanticInput),
    };
    let boundaryArgs: readonly unknown[] | undefined;
    if (revocation !== undefined) boundaryArgs = [revocation.execution];
    return buildCurrentProfileOracleFixture(oracle, input, boundaryArgs);
  });
}
