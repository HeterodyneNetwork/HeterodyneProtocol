import { buildClaimLedgerScenario } from "../claim-ledger-test-support.js";
import { buildLedgerRepositoryEvidence } from "../claim-ledger.js";
import { buildFixtures } from "../fixtures.js";
import { buildAssuranceProfileBoundaryFixtures } from "./assurance.js";
import { CURRENT_PROFILE_ORACLES } from "./profile-oracles.js";
import type { CurrentCaseFixture } from "./types.js";

/** Builds only fixtures from the independent, fixed current-profile oracle. */
export async function buildProfileCases(): Promise<CurrentCaseFixture[]> {
  const assurance = await buildAssuranceProfileBoundaryFixtures();
  const ledger = await buildClaimLedgerScenario(buildFixtures());
  const revocationRecords = [
    ledger.claimRecordOne,
    ledger.claimRecordTwo,
    ledger.grantOne,
    ledger.revocationRecord,
  ];
  const revocationRepository = buildLedgerRepositoryEvidence({
    repository_rid: ledger.rid,
    confirmed_records: revocationRecords,
    observed_at: ledger.now + 60,
    prior: ledger.baseRepository.repository,
  });
  return CURRENT_PROFILE_ORACLES.map((oracle) => {
    const fixtureName = oracle.semantic_input.assurance_profile_fixture;
    const semanticInput = typeof fixtureName === "string"
      ? assurance[fixtureName as keyof typeof assurance]
      : oracle.semantic_input;
    const input = {
      ...structuredClone(oracle.tuple),
      wire_probe: structuredClone(oracle.wire_probe),
      ...structuredClone(semanticInput),
    };
    let boundaryArgs: readonly unknown[] | undefined;
    if (oracle.semantic_boundary.includes("claim-ledger.mergeClaimLedger")) {
      const request = ledger.requestFor(ledger.claimRecordOne, ledger.claimOne);
      request.verification_context.now = revocationRepository.checkpoint.observed_at;
      boundaryArgs = [
        input,
        [ledger.claimRecordOne, ledger.claimRecordTwo, ledger.grantOne],
        [ledger.claimRecordOne, ledger.claimRecordTwo, ledger.revocationRecord],
        revocationRepository.checkpoint,
        ledger.makeContext(revocationRepository.repository),
        ledger.writerOne.did_key,
        request,
      ];
    }
    return {
      vector_id: oracle.vector_id,
      description:
        `The fixed ${oracle.tuple.profile_id} allocation is checked separately from its live semantic boundary.`,
      direction: "consume" as const,
      input,
      ...(boundaryArgs === undefined ? {} : { boundary_args: boundaryArgs }),
    };
  });
}
