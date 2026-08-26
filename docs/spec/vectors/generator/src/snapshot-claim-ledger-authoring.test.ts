import { describe, expect, it } from "vitest";
import { buildFixtures } from "./snapshot-fixtures-adapter.js";
import {
  buildSnapshotClaimLedgerVectors,
  replaySnapshotClaimLedgerVectors,
} from "./snapshot-topic-runtime.js";

const fixtures = buildFixtures();

describe("Task 4 vector closure", () => {
  it("authors the exact thirteen vectors from executable decisions", async () => {
    const vectors = await buildSnapshotClaimLedgerVectors(fixtures);
    expect(vectors).toHaveLength(13);
    expect(vectors.map(({ relativePath }) => relativePath)).toEqual(
      Array.from({ length: 13 }, (_, index) => `claim-ledger/${(index + 1).toString().padStart(3, "0")}-${[
        "reader-nid-authorized", "nidless-reader-denied", "delivered-grant-provisional", "immediate-revocation",
        "multiwriter-revocation-wins", "authority-reduction-wins", "nonmonotonic-conflict-blocks",
        "checkpoint-rollback-rejected", "keyed-path-metadata-private", "reader-removal-key-rotation",
        "multiwriter-status-allocation", "stale-minter-denied", "source-claim-revokes-token",
      ][index]}.json`),
    );
    const rollback = vectors.find(({ vector }) => vector.vector_id.endsWith("checkpoint-rollback-rejected"))!.vector;
    expect(rollback.expected_output).toEqual({ verdict: "reject", reason_code: "claim-ledger-rollback" });
    const privacy = vectors.find(({ vector }) => vector.vector_id.endsWith("keyed-path-metadata-private"))!.vector;
    expect((privacy.expected_output.normalized as { changed_entries: number }).changed_entries).toBe(256);
    const multiwriter = vectors.find(({ vector }) => vector.vector_id.endsWith("multiwriter-status-allocation"))!.vector;
    const multiwriterOutput = multiwriter.expected_output.normalized as any;
    expect(multiwriter.expected_output.verdict).toBe("accept");
    expect(multiwriterOutput.writers.map(({ eligibility }: any) => eligibility.allowed)).toEqual([true, true]);
    expect(new Set(multiwriterOutput.writers.map(({ signing_key_id }: any) => signing_key_id)).size).toBe(1);
    expect(multiwriterOutput.unique_allocation_count).toBe(2);
    expect(multiwriterOutput.durable_before_return).toBe(true);

    const stale = vectors.find(({ vector }) => vector.vector_id.endsWith("stale-minter-denied"))!.vector;
    const staleOutput = stale.expected_output.normalized as any;
    expect(staleOutput.boundary_300.allowed).toBe(true);
    expect(staleOutput.boundary_301.reason_code).toBe("oidc-checkpoint-stale");
    expect(staleOutput.zero_bound_exact.allowed).toBe(true);
    expect(staleOutput.zero_bound_after_one.reason_code).toBe("oidc-checkpoint-stale");
    expect(staleOutput.removal).toMatchObject({ allowed: false, pending_rotation: true, reason_code: "oidc-signing-key-unavailable" });
    expect(staleOutput.post_rotation).toMatchObject({ allowed: true, pending_rotation: false });
    expect(staleOutput.rotated_key.audience_key_id).not.toBe(staleOutput.rotated_key.previous_key_id);
    expect(staleOutput.issuer_epoch_fork).toEqual({
      verdict: "reject", reason_code: "claim-repository-conflict",
    });

    const invalidation = vectors.find(({ vector }) => vector.vector_id.endsWith("source-claim-revokes-token"))!.vector;
    const invalidationOutput = invalidation.expected_output.normalized as any;
    expect(invalidationOutput.converged).toBe(true);
    expect(invalidationOutput.left_token_invalidations).toEqual(["writer_one_token_0001", "writer_two_token_0001"]);
    expect(invalidationOutput.invalidation_record_jtis).toEqual([
      "writer_one_token_0001", "writer_one_token_0001",
      "writer_two_token_0001", "writer_two_token_0001",
    ]);
    expect(invalidationOutput.generated_record_count).toBe(4);
    expect(invalidationOutput.generated_matches_committed).toBe(true);
    expect(invalidationOutput.canonically_durable).toBe(true);
    expect(invalidationOutput.causes).toEqual(["signing-key-compromised", "source-claim-revoked"]);

    const boundaryMutation = structuredClone(stale.input) as any;
    boundaryMutation.evaluation_age = 300;

    const invalidationMutation = structuredClone(invalidation.input) as any;
    invalidationMutation.committed_invalidations.pop();
    const multiwriterMutation = structuredClone(multiwriter.input) as any;
    multiwriterMutation.writers[0].audience_key.hex = "00".repeat(32);
    const [boundaryReplay, invalidationReplay, multiwriterReplay] =
      await replaySnapshotClaimLedgerVectors([
        boundaryMutation,
        invalidationMutation,
        multiwriterMutation,
      ]);
    expect(boundaryReplay).toMatchObject({ verdict: "accept" });
    expect(invalidationReplay).toMatchObject({
      verdict: "reject",
      normalized: { generated_matches_committed: false },
    });
    expect(multiwriterReplay).toMatchObject({ verdict: "reject" });
  });
});
