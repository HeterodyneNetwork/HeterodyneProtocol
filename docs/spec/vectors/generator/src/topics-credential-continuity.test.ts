import { describe, expect, it } from "vitest";
import { buildCredentialContinuityVectors } from "./topics-credential-continuity.js";

describe("transport-independent credential-continuity vectors", () => {
  it("authors the exact unprofiled revision-5 draft corpus", () => {
    const vectors = buildCredentialContinuityVectors();
    expect(vectors.map(({ vector }) => vector.vector_id)).toEqual([
      "credential-continuity/checkpoint-genesis",
      "credential-continuity/stale-generation",
      "credential-continuity/pending-retirement-conservative",
      "credential-continuity/retention-inventory-genesis",
      "credential-continuity/governed-obligation-equation",
      "credential-continuity/routine-removal-complete",
      "credential-continuity/cold-root-exposure-migrates",
      "credential-continuity/candidate-exact-tip-append",
      "credential-continuity/config-git-raw-projection",
      "credential-continuity/seventeen-schemas-draft",
    ]);
    for (const { vector } of vectors) {
      expect(vector.owner_document).toBe("comms");
      expect(vector.owner_version).toBe("comms/0.5.0");
      expect(vector.dependency_versions).toEqual({ core: "core/0.5.0" });
      expect(vector.registry_revision).toBe(6);
      expect(vector.profile).toBeUndefined();
      expect(vector.spec_refs).toEqual([
        "heterodyne:comms/0.5.0#comms-credential-continuity",
      ]);
      expect(vector.expected_output).toMatchObject({
        verdict: "accept",
        normalized: {
          selected_registry_revision: 6,
          conformance_claimable: false,
        },
      });
    }
  });

  it("keeps pure draft decisions nested rather than publishing wire rejections", () => {
    const stale = buildCredentialContinuityVectors().find(
      ({ vector }) =>
        vector.vector_id === "credential-continuity/stale-generation",
    )!.vector;
    expect(stale.direction).toBe("consume");
    expect(stale.expected_output.verdict).toBe("accept");
    expect(stale.expected_output.reason_code).toBeUndefined();
    expect(stale.expected_output.normalized).toMatchObject({
      draft_credential_continuity_decision: {
        verdict: "reject",
        reason: "credential_generation_stale",
      },
      conformance_claimable: false,
    });
  });
});
