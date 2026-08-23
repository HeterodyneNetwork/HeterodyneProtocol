import { describe, expect, it } from "vitest";
import {
  compareBaseline,
  parseBaseline,
  serializeBaseline,
} from "./ratchet.js";

describe("compareBaseline", () => {
  it("reports debt removed from the measured set as stale", () => {
    expect(compareBaseline(["a"], ["a", "b"]))
      .toEqual({ newFailures: [], staleFailures: ["b"] });
  });

  it("reports debt absent from the committed baseline as new", () => {
    expect(compareBaseline(["a", "b"], ["a"]))
      .toEqual({ newFailures: ["b"], staleFailures: [] });
  });

  it("accepts two empty failure sets", () => {
    expect(compareBaseline([], []))
      .toEqual({ newFailures: [], staleFailures: [] });
  });

  it("sorts and de-duplicates both ratchet directions", () => {
    expect(compareBaseline(["z", "a", "z"], ["y", "a", "y"]))
      .toEqual({ newFailures: ["z"], staleFailures: ["y"] });
  });
});

describe("baseline documents", () => {
  const sourceCommit = "1".repeat(40);
  const artifactSetSha256 = "a".repeat(64);

  it("serializes the exact snapshot-keyed shape with one final LF", () => {
    expect(serializeBaseline(sourceCommit, artifactSetSha256, "G2", ["z", "a", "a"])).toBe(
      '{\n'
      + `  "source_commit": "${sourceCommit}",\n`
      + `  "artifact_set_sha256": "${artifactSetSha256}",\n`
      + '  "gate": "G2",\n'
      + '  "failures": [\n    "a",\n    "z"\n  ]\n}\n',
    );
  });

  it("loads a canonical baseline for its own gate", () => {
    expect(parseBaseline(
      `${JSON.stringify({
        source_commit: sourceCommit,
        artifact_set_sha256: artifactSetSha256,
        gate: "G1",
        failures: ["a", "b"],
      }, null, 2)}\n`,
      "G1",
    )).toEqual({
      sourceCommit,
      artifactSetSha256,
      gate: "G1",
      failures: ["a", "b"],
    });
  });

  it("rejects release identity, snapshot commits, and malformed snapshot identity", () => {
    expect(() => parseBaseline(
      JSON.stringify({
        source_commit: sourceCommit,
        artifact_set_sha256: artifactSetSha256,
        gate: "G1",
        failures: [],
        snapshot_commit: "2".repeat(40),
      }),
      "G1",
    )).toThrow("exactly source_commit, artifact_set_sha256, gate, and failures");
    expect(() => parseBaseline(JSON.stringify({
      source_commit: "heterodyne/0.5.0",
      artifact_set_sha256: artifactSetSha256,
      gate: "G1",
      failures: [],
    }), "G1")).toThrow("source_commit must be 40-lowercase-hex");
    expect(() => parseBaseline(JSON.stringify({
      source_commit: sourceCommit,
      artifact_set_sha256: "invalid",
      gate: "G1",
      failures: [],
    }), "G1")).toThrow("artifact_set_sha256 must be 64-lowercase-hex");
  });

  it("rejects wrong gate IDs and non-canonical failure order", () => {
    expect(() => parseBaseline(JSON.stringify({
      source_commit: sourceCommit,
      artifact_set_sha256: artifactSetSha256,
      gate: "G2",
      failures: [],
    }), "G1"))
      .toThrow("must identify G1");
    expect(() => parseBaseline(JSON.stringify({
      source_commit: sourceCommit,
      artifact_set_sha256: artifactSetSha256,
      gate: "G1",
      failures: ["b", "a"],
    }), "G1"))
      .toThrow("sorted unique strings");
  });
});
