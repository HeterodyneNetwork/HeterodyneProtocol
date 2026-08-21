import { describe, expect, it } from "vitest";
import { VECTOR_SCHEMA } from "./schema.js";
import type { RawVector } from "./types.js";
import {
  preservesVectorBehavior,
  normalizeSnapshotVector,
  validateRawVector,
  validateSnapshotVector,
} from "./snapshot-envelope.js";

function rawVector(): RawVector {
  return {
    vector_id: "identity/root-attestation-valid",
    vector_schema_version: "1.1.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: ["heterodyne:0.5.0#core-root-attestation"],
    description: "root attestation is reproduced byte-identically",
    direction: "produce",
    input: { event: { kind: 1, tags: [] } },
    expected_output: { verdict: "accept", canonical_wire: "[0,...]" },
  };
}

describe("snapshot envelope", () => {
  it("removes draft version and qualifies one legacy ref", () => {
    const raw = rawVector();
    expect(() => validateRawVector(raw, VECTOR_SCHEMA)).not.toThrow();

    const packaged = normalizeSnapshotVector(raw);

    expect(packaged).toMatchObject({
      vector_schema_version: "2.0.0",
      owner_document: "core",
      spec_refs: ["heterodyne:core#core-root-attestation"],
    });
    expect(packaged).not.toHaveProperty("spec_version");
    expect(() => validateSnapshotVector(packaged)).not.toThrow();
  });

  it("preserves behavioral fields", () => {
    const raw = {
      ...rawVector(),
      profile: "signed-event",
      conformance_checks: [{
        profile: "core-signed-event-v1",
        event_pointer: "/input/event",
        nip01_raw_pointer: "/input/nip01_raw",
        expected_terminal_stage: "signature",
      }],
    };

    const packaged = normalizeSnapshotVector(raw);

    expect({
      vector_id: packaged.vector_id,
      direction: packaged.direction,
      input: packaged.input,
      expected_output: packaged.expected_output,
      profile: packaged.profile,
      conformance_checks: packaged.conformance_checks,
    }).toEqual({
      vector_id: raw.vector_id,
      direction: raw.direction,
      input: raw.input,
      expected_output: raw.expected_output,
      profile: raw.profile,
      conformance_checks: raw.conformance_checks,
    });
  });

  it("does not invent conformance declarations", () => {
    const packaged = normalizeSnapshotVector(rawVector());

    expect(Object.hasOwn(packaged, "conformance_checks")).toBe(false);
  });

  it("rejects unknown owner document", () => {
    expect(() => normalizeSnapshotVector({
      ...rawVector(),
      owner_document: "unknown",
    })).toThrow(/owner_document/);
  });

  it("rejects malformed legacy ref", () => {
    expect(() => normalizeSnapshotVector({
      ...rawVector(),
      spec_refs: ["heterodyne:0.5.0#not_a_stable_anchor"],
    })).toThrow(/spec_refs/);
  });

  it("rejects spec_version in schema 2", () => {
    expect(() => validateSnapshotVector({
      ...normalizeSnapshotVector(rawVector()),
      spec_version: "heterodyne/0.5.0",
    })).toThrow(/additional/);
  });

  it("compares optional profile and conformance declaration presence and values", () => {
    const raw = rawVector();
    const packaged = normalizeSnapshotVector(raw);

    expect(preservesVectorBehavior(raw, packaged)).toBe(true);
    expect(preservesVectorBehavior(
      { ...raw, profile: "signed-event" },
      packaged,
    )).toBe(false);
    expect(preservesVectorBehavior(
      { ...raw, conformance_checks: [] },
      packaged,
    )).toBe(false);
  });
});
