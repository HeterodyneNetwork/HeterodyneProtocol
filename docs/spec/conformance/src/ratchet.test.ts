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
  it("serializes the exact closed shape with sorted keys and one final LF", () => {
    expect(serializeBaseline("G2", ["z", "a", "a"])).toBe(
      '{\n  "gate": "G2",\n  "failures": [\n    "a",\n    "z"\n  ]\n}\n',
    );
  });

  it("loads a canonical baseline for its own gate", () => {
    expect(parseBaseline(
      '{\n  "gate": "G1",\n  "failures": [\n    "a",\n    "b"\n  ]\n}\n',
      "G1",
    )).toEqual({ gate: "G1", failures: ["a", "b"] });
  });

  it("rejects extra members, wrong gate IDs, and non-canonical failure order", () => {
    expect(() => parseBaseline(
      '{"gate":"G1","failures":[],"extra":true}',
      "G1",
    )).toThrow("exactly gate and failures");
    expect(() => parseBaseline('{"gate":"G2","failures":[]}', "G1"))
      .toThrow("must identify G1");
    expect(() => parseBaseline('{"gate":"G1","failures":["b","a"]}', "G1"))
      .toThrow("sorted unique strings");
  });
});
