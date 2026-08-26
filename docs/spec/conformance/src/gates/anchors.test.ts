import { describe, expect, it } from "vitest";
import {
  formatSpecificationReference,
  ownerForSpecificationPath,
  parseSpecificationReference,
} from "./anchors.js";

describe("Assurance specification references", () => {
  it("recognizes Assurance as the optional sixth owner", () => {
    expect(parseSpecificationReference("heterodyne:assurance#assurance-continuity"))
      .toEqual({ owner: "assurance", anchor: "assurance-continuity" });
    expect(formatSpecificationReference("assurance", "assurance-continuity"))
      .toBe("heterodyne:assurance#assurance-continuity");
    expect(ownerForSpecificationPath("docs/spec/heterodyne-assurance.md"))
      .toBe("assurance");
  });

  it("rejects an unknown seventh owner", () => {
    expect(parseSpecificationReference("heterodyne:unknown#unknown-anchor")).toBeUndefined();
    expect(ownerForSpecificationPath("docs/spec/heterodyne-unknown.md")).toBeUndefined();
  });
});
