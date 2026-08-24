import { describe, expect, it } from "vitest";
import {
  assertAllowedDependency,
  assertCurrentFamilyVersion,
  DOCUMENTS,
  DOCUMENT_LAYERING,
  FAMILY_VERSION,
  negotiateExactFamilyVersion,
  parseFamilyVersion,
  QUALIFIED_VERSION,
} from "./family.js";

describe("protocol document family", () => {
  it("parses the single family version", () => {
    expect(QUALIFIED_VERSION).toBe(`heterodyne/${FAMILY_VERSION}`);
    expect(parseFamilyVersion("heterodyne/0.5.0")).toBe("0.5.0");
    expect(parseFamilyVersion("heterodyne/1.2.3-rc.1+build.5")).toBe(
      "1.2.3-rc.1+build.5",
    );
    expect(() => parseFamilyVersion("0.5.0")).toThrow("invalid family version");
    expect(() => parseFamilyVersion("core/0.5.0")).toThrow(
      "invalid family version",
    );
  });

  it("rejects a version other than the current release", () => {
    expect(() => assertCurrentFamilyVersion(QUALIFIED_VERSION)).not.toThrow();
    expect(() => assertCurrentFamilyVersion("heterodyne/0.4.0")).toThrow(
      QUALIFIED_VERSION,
    );
  });

  it("negotiates only the exact current family version", () => {
    expect(negotiateExactFamilyVersion(
      ["heterodyne/0.5.0"],
      ["heterodyne/0.5.0"],
    )).toBe("heterodyne/0.5.0");
    expect(negotiateExactFamilyVersion(
      ["heterodyne/0.5.0"],
      ["heterodyne/0.4.0"],
    )).toBeNull();
    expect(negotiateExactFamilyVersion(
      ["core/0.5.0"],
      ["core/0.5.0"],
    )).toBeNull();
  });

  it("enforces the document layering DAG", () => {
    expect(DOCUMENTS).toEqual([
      "core",
      "assurance",
      "comms",
      "control",
      "social",
      "workspace",
    ]);
    expect(DOCUMENT_LAYERING).toEqual({
      core: [],
      assurance: ["core"],
      comms: ["core"],
      control: ["core", "comms"],
      social: ["core", "comms"],
      workspace: ["core", "comms", "control", "social"],
    });
    expect(() => assertAllowedDependency("core", "comms")).toThrow(
      "forbidden dependency",
    );
    expect(() => assertAllowedDependency("assurance", "comms")).toThrow(
      "forbidden dependency",
    );
    expect(() => assertAllowedDependency("social", "control")).toThrow(
      "forbidden dependency",
    );
    expect(() => assertAllowedDependency("control", "workspace")).toThrow(
      "forbidden dependency",
    );
    for (const [document, dependency] of [
      ["assurance", "core"],
      ["comms", "core"],
      ["control", "core"],
      ["control", "comms"],
      ["social", "comms"],
      ["workspace", "core"],
      ["workspace", "comms"],
      ["workspace", "control"],
      ["workspace", "social"],
    ] as const) {
      expect(() => assertAllowedDependency(document, dependency)).not.toThrow();
    }
    expect(DOCUMENT_LAYERING.core).toEqual([]);
    for (const document of ["comms", "control", "social", "workspace"] as const) {
      expect(DOCUMENT_LAYERING[document]).not.toContain("assurance");
    }
  });
});
