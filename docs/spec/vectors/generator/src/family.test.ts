import { describe, expect, it } from "vitest";
import {
  assertAllowedDependency,
  DOCUMENT_DEPENDENCIES,
  OPTIONAL_DOCUMENT_DEPENDENCIES,
  parseQualifiedVersion,
} from "./family.js";

describe("protocol document family", () => {
  it("parses qualified document versions", () => {
    expect(parseQualifiedVersion("core/0.5.0")).toEqual({
      document: "core",
      semver: "0.5.0",
    });
    expect(parseQualifiedVersion("comms/1.2.3-rc.1+build.5")).toEqual({
      document: "comms",
      semver: "1.2.3-rc.1+build.5",
    });
    expect(parseQualifiedVersion("workspace/0.1.0")).toEqual({
      document: "workspace",
      semver: "0.1.0",
    });
    expect(() => parseQualifiedVersion("0.5.0")).toThrow(
      "qualified version",
    );
  });

  it("enforces the allowed document dependency DAG", () => {
    expect(() => assertAllowedDependency("core", "comms")).toThrow(
      "forbidden dependency",
    );
    expect(() => assertAllowedDependency("social", "control")).toThrow(
      "forbidden dependency",
    );
    expect(() => assertAllowedDependency("control", "comms")).not.toThrow();
    expect(() => assertAllowedDependency("control", "core")).not.toThrow();
    expect(() => assertAllowedDependency("social", "comms")).not.toThrow();
    expect(() => assertAllowedDependency("workspace", "core")).not.toThrow();
    expect(() => assertAllowedDependency("workspace", "comms")).not.toThrow();
    expect(() => assertAllowedDependency("workspace", "control")).not.toThrow();
    expect(() => assertAllowedDependency("workspace", "social")).not.toThrow();
    expect(() => assertAllowedDependency("control", "workspace")).toThrow(
      "forbidden dependency",
    );
    expect(DOCUMENT_DEPENDENCIES.workspace).toEqual(["core", "comms"]);
    expect(OPTIONAL_DOCUMENT_DEPENDENCIES.workspace).toEqual(["control", "social"]);
  });
});
