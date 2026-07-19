import { describe, expect, it } from "vitest";
import {
  assertAllowedDependency,
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
    expect(() => assertAllowedDependency("social", "comms")).not.toThrow();
  });
});
