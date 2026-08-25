import { readFileSync } from "node:fs";
import { resolve } from "node:path";
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

const generatorRoot = resolve(import.meta.dirname, "..");

describe("protocol document family", () => {
  it("keeps current-draft validation independent of frozen vector projections", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(generatorRoot, "package.json"), "utf8"),
    ) as { scripts: Record<string, string> };
    const currentProject = JSON.parse(
      readFileSync(resolve(generatorRoot, "tsconfig.current.json"), "utf8"),
    ) as { include: string[]; exclude: string[] };

    expect(packageJson.scripts["draft:check"])
      .toBe("npm run build:current && npm run test:current && npm run family:check");
    expect(packageJson.scripts["test:current"])
      .toBe("vitest run --config vitest.current.config.ts");
    expect(packageJson.scripts["build:current"])
      .toBe("node scripts/typecheck.mjs tsconfig.current.json");

    expect(currentProject.include).toEqual(["src/**/*.ts"]);
    for (const live of [
      "src/claims.test.ts",
      "src/claim-ledger.test.ts",
      "src/claim-ledger-conformance.test.ts",
      "src/stamping.test.ts",
      "src/one-time-invite.test.ts",
    ]) {
      expect(currentProject.exclude).not.toContain(live);
    }
    expect(currentProject.exclude).toEqual(expect.arrayContaining([
      "src/topics*.ts",
      "src/snapshot*.ts",
    ]));
  });

  it("keeps live OIDC continuity on active-persona authority", () => {
    const currentOidc = ["src/oidc.ts", "src/token-status.ts"]
      .map((path) => readFileSync(resolve(generatorRoot, path), "utf8"))
      .join("\n");
    expect(currentOidc).not.toMatch(
      /cold_root_npub|cold_root_hex|persona_kel_head|core_kel_authority_valid|current-persona-epoch|cold-root-recovery|validateColdRootBinding/,
    );
    expect(currentOidc).toMatch(/persona_npub/);
    expect(currentOidc).toMatch(/persona_key/);
    expect(currentOidc).toMatch(/active-persona/);
  });

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
