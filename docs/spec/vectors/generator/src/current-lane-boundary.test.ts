import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const generatorRoot = resolve(import.meta.dirname, "..");
const retiredCurrentSources = [
  "src/kel.ts",
  "src/kel-replay.ts",
  "src/kel-replay.test.ts",
  "src/keri-materialized.ts",
  "src/keri-materialized.test.ts",
] as const;

describe("current-draft compiler and Vitest boundary", () => {
  it("does not compile retired Core KEL or materialized-KEL units", () => {
    const configPath = resolve(generatorRoot, "tsconfig.current.json");
    const config = ts.readConfigFile(configPath, ts.sys.readFile);
    const parsed = ts.parseJsonConfigFileContent(
      config.config,
      ts.sys,
      generatorRoot,
      { noEmit: true },
      configPath,
    );
    const program = ts.createProgram({
      rootNames: parsed.fileNames,
      options: parsed.options,
      projectReferences: parsed.projectReferences,
    });
    const compiled = new Set(program.getSourceFiles().map((source) => resolve(source.fileName)));

    expect(retiredCurrentSources.filter((path) => compiled.has(resolve(generatorRoot, path))))
      .toEqual([]);
  });

  it("does not collect retired Core KEL or materialized-KEL tests", () => {
    const listed = execFileSync(
      process.execPath,
      [
        resolve(generatorRoot, "node_modules/vitest/vitest.mjs"),
        "list",
        "--config",
        "vitest.current.config.ts",
      ],
      { cwd: generatorRoot, encoding: "utf8" },
    );

    expect(listed).not.toContain("src/kel-replay.test.ts");
    expect(listed).not.toContain("src/keri-materialized.test.ts");
  });
});
