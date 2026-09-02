import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import currentVitestConfig from "../vitest.current.config.js";
import { assertExactCurrentModuleGraph } from "./current-import-graph.js";
import { CURRENT_MODULE_ALLOWLIST } from "./current-module-allowlist.js";

const generatorRoot = resolve(import.meta.dirname, "..");
const currentCatalogEntry = resolve(import.meta.dirname, "current-vectors/index.ts");
const retiredCurrentSources = [
  "src/kel.ts",
  "src/kel-replay.ts",
  "src/kel-replay.test.ts",
  "src/keri-materialized.ts",
  "src/keri-materialized.test.ts",
  "src/legacy-agent-delegation.ts",
  "src/legacy-agent-delegation.test.ts",
] as const;

describe("current-draft compiler and Vitest boundary", () => {
  it("bounds current-draft file execution to one worker", () => {
    expect(currentVitestConfig.test).toMatchObject({
      maxWorkers: 1,
      fileParallelism: false,
      testTimeout: 15_000,
    });
  });

  it("matches the exact reviewed current-source module graph", () => {
    expect(() => assertExactCurrentModuleGraph(
      currentCatalogEntry,
      CURRENT_MODULE_ALLOWLIST,
    )).not.toThrow();
  }, 60_000);

  it("does not compile retired KEL or caller-asserted delegation units", () => {
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
    expect(listed).not.toContain("src/legacy-agent-delegation.test.ts");
  }, 30_000);
});
