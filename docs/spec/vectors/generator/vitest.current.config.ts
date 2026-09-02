import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

const project = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "tsconfig.current.json"), "utf8"),
) as { include: string[]; exclude: string[] };

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    // Package authoring is exercised in the current test lane, but its
    // lifecycle-only snapshot imports remain outside the current type graph.
    exclude: project.exclude.filter((path) => path !== "src/current-package.test.ts"),
    maxWorkers: 1,
    fileParallelism: false,
    testTimeout: 15_000,
  },
});
