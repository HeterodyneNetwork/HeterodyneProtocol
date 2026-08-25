import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

const project = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "tsconfig.current.json"), "utf8"),
) as { include: string[] };

export default defineConfig({
  test: {
    include: project.include.filter((path) => path.endsWith(".test.ts")),
    maxWorkers: 4,
  },
});
