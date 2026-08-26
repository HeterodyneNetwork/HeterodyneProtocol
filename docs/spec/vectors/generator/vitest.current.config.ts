import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

const project = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "tsconfig.current.json"), "utf8"),
) as { include: string[]; exclude: string[] };

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    exclude: project.exclude,
    maxWorkers: 4,
  },
});
