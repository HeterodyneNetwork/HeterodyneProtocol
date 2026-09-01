import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/snapshot-manifest.test.ts"],
    maxWorkers: 1,
  },
});
