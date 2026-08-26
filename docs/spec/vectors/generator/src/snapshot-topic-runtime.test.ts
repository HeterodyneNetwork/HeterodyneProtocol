import { describe, expect, it } from "vitest";
import { cp, mkdir, mkdtemp, readdir, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildFixtures } from "./fixtures.js";
import {
  isContainedRelativePath,
  snapshotRuntimeModuleUrl,
} from "./snapshot-runtime-module-url.js";
import { buildAgentModerationVectors } from "./topics-agent-moderation.js";
import { buildSnapshotCompatibleVectors } from "./snapshot-topic-runtime.js";

const runtimePrefix = "heterodyne-snapshot-topic-runtime-";

describe("snapshot-only frozen topic runtime", () => {
  it("compiles and executes the complete frozen allTopics graph", async () => {
    const vectors = await buildSnapshotCompatibleVectors(buildFixtures());
    const vectorsById = new Map(vectors.map(({ vector }) => [vector.vector_id, vector]));

    expect(vectors).toHaveLength(499);
    expect(vectorsById.get("claims/claim-id-mismatch")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "claim-id-mismatch" });
    expect(vectorsById.get("token-status/issuer-successor")).toBeDefined();
    expect(vectorsById.get("token-status/valid-status-list")).toBeDefined();
    expect(vectorsById.get("agent-authorship/delegation-valid")?.expected_output)
      .toMatchObject({ verdict: "accept" });
    expect(vectorsById.get("workspace-key/noncanonical-recipient-rejected")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "workspace_schema_invalid" });
  }, 30_000);

  it("rejects a computed module target outside the disposable runtime root", async () => {
    const runtimeRoot = await mkdtemp(join(tmpdir(), runtimePrefix));
    const outsideRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-outside-"));
    try {
      const inside = join(runtimeRoot, "inside.js");
      const outside = join(outsideRoot, "outside.js");
      await cp(fileURLToPath(new URL("./snapshot-topic-runtime.ts", import.meta.url)), inside);
      await cp(fileURLToPath(new URL("./snapshot-topic-runtime.ts", import.meta.url)), outside);
      expect(snapshotRuntimeModuleUrl(runtimeRoot, inside)).toMatch(/^file:.*\?runtime=\d+$/);
      expect(() => snapshotRuntimeModuleUrl(runtimeRoot, outside))
        .toThrow(/outside-disposable-root/);
    } finally {
      await rm(runtimeRoot, { recursive: true, force: true });
      await rm(outsideRoot, { recursive: true, force: true });
    }
  });

  it.each([
    ["nested/module.js", true],
    ["../outside.js", false],
    ["..\\outside.js", false],
    ["/absolute/module.js", false],
    ["D:\\other-drive\\module.js", false],
    ["\\\\server\\share\\module.js", false],
  ])("classifies portable relative containment for %s", (relativePath, expected) => {
    expect(isContainedRelativePath(relativePath)).toBe(expected);
  });

  it("executes the frozen legacy moderation builder through the isolated adapter", async () => {
    await expect(buildAgentModerationVectors())
      .rejects.toThrow(/agent-policy-receipt-invalid/);

    const runtime = await import("./snapshot-topic-runtime.js").catch(() => ({}));
    const build = (runtime as {
      buildSnapshotAgentModerationVectors?: () => ReturnType<
        typeof buildAgentModerationVectors
      >;
    }).buildSnapshotAgentModerationVectors;
    const vectors = await build?.();
    expect(vectors?.find(({ vector }) =>
      vector.vector_id === "agent-moderation/receipt-valid")?.vector)
      .toEqual(expect.objectContaining({
      vector_id: "agent-moderation/receipt-valid",
      expected_output: expect.objectContaining({ verdict: "accept" }),
      }));
  });

  it("removes the disposable tree when construction fails before returning", async () => {
    const runtimeRoot = await mkdtemp(join(tmpdir(), runtimePrefix));
    const source = fileURLToPath(new URL("./snapshot-topic-runtime.ts", import.meta.url));
    const copiedGenerator = join(runtimeRoot, "docs/spec/vectors/generator");
    const emittedTopic = join(
      runtimeRoot,
      "docs/spec/vectors/generator/src/snapshot-topic-runtime.ts",
    );
    const helperSource = fileURLToPath(
      new URL("./snapshot-runtime-module-url.ts", import.meta.url),
    );
    const copiedHelper = join(
      copiedGenerator,
      "src/snapshot-runtime-module-url.ts",
    );
    await mkdir(dirname(emittedTopic), { recursive: true });
    await cp(source, emittedTopic);
    await cp(helperSource, copiedHelper);
    await symlink(resolve(dirname(source), "../node_modules"), join(copiedGenerator, "node_modules"));
    const before = new Set((await readdir(tmpdir())).filter((name) => name.startsWith(runtimePrefix)));
    let after: string[] = [];
    try {
      const isolated = await import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic)) as {
        buildSnapshotAgentModerationVectors: () => Promise<unknown>;
      };
      await expect(isolated.buildSnapshotAgentModerationVectors())
        .rejects.toThrow(/snapshot-runtime-tsconfig-missing/);
      after = (await readdir(tmpdir())).filter((name) => name.startsWith(runtimePrefix));
    } finally {
      for (const name of after) {
        if (!before.has(name)) await rm(join(tmpdir(), name), { recursive: true, force: true });
      }
      await rm(runtimeRoot, { recursive: true, force: true });
    }
    expect(new Set(after)).toEqual(before);
  });
});
