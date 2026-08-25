import { describe, expect, it } from "vitest";
import { cp, mkdir, mkdtemp, readdir, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildAgentModerationVectors } from "./topics-agent-moderation.js";

const runtimePrefix = "heterodyne-snapshot-topic-runtime-";

describe("snapshot-only frozen topic runtime", () => {
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
    const sandbox = await mkdtemp(join(tmpdir(), "snapshot-runtime-copy-test-"));
    const source = fileURLToPath(new URL("./snapshot-topic-runtime.ts", import.meta.url));
    const copiedGenerator = join(sandbox, "docs/spec/vectors/generator");
    const copiedSource = join(copiedGenerator, "src/snapshot-topic-runtime.ts");
    await mkdir(dirname(copiedSource), { recursive: true });
    await cp(source, copiedSource);
    await symlink(resolve(dirname(source), "../node_modules"), join(copiedGenerator, "node_modules"));
    const before = new Set((await readdir(tmpdir())).filter((name) => name.startsWith(runtimePrefix)));
    let after: string[] = [];
    try {
      const isolated = await import(`${pathToFileURL(copiedSource).href}?copy=${Date.now()}`) as {
        buildSnapshotAgentModerationVectors: () => Promise<unknown>;
      };
      await expect(isolated.buildSnapshotAgentModerationVectors())
        .rejects.toThrow(/snapshot-runtime-tsconfig-missing/);
      after = (await readdir(tmpdir())).filter((name) => name.startsWith(runtimePrefix));
    } finally {
      for (const name of after) {
        if (!before.has(name)) await rm(join(tmpdir(), name), { recursive: true, force: true });
      }
      await rm(sandbox, { recursive: true, force: true });
    }
    expect(new Set(after)).toEqual(before);
  });
});
