import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorAllVectors } from "./author.js";
import { writeCoverage } from "./coverage.js";
import { verifyVectorTree } from "./verify.js";
import { verifyPackagedSnapshot } from "./verify.js";

const dirs: string[] = [];
afterEach(async () => Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))));

async function authoredTree(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "heterodyne-verify-"));
  dirs.push(dir);
  await authorAllVectors(dir);
  await writeCoverage(dir);
  return dir;
}

describe("closed deterministic vector tree verification", () => {
  it("rejects packaged snapshot bytes that differ from a regenerated staging tree", async () => {
    const expected = await authoredTree();
    const actual = await mkdtemp(join(tmpdir(), "heterodyne-verify-actual-"));
    dirs.push(actual);
    const { cp } = await import("node:fs/promises");
    await cp(expected, actual, { recursive: true });
    await writeFile(join(actual, "fixtures.json"), "changed\n", "utf8");

    await expect(verifyPackagedSnapshot(expected, actual)).rejects.toThrow(/fixtures\.json/);
  }, 30_000);

  it("rejects an extra committed vector file", async () => {
    const dir = await authoredTree();
    const source = await readFile(join(dir, "versioning", "005-qualified-version-valid.json"), "utf8");
    await writeFile(join(dir, "versioning", "999-stale-extra.json"), source, "utf8");
    expect((await verifyVectorTree(dir)).errors.join("\n")).toMatch(/unexpected committed vector/);
  }, 30_000);

  it("rejects a stale manifest and Markdown projection", async () => {
    const dir = await authoredTree();
    await writeFile(join(dir, "coverage", "manifest.json"), "[]\n", "utf8");
    await writeFile(join(dir, "coverage", "core.md"), "# stale\n", "utf8");
    const errors = (await verifyVectorTree(dir)).errors.join("\n");
    expect(errors).toMatch(/coverage\/manifest\.json/);
    expect(errors).toMatch(/coverage\/core\.md/);
  }, 30_000);

  it.each([
    "fixtures.json",
    "schema/vector.schema.json",
    "schema/reason-codes.json",
    "schema/reason-codes.md",
  ])("rejects stale generated projection %s", async (path) => {
    const dir = await authoredTree();
    await writeFile(join(dir, ...path.split("/")), "stale\n", "utf8");
    expect((await verifyVectorTree(dir)).errors.join("\n")).toContain(path);
  }, 30_000);
});
