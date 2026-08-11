import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorAllVectors } from "./author.js";
import {
  INACTIVE_PROFILE_IDS,
  PENDING_PROFILE_IDS,
  buildCoverage,
  findProfileCoverageIssues,
  writeCoverage,
} from "./coverage.js";
import { buildFixtures } from "./fixtures.js";
import { loadRegistry } from "./registry.js";
import { buildAllVectors } from "./topics.js";

const tempDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs.length = 0;
});

describe("family coverage", () => {
  it("is a sorted lossless revision-5 projection with active Control coverage", async () => {
    const vectors = (await buildAllVectors(buildFixtures())).map(({ vector }) => vector);
    const coverage = buildCoverage(vectors);
    expect(coverage.map(({ vector_id }) => vector_id)).toEqual(
      [...coverage.map(({ vector_id }) => vector_id)].sort(),
    );
    expect(new Set(coverage.map(({ vector_id }) => vector_id)).size).toBe(vectors.length);
    expect(coverage.every(({ registry_revision }) => registry_revision === 5)).toBe(true);
    expect(coverage.filter(({ owner_document }) => owner_document === "control")).toHaveLength(32);
    expect(coverage).toContainEqual(expect.objectContaining({
      vector_id: "control/invitation-enrollment-only",
      profile: "heterodyne-control-marmot-frame-v1",
      spec_refs: ["heterodyne:control/0.5.0#control-invitation-policy"],
    }));
    expect(coverage).toContainEqual(expect.objectContaining({
      vector_id: "control/sftp-grant-expired",
      spec_refs: ["heterodyne:control/0.5.0#control-sftp-recovery"],
    }));
    const registry = loadRegistry(resolve(import.meta.dirname, "../../../../../"));
    expect(findProfileCoverageIssues(registry, coverage)).toEqual([]);
    expect(PENDING_PROFILE_IDS).toEqual([]);
    expect(INACTIVE_PROFILE_IDS).toEqual([]);
  }, 30_000);

  it("rejects an unlisted uncovered profile", async () => {
    const coverage = buildCoverage(
      (await buildAllVectors(buildFixtures())).map(({ vector }) => vector),
    );
    const registry = structuredClone(loadRegistry(resolve(import.meta.dirname, "../../../../../")));
    registry.kinds[0].profiles.push({
      profile_id: "unlisted-future-profile",
      owner: "comms",
      discriminator: "test:unlisted",
      stamping: false,
      first_version: "comms/0.5.0",
      status: "draft",
    });
    expect(findProfileCoverageIssues(registry, coverage)).toEqual([
      "uncovered profile: unlisted-future-profile",
    ]);
  }, 30_000);

  it("writes deterministic active-Control Markdown from the manifest", async () => {
    const vectorRoot = await mkdtemp(join(tmpdir(), "heterodyne-vector-coverage-"));
    tempDirs.push(vectorRoot);
    await authorAllVectors(vectorRoot);
    await writeCoverage(vectorRoot);
    const first = await readFile(join(vectorRoot, "coverage", "control.md"), "utf8");
    await writeCoverage(vectorRoot);
    const second = await readFile(join(vectorRoot, "coverage", "control.md"), "utf8");
    expect(second).toBe(first);
    expect(first).toContain("Status: `conformant`");
    expect(first).toContain("control/invitation-enrollment-only");
    expect(first).toContain("control/sftp-grant-expired");
  }, 30_000);
});
