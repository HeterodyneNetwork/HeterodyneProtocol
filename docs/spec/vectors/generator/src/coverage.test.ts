import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorAllVectors } from "./author.js";
import { buildCoverage, writeCoverage } from "./coverage.js";
import { buildAllVectors } from "./topics.js";
import { buildFixtures } from "./fixtures.js";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs.length = 0;
});

describe("family coverage", () => {
  it("is the sorted lossless projection of vector ownership metadata", async () => {
    const vectors = (await buildAllVectors(buildFixtures())).map(({ vector }) => vector);
    const coverage = buildCoverage(vectors);

    expect(coverage.map(({ vector_id }) => vector_id)).toEqual(
      [...coverage.map(({ vector_id }) => vector_id)].sort(),
    );
    expect(new Set(coverage.map(({ vector_id }) => vector_id)).size).toBe(vectors.length);
    expect(coverage).not.toContainEqual(expect.objectContaining({ owner_document: "control" }));
    expect(coverage).toContainEqual(
      expect.objectContaining({
        vector_id: "stamping/tier3-profile-owner",
        owner_document: "core",
        profile: "heterodyne-comms-tier3-wrapped-content-kind-1-v1",
      }),
    );
    const ownerById = new Map(
      coverage.map(({ vector_id, owner_document }) => [vector_id, owner_document]),
    );
    expect(ownerById.get("envelope/minimal-kind1-wrapped")).toBe("social");
    expect(ownerById.get("interop/wrapped-vanilla-roundtrip")).toBe("social");
    expect(ownerById.get("interop/kind31005-identity-pointer")).toBe("core");
    expect(ownerById.get("org/threshold-delegate-governance")).toBe("core");
    expect(ownerById.get("org/canonical-branch-reachability")).toBe("comms");
    expect(ownerById.get("redundancy/dedupe-across-replicas")).toBe("social");
    expect(ownerById.get("config-backup/config-blob-encrypt-decrypt")).toBe("comms");
    expect(ownerById.get("config-backup/nip49-nsec-wrap")).toBe("core");
    expect(ownerById.get("social-recovery/cache-rejects-unauthorized-content")).toBe("core");
    expect(ownerById.get("social-recovery/three-tier-caching")).toBe("social");
    expect(ownerById.get("social-recovery/cold-root-reanchor-authoritative")).toBe("core");
    expect(ownerById.get("social-recovery/cache-sourced-marked-stale")).toBe("core");
    expect(coverage.every(({ spec_refs }) => spec_refs.every((ref) => ref.startsWith("heterodyne:")))).toBe(true);
  });

  it("writes deterministic Markdown views derived from manifest.json", async () => {
    const vectorRoot = await mkdtemp(join(tmpdir(), "heterodyne-vector-coverage-"));
    tempDirs.push(vectorRoot);
    await authorAllVectors(vectorRoot);
    await writeCoverage(vectorRoot);
    const first = await Promise.all(
      ["manifest.json", "core.md", "comms.md", "control.md", "social.md", "family.md"].map(
        (name) => readFile(join(vectorRoot, "coverage", name), "utf8"),
      ),
    );
    await writeCoverage(vectorRoot);
    const second = await Promise.all(
      ["manifest.json", "core.md", "comms.md", "control.md", "social.md", "family.md"].map(
        (name) => readFile(join(vectorRoot, "coverage", name), "utf8"),
      ),
    );

    expect(second).toEqual(first);
    expect(first[3]).toContain("incomplete-draft");
    expect(first[3]).toContain("No Control conformance corpus");
  });
});
