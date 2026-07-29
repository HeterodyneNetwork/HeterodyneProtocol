import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorAllVectors } from "./author.js";
import {
  ADR034_PENDING_PROFILE_IDS,
  INACTIVE_PROFILE_IDS,
  buildCoverage,
  findProfileCoverageIssues,
  writeCoverage,
} from "./coverage.js";
import { buildAllVectors } from "./topics.js";
import { buildFixtures } from "./fixtures.js";
import { loadRegistry } from "./registry.js";
import { resolve } from "node:path";

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
    expect(coverage.filter(({ owner_document }) => owner_document === "control")).toEqual([]);
    expect(coverage).toContainEqual(expect.objectContaining({
      vector_id: "stamping/control-profile-retains-core-owner",
      owner_document: "core",
      dependency_versions: {},
      profile: "heterodyne-control-session-device-v1",
      spec_refs: ["heterodyne:core/0.5.0#core-version-stamps"],
    }));
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

    const registry = loadRegistry(resolve(import.meta.dirname, "../../../../../"));
    expect(findProfileCoverageIssues(registry, coverage)).toEqual([]);
    expect(ADR034_PENDING_PROFILE_IDS).toEqual([]);
    expect(INACTIVE_PROFILE_IDS).toEqual([
      "heterodyne-control-session-device-v1",
    ]);
    expect(
      registry.kinds
        .flatMap(({ profiles }) => profiles)
        .find(({ profile_id }) => profile_id === INACTIVE_PROFILE_IDS[0])
        ?.owner,
    ).toBe("control");
    expect(coverage.filter(({ profile }) => profile === "heterodyne-control-session-device-v1"))
      .toHaveLength(1);
  }, 30_000);

  it("fails the staged coverage gate for any unlisted uncovered profile", async () => {
    const vectors = (await buildAllVectors(buildFixtures())).map(({ vector }) => vector);
    const coverage = buildCoverage(vectors);
    const registry = structuredClone(
      loadRegistry(resolve(import.meta.dirname, "../../../../../")),
    );
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

  it("does not exempt an unlisted Control-owned profile", async () => {
    const vectors = (await buildAllVectors(buildFixtures())).map(({ vector }) => vector);
    const coverage = buildCoverage(vectors);
    const registry = structuredClone(
      loadRegistry(resolve(import.meta.dirname, "../../../../../")),
    );
    registry.kinds[0].profiles.push({
      profile_id: "unlisted-control-profile",
      owner: "control",
      discriminator: "test:unlisted-control",
      stamping: false,
      first_version: "control/0.5.0",
      status: "draft",
    });

    expect(findProfileCoverageIssues(registry, coverage)).toContain(
      "uncovered profile: unlisted-control-profile",
    );
  }, 30_000);

  it("permits only the exact inactive profile and currently-uncovered pending set", async () => {
    const vectors = (await buildAllVectors(buildFixtures())).map(({ vector }) => vector);
    const coverage = buildCoverage(vectors).filter(
      ({ profile }) => profile !== INACTIVE_PROFILE_IDS[0],
    );
    const registry = loadRegistry(resolve(import.meta.dirname, "../../../../../"));

    expect(findProfileCoverageIssues(registry, coverage)).toEqual([]);
  }, 30_000);

  it("requires the exact inactive profile to remain Control-owned", async () => {
    const vectors = (await buildAllVectors(buildFixtures())).map(({ vector }) => vector);
    const coverage = buildCoverage(vectors);
    const registry = structuredClone(
      loadRegistry(resolve(import.meta.dirname, "../../../../../")),
    );
    const inactive = registry.kinds
      .flatMap(({ profiles }) => profiles)
      .find(({ profile_id }) => profile_id === INACTIVE_PROFILE_IDS[0])!;
    inactive.owner = "comms";

    expect(findProfileCoverageIssues(registry, coverage)).toContain(
      `inactive profile owner mismatch: ${INACTIVE_PROFILE_IDS[0]}`,
    );
  }, 30_000);

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
  }, 30_000);
});
