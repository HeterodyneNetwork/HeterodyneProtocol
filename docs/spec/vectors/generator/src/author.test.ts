import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorAllVectors } from "./author.js";
import { TOPIC_SPECS } from "./topics.js";
import { verifyVectorTree } from "./verify.js";

let tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe("author mode", () => {
  it("authors at least one schema-valid vector for every ADR-024 topic", async () => {
    const outputDir = await mkdtemp(join(tmpdir(), "heterodyne-vectors-"));
    tempDirs.push(outputDir);

    const written = await authorAllVectors(outputDir);
    const topics = new Set(written.map((path) => path.split("/")[0]));

    for (const topic of Object.keys(TOPIC_SPECS)) {
      expect(topics.has(topic)).toBe(true);
    }

    const result = await verifyVectorTree(outputDir);
    expect(result.validFiles).toBe(written.length);
    expect(result.errors).toEqual([]);

    const identity = JSON.parse(
      await readFile(join(outputDir, "identity", "001-root-attestation-valid.json"), "utf8"),
    );
    expect(identity.spec_version).toBe("0.4.0");
    expect(identity.expected_output.canonical_wire).toContain('["heterodyne","root"]');
    expect(identity.expected_output.canonical_wire).toContain("31000");
    expect(identity.expected_output.id).toHaveLength(64);
    expect(identity.expected_output.sig).toHaveLength(128);
  });
});
