import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorAllVectors, packageSnapshot } from "./author.js";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) =>
    rm(path, { recursive: true, force: true })
  ));
});

describe("current schema-3 snapshot packaging", () => {
  it("retains exact traceability while removing only draft version metadata", async () => {
    const rawRoot = await mkdtemp(join(tmpdir(), "heterodyne-current-raw-"));
    const snapshotRoot = await mkdtemp(join(tmpdir(), "heterodyne-current-package-"));
    temporaryDirectories.push(rawRoot, snapshotRoot);
    const written = await authorAllVectors(rawRoot);

    const manifest = await packageSnapshot(rawRoot, snapshotRoot, "1".repeat(40));
    const relativePath = written.find((path) => path === "core/replaceable-future-quarantined.json")!;
    const raw = JSON.parse(await readFile(join(rawRoot, relativePath), "utf8"));
    const packaged = JSON.parse(await readFile(
      join(snapshotRoot, "docs/spec/vectors", relativePath),
      "utf8",
    ));
    const schema = JSON.parse(await readFile(
      join(snapshotRoot, "docs/spec/vectors/schema/vector.schema.json"),
      "utf8",
    ));
    const fixtures = JSON.parse(await readFile(
      join(snapshotRoot, "docs/spec/vectors/fixtures.json"),
      "utf8",
    ));

    expect(manifest).toMatchObject({ vector_schema_version: "3.0.0", vector_count: written.length });
    expect(schema.properties.vector_schema_version).toEqual({ const: "3.0.0" });
    expect(packaged).toMatchObject({
      vector_schema_version: "3.0.0",
      invariants: raw.invariants,
      reason_codes: raw.reason_codes,
      expected_output: raw.expected_output,
    });
    expect(packaged).not.toHaveProperty("spec_version");
    expect(packaged.spec_refs).toEqual(["heterodyne:core#core-created-at-bound"]);
    expect(fixtures.vector_schema_version).toBe("3.0.0");
    expect(fixtures).not.toHaveProperty("spec_version");
  }, 60_000);
});
