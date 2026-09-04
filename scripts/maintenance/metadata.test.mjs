import test from "node:test";
import assert from "node:assert/strict";
import { readDeclaredContracts } from "./metadata.mjs";

const repo = new URL("../../", import.meta.url).pathname;

test("current catalog is read statically with declarations and provenance", async () => {
  const result = await readDeclaredContracts({ repo, layout: "current-catalog" });
  assert.equal(result.layout, "current-catalog");
  assert.equal(result.records.length, 267);
  assert.equal(result.records[0].evidenceKind, "declared_current");
  assert.ok(result.records[0].provenance[0].sourceDigest);
});

test("missing catalog is conservative and records unresolved metadata", async () => {
  const result = await readDeclaredContracts({ repo, ref: "HEAD", layout: "current-catalog" });
  assert.ok(Array.isArray(result.unresolved));
});
