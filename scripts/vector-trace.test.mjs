import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  buildProjection,
  extractSpecAnchors,
  semanticUuid,
  verifyReceipt,
} from "./vector-trace/projection.mjs";
import { readInputs } from "./vector-trace/history.mjs";

const repo = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

function snapshotFixture({ vectorSchema = "2.0.0", manifestOwner = "core", vectorOwner = "core" } = {}) {
  const fixture = mkdtempSync(join(tmpdir(), "vector-snapshot-"));
  execFileSync("git", ["init", "-q"], { cwd: fixture });
  execFileSync("git", ["config", "user.email", "test@example.invalid"], { cwd: fixture });
  execFileSync("git", ["config", "user.name", "Test"], { cwd: fixture });
  for (const name of ["core", "assurance", "comms", "control", "social", "workspace"]) {
    mkdirSync(join(fixture, "docs/spec"), { recursive: true });
    writeFileSync(join(fixture, `docs/spec/heterodyne-${name}.md`), `# ${name}\n\n<a id=\"${name}-anchor\"></a>\nRequirement.\n`);
  }
  mkdirSync(join(fixture, "docs/spec/vectors/generator/src"), { recursive: true });
  for (const path of ["package.json", "package-lock.json", "tsconfig.json", "tsconfig.current.json"]) writeFileSync(join(fixture, "docs/spec/vectors/generator", path), "{}\n");
  writeFileSync(join(fixture, "docs/spec/vectors/generator/vitest.current.config.ts"), "export default {};\n");
  writeFileSync(join(fixture, "docs/spec/vectors/generator/src/core.ts"), "export const value = 1;\n");
  execFileSync("git", ["add", "."], { cwd: fixture });
  execFileSync("git", ["commit", "-qm", "source"], { cwd: fixture });
  const source = execFileSync("git", ["rev-parse", "HEAD"], { cwd: fixture, encoding: "utf8" }).trim();
  const vector = `${JSON.stringify({ vector_id: "not-numbered", vector_schema_version: vectorSchema, owner_document: vectorOwner }, null, 2)}\n`;
  const coverage = `${JSON.stringify([{ vector_id: "not-numbered", owner_document: manifestOwner, spec_refs: ["heterodyne:core#core-anchor"] }], null, 2)}\n`;
  const vectorPath = "docs/spec/vectors/misc/unusual-file-name.json";
  const coveragePath = "docs/spec/vectors/coverage/manifest.json";
  mkdirSync(join(fixture, "docs/spec/vectors/misc"), { recursive: true });
  mkdirSync(join(fixture, "docs/spec/vectors/coverage"), { recursive: true });
  writeFileSync(join(fixture, vectorPath), vector);
  writeFileSync(join(fixture, coveragePath), coverage);
  const hash = (value) => createHash("sha256").update(value).digest("hex");
  writeFileSync(join(fixture, "docs/spec/vectors/snapshot.json"), `${JSON.stringify({ snapshot_schema: "1", source_commit: source, vector_schema_version: vectorSchema, vector_count: 1, artifacts: [{ path: vectorPath, sha256: hash(vector) }, { path: coveragePath, sha256: hash(coverage) }] }, null, 2)}\n`);
  execFileSync("git", ["add", "."], { cwd: fixture });
  execFileSync("git", ["commit", "-qm", "snapshot"], { cwd: fixture });
  return fixture;
}

test("semanticUuid is stable and type-separated", () => {
  assert.equal(semanticUuid("spec_anchor", "heterodyne:core#identity"), "1c3a76c8-93ef-559b-b2fa-d0bc93fd6ff2");
  assert.notEqual(semanticUuid("vector", "heterodyne:core#identity"), semanticUuid("spec_anchor", "heterodyne:core#identity"));
});

test("extractSpecAnchors bounds unnumbered heading and paragraph anchors", () => {
  const items = extractSpecAnchors({
    owner: "core",
    path: "docs/spec/heterodyne-core.md",
    content: "# Intro\n\n<a id=\"intro\"></a>\nA paragraph.\n\n<a id=\"details\"></a>\n## Details\nMore.\n",
  });
  assert.deepEqual(items.map(({ semantic_id, heading, evidence_kind }) => ({ semantic_id, heading, evidence_kind })), [
    { semantic_id: "heterodyne:core#intro", heading: "Intro", evidence_kind: "normative_spec" },
    { semantic_id: "heterodyne:core#details", heading: "Details", evidence_kind: "normative_spec" },
  ]);
  assert.notEqual(items[0].source_digest, items[1].source_digest);
});

test("buildProjection requires an explicit lane", async () => {
  await assert.rejects(buildProjection({ repo }), /lane is required/);
});

test("draft projection inventories current source inputs without vectors", async () => {
  const projection = await buildProjection({ repo, lane: "draft" });
  assert.equal(projection.receipt.spec_ref, "WORKTREE");
  assert.equal(projection.items.some((item) => item.type === "vector"), false);
  assert.equal(projection.items.every((item) => item.evidence_kind && item.source_digest), true);
  assert.deepEqual(verifyReceipt(projection), { fresh: true, issues: [] });
  assert.equal(Object.keys(projection).includes("sourceContents"), false);
  assert.equal(projection.sourceContents instanceof Map, true);
});

test("snapshot projection validates schema 3 vectors and declared owners", async () => {
  const projection = await buildProjection({ repo, lane: "snapshot" });
  const vector = projection.items.find((item) => item.semantic_id === "vector:assurance/associated-key-expired");
  assert.equal(vector.owner, "assurance");
  assert.equal(vector.evidence_kind, "historical_vector");
  assert.equal(projection.edges.every((edge) => edge.source_path), true);
  assert.match(projection.receipt.graph_sha256, /^[0-9a-f]{64}$/);
});

test("snapshot projection supports historical schema 2 and matches actual vector_id rather than its path", async () => {
  const fixture = snapshotFixture();
  const projection = await buildProjection({ repo: fixture, lane: "snapshot" });
  const vector = projection.items.find((candidate) => candidate.type === "vector");
  assert.equal(vector.semantic_id, "vector:not-numbered");
  assert.equal(vector.source_path, "docs/spec/vectors/misc/unusual-file-name.json");
});

test("snapshot projection rejects an incorrect declared owner", async () => {
  const fixture = snapshotFixture({ vectorOwner: "social" });
  await assert.rejects(buildProjection({ repo: fixture, lane: "snapshot" }), /incorrect declared owner/);
});

test("readInputs reads immutable commits and refuses symlink worktree inputs", () => {
  const fixture = mkdtempSync(join(tmpdir(), "vector-trace-"));
  execFileSync("git", ["init", "-q"], { cwd: fixture });
  execFileSync("git", ["config", "user.email", "test@example.invalid"], { cwd: fixture });
  execFileSync("git", ["config", "user.name", "Test"], { cwd: fixture });
  mkdirSync(join(fixture, "docs/spec/registry"), { recursive: true });
  writeFileSync(join(fixture, "docs/spec/registry/a.json"), "{}\n");
  execFileSync("git", ["add", "."], { cwd: fixture });
  execFileSync("git", ["commit", "-qm", "fixture"], { cwd: fixture });
  const committed = readInputs(fixture, "HEAD", { paths: ["docs/spec/registry/a.json"] });
  assert.equal(committed.contents.get("docs/spec/registry/a.json"), "{}\n");
  writeFileSync(join(fixture, "outside"), "secret");
  execFileSync("ln", ["-s", "../../../outside", "docs/spec/registry/link.json"], { cwd: fixture });
  assert.throws(() => readInputs(fixture, "WORKTREE", { roots: ["docs/spec/registry"] }), /symlink input is not allowed/);
});
