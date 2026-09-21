import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";

const run = promisify(execFile);
const sha = (s) => createHash("sha256").update(s).digest("hex");
const catalogPath = "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts";

async function fixture() {
  const repo = await mkdtemp(join(tmpdir(), "reference-guard-"));
  await mkdir(join(repo, "docs/spec/vectors/generator/src/current-vectors"), { recursive: true });
  await mkdir(join(repo, "docs/spec"), { recursive: true });
  const catalog = `const CURRENT_CASE_CONTRACTS = {\n  "comms/one": { owner_document: "comms", spec_refs: ["heterodyne:0.6.0#old-anchor"] },\n  "core/two": { owner_document: "core", spec_refs: ['heterodyne:0.6.0#keep-anchor'] },\n};\n`;
  await writeFile(join(repo, catalogPath), catalog);
  await writeFile(join(repo, "docs/spec/heterodyne-core.md"), "Family version `heterodyne/0.6.0`.\n<a id=\"keep-anchor\"></a>\n");
  await writeFile(join(repo, "docs/spec/heterodyne-comms.md"), "<a id=\"old-anchor\"></a>\n<a id=\"new-anchor\"></a>\n");
  await writeFile(join(repo, "docs/spec/heterodyne-assurance.md"), "<a id=\"unused\"></a>\n");
  await writeFile(join(repo, "docs/spec/heterodyne-control.md"), "<a id=\"unused\"></a>\n");
  await writeFile(join(repo, "docs/spec/heterodyne-social.md"), "<a id=\"unused\"></a>\n");
  await writeFile(join(repo, "docs/spec/heterodyne-workspace.md"), "<a id=\"unused\"></a>\n");
  await run("git", ["init", "-q", "-b", "main"], { cwd: repo });
  await run("git", ["config", "user.email", "test@example.invalid"], { cwd: repo });
  await run("git", ["config", "user.name", "Test"], { cwd: repo });
  await run("git", ["add", "."], { cwd: repo });
  await run("git", ["commit", "-qm", "fixture"] , { cwd: repo });
  const { stdout } = await run("git", ["rev-parse", "HEAD"], { cwd: repo });
  return { repo, inputCommit: stdout.trim(), catalog };
}

test("plans a deterministic batch while preserving each reference qualifier", async () => {
  const { planReferencePatch } = await import("./reference-patch.mjs");
  const f = await fixture();
  const result = await planReferencePatch({
    repo: f.repo,
    inputCommit: f.inputCommit,
    expectedCatalogSha256: sha(f.catalog),
    proposals: [{ caseId: "comms/one", anchor: "new-anchor" }],
  });
  assert.equal(result.version, 1);
  assert.equal(result.edits.length, 1);
  assert.equal(result.edits[0].beforeRef, "heterodyne:0.6.0#old-anchor");
  assert.equal(result.edits[0].afterRef, "heterodyne:0.6.0#new-anchor");
  assert.equal(result.edits[0].after, '"heterodyne:0.6.0#new-anchor"');
  assert.equal(result.semanticAuthority, "not-validated");
  assert.equal(JSON.stringify(result), JSON.stringify(await planReferencePatch({
    repo: f.repo, inputCommit: f.inputCommit, expectedCatalogSha256: sha(f.catalog),
    proposals: [{ caseId: "comms/one", anchor: "new-anchor" }],
  })));
});

test("rejects injected or qualified anchor fragments", async () => {
  const { planReferencePatch } = await import("./reference-patch.mjs");
  const f = await fixture();
  await assert.rejects(() => planReferencePatch({ repo: f.repo, inputCommit: f.inputCommit,
    expectedCatalogSha256: sha(f.catalog), proposals: [{ caseId: "comms/one", anchor: "comms#new-anchor" }] }));
  await assert.rejects(() => planReferencePatch({ repo: f.repo, inputCommit: f.inputCommit,
    expectedCatalogSha256: sha(f.catalog), proposals: [{ caseId: "comms/one", anchor: "new-anchor?x" }] }));
});

test("returns an empty edit list for an already-correct reference", async () => {
  const { planReferencePatch } = await import("./reference-patch.mjs");
  const f = await fixture();
  const result = await planReferencePatch({ repo: f.repo, inputCommit: f.inputCommit,
    expectedCatalogSha256: sha(f.catalog), proposals: [{ caseId: "comms/one", anchor: "old-anchor" }] });
  assert.deepEqual(result.edits, []);
  assert.equal(result.beforeSha256, result.afterSha256);
});
