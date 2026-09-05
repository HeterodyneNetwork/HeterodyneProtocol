import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { renderAnchors, renderReferences, renderTests } from "./prepare.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

test("renders every draft case by declared reference, including duplicate and unknown groups", () => {
  const graph = {
    items: [
      {
        semantic_id: "heterodyne:core#core-document-conventions",
        type: "spec_anchor",
        owner: "core",
        heading: "Document conventions",
        source_path: "docs/spec/heterodyne-core.md",
        source_line: 30,
        source_digest: "a".repeat(64),
      },
      {
        semantic_id: "case:core/one",
        type: "draft_case",
        source_path: "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts",
        source_line: 12,
        boundary_id: "core.validateThing",
        spec_refs: [
          "heterodyne:core#core-document-conventions",
          "heterodyne:core#core-document-conventions",
          "heterodyne:core#missing-anchor",
        ],
      },
      {
        semantic_id: "case:comms/two",
        type: "draft_case",
        source_path: "contracts.ts",
        source_line: 4,
        boundary_id: "comms.validateThing",
        spec_refs: [],
      },
    ],
    edges: [],
  };

  const output = renderReferences(graph);
  assert.match(output, /## heterodyne:core#core-document-conventions/u);
  assert.match(output, /case:core\/one/u);
  assert.match(output, /core\.validateThing/u);
  assert.match(output, /missing-anchor.*unresolved|unresolved.*missing-anchor/us);
  assert.match(output, /## unknown \(no declared spec_refs\)/u);
  assert.match(output, /case:comms\/two/u);
  assert.equal((output.match(/case:core\/one/gu) ?? []).length, 2);
  assert.doesNotMatch(output, /governing:\s*(?:true|yes)|certified:\s*(?:true|yes)/iu);
});

test("renders all spec anchors grouped by source document without case mapping", () => {
  const graph = {
    items: [
      {
        semantic_id: "heterodyne:core#core-a",
        type: "spec_anchor",
        owner: "core",
        heading: "A",
        source_path: "docs/spec/heterodyne-core.md",
        source_line: 3,
        source_digest: "1".repeat(64),
      },
      {
        semantic_id: "heterodyne:comms#comms-a",
        type: "spec_anchor",
        owner: "comms",
        heading: "A",
        source_path: "docs/spec/heterodyne-comms.md",
        source_line: 7,
        source_digest: "2".repeat(64),
      },
    ],
  };

  const output = renderAnchors(graph);
  assert.match(output, /## core/u);
  assert.match(output, /## comms/u);
  assert.match(output, /heterodyne:core#core-a.*heterodyne-core\.md:3.*1{64}/us);
  assert.match(output, /heterodyne:comms#comms-a.*heterodyne-comms\.md:7.*2{64}/us);
  assert.doesNotMatch(output, /case:/u);
});

test("renders exact additional excerpts with source identity", () => {
  const content = "const alpha = 1;\nconst βeta = 2;";
  const digest = sha256(Buffer.from(content, "utf8"));
  const output = renderTests([{
    path: "src/example.ts",
    purpose: "Pinned helper excerpt",
    startLine: 2,
    endLine: 2,
    sourceDigest: digest,
    bytes: Buffer.byteLength(content, "utf8"),
    content: "const βeta = 2;",
  }]);
  assert.match(output, /src\/example\.ts:2-2/u);
  assert.match(output, /Pinned helper excerpt/u);
  assert.match(output, new RegExp(digest, "u"));
  assert.match(output, /const βeta = 2;/u);
});

test("refuses an existing output directory before graph compilation", async (t) => {
  const outputDirectory = await mkdtemp(join(tmpdir(), "maintenance-prepare-output-"));
  t.after(() => rm(outputDirectory, { recursive: true, force: true }));
  await writeFile(join(outputDirectory, "sentinel"), "keep\n");
  const { prepareContext } = await import("./prepare.mjs");
  await assert.rejects(
    prepareContext({
      repo: process.cwd(),
      recipe: { inputCommit: "d".repeat(40), task: { taskId: "test", semanticIds: [] } },
      outputDirectory,
    }),
    /output directory must not already exist/u,
  );
  assert.equal(await readFile(join(outputDirectory, "sentinel"), "utf8"), "keep\n");
});

test("rejects a repository-contained output and unsafe or out-of-range excerpts before graph compilation", async (t) => {
  const outside = await mkdtemp(join(tmpdir(), "maintenance-prepare-safety-"));
  t.after(() => rm(outside, { recursive: true, force: true }));
  const recipe = { inputCommit: "d".repeat(40), task: { taskId: "test", semanticIds: [] } };
  const { prepareContext } = await import("./prepare.mjs");
  await assert.rejects(
    prepareContext({ repo: process.cwd(), recipe, outputDirectory: join(process.cwd(), "preview") }),
    /output directory must be outside/u,
  );

  const currentCommit = (await import("node:child_process")).execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  await assert.rejects(
    prepareContext({
      repo: process.cwd(),
      recipe: { inputCommit: currentCommit, task: { taskId: "test", semanticIds: [] }, additionalSourceExcerpts: [{ path: "../escape", startLine: 1, endLine: 1 }] },
      outputDirectory: join(outside, "unsafe"),
    }),
    /unsafe additional source excerpt path/u,
  );
  await assert.rejects(
    prepareContext({
      repo: process.cwd(),
      recipe: { inputCommit: currentCommit, task: { taskId: "test", semanticIds: [] }, additionalSourceExcerpts: [{ path: "scripts/maintenance/packet.mjs", startLine: 1, endLine: 999999 }] },
      outputDirectory: join(outside, "range"),
    }),
    /range outside file/u,
  );
});
