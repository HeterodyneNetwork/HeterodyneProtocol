import test from "node:test";
import assert from "node:assert/strict";
import { lstat, mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
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
    receipt: { inputs: [
      { path: "docs/spec/heterodyne-core.md", sha256: "f".repeat(64) },
      { path: "docs/spec/heterodyne-comms.md", sha256: "e".repeat(64) },
    ] },
  };

  const output = renderAnchors(graph);
  assert.match(output, /## core/u);
  assert.match(output, /## comms/u);
  assert.match(output, /heterodyne:core#core-a.*heterodyne-core\.md:3.*1{64}/us);
  assert.match(output, /heterodyne:comms#comms-a.*heterodyne-comms\.md:7.*2{64}/us);
  assert.match(output, /section digest: `1{64}`; full source digest: `f{64}`/u);
  assert.match(output, /section digest: `2{64}`; full source digest: `e{64}`/u);
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

function git(root, ...args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
}

async function gitFixture(t) {
  const root = await mkdtemp(join(tmpdir(), "maintenance-prepare-git-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  git(root, "init", "-q");
  git(root, "config", "user.email", "test@example.invalid");
  git(root, "config", "user.name", "test");
  await mkdir(join(root, "src"));
  await writeFile(join(root, "src", "selected.txt"), "selected\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "fixture");
  return { root, commit: git(root, "rev-parse", "HEAD") };
}

function fixtureGraph(root, bytes) {
  const sourcePath = "src/selected.txt";
  const anchor = "heterodyne:core#core-a";
  const input = { path: sourcePath, ref: "WORKTREE", sha256: sha256(bytes) };
  return {
    items: [
      { semantic_id: anchor, type: "spec_anchor", owner: "core", heading: "A", source_path: sourcePath, source_line: 1, source_digest: sha256(bytes) },
      { semantic_id: "case:core/one", type: "draft_case", source_path: sourcePath, source_line: 1, boundary_id: "core.example", spec_refs: [anchor] },
    ],
    edges: [{ from: "case:core/one", to: anchor, relation: "declares", raw_ref: anchor }],
    receipt: { lane: "draft", spec_ref: "WORKTREE", fresh: true, inputs: [input], input_inventory_sha256: sha256(`${JSON.stringify([input])}\n`), unresolved_references: [] },
  };
}

test("publishes a small Git fixture with labeled output and sidecar accounting", async (t) => {
  const fixture = await gitFixture(t);
  const outputDirectory = join(await mkdtemp(join(tmpdir(), "maintenance-prepare-result-")), "prepared");
  t.after(() => rm(outputDirectory, { recursive: true, force: true }));
  const bytes = Buffer.from("selected\n");
  const graph = fixtureGraph(fixture.root, bytes);
  const recipe = { version: 2, inputCommit: fixture.commit, task: { taskId: "fixture", semanticIds: ["heterodyne:core#core-a"] } };
  const result = await (await import("./prepare.mjs")).prepareContext({
    repo: fixture.root,
    recipe,
    outputDirectory,
    buildGraphFn: async () => graph,
    compilePacketFn: async ({ artifactDirectory }) => {
      await writeFile(join(artifactDirectory, "sidecar.json"), '{"sidecar":true}\n');
      return { version: 1, taskId: "fixture", complete: true, unknown: { preserved: true }, relationships: { graphArtifact: { kind: "maintenance-packet-context", digest: "a".repeat(64) } } };
    },
  });
  assert.equal(result.outputDirectory, join(await realpath(dirname(outputDirectory)), "prepared"));
  const manifest = JSON.parse(await readFile(join(outputDirectory, "manifest.json"), "utf8"));
  assert.equal(manifest.input.commit, fixture.commit);
  assert.equal(manifest.recipe.taskId, "fixture");
  assert.equal(manifest.sourceInputs.files[0].path, "src/selected.txt");
  assert.equal(manifest.rootReadingSet.files.some(({ path }) => path === "manifest.json"), true);
  assert.equal(manifest.rootReadingSet.files.find(({ path }) => path === "manifest.json").sha256, undefined);
  assert.equal(manifest.sidecars[0].path, "artifacts/sidecar.json");
  assert.match(manifest.sidecars[0].sha256, /^[a-f0-9]{64}$/u);
  const sidecarActual = await readFile(join(outputDirectory, manifest.sidecars[0].path));
  assert.equal(manifest.sidecars[0].bytes, sidecarActual.length);
  assert.equal(manifest.sidecars[0].sha256, sha256(sidecarActual));
  assert.deepEqual(manifest.optionalSidecars.files, manifest.sidecars);
  assert.equal(manifest.compiler.estimatedTokens, result.packet.estimatedTokens ?? null);
  for (const file of manifest.rootReadingSet.files.filter(({ path }) => path !== "manifest.json")) {
    const actual = await readFile(join(outputDirectory, file.path));
    assert.equal(file.bytes, actual.length, file.path);
    assert.equal(file.sha256, sha256(actual), file.path);
  }
  const manifestActual = await readFile(join(outputDirectory, "manifest.json"));
  assert.equal(manifest.rootReadingSet.files.find(({ path }) => path === "manifest.json").bytes, manifestActual.length);
  assert.equal(manifest.rootReadingSet.combinedUtf8Bytes, manifest.rootReadingSet.files.reduce((sum, file) => sum + file.bytes, 0));
  assert.equal(manifest.rootReadingSet.estimatedTokens, Math.ceil(manifest.rootReadingSet.combinedUtf8Bytes / 4));
  assert.equal(JSON.parse(await readFile(join(outputDirectory, "packet.json"), "utf8")).unknown.preserved, true);
});

test("rejects wrong pin, dirty selected inputs, and symlink excerpts without creating output", async (t) => {
  const fixture = await gitFixture(t);
  const outside = await mkdtemp(join(tmpdir(), "maintenance-prepare-rejections-"));
  t.after(() => rm(outside, { recursive: true, force: true }));
  const prepare = (await import("./prepare.mjs")).prepareContext;
  const bytes = Buffer.from("selected\n");
  const graph = fixtureGraph(fixture.root, bytes);
  const base = { version: 2, inputCommit: fixture.commit, task: { taskId: "fixture", semanticIds: ["heterodyne:core#core-a"] } };
  const wrongOutput = join(outside, "wrong-output");
  await assert.rejects(
    prepare({ repo: fixture.root, recipe: { ...base, inputCommit: "0".repeat(40) }, outputDirectory: wrongOutput, buildGraphFn: async () => { throw new Error("must not build"); } }),
    /HEAD does not match recipe/u,
  );
  await assert.rejects(lstat(wrongOutput), { code: "ENOENT" });

  await writeFile(join(fixture.root, "src", "selected.txt"), "dirty\n");
  const dirtyOutput = join(outside, "dirty-output");
  await assert.rejects(
    prepare({ repo: fixture.root, recipe: base, outputDirectory: dirtyOutput, buildGraphFn: async () => graph, compilePacketFn: async () => { throw new Error("must not compile"); } }),
    /source inputs are dirty/u,
  );
  await assert.rejects(lstat(dirtyOutput), { code: "ENOENT" });

  git(fixture.root, "checkout", "--", "src/selected.txt");
  await writeFile(join(fixture.root, "src", "untracked.txt"), "untracked\n");
  const untrackedGraph = fixtureGraph(fixture.root, Buffer.from("untracked\n"));
  untrackedGraph.receipt.inputs[0].path = "src/untracked.txt";
  untrackedGraph.items.forEach((item) => { item.source_path = "src/untracked.txt"; });
  const untrackedOutput = join(outside, "untracked-output");
  await assert.rejects(
    prepare({ repo: fixture.root, recipe: base, outputDirectory: untrackedOutput, buildGraphFn: async () => untrackedGraph, compilePacketFn: async () => { throw new Error("must not compile"); } }),
    /source inputs are dirty/u,
  );
  await assert.rejects(lstat(untrackedOutput), { code: "ENOENT" });

  await symlink(join(fixture.root, "src", "selected.txt"), join(fixture.root, "src", "link.txt"));
  const symlinkOutput = join(outside, "symlink-output");
  await assert.rejects(
    prepare({ repo: fixture.root, recipe: { ...base, additionalSourceExcerpts: [{ path: "src/link.txt", startLine: 1, endLine: 1 }] }, outputDirectory: symlinkOutput, buildGraphFn: async () => { throw new Error("must not build"); } }),
    /regular file/u,
  );
  await assert.rejects(lstat(symlinkOutput), { code: "ENOENT" });
});
