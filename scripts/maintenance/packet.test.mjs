import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { compilePacket, resolvePacketHandle } from "./packet.mjs";
import { buildGraph } from "../vector-trace.mjs";

const realRepo = new URL("../../", import.meta.url).pathname;
const CATALOG = "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts";
const PROFILE_ORACLES = "docs/spec/vectors/generator/src/current-vectors/profile-oracles.ts";
const SPEC = "docs/spec/heterodyne-comms.md";
const OIDC = "docs/spec/vectors/generator/src/oidc.ts";
const ROOT_ID = "heterodyne:comms#comms-issuer-continuity";
const CASE_IDS = [
  "case:comms/oidc-issuer-mismatch",
  "case:comms/oidc-issuer-persona-continuity",
];
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const inventoryDigest = (inputs) => sha256(`${JSON.stringify(inputs)}\n`);

async function put(root, path, content) {
  await mkdir(dirname(join(root, path)), { recursive: true });
  await writeFile(join(root, path), content, "utf8");
}

async function fixtureRepo(t) {
  const root = await mkdtemp(join(tmpdir(), "maintenance-packet-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

async function artifactDirectory(t) {
  const root = await mkdtemp(join(tmpdir(), "maintenance-packet-artifacts-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function git(root, args) {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function normalizedSection(body = "Implementations MUST bind a stable issuer to its persona.\n\n### Nested rule\nReject a changed issuer before use.") {
  return `## Issuer continuity\n${body}\n`;
}

function specSource(body, newline = "\n") {
  return [
    "# Comms",
    "",
    '<a id="comms-issuer-continuity"></a>',
    "## Issuer continuity",
    ...body.split("\n"),
    "",
    '<a id="comms-next"></a>',
    "## Next section",
    "This text must not be delivered for the issuer task.",
    "",
  ].join(newline);
}

function catalogSource() {
  return `type Contract = unknown;
const CURRENT_CASE_CONTRACTS = (({
  "comms/oidc-issuer-mismatch": {
    boundary_id: "oidc.validateIssuerMetadata", owner_document: "comms",
    spec_refs: ["heterodyne:0.6.0#comms-issuer-continuity"], invariants: ["COMMS-I-ISSUER-CONTINUITY"], reason_codes: ["issuer-mismatch"]
  },
  "comms/oidc-issuer-persona-continuity": {
    boundary_id: "oidc.validateIssuerMetadata", owner_document: "comms",
    spec_refs: ["heterodyne:0.6.0#comms-issuer-continuity"], invariants: ["COMMS-I-ISSUER-CONTINUITY"], reason_codes: []
  }
} as const) satisfies Readonly<Record<string, Contract>>);
const TASK_FIFTEEN_BOUNDARIES = Object.freeze({});
`;
}

function profileSource() {
  return "const rows = []; const oracleByVectorId = new Map(rows.map((entry) => [entry.vector_id, entry])); export const CURRENT_PROFILE_ORACLES = rows; export function currentProfileOracleForVector(vectorId) { return oracleByVectorId.get(vectorId); }\n";
}

function oidcSource() {
  return `const préface = "😀";
export function validateIssuerMetadata(metadata) {
  if (metadata.issuer !== metadata.expectedIssuer) throw new Error("issuer-mismatch");
  return metadata;
}
export function unrelatedOidcOperation() { return "must not be expanded"; }
`;
}

function buildFixtureGraph({ spec, catalog, oidc, profile, unresolved = [], refs = {} }) {
  const specRef = refs.spec ?? "WORKTREE";
  const catalogRef = refs.catalog ?? specRef;
  const oidcRef = refs.oidc ?? catalogRef;
  const profileRef = refs.profile ?? catalogRef;
  const inputs = [
    { path: SPEC, ref: specRef, sha256: sha256(Buffer.from(spec)) },
    { path: CATALOG, ref: catalogRef, sha256: sha256(Buffer.from(catalog)) },
    { path: PROFILE_ORACLES, ref: profileRef, sha256: sha256(Buffer.from(profile)) },
    { path: OIDC, ref: oidcRef, sha256: sha256(Buffer.from(oidc)) },
  ];
  const root = {
    semantic_id: ROOT_ID, type: "spec_anchor", owner: "comms", heading: "Issuer continuity",
    source_path: SPEC, source_line: 3, source_digest: sha256(normalizedSection()), evidence_kind: "normative_spec",
  };
  const cases = CASE_IDS.map((semantic_id) => ({
    semantic_id, type: "draft_case", source_path: CATALOG, source_digest: sha256(Buffer.from(catalog)),
    boundary_id: "oidc.validateIssuerMetadata", evidence_kind: "declared_current",
  }));
  const boundary = {
    semantic_id: `source:${OIDC}`, type: "source_module", source_path: OIDC,
    source_digest: sha256(Buffer.from(oidc)), evidence_kind: "generator_input",
  };
  const fillers = Array.from({ length: 93 }, (_, index) => ({
    semantic_id: `vector:unrelated/${String(index).padStart(2, "0")}`,
    type: "vector",
    evidence_kind: "snapshot_vector",
  }));
  const items = [root, ...cases, boundary, ...fillers];
  const edges = [
    ...cases.map((item) => ({ from: item.semantic_id, to: ROOT_ID, relation: "declares", raw_ref: "heterodyne:0.6.0#comms-issuer-continuity" })),
    ...cases.map((item) => ({ from: item.semantic_id, to: boundary.semantic_id, relation: "defined_by", boundary_id: "oidc.validateIssuerMetadata", exported_name: "validateIssuerMetadata" })),
    ...fillers.map((item) => ({ from: item.semantic_id, to: ROOT_ID, relation: "declares" })),
  ];
  for (let index = 0; edges.length < 999; index += 1) {
    edges.push({
      from: fillers[index % fillers.length].semantic_id,
      to: fillers[(index + 1) % fillers.length].semantic_id,
      relation: "covers",
      ordinal: index,
    });
  }
  return {
    items,
    edges,
    receipt: {
      lane: refs.lane ?? "draft",
      spec_ref: refs.receiptSpec ?? specRef,
      vector_ref: refs.vector ?? null,
      fresh: true,
      inputs,
      input_inventory_sha256: inventoryDigest(inputs),
      unresolved_references: unresolved,
    },
  };
}

async function currentFixture(t, options = {}) {
  const root = await fixtureRepo(t);
  const artifacts = await artifactDirectory(t);
  const body = options.body ?? "Implementations MUST bind a stable issuer to its persona.\n\n### Nested rule\nReject a changed issuer before use.";
  const spec = specSource(body, options.newline ?? "\n");
  const catalog = catalogSource();
  const profile = profileSource();
  const oidc = oidcSource();
  await Promise.all([
    put(root, SPEC, spec),
    put(root, CATALOG, catalog),
    put(root, PROFILE_ORACLES, profile),
    put(root, OIDC, oidc),
  ]);
  const graph = buildFixtureGraph({ spec, catalog, profile, oidc, unresolved: options.unresolved ?? [] });
  if (options.body !== undefined) graph.items[0].source_digest = sha256(normalizedSection(body));
  return { root, artifactDirectory: artifacts, graph, spec, catalog, profile, oidc, body };
}

const task = {
  taskId: "issuer-continuity",
  semanticIds: [ROOT_ID],
  ownedPaths: [OIDC],
  acceptanceChecks: ["issuer-negative-conformance"],
  contract: { requirement: ROOT_ID },
};

test("96-related packet expands only governing section, two declaring cases, and exact boundary", async (t) => {
  const fixture = await currentFixture(t);
  const packet = await compilePacket({ repo: fixture.root, graph: fixture.graph, task, deliveredChunkIds: [], artifactDirectory: fixture.artifactDirectory });

  assert.equal(packet.relationships.related.count, 96);
  assert.equal(packet.relationships.edges.count, 999);
  assert.match(packet.relationships.graphArtifact.digest, /^[a-f0-9]{64}$/);
  assert.deepEqual(packet.relationships.expandedSemanticIds.sort(), [ROOT_ID, ...CASE_IDS, `source:${OIDC}`].sort());
  assert.deepEqual(packet.mustRead.map(({ kind }) => kind).sort(), ["case-declaration", "case-declaration", "interface", "normative"].sort());
  assert.deepEqual(packet.mustRead.filter(({ kind }) => kind === "case-declaration").map(({ semanticId }) => semanticId).sort(), CASE_IDS);
  assert.equal(packet.mustRead.find(({ kind }) => kind === "interface").symbolOrAnchor, "validateIssuerMetadata");
  const normative = packet.mustRead.find(({ kind }) => kind === "normative");
  assert.equal(normative.content, normalizedSection());
  assert.equal(normative.content.includes("Next section"), false);
  assert.equal(normative.sourceDigest, sha256(normalizedSection()));
  const raw = await readFile(join(fixture.root, SPEC));
  assert.equal(raw.subarray(normative.startByte, normative.endByte).toString("utf8"), normative.content);
  assert.equal(packet.mustRead.some((chunk) => chunk.endByte - chunk.startByte === Buffer.byteLength(fixture.catalog)), false);
  assert.equal(packet.mustRead.some((chunk) => chunk.endByte - chunk.startByte === Buffer.byteLength(fixture.oidc)), false);
  assert.equal(packet.estimatedTokens < 8000, true);
  assert.equal(packet.budget.maxTokens, 8000);
  const serializedPacket = { ...packet, estimatedTokens: 0 };
  assert.ok(packet.estimatedTokens >= Math.ceil(Buffer.byteLength(JSON.stringify(serializedPacket), "utf8") / 4));
  assert.equal(packet.complete, true);
  assert.equal(packet.metadata.layout, "current-catalog");
});

test("partial graph keeps normative context, every edge, and explicit unknowns", async (t) => {
  const fixture = await currentFixture(t, { unresolved: [{ reason: "unknown_profile_override", from: CASE_IDS[0] }] });
  const packet = await compilePacket({ repo: fixture.root, graph: fixture.graph, task, deliveredChunkIds: [], artifactDirectory: fixture.artifactDirectory });
  assert.equal(packet.complete, false);
  assert.ok(packet.unresolved.length > 0);
  assert.equal(packet.mustRead.some((chunk) => chunk.kind === "normative"), true);
  assert.equal(packet.relationships.edges.count, 999);
});

test("freshness checks receipt flag and full input bytes while accepting bounded normalized anchor digests", async (t) => {
  const fixture = await currentFixture(t, { newline: "\r\n" });
  const expectedNormalized = normalizedSection();
  fixture.graph.items[0].source_digest = sha256(expectedNormalized);
  const packet = await compilePacket({ repo: fixture.root, graph: fixture.graph, task, deliveredChunkIds: [], artifactDirectory: fixture.artifactDirectory });
  const normative = packet.mustRead.find(({ kind }) => kind === "normative");
  const raw = await readFile(join(fixture.root, SPEC));
  assert.equal(sha256(raw), fixture.graph.receipt.inputs.find(({ path }) => path === SPEC).sha256);
  assert.notEqual(fixture.graph.items[0].source_digest, sha256(raw));
  assert.equal(normative.normalizedContent, expectedNormalized);
  assert.equal(raw.subarray(normative.startByte, normative.endByte).toString("utf8"), normative.content);
  assert.equal(normative.content.includes("\r\n"), true);
  assert.equal(packet.complete, true);

  await put(fixture.root, OIDC, `${fixture.oidc}// changed under the same path\n`);
  const stale = await compilePacket({ repo: fixture.root, graph: fixture.graph, task, deliveredChunkIds: [], artifactDirectory: fixture.artifactDirectory });
  assert.equal(stale.complete, false);
  assert.ok(stale.unresolved.some(({ reason, path }) => reason === "input_digest_mismatch" && path === OIDC));

  const notFresh = structuredClone(fixture.graph);
  notFresh.receipt.fresh = false;
  const rejected = await compilePacket({ repo: fixture.root, graph: notFresh, task, deliveredChunkIds: [], artifactDirectory: fixture.artifactDirectory });
  assert.equal(rejected.complete, false);
  assert.ok(rejected.unresolved.some(({ reason }) => reason === "receipt_not_fresh"));
});

test("three calls retain cumulative delivery, count satisfied obligations, and resend only changed chunks", async (t) => {
  const fixture = await currentFixture(t);
  const first = await compilePacket({ repo: fixture.root, graph: fixture.graph, task, deliveredChunkIds: [], artifactDirectory: fixture.artifactDirectory });
  const second = await compilePacket({ repo: fixture.root, graph: fixture.graph, task, deliveredChunkIds: first.deliveredChunkIds, artifactDirectory: fixture.artifactDirectory });
  assert.equal(second.mustRead.length + second.mayNeed.length, 0);
  assert.deepEqual(second.deliveredChunkIds, first.deliveredChunkIds);
  assert.equal(second.alreadyDeliveredObligations, 4);
  assert.equal(second.complete, true);

  const changedBody = `${fixture.body}\nA newly adopted requirement MUST also be checked.`;
  const changedSpec = specSource(changedBody);
  await put(fixture.root, SPEC, changedSpec);
  const changed = structuredClone(fixture.graph);
  changed.items.find(({ semantic_id }) => semantic_id === ROOT_ID).source_digest = sha256(normalizedSection(changedBody));
  const specInput = changed.receipt.inputs.find(({ path }) => path === SPEC);
  specInput.sha256 = sha256(Buffer.from(changedSpec));
  changed.receipt.input_inventory_sha256 = inventoryDigest(changed.receipt.inputs);

  const third = await compilePacket({ repo: fixture.root, graph: changed, task, deliveredChunkIds: second.deliveredChunkIds, artifactDirectory: fixture.artifactDirectory });
  assert.deepEqual(third.mustRead.map(({ kind }) => kind), ["normative"]);
  assert.equal(third.alreadyDeliveredObligations, 3);
  assert.equal(third.deliveredChunkIds.length, first.deliveredChunkIds.length + 1);
  assert.equal(first.deliveredChunkIds.every((id) => third.deliveredChunkIds.includes(id)), true);
  assert.equal(third.complete, true);
});

test("over-budget requirement is intact and requests explicit expansion", async (t) => {
  const body = `Implementations MUST retain this obligation.\n${"normative detail ".repeat(2400)}`;
  const fixture = await currentFixture(t, { body });
  const packet = await compilePacket({ repo: fixture.root, graph: fixture.graph, task, deliveredChunkIds: [], artifactDirectory: fixture.artifactDirectory });
  const normative = packet.mustRead.find(({ kind }) => kind === "normative");
  assert.equal(normative.normalizedContent, normalizedSection(body));
  assert.equal(packet.estimatedTokens > 8000, true);
  assert.ok(packet.deferred.some(({ reason }) => reason === "budget_expansion_required"));
  assert.equal(packet.complete, false);
});

test("missing anchors stay unresolved and expose cited source-span discovery handles", async (t) => {
  const graph = await buildGraph({ repo: realRepo, lane: "draft", ref: "8f780ce" });
  const artifacts = await artifactDirectory(t);
  const staleCase = "case:comms/agent-attribution-encrypted-inner";
  const packet = await compilePacket({
    repo: realRepo,
    graph,
    task: { ...task, taskId: "stale-anchor", semanticIds: [staleCase] },
    deliveredChunkIds: [],
    artifactDirectory: artifacts,
  });
  const missing = packet.unresolved.find(({ reason, from }) => reason === "missing_anchor" && from === staleCase);
  assert.equal(missing.to, "heterodyne:comms#comms-mandatory-pre-sign-attribution");
  const handle = packet.discoveryHandles.find(({ reason, semanticId }) => reason === "missing_anchor" && semanticId === staleCase);
  assert.equal(handle.kind, "source-span");
  assert.equal(handle.path, CATALOG);
  assert.ok(handle.startByte >= 0 && handle.endByte > handle.startByte);
  assert.equal(handle.replacementMapping, undefined);
  assert.equal(packet.complete, false);
});

test("reconciliation reads each source at its receipt input ref, not a universal spec ref", async (t) => {
  const root = await fixtureRepo(t);
  const artifacts = await artifactDirectory(t);
  git(root, ["init", "-q"]);
  const bodyA = "A historical normative obligation MUST be used.";
  const specA = specSource(bodyA);
  await put(root, SPEC, specA);
  await put(root, CATALOG, catalogSource());
  await put(root, PROFILE_ORACLES, profileSource());
  await put(root, OIDC, "export function validateIssuerMetadata() { return 'old'; }\n");
  git(root, ["add", "."]);
  git(root, ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "spec"]);
  const specRef = git(root, ["rev-parse", "HEAD"]);

  const catalogB = catalogSource().replace("issuer-mismatch\"]", "issuer-mismatch\", \"historical\"]");
  const oidcB = "export function validateIssuerMetadata() { return 'vector-ref'; }\n";
  await put(root, CATALOG, catalogB);
  await put(root, OIDC, oidcB);
  git(root, ["add", "."]);
  git(root, ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "vector"]);
  const vectorRef = git(root, ["rev-parse", "HEAD"]);
  await put(root, SPEC, specSource("WORKTREE MUST NOT LEAK."));
  await put(root, CATALOG, "const CURRENT_CASE_CONTRACTS = {};\n");
  await put(root, OIDC, "export function validateIssuerMetadata() { return 'WORKTREE'; }\n");

  const graph = buildFixtureGraph({
    spec: specA, catalog: catalogB, profile: profileSource(), oidc: oidcB,
    refs: { lane: "reconciliation", spec: specRef, catalog: vectorRef, profile: vectorRef, oidc: vectorRef, receiptSpec: specRef, vector: vectorRef },
  });
  graph.items[0].source_digest = sha256(normalizedSection(bodyA));
  graph.items.filter(({ type }) => type === "draft_case").forEach((item) => { item.source_digest = sha256(Buffer.from(catalogB)); });
  graph.items.find(({ semantic_id }) => semantic_id === `source:${OIDC}`).source_digest = sha256(Buffer.from(oidcB));
  const packet = await compilePacket({ repo: root, graph, task, deliveredChunkIds: [], artifactDirectory: artifacts });
  assert.equal(packet.mustRead.find(({ kind }) => kind === "normative").inputRef, specRef);
  assert.equal(packet.mustRead.find(({ kind }) => kind === "normative").content.includes("historical normative"), true);
  assert.equal(packet.mustRead.filter(({ kind }) => kind === "case-declaration").every(({ inputRef }) => inputRef === vectorRef), true);
  assert.equal(packet.mustRead.find(({ kind }) => kind === "interface").inputRef, vectorRef);
  assert.equal(packet.mustRead.find(({ kind }) => kind === "interface").content.includes("vector-ref"), true);
  assert.equal(packet.mustRead.some(({ content }) => content.includes("WORKTREE")), false);
});

test("artifact handle resolves exact omitted context after WORKTREE changes and rejects missing or tampered bytes", async (t) => {
  const fixture = await currentFixture(t);
  const packet = await compilePacket({
    repo: fixture.root,
    graph: fixture.graph,
    task,
    deliveredChunkIds: [],
    artifactDirectory: fixture.artifactDirectory,
  });
  const handle = packet.relationships.graphArtifact;
  assert.equal(handle.kind, "maintenance-packet-context");
  assert.equal(handle.version, 1);
  const resolved = await resolvePacketHandle({ artifactDirectory: fixture.artifactDirectory, handle });
  assert.equal(resolved.related.length, 96);
  assert.equal(resolved.edges.length, 999);
  assert.deepEqual(resolved.unresolved, []);
  assert.deepEqual(resolved.receipt, fixture.graph.receipt);

  await put(fixture.root, SPEC, specSource("Changed WORKTREE bytes MUST NOT alter an immutable stored artifact."));
  assert.deepEqual(await resolvePacketHandle({ artifactDirectory: fixture.artifactDirectory, handle }), resolved);

  const emptyArtifacts = await artifactDirectory(t);
  await assert.rejects(resolvePacketHandle({ artifactDirectory: emptyArtifacts, handle }), /missing|ENOENT/u);
  await writeFile(join(fixture.artifactDirectory, `${handle.digest}.json`), "{}\n", "utf8");
  await assert.rejects(resolvePacketHandle({ artifactDirectory: fixture.artifactDirectory, handle }), /digest|tamper/u);
});

test("without an artifact directory all omitted relationships and unknown detail stay inline with honest expansion", async (t) => {
  const unresolved = [{
    reason: "boundary_source_unavailable",
    semanticId: CASE_IDS[0],
    source_path: CATALOG,
    line: 17,
    column: 9,
    relation: "defined_by",
    symbol: "validateIssuerMetadata",
    boundaryId: "oidc.validateIssuerMetadata",
    selector: { path: OIDC, symbol: "validateIssuerMetadata" },
  }];
  const fixture = await currentFixture(t, { unresolved });
  const packet = await compilePacket({ repo: fixture.root, graph: fixture.graph, task, deliveredChunkIds: [] });
  assert.equal(packet.relationships.graphArtifact, null);
  assert.equal(packet.relationships.related.records.length, 96);
  assert.equal(packet.relationships.edges.records.length, 999);
  assert.deepEqual(packet.unresolved.find(({ reason }) => reason === "boundary_source_unavailable"), unresolved[0]);
  assert.ok(packet.deferred.some(({ reason }) => reason === "budget_expansion_required"));
  assert.equal(packet.complete, false);
});

test("stored packets retain essential inline repair coordinates while the resolver keeps full unknowns", async (t) => {
  const unresolved = [{
    reason: "invalid_selector",
    semanticId: CASE_IDS[0],
    source_path: CATALOG,
    line: 23,
    column: 5,
    startByte: 640,
    endByte: 704,
    sourceDigest: "a".repeat(64),
    relation: "defined_by",
    symbol: "missingBoundary",
    boundaryId: "oidc.missingBoundary",
    selector: { path: OIDC, symbol: "missingBoundary", extra: "full-detail" },
  }];
  const fixture = await currentFixture(t, { unresolved });
  const packet = await compilePacket({
    repo: fixture.root,
    graph: fixture.graph,
    task,
    deliveredChunkIds: [],
    artifactDirectory: fixture.artifactDirectory,
  });
  const inline = packet.unresolved.find(({ reason }) => reason === "invalid_selector");
  assert.deepEqual(inline, unresolved[0]);
  const resolved = await resolvePacketHandle({ artifactDirectory: fixture.artifactDirectory, handle: packet.relationships.graphArtifact });
  assert.deepEqual(resolved.unresolved.find(({ reason }) => reason === "invalid_selector"), unresolved[0]);
});

test("real snapshot vector and anchor roots expand immutable vector JSON plus governing prose", async (t) => {
  const graph = await buildGraph({ repo: realRepo, lane: "snapshot" });
  const artifacts = await artifactDirectory(t);
  const vectorId = "vector:comms/oidc-issuer-mismatch";
  const vectorPacket = await compilePacket({
    repo: realRepo,
    graph,
    task: { ...task, taskId: "snapshot-vector", semanticIds: [vectorId] },
    deliveredChunkIds: [],
    artifactDirectory: artifacts,
  });
  assert.deepEqual(vectorPacket.mustRead.map(({ kind }) => kind).sort(), ["historical-vector", "normative"]);
  const vector = vectorPacket.mustRead.find(({ kind }) => kind === "historical-vector");
  assert.equal(JSON.parse(vector.content).vector_id, "comms/oidc-issuer-mismatch");
  assert.equal(vector.inputRef, graph.receipt.vector_ref);
  assert.equal(vectorPacket.mustRead.find(({ kind }) => kind === "normative").inputRef, graph.receipt.spec_ref);
  assert.equal(vectorPacket.complete, true);

  const anchorPacket = await compilePacket({
    repo: realRepo,
    graph,
    task: { ...task, taskId: "snapshot-anchor", semanticIds: [ROOT_ID] },
    deliveredChunkIds: [],
    artifactDirectory: artifacts,
  });
  assert.equal(anchorPacket.mustRead.filter(({ kind }) => kind === "historical-vector").length, 2);
  assert.equal(anchorPacket.mustRead.some(({ kind }) => kind === "normative"), true);
  assert.equal(anchorPacket.complete, true);
});

test("unsupported selected node types are unresolved instead of complete empty packets", async (t) => {
  const fixture = await currentFixture(t);
  for (const semanticId of [`source:${OIDC}`, "schema:unsupported-fixture"]) {
    const graph = structuredClone(fixture.graph);
    if (semanticId.startsWith("schema:")) graph.items.push({ semantic_id: semanticId, type: "schema_artifact" });
    const packet = await compilePacket({
      repo: fixture.root,
      graph,
      task: { ...task, taskId: semanticId, semanticIds: [semanticId] },
      deliveredChunkIds: [],
      artifactDirectory: fixture.artifactDirectory,
    });
    assert.ok(packet.unresolved.some(({ reason, semanticId: selected }) =>
      reason === "unsupported_selection_type" && selected === semanticId));
    assert.equal(packet.complete, false);
  }
});

test("historical packets refuse symlink blobs named by receipt inputs", async (t) => {
  const root = await fixtureRepo(t);
  git(root, ["init", "-q"]);
  await put(root, "target.md", specSource("A target outside the declared artifact MUST NOT be followed."));
  await mkdir(dirname(join(root, SPEC)), { recursive: true });
  await symlink("../../target.md", join(root, SPEC));
  git(root, ["add", "."]);
  git(root, ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "symlink"]);
  const ref = git(root, ["rev-parse", "HEAD"]);
  const linkBytes = Buffer.from("../../target.md");
  const graph = {
    items: [{ semantic_id: ROOT_ID, type: "spec_anchor", source_path: SPEC, source_digest: sha256(normalizedSection()) }],
    edges: [],
    receipt: {
      lane: "snapshot", spec_ref: ref, vector_ref: ref, fresh: true,
      inputs: [{ path: SPEC, ref, sha256: sha256(linkBytes) }], unresolved_references: [],
    },
  };
  const packet = await compilePacket({ repo: root, graph, task, deliveredChunkIds: [] });
  assert.equal(packet.mustRead.some(({ kind }) => kind === "normative"), false);
  assert.ok(packet.unresolved.some(({ reason, detail }) => reason === "source_unavailable" && /symlink/u.test(detail)));
  assert.equal(packet.complete, false);
});

test("real buildGraph issuer slice retains obligations and requests expansion for explicit profile unknowns", async (t) => {
  const graph = await buildGraph({ repo: realRepo, lane: "draft" });
  const artifacts = await artifactDirectory(t);
  const packet = await compilePacket({ repo: realRepo, graph, task, deliveredChunkIds: [], artifactDirectory: artifacts });
  assert.equal(packet.relationships.related.count, 96);
  assert.equal(packet.relationships.edges.count, 999);
  assert.deepEqual(packet.mustRead.filter(({ kind }) => kind === "case-declaration").map(({ semanticId }) => semanticId).sort(), CASE_IDS);
  assert.equal(packet.mustRead.find(({ kind }) => kind === "interface").symbolOrAnchor, "validateIssuerMetadata");
  const normative = packet.mustRead.find(({ kind }) => kind === "normative");
  const fullSpec = await readFile(join(realRepo, SPEC));
  assert.equal(normative.endByte - normative.startByte < fullSpec.length, true);
  assert.equal(normative.content, fullSpec.subarray(normative.startByte, normative.endByte).toString("utf8"));
  assert.equal(packet.estimatedTokens > packet.budget.maxTokens, true);
  const expansion = packet.deferred.find(({ reason }) => reason === "budget_expansion_required");
  assert.ok(expansion);
  assert.equal(expansion.maxTokens, packet.budget.maxTokens);
  assert.equal(expansion.requestedAdditionalTokens > 0, true);
  assert.equal(expansion.normativeObligationsTruncated, false);
  t.diagnostic(`Issuer packet: ${packet.estimatedTokens} estimated tokens; ${expansion.requestedAdditionalTokens} additional tokens requested.`);
  assert.equal(packet.budget.measuredFields.includes("relationships"), true);
  assert.equal(packet.complete, false);
  assert.equal(packet.unresolved.length >= 64, true);
});
