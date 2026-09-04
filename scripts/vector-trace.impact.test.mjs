import assert from "node:assert/strict";
import test from "node:test";

import {
  buildWorklist,
  compareProjections,
  coverageReport,
  queryPacket,
  traceabilityMatrix,
} from "./vector-trace/impact.mjs";

const item = (semantic_id, type, source_path, extra = {}) => ({
  semantic_id,
  type,
  source_path,
  source_digest: extra.source_digest ?? `${semantic_id}-digest`,
  evidence_kind: extra.evidence_kind ?? "declared",
  ...extra,
});

function graph(overrides = {}) {
  const items = [
    item("heterodyne:core#identity", "spec_anchor", "docs/spec/heterodyne-core.md", { owner: "core" }),
    item("case:core/identity", "draft_case", "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts", { owner: "core" }),
    item("source:docs/spec/vectors/generator/src/current-vectors/identity.ts", "source_module", "docs/spec/vectors/generator/src/current-vectors/identity.ts", { owner: "core" }),
    item("source:docs/spec/vectors/generator/src/shared-fixture.ts", "source_module", "docs/spec/vectors/generator/src/shared-fixture.ts", { owner: "core" }),
    item("source:docs/spec/vectors/generator/src/identity.test.ts", "source_module", "docs/spec/vectors/generator/src/identity.test.ts", { owner: "core" }),
    item("schema:identity-v1", "schema_artifact", "docs/spec/schemas/identity-v1.schema.json"),
    item("vector:core/identity", "vector", "docs/spec/vectors/core/identity.json", { owner: "core", profile: "default" }),
    item("registry:docs/spec/registry/core.json", "registry_artifact", "docs/spec/registry/core.json"),
    item("source:docs/spec/vectors/generator/src/other.test.ts", "source_module", "docs/spec/vectors/generator/src/other.test.ts", { owner: "core" }),
  ];
  const baseEdges = [
    { from: "case:core/identity", to: "heterodyne:core#identity", relation: "declares", source_path: "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts" },
    { from: "case:core/identity", to: "source:docs/spec/vectors/generator/src/current-vectors/identity.ts", relation: "defined_by", source_path: "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts" },
    { from: "source:docs/spec/vectors/generator/src/current-vectors/identity.ts", to: "source:docs/spec/vectors/generator/src/shared-fixture.ts", relation: "imports", source_path: "docs/spec/vectors/generator/src/current-vectors/identity.ts" },
    { from: "source:docs/spec/vectors/generator/src/identity.test.ts", to: "source:docs/spec/vectors/generator/src/current-vectors/identity.ts", relation: "imports", source_path: "docs/spec/vectors/generator/src/identity.test.ts" },
    { from: "source:docs/spec/vectors/generator/src/other.test.ts", to: "source:docs/spec/vectors/generator/src/shared-fixture.ts", relation: "imports", source_path: "docs/spec/vectors/generator/src/other.test.ts" },
    { from: "heterodyne:core#identity", to: "schema:identity-v1", relation: "uses_schema", source_path: "docs/spec/heterodyne-core.md" },
    { from: "heterodyne:core#identity", to: "registry:docs/spec/registry/core.json", relation: "uses_registry", source_path: "docs/spec/heterodyne-core.md" },
    { from: "vector:core/identity", to: "heterodyne:core#identity", relation: "covers", source_path: "docs/spec/vectors/coverage/manifest.json" },
  ];
  const edges = overrides.replaceEdges ? (overrides.edges ?? []) : [...baseEdges, ...(overrides.edges ?? [])];
  return {
    items: overrides.items ?? items,
    edges,
    receipt: overrides.receipt ?? {
      lane: "draft",
      unresolved_references: [],
      inputs: [
        { path: "docs/spec/heterodyne-core.md", ref: "WORKTREE", sha256: "core-v1" },
        { path: "docs/spec/registry/core.json", ref: "WORKTREE", sha256: "registry-v1" },
      ],
    },
  };
}

test("queryPacket follows direct contracts and imports, including reverse dependent tests", () => {
  const packet = queryPacket(graph(), "heterodyne:core#identity");
  assert.ok(packet.changed.some((entry) => entry.semantic_id === "heterodyne:core#identity"));
  assert.ok(packet.related.some((entry) => entry.semantic_id === "case:core/identity"));
  assert.ok(packet.related.some((entry) => entry.semantic_id === "source:docs/spec/vectors/generator/src/current-vectors/identity.ts"));
  assert.ok(packet.related.some((entry) => entry.semantic_id === "source:docs/spec/vectors/generator/src/identity.test.ts"));
  assert.equal(packet.related.some((entry) => entry.semantic_id === "source:docs/spec/vectors/generator/src/other.test.ts"), false);
  assert.ok(packet.suggested_checks.includes("scripts/conformance-ci.sh"));
});

test("queryPacket honors upstream/downstream direction and preserves missing links", () => {
  const projection = graph({
    edges: [{ from: "case:missing", to: "heterodyne:core#identity", relation: "declares", source_path: "contract.ts" }],
    receipt: { lane: "draft", unresolved_references: [{ from: "case:missing", to: "heterodyne:core#identity", relation: "declares", source_path: "contract.ts" }], inputs: [] },
  });
  const upstream = queryPacket(projection, "heterodyne:core#identity", { direction: "upstream" });
  assert.ok(upstream.related.some((entry) => entry.semantic_id === "schema:identity-v1"));
  assert.ok(upstream.unresolved.some((entry) => entry.to === "heterodyne:core#identity"));
  const downstream = queryPacket(projection, "heterodyne:core#identity", { direction: "downstream" });
  assert.ok(downstream.related.some((entry) => entry.semantic_id === "case:core/identity"));
  assert.equal(downstream.related.some((entry) => entry.semantic_id === "schema:identity-v1"), false);
  assert.throws(() => queryPacket(projection, "heterodyne:core#identity", { direction: "sideways" }), /direction/);
  assert.throws(() => queryPacket(projection, "heterodyne:core#deleted"), /unknown semantic id/);
});

test("queryPacket follows cyclic and transitive imports once without shared-fixture fan-out", () => {
  const projection = graph({ edges: [
    { from: "source:docs/spec/vectors/generator/src/shared-fixture.ts", to: "source:docs/spec/vectors/generator/src/current-vectors/identity.ts", relation: "imports", source_path: "shared-fixture.ts" },
  ] });
  const packet = queryPacket(projection, "source:docs/spec/vectors/generator/src/current-vectors/identity.ts");
  assert.ok(packet.related.some((entry) => entry.semantic_id === "source:docs/spec/vectors/generator/src/shared-fixture.ts"));
  assert.ok(packet.related.some((entry) => entry.semantic_id === "source:docs/spec/vectors/generator/src/identity.test.ts"));
  assert.equal(packet.related.some((entry) => entry.semantic_id === "source:docs/spec/vectors/generator/src/other.test.ts"), false);
  assert.ok(packet.related.length < projection.items.length);
});

test("queryPacket reverses an explicit source allocation to its case and anchor", () => {
  const packet = queryPacket(graph(), "source:docs/spec/vectors/generator/src/current-vectors/identity.ts");
  assert.ok(packet.related.some((entry) => entry.semantic_id === "case:core/identity"));
  assert.ok(packet.related.some((entry) => entry.semantic_id === "heterodyne:core#identity"));
});

test("compareProjections retains removed nodes and edges and reports exact input deltas", () => {
  const before = graph();
  const after = graph({
    items: before.items.filter((entry) => entry.semantic_id !== "schema:identity-v1"),
    edges: before.edges.filter((edge) => edge.to !== "schema:identity-v1"),
    replaceEdges: true,
    receipt: { ...before.receipt, inputs: [{ path: "docs/spec/heterodyne-core.md", ref: "WORKTREE", sha256: "core-v2" }] },
  });
  const diff = compareProjections(before, after);
  assert.ok(diff.removed.some((entry) => entry.semantic_id === "schema:identity-v1"));
  assert.ok(diff.edge_changes.removed.some((edge) => edge.to === "schema:identity-v1"));
  assert.deepEqual(diff.receipt.input_changes.modified, ["docs/spec/heterodyne-core.md"]);
  assert.deepEqual(diff.receipt.input_changes.removed, ["docs/spec/registry/core.json"]);
  assert.deepEqual(compareProjections(before, graph({ receipt: { ...before.receipt, inputs: before.receipt.inputs.map((input) => ({ ...input, ref: "different-ref" })) } })).receipt.input_changes.modified, []);
});

test("compareProjections exposes unanchored document changes and reverse schema dependencies", () => {
  const before = graph();
  const after = graph({ receipt: { ...before.receipt, inputs: [
    { path: "docs/spec/heterodyne-core.md", ref: "WORKTREE", sha256: "core-v2" },
    { path: "docs/spec/schemas/identity-v1.schema.json", ref: "WORKTREE", sha256: "schema-v2" },
  ] } });
  const diff = compareProjections(before, after);
  assert.ok(diff.unresolved.some((entry) => entry.path === "docs/spec/heterodyne-core.md"));
  assert.ok(diff.related.some((entry) => entry.semantic_id === "heterodyne:core#identity"));
  assert.ok(diff.related.some((entry) => entry.semantic_id === "case:core/identity"));
});

test("compareProjections ignores shifted anchor locations but keeps document impact and latest citations", () => {
  const before = graph({
    items: graph().items.map((entry) => entry.semantic_id === "heterodyne:core#identity"
      ? { ...entry, source_line: 4, declaration_location: { source_path: entry.source_path, line: 4, column: 1 } }
      : entry),
  });
  const after = graph({
    items: before.items.map((entry) => entry.semantic_id === "heterodyne:core#identity"
      ? { ...entry, source_line: 14, declaration_location: { source_path: entry.source_path, line: 14, column: 1 } }
      : entry),
    receipt: { ...before.receipt, inputs: before.receipt.inputs.map((input) => input.path === "docs/spec/heterodyne-core.md" ? { ...input, sha256: "core-v2" } : input) },
  });
  const diff = compareProjections(before, after);
  assert.equal(diff.modified.some((entry) => entry.semantic_id === "heterodyne:core#identity"), false);
  assert.equal(diff.changed.some((entry) => entry.semantic_id === "document:docs/spec/heterodyne-core.md"), true);
  assert.equal(diff.unresolved.some((entry) => entry.kind === "document_level_impact" && entry.path === "docs/spec/heterodyne-core.md"), true);
  assert.equal(diff.changed.find((entry) => entry.semantic_id === "document:docs/spec/heterodyne-core.md").source_path, "docs/spec/heterodyne-core.md");
});

test("compareProjections keeps document scope for mixed anchored and unanchored document edits", () => {
  const before = graph();
  const after = graph({
    items: before.items.map((entry) => entry.semantic_id === "heterodyne:core#identity"
      ? { ...entry, source_line: 10, source_digest: "anchor-v2" }
      : entry),
    receipt: { ...before.receipt, inputs: before.receipt.inputs.map((input) => input.path === "docs/spec/heterodyne-core.md" ? { ...input, sha256: "core-v2" } : input) },
  });
  const diff = compareProjections(before, after);
  assert.equal(diff.modified.some((entry) => entry.semantic_id === "heterodyne:core#identity"), true);
  assert.equal(diff.changed.some((entry) => entry.semantic_id === "document:docs/spec/heterodyne-core.md"), true);
  assert.equal(diff.unresolved.some((entry) => entry.kind === "document_level_impact" && entry.path === "docs/spec/heterodyne-core.md"), true);
});

test("queryPacket traverses cyclic reverse imports without losing non-test intermediates", () => {
  const source = (id, path) => item(id, "source_module", path);
  const items = [
    item("case:root", "draft_case", "contracts.ts"),
    source("source:a", "src/a.ts"),
    source("source:b", "src/b.ts"),
    source("source:fixture", "src/fixture.ts"),
    source("source:consumer", "src/consumer.ts"),
    source("source:case.test", "src/case.test.ts"),
    source("source:fixture.test", "src/fixture.test.ts"),
    item("heterodyne:core#root", "spec_anchor", "docs/spec/heterodyne-core.md"),
  ];
  const edges = [
    { from: "case:root", to: "source:a", relation: "defined_by", source_path: "contracts.ts" },
    { from: "source:a", to: "source:b", relation: "imports", source_path: "src/a.ts" },
    { from: "source:b", to: "source:a", relation: "imports", source_path: "src/b.ts" },
    { from: "source:consumer", to: "source:fixture", relation: "imports", source_path: "src/consumer.ts" },
    { from: "source:case.test", to: "source:consumer", relation: "imports", source_path: "src/case.test.ts" },
    { from: "source:fixture.test", to: "source:fixture", relation: "imports", source_path: "src/fixture.test.ts" },
    { from: "case:root", to: "source:consumer", relation: "defined_by", source_path: "src/consumer.ts" },
  ];
  const projection = graph({ items, edges, replaceEdges: true });
  const root = queryPacket(projection, "case:root");
  assert.ok(root.related.some((entry) => entry.semantic_id === "source:a"));
  assert.ok(root.related.some((entry) => entry.semantic_id === "source:b"));
  const fixture = queryPacket(projection, "source:fixture");
  assert.ok(fixture.related.some((entry) => entry.semantic_id === "source:consumer"));
  assert.ok(fixture.related.some((entry) => entry.semantic_id === "case:root"));
  assert.ok(fixture.related.some((entry) => entry.semantic_id === "source:fixture.test"));
  assert.ok(fixture.related.some((entry) => entry.semantic_id === "source:case.test"));
});

test("compareProjections reports deterministic edge provenance changes", () => {
  const before = graph();
  const after = graph({
    edges: before.edges.map((edge) => edge.relation === "declares" ? { ...edge, raw_ref: "heterodyne:0.6.0#new-anchor" } : edge),
    replaceEdges: true,
  });
  const diff = compareProjections(before, after);
  assert.equal(diff.edge_changes.removed.some((edge) => edge.relation === "declares" && edge.raw_ref === undefined), true);
  assert.equal(diff.edge_changes.added.some((edge) => edge.relation === "declares" && edge.raw_ref === "heterodyne:0.6.0#new-anchor"), true);
});

test("coverage and matrix distinguish declared coverage from execution", () => {
  const report = coverageReport(graph());
  assert.equal(report.declared_only, true);
  assert.ok(report.covered.some((entry) => entry.semantic_id === "heterodyne:core#identity"));
  assert.equal(report.uncovered.length, 0);
  assert.deepEqual(report.declared.find((entry) => entry.semantic_id === "heterodyne:core#identity").declared_by, ["case:core/identity"]);
  const matrix = traceabilityMatrix(graph());
  assert.ok(matrix.some((row) => row.from === "heterodyne:core#identity" && row.to === "schema:identity-v1"));
  assert.ok(matrix.every((row) => row.source_path));
});

test("buildWorklist groups owners and refuses parallel safety for collisions or gaps", () => {
  const packet = queryPacket(graph(), "heterodyne:core#identity");
  const worklist = buildWorklist({ ...packet, unresolved: [...packet.unresolved, { kind: "unknown_dependency", path: "dynamic.ts" }] });
  assert.equal(worklist.parallel_safe, false);
  const collidingPacket = { ...packet, changed: [
    ...packet.changed,
    item("case:core/other", "draft_case", "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts", { owner: "core" }),
  ] };
  const collidingWorklist = buildWorklist(collidingPacket);
  assert.ok(collidingWorklist.collision_risks.some((risk) => risk.path.endsWith("case-contracts.ts")));
  assert.ok(worklist.groups.some((group) => group.owner === "core"));
});
