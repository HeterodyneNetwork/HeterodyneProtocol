import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { semanticUuid } from "./vector-trace/projection.mjs";
import { enrichDraft } from "./vector-trace/draft.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");

function projectionFixture() {
  const sources = new Map([
    ["docs/spec/heterodyne-comms.md", "# Comms\n\n<a id=\"anchor\"></a>\nA requirement.\n"],
    ["docs/spec/vectors/generator/src/current-vectors/family.ts", "export const FAMILY_VERSION = \"0.6.0\";\n"],
    ["docs/spec/vectors/generator/src/current-vectors/case-contracts.ts", `
      const CURRENT_CASE_CONTRACTS = (({
        "comms/base-case": { boundary_id: "boundary.original", owner_document: "comms", spec_refs: ["heterodyne:0.6.0#anchor"], invariants: ["I-BASE"], reason_codes: [] },
        "comms/profile-profile-v1": { boundary_id: "boundary.original", owner_document: "comms", profile: "profile-v1", spec_refs: ["heterodyne:0.6.0#anchor"], invariants: ["I-PROFILE"], reason_codes: [] },
        "comms/profile-case": { boundary_id: "boundary.original", owner_document: "comms", profile: "profile-v1", spec_refs: ["heterodyne:0.6.0#anchor"], invariants: ["I-PROFILE-STATIC"], reason_codes: [] },
        "unknown/bad-owner": { boundary_id: "boundary.original", owner_document: "unknown", spec_refs: ["heterodyne:0.5.0#anchor"], invariants: [], reason_codes: [] },
      } as const) satisfies Readonly<Record<string, unknown>>);
      const TASK_FIFTEEN_BOUNDARIES = Object.freeze({ "comms/base-case": "boundary.override" });
    `],
    ["docs/spec/vectors/generator/src/current-vectors/profile-oracles.ts", "export function currentProfileOracleForVector(vectorId: string) { return oracleByVectorId.get(vectorId); }\n"],
    ["docs/spec/vectors/generator/src/boundary.ts", "export function original() {}\nexport function override() {}\n"],
    ["docs/spec/vectors/generator/src/a.ts", "import { b } from './b.js'; export const a = b;\n"],
    ["docs/spec/vectors/generator/src/b.ts", "import { a } from './a.js'; export const b = a;\n"],
    ["docs/spec/vectors/generator/src/dynamic.ts", "import('./missing.js'); import('node:fs'); import(name); require(name);\n"],
    ["docs/spec/vectors/generator/package.json", "{\"name\":\"fixture\"}\n"],
    ["docs/spec/vectors/generator/package-lock.json", "{\"lockfileVersion\":3}\n"],
  ]);
  const items = [];
  for (const [path, content] of sources) {
    if (!path.endsWith(".ts")) continue;
    const type = path.endsWith("case-contracts.ts") || path.endsWith("family.ts") ? "source_module" : "source_module";
    const semantic_id = `source:${path}`;
    items.push({ semantic_id, sara_id: semanticUuid(type, semantic_id), type, source_path: path, source_digest: hash(content), evidence_kind: "generator_input" });
  }
  const anchor = "heterodyne:comms#anchor";
  items.push({ semantic_id: anchor, sara_id: semanticUuid("spec_anchor", anchor), type: "spec_anchor", owner: "comms", source_path: "docs/spec/heterodyne-comms.md", source_digest: hash(sources.get("docs/spec/heterodyne-comms.md")), evidence_kind: "normative_spec" });
  const projection = { repository_root: "/synthetic/fixture", items, edges: [], receipt: { unresolved_references: [] } };
  Object.defineProperty(projection, "sourceContents", { value: sources, enumerable: false });
  return projection;
}

test("enrichDraft normalizes declared case refs and records boundary override provenance", () => {
  const projection = enrichDraft(projectionFixture(), { repo: "/synthetic/fixture" });
  const base = projection.items.find((item) => item.semantic_id === "case:comms/base-case");
  assert.equal(base.type, "draft_case");
  assert.deepEqual(base.raw_refs, ["heterodyne:0.6.0#anchor"]);
  assert.deepEqual(base.spec_refs, ["heterodyne:comms#anchor"]);
  const declaration = projection.edges.find((edge) => edge.from === base.semantic_id && edge.relation === "declares");
  assert.equal(declaration.to, "heterodyne:comms#anchor");
  assert.equal(declaration.raw_ref, "heterodyne:0.6.0#anchor");
  const boundary = projection.edges.find((edge) => edge.from === base.semantic_id && edge.relation === "defined_by");
  assert.equal(boundary.boundary_id, "boundary.override");
  assert.equal(boundary.override, true);
  assert.equal(boundary.exported_name, "override");
  assert.match(projection.receipt.typescript_version, /^\d+\.\d+\.\d+$/);
});

test("enrichDraft keeps invalid owner and version as unresolved references", () => {
  const projection = enrichDraft(projectionFixture(), { repo: "/synthetic/fixture" });
  const unresolved = projection.receipt.unresolved_references.filter((entry) => entry.from === "case:unknown/bad-owner");
  assert.equal(unresolved.some((entry) => entry.reason === "invalid_owner"), true);
  assert.equal(unresolved.some((entry) => entry.reason === "invalid_version"), true);
  assert.equal(projection.edges.some((edge) => edge.from === "case:unknown/bad-owner" && edge.relation === "declares"), false);
});

test("enrichDraft does not normalize a valid version ref when its owner is invalid", () => {
  const projection = projectionFixture();
  const path = "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts";
  projection.sourceContents.set(path, projection.sourceContents.get(path).replace(
    '"heterodyne:0.5.0#anchor"',
    '"heterodyne:0.6.0#anchor"',
  ));
  enrichDraft(projection, { repo: "/synthetic/fixture" });
  const bad = projection.items.find((item) => item.semantic_id === "case:unknown/bad-owner");
  assert.deepEqual(bad.spec_refs, []);
  assert.equal(projection.edges.some((edge) => edge.from === bad.semantic_id && edge.relation === "declares"), false);
  assert.ok(projection.receipt.unresolved_references.some((entry) => entry.from === bad.semantic_id && entry.reason === "invalid_owner"));
});

test("enrichDraft does not make final claims for runtime profile oracle overrides", () => {
  const projection = enrichDraft(projectionFixture(), { repo: "/synthetic/fixture" });
  const profile = projection.items.find((item) => item.semantic_id === "case:comms/profile-profile-v1");
  assert.equal(profile.runtime_override_unresolved, true);
  const gap = projection.receipt.unresolved_references.find((entry) => entry.from === profile.semantic_id && entry.reason === "runtime_profile_override");
  assert.equal(gap.source_path, "docs/spec/vectors/generator/src/current-vectors/profile-oracles.ts");
  assert.equal(Number.isInteger(gap.line), true);
  assert.equal(projection.edges.some((edge) => edge.from === profile.semantic_id && edge.relation === "defined_by"), false);
});

test("enrichDraft keeps ordinary profile allocations statically resolved", () => {
  const projection = enrichDraft(projectionFixture(), { repo: "/synthetic/fixture" });
  const profile = projection.items.find((item) => item.semantic_id === "case:comms/profile-case");
  assert.equal(profile.runtime_override_unresolved, undefined);
  assert.equal(projection.receipt.unresolved_references.some((entry) => entry.from === profile.semantic_id && entry.reason === "runtime_profile_override"), false);
  assert.ok(projection.edges.some((edge) => edge.from === profile.semantic_id && edge.relation === "defined_by"));
});

test("enrichDraft resolves cyclic local imports and records missing dynamic and external imports", () => {
  const projection = enrichDraft(projectionFixture(), { repo: "/synthetic/fixture" });
  assert.equal(projection.edges.some((edge) => edge.from === "source:docs/spec/vectors/generator/src/a.ts" && edge.to === "source:docs/spec/vectors/generator/src/b.ts" && edge.relation === "imports"), true);
  assert.equal(projection.edges.some((edge) => edge.from === "source:docs/spec/vectors/generator/src/b.ts" && edge.to === "source:docs/spec/vectors/generator/src/a.ts" && edge.relation === "imports"), true);
  assert.equal(projection.receipt.unresolved_references.some((entry) => entry.reason === "missing_import" && entry.dynamic === true && entry.source_path.endsWith("dynamic.ts")), true);
  assert.equal(projection.receipt.unresolved_references.some((entry) => entry.reason === "nonliteral_dynamic_import" && entry.source_path.endsWith("dynamic.ts")), true);
  assert.equal(projection.receipt.unresolved_references.some((entry) => entry.reason === "nonliteral_require" && entry.source_path.endsWith("dynamic.ts")), true);
  assert.equal(projection.receipt.external_dependencies.some((entry) => entry.specifier === "node:fs" && entry.external === true), true);
});

test("enrichDraft preserves input provenance and does not mutate sourceContents", () => {
  const projection = projectionFixture();
  const before = [...projection.sourceContents.entries()];
  enrichDraft(projection, { repo: "/synthetic/fixture" });
  assert.deepEqual([...projection.sourceContents.entries()], before);
  assert.deepEqual(projection.receipt.unresolved_references instanceof Array, true);
});

test("enrichDraft reports a missing case contract catalog instead of silently returning", () => {
  const projection = projectionFixture();
  projection.sourceContents.delete("docs/spec/vectors/generator/src/current-vectors/case-contracts.ts");
  enrichDraft(projection, { repo: "/synthetic/fixture" });
  assert.ok(projection.receipt.unresolved_references.some((entry) => entry.reason === "missing_contract_catalog"));
});

test("enrichDraft reports an unsupported boundary override declaration", () => {
  const projection = projectionFixture();
  const path = "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts";
  projection.sourceContents.set(path, projection.sourceContents.get(path).replace(
    "const TASK_FIFTEEN_BOUNDARIES = Object.freeze({ \"comms/base-case\": \"boundary.override\" });",
    "const TASK_FIFTEEN_BOUNDARIES = loadTaskFifteenBoundaries();",
  ));
  enrichDraft(projection, { repo: "/synthetic/fixture" });
  assert.ok(projection.receipt.unresolved_references.some((entry) => entry.reason === "unsupported_boundary_override"));
  const base = projection.items.find((item) => item.semantic_id === "case:comms/base-case");
  assert.equal(projection.edges.some((edge) => edge.from === base.semantic_id && edge.relation === "defined_by"), false);
});
