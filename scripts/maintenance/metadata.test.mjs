import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { readDeclaredContracts } from "./metadata.mjs";

const repo = new URL("../../", import.meta.url).pathname;
const ROOT = "docs/spec/vectors/generator/src";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

async function put(root, path, content) {
  await mkdir(dirname(join(root, path)), { recursive: true });
  await writeFile(join(root, path), content, "utf8");
}

async function fixtureRepo(t) {
  const root = await mkdtemp(join(tmpdir(), "maintenance-metadata-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function git(root, args) {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test("current catalog retains declarations and boundary overrides while executable profile setup stays unknown", async () => {
  const result = await readDeclaredContracts({ repo, layout: "current-catalog" });
  assert.equal(result.layout, "current-catalog");
  assert.deepEqual(result.layoutSelection, {
    requested: "current-catalog",
    detected: "current-catalog",
  });
  assert.equal(result.records.length, 267);

  const senderProof = result.records.find(({ id }) => id === "comms/agent-sender-proof-invalid");
  assert.equal(senderProof.boundaryId, "agent-publication-authorization.authorizeAndSignAgentPublication");

  const terminal = result.records.find(({ id }) => id === "comms/auth-rejected-permanent");
  assert.deepEqual(terminal.invariants, []);
  assert.deepEqual(terminal.reasonCodes, []);

  const profile = result.records.find(({ id }) => id === "core/profile-heterodyne-core-rotation-breadcrumb-profile-v1");
  assert.equal(profile.boundaryId, null);
  assert.equal(profile.ownerDocument, null);
  assert.equal(profile.profile, null);
  assert.deepEqual(profile.invariants, []);
  assert.deepEqual(profile.reasonCodes, []);
  assert.ok(profile.provenance.some(({ path, kind }) => path.endsWith("/case-contracts.ts") && kind === "catalog_declaration"));
  assert.equal(profile.provenance.some(({ kind }) => kind === "profile_oracle_override"), false);

  for (const record of [senderProof, terminal, profile]) {
    assert.deepEqual(record.unknownFields.sort(), ["boundaryId", "invariants", "ownerDocument", "profile", "reasonCodes"]);
    assert.ok(result.unresolved.some(({ reason, id }) => reason === "unsupported_profile_oracle" && id === record.id));
    for (const provenance of record.provenance) {
      const source = await readFile(join(repo, provenance.path));
      assert.equal(provenance.sourceDigest, sha256(source));
      assert.ok(provenance.span.startByte >= 0);
      assert.ok(provenance.span.endByte > provenance.span.startByte);
      assert.ok(source.subarray(provenance.span.startByte, provenance.span.endByte).length > 0);
    }
  }
});

test("unsupported canonical expressions are unresolved and never converted into claims", async (t) => {
  const root = await fixtureRepo(t);
  await put(root, `${ROOT}/current-vectors/case-contracts.ts`, `
    type Contract = unknown;
    const CURRENT_CASE_CONTRACTS = (({
      "comms/profile-profile-v1": {
        boundary_id: "boundary.base", owner_document: "comms", profile: "profile-v1",
        spec_refs: ["heterodyne:0.6.0#anchor"], invariants: ["I-BASE"], reason_codes: ["base"]
      }
    } as const) satisfies Readonly<Record<string, Contract>>);
    const TASK_FIFTEEN_BOUNDARIES = loadRuntimeBoundaries();
  `);
  await put(root, `${ROOT}/current-vectors/profile-oracles.ts`, `
    export function currentProfileOracleForVector(vectorId: string) {
      return loadRuntimeOracle(vectorId);
    }
  `);

  const result = await readDeclaredContracts({ repo: root, layout: "auto" });
  assert.equal(result.layout, "current-catalog");
  const record = result.records[0];
  assert.equal(record.id, "comms/profile-profile-v1");
  assert.equal(record.boundaryId, null);
  assert.equal(record.ownerDocument, null);
  assert.equal(record.profile, null);
  assert.deepEqual(record.invariants, []);
  assert.deepEqual(record.reasonCodes, []);
  assert.deepEqual(record.unknownFields.sort(), ["boundaryId", "invariants", "ownerDocument", "profile", "reasonCodes"].sort());
  assert.ok(result.unresolved.some(({ reason, id }) => reason === "unsupported_boundary_override" && id === record.id));
  assert.ok(result.unresolved.some(({ reason, id }) => reason === "unsupported_profile_oracle" && id === record.id));
});

test("a dynamic rows initializer makes otherwise recognized profile lookup unknown", async (t) => {
  const root = await fixtureRepo(t);
  await put(root, `${ROOT}/current-vectors/case-contracts.ts`, `
    const CURRENT_CASE_CONTRACTS = {
      "comms/profile-profile-v1": {
        boundary_id: "boundary.base", owner_document: "comms", profile: "profile-v1",
        spec_refs: ["heterodyne:0.6.0#anchor"], invariants: ["I-BASE"], reason_codes: ["base"]
      }
    } as const;
    const TASK_FIFTEEN_BOUNDARIES = Object.freeze({});
  `);
  await put(root, `${ROOT}/current-vectors/profile-oracles.ts`, `
    const rows = loadRowsFromRuntime();
    const oracleByVectorId = new Map(rows.map((entry) => [entry.vector_id, entry]));
    export function currentProfileOracleForVector(vectorId: string) {
      return oracleByVectorId.get(vectorId);
    }
  `);
  const result = await readDeclaredContracts({ repo: root, layout: "current-catalog" });
  const record = result.records[0];
  assert.equal(record.boundaryId, null);
  assert.equal(record.ownerDocument, null);
  assert.equal(record.profile, null);
  assert.deepEqual(record.invariants, []);
  assert.deepEqual(record.reasonCodes, []);
  assert.ok(result.unresolved.some(({ reason, id }) => reason === "unsupported_profile_oracle" && id === record.id));
});

test("a runtime population call after static rows initialization makes profile transforms unknown", async (t) => {
  const root = await fixtureRepo(t);
  await put(root, `${ROOT}/current-vectors/case-contracts.ts`, `
    const CURRENT_CASE_CONTRACTS = {
      "comms/profile-profile-v1": {
        boundary_id: "boundary.base", owner_document: "comms", profile: "profile-v1",
        spec_refs: ["heterodyne:0.6.0#anchor"], invariants: ["I-BASE"], reason_codes: ["base"]
      }
    } as const;
    const TASK_FIFTEEN_BOUNDARIES = Object.freeze({});
  `);
  await put(root, `${ROOT}/current-vectors/profile-oracles.ts`, `
    const rows = [];
    populateRowsAtRuntime(rows);
    const oracleByVectorId = new Map(rows.map((entry) => [entry.vector_id, entry]));
    export function currentProfileOracleForVector(vectorId: string) {
      return oracleByVectorId.get(vectorId);
    }
  `);
  const result = await readDeclaredContracts({ repo: root, layout: "current-catalog" });
  const record = result.records[0];
  assert.equal(record.boundaryId, null);
  assert.equal(record.ownerDocument, null);
  assert.equal(record.profile, null);
  assert.deepEqual(record.invariants, []);
  assert.deepEqual(record.reasonCodes, []);
  assert.ok(result.unresolved.some(({ reason, id }) => reason === "unsupported_profile_oracle" && id === record.id));
});

test("a method-indirect rows mutation makes profile transforms unknown", async (t) => {
  const root = await fixtureRepo(t);
  await put(root, `${ROOT}/current-vectors/case-contracts.ts`, `
    const CURRENT_CASE_CONTRACTS = {
      "comms/profile-profile-v1": {
        boundary_id: "boundary.base", owner_document: "comms", profile: "profile-v1",
        spec_refs: ["heterodyne:0.6.0#anchor"], invariants: ["I-BASE"], reason_codes: ["base"]
      }
    } as const;
    const TASK_FIFTEEN_BOUNDARIES = Object.freeze({});
  `);
  await put(root, `${ROOT}/current-vectors/profile-oracles.ts`, `
    const rows = [];
    const append = rows.push.bind(rows);
    append({
      vector_id: "comms/profile-profile-v1",
      semantic_boundary: "boundary.runtime",
      exercised_invariants: ["I-RUNTIME"]
    });
    const oracleByVectorId = new Map(rows.map((entry) => [entry.vector_id, entry]));
    export function currentProfileOracleForVector(vectorId: string) {
      return oracleByVectorId.get(vectorId);
    }
  `);
  const result = await readDeclaredContracts({ repo: root, layout: "current-catalog" });
  const record = result.records[0];
  assert.equal(record.boundaryId, null);
  assert.equal(record.ownerDocument, null);
  assert.equal(record.profile, null);
  assert.deepEqual(record.invariants, []);
  assert.deepEqual(record.reasonCodes, []);
  assert.ok(result.unresolved.some(({ reason, id }) => reason === "unsupported_profile_oracle" && id === record.id));
});

const pureProfileFreezer = `function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    deepFreeze((object as Record<PropertyKey, unknown>)[key], seen);
  }
  if (!ArrayBuffer.isView(object)) Object.freeze(object);
  return value;
}`;

for (const [name, helperSource, extraArgument = ""] of [
  ["changed oracle result", 'function oracle() { return { semantic_boundary: "actual.otherBoundary", exercised_invariants: ["ACTUAL"] }; }'],
  ["changed tuple result", 'function fixedTuple() { return { owner: "core", profile_id: "actual" }; } function oracle(tuple, boundary, invariants) { return { tuple, boundary, invariants }; }'],
  ["shadowed tuple", 'function fixedTuple() { return {}; } function fixedTuple() { return { owner: "core" }; } function oracle(tuple, boundary, invariants) { return { tuple, boundary, invariants }; }'],
  ["unvalidated argument cardinality", 'function oracle(tuple, boundary, invariants, replacement) { return replacement; }', ', { semantic_boundary: "actual.otherBoundary" }'],
]) {
  test(`helper-driven profile rows reject ${name}`, async (t) => {
    const root = await fixtureRepo(t);
    await put(root, `${ROOT}/current-vectors/case-contracts.ts`, `
      const CURRENT_CASE_CONTRACTS = {
        "comms/profile-profile-v1": {
          boundary_id: "boundary.base", owner_document: "comms", profile: "profile-v1",
          spec_refs: [], invariants: ["I-BASE"], reason_codes: []
        }
      } as const;
      const TASK_FIFTEEN_BOUNDARIES = Object.freeze({});
    `);
    await put(root, `${ROOT}/current-vectors/profile-oracles.ts`, `
      ${name.includes("tuple") ? "" : "function fixedTuple(kind, profile_id, owner, discriminator, stamping) { return { kind, profile_id, owner, discriminator, stamping }; }"}
      ${helperSource}
      const rows = [];
      rows.push(oracle(fixedTuple(1, "profile-v1", "comms", "tag:test", false), "reported.boundary", ["REPORTED"]${extraArgument}));
      const oracleByVectorId = new Map(rows.map((entry) => [entry.vector_id, entry]));
      export function currentProfileOracleForVector(vectorId) { return oracleByVectorId.get(vectorId); }
    `);
    const result = await readDeclaredContracts({ repo: root, layout: "current-catalog" });
    const record = result.records[0];
    assert.equal(record.boundaryId, null);
    assert.equal(record.ownerDocument, null);
    assert.equal(record.profile, null);
    assert.deepEqual(record.invariants, []);
    assert.deepEqual(record.reasonCodes, []);
    assert.ok(result.unresolved.some(({ reason, id }) => reason === "unsupported_profile_oracle" && id === record.id));
    assert.equal(record.provenance.some(({ kind }) => kind === "profile_oracle_override"), false);
  });
}

for (const [name, prelude, supported] of [
  ["throw", 'throw new Error("module initialization rejected");', false],
  ["runtime call", "initializeRuntime();", false],
  ["freezer dependency mutation", "Object.freeze = (value) => [];", false],
  ["while loop", "while (true) { throw new Error(); }", false],
  ["literal for-of loop", "for (const value of []) {}", false],
  ["unevaluable initializer", "const setup = initializeRuntime();", false],
  ["destructuring initializer", "const { setup } = initializeRuntime();", false],
  ["runtime import", 'import { setup } from "./runtime.js";', false],
  ["side-effect import", 'import "./runtime.js";', false],
  ["empty runtime import", 'import {} from "./runtime.js";', false],
  ["push before initialization", 'rows.push(oracle(fixedTuple(1, "profile-v1", "comms", "tag:test", false), "boundary.override", ["I-OVERRIDE"]));', false],
  ["safe declarations", `
    import type { Profile } from "./types.js";
    type LocalProfile = Profile;
    interface Declaration { id: string }
    function unused() { throw new Error("not executed"); }
    const VERSION = "heterodyne/0.6.0";
  `, true],
]) {
  test(`profile prelude ${supported ? "accepts" : "rejects"} ${name}`, async (t) => {
    const root = await fixtureRepo(t);
    await put(root, `${ROOT}/current-vectors/case-contracts.ts`, `
      const CURRENT_CASE_CONTRACTS = {
        "comms/profile-profile-v1": {
          boundary_id: "boundary.base", owner_document: "comms", profile: "profile-v1",
          spec_refs: [], invariants: ["I-BASE"], reason_codes: []
        }
      } as const;
      const TASK_FIFTEEN_BOUNDARIES = Object.freeze({});
    `);
    await put(root, `${ROOT}/current-vectors/profile-oracles.ts`, `
      ${prelude}
      ${pureProfileFreezer}
      const rows = [];
      const CURRENT_PROFILE_ORACLES = deepFreeze(rows);
      const oracleByVectorId = new Map(CURRENT_PROFILE_ORACLES.map((entry) => [entry.vector_id, entry]));
      export function currentProfileOracleForVector(vectorId: string) {
        return oracleByVectorId.get(vectorId);
      }
    `);
    const result = await readDeclaredContracts({ repo: root, layout: "current-catalog" });
    const record = result.records[0];
    assert.equal(record.boundaryId, supported ? "boundary.base" : null);
    assert.equal(record.ownerDocument, supported ? "comms" : null);
    assert.equal(record.profile, supported ? "profile-v1" : null);
    assert.deepEqual(record.invariants, supported ? ["I-BASE"] : []);
    assert.deepEqual(record.reasonCodes, []);
    assert.deepEqual(record.unknownFields.sort(), supported ? [] : ["boundaryId", "invariants", "ownerDocument", "profile", "reasonCodes"]);
    assert.equal(result.unresolved.some(({ reason, id }) => reason === "unsupported_profile_oracle" && id === record.id), !supported);
  });
}

for (const [name, source] of [
  ["mutating freezer", `function deepFreeze(value) { value.push(loadRuntimeOracle()); return value; }`],
  ["replacing freezer", `function deepFreeze(value) { return loadRuntimeRows(); }`],
  ["renamed freezer", pureProfileFreezer.replaceAll("deepFreeze", "otherFreeze")],
  ["shadowed freezer", `${pureProfileFreezer}\nfunction deepFreeze(value) { return []; }`],
  ["shadowed Map", `${pureProfileFreezer}\nfunction Map(entries) { return loadRuntimeLookup(); }`],
  ["shadowed Object", `${pureProfileFreezer}\nconst Object = { freeze: [] };`],
  ["shadowed Reflect", `${pureProfileFreezer}\nfunction Reflect() {}`],
  ["shadowed WeakSet", `${pureProfileFreezer}\nfunction WeakSet() {}`],
  ["shadowed ArrayBuffer", `${pureProfileFreezer}\nfunction ArrayBuffer() {}`],
  ["rejecting row count", `${pureProfileFreezer}`],
  ["replacing lookup", `${pureProfileFreezer}`],
  ["shadowed rows", `${pureProfileFreezer}\nfunction rows() {}`],
]) {
  test(`profile finalization rejects ${name}`, async (t) => {
    const root = await fixtureRepo(t);
    await put(root, `${ROOT}/current-vectors/case-contracts.ts`, `
      const CURRENT_CASE_CONTRACTS = {
        "comms/profile-profile-v1": {
          boundary_id: "boundary.base", owner_document: "comms", profile: "profile-v1",
          spec_refs: [], invariants: ["I-BASE"], reason_codes: []
        }
      } as const;
      const TASK_FIFTEEN_BOUNDARIES = Object.freeze({});
    `);
    await put(root, `${ROOT}/current-vectors/profile-oracles.ts`, `
      ${source}
      const rows = [];
      const CURRENT_PROFILE_ORACLES = deepFreeze(rows);
      ${name === "rejecting row count" ? 'if (CURRENT_PROFILE_ORACLES.length !== 31) { throw new Error("count"); }' : ""}
      const oracleByVectorId = new Map(CURRENT_PROFILE_ORACLES.map((entry) => [entry.vector_id, entry]));
      export function currentProfileOracleForVector(vectorId: string) {
        ${name === "replacing lookup" ? "return loadRuntimeOracle(vectorId); // oracleByVectorId.get(vectorId)" : "return oracleByVectorId.get(vectorId);"}
      }
    `);
    const result = await readDeclaredContracts({ repo: root, layout: "current-catalog" });
    const record = result.records[0];
    assert.equal(record.boundaryId, null);
    assert.equal(record.ownerDocument, null);
    assert.equal(record.profile, null);
    assert.deepEqual(record.invariants, []);
    assert.deepEqual(record.reasonCodes, []);
    assert.ok(result.unresolved.some(({ reason, id }) => reason === "unsupported_profile_oracle" && id === record.id));
  });
}

test("legacy auto-detection reads cited authoring inputs at their real locations and preserves unknowns", async (t) => {
  const root = await fixtureRepo(t);
  await put(root, "docs/spec/vectors/README.md", "# Test vectors\n\nGenerator declarations are authoring inputs, not boundary execution evidence.\n");
  await put(root, `${ROOT}/vector-metadata.ts`, `
    const ids = (value: string) => new Set(value.trim().split(/\\s+/));
    const COMMS_IDS = ids(\`
      oidc/discovery-exact-issuer
      oidc/issuer-mismatch-rejected
    \`);
    export function vectorMetadata(vectorId: string) { return { owner_document: "comms" }; }
  `);
  await put(root, `${ROOT}/author.ts`, `
    import { buildFixtures } from "./snapshot-fixtures-adapter.js";
    export async function authorAllVectors() { return buildFixtures(); }
  `);
  await put(root, `${ROOT}/verify.ts`, `
    import { authorAllVectors } from "./author.js";
    const fixtureAssertions = { boundary_id: "fabricated.execute", invariants: ["NOT-EVIDENCE"] };
    export async function verifyVectorTree() { return authorAllVectors(); }
  `);

  const result = await readDeclaredContracts({ repo: root, layout: "auto" });
  assert.equal(result.layout, "legacy-authoring");
  assert.deepEqual(result.layoutSelection, { requested: "auto", detected: "legacy-authoring" });
  assert.deepEqual(result.inputs.map(({ path }) => path).sort(), [
    "docs/spec/vectors/README.md",
    `${ROOT}/author.ts`,
    `${ROOT}/vector-metadata.ts`,
    `${ROOT}/verify.ts`,
  ].sort());
  assert.equal(result.records.length, 2);
  const record = result.records.find(({ id }) => id === "oidc/issuer-mismatch-rejected");
  assert.equal(record.evidenceKind, "declared_current");
  assert.equal(record.ownerDocument, "comms");
  assert.equal(record.boundaryId, null);
  assert.equal(record.profile, null);
  assert.deepEqual(record.specRefs, []);
  assert.deepEqual(record.invariants, []);
  assert.deepEqual(record.reasonCodes, []);
  assert.deepEqual(record.unknownFields.sort(), ["boundaryId", "profile", "specRefs", "invariants", "reasonCodes"].sort());
  assert.equal(record.provenance.length, 1);
  const source = await readFile(join(root, record.provenance[0].path));
  assert.equal(source.subarray(record.provenance[0].span.startByte, record.provenance[0].span.endByte).toString("utf8"), "oidc/issuer-mismatch-rejected");
  assert.equal(result.records.some(({ boundaryId }) => boundaryId === "fabricated.execute"), false);
  assert.ok(result.unresolved.some(({ reason }) => reason === "legacy_fields_unavailable"));
});

test("historical auto-detection reads every legacy input from the selected commit", async (t) => {
  const root = await fixtureRepo(t);
  git(root, ["init", "-q"]);
  await put(root, "docs/spec/vectors/README.md", "# Legacy vectors\n");
  await put(root, `${ROOT}/vector-metadata.ts`, "const COMMS_IDS = ids(`legacy/case`);\n");
  await put(root, `${ROOT}/author.ts`, "export function authorAllVectors() {}\n");
  await put(root, `${ROOT}/verify.ts`, "export function verifyVectorTree() {}\n");
  git(root, ["add", "."]);
  git(root, ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "legacy"]);
  const legacyRef = git(root, ["rev-parse", "HEAD"]);

  await put(root, `${ROOT}/current-vectors/case-contracts.ts`, `const CURRENT_CASE_CONTRACTS = {
    "comms/worktree-only": { boundary_id: "x.y", owner_document: "comms", spec_refs: [], invariants: [], reason_codes: [] }
  } as const;\n`);
  const result = await readDeclaredContracts({ repo: root, ref: legacyRef, layout: "auto" });
  assert.equal(result.layout, "legacy-authoring");
  assert.deepEqual(result.records.map(({ id }) => id), ["legacy/case"]);
  assert.equal(result.inputs.every(({ ref }) => ref === legacyRef), true);
  assert.equal(result.inputs.every(({ sourceDigest }) => /^[a-f0-9]{64}$/.test(sourceDigest)), true);
});

test("historical metadata refuses a symlink blob instead of parsing its target text", async (t) => {
  const root = await fixtureRepo(t);
  git(root, ["init", "-q"]);
  await put(root, "docs/spec/vectors/README.md", "# Legacy vectors\n");
  await put(root, `${ROOT}/author.ts`, "export function authorAllVectors() {}\n");
  await put(root, `${ROOT}/verify.ts`, "export function verifyVectorTree() {}\n");
  await symlink("author.ts", join(root, `${ROOT}/vector-metadata.ts`));
  git(root, ["add", "."]);
  git(root, ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "symlink"]);
  const ref = git(root, ["rev-parse", "HEAD"]);
  const result = await readDeclaredContracts({ repo: root, ref, layout: "legacy-authoring" });
  assert.equal(result.records.length, 0);
  assert.ok(result.unresolved.some(({ reason, path, detail }) =>
    reason === "missing_legacy_input" && path.endsWith("vector-metadata.ts") && /symlink/u.test(detail)));
});
