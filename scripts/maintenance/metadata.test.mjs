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

test("current catalog statically reproduces profile, terminal, and boundary transforms", async () => {
  const result = await readDeclaredContracts({ repo, layout: "current-catalog" });
  assert.equal(result.layout, "current-catalog");
  assert.deepEqual(result.layoutSelection, {
    requested: "current-catalog",
    detected: "current-catalog",
  });
  assert.equal(result.records.length, 267);

  const senderProof = result.records.find(({ id }) => id === "comms/agent-sender-proof-invalid");
  assert.equal(senderProof.boundaryId, "agent-publication-authorization.authorizeAndSignAgentPublication");
  assert.deepEqual(senderProof.unknownFields, []);

  const terminal = result.records.find(({ id }) => id === "comms/auth-rejected-permanent");
  assert.deepEqual(terminal.invariants, []);
  assert.deepEqual(terminal.reasonCodes, []);
  assert.deepEqual(terminal.unknownFields, []);

  const profile = result.records.find(({ id }) => id === "core/profile-heterodyne-core-rotation-breadcrumb-profile-v1");
  assert.equal(profile.boundaryId, "core-policy.validateCorePersonaSignedEvent");
  assert.equal(profile.ownerDocument, "core");
  assert.equal(profile.profile, "heterodyne-core-rotation-breadcrumb-profile-v1");
  assert.deepEqual(profile.invariants, ["CORE-I-IDENTITY-INTEGRITY"]);
  assert.deepEqual(profile.reasonCodes, []);
  assert.ok(profile.provenance.some(({ path, kind }) => path.endsWith("/case-contracts.ts") && kind === "catalog_declaration"));
  assert.ok(profile.provenance.some(({ path, kind }) => path.endsWith("/profile-oracles.ts") && kind === "profile_oracle_override"));

  for (const record of [senderProof, terminal, profile]) {
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
