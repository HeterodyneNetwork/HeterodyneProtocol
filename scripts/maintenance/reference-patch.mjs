import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { lstat, readFile, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

const run = promisify(execFile);
const require = createRequire(new URL("../../docs/spec/vectors/generator/package.json", import.meta.url));
const ts = require("typescript");
const CATALOG = "docs/spec/vectors/generator/src/current-vectors/case-contracts.ts";
const CORE = "docs/spec/heterodyne-core.md";
const DOCS = ["core", "assurance", "comms", "control", "social", "workspace"];
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const fail = (message) => { throw new Error(`reference patch rejected: ${message}`); };

async function git(repo, args, encoding = "utf8") {
  const result = await run("git", args, { cwd: repo, encoding });
  return result.stdout;
}

function staticString(node, what) {
  if (!node || !ts.isStringLiteral(node)) fail(`${what} must be a string literal`);
  return node.text;
}

function propertyName(node) {
  const name = node.name;
  if (!name) return undefined;
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

function uniqueProperties(object, what) {
  const out = new Map();
  for (const item of object.properties) {
    if (!ts.isPropertyAssignment(item)) fail(`${what} contains unsupported property`);
    const name = propertyName(item);
    if (name === undefined) fail(`${what} contains computed property`);
    if (out.has(name)) fail(`${what} contains duplicate property ${name}`);
    out.set(name, item);
  }
  return out;
}

function parseCatalog(source) {
  const file = ts.createSourceFile(CATALOG, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  if (file.parseDiagnostics?.length) fail("catalog has syntax errors");
  const declarations = [];
  const visit = (node) => {
    if (ts.isVariableDeclaration(node) && propertyName(node) === "CURRENT_CASE_CONTRACTS") declarations.push(node);
    ts.forEachChild(node, visit);
  };
  visit(file);
  if (declarations.length !== 1) fail("catalog must contain exactly one CURRENT_CASE_CONTRACTS object");
  const declaration = declarations[0];
  if (!declaration.initializer || !ts.isObjectLiteralExpression(declaration.initializer)) fail("catalog object is not static");
  const cases = uniqueProperties(declaration.initializer, "catalog");
  const byteOffset = (pos) => Buffer.byteLength(source.slice(0, pos), "utf8");
  return { file, cases, byteOffset };
}

function caseDetails(node, source) {
  if (!node.initializer || !ts.isObjectLiteralExpression(node.initializer)) fail("case declaration is not static");
  const fields = uniqueProperties(node.initializer, "case");
  const owner = staticString(fields.get("owner_document")?.initializer, "owner_document");
  const refs = fields.get("spec_refs")?.initializer;
  if (!refs || !ts.isArrayLiteralExpression(refs) || refs.elements.length !== 1) fail("case must have exactly one literal spec reference");
  const refNode = refs.elements[0];
  const ref = staticString(refNode, "spec_refs entry");
  const match = /^heterodyne:(\d+\.\d+\.\d+)#([a-z0-9]+(?:-[a-z0-9]+)*)$/.exec(ref);
  if (!match) fail(`invalid original reference ${ref}`);
  return { owner, ref, anchor: match[2], version: match[1], refNode, source };
}

async function regular(repo, path) {
  const absolute = join(repo, path);
  const parts = path.split("/");
  let current = repo;
  for (const part of parts) {
    current = join(current, part);
    const stat = await lstat(current).catch(() => fail(`missing input ${path}`));
    if (stat.isSymbolicLink()) fail(`symlink input ${path}`);
  }
  const stat = await lstat(absolute);
  if (!stat.isFile()) fail(`non-regular input ${path}`);
}

async function assertClean(repo, paths) {
  const status = await git(repo, ["status", "--porcelain", "--", ...paths]);
  if (status) fail(`selected inputs are dirty: ${paths.join(", ")}`);
}

function anchorLine(source, anchor) {
  const re = new RegExp(`<a\\s+id=(?:"${anchor}"|'${anchor}')\\s*>`, "g");
  const matches = [...source.matchAll(re)];
  if (matches.length !== 1) fail(`anchor ${anchor} must exist exactly once`);
  return source.slice(0, matches[0].index).split("\n").length;
}

export async function planReferencePatch({ repo, inputCommit, expectedCatalogSha256, proposals }) {
  if (typeof repo !== "string" || !isAbsolute(repo)) fail("repo must be an absolute path");
  const root = await realpath(resolve(repo));
  const actualRoot = (await git(root, ["rev-parse", "--show-toplevel"])).trim();
  if (resolve(actualRoot) !== root) fail("repo must be the Git worktree root");
  if (!/^[0-9a-f]{40}$/.test(inputCommit ?? "")) fail("inputCommit must be lowercase full 40-hex");
  if ((await git(root, ["rev-parse", "HEAD"])).trim() !== inputCommit) fail("inputCommit is not HEAD");
  if (!/^[0-9a-f]{64}$/.test(expectedCatalogSha256 ?? "")) fail("expectedCatalogSha256 must be 64-hex");
  if (!Array.isArray(proposals) || proposals.length === 0) fail("proposals must be nonempty");
  const seen = new Set();
  for (const proposal of proposals) {
    if (!proposal || typeof proposal.caseId !== "string" || typeof proposal.anchor !== "string") fail("invalid proposal");
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(proposal.anchor)) fail("anchor must be a bare lowercase explicit anchor");
    if (seen.has(proposal.caseId)) fail(`duplicate proposal ${proposal.caseId}`);
    seen.add(proposal.caseId);
  }

  const ownerPaths = new Set([CORE]);
  const allPaths = [CATALOG, CORE];
  for (const path of allPaths) await regular(root, path);
  await assertClean(root, [CATALOG, CORE]);
  const pinnedCatalog = await git(root, ["show", `${inputCommit}:${CATALOG}`], null);
  const pinnedCatalogHash = sha256(pinnedCatalog);
  if (pinnedCatalogHash !== expectedCatalogSha256) fail("catalog hash mismatch");
  const workingCatalog = await readFile(join(root, CATALOG));
  if (!workingCatalog.equals(pinnedCatalog)) fail("catalog changed from pinned bytes");
  const catalogText = workingCatalog.toString("utf8");
  const parsed = parseCatalog(catalogText);
  const coreText = (await git(root, ["show", `${inputCommit}:${CORE}`], null)).toString("utf8");
  const workingCore = await readFile(join(root, CORE));
  if (!workingCore.equals(Buffer.from(coreText))) fail("core document changed from pinned bytes");
  const versionMatches = [...coreText.matchAll(/Family version[\s\S]*?`heterodyne\/(\d+\.\d+\.\d+)`/g)];
  if (versionMatches.length !== 1) fail("family version is not uniquely declared");
  const version = versionMatches[0][1];

  const edits = [];
  const sourceInputs = new Map([[CATALOG, pinnedCatalogHash], [CORE, sha256(Buffer.from(coreText))]]);
  for (const proposal of proposals) {
    const declaration = parsed.cases.get(proposal.caseId);
    if (!declaration) fail(`unknown case ${proposal.caseId}`);
    const detail = caseDetails(declaration, catalogText);
    if (detail.version !== version) fail(`reference version mismatch for ${proposal.caseId}`);
    if (!DOCS.includes(detail.owner)) fail(`unknown owner document ${detail.owner}`);
    const ownerPath = `docs/spec/heterodyne-${detail.owner}.md`;
    ownerPaths.add(ownerPath);
    await regular(root, ownerPath);
    await assertClean(root, [ownerPath]);
    const ownerBytes = await git(root, ["show", `${inputCommit}:${ownerPath}`], null);
    const workingOwner = await readFile(join(root, ownerPath));
    if (!workingOwner.equals(ownerBytes)) fail(`owner document changed from pinned bytes: ${ownerPath}`);
    const ownerText = ownerBytes.toString("utf8");
    sourceInputs.set(ownerPath, sha256(ownerBytes));
    const line = anchorLine(ownerText, proposal.anchor);
    if (proposal.anchor === detail.anchor) continue;
    const startByte = parsed.byteOffset(detail.refNode.getStart(parsed.file));
    const endByte = parsed.byteOffset(detail.refNode.getEnd());
    const before = catalogText.slice(detail.refNode.getStart(parsed.file), detail.refNode.getEnd());
    const quote = before[0];
    const afterRef = `heterodyne:${version}#${proposal.anchor}`;
    const after = `${quote}${afterRef}${quote}`;
    edits.push({ caseId: proposal.caseId, startByte, endByte, before, after, _startPos: detail.refNode.getStart(parsed.file), _endPos: detail.refNode.getEnd(),
      beforeRef: detail.ref, afterRef, sourceLine: catalogText.slice(0, detail.refNode.getStart(parsed.file)).split("\n").length,
      authority: { path: ownerPath, anchor: proposal.anchor, line, sourceSha256: sha256(ownerBytes) } });
  }
  edits.sort((a, b) => a.startByte - b.startByte);
  for (let i = 1; i < edits.length; i += 1) if (edits[i - 1].endByte > edits[i].startByte) fail("overlapping edits");
  let afterText = catalogText;
  for (const edit of [...edits].reverse()) afterText = afterText.slice(0, edit._startPos) + edit.after + afterText.slice(edit._endPos);
  for (const edit of edits) { delete edit._startPos; delete edit._endPos; }
  const orderedInputs = [...sourceInputs.entries()].sort(([a], [b]) => a.localeCompare(b, "en"));
  return { version: 1, inputCommit, path: CATALOG, beforeSha256: sha256(workingCatalog), afterSha256: sha256(Buffer.from(afterText)), edits,
    sourceInputs: orderedInputs.map(([path, digest]) => ({ path, sha256: digest })), semanticAuthority: "not-validated", requiresFreshnessCheckBeforeApply: true };
}
