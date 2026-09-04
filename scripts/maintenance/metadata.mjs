import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { lstat, readFile } from "node:fs/promises";
import { join, relative, normalize, isAbsolute } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { symbolSpans } from "./symbols.mjs";

const run = promisify(execFile);
const require = createRequire(new URL("../../docs/spec/vectors/generator/package.json", import.meta.url));
const ts = require("typescript");
const ROOT = "docs/spec/vectors/generator/src/";
const CATALOG = `${ROOT}current-vectors/case-contracts.ts`;
const LEGACY = `${ROOT}vector-metadata.ts`;
const hash = (v) => createHash("sha256").update(v).digest("hex");
const jsonHash = (v) => hash(`${JSON.stringify(v)}\n`);

function literal(node) {
  while (node && (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node) || node.kind === ts.SyntaxKind.SatisfiesExpression || (ts.isCallExpression(node) && node.expression.getText() === "Object.freeze" && node.arguments.length === 1))) node = ts.isCallExpression(node) ? node.arguments[0] : node.expression;
  if (!node) return { ok: false };
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return { ok: true, value: node.text };
  if (node.kind === ts.SyntaxKind.TrueKeyword) return { ok: true, value: true };
  if (node.kind === ts.SyntaxKind.FalseKeyword) return { ok: true, value: false };
  if (ts.isArrayLiteralExpression(node)) { const values = []; for (const e of node.elements) { const x = literal(e); if (!x.ok) return { ok: false }; values.push(x.value); } return { ok: true, value: values }; }
  if (ts.isObjectLiteralExpression(node)) { const value = {}; for (const p of node.properties) { if (!ts.isPropertyAssignment(p)) return { ok: false }; const key = p.name?.text; const x = literal(p.initializer); if (!key || !x.ok) return { ok: false }; value[key] = x.value; } return { ok: true, value }; }
  return { ok: false };
}
function declaration(file, variableName) {
  let found;
  const visit = (n) => { if (found) return; if (ts.isVariableDeclaration(n) && n.name?.text === variableName) found = n; else ts.forEachChild(n, visit); };
  visit(file); return found;
}
function loc(file, node, path) { const p = file.getLineAndCharacterOfPosition(node.getStart(file)); return { path, line: p.line + 1, column: p.character + 1 }; }
function unknown(unknownFields, field, reason) { if (!unknownFields.includes(field)) unknownFields.push(field); return reason; }
async function sourceAt(repo, ref, path) {
  const safe = normalize(path).replaceAll("\\", "/");
  if (safe !== path || isAbsolute(path) || safe.startsWith("../") || safe.includes("/../")) throw new Error(`unsafe metadata path: ${path}`);
  if (ref && ref !== "WORKTREE") { const { stdout } = await run("git", ["show", `${ref}:${path}`], { cwd: repo, maxBuffer: 32 * 1024 * 1024 }); return Buffer.from(stdout); }
  const st = await lstat(join(repo, path)); if (!st.isFile() || st.isSymbolicLink()) throw new Error(`metadata path is not a regular file: ${path}`);
  return readFile(join(repo, path));
}
function normalizeRecord(id, raw, provenance, fallbackOwner) {
  const unknownFields = [];
  const value = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const specRefs = value.spec_refs ?? value.specRefs;
  const owner = value.owner_document ?? value.ownerDocument ?? fallbackOwner;
  const record = { id, evidenceKind: "declared_current", specRefs: Array.isArray(specRefs) ? specRefs : null, boundaryId: value.boundary_id ?? value.boundaryId ?? null, ownerDocument: owner ?? null, profile: value.profile ?? null, invariants: Array.isArray(value.invariants) ? value.invariants : null, reasonCodes: Array.isArray(value.reason_codes) ? value.reason_codes : null, provenance, unknownFields };
  if (!Array.isArray(specRefs)) unknown("specRefs", "spec_refs unavailable");
  if (record.ownerDocument === null) unknown("ownerDocument", "owner unavailable");
  if (record.boundaryId === null) unknown("boundaryId", "boundary unavailable");
  for (const key of Object.keys(value)) if (!["spec_refs","specRefs","boundary_id","boundaryId","owner_document","ownerDocument","profile","invariants","reason_codes"].includes(key)) unknownFields.push(key);
  return record;
}

/** Read declarations without importing or executing generator/family builders. */
export async function readDeclaredContracts({ repo, ref = "WORKTREE", layout = "auto" }) {
  const currentExists = await sourceExists(repo, ref, CATALOG);
  const selected = layout === "auto" ? (currentExists ? "current-catalog" : "legacy-authoring") : layout;
  const path = selected === "current-catalog" ? CATALOG : LEGACY;
  const unresolved = [];
  let bytes;
  try { bytes = await sourceAt(repo, ref, path); } catch (error) { unresolved.push({ reason: "missing_metadata_source", path, detail: error.message }); return { layout: selected, inputDigest: jsonHash([]), records: [], unresolved }; }
  const source = bytes.toString("utf8"), file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS), spans = symbolSpans({ source, filePath: path });
  const provenanceFor = (node, kind = "declaration") => [{ ...loc(file, node, path), span: spans.find((s) => s.startByte === Buffer.byteLength(source.slice(0, node.getStart(file)), "utf8")) ?? null, sourceDigest: hash(source), kind }];
  const records = [];
  if (selected === "current-catalog") {
    const decl = declaration(file, "CURRENT_CASE_CONTRACTS"), parsed = literal(decl?.initializer);
    if (!parsed.ok || !parsed.value || typeof parsed.value !== "object") { unresolved.push({ reason: "unsupported_contract_declaration", ...loc(file, decl ?? file, path) }); }
    else {
      for (const [id, value] of Object.entries(parsed.value)) {
        let node = decl; if (ts.isObjectLiteralExpression(decl.initializer)) node = [...decl.initializer.properties].find((p) => p.name?.text === id) ?? decl;
        records.push(normalizeRecord(id, value, provenanceFor(node), value?.owner_document));
      }
    }
    const overrides = declaration(file, "TASK_FIFTEEN_BOUNDARIES");
    if (overrides && !literal(overrides.initializer).ok) unresolved.push({ reason: "unsupported_boundary_override", ...loc(file, overrides, path) });
  } else {
    const text = source;
    const groups = [...text.matchAll(/const\s+([A-Z_]+)_IDS\s*=\s*ids\(`([\s\S]*?)`\)/g)];
    for (const [, key, body] of groups) { const owner = key.toLowerCase().replace(/_ids$/, ""); for (const id of body.trim().split(/\s+/).filter(Boolean)) records.push(normalizeRecord(id, { owner_document: owner }, [{ path, line: 1, column: 1, sourceDigest: hash(source), kind: "legacy_declaration" }], owner)); }
    if (!groups.length) unresolved.push({ reason: "unsupported_legacy_metadata", path });
    unresolved.push({ reason: "legacy_spec_refs_unavailable", fields: ["specRefs", "boundaryId", "profile", "invariants", "reasonCodes"] });
  }
  const inputDigest = jsonHash([{ path, ref, sourceDigest: hash(source), layout: selected }]);
  return { layout: selected, inputDigest, records: records.sort((a, b) => a.id.localeCompare(b.id)), unresolved };
}
async function sourceExists(repo, ref, path) { try { await sourceAt(repo, ref, path); return true; } catch { return false; } }
