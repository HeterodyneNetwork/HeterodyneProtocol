import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { extname } from "node:path";

const require = createRequire(new URL("../../docs/spec/vectors/generator/package.json", import.meta.url));
const ts = require("typescript");

const digest = (source) => createHash("sha256").update(source).digest("hex");
const nameOf = (node) => node.name && (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name)) ? node.name.text : undefined;

/** Return stable UTF-8 byte spans for named declarations and catalog properties. */
export function symbolSpans({ source, filePath = "source.ts" }) {
  if (typeof source !== "string") throw new TypeError("source must be a string");
  const file = ts.createSourceFile(filePath, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const sourceDigest = digest(source);
  const result = [];
  const add = (symbol, node) => {
    if (!symbol || !node) return;
    const start = node.getStart(file), end = node.getEnd();
    result.push({ symbol, startByte: Buffer.byteLength(source.slice(0, start), "utf8"), endByte: Buffer.byteLength(source.slice(0, end), "utf8"), sourceDigest });
  };
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isMethodDeclaration(node) || ts.isVariableDeclaration(node)) add(nameOf(node), node);
    if (ts.isPropertyAssignment(node)) add(nameOf(node), node);
    ts.forEachChild(node, visit);
  };
  visit(file);
  return result.sort((a, b) => a.startByte - b.startByte || a.symbol.localeCompare(b.symbol));
}

export { digest as sourceDigest };
