import { createHash } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(new URL("../../docs/spec/vectors/generator/package.json", import.meta.url));
const ts = require("typescript");
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function declarationName(node) {
  const name = node.name;
  if (name && (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name))) {
    return name.text;
  }
  return undefined;
}

/**
 * Return deterministic UTF-8 byte spans for named TypeScript declarations.
 * `sourceDigest` identifies the exact span bytes, not the containing file.
 */
export function symbolSpans({ source, filePath = "source.ts" }) {
  if (typeof source !== "string") throw new TypeError("source must be a string");
  const file = ts.createSourceFile(filePath, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const bytes = Buffer.from(source, "utf8");
  const spans = [];
  const byteOffset = (position) => Buffer.byteLength(source.slice(0, position), "utf8");
  const add = (node) => {
    const symbol = declarationName(node);
    if (symbol === undefined) return;
    const startByte = byteOffset(node.getStart(file));
    const endByte = byteOffset(node.getEnd());
    spans.push({
      symbol,
      startByte,
      endByte,
      sourceDigest: sha256(bytes.subarray(startByte, endByte)),
    });
  };
  const visit = (node) => {
    if (
      ts.isFunctionDeclaration(node)
      || ts.isClassDeclaration(node)
      || ts.isMethodDeclaration(node)
      || ts.isVariableDeclaration(node)
      || ts.isPropertyAssignment(node)
      || ts.isMethodSignature(node)
    ) add(node);
    ts.forEachChild(node, visit);
  };
  visit(file);
  return spans.sort((left, right) => left.startByte - right.startByte
    || left.endByte - right.endByte
    || left.symbol.localeCompare(right.symbol, "en"));
}

export function sourceDigest(value) {
  return sha256(value);
}
