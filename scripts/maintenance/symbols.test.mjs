import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { symbolSpans } from "./symbols.mjs";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

test("symbol spans byte-slice UTF-8 declarations and nested satisfies properties exactly", () => {
  const source = [
    "const café = (({",
    "  \"case/é😀\": { value: 1 },",
    "} as const) satisfies Readonly<Record<string, unknown>>);",
    "function check() {}",
    "class Récepteur { méthode() { return \"✓\"; } }",
    "",
  ].join("\n");
  const spans = symbolSpans({ source, filePath: "fixture.ts" });
  const bytes = Buffer.from(source, "utf8");
  const nested = spans.find((span) => span.symbol === "case/é😀");
  assert.ok(nested);
  const nestedBytes = bytes.subarray(nested.startByte, nested.endByte);
  assert.equal(nestedBytes.toString("utf8"), '\"case/é😀\": { value: 1 }');
  assert.equal(nested.sourceDigest, sha256(nestedBytes));

  const method = spans.find((span) => span.symbol === "méthode");
  assert.equal(bytes.subarray(method.startByte, method.endByte).toString("utf8"), 'méthode() { return "✓"; }');
  assert.equal(method.sourceDigest, sha256(bytes.subarray(method.startByte, method.endByte)));
  assert.ok(spans.some((span) => span.symbol === "check"));
  assert.ok(spans.some((span) => span.symbol === "Récepteur"));
});

test("duplicate names retain distinct deterministic byte spans", () => {
  const source = "const rows = { one: { value: 1 }, two: { value: 2 } };\nclass C { value() {} }\n";
  const spans = symbolSpans({ source, filePath: "fixture.ts" });
  const values = spans.filter((span) => span.symbol === "value");
  assert.equal(values.length, 3);
  assert.deepEqual(values.map(({ startByte }) => startByte), [...values.map(({ startByte }) => startByte)].sort((a, b) => a - b));
});
