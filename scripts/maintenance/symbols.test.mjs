import test from "node:test";
import assert from "node:assert/strict";
import { symbolSpans } from "./symbols.mjs";

test("symbol spans use UTF-8 byte offsets and include nested quoted properties", () => {
  const source = "const café = { \"case/é\": { value: 1 } };\nfunction check() {}";
  const spans = symbolSpans({ source, filePath: "fixture.ts" });
  const nested = spans.find((span) => span.symbol === "case/é");
  assert.equal(nested.startByte, Buffer.byteLength(source.slice(0, source.indexOf("\"case/é\""))));
  assert.equal(nested.sourceDigest.length, 64);
  assert.ok(spans.some((span) => span.symbol === "check"));
});
