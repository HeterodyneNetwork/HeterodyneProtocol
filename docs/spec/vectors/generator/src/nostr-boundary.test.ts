import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const LIVE_AUTHORIZATION_CONSUMERS = [
  "agent-authorship.ts",
  "agent-moderation.ts",
  "assurance.ts",
  "atproto-did-resolution.ts",
  "claims.ts",
  "control-signing.ts",
  "radicle.ts",
  "social-atproto.ts",
  "social-events.ts",
  "social-nip72.ts",
  "trusted-seed.ts",
] as const;

const LEGACY_VERIFIERS = new Set([
  "isStrictNostrSignedEvent",
  "verifyEventSignature",
]);

function calledIdentifiers(file: string): Set<string> {
  const sourceText = readFileSync(resolve(import.meta.dirname, file), "utf8");
  const source = ts.createSourceFile(
    file,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const calls = new Set<string>();
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      calls.add(node.expression.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return calls;
}

describe("live Nostr authorization boundary", () => {
  it.each(LIVE_AUTHORIZATION_CONSUMERS)(
    "%s consumes only a snapshotted or branded verified event",
    (file) => {
      const calls = calledIdentifiers(file);
      expect(
        calls.has("snapshotAndVerifyNostrEvent")
          || calls.has("isVerifiedNostrEvent"),
        `${file} must cross the immutable verified-event boundary`,
      ).toBe(true);
      expect(
        [...LEGACY_VERIFIERS].filter((name) => calls.has(name)),
        `${file} must not authorize through a legacy boolean/type predicate`,
      ).toEqual([]);
    },
  );
});
