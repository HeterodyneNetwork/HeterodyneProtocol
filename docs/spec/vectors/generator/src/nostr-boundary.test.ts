import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const LIVE_AUTHORIZATION_CONSUMERS = [
  "agent-authorship.ts",
  "agent-moderation.ts",
  "assurance.ts",
  "atproto-did-resolution.ts",
  "claim-ledger.ts",
  "claims.ts",
  "control-signing.ts",
  "core-policy.ts",
  "radicle.ts",
  "replaceable-selection.ts",
  "social-atproto.ts",
  "social-events.ts",
  "social-nip72.ts",
  "social-policy.ts",
  "trusted-seed.ts",
] as const;

const LEGACY_VERIFIERS = new Set([
  "agentBindingMessage",
  "isStrictNostrSignedEvent",
  "validateAgentDelegation",
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

function importsNostrAuthorizationBoundary(file: string): boolean {
  const sourceText = readFileSync(resolve(import.meta.dirname, file), "utf8");
  const source = ts.createSourceFile(
    file,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  return source.statements.some((statement) =>
    ts.isImportDeclaration(statement)
    && statement.moduleSpecifier.getText(source) === '"./nostr.js"'
    && statement.importClause?.namedBindings !== undefined
    && ts.isNamedImports(statement.importClause.namedBindings)
    && statement.importClause.namedBindings.elements.some(({ name }) => [
      "NostrSignedEvent",
      "VerifiedNostrEvent",
      "snapshotAndVerifyNostrEvent",
    ].includes(name.text)));
}

function liveSourceFiles(): string[] {
  return readdirSync(import.meta.dirname)
    .filter((file) => file.endsWith(".ts") && !file.endsWith(".test.ts"))
    .filter((file) => ![
      "author.ts",
      "fixtures.ts",
      "nostr.ts",
    ].includes(file))
    .filter((file) => ![
      "kel",
      "keri-",
      "legacy-",
      "snapshot-",
      "topics",
    ].some((prefix) => file.startsWith(prefix)));
}

describe("live Nostr authorization boundary", () => {
  it("has an exact compiler-visible consumer inventory", () => {
    expect(liveSourceFiles().filter(importsNostrAuthorizationBoundary).sort())
      .toEqual([...LIVE_AUTHORIZATION_CONSUMERS].sort());
  });

  it("has no live import of the retired caller-asserted delegation helper", () => {
    for (const file of liveSourceFiles()) {
      const source = readFileSync(resolve(import.meta.dirname, file), "utf8");
      expect(source, file).not.toContain("./legacy-agent-delegation.js");
    }
  });

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
