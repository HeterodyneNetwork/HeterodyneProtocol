import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import ts from "typescript";
import { afterEach, describe, expect, it } from "vitest";
import { buildCurrentVectors } from "./current-vectors/index.js";
import { validateVectorOrThrow } from "./schema.js";

const sourceRoot = resolve(import.meta.dirname);
const catalogEntry = resolve(sourceRoot, "current-vectors/index.ts");
const authorPath = resolve(sourceRoot, "author.ts");
const packagePath = resolve(sourceRoot, "../package.json");
const forbidden = [
  /\/topics[^/]*\.ts$/,
  /\/snapshot[^/]*\.ts$/,
  /\/legacy[^/]*\.ts$/,
  /\/kel(?:-replay)?\.ts$/,
  /\/keri-materialized\.ts$/,
];
const temporaryRoots: string[] = [];

afterEach(() => {
  while (temporaryRoots.length > 0) {
    rmSync(temporaryRoots.pop()!, { recursive: true, force: true });
  }
});

function commonJsLoader(expression: ts.Expression): boolean {
  if (ts.isIdentifier(expression)) return expression.text === "require";
  if (ts.isPropertyAccessExpression(expression)) {
    return expression.name.text === "require"
      || (
        expression.name.text === "resolve"
        && ts.isIdentifier(expression.expression)
        && expression.expression.text === "require"
      );
  }
  if (
    ts.isElementAccessExpression(expression)
    && expression.argumentExpression !== undefined
    && ts.isStringLiteralLike(expression.argumentExpression)
  ) {
    return expression.argumentExpression.text === "require"
      || (
        expression.argumentExpression.text === "resolve"
        && ts.isIdentifier(expression.expression)
        && expression.expression.text === "require"
      );
  }
  return false;
}

function moduleSpecifiers(path: string): string[] {
  const source = ts.createSourceFile(
    path,
    readFileSync(path, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const specifiers: string[] = [];
  const add = (expression: ts.Expression | undefined, kind: string): void => {
    if (expression === undefined || !ts.isStringLiteralLike(expression)) {
      throw new Error(`nonliteral ${kind} in current vector graph: ${path}`);
    }
    specifiers.push(expression.text);
  };
  const visit = (node: ts.Node): void => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node))
      && node.moduleSpecifier !== undefined
    ) {
      add(node.moduleSpecifier, ts.isExportDeclaration(node) ? "export" : "import");
    } else if (
      ts.isImportEqualsDeclaration(node)
      && ts.isExternalModuleReference(node.moduleReference)
    ) {
      add(node.moduleReference.expression, "import-equals");
    } else if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        add(node.arguments[0], "dynamic import");
      } else if (commonJsLoader(node.expression)) {
        add(node.arguments[0], "CommonJS require");
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return specifiers;
}

function resolveModule(importer: string, specifier: string): string {
  const unresolved = resolve(dirname(importer), specifier);
  const variants = [
    unresolved,
    unresolved.replace(/\.m?js$/u, ".ts"),
    unresolved.replace(/\.cjs$/u, ".ts"),
    `${unresolved}.ts`,
    `${unresolved}.tsx`,
    `${unresolved}.js`,
    resolve(unresolved, "index.ts"),
  ];
  const resolved = variants.find((candidate) =>
    existsSync(candidate) && statSync(candidate).isFile()
  );
  if (resolved === undefined) {
    throw new Error(`unresolved current vector import: ${importer} -> ${specifier}`);
  }
  return realpathSync(resolved);
}

function moduleDependencies(entry: string): string[] {
  const visited = new Set<string>();
  const visit = (candidate: string): void => {
    const path = realpathSync(candidate);
    if (visited.has(path)) return;
    visited.add(path);
    for (const specifier of moduleSpecifiers(path)) {
      if (!specifier.startsWith(".")) continue;
      visit(resolveModule(path, specifier));
    }
  };
  visit(entry);
  return [...visited].sort();
}

function importedNames(path: string): Set<string> {
  const source = ts.createSourceFile(
    path,
    readFileSync(path, "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
  return new Set(source.statements.flatMap((statement) => {
    if (!ts.isImportDeclaration(statement)) return [];
    const bindings = statement.importClause?.namedBindings;
    return bindings !== undefined && ts.isNamedImports(bindings)
      ? bindings.elements.map(({ name }) => name.text)
      : [];
  }));
}

describe("current vector catalog import boundary", () => {
  it("keeps the complete catalog graph free of historical authoring modules", () => {
    const graph = moduleDependencies(catalogEntry);
    expect(graph.filter((path) => forbidden.some((pattern) => pattern.test(path))))
      .toEqual([]);
  });

  it("cannot hide forbidden modules behind re-exports or executable import forms", () => {
    const root = mkdtempSync(resolve(tmpdir(), "heterodyne-current-vector-imports-"));
    temporaryRoots.push(root);
    mkdirSync(resolve(root, "nested"), { recursive: true });
    writeFileSync(
      resolve(root, "index.ts"),
      [
        'export { value as named } from "./topics-named.js";',
        'export * from "./topics-star.js";',
        'void import("./snapshot-dynamic.js");',
        'import legacy = require("./legacy-import-equals.js");',
        'require("./kel.js");',
        'module.require("./kel-replay.js");',
        'void legacy;',
      ].join("\n"),
    );
    for (const file of [
      "topics-named.ts",
      "topics-star.ts",
      "snapshot-dynamic.ts",
      "legacy-import-equals.ts",
      "kel.ts",
      "kel-replay.ts",
    ]) {
      writeFileSync(resolve(root, file), "export const value = true;\n");
    }

    const graph = moduleDependencies(resolve(root, "index.ts"));
    expect(graph.filter((path) => forbidden.some((pattern) => pattern.test(path))))
      .toEqual([
        realpathSync(resolve(root, "kel-replay.ts")),
        realpathSync(resolve(root, "kel.ts")),
        realpathSync(resolve(root, "legacy-import-equals.ts")),
        realpathSync(resolve(root, "snapshot-dynamic.ts")),
        realpathSync(resolve(root, "topics-named.ts")),
        realpathSync(resolve(root, "topics-star.ts")),
      ].sort());
  });

  it("makes current authoring consume only the current catalog", () => {
    const imports = importedNames(authorPath);
    expect(imports.has("buildCurrentVectors")).toBe(true);
    expect(imports.has("buildSnapshotCompatibleVectors")).toBe(false);
  });

  it("centralizes current vector and family versions outside family modules", () => {
    for (const family of ["core", "assurance", "comms", "control", "social", "workspace"]) {
      const source = readFileSync(resolve(sourceRoot, `current-vectors/${family}.ts`), "utf8");
      expect(source, family).not.toContain("3.0.0");
      expect(source, family).not.toContain("heterodyne/0.6.0");
    }
  });

  it("keeps the snapshot gate history-materialized instead of running a current-head hybrid", () => {
    const packageJson = JSON.parse(readFileSync(packagePath, "utf8")) as {
      scripts: Record<string, string>;
    };
    expect(packageJson.scripts["snapshot-check"]).toBe("tsx src/cli.ts snapshot-check");
    expect(packageJson.scripts["test:snapshot-adapters"]).toBe("tsx src/cli.ts snapshot-check");
  });
});

describe("current 0.6 vector catalog", () => {
  it("never serializes registry-derived trace labels as semantic vectors", async () => {
    const vectors = (await buildCurrentVectors()).map(({ vector }) => vector);
    expect(vectors.filter(({ vector_id }) => vector_id.includes("/trace/"))).toEqual([]);
    expect(vectors.filter(({ input, expected_output }) =>
      Object.hasOwn(input, "diagnostic_condition")
      || Object.hasOwn(input, "protocol_state")
      || Object.hasOwn(expected_output, "invariant_satisfied")
    )).toEqual([]);
  }, 60_000);

  it("authors the mandatory closure cases from live evaluator results", async () => {
    const vectors = await buildCurrentVectors();
    const byId = new Map(vectors.map(({ vector }) => [vector.vector_id, vector]));
    const expectedOwners = new Map<string, string>([
      ["core/replaceable-future-quarantined", "core"],
      ["core/replaceable-at-premature-boundary", "core"],
      ["core/replaceable-equal-time-lowest-id", "core"],
      ["core/replaceable-advisory-nip03-ignored", "core"],
      ["assurance/enrollment-pending-w-minus-one", "assurance"],
      ["assurance/enrollment-verified-at-window", "assurance"],
      ["assurance/enrollment-timely-contest", "assurance"],
      ["assurance/enrollment-competing-inception", "assurance"],
      ["assurance/enrollment-forged-contest-ignored", "assurance"],
      ["assurance/enrollment-late-warning-no-unpin", "assurance"],
      ["assurance/witness-threshold-pass", "assurance"],
      ["assurance/witness-threshold-fail", "assurance"],
      ["comms/checkpoint-exact-boundary", "comms"],
      ["comms/checkpoint-stale-independent", "comms"],
      ["comms/authorization-view-300-boundary", "comms"],
      ["comms/authorization-view-86400-boundary", "comms"],
      ["comms/authorization-view-maximum-malformed", "comms"],
      ["comms/tier3-recipient-confined", "comms"],
      ["control/opaque-authorization-view-accepted", "control"],
      ["control/caller-freshness-booleans-rejected", "control"],
      ["control/authorization-view-stale-at-effect", "control"],
      ["social/source-neutral-core-quarantine", "social"],
      ["social/source-neutral-vanilla-authorship", "social"],
      ["workspace/bare-key-baseline", "workspace"],
      ["workspace/assurance-verified-activation", "workspace"],
      ["workspace/assurance-pending-activation", "workspace"],
      ["workspace/assurance-unilateral-removal", "workspace"],
      ["workspace/assurance-dual-removal", "workspace"],
      ["workspace/assurance-history-mutation-revalidated", "workspace"],
    ]);
    for (const [id, owner] of expectedOwners) {
      expect(byId.get(id), id).toMatchObject({ owner_document: owner });
    }
    expect(byId.get("core/replaceable-future-quarantined")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "core-created-at-premature" });
    expect(byId.get("assurance/enrollment-pending-w-minus-one")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "assurance-enrollment-pending-window" });
    expect(byId.get("assurance/enrollment-late-warning-no-unpin")?.expected_output)
      .toMatchObject({ verdict: "accept", state: "verified" });
    expect(byId.get("comms/checkpoint-stale-independent")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "oidc-checkpoint-stale" });
    expect(byId.get("control/authorization-view-stale-at-effect")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "control-authorization-view-stale" });
    expect(byId.get("workspace/assurance-history-mutation-revalidated")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "workspace-assurance-state-required" });
  }, 60_000);

  it("emits deterministic unique paths and schema-valid exact traceability", async () => {
    const first = await buildCurrentVectors();
    const second = await buildCurrentVectors();
    expect(second).toEqual(first);
    expect(new Set(first.map(({ relativePath }) => relativePath)).size).toBe(first.length);
    expect(new Set(first.map(({ vector }) => vector.vector_id)).size).toBe(first.length);
    for (const { vector } of first) expect(() => validateVectorOrThrow(vector)).not.toThrow();
  }, 60_000);
});
