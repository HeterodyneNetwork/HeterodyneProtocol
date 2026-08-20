import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { afterEach, describe, expect, it } from "vitest";

type ImportEdge = { importer: string; specifier: string; resolved: string };
type ImportKind = "import" | "require" | "module.require" | "require.resolve";
type ImportReference = { kind: ImportKind; specifier?: string };

const repositoryRoot = fileURLToPath(new URL("../../../../../", import.meta.url));
const conformanceRoot = resolve(repositoryRoot, "docs/spec/conformance");
const generatorRoot = resolve(repositoryRoot, "docs/spec/vectors/generator");
const temporaryRoots: string[] = [];
const sourceExtensions = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs"]);

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith("..") && !path.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`));
}

function sourceFiles(root: string, visitedDirectories = new Set<string>()): string[] {
  const canonicalRoot = realpathSync(root);
  if (visitedDirectories.has(canonicalRoot)) {
    return [];
  }
  visitedDirectories.add(canonicalRoot);

  const files: string[] = [];
  for (const entry of readdirSync(canonicalRoot, { withFileTypes: true })) {
    const path = realpathSync(join(canonicalRoot, entry.name));
    const status = statSync(path);
    if (status.isDirectory()) {
      files.push(...sourceFiles(path, visitedDirectories));
    } else if (status.isFile() && sourceExtensions.has(extname(path))) {
      files.push(path);
    }
  }
  return files.sort();
}

function commonJsImportKind(expression: ts.Expression): ImportKind | undefined {
  if (ts.isIdentifier(expression) && expression.text === "require") {
    return "require";
  }
  if (ts.isPropertyAccessExpression(expression)) {
    if (expression.name.text === "require") {
      return "module.require";
    }
    if (
      expression.name.text === "resolve"
      && ts.isIdentifier(expression.expression)
      && expression.expression.text === "require"
    ) {
      return "require.resolve";
    }
  }
  if (
    ts.isElementAccessExpression(expression)
    && expression.argumentExpression !== undefined
    && ts.isStringLiteralLike(expression.argumentExpression)
  ) {
    if (expression.argumentExpression.text === "require") {
      return "module.require";
    }
    if (
      expression.argumentExpression.text === "resolve"
      && ts.isIdentifier(expression.expression)
      && expression.expression.text === "require"
    ) {
      return "require.resolve";
    }
  }
  return undefined;
}

function importReferences(path: string): ImportReference[] {
  const source = ts.createSourceFile(
    path,
    readFileSync(path, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  const references: ImportReference[] = [];
  const visit = (node: ts.Node): void => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node))
      && node.moduleSpecifier !== undefined
      && ts.isStringLiteralLike(node.moduleSpecifier)
    ) {
      references.push({ kind: "import", specifier: node.moduleSpecifier.text });
    } else if (
      ts.isImportEqualsDeclaration(node)
      && ts.isExternalModuleReference(node.moduleReference)
      && node.moduleReference.expression !== undefined
      && ts.isStringLiteralLike(node.moduleReference.expression)
    ) {
      references.push({ kind: "require", specifier: node.moduleReference.expression.text });
    } else if (
      ts.isCallExpression(node)
    ) {
      const kind = node.expression.kind === ts.SyntaxKind.ImportKeyword
        ? "import"
        : commonJsImportKind(node.expression);
      if (kind !== undefined) {
        const firstArgument = node.arguments[0];
        references.push({
          kind,
          ...(firstArgument !== undefined && ts.isStringLiteralLike(firstArgument)
            ? { specifier: firstArgument.text }
            : {}),
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return references;
}

function resolveRelativeImport(importer: string, specifier: string): string | undefined {
  const unresolved = resolve(dirname(importer), specifier);
  const variants = [
    unresolved,
    unresolved.replace(/\.js$/u, ".ts"),
    unresolved.replace(/\.js$/u, ".tsx"),
    `${unresolved}.ts`,
    `${unresolved}.tsx`,
    `${unresolved}.js`,
    join(unresolved, "index.ts"),
    join(unresolved, "index.tsx"),
    join(unresolved, "index.js"),
  ];
  const path = variants.find((candidate) => existsSync(candidate) && statSync(candidate).isFile());
  return path === undefined ? undefined : realpathSync(path);
}

function forbiddenImportEdges(
  sourceRoot: string,
  _packageRoot: string,
  forbiddenRoot: string,
  forbiddenPackageName: string,
): ImportEdge[] {
  const canonicalForbiddenRoot = realpathSync(forbiddenRoot);
  const pending = sourceFiles(sourceRoot);
  const visited = new Set<string>();
  const forbidden: ImportEdge[] = [];

  while (pending.length > 0) {
    const importer = realpathSync(pending.pop()!);
    if (visited.has(importer)) {
      continue;
    }
    visited.add(importer);
    if (isWithin(canonicalForbiddenRoot, importer)) {
      forbidden.push({ importer, specifier: "<source-entry>", resolved: importer });
      continue;
    }

    for (const reference of importReferences(importer)) {
      if (reference.specifier === undefined) {
        forbidden.push({
          importer,
          specifier: `<nonliteral:${reference.kind}>`,
          resolved: "<nonliteral>",
        });
        continue;
      }
      const specifier = reference.specifier;
      if (!specifier.startsWith(".")) {
        if (specifier === forbiddenPackageName || specifier.startsWith(`${forbiddenPackageName}/`)) {
          forbidden.push({ importer, specifier, resolved: forbiddenPackageName });
        }
        continue;
      }

      const resolved = resolveRelativeImport(importer, specifier);
      if (resolved === undefined) {
        forbidden.push({ importer, specifier, resolved: "<unresolved>" });
      } else if (isWithin(canonicalForbiddenRoot, resolved)) {
        forbidden.push({ importer, specifier, resolved });
      } else if (sourceExtensions.has(extname(resolved))) {
        pending.push(resolved);
      }
    }
  }

  return forbidden.sort((left, right) =>
    `${left.importer}\0${left.specifier}`.localeCompare(`${right.importer}\0${right.specifier}`));
}

afterEach(() => {
  while (temporaryRoots.length > 0) {
    rmSync(temporaryRoots.pop()!, { recursive: true, force: true });
  }
});

describe("reciprocal package import boundary", () => {
  it("recursively resolves conformance imports and rejects generator reachability", () => {
    expect(forbiddenImportEdges(
      resolve(conformanceRoot, "src"),
      conformanceRoot,
      generatorRoot,
      "@heterodyne/vector-generator",
    )).toEqual([]);
  });

  it("scans generator source and rejects conformance reachability", () => {
    expect(forbiddenImportEdges(
      resolve(generatorRoot, "src"),
      generatorRoot,
      conformanceRoot,
      "@heterodyne/conformance",
    )).toEqual([]);
  });

  it("detects a relative import crossing either package boundary", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(join(right, "src"), { recursive: true });
    writeFileSync(join(left, "src", "index.ts"), 'import "../../right/src/value.js";\n');
    writeFileSync(join(right, "src", "value.ts"), "export const value = 1;\n");

    expect(forbiddenImportEdges(join(left, "src"), left, right, "@right")).toHaveLength(1);
    writeFileSync(join(right, "src", "back.ts"), 'import "../../left/src/index.js";\n');
    expect(forbiddenImportEdges(join(right, "src"), right, left, "@left")).toHaveLength(1);
  });

  it("detects package-name imports and unresolved relative imports", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(right, { recursive: true });
    writeFileSync(
      join(left, "src", "index.ts"),
      'import "@right/runtime";\nexport { value } from "./missing.js";\n',
    );

    const edges = forbiddenImportEdges(join(left, "src"), left, right, "@right");
    expect(edges.map((edge) => edge.resolved).sort()).toEqual(["<unresolved>", "@right"]);
  });

  it("detects TypeScript import-equals and dynamic imports carrying options", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(join(right, "src"), { recursive: true });
    writeFileSync(
      join(left, "src", "index.ts"),
      'import runtime = require("@right/runtime");\nvoid runtime;\nvoid import("../../right/src/value.mjs", { with: { type: "json" } });\n',
    );
    writeFileSync(join(right, "src", "value.mjs"), "export const value = 1;\n");

    const edges = forbiddenImportEdges(join(left, "src"), left, right, "@right");
    expect(edges.map((edge) => edge.resolved).sort()).toEqual([
      realpathSync(join(right, "src", "value.mjs")),
      "@right",
    ].sort());
  });

  it("follows a source symlink whose real target reaches the forbidden package", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    const shared = join(root, "shared");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(join(right, "src"), { recursive: true });
    mkdirSync(shared, { recursive: true });
    writeFileSync(join(right, "src", "value.ts"), "export const value = 1;\n");
    writeFileSync(join(shared, "helper.ts"), 'import "../right/src/value.js";\n');
    symlinkSync(join(shared, "helper.ts"), join(left, "src", "linked.ts"));

    const edges = forbiddenImportEdges(join(left, "src"), left, right, "@right");
    expect(edges.map((edge) => edge.resolved)).toEqual([
      realpathSync(join(right, "src", "value.ts")),
    ]);
  });

  it("rejects a source symlink whose target is itself in the forbidden package", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(join(right, "src"), { recursive: true });
    writeFileSync(join(right, "src", "value.ts"), "export const value = 1;\n");
    symlinkSync(join(right, "src", "value.ts"), join(left, "src", "linked.ts"));

    const edges = forbiddenImportEdges(join(left, "src"), left, right, "@right");
    expect(edges.map((edge) => edge.resolved)).toEqual([
      realpathSync(join(right, "src", "value.ts")),
    ]);
  });

  it("follows a two-hop relative import through a helper outside both packages", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    const shared = join(root, "shared");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(join(right, "src"), { recursive: true });
    mkdirSync(shared, { recursive: true });
    writeFileSync(join(left, "src", "index.ts"), 'import "../../shared/helper.js";\n');
    writeFileSync(join(shared, "helper.ts"), 'import "../right/src/value.js";\n');
    writeFileSync(join(right, "src", "value.ts"), "export const value = 1;\n");

    const edges = forbiddenImportEdges(join(left, "src"), left, right, "@right");
    expect(edges.map((edge) => edge.resolved)).toEqual([
      realpathSync(join(right, "src", "value.ts")),
    ]);
  });

  it("fails closed on nonliteral import and CommonJS require variants", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(join(right, "src"), { recursive: true });
    writeFileSync(
      join(left, "src", "index.ts"),
      'const target = "../../right/src/value.js";\nvoid import(target);\nrequire(target);\nmodule.require(target);\nmodule["require"](target);\nrequire.resolve(target);\nmodule.require("../../right/src/value.js");\nrequire.resolve("../../right/src/value.js");\n',
    );
    writeFileSync(join(right, "src", "value.ts"), "export const value = 1;\n");

    const edges = forbiddenImportEdges(join(left, "src"), left, right, "@right");
    expect(edges.map((edge) => edge.resolved).sort()).toEqual([
      "<nonliteral>",
      "<nonliteral>",
      "<nonliteral>",
      "<nonliteral>",
      "<nonliteral>",
      realpathSync(join(right, "src", "value.ts")),
      realpathSync(join(right, "src", "value.ts")),
    ].sort());
  });

  it("allows legitimate reachable local and external helper imports", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    const shared = join(root, "shared");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(right, { recursive: true });
    mkdirSync(shared, { recursive: true });
    writeFileSync(
      join(left, "src", "index.ts"),
      'import "./local.js";\nimport "../../shared/helper.js";\n',
    );
    writeFileSync(join(left, "src", "local.ts"), "export const local = 1;\n");
    writeFileSync(join(shared, "helper.ts"), "export const shared = 1;\n");

    expect(forbiddenImportEdges(join(left, "src"), left, right, "@right")).toEqual([]);
  });
});
