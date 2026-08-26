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
type ImportReference = {
  kind: ImportKind;
  specifier?: string;
  verifiedSnapshotRuntimeTarget?: boolean;
};
type ResolvedRelativeImport = { path: string; sourceEligible: boolean };

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
    const reachablePath = join(canonicalRoot, entry.name);
    const path = realpathSync(reachablePath);
    const status = statSync(path);
    if (status.isDirectory()) {
      files.push(...sourceFiles(path, visitedDirectories));
    } else if (status.isFile() && sourceExtensions.has(extname(reachablePath))) {
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
  let semanticContext: { source: ts.SourceFile; checker: ts.TypeChecker } | undefined;
  const loadSemanticContext = (): { source: ts.SourceFile; checker: ts.TypeChecker } => {
    if (semanticContext !== undefined) return semanticContext;
    const program = ts.createProgram({
      rootNames: [path],
      options: {
        allowJs: true,
        checkJs: false,
        jsx: ts.JsxEmit.Preserve,
        module: ts.ModuleKind.NodeNext,
        moduleResolution: ts.ModuleResolutionKind.NodeNext,
        skipLibCheck: true,
        target: ts.ScriptTarget.ES2022,
      },
    });
    const semanticSource = program.getSourceFile(path);
    if (semanticSource === undefined) throw new Error(`cannot analyze import bindings in ${path}`);
    semanticContext = { source: semanticSource, checker: program.getTypeChecker() };
    return semanticContext;
  };
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
          ...(kind === "import" && isVerifiedSnapshotRuntimeTarget(
            firstArgument,
            source,
            loadSemanticContext,
          )
            ? { verifiedSnapshotRuntimeTarget: true }
            : {}),
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return references;
}

function isVerifiedSnapshotRuntimeTarget(
  expression: ts.Expression | undefined,
  parsedSource: ts.SourceFile,
  loadSemanticContext: () => { source: ts.SourceFile; checker: ts.TypeChecker },
): boolean {
  if (
    expression === undefined
    || !ts.isCallExpression(expression)
    || !ts.isIdentifier(expression.expression)
    || expression.expression.text !== "snapshotRuntimeModuleUrl"
    || expression.arguments.length !== 2
  ) return false;

  const { source, checker } = loadSemanticContext();
  const expressionStart = expression.getStart(parsedSource);
  let semanticExpression: ts.CallExpression | undefined;
  const locate = (node: ts.Node): void => {
    if (semanticExpression !== undefined) return;
    if (ts.isCallExpression(node) && node.getStart(source) === expressionStart) {
      semanticExpression = node;
      return;
    }
    ts.forEachChild(node, locate);
  };
  locate(source);
  if (
    semanticExpression === undefined
    || !ts.isIdentifier(semanticExpression.expression)
  ) return false;

  const wrapperSymbol = checker.getSymbolAtLocation(semanticExpression.expression);
  if (
    wrapperSymbol === undefined
    || !isExactImportedBinding(
      wrapperSymbol,
      "./snapshot-runtime-module-url.js",
      "snapshotRuntimeModuleUrl",
    )
    || symbolHasWrite(source, checker, wrapperSymbol)
  ) return false;

  const runtimeRoot = semanticExpression.arguments[0];
  const emittedTopic = semanticExpression.arguments[1];
  if (
    !ts.isIdentifier(runtimeRoot)
    || runtimeRoot.text !== "runtimeRoot"
    || !ts.isIdentifier(emittedTopic)
    || !/^emittedTopics?$/u.test(emittedTopic.text)
  ) return false;
  const runtimeRootSymbol = checker.getSymbolAtLocation(runtimeRoot);
  const emittedTopicSymbol = checker.getSymbolAtLocation(emittedTopic);
  return runtimeRootSymbol !== undefined
    && emittedTopicSymbol !== undefined
    && isImmutableRuntimeRoot(runtimeRootSymbol, source, checker)
    && isImmutableEmittedTopic(
      emittedTopicSymbol,
      runtimeRootSymbol,
      source,
      checker,
    );
}

function isExactImportedBinding(
  symbol: ts.Symbol,
  moduleSpecifier: string,
  importedName: string,
): boolean {
  if (symbol.declarations?.length !== 1) return false;
  const declaration = symbol.declarations[0];
  if (
    !ts.isImportSpecifier(declaration)
    || declaration.propertyName !== undefined
    || declaration.name.text !== importedName
  ) return false;
  const importDeclaration = declaration.parent.parent.parent;
  return ts.isImportDeclaration(importDeclaration)
    && ts.isStringLiteralLike(importDeclaration.moduleSpecifier)
    && importDeclaration.moduleSpecifier.text === moduleSpecifier;
}

function isImmutableRuntimeRoot(
  symbol: ts.Symbol,
  source: ts.SourceFile,
  checker: ts.TypeChecker,
): boolean {
  const declaration = immutableIdentifierDeclaration(symbol, source, checker);
  if (declaration?.initializer === undefined) return false;
  const initializer = ts.isAwaitExpression(declaration.initializer)
    ? declaration.initializer.expression
    : declaration.initializer;
  if (!ts.isCallExpression(initializer) || !ts.isIdentifier(initializer.expression)) return false;
  const factory = checker.getSymbolAtLocation(initializer.expression);
  if (factory === undefined) return false;
  if (initializer.expression.text === "materializeSnapshotRuntime") {
    return isExactModuleScopeFactory(
      factory,
      "materializeSnapshotRuntime",
      source,
      checker,
    );
  }
  return source.fileName.endsWith("snapshot-topic-runtime.test.ts")
    && initializer.expression.text === "mkdtemp"
    && isExactImportedBinding(factory, "node:fs/promises", "mkdtemp");
}

function isImmutableEmittedTopic(
  symbol: ts.Symbol,
  runtimeRootSymbol: ts.Symbol,
  source: ts.SourceFile,
  checker: ts.TypeChecker,
): boolean {
  const declaration = immutableIdentifierDeclaration(symbol, source, checker);
  const initializer = declaration?.initializer;
  if (
    initializer === undefined
    || !ts.isCallExpression(initializer)
    || !ts.isIdentifier(initializer.expression)
    || initializer.arguments.length < 2
    || !ts.isIdentifier(initializer.arguments[0])
    || checker.getSymbolAtLocation(initializer.arguments[0]) !== runtimeRootSymbol
  ) return false;
  const factory = checker.getSymbolAtLocation(initializer.expression);
  if (factory === undefined) return false;
  if (initializer.expression.text === "emittedPath") {
    return isExactModuleScopeFactory(factory, "emittedPath", source, checker);
  }
  return source.fileName.endsWith("snapshot-topic-runtime.test.ts")
    && initializer.expression.text === "join"
    && isExactImportedBinding(factory, "node:path", "join")
    && initializer.arguments.slice(1).every((argument) =>
      ts.isStringLiteralLike(argument)
      && !argument.text.split(/[\\/]/u).includes(".."));
}

function isExactModuleScopeFactory(
  symbol: ts.Symbol,
  expectedName: string,
  source: ts.SourceFile,
  checker: ts.TypeChecker,
): boolean {
  const declaration = symbol.valueDeclaration;
  return symbol.declarations?.length === 1
    && declaration !== undefined
    && ts.isFunctionDeclaration(declaration)
    && declaration.name?.text === expectedName
    && declaration.parent === source
    && !symbolHasWrite(source, checker, symbol);
}

function immutableIdentifierDeclaration(
  symbol: ts.Symbol,
  source: ts.SourceFile,
  checker: ts.TypeChecker,
): ts.VariableDeclaration | undefined {
  const declaration = symbol.valueDeclaration;
  if (
    declaration === undefined
    || !ts.isVariableDeclaration(declaration)
    || !ts.isIdentifier(declaration.name)
    || !ts.isVariableDeclarationList(declaration.parent)
    || (declaration.parent.flags & ts.NodeFlags.Const) === 0
    || symbolHasWrite(source, checker, symbol)
  ) return undefined;
  return declaration;
}

function symbolHasWrite(
  source: ts.SourceFile,
  checker: ts.TypeChecker,
  symbol: ts.Symbol,
): boolean {
  let written = false;
  const visit = (node: ts.Node): void => {
    if (written) return;
    if (
      ts.isIdentifier(node)
      && checker.getSymbolAtLocation(node) === symbol
      && (ts as unknown as { isAssignmentTarget(value: ts.Node): boolean })
        .isAssignmentTarget(node)
      && !(ts as unknown as { isDeclarationName(value: ts.Node): boolean })
        .isDeclarationName(node)
    ) {
      written = true;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return written;
}

function resolveRelativeImport(importer: string, specifier: string): ResolvedRelativeImport | undefined {
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
  return path === undefined
    ? undefined
    : { path: realpathSync(path), sourceEligible: sourceExtensions.has(extname(path)) };
}

function forbiddenImportEdges(
  sourceRoot: string,
  _packageRoot: string,
  forbiddenRoot: string,
  forbiddenPackageName: string,
  allowedNonliteralImporters: ReadonlySet<string> = new Set(),
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
        if (
          allowedNonliteralImporters.has(importer) &&
          reference.verifiedSnapshotRuntimeTarget === true
        ) continue;
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
      } else if (isWithin(canonicalForbiddenRoot, resolved.path)) {
        forbidden.push({ importer, specifier, resolved: resolved.path });
      } else if (resolved.sourceEligible) {
        pending.push(resolved.path);
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
    const snapshotOnlyNonliteralImporters = new Set([
      realpathSync(resolve(generatorRoot, "src/snapshot-topic-runtime.ts")),
      realpathSync(resolve(generatorRoot, "src/snapshot-topic-runtime.test.ts")),
    ]);
    expect(forbiddenImportEdges(
      resolve(generatorRoot, "src"),
      generatorRoot,
      conformanceRoot,
      "@heterodyne/conformance",
      snapshotOnlyNonliteralImporters,
    )).toEqual([]);
  }, 30_000);

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

  it("follows a source-visible symlink when its real target has no source suffix", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    const shared = join(root, "shared");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(join(right, "src"), { recursive: true });
    mkdirSync(shared, { recursive: true });
    writeFileSync(join(right, "src", "value.ts"), "export const value = 1;\n");
    writeFileSync(join(shared, "helper"), 'import "../right/src/value.js";\n');
    symlinkSync(join(shared, "helper"), join(left, "src", "linked.ts"));

    const edges = forbiddenImportEdges(join(left, "src"), left, right, "@right");
    expect(edges.map((edge) => edge.resolved)).toEqual([
      realpathSync(join(right, "src", "value.ts")),
    ]);
  });

  it("follows an imported source-visible symlink to a suffixless external helper", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    const shared = join(root, "shared");
    const external = join(root, "external");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(join(right, "src"), { recursive: true });
    mkdirSync(shared, { recursive: true });
    mkdirSync(external, { recursive: true });
    writeFileSync(join(left, "src", "index.ts"), 'import "../../shared/linked.js";\n');
    writeFileSync(join(right, "src", "value.ts"), "export const value = 1;\n");
    writeFileSync(join(external, "helper"), 'import "../right/src/value.js";\n');
    symlinkSync(join(external, "helper"), join(shared, "linked.ts"));

    const edges = forbiddenImportEdges(join(left, "src"), left, right, "@right");
    expect(edges.map((edge) => edge.resolved)).toEqual([
      realpathSync(join(right, "src", "value.ts")),
    ]);
  });

  it("allows a clean source-visible symlink whose real target has a different suffix", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    const shared = join(root, "shared");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(right, { recursive: true });
    mkdirSync(shared, { recursive: true });
    writeFileSync(join(shared, "helper.source"), "export const value = 1;\n");
    symlinkSync(join(shared, "helper.source"), join(left, "src", "linked.ts"));

    expect(forbiddenImportEdges(join(left, "src"), left, right, "@right")).toEqual([]);
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

  it("allows only the verified snapshot-runtime wrapper form, not a whole importer file", () => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(right, { recursive: true });
    const snapshotOnly = join(left, "src", "snapshot-only.ts");
    const current = join(left, "src", "current.ts");
    writeFileSync(
      join(left, "src", "snapshot-runtime-module-url.ts"),
      "export function snapshotRuntimeModuleUrl(root: string, target: string): string { return root + target; }\n",
    );
    writeFileSync(
      snapshotOnly,
      'import "@right/runtime";\n'
        + 'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'async function materializeSnapshotRuntime(): Promise<string> { return "/tmp/runtime"; }\n'
        + 'function emittedPath(root: string, source: string): string { return root + source; }\n'
        + 'export async function load(computedConformancePath: string) {\n'
        + '  const runtimeRoot = await materializeSnapshotRuntime();\n'
        + '  const emittedTopic = emittedPath(runtimeRoot, "/topic.js");\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '  void import(computedConformancePath);\n'
        + '}\n',
    );
    writeFileSync(current, "void import(computedCurrentPath);\n");

    const edges = forbiddenImportEdges(
      join(left, "src"),
      left,
      right,
      "@right",
      new Set([realpathSync(snapshotOnly)]),
    );
    expect(edges).toEqual([
      {
        importer: realpathSync(current),
        resolved: "<nonliteral>",
        specifier: "<nonliteral:import>",
      },
      {
        importer: realpathSync(snapshotOnly),
        resolved: "@right",
        specifier: "@right/runtime",
      },
      {
        importer: realpathSync(snapshotOnly),
        resolved: "<nonliteral>",
        specifier: "<nonliteral:import>",
      },
    ]);
  });

  it.each([
    [
      "local same-name wrapper",
      'function snapshotRuntimeModuleUrl(root: string, target: string): string { return root + target; }\n'
        + 'export async function load(runtimeRoot: string, emittedTopic: string) {\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '}\n',
    ],
    [
      "shadowed approved import",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'export async function load(runtimeRoot: string, emittedTopic: string) {\n'
        + '  const snapshotRuntimeModuleUrl = (root: string, target: string) => root + target;\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '}\n',
    ],
    [
      "computed target argument",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'export async function load(runtimeRoot: string, emittedTopic: string) {\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic + ".js"));\n'
        + '}\n',
    ],
    [
      "later lexical shadow",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'export async function load(runtimeRoot: string, emittedTopic: string) {\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '  const snapshotRuntimeModuleUrl = (root: string, target: string) => root + target;\n'
        + '}\n',
    ],
    [
      "rebound approved import",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'snapshotRuntimeModuleUrl = ((root: string, target: string) => root + target) as never;\n'
        + 'export async function load(runtimeRoot: string, emittedTopic: string) {\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '}\n',
    ],
    [
      "arbitrary constant arguments",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'export async function load() {\n'
        + '  const runtimeRoot = "../../right";\n'
        + '  const emittedTopic = "../../right/src/value.js";\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '}\n',
    ],
    [
      "destructured lexical shadow",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'export async function load(runtimeRoot: string, emittedTopic: string, helpers: never) {\n'
        + '  const { snapshotRuntimeModuleUrl } = helpers;\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '}\n',
    ],
    [
      "catch-parameter shadow",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'export async function load(runtimeRoot: string, emittedTopic: string) {\n'
        + '  try { throw new Error(); } catch (snapshotRuntimeModuleUrl) {\n'
        + '    void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '  }\n'
        + '}\n',
    ],
    [
      "loop-binding shadow",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'export async function load(runtimeRoot: string, emittedTopic: string, wrappers: never[]) {\n'
        + '  for (const snapshotRuntimeModuleUrl of wrappers) {\n'
        + '    void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '  }\n'
        + '}\n',
    ],
    [
      "block-local runtime-root factory",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'function emittedPath(root: string, source: string): string { return root + source; }\n'
        + 'export async function load() {\n'
        + '  function materializeSnapshotRuntime(): string { return "../../right"; }\n'
        + '  const runtimeRoot = await materializeSnapshotRuntime();\n'
        + '  const emittedTopic = emittedPath(runtimeRoot, "/topic.js");\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '}\n',
    ],
    [
      "block-local emitted-path factory",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'async function materializeSnapshotRuntime(): Promise<string> { return "/tmp/runtime"; }\n'
        + 'export async function load() {\n'
        + '  function emittedPath(root: string, source: string): string { return "../../right" + source; }\n'
        + '  const runtimeRoot = await materializeSnapshotRuntime();\n'
        + '  const emittedTopic = emittedPath(runtimeRoot, "/topic.js");\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '}\n',
    ],
    [
      "rebound runtime-root factory",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'async function materializeSnapshotRuntime(): Promise<string> { return "/tmp/runtime"; }\n'
        + 'function emittedPath(root: string, source: string): string { return root + source; }\n'
        + 'materializeSnapshotRuntime = (async () => "../../right") as never;\n'
        + 'export async function load() {\n'
        + '  const runtimeRoot = await materializeSnapshotRuntime();\n'
        + '  const emittedTopic = emittedPath(runtimeRoot, "/topic.js");\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '}\n',
    ],
    [
      "rebound emitted-path factory",
      'import { snapshotRuntimeModuleUrl } from "./snapshot-runtime-module-url.js";\n'
        + 'async function materializeSnapshotRuntime(): Promise<string> { return "/tmp/runtime"; }\n'
        + 'function emittedPath(root: string, source: string): string { return root + source; }\n'
        + 'emittedPath = ((root: string, source: string) => "../../right" + source) as never;\n'
        + 'export async function load() {\n'
        + '  const runtimeRoot = await materializeSnapshotRuntime();\n'
        + '  const emittedTopic = emittedPath(runtimeRoot, "/topic.js");\n'
        + '  void import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic));\n'
        + '}\n',
    ],
  ])("rejects a nonliteral import through a %s", (_name, source) => {
    const root = mkdtempSync(join(tmpdir(), "heterodyne-import-boundary-"));
    temporaryRoots.push(root);
    const left = join(root, "left");
    const right = join(root, "right");
    mkdirSync(join(left, "src"), { recursive: true });
    mkdirSync(right, { recursive: true });
    const snapshotOnly = join(left, "src", "snapshot-only.ts");
    writeFileSync(
      join(left, "src", "snapshot-runtime-module-url.ts"),
      "export function snapshotRuntimeModuleUrl(root: string, target: string): string { return root + target; }\n",
    );
    writeFileSync(snapshotOnly, source);

    expect(forbiddenImportEdges(
      join(left, "src"),
      left,
      right,
      "@right",
      new Set([realpathSync(snapshotOnly)]),
    )).toEqual([{
      importer: realpathSync(snapshotOnly),
      resolved: "<nonliteral>",
      specifier: "<nonliteral:import>",
    }]);
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
