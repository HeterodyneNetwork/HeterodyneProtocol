import { existsSync, readFileSync, realpathSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import ts from "typescript";

const SOURCE_ROOT = resolve(import.meta.dirname);
const NODE_BUILTINS = new Set(
  builtinModules.map((specifier) => specifier.replace(/^node:/u, "")),
);
const RUNTIME_LOADER_CAPABILITIES = new Set([
  "createRequire",
  "getBuiltinModule",
  "require",
]);
export const CURRENT_TSCONFIG_PATH = resolve(SOURCE_ROOT, "../tsconfig.current.json");

function isInside(candidate: string, root: string): boolean {
  const rel = relative(root, candidate);
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

export function currentCompilerConfigPath(entry: string): string | undefined {
  const path = realpathSync(entry);
  return isInside(path, SOURCE_ROOT)
    ? CURRENT_TSCONFIG_PATH
    : ts.findConfigFile(dirname(path), ts.sys.fileExists);
}

export function currentCompilerOptions(entry: string): ts.CompilerOptions {
  const configPath = currentCompilerConfigPath(entry);
  if (configPath === undefined) {
    return {
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
    };
  }
  const loaded = ts.readConfigFile(configPath, ts.sys.readFile);
  if (loaded.error !== undefined) {
    throw new Error(`invalid current vector tsconfig: ${configPath}`);
  }
  const parsed = ts.parseJsonConfigFileContent(
    loaded.config,
    ts.sys,
    dirname(configPath),
    undefined,
    configPath,
  );
  if (parsed.errors.length > 0) {
    throw new Error(`invalid current vector tsconfig: ${configPath}`);
  }
  return parsed.options;
}

function staticSpecifier(
  expression: ts.Expression | undefined,
  kind: string,
  path: string,
): string {
  if (expression === undefined || !ts.isStringLiteralLike(expression)) {
    throw new Error(`nonliteral ${kind} in current vector graph: ${path}`);
  }
  return expression.text;
}

function rejectRuntimeLoader(
  path: string,
  source: ts.SourceFile,
  node: ts.Node,
): never {
  const location = source.getLineAndCharacterOfPosition(node.getStart(source));
  throw new Error(
    `runtime-loader syntax prohibited in current vector graph: ${path}`
      + `:${location.line + 1}:${location.character + 1}`,
  );
}

function validateStaticOnly(
  source: ts.SourceFile,
  path: string,
  checker: ts.TypeChecker,
): void {
  const visit = (node: ts.Node): void => {
    // External-module import-equals is the one permitted require-shaped static
    // form. TypeScript resolves it before the graph follows the literal edge.
    if (
      ts.isImportEqualsDeclaration(node)
      && ts.isExternalModuleReference(node.moduleReference)
    ) return;

    if (
      ts.isCallExpression(node)
      && node.expression.kind === ts.SyntaxKind.ImportKeyword
    ) rejectRuntimeLoader(path, source, node);

    if (
      ts.isImportDeclaration(node)
      && ts.isStringLiteralLike(node.moduleSpecifier)
      && ["module", "node:module"].includes(node.moduleSpecifier.text)
    ) {
      const clause = node.importClause;
      if (
        clause?.name !== undefined
        || (clause?.namedBindings !== undefined
          && ts.isNamespaceImport(clause.namedBindings))
      ) rejectRuntimeLoader(path, source, node);
    }

    if (
      ts.isIdentifier(node)
      && RUNTIME_LOADER_CAPABILITIES.has(node.text)
    ) rejectRuntimeLoader(path, source, node);

    if (ts.isIdentifier(node) && node.text === "module") {
      const symbol = checker.getSymbolAtLocation(node);
      const locallyDeclared = symbol?.declarations?.some((declaration) =>
        declaration.getSourceFile() === source
      ) === true;
      if (!locallyDeclared) rejectRuntimeLoader(path, source, node);
    }

    if (
      ts.isElementAccessExpression(node)
      && node.argumentExpression !== undefined
      && ts.isStringLiteralLike(node.argumentExpression)
      && RUNTIME_LOADER_CAPABILITIES.has(node.argumentExpression.text)
    ) rejectRuntimeLoader(path, source, node);

    ts.forEachChild(node, visit);
  };
  visit(source);
}

function collectStaticSpecifiers(
  source: ts.SourceFile,
  path: string,
  checker: ts.TypeChecker,
): string[] {
  validateStaticOnly(source, path, checker);
  const specifiers: string[] = [];
  for (const statement of source.statements) {
    if (ts.isImportDeclaration(statement)) {
      specifiers.push(staticSpecifier(statement.moduleSpecifier, "import", path));
      continue;
    }
    if (ts.isExportDeclaration(statement) && statement.moduleSpecifier !== undefined) {
      specifiers.push(staticSpecifier(statement.moduleSpecifier, "export", path));
      continue;
    }
    if (
      ts.isImportEqualsDeclaration(statement)
      && ts.isExternalModuleReference(statement.moduleReference)
    ) {
      specifiers.push(staticSpecifier(
        statement.moduleReference.expression,
        "import-equals",
        path,
      ));
    }
  }
  return specifiers;
}

export function currentModuleSpecifiers(
  path: string,
  options = currentCompilerOptions(path),
): string[] {
  const canonical = realpathSync(path);
  const program = ts.createProgram({
    rootNames: [canonical],
    options: { ...options, noEmit: true },
  });
  const source = program.getSourceFile(canonical) ?? ts.createSourceFile(
    canonical,
    readFileSync(canonical, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  return collectStaticSpecifiers(source, canonical, program.getTypeChecker());
}

export function currentNamedImports(path: string): Set<string> {
  const source = ts.createSourceFile(
    path,
    readFileSync(path, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  return new Set(source.statements.flatMap((statement) => {
    if (!ts.isImportDeclaration(statement)) return [];
    const bindings = statement.importClause?.namedBindings;
    return bindings !== undefined && ts.isNamedImports(bindings)
      ? bindings.elements.map(({ name }) => name.text)
      : [];
  }));
}

function isNodeBuiltin(specifier: string): boolean {
  const bare = specifier.replace(/^node:/u, "");
  if (specifier.startsWith("node:") && !NODE_BUILTINS.has(bare)) {
    throw new Error(`unknown Node builtin in current vector graph: ${specifier}`);
  }
  return NODE_BUILTINS.has(bare);
}

export function resolveCurrentModule(
  importer: string,
  specifier: string,
  options: ts.CompilerOptions,
  cache?: ts.ModuleResolutionCache,
): string | null {
  if (isNodeBuiltin(specifier)) return null;
  const resolution = ts.resolveModuleName(
    specifier,
    importer,
    options,
    ts.sys,
    cache,
  ).resolvedModule;
  if (resolution === undefined) {
    throw new Error(`unresolved current vector import: ${importer} -> ${specifier}`);
  }
  if (
    resolution.isExternalLibraryImport
    || resolution.resolvedFileName.split(/[\\/]/u).includes("node_modules")
  ) return null;
  if (!existsSync(resolution.resolvedFileName)) {
    throw new Error(`unresolved current vector import: ${importer} -> ${specifier}`);
  }
  return realpathSync(resolution.resolvedFileName);
}

export function currentModuleDependencies(entry: string): string[] {
  const root = realpathSync(entry);
  const options = currentCompilerOptions(root);
  const program = ts.createProgram({
    rootNames: [root],
    options: { ...options, noEmit: true },
  });
  const cache = ts.createModuleResolutionCache(
    dirname(root),
    ts.sys.useCaseSensitiveFileNames ? (path) => path : (path) => path.toLowerCase(),
    options,
  );
  const sources = new Map<string, ts.SourceFile>();
  for (const source of program.getSourceFiles()) {
    if (!existsSync(source.fileName)) continue;
    sources.set(realpathSync(source.fileName), source);
  }

  const visited = new Set<string>();
  const visit = (path: string): void => {
    const canonical = realpathSync(path);
    if (visited.has(canonical)) return;
    visited.add(canonical);
    const source = sources.get(canonical) ?? ts.createSourceFile(
      canonical,
      readFileSync(canonical, "utf8"),
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS,
    );
    for (const specifier of collectStaticSpecifiers(
      source,
      canonical,
      program.getTypeChecker(),
    )) {
      const dependency = resolveCurrentModule(
        canonical,
        specifier,
        options,
        cache,
      );
      if (dependency !== null) visit(dependency);
    }
  };
  visit(root);
  return [...visited].sort();
}
