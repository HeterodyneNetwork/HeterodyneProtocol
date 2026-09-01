import { existsSync, readFileSync, realpathSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import ts from "typescript";

const SOURCE_ROOT = resolve(import.meta.dirname);
const REPOSITORY_ROOT = resolve(SOURCE_ROOT, "../../../../../");
const NODE_BUILTINS = new Set(
  builtinModules.map((specifier) => specifier.replace(/^node:/u, "")),
);
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

function unwrapParentheses(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (ts.isParenthesizedExpression(current)) current = current.expression;
  return current;
}

function variableDeclarations(source: ts.SourceFile): ts.VariableDeclaration[] {
  const declarations: ts.VariableDeclaration[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      declarations.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return declarations;
}

function isAmbientRequire(
  identifier: ts.Identifier,
  checker: ts.TypeChecker,
): boolean {
  if (identifier.text !== "require") return false;
  const symbol = checker.getSymbolAtLocation(identifier);
  return symbol === undefined
    || (symbol.declarations?.length ?? 0) > 0
      && symbol.declarations!.every((declaration) => declaration.getSourceFile().isDeclarationFile);
}

function identifierSymbol(
  identifier: ts.Identifier,
  checker: ts.TypeChecker,
): ts.Symbol | undefined {
  if (
    identifier.parent !== undefined
    && ts.isShorthandPropertyAssignment(identifier.parent)
    && identifier.parent.name === identifier
  ) {
    return checker.getShorthandAssignmentValueSymbol(identifier.parent)
      ?? checker.getSymbolAtLocation(identifier);
  }
  return checker.getSymbolAtLocation(identifier);
}

function isRequireAliasInitializer(
  expression: ts.Expression | undefined,
  aliases: ReadonlySet<ts.Symbol>,
  checker: ts.TypeChecker,
): expression is ts.Identifier {
  if (expression === undefined) return false;
  const unwrapped = unwrapParentheses(expression);
  if (!ts.isIdentifier(unwrapped)) return false;
  if (isAmbientRequire(unwrapped, checker)) return true;
  const symbol = identifierSymbol(unwrapped, checker);
  return symbol !== undefined && aliases.has(symbol);
}

function containsUncalledAliasReference(
  expression: ts.Expression,
  aliases: ReadonlySet<ts.Symbol>,
  checker: ts.TypeChecker,
): boolean {
  let found = false;
  const visit = (node: ts.Node, parent?: ts.Node): void => {
    if (found) return;
    if (
      ts.isIdentifier(node)
      && (isAmbientRequire(node, checker)
        || (() => {
          const symbol = identifierSymbol(node, checker);
          return symbol !== undefined && aliases.has(symbol);
        })())
      && !(parent !== undefined
        && ts.isCallExpression(parent)
        && parent.expression === node)
    ) {
      found = true;
      return;
    }
    ts.forEachChild(node, (child) => visit(child, node));
  };
  visit(expression);
  return found;
}

function targetContainsAlias(
  target: ts.Node,
  aliases: ReadonlySet<ts.Symbol>,
  checker: ts.TypeChecker,
): boolean {
  let found = false;
  const visit = (node: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(node)) {
      const symbol = identifierSymbol(node, checker);
      if (symbol !== undefined && aliases.has(symbol)) {
        found = true;
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(target);
  return found;
}

function requireAliases(
  source: ts.SourceFile,
  path: string,
  checker: ts.TypeChecker,
): Set<ts.Symbol> {
  const declarations = variableDeclarations(source);
  const aliases = new Set<ts.Symbol>();
  let changed = true;
  while (changed) {
    changed = false;
    for (const declaration of declarations) {
      if (!ts.isIdentifier(declaration.name)) continue;
      const symbol = identifierSymbol(declaration.name, checker);
      if (
        symbol === undefined
        || aliases.has(symbol)
        || !isRequireAliasInitializer(declaration.initializer, aliases, checker)
      ) continue;
      aliases.add(symbol);
      changed = true;
    }
  }

  for (const declaration of declarations) {
    if (
      declaration.initializer !== undefined
      && !isRequireAliasInitializer(declaration.initializer, aliases, checker)
      && containsUncalledAliasReference(declaration.initializer, aliases, checker)
    ) {
      throw new Error(`ambiguous require alias in current vector graph: ${path}`);
    }
  }

  const visit = (node: ts.Node): void => {
    if (
      ts.isBinaryExpression(node)
      && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
      && targetContainsAlias(node.left, aliases, checker)
    ) {
      throw new Error(`reassigned require alias in current vector graph: ${path}`);
    }
    if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
      && (node.operator === ts.SyntaxKind.PlusPlusToken
        || node.operator === ts.SyntaxKind.MinusMinusToken)
      && targetContainsAlias(node.operand, aliases, checker)
    ) {
      throw new Error(`reassigned require alias in current vector graph: ${path}`);
    }
    if (
      (ts.isForInStatement(node) || ts.isForOfStatement(node))
      && targetContainsAlias(node.initializer, aliases, checker)
    ) {
      throw new Error(`reassigned require alias in current vector graph: ${path}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return aliases;
}

function collectStaticSpecifiers(
  source: ts.SourceFile,
  path: string,
  checker: ts.TypeChecker,
): string[] {
  const specifiers: string[] = [];
  const aliases = requireAliases(source, path, checker);
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node)) {
      specifiers.push(staticSpecifier(node.moduleSpecifier, "import", path));
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) {
      specifiers.push(staticSpecifier(node.moduleSpecifier, "export", path));
    } else if (
      ts.isImportEqualsDeclaration(node)
      && ts.isExternalModuleReference(node.moduleReference)
    ) {
      specifiers.push(staticSpecifier(
        node.moduleReference.expression,
        "import-equals",
        path,
      ));
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      specifiers.push(staticSpecifier(node.arguments[0], "import()", path));
    } else if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      if (isAmbientRequire(node.expression, checker)) {
        specifiers.push(staticSpecifier(node.arguments[0], "require", path));
      } else {
        const symbol = identifierSymbol(node.expression, checker);
        if (symbol !== undefined && aliases.has(symbol)) {
          specifiers.push(staticSpecifier(node.arguments[0], "require alias", path));
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
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
  const source = program.getSourceFile(canonical);
  if (source === undefined) {
    throw new Error(`unreadable current vector module: ${canonical}`);
  }
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

/**
 * Audit compiler-resolved static composition of trusted current-catalog
 * source. This intentionally does not interpret or sandbox runtime code.
 */
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
  const checker = program.getTypeChecker();
  const sources = new Map<string, Readonly<{
    source: ts.SourceFile;
    checker: ts.TypeChecker;
  }>>();
  for (const source of program.getSourceFiles()) {
    if (!existsSync(source.fileName)) continue;
    sources.set(realpathSync(source.fileName), { source, checker });
  }

  const visited = new Set<string>();
  const visit = (path: string): void => {
    const canonical = realpathSync(path);
    if (visited.has(canonical)) return;
    visited.add(canonical);
    let analysis = sources.get(canonical);
    if (analysis === undefined) {
      const dependencyProgram = ts.createProgram({
        rootNames: [canonical],
        options: { ...options, noEmit: true },
      });
      const source = dependencyProgram.getSourceFile(canonical);
      if (source === undefined) {
        throw new Error(`unreadable current vector module: ${canonical}`);
      }
      analysis = { source, checker: dependencyProgram.getTypeChecker() };
      sources.set(canonical, analysis);
    }
    for (const specifier of collectStaticSpecifiers(
      analysis.source,
      canonical,
      analysis.checker,
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

export function assertExactCurrentModuleGraph(
  entry: string,
  allowlist: readonly string[],
): void {
  const actual = currentModuleDependencies(entry).map((path) =>
    relative(REPOSITORY_ROOT, path).split(sep).join("/")).sort();
  const exact = actual.length === allowlist.length
    && actual.every((path, index) => path === allowlist[index]);
  if (!exact) {
    throw new Error([
      "exact current module graph mismatch",
      `expected: ${JSON.stringify(allowlist)}`,
      `actual: ${JSON.stringify(actual)}`,
    ].join("\n"));
  }
}
