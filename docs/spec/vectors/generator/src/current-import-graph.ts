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

function incrementBindingCount(bindings: Map<string, number>, name: ts.BindingName): void {
  if (ts.isIdentifier(name)) {
    bindings.set(name.text, (bindings.get(name.text) ?? 0) + 1);
    return;
  }
  for (const element of name.elements) {
    if (!ts.isOmittedExpression(element)) incrementBindingCount(bindings, element.name);
  }
}

function declarationBindings(source: ts.SourceFile): Map<string, number> {
  const bindings = new Map<string, number>();
  const visit = (node: ts.Node): void => {
    if (
      ts.isVariableDeclaration(node)
      || ts.isParameter(node)
      || ts.isBindingElement(node)
    ) {
      incrementBindingCount(bindings, node.name);
    } else if (
      (ts.isFunctionDeclaration(node)
        || ts.isClassDeclaration(node)
        || ts.isEnumDeclaration(node)
        || ts.isModuleDeclaration(node)
        || ts.isImportEqualsDeclaration(node))
      && node.name !== undefined
      && ts.isIdentifier(node.name)
    ) {
      incrementBindingCount(bindings, node.name);
    } else if (ts.isImportClause(node) && node.name !== undefined) {
      incrementBindingCount(bindings, node.name);
    } else if (ts.isImportSpecifier(node) || ts.isNamespaceImport(node)) {
      incrementBindingCount(bindings, node.name);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return bindings;
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

function isRequireAliasInitializer(
  expression: ts.Expression | undefined,
  aliases: ReadonlySet<string>,
): expression is ts.Identifier {
  if (expression === undefined) return false;
  const unwrapped = unwrapParentheses(expression);
  return ts.isIdentifier(unwrapped)
    && (unwrapped.text === "require" || aliases.has(unwrapped.text));
}

function containsUncalledAliasReference(
  expression: ts.Expression,
  aliases: ReadonlySet<string>,
): boolean {
  let found = false;
  const visit = (node: ts.Node, parent?: ts.Node): void => {
    if (found) return;
    if (
      ts.isIdentifier(node)
      && aliases.has(node.text)
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

function requireAliases(source: ts.SourceFile, path: string): Set<string> {
  const declarations = variableDeclarations(source);
  const aliases = new Set<string>();
  let changed = true;
  while (changed) {
    changed = false;
    for (const declaration of declarations) {
      if (
        !ts.isIdentifier(declaration.name)
        || aliases.has(declaration.name.text)
        || !isRequireAliasInitializer(declaration.initializer, aliases)
      ) continue;
      aliases.add(declaration.name.text);
      changed = true;
    }
  }

  const bindings = declarationBindings(source);
  for (const alias of aliases) {
    if ((bindings.get(alias) ?? 0) !== 1) {
      throw new Error(`ambiguous require alias in current vector graph: ${path}`);
    }
  }

  const requireReferences = new Set(["require", ...aliases]);
  for (const declaration of declarations) {
    if (
      declaration.initializer !== undefined
      && !isRequireAliasInitializer(declaration.initializer, aliases)
      && containsUncalledAliasReference(declaration.initializer, requireReferences)
    ) {
      throw new Error(`ambiguous require alias in current vector graph: ${path}`);
    }
  }

  const visit = (node: ts.Node): void => {
    if (
      ts.isBinaryExpression(node)
      && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
      && ts.isIdentifier(node.left)
      && aliases.has(node.left.text)
    ) {
      throw new Error(`reassigned require alias in current vector graph: ${path}`);
    }
    if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node))
      && ts.isIdentifier(node.operand)
      && aliases.has(node.operand.text)
      && (node.operator === ts.SyntaxKind.PlusPlusToken
        || node.operator === ts.SyntaxKind.MinusMinusToken)
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
): string[] {
  const specifiers: string[] = [];
  const aliases = requireAliases(source, path);
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
      if (node.expression.text === "require") {
        specifiers.push(staticSpecifier(node.arguments[0], "require", path));
      } else if (aliases.has(node.expression.text)) {
        specifiers.push(staticSpecifier(node.arguments[0], "require alias", path));
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
  const source = program.getSourceFile(canonical) ?? ts.createSourceFile(
    canonical,
    readFileSync(canonical, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  return collectStaticSpecifiers(source, canonical);
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
    for (const specifier of collectStaticSpecifiers(source, canonical)) {
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
