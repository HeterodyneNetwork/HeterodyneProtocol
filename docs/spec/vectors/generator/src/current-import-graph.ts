import { existsSync, readFileSync, realpathSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import ts from "typescript";

const SOURCE_ROOT = resolve(import.meta.dirname);
const NODE_BUILTINS = new Set(builtinModules);
export const CURRENT_TSCONFIG_PATH = resolve(SOURCE_ROOT, "../tsconfig.current.json");

type Provenance =
  | "none"
  | "require"
  | "create-require"
  | "module-namespace"
  | "ambiguous";

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

function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current)
    || ts.isAsExpression(current)
    || ts.isTypeAssertionExpression(current)
    || ts.isNonNullExpression(current)
    || ts.isSatisfiesExpression(current)
  ) current = current.expression;
  return current;
}

function joinProvenance(left: Provenance, right: Provenance): Provenance {
  if (left === right) return left;
  if (left === "ambiguous" || right === "ambiguous") return "ambiguous";
  return left === "none" && right === "none" ? "none" : "ambiguous";
}

function propertyNameText(name: ts.PropertyName | undefined): string | undefined {
  if (name === undefined) return undefined;
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) return name.text;
  return undefined;
}

class ImportCollector {
  readonly #source: ts.SourceFile;
  readonly #checker: ts.TypeChecker;
  readonly #path: string;
  readonly #specifiers: string[] = [];
  readonly #states = new Map<ts.Symbol, Provenance>();

  constructor(path: string, options: ts.CompilerOptions) {
    this.#path = realpathSync(path);
    const program = ts.createProgram({
      rootNames: [this.#path],
      options: { ...options, noEmit: true },
    });
    this.#checker = program.getTypeChecker();
    this.#source = program.getSourceFile(this.#path) ?? ts.createSourceFile(
      this.#path,
      readFileSync(this.#path, "utf8"),
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS,
    );
  }

  collect(): string[] {
    this.#registerImports();
    for (const statement of this.#source.statements) this.#statement(statement);
    return this.#specifiers;
  }

  #symbol(identifier: ts.Identifier): ts.Symbol | undefined {
    return this.#checker.getSymbolAtLocation(identifier);
  }

  #localSymbol(identifier: ts.Identifier): ts.Symbol | undefined {
    const symbol = this.#symbol(identifier);
    return symbol?.declarations?.some((declaration) =>
      declaration.getSourceFile() === this.#source
    ) === true
      ? symbol
      : undefined;
  }

  #set(identifier: ts.Identifier, state: Provenance): void {
    const symbol = this.#symbol(identifier);
    if (symbol !== undefined) this.#states.set(symbol, state);
  }

  #state(identifier: ts.Identifier): Provenance {
    const symbol = this.#symbol(identifier);
    if (symbol !== undefined && this.#states.has(symbol)) {
      return this.#states.get(symbol)!;
    }
    if (this.#localSymbol(identifier) !== undefined) return "none";
    if (identifier.text === "require") return "require";
    if (identifier.text === "module") return "module-namespace";
    return "none";
  }

  #registerImports(): void {
    for (const statement of this.#source.statements) {
      if (!ts.isImportDeclaration(statement)) continue;
      this.#add(statement.moduleSpecifier, "import");
      if (!ts.isStringLiteralLike(statement.moduleSpecifier)) continue;
      if (statement.moduleSpecifier.text !== "node:module") continue;
      const bindings = statement.importClause?.namedBindings;
      if (bindings !== undefined && ts.isNamespaceImport(bindings)) {
        this.#set(bindings.name, "module-namespace");
      } else if (bindings !== undefined && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) {
          if ((element.propertyName?.text ?? element.name.text) === "createRequire") {
            this.#set(element.name, "create-require");
          }
        }
      }
    }
  }

  #add(expression: ts.Expression | undefined, kind: string): void {
    if (expression === undefined || !ts.isStringLiteralLike(unwrap(expression))) {
      throw new Error(`nonliteral ${kind} in current vector graph: ${this.#path}`);
    }
    this.#specifiers.push((unwrap(expression) as ts.StringLiteralLike).text);
  }

  #snapshot(): Map<ts.Symbol, Provenance> {
    return new Map(this.#states);
  }

  #restore(snapshot: ReadonlyMap<ts.Symbol, Provenance>): void {
    this.#states.clear();
    for (const [symbol, state] of snapshot) this.#states.set(symbol, state);
  }

  #merge(
    before: ReadonlyMap<ts.Symbol, Provenance>,
    left: ReadonlyMap<ts.Symbol, Provenance>,
    right: ReadonlyMap<ts.Symbol, Provenance>,
  ): void {
    this.#states.clear();
    const symbols = new Set([...before.keys(), ...left.keys(), ...right.keys()]);
    for (const symbol of symbols) {
      const initial = before.get(symbol) ?? "none";
      this.#states.set(
        symbol,
        joinProvenance(left.get(symbol) ?? initial, right.get(symbol) ?? initial),
      );
    }
  }

  #statement(statement: ts.Statement): void {
    if (ts.isImportDeclaration(statement)) return;
    if (ts.isExportDeclaration(statement)) {
      if (statement.moduleSpecifier !== undefined) this.#add(statement.moduleSpecifier, "export");
      return;
    }
    if (
      ts.isImportEqualsDeclaration(statement)
      && ts.isExternalModuleReference(statement.moduleReference)
    ) {
      this.#add(statement.moduleReference.expression, "import-equals");
      return;
    }
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (declaration.initializer !== undefined) this.#expression(declaration.initializer);
        this.#bind(declaration.name, declaration.initializer);
      }
      return;
    }
    if (ts.isExpressionStatement(statement)) {
      this.#expression(statement.expression);
      return;
    }
    if (ts.isIfStatement(statement)) {
      this.#expression(statement.expression);
      const before = this.#snapshot();
      this.#statementOrBlock(statement.thenStatement);
      const left = this.#snapshot();
      this.#restore(before);
      if (statement.elseStatement !== undefined) this.#statementOrBlock(statement.elseStatement);
      const right = this.#snapshot();
      this.#merge(before, left, right);
      return;
    }
    if (ts.isBlock(statement)) {
      for (const child of statement.statements) this.#statement(child);
      return;
    }
    if (
      ts.isFunctionDeclaration(statement)
      || ts.isClassDeclaration(statement)
    ) {
      const before = this.#snapshot();
      if (ts.isFunctionDeclaration(statement)) {
        for (const parameter of statement.parameters) this.#bind(parameter.name, undefined);
        if (statement.body !== undefined) this.#statement(statement.body);
      } else {
        for (const member of statement.members) {
          if (member.name !== undefined && ts.isComputedPropertyName(member.name)) {
            this.#expression(member.name.expression);
          }
          if (
            (ts.isMethodDeclaration(member)
              || ts.isConstructorDeclaration(member)
              || ts.isGetAccessorDeclaration(member)
              || ts.isSetAccessorDeclaration(member))
            && member.body !== undefined
          ) this.#statement(member.body);
          if (ts.isPropertyDeclaration(member) && member.initializer !== undefined) {
            this.#expression(member.initializer);
          }
        }
      }
      this.#restore(before);
      return;
    }
    if (
      ts.isForStatement(statement)
      || ts.isForInStatement(statement)
      || ts.isForOfStatement(statement)
      || ts.isWhileStatement(statement)
      || ts.isDoStatement(statement)
    ) {
      const before = this.#snapshot();
      if (ts.isForStatement(statement)) {
        if (statement.initializer !== undefined) {
          if (ts.isVariableDeclarationList(statement.initializer)) {
            for (const declaration of statement.initializer.declarations) {
              if (declaration.initializer !== undefined) this.#expression(declaration.initializer);
              this.#bind(declaration.name, declaration.initializer);
            }
          } else this.#expression(statement.initializer);
        }
        if (statement.condition !== undefined) this.#expression(statement.condition);
        if (statement.incrementor !== undefined) this.#expression(statement.incrementor);
      } else if (ts.isForInStatement(statement) || ts.isForOfStatement(statement)) {
        this.#expression(statement.expression);
      } else this.#expression(statement.expression);
      this.#statementOrBlock(statement.statement);
      const after = this.#snapshot();
      this.#merge(before, before, after);
      return;
    }
    if (ts.isReturnStatement(statement) || ts.isThrowStatement(statement)) {
      if (statement.expression !== undefined) this.#expression(statement.expression);
      return;
    }
    if (ts.isTryStatement(statement)) {
      const before = this.#snapshot();
      this.#statement(statement.tryBlock);
      const tried = this.#snapshot();
      this.#restore(before);
      if (statement.catchClause !== undefined) {
        if (statement.catchClause.variableDeclaration !== undefined) {
          this.#bind(statement.catchClause.variableDeclaration.name, undefined);
        }
        this.#statement(statement.catchClause.block);
      }
      const caught = this.#snapshot();
      this.#merge(before, tried, caught);
      if (statement.finallyBlock !== undefined) this.#statement(statement.finallyBlock);
      return;
    }
    ts.forEachChild(statement, (node) => {
      if (ts.isExpression(node)) this.#expression(node);
      else if (ts.isStatement(node)) this.#statement(node);
    });
  }

  #statementOrBlock(statement: ts.Statement): void {
    this.#statement(statement);
  }

  #bind(name: ts.BindingName, initializer: ts.Expression | undefined): void {
    if (ts.isIdentifier(name)) {
      this.#set(name, initializer === undefined ? "none" : this.#provenance(initializer));
      return;
    }
    if (ts.isObjectBindingPattern(name)) {
      const source = initializer === undefined ? "none" : this.#provenance(initializer);
      for (const element of name.elements) {
        if (element.dotDotDotToken !== undefined) {
          this.#bind(element.name, undefined);
          continue;
        }
        const member = propertyNameText(element.propertyName)
          ?? (ts.isIdentifier(element.name) ? element.name.text : undefined);
        let state: Provenance = "none";
        if (source === "ambiguous") state = "ambiguous";
        else if (source === "module-namespace" && member === "require") state = "require";
        else if (source === "module-namespace" && member === "createRequire") {
          state = "create-require";
        }
        this.#bindState(element.name, state);
      }
      return;
    }
    const array = initializer === undefined ? undefined : unwrap(initializer);
    name.elements.forEach((element, index) => {
      if (!ts.isBindingElement(element)) return;
      const source = array !== undefined && ts.isArrayLiteralExpression(array)
        ? array.elements[index]
        : undefined;
      this.#bind(
        element.name,
        source !== undefined && ts.isExpression(source) ? source : undefined,
      );
    });
  }

  #bindState(name: ts.BindingName, state: Provenance): void {
    if (ts.isIdentifier(name)) this.#set(name, state);
    else {
      for (const element of name.elements) {
        if (ts.isBindingElement(element)) this.#bindState(element.name, state);
      }
    }
  }

  #assign(left: ts.Expression, right: ts.Expression): void {
    const target = unwrap(left);
    if (ts.isIdentifier(target)) {
      this.#set(target, this.#provenance(right));
      return;
    }
    if (ts.isObjectLiteralExpression(target)) {
      const source = this.#provenance(right);
      for (const property of target.properties) {
        if (!ts.isShorthandPropertyAssignment(property) && !ts.isPropertyAssignment(property)) {
          continue;
        }
        const destination = ts.isShorthandPropertyAssignment(property)
          ? property.name
          : unwrap(property.initializer);
        if (!ts.isIdentifier(destination)) continue;
        const member = propertyNameText(property.name);
        const state = source === "ambiguous"
          ? "ambiguous"
          : source === "module-namespace" && member === "require"
            ? "require"
            : source === "module-namespace" && member === "createRequire"
              ? "create-require"
              : "none";
        this.#set(destination, state);
      }
      return;
    }
    if (ts.isArrayLiteralExpression(target)) {
      const source = unwrap(right);
      target.elements.forEach((destination, index) => {
        if (!ts.isIdentifier(destination)) return;
        const element = ts.isArrayLiteralExpression(source) ? source.elements[index] : undefined;
        this.#set(
          destination,
          element !== undefined && ts.isExpression(element)
            ? this.#provenance(element)
            : "none",
        );
      });
    }
  }

  #provenance(expression: ts.Expression): Provenance {
    const value = unwrap(expression);
    if (ts.isIdentifier(value)) return this.#state(value);
    if (ts.isPropertyAccessExpression(value)) {
      const source = this.#provenance(value.expression);
      if (source === "ambiguous") return "ambiguous";
      if (source === "module-namespace" && value.name.text === "require") return "require";
      if (source === "module-namespace" && value.name.text === "createRequire") {
        return "create-require";
      }
      if (source === "require" && value.name.text === "resolve") return "require";
      return "none";
    }
    if (
      ts.isElementAccessExpression(value)
      && value.argumentExpression !== undefined
      && ts.isStringLiteralLike(unwrap(value.argumentExpression))
    ) {
      const source = this.#provenance(value.expression);
      const member = (unwrap(value.argumentExpression) as ts.StringLiteralLike).text;
      if (source === "ambiguous") return "ambiguous";
      if (source === "module-namespace" && member === "require") return "require";
      if (source === "module-namespace" && member === "createRequire") {
        return "create-require";
      }
      if (source === "require" && member === "resolve") return "require";
      return "none";
    }
    if (ts.isCallExpression(value)) {
      const callee = this.#provenance(value.expression);
      if (callee === "create-require") return "require";
      if (
        callee === "require"
        && value.arguments.length > 0
        && ts.isStringLiteralLike(unwrap(value.arguments[0]!))
        && (unwrap(value.arguments[0]!) as ts.StringLiteralLike).text === "node:module"
      ) return "module-namespace";
      return callee === "ambiguous" ? "ambiguous" : "none";
    }
    if (ts.isConditionalExpression(value)) {
      return joinProvenance(
        this.#provenance(value.whenTrue),
        this.#provenance(value.whenFalse),
      );
    }
    return "none";
  }

  #expression(expression: ts.Expression): void {
    const value = unwrap(expression);
    if (ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      this.#expression(value.right);
      this.#assign(value.left, value.right);
      return;
    }
    if (ts.isCallExpression(value)) {
      if (value.expression.kind === ts.SyntaxKind.ImportKeyword) {
        this.#add(value.arguments[0], "dynamic import");
      } else {
        const callee = this.#provenance(value.expression);
        if (callee === "ambiguous") {
          throw new Error(`ambiguous CommonJS loader in current vector graph: ${this.#path}`);
        }
        if (callee === "require") this.#add(value.arguments[0], "CommonJS require");
        for (const argument of value.arguments) this.#expression(argument);
      }
      return;
    }
    if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) {
      const before = this.#snapshot();
      for (const parameter of value.parameters) this.#bind(parameter.name, undefined);
      if (ts.isBlock(value.body)) this.#statement(value.body);
      else this.#expression(value.body);
      this.#restore(before);
      return;
    }
    if (ts.isConditionalExpression(value)) {
      this.#expression(value.condition);
      const before = this.#snapshot();
      this.#expression(value.whenTrue);
      const left = this.#snapshot();
      this.#restore(before);
      this.#expression(value.whenFalse);
      const right = this.#snapshot();
      this.#merge(before, left, right);
      return;
    }
    ts.forEachChild(value, (node) => {
      if (ts.isExpression(node)) this.#expression(node);
    });
  }
}

export function currentModuleSpecifiers(
  path: string,
  options = currentCompilerOptions(path),
): string[] {
  return new ImportCollector(path, options).collect();
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

export function resolveCurrentModule(
  importer: string,
  specifier: string,
  options: ts.CompilerOptions,
): string | null {
  if (specifier.startsWith("node:") || NODE_BUILTINS.has(specifier)) return null;
  const resolution = ts.resolveModuleName(
    specifier,
    importer,
    options,
    ts.sys,
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
  const visited = new Set<string>();
  const options = currentCompilerOptions(entry);
  const visit = (candidate: string): void => {
    const path = realpathSync(candidate);
    if (visited.has(path)) return;
    visited.add(path);
    for (const specifier of currentModuleSpecifiers(path, options)) {
      const dependency = resolveCurrentModule(path, specifier, options);
      if (dependency !== null) visit(dependency);
    }
  };
  visit(entry);
  return [...visited].sort();
}
