import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { lstat, readFile, realpath } from "node:fs/promises";
import { isAbsolute, join, normalize, relative, sep } from "node:path";
import { spawnSync } from "node:child_process";

const require = createRequire(new URL("../../docs/spec/vectors/generator/package.json", import.meta.url));
const ts = require("typescript");

const SOURCE_ROOT = "docs/spec/vectors/generator/src";
const CATALOG_PATH = `${SOURCE_ROOT}/current-vectors/case-contracts.ts`;
const PROFILE_PATH = `${SOURCE_ROOT}/current-vectors/profile-oracles.ts`;
const LEGACY_PATHS = [
  "docs/spec/vectors/README.md",
  `${SOURCE_ROOT}/author.ts`,
  `${SOURCE_ROOT}/vector-metadata.ts`,
  `${SOURCE_ROOT}/verify.ts`,
];
const LEGACY_METADATA = `${SOURCE_ROOT}/vector-metadata.ts`;
const KNOWN_LAYOUTS = new Set(["auto", "current-catalog", "legacy-authoring"]);
const OWNER_BY_GROUP = new Map([
  ["CORE", "core"],
  ["ASSURANCE", "assurance"],
  ["COMMS", "comms"],
  ["CONTROL", "control"],
  ["SOCIAL", "social"],
  ["WORKSPACE", "workspace"],
]);

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
};
const digestJson = (value) => sha256(`${JSON.stringify(canonical(value))}\n`);

function safeRelativePath(path) {
  if (typeof path !== "string" || path.length === 0 || isAbsolute(path)) return false;
  const cleaned = normalize(path).split(sep).join("/");
  return cleaned === path && cleaned !== ".." && !cleaned.startsWith("../") && !cleaned.includes("/../");
}

async function worktreeBytes(repo, path) {
  if (!safeRelativePath(path)) throw new Error(`unsafe metadata path: ${path}`);
  const root = await realpath(repo);
  const absolute = join(root, ...path.split("/"));
  const status = await lstat(absolute);
  if (!status.isFile() || status.isSymbolicLink()) throw new Error(`metadata input is not a regular file: ${path}`);
  const resolved = await realpath(absolute);
  const rel = relative(root, resolved);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error(`metadata input escapes repository: ${path}`);
  return readFile(resolved);
}

async function sourceAt(repo, ref, path) {
  if (!safeRelativePath(path)) throw new Error(`unsafe metadata path: ${path}`);
  if (ref === undefined || ref === null || ref === "WORKTREE") return worktreeBytes(repo, path);
  const tree = spawnSync("git", ["ls-tree", "-z", ref, "--", path], {
    cwd: repo,
    encoding: null,
    maxBuffer: 1024 * 1024,
  });
  const listing = Buffer.from(tree.stdout ?? []).toString("utf8").replace(/\0$/u, "");
  const match = /^(\d{6})\s+blob\s+[a-f0-9]+\t([\s\S]+)$/u.exec(listing);
  if (tree.status !== 0 || !match || match[2] !== path) throw new Error(`historical metadata input is not a blob: ${ref}:${path}`);
  if (match[1] === "120000") throw new Error(`historical metadata input is a symlink: ${ref}:${path}`);
  if (match[1] !== "100644" && match[1] !== "100755") throw new Error(`unsupported historical metadata mode ${match[1]}: ${ref}:${path}`);
  const result = spawnSync("git", ["show", `${ref}:${path}`], {
    cwd: repo,
    encoding: null,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const detail = Buffer.from(result.stderr ?? []).toString("utf8").trim();
    throw new Error(detail || `git show ${ref}:${path} failed`);
  }
  return Buffer.from(result.stdout);
}

async function existsAt(repo, ref, path) {
  try {
    await sourceAt(repo, ref, path);
    return true;
  } catch {
    return false;
  }
}

function sourceFile(path, bytes) {
  return ts.createSourceFile(path, bytes.toString("utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

function unwrap(node) {
  let current = node;
  while (current) {
    if (
      ts.isParenthesizedExpression(current)
      || ts.isAsExpression(current)
      || ts.isTypeAssertionExpression(current)
      || ts.isNonNullExpression(current)
      || current.kind === ts.SyntaxKind.SatisfiesExpression
    ) {
      current = current.expression;
      continue;
    }
    if (
      ts.isCallExpression(current)
      && ts.isPropertyAccessExpression(current.expression)
      && ts.isIdentifier(current.expression.expression)
      && current.expression.expression.text === "Object"
      && current.expression.name.text === "freeze"
      && current.arguments.length === 1
    ) {
      current = current.arguments[0];
      continue;
    }
    break;
  }
  return current;
}

function propertyName(node) {
  const name = node?.name;
  if (name && (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name))) return name.text;
  return undefined;
}

function variable(file, name) {
  let result;
  const visit = (node) => {
    if (result) return;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) {
      result = node;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return result;
}

function findNode(file, predicate) {
  let result;
  const visit = (node) => {
    if (result) return;
    if (predicate(node)) {
      result = node;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return result;
}

function literal(node, env = new Map()) {
  const valueNode = unwrap(node);
  if (!valueNode) return { ok: false };
  if (ts.isStringLiteral(valueNode) || ts.isNoSubstitutionTemplateLiteral(valueNode)) return { ok: true, value: valueNode.text };
  if (ts.isNumericLiteral(valueNode)) return { ok: true, value: Number(valueNode.text) };
  if (valueNode.kind === ts.SyntaxKind.TrueKeyword) return { ok: true, value: true };
  if (valueNode.kind === ts.SyntaxKind.FalseKeyword) return { ok: true, value: false };
  if (valueNode.kind === ts.SyntaxKind.NullKeyword) return { ok: true, value: null };
  if (ts.isIdentifier(valueNode)) return env.has(valueNode.text) ? { ok: true, value: env.get(valueNode.text) } : { ok: false };
  if (ts.isTemplateExpression(valueNode)) {
    let text = valueNode.head.text;
    for (const span of valueNode.templateSpans) {
      const part = literal(span.expression, env);
      if (!part.ok || !["string", "number", "boolean"].includes(typeof part.value)) return { ok: false };
      text += String(part.value) + span.literal.text;
    }
    return { ok: true, value: text };
  }
  if (ts.isArrayLiteralExpression(valueNode)) {
    const values = [];
    for (const element of valueNode.elements) {
      const parsed = literal(element, env);
      if (!parsed.ok) return { ok: false };
      values.push(parsed.value);
    }
    return { ok: true, value: values };
  }
  if (ts.isObjectLiteralExpression(valueNode)) {
    const value = {};
    for (const property of valueNode.properties) {
      if (!ts.isPropertyAssignment(property)) return { ok: false };
      const key = propertyName(property);
      const parsed = literal(property.initializer, env);
      if (key === undefined || !parsed.ok) return { ok: false };
      value[key] = parsed.value;
    }
    return { ok: true, value };
  }
  if (ts.isConditionalExpression(valueNode)) {
    const condition = literal(valueNode.condition, env);
    if (!condition.ok || typeof condition.value !== "boolean") return { ok: false };
    return literal(condition.value ? valueNode.whenTrue : valueNode.whenFalse, env);
  }
  if (ts.isBinaryExpression(valueNode)) {
    const left = literal(valueNode.left, env);
    const right = literal(valueNode.right, env);
    if (!left.ok || !right.ok) return { ok: false };
    if (valueNode.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken) return { ok: true, value: left.value === right.value };
    if (valueNode.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken) return { ok: true, value: left.value !== right.value };
  }
  return { ok: false };
}

function byteSpan(file, node) {
  const source = file.text;
  return {
    startByte: Buffer.byteLength(source.slice(0, node.getStart(file)), "utf8"),
    endByte: Buffer.byteLength(source.slice(0, node.getEnd()), "utf8"),
  };
}

function provenance(file, bytes, node, path, kind) {
  const point = file.getLineAndCharacterOfPosition(node.getStart(file));
  return {
    path,
    span: byteSpan(file, node),
    line: point.line + 1,
    column: point.character + 1,
    sourceDigest: sha256(bytes),
    kind,
  };
}

function propertyNodes(declaration) {
  const object = unwrap(declaration?.initializer);
  if (!object || !ts.isObjectLiteralExpression(object)) return new Map();
  return new Map(object.properties.map((property) => [propertyName(property), property]).filter(([name]) => name !== undefined));
}

function bindLoop(name, value, env) {
  const next = new Map(env);
  if (ts.isIdentifier(name)) {
    next.set(name.text, value);
    return next;
  }
  if (ts.isArrayBindingPattern(name) && Array.isArray(value)) {
    name.elements.forEach((element, index) => {
      if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) next.set(element.name.text, value[index]);
    });
    return next;
  }
  return null;
}

function fixedTuple(node, env) {
  const call = unwrap(node);
  if (!call || !ts.isCallExpression(call) || !ts.isIdentifier(call.expression) || call.expression.text !== "fixedTuple") return { ok: false };
  const fields = ["kind", "profile_id", "owner", "discriminator", "stamping"];
  const tuple = {};
  for (let index = 0; index < fields.length; index += 1) {
    const parsed = literal(call.arguments[index], env);
    if (!parsed.ok) return { ok: false };
    tuple[fields[index]] = parsed.value;
  }
  return { ok: true, value: tuple };
}

function oracleFromPush(statement, env, file, bytes, path) {
  if (!ts.isExpressionStatement(statement)) return { matched: false };
  const push = unwrap(statement.expression);
  if (
    !push || !ts.isCallExpression(push)
    || !ts.isPropertyAccessExpression(push.expression)
    || !ts.isIdentifier(push.expression.expression)
    || push.expression.expression.text !== "rows"
    || push.expression.name.text !== "push"
    || push.arguments.length !== 1
  ) return { matched: false };
  const oracleCall = unwrap(push.arguments[0]);
  if (!oracleCall || !ts.isCallExpression(oracleCall) || !ts.isIdentifier(oracleCall.expression) || oracleCall.expression.text !== "oracle") {
    return { matched: true, ok: false };
  }
  const tuple = fixedTuple(oracleCall.arguments[0], env);
  const boundary = literal(oracleCall.arguments[1], env);
  const invariants = literal(oracleCall.arguments[2], env);
  if (!tuple.ok || !boundary.ok || typeof boundary.value !== "string" || !invariants.ok || !Array.isArray(invariants.value)) {
    return { matched: true, ok: false };
  }
  const record = {
    id: `${tuple.value.owner}/profile-${tuple.value.profile_id}`,
    boundaryId: boundary.value,
    ownerDocument: tuple.value.owner,
    profile: tuple.value.profile_id,
    invariants: invariants.value,
    reasonCodes: [],
    provenance: provenance(file, bytes, oracleCall, path, "profile_oracle_override"),
  };
  return { matched: true, ok: true, record };
}

// This is a closed recognizer, not a helper evaluator. Formatting/comments may
// vary; any change to the observed helper's tokens requires explicit support.
const PROFILE_FREEZER = `function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    deepFreeze((object as Record<PropertyKey, unknown>)[key], seen);
  }
  if (!ArrayBuffer.isView(object)) Object.freeze(object);
  return value;
}`;

function tokens(source) {
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, true, ts.LanguageVariant.Standard, source);
  const result = [];
  for (let token = scanner.scan(); token !== ts.SyntaxKind.EndOfFileToken; token = scanner.scan()) {
    result.push([token, scanner.getTokenText()]);
  }
  return JSON.stringify(result);
}

function profileBindings(file) {
  const bindings = new Map();
  const add = (name, node) => {
    if (ts.isIdentifier(name)) bindings.set(name.text, [...(bindings.get(name.text) ?? []), node]);
    else if (ts.isArrayBindingPattern(name) || ts.isObjectBindingPattern(name)) {
      for (const element of name.elements) if (ts.isBindingElement(element)) add(element.name, node);
    }
  };
  for (const statement of file.statements) {
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) add(declaration.name, declaration);
    } else if (ts.isImportDeclaration(statement)) {
      const clause = statement.importClause;
      if (!clause || clause.isTypeOnly) continue;
      if (clause.name) add(clause.name, statement);
      if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) add(clause.namedBindings.name, statement);
      else for (const element of clause.namedBindings?.elements ?? []) if (!element.isTypeOnly) add(element.name, statement);
    } else if (!isNonexecutedProfileDeclaration(statement) || ts.isFunctionDeclaration(statement)) {
      if (statement.name) add(statement.name, statement);
    }
  }
  return bindings;
}

function isProfileGetter(node) {
  if (!node || !ts.isFunctionDeclaration(node) || node.asteriskToken
    || node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
    || node.parameters.length !== 1 || node.body?.statements.length !== 1) return false;
  const parameter = node.parameters[0];
  if (!ts.isIdentifier(parameter.name) || parameter.name.text !== "vectorId"
    || parameter.initializer || parameter.dotDotDotToken) return false;
  const statement = node.body.statements[0];
  return ts.isReturnStatement(statement) && statement.expression
    && tokens(statement.expression.getText()) === tokens("oracleByVectorId.get(vectorId)");
}

function isProfileRowsFinalizer(declaration, freezer) {
  if (!ts.isIdentifier(declaration.name) || declaration.name.text !== "CURRENT_PROFILE_ORACLES") return false;
  const call = unwrap(declaration.initializer);
  return Boolean(
    freezer && tokens(freezer.getText()) === tokens(PROFILE_FREEZER)
    && call && ts.isCallExpression(call)
    && ts.isIdentifier(call.expression) && call.expression.text === "deepFreeze"
    && call.arguments.length === 1
    && ts.isIdentifier(unwrap(call.arguments[0])) && unwrap(call.arguments[0]).text === "rows",
  );
}

function isProfileLookup(declaration) {
  if (!ts.isIdentifier(declaration.name) || declaration.name.text !== "oracleByVectorId") return false;
  const construct = unwrap(declaration.initializer);
  if (
    !construct || !ts.isNewExpression(construct)
    || !ts.isIdentifier(construct.expression) || construct.expression.text !== "Map"
    || construct.arguments?.length !== 1
  ) return false;
  const map = unwrap(construct.arguments[0]);
  if (
    !map || !ts.isCallExpression(map)
    || !ts.isPropertyAccessExpression(map.expression)
    || !ts.isIdentifier(map.expression.expression)
    || !["rows", "CURRENT_PROFILE_ORACLES"].includes(map.expression.expression.text)
    || map.expression.name.text !== "map" || map.arguments.length !== 1
  ) return false;
  const callback = unwrap(map.arguments[0]);
  if (!callback || !ts.isArrowFunction(callback) || callback.parameters.length !== 1) return false;
  const parameter = callback.parameters[0].name;
  if (callback.parameters[0].initializer || callback.parameters[0].dotDotDotToken
    || callback.modifiers?.length) return false;
  const body = unwrap(callback.body);
  return Boolean(
    ts.isIdentifier(parameter)
    && body && ts.isArrayLiteralExpression(body) && body.elements.length === 2
    && ts.isPropertyAccessExpression(unwrap(body.elements[0]))
    && ts.isIdentifier(unwrap(body.elements[0]).expression)
    && unwrap(body.elements[0]).expression.text === parameter.text
    && unwrap(body.elements[0]).name.text === "vector_id"
    && ts.isIdentifier(unwrap(body.elements[1]))
    && unwrap(body.elements[1]).text === parameter.text,
  );
}

function isProfileCountGuard(statement) {
  if (!ts.isIfStatement(statement) || statement.elseStatement) return false;
  const condition = unwrap(statement.expression);
  if (!condition || !ts.isBinaryExpression(condition)) return false;
  const left = unwrap(condition.left);
  const right = literal(condition.right);
  const body = ts.isBlock(statement.thenStatement)
    ? [...statement.thenStatement.statements]
    : [statement.thenStatement];
  return Boolean(
    condition.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken
    && left && ts.isPropertyAccessExpression(left)
    && ts.isIdentifier(left.expression) && left.expression.text === "CURRENT_PROFILE_ORACLES"
    && left.name.text === "length" && right.ok && right.value === 31
    && body.length === 1 && ts.isThrowStatement(body[0]),
  );
}

function isNonexecutedProfileDeclaration(statement) {
  return ts.isFunctionDeclaration(statement)
    || ts.isTypeAliasDeclaration(statement)
    || ts.isInterfaceDeclaration(statement);
}

function extractProfileOracles(path, bytes) {
  const file = sourceFile(path, bytes);
  const bindings = profileBindings(file);
  const unique = (name) => bindings.get(name)?.length === 1 ? bindings.get(name)[0] : undefined;
  const rowsDeclaration = unique("rows");
  const lookup = isProfileGetter(unique("currentProfileOracleForVector"));
  const initialRows = literal(rowsDeclaration?.initializer);
  const globals = ["Map", "Object", "WeakSet", "Reflect", "ArrayBuffer"];
  if (file.parseDiagnostics.length || globals.some((name) => bindings.has(name))
    || !rowsDeclaration || !unique("oracleByVectorId") || !lookup
    || !initialRows.ok || !Array.isArray(initialRows.value) || initialRows.value.length !== 0) {
    return { supported: false, records: new Map() };
  }
  const records = new Map();
  let supported = true;
  let rowsDeclared = false;
  let finalized = false;
  let lookupDeclared = false;

  const executeStatements = (statements, env) => {
    for (const statement of statements) {
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (!ts.isIdentifier(declaration.name)) {
            if (rowsDeclared) supported = false;
            continue;
          }
          const name = declaration.name.text;
          if (["rows", "CURRENT_PROFILE_ORACLES", "oracleByVectorId"].includes(name)
            && declaration !== unique(name)) supported = false;
          if (name === "CURRENT_PROFILE_ORACLES") {
            const initializer = unwrap(declaration.initializer);
            const alias = initializer && ts.isIdentifier(initializer) && initializer.text === "rows";
            if (!rowsDeclared || (!alias && !isProfileRowsFinalizer(declaration, unique("deepFreeze")))) supported = false;
            finalized = true;
            continue;
          }
          if (name === "oracleByVectorId") {
            if (!rowsDeclared || !isProfileLookup(declaration)
              || (declaration.initializer.getText().includes("CURRENT_PROFILE_ORACLES") && !finalized)) supported = false;
            lookupDeclared = true;
            continue;
          }
          const parsed = literal(declaration.initializer, env);
          if (parsed.ok) env.set(declaration.name.text, parsed.value);
          else if (rowsDeclared) supported = false;
          if (declaration === rowsDeclaration) rowsDeclared = true;
        }
        continue;
      }
      if (ts.isForOfStatement(statement)) {
        const iterable = literal(statement.expression, env);
        const declaration = statement.initializer.declarations?.[0];
        if (!iterable.ok || !Array.isArray(iterable.value) || !declaration) {
          supported = false;
          continue;
        }
        for (const value of iterable.value) {
          const loopEnv = bindLoop(declaration.name, value, env);
          const protectedNames = [...globals, "deepFreeze", "rows", "CURRENT_PROFILE_ORACLES", "oracleByVectorId", "oracle", "fixedTuple"];
          if (!loopEnv || protectedNames.some((name) => loopEnv.has(name) && loopEnv.get(name) !== env.get(name))) {
            supported = false;
            continue;
          }
          const body = ts.isBlock(statement.statement) ? statement.statement.statements : [statement.statement];
          executeStatements(body, loopEnv);
        }
        continue;
      }
      const oracle = oracleFromPush(statement, env, file, bytes, path);
      if (oracle.matched) {
        if (!rowsDeclared || finalized || lookupDeclared || !oracle.ok) supported = false;
        else if (records.has(oracle.record.id)) supported = false;
        else records.set(oracle.record.id, oracle.record);
        continue;
      }
      if (isProfileCountGuard(statement)) {
        if (!finalized || records.size !== 31) supported = false;
        continue;
      }
      if (isNonexecutedProfileDeclaration(statement) || ts.isImportDeclaration(statement)) continue;
      if (rowsDeclared) supported = false;
    }
  };

  const env = new Map();
  executeStatements(file.statements, env);
  return { supported: supported && lookupDeclared, records };
}

function unknown(record, field) {
  if (!record.unknownFields.includes(field)) record.unknownFields.push(field);
  if (["specRefs", "invariants", "reasonCodes"].includes(field)) record[field] = [];
  else record[field] = null;
}

function baseRecord(id, raw, catalogProvenance) {
  const value = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  const record = {
    id,
    evidenceKind: "declared_current",
    specRefs: Array.isArray(value.spec_refs) ? [...value.spec_refs] : [],
    boundaryId: typeof value.boundary_id === "string" ? value.boundary_id : null,
    ownerDocument: typeof value.owner_document === "string" ? value.owner_document : null,
    profile: typeof value.profile === "string" ? value.profile : null,
    invariants: Array.isArray(value.invariants) ? [...value.invariants] : [],
    reasonCodes: Array.isArray(value.reason_codes) ? [...value.reason_codes] : [],
    provenance: [catalogProvenance],
    unknownFields: [],
  };
  if (!Array.isArray(value.spec_refs)) unknown(record, "specRefs");
  if (typeof value.boundary_id !== "string") unknown(record, "boundaryId");
  if (typeof value.owner_document !== "string") unknown(record, "ownerDocument");
  if (!Array.isArray(value.invariants)) unknown(record, "invariants");
  if (!Array.isArray(value.reason_codes)) unknown(record, "reasonCodes");
  return record;
}

async function readCurrent({ repo, ref, requested }) {
  const unresolved = [];
  let catalogBytes;
  try {
    catalogBytes = await sourceAt(repo, ref, CATALOG_PATH);
  } catch (error) {
    unresolved.push({ reason: "missing_metadata_source", path: CATALOG_PATH, ref, detail: error.message });
    return {
      layout: "current-catalog",
      layoutSelection: { requested, detected: "current-catalog" },
      inputDigest: digestJson([]),
      inputs: [],
      records: [],
      unresolved,
    };
  }
  const inputs = [{ path: CATALOG_PATH, ref, sourceDigest: sha256(catalogBytes), bytes: catalogBytes.length }];
  const catalogFile = sourceFile(CATALOG_PATH, catalogBytes);
  const declaration = variable(catalogFile, "CURRENT_CASE_CONTRACTS");
  const parsed = literal(declaration?.initializer);
  if (!declaration || !parsed.ok || !parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
    unresolved.push({ reason: "unsupported_contract_declaration", path: CATALOG_PATH, ref });
    return {
      layout: "current-catalog",
      layoutSelection: { requested, detected: "current-catalog" },
      inputDigest: digestJson(inputs),
      inputs,
      records: [],
      unresolved,
    };
  }
  const nodes = propertyNodes(declaration);
  const records = new Map(Object.entries(parsed.value).map(([id, raw]) => {
    const node = nodes.get(id) ?? declaration;
    return [id, baseRecord(id, raw, provenance(catalogFile, catalogBytes, node, CATALOG_PATH, "catalog_declaration"))];
  }));

  let profileExtraction = { supported: false, records: new Map() };
  try {
    const profileBytes = await sourceAt(repo, ref, PROFILE_PATH);
    inputs.push({ path: PROFILE_PATH, ref, sourceDigest: sha256(profileBytes), bytes: profileBytes.length });
    profileExtraction = extractProfileOracles(PROFILE_PATH, profileBytes);
  } catch (error) {
    unresolved.push({ reason: "missing_profile_oracle_source", path: PROFILE_PATH, ref, detail: error.message });
  }
  if (profileExtraction.supported) {
    for (const [id, oracle] of profileExtraction.records) {
      const record = records.get(id);
      if (!record) {
        unresolved.push({ reason: "profile_oracle_without_contract", id, path: PROFILE_PATH, ref });
        continue;
      }
      record.boundaryId = oracle.boundaryId;
      record.ownerDocument = oracle.ownerDocument;
      record.profile = oracle.profile;
      record.invariants = [...oracle.invariants];
      record.reasonCodes = [];
      record.provenance.push(oracle.provenance);
    }
  } else {
    for (const record of records.values()) {
      for (const field of ["boundaryId", "ownerDocument", "profile", "invariants", "reasonCodes"]) unknown(record, field);
      unresolved.push({ reason: "unsupported_profile_oracle", id: record.id, path: PROFILE_PATH, ref });
    }
  }

  const terminal = records.get("comms/auth-rejected-permanent");
  if (terminal && profileExtraction.supported) {
    terminal.invariants = [];
    terminal.reasonCodes = [];
    const marker = findNode(catalogFile, (node) => ts.isIfStatement(node)
      && node.expression.getText(catalogFile).includes('vectorId === "comms/auth-rejected-permanent"'));
    if (marker) terminal.provenance.push(provenance(catalogFile, catalogBytes, marker, CATALOG_PATH, "terminal_semantic_exclusion"));
  }

  const overrideDeclaration = variable(catalogFile, "TASK_FIFTEEN_BOUNDARIES");
  const overrides = literal(overrideDeclaration?.initializer);
  const overrideNodes = propertyNodes(overrideDeclaration);
  if (!overrideDeclaration || !overrides.ok || !overrides.value || typeof overrides.value !== "object" || Array.isArray(overrides.value)) {
    for (const record of records.values()) {
      unknown(record, "boundaryId");
      unresolved.push({ reason: "unsupported_boundary_override", id: record.id, path: CATALOG_PATH, ref });
    }
  } else {
    for (const [id, boundary] of Object.entries(overrides.value)) {
      const record = records.get(id);
      if (!record || typeof boundary !== "string") {
        unresolved.push({ reason: "invalid_boundary_override", id, path: CATALOG_PATH, ref });
        if (record) unknown(record, "boundaryId");
        continue;
      }
      record.boundaryId = boundary;
      const node = overrideNodes.get(id) ?? overrideDeclaration;
      record.provenance.push(provenance(catalogFile, catalogBytes, node, CATALOG_PATH, "boundary_override"));
    }
  }

  const sortedRecords = [...records.values()].sort((left, right) => left.id.localeCompare(right.id, "en"));
  return {
    layout: "current-catalog",
    layoutSelection: { requested, detected: "current-catalog" },
    inputDigest: digestJson(inputs),
    inputs,
    records: sortedRecords,
    unresolved,
  };
}

function legacyGroups(path, bytes) {
  const file = sourceFile(path, bytes);
  const groups = [];
  const visit = (node) => {
    if (
      ts.isVariableDeclaration(node)
      && ts.isIdentifier(node.name)
      && node.name.text.endsWith("_IDS")
    ) {
      const owner = OWNER_BY_GROUP.get(node.name.text.slice(0, -4));
      const call = unwrap(node.initializer);
      const argument = call && ts.isCallExpression(call) && ts.isIdentifier(call.expression) && call.expression.text === "ids"
        ? unwrap(call.arguments[0])
        : undefined;
      if (owner && argument && (ts.isNoSubstitutionTemplateLiteral(argument) || ts.isStringLiteral(argument))) {
        groups.push({ owner, argument, ids: argument.text.trim().split(/\s+/u).filter(Boolean) });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return { file, groups };
}

async function readLegacy({ repo, ref, requested }) {
  const inputs = [];
  const unresolved = [];
  const sources = new Map();
  for (const path of LEGACY_PATHS) {
    try {
      const bytes = await sourceAt(repo, ref, path);
      sources.set(path, bytes);
      inputs.push({ path, ref, sourceDigest: sha256(bytes), bytes: bytes.length });
    } catch (error) {
      unresolved.push({ reason: "missing_legacy_input", path, ref, detail: error.message });
    }
  }
  const metadataBytes = sources.get(LEGACY_METADATA);
  const records = [];
  if (metadataBytes) {
    const { file, groups } = legacyGroups(LEGACY_METADATA, metadataBytes);
    for (const group of groups) {
      let searchFrom = group.argument.getStart(file);
      for (const id of group.ids) {
        const charStart = file.text.indexOf(id, searchFrom);
        if (charStart < 0 || charStart >= group.argument.getEnd()) continue;
        const charEnd = charStart + id.length;
        searchFrom = charEnd;
        const nodeLike = {
          getStart: () => charStart,
          getEnd: () => charEnd,
        };
        records.push({
          id,
          evidenceKind: "declared_current",
          specRefs: [],
          boundaryId: null,
          ownerDocument: group.owner,
          profile: null,
          invariants: [],
          reasonCodes: [],
          provenance: [provenance(file, metadataBytes, nodeLike, LEGACY_METADATA, "legacy_id_allocation")],
          unknownFields: ["specRefs", "boundaryId", "profile", "invariants", "reasonCodes"],
        });
      }
    }
    if (groups.length === 0) unresolved.push({ reason: "unsupported_legacy_metadata", path: LEGACY_METADATA, ref });
  }
  unresolved.push({
    reason: "legacy_fields_unavailable",
    fields: ["specRefs", "boundaryId", "profile", "invariants", "reasonCodes"],
    inspected: LEGACY_PATHS,
    evidenceKind: "declared_current",
  });
  records.sort((left, right) => left.id.localeCompare(right.id, "en"));
  return {
    layout: "legacy-authoring",
    layoutSelection: { requested, detected: "legacy-authoring" },
    inputDigest: digestJson(inputs),
    inputs,
    records,
    unresolved,
  };
}

/** Read current or historical declarations without importing generator builders. */
export async function readDeclaredContracts({ repo, ref = "WORKTREE", layout = "auto" }) {
  if (typeof repo !== "string" || repo.length === 0) throw new TypeError("repo is required");
  if (!KNOWN_LAYOUTS.has(layout)) throw new Error(`unsupported metadata layout: ${layout}`);
  const selected = layout === "auto"
    ? await existsAt(repo, ref, CATALOG_PATH) ? "current-catalog" : "legacy-authoring"
    : layout;
  if (selected === "current-catalog") return readCurrent({ repo, ref, requested: layout });
  return readLegacy({ repo, ref, requested: layout });
}
