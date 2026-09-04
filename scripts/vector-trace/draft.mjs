import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { basename, dirname, extname, join, posix } from "node:path";

import { semanticUuid } from "./projection.mjs";

// Resolve TypeScript from the generator package owned by this worktree.  The
// selected repository is data only: no repository source is imported or run.
const require = createRequire(new URL("../../docs/spec/vectors/generator/package.json", import.meta.url));
const ts = require("typescript");

const FAMILY_VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const OWNERS = new Set(["core", "assurance", "comms", "control", "social", "workspace"]);
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];
const CODE_EXTENSIONS = new Set(SOURCE_EXTENSIONS);

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function unwrap(node) {
  let value = node;
  while (value) {
    if (ts.isParenthesizedExpression(value) || ts.isAsExpression(value) || ts.isTypeAssertionExpression(value) || ts.isNonNullExpression(value)) {
      value = value.expression;
      continue;
    }
    if (value.kind === ts.SyntaxKind.SatisfiesExpression) {
      value = value.expression;
      continue;
    }
    if (ts.isCallExpression(value) && value.arguments.length === 1 && value.expression.getText() === "Object.freeze") {
      value = value.arguments[0];
      continue;
    }
    break;
  }
  return value;
}

function propertyName(node) {
  const name = node.name;
  if (!name) return undefined;
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) return name.text;
  return undefined;
}

function literal(node) {
  const value = unwrap(node);
  if (!value) return { supported: false };
  if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) return { supported: true, value: value.text };
  if (value.kind === ts.SyntaxKind.TrueKeyword) return { supported: true, value: true };
  if (value.kind === ts.SyntaxKind.FalseKeyword) return { supported: true, value: false };
  if (ts.isArrayLiteralExpression(value)) {
    const values = [];
    for (const element of value.elements) {
      const parsed = literal(element);
      if (!parsed.supported) return { supported: false };
      values.push(parsed.value);
    }
    return { supported: true, value: values };
  }
  if (ts.isObjectLiteralExpression(value)) {
    const result = {};
    for (const element of value.properties) {
      if (!ts.isPropertyAssignment(element)) return { supported: false };
      const key = propertyName(element);
      const parsed = literal(element.initializer);
      if (key === undefined || !parsed.supported) return { supported: false };
      result[key] = parsed.value;
    }
    return { supported: true, value: result };
  }
  return { supported: false };
}

function variable(sourceFile, name) {
  let found;
  function visit(node) {
    if (found) return;
    if (ts.isVariableDeclaration(node) && propertyName(node) === name) {
      found = node;
      return;
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return found;
}

function namedDeclaration(sourceFile, name) {
  let found;
  function visit(node) {
    if (found) return;
    if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isVariableDeclaration(node)) && node.name?.text === name) {
      found = node;
      return;
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return found;
}

function location(sourceFile, node) {
  const point = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return { source_path: sourceFile.fileName, line: point.line + 1, column: point.character + 1 };
}

function parseSource(path, content) {
  return ts.createSourceFile(path, content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

function staticValue(sourceFile, name) {
  const declaration = variable(sourceFile, name);
  if (!declaration) return undefined;
  const parsed = literal(declaration.initializer);
  return parsed.supported ? { value: parsed.value, declaration, location: location(sourceFile, declaration) } : undefined;
}

function sourceModules(projection, sourceContents) {
  const items = projection.items;
  const byPath = new Map(items.filter((item) => item.type === "source_module").map((item) => [item.source_path, item]));
  for (const [path, content] of sourceContents) {
    if (!path.startsWith("docs/spec/vectors/generator/") || byPath.has(path)) continue;
    if (!CODE_EXTENSIONS.has(extname(path)) && !/^(?:package(?:-lock)?|tsconfig[^/]*)\.json$/.test(basename(path))) continue;
    const semanticId = `source:${path}`;
    const item = { semantic_id: semanticId, sara_id: semanticUuid("source_module", semanticId), type: "source_module", source_path: path, source_digest: digest(content), evidence_kind: "generator_input" };
    items.push(item);
    byPath.set(path, item);
  }
  return byPath;
}

function addUnresolved(unresolved, value) {
  const key = JSON.stringify(value);
  if (!unresolved.some((entry) => JSON.stringify(entry) === key)) unresolved.push(value);
}

function splitBoundary(boundary) {
  let moduleName;
  return String(boundary).split("+").map((part) => {
    const value = part.trim();
    const parsed = boundaryParts(value);
    if (parsed) moduleName = parsed.module;
    return parsed || (moduleName ? `${moduleName}.${value}` : value);
  }).filter(Boolean).map((part) => typeof part === "string" ? part : `${part.module}.${part.exported}`);
}

function boundaryParts(boundary) {
  const dot = boundary.lastIndexOf(".");
  if (dot <= 0 || dot === boundary.length - 1) return undefined;
  return { module: boundary.slice(0, dot), exported: boundary.slice(dot + 1) };
}

function moduleCandidates(moduleName, modules) {
  const paths = [...modules.keys()].filter((path) => CODE_EXTENSIONS.has(extname(path)));
  return paths.filter((path) => basename(path, extname(path)) === moduleName);
}

function hasExportedDeclaration(sourceFile, name) {
  let found = false;
  function visit(node) {
    if (found) return;
    if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isEnumDeclaration(node) || ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) && node.name?.text === name) {
      found = node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false;
    } else if (ts.isVariableDeclaration(node) && propertyName(node) === name) {
      const statement = node.parent?.parent;
      found = statement?.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false;
    } else if (ts.isExportDeclaration(node) && node.exportClause && ts.isNamedExports(node.exportClause)) {
      found = node.exportClause.elements.some((element) => (element.name.text === name || element.propertyName?.text === name));
    }
    if (!found) ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return found;
}

function resolveImport(importer, specifier, modules) {
  if (!specifier.startsWith(".")) return { external: true, target: `external:${specifier}` };
  const base = posix.normalize(posix.join(dirname(importer), specifier));
  const candidates = [base];
  const extension = extname(base);
  if (extension === ".js" || extension === ".mjs" || extension === ".cjs") {
    for (const replacement of [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs"]) candidates.push(`${base.slice(0, -extension.length)}${replacement}`);
  } else if (!extension) {
    for (const replacement of SOURCE_EXTENSIONS) candidates.push(`${base}${replacement}`);
  }
  candidates.push(...SOURCE_EXTENSIONS.map((replacement) => join(base, `index${replacement}`)));
  const target = candidates.find((candidate) => modules.has(candidate));
  return target === undefined ? { missing: true } : { target: modules.get(target).semantic_id, path: target };
}

function importReferences(sourceFile) {
  const references = [];
  function visit(node) {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) references.push({ specifier: node.moduleSpecifier.text, dynamic: false, node });
    else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) references.push({ specifier: node.moduleSpecifier.text, dynamic: false, node });
    else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      references.push({ specifier: node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0]) ? node.arguments[0].text : undefined, dynamic: true, nonliteral: !(node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])), node });
    } else if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require") {
      references.push({ specifier: node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0]) ? node.arguments[0].text : undefined, dynamic: false, nonliteral: !(node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])), require: true, node });
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return references;
}

function enrichImports(projection, modules, sourceContents, sourceFiles, unresolved) {
  const edges = projection.edges;
  const external = Array.isArray(projection.receipt.external_dependencies) ? [...projection.receipt.external_dependencies] : [];
  for (const [path, moduleItem] of modules) {
    const content = sourceContents.get(path);
    if (content === undefined || !CODE_EXTENSIONS.has(extname(path))) continue;
    const sourceFile = sourceFiles.get(path) ?? parseSource(path, content);
    for (const reference of importReferences(sourceFile)) {
      const point = location(sourceFile, reference.node);
      if (reference.nonliteral) {
        addUnresolved(unresolved, { from: moduleItem.semantic_id, to: "<non-literal>", relation: "imports", reason: reference.require ? "nonliteral_require" : "nonliteral_dynamic_import", source_path: path, line: point.line, dynamic: reference.dynamic });
        continue;
      }
      const resolved = resolveImport(path, reference.specifier, modules);
      if (resolved.external) {
        const entry = { from: moduleItem.semantic_id, specifier: reference.specifier, relation: "imports", source_path: path, line: point.line, external: true, dynamic: reference.dynamic };
        if (!external.some((candidate) => JSON.stringify(candidate) === JSON.stringify(entry))) external.push(entry);
      } else if (resolved.missing) {
        addUnresolved(unresolved, { from: moduleItem.semantic_id, to: reference.specifier, relation: "imports", reason: "missing_import", source_path: path, line: point.line, dynamic: reference.dynamic });
      } else {
        edges.push({ from: moduleItem.semantic_id, to: resolved.target, relation: "imports", source_path: path, ...point, dynamic: reference.dynamic });
      }
    }
  }
  projection.receipt.external_dependencies = external;
}

function enrichContracts(projection, modules, sourceContents, sourceFiles, unresolved) {
  const contractPath = [...sourceContents.keys()].find((path) => path.endsWith("/current-vectors/case-contracts.ts"));
  if (!contractPath) return;
  const contractContent = sourceContents.get(contractPath);
  const sourceFile = sourceFiles.get(contractPath) ?? parseSource(contractPath, contractContent);
  const contracts = staticValue(sourceFile, "CURRENT_CASE_CONTRACTS");
  const overrides = staticValue(sourceFile, "TASK_FIFTEEN_BOUNDARIES");
  const familyPath = [...sourceContents.keys()].find((path) => path.endsWith("/current-vectors/family.ts") || path.endsWith("/src/family.ts"));
  const family = familyPath === undefined ? undefined : staticValue(sourceFiles.get(familyPath) ?? parseSource(familyPath, sourceContents.get(familyPath)), "FAMILY_VERSION");
  const familyVersion = typeof family?.value === "string" && FAMILY_VERSION_PATTERN.test(family.value) ? family.value : undefined;
  if (familyVersion === undefined) addUnresolved(unresolved, { reason: "family_version_unresolved", ...location(sourceFile, variable(sourceFile, "CURRENT_CASE_CONTRACTS") ?? sourceFile) });
  const profilePath = [...sourceContents.keys()].find((path) => path.endsWith("/current-vectors/profile-oracles.ts"));
  const profileSource = profilePath === undefined ? undefined : (sourceFiles.get(profilePath) ?? parseSource(profilePath, sourceContents.get(profilePath)));
  const profileFunction = profileSource === undefined ? undefined : namedDeclaration(profileSource, "currentProfileOracleForVector");
  const profileLocation = profileFunction ? location(profileSource, profileFunction) : profilePath ? { source_path: profilePath, line: 1, column: 1 } : undefined;
  if (!contracts) {
    addUnresolved(unresolved, { reason: "unsupported_contract_declaration", ...location(sourceFile, variable(sourceFile, "CURRENT_CASE_CONTRACTS") ?? sourceFile) });
    return;
  }
  const values = contracts.value;
  if (!values || typeof values !== "object" || Array.isArray(values)) return;
  const anchorIds = new Set(projection.items.filter((item) => item.type === "spec_anchor").map((item) => item.semantic_id));
  const overrideValues = overrides?.value && typeof overrides.value === "object" ? overrides.value : {};
  const contractDeclaration = variable(sourceFile, "CURRENT_CASE_CONTRACTS");
  const caseNode = unwrap(contractDeclaration?.initializer);
  const caseProperties = new Map();
  if (ts.isObjectLiteralExpression(caseNode)) for (const property of caseNode.properties) {
    const key = propertyName(property);
    if (key !== undefined) caseProperties.set(key, property);
  }
  for (const [vectorId, declaration] of Object.entries(values)) {
    const property = caseProperties.get(vectorId);
    const metadata = declaration && typeof declaration === "object" ? declaration : {};
    const rawRefs = Array.isArray(metadata.raw_refs) ? metadata.raw_refs : Array.isArray(metadata.spec_refs) ? metadata.spec_refs : undefined;
    const caseLocation = property ? location(sourceFile, property) : contractDeclaration ? location(sourceFile, contractDeclaration) : { source_path: contractPath, line: 1, column: 1 };
    const semanticId = `case:${vectorId}`;
    const terminalOnly = vectorId === "comms/auth-rejected-permanent";
    const item = {
      semantic_id: semanticId,
      sara_id: semanticUuid("draft_case", semanticId),
      type: "draft_case",
      source_path: contractPath,
      source_digest: digest(contractContent),
      evidence_kind: "declared_current",
      owner: metadata.owner_document,
      boundary_id: metadata.boundary_id,
      ...(metadata.profile === undefined ? {} : { profile: metadata.profile }),
      ...(rawRefs === undefined ? {} : { raw_refs: rawRefs, spec_refs: [] }),
      ...(terminalOnly
        ? { invariants: [], ...(Array.isArray(metadata.invariants) ? { terminal_vector_invariants: metadata.invariants } : {}), reason_codes: [] }
        : {
            ...(Array.isArray(metadata.invariants) ? { invariants: metadata.invariants } : {}),
            ...(Array.isArray(metadata.reason_codes) ? { reason_codes: metadata.reason_codes } : {}),
          }),
      declaration_location: caseLocation,
    };
    if (profileLocation && metadata.profile !== undefined) {
      item.runtime_override_unresolved = true;
      item.runtime_override_location = profileLocation;
    }
    projection.items.push(item);
    if (!OWNERS.has(metadata.owner_document)) {
      addUnresolved(unresolved, { from: semanticId, reason: "invalid_owner", value: metadata.owner_document, ...caseLocation });
    }
    if (!Array.isArray(rawRefs) || rawRefs.length === 0) {
      addUnresolved(unresolved, { from: semanticId, reason: "missing_raw_refs", ...caseLocation });
    } else {
      for (const rawRef of rawRefs) {
        if (typeof rawRef !== "string") {
          addUnresolved(unresolved, { from: semanticId, reason: "invalid_ref", value: rawRef, ...caseLocation });
          continue;
        }
        const match = /^heterodyne:([^#]+)#([a-z0-9][a-z0-9-]*)$/.exec(rawRef);
        if (!match) {
          addUnresolved(unresolved, { from: semanticId, reason: "invalid_ref", raw_ref: rawRef, ...caseLocation });
          continue;
        }
        const qualifier = match[1];
        const anchor = match[2];
        let owner = metadata.owner_document;
        if (FAMILY_VERSION_PATTERN.test(qualifier)) {
          if (familyVersion === undefined || qualifier !== familyVersion) {
            addUnresolved(unresolved, { from: semanticId, reason: "invalid_version", raw_ref: rawRef, expected: familyVersion, ...caseLocation });
            continue;
          }
        } else if (OWNERS.has(qualifier)) {
          if (qualifier !== metadata.owner_document) {
            addUnresolved(unresolved, { from: semanticId, reason: "invalid_owner", raw_ref: rawRef, expected: metadata.owner_document, ...caseLocation });
            continue;
          }
          owner = qualifier;
        } else {
          addUnresolved(unresolved, { from: semanticId, reason: "invalid_version_or_owner", raw_ref: rawRef, ...caseLocation });
          continue;
        }
        const normalized = `heterodyne:${owner}#${anchor}`;
        item.spec_refs.push(normalized);
        if (!anchorIds.has(normalized)) {
          addUnresolved(unresolved, { from: semanticId, to: normalized, relation: "declares", reason: "missing_anchor", raw_ref: rawRef, ...caseLocation });
        } else {
          projection.edges.push({ from: semanticId, to: normalized, relation: "declares", source_path: contractPath, ...caseLocation, raw_ref: rawRef, declared: true });
        }
      }
    }
    const boundary = typeof overrideValues[vectorId] === "string" ? overrideValues[vectorId] : metadata.boundary_id;
    const isOverride = typeof overrideValues[vectorId] === "string";
    if (typeof boundary !== "string") {
      addUnresolved(unresolved, { from: semanticId, reason: "missing_boundary", ...caseLocation });
      continue;
    }
    if (item.runtime_override_unresolved) {
      addUnresolved(unresolved, { from: semanticId, reason: "runtime_profile_override", boundary_id: boundary, ...(profileLocation ?? caseLocation) });
      continue;
    }
    for (const part of splitBoundary(boundary)) {
      const parsed = boundaryParts(part);
      if (!parsed) {
        addUnresolved(unresolved, { from: semanticId, reason: "invalid_boundary", boundary_id: part, ...caseLocation });
        continue;
      }
      const candidates = moduleCandidates(parsed.module, modules);
      const exportedCandidates = candidates.filter((candidate) => hasExportedDeclaration(sourceFiles.get(candidate) ?? parseSource(candidate, sourceContents.get(candidate)), parsed.exported));
      const resolvedCandidates = exportedCandidates.length ? exportedCandidates : candidates;
      if (resolvedCandidates.length !== 1) {
        addUnresolved(unresolved, { from: semanticId, reason: resolvedCandidates.length === 0 ? "missing_boundary_module" : "ambiguous_boundary_module", boundary_id: part, candidates: resolvedCandidates, ...caseLocation });
        continue;
      }
      const boundaryPath = resolvedCandidates[0];
      const boundarySource = sourceFiles.get(boundaryPath) ?? parseSource(boundaryPath, sourceContents.get(boundaryPath));
      const exported = hasExportedDeclaration(boundarySource, parsed.exported);
      if (!exported) {
        addUnresolved(unresolved, { from: semanticId, reason: "missing_boundary_export", boundary_id: part, exported_name: parsed.exported, source_path: boundaryPath, ...caseLocation });
        continue;
      }
      projection.edges.push({ from: semanticId, to: modules.get(boundaryPath).semantic_id, relation: "defined_by", source_path: contractPath, ...caseLocation, boundary_id: part, exported_name: parsed.exported, ...(isOverride ? { override: true } : { declared: true }) });
    }
  }
}

/** Enriches a draft projection in place with conservative static declarations. */
export function enrichDraft(projection, { repo } = {}) {
  if (!projection || !(projection.sourceContents instanceof Map)) throw new Error("draft projection sourceContents map is required");
  if (repo === undefined) throw new Error("repo is required");
  const sourceContents = projection.sourceContents;
  const modules = sourceModules(projection, sourceContents);
  const sourceFiles = new Map([...sourceContents].filter(([path]) => CODE_EXTENSIONS.has(extname(path))).map(([path, content]) => [path, parseSource(path, content)]));
  const unresolved = Array.isArray(projection.receipt?.unresolved_references) ? [...projection.receipt.unresolved_references] : [];
  enrichContracts(projection, modules, sourceContents, sourceFiles, unresolved);
  enrichImports(projection, modules, sourceContents, sourceFiles, unresolved);
  projection.receipt.unresolved_references = unresolved;
  projection.receipt.typescript_version = ts.version;
  return projection;
}
