import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import ts from "typescript";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateAssuranceCompromiseContinuation } from "./assurance-policy.js";
import { evaluateSuccession } from "./assurance.js";
import { validateControlSignedEffect } from "./control-policy.js";
import { buildCurrentCases, buildCurrentVectors } from "./current-vectors/index.js";
import { assertProjectionPreservesVerdict } from "./current-vectors/boundary-runners.js";
import { buildProfileCases } from "./current-vectors/profiles.js";
import { validateCurrentKindProfileNegotiation } from "./profile-negotiation.js";
import { loadRegistry } from "./registry.js";
import { validateVectorOrThrow } from "./schema.js";

const sourceRoot = resolve(import.meta.dirname);
const catalogEntry = resolve(sourceRoot, "current-vectors/index.ts");
const currentConfigPath = resolve(sourceRoot, "../tsconfig.current.json");
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

function commonJsLoader(
  expression: ts.Expression,
  aliases: ReadonlySet<string> = new Set(["require"]),
): boolean {
  if (ts.isIdentifier(expression)) return aliases.has(expression.text);
  if (ts.isPropertyAccessExpression(expression)) {
    return (
      expression.name.text === "require"
      && ts.isIdentifier(expression.expression)
      && expression.expression.text === "module"
    )
      || (
        expression.name.text === "resolve"
        && ts.isIdentifier(expression.expression)
        && aliases.has(expression.expression.text)
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
        && aliases.has(expression.expression.text)
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
  const requireAliases = new Set(["require"]);
  const createRequireFactories = new Set<string>();
  const moduleNamespaces = new Set<string>();
  for (const statement of source.statements) {
    if (
      ts.isImportDeclaration(statement)
      && ts.isStringLiteralLike(statement.moduleSpecifier)
      && statement.moduleSpecifier.text === "node:module"
    ) {
      const bindings = statement.importClause?.namedBindings;
      if (bindings !== undefined && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) {
          if ((element.propertyName?.text ?? element.name.text) === "createRequire") {
            createRequireFactories.add(element.name.text);
          }
        }
      } else if (bindings !== undefined && ts.isNamespaceImport(bindings)) {
        moduleNamespaces.add(bindings.name.text);
      }
    }
  }
  const createsRequire = (expression: ts.Expression): boolean =>
    ts.isIdentifier(expression)
      ? createRequireFactories.has(expression.text)
      : ts.isPropertyAccessExpression(expression)
        && expression.name.text === "createRequire"
        && ts.isIdentifier(expression.expression)
        && moduleNamespaces.has(expression.expression.text);
  let changed = true;
  while (changed) {
    changed = false;
    const collectAliases = (node: ts.Node): void => {
      if (
        ts.isVariableDeclaration(node)
        && ts.isIdentifier(node.name)
        && node.initializer !== undefined
      ) {
        const initializer = node.initializer;
        if (
          commonJsLoader(initializer, requireAliases)
          || (ts.isIdentifier(initializer) && requireAliases.has(initializer.text))
          || (ts.isCallExpression(initializer) && createsRequire(initializer.expression))
        ) {
          if (!requireAliases.has(node.name.text)) {
            requireAliases.add(node.name.text);
            changed = true;
          }
        } else if (
          (ts.isIdentifier(initializer) && createRequireFactories.has(initializer.text))
          || createsRequire(initializer)
        ) {
          if (!createRequireFactories.has(node.name.text)) {
            createRequireFactories.add(node.name.text);
            changed = true;
          }
        }
      }
      ts.forEachChild(node, collectAliases);
    };
    collectAliases(source);
  }
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
      } else if (
        !createsRequire(node.expression)
        && commonJsLoader(node.expression, requireAliases)
      ) {
        add(node.arguments[0], "CommonJS require");
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return specifiers;
}

function compilerConfigPath(entry: string): string | undefined {
  const relativeToCurrentSource = relative(sourceRoot, realpathSync(entry));
  const inCurrentSource = relativeToCurrentSource !== ".."
    && !relativeToCurrentSource.startsWith(`..${sep}`)
    && !isAbsolute(relativeToCurrentSource);
  return inCurrentSource
    ? currentConfigPath
    : ts.findConfigFile(dirname(entry), ts.sys.fileExists);
}

function compilerOptions(entry: string): ts.CompilerOptions {
  const configPath = compilerConfigPath(entry);
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

function resolveModule(
  importer: string,
  specifier: string,
  options: ts.CompilerOptions,
): string | null {
  if (specifier.startsWith("node:")) return null;
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

function moduleDependencies(entry: string): string[] {
  const visited = new Set<string>();
  const options = compilerOptions(entry);
  const visit = (candidate: string): void => {
    const path = realpathSync(candidate);
    if (visited.has(path)) return;
    visited.add(path);
    for (const specifier of moduleSpecifiers(path)) {
      const dependency = resolveModule(path, specifier, options);
      if (dependency !== null) visit(dependency);
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
    expect(compilerConfigPath(catalogEntry)).toBe(currentConfigPath);
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

  it("cannot hide forbidden modules behind require aliases or createRequire", () => {
    const root = mkdtempSync(resolve(tmpdir(), "heterodyne-current-vector-aliases-"));
    temporaryRoots.push(root);
    writeFileSync(
      resolve(root, "index.ts"),
      [
        'import { createRequire as makeRequire } from "node:module";',
        "const direct = require;",
        "const moduleLoader = module.require;",
        "const created = makeRequire(import.meta.url);",
        'direct("./topics-alias.js");',
        'moduleLoader("./snapshot-module-alias.js");',
        'created("./legacy-create-require.js");',
      ].join("\n"),
    );
    for (const file of [
      "topics-alias.ts",
      "snapshot-module-alias.ts",
      "legacy-create-require.ts",
    ]) writeFileSync(resolve(root, file), "export const value = true;\n");

    expect(moduleDependencies(resolve(root, "index.ts")).filter((path) =>
      forbidden.some((pattern) => pattern.test(path))
    )).toEqual([
      realpathSync(resolve(root, "legacy-create-require.ts")),
      realpathSync(resolve(root, "snapshot-module-alias.ts")),
      realpathSync(resolve(root, "topics-alias.ts")),
    ].sort());
  });

  it("fails closed on nonliteral aliased module loads", () => {
    const root = mkdtempSync(resolve(tmpdir(), "heterodyne-current-vector-nonliteral-"));
    temporaryRoots.push(root);
    writeFileSync(
      resolve(root, "index.ts"),
      [
        "const localRequire = require;",
        'const hidden = "./topics-nonliteral.js";',
        "localRequire(hidden);",
      ].join("\n"),
    );
    expect(() => moduleDependencies(resolve(root, "index.ts")))
      .toThrow(/nonliteral CommonJS require/u);
  });

  it("resolves configured local aliases through TypeScript and rejects missing ones", () => {
    const root = mkdtempSync(resolve(tmpdir(), "heterodyne-current-vector-paths-"));
    temporaryRoots.push(root);
    mkdirSync(resolve(root, "src"), { recursive: true });
    writeFileSync(resolve(root, "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        module: "NodeNext",
        moduleResolution: "NodeNext",
        baseUrl: ".",
        paths: { "@local/*": ["src/*"] },
      },
    }));
    writeFileSync(resolve(root, "index.ts"), 'export * from "@local/topics-path.js";\n');
    writeFileSync(resolve(root, "src/topics-path.ts"), "export const value = true;\n");
    expect(moduleDependencies(resolve(root, "index.ts"))).toContain(
      realpathSync(resolve(root, "src/topics-path.ts")),
    );

    writeFileSync(resolve(root, "missing.ts"), 'void import("@local/missing.js");\n');
    expect(() => moduleDependencies(resolve(root, "missing.ts")))
      .toThrow(/unresolved current vector import/u);
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

  it("keeps family builders limited to boundary-specific fixture data", () => {
    const forbiddenCaseMetadata = [
      /\bsemantic_boundary\s*:/u,
      /\bowner_document\s*:/u,
      /\bspec_refs\s*:/u,
      /\binvariants\s*:/u,
      /\breason_codes\s*:/u,
      /\bexpected_output\s*:/u,
      /\bexecuted[A-Z][A-Za-z]+Rejection\b/u,
      /\bboundary\s*:\s*(?:String|string)\b/u,
      /\binvariant\s*:\s*(?:String|string)\b/u,
      /\bdecision\s*:\s*(?:decision|Readonly)\b/u,
    ];
    for (const family of [
      "core",
      "assurance",
      "comms",
      "control",
      "social",
      "workspace",
      "profiles",
    ]) {
      const source = readFileSync(resolve(sourceRoot, `current-vectors/${family}.ts`), "utf8");
      for (const pattern of forbiddenCaseMetadata) {
        expect(source, `${family}: ${String(pattern)}`).not.toMatch(pattern);
      }
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
  it("rejects any catalog projector that changes the raw verdict class", () => {
    expect(() => assertProjectionPreservesVerdict("reject", { verdict: "accept" }))
      .toThrow(/projector changed semantic verdict/u);
    expect(() => assertProjectionPreservesVerdict(
      "reject",
      { verdict: "reject", reason_code: "bad_signature" },
      "delegation_mismatch",
    )).toThrow(/projector changed semantic reason/u);
    expect(() => assertProjectionPreservesVerdict(
      "indeterminate",
      { verdict: "indeterminate", reason_code: "control-signer-effect-indeterminate" },
    )).not.toThrow();
  });

  it("validates profile wire semantics instead of accepting a registry echo", () => {
    const registry = loadRegistry(resolve(sourceRoot, "../../../../../"));
    const profileCase = buildProfileCases(registry).find(({ vector_id }) =>
      vector_id === "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1"
    )!;
    expect(validateCurrentKindProfileNegotiation(registry, profileCase.input))
      .toMatchObject({ verdict: "accept", stamp_owner: "comms" });

    const malformed = structuredClone(profileCase.input) as {
      wire_probe: { tags: string[][] };
    };
    malformed.wire_probe.tags = [];
    expect(validateCurrentKindProfileNegotiation(registry, malformed)).toEqual({
      verdict: "reject",
      reason: "profile-wire-discriminator-mismatch",
    });

    const activeKey = buildProfileCases(registry).find(({ vector_id }) =>
      vector_id === "assurance/profile-heterodyne-assurance-active-key-acceptance-v1"
    )!;
    expect(validateCurrentKindProfileNegotiation(registry, activeKey.input))
      .toMatchObject({ verdict: "accept", stamp_owner: "assurance" });
    const coreBreadcrumb = buildProfileCases(registry).find(({ vector_id }) =>
      vector_id === "core/profile-heterodyne-core-rotation-breadcrumb-profile-v1"
    )!;
    expect(validateCurrentKindProfileNegotiation(registry, coreBreadcrumb.input))
      .toMatchObject({ verdict: "accept", stamp_owner: null });
  });

  it("preserves exact evaluator results including Control indeterminate", async () => {
    const cases = await buildCurrentCases();
    const byId = new Map(cases.map((entry) => [entry.vector_id, entry]));

    const signerEffect = byId.get("control/signer-effect-indeterminate")!;
    const signerInput = {
      canonical_event_valid: true,
      fields_exact: true,
      effect_certain: false,
    };
    expect(signerEffect.expected_output).toEqual(validateControlSignedEffect(signerInput));
    expect(signerEffect.expected_output).toMatchObject({
      verdict: "indeterminate",
      reason_code: "control-signer-effect-indeterminate",
    });
    expect(Object.isFrozen(signerEffect.expected_output)).toBe(true);
  }, 60_000);

  it("binds crossed Assurance cases to the evaluator that produced their result", async () => {
    const cases = await buildCurrentCases();
    const byId = new Map(cases.map((entry) => [entry.vector_id, entry]));

    const succession = byId.get("assurance/succession-valid")!;
    expect(succession.semantic_boundary).toBe("assurance.evaluateSuccession");
    expect(succession.expected_output).toEqual(evaluateSuccession(
      succession.input as Parameters<typeof evaluateSuccession>[0],
    ));

    const continuation = byId.get(
      "assurance/compromise-subordinate-continuation-forbidden",
    )!;
    expect(continuation.semantic_boundary).toBe(
      "assurance-policy.evaluateAssuranceCompromiseContinuation",
    );
    expect(continuation.expected_output).toEqual(
      evaluateAssuranceCompromiseContinuation({
        transition_class: "compromise",
        subordinate_reauthorization_ids:
          continuation.input.subordinate_reauthorization_ids as readonly string[],
      }),
    );
  }, 60_000);

  it("never serializes registry-derived trace labels as semantic vectors", async () => {
    const vectors = (await buildCurrentVectors()).map(({ vector }) => vector);
    expect(vectors.filter(({ vector_id }) => vector_id.includes("/trace/"))).toEqual([]);
    expect(vectors.filter(({ input, expected_output }) =>
      Object.hasOwn(input, "diagnostic_condition")
      || Object.hasOwn(input, "protocol_state")
      || Object.hasOwn(expected_output, "invariant_satisfied")
    )).toEqual([]);
    for (const vector of vectors) {
      const serialized = JSON.stringify(vector);
      expect(serialized).not.toMatch(
        /boundary_args|raw_result|semantic_reason_codes|evidence_brand/u,
      );
    }
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
    expect(byId.get("assurance/persona-author-mismatch")?.expected_output)
      .toEqual({ verdict: "reject", reason_code: "delegation_mismatch" });
    expect(byId.get("assurance/keri-wire-format-rejected")?.expected_output)
      .toEqual({ verdict: "reject", reason_code: "keri_wire_format_rejected" });
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
