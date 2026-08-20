import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { afterEach, describe, expect, it } from "vitest";

type ImportEdge = { importer: string; specifier: string; resolved: string };

const repositoryRoot = fileURLToPath(new URL("../../../../../", import.meta.url));
const conformanceRoot = resolve(repositoryRoot, "docs/spec/conformance");
const generatorRoot = resolve(repositoryRoot, "docs/spec/vectors/generator");
const temporaryRoots: string[] = [];

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith("..") && !path.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`));
}

function sourceFiles(root: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...sourceFiles(path));
    } else if (entry.isFile() && [".ts", ".tsx", ".js", ".mjs", ".cjs"].includes(extname(entry.name))) {
      files.push(path);
    }
  }
  return files.sort();
}

function importSpecifiers(path: string): string[] {
  const source = ts.createSourceFile(
    path,
    readFileSync(path, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  const specifiers: string[] = [];
  const visit = (node: ts.Node): void => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node))
      && node.moduleSpecifier !== undefined
      && ts.isStringLiteralLike(node.moduleSpecifier)
    ) {
      specifiers.push(node.moduleSpecifier.text);
    } else if (
      ts.isImportEqualsDeclaration(node)
      && ts.isExternalModuleReference(node.moduleReference)
      && node.moduleReference.expression !== undefined
      && ts.isStringLiteralLike(node.moduleReference.expression)
    ) {
      specifiers.push(node.moduleReference.expression.text);
    } else if (
      ts.isCallExpression(node)
      && node.arguments.length >= 1
      && ts.isStringLiteralLike(node.arguments[0]!)
      && (node.expression.kind === ts.SyntaxKind.ImportKeyword
        || (ts.isIdentifier(node.expression) && node.expression.text === "require"))
    ) {
      specifiers.push(node.arguments[0]!.text);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return specifiers;
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
  packageRoot: string,
  forbiddenRoot: string,
  forbiddenPackageName: string,
): ImportEdge[] {
  const canonicalPackageRoot = realpathSync(packageRoot);
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

    for (const specifier of importSpecifiers(importer)) {
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
      } else if (isWithin(canonicalPackageRoot, resolved) && [".ts", ".tsx", ".js", ".mjs", ".cjs"].includes(extname(resolved))) {
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
});
