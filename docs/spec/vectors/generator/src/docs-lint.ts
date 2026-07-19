import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { relative, resolve, sep } from "node:path";
import {
  assertAllowedDependency,
  parseQualifiedVersion,
} from "./family.js";
import type { DocumentId } from "./types.js";
import { loadRegistry } from "./registry.js";

export type FamilyDocIssue = {
  path: string;
  line: number;
  code:
    | "duplicate-anchor"
    | "unresolved-reference"
    | "forbidden-dependency"
    | "undeclared-dependency"
    | "bare-normative-link"
    | "missing-cutover-artifact"
    | "archive-digest-mismatch"
    | "archive-map-mismatch"
    | "overview-normative-language"
    | "extraction-banner"
    | "release-manifest-mismatch";
  message: string;
};

type FamilyDocument = {
  document: DocumentId;
  absolutePath: string;
  displayPath: string;
  lines: string[];
};

const DOCUMENTS: readonly DocumentId[] = [
  "core",
  "comms",
  "control",
  "social",
];

const EXPLICIT_ANCHOR = /<a\s+id="([a-z0-9]+(?:-[a-z0-9]+)*)"\s*><\/a>/g;
const QUALIFIED_REFERENCE =
  /heterodyne:(core|comms|control|social)\/((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)#([a-z0-9]+(?:-[a-z0-9]+)*)/g;
const BARE_FAMILY_LINK =
  /\]\((?:\.\/)?heterodyne-(core|comms|control|social)\.md(?:#[^)]+)?\)/i;
const BCP14_KEYWORD =
  /\b(?:MUST(?: NOT)?|REQUIRED|SHALL(?: NOT)?|SHOULD(?: NOT)?|RECOMMENDED|NOT RECOMMENDED|MAY|OPTIONAL)\b/;
const EXPLICIT_NORMATIVE =
  /(?<!non-)(?<!non )\bnormative(?:ly)?\b/i;
const LIST_ITEM = /^\s{0,3}(?:[-+*]|\d+[.)])\s+/;
const TABLE_ROW = /^\s*\|.*\|\s*$/;
const WRAPPED_DEPENDENCY_DECLARATION = /^\s*Normative dependencies\s*:\s*$/i;
const ARCHIVE_SHA256 =
  "357f4082b3dd82e3870859c654c354106267399ff8589cf7e22894ee2033c83d";

function displayPath(repoRoot: string, path: string): string {
  return relative(repoRoot, path).split(sep).join("/");
}

function loadFamilyDocuments(repoRoot: string): FamilyDocument[] {
  return DOCUMENTS.flatMap((document) => {
    const absolutePath = resolve(
      repoRoot,
      "docs/spec",
      `heterodyne-${document}.md`,
    );
    if (!existsSync(absolutePath)) return [];
    return [
      {
        document,
        absolutePath,
        displayPath: displayPath(repoRoot, absolutePath),
        lines: readFileSync(absolutePath, "utf8").split(/\r?\n/),
      },
    ];
  });
}

function carriesNormativeForce(line: string): boolean {
  return BCP14_KEYWORD.test(line) || EXPLICIT_NORMATIVE.test(line);
}

function normativeParagraphLines(lines: readonly string[]): Set<number> {
  const normative = new Set<number>();
  let paragraph: number[] = [];
  let fenced = false;
  let dependencyState: "none" | "awaiting-list" | "in-list" = "none";

  const flush = (): void => {
    if (
      paragraph.some((lineNumber) => carriesNormativeForce(lines[lineNumber]))
    ) {
      for (const lineNumber of paragraph) normative.add(lineNumber);
    }
    paragraph = [];
    dependencyState = "none";
  };

  for (const [lineNumber, line] of lines.entries()) {
    if (/^\s*```/.test(line)) {
      flush();
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    if (line.trim() === "") {
      if (dependencyState === "awaiting-list") continue;
      flush();
      continue;
    }
    if (/^#{1,6}\s/.test(line) || /^<a\s+id=/.test(line)) {
      flush();
      continue;
    }

    if (WRAPPED_DEPENDENCY_DECLARATION.test(line)) {
      flush();
      paragraph.push(lineNumber);
      dependencyState = "awaiting-list";
      continue;
    }

    if (TABLE_ROW.test(line)) {
      flush();
      paragraph.push(lineNumber);
      flush();
      continue;
    }

    if (LIST_ITEM.test(line)) {
      if (dependencyState === "awaiting-list") {
        dependencyState = "in-list";
      } else if (dependencyState !== "in-list" && paragraph.length > 0) {
        flush();
      }
      paragraph.push(lineNumber);
      continue;
    }

    if (dependencyState === "in-list" && /^\s+/.test(line)) {
      paragraph.push(lineNumber);
      continue;
    }

    if (dependencyState !== "none") flush();
    paragraph.push(lineNumber);
  }
  flush();
  return normative;
}

function declaredNormativeDependencies(
  lines: readonly string[],
): Set<string> {
  const declared = new Set<string>();
  const addReferences = (line: string): void => {
    for (const match of line.matchAll(QUALIFIED_REFERENCE)) {
      declared.add(`${match[1]}/${match[2]}`);
    }
  };

  for (const [index, line] of lines.entries()) {
    if (!/^\s*Normative dependencies\s*:/i.test(line)) continue;
    addReferences(line);
    let listStarted = false;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const candidate = lines[cursor];
      if (candidate.trim() === "") {
        if (listStarted) break;
        continue;
      }
      if (LIST_ITEM.test(candidate)) {
        listStarted = true;
        addReferences(candidate);
        continue;
      }
      if (listStarted && /^\s+/.test(candidate)) {
        addReferences(candidate);
        continue;
      }
      break;
    }
  }
  return declared;
}

export function lintFamilyDocs(repoRoot: string): FamilyDocIssue[] {
  const documents = loadFamilyDocuments(repoRoot);
  const issues: FamilyDocIssue[] = [];
  const anchors = new Map<string, { path: string; line: number }>();
  const documentAnchors = new Set<string>();

  for (const document of documents) {
    for (const [index, line] of document.lines.entries()) {
      for (const match of line.matchAll(EXPLICIT_ANCHOR)) {
        const anchor = match[1];
        documentAnchors.add(`${document.document}:${anchor}`);
        const existing = anchors.get(anchor);
        if (existing !== undefined) {
          issues.push({
            path: document.displayPath,
            line: index + 1,
            code: "duplicate-anchor",
            message: `anchor ${anchor} duplicates ${existing.path}:${existing.line}`,
          });
        } else {
          anchors.set(anchor, {
            path: document.displayPath,
            line: index + 1,
          });
        }
      }
    }
  }

  for (const document of documents) {
    const normativeLines = normativeParagraphLines(document.lines);
    const declaredDependencies = declaredNormativeDependencies(document.lines);
    for (const [index, line] of document.lines.entries()) {
      const lineNumber = index + 1;
      const references = [...line.matchAll(QUALIFIED_REFERENCE)];

      for (const match of references) {
        const target = match[1] as DocumentId;
        const version = match[2];
        const anchor = match[3];
        parseQualifiedVersion(`${target}/${version}`);
        if (!documentAnchors.has(`${target}:${anchor}`)) {
          issues.push({
            path: document.displayPath,
            line: lineNumber,
            code: "unresolved-reference",
            message: `${match[0]} does not resolve to an explicit family anchor`,
          });
        }
      }

      if (normativeLines.has(index)) {
        for (const match of references) {
          const target = match[1] as DocumentId;
          const targetVersion = `${target}/${match[2]}`;
          if (
            target !== document.document &&
            !declaredDependencies.has(targetVersion)
          ) {
            issues.push({
              path: document.displayPath,
              line: lineNumber,
              code: "undeclared-dependency",
              message: `${document.document} normatively references undeclared dependency ${targetVersion}`,
            });
          }
          try {
            assertAllowedDependency(document.document, target);
          } catch {
            issues.push({
              path: document.displayPath,
              line: lineNumber,
              code: "forbidden-dependency",
              message: `${document.document} cannot normatively depend on ${target}`,
            });
          }
        }
      }

      if (normativeLines.has(index) && BARE_FAMILY_LINK.test(line)) {
        issues.push({
          path: document.displayPath,
          line: lineNumber,
          code: "bare-normative-link",
          message:
            "normative family references must use a qualified heterodyne: URI",
        });
      }
    }
  }

  return issues;
}

function githubHeadingAnchors(markdown: string): string[] {
  const anchors: string[] = [];
  const counts = new Map<string, number>();
  let fenced = false;
  for (const line of markdown.split(/\r?\n/)) {
    if (/^\s*```/.test(line)) {
      fenced = !fenced;
      continue;
    }
    if (fenced) continue;
    const heading = line.match(/^#{1,6}\s+(.+?)\s*#*\s*$/)?.[1];
    if (!heading) continue;
    const base = heading
      .toLowerCase()
      .replace(/<[^>]*>/g, "")
      .replace(/[^\p{L}\p{N}\s_-]/gu, "")
      .replace(/ /g, "-");
    const duplicate = counts.get(base) ?? 0;
    counts.set(base, duplicate + 1);
    anchors.push(`#${base}${duplicate === 0 ? "" : `-${duplicate}`}`);
  }
  return anchors;
}

type ReleaseManifest = {
  document: DocumentId;
  version: "0.5.0";
  qualified_version: `${DocumentId}/0.5.0`;
  registry_revision: number;
  registry_sha256: string;
  dependencies: Partial<Record<DocumentId, `${DocumentId}/0.5.0`>>;
  features: string[];
  conformance_status: "conformant" | "incomplete-draft";
};

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right, "en"))
      .map(([key, member]) => `${JSON.stringify(key)}:${canonicalJson(member)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function expectedReleaseManifests(repoRoot: string): Record<DocumentId, ReleaseManifest> {
  const registry = loadRegistry(repoRoot);
  const registryRevision = registry.manifest.revision;
  const registrySha256 = registry.manifest.entry_set_sha256;
  return {
    core: {
      document: "core",
      version: "0.5.0",
      qualified_version: "core/0.5.0",
      registry_revision: registryRevision,
      registry_sha256: registrySha256,
      dependencies: {},
      features: [],
      conformance_status: "conformant",
    },
    comms: {
      document: "comms",
      version: "0.5.0",
      qualified_version: "comms/0.5.0",
      registry_revision: registryRevision,
      registry_sha256: registrySha256,
      dependencies: { core: "core/0.5.0" },
      features: [],
      conformance_status: "conformant",
    },
    control: {
      document: "control",
      version: "0.5.0",
      qualified_version: "control/0.5.0",
      registry_revision: registryRevision,
      registry_sha256: registrySha256,
      dependencies: { core: "core/0.5.0", comms: "comms/0.5.0" },
      features: ["double-ratchet"],
      conformance_status: "incomplete-draft",
    },
    social: {
      document: "social",
      version: "0.5.0",
      qualified_version: "social/0.5.0",
      registry_revision: registryRevision,
      registry_sha256: registrySha256,
      dependencies: { core: "core/0.5.0", comms: "comms/0.5.0" },
      features: [],
      conformance_status: "conformant",
    },
  };
}

export function writeReleaseManifests(repoRoot: string): string[] {
  const expected = expectedReleaseManifests(repoRoot);
  const written: string[] = [];
  for (const document of DOCUMENTS) {
    const directory = resolve(repoRoot, "docs/spec/releases", document);
    const path = resolve(directory, "0.5.0.json");
    mkdirSync(directory, { recursive: true });
    writeFileSync(path, `${JSON.stringify(expected[document], null, 2)}\n`, "utf8");
    written.push(path);
  }
  return written;
}

export function lintFamilyCutover(repoRoot: string): FamilyDocIssue[] {
  const issues: FamilyDocIssue[] = [];
  const archivePath = resolve(repoRoot, "docs/spec/archive/heterodyne-0.4.0.md");
  const mapPath = resolve(
    repoRoot,
    "docs/spec/archive/heterodyne-0.4.0-anchor-map.md",
  );
  const overviewPath = resolve(repoRoot, "docs/spec/heterodyne.md");
  const required = [archivePath, mapPath, overviewPath];
  for (const path of required) {
    if (!existsSync(path)) {
      issues.push({
        path: displayPath(repoRoot, path),
        line: 1,
        code: "missing-cutover-artifact",
        message: "required family-cutover artifact is missing",
      });
    }
  }
  if (issues.length > 0) return issues;

  const archive = readFileSync(archivePath, "utf8");
  const archiveDigest = createHash("sha256").update(archive, "utf8").digest("hex");
  if (archiveDigest !== ARCHIVE_SHA256) {
    issues.push({
      path: displayPath(repoRoot, archivePath),
      line: 1,
      code: "archive-digest-mismatch",
      message: `expected ${ARCHIVE_SHA256}, got ${archiveDigest}`,
    });
  }

  const map = readFileSync(mapPath, "utf8");
  const expectedOldAnchors = githubHeadingAnchors(archive);
  const rows = [...map.matchAll(
    /^\| `(#(?:[^`]+))` \| (Core|Comms|Control|Social) \| `heterodyne:(core|comms|control|social)\/0\.5\.0#([a-z0-9]+(?:-[a-z0-9]+)*)` \|$/gm,
  )];
  const mappedAnchors = rows.map((row) => row[1]);
  const familyDocs = loadFamilyDocuments(repoRoot);
  const destinations = new Set(
    familyDocs.flatMap((document) =>
      document.lines.flatMap((line) =>
        [...line.matchAll(EXPLICIT_ANCHOR)].map(
          (match) => `${document.document}:${match[1]}`,
        ),
      ),
    ),
  );
  if (
    !map.includes(`Archive SHA-256: \`${ARCHIVE_SHA256}\``) ||
    JSON.stringify(mappedAnchors) !== JSON.stringify(expectedOldAnchors) ||
    new Set(mappedAnchors).size !== expectedOldAnchors.length ||
    rows.some(
      (row) =>
        row[2].toLowerCase() !== row[3] ||
        !destinations.has(`${row[3]}:${row[4]}`),
    )
  ) {
    issues.push({
      path: displayPath(repoRoot, mapPath),
      line: 1,
      code: "archive-map-mismatch",
      message: "anchor map must cover every archive heading once with a resolvable owner-qualified destination",
    });
  }

  const overview = readFileSync(overviewPath, "utf8");
  if (BCP14_KEYWORD.test(overview)) {
    issues.push({
      path: displayPath(repoRoot, overviewPath),
      line: 1,
      code: "overview-normative-language",
      message: "the non-normative family overview contains an uppercase BCP 14 keyword",
    });
  }
  for (const document of familyDocs) {
    if (/pre-release extraction draft/i.test(document.lines.join("\n"))) {
      issues.push({
        path: document.displayPath,
        line: 1,
        code: "extraction-banner",
        message: "pre-release extraction banner remains after cutover",
      });
    }
  }

  const expected = expectedReleaseManifests(repoRoot);
  const schemaPath = resolve(repoRoot, "docs/spec/releases/release-manifest.schema.json");
  if (!existsSync(schemaPath)) {
    issues.push({
      path: displayPath(repoRoot, schemaPath),
      line: 1,
      code: "missing-cutover-artifact",
      message: "release manifest schema is missing",
    });
    return issues;
  }
  const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as {
    properties?: { registry_sha256?: { const?: unknown } };
  };
  if (schema.properties?.registry_sha256?.const !== expected.core.registry_sha256) {
    issues.push({
      path: displayPath(repoRoot, schemaPath),
      line: 1,
      code: "release-manifest-mismatch",
      message: "release schema does not pin the validated registry digest",
    });
  }
  for (const document of DOCUMENTS) {
    const path = resolve(repoRoot, `docs/spec/releases/${document}/0.5.0.json`);
    if (!existsSync(path)) {
      issues.push({
        path: displayPath(repoRoot, path),
        line: 1,
        code: "missing-cutover-artifact",
        message: `${document} release manifest is missing`,
      });
      continue;
    }
    const actual = JSON.parse(readFileSync(path, "utf8"));
    if (canonicalJson(actual) !== canonicalJson(expected[document])) {
      issues.push({
        path: displayPath(repoRoot, path),
        line: 1,
        code: "release-manifest-mismatch",
        message: `${document} release manifest differs from the validated registry-derived form`,
      });
    }
  }
  return issues;
}
