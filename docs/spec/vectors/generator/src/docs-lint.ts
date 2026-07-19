import { existsSync, readFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import {
  assertAllowedDependency,
  parseQualifiedVersion,
} from "./family.js";
import type { DocumentId } from "./types.js";

export type FamilyDocIssue = {
  path: string;
  line: number;
  code:
    | "duplicate-anchor"
    | "unresolved-reference"
    | "forbidden-dependency"
    | "bare-normative-link";
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
