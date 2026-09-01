import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { Parser } from "commonmark";
import type { Node as CommonmarkNode } from "commonmark";
import ts from "typescript";
import {
  assertAllowedDependency,
  DOCUMENTS,
  FAMILY_VERSION,
  QUALIFIED_VERSION,
} from "./family.js";
import type { DocumentId } from "./types.js";
import { computeRegistryDigest, loadRegistry } from "./registry.js";
import { verifyMarmotArchive } from "./marmot-archive.js";

/** The complete claims/OIDC invariant set required in the family threat model. */
export const CLAIMS_OIDC_INVARIANT_IDS = [
  "COMMS-I-CLAIM-AUTHENTICITY",
  "COMMS-I-CLAIM-ATTENUATION",
  "COMMS-I-CLAIM-REPOSITORY-AUTHORITY",
  "COMMS-I-CLAIM-REVOCATION",
  "COMMS-I-LEDGER-CONFINEMENT",
  "COMMS-I-ISSUER-KEY-CONFINEMENT",
  "COMMS-I-MINT-FRESHNESS",
  "COMMS-I-ISSUER-CONTINUITY",
  "COMMS-I-CLAIM-RELEASE",
  "COMMS-I-JWT-TYPE-AUDIENCE",
  "COMMS-I-STATUS-INTEGRITY",
] as const;

export type FamilyDocIssue = {
  path: string;
  line: number;
  code:
    | "duplicate-anchor"
    | "unresolved-reference"
    | "forbidden-dependency"
    | "bare-normative-link"
    | "noncanonical-decision-reference"
    | "marmot-archive-invalid"
    | "generic-repo-relay-server-claim"
    | "ambiguous-nostr-wire-key"
    | "claim-profile-revision-ambiguous"
    | "missing-upstream-kind-allocation"
    | "strict-profile-closure-invalid"
    | "unresolved-section-reference"
    | "registry-digest-drift"
    | "unregistered-feature-id"
    | "unregistered-proof-domain"
    | "mislinked-reference"
    | "retired-authoring-model"
    | "stale-family-version"
    | "markdown-resource-limit"
    | "profile-revision-registry-context-missing"
    | "defensive-validation-scope"
    | "defensive-validation-target"
    | "snapshot-manifest-invalid"
    | "snapshot-guidance-missing"
    | "snapshot-guidance-stale";
  message: string;
};

export type DocsLintIssue = FamilyDocIssue;

type FamilyDocument = {
  document: DocumentId;
  absolutePath: string;
  displayPath: string;
  lines: string[];
};

const EXPLICIT_ANCHOR = /<a\s+id="([a-z0-9]+(?:-[a-z0-9]+)*)"\s*><\/a>/g;
const QUALIFIED_REFERENCE = new RegExp(
  `heterodyne:((?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?)#([a-z0-9]+(?:-[a-z0-9]+)*)`,
  "g",
);
// A normative cross-reference is a clickable link whose text is its own
// qualified URI: [`heterodyne:<ver>#<anchor>`](<file>#<anchor>).
const LINKED_QUALIFIED_REFERENCE = new RegExp(
  "\\[`heterodyne:[^`]+#([a-z0-9-]+)`\\]"
    + "\\((?:heterodyne-(core|assurance|comms|control|social|workspace)\\.md)?#([a-z0-9-]+)\\)",
  "g",
);
// Within a document [12.2](#anchor) is fine; across one, the version has to
// travel with the reference.
const CROSS_DOCUMENT_LINK =
  /\]\((?:\.\/)?heterodyne-(?:core|assurance|comms|control|social|workspace)\.md#[^)]+\)/;
const LOCAL_ANCHOR_LINK = /\]\(#([a-z0-9-]+)\)/g;
const NONCANONICAL_DECISION_REFERENCE = /\bADR-\d{3}\b|docs\/adr\//;
const NUMBERED_HEADING = /^#{2,6}\s+(\d+(?:\.\d+)*)\.?\s/;
const SECTION_REFERENCE = /§(\d+(?:\.\d+)*)/g;
const STALE_BARE_FAMILY_VERSION =
  /\b(?:Core|Assurance|Comms|Control|Social|Workspace)\s+0\.5(?:\.0)?\b(?!\.\d)/giu;
const PROOF_DOMAIN = /\bdomain\s+`(heterodyne-[a-z0-9-]*-v[1-9][0-9]*)`/gi;
const PROOF_DOMAIN_FENCED = /`?<?(heterodyne-[a-z0-9-]*-v[1-9][0-9]*) proof bytes>?`?/g;
const FEATURE_ID =
  /`((?:core|assurance|comms|control|social|workspace)\.[a-z0-9-]+(?:\.[a-z0-9-]+)*\.v\d+)`/g;
const BCP14_KEYWORD =
  /\b(?:MUST(?: NOT)?|REQUIRED|SHALL(?: NOT)?|SHOULD(?: NOT)?|RECOMMENDED|NOT RECOMMENDED|MAY|OPTIONAL)\b/;
const EXPLICIT_NORMATIVE =
  /(?<!non-)(?<!non )\bnormative(?:ly)?\b/i;
const LIST_ITEM = /^\s{0,3}(?:[-+*]|\d+[.)])\s+/;
const TABLE_ROW = /^\s*\|.*\|\s*$/;
const WRAPPED_DEPENDENCY_DECLARATION = /^\s*Normative dependencies\s*:\s*$/i;
const RETIRED_MAINTAINED_GUIDE_PATTERNS = [
  /owner_version/,
  /dependency_versions/,
  /heterodyne:(?:core|assurance|comms|control|social|workspace)\//,
  /run release-manifests/,
  /JSON member remains named\s+`registry_revision`/,
  /five documents are independently versioned/i,
  /five independently versioned documents/i,
  /deleted\s+`?docs\/spec\/releases\//i,
  /comms\.node-scoped-jwt\.v1/,
  /supplies exactly four things/i,
  /claim profile registry revision/i,
  /dependency versions above/i,
  /(?:committed\s+JSON\s+|conformance\s+)?vectors?\s+(?:are|is)\s+the\s+normative\s+artifacts?/i,
  /vectors?\s+are\s+normative\s+for\s+the\s+behavior\s+they\s+cover/i,
  /normative\s+vector\s+corpus/i,
  /wire-level changes require corresponding normative vector changes/i,
  /npm --prefix docs\/spec\/vectors\/generator run release-(?:author|check|manifests)/i,
  /(?:docs\/spec\/)?releases\/family\/0\.5\.0\.json/i,
  /family-release-manifest\.schema\.json/i,
  /family\s+release\s+manifest/i,
  /one\s+content-addressed\s+family\s+release\s+record/i,
  /protocol\s+authority\s+is\s+the\s+versioned\s+specification\s+family\s+and\s+its\s+normative\s+registries,\s+schemas,\s+release\s+metadata,\s+and\s+conformance\s+vectors/i,
  /live\s+specifications,\s+registry,\s+schemas,\s+release\s+metadata,\s+and\s+vectors\s+remain\s+the\s+protocol\s+authority/i,
  /generator-owned\s+protocol\s+inputs:\s+live\s+normative\s+machine-readable\s+artifacts/i,
  /recheck the named family release/i,
];

const DEFENSIVE_VALIDATION_TARGET_CATEGORIES = [
  {
    item: "live[-\\s]+targets?",
    affirmative: /\blive[-\s]+targets?\b/giu,
  },
  {
    item: "live\\s+(?:relays?|nodes?|services?|deployments?|identity\\s+providers?|accounts?|credentials?)",
    affirmative:
      /\blive\s+(?:relays?|nodes?|services?|deployments?|identity\s+providers?|accounts?|credentials?)\b/giu,
  },
  {
    item: "production\\s+(?:deployments?|services?|relays?|nodes?|systems?)",
    affirmative: /\bproduction\s+(?:deployments?|services?|relays?|nodes?|systems?)\b/giu,
  },
  {
    item: "(?:real|external)\\s+(?:accounts?|credentials?|data)",
    affirmative: /\b(?:real|external)\s+(?:accounts?|credentials?|data)\b/giu,
  },
  {
    item: "(?:external|third[-\\s]+party)\\s+systems?",
    affirmative: /\b(?:external|third[-\s]+party)\s+systems?\b/giu,
  },
  {
    item: "external\\s+targets?",
    affirmative:
      /\b(?:use|contact|access|scan|exercise|test|reach)(?:s|ed|ing)?\s+(?:(?:any|a|an|the)\s+)?(?<target>external\s+targets?)\b/giu,
  },
  {
    item: "(?:reusable|functional|deployable)\\s+(?:exploits?|payloads?)(?:\\s+directions?)?",
    affirmative:
      /\b(?:reusable|functional|deployable)\s+(?:exploits?|payloads?)(?:\s+directions?)?\b/giu,
  },
  {
    item: "targets?",
    affirmative:
      /\b(?:use|contact|access|scan|exercise|test|reach)(?:s|ed|ing)?\s+(?:(?:any|a|an|the)\s+)?(?<target>targets?)\b/giu,
  },
] as const;
const DEFENSIVE_VALIDATION_TARGET_ITEM =
  `(?:${DEFENSIVE_VALIDATION_TARGET_CATEGORIES.map(({ item }) => item).join("|")})`;
const DEFENSIVE_VALIDATION_PROHIBITED_LIST = new RegExp(
  String.raw`\b(?:no|without)\s+${DEFENSIVE_VALIDATION_TARGET_ITEM}`
    + String.raw`(?:\s*,\s*${DEFENSIVE_VALIDATION_TARGET_ITEM})*`
    + String.raw`(?:\s*,?\s*(?:or|and)\s+${DEFENSIVE_VALIDATION_TARGET_ITEM})?`
    + String.raw`(?:\s+(?:is|are)\s+(?:used|contacted|accessed|tested|created|produced|generated|delivered|deployed))?\b`,
  "giu",
);
const DEFENSIVE_VALIDATION_DIRECT_PROHIBITION_BEFORE =
  /\b(?:no|without|never)\s+(?:(?:any|a|an|the)\s+)?$|\b(?:must|shall|do)\s+not\s+(?:(?:use|contact|target|access|exercise|interact\s+with|test|create|produce|generate|deliver|send|run|deploy|connect)\s+)?(?:(?:any|a|an|the)\s+)?$|\b(?:avoid|exclude|excluding|excluded?|prohibit(?:s|ed)?|forbid(?:s|den)?)\s*$/iu;
const DEFENSIVE_VALIDATION_DIRECT_PROHIBITION_AFTER =
  /^\s*(?:(?:is|are|was|were|must|shall)\s+)?(?:prohibited|forbidden|disallowed|excluded|not\s+(?:allowed|permitted)|must\s+not\s+be\s+used)\b/iu;
const DEFENSIVE_VALIDATION_DIRECT_ACTION_PROHIBITION_BEFORE =
  /\b(?:never|do\s+not|must\s+not|shall\s+not)\s+(?:(?:use|contact|target|access|exercise|test|create|produce|generate|deliver|send|run|deploy|connect|scan)(?:s|ed|ing)?|sign(?:s|ed|ing)?\s+for)(?:\s+or\s+(?:(?:use|contact|target|access|exercise|test|create|produce|generate|deliver|send|run|deploy|connect|scan)(?:s|ed|ing)?|sign(?:s|ed|ing)?\s+for))*\s+(?:(?:any|a|an|the)\s+)?$/iu;
function defensiveValidationTargetIsProhibited(
  text: string,
  matchStart: number,
  matchEnd: number,
  prohibitedListRanges: readonly (readonly [number, number])[],
): boolean {
  const before = text.slice(Math.max(0, matchStart - 128), matchStart);
  const after = text.slice(matchEnd, matchEnd + 96);
  return DEFENSIVE_VALIDATION_DIRECT_PROHIBITION_BEFORE.test(before)
    || DEFENSIVE_VALIDATION_DIRECT_ACTION_PROHIBITION_BEFORE.test(before)
    || DEFENSIVE_VALIDATION_DIRECT_PROHIBITION_AFTER.test(after)
    || prohibitedListRanges.some(([start, end]) =>
      start <= matchStart && end >= matchEnd
    );
}

const APPROVED_CLOSURE_PLAN_PATH =
  "docs/superpowers/plans/2026-08-29-heterodyne-0.6-final-security-closure.md";
const DEFENSIVE_REVIEW_PATH = /(?:\.test\.ts|(?:brief|review)\.(?:md|txt))$/iu;

/** Check new hostile-boundary test or brief prose for defensive framing. */
export function lintDefensiveValidationText(
  text: string,
  path: string,
): DocsLintIssue[] {
  const hostile = /\b(hostile|adversarial|attacker|attack)\b/iu.test(text);
  const defensive = /\bBLUE TEAM VALIDATION\b/u.test(text)
    && /\b(synthetic|local)\b/iu.test(text);
  const issues: DocsLintIssue[] = [];
  if (hostile && !defensive) {
    issues.push({
      path,
      line: 1,
      code: "defensive-validation-scope",
      message: "hostile-boundary validation must be framed as synthetic/local BLUE TEAM VALIDATION",
    });
  }
  if (hostile) {
    const prohibitedListRanges = [...text.matchAll(DEFENSIVE_VALIDATION_PROHIBITED_LIST)]
      .map((match) => [match.index, match.index + match[0].length] as const);
    for (const { affirmative } of DEFENSIVE_VALIDATION_TARGET_CATEGORIES) {
      for (const match of text.matchAll(affirmative)) {
        const target = match.groups?.target ?? match[0];
        const matchStart = match.index + match[0].lastIndexOf(target);
        const matchEnd = matchStart + target.length;
        if (defensiveValidationTargetIsProhibited(
          text,
          matchStart,
          matchEnd,
          prohibitedListRanges,
        )) continue;
        issues.push({
          path,
          line: 1,
          code: "defensive-validation-target",
          message: "hostile-boundary validation must prohibit live targets, real credentials, external systems, and reusable payload directions",
        });
        return issues;
      }
    }
  }
  return issues;
}

const BLUE_TEAM_TEST_PREFIX = "BLUE TEAM VALIDATION: synthetic/local";

function isTestApi(expression: ts.Expression): boolean {
  return ts.isIdentifier(expression)
    && (expression.text === "it"
      || expression.text === "test"
      || expression.text === "describe");
}

function isTestDeclarationCall(node: ts.CallExpression): boolean {
  const expression = node.expression;
  if (isTestApi(expression)) return true;
  if (ts.isPropertyAccessExpression(expression)) {
    return isTestApi(expression.expression)
      && ["only", "skip", "todo"].includes(expression.name.text);
  }
  if (!ts.isCallExpression(expression)
    || !ts.isPropertyAccessExpression(expression.expression)) return false;
  return isTestApi(expression.expression.expression)
    && ["each", "for"].includes(expression.expression.name.text);
}

function isSuiteDeclarationCall(node: ts.CallExpression): boolean {
  const expression = node.expression;
  if (ts.isIdentifier(expression)) return expression.text === "describe";
  if (ts.isPropertyAccessExpression(expression)) {
    return ts.isIdentifier(expression.expression)
      && expression.expression.text === "describe";
  }
  return ts.isCallExpression(expression)
    && ts.isPropertyAccessExpression(expression.expression)
    && ts.isIdentifier(expression.expression.expression)
    && expression.expression.expression.text === "describe";
}

function literalTestTitle(node: ts.CallExpression): string | undefined {
  const title = node.arguments[0];
  if (title === undefined || !ts.isStringLiteralLike(title)) return undefined;
  return title.text;
}

function identifierTokens(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/gu, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/gu, "$1 $2")
    .split(/[^A-Za-z0-9]+/u)
    .filter((token) => token.length > 0)
    .map((token) => token.toLowerCase());
}

function declarationNamesHostileFixture(node: ts.CallExpression): boolean {
  const title = literalTestTitle(node);
  if (title !== undefined && /\b(?:hostile|adversarial|attacker|attack)\b/iu.test(title)) return true;
  let hostile = false;
  const visit = (child: ts.Node): void => {
    if (hostile) return;
    if (ts.isIdentifier(child)
      && identifierTokens(child.text).some((token) =>
        token === "hostile" || token === "adversarial"
        || token === "attacker" || token === "attack"
      )) {
      hostile = true;
      return;
    }
    if (
      ts.isStringLiteralLike(child)
      && /\b(?:hostile|adversarial|attacker|attack)\b/iu.test(child.text)
      && ts.isPropertyAssignment(child.parent)
      && child.parent.initializer === child
    ) {
      hostile = true;
      return;
    }
    ts.forEachChild(child, visit);
  };
  visit(isSuiteDeclarationCall(node) ? node.expression : node);
  return hostile;
}

function hasExactBlueTeamTestPrefix(title: string): boolean {
  if (!title.startsWith(BLUE_TEAM_TEST_PREFIX)) return false;
  const boundary = title[BLUE_TEAM_TEST_PREFIX.length];
  return boundary === undefined || /[\s:;,.!?()[\]{}—–-]/u.test(boundary);
}

/** Require exact BLUE TEAM framing on each explicitly hostile test declaration. */
export function lintDefensiveValidationTestDeclarations(
  text: string,
  path: string,
): DocsLintIssue[] {
  const source = ts.createSourceFile(
    path,
    text,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const issues: DocsLintIssue[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && isTestDeclarationCall(node)) {
      const title = literalTestTitle(node);
      if (declarationNamesHostileFixture(node)
        && (title === undefined || !hasExactBlueTeamTestPrefix(title))) {
        issues.push({
          path,
          line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1,
          code: "defensive-validation-scope",
          message:
            `hostile test title must start exactly ${BLUE_TEAM_TEST_PREFIX}`,
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return issues;
}

function generatorTestPaths(repoRoot: string): string[] {
  const sourcePath = "docs/spec/vectors/generator/src";
  const sourceRoot = resolve(repoRoot, sourcePath);
  if (!existsSync(sourceRoot)) return [];
  const visit = (absolute: string): string[] => readdirSync(
    absolute,
    { withFileTypes: true },
  ).flatMap((entry) => {
    if (entry.isSymbolicLink()) return [];
    const path = join(absolute, entry.name);
    if (entry.isDirectory()) return visit(path);
    if (!entry.isFile() || !entry.name.endsWith(".test.ts")) return [];
    return [relative(repoRoot, path).split(sep).join("/")];
  });
  return visit(sourceRoot).sort();
}

function defensiveValidationFileText(text: string, path: string): string {
  const source = ts.createSourceFile(
    path,
    text,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const excluded: Array<readonly [number, number]> = [];
  const visit = (node: ts.Node): void => {
    if (ts.isTemplateExpression(node)) {
      excluded.push([node.getStart(source), node.end]);
      return;
    }
    if (ts.isStringLiteralLike(node)) {
      const parent = node.parent;
      const isTitle = ts.isCallExpression(parent)
        && isTestDeclarationCall(parent)
        && parent.arguments[0] === node;
      if (!isTitle) excluded.push([node.getStart(source), node.end]);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  if (excluded.length === 0) return text;
  const characters = text.split("");
  for (const [start, end] of excluded) {
    for (let index = start; index < end; index += 1) {
      if (characters[index] !== "\n" && characters[index] !== "\r") {
        characters[index] = " ";
      }
    }
  }
  return characters.join("");
}

/** Review every generator test declaration, excluding non-source dependency/build trees. */
export function lintDefensiveValidationRepositoryTests(
  repoRoot: string,
): DocsLintIssue[] {
  return generatorTestPaths(repoRoot).flatMap((path) => {
    const text = readFileSync(resolve(repoRoot, path), "utf8");
    return [
      ...lintDefensiveValidationText(defensiveValidationFileText(text, path), path),
      ...lintDefensiveValidationTestDeclarations(text, path),
    ];
  });
}

function lintDefensiveValidationReviews(
  repoRoot: string,
  contentOverrides: Readonly<Record<string, string>> = {},
): DocsLintIssue[] {
  const paths = [APPROVED_CLOSURE_PLAN_PATH];
  const issues: DocsLintIssue[] = [];
  const auditRepositoryReviews = Object.keys(contentOverrides).length === 0;
  if (auditRepositoryReviews) {
    issues.push(...lintDefensiveValidationRepositoryTests(repoRoot));
  }
  for (const path of paths) {
    if (!auditRepositoryReviews && !Object.hasOwn(contentOverrides, path)) continue;
    const text = contentOverrides[path]
      ?? (existsSync(resolve(repoRoot, path))
        ? readFileSync(resolve(repoRoot, path), "utf8")
        : undefined);
    if (text !== undefined) {
      issues.push(...lintDefensiveValidationText(text, path));
      if (path.endsWith(".test.ts")) {
        issues.push(...lintDefensiveValidationTestDeclarations(text, path));
      }
    }
  }
  for (const [path, text] of Object.entries(contentOverrides)) {
    if (paths.includes(path as (typeof paths)[number]) || !DEFENSIVE_REVIEW_PATH.test(path)) {
      continue;
    }
    issues.push(...lintDefensiveValidationText(text, path));
    if (path.endsWith(".test.ts")) {
      issues.push(...lintDefensiveValidationTestDeclarations(text, path));
    }
  }
  return issues;
}

// These patterns target affirmative live guidance, not historical or explicit
// retirement/optionality statements. Whitespace is intentionally flexible so
// Markdown wrapping cannot bypass the maintained-guide gate.
const CANONICAL_FEED_INDEX_SOURCE = "canonical[-\\s]+feed[-\\s]+index";
const CANONICAL_FEED_INDEX_PATTERN = new RegExp(CANONICAL_FEED_INDEX_SOURCE, "i");
const CANONICAL_SCOPE_PREFIX_SOURCE = "\\s*(?:[-+*]\\s+)?(?:(?:(?:for\\s+baseline\\s+conformance)|(?:(?:for|under|within)\\s+(?:(?:this|the|current)\\s+)?(?:protocol|specification|baseline)))\\s*,\\s*)?";
const CANONICAL_SCOPE_SUFFIX_SOURCE = "(?:\\s+(?:(?:by|in|under|within)\\s+(?:(?:this|the|current)\\s+)?(?:protocol|specification|baseline)|for\\s+baseline\\s+conformance))?";
const CANONICAL_PROVISION_VERBS = [
  "provide",
  "maintain",
  "preserve",
  "publish",
  "define",
  "implement",
  "include",
  "use",
  "retain",
] as const;
const CANONICAL_OMISSION_VERBS = [
  "omit",
  "remove",
  "exclude",
  "ignore",
  "drop",
] as const;
const CANONICAL_ONE_ADJUNCTS = [
  "although",
  "and",
  "as",
  "because",
  "before",
  "but",
  "by",
  "during",
  "for",
  "from",
  "if",
  "in",
  "into",
  "on",
  "since",
  "though",
  "to",
  "under",
  "unless",
  "until",
  "when",
  "where",
  "whereas",
  "while",
  "with",
  "without",
  "yet",
] as const;
const RETIRED_NOSTR_FIRST_GUIDE_PATTERNS = [
  /persona\s+is\s+(?:identified|anchored)\s+by\s+(?:a\s+)?cold[-\s]+root\s+(?:Nostr\s+)?npub/i,
  /every\s+persona\s+requires\s+(?:an\s+)?accepted\s+KEL(?:\s+and\s+(?:an\s+)?epoch\s+key)?/i,
  /(?:human\s+)?Marmot\s+account\s+is\s+separate\s+from\s+the\s+active\s+Nostr\s+key/i,
  /kind\s*:?\s*`?31005`?\s+is\s+required/i,
  /kind\s*:?\s*`?31007`?\s+is\s+required/i,
  CANONICAL_FEED_INDEX_PATTERN,
  /repository\s+copies?\s+take\s+precedence\s+over\s+(?:newer\s+)?relay\s+events?/i,
  /full\s+node\s+is\s+(?:a\s+)?required\s+(?:Nostr\s+)?relay/i,
  /(?:each|one)\s+group\s+has\s+one\s+canonical\s+trusted\s+seed/i,
  /caller\s+may\s+remove\s+agent\s+attribution\s+before\s+signing/i,
  /(?:automated\s+(?:agent\s+)?)?publication\s+(?:may|can|should|must)\s+(?:omit|remove)\s+(?:NIP[-\s]*32\s+)?(?:agent\s+)?attribution/i,
  /bare[-\s]+(?:active[-\s]+)?key(?:\s+persona)?\s+(?:is\s+)?(?:incomplete|insufficient)\s+without\s+Assurance/i,
  /bare[-\s]+(?:active[-\s]+)?key(?:\s+persona)?\s+does\s+not\s+satisfy\s+(?:baseline\s+)?conformance\s+unless\s+Assurance/i,
  /(?:rolling\s+)?vector[-\s]+snapshot\s+(?:defines\s+current[-\s]+draft\s+conformance|is\s+(?:the\s+)?(?:normative|authoritative)(?:\s+authority)?\s+for\s+(?:the\s+)?current[-\s]+draft)/i,
];

const UNSAFE_AGENT_SECURITY_FRAMING = [
  /agents?\s+may\s+test\s+live\s+(?:relays|nodes|deployments|identity providers|accounts|third-party systems)\s+without\s+authorization/i,
  /produce\s+(?:a\s+)?functional\s+exploit\s+payload\s+for\s+deployment/i,
  /use\s+real\s+credentials\s+and\s+scan\s+third-party\s+systems/i,
  /add\s+persistence\s*,\s*evasion\s*,\s*and\s+anti-forensics\s+to\s+the\s+proof/i,
  /agents?\s+(?:may|should|must)\s+(?:build|create|deploy)\s+(?:malware|shells?|phishing|command-and-control|C2)/i,
  /agents?\s+(?:may|should|must)\s+(?:perform|take)\s+destructive\s+actions?/i,
  /agents?\s+(?:may|should|must)\s+weaken\s+(?:security\s+)?controls?/i,
  /agents?\s+(?:may|should|must)\s+exploit\s+live\s+third[-\s]+party\s+(?:relays|nodes|deployments|identity providers|accounts|systems)/i,
];

const RETIRED_NORMATIVE_CLAIMS = [
  /require\s+a\s+`?valid`?\s+Core\/KEL\s+authority\s+result/i,
  /current\s+persona\s+epoch\s+or\s+cold-root\s+authority/i,
  /KEL\/key\s+revocation\s+(?:is\s+(?!not\b)|remains\s+(?!not\b)|wins\b)/i,
  /\b(?:may|can|MUST|SHOULD)\s+be\s+justified\s+by\s+a\s+KEL\s+alias/i,
  /(?<!no\s)epoch-key\s+NIP-59\s+inbox\s+exists/i,
  /temporary\s+private-repository\s+access\s+only\s+through\s+the\s+optional\s+recovery\s+grants/i,
  /optional\s+prepared\s+recovery\s+activation\s*,\s*finite\s+recovery\s+grants/i,
  /writers?\s+still\s+authenticate\s+against\s+current\s+Core\/KER[IL]\s+state/i,
  /Private-Radicle\s+recovery\s+and\s+SFTP\s+overflow\s+are\s+optional\s+Control\s+profiles/i,
];

const RETIRED_BASELINE_AUTHORITY_CLAIMS = [
  /(?:conformant\s+)?personas?\s+(?:(?:MUST\s+(?:have|use)|requires?)|does\s+not\s+require)\s+(?:an?\s+)?(?:accepted\s+)?(?:KEL|cold[-\s]+root|epoch[-\s]+key)/i,
];

function isExplicitlyGatedAssurance(
  path: string,
  text: string,
  matchIndex: number,
): boolean {
  if (/(?:^|\/)heterodyne-assurance\.md$/.test(path)) return true;
  const { start } = assertionClauseBounds(text, matchIndex);
  const prefix = text.slice(start, matchIndex).replace(/\s+/gu, " ");
  // In a non-Assurance document, gating must grammatically introduce this
  // exact subject. Merely mentioning Assurance earlier in the sentence does
  // not exempt a later baseline assertion.
  return /\b(?:when\s+(?:optional\s+)?Assurance\s+is\s+claimed|implementations?\s+claiming\s+Assurance|for\s+(?:the\s+)?optional\s+Assurance\s+(?:profile|composition)|in\s+an?\s+optional\s+Assurance\s+(?:profile|composition))\s*,\s*(?:an?\s+)?$/i
    .test(prefix);
}

function assertionClauseBounds(
  text: string,
  matchIndex: number,
): { start: number; end: number } {
  const prior = text.slice(0, matchIndex);
  let boundary = Math.max(
    prior.lastIndexOf("."),
    prior.lastIndexOf("!"),
    prior.lastIndexOf("?"),
    prior.lastIndexOf(";"),
  );
  for (const coordinator of prior.matchAll(
    /(?:,\s*(?:and|but|yet|while|whereas)|\s+(?:but|yet|while|whereas))\s+/giu,
  )) {
    boundary = Math.max(boundary, coordinator.index + coordinator[0].length - 1);
  }
  const remainder = text.slice(matchIndex);
  const punctuationBoundary = remainder.search(/[.!?;]/u);
  const coordinatorBoundary = remainder.search(
    /(?:,\s*(?:and|but|yet|while|whereas)|\s+(?:but|yet|while|whereas))\s+/iu,
  );
  const followingBoundary = punctuationBoundary < 0
    ? coordinatorBoundary
    : coordinatorBoundary < 0
      ? punctuationBoundary
      : Math.min(punctuationBoundary, coordinatorBoundary);
  const end = followingBoundary < 0
    ? text.length
    : matchIndex + followingBoundary + 1;
  return { start: boundary + 1, end };
}

function isPredicateLocallyRetired(
  text: string,
  matchIndex: number,
  matchLength: number,
): boolean {
  const { start, end } = assertionClauseBounds(text, matchIndex);
  const assertion = text.slice(start, end);
  const matched = text.slice(matchIndex, matchIndex + matchLength);
  const localIndex = matchIndex - start;
  if (localIndex < 0 || localIndex + matchLength > assertion.length) return false;
  const before = assertion.slice(0, localIndex).replace(/\s+/gu, " ");
  const after = assertion.slice(localIndex + matched.length).replace(/\s+/gu, " ");

  // Only polarity attached immediately to the matched subject can retire it.
  // A later MUST NOT, a relative "that is not ...", or negative optionality
  // therefore cannot suppress an affirmative retired predicate.
  const directlyNegativeSubject = /(?:^(?:\s*[-+*]\s+)?|[,:;(]\s*|\bthere\s+(?:is|are)\s+)no\s+(?:(?:an?|the|baseline|current)\s+)?$/i
    .test(before)
    || /\bnever\s+(?:an?\s+|the\s+)?$/i.test(before);
  const directlyNegativePredicate = /(?:conformant\s+)?personas?\s+does\s+not\s+require\s+(?:an?\s+)?(?:accepted\s+)?(?:KEL|cold[-\s]+root|epoch[-\s]+key)$/i
    .test(matched.replace(/\s+/gu, " "));
  const directlyRetiredPredicate = /^\s+(?:is|are|was|were|has\s+been)\s+(?:retired|deprecated|withdrawn|not\s+(?:required|valid(?:\s+authority)?|current(?:\s+authority)?|authoritative|normative)|no\s+longer\s+(?:required|valid(?:\s+authority)?|current(?:\s+authority)?|authoritative|normative))\b/i
    .test(after);
  return directlyNegativeSubject || directlyNegativePredicate || directlyRetiredPredicate;
}

const MAX_MARKDOWN_FILE_BYTES = 512 * 1024;
const MAX_MARKDOWN_CORPUS_BYTES = 2 * 1024 * 1024;
const MAX_MARKDOWN_AST_DEPTH = 64;
const MAX_MARKDOWN_AST_NODES = 50_000;

type VisibleMarkdownBlock = {
  line: number;
  text: string;
};

type MarkdownAnalysis = {
  blocks: readonly VisibleMarkdownBlock[];
  maxDepth: number;
  nodeCount: number;
};

const markdownParser = new Parser();

function visibleInlineText(block: CommonmarkNode): string {
  const visible: string[] = [];
  const stack: CommonmarkNode[] = [];
  const pushChildren = (node: CommonmarkNode): void => {
    const children: CommonmarkNode[] = [];
    for (let child = node.firstChild; child !== null; child = child.next) {
      children.push(child);
    }
    stack.push(...children.reverse());
  };
  pushChildren(block);
  while (stack.length > 0) {
    const node = stack.pop()!;
    switch (node.type) {
      case "text":
        visible.push(node.literal ?? "");
        break;
      case "softbreak":
      case "linebreak":
        visible.push(" ");
        break;
      case "emph":
      case "strong":
      case "link":
        pushChildren(node);
        break;
      case "code":
      case "html_inline":
      case "image":
        visible.push(" ");
        break;
      default:
        visible.push(" ");
        break;
    }
  }
  return visible.join("").replace(/\s+/gu, " ").trim();
}

function analyzeMarkdown(text: string): MarkdownAnalysis {
  const root = markdownParser.parse(text);
  const blockNodes: CommonmarkNode[] = [];
  let maxDepth = 0;
  let nodeCount = 0;
  const stack: { node: CommonmarkNode; depth: number }[] = [{ node: root, depth: 1 }];
  while (stack.length > 0) {
    const { node, depth } = stack.pop()!;
    nodeCount += 1;
    if (nodeCount > MAX_MARKDOWN_AST_NODES) {
      return { blocks: [], maxDepth, nodeCount };
    }
    if (depth > MAX_MARKDOWN_AST_DEPTH) {
      return { blocks: [], maxDepth: depth, nodeCount };
    }
    maxDepth = Math.max(maxDepth, depth);
    if (node.type === "paragraph" || node.type === "heading") {
      blockNodes.push(node);
    }
    const children: CommonmarkNode[] = [];
    for (let child = node.firstChild; child !== null; child = child.next) {
      children.push(child);
    }
    for (const child of children.reverse()) {
      stack.push({ node: child, depth: depth + 1 });
    }
  }
  const blocks = blockNodes.map((node) => ({
    line: node.sourcepos[0][0],
    text: visibleInlineText(node),
  }));
  return { blocks, maxDepth, nodeCount };
}

function normalizeVisibleMarkdown(text: string): string {
  return text.replace(/\s+/gu, " ");
}

function isCanonicalFeedIndexLocallyRetired(
  text: string,
  matchIndex: number,
  matchLength: number,
): boolean {
  const { start, end } = assertionClauseBounds(text, matchIndex);
  const before = normalizeVisibleMarkdown(text.slice(start, matchIndex));
  const after = normalizeVisibleMarkdown(text.slice(matchIndex + matchLength, end));
  const directlyNegativeSubject = new RegExp(
    `^${CANONICAL_SCOPE_PREFIX_SOURCE}(?:no|there\\s+(?:is|are)\\s+no)\\s+$`,
    "i",
  ).test(before);
  const negativeExistenceOrRequirement = new RegExp(
    `^\\s*(?:(?:exists?|(?:is|are)\\s+required)${CANONICAL_SCOPE_SUFFIX_SOURCE}\\s*)?(?:[.!?;]|$)$`,
    "i",
  ).test(after);
  const directlyNegativeDefinition = new RegExp(
    `^${CANONICAL_SCOPE_PREFIX_SOURCE}(?:the\\s+)?(?:protocol|specification|baseline)\\s+(?:does|do)\\s+not\\s+(?:define|require|specify)\\s+(?:an?\\s+|the\\s+)?$`,
    "i",
  ).test(before);
  const negativeDefinition = new RegExp(
    `^${CANONICAL_SCOPE_SUFFIX_SOURCE}\\s*(?:[.!?;]|$)$`,
    "i",
  ).test(after);
  const directlyRetiredSubject = new RegExp(
    `^${CANONICAL_SCOPE_PREFIX_SOURCE}(?:an?|the)?\\s*$`,
    "i",
  ).test(before);
  const directlyRetiredPredicate = new RegExp(
    `^\\s+(?:is|are|was|were|has\\s+been)\\s+(?:retired|deprecated|withdrawn|not\\s+(?:required|valid(?:\\s+authority)?|current(?:\\s+authority)?|authoritative|normative)|no\\s+longer\\s+(?:required|valid(?:\\s+authority)?|current(?:\\s+authority)?|authoritative|normative))${CANONICAL_SCOPE_SUFFIX_SOURCE}\\s*(?:[.!?;]|$)$`,
    "i",
  ).test(after);
  const localClauseRetires = (directlyNegativeSubject && negativeExistenceOrRequirement)
    || (directlyNegativeDefinition && negativeDefinition)
    || (directlyRetiredSubject && directlyRetiredPredicate);
  if (!localClauseRetires) return false;

  const preceding = text.slice(0, start);
  const sentenceStart = Math.max(
    preceding.lastIndexOf("."),
    preceding.lastIndexOf("!"),
    preceding.lastIndexOf("?"),
  ) + 1;
  const following = text.slice(end);
  const terminator = following.search(/[.!?](?:\s|$)/u);
  const sentenceEnd = terminator < 0 ? text.length : end + terminator + 1;
  const otherClauses = normalizeVisibleMarkdown(
    `${text.slice(sentenceStart, matchIndex)} ${text.slice(end, sentenceEnd)}`,
  );
  const canonicalReference = `(?<!\\[)${CANONICAL_FEED_INDEX_SOURCE}\\b(?!\\])`;
  const oneAdjunct = CANONICAL_ONE_ADJUNCTS.join("|");
  const objectReference = `(?:${canonicalReference}|(?<!\\[)it\\b(?!\\])|(?<!\\[)one\\b(?!\\])(?=\\s*(?:\`+\\s*)?(?:[.;!?)]|,\\s*(?:${oneAdjunct})\\b|(?:${oneAdjunct})\\b|$)))`;
  const subjectReference = `(?:${canonicalReference}|(?<!\\[)(?:one|it)\\b(?!\\]))`;
  const provisionVerb = CANONICAL_PROVISION_VERBS.join("|");
  const requiredByOperator = new RegExp(
    `(?<!\\[)\\b(?:MUST|SHALL|(?:is|are)\\s+required\\s+to)(?!\\])\\s+(?:still\\s+)?(?:${provisionVerb})\\s+(?:(?:an?|the)\\s+)?${objectReference}`,
    "i",
  );
  const requiredAsSubject = new RegExp(
    `\\b${subjectReference}\\s+(?:(?:MUST|SHALL)\\s+(?:still\\s+)?(?:exist|be\\s+(?:provided|required|maintained|published|defined|included|used|retained))|(?:is|remains)\\s+(?:still\\s+)?required)\\b`,
    "i",
  );
  const omissionVerb = CANONICAL_OMISSION_VERBS.join("|");
  const prohibitedOmission = new RegExp(
    `(?<!\\[)\\b(?:MUST|SHALL)(?!\\])\\s+NOT\\s+(?:${omissionVerb})\\s+(?:(?:an?|the)\\s+)?${objectReference}`,
    "i",
  );
  return !(
    requiredByOperator.test(otherClauses)
    || requiredAsSubject.test(otherClauses)
    || prohibitedOmission.test(otherClauses)
  );
}

function allPatternMatches(pattern: RegExp, text: string): RegExpExecArray[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return [...text.matchAll(new RegExp(pattern.source, flags))];
}

export function findRetiredNormativeClaimIssues(
  path: string,
  text: string,
): FamilyDocIssue[] {
  const retired = RETIRED_NORMATIVE_CLAIMS.flatMap((pattern) => {
    return allPatternMatches(pattern, text).flatMap((match) =>
      isPredicateLocallyRetired(text, match.index, match[0].length) ? [] : [{
      path,
      line: text.slice(0, match.index).split(/\r?\n/).length,
      code: "retired-authoring-model" as const,
      message: `retired normative authority: ${match[0]}`,
      }]);
  });
  const baselineAuthority = RETIRED_BASELINE_AUTHORITY_CLAIMS.flatMap((pattern) => {
    return allPatternMatches(pattern, text).flatMap((match) =>
      isPredicateLocallyRetired(text, match.index, match[0].length)
      || isExplicitlyGatedAssurance(path, text, match.index) ? [] : [{
      path,
      line: text.slice(0, match.index).split(/\r?\n/).length,
      code: "retired-authoring-model" as const,
      message: `retired baseline authority: ${match[0]}`,
      }]);
  });
  return [...retired, ...baselineAuthority];
}

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

function anchorInventory(
  documents: readonly FamilyDocument[],
): ReadonlyMap<DocumentId, ReadonlySet<string>> {
  const inventory = new Map<DocumentId, ReadonlySet<string>>();
  for (const document of documents) {
    const anchors = new Set<string>();
    for (const line of document.lines) {
      for (const match of line.matchAll(EXPLICIT_ANCHOR)) anchors.add(match[1]);
    }
    inventory.set(document.document, anchors);
  }
  return inventory;
}

/** Explicit live specification anchors keyed by their owning family document. */
export function loadFamilyAnchorInventory(
  repoRoot: string,
): ReadonlyMap<DocumentId, ReadonlySet<string>> {
  return anchorInventory(loadFamilyDocuments(repoRoot));
}

type VersionQualifierSurface = {
  path: string;
  text: string;
};

// Mirror the current compiler lane: tests and generator-owned historical
// authoring/snapshot sources must not turn preserved 0.5 evidence into lint.
const HISTORICAL_GENERATOR_SOURCE_PREFIXES = [
  "kel",
  "keri-",
  "legacy-",
  "snapshot",
  "topics",
] as const;
const HISTORICAL_GENERATOR_SOURCE_NAMES = new Set([
  "author.ts",
  "cli.ts",
  "coverage.ts",
  "verify.ts",
]);
const SNAPSHOT_TRANSITION_PATH = "docs/spec/heterodyne.md";
const SNAPSHOT_TRANSITION_HEADING = "## Live validation and frozen history";

function isCurrentGeneratorSource(file: string): boolean {
  return file.endsWith(".ts")
    && !file.endsWith(".test.ts")
    && !HISTORICAL_GENERATOR_SOURCE_NAMES.has(file)
    && !HISTORICAL_GENERATOR_SOURCE_PREFIXES.some((prefix) => file.startsWith(prefix));
}

function isIntentionalSnapshotTransitionQualifier(
  path: string,
  text: string,
  offset: number,
): boolean {
  if (path !== SNAPSHOT_TRANSITION_PATH) return false;
  const start = text.indexOf(SNAPSHOT_TRANSITION_HEADING);
  if (start < 0) return false;
  const nextHeading = text.indexOf("\n## ", start + SNAPSHOT_TRANSITION_HEADING.length);
  return offset >= start && (nextHeading < 0 || offset < nextHeading);
}

function loadVersionQualifierSurfaces(
  repoRoot: string,
  documents: readonly FamilyDocument[],
): VersionQualifierSurface[] {
  const surfaces = documents.map(({ displayPath: path, lines }) => ({
    path,
    text: lines.join("\n"),
  }));
  const overviewPath = resolve(repoRoot, SNAPSHOT_TRANSITION_PATH);
  if (existsSync(overviewPath)) {
    surfaces.push({
      path: SNAPSHOT_TRANSITION_PATH,
      text: readFileSync(overviewPath, "utf8"),
    });
  }
  const sourceDirectory = resolve(repoRoot, "docs/spec/vectors/generator/src");
  if (!existsSync(sourceDirectory)) return surfaces;
  for (const entry of readdirSync(sourceDirectory, { withFileTypes: true })) {
    if (!entry.isFile() || !isCurrentGeneratorSource(entry.name)) continue;
    const absolutePath = resolve(sourceDirectory, entry.name);
    surfaces.push({
      path: displayPath(repoRoot, absolutePath),
      text: readFileSync(absolutePath, "utf8"),
    });
  }
  return surfaces;
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
  issues.push(...lintDefensiveValidationReviews(repoRoot));
  const anchors = new Map<string, { path: string; line: number }>();
  const documentAnchors = new Set(
    [...anchorInventory(documents)].flatMap(([document, documentValues]) =>
      [...documentValues].map((anchor) => `${document}:${anchor}`)
    ),
  );
  const sections = new Map<DocumentId, Set<string>>();
  const anchorOwner = new Map<string, DocumentId>();

  for (const document of documents) {
    sections.set(
      document.document,
      new Set(
        document.lines.flatMap((line) => NUMBERED_HEADING.exec(line)?.[1] ?? []),
      ),
    );
    for (const [index, line] of document.lines.entries()) {
      for (const match of line.matchAll(EXPLICIT_ANCHOR)) {
        const anchor = match[1];
        anchorOwner.set(anchor, document.document);
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

  const registry = loadRegistry(repoRoot);
  const registeredFeatures = new Set(registry.features.map(({ id }) => id));
  const registeredProofDomains = new Set(
    registry.proof_domains.map(({ id }) => id),
  );

  for (const document of documents) {
    issues.push(...findRetiredNormativeClaimIssues(
      document.displayPath,
      document.lines.join("\n"),
    ));
  }

  for (const { path, text } of loadVersionQualifierSurfaces(repoRoot, documents)) {
    for (const match of text.matchAll(STALE_BARE_FAMILY_VERSION)) {
      if (isIntentionalSnapshotTransitionQualifier(path, text, match.index)) continue;
      issues.push({
        path,
        line: text.slice(0, match.index).split(/\r?\n/).length,
        code: "stale-family-version",
        message: `${match[0]} is not the current family version ${FAMILY_VERSION}`,
      });
    }
  }

  for (const document of documents) {
    const normativeLines = normativeParagraphLines(document.lines);
    for (const [index, line] of document.lines.entries()) {
      const lineNumber = index + 1;
      const references = [...line.matchAll(QUALIFIED_REFERENCE)];

      if (NONCANONICAL_DECISION_REFERENCE.test(line)) {
        issues.push({
          path: document.displayPath,
          line: lineNumber,
          code: "noncanonical-decision-reference",
          message:
            "live specifications must express requirements without depending on ADRs",
        });
      }

      for (const match of references) {
        const version = match[1];
        const anchor = match[2];
        // The anchor prefix names its owning document, so one qualified
        // reference form resolves and layer-checks without a per-document
        // version to carry the owner.
        const target = anchor.split("-", 1)[0] as DocumentId;
        if (version !== FAMILY_VERSION) {
          issues.push({
            path: document.displayPath,
            line: lineNumber,
            code: "unresolved-reference",
            message: `${match[0]} is not the current family version ${QUALIFIED_VERSION}`,
          });
          continue;
        }
        if (!documentAnchors.has(`${target}:${anchor}`)) {
          issues.push({
            path: document.displayPath,
            line: lineNumber,
            code: "unresolved-reference",
            message: `${match[0]} does not resolve to an explicit family anchor`,
          });
          continue;
        }
        if (
          normativeLines.has(index) &&
          target !== document.document
        ) {
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

      // The registry is the sole feature-ID authority; prose that invents
      // an ID reads as a real capability claim and nothing else catches it.
      for (const match of line.matchAll(FEATURE_ID)) {
        if (!registeredFeatures.has(match[1])) {
          issues.push({
            path: document.displayPath,
            line: lineNumber,
            code: "unregistered-feature-id",
            message: `${match[1]} is not allocated in registry/features.json`,
          });
        }
      }

      // Section numbers are a second naming scheme over the same headings;
      // without this they rot silently whenever a document is renumbered.
      for (const match of line.matchAll(SECTION_REFERENCE)) {
        if (!sections.get(document.document)?.has(match[1])) {
          issues.push({
            path: document.displayPath,
            line: lineNumber,
            code: "unresolved-section-reference",
            message: `${match[0]} is not a heading in ${document.document}`,
          });
        }
      }

      // The link text carries the version and the target carries the file;
      // a mismatch between them is a reference that resolves to the wrong
      // section while still reading as correct.
      for (const match of line.matchAll(LINKED_QUALIFIED_REFERENCE)) {
        const [, textAnchor, targetFile, targetAnchor] = match;
        const expectedFile = anchorOwner.get(textAnchor);
        if (textAnchor !== targetAnchor) {
          issues.push({
            path: document.displayPath,
            line: lineNumber,
            code: "mislinked-reference",
            message: `link text names ${textAnchor} but targets ${targetAnchor}`,
          });
        } else if (expectedFile !== undefined
          && (targetFile ?? document.document) !== expectedFile) {
          issues.push({
            path: document.displayPath,
            line: lineNumber,
            code: "mislinked-reference",
            message: `${textAnchor} is owned by ${expectedFile}, not ${targetFile ?? document.document}`,
          });
        }
      }

      // An unqualified cross-document link drops the version.
      const withoutQualified = line.replace(LINKED_QUALIFIED_REFERENCE, "");
      const crossesDocuments = CROSS_DOCUMENT_LINK.test(withoutQualified)
        || [...withoutQualified.matchAll(LOCAL_ANCHOR_LINK)].some(
          ([, anchor]) => (anchorOwner.get(anchor) ?? document.document) !== document.document,
        );
      if (normativeLines.has(index) && crossesDocuments) {
        issues.push({
          path: document.displayPath,
          line: lineNumber,
          code: "bare-normative-link",
          message:
            "a normative cross-document reference must be [`heterodyne:<version>#<anchor>`](<file>#<anchor>)",
        });
      }
    }
  }

  const core = documents.find(({ document }) => document === "core");
  if (core?.lines.some((line) => /core\.repo-relay-(?:server|storage)\./.test(line))) {
    issues.push({ path: core.displayPath, line: 1, code: "generic-repo-relay-server-claim", message: "Core defines no generic repo-relay server/storage feature" });
  }
  const comms = documents.find(({ document }) => document === "comms");
  if (comms !== undefined) {
    const wireStart = comms.lines.findIndex((line) => line.includes('<a id="comms-audience-keys"'));
    const wireEnd = comms.lines.findIndex((line, index) => index > wireStart && line.includes('<a id="comms-tier-three-profile"'));
    const wire = comms.lines.slice(wireStart, wireEnd).join("\n");
    if (/<recipient npub>|recipient's npub/.test(wire)) {
      issues.push({ path: comms.displayPath, line: wireStart + 1, code: "ambiguous-nostr-wire-key", message: "Tier 3 wire keys must use lowercase 64-hex rather than npub" });
    }
    if (/\bregistry_revision\b/.test(comms.lines.join("\n"))) {
      issues.push({ path: comms.displayPath, line: 1, code: "claim-profile-revision-ambiguous", message: "the frozen claim-profile revision must be named profile_revision, distinct from the registry pin" });
    }
  }
  for (const kind of [1059, 22242]) {
    if (!registry.kinds.some((entry) => entry.kind === kind && entry.allocation_authority === "nostr")) {
      issues.push({ path: "docs/spec/registry/kinds.json", line: 1, code: "missing-upstream-kind-allocation", message: `missing upstream kind ${kind}` });
    }
  }
  for (const message of verifyMarmotArchive(resolve(repoRoot, "docs/spec/external/marmot"))) {
    issues.push({ path: "docs/spec/external/marmot/manifest.json", line: 1, code: "marmot-archive-invalid", message });
  }
  // Core's capability example pastes the manifest digest; nothing else
  // reconciles the two, so a registry regeneration desyncs it silently.
  if (core !== undefined) {
    for (const [index, line] of core.lines.entries()) {
      const pasted = /"registry_sha256"\s*:\s*"([0-9a-f]{64})"/.exec(line)?.[1];
      if (pasted !== undefined && pasted !== registry.manifest.entry_set_sha256) {
        issues.push({
          path: core.displayPath,
          line: index + 1,
          code: "registry-digest-drift",
          message: `registry_sha256 does not match registry/manifest.json entry_set_sha256`,
        });
      }
    }
  }

  // A proof domain names exact signed bytes; an unallocated one has no
  // bound-member declaration for an implementer to sign against, and an
  // allocated one nothing specifies is bytes nobody can produce. The citation
  // routinely wraps, so scan joined text and recover the line from the offset.
  const citedProofDomains = new Set<string>();
  for (const document of documents) {
    const text = document.lines.join("\n");
    for (const pattern of [PROOF_DOMAIN, PROOF_DOMAIN_FENCED]) {
      for (const match of text.matchAll(pattern)) {
        citedProofDomains.add(match[1]);
        if (registeredProofDomains.has(match[1])) continue;
        issues.push({
          path: document.displayPath,
          line: text.slice(0, match.index).split("\n").length,
          code: "unregistered-proof-domain",
          message: `${match[1]} is not allocated in registry/proof-domains.json`,
        });
      }
    }
  }
  for (const entry of registry.proof_domains) {
    if (!citedProofDomains.has(entry.id)) {
      issues.push({
        path: "docs/spec/registry/proof-domains.json",
        line: 1,
        code: "unregistered-proof-domain",
        message: `${entry.id} is allocated but no document specifies its bytes`,
      });
    }
  }

  const strictProfileIssues = findStrictProfileClosureIssues(
    Object.fromEntries(documents.map(({ document, lines }) => [document, lines.join("\n")])),
    registry.security_invariants,
  );
  for (const message of strictProfileIssues) {
    issues.push({ path: "docs/spec/heterodyne-core.md", line: 1, code: "strict-profile-closure-invalid", message });
  }

  return issues;
}


function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, member]) => `${JSON.stringify(key)}:${canonicalJson(member)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function parseInvariantRows(text: string): Map<string, string> {
  return new Map(
    [...text.matchAll(
      /^- \*\*((?:CORE|ASSURANCE|COMMS|CONTROL|SOCIAL|WORKSPACE)-I-[A-Z0-9]+(?:-[A-Z0-9]+)*):\*\* ([^\r\n]+)$/gm,
    )].map((match) => [match[1], match[2]]),
  );
}

export function findInvariantEvidenceIssues(
  invariants: readonly { id: string; description: string }[],
  threatModel: string,
): string[] {
  const threatRows = parseInvariantRows(threatModel);
  const registered = new Map(invariants.map(({ id, description }) => [id, description]));
  const issues: string[] = [];

  for (const id of CLAIMS_OIDC_INVARIANT_IDS) {
    if (!registered.has(id)) issues.push(`claims/OIDC invariant not registered: ${id}`);
  }
  for (const { id, description } of invariants) {
    if (threatRows.get(id) !== description) {
      issues.push(`missing invariant evidence: ${id}`);
    }
  }
  return issues.sort();
}

type StrictProfileFixture = {
  profile_id: string;
  requires_profiles: string[];
  adds_invariants: string[];
};

export function findStrictProfileClosureIssues(
  documents: Record<string, string>,
  registeredInvariants?: readonly { id: string; owner: DocumentId; feature?: string }[],
): string[] {
  const profiles = new Map<string, StrictProfileFixture>();
  const issues: string[] = [];
  const fixturePattern = /<!-- fixture:[^>]*strict-profile[^>]* -->\s*```json\s*([\s\S]*?)\s*```/g;
  for (const [document, text] of Object.entries(documents)) {
    for (const match of text.matchAll(fixturePattern)) {
      let profile: StrictProfileFixture;
      try {
        profile = JSON.parse(match[1]) as StrictProfileFixture;
      } catch {
        issues.push(`invalid strict-profile fixture JSON: ${document}`);
        continue;
      }
      const prior = profiles.get(profile.profile_id);
      if (prior !== undefined && canonicalJson(prior) !== canonicalJson(profile)) {
        issues.push(`conflicting strict-profile declaration: ${profile.profile_id}`);
        continue;
      }
      if (new Set(profile.adds_invariants).size !== profile.adds_invariants.length) {
        issues.push(`duplicate added invariant: ${profile.profile_id}`);
      }
      profiles.set(profile.profile_id, profile);
    }
  }

  // The required set is the transitive closure of prerequisites plus the
  // profile's own additions; nothing restates a flattened list.
  const closures = new Map<string, Set<string>>();
  const visiting = new Set<string>();
  const closureOf = (id: string): Set<string> => {
    const cached = closures.get(id);
    if (cached !== undefined) return cached;
    if (visiting.has(id)) {
      issues.push(`strict-profile prerequisite cycle: ${id}`);
      return new Set();
    }
    visiting.add(id);
    const profile = profiles.get(id);
    const required = new Set<string>();
    for (const prerequisiteId of profile?.requires_profiles ?? []) {
      if (!profiles.has(prerequisiteId)) {
        issues.push(`unknown strict-profile prerequisite: ${id} -> ${prerequisiteId}`);
        continue;
      }
      for (const invariant of closureOf(prerequisiteId)) required.add(invariant);
    }
    for (const invariant of profile?.adds_invariants ?? []) {
      if (required.has(invariant)) {
        issues.push(`redundant added invariant: ${id} already inherits ${invariant}`);
      }
      required.add(invariant);
    }
    visiting.delete(id);
    closures.set(id, required);
    return required;
  };

  const registered = new Map(
    (registeredInvariants ?? []).map((entry) => [entry.id, entry]),
  );
  for (const profile of profiles.values()) {
    closureOf(profile.profile_id);
    if (registeredInvariants === undefined) continue;
    const declaringOwner = /^heterodyne-([a-z]+)-strict-/.exec(profile.profile_id)?.[1];
    for (const invariant of profile.adds_invariants) {
      const entry = registered.get(invariant);
      if (entry === undefined) {
        issues.push(`unregistered added invariant: ${profile.profile_id} -> ${invariant}`);
      } else if (entry.owner !== declaringOwner) {
        issues.push(
          `added invariant is not owned by the declaring document: ${profile.profile_id} -> ${invariant}`,
        );
      } else if (entry.feature !== undefined) {
        // A feature-bound invariant is owed whenever its feature is claimed, so
        // adding it to a profile would make the profile require the feature.
        issues.push(
          `feature-bound added invariant: ${profile.profile_id} -> ${invariant} is bound to ${entry.feature}`,
        );
      }
    }
  }
  return issues.sort();
}

type SnapshotGuidanceArtifact = {
  path: string;
  sha256: string;
};

type SnapshotGuidanceManifest = {
  snapshot_schema: "1";
  source_commit: string;
  vector_schema_version: string;
  vector_count: number;
  artifacts: SnapshotGuidanceArtifact[];
  owner_documents: string[];
};

const SNAPSHOT_MANIFEST_PATH = "docs/spec/vectors/snapshot.json";
const SNAPSHOT_VECTOR_ROOT = "docs/spec/vectors";
const SNAPSHOT_FULL_COMMIT = /^[0-9a-f]{40}$/u;
const SNAPSHOT_SHA256 = /^[0-9a-f]{64}$/u;
const SNAPSHOT_SEMVER = /^\d+\.\d+\.\d+$/u;
const SNAPSHOT_SAFE_PATH = /^[A-Za-z0-9._/-]+$/u;
const SNAPSHOT_SUPPORT_PATHS = [
  "fixtures.json",
  "schema/vector.schema.json",
  "schema/reason-codes.json",
  "schema/reason-codes.md",
  "coverage/manifest.json",
  "coverage/core.md",
  "coverage/comms.md",
  "coverage/control.md",
  "coverage/social.md",
  "coverage/workspace.md",
  "coverage/family.md",
] as const;
const SNAPSHOT_OPTIONAL_ASSURANCE_COVERAGE = "coverage/assurance.md";
const SNAPSHOT_EXCLUDED_DIRECTORIES = new Set(["coverage", "generator", "schema"]);
const SNAPSHOT_EXCLUDED_FILES = new Set([
  "fixtures.json",
  "snapshot.json",
  "snapshot.meta.schema.json",
  "snapshot.schema.json",
  "snapshot-unique-by-path.meta.schema.json",
]);

function snapshotGuidanceRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function snapshotGuidanceExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  for (const key of keys) {
    if (!Object.hasOwn(value, key)) throw new Error(`${label} missing property: ${key}`);
  }
  for (const key of Object.keys(value)) {
    if (!keys.includes(key)) throw new Error(`${label} has unexpected property: ${key}`);
  }
}

function snapshotGuidanceSafePath(path: string): boolean {
  return SNAPSHOT_SAFE_PATH.test(path)
    && path.startsWith(`${SNAPSHOT_VECTOR_ROOT}/`)
    && !path.includes("//")
    && path.split("/").every((segment) =>
      segment !== "" && segment !== "." && segment !== ".."
    );
}

function parseSnapshotGuidanceManifest(value: unknown): Omit<SnapshotGuidanceManifest, "owner_documents"> {
  if (!snapshotGuidanceRecord(value)) throw new Error("snapshot manifest must be an object");
  snapshotGuidanceExactKeys(
    value,
    ["snapshot_schema", "source_commit", "vector_schema_version", "vector_count", "artifacts"],
    "snapshot manifest",
  );
  if (value.snapshot_schema !== "1") throw new Error("snapshot schema must be 1");
  if (typeof value.source_commit !== "string" || !SNAPSHOT_FULL_COMMIT.test(value.source_commit)) {
    throw new Error("snapshot source commit must be 40-lowercase-hex");
  }
  if (typeof value.vector_schema_version !== "string"
    || !SNAPSHOT_SEMVER.test(value.vector_schema_version)) {
    throw new Error("snapshot vector schema version must be semantic version syntax");
  }
  if (!Number.isSafeInteger(value.vector_count) || (value.vector_count as number) < 0) {
    throw new Error("snapshot vector count must be a non-negative safe integer");
  }
  if (!Array.isArray(value.artifacts)) throw new Error("snapshot artifacts must be an array");
  const seen = new Set<string>();
  const artifacts = value.artifacts.map((entry, index): SnapshotGuidanceArtifact => {
    if (!snapshotGuidanceRecord(entry)) {
      throw new Error(`snapshot artifact ${index} must be an object`);
    }
    snapshotGuidanceExactKeys(entry, ["path", "sha256"], `snapshot artifact ${index}`);
    if (typeof entry.path !== "string" || !snapshotGuidanceSafePath(entry.path)) {
      throw new Error(`unsafe artifact path: ${String(entry.path)}`);
    }
    if (seen.has(entry.path)) throw new Error(`duplicate artifact path: ${entry.path}`);
    seen.add(entry.path);
    if (typeof entry.sha256 !== "string" || !SNAPSHOT_SHA256.test(entry.sha256)) {
      throw new Error(`invalid artifact digest: ${entry.path}`);
    }
    return { path: entry.path, sha256: entry.sha256 };
  });
  if (artifacts.some((entry, index) => index > 0 && artifacts[index - 1]!.path >= entry.path)) {
    throw new Error("snapshot artifact paths must be unique and strictly sorted");
  }
  return {
    snapshot_schema: "1",
    source_commit: value.source_commit,
    vector_schema_version: value.vector_schema_version,
    vector_count: value.vector_count as number,
    artifacts,
  };
}

function snapshotGuidanceBytes(repoRoot: string, path: string): Buffer {
  const repositoryRoot = resolve(repoRoot);
  const rootStatus = lstatSync(repositoryRoot);
  if (rootStatus.isSymbolicLink() || !rootStatus.isDirectory()) {
    throw new Error("snapshot repository root must be a non-symbolic-link directory");
  }
  const rootRealPath = realpathSync(repositoryRoot);
  let current = repositoryRoot;
  for (const [index, segment] of path.split("/").entries()) {
    current = join(current, segment);
    const status = lstatSync(current);
    if (status.isSymbolicLink()) throw new Error(`snapshot path must not be a symbolic link: ${path}`);
    const final = index === path.split("/").length - 1;
    if (final ? !status.isFile() : !status.isDirectory()) {
      throw new Error(
        final
          ? `snapshot artifact must be a regular file: ${path}`
          : `snapshot artifact parent must be a directory: ${path}`,
      );
    }
  }
  const realPath = realpathSync(current);
  const relativePath = relative(rootRealPath, realPath);
  if (relativePath === ".." || relativePath.startsWith(`..${sep}`) || realPath === rootRealPath) {
    throw new Error(`snapshot artifact escapes repository root: ${path}`);
  }
  return readFileSync(realPath);
}

function snapshotGuidanceJson(bytes: Buffer, label: string): unknown {
  try {
    return JSON.parse(bytes.toString("utf8")) as unknown;
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function snapshotGuidanceVectorPaths(vectorRoot: string): string[] {
  const nestedJsonPaths = (root: string, current: string): string[] =>
    readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
      const absolute = join(current, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`snapshot path must not be a symbolic link: ${entry.name}`);
      }
      if (entry.isDirectory()) return nestedJsonPaths(root, absolute);
      if (!entry.isFile() || !entry.name.endsWith(".json")) return [];
      return [`${SNAPSHOT_VECTOR_ROOT}/${relative(root, absolute).split(sep).join("/")}`];
    });
  return readdirSync(vectorRoot, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isSymbolicLink()) {
      throw new Error(`snapshot path must not be a symbolic link: ${entry.name}`);
    }
    if (entry.isDirectory()) {
      return SNAPSHOT_EXCLUDED_DIRECTORIES.has(entry.name)
        ? []
        : nestedJsonPaths(vectorRoot, join(vectorRoot, entry.name));
    }
    if (!entry.isFile() || !entry.name.endsWith(".json")
      || SNAPSHOT_EXCLUDED_FILES.has(entry.name)) return [];
    return [`${SNAPSHOT_VECTOR_ROOT}/${entry.name}`];
  }).sort();
}

function loadSnapshotGuidanceManifest(repoRoot: string): SnapshotGuidanceManifest {
  const bytes = snapshotGuidanceBytes(repoRoot, SNAPSHOT_MANIFEST_PATH).toString("utf8");
  const manifest = parseSnapshotGuidanceManifest(snapshotGuidanceJson(
    Buffer.from(bytes, "utf8"),
    "snapshot manifest",
  ));
  const canonical = `${JSON.stringify({
    snapshot_schema: manifest.snapshot_schema,
    source_commit: manifest.source_commit,
    vector_schema_version: manifest.vector_schema_version,
    vector_count: manifest.vector_count,
    artifacts: manifest.artifacts,
  }, null, 2)}\n`;
  if (bytes !== canonical) {
    throw new Error("snapshot manifest is not canonical two-space JSON with one trailing LF");
  }

  const schemaPath = `${SNAPSHOT_VECTOR_ROOT}/schema/vector.schema.json`;
  const schema = snapshotGuidanceJson(
    snapshotGuidanceBytes(repoRoot, schemaPath),
    "packaged vector schema",
  );
  if (!snapshotGuidanceRecord(schema) || !snapshotGuidanceRecord(schema.properties)) {
    throw new Error("packaged vector schema has no properties object");
  }
  const versionRule = schema.properties.vector_schema_version;
  const ownerRule = schema.properties.owner_document;
  if (!snapshotGuidanceRecord(versionRule)
    || typeof versionRule.const !== "string"
    || !SNAPSHOT_SEMVER.test(versionRule.const)) {
    throw new Error("packaged vector schema has no exact vector_schema_version const");
  }
  if (!snapshotGuidanceRecord(ownerRule)
    || !Array.isArray(ownerRule.enum)
    || ownerRule.enum.length === 0
    || ownerRule.enum.some((owner) => typeof owner !== "string")
    || new Set(ownerRule.enum).size !== ownerRule.enum.length) {
    throw new Error("packaged vector schema has no closed unique owner_document enum");
  }
  const ownerDocuments = ownerRule.enum as string[];
  if (manifest.vector_schema_version !== versionRule.const) {
    throw new Error(
      `snapshot schema version disagreement: manifest ${manifest.vector_schema_version}, packaged schema ${versionRule.const}`,
    );
  }

  const vectorRoot = resolve(repoRoot, SNAPSHOT_VECTOR_ROOT);
  const vectorPaths = snapshotGuidanceVectorPaths(vectorRoot);
  for (const path of vectorPaths) {
    const vector = snapshotGuidanceJson(snapshotGuidanceBytes(repoRoot, path), `snapshot vector ${path}`);
    if (!snapshotGuidanceRecord(vector) || vector.vector_schema_version !== versionRule.const) {
      throw new Error(`snapshot schema version disagreement: ${path} does not use ${versionRule.const}`);
    }
  }
  if (manifest.vector_count !== vectorPaths.length) {
    throw new Error(
      `snapshot vector count mismatch: expected ${vectorPaths.length}, found ${manifest.vector_count}`,
    );
  }
  const supportPaths: string[] = [...SNAPSHOT_SUPPORT_PATHS];
  if (existsSync(resolve(repoRoot, SNAPSHOT_VECTOR_ROOT, SNAPSHOT_OPTIONAL_ASSURANCE_COVERAGE))) {
    supportPaths.push(SNAPSHOT_OPTIONAL_ASSURANCE_COVERAGE);
  }
  const expectedPaths = [
    ...vectorPaths,
    ...supportPaths.map((path) => `${SNAPSHOT_VECTOR_ROOT}/${path}`),
  ].sort();
  if (manifest.artifacts.length !== expectedPaths.length) {
    throw new Error("snapshot artifact inventory length mismatch");
  }
  for (const [index, path] of expectedPaths.entries()) {
    const artifact = manifest.artifacts[index];
    if (artifact?.path !== path) throw new Error(`snapshot artifact inventory mismatch: ${path}`);
    const digest = createHash("sha256").update(snapshotGuidanceBytes(repoRoot, path)).digest("hex");
    if (artifact.sha256 !== digest) throw new Error(`artifact digest mismatch: ${path}`);
  }
  return { ...manifest, owner_documents: ownerDocuments };
}

const MAINTAINED_SNAPSHOT_GUIDANCE_PATHS = [
  "docs/spec/heterodyne-core.md",
  "docs/spec/heterodyne.md",
  "README.md",
  "docs/spec/vectors/README.md",
  "docs/architecture.md",
  "docs/glossary.md",
  "docs/security/threat-model.md",
  "AGENTS.md",
  "CHANGELOG.md",
] as const;
const SOURCE_COMMIT_STATEMENT = /\bsource commit(?:\s+is)?\s+`?([0-9a-f]{40})`?/giu;
const SNAPSHOT_COMMIT_STATEMENT = /\bsnapshot commit(?:\s+is)?\s+`?([0-9a-f]{40})`?/giu;
const VECTOR_COUNT_STATEMENT = /(?<![A-Za-z0-9-])([0-9]+)[-\s]+vectors?\b/giu;
const ARTIFACT_COUNT_STATEMENT =
  /(?<![A-Za-z0-9-])([0-9]+)[-\s]+(?:(?:manifest[-\s]+listed|digest[-\s]+bound)\s+)?artifacts?\b/giu;
const VECTOR_SCHEMA_STATEMENT =
  /\b(?:vector[-\s]+)?schema[-\s]+([0-9]+\.[0-9]+\.[0-9]+)\b/giu;
const STALE_SNAPSHOT_GUIDANCE = [
  /\bcurrent(?:[-\s]+(?:draft|lane|generator))?[^.\n]{0,80}\b0\.5(?:\.0)?\b/iu,
  /\b(?:source root|snapshot)[^.\n]{0,100}\bfive documents?\b/iu,
  /\bschema[-\s]+2(?:\.0\.0)?\b/iu,
  /\bzero (?:declared )?(?:reference[-\s]+checker|executable)(?: cases?| declarations?)?\b/iu,
] as const;

function currentChangelogText(text: string): string {
  const datedRelease = text.search(/^## \[[0-9]+\.[0-9]+\.[0-9]+\]\s+[-—]/mu);
  return datedRelease < 0 ? text : text.slice(0, datedRelease);
}

/** Lint current snapshot guidance against the closed manifest and history mechanism. */
export function lintMaintainedSnapshotGuidance(
  repoRoot: string,
): DocsLintIssue[] {
  let manifest;
  try {
    manifest = loadSnapshotGuidanceManifest(repoRoot);
  } catch (error) {
    return [{
      path: SNAPSHOT_MANIFEST_PATH,
      line: 1,
      code: "snapshot-manifest-invalid",
      message: `snapshot guidance cannot load the closed manifest: ${String(error)}`,
    }];
  }

  const issues: DocsLintIssue[] = [];
  const addIssue = (
    path: string,
    text: string,
    offset: number,
    code: "snapshot-guidance-missing" | "snapshot-guidance-stale",
    message: string,
  ): void => {
    issues.push({
      path,
      line: text.slice(0, offset).split(/\r?\n/u).length,
      code,
      message,
    });
  };

  for (const path of MAINTAINED_SNAPSHOT_GUIDANCE_PATHS) {
    const source = readFileSync(resolve(repoRoot, path), "utf8");
    const text = path === "CHANGELOG.md" ? currentChangelogText(source) : source;
    if (!text.includes(SNAPSHOT_MANIFEST_PATH)
      || !/\bexact\b[\s\S]{0,160}\b(?:fact|source|identity|authority)/iu.test(text)) {
      addIssue(
        path,
        text,
        0,
        "snapshot-guidance-missing",
        `guide must identify ${SNAPSHOT_MANIFEST_PATH} as the exact source of mutable snapshot facts`,
      );
    }
    if (!/(?:`snapshot-check`[\s\S]{0,220}\blast commit that changed|last commit that changed[\s\S]{0,220}`snapshot-check`)/iu
      .test(text)) {
      addIssue(
        path,
        text,
        0,
        "snapshot-guidance-missing",
        "guide must state that snapshot-check derives snapshot identity from the last manifest-changing commit",
      );
    }
    if (!/\b(?:current[-\s]+draft|draft)[\s\S]{0,200}\bindependent/iu.test(text)
      && !/\bindependent[\s\S]{0,200}\b(?:current[-\s]+draft|draft)/iu.test(text)) {
      addIssue(
        path,
        text,
        0,
        "snapshot-guidance-missing",
        "guide must keep current-draft and history-bound snapshot checks independent",
      );
    }

    for (const match of text.matchAll(SOURCE_COMMIT_STATEMENT)) {
      if (match[1] === manifest.source_commit) continue;
      addIssue(
        path,
        text,
        match.index,
        "snapshot-guidance-stale",
        "copied snapshot source commit disagrees with the closed manifest",
      );
    }
    for (const match of text.matchAll(SNAPSHOT_COMMIT_STATEMENT)) {
      addIssue(
        path,
        text,
        match.index,
        "snapshot-guidance-stale",
        "snapshot commit must be history-derived and must not be copied into maintained prose",
      );
    }
    for (const match of text.matchAll(VECTOR_COUNT_STATEMENT)) {
      if (Number(match[1]) === manifest.vector_count) continue;
      addIssue(
        path,
        text,
        match.index,
        "snapshot-guidance-stale",
        "copied snapshot vector count disagrees with the closed manifest",
      );
    }
    for (const match of text.matchAll(ARTIFACT_COUNT_STATEMENT)) {
      if (Number(match[1]) === manifest.artifacts.length) continue;
      addIssue(
        path,
        text,
        match.index,
        "snapshot-guidance-stale",
        "copied snapshot artifact count disagrees with the closed manifest",
      );
    }
    for (const match of text.matchAll(VECTOR_SCHEMA_STATEMENT)) {
      if (match[1] === manifest.vector_schema_version) continue;
      addIssue(
        path,
        text,
        match.index,
        "snapshot-guidance-stale",
        "copied snapshot vector schema version disagrees with the closed manifest",
      );
    }
    for (const pattern of STALE_SNAPSHOT_GUIDANCE) {
      const match = pattern.exec(text);
      if (match === null) continue;
      addIssue(
        path,
        text,
        match.index,
        "snapshot-guidance-stale",
        `retired current snapshot guidance: ${match[0]}`,
      );
    }
    if (path === "docs/spec/vectors/README.md") {
      const ownerExample = /"owner_document"\s*:\s*"([^"]+)"/u.exec(text);
      if (ownerExample !== null) {
        const documentedOwners = ownerExample[1]!.split("|").map((owner) => owner.trim());
        if (documentedOwners.length !== manifest.owner_documents.length
          || documentedOwners.some((owner, index) => owner !== manifest.owner_documents[index])) {
          addIssue(
            path,
            text,
            ownerExample.index,
            "snapshot-guidance-stale",
            "owner_document example must match the packaged vector schema enum",
          );
        }
      }
    }
  }
  return issues;
}

const CURRENT_PRIVACY_TIER_GUIDE_PATHS = new Set([
  "README.md",
  "docs/spec/heterodyne.md",
  "docs/architecture.md",
  "docs/glossary.md",
  "docs/security/threat-model.md",
]);
const OBSOLETE_PRIVACY_TIER_GUIDANCE = [
  /\bTier\s*2\b(?:(?!\bTier\s*3\b)[\s\S]){0,180}\bplaintext\b(?:(?!\bTier\s*3\b)[\s\S]){0,120}\bprivate repositor/iu,
  /\bTier\s*2\b(?:(?!\bTier\s*3\b)[\s\S]){0,180}\bprivate repositor(?:(?!\bTier\s*3\b)[\s\S]){0,120}\bplaintext\b/iu,
  /\bTier\s*3\b[\s\S]{0,180}\b(?:audience|group)[-\s]+encrypted\b[\s\S]{0,160}\bcarriers?\b[\s\S]{0,80}\bdo not receive plaintext\b/iu,
] as const;

/** Reject the superseded privacy-tier model only in maintained current guides. */
export function findObsoletePrivacyTierGuidanceIssues(
  text: string,
  path: string,
): DocsLintIssue[] {
  if (!CURRENT_PRIVACY_TIER_GUIDE_PATHS.has(path)) return [];
  return OBSOLETE_PRIVACY_TIER_GUIDANCE.flatMap((pattern) => {
    const match = pattern.exec(text);
    if (match === null) return [];
    return [{
      path,
      line: text.slice(0, match.index).split(/\r?\n/u).length,
      code: "retired-authoring-model" as const,
      message: "obsolete privacy-tier guidance conflicts with the current Comms carrier model",
    }];
  });
}

/** Lint the maintained authoring guides against the single-family model. */
export function lintMaintainedGuides(
  repoRoot: string,
  contentOverrides: Readonly<Record<string, string>> = {},
): FamilyDocIssue[] {
  const issues: FamilyDocIssue[] = [];
  const guides = [
    "AGENTS.md",
    "README.md",
    "docs/adr/archive/2026-08-24-047-nostr-first-interoperability.md",
    "docs/adr/README.md",
    "docs/spec/heterodyne.md",
    "docs/spec/vectors/README.md",
    "docs/spec/vectors/generator/README.md",
    "docs/spec/extensions/nips/README.md",
    "docs/glossary.md",
    "docs/security/threat-model.md",
    "docs/architecture.md",
    "docs/spec/heterodyne-social.md",
    "CHANGELOG.md",
  ];
  const contents = new Map(
    guides.map((path) => [
      path,
      contentOverrides[path] ?? readFileSync(resolve(repoRoot, path), "utf8"),
    ]),
  );
  for (const [path, text] of contents) {
    issues.push(...findObsoletePrivacyTierGuidanceIssues(text, path));
  }
  issues.push(...lintDefensiveValidationReviews(repoRoot, contentOverrides));
  const corpusBytes = [...contents.values()].reduce(
    (total, text) => total + Buffer.byteLength(text, "utf8"),
    0,
  );
  if (corpusBytes > MAX_MARKDOWN_CORPUS_BYTES) {
    return [{
      path: "<maintained-guides>",
      line: 1,
      code: "markdown-resource-limit",
      message: `maintained Markdown corpus exceeds ${MAX_MARKDOWN_CORPUS_BYTES} bytes`,
    }];
  }
  for (const [path, text] of contents) {
    const bytes = Buffer.byteLength(text, "utf8");
    if (bytes > MAX_MARKDOWN_FILE_BYTES) {
      return [{
        path,
        line: 1,
        code: "markdown-resource-limit",
        message: `maintained Markdown file exceeds ${MAX_MARKDOWN_FILE_BYTES} bytes`,
      }];
    }
  }
  const markdownAnalyses = new Map<string, MarkdownAnalysis>();
  for (const [path, text] of contents) {
    let analysis: MarkdownAnalysis;
    try {
      analysis = analyzeMarkdown(text);
    } catch (error) {
      return [{
        path,
        line: 1,
        code: "markdown-resource-limit",
        message: `maintained Markdown parse failed closed: ${String(error)}`,
      }];
    }
    if (analysis.maxDepth > MAX_MARKDOWN_AST_DEPTH) {
      return [{
        path,
        line: 1,
        code: "markdown-resource-limit",
        message: `maintained Markdown AST exceeds depth ${MAX_MARKDOWN_AST_DEPTH}`,
      }];
    }
    if (analysis.nodeCount > MAX_MARKDOWN_AST_NODES) {
      return [{
        path,
        line: 1,
        code: "markdown-resource-limit",
        message: `maintained Markdown AST exceeds ${MAX_MARKDOWN_AST_NODES} nodes`,
      }];
    }
    markdownAnalyses.set(path, analysis);
  }
  const lineFor = (text: string, offset: number) =>
    text.slice(0, offset).split(/\r?\n/).length;

  for (const [path, text] of contents) {
    for (const pattern of RETIRED_MAINTAINED_GUIDE_PATTERNS) {
      const match = pattern.exec(text);
      if (match !== null) {
        issues.push({
          path,
          line: lineFor(text, match.index),
          code: "retired-authoring-model",
          message: `retired authoring terminology: ${match[0]}`,
        });
      }
    }
  }

  const liveNostrFirstPaths = [
    "AGENTS.md",
    "README.md",
    "docs/spec/heterodyne.md",
    "docs/architecture.md",
    "docs/glossary.md",
    "docs/security/threat-model.md",
    "docs/spec/extensions/nips/README.md",
  ];
  for (const path of liveNostrFirstPaths) {
    const text = contents.get(path)!;
    for (const pattern of RETIRED_NOSTR_FIRST_GUIDE_PATTERNS) {
      if (pattern === CANONICAL_FEED_INDEX_PATTERN) {
        for (const block of markdownAnalyses.get(path)!.blocks) {
          for (const match of allPatternMatches(pattern, block.text)) {
            if (isCanonicalFeedIndexLocallyRetired(
              block.text,
              match.index,
              match[0].length,
            )) continue;
            issues.push({
              path,
              line: block.line,
              code: "retired-authoring-model",
              message: `retired Nostr-first terminology: ${match[0]}`,
            });
          }
        }
        continue;
      }
      for (const match of allPatternMatches(pattern, text)) {
        if (isPredicateLocallyRetired(
          text,
          match.index,
          match[0].length,
        )) continue;
        issues.push({
          path,
          line: lineFor(text, match.index),
          code: "retired-authoring-model",
          message: `retired Nostr-first terminology: ${match[0]}`,
        });
      }
    }
  }

  const agents = contents.get("AGENTS.md")!;
  for (const pattern of UNSAFE_AGENT_SECURITY_FRAMING) {
    const match = pattern.exec(agents);
    if (match === null) continue;
    issues.push({
      path: "AGENTS.md",
      line: lineFor(agents, match.index),
      code: "retired-authoring-model",
      message: `unsafe security-task framing: ${match[0]}`,
    });
  }

  const registryRevision = loadRegistry(repoRoot).manifest.revision;
  const namesCurrentRegistryRevision = new RegExp(
    `distinct from[^.\n]*current family registry revision ${registryRevision}\\b`,
  );
  for (const path of ["docs/glossary.md", "docs/security/threat-model.md"]) {
    const text = contents.get(path)!;
    const profileRevisionIndex = text.indexOf("`profile_revision`");
    const namesProfileRevision = profileRevisionIndex >= 0;
    const profileRevisionContext = namesProfileRevision
      ? text.slice(Math.max(0, profileRevisionIndex - 80), profileRevisionIndex + 160)
      : "";
    const statesFrozenStatus = /\bfrozen\b/i.test(profileRevisionContext);
    const statesValueTwo = /`2`/.test(profileRevisionContext);
    if (!namesProfileRevision
      || !statesFrozenStatus
      || !statesValueTwo
      || !namesCurrentRegistryRevision.test(text)) {
      issues.push({
        path,
        line: 1,
        code: "profile-revision-registry-context-missing",
        message:
          `guide must state profile_revision, its frozen value 2, and its distinction from current family registry revision ${registryRevision}`,
      });
    }
  }

  return issues;
}
