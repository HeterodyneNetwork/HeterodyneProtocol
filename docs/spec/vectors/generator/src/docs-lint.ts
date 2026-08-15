import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { relative, resolve, sep } from "node:path";
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
    | "missing-cutover-artifact"
    | "overview-normative-language"
    | "extraction-banner"
    | "noncanonical-decision-reference"
    | "premature-release-claim"
    | "marmot-archive-invalid"
    | "generic-repo-relay-server-claim"
    | "ambiguous-nostr-wire-key"
    | "claim-profile-revision-ambiguous"
    | "missing-upstream-kind-allocation"
    | "strict-profile-closure-invalid"
    | "unresolved-section-reference"
    | "registry-digest-drift";
  message: string;
};

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
const BARE_FAMILY_LINK =
  /\]\((?:\.\/)?heterodyne-(core|comms|control|social|workspace)\.md(?:#[^)]+)?\)/i;
const NONCANONICAL_DECISION_REFERENCE = /\bADR-\d{3}\b|docs\/adr\//;
const NUMBERED_HEADING = /^#{2,6}\s+(\d+(?:\.\d+)*)\.?\s/;
const SECTION_REFERENCE = /§(\d+(?:\.\d+)*)/g;
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
  const sections = new Map<DocumentId, Set<string>>();

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
  const registry = loadRegistry(repoRoot);
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
      /^- \*\*((?:CORE|COMMS|CONTROL|SOCIAL|WORKSPACE)-I-[A-Z0-9]+(?:-[A-Z0-9]+)*):\*\* ([^\r\n]+)$/gm,
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
  registeredInvariants?: readonly { id: string; owner: DocumentId }[],
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

  const owners = new Map(
    (registeredInvariants ?? []).map(({ id, owner }) => [id, owner]),
  );
  for (const profile of profiles.values()) {
    closureOf(profile.profile_id);
    if (registeredInvariants === undefined) continue;
    const declaringOwner = /^heterodyne-([a-z]+)-strict-/.exec(profile.profile_id)?.[1];
    for (const invariant of profile.adds_invariants) {
      const owner = owners.get(invariant);
      if (owner === undefined) {
        issues.push(`unregistered added invariant: ${profile.profile_id} -> ${invariant}`);
      } else if (owner !== declaringOwner) {
        issues.push(
          `added invariant is not owned by the declaring document: ${profile.profile_id} -> ${invariant}`,
        );
      }
    }
  }
  return issues.sort();
}
export function lintReleaseReadiness(repoRoot: string): FamilyDocIssue[] {
  const issues: FamilyDocIssue[] = [];
  const overviewPath = resolve(repoRoot, "docs/spec/heterodyne.md");
  if (!existsSync(overviewPath)) {
    return [{
      path: displayPath(repoRoot, overviewPath),
      line: 1,
      code: "missing-cutover-artifact",
      message: "the family overview is missing",
    }];
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
  if (
    !/prepared documents/i.test(overview) ||
    !/unreleased[\s\S]*explicit\s+release\s+approval/i.test(
      overview,
    ) ||
    /current release|release records/i.test(overview)
  ) {
    issues.push({
      path: displayPath(repoRoot, overviewPath),
      line: 1,
      code: "premature-release-claim",
      message: "overview must distinguish current normative authority from the prepared, unreleased 0.x artifacts",
    });
  }

  const changelogPath = resolve(repoRoot, "CHANGELOG.md");
  if (existsSync(changelogPath)) {
    const changelog = readFileSync(changelogPath, "utf8");
    const current = changelog.split("### Historical 0.4.0", 1)[0];
    if (
      !/^## \[Unreleased\]$/m.test(current) ||
      !/prepared[\s\S]*0\.5\.0/i.test(current) ||
      /## 0\.5\.0 document releases|\bPublished\b/.test(current)
    ) {
      issues.push({
        path: displayPath(repoRoot, changelogPath),
        line: 1,
        code: "premature-release-claim",
        message: "0.5.0 must remain in Unreleased pending explicit approval",
      });
    }
  }
  for (const document of loadFamilyDocuments(repoRoot)) {
    if (/pre-release extraction draft/i.test(document.lines.join("\n"))) {
      issues.push({
        path: document.displayPath,
        line: 1,
        code: "extraction-banner",
        message: "pre-release extraction banner remains after cutover",
      });
    }
  }

  return issues;
}
