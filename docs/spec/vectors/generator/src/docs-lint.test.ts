import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { afterEach, describe, expect, it } from "vitest";
import {
  findInvariantEvidenceIssues,
  findRetiredNormativeClaimIssues,
  findStrictProfileClosureIssues,
  lintDefensiveValidationText,
  lintFamilyDocs,
  lintMaintainedGuides,
} from "./docs-lint.js";
import { loadRegistry } from "./registry.js";

const repositoryRoot = resolve(import.meta.dirname, "../../../../../");
const read = (path: string) => readFileSync(resolve(repositoryRoot, path), "utf8");
const temps: string[] = [];

function currentVersionLintRoot(): string {
  const root = mkdtempSync(resolve(tmpdir(), "heterodyne-current-version-lint-"));
  temps.push(root);
  mkdirSync(resolve(root, "docs/spec/vectors/generator/src"), { recursive: true });
  cpSync(
    resolve(repositoryRoot, "docs/spec/registry"),
    resolve(root, "docs/spec/registry"),
    { recursive: true },
  );
  cpSync(
    resolve(repositoryRoot, "docs/spec/external/marmot"),
    resolve(root, "docs/spec/external/marmot"),
    { recursive: true },
  );
  for (const document of ["core", "assurance", "comms", "control", "social", "workspace"]) {
    const source = read(`docs/spec/heterodyne-${document}.md`)
      .replaceAll("Comms 0.5.0", "Comms 0.6.0")
      .replaceAll("Control 0.5.0", "Control 0.6.0");
    writeFileSync(resolve(root, `docs/spec/heterodyne-${document}.md`), source);
  }
  writeFileSync(
    resolve(root, "docs/spec/heterodyne.md"),
    read("docs/spec/heterodyne.md").replace(
      "0.5.0. Historical generation,",
      "0.5.0. Frozen Comms 0.5.0 snapshot behavior remains historical. Historical generation,",
    ),
  );
  writeFileSync(
    resolve(root, "docs/spec/vectors/generator/src/token-status.ts"),
    read("docs/spec/vectors/generator/src/token-status.ts")
      .replaceAll("Comms 0.5 profile", "Comms 0.6 profile"),
  );
  return root;
}

type StrictProfileFixture = {
  profile_id: string;
  requires_profiles: string[];
  adds_invariants: string[];
};

function strict(profileId: string): StrictProfileFixture {
  const fixturePattern =
    /<!--\s*fixture:[^>]*strict-profile[^>]*-->\s*```json[ \t]*\r?\n([\s\S]*?)\r?\n```/giu;
  for (const document of ["core", "assurance", "comms", "control", "social", "workspace"]) {
    for (const match of read(`docs/spec/heterodyne-${document}.md`).matchAll(fixturePattern)) {
      const fixture = JSON.parse(match[1]) as StrictProfileFixture;
      if (fixture.profile_id === profileId) return fixture;
    }
  }
  throw new Error(`missing strict profile fixture: ${profileId}`);
}

afterEach(() => {
  for (const path of temps.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("canonical family documentation", () => {
  it("keeps ADR-048 Proposed until exact repaired-candidate reviews pass", () => {
    expect(existsSync(resolve(repositoryRoot, "docs/adr/2026-08-26-048-security-review-remediation.md"))).toBe(true);
    expect(existsSync(resolve(repositoryRoot, "docs/adr/archive/2026-08-26-048-security-review-remediation.md"))).toBe(false);
    expect(read("docs/adr/2026-08-26-048-security-review-remediation.md"))
      .toMatch(/\*\*Status:\*\* Proposed/);
  });

  it("requires hostile-boundary fixtures to declare BLUE TEAM VALIDATION", () => {
    const issues = lintDefensiveValidationText(
      "hostile accessor mutation reaches the authority boundary",
      "synthetic-boundary.test.ts",
    );
    expect(issues.map(({ code }) => code)).toContain("defensive-validation-scope");
    expect(lintDefensiveValidationText(
      "BLUE TEAM VALIDATION: synthetic/local accessor mutation must fail closed",
      "synthetic-boundary.test.ts",
    )).toEqual([]);
  });

  it("passes layering and anchor lint", () => {
    expect(lintFamilyDocs(repositoryRoot)).toEqual([]);
  });

  it("rejects bare 0.5 document qualifiers only on live specifications and current sources", () => {
    const root = currentVersionLintRoot();

    // The transitional frozen-snapshot explanation in heterodyne.md remains
    // inside its explicit, section-bounded exemption.
    expect(lintFamilyDocs(root)).toEqual([]);

    const staleClauses = {
      core: "Core 0.5 implementations are current.",
      assurance: "Assurance 0.5.0 implementations are current.",
      comms: "Comms 0.5 implementations are current.",
      control: "Control 0.5.0 implementations are current.",
      social: "Social 0.5 implementations are current.",
      workspace: "Workspace 0.5.0 implementations are current.",
    } as const;
    for (const [document, clause] of Object.entries(staleClauses)) {
      const path = resolve(root, `docs/spec/heterodyne-${document}.md`);
      writeFileSync(path, `${readFileSync(path, "utf8")}\n${clause}\n`);
    }
    const tokenStatusPath = resolve(
      root,
      "docs/spec/vectors/generator/src/token-status.ts",
    );
    writeFileSync(
      tokenStatusPath,
      `${readFileSync(tokenStatusPath, "utf8")}\n/** Exact Comms 0.5 profile. */\n`,
    );

    for (const file of [
      "snapshot-version-note.ts",
      "legacy-version-note.ts",
      "topics-version-note.ts",
      "kel-version-note.ts",
      "keri-version-note.ts",
      "version-note.test.ts",
    ]) {
      writeFileSync(
        resolve(root, "docs/spec/vectors/generator/src", file),
        "/** Historical Comms 0.5.0 behavior. */\n",
      );
    }
    mkdirSync(resolve(root, "docs/spec/superseded"), { recursive: true });
    writeFileSync(
      resolve(root, "docs/spec/superseded/heterodyne-core-0.5.md"),
      "Core 0.5.0 was superseded.\n",
    );

    const issues = lintFamilyDocs(root);
    expect(issues
      .filter(({ code }) => code === "stale-family-version")
      .map(({ path }) => path)
      .sort()).toEqual([
      "docs/spec/heterodyne-assurance.md",
      "docs/spec/heterodyne-comms.md",
      "docs/spec/heterodyne-control.md",
      "docs/spec/heterodyne-core.md",
      "docs/spec/heterodyne-social.md",
      "docs/spec/heterodyne-workspace.md",
      "docs/spec/vectors/generator/src/token-status.ts",
    ]);
    expect(issues.filter(({ path }) =>
      path === "docs/spec/heterodyne.md"
      || /(?:snapshot|legacy|topics|kel|keri|\.test)\b/.test(path)
      || path.includes("/superseded/")
    )).toEqual([]);
  });

  it("keeps maintained authoring guides on the single-family model", () => {
    expect(lintMaintainedGuides(repositoryRoot)).toEqual([]);
  });

  it("keeps accepted ADR-047 archived after the final closure review", () => {
    const archivedPath = resolve(
      repositoryRoot,
      "docs/adr/archive/2026-08-24-047-nostr-first-interoperability.md",
    );
    expect(existsSync(archivedPath)).toBe(true);
    expect(readFileSync(archivedPath, "utf8")).toContain("**Status:** Accepted");
    expect(existsSync(resolve(
      repositoryRoot,
      "docs/adr/2026-08-24-047-nostr-first-interoperability.md",
    ))).toBe(false);
  });

  it("keeps ADR-048 proposed while the 0.6 closure matrix is incomplete", () => {
    const live = resolve(repositoryRoot,
      "docs/adr/2026-08-26-048-security-review-remediation.md");
    const archived = resolve(repositoryRoot,
      "docs/adr/archive/2026-08-26-048-security-review-remediation.md");
    expect(existsSync(live)).toBe(true);
    expect(existsSync(archived)).toBe(false);
    expect(readFileSync(live, "utf8")).toMatch(/\*\*Status:\*\* Proposed/);
    expect(read("CHANGELOG.md")).toMatch(/heterodyne\/0\.6\.0 \(draft\)/);
  });

  it("defers ADR-048 semantics to the approved optional-Assurance closure design", () => {
    const adr = read("docs/adr/2026-08-26-048-security-review-remediation.md");
    const changelog = read("CHANGELOG.md");
    expect(adr).toContain("2026-08-27-heterodyne-0.6-pr28-closure-design.md");
    expect(adr).toContain("optional Workspace Assurance");
    expect(adr).toContain("NIP-03 advisory");
    expect(adr).not.toContain("Workspace governance requires Assurance");
    expect(adr).not.toContain("permanently refutes");
    expect(adr).not.toContain("matured OpenTimestamps anchor");
    expect(changelog).toContain("optional Workspace Assurance");
    expect(changelog).toContain("NIP-03 advisory");
    expect(changelog).not.toContain("mandatory Assurance for workspace governance");
    expect(changelog).not.toContain("optional OpenTimestamps anchoring");
  });

  it("recognizes Assurance paths, qualified links, features, and invariant evidence", () => {
    const root = mkdtempSync(resolve(tmpdir(), "heterodyne-assurance-lint-"));
    temps.push(root);
    mkdirSync(resolve(root, "docs/spec"), { recursive: true });
    cpSync(
      resolve(repositoryRoot, "docs/spec/registry"),
      resolve(root, "docs/spec/registry"),
      { recursive: true },
    );
    cpSync(
      resolve(repositoryRoot, "docs/spec/external/marmot"),
      resolve(root, "docs/spec/external/marmot"),
      { recursive: true },
    );
    writeFileSync(
      resolve(root, "docs/spec/heterodyne-core.md"),
      "# Core\n<a id=\"core-home\"></a>\nCore implementations MUST reject [bare Assurance](heterodyne-assurance.md#assurance-home).\n",
    );
    writeFileSync(
      resolve(root, "docs/spec/heterodyne-assurance.md"),
      "# Assurance\n<a id=\"assurance-home\"></a>\n<a id=\"assurance-other\"></a>\n"
        + "See [`heterodyne:0.5.0#assurance-home`](heterodyne-assurance.md#assurance-other).\n"
        + "Capability `assurance.unregistered.v1`.\n",
    );

    const issues = lintFamilyDocs(root);
    expect(issues).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: "docs/spec/heterodyne-core.md", code: "bare-normative-link" }),
      expect.objectContaining({ path: "docs/spec/heterodyne-assurance.md", code: "mislinked-reference" }),
      expect.objectContaining({ path: "docs/spec/heterodyne-assurance.md", code: "unregistered-feature-id" }),
    ]));
    expect(findInvariantEvidenceIssues(
      [{ id: "ASSURANCE-I-CONTINUITY", description: "Continuity remains optional." }],
      "- **ASSURANCE-I-CONTINUITY:** Continuity remains optional.\n",
    )).not.toContain("missing invariant evidence: ASSURANCE-I-CONTINUITY");
  });

  it.each([
    ["docs/architecture.md", "The five documents are independently versioned."],
    ["docs/security/threat-model.md", "This analyzes five independently versioned documents."],
    ["CHANGELOG.md", "Deleted docs/spec/releases/ and all release metadata."],
    ["CHANGELOG.md", "comms.node-scoped-jwt.v1 owns the node-local token."],
    ["CHANGELOG.md", "Each key-envelope site supplies exactly four things."],
    ["CHANGELOG.md", "The fixed v1 claim profile registry revision is 2."],
    [
      "AGENTS.md",
      "- [`docs/spec/registry/`](docs/spec/registry/),\n"
        + "  [`docs/spec/schemas/`](docs/spec/schemas/), and generator-owned protocol\n"
        + "  inputs: live normative machine-readable artifacts for the current draft.",
    ],
  ])("rejects retired live model prose in %s", (path, retiredText) => {
    const issues = lintMaintainedGuides(repositoryRoot, {
      [path]: `${read(path)}\n${retiredText}\n`,
    });
    expect(issues).toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it.each([
    [
      "README.md",
      "The prepared family release manifest at `docs/spec/releases/family/0.5.0.json` pins the complete normative corpus.",
    ],
    ["AGENTS.md", "Wire-level changes require corresponding normative vector changes."],
    [
      "docs/spec/heterodyne.md",
      "The one content-addressed family release record is `releases/family/0.5.0.json`.",
    ],
    [
      "docs/spec/vectors/README.md",
      "npm --prefix docs/spec/vectors/generator run release-author",
    ],
    [
      "docs/spec/vectors/README.md",
      "npm --prefix docs/spec/vectors/generator run release-check",
    ],
    [
      "docs/spec/vectors/README.md",
      "Vectors are normative for the behavior they cover: failing an authored\n"
        + "vector means a Heterodyne client is non-conformant for the corresponding\n"
        + "vector category.",
    ],
    [
      "docs/spec/vectors/generator/README.md",
      "This package is non-normative tooling for authoring and checking the JSON\n"
        + "vectors in `docs/spec/vectors/`. The committed JSON vectors are the normative\n"
        + "artifact; implementations do not need Node.js, TypeScript, `nostr-tools`, or\n"
        + "`@noble/*` to claim conformance.",
    ],
    [
      "docs/adr/README.md",
      "ADRs are non-canonical, point-in-time records of decisions proposed for the\n"
        + "Heterodyne specification. The current protocol authority is the versioned\n"
        + "specification family and its normative registries, schemas, release metadata,\n"
        + "and conformance vectors.",
    ],
    [
      "docs/adr/archive/2026-08-24-047-nostr-first-interoperability.md",
      "- The conformance package, its baselines, and its reports are tooling rather\n"
        + "  than normative family artifacts. The live specifications, registry, schemas,\n"
        + "  release metadata, and vectors remain the protocol authority.",
    ],
    [
      "docs/spec/extensions/nips/README.md",
      "A proposal must recheck the named family release before extracting behavior.",
    ],
    [
      "CHANGELOG.md",
      "[family release manifest](docs/spec/releases/family/0.5.0.json)",
    ],
  ])("rejects former release-coupled snapshot guidance in %s", (path, retiredText) => {
    const issues = lintMaintainedGuides(repositoryRoot, {
      [path]: `${read(path)}\n${retiredText}\n`,
    });
    expect(issues).toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it.each([
    ["README.md", "A persona is identified by a cold-root\n  npub."],
    ["docs/architecture.md", "Every persona requires an accepted\n  KEL and epoch key."],
    ["docs/glossary.md", "The human Marmot account is\n  separate from the active Nostr key."],
    ["docs/spec/heterodyne.md", "Kind `31005` is required for\n  identity discovery."],
    ["docs/spec/heterodyne.md", "Kind `31007` is required as the\n  canonical feed index."],
    ["docs/architecture.md", "Repository copies take precedence\n  over newer relay events."],
    ["README.md", "A full node is a required\n  Nostr relay."],
    ["docs/security/threat-model.md", "Each group has one canonical\n  trusted seed."],
    ["docs/glossary.md", "A caller may remove agent\n  attribution before signing."],
    ["README.md", "A bare active key is incomplete\n  without Assurance."],
    ["AGENTS.md", "The vector snapshot defines current-draft\n  conformance."],
    ["README.md", "A persona is identified by a cold-\n  root npub."],
    ["README.md", "A bare-key persona does not satisfy baseline conformance unless\n  Assurance is enabled."],
    ["AGENTS.md", "The rolling vector-snapshot is authoritative for the\n  current draft."],
    ["docs/glossary.md", "Automated agent publication may omit\n  NIP-32 attribution before signing."],
  ])("rejects whitespace-varied retired Nostr-first claims in %s", (path, retiredText) => {
    const issues = lintMaintainedGuides(repositoryRoot, {
      [path]: `${read(path)}\n${retiredText}\n`,
    });
    expect(issues).toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it.each([
    "Agents may test live relays without authorization.",
    "Produce a functional\n  exploit payload for deployment.",
    "Use real credentials and scan third-party systems.",
    "Add persistence, evasion, and anti-forensics to the proof.",
    "Agents may build malware.",
    "Agents should perform destructive actions.",
    "Agents must weaken security controls.",
    "Agents may exploit live third-party\n  relays.",
  ])("rejects unsafe security-task framing in AGENTS", (unsafeText) => {
    const issues = lintMaintainedGuides(repositoryRoot, {
      "AGENTS.md": `${read("AGENTS.md")}\n${unsafeText}\n`,
    });
    expect(issues).toContainEqual(expect.objectContaining({
      path: "AGENTS.md",
      code: "retired-authoring-model",
    }));
  });

  it.each([
    ["AGENTS.md", "The rolling vector snapshot is not authoritative for the current draft."],
    ["docs/glossary.md", "Automated publication must not omit NIP-32 attribution."],
    ["AGENTS.md", "Agents must not exploit live third-party systems."],
  ])("permits explicit negation of retired guidance in %s", (path, retiredText) => {
    const issues = lintMaintainedGuides(repositoryRoot, {
      [path]: `${read(path)}\n${retiredText}\n`,
    });
    expect(issues).not.toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it.each([
    "A canonical feed index is not optional.",
    "A canonical feed index MUST exist and MUST NOT expose private identities.",
    "A canonical feed index that is not public remains part of the protocol.",
    "A canonical\n  feed index is not\n  optional.",
    "A canonical feed index is retired and a canonical feed index is not optional.",
    "A canonical-feed index is required.",
    "A canonical feed-index is required.",
    "A canonical-feed-index is required.",
  ])("does not treat unrelated or negative-polarity guide text as retirement", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, {
      [path]: `${read(path)}\n${text}\n`,
    })).toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it.each([
    "The canonical feed index is retired.",
    "A canonical feed index is not required.",
    "A canonical\n  feed index is no longer required.",
    "A canonical-feed index is retired.",
    "A canonical feed-index is not required.",
    "A canonical-feed-index is no longer required.",
    "A bare-key persona is not incomplete without Assurance.",
  ])("permits predicate-local retirement of guide claims", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, {
      [path]: `${read(path)}\n${text}\n`,
    })).not.toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it("rejects negative optionality that affirmatively requires a canonical index", () => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, {
      [path]: "No canonical feed index is optional; implementations MUST provide one.",
    })).toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it("permits a protocol-local negative definition of the retired index", () => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, {
      [path]: "The protocol does not define a canonical feed index.",
    })).not.toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it.each([
    "No canonical feed index exists only for premium users.",
    "No canonical feed index is required to be private; implementations MUST provide one.",
    "The protocol does not define a canonical feed index as optional; implementations MUST provide one.",
    "The canonical feed index is retired only for legacy clients.",
    "A canonical feed index is not required to be private; implementations MUST provide one.",
    "A canonical feed index is no longer required for premium users only.",
    "For premium users, there is no canonical feed index.",
    "For premium users, the protocol does not define a canonical feed index.",
    "For legacy clients, the canonical feed index is retired.",
  ])("rejects qualified predicates that do not retire the canonical index: %s", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  it.each([
    "Context.\nNo canonical feed index exists.",
    "Context.\nNo canonical feed index is required.",
    "For baseline conformance, no canonical feed index exists.",
    "No canonical feed index is required by this protocol.",
    "- For baseline\n  conformance, no canonical-feed index exists.",
    "No canonical feed-index is required\n  by this protocol.",
  ])("permits whitespace-prefixed negative existence or requirement", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .not.toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  it.each([
    "No canonical feed index exists; implementations MUST provide one.",
    "The protocol does not define a canonical feed index; implementations MUST provide one.",
    "The canonical feed index is retired; implementations MUST still provide it.",
    "No canonical-feed-index exists;\n  implementations MUST provide one.",
    "- The canonical feed-index is retired;\n  implementations SHALL still maintain it.",
    "Implementations MUST provide one, no canonical feed index exists.",
    "Implementations MUST preserve it, but no canonical feed index exists.",
    "No canonical feed index exists; implementations **MUST** provide one.",
    "Implementations MUST provide one although there is no canonical feed index.",
    "Implementations MUST provide one although the protocol does not define a canonical feed index.",
    "Implementations MUST provide one although the canonical feed index is retired.",
    "No canonical feed index exists; implementations MUST provide a [canonical feed index](#index).",
    "No canonical feed index exists; implementations [**MUST**](#requirement) provide [one](#index).",
    "No canonical feed index exists; implementations MUST\\\n  provide one.",
    "No canonical feed index exists; implementations MUST retain it for compatibility.",
    "No canonical feed index exists; implementations MUST provide one because legacy clients expect it.",
    "No canonical feed index exists; implementations MUST NOT omit one from responses.",
  ])("does not let a retirement clause exempt another canonical-index requirement: %s", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  it("distinguishes a canonical-index prohibition from a preservation requirement", () => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, {
      [path]: "No canonical feed index exists; implementations MUST NOT provide one.",
    })).not.toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
    expect(lintMaintainedGuides(repositoryRoot, {
      [path]: "No canonical feed index exists; implementations MUST NOT omit one.",
    })).toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it.each([
    "No canonical feed index exists; implementations [MUST] provide one.\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations MUST provide [one].\n\n[one]: #index",
    "No canonical feed index exists; implementations [MuSt] provide one.\n\n[mUsT]: <#requirement>",
    "No canonical feed index exists; implementations [MUST   provide] [one].\n\n[must provide]: #requirement\n[ ONE ]: #index",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n   [must]:   #requirement \"normative\"",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n> [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n- [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n> - [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n> 2. [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n# Heading\n2. [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n2. ```md\ntext\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n<!--\n```md\n-->\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n<!--\n~~~md\n-->\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n~~~md\n<!--\n~~~\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n````md\n<!--\n`````\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n\\<!--\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n`unmatched\n~~~\n~~~\n<!--\n`\n~~~\n-->\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n> `literal\n> <!--`\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n- `literal\n  <!--`\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n> `literal\ntext <!--`\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n- `literal\ntext <!--`\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n1. [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n1. item\n\n   [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n10. item\n\n    [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n-   item\n\n    [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n- paragraph\n\n  2. [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n\\\\<!--\n\n[MUST]: #requirement",
  ])("resolves valid CommonMark shortcut references before classification: %s", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  it.each([
    "No canonical feed index exists; implementations [MUST] provide one.",
    "Implementations **MUST** provide `one`; no canonical-feed-index exists.",
    "No canonical feed index exists; implementations MUST provide `one`.",
    "No canonical feed index exists; `one` remains required.",
    "No canonical feed index exists; implementations MUST provide [one][index].",
    "No canonical feed index exists; implementations [MUST][require] provide one.",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n`a` `b` `c` `d` --> <!--\n~~~\n-->\n[MUST]: #requirement",
    "No canonical feed index exists; example `[MUST] provide one`.\n\n[MUST]: #requirement",
    "No canonical feed index exists; example `MUST provide [one]`.\n\n[one]: #index",
    "No canonical feed index exists; image ![MUST](#badge) provide one.",
    "No canonical feed index exists; image ![MUST] provide one.\n\n[MUST]: #badge",
    "No canonical feed index exists; image ![MUST][badge] provide one.\n\n[badge]: #badge",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n```md\n[MUST]: #requirement\n```",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n~~~\n [MUST]: #requirement\n~~~",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n<!--\n[MUST]: #requirement\n-->",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n- ```md\n  [MUST]: #requirement\n  ```",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n1. ~~~\n   [MUST]: #requirement\n   ~~~",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n```md\ntext ``` still code\n[MUST]: #requirement\n```",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n```md\n- ```\n[MUST]: #requirement\n```",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n~~~md\n> ~~~\n[MUST]: #requirement\n~~~",
    "No canonical feed index exists; example ``[MUST] provide one``.\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n`[MUST]: #requirement`",
    "No canonical feed index exists; implementations [MUST] provide one.\n2. [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n- paragraph\n  2. [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n> 10. item\n    [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n1. item\n   [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n10. item\n    [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n-   item\n    [MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n-     item\n      [MUST]: #requirement",
  ])("does not classify arbitrary brackets, code spans, or image labels: %s", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .not.toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  it.each([
    ["recursive bullets", "- - [MUST]: #requirement"],
    ["quote and recursive bullets", "> - - [MUST]: #requirement"],
    ["recursive ordered lists", "1. 1. [MUST]: #requirement"],
    ["list then quote", "- > [MUST]: #requirement"],
  ])("resolves active %s shortcut definitions", (_name, definition) => {
    const path = "README.md";
    const text = `No canonical feed index exists; implementations [MUST] provide one.\n\n${definition}`;
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  it.each([
    ["bullet", "- item", "  [MUST]: #requirement"],
    ["ordered one", "1. item", "   [MUST]: #requirement"],
    ["ordered ten", "10. item", "    [MUST]: #requirement"],
    ["four-space bullet padding", "-   item", "    [MUST]: #requirement"],
  ])("requires a blank before a definition following %s item text", (
    _name,
    item,
    definition,
  ) => {
    const path = "README.md";
    const prefix = "No canonical feed index exists; implementations [MUST] provide one.";
    expect(lintMaintainedGuides(repositoryRoot, {
      [path]: `${prefix}\n\n${item}\n${definition}`,
    })).not.toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
    expect(lintMaintainedGuides(repositoryRoot, {
      [path]: `${prefix}\n\n${item}\n\n${definition}`,
    })).toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it.each([
    [1, "- "],
    [2, "- - "],
    [4, "- - - - "],
    [16, "- - - - - - - - - - - - - - - - "],
    [17, "- - - - - - - - - - - - - - - - - "],
  ])("fails closed for shortcut definitions at container depth %i", (_depth, containers) => {
    const path = "README.md";
    const text = `No canonical feed index exists; implementations [MUST] provide one.\n\n${containers}[MUST]: #requirement`;
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  it.each([
    "No canonical feed index exists; implementations [MUST] provide one.\n\n- - ```md\n    [MUST]: #requirement\n    ```",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n> - - ~~~\n>     [MUST]: #requirement\n>     ~~~",
  ])("does not activate recursive definitions inside fenced code: %s", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .not.toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  it("fails closed when one maintained guide exceeds the Markdown byte limit", () => {
    const path = "README.md";
    const text = "x".repeat((512 * 1024) + 1);
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        code: "markdown-resource-limit",
      }));
  });

  it("fails closed when the maintained Markdown corpus exceeds its byte limit", () => {
    const paths = [
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
    const overrides = Object.fromEntries(
      paths.map((path) => [path, "x".repeat(170_000)]),
    );
    expect(lintMaintainedGuides(repositoryRoot, overrides))
      .toContainEqual(expect.objectContaining({
        path: "<maintained-guides>",
        code: "markdown-resource-limit",
      }));
  });

  it("fails closed when maintained Markdown exceeds the AST depth limit", () => {
    const path = "README.md";
    const text = `${"> ".repeat(65)}text`;
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        code: "markdown-resource-limit",
      }));
  });

  it("rejects adversarial Markdown depth within a bounded wall time", () => {
    const path = "README.md";
    const text = `${"> ".repeat(100_000)}text`;
    const startedAt = performance.now();
    const result = lintMaintainedGuides(repositoryRoot, { [path]: text });
    const elapsedMilliseconds = performance.now() - startedAt;
    expect(result).toContainEqual(expect.objectContaining({
      path,
      code: "markdown-resource-limit",
    }));
    expect(elapsedMilliseconds).toBeLessThan(2_000);
  }, 5_000);

  it("fails closed when maintained Markdown exceeds the AST node limit", () => {
    const path = "README.md";
    const text = "- x\n".repeat(20_000);
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        code: "markdown-resource-limit",
      }));
  });

  it("reports a retired claim at its CommonMark block start line", () => {
    const path = "README.md";
    const text = [
      "# Context",
      "",
      "> No canonical feed index exists;",
      "> implementations **MUST** provide [one](#index).",
    ].join("\n");
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        line: 3,
        code: "retired-authoring-model",
      }));
  });

  it.each([
    "No canonical feed index exists; implementations `[MUST] provide one``.\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations \\![MUST](#requirement) provide one.",
    "No canonical feed index exists; implementations [MUST] provide one. `<!--`\n\n[MUST]: #requirement",
    "No canonical feed index exists; implementations [MUST] provide one.\n\n> ~~~\n> code\n> ~~~\n\n[MUST]: #requirement",
  ])("keeps unmatched code delimiters and escaped image markers in prose: %s", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  it.each([
    "Implementations MUST provide one signature, but no canonical feed index exists.",
    "Implementations MUST provide one-time proof, but no canonical feed index exists.",
    "Implementations MUST provide one, two, or three signatures, but no canonical feed index exists.",
  ])("does not treat an unrelated one-determiner as a canonical-index reference: %s", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, { [path]: text }))
      .not.toContainEqual(expect.objectContaining({
        path,
        code: "retired-authoring-model",
      }));
  });

  const canonicalSubjectForms = [
    "canonical feed index",
    "canonical-feed index",
    "canonical feed-index",
    "canonical-feed-index",
  ];
  const canonicalRetirementForms = [
    (subject: string) => `no ${subject} exists`,
    (subject: string) => `no ${subject} is required`,
    (subject: string) => `the protocol does not define a ${subject}`,
    (subject: string) => `the ${subject} is retired`,
  ];
  const harmlessCanonicalScopes = [
    (clause: string) => clause,
    (clause: string) => `for baseline conformance, ${clause}`,
    (clause: string) => `${clause} under this protocol`,
  ];

  it("accepts the finite canonical retirement grammar cross product", () => {
    const path = "README.md";
    for (const subject of canonicalSubjectForms) {
      for (const retirement of canonicalRetirementForms) {
        for (const scope of harmlessCanonicalScopes) {
          const clause = scope(retirement(subject));
          for (const text of [
            `${clause}.`,
            `Informational context only; ${clause}.`,
            `${clause}; implementations MUST NOT provide one.`,
            `**${clause}.**`,
          ]) {
            expect(
              lintMaintainedGuides(repositoryRoot, { [path]: text }),
              text,
            ).not.toContainEqual(expect.objectContaining({
              path,
              code: "retired-authoring-model",
            }));
          }
        }
      }
    }
  });

  it("rejects provision across the finite retirement grammar cross product", () => {
    const path = "README.md";
    for (const subject of canonicalSubjectForms) {
      for (const retirement of canonicalRetirementForms) {
        for (const scope of harmlessCanonicalScopes) {
          const clause = scope(retirement(subject));
          for (const text of [
            `${clause}; implementations MUST provide one.`,
            `Implementations MUST provide one although ${clause}.`,
            `${clause}; implementations [MUST][require] preserve [it][index].\n\n[require]: #requirement\n[index]: #index`,
            `${clause}; implementations MUST provide a ${subject}.`,
          ]) {
            expect(
              lintMaintainedGuides(repositoryRoot, { [path]: text }),
              text,
            ).toContainEqual(expect.objectContaining({
              path,
              code: "retired-authoring-model",
            }));
          }
        }
      }
    }
  });

  it("documents the six-document active-key family and frozen snapshot boundary", () => {
    const maintained = [
      "README.md",
      "docs/spec/heterodyne.md",
      "docs/architecture.md",
      "docs/glossary.md",
      "docs/security/threat-model.md",
    ].map(read).join("\n");
    expect(maintained).toMatch(/six[- ]document/i);
    expect(maintained).toMatch(/active Nostr (?:public )?key/i);
    expect(maintained).toMatch(/bare (?:active )?key[\s\S]{0,120}first-class/i);
    expect(maintained).toMatch(/kind `0`[\s\S]{0,160}NIP-05[\s\S]{0,160}NIP-65/i);
    expect(maintained).toMatch(/active (?:persona )?key[\s\S]{0,120}Marmot account/i);
    expect(maintained).toMatch(/source-neutral/i);
    expect(maintained).toMatch(/trusted seeds?[\s\S]{0,180}availability/i);
    expect(maintained).toMatch(/full node[\s\S]{0,180}(?:signer|signing)/i);
    expect(maintained).toMatch(/seven days[\s\S]{0,160}warning/i);
    expect(maintained).toMatch(/compromise[\s\S]{0,180}(?:complete|full) reset/i);
    expect(maintained).toContain("2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43");
    expect(maintained).toContain("5d4bb5fb58b35c88d8a9db120a09f1087237f35c");
  });

  it("documents every document strict profile without a singular family profile", () => {
    const guides = `${read("README.md")}\n${read("docs/glossary.md")}`;
    expect(guides).toContain("heterodyne-assurance-strict-v1");
    expect(guides).not.toMatch(/six[- ]document strict profile/i);
    expect(guides).not.toMatch(/Assurance[\s\S]{0,160}no strict profile/i);
  });

  it("limits the seven-day warning-only rule to kind 0 and kind 10002", () => {
    const registry = loadRegistry(repositoryRoot);
    const description = registry.security_invariants.find(
      ({ id }) => id === "SOCIAL-I-SOURCE-NEUTRAL-SELECTION",
    )?.description;
    expect(description).toMatch(
      /only kind `0` profiles and kind `10002` relay lists[\s\S]*warning-only[\s\S]*every other state[\s\S]*(?:freshness and expiry|expiry and freshness)[\s\S]*fails closed/i,
    );
    expect(read("docs/spec/heterodyne-social.md")).toContain(description);
    expect(read("docs/security/threat-model.md")).toContain(description);
    for (const path of [
      "docs/architecture.md",
      "docs/glossary.md",
      "docs/security/threat-model.md",
      "docs/spec/heterodyne-social.md",
    ]) {
      const text = read(path);
      expect(text).toMatch(/kind `0`[\s\S]{0,100}kind `10002`/i);
      expect(text).toMatch(/other state[\s\S]{0,120}(?:freshness|expiry)[\s\S]{0,120}fail/i);
    }
  });

  it("keeps every future-NIP extraction anchored to a live family section", () => {
    const index = read("docs/spec/extensions/nips/README.md");
    const sources = [
      ["core", "core-identity-discovery"],
      ["assurance", "assurance-reciprocal-enrollment"],
      ["comms", "comms-marmot-event-repository"],
      ["comms", "comms-trusted-seed-private-relay"],
      ["social", "social-moderation"],
      ["social", "social-lists"],
    ] as const;
    for (const [document, anchor] of sources) {
      expect(index).toContain(`heterodyne:0.6.0#${anchor}`);
      expect(read(`docs/spec/heterodyne-${document}.md`))
        .toContain(`<a id="${anchor}"></a>`);
    }
  });

  it("states Social conformance through Core layering and the one family version", () => {
    const social = read("docs/spec/heterodyne-social.md");
    expect(social).not.toMatch(/dependency versions above/i);
    expect(social).toMatch(/Core-defined layering[\s\S]{0,160}same family version/i);
  });

  it("requires every guide to state each profile-revision fact", () => {
    const { revision } = JSON.parse(
      read("docs/spec/registry/manifest.json"),
    ) as { revision: number };
    const currentRegistryRevision = `current family registry revision ${revision}`;
    const guides = ["docs/glossary.md", "docs/security/threat-model.md"];
    const mutations = [
      ["member", (text: string) => text.replace("`profile_revision` has value", "`claim_profile_revision` has value")],
      ["frozen status", (text: string) => text.replace("The frozen claim schema member", "The recorded claim schema member")],
      ["value", (text: string) => text.replace("`profile_revision` has value `2`", "`profile_revision` has value `3`")],
      ["registry distinction", (text: string) => text.replace(
        currentRegistryRevision,
        `current family registry revision ${revision + 1}`,
      )],
    ] as const;

    for (const [, mutate] of mutations) {
      const issues = lintMaintainedGuides(
        repositoryRoot,
        Object.fromEntries(guides.map((path) => [path, mutate(read(path))])),
      );
      expect(issues).toEqual(expect.arrayContaining(guides.map((path) =>
        expect.objectContaining({
          path,
          code: "profile-revision-registry-context-missing",
        }),
      )));
    }
  });

  it("keeps live specifications independent of noncanonical decision records", () => {
    for (const document of ["core", "assurance", "comms", "control", "social", "workspace"]) {
      const text = read(`docs/spec/heterodyne-${document}.md`);
      expect(text).not.toMatch(/docs\/adr|ADR-\d+/);
    }
  });

  it("defines active Marmot Control and optional recovery without legacy carriers", () => {
    const control = read("docs/spec/heterodyne-control.md");
    expect(control).toContain('"can_claim_control_conformance": true');
    expect(control).toContain('"transport_owner": "marmot"');
    expect(control).toMatch(/default is five minutes/i);
    expect(control).toMatch(/Sixty minutes is an[\s\S]*absolute maximum/i);
    expect(control).toMatch(/bare\s+active Nostr key is a complete Control persona/i);
    expect(control).toMatch(/retired recovery prerequisites[\s\S]*not current baseline Control/i);
    expect(control).toMatch(/complete reset\s+closure/i);
  });

  it("contains no retired Control or direct-message wire vocabulary in live specs", () => {
    const text = ["core", "comms", "control", "social", "workspace"]
      .map((document) => read(`docs/spec/heterodyne-${document}.md`))
      .join("\n");
    expect(text).not.toMatch(/kind:31015|kind:31016|kind:1059|kind:1060/i);
    expect(text).not.toMatch(/session-device|ingress-relay|nostr-double-ratchet/i);
  });

  it.each([
    "Require a valid Core/KEL\n  authority result for the issuer.",
    "Current persona epoch or\n  cold-root authority may revoke the claim.",
    "KEL/key\n  revocation is cumulative.",
    "A same-issuer update may be justified by a\n  KEL alias.",
    "The epoch-key NIP-59\n  inbox exists for recovery nodes.",
    "A joining node gets temporary private-repository access only through the\n  optional recovery grants.",
    "The registry contains optional prepared recovery activation, finite\n  recovery grants, and completion receipts.",
    "Repository writers still authenticate against current\n  Core/KERI state.",
    "Private-Radicle recovery and SFTP overflow are optional\n  Control profiles.",
  ])("rejects retired normative Comms authority: %s", (retiredText) => {
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-comms.md",
      retiredText,
    )).toEqual([expect.objectContaining({
      path: "docs/spec/heterodyne-comms.md",
      code: "retired-authoring-model",
    })]);
  });

  it("keeps Comms claims, registry access, and issuer continuity active-key scoped", () => {
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-comms.md",
      read("docs/spec/heterodyne-comms.md"),
    )).toEqual([]);
  });

  it("permits explicit normative retirement of the former authority paths", () => {
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-comms.md",
      "No epoch-key NIP-59 inbox exists. A manifest cannot be justified by a KEL alias. "
        + "KEL/key revocation is not current authority.",
    )).toEqual([]);
  });

  it("rejects baseline KEL/root/epoch requirements but permits explicitly gated Assurance", () => {
    const retired = "A conformant persona MUST have an accepted KEL, epoch key, and cold root.";
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-core.md",
      retired,
    )).toEqual([expect.objectContaining({
      path: "docs/spec/heterodyne-core.md",
      code: "retired-authoring-model",
    })]);
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-core.md",
      `When optional Assurance is claimed, ${retired}`,
    )).toEqual([]);
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-assurance.md",
      retired,
    )).toEqual([]);
  });

  it.each([
    "When optional Assurance is claimed, a persona MUST have an accepted KEL.",
    "When optional\n  Assurance is claimed, a persona MUST have an accepted\n  KEL.",
    "Implementations claiming Assurance, a persona MUST have a cold-\n  root for that Assurance profile.",
    "For the optional Assurance profile, a persona MUST have an accepted KEL.",
    "In an optional Assurance composition, a persona MUST have an epoch key.",
  ])("permits Assurance gating attached to the exact authority assertion", (text) => {
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-core.md",
      text,
    )).toEqual([]);
  });

  it.each([
    "Optional Assurance composition may use recovery material. A conformant persona MUST have an accepted KEL.",
    "Optional Assurance composition may use recovery material; a conformant persona MUST have an epoch key.",
    "When Assurance is claimed, recovery MAY use a KEL.\n  Baseline personas require a cold-\n  root.",
  ])("does not let a separate Assurance clause exempt baseline authority", (text) => {
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-core.md",
      text,
    )).toEqual([expect.objectContaining({
      code: "retired-authoring-model",
    })]);
  });

  it.each([
    "A conformant persona does not require an accepted KEL.",
    "A conformant persona does\n  not require an accepted KEL.",
    "The former requirement that a persona requires a cold root is retired.",
    "No baseline persona requires an epoch-\n  key.",
    "Current persona epoch or cold-root authority is not valid authority.",
    "Current persona\n  epoch or cold-root authority is not valid authority.",
  ])("permits an explicit negation or retirement of baseline authority", (text) => {
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-core.md",
      text,
    )).toEqual([]);
  });

  it.each([
    "A conformant persona MUST have an accepted KEL and MUST NOT expose private key material.",
    "A conformant persona MUST have an accepted KEL that is not public.",
    "A conformant persona MUST have a cold-\n  root and is not required to publish it.",
    "Current persona epoch or cold-root authority is not optional.",
    "Current persona epoch or cold-root authority that is not public remains valid.",
    "A persona requires a KEL is retired and a persona requires a KEL for baseline.",
  ])("does not let unrelated or negative-polarity normative text negate retired authority", (text) => {
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-core.md",
      text,
    )).toEqual([expect.objectContaining({
      code: "retired-authoring-model",
    })]);
  });

  it.each([
    "The statement that a persona requires an accepted KEL is retired.",
    "Current persona epoch or cold-root authority is retired.",
    "Current persona epoch or cold-root authority is no longer valid authority.",
  ])("permits retirement only when it governs the matched authority predicate", (text) => {
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-core.md",
      text,
    )).toEqual([]);
  });

  it.each([
    "There is no canonical feed index.",
    "There is no canonical\n  feed index.",
    "- No canonical feed index exists.",
  ])("permits the exact negated canonical-index retirement probe", (text) => {
    const path = "README.md";
    expect(lintMaintainedGuides(repositoryRoot, {
      [path]: `${read(path)}\n${text}\n`,
    })).not.toContainEqual(expect.objectContaining({
      path,
      code: "retired-authoring-model",
    }));
  });

  it.each([
    "Optional Assurance adds supplemental evidence. A conformant persona MUST have an accepted KEL.",
    "Optional Assurance adds supplemental evidence.\n  A conformant persona MUST have an accepted\n  KEL.",
    "Optional Assurance composition may use recovery material, but a conformant persona MUST have an accepted KEL.",
    "The Assurance profile does not require a KEL, but a conformant persona MUST have an accepted KEL.",
    "Optional Assurance composition may use recovery material,\n  but a conformant persona MUST have an accepted\n  KEL.",
    "The Assurance profile does not require a KEL but a conformant persona MUST have an accepted KEL.",
    "Optional Assurance composition may use recovery material yet a conformant persona MUST have an accepted KEL.",
    "Optional Assurance composition may use recovery material and a conformant persona MUST have an accepted KEL.",
    "Optional Assurance composition may use recovery material, a conformant persona MUST have an accepted KEL.",
  ])("rejects the exact cross-sentence Assurance exemption probe", (text) => {
    expect(findRetiredNormativeClaimIssues(
      "docs/spec/heterodyne-core.md",
      text,
    )).toEqual([expect.objectContaining({
      code: "retired-authoring-model",
    })]);
  });

  it("keeps pairwise claims and direct messages on standard Marmot groups", () => {
    const comms = read("docs/spec/heterodyne-comms.md");
    expect(comms).toMatch(/pairwise-private[\s\S]*two-member Marmot group/i);
    expect(comms).toMatch(/Direct messages[\s\S]*standard[\s\S]*Marmot/i);
    expect(comms).toMatch(/credential continuity drafts[\s\S]*not required by baseline Control/i);
  });

  it("keeps Control-shaped node token semantics out of live Comms prose", () => {
    const comms = read("docs/spec/heterodyne-comms.md");
    expect(comms).not.toContain("comms.node-scoped-jwt.v1");
    expect(comms).not.toContain("A Control token has");
    expect(comms).not.toContain('id="comms-control-token"');

    const agentToken = comms.match(
      /<a id="comms-agent-token"><\/a>[\s\S]*?(?=<a id="comms-agent-attribution"><\/a>)/,
    )?.[0];
    expect(agentToken).toBeDefined();
    expect(agentToken).toMatch(/third-party OIDC/i);
    expect(agentToken).not.toMatch(
      /node-scoped|Marmot|Control|control\.token\.extended|five minutes|sixty minutes|group binding|operation ID/i,
    );
  });

  it("keeps the full-node registry and recovery contract explicit in Core", () => {
    const core = read("docs/spec/heterodyne-core.md");
    expect(core).toMatch(/full-node Control and recovery metadata/i);
    expect(core).toMatch(/light-only Control principal[\s\S]*not a Core device/i);
  });

  it("binds independent-checker refusal codes at their owning Core sections", () => {
    const core = read("docs/spec/heterodyne-core.md");
    const rotation = core.slice(
      core.indexOf('<a id="core-kel-rotation"></a>'),
      core.indexOf('<a id="core-kel-verification"></a>'),
    );
    const verification = core.slice(
      core.indexOf('<a id="core-verification"></a>'),
      core.indexOf('<a id="core-retired-key-observation"></a>'),
    );

    expect(rotation).toContain("successor_persona_mismatch");
    expect(rotation).toContain("retiring_key_nip05_invalid");
    expect(rotation).toContain("compromise_rotation_breadcrumb_forbidden");
    expect(verification).toContain("nip01_raw_mismatch");
  });

  it("closes the follow-up hardening documentation and archive rules", () => {
    const issues = lintFamilyDocs(repositoryRoot);
    expect(issues.filter(({ code }) => [
      "marmot-archive-invalid",
      "generic-repo-relay-server-claim",
      "ambiguous-nostr-wire-key",
      "claim-profile-revision-ambiguous",
      "missing-upstream-kind-allocation",
    ].includes(code))).toEqual([]);
    const kinds = loadRegistry(repositoryRoot).kinds;
    for (const kind of [1059, 22242]) {
      expect(kinds.find((entry) => entry.kind === kind)).toMatchObject({
        allocation_authority: "nostr",
        profiles: [],
      });
    }
  });

  it("derives strict-profile membership from prerequisite closures", () => {
    const documents = Object.fromEntries(
      ["core", "assurance", "comms", "control", "social", "workspace"].map((document) => [
        document,
        read(`docs/spec/heterodyne-${document}.md`),
      ]),
    );
    const invariants = loadRegistry(repositoryRoot).security_invariants;
    expect(findStrictProfileClosureIssues(documents, invariants)).toEqual([]);

    const fixture = (profile: unknown) =>
      `\n<!-- fixture:extra-strict-profile -->\n\`\`\`json\n${JSON.stringify(profile)}\n\`\`\`\n`;
    const withFixture = (profile: unknown, document = "core") =>
      findStrictProfileClosureIssues(
        { ...documents, [document]: documents[document] + fixture(profile) },
        invariants,
      );

    expect(withFixture({
      profile_id: "heterodyne-core-strict-v1",
      requires_profiles: [],
      adds_invariants: ["CORE-I-IDENTITY-INTEGRITY"],
    })).toContain("conflicting strict-profile declaration: heterodyne-core-strict-v1");

    expect(withFixture({
      profile_id: "heterodyne-core-strict-v9",
      requires_profiles: ["heterodyne-core-strict-v8"],
      adds_invariants: [],
    })).toContain(
      "unknown strict-profile prerequisite: heterodyne-core-strict-v9 -> heterodyne-core-strict-v8",
    );

    expect(withFixture({
      profile_id: "heterodyne-core-strict-v9",
      requires_profiles: ["heterodyne-core-strict-v1"],
      adds_invariants: ["CORE-I-IDENTITY-INTEGRITY"],
    })).toContain(
      "redundant added invariant: heterodyne-core-strict-v9 already inherits CORE-I-IDENTITY-INTEGRITY",
    );

    expect(withFixture({
      profile_id: "heterodyne-core-strict-v9",
      requires_profiles: [],
      adds_invariants: ["COMMS-I-TIER3-BLIND-CARRIER"],
    })).toContain(
      "added invariant is not owned by the declaring document: heterodyne-core-strict-v9 -> COMMS-I-TIER3-BLIND-CARRIER",
    );

    expect(withFixture({
      profile_id: "heterodyne-core-strict-v9",
      requires_profiles: [],
      adds_invariants: ["CORE-I-NOT-REGISTERED"],
    })).toContain(
      "unregistered added invariant: heterodyne-core-strict-v9 -> CORE-I-NOT-REGISTERED",
    );

    expect(withFixture({
      profile_id: "heterodyne-control-strict-v9",
      requires_profiles: [],
      adds_invariants: ["CONTROL-I-NIP46-OIDC-ACTIVATION"],
    }, "control")).toContain(
      "feature-bound added invariant: heterodyne-control-strict-v9 -> CONTROL-I-NIP46-OIDC-ACTIVATION"
        + " is bound to control.nip46-oidc-signing.v1",
    );
  });

  it("closes the 0.6 Assurance, Comms, and Workspace strict profiles", () => {
    expect(strict("heterodyne-assurance-strict-v1").requires_profiles)
      .toEqual(["heterodyne-core-strict-v1"]);
    expect(strict("heterodyne-assurance-strict-v1").adds_invariants)
      .toContain("ASSURANCE-I-ENROLLMENT-WINDOWED");
    expect(strict("heterodyne-comms-strict-v1").adds_invariants)
      .toContain("COMMS-I-TIER3-CONFINED");
    expect(strict("heterodyne-workspace-strict-v1").adds_invariants)
      .toContain("WORKSPACE-I-OPTIONAL-ASSURANCE");
    expect(strict("heterodyne-workspace-strict-v1").adds_invariants)
      .not.toContain("WORKSPACE-I-GOVERNANCE-ASSURED");
  });

  it("scopes every invariant to baseline or one feature its own document owns", () => {
    const registry = loadRegistry(repositoryRoot);
    const features = new Set(registry.features.map(({ id }) => id));
    for (const { id, owner, feature } of registry.security_invariants) {
      if (feature === undefined) continue;
      expect(features).toContain(feature);
      expect(feature.startsWith(`${owner}.`)).toBe(true);
      expect(id.startsWith(`${owner.toUpperCase()}-I-`)).toBe(true);
    }
    // Baseline is what an implementation owes for merely claiming the document,
    // so the OIDC, status, claim, and agent stacks must all be feature-bound.
    const baseline = registry.security_invariants
      .filter(({ feature }) => feature === undefined)
      .map(({ id }) => id);
    expect(baseline).not.toContain("COMMS-I-ISSUER-CONTINUITY");
    expect(baseline).not.toContain("COMMS-I-CLAIM-RELEASE");
    expect(baseline).not.toContain("COMMS-I-STATUS-INTEGRITY");
    expect(baseline).not.toContain("COMMS-I-AGENT-ATTRIBUTION");
    expect(baseline).toContain("COMMS-I-TIER3-BLIND-CARRIER");
  });

  it("requires the OIDC issuer only through the features that need it", () => {
    const features = new Map(
      loadRegistry(repositoryRoot).features.map((entry) => [entry.id, entry]),
    );
    const requires = (id: string, target: string): boolean => {
      const entry = features.get(id);
      if (entry === undefined) return false;
      return entry.prerequisites.some(
        (prerequisite) => prerequisite === target || requires(prerequisite, target),
      );
    };
    const oidc = "comms.oidc-jwt-projection.v1";
    expect(requires("comms.agent-authorship.v1", oidc)).toBe(true);
    expect(features.has("control.oauth-device-enrollment.v1")).toBe(false);
    expect(requires("control.nip46-oidc-signing.v1", oidc)).toBe(true);
    // The token is a projection of the OIDC-authorized signer grant, so the
    // current feature closure intentionally retains that prerequisite.
    expect(requires("control.node-scoped-token.v1", oidc)).toBe(true);
    expect(features.has("comms.node-scoped-jwt.v1")).toBe(false);
    expect(requires("comms.marmot-conversations.v1", oidc)).toBe(false);
    expect(requires("comms.public-reader.v1", oidc)).toBe(false);
  });
});

describe("registry-bound artifacts", () => {
  it("pins one registry revision and digest in exactly one place", () => {
    const registry = loadRegistry(repositoryRoot);
    expect(registry.manifest.entry_set_sha256).toMatch(/^[0-9a-f]{64}$/);
    for (const document of ["core", "comms", "control", "social", "workspace"]) {
      expect(read(`docs/spec/heterodyne-${document}.md`))
        .not.toMatch(/^Registry revision:/m);
    }
  });

  it("retains historical registry introductions alongside the current family version", () => {
    const registry = loadRegistry(repositoryRoot);
    const versions = new Set([
      ...registry.kinds.map(({ first_version }) => first_version),
      ...registry.kinds.flatMap(({ profiles }) =>
        profiles.map(({ first_version }) => first_version)),
      ...registry.reason_codes.map(({ first_version }) => first_version),
      ...registry.security_invariants.map(({ first_version }) => first_version),
      ...registry.features.map(({ first_version }) => first_version),
      ...registry.objects.map(({ first_version }) => first_version),
      ...registry.proof_domains.map(({ first_version }) => first_version),
    ]);
    expect([...versions].sort()).toEqual([
      "heterodyne/0.5.0",
      "heterodyne/0.6.0",
    ]);
  });

  it("resolves every feature prerequisite within the registry", () => {
    const registry = loadRegistry(repositoryRoot);
    const byId = new Map(registry.features.map((entry) => [entry.id, entry]));
    for (const feature of registry.features) {
      for (const prerequisite of feature.prerequisites) {
        expect(byId.has(prerequisite)).toBe(true);
      }
    }
  });

  it("mirrors every registered invariant exactly in the threat model", () => {
    const registry = loadRegistry(repositoryRoot);
    expect(findInvariantEvidenceIssues(
      registry.security_invariants,
      read("docs/security/threat-model.md"),
    )).toEqual([]);
  });

  it("mirrors every Assurance invariant in both its owner document and threat model", () => {
    const invariants = loadRegistry(repositoryRoot).security_invariants;
    const assurance = invariants
      .filter(({ owner }) => owner === "assurance");
    expect(assurance.length).toBeGreaterThan(0);
    expect(findInvariantEvidenceIssues(
      invariants,
      read("docs/spec/heterodyne-assurance.md"),
    ).filter((issue) => issue.startsWith("missing invariant evidence: ASSURANCE-")))
      .toEqual([]);
    expect(findInvariantEvidenceIssues(
      invariants,
      read("docs/security/threat-model.md"),
    ).filter((issue) => issue.startsWith("missing invariant evidence: ASSURANCE-")))
      .toEqual([]);
  });
});
