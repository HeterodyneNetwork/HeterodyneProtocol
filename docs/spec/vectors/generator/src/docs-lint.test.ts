import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { lintFamilyDocs } from "./docs-lint.js";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, "../../../../../");
const corePath = resolve(repositoryRoot, "docs/spec/heterodyne-core.md");

function withFamilyDocs(
  documents: Partial<Record<"core" | "comms" | "control" | "social", string>>,
  run: (root: string) => void,
): void {
  const root = mkdtempSync(resolve(tmpdir(), "heterodyne-docs-lint-"));
  const spec = resolve(root, "docs/spec");
  mkdirSync(spec, { recursive: true });
  try {
    for (const [document, text] of Object.entries(documents)) {
      writeFileSync(resolve(spec, `heterodyne-${document}.md`), text, "utf8");
    }
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("protocol family documents", () => {
  it("keeps Heterodyne Core on its extraction boundary", () => {
    const text = readFileSync(corePath, "utf8");

    expect(text).toContain("Document ID: `core`");
    expect(text).toContain("Version: `core/0.5.0`");
    expect(text).toContain("Registry revision: `1`");
    expect(text).not.toMatch(
      /normative[^\n]*(heterodyne-comms|heterodyne-control|heterodyne-social)/i,
    );
    expect(text).not.toMatch(
      /follow|mutual follow|friend|Matrix identity-room cache/i,
    );
  });

  it("retains the Core KEL and delegation verification requirements", () => {
    const text = readFileSync(corePath, "utf8");

    expect(text).toMatch(
      /`scheme` MUST be one of `bip340`, `did:key`, or `atproto`/,
    );
    expect(text).toMatch(/scheme\/identifier mismatch MUST be rejected/);
    expect(text).toMatch(
      /empty `valid_until` means no expiry[\s\S]*strictly greater than the evaluation clock/,
    );
  });

  it("retains the closed rotation content schema and degraded export label", () => {
    const text = readFileSync(corePath, "utf8");

    expect(text).toMatch(
      /rotation event `content` MUST be the compact UTF-8 JSON[\s\S]*`spec_version`[\s\S]*`receipts`/,
    );
    expect(text).toMatch(
      /missing, duplicate, or unknown[\s\S]*top-level member[\s\S]*MUST be rejected/,
    );
    expect(text).toMatch(/MUST NOT be labeled complete/);
  });

  it("keeps deny-until-repo key material out of provisional acceptance", () => {
    const text = readFileSync(corePath, "utf8");

    expect(text).toMatch(
      /Under `deny-until-repo`[\s\S]*MUST return `reject` with reason `provisional_not_final`/,
    );
    expect(text).not.toMatch(
      /reason `provisional_not_final`[\s\S]{0,240}maps to[\s\S]*`accept_provisional`/,
    );
  });

  it("retains operator consent and exact materialized-KEL atomicity", () => {
    const text = readFileSync(corePath, "utf8");

    expect(text).toMatch(
      /MUST NOT enable an export AID[\s\S]*operator[\s\S]*consent/,
    );
    expect(text).toMatch(/inception[\s\S]*log commit is parentless/);
    expect(text).toMatch(/empty accepted KEL MUST[\s\S]*delete both refs/);
    expect(text).toMatch(/MUST NOT claim this profile/);
    expect(text).toMatch(
      /Readers MUST verify that both tips[\s\S]*same accepted KEL head/,
    );
  });

  it("defines a closed legacy owner-inference mapping", () => {
    const text = readFileSync(corePath, "utf8");

    expect(text).toContain("Closed legacy owner-inference table");
    expect(text).toContain("`31000`, `31001`, `31002`, `31003`, `31005`, `31010`");
    expect(text).toContain("`31007`, `31011`, `31012`");
    expect(text).toContain("`31004`, `31008`, `31009`");
    expect(text).toMatch(/No legacy kind maps to Control/);
  });

  it("accepts resolved qualified references along the allowed DAG", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          "Normative dependencies: None.",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        comms: [
          "Document ID: `comms`",
          "Normative dependencies: `heterodyne:core/0.5.0#core-identity-model`.",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) => expect(lintFamilyDocs(root)).toEqual([]),
    );
  });

  it("reports duplicate anchors with the duplicate line", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          '<a id="core-identity-model"></a>',
          "text",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-core.md",
            line: 4,
            code: "duplicate-anchor",
          }),
        ),
    );
  });

  it("reports unresolved qualified anchors", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        comms: [
          "Document ID: `comms`",
          "See `heterodyne:core/0.5.0#core-missing`.",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-comms.md",
            line: 2,
            code: "unresolved-reference",
          }),
        ),
    );
  });

  it("resolves an anchor only in the referenced document", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          "See `heterodyne:core/0.5.0#social-shared-name`.",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        social: [
          "Document ID: `social`",
          '<a id="social-shared-name"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-core.md",
            line: 2,
            code: "unresolved-reference",
          }),
        ),
    );
  });

  it("reports forbidden normative dependency edges", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          "Normative dependencies: `heterodyne:comms/0.5.0#comms-envelope`.",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        comms: [
          "Document ID: `comms`",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-core.md",
            line: 2,
            code: "forbidden-dependency",
          }),
        ),
    );
  });

  it("reports a forbidden Core body reference carrying normative force", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          "Core MUST implement `heterodyne:comms/0.5.0#comms-envelope`.",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        comms: [
          "Document ID: `comms`",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-core.md",
            line: 2,
            code: "forbidden-dependency",
          }),
        ),
    );
  });

  it("reports a forbidden Social body reference to Control", () => {
    withFamilyDocs(
      {
        control: [
          "Document ID: `control`",
          '<a id="control-enrollment"></a>',
        ].join("\n"),
        social: [
          "Document ID: `social`",
          "This profile SHALL use `heterodyne:control/0.5.0#control-enrollment`.",
          '<a id="social-profile"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-social.md",
            line: 2,
            code: "forbidden-dependency",
          }),
        ),
    );
  });

  it("reports forbidden edges in wrapped dependency declarations", () => {
    withFamilyDocs(
      {
        control: [
          "Document ID: `control`",
          '<a id="control-enrollment"></a>',
        ].join("\n"),
        social: [
          "Document ID: `social`",
          "Normative dependencies:",
          "- `heterodyne:control/0.5.0#control-enrollment`",
          '<a id="social-profile"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-social.md",
            line: 3,
            code: "forbidden-dependency",
          }),
        ),
    );
  });

  it("reports a wrapped dependency list after blank lines", () => {
    withFamilyDocs(
      {
        control: [
          "Document ID: `control`",
          '<a id="control-enrollment"></a>',
        ].join("\n"),
        social: [
          "Document ID: `social`",
          "Normative dependencies:",
          "",
          "",
          "- `heterodyne:control/0.5.0#control-enrollment`",
          '<a id="social-profile"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-social.md",
            line: 5,
            code: "forbidden-dependency",
          }),
        ),
    );
  });

  it("ends wrapped dependency force after the dependency list", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        control: [
          "Document ID: `control`",
          '<a id="control-enrollment"></a>',
        ].join("\n"),
        social: [
          "Document ID: `social`",
          "Normative dependencies:",
          "",
          "- `heterodyne:core/0.5.0#core-identity-model`",
          "",
          "Background references:",
          "- `heterodyne:control/0.5.0#control-enrollment`",
          '<a id="social-profile"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(
          lintFamilyDocs(root).filter(
            (issue) => issue.code === "forbidden-dependency",
          ),
        ).toEqual([]),
    );
  });

  it("does not carry normative force into an adjacent informative bullet", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          "- Core MUST validate its local state.",
          "- Background: `heterodyne:comms/0.5.0#comms-envelope`.",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        comms: [
          "Document ID: `comms`",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(
          lintFamilyDocs(root).filter(
            (issue) => issue.code === "forbidden-dependency",
          ),
        ).toEqual([]),
    );
  });

  it("keeps continuation lines in the same normative bullet", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          "- Core MUST validate its local state using",
          "  `heterodyne:comms/0.5.0#comms-envelope`.",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        comms: [
          "Document ID: `comms`",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-core.md",
            line: 3,
            code: "forbidden-dependency",
          }),
        ),
    );
  });

  it("does not carry normative force into an adjacent informative table row", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          "| Rule | Detail |",
          "|---|---|",
          "| Core MUST validate state | Locally |",
          "| Background | `heterodyne:comms/0.5.0#comms-envelope` |",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        comms: [
          "Document ID: `comms`",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(
          lintFamilyDocs(root).filter(
            (issue) => issue.code === "forbidden-dependency",
          ),
        ).toEqual([]),
    );
  });

  it("reports bare relative normative cross-document links", () => {
    withFamilyDocs(
      {
        comms: [
          "Document ID: `comms`",
          "This is normatively defined by [Core](heterodyne-core.md#identity-model).",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-comms.md",
            line: 2,
            code: "bare-normative-link",
          }),
        ),
    );
  });

  it("recognizes SHOULD, MAY, and OPTIONAL as normative link contexts", () => {
    withFamilyDocs(
      {
        comms: [
          "Document ID: `comms`",
          "A client SHOULD use [Core](heterodyne-core.md#core-identity-model).",
          "",
          "A client MAY use [Core](./heterodyne-core.md#core-identity-model).",
          "",
          "This [Core](heterodyne-core.md#core-identity-model) behavior is OPTIONAL.",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) => {
        const issues = lintFamilyDocs(root).filter(
          (issue) => issue.code === "bare-normative-link",
        );
        expect(issues.map((issue) => issue.line)).toEqual([2, 4, 6]);
      },
    );
  });

  it("does not infer an edge from explicitly nonnormative prose", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          "Nonnormative background: `heterodyne:comms/0.5.0#comms-envelope`.",
          '<a id="core-identity-model"></a>',
        ].join("\n"),
        comms: [
          "Document ID: `comms`",
          '<a id="comms-envelope"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(
          lintFamilyDocs(root).filter(
            (issue) => issue.code === "forbidden-dependency",
          ),
        ).toEqual([]),
    );
  });
});
