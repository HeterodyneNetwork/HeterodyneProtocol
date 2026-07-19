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
const commsPath = resolve(repositoryRoot, "docs/spec/heterodyne-comms.md");

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

  it("keeps Heterodyne Comms on its Thin-P1 extraction boundary", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toContain("Document ID: `comms`");
    expect(text).toContain("Version: `comms/0.5.0`");
    expect(text).toContain("Registry revision: `1`");
    expect(text).toContain(
      "heterodyne:core/0.5.0#core-conformance",
    );
    expect(text).not.toMatch(
      /normative[^\n]*(heterodyne-control|heterodyne-social)/i,
    );
    expect(text).not.toMatch(/follow.*gate|web-of-trust.*gate/i);
    expect(text).not.toMatch(/NIP-51.*core construct/i);
  });

  it("defines the authenticated Comms acceptance hook", () => {
    const text = readFileSync(commsPath, "utf8");

    for (const outcome of ["accept", "hold-as-message-request", "reject"]) {
      expect(text).toContain(outcome);
    }
    for (const context of [
      "ordinary-dm",
      "credential-sync",
      "control-enrollment",
    ]) {
      expect(text).toContain(context);
    }
    expect(text).toMatch(
      /cryptographic checks[\s\S]*before[\s\S]*acceptance policy/i,
    );
    expect(text).toMatch(
      /hold-as-message-request[\s\S]*MUST NOT[\s\S]*(receipt|sender-observable)/,
    );
  });

  it("retains the double-ratchet no-repository and no-backfill boundary", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toContain("heterodyne-comms-double-ratchet-invite-v1");
    expect(text).toContain(
      "heterodyne-comms-double-ratchet-invite-response-v1",
    );
    expect(text).toContain("heterodyne-comms-double-ratchet-message-v1");
    expect(text).toMatch(/`kind:1060`[\s\S]*MUST NOT[\s\S]*repo/i);
    expect(text).toMatch(/double-ratchet[\s\S]*no backfill/i);
    expect(text).toMatch(/MUST delete[\s\S]*message key/i);
  });

  it("retains privacy-tier honesty and org-threshold authorization", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(
      /Tier 2[\s\S]*MUST NOT[\s\S]*(encrypted|end-to-end encrypted)/i,
    );
    expect(text).toMatch(
      /Tier 3[\s\S]*encrypted before[\s\S]*(repository|full node|seed)/i,
    );
    expect(text).toMatch(
      /org-owned[\s\S]*posts[\s\S]*feed indexes[\s\S]*threshold/i,
    );
    expect(text).toMatch(/lone[\s\S]*epoch-key[\s\S]*MUST NOT/i);
  });

  it("defines credential-sync and generic subprotocol negotiation", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(
      /credential-sync[\s\S]*target NID[\s\S]*purpose[\s\S]*KEL[\s\S]*revoc/i,
    );
    expect(text).toMatch(/NID-less session device[\s\S]*MUST[\s\S]*reject/i);
    for (const field of [
      "protocol_id",
      "supported_versions",
      "required_features",
    ]) {
      expect(text).toContain(field);
    }
    expect(text).toContain("comms-subprotocol-negotiation-v1");
    expect(text).toContain("comms-subprotocol-payload-v1");
    expect(text).toMatch(
      /negotiat[\s\S]*before[\s\S]*payload[\s\S]*interpret/i,
    );
    expect(text).toMatch(/local audit records/);
    expect(text).toMatch(/Control[\s\S]*MUST NOT[\s\S]*wire stamp/i);
  });

  it("binds all registered Comms security invariants", () => {
    const text = readFileSync(commsPath, "utf8");

    for (const invariant of [
      "COMMS-I-TIER3-BLIND-CARRIER",
      "COMMS-I-TIER2-HONESTY",
      "COMMS-I-CONFIG-AT-REST",
      "COMMS-I-CLIENT-SIDE-DELIVERY",
      "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
    ]) {
      expect(text).toContain(invariant);
    }
  });

  it("closes Tier 3 wrapping to registered stamping profiles and integrity tags", () => {
    const text = readFileSync(commsPath, "utf8");

    for (const kind of [1, 6, 16, 1063, 30023, 30402]) {
      expect(text).toContain(
        `heterodyne-comms-tier3-wrapped-content-kind-${kind}-v1`,
      );
    }
    expect(text).toMatch(
      /other upstream kind[\s\S]*MUST NOT[\s\S]*`room_key\.v2`/i,
    );
    expect(text).toMatch(
      /Tier 3 post[\s\S]*`kel_head`[\s\S]*exactly[\s\S]*Core/i,
    );
    expect(text).toMatch(
      /`spec_version`[\s\S]*`comms\/0\.5\.0`[\s\S]*stamping profile/i,
    );
  });

  it("defines complete closed unsigned carrier-rumor wire forms", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(/`content` MUST be a JSON string/i);
    expect(text).toMatch(/object-valued `content` MUST be rejected/i);
    expect(text).toMatch(/unsigned Nostr rumor[\s\S]*`id`[\s\S]*`pubkey`/i);
    expect(text).toMatch(
      /`created_at`[\s\S]*`kind`[\s\S]*`tags`[\s\S]*`content`[\s\S]*MUST NOT include `sig`/i,
    );
    expect(text).toMatch(
      /a missing,[\s\S]*duplicate, unknown, misordered, or wrongly typed[\s\S]*MUST[\s\S]*rejected/i,
    );
    expect(text).toMatch(/SHA-256[\s\S]*NIP-01 serialization[\s\S]*`id`/i);
  });

  it("makes the config authorization ledger authoritative and deterministic", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(/authoritative authorization ledger/i);
    expect(text).toMatch(/inside the encrypted private config repository/i);
    expect(text).toMatch(/keyed by[\s\S]*`authorization_id`[\s\S]*target NID/i);
    expect(text).toMatch(/revoke wins[\s\S]*exact-time tie/i);
    expect(text).toMatch(/Before any credential transfer, the source MUST sync/i);
    expect(text).toMatch(/verify canonical[\s\S]*config-repository state/i);
    expect(text).toMatch(/offline device[\s\S]*discover[\s\S]*revocation/i);
    expect(text).toMatch(/self-DM[\s\S]*MUST NOT[\s\S]*authorit/i);
  });

  it("defines a total Comms-native acceptance decision table", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(/established locally accepted[\s\S]*`accept`/i);
    expect(text).toMatch(/new `ordinary-dm`[\s\S]*`hold-as-message-request`/i);
    expect(text).toMatch(
      /`credential-sync`[\s\S]*`accept` iff[\s\S]*authoritative ledger/i,
    );
    expect(text).toMatch(
      /current state[\s\S]*cannot be established[\s\S]*`hold-as-message-request`/i,
    );
    expect(text).toMatch(
      /invalid, revoked, expired, mismatched, or NID-less[\s\S]*`reject`/i,
    );
    expect(text).toMatch(/`control-enrollment`[\s\S]*`hold-as-message-request`/i);
  });

  it("retains DR lifecycle, audience rotation, and vanilla fallback", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(/empty-content replacement[\s\S]*tombstone/i);
    expect(text).toMatch(/out-of-band invite[\s\S]*URL fragment/i);
    expect(text).toMatch(/delegation expires or is revoked/);
    expect(text).toMatch(/active peers MUST stop[\s\S]*sending/);
    expect(text).toMatch(/vanilla[\s\S]*MUST[\s\S]*NIP-17 fallback/i);
    expect(text).toMatch(
      /member addition MUST publish a replacing `kind:31012` under the same\s+`key_id`/i,
    );
    expect(text).toMatch(
      /member removal[\s\S]*republish[\s\S]*encrypted index[\s\S]*60 seconds/i,
    );
  });

  it("retains tier-specific publication and exact retrieval metadata", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(/Tier 1[\s\S]*ordinary relays[\s\S]*repo relay/i);
    expect(text).toMatch(
      /Tier 2[\s\S]*private[\s\S]*MUST NOT[\s\S]*public relay/i,
    );
    expect(text).toMatch(/Tier 3[\s\S]*ciphertext[\s\S]*ordinary[\s\S]*repo/i);
    expect(text).toMatch(/`retrieval_hints\.archive_url`/);
    expect(text).toMatch(/`<nostr_event_id>`[\s\S]*`\?id=<nostr_event_id>`/);
    expect(text).toMatch(/known_relays[\s\S]*union[\s\S]*NIP-65[\s\S]*relay hints/i);
    expect(text).toMatch(/NIP-13[\s\S]*PERMANENT/);
    expect(text).toMatch(/plaintext[\s\S]*may persist[\s\S]*every node/i);
  });

  it("retains exact public and private feed-index addressing", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toContain('["d", "<feed_id>:<page_id>"]');
    expect(text).toContain('["previous_index", "<event_id>"]');
    expect(text).toContain('["prev_page_hash", "<hex-sha256>"]');
    expect(text).toMatch(
      /Tier 3[\s\S]*opaque `d`[\s\S]*128 bits[\s\S]*(random|keyed)/i,
    );
    expect(text).toContain("retrieval_hints");
    expect(text).toContain("feed_label");
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
