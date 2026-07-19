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
import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import { lintFamilyDocs } from "./docs-lint.js";
import { hexToBytes, utf8Bytes } from "./hex.js";
import { verifyEventSignature, type NostrSignedEvent } from "./nostr.js";
import { loadRegistry, resolveStampingProfile } from "./registry.js";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, "../../../../../");
const corePath = resolve(repositoryRoot, "docs/spec/heterodyne-core.md");
const commsPath = resolve(repositoryRoot, "docs/spec/heterodyne-comms.md");
const controlPath = resolve(repositoryRoot, "docs/spec/heterodyne-control.md");
const socialPath = resolve(repositoryRoot, "docs/spec/heterodyne-social.md");
const threatModelPath = resolve(repositoryRoot, "docs/security/threat-model.md");
const companionPaths = [
  "README.md",
  "CLAUDE.md",
  "AGENTS.md",
  "docs/architecture.md",
  "docs/glossary.md",
  "docs/security/threat-model.md",
  "research/INDEX.md",
  "docs/spec/extensions/nips/README.md",
  "docs/spec/extensions/mscs/README.md",
] as const;
const preCutoverCompanionPaths = [...companionPaths, "CHANGELOG.md"] as const;
const adr030Path = resolve(
  repositoryRoot,
  "docs/adr/2026-07-07-030-light-client-enrollment-rpc-over-dr-dms.md",
);
const adr031Path = resolve(
  repositoryRoot,
  "docs/adr/2026-07-07-031-vanilla-nostr-breadcrumbs-and-interop.md",
);

type CredentialRecordProbe = {
  authorizationId: string;
  targetNid: string;
  action: "grant" | "revoke";
  issuedAt: number;
  validUntil: number;
  signedDigest: string;
};

function hasValidAuthorizationIdHistoryProbe(
  records: readonly CredentialRecordProbe[],
): boolean {
  const uniqueRecords = [
    ...new Map(records.map((record) => [record.signedDigest, record])).values(),
  ];
  const grants = uniqueRecords.filter((record) => record.action === "grant");
  if (grants.length !== 1) return false;
  const [grant] = grants;
  return uniqueRecords.every(
    (record) =>
      record.authorizationId === grant.authorizationId &&
      record.targetNid === grant.targetNid &&
      (record.action === "grant" || record.issuedAt > grant.issuedAt),
  );
}

function resolveCredentialProbe(
  records: readonly CredentialRecordProbe[],
  now: number,
): "grant" | "revoke" | "inactive" | "invalid" {
  if (!hasValidAuthorizationIdHistoryProbe(records)) return "invalid";
  if (records.some((record) => record.action === "revoke")) return "revoke";
  const representative = records
    .filter((record) => record.action === "grant")
    .sort(
      (left, right) =>
        right.issuedAt - left.issuedAt ||
        left.signedDigest.localeCompare(right.signedDigest),
    )[0];
  return representative.validUntil > now ? "grant" : "inactive";
}

function canonicalRecordDigestsProbe(
  records: readonly CredentialRecordProbe[],
): string[] {
  return [
    ...new Map(records.map((record) => [record.signedDigest, record])).values(),
  ]
    .sort(
      (left, right) =>
        left.authorizationId.localeCompare(right.authorizationId) ||
        left.targetNid.localeCompare(right.targetNid) ||
        left.issuedAt - right.issuedAt ||
        left.action.localeCompare(right.action) ||
        left.signedDigest.localeCompare(right.signedDigest),
    )
    .map((record) => record.signedDigest);
}

function ledgerDigestProbe(
  records: readonly CredentialRecordProbe[],
  _evaluationTime: number,
): string {
  return createHash("sha256")
    .update(JSON.stringify(canonicalRecordDigestsProbe(records)), "utf8")
    .digest("hex");
}

function rotationPreservesCompleteRecordSetProbe(
  predecessor: readonly CredentialRecordProbe[],
  successor: readonly CredentialRecordProbe[],
  claimedPredecessorDigest: string,
  evaluationTime: number,
): boolean {
  if (ledgerDigestProbe(predecessor, evaluationTime) !== claimedPredecessorDigest) {
    return false;
  }
  const successorSet = new Set(canonicalRecordDigestsProbe(successor));
  return canonicalRecordDigestsProbe(predecessor).every((recordDigest) =>
    successorSet.has(recordDigest),
  );
}

function negotiationAllowsPayloadProbe(
  processed: ReadonlySet<"offer" | "selection" | "confirmation">,
): boolean {
  return (
    processed.has("offer") &&
    processed.has("selection") &&
    processed.has("confirmation")
  );
}

type SocialPolicyOutcome = "accept" | "hold-as-message-request" | "reject";

function approvalCountsProbe(input: {
  indexed: boolean;
  signatureValid: boolean;
  moderatorAuthorizedAtAnchor: boolean;
  requiredAnchorPresent: boolean;
  deleted: boolean;
}): boolean {
  return (
    input.indexed &&
    input.signatureValid &&
    input.moderatorAuthorizedAtAnchor &&
    input.requiredAnchorPresent &&
    !input.deleted
  );
}

function declaredDependencies(text: string): string[] {
  const declaration = text.match(
    /Normative dependencies:\n\n((?:- `heterodyne:[^`]+`\n?)+)/,
  );
  if (!declaration) return [];
  return [...declaration[1].matchAll(/- `(heterodyne:[^`]+)`/g)].map(
    (match) => match[1],
  );
}

function allocationTable(
  text: string,
  heading: string,
): Record<string, string> {
  const start = text.indexOf(heading);
  if (start < 0) return {};
  const remainder = text.slice(start + heading.length);
  const nextHeading = remainder.search(/^## /m);
  const section = nextHeading < 0 ? remainder : remainder.slice(0, nextHeading);
  const rows: Record<string, string> = {};
  for (const line of section.split("\n")) {
    if (!line.startsWith("|")) continue;
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((cell) => cell.trim());
    if (
      cells.length !== 2 ||
      cells[0] === "Family document" ||
      /^-+$/.test(cells[0])
    ) {
      continue;
    }
    rows[cells[0].replaceAll("`", "")] = cells[1];
  }
  return rows;
}

function sectionUnderHeading(text: string, heading: string): string {
  const start = text.indexOf(heading);
  if (start < 0) return "";
  const remainder = text.slice(start + heading.length);
  const nextHeading = remainder.search(/^## /m);
  return nextHeading < 0 ? remainder : remainder.slice(0, nextHeading);
}

function jsonBlockUnderAnchor<T>(text: string, anchor: string): T {
  const start = text.indexOf(`<a id="${anchor}"></a>`);
  if (start < 0) throw new Error(`missing anchor:${anchor}`);
  const match = text.slice(start).match(/```json\n([\s\S]*?)\n```/);
  if (!match) throw new Error(`missing JSON block under anchor:${anchor}`);
  return JSON.parse(match[1]) as T;
}

function matchesReservedSessionDeviceDiscriminator(event: ExampleEvent): boolean {
  const names = new Set(event.tags.map((tag) => tag[0]));
  return (
    tagValues(event, "heterodyne").some((tag) => tag[1] === "delegation") &&
    names.has("binding_nonce") &&
    names.has("key_proof") &&
    !names.has("radicle_nid")
  );
}

function fixtureFromMarkdown<T>(text: string, name: string): T {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = text.match(
    new RegExp(`<!-- fixture:${escaped} -->\\s*\\x60\\x60\\x60json\\n([\\s\\S]*?)\\n\\x60\\x60\\x60`),
  );
  if (!match) throw new Error(`missing fixture:${name}`);
  return JSON.parse(match[1]) as T;
}

type ExampleEvent = {
  id?: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig?: string;
};

function tagValues(event: ExampleEvent, name: string): string[][] {
  return event.tags.filter((tag) => tag[0] === name);
}

function hasValidNostrSignature(event: ExampleEvent): boolean {
  if (!event.id || !event.sig) return false;
  try {
    return verifyEventSignature(event as NostrSignedEvent);
  } catch {
    return false;
  }
}

function validateOrgFeedExample(
  event: ExampleEvent,
  tier: 1 | 2 | 3,
  registry: ReturnType<typeof loadRegistry>,
): string[] {
  const errors: string[] = [];
  const exactContent =
    '{"profile":"heterodyne.social.org-feed.v1","spec_version":"social/0.5.0"}';
  let parsedContent: unknown;
  try {
    parsedContent = JSON.parse(event.content);
  } catch {
    parsedContent = null;
  }
  const discriminator =
    parsedContent && typeof parsedContent === "object"
      ? `content.profile=${String((parsedContent as { profile?: unknown }).profile)}`
      : "";
  const profile = resolveStampingProfile(registry, event.kind, discriminator);
  if (event.kind !== 31007) errors.push("kind");
  if (profile?.profile_id !== "heterodyne-social-org-feed-v1") {
    errors.push("profile");
  }
  if (tier === 3) errors.push("tier3-forbidden");
  if (event.content !== exactContent) errors.push("content");
  if (tagValues(event, "d").length !== 1 || !tagValues(event, "d")[0][1]?.includes(":")) {
    errors.push("d");
  }
  if (tagValues(event, "heterodyne")[0]?.[1] !== "feed_index") errors.push("heterodyne");
  for (const required of ["cold_root", "kel_head"]) {
    if (tagValues(event, required).length !== 1) errors.push(required);
  }
  const rid = tagValues(event, "rid");
  if (rid.length > 1 || (rid.length === 1 && !rid[0][1])) errors.push("rid");
  const previous = tagValues(event, "previous_index");
  const previousHash = tagValues(event, "prev_page_hash");
  if ((previous.length === 1) !== (previousHash.length === 1)) errors.push("paging-pair");
  if (tagValues(event, "e").length > 500) errors.push("page-size");
  if (tagValues(event, "spec_version").length !== 0) errors.push("version-tag");
  if (tagValues(event, "heterodyne_wrap").length !== 0 || tagValues(event, "key_id").length !== 0) {
    errors.push("tier3-tags");
  }
  return [...new Set(errors)].sort();
}

type RelatedPairFixture = {
  left: ExampleEvent;
  right: ExampleEvent;
  kel_authority?: {
    left: { cold_root: string; accepted_head: string; authorized_epoch_key: string };
    right: { cold_root: string; accepted_head: string; authorized_epoch_key: string };
  };
};

function validateRelatedPairStructure(pair: RelatedPairFixture): string[] {
  const errors: string[] = [];
  const relationOf = (event: ExampleEvent) => tagValues(event, "relation")[0]?.[1];
  const otherOf = (event: ExampleEvent) => tagValues(event, "other_npub")[0]?.[1];
  const rootOf = (event: ExampleEvent) => tagValues(event, "cold_root")[0]?.[1];
  const scopeOf = (event: ExampleEvent) => tagValues(event, "scope")[0]?.[1];
  const expectedReverse: Record<string, string> = {
    endorses: "endorsed_by",
    endorsed_by: "endorses",
    same_holder: "same_holder",
    linked: "linked",
  };
  for (const event of [pair.left, pair.right]) {
    const relation = relationOf(event);
    const other = otherOf(event);
    if (event.kind !== 31004) errors.push("kind");
    if (
      tagValues(event, "relation").length !== 1 ||
      tagValues(event, "other_npub").length !== 1 ||
      tagValues(event, "d").length !== 1 ||
      !relation ||
      !other ||
      tagValues(event, "d")[0]?.[1] !== `${relation}:${other}`
    ) {
      errors.push("d-binding");
    }
    if (
      tagValues(event, "heterodyne").length !== 1 ||
      tagValues(event, "heterodyne")[0]?.[1] !== "related_persona" ||
      tagValues(event, "spec_version").length !== 1 ||
      tagValues(event, "spec_version")[0]?.[1] !== "social/0.5.0" ||
      tagValues(event, "cold_root").length !== 1 ||
      tagValues(event, "kel_head").length !== 1 ||
      event.content !== "" ||
      !event.id ||
      !event.sig
    ) {
      errors.push("proof");
    }
    if (tagValues(event, "scope").length > 1) errors.push("scope");
  }
  if (otherOf(pair.left) !== rootOf(pair.right) || otherOf(pair.right) !== rootOf(pair.left)) {
    errors.push("cross-binding");
  }
  if (expectedReverse[relationOf(pair.left)] !== relationOf(pair.right)) errors.push("relation-pair");
  if (scopeOf(pair.left) !== scopeOf(pair.right)) errors.push("scope");
  if (
    pair.left.pubkey === pair.right.pubkey ||
    rootOf(pair.left) === rootOf(pair.right) ||
    tagValues(pair.left, "kel_head")[0]?.[1] === tagValues(pair.right, "kel_head")[0]?.[1]
  ) {
    errors.push("independent-signers");
  }
  return [...new Set(errors)].sort();
}

function validateRelatedPairCryptography(pair: RelatedPairFixture): string[] {
  const errors: string[] = [];
  for (const [side, event] of [["left", pair.left], ["right", pair.right]] as const) {
    const authority = pair.kel_authority?.[side];
    if (
      !authority ||
      authority.cold_root !== tagValues(event, "cold_root")[0]?.[1] ||
      authority.accepted_head !== tagValues(event, "kel_head")[0]?.[1] ||
      authority.authorized_epoch_key !== event.pubkey ||
      !hasValidNostrSignature(event)
    ) {
      errors.push("proof");
    }
  }
  if (pair.left.id === pair.right.id || pair.left.sig === pair.right.sig) {
    errors.push("independent-signers");
  }
  return [...new Set(errors)].sort();
}

type MatrixStateFixture = {
  type: string;
  state_key: string;
  sender?: string;
  origin_server_ts?: number;
  content: Record<string, unknown>;
};

type StrictProfileFixture = {
  profile_id: string;
  conformance_class: string;
  state: "active" | "reserved-inactive";
  requires_profiles: string[];
  required_invariants: string[];
  matrix_obligations?: string[];
};

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return JSON.stringify(Object.keys(value)) === JSON.stringify(keys);
}

function validateCapabilityBootstrap(content: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const supported = content.supported_versions as Record<string, unknown> | undefined;
  if (content.descriptor !== "heterodyne-capabilities-v1") errors.push("descriptor");
  if (content.bootstrap_version !== "core/0.5.0") errors.push("bootstrap-version");
  if (content.registry_revision !== 1) errors.push("registry-revision");
  if (!supported || !exactKeys(supported, ["core", "comms", "control", "social"])) {
    errors.push("document-set");
  } else {
    if (JSON.stringify(supported.core) !== JSON.stringify(["core/0.5.0"])) errors.push("core-support");
    if (JSON.stringify(supported.comms) !== JSON.stringify(["comms/0.5.0"])) errors.push("comms-support");
    if (JSON.stringify(supported.control) !== JSON.stringify([])) errors.push("control-support");
    if (JSON.stringify(supported.social) !== JSON.stringify(["social/0.5.0"])) errors.push("social-support");
  }
  if (!Array.isArray(content.required_features)) errors.push("required-features");
  if (!Array.isArray(content.strict_profiles)) errors.push("strict-profiles");
  return [...new Set(errors)].sort();
}

function matrixTailAcceptsFromFixture(
  flip: MatrixStateFixture,
  event: { origin_server_ts: number; pre_flip_session: boolean; member_at_flip: boolean },
): boolean {
  if (typeof flip.origin_server_ts !== "number") return false;
  const delta = event.origin_server_ts - flip.origin_server_ts;
  return delta >= 0 && delta <= 60_000 && event.pre_flip_session && event.member_at_flip;
}

type AtprotoFixture = {
  nostr_event: ExampleEvent;
  pds_record: {
    collection: string;
    rkey: string;
    value: Record<string, unknown>;
    algorithm: string;
    public_key: string;
    signed_payload_hash: string;
    signature: string;
  };
  matrix_mirror: MatrixStateFixture;
};

function validateAtprotoFixture(fixture: AtprotoFixture): string[] {
  const errors: string[] = [];
  const payload = fixture.pds_record.value;
  if (fixture.pds_record.collection !== "social.heterodyne.identityLink") errors.push("collection");
  if (fixture.pds_record.rkey !== "self") errors.push("rkey");
  if (fixture.nostr_event.kind !== 31009 || fixture.nostr_event.content !== JSON.stringify(payload)) {
    errors.push("shared-payload");
  }
  const canonicalPayload = JSON.stringify(payload);
  const payloadHash = sha256(utf8Bytes(canonicalPayload));
  const payloadHashHex = Buffer.from(payloadHash).toString("hex");
  if (
    !hasValidNostrSignature(fixture.nostr_event)
  ) {
    errors.push("nostr-signature");
  }
  let didSignatureValid = false;
  if (
    fixture.pds_record.algorithm === "Ed25519" &&
    fixture.pds_record.signed_payload_hash === payloadHashHex &&
    typeof fixture.pds_record.signature === "string" &&
    typeof fixture.pds_record.public_key === "string"
  ) {
    try {
      didSignatureValid = ed25519.verify(
        hexToBytes(fixture.pds_record.signature),
        payloadHash,
        hexToBytes(fixture.pds_record.public_key),
      );
    } catch {
      didSignatureValid = false;
    }
  }
  if (!didSignatureValid) {
    errors.push("atproto-signature");
  }
  if (tagValues(fixture.nostr_event, "d")[0]?.[1] !== payload.did) errors.push("did-binding");
  if (tagValues(fixture.nostr_event, "cold_root")[0]?.[1] !== payload.npub) errors.push("npub-binding");
  const matrixAttestation = fixture.matrix_mirror.content.atproto_attestation as
    | Record<string, unknown>
    | undefined;
  if (
    fixture.matrix_mirror.state_key !== payload.did ||
    fixture.matrix_mirror.content.did !== payload.did ||
    fixture.matrix_mirror.sender !== fixture.matrix_mirror.content.mxid ||
    fixture.matrix_mirror.content.binding_payload !== fixture.nostr_event.content ||
    matrixAttestation?.alg !== fixture.pds_record.algorithm ||
    matrixAttestation?.public_key !== fixture.pds_record.public_key ||
    matrixAttestation?.sig !== fixture.pds_record.signature ||
    matrixAttestation?.signed_payload_hash !== fixture.pds_record.signed_payload_hash
  ) {
    errors.push("matrix-binding");
  }
  return [...new Set(errors)].sort();
}

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
    expect(text).toMatch(/record[\s\S]*identified by its signed bytes/i);
    expect(text).toMatch(/revocation is absorbing/i);
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

  it("makes credential revocation an absorbing permanent tombstone", () => {
    const text = readFileSync(commsPath, "utf8");
    const grant: CredentialRecordProbe = {
      authorizationId: "00".repeat(16),
      targetNid: "did:key:zTarget",
      action: "grant",
      issuedAt: 10,
      validUntil: 20,
      signedDigest: "11".repeat(32),
    };
    const revoke: CredentialRecordProbe = {
      ...grant,
      action: "revoke",
      issuedAt: 15,
      validUntil: 0,
      signedDigest: "22".repeat(32),
    };
    const reusedGrant: CredentialRecordProbe = {
      ...grant,
      issuedAt: 30,
      validUntil: 100,
      signedDigest: "33".repeat(32),
    };

    expect(hasValidAuthorizationIdHistoryProbe([grant, revoke])).toBe(true);
    expect(resolveCredentialProbe([grant, revoke], 40)).toBe("revoke");
    expect(hasValidAuthorizationIdHistoryProbe([grant, revoke, reusedGrant])).toBe(false);
    expect(resolveCredentialProbe([grant, revoke, reusedGrant], 40)).toBe("invalid");
    expect(text).toMatch(/revoke[\s\S]*`valid_until`[\s\S]*`0`[\s\S]*permanent/i);
    expect(text).toMatch(/tombstone[\s\S]*MUST NOT expire/i);
    expect(text).toMatch(/new grant[\s\S]*authorization_id[\s\S]*not previously used/i);
    expect(text).toMatch(/revoke[\s\S]*reuse[\s\S]*grant[\s\S]*ID[\s\S]*target/i);
    expect(text).toMatch(/records[\s\S]*unique[\s\S]*signed[\s\S]*(digest|bytes)/i);
  });

  it("hashes and migrates the complete time-independent signed-record set", () => {
    const text = readFileSync(commsPath, "utf8");
    const expiredGrant: CredentialRecordProbe = {
      authorizationId: "00".repeat(16),
      targetNid: "did:key:zExpired",
      action: "grant",
      issuedAt: 10,
      validUntil: 20,
      signedDigest: "11".repeat(32),
    };
    const liveGrant: CredentialRecordProbe = {
      authorizationId: "aa".repeat(16),
      targetNid: "did:key:zLive",
      action: "grant",
      issuedAt: 12,
      validUntil: 100,
      signedDigest: "22".repeat(32),
    };
    const revoke: CredentialRecordProbe = {
      ...liveGrant,
      action: "revoke",
      issuedAt: 18,
      validUntil: 0,
      signedDigest: "33".repeat(32),
    };
    const predecessor = [expiredGrant, liveGrant, revoke];
    const beforeExpiry = ledgerDigestProbe(predecessor, 19);
    const afterExpiry = ledgerDigestProbe(predecessor, 21);

    expect(afterExpiry).toBe(beforeExpiry);
    expect(canonicalRecordDigestsProbe(predecessor)).toContain(expiredGrant.signedDigest);
    expect(
      rotationPreservesCompleteRecordSetProbe(
        predecessor,
        [liveGrant, revoke],
        afterExpiry,
        21,
      ),
    ).toBe(false);
    expect(
      rotationPreservesCompleteRecordSetProbe(
        predecessor,
        predecessor,
        afterExpiry,
        21,
      ),
    ).toBe(true);
    expect(text).toContain("predecessor_ledger_digest");
    expect(text).toMatch(/complete canonical[\s\S]*signed-record set/i);
    expect(text).toMatch(/MUST include expired grants/i);
    expect(text).toMatch(/independent of[\s\S]*evaluation time/i);
    expect(text).toMatch(/operational[\s\S]*explicit evaluation time/i);
    expect(text).toMatch(/Before a config[\s\S]*rotation retires/i);
    expect(text).toMatch(/new branch MUST[\s\S]*atomically commit/i);
    expect(text).toMatch(/refuse[\s\S]*credential transfer/i);
  });

  it("keeps tier publication and encrypted retrieval hints coherent", () => {
    const text = readFileSync(commsPath, "utf8");
    const intro = text.slice(
      text.indexOf('<a id="comms-feed-index">'),
      text.indexOf('<a id="comms-org-authorization">'),
    );

    expect(intro).not.toMatch(/published to ordinary relays and its repo relay/);
    expect(intro).toMatch(/Tier 1 and Tier 2[\s\S]*empty `content`/i);
    expect(intro).toMatch(/Tier 3[\s\S]*`content` MUST be ciphertext/i);
    expect(text).toMatch(/Tier 3 index[\s\S]*MUST[\s\S]*ordinary relays[\s\S]*repo relay/i);
    expect(text).toContain("max(3, ceil(len(known_relays) * 0.5))");
    expect(text).toMatch(
      /decrypted payload[\s\S]*optional `retrieval_hints`/i,
    );
    expect(text).toMatch(
      /Relay-visible tags MUST NOT[\s\S]*`retrieval_hints`/i,
    );
  });

  it("requires mutual negotiation confirmation before payload", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(
      negotiationAllowsPayloadProbe(new Set(["offer", "selection"])),
    ).toBe(false);
    expect(
      negotiationAllowsPayloadProbe(
        new Set(["offer", "selection", "confirmation"]),
      ),
    ).toBe(true);
    expect(text).toMatch(/initiator[\s\S]*offer[\s\S]*normative preference/i);
    expect(text).toMatch(/responder[\s\S]*first\s+offered exact version/i);
    expect(text).toMatch(/selection[\s\S]*confirm[\s\S]*tuple[\s\S]*hash/i);
    expect(text).toMatch(/MUST NOT accept[\s\S]*`kind:31016`[\s\S]*confirmation/i);
  });

  it("requires fresh-generation continuation and remembered truncation", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(
      /every subsequent post, index, and descriptor[\s\S]*fresh[\s\S]*`key_id`/i,
    );
    expect(text).toMatch(/MUST persist[\s\S]*across process[\s\S]*restart/i);
    expect(text).toContain(
      "feed truncated after `<created_at-of-referring-page>` / `<d-tag-of-referring-page>`; missing `<event_id>`",
    );
    expect(text).toMatch(
      /persist[\s\S]*predecessor event id[\s\S]*referring-page locator[\s\S]*process[\s\S]*restart/i,
    );
  });

  it("declares Control as an incomplete Comms profile with an exact dependency contract", () => {
    const text = readFileSync(controlPath, "utf8");
    const metadata = fixtureFromMarkdown<{
      document_id: string;
      version: string;
      status: string;
      conformance_expression: string;
      direct_dependencies: string[];
      supported_comms_versions: string[];
      required_comms_features: string[];
      transport_owner: string;
      wire_stamp_owner: string | null;
    }>(text, "control-profile-metadata");

    expect(metadata).toEqual({
      document_id: "control",
      version: "control/0.5.0",
      status: "incomplete 0.5.0 draft",
      conformance_expression: "Core + Comms conformant + Control profile",
      direct_dependencies: ["heterodyne:comms/0.5.0#comms-conformance"],
      supported_comms_versions: ["comms/0.5.0"],
      required_comms_features: ["double-ratchet"],
      transport_owner: "comms",
      wire_stamp_owner: null,
    });
    expect(declaredDependencies(text)).toEqual([
      "heterodyne:comms/0.5.0#comms-conformance",
    ]);
  });

  it("keeps the registered non-stamping session-device profile reserved and inactive", () => {
    const text = readFileSync(controlPath, "utf8");
    const coreText = readFileSync(corePath, "utf8");
    const registry = loadRegistry(repositoryRoot);
    const delegation = registry.kinds.find((entry) => entry.kind === 31001);
    const profile = delegation?.profiles.find(
      (entry) =>
        entry.discriminator ===
        "tags:heterodyne=delegation,binding_nonce,key_proof;radicle_nid=absent",
    );

    expect(delegation?.base_schema_owner).toBe("core");
    expect(profile).toMatchObject({
      profile_id: "heterodyne-control-session-device-v1",
      owner: "control",
      stamping: false,
      first_version: "control/0.5.0",
    });
    const coreEvent = jsonBlockUnderAnchor<ExampleEvent>(
      coreText,
      "core-nid-delegation",
    );
    expect(coreEvent.kind).toBe(31001);
    expect(tagValues(coreEvent, "d")[0]?.[1]).toMatch(/^nid:/);
    expect(tagValues(coreEvent, "radicle_nid")).toHaveLength(1);
    expect(tagValues(coreEvent, "nid_proof")).toHaveLength(1);
    expect(matchesReservedSessionDeviceDiscriminator(coreEvent)).toBe(false);

    const reservation = fixtureFromMarkdown<{
      profile_id: string;
      registry_status: string;
      profile_state: string;
      current_core_compatible: boolean;
      conforming_events_allowed: boolean;
      activation_requires: string[];
    }>(text, "control-session-device-reservation");
    expect(reservation).toEqual({
      profile_id: "heterodyne-control-session-device-v1",
      registry_status: "draft",
      profile_state: "reserved-inactive",
      current_core_compatible: false,
      conforming_events_allowed: false,
      activation_requires: [
        "adr-030-accepted",
        "future-core-kind-31001-subtype-amendment",
        "control-vectors-and-registry-integration-gate",
      ],
    });
    expect(text).toMatch(/current Core[\s\S]*does not accept[\s\S]*discriminator/i);
    expect(text).toMatch(/no event may claim conformance[\s\S]*profile/i);
    expect(text).toMatch(/ownership[\s\S]*stamp intention[\s\S]*does not\s+make it active/i);
    expect(text).not.toContain("heterodyne:core/");
    expect(text).toMatch(/Control MUST NOT[\s\S]*wire stamp/i);
    expect(text).not.toMatch(/control\/0\.5\.0.*stamp/i);
  });

  it("requires the exact registered Comms double-ratchet profile set", () => {
    const text = readFileSync(controlPath, "utf8");
    const registry = loadRegistry(repositoryRoot);
    const required = [
      "heterodyne-comms-double-ratchet-invite-v1",
      "heterodyne-comms-double-ratchet-invite-response-v1",
      "heterodyne-comms-double-ratchet-message-v1",
    ];
    const registered = registry.kinds
      .flatMap((entry) => entry.profiles)
      .filter((profile) => required.includes(profile.profile_id))
      .map((profile) => profile.profile_id)
      .sort();

    expect(registered).toEqual([...required].sort());
    for (const profileId of required) expect(text).toContain(profileId);
  });

  it("keeps the Control conformance gate closed until ADR-030 integration and vectors", () => {
    const text = readFileSync(controlPath, "utf8");
    const gate = fixtureFromMarkdown<{
      can_claim_control_conformance: boolean;
      blockers: string[];
    }>(text, "control-conformance-gate");

    expect(gate).toEqual({
      can_claim_control_conformance: false,
      blockers: [
        "adr-030-accepted",
        "adr-030-integrated",
        "minimum-control-vectors",
      ],
    });
    expect(text).toContain("no Control conformance claim");
    expect(text).toMatch(/negotiated Control version[\s\S]*audit/i);
    for (const invariant of [
      "CONTROL-I-AUDIT-AT-REST",
      "CONTROL-I-SESSION-KEY-CONFINEMENT",
    ]) {
      expect(text).toContain(invariant);
    }
  });

  it("amends ADR-030 with the exact Core, Comms, and Control allocation", () => {
    const text = readFileSync(adr030Path, "utf8");
    const rows = allocationTable(text, "## Family-allocation amendment (2026-07-19)");

    expect(Object.keys(rows)).toEqual(["Core", "Comms", "Control"]);
    expect(rows.Core).toMatch(/session-device base extensibility/i);
    expect(rows.Comms).toMatch(
      /epoch-key invite[\s\S]*undelegated initiator[\s\S]*DR contexts[\s\S]*negotiation/i,
    );
    expect(rows.Control).toMatch(
      /enrollment[\s\S]*RPC[\s\S]*grants[\s\S]*tokens[\s\S]*MCP/i,
    );
    expect(text).toMatch(
      /session devices[\s\S]*MUST NOT\s+receive[\s\S]*epoch[\s\S]*NID[\s\S]*audience[\s\S]*ratchet/i,
    );
    expect(text).toMatch(
      /authorized durable NID devices[\s\S]*credential-plane synchronization/i,
    );
    const amendment = sectionUnderHeading(
      text,
      "## Family-allocation amendment (2026-07-19)",
    );
    expect(amendment).toContain("heterodyne:core/0.5.0#core-nid-delegation");
    expect(amendment).toContain("heterodyne:comms/0.5.0#comms-direct-messages");
    expect(amendment).not.toMatch(/docs\/spec\/heterodyne\.md|§[0-9]/);
    expect(text).toMatch(/unqualified `§/);
    expect(text).toMatch(/historical[\s\S]*frozen 0\.4\.0 monolith/i);
  });

  it("keeps ADR-030 on unsigned generic Comms carriers without dedicated Control kinds", () => {
    const text = readFileSync(adr030Path, "utf8");

    expect(text).toMatch(/session device\s+key signs the enrollment `key_proof`/i);
    expect(text).toMatch(/participates in Comms DR wire\s+authentication/i);
    expect(text).toMatch(/Control RPC inner rumors are unsigned/i);
    expect(text).toMatch(
      /authenticated by the accepted DR session, transcript, and carrier\s+validation/i,
    );
    expect(text).toMatch(/single generic Comms[\s\S]*kind:31015[\s\S]*kind:31016/i);
    expect(text).toMatch(
      /negotiated Control\s+protocol[\s\S]*method[\s\S]*direction[\s\S]*capabilities/i,
    );
    expect(text).not.toMatch(/signs only[\s\S]{0,180}RPC requests/i);
    expect(text).not.toMatch(/separate kinds|both rumor families|dedicated Control kind/i);
  });

  it("amends ADR-031 with Core breadcrumb and Social interop ownership", () => {
    const text = readFileSync(adr031Path, "utf8");
    const rows = allocationTable(text, "## Family-allocation amendment (2026-07-19)");

    expect(Object.keys(rows)).toEqual(["Core", "Social"]);
    expect(rows.Core).toMatch(/production[\s\S]*verification exclusion/i);
    expect(rows.Social).toMatch(/vanilla[\s\S]*follow[\s\S]*UI/i);
    expect(text).toContain("heterodyne-core-rotation-breadcrumb-profile-v1");
    expect(text).toContain("heterodyne-core-rotation-breadcrumb-note-v1");
    expect(text).toMatch(/both profiles[\s\S]*non-stamping/i);
    const amendment = sectionUnderHeading(
      text,
      "## Family-allocation amendment (2026-07-19)",
    );
    expect(amendment).toContain("heterodyne:core/0.5.0#core-version-stamps");
    expect(amendment).toContain("heterodyne:social/0.5.0#social-following");
    expect(amendment).not.toMatch(/docs\/spec\/heterodyne\.md|§[0-9]/);
    expect(text).toMatch(/unqualified `§/);
    expect(text).toMatch(/historical[\s\S]*frozen 0\.4\.0 monolith/i);
  });

  it("declares the exact Social dependency set and Matrix-free claim", () => {
    const text = readFileSync(socialPath, "utf8");

    expect(text).toContain("Document ID: `social`");
    expect(text).toContain("Version: `social/0.5.0`");
    expect(text).toContain("Registry revision: `1`");
    expect(declaredDependencies(text)).toEqual([
      "heterodyne:core/0.5.0#core-conformance",
      "heterodyne:comms/0.5.0#comms-conformance",
    ]);
    expect(text).not.toContain("heterodyne:control/");
    expect(text).toMatch(/Matrix-free implementation[\s\S]*fully Social-conformant/i);
    expect(text).toMatch(/distinct[\s\S]*`Social`[\s\S]*`Social\+Matrix`[\s\S]*claims/i);
  });

  it("keeps Matrix-free Social behavior complete", () => {
    const text = readFileSync(socialPath, "utf8");

    expect(text).toMatch(/replies[\s\S]*reactions[\s\S]*thread/i);
    expect(text).toMatch(/following[\s\S]*transitive[\s\S]*discovery/i);
    expect(text).toMatch(/cross-persona[\s\S]*advertisement/i);
    expect(text).toMatch(/reply inbox/i);
    expect(text).toMatch(/mixed-tier[\s\S]*fan-out/i);
    expect(text).toMatch(/NIP-72[\s\S]*Radicle editorial/i);
    expect(text).toMatch(/starter pack[\s\S]*ATProto/i);
    expect(text).toMatch(/None of these[\s\S]*require Matrix/i);
  });

  it("binds Social wire profiles and leaves plain NIP-51 unstamped", () => {
    const text = readFileSync(socialPath, "utf8");
    const registry = loadRegistry(repositoryRoot);
    const muteProfile = resolveStampingProfile(
      registry,
      10000,
      "tag:heterodyne=social-mute-list-v1",
    );
    const orgProfile = resolveStampingProfile(
      registry,
      31007,
      "content.profile=heterodyne.social.org-feed.v1",
    );

    expect(muteProfile).toMatchObject({
      profile_id: "heterodyne-social-mute-list-v1",
      owner: "social",
      stamping: true,
      first_version: "social/0.5.0",
    });
    expect(orgProfile).toMatchObject({
      profile_id: "heterodyne-social-org-feed-v1",
      owner: "social",
      stamping: true,
      first_version: "social/0.5.0",
    });
    expect(resolveStampingProfile(registry, 10000, "")).toBeNull();

    expect(text).toContain("heterodyne-social-mute-list-v1");
    expect(text).toContain("tag:heterodyne=social-mute-list-v1");
    expect(text).toContain('["heterodyne", "social-mute-list-v1"]');
    expect(text).toContain('["spec_version", "social/0.5.0"]');
    expect(text).toMatch(/plain upstream NIP-51[\s\S]*MUST remain unstamped/i);
    expect(text).toMatch(/ordinary Social NIP-51[\s\S]*public dual-backend carrier/i);
    expect(text).toMatch(/NIP-44-encrypted to self[\s\S]*publishable event/i);
    expect(text).toMatch(/MUST NOT imply Tier 2/i);
    expect(text).toMatch(/existence[\s\S]*size[\s\S]*encrypted config repository/i);
    expect(text).toContain("heterodyne-social-org-feed-v1");
    expect(text).toContain("content.profile=heterodyne.social.org-feed.v1");
  });

  it("validates the complete Social org-feed profile event and rejects incompatible forms", () => {
    const text = readFileSync(socialPath, "utf8");
    const registry = loadRegistry(repositoryRoot);
    const event = fixtureFromMarkdown<ExampleEvent>(text, "social-org-feed-index");

    expect(validateOrgFeedExample(event, 1, registry)).toEqual([]);
    expect(validateOrgFeedExample(event, 2, registry)).toEqual([]);
    expect(
      validateOrgFeedExample(
        { ...event, tags: event.tags.filter((tag) => tag[0] !== "rid") },
        1,
        registry,
      ),
    ).toEqual([]);
    expect(
      validateOrgFeedExample(
        { ...event, tags: [...event.tags, ["rid", "rad:zDuplicate"]] },
        1,
        registry,
      ),
    ).toContain("rid");
    expect(validateOrgFeedExample({ ...event, content: "" }, 1, registry)).toContain("content");
    expect(
      validateOrgFeedExample(
        { ...event, tags: [...event.tags, ["spec_version", "comms/0.5.0"]] },
        1,
        registry,
      ),
    ).toContain("version-tag");
    expect(
      validateOrgFeedExample(
        {
          ...event,
          content:
            '{"profile":"heterodyne.social.org-feed.v1","spec_version":"social/0.5.0","extra":true}',
        },
        1,
        registry,
      ),
    ).toContain("content");
    expect(validateOrgFeedExample(event, 3, registry)).toContain("tier3-forbidden");
    expect(
      validateOrgFeedExample(
        { ...event, tags: [...event.tags, ["heterodyne_wrap", "room_key.v2"], ["key_id", "opaque"]] },
        3,
        registry,
      ),
    ).toEqual(expect.arrayContaining(["tier3-forbidden", "tier3-tags"]));
  });

  it("implements Social admission only as a tighten-only Comms hook", () => {
    const text = readFileSync(socialPath, "utf8");
    const lattice = fixtureFromMarkdown<Record<SocialPolicyOutcome, SocialPolicyOutcome[]>>(
      text,
      "social-acceptance-lattice",
    );

    expect(lattice).toEqual({
      accept: ["accept", "hold-as-message-request", "reject"],
      "hold-as-message-request": ["hold-as-message-request", "reject"],
      reject: ["reject"],
    });
    expect(lattice.reject).not.toContain("hold-as-message-request");
    expect(lattice.reject).not.toContain("accept");
    expect(lattice["hold-as-message-request"]).not.toContain("accept");

    expect(text).toContain("heterodyne:comms/0.5.0#comms-acceptance-hook");
    expect(text).toMatch(/mute[\s\S]*web-of-trust[\s\S]*tighten/i);
    expect(text).toMatch(/MUST NOT[\s\S]*(loosen|convert)[\s\S]*`reject`/i);
    expect(text).toMatch(/MUST NOT[\s\S]*bypass[\s\S]*cryptographic/i);
    expect(text).toMatch(/hold-as-message-request[\s\S]*no[\s\S]*receipt/i);
  });

  it("binds generic Core recovery roles only inside Social", () => {
    const text = readFileSync(socialPath, "utf8");
    const duties = fixtureFromMarkdown<Record<string, string>>(
      text,
      "social-recovery-cache-duties",
    );

    expect(duties).toEqual({
      follower: "may",
      "mutual-follow": "should",
      "declared-witness": "must",
    });

    expect(text).toContain("heterodyne:core/0.5.0#core-recovery");
    expect(text).toMatch(/recovery peers[\s\S]*follows[\s\S]*mutual follows[\s\S]*friends/i);
    expect(text).toMatch(/Matrix identity-room cache/i);
    expect(text).toMatch(/advisory[\s\S]*MUST NOT[\s\S]*replace[\s\S]*(cold-root|Core)/i);
  });

  it("validates exact cross-persona pair binding", () => {
    const text = readFileSync(socialPath, "utf8");
    const pair = fixtureFromMarkdown<RelatedPairFixture>(text, "related-persona-pair");

    expect(validateRelatedPairStructure(pair)).toEqual([]);
    expect(validateRelatedPairCryptography(pair)).toEqual([]);
    expect(
      validateRelatedPairCryptography({
        ...pair,
        left: { ...pair.left, sig: `${pair.left.sig?.slice(0, -2)}00` },
      }),
    ).toContain("proof");
    expect(
      validateRelatedPairCryptography({
        ...pair,
        kel_authority: pair.kel_authority
          ? {
              ...pair.kel_authority,
              left: {
                ...pair.kel_authority.left,
                authorized_epoch_key: pair.right.pubkey,
              },
            }
          : undefined,
      }),
    ).toContain("proof");
    for (const symmetric of ["same_holder", "linked"] as const) {
      const symmetricPair: RelatedPairFixture = {
        left: {
          ...pair.left,
          tags: pair.left.tags.map((tag) =>
            tag[0] === "relation"
              ? ["relation", symmetric]
              : tag[0] === "d"
                ? ["d", `${symmetric}:${tagValues(pair.left, "other_npub")[0][1]}`]
                : tag,
          ),
        },
        right: {
          ...pair.right,
          tags: pair.right.tags.map((tag) =>
            tag[0] === "relation"
              ? ["relation", symmetric]
              : tag[0] === "d"
                ? ["d", `${symmetric}:${tagValues(pair.right, "other_npub")[0][1]}`]
                : tag,
          ),
        },
      };
      expect(validateRelatedPairStructure(symmetricPair)).toEqual([]);
    }
    expect(
      validateRelatedPairStructure({
        ...pair,
        right: {
          ...pair.right,
          tags: pair.right.tags.map((tag) =>
            tag[0] === "other_npub" ? ["other_npub", "ff".repeat(32)] : tag,
          ),
        },
      }),
    ).toContain("cross-binding");
    expect(
      validateRelatedPairStructure({
        ...pair,
        right: {
          ...pair.right,
          tags: pair.right.tags.map((tag) =>
            tag[0] === "relation" ? ["relation", "endorses"] : tag,
          ),
        },
      }),
    ).toContain("relation-pair");
    expect(
      validateRelatedPairCryptography({
        ...pair,
        right: { ...pair.right, sig: pair.left.sig },
      }),
    ).toContain("independent-signers");
    expect(
      validateRelatedPairStructure({
        ...pair,
        right: {
          ...pair.right,
          tags: pair.right.tags.map((tag) =>
            tag[0] === "scope" ? ["scope", "different"] : tag,
          ),
        },
      }),
    ).toContain("scope");
  });

  it("retains the complete optional Matrix security boundary", () => {
    const text = readFileSync(socialPath, "utf8");

    expect(text).toMatch(/MXID delegation[\s\S]*epoch-key[\s\S]*self-publication/i);
    expect(text).toMatch(/active-room election[\s\S]*publish lease[\s\S]*failover/i);
    expect(text).toMatch(/wrapped[\s\S]*bare[\s\S]*nip01_raw/i);
    expect(text).toMatch(/private_discussion[\s\S]*Megolm[\s\S]*MLS/i);
    expect(text).toMatch(/encrypted state[\s\S]*downgrade/i);
    expect(text).toMatch(/headless bridge[\s\S]*user-controlled/i);
    expect(text).toMatch(/homeserver[\s\S]*MUST NOT[\s\S]*plaintext/i);
    expect(text).toMatch(/vanilla Matrix[\s\S]*fallback/i);
  });

  it("parses the complete Matrix encryption and MLS migration schemas", () => {
    const text = readFileSync(socialPath, "utf8");
    const baseline = fixtureFromMarkdown<MatrixStateFixture>(text, "matrix-encryption-megolm");
    const capabilities = fixtureFromMarkdown<MatrixStateFixture>(text, "matrix-mls-capabilities");
    const intent = fixtureFromMarkdown<MatrixStateFixture>(text, "matrix-mls-intent");
    const ack = fixtureFromMarkdown<MatrixStateFixture>(text, "matrix-mls-ack");
    const abort = fixtureFromMarkdown<MatrixStateFixture>(text, "matrix-mls-abort");
    const flip = fixtureFromMarkdown<MatrixStateFixture>(text, "matrix-mls-flip");

    expect(baseline).toMatchObject({
      type: "m.heterodyne.encryption_version.v1",
      state_key: "",
      content: {
        spec_version: "social/0.5.0",
        algorithm: "megolm",
        migrated_from: null,
        migrated_at: null,
      },
    });
    expect(exactKeys(baseline.content, ["spec_version", "algorithm", "migrated_from", "migrated_at"])).toBe(true);
    expect(capabilities.type).toBe("m.heterodyne.capabilities.v1");
    expect(capabilities.state_key).toBe(capabilities.sender);
    expect(validateCapabilityBootstrap(capabilities.content)).toEqual([]);
    expect(exactKeys(capabilities.content, ["descriptor", "bootstrap_version", "registry_revision", "supported_versions", "required_features", "strict_profiles", "backends", "node_roles", "matrix", "event_types", "nostr_kinds", "encryption_algorithms_supported", "advertised_at"])).toBe(true);
    expect(capabilities.content.encryption_algorithms_supported).toEqual(["megolm", "mls"]);
    expect(validateCapabilityBootstrap({ ...capabilities.content, descriptor: undefined })).toContain("descriptor");
    expect(validateCapabilityBootstrap({ ...capabilities.content, registry_revision: 2 })).toContain("registry-revision");
    expect(
      validateCapabilityBootstrap({
        ...capabilities.content,
        supported_versions: {
          ...(capabilities.content.supported_versions as Record<string, unknown>),
          extra: [],
        },
      }),
    ).toContain("document-set");
    expect(
      validateCapabilityBootstrap({
        ...capabilities.content,
        supported_versions: {
          ...(capabilities.content.supported_versions as Record<string, unknown>),
          core: [],
        },
      }),
    ).toContain("core-support");
    expect(intent.type).toBe("m.heterodyne.migration_intent.v1");
    expect(intent.state_key).toBe(intent.content.intent_id);
    expect(exactKeys(intent.content, ["spec_version", "target_algorithm", "drain_window_seconds", "intent_id", "initiator_mxid", "initiator_npub"])).toBe(true);
    expect(intent.content.drain_window_seconds).toBe(60);
    expect(String(intent.content.intent_id)).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(ack.type).toBe("m.heterodyne.migration_ack.v1");
    expect(ack.state_key).toBe(`${ack.content.intent_id}:${ack.content.member_npub}`);
    expect(exactKeys(ack.content, ["spec_version", "intent_id", "member_npub", "acked_at"])).toBe(true);
    expect(abort.type).toBe("m.heterodyne.migration_abort.v1");
    expect(abort.state_key).toBe(abort.content.intent_id);
    expect(abort.content.reason).toBe("missing_acks");
    expect(exactKeys(abort.content, ["spec_version", "intent_id", "reason", "missing_npubs", "aborted_at"])).toBe(true);
    expect(flip.type).toBe("m.heterodyne.encryption_version.v1");
    expect(flip.state_key).toBe("");
    expect(exactKeys(flip.content, ["spec_version", "algorithm", "migrated_from", "migrated_at", "intent_id"])).toBe(true);
    expect(typeof flip.origin_server_ts).toBe("number");
    expect(flip.content.migrated_at).toBe((flip.origin_server_ts as number) / 1000);

    const flipTs = flip.origin_server_ts as number;
    expect(matrixTailAcceptsFromFixture(flip, { origin_server_ts: flipTs + 60_000, pre_flip_session: true, member_at_flip: true })).toBe(true);
    expect(matrixTailAcceptsFromFixture(flip, { origin_server_ts: flipTs + 60_001, pre_flip_session: true, member_at_flip: true })).toBe(false);
    expect(matrixTailAcceptsFromFixture(flip, { origin_server_ts: flipTs + 30_000, pre_flip_session: false, member_at_flip: true })).toBe(false);
    expect(matrixTailAcceptsFromFixture(flip, { origin_server_ts: flipTs + 30_000, pre_flip_session: true, member_at_flip: false })).toBe(false);
  });

  it("cryptographically validates the ATProto binding and structurally parses revocation mirrors", () => {
    const text = readFileSync(socialPath, "utf8");
    const fixture = fixtureFromMarkdown<AtprotoFixture>(text, "atproto-identity-link");
    const revocations = fixtureFromMarkdown<{
      nostr: ExampleEvent;
      atproto: AtprotoFixture["pds_record"];
      matrix: MatrixStateFixture;
    }>(text, "atproto-link-revocations");

    expect(validateAtprotoFixture(fixture)).toEqual([]);
    expect(exactKeys(fixture.pds_record.value, ["spec_version", "did", "did_signing_key_id", "npub", "rid", "established_at"])).toBe(true);
    expect(fixture.matrix_mirror.type).toBe("m.heterodyne.atproto_link.v1");
    expect(fixture.matrix_mirror.content.binding_payload).toBe(fixture.nostr_event.content);
    expect(tagValues(fixture.nostr_event, "spec_version")).toEqual([]);
    expect(validateAtprotoFixture({ ...fixture, pds_record: { ...fixture.pds_record, collection: "wrong" } })).toContain("collection");
    expect(
      validateAtprotoFixture({
        ...fixture,
        nostr_event: { ...fixture.nostr_event, id: "00".repeat(32) },
      }),
    ).toContain("nostr-signature");
    expect(
      validateAtprotoFixture({
        ...fixture,
        nostr_event: { ...fixture.nostr_event, sig: "00".repeat(64) },
      }),
    ).toContain("nostr-signature");
    expect(
      validateAtprotoFixture({
        ...fixture,
        pds_record: { ...fixture.pds_record, signed_payload_hash: "00".repeat(32) },
      }),
    ).toContain("atproto-signature");
    expect(
      validateAtprotoFixture({
        ...fixture,
        pds_record: { ...fixture.pds_record, signature: "00".repeat(64) },
      }),
    ).toContain("atproto-signature");
    expect(validateAtprotoFixture({ ...fixture, matrix_mirror: { ...fixture.matrix_mirror, state_key: "did:web:other.example" } })).toContain("matrix-binding");
    expect(revocations.nostr.kind).toBe(31009);
    const nostrRevocation = JSON.parse(revocations.nostr.content) as Record<string, unknown>;
    expect(nostrRevocation).toMatchObject({
      spec_version: "social/0.5.0",
      record_type: "atproto_link_revocation",
      revoked_at: expect.any(Number),
    });
    expect(exactKeys(nostrRevocation, ["spec_version", "record_type", "did", "npub", "binding_hash", "revoked_at"])).toBe(true);
    expect(revocations.atproto.collection).toBe("social.heterodyne.identityLink");
    expect(revocations.atproto.value.revoked_at).toEqual(expect.any(Number));
    expect(revocations.matrix.type).toBe("m.heterodyne.atproto_link.v1");
    expect(revocations.matrix.state_key).toBe(revocations.matrix.content.did);
    expect(revocations.matrix.sender).toBe(revocations.matrix.content.mxid);
  });

  it("binds every registered Social security invariant", () => {
    const text = readFileSync(socialPath, "utf8");

    for (const invariant of [
      "SOCIAL-I-MATRIX-E2EE",
      "SOCIAL-I-MXID-DELEGATION-DUAL-PROOF",
      "SOCIAL-I-PRIVATE-STATE-AT-REST",
      "SOCIAL-I-CLIENT-SIDE-MATRIX-BRIDGE",
      "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
    ]) {
      expect(text).toContain(invariant);
    }
  });

  it("defines exact composable strict profiles without opening Control conformance", () => {
    const core = readFileSync(corePath, "utf8");
    const comms = readFileSync(commsPath, "utf8");
    const control = readFileSync(controlPath, "utf8");
    const social = readFileSync(socialPath, "utf8");
    const coreInvariants = [
      "CORE-I-IDENTITY-INTEGRITY",
      "CORE-I-NID-DELEGATION-DUAL-PROOF",
      "CORE-I-VERIFY-BEFORE-USE",
      "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
      "CORE-I-KEY-MATERIAL-AT-REST",
    ];
    const commsInvariants = [
      ...coreInvariants,
      "COMMS-I-TIER3-BLIND-CARRIER",
      "COMMS-I-TIER2-HONESTY",
      "COMMS-I-CONFIG-AT-REST",
      "COMMS-I-CLIENT-SIDE-DELIVERY",
      "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
    ];
    const controlInvariants = [
      ...commsInvariants,
      "CONTROL-I-AUDIT-AT-REST",
      "CONTROL-I-SESSION-KEY-CONFINEMENT",
    ];
    const nonMatrixSocialInvariants = [
      ...commsInvariants,
      "SOCIAL-I-PRIVATE-STATE-AT-REST",
      "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
    ];
    const matrixSocialInvariants = [
      ...nonMatrixSocialInvariants,
      "SOCIAL-I-MATRIX-E2EE",
      "SOCIAL-I-MXID-DELEGATION-DUAL-PROOF",
      "SOCIAL-I-CLIENT-SIDE-MATRIX-BRIDGE",
    ];

    expect(fixtureFromMarkdown<StrictProfileFixture>(core, "core-strict-profile")).toEqual({
      profile_id: "heterodyne-core-strict-v1",
      conformance_class: "Core",
      state: "active",
      requires_profiles: [],
      required_invariants: coreInvariants,
    });
    expect(fixtureFromMarkdown<StrictProfileFixture>(comms, "comms-strict-profile")).toEqual({
      profile_id: "heterodyne-comms-strict-v1",
      conformance_class: "Core+Comms",
      state: "active",
      requires_profiles: ["heterodyne-core-strict-v1"],
      required_invariants: commsInvariants,
    });
    expect(fixtureFromMarkdown<StrictProfileFixture>(control, "control-strict-profile")).toEqual({
      profile_id: "heterodyne-control-strict-v1",
      conformance_class: "Core+Comms+Control profile",
      state: "reserved-inactive",
      requires_profiles: [
        "heterodyne-core-strict-v1",
        "heterodyne-comms-strict-v1",
      ],
      required_invariants: controlInvariants,
    });
    expect(fixtureFromMarkdown<StrictProfileFixture>(social, "social-strict-profile")).toEqual({
      profile_id: "heterodyne-social-strict-v1",
      conformance_class: "Social",
      state: "active",
      requires_profiles: [
        "heterodyne-core-strict-v1",
        "heterodyne-comms-strict-v1",
      ],
      required_invariants: nonMatrixSocialInvariants,
    });
    expect(fixtureFromMarkdown<StrictProfileFixture>(social, "social-matrix-strict-profile")).toEqual({
      profile_id: "heterodyne-social-matrix-strict-v1",
      conformance_class: "Social+Matrix",
      state: "active",
      requires_profiles: ["heterodyne-social-strict-v1"],
      required_invariants: matrixSocialInvariants,
      matrix_obligations: [
        "encrypted-private-content-and-state",
        "mxid-dual-proof",
        "downgrade-warning",
        "bare-message-visibility",
      ],
    });

    expect(control).toMatch(/heterodyne-control-strict-v1[\s\S]*MUST NOT[\s\S]*`strict_profiles`/);
    expect(control).toMatch(/CONTROL-I-AUDIT-AT-REST[\s\S]*MUST NOT[\s\S]*SOCIAL-I/);
  });

  it("makes strict-profile advertisements and conformance reports fail closed", () => {
    const core = readFileSync(corePath, "utf8");

    expect(core).toMatch(/`strict_profiles`[\s\S]*MUST contain only[\s\S]*actually met/i);
    expect(core).toMatch(/unknown strict-profile ID[\s\S]*MUST NOT[\s\S]*(infer|grant|satisf)/i);
    expect(core).toMatch(/conformance report[\s\S]*strict-profile ID[\s\S]*required invariant/i);
    expect(core).toMatch(/composed profile[\s\S]*prerequisite profile/i);
  });

  it("uses only namespaced current invariants and exact registry descriptions", () => {
    const threatModel = readFileSync(threatModelPath, "utf8");
    const registry = JSON.parse(
      readFileSync(resolve(repositoryRoot, "docs/spec/registry/security-invariants.json"), "utf8"),
    ) as { security_invariants: Array<{ id: string; description: string }> };

    expect(threatModel).not.toMatch(/\bI(?:1|3|6|7)\b/);
    for (const invariant of registry.security_invariants) {
      expect(threatModel).toContain(invariant.id);
      expect(threatModel).toContain(invariant.description);
    }
  });

  it("navigates every current companion through the four-document family", () => {
    for (const relativePath of companionPaths) {
      const text = readFileSync(resolve(repositoryRoot, relativePath), "utf8");
      for (const document of ["core", "comms", "control", "social"]) {
        expect(text, `${relativePath} missing ${document}`).toContain(
          `heterodyne-${document}.md`,
        );
      }
      expect(text, `${relativePath} uses retired uppercase CORE terminology`).not.toMatch(
        /\bCORE\b(?!-I-)/,
      );
    }

    const changelog = readFileSync(resolve(repositoryRoot, "CHANGELOG.md"), "utf8");
    for (const document of ["core", "comms", "control", "social"]) {
      expect(changelog).toContain(`heterodyne-${document}.md`);
    }
    const historicalChangelog = changelog.indexOf("Historical 0.4.0");
    expect(historicalChangelog).toBeGreaterThan(-1);
    expect(changelog.slice(0, historicalChangelog)).not.toMatch(/\bCORE\b(?!-I-)/);

    const architecture = readFileSync(resolve(repositoryRoot, "docs/architecture.md"), "utf8");
    expect(architecture).toContain("Core <- Comms <- Control");
    expect(architecture).toContain("Core <- Comms <- Social");
    const glossary = readFileSync(resolve(repositoryRoot, "docs/glossary.md"), "utf8");
    expect(glossary).toMatch(/non-normative index/i);
    expect(glossary).toMatch(/shared normative terminology[\s\S]*heterodyne-core\.md/i);
  });

  it("keeps the 0.4.0 monolith authoritative until the family cutover", () => {
    for (const relativePath of preCutoverCompanionPaths) {
      const text = readFileSync(resolve(repositoryRoot, relativePath), "utf8");
      expect(text, `${relativePath} omits the current monolith`).toContain(
        "heterodyne.md",
      );
      expect(text, `${relativePath} omits current pre-cutover authority`).toMatch(
        /current normative 0\.4\.0 monolith/i,
      );
      expect(text, `${relativePath} omits candidate status`).toMatch(
        /candidate/i,
      );
      expect(text, `${relativePath} omits cutover sequencing`).toMatch(
        /cutover/i,
      );
      expect(text, `${relativePath} cuts authority over early`).not.toMatch(
        /heterodyne\.md[^\n]{0,80}(?:is|remains) (?:a )?non-normative|four independently versioned normative documents:/i,
      );
    }
  });

  it("retains concrete federation, ratchet, moderation, storage, and crypto residuals", () => {
    const text = readFileSync(threatModelPath, "utf8");

    expect(text).toMatch(
      /Federation peer[\s\S]*membership graph[\s\S]*peer set[\s\S]*(metadata|origin_server_ts)/i,
    );
    expect(text).toMatch(
      /within (?:a )?ratchet epoch[\s\S]*outer signer[\s\S]*link/i,
    );
    expect(text).toMatch(
      /lost or corrupt(?:ed)? ratchet state[\s\S]*no backfill[\s\S]*unrecoverable/i,
    );
    expect(text).toMatch(
      /listed[- ]then[- ]removed moderator[\s\S]*relay-only[\s\S]*backdat[\s\S]*repo(?:sitory)? anchor/i,
    );
    expect(text).toMatch(/not post-quantum[\s\S]*quantum adversar/i);
    expect(text).toMatch(
      /config repository[\s\S]*allow-list[\s\S]*(location|RID)[\s\S]*(link|correlat|compromis)/i,
    );
    expect(text).toMatch(
      /keys repository[\s\S]*backup loss[\s\S]*permanent(?:ly)?[\s\S]*(decrypt|identity recover)/i,
    );
    expect(text).toMatch(
      /removable-media[\s\S]*produced[\s\S]*followed[\s\S]*freshness[\s\S]*restore/i,
    );
    expect(text).toMatch(
      /registry-bound rows cite[\s\S]*directly govern[\s\S]*residual[\s\S]*cross-cutting/i,
    );
  });

  it("requires every moderation condition at the approval anchor", () => {
    const text = readFileSync(socialPath, "utf8");
    const valid = fixtureFromMarkdown<Parameters<typeof approvalCountsProbe>[0]>(
      text,
      "social-approval-anchor-evidence",
    );

    expect(approvalCountsProbe(valid)).toBe(true);
    for (const omitted of [
      "indexed",
      "signatureValid",
      "moderatorAuthorizedAtAnchor",
      "requiredAnchorPresent",
    ] as const) {
      expect(approvalCountsProbe({ ...valid, [omitted]: false })).toBe(false);
    }
    expect(approvalCountsProbe({ ...valid, deleted: true })).toBe(false);
    expect(text).toMatch(/moderator set is evaluated at the anchor/i);
    expect(text).toMatch(/lacking it MUST NOT\s+count/i);
    expect(text).toMatch(/kind:5[\s\S]*updated moderator index/i);
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

  it("reports a normative reference omitted from declared dependencies", () => {
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
          '<a id="comms-conformance"></a>',
        ].join("\n"),
        control: [
          "Document ID: `control`",
          "Normative dependencies:",
          "",
          "- `heterodyne:comms/0.5.0#comms-conformance`",
          '<a id="control-scope"></a>',
          "A verifier MUST use `heterodyne:core/0.5.0#core-identity-model`.",
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-control.md",
            line: 6,
            code: "undeclared-dependency",
          }),
        ),
    );
  });

  it("requires normative references to match the exact declared dependency version", () => {
    withFamilyDocs(
      {
        comms: [
          "Document ID: `comms`",
          '<a id="comms-conformance"></a>',
        ].join("\n"),
        control: [
          "Document ID: `control`",
          "Normative dependencies: `heterodyne:comms/0.5.0#comms-conformance`.",
          "A client MUST apply `heterodyne:comms/0.6.0#comms-conformance`.",
          '<a id="control-scope"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-control.md",
            line: 3,
            code: "undeclared-dependency",
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
