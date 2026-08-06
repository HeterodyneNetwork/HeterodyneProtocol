import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { Ajv, type AnySchema } from "ajv";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import {
  CLAIMS_OIDC_INVARIANT_IDS,
  expectedReleaseManifests,
  findInvariantEvidenceIssues,
  lintFamilyCutover,
  lintFamilyDocs,
  loadReleaseSchemaRegistryPin,
  validateReleaseManifestRegistryPin,
  validateReleaseManifestSchemaPin,
  writeReleaseManifests,
} from "./docs-lint.js";
import { hexToBytes, utf8Bytes } from "./hex.js";
import { verifyEventSignature, type NostrSignedEvent } from "./nostr.js";
import {
  computeRegistryDigest,
  loadRegistry,
  resolveStampingProfile,
} from "./registry.js";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, "../../../../../");
const corePath = resolve(repositoryRoot, "docs/spec/heterodyne-core.md");
const commsPath = resolve(repositoryRoot, "docs/spec/heterodyne-comms.md");
const controlPath = resolve(repositoryRoot, "docs/spec/heterodyne-control.md");
const socialPath = resolve(repositoryRoot, "docs/spec/heterodyne-social.md");
const overviewPath = resolve(repositoryRoot, "docs/spec/heterodyne.md");
const archivePath = resolve(
  repositoryRoot,
  "docs/spec/archive/heterodyne-0.4.0.md",
);
const anchorMapPath = resolve(
  repositoryRoot,
  "docs/spec/archive/heterodyne-0.4.0-anchor-map.md",
);
const releasesPath = resolve(repositoryRoot, "docs/spec/releases");
const threatModelPath = resolve(repositoryRoot, "docs/security/threat-model.md");

const companionPaths = [
  "README.md",
  "AGENTS.md",
  "docs/architecture.md",
  "docs/glossary.md",
  "docs/security/threat-model.md",
  "research/INDEX.md",
  "docs/spec/extensions/nips/README.md",
] as const;
const preCutoverCompanionPaths = [...companionPaths, "CHANGELOG.md"] as const;

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

function canonicalJsonProbe(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJsonProbe).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, member]) => `${JSON.stringify(key)}:${canonicalJsonProbe(member)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
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

function validateCapabilityBootstrap(content: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const supported = content.supported_versions as Record<string, unknown> | undefined;
  if (content.descriptor !== "heterodyne-capabilities-v1") errors.push("descriptor");
  if (content.bootstrap_version !== "core/0.5.0") errors.push("bootstrap-version");
  if (content.registry_revision !== 3) errors.push("registry-revision");
  if (content.implementation_role !== "authenticated-light") {
    errors.push("implementation-role");
  }
  if (!supported || !exactKeys(supported, ["core", "comms", "control", "social"])) {
    errors.push("document-set");
  } else {
    if (JSON.stringify(supported.core) !== JSON.stringify(["core/0.5.0"])) errors.push("core-support");
    if (JSON.stringify(supported.comms) !== JSON.stringify(["comms/0.5.0"])) errors.push("comms-support");
    if (JSON.stringify(supported.control) !== JSON.stringify([])) errors.push("control-support");
    if (JSON.stringify(supported.social) !== JSON.stringify(["social/0.5.0"])) errors.push("social-support");
  }
  if (!Array.isArray(content.required_features)) {
    errors.push("required-features");
  } else {
    const features = content.required_features as unknown[];
    for (const required of [
      "core.nostr-relay-read.v1",
      "core.outbound-tor.v1",
      "core.repo-relay-client.v1",
    ]) {
      if (!features.includes(required)) errors.push("required-features");
    }
    if (
      features.includes("core.identity.v1")
      || features.includes("core.embedded-tor.v1")
    ) {
      errors.push("obsolete-feature");
    }
  }
  if (!Array.isArray(content.strict_profiles)) errors.push("strict-profiles");
  return [...new Set(errors)].sort();
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

function withReleaseFixture(
  revision: number,
  digest: string,
  run: (root: string) => void,
): void {
  const root = mkdtempSync(resolve(tmpdir(), "heterodyne-release-pin-"));
  const spec = resolve(root, "docs/spec");
  mkdirSync(spec, { recursive: true });
  try {
    cpSync(resolve(repositoryRoot, "docs/spec/registry"), resolve(spec, "registry"), {
      recursive: true,
    });
    cpSync(releasesPath, resolve(spec, "releases"), { recursive: true });
    const schemaPath = resolve(spec, "releases/release-manifest.schema.json");
    const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as {
      properties: {
        registry_revision: { const: number };
        registry_sha256: { const: string };
      };
    };
    schema.properties.registry_revision.const = revision;
    schema.properties.registry_sha256.const = digest;
    writeFileSync(schemaPath, `${JSON.stringify(schema, null, 2)}\n`, "utf8");
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
    expect(text).toContain("Registry revision: `4`");
    expect(text).not.toMatch(
      /normative[^\n]*(heterodyne-comms|heterodyne-control|heterodyne-social)/i,
    );
    expect(text).not.toMatch(
      /follow|mutual follow|friend/i,
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
    expect(text).toContain("Registry revision: `4`");
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
      "credential-sync",
      "control-enrollment",
      "control-human-rpc",
      "control-agent-rpc",
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
    expect(text).toMatch(/responses and messages MUST NOT be committed to a repository/i);
    expect(text).toMatch(/They have no backfill/i);
    expect(text).toMatch(/Before plaintext reaches Control/i);
    expect(text).toMatch(/atomically advance and durably persist ratchet state/i);
    expect(text).toMatch(/consumed\s+message key cryptographically unavailable/i);
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
      "COMMS-I-PUBLIC-READER-TIER1-ONLY",
      "COMMS-I-AGENT-ROLE-BINDING",
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT",
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY",
      "COMMS-I-MARMOT-EXACT-BYTES",
      "COMMS-I-MARMOT-SECRET-CONFINEMENT",
      "COMMS-I-RADICLE-ROUTING-AUTHORITY",
      "COMMS-I-RADICLE-NON-ERASURE",
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

  it("defines a mutually exclusive Comms-native acceptance decision table", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(/`control-human-rpc` or `control-agent-rpc`[\s\S]*`hold-as-message-request`/i);
    expect(text).toMatch(
      /delegated `credential-sync`[\s\S]*every[\s\S]*authoritative ledger[\s\S]*`accept`/i,
    );
    expect(text).toMatch(
      /current state[\s\S]*cannot be established[\s\S]*`hold-as-message-request`/i,
    );
    expect(text).toMatch(
      /invalid, revoked, expired, mismatched, or NID-less[\s\S]*`reject`/i,
    );
    expect(text).toMatch(
      /undelegated `credential-sync` initiator[\s\S]*`reject`/i,
    );
    expect(text).toMatch(/`control-enrollment`[\s\S]*`hold-as-message-request`/i);
  });

  it("confines DR lifecycle to bootstrap and Control", () => {
    const text = readFileSync(commsPath, "utf8");

    expect(text).toMatch(/only for point-to-point[\s\S]*bootstrap[\s\S]*Control RPC/i);
    expect(text).toMatch(/MUST NOT carry ordinary user conversation/i);
    expect(text).toMatch(/revoked or expired peer delegation[\s\S]*stops its sessions/i);
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
    expect(text).toMatch(
      /localizable structured outcome[\s\S]*`missing-predecessor`[\s\S]*attempt\/deadline\/last-attempt[\s\S]*allowed user actions[\s\S]*allocates\s+no reason code/i,
    );
    expect(text).toMatch(
      /persist[\s\S]*predecessor event id[\s\S]*referring-page locator[\s\S]*process[\s\S]*restart/i,
    );
  });

  it("integrates privacy, identity, recovery, deadline, and resolver corrections", () => {
    const core = readFileSync(corePath, "utf8");
    const comms = readFileSync(commsPath, "utf8");
    const social = readFileSync(socialPath, "utf8");
    const threatModel = readFileSync(threatModelPath, "utf8");

    expect(core).toMatch(
      /MUST NOT infer or publish[\s\S]*higher-layer document[\s\S]*authorization by both\s+personas/i,
    );
    expect(core).toMatch(
      /Changed-RID re-anchor[\s\S]*infrastructure[\s\S]*MUST NOT[\s\S]*cold-root compromise/i,
    );
    expect(comms).toMatch(
      /Tier\s+3 protects content[\s\S]*MUST NOT label Tier 3 membership-private/i,
    );
    expect(comms).toMatch(
      /kind:31011[\s\S]*kind:31012[\s\S]*`key_id`[\s\S]*timing[\s\S]*size/i,
    );
    expect(comms).toMatch(
      /general Control\s+conformance is closed[\s\S]*No current document\s+combination[\s\S]*unreachable/i,
    );
    expect(social).toMatch(
      /dual-signed pair[\s\S]*`same_holder`[\s\S]*explicit confirmation[\s\S]*permanently/i,
    );
    expect(social).toMatch(/KERI compromise cutoff[\s\S]*invalidate approvals/i);
    expect(social).toMatch(
      /connect directly[\s\S]*established peer address[\s\S]*TLS SNI[\s\S]*Automatic\s+redirect[\s\S]*MUST NOT claim ATProto\s+resolver conformance/i,
    );
    expect(social).toMatch(
      /localizable structured outcome[\s\S]*moderation-approval-window-expired[\s\S]*allowed actions/i,
    );
    expect(threatModel).toMatch(
      /Tier 3 audience membership is inferred[\s\S]*recipient[\s\S]*roster[\s\S]*timing/i,
    );
    expect(threatModel).toMatch(
      /ATProto DNS validation[\s\S]*dial one validated address[\s\S]*inspect the connected peer/i,
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
      core_candidate_shape_defined: boolean;
      conforming_events_allowed: boolean;
      activation_requires: string[];
    }>(text, "control-session-device-reservation");
    expect(reservation).toEqual({
      profile_id: "heterodyne-control-session-device-v1",
      registry_status: "draft",
      profile_state: "reserved-inactive",
      core_candidate_shape_defined: true,
      conforming_events_allowed: false,
      activation_requires: [
        "closed-control-profile",
        "complete-credential-continuity-and-recovery-vector-batch",
        "atomic-future-registry-feature-and-schema-allocation",
        "matching-family-and-release-manifests",
      ],
    });
    expect(coreText).toContain(
      "heterodyne-light-binding-v1|<cold-root-hex>|<publishing-key-hex>|session-device|<binding-nonce>",
    );
    expect(coreText).toMatch(/exact UTF-8 bytes directly[\s\S]*without an additional prehash/i);
    expect(coreText).toMatch(/Core treats `binding_nonce` as[\s\S]*opaque profile field[\s\S]*no challenge, token, or acceptance/i);
    expect(coreText).toMatch(/profile remains `reserved-inactive`[\s\S]*conformance_claimable = false/i);
    expect(text).toMatch(/structural diagnostics[\s\S]*does not\s+activate/i);
    expect(text).toMatch(/final candidate[\s\S]*grants no Control authority/i);
    expect(text).toMatch(/ownership[\s\S]*stamp intention[\s\S]*does not\s+make it active/i);
    expect(text).toMatch(/future registry revision[\s\S]*matching family\/release manifests/i);
    expect(text).toMatch(/recovery feature[\s\S]*no placeholder/i);
    expect(text).not.toContain("heterodyne:core/");
    expect(text).toMatch(/Control MUST NOT[\s\S]*wire stamp/i);
    expect(text).not.toMatch(/control\/0\.5\.0.*stamp/i);
  });

  it("defines the exact Comms epoch invite while holding gated enrollment", () => {
    const comms = readFileSync(commsPath, "utf8");

    expect(comms).toMatch(/`kind:30078`[\s\S]*`d = double-ratchet\/invites\/epoch`/i);
    expect(comms).toMatch(/current\s+KERI-authoritative epoch signer[\s\S]*`kel_head`/i);
    expect(comms).toMatch(/bind the active invite event ID[\s\S]*first Control request/i);
    expect(comms).toMatch(/control-enrollment[\s\S]*higher profile gated[\s\S]*hold-as-message-request/i);
    expect(comms).toMatch(/Tor-capable light client[\s\S]*shared clearnet relay/i);
    expect(comms).toMatch(/Enrollment requires no direct client-to-node address/i);
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

  it("keeps the Control conformance gate closed after gated profile integration", () => {
    const text = readFileSync(controlPath, "utf8");
    const gate = fixtureFromMarkdown<{
      can_claim_control_conformance: boolean;
      blockers: string[];
      integrated_normative_subsets: string[];
    }>(text, "control-conformance-gate");

    expect(gate).toEqual({
      can_claim_control_conformance: false,
      blockers: [
        "activating-registry-revision-not-published",
        "recovery-feature-and-core-schemas-not-integrated",
        "credential-continuity-and-recovery-vector-batch-incomplete",
        "matching-family-and-release-manifests-not-issued",
      ],
      integrated_normative_subsets: [
        "gated-control-profile",
        "ingress-relay-affinity",
        "agent-workload-publication",
        "node-mediated-marmot",
      ],
    });
    expect(text).toContain("no Control conformance claim");
    expect(text).toMatch(/negotiated Control version[\s\S]*audit/i);
    for (const invariant of [
      "CONTROL-I-AUDIT-AT-REST",
      "CONTROL-I-SESSION-KEY-CONFINEMENT",
      "CONTROL-I-INGRESS-RELAY-AFFINITY",
      "CONTROL-I-AGENT-NO-KEY-RELEASE",
      "CONTROL-I-AGENT-INTENT-ONLY",
      "CONTROL-I-AGENT-AUTHORIZATION-FRESHNESS",
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT",
    ]) {
      expect(text).toContain(invariant);
    }
  });

  it("selects registry revision 4 while preserving the separate recovery gate", () => {
    const registry = loadRegistry(repositoryRoot);
    expect(registry.manifest.revision).toBe(4);
    expect(registry.history.has(4)).toBe(true);
    expect(
      existsSync(resolve(repositoryRoot, "docs/spec/registry/history/4.json")),
    ).toBe(true);

    for (const path of [corePath, commsPath, socialPath]) {
      const text = readFileSync(path, "utf8");
      expect(text).toContain("Registry revision: `4`");
    }
    expect(readFileSync(commsPath, "utf8")).toMatch(/non-claimable/i);
    expect(readFileSync(controlPath, "utf8")).toMatch(
      /future activating registry revision[\s\S]*credential-continuity and recovery[\s\S]*land\s+atomically/i,
    );
  });

  it("defines all credential-continuity drafts while preserving their activation gate", () => {
    const text = readFileSync(commsPath, "utf8");
    for (const anchor of [
      "comms-credential-continuity-gate",
      "comms-credential-checkpoints",
      "comms-secret-inventory",
      "comms-retention-inventory",
      "comms-secret-transitions",
      "comms-emergency-reset",
      "comms-config-git-structure",
      "comms-dr-terminalization",
      "comms-credential-generation",
    ]) {
      expect(text).toContain(`<a id="${anchor}"></a>`);
    }
    expect(text).toContain("They are **not** active");
    expect(text).toContain("under selected registry revision 4");
    expect(text).toMatch(
      /MUST NOT advertise, negotiate, require, produce as authoritative, or claim\s+conformance/i,
    );
    expect(text).toMatch(/two\s+Core-owned offline-recovery schemas/i);
    expect(text).toMatch(/governed-decrypt source-profile\s+catalog/i);
    expect(text).toMatch(/explicit conformance\s+evidence/i);
    expect(text).toMatch(
      /conformance_claimable:false[\s\S]*do not establish recovery-profile\s+conformance/i,
    );
    expect(text).toMatch(
      /"persona": "<64 lowercase hex cold-root npub>",\s+"credential_ledger_generation": 0/,
    );
    expect(text).toMatch(
      /claim-ledger-record-v1\.schema\.json[\s\S]*`record_id`, `record_type`, `persona`, `credential_ledger_generation`/,
    );
    expect(text).toMatch(
      /authorization key\s+claim uses both explicit members[\s\S]*descriptive key claim carries both\s+members as JSON `null`/i,
    );
    expect(text).toMatch(
      /authorization-code transaction[\s\S]*`credential_ledger_persona`[\s\S]*`credential_ledger_generation`[\s\S]*emergency reset purges every prior-generation pending code/i,
    );
    expect(text).toMatch(
      /Status List Token[\s\S]*Claims are[\s\S]*`credential_ledger_persona`,\s*`credential_ledger_generation`/i,
    );

    const schemaNames = [
      "repository-retention-inventory-v1.schema.json",
      "governed-decrypt-key-binding-v1.schema.json",
      "historical-decrypt-obligation-v1.schema.json",
      "credential-ledger-checkpoint-v1.schema.json",
      "credential-ledger-checkpoint-receipt-v1.schema.json",
      "credential-ledger-removal-observation-v1.schema.json",
      "credential-ledger-candidate-abandonment-v1.schema.json",
      "credential-ledger-staging-ref-cleanup-v1.schema.json",
      "credential-ledger-config-key-bootstrap-recipient-array-v1.schema.json",
      "credential-ledger-emergency-reset-v1.schema.json",
      "credential-ledger-reset-recipient-array-v1.schema.json",
      "node-secret-source-v1.schema.json",
      "node-secret-exposure-v1.schema.json",
      "credential-ledger-secret-transition-v1.schema.json",
      "node-secret-transition-action-v1.schema.json",
      "double-ratchet-session-termination-v1.schema.json",
      "credential-ledger-lost-generation-path-v1.schema.json",
      "config-repository-git-structure-v1.schema.json",
      "double-ratchet-peer-tombstone-rumor-v1.schema.json",
      "double-ratchet-peer-tombstone-gift-wrap-v1.schema.json",
    ];
    expect(schemaNames).toHaveLength(20);
    const schemaRoot = resolve(repositoryRoot, "docs/spec/schemas/comms");
    for (const schemaName of schemaNames) {
      const schema = JSON.parse(
        readFileSync(resolve(schemaRoot, schemaName), "utf8"),
      ) as { $schema?: string; $id?: string };
      expect(schema).toMatchObject({
        $schema: "http://json-schema.org/draft-07/schema#",
        $id: `https://heterodyne.network/schemas/comms/${schemaName}`,
      });
    }

    const registry = loadRegistry(repositoryRoot);
    const activeProfiles = registry.kinds.flatMap(({ profiles }) =>
      profiles.map(({ profile_id }) => profile_id),
    );
    for (const profile of [
      "comms.repository-retention-inventory.v1",
      "comms.credential-ledger-checkpoint.v1",
      "comms.credential-ledger-secret-transition.v1",
      "heterodyne-comms-double-ratchet-peer-tombstone-v1",
    ]) {
      expect(activeProfiles).not.toContain(profile);
    }
    expect(
      existsSync(resolve(repositoryRoot, "docs/spec/registry/history/4.json")),
    ).toBe(true);
  });

  it("defines closed draft enrollment, grants, RPC, lifecycle, and MCP without a Control wire stamp", () => {
    const text = readFileSync(controlPath, "utf8");
    for (const anchor of [
      "control-enrollment",
      "control-enrollment-token",
      "control-grants",
      "control-rpc",
      "control-configuration",
      "control-session-lifecycle",
      "control-mcp",
      "control-audit-retention",
    ]) {
      expect(text).toContain(`<a id="${anchor}"></a>`);
    }
    expect(text).toMatch(/default grant[\s\S]*`regular`/i);
    expect(text).toMatch(/security-policy[\s\S]*not configuration[\s\S]*MUST reject/i);
    expect(text).toMatch(/same-token, same-key retry[\s\S]*idempotently[\s\S]*different-key retry conflicts/i);
    expect(text).toMatch(/initialize[\s\S]*before any tool call[\s\S]*did not advertise/i);
    expect(text).toMatch(/Cancellation notifications[\s\S]*negotiated timeout/i);
    expect(text).toMatch(/inbound execution is absent by\s+default/i);
    expect(text).toMatch(/requests and responses[\s\S]*never repository-committed or backfilled/i);

    const schemaRoot = resolve(repositoryRoot, "docs/spec/schemas/control");
    for (const schemaName of [
      "control-enrollment-request-v1.schema.json",
      "control-enrollment-token-v1.schema.json",
      "control-grant-v1.schema.json",
      "control-mcp-frame-v1.schema.json",
      "control-capability-set-v1.schema.json",
      "control-rpc-request-v1.schema.json",
      "control-rpc-response-v1.schema.json",
    ]) {
      const schema = JSON.parse(
        readFileSync(resolve(schemaRoot, schemaName), "utf8"),
      ) as { $schema?: string };
      expect(schema.$schema).toBe("http://json-schema.org/draft-07/schema#");
    }
    const request = JSON.parse(
      readFileSync(
        resolve(schemaRoot, "control-rpc-request-v1.schema.json"),
        "utf8",
      ),
    ) as {
      required: string[];
      properties: Record<string, unknown>;
      additionalProperties: boolean;
    };
    expect(request.required).toEqual(["id", "method", "params", "expires_at"]);
    expect(Object.keys(request.properties)).toEqual([
      "id",
      "method",
      "params",
      "expires_at",
    ]);
    expect(request.additionalProperties).toBe(false);
  });

  it("keeps Control strict v2 reserved while composing the integrated subsets", () => {
    const control = readFileSync(controlPath, "utf8");
    const comms = readFileSync(commsPath, "utf8");
    const commsV2 = fixtureFromMarkdown<StrictProfileFixture>(
      comms,
      "comms-strict-profile-v2",
    );
    const controlV2 = fixtureFromMarkdown<StrictProfileFixture>(
      control,
      "control-strict-profile-v2",
    );
    expect(controlV2).toEqual({
      profile_id: "heterodyne-control-strict-v2",
      conformance_class: "Core+Comms+Control profile",
      state: "reserved-inactive",
      requires_profiles: ["heterodyne-comms-strict-v2"],
      required_invariants: [
        ...commsV2.required_invariants,
        "CONTROL-I-AUDIT-AT-REST",
        "CONTROL-I-SESSION-KEY-CONFINEMENT",
        "CONTROL-I-INGRESS-RELAY-AFFINITY",
        "CONTROL-I-AGENT-NO-KEY-RELEASE",
        "CONTROL-I-AGENT-INTENT-ONLY",
        "CONTROL-I-AGENT-AUTHORIZATION-FRESHNESS",
      ],
    });
    expect(control).toMatch(
      /Requirements for automated agents[\s\S]*MUST refuse[\s\S]*sign_event/i,
    );
    expect(control).toMatch(
      /gated-Control, ingress-relay-affinity, and\s+automated-agent draft evidence[\s\S]*Incomplete conformance gate/i,
    );
  });

  it("verifies the producer-only Core breadcrumb workflow and manual Social following", () => {
    const core = readFileSync(corePath, "utf8");
    const social = readFileSync(socialPath, "utf8");
    const threatModel = readFileSync(threatModelPath, "utf8");

    const rotation = sectionUnderHeading(
      core,
      "#### 4.3.1 Vanilla Nostr routine-rotation breadcrumbs",
    );
    expect(rotation).toMatch(
      /prior accepted KEL[\s\S]*accepted routine rotation[\s\S]*retiring key[\s\S]*successor key[\s\S]*NIP-65[\s\S]*exact candidate/i,
    );
    expect(rotation).toMatch(/partial relay failure[\s\S]*does not\s+undo/i);
    expect(rotation).toMatch(/consumer[\s\S]*MUST NOT\s+infer a\s+v1 profile/i);
    expect(rotation).toMatch(/future machine-recognizable[\s\S]*v2/i);

    const following = sectionUnderHeading(
      social,
      "### 3.1 Following semantics and private state",
    );
    expect(following).toMatch(/first-class[\s\S]*NIP-65/i);
    expect(following).toMatch(
      /explicit user action[\s\S]*MUST NOT change a follow\s+automatically/i,
    );
    expect(following).toMatch(/external identity[\s\S]*compatible Marmot account/i);

    expect(threatModel).toMatch(/Retired-key breadcrumb[\s\S]*redirect/i);
    expect(threatModel).toMatch(/Breadcrumb-like prose[\s\S]*explicit user action/i);
  });

  it("declares the exact Social dependency set and public-Social scope", () => {
    const text = readFileSync(socialPath, "utf8");

    expect(text).toContain("Document ID: `social`");
    expect(text).toContain("Version: `social/0.5.0`");
    expect(text).toContain("Registry revision: `4`");
    expect(declaredDependencies(text)).toEqual([
      "heterodyne:core/0.5.0#core-conformance",
      "heterodyne:comms/0.5.0#comms-conformance",
    ]);
    expect(text).not.toContain("heterodyne:control/");
    expect(text).toMatch(/public and audience publishing[\s\S]*moderation/i);
    expect(text).toMatch(/private conversation[\s\S]*Marmot/i);
  });

  it("keeps public Social behavior complete", () => {
    const text = readFileSync(socialPath, "utf8");

    expect(text).toMatch(/replies[\s\S]*reactions[\s\S]*thread/i);
    expect(text).toMatch(/following[\s\S]*transitive[\s\S]*discovery/i);
    expect(text).toMatch(/cross-persona[\s\S]*advertisement/i);
    expect(text).toMatch(/reply inbox/i);
    expect(text).toMatch(/mixed-tier[\s\S]*fan-out/i);
    expect(text).toMatch(/NIP-72[\s\S]*Radicle editorial/i);
    expect(text).toMatch(/starter pack[\s\S]*ATProto/i);
    expect(text).toMatch(/private[\s\S]*(?:reply|reaction)[\s\S]*Marmot/i);
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
    expect(text).toMatch(/serving peer[\s\S]*cached data/i);
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

  it("cryptographically validates the ATProto binding and parses bilateral revocations", () => {
    const text = readFileSync(socialPath, "utf8");
    const fixture = fixtureFromMarkdown<AtprotoFixture>(text, "atproto-identity-link");
    const revocations = fixtureFromMarkdown<{
      nostr: ExampleEvent;
      atproto: AtprotoFixture["pds_record"];
    }>(text, "atproto-link-revocations");

    expect(validateAtprotoFixture(fixture)).toEqual([]);
    expect(exactKeys(fixture.pds_record.value, ["spec_version", "did", "did_signing_key_id", "npub", "rid", "established_at"])).toBe(true);
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
  });

  it("binds every registered Social security invariant", () => {
    const text = readFileSync(socialPath, "utf8");

    for (const invariant of [
      "SOCIAL-I-PRIVATE-STATE-AT-REST",
      "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
      "SOCIAL-I-AGENT-POLICY-LOCAL",
      "SOCIAL-I-AGENT-REMEDIATION-SCOPED",
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
    ];
    const controlInvariants = [
      ...commsInvariants,
      "CONTROL-I-AUDIT-AT-REST",
      "CONTROL-I-SESSION-KEY-CONFINEMENT",
    ];
    const socialInvariants = [
      ...commsInvariants,
      "SOCIAL-I-PRIVATE-STATE-AT-REST",
      "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
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
      required_invariants: socialInvariants,
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

  it("adds Comms strict v2 without changing strict v1 membership", () => {
    const comms = readFileSync(commsPath, "utf8");
    const v1 = fixtureFromMarkdown<StrictProfileFixture>(comms, "comms-strict-profile");
    const v2 = fixtureFromMarkdown<StrictProfileFixture>(comms, "comms-strict-profile-v2");

    expect(v1.profile_id).toBe("heterodyne-comms-strict-v1");
    expect(v1.required_invariants).not.toContain("COMMS-I-PUBLIC-READER-TIER1-ONLY");
    expect(v1.required_invariants).not.toContain("COMMS-I-AGENT-ATTRIBUTION");
    expect(v2).toEqual({
      profile_id: "heterodyne-comms-strict-v2",
      conformance_class: "Core+Comms",
      state: "active",
      requires_profiles: ["heterodyne-core-strict-v1"],
      required_invariants: [
        "CORE-I-IDENTITY-INTEGRITY",
        "CORE-I-NID-DELEGATION-DUAL-PROOF",
        "CORE-I-VERIFY-BEFORE-USE",
        "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
        "CORE-I-KEY-MATERIAL-AT-REST",
        "COMMS-I-TIER3-BLIND-CARRIER",
        "COMMS-I-TIER2-HONESTY",
        "COMMS-I-CONFIG-AT-REST",
        "COMMS-I-CLIENT-SIDE-DELIVERY",
        "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
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
        "COMMS-I-PUBLIC-READER-TIER1-ONLY",
        "COMMS-I-AGENT-ROLE-BINDING",
        "COMMS-I-AGENT-ATTRIBUTION",
        "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT",
      ],
    });
  });

  it("adds subscriber-local Social strict v2 without changing v1 or depending on Control", () => {
    const comms = readFileSync(commsPath, "utf8");
    const social = readFileSync(socialPath, "utf8");
    const commsV2 = fixtureFromMarkdown<StrictProfileFixture>(
      comms,
      "comms-strict-profile-v2",
    );
    const socialV1 = fixtureFromMarkdown<StrictProfileFixture>(
      social,
      "social-strict-profile",
    );
    const socialV2 = fixtureFromMarkdown<StrictProfileFixture>(
      social,
      "social-strict-profile-v2",
    );
    const socialV2Invariants = [
      ...commsV2.required_invariants,
      "SOCIAL-I-PRIVATE-STATE-AT-REST",
      "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
      "SOCIAL-I-AGENT-POLICY-LOCAL",
      "SOCIAL-I-AGENT-REMEDIATION-SCOPED",
    ];

    expect(socialV1.required_invariants).not.toContain("SOCIAL-I-AGENT-POLICY-LOCAL");
    expect(socialV2).toEqual({
      profile_id: "heterodyne-social-strict-v2",
      conformance_class: "Social",
      state: "active",
      requires_profiles: ["heterodyne-comms-strict-v2"],
      required_invariants: socialV2Invariants,
    });
    expect(social).toMatch(
      /Normative dependencies:[\s\S]*- `heterodyne:core\/0\.5\.0#core-conformance`[\s\S]*- `heterodyne:comms\/0\.5\.0#comms-conformance`/,
    );
    expect(social.slice(0, social.indexOf("<a id=\"social-scope\"></a>")))
      .not.toMatch(/control/i);
  });

  it("makes agent-policy moderation advisory, subscriber-local, and device-key scoped", () => {
    const social = readFileSync(socialPath, "utf8");

    expect(social).toMatch(/A valid receipt publicly informs[\s\S]*does not mute/i);
    expect(social).toMatch(/Only an explicitly subscribed policy list affects a client/i);
    expect(social).toMatch(/No moderator,[\s\S]*has global power/i);
    expect(social).toMatch(/Enforcement mutes exactly the listed device-publishing key/i);
    expect(social).toMatch(/MUST NOT mute[\s\S]*epoch key[\s\S]*human devices/i);
    expect(social).toMatch(/Epoch-key\s+rotation is neither required nor permitted/i);
    expect(social).toMatch(/relay-only list candidate or[\s\S]*unmerged Radicle PR has no policy effect/i);
    expect(social).toMatch(/let the user inspect, disable, or\s+replace it/i);
  });

  it("defines the mandatory agent path without a Comms-to-Control dependency", () => {
    const comms = readFileSync(commsPath, "utf8");
    for (const anchor of [
      "comms-agent-authorship",
      "comms-agent-delegation",
      "comms-agent-workload",
      "comms-agent-token",
      "comms-agent-attribution",
      "comms-agent-fail-closed",
    ]) {
      expect(comms).toContain(`<a id="${anchor}"></a>`);
    }
    expect(comms).toContain(
      "Normative dependencies: `heterodyne:core/0.5.0#core-conformance`.",
    );
    expect(comms).not.toMatch(/Normative dependencies:[^\n]*control/i);
    expect(comms).toContain(
      "heterodyne-agent-signing-binding-v1|<cold-root-hex>|<nid>|<role-id>|<publishing-key>",
    );
    expect(comms).toMatch(
      /\["L", "network\.heterodyne\.agent"\][\s\S]*\["l", "ai" \| "programmatic", "network\.heterodyne\.agent"\][\s\S]*\["heterodyne_agent", "v1"/,
    );
    expect(comms).toMatch(/raw token[\s\S]*MUST NOT[\s\S]*public event/i);
    expect(comms).toMatch(/There is no[\s\S]*fallback[\s\S]*unlabeled event/i);
  });

  it("keeps one concise agent guide with the spec-canonical decision workflow", () => {
    const agents = readFileSync(resolve(repositoryRoot, "AGENTS.md"), "utf8");

    expect(existsSync(resolve(repositoryRoot, "CLAUDE.md"))).toBe(false);
    expect(agents).toMatch(/ADRs are non-canonical point-in-time decision records/i);
    expect(agents).toMatch(/If an ADR and the specification disagree, the specification\s+governs/i);
    expect(agents).toMatch(/same\s+branch and patch or pull request/i);
    expect(agents).toMatch(/registry, schemas, release metadata, and conformance vectors/i);
    expect(agents).toMatch(/mark the ADR accepted and move it to[\s\S]*docs\/adr\/archive/i);
    expect(agents).toMatch(/Merge only when the specification stands on its own/i);
  });

  it("integrates Marmot and Radicle conversations without a live Matrix profile", () => {
    const core = readFileSync(corePath, "utf8");
    const comms = readFileSync(commsPath, "utf8");
    const control = readFileSync(controlPath, "utf8");
    const social = readFileSync(socialPath, "utf8");
    const overview = readFileSync(overviewPath, "utf8");
    const architecture = readFileSync(
      resolve(repositoryRoot, "docs/architecture.md"),
      "utf8",
    );
    const threatModel = readFileSync(threatModelPath, "utf8");

    for (const anchor of [
      "core-marmot-role-binding",
      "core-radicle-group-admission",
    ]) {
      expect(core).toContain(`<a id="${anchor}"></a>`);
    }
    for (const anchor of [
      "comms-marmot",
      "comms-marmot-participation",
      "comms-marmot-groups",
      "comms-marmot-directory",
      "comms-marmot-routing-generation",
      "comms-marmot-event-repository",
      "comms-marmot-exact-bytes",
      "comms-marmot-relay",
      "comms-marmot-rotation",
      "comms-marmot-retention",
      "comms-marmot-persona-inbox",
      "comms-marmot-media",
    ]) {
      expect(comms).toContain(`<a id="${anchor}"></a>`);
    }
    for (const anchor of [
      "control-marmot-operations",
      "control-marmot-agent-operations",
    ]) {
      expect(control).toContain(`<a id="${anchor}"></a>`);
    }

    expect(comms).toContain("4ad4ae21479c3f3fa9950c6fc4556a76941a62e1");
    expect(comms).toMatch(/kind:445[\s\S]*exact bytes/i);
    expect(comms).toMatch(/one-to-one[\s\S]*`h`[\s\S]*event-repository RID/i);
    expect(comms).toMatch(/5 GB[\s\S]*logical unique/i);
    expect(comms).toMatch(/two-member Marmot group/i);
    expect(comms).toMatch(/Double Ratchet[\s\S]*Control[\s\S]*bootstrap/i);
    expect(control).toMatch(/node-mediated[\s\S]*designated full or recovery node/i);
    expect(control).toMatch(/MUST NOT supply[\s\S]*MLS secret/i);
    expect(social).toMatch(/public[\s\S]*publishing[\s\S]*moderation/i);

    for (const relativePath of [
      "docs/spec/schemas/comms/marmot-group-directory-v1.schema.json",
      "docs/spec/schemas/comms/marmot-routing-binding-v1.schema.json",
      "docs/spec/schemas/comms/marmot-event-repository-genesis-v1.schema.json",
      "docs/spec/schemas/comms/marmot-persona-inbox-bundle-v1.schema.json",
      "docs/spec/schemas/comms/marmot-persona-inbox-manifest-v1.schema.json",
    ]) {
      expect(existsSync(resolve(repositoryRoot, relativePath)), relativePath).toBe(true);
    }

    for (const [name, text] of [
      ["overview", overview],
      ["core", core],
      ["comms", comms],
      ["control", control],
      ["social", social],
      ["architecture", architecture],
      ["threat model", threatModel],
    ] as const) {
      expect(text, `${name} retains live Matrix behavior`).not.toMatch(
        /\b(?:Matrix|Megolm|MXID|Social\+Matrix)\b/,
      );
    }
  });

  it("aligns companion architecture with role-scoped Tor, public reading, and agent authorship", () => {
    const readme = readFileSync(resolve(repositoryRoot, "README.md"), "utf8");
    const architecture = readFileSync(
      resolve(repositoryRoot, "docs/architecture.md"),
      "utf8",
    );
    const glossary = readFileSync(resolve(repositoryRoot, "docs/glossary.md"), "utf8");
    const overview = readFileSync(overviewPath, "utf8");

    for (const text of [readme, architecture, overview]) {
      expect(text).toMatch(/full nodes?[\s\S]*onion/i);
      expect(text).toMatch(/browser[\s\S]*reduced-assurance/i);
      expect(text).toMatch(/agent[\s\S]*(scoped|workload token)/i);
    }
    expect(architecture).not.toContain(
      "Every Core client includes self-contained onion reachability.",
    );
    for (const term of [
      "**Public reader.**",
      "**Universal public launcher.**",
      "**Outbound-only Tor client.**",
      "**Agent role.**",
      "**Workload token.**",
      "**Agent-policy receipt.**",
      "**Agent-policy list.**",
    ]) {
      expect(glossary).toContain(term);
    }
  });

  it("models public-reader, agent, relay-affinity, and subscriber-local policy threats", () => {
    const threatModel = readFileSync(threatModelPath, "utf8");

    expect(threatModel).toContain(
      "| Agent role key | Full-node key store; never released to the automated principal |",
    );
    expect(threatModel).toMatch(/Browser claims Tor assurance[\s\S]*reduced-assurance/i);
    expect(threatModel).toMatch(/Public reader crosses a privacy tier[\s\S]*Tier 1/i);
    expect(threatModel).toMatch(/Automated principal impersonates a human[\s\S]*never fallback/i);
    expect(threatModel).toMatch(/Cross-relay retry executes twice[\s\S]*ingress relay/i);
    expect(threatModel).toMatch(/receipt silently becomes a global mute[\s\S]*explicitly subscribes/i);
    expect(threatModel).toMatch(/violation mutes the persona[\s\S]*exact offending device-publishing key/i);
  });

  it("uses only namespaced current invariants and exact registry descriptions", () => {
    const threatModel = readFileSync(threatModelPath, "utf8");
    const registry = JSON.parse(
      readFileSync(resolve(repositoryRoot, "docs/spec/registry/security-invariants.json"), "utf8"),
    ) as { security_invariants: Array<{ id: string; description: string }> };

    expect(threatModel).not.toMatch(/\bI(?:1|3|6|7)\b/);
    expect(findInvariantEvidenceIssues(
      registry.security_invariants,
      threatModel,
    )).toEqual([]);
    expect(CLAIMS_OIDC_INVARIANT_IDS).toHaveLength(11);

    expect(findInvariantEvidenceIssues(
      [...registry.security_invariants, {
        id: "COMMS-I-UNLISTED-FUTURE-INVARIANT",
        description: "A future invariant with no evidence.",
      }],
      threatModel,
    )).toContain(
      "missing invariant evidence: COMMS-I-UNLISTED-FUTURE-INVARIANT",
    );
  });

  it("requires structurally paired threat-model invariant evidence", () => {
    const threatModel = readFileSync(threatModelPath, "utf8");
    const registry = JSON.parse(
      readFileSync(resolve(repositoryRoot, "docs/spec/registry/security-invariants.json"), "utf8"),
    ) as { security_invariants: Array<{ id: string; description: string }> };
    const [firstId, secondId] = CLAIMS_OIDC_INVARIANT_IDS;
    const first = registry.security_invariants.find(({ id }) => id === firstId)!;
    const second = registry.security_invariants.find(({ id }) => id === secondId)!;
    const firstRow = `- **${first.id}:** ${first.description}`;
    const secondRow = `- **${second.id}:** ${second.description}`;
    const swapped = threatModel
      .replace(firstRow, `- **${first.id}:** ${second.description}`)
      .replace(secondRow, `- **${second.id}:** ${first.description}`);
    const floating = threatModel.replace(
      firstRow,
      `${first.id}\n\n${first.description}`,
    );

    expect(findInvariantEvidenceIssues(
      registry.security_invariants,
      swapped,
    )).toEqual(expect.arrayContaining([
      `missing invariant evidence: ${first.id}`,
      `missing invariant evidence: ${second.id}`,
    ]));
    expect(findInvariantEvidenceIssues(
      registry.security_invariants,
      floating,
    )).toContain(`missing invariant evidence: ${first.id}`);
  });

  it("requires claims/OIDC invariant integration in the threat model", () => {
    const threatModel = readFileSync(threatModelPath, "utf8");
    const registry = JSON.parse(
      readFileSync(resolve(repositoryRoot, "docs/spec/registry/security-invariants.json"), "utf8"),
    ) as { security_invariants: Array<{ id: string; description: string }> };
    const required = registry.security_invariants.filter(({ id }) =>
      CLAIMS_OIDC_INVARIANT_IDS.includes(
        id as typeof CLAIMS_OIDC_INVARIANT_IDS[number],
      ),
    );

    expect(required).toHaveLength(11);
    for (const invariant of required) {
      expect(threatModel).toContain(`- **${invariant.id}:** ${invariant.description}`);
    }

    const [integrated] = required;
    const withoutIntegratedRow = threatModel.replace(
      `- **${integrated.id}:** ${integrated.description}`,
      "",
    );
    expect(findInvariantEvidenceIssues(
      registry.security_invariants,
      withoutIntegratedRow,
    )).toContain(`missing invariant evidence: ${integrated.id}`);
  });

  it("maps every claims/OIDC threat to an invariant, Comms anchor, and vectors", () => {
    const threatModel = readFileSync(threatModelPath, "utf8");
    const threatNames = [
      "Claim forgery or semantic malleation",
      "Compromised or stale claim issuer",
      "Delegation-chain amplification",
      "Subject-proof replay",
      "Provisional authorization use",
      "Private-ledger rollback",
      "Private-ledger metadata leakage",
      "Removed ledger reader retains access",
      "Multi-writer policy conflict",
      "OIDC signing-key overdistribution",
      "Stale token minter",
      "Confused deputy or JWT type/audience confusion",
      "OIDC issuer mix-up",
      "Consent overrelease",
      "Status collision, staleness, or downgrade",
      "Radicle/HTTPS equivocation",
      "Issuer-successor hijack",
      "Status-correlation privacy leakage",
    ] as const;
    for (const threat of threatNames) {
      const row = threatModel.split("\n").find((line) => line.startsWith(`| ${threat} |`));
      expect(row, `missing threat row: ${threat}`).toBeDefined();
      expect(row, `${threat} lacks namespaced invariant`).toMatch(/COMMS-I-[A-Z0-9-]+/);
      expect(row, `${threat} lacks permanent Comms mitigation anchor`).toMatch(
        /heterodyne:comms\/0\.5\.0#comms-[a-z0-9-]+/,
      );
      expect(row, `${threat} lacks vector evidence`).toMatch(
        /`(?:claims|claim-ledger|oidc|token-status)\/[0-9]{3}(?:-[a-z0-9-]+)?`/,
      );
    }
  });

  it("keeps private claim state out of public issuer discovery", () => {
    const threatModel = readFileSync(threatModelPath, "utf8");
    for (const privateItem of [
      "private claim",
      "consent record",
      "issuance mapping",
      "audience key",
    ]) {
      expect(threatModel, privateItem).toMatch(
        new RegExp(`${privateItem}[\\s\\S]{0,180}(?:MUST NOT|never)[\\s\\S]{0,120}public (?:issuer )?(?:discovery|continuity)`, "i"),
      );
    }
  });

  it("documents mixed immutable registry revisions without rewriting vector history", () => {
    const readme = readFileSync(resolve(repositoryRoot, "docs/spec/vectors/README.md"), "utf8");
    const coverage = JSON.parse(
      readFileSync(resolve(repositoryRoot, "docs/spec/vectors/coverage/manifest.json"), "utf8"),
    ) as Array<{ registry_revision: number }>;
    const counts = new Map<number, number>();
    for (const { registry_revision: revision } of coverage) {
      counts.set(revision, (counts.get(revision) ?? 0) + 1);
    }

    expect(readme).toContain('"registry_revision": "<pinned-registry-revision>"');
    expect(readme).toMatch(
      new RegExp(`${counts.get(1)}\\s+registry-revision-1\\s+vectors`),
    );
    expect(readme).toMatch(
      new RegExp(`${counts.get(2)} claims/OIDC registry-revision-2 vectors`),
    );
    expect(readme).toMatch(
      new RegExp(`${counts.get(3)}\\s+registry-revision-3 vectors`),
    );
    expect(readme).toMatch(
      new RegExp(`${counts.get(4)} Marmot/Radicle\\s+registry-revision-4 vectors`),
    );
    expect(readme).toMatch(
      /159 cover the gated\s+Control,[\s\S]*11 are\s+credential-continuity draft outer evaluations[\s\S]*`conformance_claimable:false`[\s\S]*do not activate or\s+claim the gated profiles/i,
    );
    expect(readme).toMatch(
      /Historical released vectors[\s\S]*MUST NOT[\s\S]*rewritten/i,
    );
  });

  it("maps exact revocation stamp, tag, and proof checks to their revocation vector", () => {
    const threatModel = readFileSync(threatModelPath, "utf8");
    const row = threatModel.split("\n").find((line) =>
      line.startsWith("| Claim forgery or semantic malleation |")
    );

    expect(row).toContain("`claims/015-authorization-self-revocation`");
    expect(row).toContain("`kind:31014`");
    expect(row).toContain("`comms/0.5.0`");
    expect(row).toContain('`[["d","<claim_id>"]]`');
    expect(row).toMatch(/native proof[\s\S]*Comms profile[\s\S]*registry revision/i);
  });

  it("keeps release approval as the only remaining 0.5.0 release condition", () => {
    const changelog = readFileSync(resolve(repositoryRoot, "CHANGELOG.md"), "utf8");
    const unreleased = sectionUnderHeading(changelog, "## [Unreleased]");
    expect(unreleased).toMatch(/unreleased[\s\S]*explicit release approval/i);
    expect(unreleased).not.toMatch(/until the claims\/OIDC\s+work is complete/i);
  });

  it("advertises claims/OIDC release features only from Comms", () => {
    const manifests = Object.fromEntries(
      (["core", "comms", "control", "social"] as const).map((document) => [
        document,
        JSON.parse(readFileSync(resolve(releasesPath, document, "0.5.0.json"), "utf8")) as {
          registry_revision: number;
          registry_sha256: string;
          dependencies: Record<string, string>;
          features: string[];
        },
      ]),
    );
    const features = [
      "key-claims",
      "private-claim-ledger",
      "oidc-jwt-projection",
      "token-status-list-draft-21",
      "comms.public-reader.v1",
      "comms.agent-authorship.v1",
      "comms.marmot-conversations.v1",
      "comms.radicle-marmot-storage.v1",
      "comms.radicle-backed-marmot-relay.v1",
    ];

    for (const manifest of Object.values(manifests)) {
      expect(manifest.registry_revision).toBe(4);
    }
    expect(manifests.comms.features).toEqual(features);
    expect(manifests.core.features).toEqual([
      "core.nostr-relay-read.v1",
      "core.outbound-tor.v1",
      "core.repo-relay-client.v1",
      "core.onion-service-host.v1",
      "core.browser-shared-relay.v1",
      "core.marmot-role-attribution.v1",
    ]);
    expect(manifests.social.features).toEqual(["social.agent-policy-moderation.v1"]);
    expect(manifests.control.features).toEqual([
      "double-ratchet",
      "control.relay-affinity.v1",
      "control.agent-workload-publication.v1",
      "control.node-mediated-marmot.v1",
    ]);
    expect(manifests.control.dependencies.comms).toBe("comms/0.5.0");
    const control = readFileSync(controlPath, "utf8");
    expect(control).toMatch(/authorize with only `active` state[\s\S]*Comms claim/i);
    expect(control).not.toMatch(/Control-owned claim (?:wire|transport|status) profile/i);
  });

  it("assigns permanent Comms anchors to every claims, ledger, OIDC, status, minting, and continuity surface", () => {
    const comms = readFileSync(commsPath, "utf8");
    const requiredAnchors = [
      "comms-key-claims", "comms-claim-verification", "comms-claim-chain",
      "comms-claim-revocation", "comms-claim-ledger", "comms-oidc-endpoints",
      "comms-oidc-authorization", "comms-jwt-projection", "comms-token-status",
      "comms-multiwriter-minting", "comms-issuer-continuity",
    ];
    for (const anchor of requiredAnchors) expect(comms).toContain(`<a id="${anchor}"></a>`);
    expect(comms).toMatch(/whole atomic signed claims[\s\S]*MUST NOT[\s\S]*SD-JWT/i);
    expect(comms).toMatch(/MUST NOT[\s\S]*automatic(?:ally)?[\s\S]*multiple claim names/i);
    for (const invariant of CLAIMS_OIDC_INVARIANT_IDS) expect(comms).toContain(`**${invariant}:**`);
  });

  it("defines exact claim visibility and repository-backed OAuth claim semantics", () => {
    const comms = readFileSync(commsPath, "utf8");
    expect(comms).toMatch(/`public`[\s\S]*ordinary relays[\s\S]*public profile repository/i);
    expect(comms).toMatch(/`pairwise-private`[\s\S]*full atomic signed claim[\s\S]*Double Ratchet[\s\S]*no backfill/i);
    expect(comms).toMatch(/`repository-private`[\s\S]*encrypted private (?:claim )?ledger/i);
    expect(comms).toMatch(/`local-only`[\s\S]*no protocol artifact/i);
    expect(comms).toMatch(/MUST NOT[\s\S]*cross-visibility[\s\S]*(?:fallback|downgrade)/i);
    expect(comms).toMatch(/unknown visibility[\s\S]*MUST[\s\S]*reject/i);

    expect(comms).toContain("`heterodyne.oidc/client-registration`");
    expect(comms).toContain("`heterodyne.oidc/consent`");
    for (const member of [
      "redirect_uris", "grant_types", "scopes", "audiences", "claims",
      "assertion_profiles", "sector_identifier", "source_claim_ids",
    ]) expect(comms).toContain(`\`${member}\``);
    expect(comms).toMatch(/same exact typed-key subject[\s\S]*repository-private/i);
    expect(comms).toMatch(/concurrent[\s\S]*(?:registration|consent)[\s\S]*conflict[\s\S]*fail closed/i);
    expect(comms).toContain("heterodyne-oidc-pairwise-sub-v1\\0<exact-sector-origin>\\0<local-subject>");
    expect(comms).toMatch(/`local-subject`[\s\S]*exactly 64 lowercase hexadecimal[\s\S]*SHA-256[\s\S]*RFC 8785 JCS[\s\S]*exact typed-key subject/i);
    expect(comms).toMatch(/HMAC[\s\S]*NUL[\s\S]*exact 64 UTF-8 hex\s+characters[\s\S]*unpadded base64url/i);
    expect(comms).toMatch(/HMAC-SHA-256[\s\S]*unpadded base64url[\s\S]*stable across/i);
  });

  it("fully specifies continuity authority, retained material, succession, and status freshness", () => {
    const comms = readFileSync(commsPath, "utf8");
    expect(comms).toMatch(/authority proof[\s\S]*`issued_at`[\s\S]*greater than or equal to[\s\S]*checkpoint/i);
    expect(comms).toMatch(/writer[\s\S]*KEL authority[\s\S]*evaluated at[\s\S]*`issued_at`/i);
    expect(comms).toMatch(/previous-to-current KEL[\s\S]*persona[\s\S]*previous head[\s\S]*current head[\s\S]*half-open/i);
    expect(comms).toMatch(/candidate[\s\S]*exact current[\s\S]*KEL head/i);
    expect(comms).toMatch(/raw closed JWKS bytes[\s\S]*SHA-256[\s\S]*current[\s\S]*retiring[\s\S]*`kid`/i);
    expect(comms).toMatch(/every confirmed unexpired issuance[\s\S]*transitive[\s\S]*status path[\s\S]*usable bytes/i);
    expect(comms).toMatch(/predecessor chain[\s\S]*original issuer[\s\S]*URI/i);
    expect(comms).toMatch(/old issuer[\s\S]*MUST NOT[\s\S]*new issuance[\s\S]*successor/i);
    expect(comms).toMatch(/routine rotation[\s\S]*compromise[\s\S]*INVALID replacement/i);
    expect(comms).toMatch(/status `iat`[\s\S]*manifest checkpoint/i);
    expect(comms).toMatch(/trusted `resolved_at`[\s\S]*`resolved_at \+ ttl < now`[\s\S]*equality[\s\S]*fresh/i);
    expect(comms).toMatch(/`ttl`[\s\S]*finite positive JSON number[\s\S]*`exp`[\s\S]*separate/i);
    expect(comms).toMatch(/retained Status List Token[\s\S]*retiring key[\s\S]*newly generated[\s\S]*current canonical issuer key/i);
  });

  it("keeps every family document unreleased only pending explicit release approval", () => {
    for (const text of [corePath, commsPath, controlPath, socialPath].map((path) => readFileSync(path, "utf8"))) {
      const header = text.split("\n").slice(0, 24).join("\n");
      expect(header).toMatch(/remains unreleased pending explicit release approval/i);
      expect(header).not.toMatch(/pending claims\/OIDC completion/i);
      expect(header).not.toMatch(/\breleased\b|published release/i);
    }
  });

  it("keeps claim and OIDC authority out of Core and wire definitions out of Control and Social", () => {
    const core = readFileSync(corePath, "utf8");
    const comms = readFileSync(commsPath, "utf8");
    const control = readFileSync(controlPath, "utf8");
    const social = readFileSync(socialPath, "utf8");
    for (const text of [core, comms, control, social]) expect(text).toContain("Registry revision: `4`");
    for (const anchor of ["core-typed-key-references", "core-authority-interfaces"]) {
      expect(core).toContain(`<a id="${anchor}"></a>`);
    }
    expect(core).toMatch(/does not define[\s\S]*claims[\s\S]*OIDC[\s\S]*JWT[\s\S]*status/i);
    expect(core).not.toMatch(/kind:31013|kind:31014|statuslist\+jwt|typ: at\+jwt|\/oidc\/<cold-root/i);
    expect(control).toContain('<a id="control-claim-consumption"></a>');
    expect(control).toMatch(/only `active`[\s\S]*Comms claim/i);
    expect(control).toMatch(/provisional[\s\S]*untrusted[\s\S]*conflicted[\s\S]*never[\s\S]*authority/i);
    expect(control).toMatch(/NID-less session devices[\s\S]*filtered[\s\S]*never[\s\S]*(?:ledger|repository)[\s\S]*(?:key|decryption|direct)/i);
    expect(control).not.toMatch(/kind:31013|kind:31014|statuslist\+jwt|claim_id.*SHA-256/i);
    expect(social).not.toMatch(/kind:31013|kind:31014|statuslist\+jwt|\/oidc\/<cold-root|claim_id.*SHA-256/i);
    expect(declaredDependencies(social)).toEqual([
      "heterodyne:core/0.5.0#core-conformance",
      "heterodyne:comms/0.5.0#comms-conformance",
    ]);
  });

  it("resolves every revision-2 claims/OIDC registry and vector reference to a qualified permanent anchor", () => {
    const comms = readFileSync(commsPath, "utf8");
    const anchors = new Set([...comms.matchAll(/<a id="(comms-[a-z0-9-]+)"><\/a>/g)].map((match) => match[1]));
    const revision1 = JSON.parse(readFileSync(resolve(repositoryRoot, "docs/spec/registry/history/1.json"), "utf8")) as {
      reason_codes: Array<{ code: string }>;
    };
    const revision2 = JSON.parse(readFileSync(resolve(repositoryRoot, "docs/spec/registry/history/2.json"), "utf8")) as {
      reason_codes: Array<{ code: string; spec_refs?: string[] }>;
    };
    const oldCodes = new Set(revision1.reason_codes.map(({ code }) => code));
    for (const entry of revision2.reason_codes.filter(({ code }) => !oldCodes.has(code))) {
      expect(entry.spec_refs, entry.code).toHaveLength(1);
      const match = entry.spec_refs![0].match(/^heterodyne:comms\/0\.5\.0#(comms-[a-z0-9-]+)$/);
      expect(match, entry.code).not.toBeNull();
      expect(anchors.has(match![1]), entry.code).toBe(true);
    }

    const vectors = ["claims", "claim-ledger", "oidc", "token-status"].flatMap((topic) => {
      const directory = resolve(repositoryRoot, "docs/spec/vectors", topic);
      return readdirSync(directory)
        .filter((name) => name.endsWith(".json"))
        .map((name) => JSON.parse(readFileSync(resolve(directory, name), "utf8")) as {
          vector_id: string;
          owner_document: string;
          registry_revision: number;
          spec_refs: string[];
        });
    });
    expect(vectors.length).toBeGreaterThan(0);
    for (const vector of vectors) {
      expect(vector.owner_document, vector.vector_id).toBe("comms");
      expect(vector.registry_revision, vector.vector_id).toBe(2);
      expect(vector.spec_refs, vector.vector_id).toHaveLength(1);
      for (const ref of vector.spec_refs) {
        expect(ref, vector.vector_id).not.toContain("temporary:");
        expect(ref, vector.vector_id).not.toMatch(/#comms-conformance$/);
        const match = ref.match(/^heterodyne:comms\/0\.5\.0#(comms-[a-z0-9-]+)$/);
        expect(match, vector.vector_id).not.toBeNull();
        expect(anchors.has(match![1]), `${vector.vector_id}:${ref}`).toBe(true);
      }
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

  it("maps every archived ATX heading exactly once to a current permanent anchor", () => {
    const archive = readFileSync(archivePath, "utf8");
    const anchorMap = readFileSync(anchorMapPath, "utf8");
    const archiveDigest = createHash("sha256").update(archive, "utf8").digest("hex");
    expect(anchorMap).toContain(`Archive SHA-256: \`${archiveDigest}\``);

    const expectedOldAnchors = githubHeadingAnchors(archive);
    const rows = [...anchorMap.matchAll(
      /^\| `(#(?:[^`]+))` \| (Core|Comms|Control|Social) \| `(heterodyne:(core|comms|control|social)\/0\.5\.0#([a-z0-9]+(?:-[a-z0-9]+)*))` \|$/gm,
    )];
    expect(rows.map((row) => row[1])).toEqual(expectedOldAnchors);
    expect(new Set(rows.map((row) => row[1])).size).toBe(expectedOldAnchors.length);

    const family = new Map([
      ["core", readFileSync(corePath, "utf8")],
      ["comms", readFileSync(commsPath, "utf8")],
      ["control", readFileSync(controlPath, "utf8")],
      ["social", readFileSync(socialPath, "utf8")],
    ]);
    for (const row of rows) {
      expect(row[2].toLowerCase()).toBe(row[4]);
      expect(family.get(row[4]), row[3]).toContain(`<a id="${row[5]}"></a>`);
    }
  });

  it("cuts heterodyne.md over to a requirement-free family overview", () => {
    const text = readFileSync(overviewPath, "utf8");

    expect(text).toMatch(/non-normative family overview/i);
    expect(text).toContain("Core <- Comms <- Control");
    expect(text).toContain("Core <- Comms <- Social");
    expect(text).toMatch(/prepared 0\.5\.0 documents/i);
    expect(text).toMatch(
      /unreleased.*explicit\s+release\s+approval/is,
    );
    expect(text).not.toMatch(/current release|release records/i);
    for (const document of ["core", "comms", "control", "social"]) {
      expect(text).toContain(`heterodyne-${document}.md`);
      expect(text).toContain(`${document}/0.5.0`);
    }
    expect(text).toContain("archive/heterodyne-0.4.0.md");
    expect(text).toContain("archive/heterodyne-0.4.0-anchor-map.md");
    expect(text).toContain("registry/manifest.json");
    expect(text).toContain("vectors/coverage/manifest.json");
    expect(text).toContain("vectors/coverage/family.md");
    expect(text).not.toMatch(
      /\b(?:MUST(?: NOT)?|REQUIRED|SHALL(?: NOT)?|SHOULD(?: NOT)?|RECOMMENDED|NOT RECOMMENDED|MAY|OPTIONAL)\b/,
    );
  });

  it("publishes exact registry-bound 0.5.0 release manifests", () => {
    const schema = JSON.parse(
      readFileSync(resolve(releasesPath, "release-manifest.schema.json"), "utf8"),
    ) as AnySchema;
    const validate = new Ajv({ allErrors: true, strict: false }).compile(schema);
    for (const document of ["core", "comms", "control", "social"] as const) {
      const bytes = readFileSync(
        resolve(releasesPath, document, "0.5.0.json"),
        "utf8",
      );
      const actual = JSON.parse(bytes) as ReturnType<typeof expectedReleaseManifests>[typeof document];
      const expected = expectedReleaseManifests(repositoryRoot)[document];
      expect(actual).toEqual(expected);
      expect(() => validateReleaseManifestRegistryPin(repositoryRoot, actual)).not.toThrow();
      expect(() => validateReleaseManifestSchemaPin(repositoryRoot, actual)).not.toThrow();
      expect(validate(actual), JSON.stringify(validate.errors)).toBe(true);
      expect(bytes).toBe(`${canonicalJsonProbe(expected)}\n`);
    }
  });

  it("validates historical and current release pins and rejects unknown or mismatched pins", () => {
    const historical = expectedReleaseManifests(repositoryRoot, 1).core;
    const revision2 = expectedReleaseManifests(repositoryRoot, 2).core;
    const current = expectedReleaseManifests(repositoryRoot, 4).core;
    expect(() => validateReleaseManifestRegistryPin(repositoryRoot, historical)).not.toThrow();
    expect(() => validateReleaseManifestRegistryPin(repositoryRoot, revision2)).not.toThrow();
    expect(() => validateReleaseManifestRegistryPin(repositoryRoot, current)).not.toThrow();
    expect(() => validateReleaseManifestRegistryPin(repositoryRoot, {
      ...historical,
      registry_revision: 999,
    })).toThrow(/unknown registry history revision 999/);
    expect(() => validateReleaseManifestRegistryPin(repositoryRoot, {
      ...historical,
      registry_sha256: "0".repeat(64),
    })).toThrow(/registry digest mismatch/);
    expect(loadReleaseSchemaRegistryPin(repositoryRoot)).toEqual({
      registry_revision: 4,
      registry_sha256: current.registry_sha256,
    });
    expect(() => validateReleaseManifestSchemaPin(repositoryRoot, historical)).toThrow(
      /does not match release schema pin/,
    );
    expect(() => validateReleaseManifestSchemaPin(repositoryRoot, current)).not.toThrow();
  });

  it("can generate an explicitly selected historical pin without drift", () => {
    const historical = expectedReleaseManifests(repositoryRoot, 1).core;
    withReleaseFixture(1, historical.registry_sha256, (root) => {
      const paths = ["core", "comms", "control", "social"].map((document) =>
        resolve(root, `docs/spec/releases/${document}/0.5.0.json`),
      );
      writeReleaseManifests(root);
      const first = paths.map((path) => readFileSync(path, "utf8"));
      writeReleaseManifests(root);
      const second = paths.map((path) => readFileSync(path, "utf8"));
      expect(second).toEqual(first);
      expect(second.every((bytes) => JSON.parse(bytes).registry_revision === 1)).toBe(true);
    });
  });

  it("uses a revision-2 schema pin deterministically and rejects bad schema pins", () => {
    const revision2 = expectedReleaseManifests(repositoryRoot, 2).core;
    withReleaseFixture(2, revision2.registry_sha256, (root) => {
      writeReleaseManifests(root);
      const first = readFileSync(resolve(root, "docs/spec/releases/core/0.5.0.json"), "utf8");
      writeReleaseManifests(root);
      const second = readFileSync(resolve(root, "docs/spec/releases/core/0.5.0.json"), "utf8");
      expect(second).toBe(first);
      expect(JSON.parse(second)).toMatchObject({
        registry_revision: 2,
        registry_sha256: revision2.registry_sha256,
      });
    });

    withReleaseFixture(999, "0".repeat(64), (root) => {
      expect(() => writeReleaseManifests(root)).toThrow(
        /unknown registry history revision 999/,
      );
    });
    withReleaseFixture(1, "0".repeat(64), (root) => {
      expect(() => writeReleaseManifests(root)).toThrow(/registry digest mismatch/);
    });
  });

  it("finalizes sibling lineage and companion authority at cutover", () => {
    for (const path of [corePath, commsPath, controlPath, socialPath]) {
      const text = readFileSync(path, "utf8");
      expect(text).not.toMatch(/pre-release extraction draft/i);
      expect(text).toMatch(
        /first[\s\S]*0\.5\.0[\s\S]*release[\s\S]*descended[\s\S]*0\.4\.x/i,
      );
    }
    const control = readFileSync(controlPath, "utf8");
    expect(control).toMatch(/incomplete 0\.5\.0 draft/i);
    expect(control).toMatch(/makes no Control\s+conformance claim/);

    for (const relativePath of preCutoverCompanionPaths) {
      const text = readFileSync(resolve(repositoryRoot, relativePath), "utf8");
      expect(text, `${relativePath} retains stale pre-cutover authority`).not.toMatch(
        /pre-cutover authority|current normative 0\.4\.0 monolith|until the Task 9 cutover/i,
      );
    }

    const changelog = readFileSync(resolve(repositoryRoot, "CHANGELOG.md"), "utf8");
    const unreleased = sectionUnderHeading(changelog, "## [Unreleased]");
    expect(unreleased).toMatch(/prepared[\s\S]*0\.5\.0/i);
    for (const document of ["Core", "Comms", "Control", "Social"]) {
      expect(unreleased).toContain(`### ${document} 0.5.0`);
    }
    expect(changelog).not.toMatch(/## 0\.5\.0 document releases|\bPublished\b/);
  });

  it("passes the executable family-cutover lint", () => {
    expect(lintFamilyCutover(repositoryRoot)).toEqual([]);
  });

  it("retains concrete group, ratchet, moderation, storage, and crypto residuals", () => {
    const text = readFileSync(threatModelPath, "utf8");

    expect(text).toMatch(
      /Marmot and Radicle group paths[\s\S]*ref activity[\s\S]*host topology/i,
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

  it.each([
    ["ADR number", "ADR-039 records this decision."],
    ["ADR path", "See docs/adr/archive/ for rationale."],
  ])("rejects non-canonical %s references in live specifications", (_case, reference) => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          reference,
          '<a id="core-identity-model"></a>',
        ].join("\n"),
      },
      (root) =>
        expect(lintFamilyDocs(root)).toContainEqual(
          expect.objectContaining({
            path: "docs/spec/heterodyne-core.md",
            line: 2,
            code: "noncanonical-decision-reference",
          }),
      ),
    );
  });

  it("permits lowercase legacy text inside an opaque protocol identifier", () => {
    withFamilyDocs(
      {
        core: [
          "Document ID: `core`",
          "The discriminator is `production-rule:adr-031-kind0-v1`.",
          '<a id="core-identity-model"></a>',
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
