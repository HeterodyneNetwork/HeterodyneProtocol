import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  computeRegistryDigest,
  validateRegistry,
  type RegistryEntrySet,
  type RegistryManifest,
} from "./registry.js";

const here = dirname(fileURLToPath(import.meta.url));
const registryRoot = resolve(here, "../../../registry");

const REVISION_17_ENTRY_SET_SHA256 =
  "1e37021c334fcbd01b3b15679779d59308833a85f612180630061e41cf72fb17";
const REVISION_18_ENTRY_SET_SHA256 =
  "068c36d589bd2eac4a65245c93095beca4134bbdfae9dabc845485a71c58933f";
const REVISION_17_IDENTITY_TUPLES_SHA256 =
  "852355247956e80edfc1e987d5e46c6f1c15b47c635d2f176d69450967806a26";

const PUBLIC_READER_PRIVATE_CONTENT_OLD_DESCRIPTION =
  "Public-reader mode was asked to render Tier 2 plaintext or interpret Tier 3 ciphertext as public content.";
const PUBLIC_READER_PRIVATE_CONTENT_NEW_DESCRIPTION =
  "Public-reader mode was asked to render private-repository plaintext or interpret Tier 2 or Tier 3 ciphertext as public content.";

const REVISION_17_REASON_REFINEMENTS = [
  ["agent-attribution-bypass-prohibited", "Retained non-wire history for the retired diagnostic that classified omitted, altered, or falsified canonical agent attribution; current attribution-before-signing is governed by live publication authority.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-human-profile-prohibited", "Retained non-wire history for the retired diagnostic that classified bypass of the selected persona vault, signer, or key class; current signer selection is governed by live publication authority.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-key-access-prohibited", "Retained non-wire history for the retired diagnostic that classified requests for private key material or raw signing authority; current key confinement is governed by live signer boundaries.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-method-prohibited", "Retained non-wire history for the retired diagnostic that classified methods outside the closed agentic Control surface; current method authorization is governed by exact grants.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-resource-denied", "Retained non-wire history for the retired diagnostic that classified operations outside an exact active signer grant; current resource authorization is governed by exact grants.", "heterodyne:0.6.0#control-retired-semantics"],
  ["agent-sender-proof-invalid", "The required per-use DPoP/JWK proof is missing, replayed, malformed, or mismatched with the verified token, registered sender key, method, target, or nonce.", "heterodyne:0.6.0#comms-agent-token"],
  ["auth_rejected_permanent", "Local relay-write diagnostic for a repeated post-NIP-42 AUTH rejection; it is diagnostic-only and non-wire for semantic coverage and proves no cryptographic or upstream authority.", "heterodyne:0.6.0#comms-retired-semantics"],
  ["control-keypackage-replenishment-paused", "Authenticated current enrollment state marks public Control KeyPackage replenishment as paused.", "heterodyne:0.6.0#control-invitation-policy"],
  ["control-request-id-conflict", "Retained non-wire history for the retired diagnostic that classified request-identifier reuse with different canonical bound bytes; current at-most-once execution is governed by the durable signer fence.", "heterodyne:0.6.0#control-retired-semantics"],
  ["control-signed-event-invalid", "Retained non-wire history for the retired diagnostic that classified altered or invalid signer output; current signer-output verification is governed by publication and signer-fence boundaries.", "heterodyne:0.6.0#control-retired-semantics"],
  ["dm_invite_revoked_device", "Retained non-wire history for the retired kind:30078 device-revocation diagnostic; current invitation authentication and revocation boundaries do not emit this code.", "heterodyne:0.6.0#comms-retired-semantics"],
  ["dm_invite_unbound_device", "Retained non-wire history for the retired kind:30078 device-delegation diagnostic; current invitation authentication and account-binding boundaries do not emit this code.", "heterodyne:0.6.0#comms-retired-semantics"],
  ["invite-preauthorization-invalid", "The signed Control invite, exact preauthorization template, client binding, purpose, expiry, or current revocation state does not authorize the captured request.", "heterodyne:0.6.0#control-one-time-invites"],
  ["marmot-agent-scope-denied", "The authenticated current persona-inbox authorization does not permit the captured agent sender, request, or required first-contact scope.", "heterodyne:0.6.0#comms-marmot-persona-inbox"],
  ["marmot-keypackage-replayed", "The selected Marmot KeyPackage is already durably consumed by authenticated inbox state or a closed available or committed reservation.", "heterodyne:0.6.0#comms-marmot-persona-inbox"],
  ["marmot-private-inbox-nid-required", "The authenticated current recipient repository authorization lacks the NID binding required for private persona-inbox admission.", "heterodyne:0.6.0#comms-marmot-persona-inbox"],
  ["profile-repository-selection-required", "The selected canonical profile requires authenticated repository state, but no current writer-authenticated repository candidate supplies it.", "heterodyne:0.6.0#core-persona-profile"],
  ["relay_profile_mutation", "The retained raw profile-event bytes do not exactly match a valid NIP-01 event identifier, signature, or exposed event fields.", "heterodyne:0.6.0#core-operational-authority-views"],
  ["retired-key-authority-window-invalid", "Retained non-wire history for retired-key content outside a former key-authority window; current Core verification and source-neutral selection do not emit this code.", "heterodyne:0.6.0#core-retired-semantics"],
  ["revoked_key_post_compromise", "Retained non-wire history for the retired duplicate classification at or after an accepted compromise_since cutoff; current Assurance uses evaluateAssuranceAuthorityAt.", "heterodyne:0.6.0#assurance-retired-semantics"],
  ["strict_mode_tor_disabled", "The captured client role claims the strict profile while the current transport route is not Tor.", "heterodyne:0.6.0#core-operational-authority-views"],
  ["unauthorized_cache_content", "A friend-cache candidate lacks an exact valid NIP-01 signature by the expected persona author.", "heterodyne:0.6.0#core-operational-authority-views"],
  ["workspace_replay", "A Workspace invitation or other consuming authority input was reused with mismatched bindings or before its exact committed terminal was established.", "heterodyne:0.6.0#workspace-errors"],
] as const;

function readJson<T>(name: string): T {
  return JSON.parse(readFileSync(join(registryRoot, name), "utf8")) as T;
}

function readEntrySet(): RegistryEntrySet {
  return {
    kinds: readJson<{ kinds: RegistryEntrySet["kinds"] }>("kinds.json").kinds,
    reason_codes: readJson<{ reason_codes: RegistryEntrySet["reason_codes"] }>("reason-codes.json").reason_codes,
    security_invariants: readJson<{ security_invariants: RegistryEntrySet["security_invariants"] }>("security-invariants.json").security_invariants,
    features: readJson<{ features: RegistryEntrySet["features"] }>("features.json").features,
    objects: readJson<{ objects: RegistryEntrySet["objects"] }>("objects.json").objects,
    proof_domains: readJson<{ proof_domains: RegistryEntrySet["proof_domains"] }>("proof-domains.json").proof_domains,
  };
}

function identityTuples(entrySet: RegistryEntrySet): Array<[string, string, string, string, string]> {
  return [
    ...entrySet.features.map(({ id, owner, status, first_version }) => ["feature", id, owner, status, first_version] as [string, string, string, string, string]),
    ...entrySet.kinds.map(({ kind, allocation_authority, status, first_version }) => ["kind", String(kind), allocation_authority, status, first_version] as [string, string, string, string, string]),
    ...entrySet.kinds.flatMap(({ kind, profiles }) => profiles.map(({ profile_id, owner, status, first_version }) => ["kind-profile", `${kind}:${profile_id}`, owner, status, first_version] as [string, string, string, string, string])),
    ...entrySet.objects.map(({ id, owner, status, first_version }) => ["object", id, owner, status, first_version] as [string, string, string, string, string]),
    ...entrySet.proof_domains.map(({ id, owner, status, first_version }) => ["proof-domain", id, owner, status, first_version] as [string, string, string, string, string]),
    ...entrySet.reason_codes.map(({ code, owner, status, first_version }) => ["reason-code", code, owner, status, first_version] as [string, string, string, string, string]),
    ...entrySet.security_invariants.map(({ id, owner, status, first_version }) => ["security-invariant", id, owner, status, first_version] as [string, string, string, string, string]),
  ].sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

describe("registry revision 17 historical reconstruction", () => {
  it("BLUE TEAM VALIDATION: raw JSON reconstructs immutable revision 17 from the sole live revision 18 semantic delta", () => {
    const manifestText = readFileSync(join(registryRoot, "manifest.json"), "utf8");
    const manifest = JSON.parse(manifestText) as RegistryManifest;
    expect(manifest).toEqual({
      revision: 18,
      schema_version: "3.0.0",
      entry_set_sha256: REVISION_18_ENTRY_SET_SHA256,
    });

    const entrySet = readEntrySet();
    const rows = identityTuples(entrySet);
    expect(rows).toHaveLength(458);
    expect(createHash("sha256").update(JSON.stringify(rows)).digest("hex"))
      .toBe(REVISION_17_IDENTITY_TUPLES_SHA256);

    const reason = entrySet.reason_codes.find(
      ({ code }) => code === "public-reader-private-content",
    );
    expect(reason).toEqual({
      code: "public-reader-private-content",
      owner: "comms",
      status: "draft",
      first_version: "heterodyne/0.5.0",
      description: PUBLIC_READER_PRIVATE_CONTENT_NEW_DESCRIPTION,
      spec_refs: ["heterodyne:0.6.0#comms-retrieval"],
    });

    const revision17EntrySet = structuredClone(entrySet);
    const revision17Reason = revision17EntrySet.reason_codes.find(
      ({ code }) => code === "public-reader-private-content",
    );
    if (revision17Reason === undefined) {
      throw new Error("revision 18 preflight requires public-reader-private-content");
    }
    revision17Reason.description = PUBLIC_READER_PRIVATE_CONTENT_OLD_DESCRIPTION;

    expect(computeRegistryDigest(revision17EntrySet))
      .toBe(REVISION_17_ENTRY_SET_SHA256);
    const revision17Manifest: RegistryManifest = {
      ...manifest,
      revision: 17,
      entry_set_sha256: REVISION_17_ENTRY_SET_SHA256,
    };
    expect(() => validateRegistry({
      manifest: revision17Manifest,
      ...revision17EntrySet,
    }, registryRoot))
      .not.toThrow();

    const revision18Digest = computeRegistryDigest(entrySet);
    expect(revision18Digest).toBe(REVISION_18_ENTRY_SET_SHA256);
    expect(() => validateRegistry({
      manifest,
      ...entrySet,
    }, registryRoot)).not.toThrow();

    const reasons = new Map(entrySet.reason_codes.map((entry) => [entry.code, entry]));
    for (const [code, description, specRef] of REVISION_17_REASON_REFINEMENTS) {
      expect(reasons.get(code)).toMatchObject({ description, spec_refs: [specRef] });
    }
  });
});
