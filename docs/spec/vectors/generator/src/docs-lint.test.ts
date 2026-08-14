import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  expectedReleaseManifests,
  findInvariantEvidenceIssues,
  findStrictProfileClosureIssues,
  lintFamilyCutover,
  lintFamilyDocs,
  loadReleaseSchemaRegistryPin,
  releaseManifestBytes,
  validateReleaseManifestRegistryPin,
  validateReleaseFeatureResolution,
} from "./docs-lint.js";
import { loadRegistry } from "./registry.js";

const repositoryRoot = resolve(import.meta.dirname, "../../../../../");
const read = (path: string) => readFileSync(resolve(repositoryRoot, path), "utf8");

describe("canonical family documentation", () => {
  it("passes dependency, anchor, archive, release, and cutover lint", () => {
    expect(lintFamilyDocs(repositoryRoot)).toEqual([]);
    expect(lintFamilyCutover(repositoryRoot)).toEqual([]);
  });

  it("keeps live specifications independent of noncanonical decision records", () => {
    for (const document of ["core", "comms", "control", "social", "workspace"]) {
      const text = read(`docs/spec/heterodyne-${document}.md`);
      expect(text).not.toMatch(/docs\/adr|ADR-\d+/);
    }
  });

  it("defines active Marmot Control and optional recovery without legacy carriers", () => {
    const control = read("docs/spec/heterodyne-control.md");
    expect(control).toContain("Status: **0.5.0 draft**");
    expect(control).toContain('"can_claim_control_conformance": true');
    expect(control).toContain('"transport_owner": "marmot"');
    expect(control).toMatch(/default is five minutes/i);
    expect(control).toMatch(/Sixty minutes is an[\s\S]*absolute maximum/i);
    expect(control).toMatch(/portable recovery[\s\S]*not\s+required for baseline Control/i);
    expect(control).toMatch(/separate\s+onion service[\s\S]*separate operating-system process/i);
  });

  it("contains no retired Control or direct-message wire vocabulary in live specs", () => {
    const text = ["core", "comms", "control", "social"]
      .map((document) => read(`docs/spec/heterodyne-${document}.md`))
      .join("\n");
    expect(text).not.toMatch(/kind:31015|kind:31016|kind:1059|kind:1060/i);
    expect(text).not.toMatch(/session-device|ingress-relay|nostr-double-ratchet/i);
  });

  it("keeps pairwise claims and direct messages on standard Marmot groups", () => {
    const comms = read("docs/spec/heterodyne-comms.md");
    expect(comms).toMatch(/pairwise-private[\s\S]*two-member Marmot group/i);
    expect(comms).toMatch(/Direct messages[\s\S]*standard[\s\S]*Marmot/i);
    expect(comms).toMatch(/credential continuity drafts[\s\S]*not required by baseline Control/i);
  });

  it("keeps the full-node registry and recovery contract explicit in Core", () => {
    const core = read("docs/spec/heterodyne-core.md");
    expect(core).toMatch(/full-node Control and recovery metadata/i);
    expect(core).toMatch(/light-only Control principal[\s\S]*not a Core device/i);
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

  it("declares complete flattened strict-profile prerequisite membership", () => {
    const documents = Object.fromEntries(
      ["core", "comms", "control", "social", "workspace"].map((document) => [
        document,
        read(`docs/spec/heterodyne-${document}.md`),
      ]),
    );
    expect(findStrictProfileClosureIssues(documents)).toEqual([]);
    documents.core += `\n<!-- fixture:conflicting-strict-profile -->\n\`\`\`json\n${JSON.stringify({
      profile_id: "heterodyne-core-strict-v1",
      requires_profiles: [],
      required_invariants: ["CORE-I-IDENTITY-INTEGRITY"],
    })}\n\`\`\`\n`;
    expect(findStrictProfileClosureIssues(documents))
      .toContain("conflicting strict-profile membership: heterodyne-core-strict-v1");
  });
});

describe("registry-bound release artifacts", () => {
  it("pins release schema and all manifests to registry revision 8", () => {
    const pin = loadReleaseSchemaRegistryPin(repositoryRoot);
    expect(pin.registry_revision).toBe(8);
    expect(pin.registry_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(() => validateReleaseManifestRegistryPin(repositoryRoot, pin)).not.toThrow();

    const expected = expectedReleaseManifests(repositoryRoot);
    for (const document of ["core", "comms", "control", "social"] as const) {
      expect(read(`docs/spec/releases/${document}/0.5.0.json`))
        .toBe(releaseManifestBytes(expected[document]));
    }
    expect(read("docs/spec/releases/workspace/0.1.0.json"))
      .toBe(releaseManifestBytes(expected.workspace));
  });

  it("publishes the base Workspace release with optional higher-layer dependencies", () => {
    const manifest = expectedReleaseManifests(repositoryRoot).workspace;
    expect(manifest.qualified_version).toBe("workspace/0.1.0");
    expect(manifest.dependencies).toEqual({
      core: "core/0.5.0",
      comms: "comms/0.5.0",
      control: "control/0.5.0",
      social: "social/0.5.0",
    });
    expect(manifest.required_features).toEqual([
      "core.marmot-role-attribution.v1",
      "core.repo-relay-client.v1",
      "comms.marmot-conversations.v1",
      "comms.radicle-marmot-storage.v1",
      "comms.radicle-backed-marmot-relay.v1",
    ]);
  });

  it("advertises active Control separately from optional recovery features", () => {
    const manifest = expectedReleaseManifests(repositoryRoot).control;
    expect(manifest.conformance_status).toBe("conformant");
    expect(manifest.provided_features).toEqual([
      "control.marmot.v1",
      "control.oauth-device-enrollment.v1",
      "control.private-entitlement.v1",
      "control.node-scoped-token.v1",
      "control.agent-workload-publication.v1",
      "control.node-mediated-marmot.v1",
      "control.recovery.radicle.v1",
      "control.recovery.epoch-inbox.v1",
      "control.recovery.sftp.v1",
    ]);
    expect(manifest.required_features).toEqual([
      "core.repo-relay-client.v1",
      "comms.agent-authorship.v1",
      "comms.marmot-conversations.v1",
      "comms.oidc-jwt-projection.v1",
      "comms.private-claim-ledger.v1",
      "comms.radicle-marmot-storage.v1",
    ]);
    expect(new Set(manifest.provided_features).size)
      .toBe(manifest.provided_features.length);
    expect(new Set(manifest.required_features).size)
      .toBe(manifest.required_features.length);
  });

  it("rejects a required feature absent from the exact dependency release", () => {
    const manifests = structuredClone(expectedReleaseManifests(repositoryRoot));
    manifests.comms.provided_features = manifests.comms.provided_features
      .filter((feature) => feature !== "comms.agent-authorship.v1");
    expect(() => validateReleaseFeatureResolution(loadRegistry(repositoryRoot), manifests))
      .toThrow(/not provided by exact dependency/);
  });

  it("rejects a provided feature whose external prerequisite is undeclared", () => {
    const manifests = structuredClone(expectedReleaseManifests(repositoryRoot));
    manifests.comms.required_features = manifests.comms.required_features
      .filter((feature) => feature !== "core.marmot-role-attribution.v1");
    expect(() => validateReleaseFeatureResolution(loadRegistry(repositoryRoot), manifests))
      .toThrow(/external prerequisite not required/);
  });

  it("mirrors every registered invariant exactly in the threat model", () => {
    const registry = loadRegistry(repositoryRoot);
    expect(findInvariantEvidenceIssues(
      registry.security_invariants,
      read("docs/security/threat-model.md"),
    )).toEqual([]);
  });
});
