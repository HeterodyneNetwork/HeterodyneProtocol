import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  expectedReleaseManifests,
  findInvariantEvidenceIssues,
  lintFamilyCutover,
  lintFamilyDocs,
  loadReleaseSchemaRegistryPin,
  releaseManifestBytes,
  validateReleaseManifestRegistryPin,
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
    for (const document of ["core", "comms", "control", "social"]) {
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
});

describe("registry-bound release artifacts", () => {
  it("pins release schema and all manifests to registry revision 5", () => {
    const pin = loadReleaseSchemaRegistryPin(repositoryRoot);
    expect(pin.registry_revision).toBe(5);
    expect(pin.registry_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(() => validateReleaseManifestRegistryPin(repositoryRoot, pin)).not.toThrow();

    const expected = expectedReleaseManifests(repositoryRoot);
    for (const document of ["core", "comms", "control", "social"] as const) {
      expect(read(`docs/spec/releases/${document}/0.5.0.json`))
        .toBe(releaseManifestBytes(expected[document]));
    }
  });

  it("advertises active Control separately from optional recovery features", () => {
    const manifest = expectedReleaseManifests(repositoryRoot).control;
    expect(manifest.conformance_status).toBe("conformant");
    expect(manifest.features).toEqual([
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
  });

  it("mirrors every registered invariant exactly in the threat model", () => {
    const registry = loadRegistry(repositoryRoot);
    expect(findInvariantEvidenceIssues(
      registry.security_invariants,
      read("docs/security/threat-model.md"),
    )).toEqual([]);
  });
});
