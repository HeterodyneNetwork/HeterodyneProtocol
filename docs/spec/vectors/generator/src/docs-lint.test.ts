import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  findInvariantEvidenceIssues,
  findStrictProfileClosureIssues,
  lintFamilyDocs,
  lintMaintainedGuides,
  lintReleaseReadiness,
} from "./docs-lint.js";
import { loadRegistry } from "./registry.js";

const repositoryRoot = resolve(import.meta.dirname, "../../../../../");
const read = (path: string) => readFileSync(resolve(repositoryRoot, path), "utf8");

describe("canonical family documentation", () => {
  it("passes layering, anchor, and release-readiness lint", () => {
    expect(lintFamilyDocs(repositoryRoot)).toEqual([]);
    expect(lintReleaseReadiness(repositoryRoot)).toEqual([]);
  });

  it("keeps maintained authoring guides on the single-family model", () => {
    expect(lintMaintainedGuides(repositoryRoot)).toEqual([]);

    const vectors = JSON.parse(
      read("docs/spec/vectors/coverage/manifest.json"),
    ) as unknown[];
    const vectorReadme = read("docs/spec/vectors/README.md");
    expect(vectorReadme).toContain(`${vectors.length} normative vectors`);
  });

  it("requires every guide to state each profile-revision fact", () => {
    const { revision } = JSON.parse(
      read("docs/spec/registry/manifest.json"),
    ) as { revision: number };
    const currentRegistryRevision = `current family registry revision ${revision}`;
    const guides = ["docs/glossary.md", "docs/security/threat-model.md"];
    const mutations = [
      ["member", (text: string) => text.replace("profile_revision", "claim_profile_revision")],
      ["frozen status", (text: string) => text.replace("frozen", "recorded")],
      ["value", (text: string) => text.replace("`2`", "`3`")],
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
    for (const document of ["core", "comms", "control", "social", "workspace"]) {
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
    expect(control).toMatch(/portable recovery[\s\S]*not\s+required for baseline Control/i);
    expect(control).toMatch(/separate\s+onion service[\s\S]*separate operating-system process/i);
  });

  it("contains no retired Control or direct-message wire vocabulary in live specs", () => {
    const text = ["core", "comms", "control", "social", "workspace"]
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
      ["core", "comms", "control", "social", "workspace"].map((document) => [
        document,
        read(`docs/spec/heterodyne-${document}.md`),
      ]),
    );
    const invariants = loadRegistry(repositoryRoot).security_invariants;
    expect(findStrictProfileClosureIssues(documents, invariants)).toEqual([]);

    const fixture = (profile: unknown) =>
      `\n<!-- fixture:extra-strict-profile -->\n\`\`\`json\n${JSON.stringify(profile)}\n\`\`\`\n`;
    const withFixture = (profile: unknown) =>
      findStrictProfileClosureIssues(
        { ...documents, core: documents.core + fixture(profile) },
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
      profile_id: "heterodyne-core-strict-v9",
      requires_profiles: [],
      adds_invariants: ["CORE-I-MARMOT-ROLE-ATTRIBUTION"],
    })).toContain(
      "feature-bound added invariant: heterodyne-core-strict-v9 -> CORE-I-MARMOT-ROLE-ATTRIBUTION"
        + " is bound to core.marmot-role-attribution.v1",
    );
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
    expect(requires("control.oauth-device-enrollment.v1", oidc)).toBe(true);
    // A node-scoped token is verified only by its own issuer, so it needs none
    // of the third-party discovery, continuity, or status machinery.
    expect(requires("control.node-scoped-token.v1", oidc)).toBe(false);
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

  it("carries the single family version on every registry entry", () => {
    const registry = loadRegistry(repositoryRoot);
    const versions = new Set([
      ...registry.kinds.map(({ first_version }) => first_version),
      ...registry.kinds.flatMap(({ profiles }) =>
        profiles.map(({ first_version }) => first_version)),
      ...registry.reason_codes.map(({ first_version }) => first_version),
      ...registry.security_invariants.map(({ first_version }) => first_version),
      ...registry.features.map(({ first_version }) => first_version),
      ...registry.objects.map(({ first_version }) => first_version),
    ]);
    expect([...versions]).toEqual(["heterodyne/0.5.0"]);
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
});
