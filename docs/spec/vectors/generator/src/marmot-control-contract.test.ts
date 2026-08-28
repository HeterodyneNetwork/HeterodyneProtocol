import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../../../../");

function read(relativePath: string): string {
  return readFileSync(resolve(repositoryRoot, relativePath), "utf8");
}

describe("Marmot Control canonical contract", () => {
  it("activates baseline Control from the active key without Double Ratchet or Assurance gating", () => {
    const control = read("docs/spec/heterodyne-control.md");

    expect(control).toContain('"spec_version": "heterodyne/0.6.0"');
    expect(control).toContain('"transport_owner": "marmot"');
    expect(control).toContain('"can_claim_control_conformance": true');
    expect(control).toMatch(/bare[\s\S]*active Nostr key[\s\S]*complete Control persona/i);
    expect(control).toMatch(/Assurance[\s\S]*not a Control prerequisite/i);
    expect(control).not.toMatch(/nostr-double-ratchet|kind:31015|kind:31016/i);
  });

  it("defines the closed Marmot frame, entitlement, token, failover, and recovery anchors", () => {
    const control = read("docs/spec/heterodyne-control.md");
    for (const anchor of [
      "control-discovery",
      "control-invitation-policy",
      "control-frame",
      "control-enrollment",
      "control-entitlement",
      "control-token",
      "control-request-processing",
      "control-failover",
      "control-retention",
      "control-epoch-bootstrap",
      "control-radicle-recovery",
      "control-sftp-recovery",
      "control-conformance",
    ]) {
      expect(control).toContain(`<a id="${anchor}"></a>`);
    }
  });

  it("uses one registry pin, an invite rumor kind, and one inner-only Control profile", () => {
    const manifest = JSON.parse(read("docs/spec/registry/manifest.json")) as {
      revision: number;
    };
    const kinds = JSON.parse(read("docs/spec/registry/kinds.json")) as {
      kinds: Array<{ kind: number; profiles: Array<{ profile_id: string; owner: string; discriminator: string }> }>;
    };

    expect(manifest.revision).toBeGreaterThan(0);
    expect(kinds.kinds.find(({ kind }) => kind === 31017)?.profiles).toContainEqual(
      expect.objectContaining({
        profile_id: "heterodyne-control-marmot-frame-v1",
        owner: "control",
        discriminator: "marmot-inner-only;content=control-frame-v1",
      }),
    );
    expect(kinds.kinds.find(({ kind }) => kind === 31018)).toMatchObject({
      base_schema_owner: "comms",
      profiles: [],
    });
    expect(JSON.stringify(kinds)).not.toMatch(/heterodyne-comms-double-ratchet|heterodyne-control-session-device/);
  });

  it("publishes every current closed Control schema", () => {
    for (const name of [
      "control-frame-v1.schema.json",
      "control-client-authorization-v1.schema.json",
      "control-operation-record-v1.schema.json",
      "control-agent-publish-v1.schema.json",
      "control-audit-record-v1.schema.json",
      "control-capability-set-v1.schema.json",
      "control-device-authorization-state-v1.schema.json",
      "control-recovery-grant-v1.schema.json",
      "control-recovery-completion-v1.schema.json",
    ]) {
      expect(existsSync(resolve(repositoryRoot, "docs/spec/schemas/control", name)), name).toBe(true);
    }
  });

  it("registers multi-persona signing and compromise reset features", () => {
    const features = JSON.parse(read("docs/spec/registry/features.json")) as {
      features: Array<{ id: string; owner: string }>;
    };
    const control = features.features
      .filter(({ owner }) => owner === "control")
      .map(({ id }) => id);
    expect(control).toEqual(expect.arrayContaining([
      "control.marmot.v1",
      "control.multi-persona-vaults.v1",
      "control.nip46-oidc-signing.v1",
      "control.agent-workload-publication.v1",
      "control.trusted-seed-provisioning.v1",
      "control.compromise-reset.v1",
    ]));
    const specText = read("docs/spec/heterodyne-control.md");
    expect(specText).toMatch(/Optional Assurance[\s\S]*not a Control prerequisite/);
  });
});
