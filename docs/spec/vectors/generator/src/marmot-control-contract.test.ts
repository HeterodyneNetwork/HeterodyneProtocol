import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../../../../");

function read(relativePath: string): string {
  return readFileSync(resolve(repositoryRoot, relativePath), "utf8");
}

describe("Marmot Control canonical contract", () => {
  it("activates baseline Control without Double Ratchet or recovery gating", () => {
    const control = read("docs/spec/heterodyne-control.md");

    expect(control).toMatch(/Status: \*\*0\.5\.0 draft\*\*/);
    expect(control).toContain('"transport_owner": "marmot"');
    expect(control).toContain('"can_claim_control_conformance": true');
    expect(control).toMatch(/portable recovery[\s\S]*not\s+required for baseline Control/i);
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

  it("uses registry revision 8, an invite rumor kind, and one inner-only Control profile", () => {
    const manifest = JSON.parse(read("docs/spec/registry/manifest.json")) as {
      revision: number;
    };
    const kinds = JSON.parse(read("docs/spec/registry/kinds.json")) as {
      kinds: Array<{ kind: number; profiles: Array<{ profile_id: string; owner: string; discriminator: string }> }>;
    };

    expect(manifest.revision).toBe(8);
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

  it("publishes every replacement closed schema", () => {
    for (const name of [
      "control-frame-v1.schema.json",
      "control-client-authorization-v1.schema.json",
      "control-operation-record-v1.schema.json",
      "control-epoch-registration-v1.schema.json",
      "control-prepared-activation-v1.schema.json",
      "control-recovery-grant-v1.schema.json",
      "control-recovery-completion-v1.schema.json",
      "control-sftp-grant-v1.schema.json",
    ]) {
      expect(existsSync(resolve(repositoryRoot, "docs/spec/schemas/control", name)), name).toBe(true);
    }
  });

  it("makes Control conformant while advertising recovery as optional features", () => {
    const release = JSON.parse(read("docs/spec/releases/control/0.5.0.json")) as {
      conformance_status: string;
      provided_features: string[];
    };
    expect(release.conformance_status).toBe("conformant");
    expect(release.provided_features).toEqual([
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
});
