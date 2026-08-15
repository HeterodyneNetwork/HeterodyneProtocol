import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorAllVectors } from "./author.js";
import { TOPIC_SPECS } from "./topics.js";
import { verifyVectorTree } from "./verify.js";
import { verifyEventSignature } from "./nostr.js";
import { writeCoverage } from "./coverage.js";
import { buildFixtures } from "./fixtures.js";
import { validateNodeAdvertisement } from "./radicle.js";

let tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe("author mode", () => {
  it("authors at least one schema-valid vector for every required topic", async () => {
    const outputDir = await mkdtemp(join(tmpdir(), "heterodyne-vectors-"));
    tempDirs.push(outputDir);

    const written = await authorAllVectors(outputDir);
    await writeCoverage(outputDir);
    const topics = new Set(written.map((path) => path.split("/")[0]));

    for (const topic of Object.keys(TOPIC_SPECS)) {
      expect(topics.has(topic)).toBe(true);
    }

    const result = await verifyVectorTree(outputDir);
    expect(result.validFiles).toBe(written.length);
    expect(result.errors).toEqual([]);
    // The corpus authors exactly one current form per behavior: no archived
    // monolith consume twin, and no `-v050` produce twin derived from it.
    expect(written.filter((path) => /-v050\.json$/.test(path))).toEqual([]);

    for (const path of written.filter((candidate) => candidate.startsWith("keri/"))) {
      const scenario = JSON.parse(await readFile(join(outputDir, ...path.split("/")), "utf8"));
      expect(scenario.input.evidence_classification).toBe("non-wire-behavioral-scenario");
    }

    const identity = JSON.parse(
      await readFile(join(outputDir, "identity", "001-root-attestation-valid.json"), "utf8"),
    );
    expect(identity.owner_document).toBe("core");
    expect(identity.spec_version).toBe("heterodyne/0.5.0");
    expect(identity).not.toHaveProperty("owner_version");
    expect(identity).not.toHaveProperty("dependency_versions");
    expect(identity).not.toHaveProperty("registry_revision");
    expect(identity.spec_refs).toEqual(
      expect.arrayContaining([
        "heterodyne:0.5.0#core-root-attestation",
      ]),
    );
    expect(identity.direction).toBe("produce");
    expect(identity.expected_output.canonical_wire).toContain('["heterodyne","root"]');
    expect(identity.expected_output.canonical_wire).toContain('["spec_version","heterodyne/0.5.0"]');
    expect(verifyEventSignature(identity.expected_output.decoded.event)).toBe(true);

    const control = JSON.parse(await readFile(join(outputDir, "control", "001-invitation-enrollment-only.json"), "utf8"));
    expect(control.owner_document).toBe("control");
    expect(control.profile).toBe("heterodyne-control-marmot-frame-v1");
    expect(control.expected_output).toMatchObject({ verdict: "accept", state: "enrollment-only" });

    const verification = JSON.parse(
      await readFile(join(outputDir, "verification", "001-bad-signature-rejects.json"), "utf8"),
    );
    expect(verification.expected_output).not.toHaveProperty("decision_trace");
    expect(verification.input.vector_context.decision_trace).toEqual([
      "validate_nip01_id",
      "verify_bip340_signature",
    ]);
  }, 30_000);

  it("authors one current production form per addressable identity/privacy/list vector", async () => {
    const outputDir = await mkdtemp(join(tmpdir(), "heterodyne-vectors-"));
    tempDirs.push(outputDir);
    await authorAllVectors(outputDir);
    const fixtures = buildFixtures();
    const produced = [
      ["identity/001-root-attestation-valid.json", "heterodyne/0.5.0"],
      ["identity-doc/003-emergency-reanchor.json", "heterodyne/0.5.0"],
      ["nid-binding/001-bidirectional-valid.json", "heterodyne/0.5.0"],
      ["node-advert/001-valid-dual-signed.json", "heterodyne/0.5.0"],
      ["privacy-tiers/001-tier1-public-plaintext-both-backends.json", "heterodyne/0.5.0"],
      ["privacy-tiers/004-tier3-index-key-derivation-and-encryption.json", "heterodyne/0.5.0"],
      ["privacy-tiers/003-tier3-kind31011-audience-key-wrap.json", "heterodyne/0.5.0"],
      ["privacy-tiers/008-tier3-kind31012-audience-roster.json", "heterodyne/0.5.0"],
      ["lists/001-mute-list-public-roundtrip.json", "heterodyne/0.5.0"],
      ["lists/002-mute-list-private-items-encrypted-to-self.json", "heterodyne/0.5.0"],
    ];
    for (const [path, stamp] of produced) {
      const vector = JSON.parse(await readFile(join(outputDir, ...path.split("/")), "utf8"));
      expect(vector.direction).toBe("produce");
      expect(vector.expected_output.canonical_wire).toContain(stamp);
      expect(verifyEventSignature(vector.expected_output.decoded.event)).toBe(true);
      expect(
        vector.expected_output.decoded.event.tags.find((tag: string[]) => tag[0] === "kel_head"),
      ).toEqual(
        vector.expected_output.decoded.event.kind === 31005
          ? undefined
          : ["kel_head", fixtures.kel.alice.head.id, "0"],
      );
    }

    // Audience material addresses delegated device publishing keys, never a
    // persona cold root.
    const wrap = JSON.parse(await readFile(
      join(outputDir, "privacy-tiers", "003-tier3-kind31011-audience-key-wrap.json"), "utf8",
    ));
    expect(wrap.input.recipient_pubkey).toBe(fixtures.device_publishing_keys.bob_device_1.pubkey);
    expect(wrap.input.recipient_pubkey).not.toBe(fixtures.personas.bob.cold_root.pubkey);
    const roster = JSON.parse(await readFile(
      join(outputDir, "privacy-tiers", "008-tier3-kind31012-audience-roster.json"), "utf8",
    ));
    expect(roster.input.recipients).toEqual([
      fixtures.device_publishing_keys.alice_device_1.pubkey,
      fixtures.device_publishing_keys.bob_device_1.pubkey,
    ].sort());
    expect(roster.input.recipients).not.toContain(fixtures.personas.bob.cold_root.pubkey);

    const advertisement = JSON.parse(await readFile(
      join(outputDir, "node-advert", "001-valid-dual-signed.json"), "utf8",
    ));
    expect(validateNodeAdvertisement(
      advertisement.expected_output.decoded.event,
      advertisement.input.validation_context,
    )).toMatchObject({
      status: "accepted",
      repo_head: advertisement.input.validation_context.graph_fetch.reachable_oids[0],
    });
  }, 30_000);
});
