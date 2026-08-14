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
    for (const retiredPath of [
      "broadcast/001-private-broadcast-wrapped.json",
      "broadcast/002-member-decrypts.json",
      "broadcast/003-non-member-cannot-decrypt.json",
      "broadcast/004-reaction-reply-bare-not-indexed.json",
      "broadcast/005-nip59-rejected.json",
      "broadcast/006-private-broadcast-wrapped-v050.json",
      "index/001-room-key-wrap-encryption.json",
      "index/004-context-binding-mismatch.json",
    ]) {
      expect(written).not.toContain(retiredPath);
    }
    expect(written.some((path) => path.startsWith("broadcast/"))).toBe(false);

    for (const path of written.filter((candidate) => candidate.startsWith("keri/"))) {
      const scenario = JSON.parse(await readFile(join(outputDir, ...path.split("/")), "utf8"));
      expect(scenario.input.evidence_classification).toBe("non-wire-behavioral-scenario");
    }

    const identity = JSON.parse(
      await readFile(join(outputDir, "identity", "001-root-attestation-valid.json"), "utf8"),
    );
    expect(identity).not.toHaveProperty("spec_version");
    expect(identity.owner_document).toBe("core");
    expect(identity.owner_version).toBe("core/0.5.0");
    expect(identity.dependency_versions).toEqual({});
    expect(identity.registry_revision).toBe(8);
    expect(identity.spec_refs).toEqual(
      expect.arrayContaining([
        "heterodyne:core/0.5.0#core-root-attestation",
      ]),
    );
    expect(identity.direction).toBe("consume");
    expect(identity.input.source_schema).toBe("monolith/0.4.0");
    expect(identity.input.historical_expected_output.canonical_wire).toContain('["heterodyne","root"]');
    expect(identity.expected_output.normalized.restamped).toBe(false);

    const currentIdentity = JSON.parse(
      await readFile(join(outputDir, "identity", "008-root-attestation-valid-v050.json"), "utf8"),
    );
    expect(currentIdentity.direction).toBe("produce");
    expect(currentIdentity.expected_output.canonical_wire).toContain('["spec_version","core/0.5.0"]');
    expect(verifyEventSignature(currentIdentity.expected_output.decoded.event)).toBe(true);

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

  it("keeps archived bytes as verification inputs and emits separately identified 0.5 production forms", async () => {
    const outputDir = await mkdtemp(join(tmpdir(), "heterodyne-vectors-"));
    tempDirs.push(outputDir);
    await authorAllVectors(outputDir);
    const pairs = [
      ["identity/001-root-attestation-valid.json", "identity/008-root-attestation-valid-v050.json", "core/0.5.0"],
      ["identity-doc/003-emergency-reanchor.json", "identity-doc/004-emergency-reanchor-v050.json", "core/0.5.0"],
      ["nid-binding/001-bidirectional-valid.json", "nid-binding/004-bidirectional-valid-v050.json", "core/0.5.0"],
      ["node-advert/001-valid-dual-signed.json", "node-advert/005-valid-dual-signed-v050.json", "core/0.5.0"],
      ["privacy-tiers/001-tier1-public-plaintext-both-backends.json", "privacy-tiers/011-tier1-public-plaintext-both-backends-v050.json", "comms/0.5.0"],
      ["privacy-tiers/004-tier3-index-key-derivation-and-encryption.json", "privacy-tiers/012-tier3-index-key-derivation-and-encryption-v050.json", "comms/0.5.0"],
      ["privacy-tiers/003-tier3-kind31011-audience-key-wrap.json", "privacy-tiers/013-tier3-kind31011-audience-key-wrap-v050.json", "comms/0.5.0"],
      ["privacy-tiers/008-tier3-kind31012-audience-roster.json", "privacy-tiers/014-tier3-kind31012-audience-roster-v050.json", "comms/0.5.0"],
      ["lists/001-mute-list-public-roundtrip.json", "lists/007-mute-list-public-roundtrip-v050.json", "social/0.5.0"],
      ["lists/002-mute-list-private-items-encrypted-to-self.json", "lists/008-mute-list-private-items-encrypted-to-self-v050.json", "social/0.5.0"],
    ];
    for (const [legacyPath, currentPath, stamp] of pairs) {
      const legacy = JSON.parse(await readFile(join(outputDir, ...legacyPath.split("/")), "utf8"));
      const current = JSON.parse(await readFile(join(outputDir, ...currentPath.split("/")), "utf8"));
      expect(legacy.direction).toBe("consume");
      expect(legacy.input.source_schema).toBe("monolith/0.4.0");
      expect(legacy.expected_output.normalized.historical_bytes_preserved).toBe(true);
      expect(current.direction).toBe("produce");
      expect(current.expected_output.canonical_wire).toContain(stamp);
      expect(verifyEventSignature(current.expected_output.decoded.event)).toBe(true);
    }
    const currentWrap = JSON.parse(await readFile(
      join(outputDir, "privacy-tiers", "013-tier3-kind31011-audience-key-wrap-v050.json"), "utf8",
    ));
    expect(currentWrap.input.recipient_pubkey).toBe(buildFixtures().device_publishing_keys.bob_device_1.pubkey);
    expect(currentWrap.input.recipient_pubkey).not.toBe(buildFixtures().personas.bob.cold_root.pubkey);
    const currentRoster = JSON.parse(await readFile(
      join(outputDir, "privacy-tiers", "014-tier3-kind31012-audience-roster-v050.json"), "utf8",
    ));
    expect(currentRoster.input.recipients).toEqual([
      buildFixtures().device_publishing_keys.alice_device_1.pubkey,
      buildFixtures().device_publishing_keys.bob_device_1.pubkey,
    ].sort());
    expect(currentRoster.input.recipients).not.toContain(buildFixtures().personas.bob.cold_root.pubkey);

    const fixtures = buildFixtures();
    expect(fixtures.legacy_kel.alice.head.id).toBe(
      "2a182dd311941fa1bc6a9847d700c261d4dc1ef31168b8635aaea8d3d0171def",
    );
    expect(fixtures.kel.alice.head.id).not.toBe(fixtures.legacy_kel.alice.head.id);

    const archivedIdentity = JSON.parse(
      await readFile(join(outputDir, "identity", "001-root-attestation-valid.json"), "utf8"),
    );
    expect(archivedIdentity.input.historical_expected_output.id).toBe(
      "7d9c544d18a4c820060d2425f9e4ee74256c960fa26b76dee7cabcd3017fd4d6",
    );
    expect(
      archivedIdentity.input.historical_expected_output.decoded.tags.find(
        (tag: string[]) => tag[0] === "kel_head",
      ),
    ).toEqual(["kel_head", fixtures.legacy_kel.alice.head.id, "0"]);

    const currentIdentity = JSON.parse(
      await readFile(join(outputDir, "identity", "008-root-attestation-valid-v050.json"), "utf8"),
    );
    expect(
      currentIdentity.expected_output.decoded.event.tags.find(
        (tag: string[]) => tag[0] === "kel_head",
      ),
    ).toEqual(["kel_head", fixtures.kel.alice.head.id, "0"]);

    const currentNodeAdvertisement = JSON.parse(
      await readFile(join(outputDir, "node-advert", "005-valid-dual-signed-v050.json"), "utf8"),
    );
    expect(validateNodeAdvertisement(
      currentNodeAdvertisement.expected_output.decoded.event,
      currentNodeAdvertisement.input.validation_context,
    )).toMatchObject({
      status: "accepted",
      repo_head: currentNodeAdvertisement.input.validation_context.graph_fetch.reachable_oids[0],
    });
  }, 30_000);
});
