import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorAllVectors } from "./author.js";
import { buildAllVectors, TOPIC_SPECS } from "./topics.js";
import { verifyVectorTree } from "./verify.js";
import { verifyEventSignature, type NostrSignedEvent } from "./nostr.js";
import { writeCoverage } from "./coverage.js";
import { buildFixtures } from "./fixtures.js";
import { validateNodeAdvertisement } from "./radicle.js";

let tempDirs: string[] = [];

const DECLARED_VECTOR_PATHS = [
  "node-advert/002-outer-sig-invalid-rejected.json",
  "verification/001-bad-signature-rejects.json",
  "verification/005-valid-core-signed-event-accepts.json",
];
const SIGNATURE_CHECK = {
  profile: "core-signed-event-v1",
  event_pointer: "/input/event",
  nip01_raw_pointer: "/input/nip01_raw",
  expected_terminal_stage: "signature",
};
const BAD_SIGNATURE_RAW =
  '[0,"1111111111111111111111111111111111111111111111111111111111111111",1767225600,1,[],"tampered"]';
const NODE_ADVERT_RAW =
  '[0,"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",1767311700,31010,[["d","rad:z2TJoDAhK5pTmLzqmK9W4FMdtjyy1"],["heterodyne","node_advert"],["rid","rad:z2TJoDAhK5pTmLzqmK9W4FMdtjyy1"],["nid","did:key:z6MkqZeuNH8HQixdH8KLGc4eyQK3pZSNQZ43BuAGgqSVRUMC"],["endpoint","wss://node-a.example/relay"],["repo_head","4a19af7f069f3c32d4235c726f666fc8cd0175fa"],["expiry","1767312000"],["nid_proof","500a6491bc4bf613a6b1fb765cf940917f1a1351c764bce07676860ed2c986b1881c23d4093b078d99a1311f077abe1caac0188f0aff933b58e0e6f6dd44ff00"],["kel_head","7e81c45ab6de08b6a1795f60068944db1405fa19c742a6c7b86ee46f2f04f8bf","0"],["spec_version","heterodyne/0.5.0"]],""]';
const ACCEPTED_RAW =
  '[0,"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",1767225660,1,[["kel_head","7e81c45ab6de08b6a1795f60068944db1405fa19c742a6c7b86ee46f2f04f8bf","0"],["spec_version","heterodyne/0.5.0"]],"valid-core-signed-event"]';

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
    expect(written).toHaveLength(499);
    const declaredPaths: string[] = [];
    for (const path of written) {
      const vector = JSON.parse(await readFile(join(outputDir, ...path.split("/")), "utf8"));
      expect(vector.vector_schema_version).toBe("1.1.0");
      if (vector.conformance_checks === undefined) {
        expect(DECLARED_VECTOR_PATHS).not.toContain(path);
      } else {
        declaredPaths.push(path);
      }
    }
    expect(declaredPaths).toEqual(DECLARED_VECTOR_PATHS);
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

  it("authors stage-isolated signed-event negatives and one full accepted Core case", async () => {
    const authored = await buildAllVectors(buildFixtures());
    const byId = (vectorId: string) => {
      const match = authored.find(({ vector }) => vector.vector_id === vectorId);
      expect(match, `missing ${vectorId}`).toBeDefined();
      return match!.vector;
    };

    const badSignature = byId("verification/bad-signature-rejects");
    expect(badSignature.input.nip01_raw).toBe(BAD_SIGNATURE_RAW);
    expect((badSignature.input.event as Record<string, unknown>).id).toBe(
      "762b00f96409915a2afce5e93e143188eb80aadb56f13240cd0b1af07cecd35e",
    );
    expect(verifyEventSignature(badSignature.input.event as NostrSignedEvent)).toBe(false);
    expect(badSignature.conformance_checks).toEqual([SIGNATURE_CHECK]);

    const nodeAdvert = byId("node-advert/outer-sig-invalid-rejected");
    expect(nodeAdvert.input.nip01_raw).toBe(NODE_ADVERT_RAW);
    expect((nodeAdvert.input.event as Record<string, unknown>).id).toBe(
      "5e07eab58c7e0bb2a1cb059a1f8611265a608f4b74f7710c4bd96b69712c8e50",
    );
    expect(verifyEventSignature(nodeAdvert.input.event as NostrSignedEvent)).toBe(false);
    expect(nodeAdvert.conformance_checks).toEqual([SIGNATURE_CHECK]);

    const accepted = byId("verification/valid-core-signed-event-accepts");
    expect(accepted.spec_refs).toEqual(["heterodyne:0.5.0#core-verification"]);
    expect(accepted.input.event).toEqual({
      pubkey: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      created_at: 1767225660,
      kind: 1,
      tags: [
        ["kel_head", "7e81c45ab6de08b6a1795f60068944db1405fa19c742a6c7b86ee46f2f04f8bf", "0"],
        ["spec_version", "heterodyne/0.5.0"],
      ],
      content: "valid-core-signed-event",
      id: "0a6ef156aa1561171a866231ee3fc723e020ae26147909b543e8ceeaa4a55440",
      sig: "53b2dbd363e1d475d03fed84235406911ffaf232639234dc757af6298f9f2463a85084c77ad74db2b8c99d489344afde6a77bb3981de31c81296dc194b70907a",
    });
    expect(accepted.input.nip01_raw).toBe(ACCEPTED_RAW);
    expect(verifyEventSignature(accepted.input.event as NostrSignedEvent)).toBe(true);
    expect(accepted.input.vector_context).toEqual({
      core_verification: {
        persona: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        evaluation_time: 1767225660,
        nid_clock_skew_allowance: 0,
        clock_uncertainty: 0,
        pointer: {
          persona: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
          kel_head: {
            event_id: "7e81c45ab6de08b6a1795f60068944db1405fa19c742a6c7b86ee46f2f04f8bf",
            sequence: 0,
          },
        },
        kel: [{
          event_id: "7e81c45ab6de08b6a1795f60068944db1405fa19c742a6c7b86ee46f2f04f8bf",
          sequence: 0,
          prior_event_id: null,
          epoch_pubkey: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
          effective_from: 1767225600,
          effective_until: null,
          compromise_since: null,
        }],
        signer: {
          type: "epoch",
          pubkey: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
          delegation: null,
        },
        version_policy: { mode: "required", value: "heterodyne/0.5.0" },
        kel_head_policy: { mode: "required" },
        subtype_policy: { mode: "generic", nid_pubkey: null },
      },
    });
    expect(accepted.expected_output).toEqual({ verdict: "accept" });
    expect(accepted.conformance_checks).toEqual([{
      profile: "core-signed-event-v1",
      event_pointer: "/input/event",
      nip01_raw_pointer: "/input/nip01_raw",
      context_pointer: "/input/vector_context/core_verification",
      expected_terminal_stage: "accept",
    }]);
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
