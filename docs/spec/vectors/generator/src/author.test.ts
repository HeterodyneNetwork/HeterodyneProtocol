import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  authorAllVectors,
  packageSnapshot,
  replaceSnapshotData,
  SnapshotReplacementRecoveryError,
} from "./author.js";
import { buildAllVectors, TOPIC_SPECS } from "./topics.js";
import { verifyVectorTree } from "./verify.js";
import { snapshotPackageCheck } from "./verify.js";
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
  '[0,"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",1767225660,1,[],"valid-core-signed-event"]';

afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs = [];
});

describe("author mode", () => {
  it("validates raw schema before normalization and schema 2 after packaging", async () => {
    const rawRoot = await mkdtemp(join(tmpdir(), "heterodyne-raw-package-"));
    const snapshotRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-package-"));
    tempDirs.push(rawRoot, snapshotRoot);
    await writeRawPackageInput(rawRoot, {
      type: "object",
      required: ["raw_schema_marker"],
      properties: { raw_schema_marker: { const: true } },
    }, rawVector());

    await expect(packageSnapshot(rawRoot, snapshotRoot, "1".repeat(40)))
      .rejects.toThrow(/identity\/001-example\.json.*raw-vector-invalid/);

  });

  it("packages versionless schema-2 vectors, fixtures, coverage, and exact behavior", async () => {
    const rawRoot = await mkdtemp(join(tmpdir(), "heterodyne-raw-package-"));
    const snapshotRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-package-"));
    tempDirs.push(rawRoot, snapshotRoot);
    const raw = rawVector();
    await writeRawPackageInput(rawRoot, rawVectorSchema(), raw);

    const manifest = await packageSnapshot(rawRoot, snapshotRoot, "1".repeat(40));
    const packaged = JSON.parse(await readFile(
      join(snapshotRoot, "docs/spec/vectors/identity/001-example.json"),
      "utf8",
    ));
    const fixtures = JSON.parse(await readFile(
      join(snapshotRoot, "docs/spec/vectors/fixtures.json"),
      "utf8",
    ));
    const coverage = JSON.parse(await readFile(
      join(snapshotRoot, "docs/spec/vectors/coverage/manifest.json"),
      "utf8",
    ));

    expect(manifest.vector_count).toBe(1);
    expect(packaged).toMatchObject({
      vector_id: raw.vector_id,
      vector_schema_version: "2.0.0",
      spec_refs: ["heterodyne:core#core-root-attestation"],
      input: raw.input,
      expected_output: raw.expected_output,
    });
    expect(packaged).not.toHaveProperty("spec_version");
    expect(packaged).not.toHaveProperty("conformance_checks");
    expect(fixtures).toEqual({
      vector_schema_version: "2.0.0",
      nested: { spec_version: "behavioral-version" },
    });
    expect(coverage).toEqual([{
      vector_id: raw.vector_id,
      owner_document: "core",
      spec_refs: ["heterodyne:core#core-root-attestation"],
    }]);
    const reasonCodes = JSON.parse(await readFile(
      join(snapshotRoot, "docs/spec/vectors/schema/reason-codes.json"),
      "utf8",
    ));
    const reasonMarkdown = await readFile(
      join(snapshotRoot, "docs/spec/vectors/schema/reason-codes.md"),
      "utf8",
    );
    expect(reasonCodes.reason_codes[0]).toMatchObject({
      first_version: "heterodyne/0.5.0",
      spec_refs: ["heterodyne:core#core-conformance"],
    });
    expect(reasonMarkdown).toContain("heterodyne:core#core-conformance");
    expect(reasonMarkdown).not.toContain("heterodyne:0.5.0#core-conformance");
  });

  it("retains source-native behavioral vocabulary in the schema-2 envelope", async () => {
    const rawRoot = await mkdtemp(join(tmpdir(), "heterodyne-raw-package-"));
    const snapshotRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-package-"));
    tempDirs.push(rawRoot, snapshotRoot);
    const schema = rawVectorSchema();
    (schema.properties as Record<string, unknown>).expected_output = {
      type: "object",
      required: ["verdict", "reason_code"],
      properties: {
        verdict: { const: "reject" },
        reason_code: { const: "source-only-reason" },
      },
    };
    await writeRawPackageInput(rawRoot, schema, {
      ...rawVector(),
      expected_output: { verdict: "reject", reason_code: "source-only-reason" },
    });

    await expect(packageSnapshot(rawRoot, snapshotRoot, "1".repeat(40))).resolves.toMatchObject({
      vector_schema_version: "2.0.0",
      vector_count: 1,
    });
    const packagedSchema = JSON.parse(await readFile(
      join(snapshotRoot, "docs/spec/vectors/schema/vector.schema.json"),
      "utf8",
    ));
    expect(packagedSchema.properties.expected_output.properties.reason_code)
      .toEqual({ const: "source-only-reason" });
  });

  it("repackages and compares a snapshot without history orchestration", async () => {
    const rawRoot = await mkdtemp(join(tmpdir(), "heterodyne-raw-package-"));
    const snapshotRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-package-"));
    tempDirs.push(rawRoot, snapshotRoot);
    await writeRawPackageInput(rawRoot, rawVectorSchema(), rawVector());
    await packageSnapshot(rawRoot, snapshotRoot, "1".repeat(40));

    await expect(snapshotPackageCheck(rawRoot, snapshotRoot)).resolves.toBeUndefined();
    await writeRawPackageInput(rawRoot, rawVectorSchema(), {
      ...rawVector(),
      input: { changed: true },
    });
    await expect(snapshotPackageCheck(rawRoot, snapshotRoot)).rejects.toThrow(/regenerated bytes differ/);
  });

  it("replaces accepted top-level vector files and removes obsolete peers", async () => {
    const repositoryRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-repo-"));
    const stagedRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-stage-"));
    tempDirs.push(repositoryRoot, stagedRoot);
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/obsolete.json", "old vector\n");
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/fixtures.json", "old fixtures\n");
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/snapshot.json", "old manifest\n");
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/snapshot.schema.json", "meta schema\n");
    await writeTreeFile(stagedRoot, "docs/spec/vectors/added.json", "new vector\n");
    await writeTreeFile(stagedRoot, "docs/spec/vectors/fixtures.json", "new fixtures\n");
    await writeTreeFile(stagedRoot, "docs/spec/vectors/snapshot.json", "new manifest\n");

    await replaceSnapshotData(repositoryRoot, stagedRoot);

    expect(await readFile(join(repositoryRoot, "docs/spec/vectors/added.json"), "utf8"))
      .toBe("new vector\n");
    await expect(readFile(join(repositoryRoot, "docs/spec/vectors/obsolete.json"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(join(repositoryRoot, "docs/spec/vectors/fixtures.json"), "utf8"))
      .toBe("new fixtures\n");
    expect(await readFile(join(repositoryRoot, "docs/spec/vectors/snapshot.json"), "utf8"))
      .toBe("new manifest\n");
    expect(await readFile(join(repositoryRoot, "docs/spec/vectors/snapshot.schema.json"), "utf8"))
      .toBe("meta schema\n");
  });

  it("rejects a symlinked destination parent before the first move", async () => {
    const repositoryRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-repo-"));
    const stagedRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-stage-"));
    const outsideRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-outside-"));
    tempDirs.push(repositoryRoot, stagedRoot, outsideRoot);
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/fixtures.json", "old fixtures\n");
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/schema/placeholder", "inside\n");
    await rm(join(repositoryRoot, "docs/spec/vectors/schema"), { recursive: true });
    await writeTreeFile(outsideRoot, "vector.schema.json", "outside sentinel\n");
    await symlink(outsideRoot, join(repositoryRoot, "docs/spec/vectors/schema"), "dir");
    await writeTreeFile(stagedRoot, "docs/spec/vectors/fixtures.json", "new fixtures\n");
    await writeTreeFile(
      stagedRoot,
      "docs/spec/vectors/schema/vector.schema.json",
      "new schema\n",
    );
    let moves = 0;

    await expect(replaceSnapshotData(repositoryRoot, stagedRoot, {
      async rename(from, to) {
        moves += 1;
        const { rename } = await import("node:fs/promises");
        await rename(from, to);
      },
    })).rejects.toThrow(/unsafe snapshot destination parent.*symbolic link/i);

    expect(moves).toBe(0);
    expect(await readFile(join(outsideRoot, "vector.schema.json"), "utf8"))
      .toBe("outside sentinel\n");
    expect(await readFile(join(repositoryRoot, "docs/spec/vectors/fixtures.json"), "utf8"))
      .toBe("old fixtures\n");
  });

  it("rolls back a newly installed top-level vector when a later move fails", async () => {
    const repositoryRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-repo-"));
    const stagedRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-stage-"));
    tempDirs.push(repositoryRoot, stagedRoot);
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/obsolete.json", "old vector\n");
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/fixtures.json", "old fixtures\n");
    await writeTreeFile(stagedRoot, "docs/spec/vectors/added.json", "new vector\n");
    await writeTreeFile(stagedRoot, "docs/spec/vectors/fixtures.json", "new fixtures\n");
    let installedTopLevelVector = false;

    await expect(replaceSnapshotData(repositoryRoot, stagedRoot, {
      async rename(from, to) {
        if (installedTopLevelVector) throw new Error("injected after top-level vector install");
        const { rename } = await import("node:fs/promises");
        await rename(from, to);
        if (from.endsWith("/added.json")) installedTopLevelVector = true;
      },
    })).rejects.toThrow("injected after top-level vector install");

    await expect(readFile(join(repositoryRoot, "docs/spec/vectors/added.json"), "utf8"))
      .rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(join(stagedRoot, "docs/spec/vectors/added.json"), "utf8"))
      .toBe("new vector\n");
    expect(await readFile(join(repositoryRoot, "docs/spec/vectors/obsolete.json"), "utf8"))
      .toBe("old vector\n");
    expect(await readFile(join(repositoryRoot, "docs/spec/vectors/fixtures.json"), "utf8"))
      .toBe("old fixtures\n");
  });

  it("rolls back snapshot data and measured projections after a partial replacement", async () => {
    const repositoryRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-repo-"));
    const stagedRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-stage-"));
    tempDirs.push(repositoryRoot, stagedRoot);
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/fixtures.json", "old fixtures\n");
    await writeTreeFile(repositoryRoot, "docs/spec/conformance/report.json", "old report\n");
    await writeTreeFile(stagedRoot, "docs/spec/vectors/fixtures.json", "new fixtures\n");
    await writeTreeFile(stagedRoot, "docs/spec/conformance/report.json", "new report\n");
    let renames = 0;

    await expect(replaceSnapshotData(repositoryRoot, stagedRoot, {
      async rename(from, to) {
        renames += 1;
        if (renames === 3) throw new Error("injected partial replacement");
        const { rename } = await import("node:fs/promises");
        await rename(from, to);
      },
    })).rejects.toThrow("injected partial replacement");

    expect(await readFile(join(repositoryRoot, "docs/spec/vectors/fixtures.json"), "utf8"))
      .toBe("old fixtures\n");
    expect(await readFile(join(repositoryRoot, "docs/spec/conformance/report.json"), "utf8"))
      .toBe("old report\n");
  });

  it("retains prior bytes and a recovery path when rollback is incomplete", async () => {
    const repositoryRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-repo-"));
    const stagedRoot = await mkdtemp(join(tmpdir(), "heterodyne-replace-stage-"));
    tempDirs.push(repositoryRoot, stagedRoot);
    const target = join(repositoryRoot, "docs/spec/vectors/fixtures.json");
    const staged = join(stagedRoot, "docs/spec/vectors/fixtures.json");
    await writeTreeFile(repositoryRoot, "docs/spec/vectors/fixtures.json", "old fixtures\n");
    await writeTreeFile(stagedRoot, "docs/spec/vectors/fixtures.json", "new fixtures\n");

    let failure: unknown;
    try {
      await replaceSnapshotData(repositoryRoot, stagedRoot, {
        async rename(from, to) {
          if (from === staged) {
            await mkdir(target);
            throw new Error("injected install failure");
          }
          const { rename } = await import("node:fs/promises");
          await rename(from, to);
        },
      });
    } catch (error) {
      failure = error;
    }

    const recoveryDirectories = (await readdir(dirname(repositoryRoot)))
      .filter((name) => name.startsWith(".heterodyne-snapshot-backup-"));
    expect(recoveryDirectories).toHaveLength(1);
    expect(failure).toBeInstanceOf(SnapshotReplacementRecoveryError);
    const recovery = failure as SnapshotReplacementRecoveryError;
    expect(recovery.errors).toEqual(expect.arrayContaining([
      expect.objectContaining({ message: "injected install failure" }),
      expect.objectContaining({ message: expect.stringMatching(/rollback failed/) }),
    ]));
    expect(recovery.message).toContain(recovery.recoveryPath);
    tempDirs.push(recovery.recoveryPath);
    expect(await readFile(
      join(recovery.recoveryPath, "docs/spec/vectors/fixtures.json"),
      "utf8",
    )).toBe("old fixtures\n");
  });

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
      tags: [],
      content: "valid-core-signed-event",
      id: "87205a88f5d332b9556faf13347575ed8b71baaa9e7a58596ad3618b974a9b65",
      sig: "6fa07764015c24bc03ec439225b6c0647f1050029b24f5c3fa5f880cacfd8fbd52371327913877caf5cdbccdcbab079773b84813bdc803b66d2664675406379c",
    });
    expect(accepted.input.nip01_raw).toBe(ACCEPTED_RAW);
    expect(verifyEventSignature(accepted.input.event as NostrSignedEvent)).toBe(true);
    expect(accepted.input.vector_context).toEqual({
      core_verification: {
        persona: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        evaluation_time: 1767225660,
        nid_clock_skew_allowance: 0,
        clock_uncertainty: 0,
        retired_key_evidence: {
          first_observed_at: 1767225660,
          prior_anchor: null,
        },
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
        kel_refresh: { status: "not-needed" },
        signer: {
          type: "epoch",
          pubkey: "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
          delegation: null,
        },
        version_policy: { mode: "forbidden", value: "heterodyne/0.5.0" },
        kel_head_policy: { mode: "forbidden" },
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

function rawVector(): Record<string, unknown> {
  return {
    vector_id: "identity/example",
    vector_schema_version: "1.0.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: ["heterodyne:0.5.0#core-root-attestation"],
    description: "example",
    direction: "produce",
    input: { spec_version: "behavioral-input-version" },
    expected_output: { spec_version: "behavioral-output-version" },
  };
}

function rawVectorSchema(): Record<string, unknown> {
  return {
    type: "object",
    additionalProperties: true,
    required: [
      "vector_id", "vector_schema_version", "owner_document", "spec_version",
      "spec_refs", "description", "direction", "input", "expected_output",
    ],
    properties: {
      vector_id: { type: "string" },
      vector_schema_version: { const: "1.0.0" },
      owner_document: { const: "core" },
      spec_version: { type: "string" },
      spec_refs: { type: "array", items: { type: "string" } },
      description: { type: "string" },
      direction: { enum: ["produce", "consume", "round-trip"] },
      input: { type: "object" },
      expected_output: { type: "object" },
    },
  };
}

async function writeRawPackageInput(
  root: string,
  schema: Record<string, unknown>,
  vector: Record<string, unknown>,
): Promise<void> {
  await writeTreeFile(root, "schema/vector.schema.json", `${JSON.stringify(schema, null, 2)}\n`);
  await writeTreeFile(root, "schema/reason-codes.json", `${JSON.stringify({
    reason_codes: [{
      code: "example",
      owner: "core",
      status: "draft",
      first_version: "heterodyne/0.5.0",
      description: "example reason",
      spec_refs: ["heterodyne:0.5.0#core-conformance"],
    }],
  }, null, 2)}\n`);
  await writeTreeFile(
    root,
    "schema/reason-codes.md",
    "# Reason codes\n\nheterodyne:0.5.0#core-conformance\n",
  );
  await writeTreeFile(root, "fixtures.json", `${JSON.stringify({
    vector_schema_version: "1.0.0",
    spec_version: "heterodyne/0.5.0",
    nested: { spec_version: "behavioral-version" },
  }, null, 2)}\n`);
  await writeTreeFile(root, "identity/001-example.json", `${JSON.stringify(vector, null, 2)}\n`);
}

async function writeTreeFile(root: string, path: string, contents: string): Promise<void> {
  const target = join(root, ...path.split("/"));
  await mkdir(join(target, ".."), { recursive: true });
  await writeFile(target, contents, "utf8");
}
