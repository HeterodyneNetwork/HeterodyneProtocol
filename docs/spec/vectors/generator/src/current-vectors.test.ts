import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, describe, expect, it } from "vitest";
import { evaluateAssuranceCompromiseContinuation } from "./assurance-policy.js";
import { evaluateSuccession } from "./assurance.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import { buildLedgerRepositoryEvidence } from "./claim-ledger.js";
import { validateControlSignedEffect } from "./control-policy.js";
import { buildCurrentCases, buildCurrentVectors } from "./current-vectors/index.js";
import { currentCaseIds } from "./current-vectors/case-contracts.js";
import {
  assertProjectionPreservesVerdict,
  invokeCurrentBoundary,
} from "./current-vectors/boundary-runners.js";
import { buildProfileCases } from "./current-vectors/profiles.js";
import {
  CURRENT_PROFILE_ORACLES,
  currentProfileOracleForVector,
} from "./current-vectors/profile-oracles.js";
import { buildFixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { signEvent } from "./nostr.js";
import { validateCurrentKindProfileNegotiation } from "./profile-negotiation.js";
import { loadRegistry } from "./registry.js";
import { validateVectorOrThrow } from "./schema.js";
import { AUX_RAND } from "./vector-helpers.js";
import {
  currentCompilerConfigPath as compilerConfigPath,
  currentModuleDependencies as moduleDependencies,
  currentNamedImports as importedNames,
} from "./current-import-graph.js";

const sourceRoot = resolve(import.meta.dirname);
const catalogEntry = resolve(sourceRoot, "current-vectors/index.ts");
const currentConfigPath = resolve(sourceRoot, "../tsconfig.current.json");
const authorPath = resolve(sourceRoot, "author.ts");
const coveragePath = resolve(sourceRoot, "coverage.ts");
const packagePath = resolve(sourceRoot, "../package.json");
const forbidden = [
  /\/topics[^/]*\.ts$/,
  /\/snapshot[^/]*\.ts$/,
  /\/legacy[^/]*\.ts$/,
  /\/kel(?:-replay)?\.ts$/,
  /\/keri-materialized\.ts$/,
];
const temporaryRoots: string[] = [];

afterEach(() => {
  while (temporaryRoots.length > 0) {
    rmSync(temporaryRoots.pop()!, { recursive: true, force: true });
  }
});

describe("current vector catalog import boundary", () => {
  it("BLUE TEAM VALIDATION: synthetic/local compiler graph omits retired Core evaluators", () => {
    // BLUE TEAM VALIDATION: inspect only compiler-resolved local current-source imports.
    const coreImports = importedNames(resolve(sourceRoot, "current-vectors/core.ts"));
    expect(coreImports.has("validateOrganizationMemberAddition")).toBe(false);
    expect(coreImports.has("validateRoleDelegation")).toBe(false);
  });

  it("audits the exact trusted-source static graph without historical authoring modules", () => {
    expect(compilerConfigPath(catalogEntry)).toBe(currentConfigPath);
    const graph = moduleDependencies(catalogEntry);
    expect(graph).toHaveLength(79);
    expect(graph.filter((path) => forbidden.some((pattern) => pattern.test(path))))
      .toEqual([]);
  }, 60_000);

  it("follows every compiler-resolved static re-export and import-equals edge", () => {
    const root = mkdtempSync(resolve(tmpdir(), "heterodyne-current-vector-imports-"));
    temporaryRoots.push(root);
    mkdirSync(resolve(root, "nested"), { recursive: true });
    writeFileSync(
      resolve(root, "index.ts"),
      [
        'export { value as named } from "./topics-named.js";',
        'export * from "./topics-star.js";',
        'import legacy = require("./legacy-import-equals.js");',
        'void legacy;',
      ].join("\n"),
    );
    for (const file of [
      "topics-named.ts",
      "topics-star.ts",
      "legacy-import-equals.ts",
    ]) {
      writeFileSync(resolve(root, file), "export const value = true;\n");
    }

    const graph = moduleDependencies(resolve(root, "index.ts"));
    expect(graph.filter((path) => forbidden.some((pattern) => pattern.test(path))))
      .toEqual([
        realpathSync(resolve(root, "legacy-import-equals.ts")),
        realpathSync(resolve(root, "topics-named.ts")),
        realpathSync(resolve(root, "topics-star.ts")),
      ].sort());
  });

  it("resolves configured local aliases through TypeScript and rejects missing ones", () => {
    const root = mkdtempSync(resolve(tmpdir(), "heterodyne-current-vector-paths-"));
    temporaryRoots.push(root);
    mkdirSync(resolve(root, "src"), { recursive: true });
    writeFileSync(resolve(root, "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        module: "NodeNext",
        moduleResolution: "NodeNext",
        baseUrl: ".",
        paths: { "@local/*": ["src/*"] },
      },
    }));
    writeFileSync(resolve(root, "index.ts"), 'export * from "@local/topics-path.js";\n');
    writeFileSync(resolve(root, "src/topics-path.ts"), "export const value = true;\n");
    expect(moduleDependencies(resolve(root, "index.ts"))).toContain(
      realpathSync(resolve(root, "src/topics-path.ts")),
    );

    writeFileSync(resolve(root, "missing.ts"), 'export * from "@local/missing.js";\n');
    expect(() => moduleDependencies(resolve(root, "missing.ts")))
      .toThrow(/unresolved current vector import/u);
  });

  it("terminates only verified external package leaves", () => {
    const root = mkdtempSync(resolve(tmpdir(), "heterodyne-current-vector-external-"));
    temporaryRoots.push(root);
    writeFileSync(
      resolve(root, "index.ts"),
      'export * from "@heterodyne-test/missing-current-vector-leaf";\n',
    );

    expect(() => moduleDependencies(resolve(root, "index.ts")))
      .toThrow(/unresolved current vector import/u);
  });

  it("accepts only Node builtins present in builtinModules", () => {
    const root = mkdtempSync(resolve(tmpdir(), "heterodyne-current-vector-builtins-"));
    temporaryRoots.push(root);
    writeFileSync(resolve(root, "valid.ts"), 'import "node:assert";\n');
    expect(moduleDependencies(resolve(root, "valid.ts")))
      .toEqual([realpathSync(resolve(root, "valid.ts"))]);

    writeFileSync(resolve(root, "unknown.ts"), 'import "node:not-a-current-builtin";\n');
    expect(() => moduleDependencies(resolve(root, "unknown.ts")))
      .toThrow(/unknown Node builtin in current vector graph/u);
  });

  it("makes current authoring and coverage consume only the trusted current catalog", () => {
    const imports = importedNames(authorPath);
    expect(imports.has("buildCurrentVectors")).toBe(true);
    expect(imports.has("buildIsolatedCurrentCatalog")).toBe(false);
    expect(imports.has("buildSnapshotCompatibleVectors")).toBe(false);
    const coverageSource = readFileSync(coveragePath, "utf8");
    expect(coverageSource).toContain('import("./current-vectors/index.js")');
    expect(coverageSource).not.toContain("current-authoring-runtime");
  });

  it("centralizes current vector and family versions outside family modules", () => {
    for (const family of ["core", "assurance", "comms", "control", "social", "workspace"]) {
      const source = readFileSync(resolve(sourceRoot, `current-vectors/${family}.ts`), "utf8");
      expect(source, family).not.toContain("3.0.0");
      expect(source, family).not.toContain("heterodyne/0.6.0");
    }
  });

  it("keeps family builders limited to boundary-specific fixture data", () => {
    const forbiddenCaseMetadata = [
      /\bsemantic_boundary\s*:/u,
      /\bowner_document\s*:/u,
      /\bspec_refs\s*:/u,
      /\binvariants\s*:/u,
      /\breason_codes\s*:/u,
      /\bexpected_output\s*:/u,
      /\bexecuted[A-Z][A-Za-z]+Rejection\b/u,
      /\bboundary\s*:\s*(?:String|string)\b/u,
      /\binvariant\s*:\s*(?:String|string)\b/u,
      /\bdecision\s*:\s*(?:decision|Readonly)\b/u,
    ];
    for (const family of [
      "core",
      "assurance",
      "comms",
      "control",
      "social",
      "workspace",
      "profiles",
    ]) {
      const source = readFileSync(resolve(sourceRoot, `current-vectors/${family}.ts`), "utf8");
      for (const pattern of forbiddenCaseMetadata) {
        expect(source, `${family}: ${String(pattern)}`).not.toMatch(pattern);
      }
    }
  });

  it("keeps the snapshot gate history-materialized instead of running a current-head hybrid", () => {
    const packageJson = JSON.parse(readFileSync(packagePath, "utf8")) as {
      scripts: Record<string, string>;
    };
    expect(packageJson.scripts["snapshot-check"]).toBe("tsx src/cli.ts snapshot-check");
    expect(packageJson.scripts["test:snapshot-adapters"]).toBe("tsx src/cli.ts snapshot-check");
  });
});

describe("current 0.6 vector catalog", () => {
  it("BLUE TEAM VALIDATION: synthetic/local catalog cannot execute retired Core semantics", async () => {
    // BLUE TEAM VALIDATION: deterministic in-process fixtures exercise no external target.
    const retiredCaseIds = new Set([
      "core/org-member-add-unauthorized",
      "core/role-delegation-address-invalid",
      "core/role-delegation-key-proof-invalid",
    ]);
    const cases = await buildCurrentCases();
    expect(currentCaseIds().filter((id) => retiredCaseIds.has(id))).toEqual([]);
    expect(cases.filter(({ vector_id }) => retiredCaseIds.has(vector_id))).toEqual([]);
    expect(cases.filter(({ semantic_boundary }) =>
      semantic_boundary === "core-policy.validateOrganizationMemberAddition"
      || semantic_boundary === "core-policy.validateRoleDelegation"
    )).toEqual([]);

    await expect(invokeCurrentBoundary(
      "core-policy.validateOrganizationMemberAddition",
      {
        vector_id: "synthetic/retired-member-kel",
        description: "BLUE TEAM VALIDATION: synthetic/local retired member-KEL probe",
        direction: "consume",
        input: {
          member_kel_authorized: true,
          org_admin_threshold_authorized: true,
        },
      },
    )).rejects.toThrow(/current boundary is not executable/u);
    await expect(invokeCurrentBoundary(
      "core-policy.validateRoleDelegation",
      {
        vector_id: "synthetic/retired-role-delegation",
        description: "BLUE TEAM VALIDATION: synthetic/local retired role-delegation probe",
        direction: "consume",
        input: {
          namespace: "workspace.role",
          registered_namespace: "workspace.role",
          role_id: "maintainer",
          key_proof_valid: true,
        },
      },
    )).rejects.toThrow(/current boundary is not executable/u);
  }, 30_000);

  it("rejects any catalog projector that changes the raw verdict class", () => {
    expect(() => assertProjectionPreservesVerdict("reject", { verdict: "accept" }))
      .toThrow(/projector changed semantic verdict/u);
    expect(() => assertProjectionPreservesVerdict(
      "reject",
      { verdict: "reject", reason_code: "bad_signature" },
      "delegation_mismatch",
    )).toThrow(/projector changed semantic reason/u);
    expect(() => assertProjectionPreservesVerdict(
      "indeterminate",
      { verdict: "indeterminate", reason_code: "control-signer-effect-indeterminate" },
    )).not.toThrow();
  });

  it("validates profile wire semantics instead of accepting a registry echo", async () => {
    const registry = loadRegistry(resolve(sourceRoot, "../../../../../"));
    const profileCases = await buildProfileCases();
    const profileCase = profileCases.find(({ vector_id }) =>
      vector_id === "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1"
    )!;
    expect(validateCurrentKindProfileNegotiation(registry, profileCase.input))
      .toMatchObject({ verdict: "accept", stamp_owner: "comms" });

    const malformed = structuredClone(profileCase.input) as {
      wire_probe: { tags: string[][] };
    };
    malformed.wire_probe.tags = [];
    expect(validateCurrentKindProfileNegotiation(registry, malformed)).toEqual({
      verdict: "reject",
      reason: "profile-wire-discriminator-mismatch",
    });

    const activeKey = profileCases.find(({ vector_id }) =>
      vector_id === "assurance/profile-heterodyne-assurance-active-key-acceptance-v1"
    )!;
    expect(validateCurrentKindProfileNegotiation(registry, activeKey.input))
      .toMatchObject({ verdict: "accept", stamp_owner: "assurance" });
    const coreBreadcrumb = profileCases.find(({ vector_id }) =>
      vector_id === "core/profile-heterodyne-core-rotation-breadcrumb-profile-v1"
    )!;
    expect(validateCurrentKindProfileNegotiation(registry, coreBreadcrumb.input))
      .toMatchObject({ verdict: "accept", stamp_owner: null });
  });

  it("keeps the fixed profile oracle independent from a mutated live registry", async () => {
    const registry = loadRegistry(resolve(sourceRoot, "../../../../../"));
    const mutated = structuredClone(registry);
    const tier3 = mutated.kinds
      .flatMap(({ profiles }) => profiles)
      .find(({ profile_id }) =>
        profile_id === "heterodyne-comms-tier3-wrapped-content-kind-1-v1"
      )!;
    tier3.discriminator = "tag:heterodyne_wrap=bogus-tier3-v99";

    const expected = (await buildProfileCases()).find(({ vector_id }) =>
      vector_id === "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1"
    )!;
    const underMutation = (await buildProfileCases()).find(({ vector_id }) =>
      vector_id === expected.vector_id
    )!;

    expect(underMutation.input).toEqual(expected.input);
    expect(validateCurrentKindProfileNegotiation(mutated, underMutation.input))
      .toEqual({ verdict: "reject", reason: "profile-metadata-mismatch" });
  });

  it("rejects a Core breadcrumb profile when its NIP-01 signature or identity is mutated", async () => {
    const original = (await buildProfileCases()).find(({ vector_id }) =>
      vector_id === "core/profile-heterodyne-core-rotation-breadcrumb-note-v1"
    )!;
    for (const [mutation, expectedReason] of [
      [
        (input: Record<string, unknown>) => {
          const event = input.event !== null && typeof input.event === "object"
            ? input.event as Record<string, unknown>
            : {};
          input.event = { ...event, sig: "00".repeat(64) };
        },
        "bad_signature",
      ],
      [
        (input: Record<string, unknown>) => {
          input.active_persona_key = "ff".repeat(32);
        },
        "delegation_mismatch",
      ],
    ] as const) {
      const fixture = structuredClone(original);
      mutation(fixture.input as Record<string, unknown>);
      const oracle = currentProfileOracleForVector(fixture.vector_id)!;
      await expect(invokeCurrentBoundary(oracle.semantic_boundary, fixture))
        .resolves.toMatchObject({
          projected_output: { verdict: "reject", reason_code: expectedReason },
        });
    }
  });

  it("rejects a Tier-3 profile when its carrier, repository, or recipient escapes confinement", async () => {
    const original = (await buildProfileCases()).find(({ vector_id }) =>
      vector_id === "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1"
    )!;
    for (const [mutation, expectedReason] of [
      [
        (input: Record<string, unknown>) => Object.assign(input, {
          private_group: true,
          requested_route: "wss://public-relay.example",
          authorized_routes: ["wss://public-relay.example"],
        }),
        "marmot-private-route-required",
      ],
      [
        (input: Record<string, unknown>) => {
          input.requested_repository_rid = "rad:zDifferentPrivateRepository";
        },
        "marmot-private-route-required",
      ],
      [
        (input: Record<string, unknown>) => {
          input.requested_interface_id = "ordinary-nostr-relay";
        },
        "marmot-private-route-required",
      ],
      [
        (input: Record<string, unknown>) => {
          input.requested_route = "rad:zDifferentPrivateRepository";
        },
        "marmot-private-route-required",
      ],
      [
        (input: Record<string, unknown>) => {
          input.selected = ["ff".repeat(32)];
        },
        "tier3-recipient-not-active-device",
      ],
    ] as const) {
      const fixture = structuredClone(original);
      mutation(fixture.input as Record<string, unknown>);
      const oracle = currentProfileOracleForVector(fixture.vector_id)!;
      await expect(invokeCurrentBoundary(oracle.semantic_boundary, fixture))
        .resolves.toMatchObject({
          projected_output: { verdict: "reject", reason_code: expectedReason },
      });
    }
  });

  it("derives Tier-3 authority from the fixed private-repository oracle and binds its evidence to one row", async () => {
    const profiles = await buildProfileCases();
    const first = profiles.find(({ vector_id }) =>
      vector_id === "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1"
    )!;
    const second = profiles.find(({ vector_id }) =>
      vector_id === "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-6-v1"
    )!;
    expect(first.input).toMatchObject({
      requested_repository_rid: "rad:z3CurrentPrivateRepository",
      requested_interface_id: "radicle-native-private",
      requested_route: "rad:z3CurrentPrivateRepository",
    });
    for (const callerAuthorityField of [
      "authorized_routes",
      "private_group",
      "interface_class",
      "repository_visibility",
    ]) expect(first.input).not.toHaveProperty(callerAuthorityField);

    const firstOracle = currentProfileOracleForVector(first.vector_id)!;
    const secondOracle = currentProfileOracleForVector(second.vector_id)!;
    const firstExecution = await invokeCurrentBoundary(firstOracle.semantic_boundary, first);
    const secondExecution = await invokeCurrentBoundary(secondOracle.semantic_boundary, second);
    const firstSemantic = (firstExecution.raw_result as {
      semantic_result: {
        route_evidence: {
          vector_id: string;
          request_digest: string;
          repository_rid: string;
          interface_id: string;
          route: string;
        };
      };
    }).semantic_result;
    const secondSemantic = (secondExecution.raw_result as typeof firstExecution.raw_result & {
      semantic_result: typeof firstSemantic;
    }).semantic_result;

    expect(firstExecution.projected_output).toMatchObject({
      verdict: "accept",
      route: { verdict: "accept" },
    });
    expect(firstExecution.projected_output).not.toHaveProperty("route_evidence");
    expect(firstSemantic.route_evidence).toMatchObject({
      vector_id: first.vector_id,
      repository_rid: "rad:z3CurrentPrivateRepository",
      interface_id: "radicle-native-private",
      route: "rad:z3CurrentPrivateRepository",
    });
    expect(firstSemantic.route_evidence.request_digest).toMatch(/^[0-9a-f]{64}$/u);
    expect(secondSemantic.route_evidence.vector_id).toBe(second.vector_id);
    expect(secondSemantic.route_evidence.request_digest)
      .not.toBe(firstSemantic.route_evidence.request_digest);
  });

  it("mints a fresh request-bound Tier-3 authority for each build and rejects replayed evidence", async () => {
    const original = (await buildProfileCases()).find(({ vector_id }) =>
      vector_id === "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1"
    )!;
    const oracle = currentProfileOracleForVector(original.vector_id)!;
    const first = await invokeCurrentBoundary(oracle.semantic_boundary, original);
    const firstEvidence = (first.raw_result as {
      semantic_result: {
        route_evidence: { authority_identity: object; request_digest: string };
      };
    }).semantic_result.route_evidence;

    const replay = structuredClone(original);
    (replay.input as Record<string, unknown>).route_evidence = firstEvidence;
    await expect(invokeCurrentBoundary(oracle.semantic_boundary, replay))
      .resolves.toMatchObject({
        projected_output: {
          verdict: "reject",
          reason_code: "marmot-private-route-required",
        },
      });

    const second = await invokeCurrentBoundary(oracle.semantic_boundary, original);
    const secondEvidence = (second.raw_result as {
      semantic_result: { route_evidence: typeof firstEvidence };
    }).semantic_result.route_evidence;
    expect(secondEvidence.request_digest).toBe(firstEvidence.request_digest);
    expect(secondEvidence.authority_identity).not.toBe(firstEvidence.authority_identity);
    expect((await buildCurrentCases()).length).toBe(274);
    expect((await buildCurrentCases()).length).toBe(274);
  }, 30_000);

  it("rejects a revocation profile when the signed revocation is mutated before merge", async () => {
    const original = (await buildProfileCases()).find(({ vector_id }) =>
      vector_id === "comms/profile-heterodyne-comms-claim-revocation-nostr-bip340-v1"
    )!;
    const fixture = structuredClone(original);
    const execution = fixture.boundary_args?.[0] as {
      right: Array<{
        record_type: string;
        payload: { revocation_artifact?: { event: { sig: string } } };
      }>;
    };
    const artifact = execution.right.find(({ record_type }) =>
      record_type === "revocation"
    )!.payload.revocation_artifact!;
    expect(fixture.input.revocation_artifact).toBe(artifact);
    artifact.event.sig = "00".repeat(64);
    const oracle = currentProfileOracleForVector(fixture.vector_id)!;

    await expect(invokeCurrentBoundary(oracle.semantic_boundary, fixture))
      .resolves.toMatchObject({
        projected_output: { verdict: "reject" },
      });
  });

  it("rejects caller-supplied purpose cross-labels for every revocation proof suite", async () => {
    const profiles = (await buildProfileCases()).filter(({ vector_id }) =>
      vector_id.includes("/profile-heterodyne-comms-claim-revocation-")
    );
    expect(profiles).toHaveLength(3);
    for (const original of profiles) {
      const fixture = structuredClone(original);
      (fixture.input as Record<string, unknown>).proof_purpose = "claim-subject-pop";
      const oracle = currentProfileOracleForVector(fixture.vector_id)!;
      await expect(invokeCurrentBoundary(oracle.semantic_boundary, fixture))
        .resolves.toMatchObject({
          projected_output: {
            verdict: "reject",
            reason_code: "claim-subject-proof-invalid",
          },
        });
    }
  });

  it("verifies and merges the exact row-fixed revocation artifact before applying its irreversible effect", async () => {
    const expectedRows = new Map([
      [
        "comms/profile-heterodyne-comms-claim-revocation-nostr-bip340-v1",
        { suite: "nostr-bip340", effect: "reader-denied" },
      ],
      [
        "comms/profile-heterodyne-comms-claim-revocation-radicle-ed25519-v1",
        { suite: "radicle-ed25519", effect: "reader-denied" },
      ],
      [
        "comms/profile-heterodyne-comms-claim-revocation-jwk-jws-v1",
        { suite: "jwk-jws", effect: "descriptive-claim-revoked" },
      ],
    ] as const);
    const profiles = await buildProfileCases();

    for (const [vectorId, expected] of expectedRows) {
      const fixture = profiles.find(({ vector_id }) => vector_id === vectorId)!;
      expect(fixture.input, vectorId).toHaveProperty("revocation_artifact");
      for (const callerLabel of ["proof_purpose", "proof_suite", "message"]) {
        expect(fixture.input, `${vectorId}: ${callerLabel}`)
          .not.toHaveProperty(callerLabel);
      }
      const executionArgs = fixture.boundary_args?.[0] as {
        right: Array<{
          record_id: string;
          record_type: string;
          payload: { revocation_artifact?: unknown };
        }>;
      };
      const revocationRecord = executionArgs.right.find(({ record_type }) =>
        record_type === "revocation"
      )!;
      expect(fixture.input.revocation_artifact).toBe(
        revocationRecord.payload.revocation_artifact,
      );

      const oracle = currentProfileOracleForVector(fixture.vector_id)!;
      const result = await invokeCurrentBoundary(oracle.semantic_boundary, fixture);
      const semantic = (result.raw_result as {
        semantic_result: {
          revocation_evidence: {
            expected_suite: string;
            expected_purpose: string;
            artifact_object_identity: boolean;
            merged_record_object_identity: boolean;
            merged_artifact_object_identity: boolean;
            artifact_digest: string;
            artifact_digest_after_merge: string;
            merged_record_id: string;
            irreversible_effect: string;
          };
        };
      }).semantic_result;
      expect(result.projected_output).toMatchObject({ verdict: "accept" });
      expect(result.projected_output).not.toHaveProperty("revocation_evidence");
      expect(semantic.revocation_evidence).toMatchObject({
        expected_suite: expected.suite,
        expected_purpose: "claim-revoker",
        artifact_object_identity: true,
        merged_record_object_identity: true,
        merged_artifact_object_identity: true,
        merged_record_id: revocationRecord.record_id,
        irreversible_effect: expected.effect,
      });
      expect(semantic.revocation_evidence.artifact_digest)
        .toMatch(/^[0-9a-f]{64}$/u);
      expect(semantic.revocation_evidence.artifact_digest_after_merge)
        .toBe(semantic.revocation_evidence.artifact_digest);
      expect(Object.isFrozen(revocationRecord.payload.revocation_artifact)).toBe(true);
    }
  });

  it("rejects cross-suite, mutated, grafted, and unrelated revocation proofs for every fixed row", async () => {
    type Artifact = {
      event: {
        id: string;
        pubkey: string;
        created_at: number;
        kind: number;
        tags: string[][];
        content: string;
        sig: string;
      };
      semantic: Record<string, unknown>;
    };
    type ExecutionArgs = {
      right: Array<{
        record_type: string;
        payload: { revocation_artifact?: Artifact };
      }>;
    };
    const suiteRows = [
      ["nostr-bip340", "comms/profile-heterodyne-comms-claim-revocation-nostr-bip340-v1"],
      ["radicle-ed25519", "comms/profile-heterodyne-comms-claim-revocation-radicle-ed25519-v1"],
      ["jwk-jws", "comms/profile-heterodyne-comms-claim-revocation-jwk-jws-v1"],
    ] as const;
    const epoch = buildFixtures().personas.alice.epoch_keys.epoch_1;
    const proofSigner = buildFixtures().ed25519_nids.alice_device_1;
    const unrelated = sha256(utf8Bytes("unrelated-current-revocation-proof"));
    const artifactOf = (fixture: Awaited<ReturnType<typeof buildProfileCases>>[number]) => {
      expect(fixture.input).toHaveProperty("revocation_artifact");
      const execution = fixture.boundary_args?.[0] as ExecutionArgs;
      const record = execution.right.find(({ record_type }) => record_type === "revocation")!;
      const artifact = record.payload.revocation_artifact!;
      (fixture.input as Record<string, unknown>).revocation_artifact = artifact;
      return artifact;
    };
    const expectRejected = async (
      fixture: Awaited<ReturnType<typeof buildProfileCases>>[number],
      label: string,
    ) => {
      const oracle = currentProfileOracleForVector(fixture.vector_id)!;
      const result = await invokeCurrentBoundary(oracle.semantic_boundary, fixture);
      expect(result.projected_output, `${fixture.vector_id}: ${label}`)
        .toMatchObject({ verdict: "reject" });
    };

    const suiteFixtures = new Map((await buildProfileCases())
      .filter(({ vector_id }) => vector_id.includes("/profile-heterodyne-comms-claim-revocation-"))
      .map((fixture) => [fixture.vector_id, fixture]));
    for (let index = 0; index < suiteRows.length; index += 1) {
      const [suite, vectorId] = suiteRows[index];
      const sourceId = suiteRows[(index + 1) % suiteRows.length][1];
      const target = structuredClone(suiteFixtures.get(vectorId)!);
      const source = structuredClone(suiteFixtures.get(sourceId)!);
      const targetArtifact = artifactOf(target);
      const sourceArtifact = artifactOf(source);
      const targetRecord = (target.boundary_args?.[0] as ExecutionArgs).right
        .find(({ record_type }) => record_type === "revocation")!;
      targetRecord.payload.revocation_artifact = sourceArtifact;
      (target.input as Record<string, unknown>).revocation_artifact = sourceArtifact;
      await expectRejected(target, "cross-suite artifact");

      const mutated = structuredClone(suiteFixtures.get(vectorId)!);
      artifactOf(mutated).event.sig = "00".repeat(64);
      await expectRejected(mutated, "signed artifact mutation");

      const grafted = structuredClone(suiteFixtures.get(vectorId)!);
      const graftedArtifact = artifactOf(grafted);
      const graftedSemantic = {
        ...graftedArtifact.semantic,
        revoked_at: Number(graftedArtifact.semantic.revoked_at) + 1,
      };
      if (suite === "nostr-bip340") {
        graftedArtifact.semantic = graftedSemantic;
        graftedArtifact.event = {
          ...graftedArtifact.event,
          created_at: Number(graftedSemantic.revoked_at),
          content: jcsCanonicalize(graftedSemantic),
        };
      } else {
        graftedArtifact.semantic = graftedSemantic;
        graftedArtifact.event = await signEvent({
          secretKey: epoch.private_key,
          auxRand: AUX_RAND,
          created_at: Number(graftedSemantic.revoked_at),
          kind: 31014,
          tags: [["d", String(graftedArtifact.semantic.claim_id)]],
          content: jcsCanonicalize(graftedSemantic),
        });
      }
      await expectRejected(grafted, "proof grafted to another revocation");

      const unrelatedProof = structuredClone(suiteFixtures.get(vectorId)!);
      const unrelatedArtifact = artifactOf(unrelatedProof);
      if (suite === "nostr-bip340") {
        unrelatedArtifact.event.sig = bytesToHex(schnorr.sign(
          unrelated,
          hexToBytes(epoch.private_key),
          hexToBytes(AUX_RAND),
        ));
      } else {
        const semantic = unrelatedArtifact.semantic as {
          proof: Record<string, unknown>;
        };
        if (suite === "radicle-ed25519") {
          semantic.proof.signature = bytesToHex(ed25519.sign(
            unrelated,
            hexToBytes(proofSigner.private_key),
          ));
        } else {
          const protectedHeader = String(semantic.proof.protected);
          const signingInput = utf8Bytes(
            `${protectedHeader}.${Buffer.from(unrelated).toString("base64url")}`,
          );
          semantic.proof.signature = Buffer.from(ed25519.sign(
            signingInput,
            hexToBytes(proofSigner.private_key),
          )).toString("base64url");
        }
        unrelatedArtifact.event = await signEvent({
          secretKey: epoch.private_key,
          auxRand: AUX_RAND,
          created_at: unrelatedArtifact.event.created_at,
          kind: 31014,
          tags: unrelatedArtifact.event.tags,
          content: jcsCanonicalize(semantic),
        });
      }
      await expectRejected(unrelatedProof, "unrelated signed digest");
      expect(targetArtifact).not.toBe(sourceArtifact);
    }
  });

  it("rejects a Control profile when account, leaf, grant, content, or secret confinement is crossed", async () => {
    const original = (await buildProfileCases()).find(({ vector_id }) =>
      vector_id === "control/profile-heterodyne-control-marmot-frame-v1"
    )!;
    Object.assign(original.input, {
      active_account: "11".repeat(32),
      authenticated_account: "11".repeat(32),
      grant_account: "11".repeat(32),
      requested_device: "device-one",
      grant_device: "device-one",
      requested_leaf: "leaf-one",
      grant_leaf: "leaf-one",
      requested_group: "group-one",
      grant_group: "group-one",
      requested_grant: "grant-one",
      grant_id: "grant-one",
      requested_content_ids: ["content-one"],
      granted_content_ids: ["content-one"],
      requested_secret_classes: [],
    });
    const mutations = [
      (input: Record<string, unknown>) => {
        input.authenticated_account = "22".repeat(32);
      },
      (input: Record<string, unknown>) => {
        input.active_account = "not-a-canonical-account";
        input.authenticated_account = "not-a-canonical-account";
        input.grant_account = "not-a-canonical-account";
      },
      (input: Record<string, unknown>) => {
        input.requested_leaf = "leaf-other";
      },
      (input: Record<string, unknown>) => {
        input.requested_grant = "grant-other";
      },
      (input: Record<string, unknown>) => {
        input.requested_content_ids = ["content-other"];
      },
      (input: Record<string, unknown>) => {
        input.requested_secret_classes = ["marmot-leaf-secret"];
      },
    ];
    for (const mutation of mutations) {
      const fixture = structuredClone(original);
      mutation(fixture.input as Record<string, unknown>);
      const oracle = currentProfileOracleForVector(fixture.vector_id)!;
      await expect(invokeCurrentBoundary(oracle.semantic_boundary, fixture))
        .resolves.toMatchObject({
          projected_output: { verdict: "reject", reason_code: "control-token-invalid" },
        });
    }
  });

  it("binds all 31 fixed profile rows to their exercised live boundary", async () => {
    const profileCases = (await buildCurrentCases()).filter(({ profile, vector_id }) =>
      profile !== undefined && vector_id.includes("/profile-heterodyne-")
    );
    expect(CURRENT_PROFILE_ORACLES).toHaveLength(31);
    expect(profileCases).toHaveLength(31);
    for (const oracle of CURRENT_PROFILE_ORACLES) {
      expect(profileCases.find(({ vector_id }) => vector_id === oracle.vector_id))
        .toMatchObject({
          semantic_boundary: oracle.semantic_boundary,
          owner_document: oracle.tuple.owner,
          profile: oracle.tuple.profile_id,
          invariants: oracle.exercised_invariants,
        });
    }
  }, 60_000);

  it("backs private Social state at rest with authenticated encryption", async () => {
    const mute = (await buildCurrentCases()).find(({ vector_id }) =>
      vector_id === "social/profile-heterodyne-social-mute-list-v1"
    )!;

    expect(mute.semantic_boundary).toBe(
      "privacy-crypto.deriveConfigPostKey+nostr-tools.nip44",
    );
    expect(mute.expected_output).toMatchObject({
      verdict: "accept",
      recovered_plaintext: mute.input.plaintext,
    });
    expect(mute.expected_output.ciphertext).not.toBe(mute.input.plaintext);
  }, 60_000);

  it("preserves exact evaluator results including Control indeterminate", async () => {
    const cases = await buildCurrentCases();
    const byId = new Map(cases.map((entry) => [entry.vector_id, entry]));

    const signerEffect = byId.get("control/signer-effect-indeterminate")!;
    const signerInput = {
      canonical_event_valid: true,
      fields_exact: true,
      effect_certain: false,
    };
    expect(signerEffect.expected_output).toEqual(validateControlSignedEffect(signerInput));
    expect(signerEffect.expected_output).toMatchObject({
      verdict: "indeterminate",
      reason_code: "control-signer-effect-indeterminate",
    });
    expect(Object.isFrozen(signerEffect.expected_output)).toBe(true);
  }, 60_000);

  it("binds crossed Assurance cases to the evaluator that produced their result", async () => {
    const cases = await buildCurrentCases();
    const byId = new Map(cases.map((entry) => [entry.vector_id, entry]));

    const succession = byId.get("assurance/succession-valid")!;
    expect(succession.semantic_boundary).toBe("assurance.evaluateSuccession");
    expect(succession.expected_output).toEqual(evaluateSuccession(
      succession.input as Parameters<typeof evaluateSuccession>[0],
    ));

    const continuation = byId.get(
      "assurance/compromise-subordinate-continuation-forbidden",
    )!;
    expect(continuation.semantic_boundary).toBe(
      "assurance-policy.evaluateAssuranceCompromiseContinuation",
    );
    expect(continuation.expected_output).toEqual(
      evaluateAssuranceCompromiseContinuation({
        transition_class: "compromise",
        subordinate_reauthorization_ids:
          continuation.input.subordinate_reauthorization_ids as readonly string[],
      }),
    );
  }, 60_000);

  it("never serializes registry-derived trace labels as semantic vectors", async () => {
    const vectors = (await buildCurrentVectors()).map(({ vector }) => vector);
    expect(vectors.filter(({ vector_id }) => vector_id.includes("/trace/"))).toEqual([]);
    expect(vectors.filter(({ input, expected_output }) =>
      Object.hasOwn(input, "diagnostic_condition")
      || Object.hasOwn(input, "protocol_state")
      || Object.hasOwn(expected_output, "invariant_satisfied")
    )).toEqual([]);
    for (const vector of vectors) {
      const serialized = JSON.stringify(vector);
      expect(serialized).not.toMatch(
        /artifact_object_identity|authority_identity|boundary_args|evidence_brand|raw_result|revocation_evidence|route_evidence|semantic_reason_codes/u,
      );
    }
  }, 60_000);

  it("authors the mandatory closure cases from live evaluator results", async () => {
    const vectors = await buildCurrentVectors();
    const byId = new Map(vectors.map(({ vector }) => [vector.vector_id, vector]));
    const expectedOwners = new Map<string, string>([
      ["core/replaceable-future-quarantined", "core"],
      ["core/replaceable-at-premature-boundary", "core"],
      ["core/replaceable-equal-time-lowest-id", "core"],
      ["core/replaceable-advisory-nip03-ignored", "core"],
      ["assurance/enrollment-pending-w-minus-one", "assurance"],
      ["assurance/enrollment-verified-at-window", "assurance"],
      ["assurance/enrollment-timely-contest", "assurance"],
      ["assurance/enrollment-competing-inception", "assurance"],
      ["assurance/enrollment-forged-contest-ignored", "assurance"],
      ["assurance/enrollment-late-warning-no-unpin", "assurance"],
      ["assurance/witness-threshold-pass", "assurance"],
      ["assurance/witness-threshold-fail", "assurance"],
      ["comms/checkpoint-exact-boundary", "comms"],
      ["comms/checkpoint-stale-independent", "comms"],
      ["comms/authorization-view-300-boundary", "comms"],
      ["comms/authorization-view-86400-boundary", "comms"],
      ["comms/authorization-view-maximum-malformed", "comms"],
      ["comms/tier3-recipient-confined", "comms"],
      ["control/opaque-authorization-view-accepted", "control"],
      ["control/caller-freshness-booleans-rejected", "control"],
      ["control/authorization-view-stale-at-effect", "control"],
      ["social/source-neutral-core-quarantine", "social"],
      ["social/source-neutral-vanilla-authorship", "social"],
      ["workspace/bare-key-baseline", "workspace"],
      ["workspace/assurance-verified-activation", "workspace"],
      ["workspace/assurance-pending-activation", "workspace"],
      ["workspace/assurance-unilateral-removal", "workspace"],
      ["workspace/assurance-dual-removal", "workspace"],
      ["workspace/assurance-history-mutation-revalidated", "workspace"],
    ]);
    for (const [id, owner] of expectedOwners) {
      expect(byId.get(id), id).toMatchObject({ owner_document: owner });
    }
    expect(byId.get("core/replaceable-future-quarantined")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "core-created-at-premature" });
    expect(byId.get("assurance/enrollment-pending-w-minus-one")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "assurance-enrollment-pending-window" });
    expect(byId.get("assurance/enrollment-late-warning-no-unpin")?.expected_output)
      .toMatchObject({ verdict: "accept", state: "verified" });
    expect(byId.get("comms/checkpoint-stale-independent")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "oidc-checkpoint-stale" });
    expect(byId.get("control/authorization-view-stale-at-effect")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "control-authorization-view-stale" });
    expect(byId.get("workspace/assurance-history-mutation-revalidated")?.expected_output)
      .toMatchObject({ verdict: "reject", reason_code: "workspace-assurance-state-required" });
    expect(byId.get("assurance/persona-author-mismatch")?.expected_output)
      .toEqual({ verdict: "reject", reason_code: "delegation_mismatch" });
    expect(byId.get("assurance/keri-wire-format-rejected")?.expected_output)
      .toEqual({ verdict: "reject", reason_code: "keri_wire_format_rejected" });
  }, 60_000);

  it("emits deterministic unique paths and schema-valid exact traceability", async () => {
    const first = await buildCurrentVectors();
    const second = await buildCurrentVectors();
    expect(second).toEqual(first);
    expect(new Set(first.map(({ relativePath }) => relativePath)).size).toBe(first.length);
    expect(new Set(first.map(({ vector }) => vector.vector_id)).size).toBe(first.length);
    for (const { vector } of first) expect(() => validateVectorOrThrow(vector)).not.toThrow();
  }, 60_000);
});
