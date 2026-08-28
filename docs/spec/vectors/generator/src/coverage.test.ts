import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  INACTIVE_PROFILE_IDS,
  NON_WIRE_REASON_EXCLUSIONS,
  PENDING_PROFILE_IDS,
  buildCoverage,
  buildSemanticCoverage,
  findInvariantCoverageIssues,
  findProfileCoverageIssues,
  findReasonCoverageIssues,
  writeCoverage,
} from "./coverage.js";
import { buildCurrentCases, buildCurrentVectors } from "./current-vectors/index.js";
import { loadRegistry } from "./registry.js";

const tempDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs.length = 0;
});

describe("current family coverage", () => {
  it("is a sorted lossless six-owner schema-3 projection with complete closure", async () => {
    const vectors = (await buildCurrentVectors()).map(({ vector }) => vector);
    const coverage = buildCoverage(vectors);
    const semanticCoverage = buildSemanticCoverage(await buildCurrentCases());
    expect(vectors).toHaveLength(275);
    expect(semanticCoverage).toHaveLength(275);
    expect(coverage.map(({ vector_id }) => vector_id)).toEqual(
      [...coverage.map(({ vector_id }) => vector_id)].sort(),
    );
    expect(new Set(coverage.map(({ vector_id }) => vector_id)).size).toBe(vectors.length);
    expect(vectors.every(({ vector_schema_version }) => vector_schema_version === "3.0.0"))
      .toBe(true);
    expect(coverage.every((entry) => !Object.hasOwn(entry, "spec_version"))).toBe(true);
    expect(new Set(coverage.map(({ owner_document }) => owner_document))).toEqual(new Set([
      "assurance",
      "comms",
      "control",
      "core",
      "social",
      "workspace",
    ]));
    expect(coverage.every(({ invariants }) => invariants.length > 0)).toBe(true);
    const registry = loadRegistry(resolve(import.meta.dirname, "../../../../../"));
    expect(registry.security_invariants).toHaveLength(74);
    expect(new Set(semanticCoverage.flatMap(({ invariants }) => invariants)).size).toBe(74);
    expect(registry.reason_codes).toHaveLength(211);
    expect(new Set(semanticCoverage.flatMap(({ reason_codes }) => reason_codes)).size).toBe(195);
    expect(NON_WIRE_REASON_EXCLUSIONS).toHaveLength(16);
    expect(registry.kinds.flatMap(({ profiles }) => profiles)).toHaveLength(31);
    expect(new Set(semanticCoverage.flatMap(({ profile }) =>
      profile === undefined ? [] : [profile]
    )).size).toBe(31);
    expect(findInvariantCoverageIssues(registry, semanticCoverage)).toEqual([]);
    expect(findReasonCoverageIssues(registry, semanticCoverage)).toEqual([]);
    expect(findProfileCoverageIssues(registry, semanticCoverage)).toEqual([]);
    expect(PENDING_PROFILE_IDS).toEqual([]);
    expect(INACTIVE_PROFILE_IDS).toEqual([]);
  }, 30_000);

  it("does not treat an administrative vector projection as executable evidence", async () => {
    const registry = loadRegistry(resolve(import.meta.dirname, "../../../../../"));
    const administrative = buildCoverage(
      (await buildCurrentVectors()).map(({ vector }) => vector),
    );
    expect(findInvariantCoverageIssues(registry, administrative)).toContain(
      `coverage entry lacks executable boundary: ${administrative[0]!.vector_id}`,
    );
  }, 30_000);

  it("rejects cloned semantic evidence", async () => {
    const cases = await buildCurrentCases();
    const badSignature = cases.find(({ vector_id }) =>
      vector_id === "core/node-advert-bad-signature"
    )!;
    expect(() => buildSemanticCoverage([{ ...badSignature }])).toThrow(
      /unbranded semantic evidence/u,
    );
  }, 30_000);

  it("rejects same-owner invariant reassignment", async () => {
    const badSignature = (await buildCurrentCases()).find(({ vector_id }) =>
      vector_id === "core/node-advert-bad-signature"
    )!;
    expect(() => buildSemanticCoverage([{
      ...badSignature,
      invariants: ["CORE-I-IDENTITY-INTEGRITY"],
    }])).toThrow(/unbranded semantic evidence/u);
  }, 30_000);

  it("rejects same-owner reason reassignment", async () => {
    const badSignature = (await buildCurrentCases()).find(({ vector_id }) =>
      vector_id === "core/node-advert-bad-signature"
    )!;
    expect(() => buildSemanticCoverage([{
      ...badSignature,
      reason_codes: ["nid_proof_invalid"],
    }])).toThrow(/unbranded semantic evidence/u);
  }, 30_000);

  it("rejects fabricated accept evidence for bad_signature", async () => {
    const badSignature = (await buildCurrentCases()).find(({ vector_id }) =>
      vector_id === "core/node-advert-bad-signature"
    )!;
    expect(() => buildSemanticCoverage([{
      ...badSignature,
      expected_output: { verdict: "accept" },
      reason_codes: ["bad_signature"],
    }])).toThrow(/unbranded semantic evidence/u);
  }, 30_000);

  it("reports missing owner-bound invariant, reason, and profile evidence", async () => {
    const registry = loadRegistry(resolve(import.meta.dirname, "../../../../../"));
    const coverage = buildSemanticCoverage(await buildCurrentCases());
    const invariant = registry.security_invariants.find(({ id }) =>
      coverage.some((entry) => entry.invariants.includes(id))
    )!;
    const withoutInvariant = coverage.map((entry) => ({
      ...entry,
      invariants: entry.invariants.filter((id) => id !== invariant.id),
    }));
    expect(findInvariantCoverageIssues(registry, withoutInvariant)).toContain(
      `uncovered invariant: ${invariant.id}`,
    );

    const excluded = new Set(NON_WIRE_REASON_EXCLUSIONS.map(({ code }) => code));
    const reason = registry.reason_codes.find(({ code }) =>
      !excluded.has(code) && coverage.some((entry) => entry.reason_codes.includes(code))
    )!;
    const withoutReason = coverage.map((entry) => ({
      ...entry,
      reason_codes: entry.reason_codes.filter((code) => code !== reason.code),
    }));
    expect(findReasonCoverageIssues(registry, withoutReason)).toContain(
      `uncovered reason code: ${reason.code}`,
    );

    const profile = registry.kinds.flatMap(({ profiles }) => profiles)[0]!;
    expect(findProfileCoverageIssues(
      registry,
      coverage.map((entry) => entry.profile === profile.profile_id
        ? { ...entry, profile: undefined }
        : entry),
    )).toContain(`uncovered profile: ${profile.profile_id}`);
    const profiled = coverage.find((entry) => entry.profile === profile.profile_id)!;
    expect(findProfileCoverageIssues(registry, coverage.map((entry) => entry === profiled
      ? { ...entry, owner_document: profile.owner === "core" ? "comms" : "core" }
      : entry,
    ))).toContain(`profile owner mismatch: ${profiled.vector_id} -> ${profile.profile_id}`);
  }, 30_000);

  it("keeps the non-wire reason exclusion audit closed and specific", () => {
    const codes = NON_WIRE_REASON_EXCLUSIONS.map(({ code }) => code);
    expect(codes).toEqual([
      "compromise_rotation_breadcrumb_forbidden",
      "equivocation_flagged",
      "expired_delegation",
      "informal_vouch_not_counted",
      "kel_head_forbidden",
      "kel_head_mismatch",
      "kel_head_missing",
      "kel_revoked_nid",
      "nid_binding_missing_signature",
      "provisional_not_final",
      "repo_head_regression",
      "retiring_key_nip05_invalid",
      "revoked_key_post_revoked_at",
      "signing_key_compromised_at_created_at",
      "successor_persona_mismatch",
      "withdrawn_on_reconcile",
    ]);
    expect(new Set(codes).size)
      .toBe(NON_WIRE_REASON_EXCLUSIONS.length);
    expect(NON_WIRE_REASON_EXCLUSIONS.every(({ justification }) =>
      justification.trim().length >= 24
    )).toBe(true);
  });

  it("keeps qualified snapshot references without adding version metadata", () => {
    const coverage = buildCoverage([{
      vector_id: "identity/example",
      owner_document: "core",
      spec_refs: ["heterodyne:core#core-root-attestation"],
      invariants: ["CORE-I-IDENTITY-INTEGRITY"],
      reason_codes: [],
    }]);

    expect(coverage).toEqual([{
      vector_id: "identity/example",
      owner_document: "core",
      spec_refs: ["heterodyne:core#core-root-attestation"],
      invariants: ["CORE-I-IDENTITY-INTEGRITY"],
      reason_codes: [],
    }]);
  });

  it("rejects an unlisted uncovered profile", async () => {
    const coverage = buildSemanticCoverage(await buildCurrentCases());
    const registry = structuredClone(loadRegistry(resolve(import.meta.dirname, "../../../../../")));
    registry.kinds[0].profiles.push({
      profile_id: "unlisted-future-profile",
      owner: "comms",
      discriminator: "test:unlisted",
      stamping: false,
      first_version: "heterodyne/0.6.0",
      status: "draft",
    });
    expect(findProfileCoverageIssues(registry, coverage)).toContain(
      "uncovered profile: unlisted-future-profile",
    );
  }, 30_000);

  it("writes deterministic six-owner Markdown from the current manifest", async () => {
    const vectorRoot = await mkdtemp(join(tmpdir(), "heterodyne-vector-coverage-"));
    tempDirs.push(vectorRoot);
    await writeCoverage(vectorRoot);
    const first = await readFile(join(vectorRoot, "coverage", "assurance.md"), "utf8");
    await writeCoverage(vectorRoot);
    const second = await readFile(join(vectorRoot, "coverage", "assurance.md"), "utf8");
    expect(second).toBe(first);
    expect(first).toContain("assurance/enrollment-pending-w-minus-one");
    expect(first).toContain("assurance/witness-threshold-pass");
  }, 30_000);
});
