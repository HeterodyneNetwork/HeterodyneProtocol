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
  writeCoverageFromVectors,
} from "./coverage.js";
import { buildCurrentCases, buildCurrentVectors } from "./current-vectors/index.js";
import { currentCaseIds } from "./current-vectors/case-contracts.js";
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
    expect(vectors).toHaveLength(currentCaseIds().length);
    expect(semanticCoverage).toHaveLength(currentCaseIds().length);
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
    expect(coverage.filter(({ invariants }) => invariants.length === 0).map(({ vector_id }) => vector_id))
      .toEqual([]);
    expect(semanticCoverage.find(({ vector_id }) => vector_id === "comms/auth-rejected-permanent"))
      .toMatchObject({ invariants: [], reason_codes: [] });
    const registry = loadRegistry(resolve(import.meta.dirname, "../../../../../"));
    expect(registry.security_invariants).toHaveLength(74);
    expect(new Set(semanticCoverage.flatMap(({ invariants }) => invariants)).size).toBe(74);
    expect(registry.reason_codes).toHaveLength(215);
    expect(new Set(semanticCoverage.flatMap(({ reason_codes }) => reason_codes)).size)
      .toBeGreaterThan(0);
    expect(NON_WIRE_REASON_EXCLUSIONS.length).toBeGreaterThan(0);
    expect(new Set(NON_WIRE_REASON_EXCLUSIONS.map(({ code }) => code)).size)
      .toBe(NON_WIRE_REASON_EXCLUSIONS.length);
    expect(registry.kinds.flatMap(({ profiles }) => profiles)).toHaveLength(31);
    expect(new Set(semanticCoverage.flatMap(({ profile }) =>
      profile === undefined ? [] : [profile]
    )).size).toBe(31);
    expect(findInvariantCoverageIssues(registry, semanticCoverage)).toEqual([]);
    expect(findReasonCoverageIssues(registry, semanticCoverage)).toEqual([]);
    expect(findProfileCoverageIssues(registry, semanticCoverage)).toEqual([]);
    expect(PENDING_PROFILE_IDS).toEqual([]);
    expect(INACTIVE_PROFILE_IDS).toEqual([]);
  }, 60_000);

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

  it("BLUE TEAM VALIDATION: synthetic/local revision 17 retains only exact retired security diagnostics", () => {
    const codes = NON_WIRE_REASON_EXCLUSIONS.map(({ code }) => code);
    expect(codes).toEqual([
      "agent-attribution-bypass-prohibited",
      "agent-human-profile-prohibited",
      "agent-key-access-prohibited",
      "agent-method-prohibited",
      "agent-resource-denied",
      "auth_rejected_permanent",
      "compromise_rotation_breadcrumb_forbidden",
      "control-request-id-conflict",
      "control-signed-event-invalid",
      "dm_invite_revoked_device",
      "dm_invite_unbound_device",
      "equivocation_flagged",
      "expired_delegation",
      "informal_vouch_not_counted",
      "kel_head_forbidden",
      "kel_head_mismatch",
      "kel_head_missing",
      "kel_revoked_nid",
      "nid_binding_missing_signature",
      "org_member_add_unauthorized",
      "provisional_not_final",
      "repo_head_regression",
      "retired-key-authority-window-invalid",
      "retiring_key_nip05_invalid",
      "revoked_key_post_compromise",
      "revoked_key_post_revoked_at",
      "role-delegation-address-invalid",
      "role-delegation-key-proof-invalid",
      "signing_key_compromised_at_created_at",
      "successor_persona_mismatch",
      "withdrawn_on_reconcile",
    ]);
    expect(NON_WIRE_REASON_EXCLUSIONS.filter(({ code }) => [
      "agent-attribution-bypass-prohibited",
      "agent-human-profile-prohibited",
      "agent-key-access-prohibited",
      "agent-method-prohibited",
      "agent-resource-denied",
      "auth_rejected_permanent",
      "control-request-id-conflict",
      "control-signed-event-invalid",
      "dm_invite_revoked_device",
      "dm_invite_unbound_device",
      "retired-key-authority-window-invalid",
      "revoked_key_post_compromise",
    ].includes(code))).toEqual([
      { code: "agent-attribution-bypass-prohibited", justification: "Retained only as non-wire history for the retired attribution-bypass diagnostic; live attribution-before-signing is enforced by publication authority." },
      { code: "agent-human-profile-prohibited", justification: "Retained only as non-wire history for the retired persona-vault and signer-selection diagnostic; live signer selection is enforced by publication authority." },
      { code: "agent-key-access-prohibited", justification: "Retained only as non-wire history for the retired private-key-access diagnostic; live key confinement is enforced by signer boundaries." },
      { code: "agent-method-prohibited", justification: "Retained only as non-wire history for the retired closed-method diagnostic; live method authorization is enforced by exact grants." },
      { code: "agent-resource-denied", justification: "Retained only as non-wire history for the retired signer-resource diagnostic; live resource authorization is enforced by exact grants." },
      { code: "auth_rejected_permanent", justification: "Current local relay-write diagnostic only; a post-AUTH rejection proves no cryptographic or upstream authority and cannot satisfy semantic coverage." },
      { code: "control-request-id-conflict", justification: "Retained only as non-wire history for the retired request-ID diagnostic; live at-most-once execution is enforced by the durable signer fence." },
      { code: "control-signed-event-invalid", justification: "Retained only as non-wire history for the retired signer-output diagnostic; live output verification is enforced by publication and signer-fence boundaries." },
      { code: "dm_invite_revoked_device", justification: "Retained only as non-wire history for the retired device-revocation DM-invite diagnostic; current invite authority does not emit it." },
      { code: "dm_invite_unbound_device", justification: "Retained only as non-wire history for the retired device-delegation DM-invite diagnostic; current invite authority does not emit it." },
      { code: "retired-key-authority-window-invalid", justification: "Retained only as non-wire history for the retired Core key-window diagnostic; current verification and selection do not emit it." },
      { code: "revoked_key_post_compromise", justification: "Retained only as non-wire history for the duplicate post-compromise diagnostic; live cutoff evidence comes from evaluateAssuranceAuthorityAt." },
    ]);
    expect(new Set(codes).size)
      .toBe(NON_WIRE_REASON_EXCLUSIONS.length);
    expect(NON_WIRE_REASON_EXCLUSIONS.every(({ justification }) =>
      justification.trim().length >= 24
    )).toBe(true);
  });

  it("BLUE TEAM VALIDATION: synthetic/local revision 17 live authority reasons are never excluded", () => {
    const liveReasons = [
      "agent-sender-proof-invalid", "conversation-rejected", "invite-authentication-invalid",
      "marmot-agent-scope-denied", "marmot-keypackage-replayed", "marmot-premature-ack",
      "marmot-private-inbox-nid-required", "control-compromise-reset-evidence-invalid",
      "control-compromise-reset-inventory-mismatch", "control-compromise-reset-unauthenticated",
      "control-subordinate-reauthorization-required", "control-device-code-display-mismatch",
      "control-device-code-invalid", "control-device-code-rate-limited", "control-enrollment-unavailable",
      "control-frame-invalid", "invite-preauthorization-invalid", "control-keypackage-invalid",
      "control-keypackage-replenishment-paused", "control-signer-effect-indeterminate",
      "control-token-invalid", "capability_escalation", "policy_denied", "workspace_replay",
      "profile-repository-selection-required", "relay_profile_mutation", "strict_mode_tor_disabled",
      "unauthorized_cache_content",
    ];
    expect(liveReasons).toHaveLength(28);
    const exclusions = new Set(NON_WIRE_REASON_EXCLUSIONS.map(({ code }) => code));
    expect(liveReasons.filter((code) => exclusions.has(code))).toEqual([]);
  });

  it("BLUE TEAM VALIDATION: synthetic/local semantic coverage omits retired Core authority", async () => {
    // BLUE TEAM VALIDATION: inspect only deterministic current cases built in-process.
    const retiredReasons = new Set([
      "org_member_add_unauthorized",
      "role-delegation-address-invalid",
      "role-delegation-key-proof-invalid",
    ]);
    const coverage = buildSemanticCoverage(await buildCurrentCases());
    expect(coverage.filter(({ reason_codes }) =>
      reason_codes.some((code) => retiredReasons.has(code))
    )).toEqual([]);
    expect(coverage.filter(({ semantic_boundary }) =>
      semantic_boundary === "core-policy.validateOrganizationMemberAddition"
      || semantic_boundary === "core-policy.validateRoleDelegation"
    )).toEqual([]);
    expect(coverage.filter(({ vector_id }) =>
      vector_id === "core/node-advert-dual-proof-valid"
      || vector_id === "core/node-advert-nid-proof-invalid"
    ).flatMap(({ invariants }) => invariants))
      .not.toContain("CORE-I-NID-DELEGATION-DUAL-PROOF");
    const exclusions = new Set(NON_WIRE_REASON_EXCLUSIONS.map(({ code }) => code));
    expect([...retiredReasons].every((code) => exclusions.has(code))).toBe(true);
  }, 30_000);

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
    const vectors = (await buildCurrentVectors()).map(({ vector }) => vector);
    await writeCoverageFromVectors(vectorRoot, vectors);
    const first = await readFile(join(vectorRoot, "coverage", "assurance.md"), "utf8");
    await writeCoverageFromVectors(vectorRoot, vectors);
    const second = await readFile(join(vectorRoot, "coverage", "assurance.md"), "utf8");
    expect(second).toBe(first);
    expect(first).toContain("assurance/enrollment-pending-w-minus-one");
    expect(first).toContain("assurance/witness-threshold-pass");
  }, 30_000);
});
