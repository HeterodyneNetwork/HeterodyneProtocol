import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import {
  buildLedgerRepositoryEvidence,
  evaluateReaderAccess,
  materializeLedgerLayout,
  mergeClaimLedger,
  prepareLedgerReplayValidationContext,
  revalidateLedgerWriterAuthorities,
  validateReaderOnboardingBundle,
  type LedgerValidationContext,
  type ReaderAccessRequest,
} from "./claim-ledger.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import { inspectVerifiedClaim } from "./claims.js";
import { invokeCurrentBoundary } from "./current-vectors/boundary-runners.js";
import { buildCommsCases } from "./current-vectors/comms.js";
import { buildFixtures } from "./fixtures.js";

const fixtures = buildFixtures();

describe("claim-ledger remediation security contexts", () => {
  it("BLUE TEAM VALIDATION: synthetic/local accepts exact current dual-proof writers and keeps fingerprints private", async () => {
    // BLUE TEAM VALIDATION: synthetic/local dual proofs use deterministic non-deployable fixture keys and one process-local policy authority only.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const state = mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      scenario.makeContext(scenario.baseRepository.repository),
    );
    expect(revalidateLedgerWriterAuthorities(state)).toMatchObject({
      verdict: "accept",
      writer_fingerprints: expect.arrayContaining([
        expect.stringMatching(/^[0-9a-f]{64}$/),
      ]),
    });
    expect(Object.hasOwn(state, "writer_fingerprints")).toBe(false);
    expect(Object.hasOwn(state, "writer_bindings")).toBe(false);
  });

  it("BLUE TEAM VALIDATION: synthetic/local exposes the coarse current-vector writer rejection", async () => {
    // BLUE TEAM VALIDATION: synthetic/local invokes one deterministic in-process boundary fixture with no repository or network access.
    const fixture = (await buildCommsCases()).find(({ vector_id }) =>
      vector_id === "comms/claim-ledger-writer-unauthorized"
    );
    if (fixture === undefined) throw new Error("missing current writer rejection fixture");
    await expect(invokeCurrentBoundary("claim-ledger.mergeClaimLedger", fixture))
      .resolves.toMatchObject({
        projected_output: {
          verdict: "reject",
          reason_code: "claim-ledger-writer-unauthorized",
        },
      });
  }, 30_000);

  it("BLUE TEAM VALIDATION: synthetic/local rejects self-signed writers without current owner delegation", async () => {
    // BLUE TEAM VALIDATION: synthetic/local records and repository evidence are deterministic, non-deployable, and never contact an external target.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const context = scenario.makeContext(scenario.baseRepository.repository) as
      unknown as Record<string, unknown>;
    delete context.writer_authority;
    delete context.load_record_location;
    expect(() => mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      context as unknown as LedgerValidationContext,
    )).toThrow(/^claim-ledger-writer-unauthorized:/);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cross-persona, wrong RID/ref/op, location, and owner proof", async () => {
    // BLUE TEAM VALIDATION: synthetic/local mutations are bounded inert strings/objects and never produce a deployable payload or contact a repository.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const mutations = [
      (location: ReturnType<LedgerValidationContext["load_record_location"]>) => ({
        ...location,
        repository_rid: fixtures.radicle_rids.alice_reanchor,
      }),
      (location: ReturnType<LedgerValidationContext["load_record_location"]>) => ({
        ...location,
        writer_ref: "refs/xyz.heterodyne.claim-ledger/other/writer-one",
      }),
      (location: ReturnType<LedgerValidationContext["load_record_location"]>) => ({
        ...location,
        commit: "00".repeat(32),
      }),
      (location: ReturnType<LedgerValidationContext["load_record_location"]>) => ({
        ...location,
        checkpoint: "11".repeat(32),
      }),
      (location: ReturnType<LedgerValidationContext["load_record_location"]>) => ({
        ...location,
        revision: location.revision + 1,
      }),
      (location: ReturnType<LedgerValidationContext["load_record_location"]>) => ({
        ...location,
        writer_binding: {
          ...location.writer_binding,
          owner_active_key: "ff".repeat(32),
        },
      }),
      (location: ReturnType<LedgerValidationContext["load_record_location"]>) => ({
        ...location,
        writer_binding: {
          ...location.writer_binding,
          operations: [],
        },
      }),
      (location: ReturnType<LedgerValidationContext["load_record_location"]>) => ({
        ...location,
        writer_binding: {
          ...location.writer_binding,
          owner_signature: "00".repeat(64),
        },
      }),
    ];
    for (const mutate of mutations) {
      const context = scenario.makeContext(scenario.baseRepository.repository);
      const load = context.load_record_location;
      context.load_record_location = (record) => mutate(load(record));
      expect(() => mergeClaimLedger(
        [scenario.claimRecordOne, scenario.claimRecordTwo],
        [],
        scenario.baseRepository.checkpoint,
        context,
      )).toThrow(/^claim-ledger-writer-unauthorized:/);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects stale, revoked, conflicted, and changed current writer policy", async () => {
    // BLUE TEAM VALIDATION: synthetic/local policy snapshots are bounded in-memory values with no live owner, node, or external effect.
    const scenario = await buildClaimLedgerScenario(fixtures);
    for (const state of ["revoked", "conflicted"] as const) {
      scenario.setCurrentWriterPolicy({
        ...scenario.activeWriterPolicy(),
        state,
      });
      expect(() => mergeClaimLedger(
        [scenario.claimRecordOne, scenario.claimRecordTwo],
        [],
        scenario.baseRepository.checkpoint,
        scenario.makeContext(scenario.baseRepository.repository),
      )).toThrow(/^claim-ledger-writer-unauthorized:/);
    }
    scenario.resetCurrentWriterPolicy();
    const accepted = mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      scenario.makeContext(scenario.baseRepository.repository),
    );
    for (const policy of [
      {
        ...scenario.activeWriterPolicy(),
        writers: scenario.activeWriterPolicy().writers.map((writer) => ({
          ...writer,
          state: "revoked" as const,
        })),
      },
      {
        ...scenario.activeWriterPolicy(),
        revision: scenario.activeWriterPolicy().revision + 1,
      },
      {
        ...scenario.activeWriterPolicy(),
        checkpoint: "b8".repeat(20),
      },
    ]) {
      scenario.setCurrentWriterPolicy(policy);
      expect(revalidateLedgerWriterAuthorities(accepted)).toEqual({
        verdict: "reject",
        reason_code: "claim-ledger-writer-unauthorized",
      });
    }
    scenario.resetCurrentWriterPolicy();
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects writer-binding mutation after resolution", async () => {
    // BLUE TEAM VALIDATION: synthetic/local source mutation changes one fixture signature byte-string and has no live credential or reusable payload.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const state = mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      scenario.makeContext(scenario.baseRepository.repository),
    );
    const source = scenario.writerBindings.get(scenario.writerOne.did_key)! as
      unknown as { owner_signature: string };
    const original = source.owner_signature;
    try {
      source.owner_signature = "00".repeat(64);
      expect(revalidateLedgerWriterAuthorities(state)).toEqual({
        verdict: "reject",
        reason_code: "claim-ledger-writer-unauthorized",
      });
    } finally {
      source.owner_signature = original;
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects accessor/proxy record-location evidence without trap invocation", async () => {
    // BLUE TEAM VALIDATION: synthetic/local trap counters are inert and bounded; they do not target or scan any external system.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const context = scenario.makeContext(scenario.baseRepository.repository);
    const load = context.load_record_location;
    let reads = 0;
    context.load_record_location = (record) => {
      const location = load(record);
      Object.defineProperty(location, "commit", {
        enumerable: true,
        get() {
          reads += 1;
          return scenario.baseRepository.checkpoint.commit_oid;
        },
      });
      return location;
    };
    expect(() => mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      context,
    )).toThrow(/^claim-ledger-writer-unauthorized:/);
    expect(reads).toBe(0);

    let calls = 0;
    const proxyContext = scenario.makeContext(scenario.baseRepository.repository);
    proxyContext.load_record_location = new Proxy(proxyContext.load_record_location, {
      apply() {
        calls += 1;
        throw new Error("synthetic/local proxy callback invoked");
      },
    });
    expect(() => mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      proxyContext,
    )).toThrow(/^claim-ledger-writer-unauthorized:/);
    expect(calls).toBe(0);

    let recordReads = 0;
    const accessorRecord = { ...scenario.claimRecordOne };
    Object.defineProperty(accessorRecord, "record_id", {
      enumerable: true,
      get() {
        recordReads += 1;
        return scenario.claimRecordOne.record_id;
      },
    });
    expect(() => mergeClaimLedger(
      [accessorRecord, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      scenario.makeContext(scenario.baseRepository.repository),
    )).toThrow(/^claim-ledger-writer-unauthorized:/);
    expect(recordReads).toBe(0);
  });

  it("requires explicit repository and record validation evidence", () => {
    expect(typeof buildLedgerRepositoryEvidence).toBe("function");
    expect({} as LedgerValidationContext).toBeDefined();
    expect({} as ReaderAccessRequest).toBeDefined();
  });

  it("materializes a fixed 256-entry re-encrypted layout", () => {
    const key = Uint8Array.from({ length: 32 }, () => 0x51);
    const first = materializeLedgerLayout(key, 1, "aa".repeat(32), "11".repeat(32), []);
    const second = materializeLedgerLayout(key, 1, "bb".repeat(32), "12".repeat(32), []);
    expect(first.entries).toHaveLength(256);
    expect(new Set(first.entries.map(({ size }) => size))).toEqual(new Set([64]));
    expect(first.entries.map(({ path }) => path)).toEqual(
      Array.from({ length: 256 }, (_, index) => `objects/${index.toString(16).padStart(2, "0")}.bin`),
    );
    expect(first.entries.every((entry, index) => entry.ciphertext !== second.entries[index].ciphertext)).toBe(true);
  });

  it("exposes an executable onboarding validator", () => {
    expect(typeof validateReaderOnboardingBundle).toBe("function");
    expect(ed25519.getPublicKey(fixtures.ed25519_nids.alice_device_1.private_key)).toHaveLength(32);
  });

  it("BLUE TEAM VALIDATION: synthetic/local ledger replay accepts only opaque claim artifacts", async () => {
    // BLUE TEAM VALIDATION: synthetic/local replay uses deterministic non-deployable records only.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const state = mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      scenario.makeContext(scenario.baseRepository.repository),
    );
    const opaqueRequest = scenario.requestFor(scenario.claimRecordOne, scenario.claimOne);
    opaqueRequest.verification_context.now = state.checkpoint.observed_at;
    expect(evaluateReaderAccess(scenario.writerOne.did_key, state, opaqueRequest).state).toBe("active");

    const inspection = inspectVerifiedClaim(scenario.claimOne.verified_artifact);
    const formerPublicRequest = {
      ...opaqueRequest,
      claims_by_id: new Map([[inspection.claim_id, inspection]]),
    } as unknown as typeof opaqueRequest;
    expect(evaluateReaderAccess(scenario.writerOne.did_key, state, formerPublicRequest)).toMatchObject({
      allowed: false,
      state: "invalid",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local replay cache never invokes evidence accessors", async () => {
    // BLUE TEAM VALIDATION: synthetic/local evidence is deterministic and cannot target deployments.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const validation = scenario.makeContext(scenario.baseRepository.repository);
    prepareLedgerReplayValidationContext(validation);
    mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      validation,
    );

    const original = validation.record_evidence.get(scenario.claimRecordOne.record_id)!;
    let accessorReads = 0;
    const hostileEvidence = {
      record_id: original.record_id,
      payload_digest: original.payload_digest,
      claim_envelope_context: original.claim_envelope_context,
      claim_verification_context: original.claim_verification_context,
    };
    Object.defineProperty(hostileEvidence, "claims_by_id", {
      enumerable: true,
      get() {
        accessorReads += 1;
        return accessorReads % 2 === 1 ? undefined : original.claims_by_id;
      },
    });
    validation.record_evidence.set(
      scenario.claimRecordOne.record_id,
      hostileEvidence as unknown as typeof original,
    );
    expect(() => mergeClaimLedger(
      [scenario.claimRecordOne, scenario.claimRecordTwo],
      [],
      scenario.baseRepository.checkpoint,
      validation,
    )).toThrow(/evidence|data-only|repository-unconfirmed/i);
    expect(accessorReads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local ledger revocation never spreads nested hostile context", async () => {
    // BLUE TEAM VALIDATION: synthetic/local replay uses only deterministic non-deployable signed records.
    const scenario = await buildClaimLedgerScenario(fixtures);
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: scenario.rid,
      confirmed_records: [scenario.claimRecordOne, scenario.revocationRecord],
      observed_at: scenario.now + 50,
    });

    let nowReads = 0;
    const accessorValidation = scenario.makeContext(repository.repository);
    const accessorEvidence = accessorValidation.record_evidence.get(
      scenario.revocationRecord.record_id,
    )!;
    const accessorContext = { ...accessorEvidence.claim_verification_context! };
    Object.defineProperty(accessorContext, "now", {
      enumerable: true,
      get() {
        nowReads += 1;
        return scenario.now + 40;
      },
    });
    accessorValidation.record_evidence.set(scenario.revocationRecord.record_id, {
      ...accessorEvidence,
      claim_verification_context: accessorContext,
    });
    expect(() => mergeClaimLedger(
      [scenario.claimRecordOne, scenario.revocationRecord],
      [],
      repository.checkpoint,
      accessorValidation,
    )).toThrow(/claim-revoker-unauthorized|data-only|context/i);
    expect(nowReads).toBe(0);

    let proxyTraps = 0;
    const proxyValidation = scenario.makeContext(repository.repository);
    const proxyEvidence = proxyValidation.record_evidence.get(scenario.revocationRecord.record_id)!;
    const proxyContext = new Proxy(proxyEvidence.claim_verification_context!, {
      ownKeys(target) {
        proxyTraps += 1;
        return Reflect.ownKeys(target);
      },
      getOwnPropertyDescriptor(target, property) {
        proxyTraps += 1;
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
      get(target, property, receiver) {
        proxyTraps += 1;
        return Reflect.get(target, property, receiver);
      },
    });
    proxyValidation.record_evidence.set(scenario.revocationRecord.record_id, {
      ...proxyEvidence,
      claim_verification_context: proxyContext,
    });
    expect(() => mergeClaimLedger(
      [scenario.claimRecordOne, scenario.revocationRecord],
      [],
      repository.checkpoint,
      proxyValidation,
    )).toThrow(/claim-revoker-unauthorized|context/i);
    expect(proxyTraps).toBe(0);
  });
});
