import { schnorr } from "@noble/curves/secp256k1";
import { beforeAll, describe, expect, it } from "vitest";
import {
  authorizeClaimEffect,
  createClaimAuthorizationAuthority,
  inspectClaimState,
  type ClaimAuthorizationEffectInput,
  type ClaimEffectRecord,
  type ClaimEffectStore,
  type CurrentClaimAuthorizationView,
} from "./claim-authorization.js";
import {
  computeClaimId,
  inspectVerifiedClaim,
  subjectProofPayload,
  verifyClaimEnvelope,
  verifyClaimRevocationEnvelope,
  type ClaimRevocation,
  type ClaimSemanticBody,
  type SubjectProofChallenge,
  type VerifiedClaimArtifact,
} from "./claims.js";
import { buildFixtures } from "./fixtures.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { getEventId, type NostrSignedEvent, type NostrUnsignedEvent } from "./nostr.js";
import { invokeCurrentBoundary } from "./current-vectors/boundary-runners.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";

const fixtures = buildFixtures();
const issuer = fixtures.personas.alice.epoch_keys.epoch_1;
const subject = fixtures.device_publishing_keys.alice_device_2;
const auxRand = fixtures.pinned_randomness.schnorr_aux_rand;
const now = 1_784_390_420;
const ledger = Object.freeze({
  credential_ledger_persona: issuer.pubkey,
  credential_ledger_generation: 0,
});
let writerScenario: Awaited<ReturnType<typeof buildClaimLedgerScenario>>;

beforeAll(async () => {
  writerScenario = await buildClaimLedgerScenario(fixtures);
});

type StoreHarness = Readonly<{
  store: ClaimEffectStore;
  records: Map<string, ClaimEffectRecord>;
  calls: { load: number; acquire: number; commit: number; mark: number };
}>;

function copied<T>(value: T): T {
  return structuredClone(value);
}

function storeHarness(overrides: Partial<ClaimEffectStore> = {}): StoreHarness {
  const records = new Map<string, ClaimEffectRecord>();
  const calls = { load: 0, acquire: 0, commit: 0, mark: 0 };
  const store: ClaimEffectStore = {
    load(singleUseKey) {
      calls.load += 1;
      const record = records.get(singleUseKey);
      return record === undefined ? null : copied(record);
    },
    acquire(singleUseKey, bindingDigest, executionToken) {
      calls.acquire += 1;
      const record = records.get(singleUseKey);
      if (record === undefined) {
        records.set(singleUseKey, {
          state: "executing",
          binding_digest: bindingDigest,
          execution_token: executionToken,
        });
        return "acquired";
      }
      return record.binding_digest === bindingDigest ? "replay" : "conflict";
    },
    commit(executionToken, resultDigest, cachedResult) {
      calls.commit += 1;
      for (const [key, record] of records) {
        if (record.execution_token !== executionToken || record.state !== "executing") continue;
        records.set(key, {
          state: "committed",
          binding_digest: record.binding_digest,
          execution_token: executionToken,
          result_digest: resultDigest,
          cached_result: copied(cachedResult),
        });
        return "committed";
      }
      return "conflict";
    },
    markIndeterminate(executionToken, reconciliationDigest) {
      calls.mark += 1;
      for (const [key, record] of records) {
        if (record.execution_token !== executionToken || record.state !== "executing") continue;
        records.set(key, {
          state: "indeterminate",
          binding_digest: record.binding_digest,
          execution_token: executionToken,
          reconciliation_digest: reconciliationDigest,
        });
        return "indeterminate";
      }
      return "conflict";
    },
    ...overrides,
  };
  return { store, records, calls };
}

function signedArtifact(createdAt = now - 20): VerifiedClaimArtifact {
  const withoutId = {
    issuer: { type: "nostr-secp256k1" as const, value: issuer.pubkey },
    subject: { type: "nostr-secp256k1" as const, value: subject.pubkey },
    claim_class: "authorization" as const,
    ...ledger,
    namespace: "heterodyne.device",
    name: "claim-ledger-reader",
    value: true,
    issued_at: now - 20,
    not_before: now - 20,
    expires_at: now + 300,
    audience: [issuer.pubkey],
    resources: ["rad:claims/device"],
    visibility: "repository-private" as const,
    spec_version: "heterodyne/0.6.0" as const,
    profile_revision: 2 as const,
  };
  const semantic: ClaimSemanticBody = { claim_id: computeClaimId(withoutId), ...withoutId };
  const unsigned: NostrUnsignedEvent = {
    pubkey: issuer.pubkey,
    created_at: createdAt,
    kind: 31013,
    tags: [["d", semantic.claim_id]],
    content: jcsCanonicalize(semantic),
  };
  const id = getEventId(unsigned);
  const event: NostrSignedEvent = {
    ...unsigned,
    id,
    sig: bytesToHex(schnorr.sign(id, hexToBytes(issuer.private_key), auxRand)),
  };
  return verifyClaimEnvelope(event, { profile_revision: 2, credential_ledger: ledger });
}

function proofFor(
  artifact: VerifiedClaimArtifact,
  overrides: Partial<SubjectProofChallenge> = {},
) {
  const semantic = inspectVerifiedClaim(artifact);
  const challenge: SubjectProofChallenge = {
    domain: "heterodyne-claim-pop-v1",
    claim_id: semantic.claim_id,
    nonce: "ab".repeat(16),
    audience: issuer.pubkey,
    resource: "rad:claims/device",
    operation: "read",
    issued_at: now - 5,
    expires_at: now + 55,
    ...overrides,
  };
  return {
    key: semantic.subject,
    challenge,
    proof: {
      type: "nostr-bip340" as const,
      signature: bytesToHex(schnorr.sign(
        subjectProofPayload(challenge),
        hexToBytes(subject.private_key),
        auxRand,
      )),
    },
  };
}

function signedRevocation(artifact: VerifiedClaimArtifact) {
  const claim = inspectVerifiedClaim(artifact);
  const semantic: ClaimRevocation = {
    claim_id: claim.claim_id,
    revoked_at: now - 1,
    reason_code: "claim-revoked",
    revoker: claim.issuer,
    spec_version: "heterodyne/0.6.0",
    profile_revision: 2,
  };
  const unsigned: NostrUnsignedEvent = {
    pubkey: issuer.pubkey,
    created_at: semantic.revoked_at,
    kind: 31014,
    tags: [["d", semantic.claim_id]],
    content: jcsCanonicalize(semantic),
  };
  const id = getEventId(unsigned);
  return verifyClaimRevocationEnvelope({
    ...unsigned,
    id,
    sig: bytesToHex(schnorr.sign(id, hexToBytes(issuer.private_key), auxRand)),
  });
}

function currentView(
  artifact: VerifiedClaimArtifact,
  overrides: Partial<CurrentClaimAuthorizationView> = {},
): CurrentClaimAuthorizationView {
  return {
    credential_ledger: ledger,
    checkpoint_digest: "cd".repeat(32),
    repository_revision: 7,
    claims: [artifact],
    revocations: [],
    conflicted_claim_ids: [],
    ledger_state: writerScenario.issuerKeyEpochOneState,
    ...overrides,
  };
}

function scenario(options: Readonly<{
  artifact?: VerifiedClaimArtifact;
  store?: StoreHarness;
  authorityId?: string;
  load?: () => CurrentClaimAuthorizationView;
  trustedNow?: () => number;
}> = {}) {
  const artifact = options.artifact ?? signedArtifact();
  const store = options.store ?? storeHarness();
  const view = currentView(artifact);
  const authority = createClaimAuthorizationAuthority({
    authority_id: options.authorityId ?? "claim-authority-A",
    trusted_now: options.trustedNow ?? (() => now),
    trusted_issuers: [inspectVerifiedClaim(artifact).issuer],
    load_current_view: options.load ?? (() => view),
    store: store.store,
    effect_timeout_ms: 60_000,
    schedule_effect_deadline: { schedule: () => () => {} },
  });
  let effects = 0;
  const input: ClaimAuthorizationEffectInput<{ receipt: string }> = {
    leaf: artifact,
    chain: [artifact],
    audience: issuer.pubkey,
    resource: "rad:claims/device",
    requested_namespace: "heterodyne.device",
    operation: "read",
    nonce: "ab".repeat(16),
    subject_proof: proofFor(artifact),
    idempotency_key: "read-device-claim-once",
    effect_digest: "ef".repeat(32),
    effect(executionToken) {
      effects += 1;
      expect(executionToken).toMatch(/^[0-9a-f]{64}$/);
      expect([...store.records.values()][0]?.state).toBe("executing");
      return { status: "completed", result: { receipt: "committed" } };
    },
  };
  return { artifact, authority, input, store, effects: () => effects, view };
}

function authorityWithEffectDeadline(
  value: ReturnType<typeof scenario>,
  schedule: (durationMs: number, fire: () => void) => () => void,
) {
  return createClaimAuthorizationAuthority({
    authority_id: "claim-authority-deadline",
    trusted_now: () => now,
    trusted_issuers: [inspectVerifiedClaim(value.artifact).issuer],
    load_current_view: () => value.view,
    store: value.store.store,
    effect_timeout_ms: 12,
    schedule_effect_deadline: { schedule },
  } as unknown as Parameters<typeof createClaimAuthorizationAuthority>[0]);
}

function deterministicDeadlineScheduler() {
  let nowMs = 0;
  let latestDuration = -1;
  const entries: Array<{ due: number; active: boolean; fire: () => void }> = [];
  return {
    schedule(durationMs: number, fire: () => void) {
      latestDuration = durationMs;
      const entry = { due: nowMs + durationMs, active: true, fire };
      entries.push(entry);
      return () => { entry.active = false; };
    },
    advance(durationMs: number) {
      nowMs += durationMs;
      for (const entry of entries) {
        if (entry.active && entry.due <= nowMs) {
          entry.active = false;
          entry.fire();
        }
      }
    },
    latestDuration: () => latestDuration,
  };
}

describe("claim authorization proof/effect fence", () => {
  it("executes the current positive claim effect and inspects unconfirmed state directly", async () => {
    const active = scenario();
    const activeExecution = await invokeCurrentBoundary(
      "claim-authorization.authorizeClaimEffect",
      {
        vector_id: "comms/claim-active-authenticated",
        description: "current synthetic claim effect",
        direction: "consume",
        input: {},
        boundary_args: [active.authority, active.input],
      },
    );
    expect(activeExecution.projected_output).toMatchObject({
      verdict: "accept",
      authorization: { allowed: true, disposition: "executed" },
    });

    const artifact = signedArtifact();
    const unconfirmed = scenario({
      artifact,
      load: () => currentView(artifact, { claims: [] }),
    });
    const unconfirmedExecution = await invokeCurrentBoundary(
      "claim-authorization.inspectClaimState",
      {
        vector_id: "comms/claim-repository-unconfirmed",
        description: "current synthetic unconfirmed inspection",
        direction: "consume",
        input: {},
        boundary_args: [unconfirmed.authority, unconfirmed.input],
      },
    );
    expect(unconfirmedExecution.projected_output).toMatchObject({
      verdict: "reject",
      reason_code: "claim-repository-unconfirmed",
      evaluator_output: { allowed: false, state: "provisional" },
    });
  });

  it("inspects active state without returning authority or acquiring a proof", () => {
    const value = scenario();
    expect(inspectClaimState(value.authority, value.input)).toEqual({
      allowed: false,
      state: "active",
      reason_code: null,
    });
    expect(value.store.calls.acquire).toBe(0);
    expect(value.effects()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local acquires exactly once before one effect and caches a defensive result", async () => {
    // BLUE TEAM VALIDATION: synthetic/local fixture is deterministic, minimal, and non-deployable; it has no live target, deployment, account, credential, external system, or reusable payload.
    const value = scenario();
    const first = await authorizeClaimEffect(value.authority, value.input);
    expect(first).toEqual({
      verdict: "accept",
      allowed: true,
      state: "active",
      disposition: "executed",
      result: { receipt: "committed" },
    });
    if (first.verdict !== "accept") throw new Error("synthetic/local effect did not commit");
    expect(value.store.calls.acquire).toBe(1);
    expect(value.store.calls.commit).toBe(1);
    expect(value.effects()).toBe(1);
    expect(Object.isFrozen(first.result)).toBe(true);

    const retry = await authorizeClaimEffect(value.authority, value.input);
    expect(retry).toEqual({ ...first, disposition: "cached" });
    if (retry.verdict !== "accept") throw new Error("synthetic/local retry was not cached");
    expect(value.store.calls.acquire).toBe(2);
    expect(value.effects()).toBe(1);
    expect(retry.result).not.toBe(first.result);
  });

  it("BLUE TEAM VALIDATION: synthetic/local lets only one simultaneous worker invoke the effect", async () => {
    // BLUE TEAM VALIDATION: synthetic/local promise only coordinates two local calls; it performs no network or production action.
    const value = scenario();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let calls = 0;
    const input = {
      ...value.input,
      async effect() {
        calls += 1;
        await gate;
        return { status: "completed" as const, result: { receipt: "committed" } };
      },
    };
    const first = authorizeClaimEffect(value.authority, input);
    await Promise.resolve();
    const competing = await authorizeClaimEffect(value.authority, input);
    expect(competing).toMatchObject({
      verdict: "indeterminate",
      allowed: false,
      reason_code: "claim-authorization-effect-indeterminate",
    });
    expect(calls).toBe(1);
    release();
    await expect(first).resolves.toMatchObject({ verdict: "accept", disposition: "executed" });
    expect(calls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects altered request bindings before proof acquisition", async () => {
    // BLUE TEAM VALIDATION: synthetic/local mutations are bounded strings and never leave the local verifier.
    const mutations: readonly [
      Partial<ClaimAuthorizationEffectInput<{ receipt: string }>>,
      string,
    ][] = [
      [{ audience: "https://other.example" }, "claim-attenuation-violation"],
      [{ resource: "rad:claims/other" }, "claim-attenuation-violation"],
      [{ operation: "write" }, "claim-subject-proof-invalid"],
      [{ nonce: "ff".repeat(16) }, "claim-subject-proof-invalid"],
    ];
    for (const [patch, reason_code] of mutations) {
      const value = scenario();
      await expect(authorizeClaimEffect(value.authority, { ...value.input, ...patch }))
        .resolves.toMatchObject({
          verdict: "reject",
          allowed: false,
          reason_code,
        });
      expect(value.store.calls.acquire).toBe(0);
      expect(value.effects()).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects changed chain, authority, effect, and idempotency bindings", async () => {
    // BLUE TEAM VALIDATION: synthetic/local substitutions use only separately signed local artifacts and inert identifiers.
    const shared = storeHarness();
    const first = scenario({ store: shared });
    await expect(authorizeClaimEffect(first.authority, first.input))
      .resolves.toMatchObject({ verdict: "accept" });

    const alternate = signedArtifact(now - 19);
    const changedChain = scenario({ artifact: alternate, store: shared });
    await expect(authorizeClaimEffect(changedChain.authority, changedChain.input))
      .resolves.toMatchObject({ verdict: "reject", reason_code: "claim-subject-proof-replayed" });
    const otherAuthority = scenario({ store: shared, authorityId: "claim-authority-B" });
    await expect(authorizeClaimEffect(otherAuthority.authority, otherAuthority.input))
      .resolves.toMatchObject({ verdict: "reject", reason_code: "claim-subject-proof-replayed" });
    for (const patch of [
      { effect_digest: "ee".repeat(32) },
      { idempotency_key: "different-idempotency-key" },
    ]) {
      await expect(authorizeClaimEffect(first.authority, { ...first.input, ...patch }))
        .resolves.toMatchObject({ verdict: "reject", reason_code: "claim-subject-proof-replayed" });
    }
    expect(first.effects()).toBe(1);
    expect(changedChain.effects()).toBe(0);
    expect(otherAuthority.effects()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local treats acquire conflict as replay without invoking an effect", async () => {
    // BLUE TEAM VALIDATION: synthetic/local CAS double is process-local and contains no reusable external payload.
    const base = storeHarness();
    const value = scenario({ store: {
      ...base,
      store: { ...base.store, acquire: () => "conflict" },
    } });
    await expect(authorizeClaimEffect(value.authority, value.input)).resolves.toEqual({
      verdict: "reject",
      allowed: false,
      state: "invalid",
      reason_code: "claim-subject-proof-replayed",
    });
    expect(value.effects()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local refuses unknown acquire replies before invoking an effect", async () => {
    // BLUE TEAM VALIDATION: synthetic/local store replies are bounded inert values and never leave this local authority.
    for (const acquisition of [undefined, "unexpected-acquire-state"] as const) {
      const base = storeHarness();
      const value = scenario({ store: {
        ...base,
        store: { ...base.store, acquire: () => acquisition as never },
      } });
      await expect(authorizeClaimEffect(value.authority, value.input)).resolves.toMatchObject({
        allowed: false,
      });
      expect(value.effects()).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local confirms the exact acquired executing record before invoking an effect", async () => {
    // BLUE TEAM VALIDATION: synthetic/local store mismatches are bounded in-memory records with no live effect.
    for (const mismatched of [false, true]) {
      const base = storeHarness();
      const value = scenario({ store: {
        ...base,
        store: {
          ...base.store,
          acquire(key, _binding, token) {
            if (mismatched) {
              base.records.set(key, {
                state: "executing",
                binding_digest: "00".repeat(32),
                execution_token: token,
              });
            }
            return "acquired";
          },
        },
      } });
      await expect(authorizeClaimEffect(value.authority, value.input)).resolves.toMatchObject({
        allowed: false,
      });
      expect(value.effects()).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local marks one never-settling effect indeterminate at its authority deadline", async () => {
    // BLUE TEAM VALIDATION: synthetic/local scheduling advances only a bounded in-memory millisecond clock, never a wall clock or external timer.
    const value = scenario();
    const scheduler = deterministicDeadlineScheduler();
    const authority = authorityWithEffectDeadline(value, scheduler.schedule);
    let effects = 0;
    const pending = authorizeClaimEffect(authority, {
      ...value.input,
      effect: () => {
        effects += 1;
        return new Promise<never>(() => {});
      },
    });
    let settled = false;
    void pending.then(() => { settled = true; });
    await Promise.resolve();
    expect(scheduler.latestDuration()).toBe(12);
    expect(effects).toBe(1);
    scheduler.advance(11);
    await Promise.resolve();
    expect(settled).toBe(false);
    expect(value.store.calls.mark).toBe(0);
    scheduler.advance(1);
    await expect(pending).resolves.toMatchObject({
      verdict: "indeterminate",
      allowed: false,
      reason_code: "claim-authorization-effect-indeterminate",
    });
    expect(value.store.calls.mark).toBe(1);
    expect(await authorizeClaimEffect(authority, {
      ...value.input,
      effect: () => ({ status: "completed" as const, result: { receipt: "reopened" } }),
    })).toMatchObject({ verdict: "indeterminate", allowed: false });
    expect(effects).toBe(1);
    expect(value.store.calls.mark).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local never invokes an effect after an immediate authority deadline", async () => {
    // BLUE TEAM VALIDATION: synthetic/local scheduling fires one in-memory callback before any inert effect callback can run.
    const value = scenario();
    const authority = authorityWithEffectDeadline(value, (_deadline, fire) => {
      fire();
      return () => {};
    });
    let effects = 0;
    await expect(authorizeClaimEffect(authority, {
      ...value.input,
      effect: () => {
        effects += 1;
        return { status: "completed" as const, result: { receipt: "too-late" } };
      },
    })).resolves.toMatchObject({
      verdict: "indeterminate",
      allowed: false,
      reason_code: "claim-authorization-effect-indeterminate",
    });
    expect(effects).toBe(0);
    expect(value.store.calls.mark).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes thrown and timeout/unknown effects durably indeterminate", async () => {
    // BLUE TEAM VALIDATION: synthetic/local callbacks are inert local functions with no live or external side effects.
    for (const effect of [
      () => { throw new Error("synthetic/local effect outcome unknown"); },
      () => ({ status: "unknown" as const }),
    ]) {
      const value = scenario();
      const input = { ...value.input, effect };
      const result = await authorizeClaimEffect(value.authority, input);
      expect(result).toMatchObject({
        verdict: "indeterminate",
        allowed: false,
        reason_code: "claim-authorization-effect-indeterminate",
      });
      expect(value.store.calls.mark).toBe(1);
      const retry = await authorizeClaimEffect(value.authority, input);
      expect(retry).toEqual(result);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local never authorizes after terminal-write failure or an unsafe result", async () => {
    // BLUE TEAM VALIDATION: synthetic/local failures model only a local durable-store boundary and bounded unserializable data.
    const terminalFailureBase = storeHarness();
    const terminalFailure = scenario({ store: {
      ...terminalFailureBase,
      store: {
        ...terminalFailureBase.store,
        commit: () => "conflict",
      },
    } });
    await expect(authorizeClaimEffect(terminalFailure.authority, terminalFailure.input))
      .resolves.toMatchObject({
        verdict: "indeterminate",
        allowed: false,
        reason_code: "claim-authorization-effect-indeterminate",
      });
    expect(terminalFailure.effects()).toBe(1);

    const unsafe = scenario();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    await expect(authorizeClaimEffect(unsafe.authority, {
      ...unsafe.input,
      effect: () => ({ status: "completed", result: cyclic }),
    })).resolves.toMatchObject({
      verdict: "indeterminate",
      allowed: false,
      reason_code: "claim-authorization-effect-indeterminate",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local keeps the exact reconciliation digest when indeterminate persistence fails", async () => {
    // BLUE TEAM VALIDATION: synthetic/local store failure is deterministic, process-local, and has no live target or external effect.
    const base = storeHarness();
    const value = scenario({ store: {
      ...base,
      store: {
        ...base.store,
        markIndeterminate: () => "conflict",
      },
    } });
    const input = {
      ...value.input,
      effect: () => ({ status: "unknown" as const }),
    };
    const first = await authorizeClaimEffect(value.authority, input);
    const retry = await authorizeClaimEffect(value.authority, input);
    expect(first).toMatchObject({ verdict: "indeterminate", allowed: false });
    expect(retry).toEqual(first);
    expect(value.store.calls.acquire).toBe(2);
  });

  it("BLUE TEAM VALIDATION: synthetic/local reconciles an acquire callback that throws after durable acquisition", async () => {
    // BLUE TEAM VALIDATION: synthetic/local callback throws only after updating one process-local record; it has no external target or effect.
    const base = storeHarness();
    const value = scenario({ store: {
      ...base,
      store: {
        ...base.store,
        acquire(singleUseKey, bindingDigest, executionToken) {
          base.store.acquire(singleUseKey, bindingDigest, executionToken);
          throw new Error("synthetic/local acquire return lost");
        },
      },
    } });
    const first = await authorizeClaimEffect(value.authority, value.input);
    const retry = await authorizeClaimEffect(value.authority, value.input);
    expect(first).toMatchObject({ verdict: "indeterminate", allowed: false });
    expect(retry).toEqual(first);
    expect(value.effects()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local revalidates repository and revocation state immediately before acquire", async () => {
    // BLUE TEAM VALIDATION: synthetic/local loader returns two bounded in-memory snapshots and contacts no repository or relay.
    for (const changed of ["conflict", "removed"] as const) {
      const artifact = signedArtifact();
      const views = [
        currentView(artifact),
        currentView(artifact, changed === "conflict"
          ? { conflicted_claim_ids: [inspectVerifiedClaim(artifact).claim_id] }
          : { claims: [] }),
      ];
      let loads = 0;
      const value = scenario({ artifact, load: () => views[Math.min(loads++, 1)] });
      await expect(authorizeClaimEffect(value.authority, value.input)).resolves.toMatchObject({
        verdict: "reject",
        allowed: false,
        reason_code: changed === "conflict"
          ? "claim-repository-conflict"
          : "claim-repository-unconfirmed",
      });
      expect(loads).toBe(2);
      expect(value.store.calls.acquire).toBe(0);
      expect(value.effects()).toBe(0);
    }

    const artifact = signedArtifact();
    const revocation = signedRevocation(artifact);
    let revocationLoads = 0;
    const revoked = scenario({
      artifact,
      load: () => revocationLoads++ === 0
        ? currentView(artifact)
        : currentView(artifact, { revocations: [revocation] }),
    });
    await expect(authorizeClaimEffect(revoked.authority, revoked.input)).resolves.toMatchObject({
      verdict: "reject",
      allowed: false,
      reason_code: "claim-revoked",
    });
    expect(revoked.store.calls.acquire).toBe(0);
    expect(revoked.effects()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects writer removal immediately before effect acquisition", async () => {
    // BLUE TEAM VALIDATION: synthetic/local policy replacement and effect counters are bounded in-memory fixtures with no external target or reusable payload.
    const artifact = signedArtifact();
    let loads = 0;
    const value = scenario({
      artifact,
      load: () => {
        loads += 1;
        if (loads === 2) {
          writerScenario.setCurrentWriterPolicy({
            ...writerScenario.activeWriterPolicy(),
            writers: writerScenario.activeWriterPolicy().writers.map((writer) => ({
              ...writer,
              state: "revoked" as const,
            })),
          });
        }
        return {
          ...currentView(artifact),
          ledger_state: writerScenario.issuerKeyEpochOneState,
        } as unknown as CurrentClaimAuthorizationView;
      },
    });
    try {
      await expect(authorizeClaimEffect(value.authority, value.input)).resolves.toMatchObject({
        verdict: "reject",
        allowed: false,
        reason_code: "claim-ledger-writer-unauthorized",
      });
      expect(loads).toBe(2);
      expect(value.store.calls.acquire).toBe(0);
      expect(value.effects()).toBe(0);
    } finally {
      writerScenario.resetCurrentWriterPolicy();
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects regressed trusted time and repository revision before acquire", async () => {
    // BLUE TEAM VALIDATION: synthetic/local regressions are two bounded scalar values with no live clock, repository, or external system.
    const artifact = signedArtifact();
    let loads = 0;
    const revisionRegression = scenario({
      artifact,
      load: () => currentView(artifact, { repository_revision: loads++ === 0 ? 7 : 6 }),
    });
    await expect(authorizeClaimEffect(revisionRegression.authority, revisionRegression.input))
      .resolves.toMatchObject({ verdict: "reject", allowed: false });
    expect(revisionRegression.store.calls.acquire).toBe(0);

    let clockCalls = 0;
    const clockRegression = scenario({
      artifact,
      trustedNow: () => clockCalls++ === 0 ? now : now - 1,
    });
    await expect(authorizeClaimEffect(clockRegression.authority, clockRegression.input))
      .resolves.toMatchObject({ verdict: "reject", allowed: false });
    expect(clockRegression.store.calls.acquire).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects accessor/proxy configuration and current views without traps", async () => {
    // BLUE TEAM VALIDATION: synthetic/local trap counters prove bounded fail-closed capture; no external system is referenced.
    const artifact = signedArtifact();
    const base = scenario({ artifact });
    let reads = 0;
    const config = {
      authority_id: "claim-authority-accessor",
      trusted_now: () => now,
      trusted_issuers: [inspectVerifiedClaim(artifact).issuer],
      load_current_view: () => currentView(artifact),
      store: base.store.store,
      effect_timeout_ms: 60_000,
      schedule_effect_deadline: { schedule: () => () => {} },
    };
    Object.defineProperty(config, "trusted_now", {
      enumerable: true,
      get() {
        reads += 1;
        return () => now;
      },
    });
    expect(() => createClaimAuthorizationAuthority(config)).toThrow(/data-only|configuration/i);
    expect(reads).toBe(0);

    let viewReads = 0;
    const hostileView = currentView(artifact) as CurrentClaimAuthorizationView & Record<string, unknown>;
    Object.defineProperty(hostileView, "repository_revision", {
      enumerable: true,
      get() {
        viewReads += 1;
        return 7;
      },
    });
    const value = scenario({ artifact, load: () => hostileView });
    await expect(authorizeClaimEffect(value.authority, value.input))
      .resolves.toMatchObject({ verdict: "reject", allowed: false });
    expect(viewReads).toBe(0);
    expect(value.effects()).toBe(0);

    let callbackTraps = 0;
    const callbackProxy = new Proxy(() => now, {
      apply() {
        callbackTraps += 1;
        return now;
      },
    });
    expect(() => createClaimAuthorizationAuthority({
      authority_id: "claim-authority-proxy-callback",
      trusted_now: callbackProxy,
      trusted_issuers: [inspectVerifiedClaim(artifact).issuer],
      load_current_view: () => currentView(artifact),
      store: base.store.store,
      effect_timeout_ms: 60_000,
      schedule_effect_deadline: { schedule: () => () => {} },
    })).toThrow(/non-proxy callback/i);
    expect(callbackTraps).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects malformed store terminals without invoking accessors", async () => {
    // BLUE TEAM VALIDATION: synthetic/local terminal is one inert local object with no live state, account, credential, or external system.
    const base = storeHarness();
    let reads = 0;
    const terminal = {
      state: "committed",
      binding_digest: "aa".repeat(32),
      execution_token: "bb".repeat(32),
      result_digest: "cc".repeat(32),
    } as ClaimEffectRecord & { cached_result?: unknown };
    Object.defineProperty(terminal, "cached_result", {
      enumerable: true,
      get() {
        reads += 1;
        return { receipt: "unsafe" };
      },
    });
    const value = scenario({ store: {
      ...base,
      store: {
        ...base.store,
        acquire: () => "replay",
        load: () => terminal,
      },
    } });
    await expect(authorizeClaimEffect(value.authority, value.input)).resolves.toMatchObject({
      verdict: "indeterminate",
      allowed: false,
      reason_code: "claim-authorization-effect-indeterminate",
    });
    expect(reads).toBe(0);
    expect(value.effects()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a proxy effect result without promise-assimilation traps", async () => {
    // BLUE TEAM VALIDATION: synthetic/local proxy is an inert trap counter and contains no reusable payload or external action.
    const value = scenario();
    let traps = 0;
    const hostileResult = new Proxy(
      { status: "completed" as const, result: { receipt: "unsafe" } },
      {
        get() {
          traps += 1;
          throw new Error("synthetic/local promise-assimilation trap");
        },
      },
    );
    await expect(authorizeClaimEffect(value.authority, {
      ...value.input,
      effect: () => hostileResult,
    })).resolves.toMatchObject({
      verdict: "indeterminate",
      allowed: false,
      reason_code: "claim-authorization-effect-indeterminate",
    });
    expect(traps).toBe(0);
  });
});
