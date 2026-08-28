import { beforeAll, describe, expect, it } from "vitest";
import {
  createAuthorizationFreshnessAuthority,
  evaluateAuthorizationFreshness,
  revalidateAuthorizationViewAtEffect,
  type AuthorizationFreshnessAuthority,
} from "./authorization-freshness.js";
import {
  buildLedgerRepositoryEvidence,
  mergeClaimLedger,
} from "./claim-ledger.js";
import { buildAuthorizationFreshnessTestSupport } from "./authorization-freshness-test-support.js";
import { continuityManifestDigest } from "./token-status.js";

type FreshnessSupport = Awaited<ReturnType<typeof buildAuthorizationFreshnessTestSupport>>;
let support: FreshnessSupport;
let scenario: FreshnessSupport["scenario"];

beforeAll(async () => {
  support = await buildAuthorizationFreshnessTestSupport();
  scenario = support.scenario;
});

function signedManifest(...args: Parameters<FreshnessSupport["signedManifest"]>) {
  return support.signedManifest(...args);
}

function authorityFor(...args: Parameters<FreshnessSupport["authorityFor"]>) {
  return support.authorityFor(...args);
}

describe("opaque current authorization freshness", () => {
  it.each([
    { checkpointAge: 300, viewAge: 300, max: 300, expected: "accept" },
    { checkpointAge: 301, viewAge: 301, max: 86_400, expected: "oidc-checkpoint-stale" },
    { checkpointAge: 0, viewAge: 86_400, max: 86_400, expected: "accept" },
    { checkpointAge: 0, viewAge: 86_401, max: 86_400, expected: "control-authorization-view-stale" },
  ])("enforces independent exact ages: $expected", ({ checkpointAge, viewAge, max, expected }) => {
    const state = scenario.issuerKeyEpochOneState;
    const manifest = signedManifest(state, {
      checkpoint_age: checkpointAge,
      authorization_view_max_age: max,
    });
    const clock = { now: state.checkpoint.observed_at + viewAge };
    const result = evaluateAuthorizationFreshness(authorityFor(manifest, state, clock), manifest);
    expect("reason" in result ? result.reason : result.verdict).toBe(expected);
  });

  it("fails closed when a prepared view becomes stale before effect", () => {
    const state = scenario.issuerKeyEpochOneState;
    const manifest = signedManifest(state);
    const clock = { now: state.checkpoint.observed_at + 300 };
    const prepared = evaluateAuthorizationFreshness(authorityFor(manifest, state, clock), manifest);
    expect(prepared.verdict).toBe("accept");
    if (prepared.verdict !== "accept") throw new Error("fixture rejected");

    clock.now += 1;
    expect(revalidateAuthorizationViewAtEffect(prepared.view)).toEqual({
      verdict: "reject",
      reason: "control-authorization-view-stale",
    });
  });

  it("rejects manifest substitution at preparation and immediately before effect", () => {
    const state = scenario.issuerKeyEpochOneState;
    const manifest = signedManifest(state);
    const substituted = signedManifest(state, { authorization_view_max_age: 301 });
    const clock = { now: state.checkpoint.observed_at };
    const authority = authorityFor(manifest, state, clock);
    expect(evaluateAuthorizationFreshness(authority, substituted)).toEqual({
      verdict: "reject",
      reason: "oidc-issuer-authority-invalid",
    });

    let currentManifest = manifest;
    const reloadable = authorityFor(
      manifest,
      state,
      clock,
      () => ({ manifest: currentManifest, ledger_state: state }),
    );
    const prepared = evaluateAuthorizationFreshness(reloadable, manifest);
    if (prepared.verdict !== "accept") throw new Error("fixture rejected");
    currentManifest = substituted;
    expect(revalidateAuthorizationViewAtEffect(prepared.view)).toEqual({
      verdict: "reject",
      reason: "oidc-issuer-authority-invalid",
    });
  });

  it("rejects authoritative checkpoint substitution immediately before effect", () => {
    const state = scenario.issuerKeyEpochOneState;
    const manifest = signedManifest(state);
    const clock = { now: state.checkpoint.observed_at };
    let currentState = state;
    const authority = authorityFor(
      manifest,
      state,
      clock,
      () => ({ manifest, ledger_state: currentState }),
    );
    const prepared = evaluateAuthorizationFreshness(authority, manifest);
    if (prepared.verdict !== "accept") throw new Error("fixture rejected");

    const repository = buildLedgerRepositoryEvidence({
      repository_rid: scenario.rid,
      confirmed_records: state.records,
      observed_at: state.checkpoint.observed_at + 1,
      prior: scenario.issuerKeyEpochOneRepository.repository,
    });
    currentState = mergeClaimLedger(
      state.records,
      [],
      repository.checkpoint,
      scenario.makeTask5Context(repository.repository),
    );
    expect(revalidateAuthorizationViewAtEffect(prepared.view)).toEqual({
      verdict: "reject",
      reason: "control-authorization-view-stale",
    });
  });

  it("rejects caller-authored clocks, freshness claims, authorities, and views", () => {
    const state = scenario.issuerKeyEpochOneState;
    const manifest = signedManifest(state);
    const binding = {
      repository_rid: manifest.repository_rid,
      persona_key: manifest.persona_key,
      manifest_digest: continuityManifestDigest(manifest),
    };
    const callerAuthoredSource = {
      trusted_now: () => state.checkpoint.observed_at,
      load_current_view: () => ({ manifest, ledger_state: state }),
      now: state.checkpoint.observed_at,
      authorization_view_authenticated: true,
    };
    expect(() => createAuthorizationFreshnessAuthority(binding, callerAuthoredSource))
      .toThrow(/authority source/i);
    expect(evaluateAuthorizationFreshness({} as AuthorizationFreshnessAuthority, manifest)).toEqual({
      verdict: "reject",
      reason: "control-authorization-view-stale",
    });
    expect(revalidateAuthorizationViewAtEffect({} as never)).toEqual({
      verdict: "reject",
      reason: "control-authorization-view-stale",
    });
  });

  it("rejects a conflicting authoritative current ledger view", () => {
    const records = [
      ...scenario.issuerKeyEpochOneState.records,
      scenario.grantOne,
      scenario.grantDivergent,
    ];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: scenario.rid,
      confirmed_records: records,
      observed_at: scenario.issuerKeyEpochOneState.checkpoint.observed_at + 1,
      prior: scenario.issuerKeyEpochOneRepository.repository,
    });
    const state = mergeClaimLedger(
      records,
      [],
      repository.checkpoint,
      scenario.makeTask5Context(repository.repository),
    );
    expect(state.conflicted_claim_ids).not.toEqual([]);
    const manifest = signedManifest(state);
    const clock = { now: state.checkpoint.observed_at };
    expect(evaluateAuthorizationFreshness(authorityFor(manifest, state, clock), manifest)).toEqual({
      verdict: "reject",
      reason: "control-authorization-view-stale",
    });
  });
});
