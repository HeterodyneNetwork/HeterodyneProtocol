import { beforeAll, describe, expect, it } from "vitest";
import {
  createAuthorizationFreshnessAuthority,
  evaluateAuthorizationFreshness,
  revalidateAuthorizationViewAtEffect,
  type AuthorizationFreshnessAuthority,
  type AuthoritativeAuthorizationView,
} from "./authorization-freshness.js";
import {
  buildLedgerRepositoryEvidence,
  mergeClaimLedger,
  type LedgerMergeResult,
} from "./claim-ledger.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import { buildFixtures } from "./fixtures.js";
import { utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import { nip19 } from "nostr-tools";
import { createHash } from "node:crypto";
import {
  continuityManifestDigest,
  createContinuityAuthorityProof,
  type ContinuityManifest,
  type ContinuityManifestBody,
} from "./token-status.js";

const fixtures = buildFixtures();
let scenario: Awaited<ReturnType<typeof buildClaimLedgerScenario>>;

beforeAll(async () => {
  scenario = await buildClaimLedgerScenario(fixtures);
});

const sha256 = (value: Uint8Array): string =>
  createHash("sha256").update(value).digest("hex");

function signedManifest(
  state: LedgerMergeResult,
  options: {
    checkpoint_age?: number;
    authorization_view_max_age?: number;
  } = {},
): ContinuityManifest {
  const personaKey = fixtures.personas.alice.epoch_keys.epoch_1.pubkey;
  const personaNpub = nip19.npubEncode(personaKey);
  const body: ContinuityManifestBody = {
    profile: "heterodyne-oidc-continuity-v1",
    repository_rid: scenario.rid,
    branch: "main",
    persona_npub: personaNpub,
    persona_key: personaKey,
    issuer: `https://node.example/oidc/${personaNpub}`,
    sequence: 0,
    predecessor_digest: null,
    max_checkpoint_age_seconds: 300,
    authorization_view_max_age: options.authorization_view_max_age ?? 300,
    current_jwks_sha256: sha256(utf8Bytes(jcsCanonicalize({ keys: [OIDC_RSA_ONE.public_jwk] }))),
    current_signing_key_id: OIDC_RSA_ONE.key_id,
    current_signing_jwk_sha256: sha256(utf8Bytes(jcsCanonicalize(OIDC_RSA_ONE.public_jwk))),
    retiring_signing_key_ids: [],
    retiring_jwks_sha256: [],
    status_lists: [],
    successor: null,
    authority: {
      writer_nid: scenario.writerOne.did_key,
      issued_at: state.checkpoint.observed_at + (options.checkpoint_age ?? 0),
      checkpoint: state.checkpoint,
    },
  };
  return {
    ...body,
    authority_proof: createContinuityAuthorityProof(body, scenario.writerOne.private_key),
  };
}

function authorityFor(
  manifest: ContinuityManifest,
  state: LedgerMergeResult,
  clock: { now: number },
  load = (): AuthoritativeAuthorizationView => ({ manifest, ledger_state: state }),
): AuthorizationFreshnessAuthority {
  return createAuthorizationFreshnessAuthority({
    repository_rid: manifest.repository_rid,
    persona_key: manifest.persona_key,
    manifest_digest: continuityManifestDigest(manifest),
  }, {
    trusted_now: () => clock.now,
    load_current_view: (binding) => {
      if (binding.repository_rid !== manifest.repository_rid
        || binding.persona_key !== manifest.persona_key
        || binding.manifest_digest !== continuityManifestDigest(manifest)) {
        throw new Error("freshness loader received an unbound request");
      }
      return load();
    },
  });
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
    expect(() => createAuthorizationFreshnessAuthority(binding, {
      trusted_now: () => state.checkpoint.observed_at,
      load_current_view: () => ({ manifest, ledger_state: state }),
      now: state.checkpoint.observed_at,
      authorization_view_authenticated: true,
    } as never)).toThrow(/authority source/i);
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
