import { beforeAll, describe, expect, it } from "vitest";
import {
  type CurrentAuthorizationView,
} from "./authorization-freshness.js";
import { nip19 } from "nostr-tools";
import {
  commitControlEnrollment,
  issueControlToken,
  validateControlTokenUse,
  type ControlAuthorizationRecord,
} from "./control-profile.js";
import { buildAuthorizationFreshnessTestSupport } from "./authorization-freshness-test-support.js";
import { buildLedgerRepositoryEvidence, mergeClaimLedger } from "./claim-ledger.js";

type FreshnessSupport = Awaited<ReturnType<typeof buildAuthorizationFreshnessTestSupport>>;
let support: FreshnessSupport;
let scenario: FreshnessSupport["scenario"];

beforeAll(async () => {
  support = await buildAuthorizationFreshnessTestSupport();
  scenario = support.scenario;
  entitlement = {
    ...authorizationRecord,
    persona: scenario.persona,
  };
});

const client = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const node = "22".repeat(32);
const group = "33".repeat(32);
const object = { class: "repository" as const, id: "rad:control" };

const authorizationRecord: ControlAuthorizationRecord = {
  record_id: "11".repeat(32),
  persona: "aa".repeat(32),
  client_key: client,
  client_class: "human-light",
  approving_node: node,
  approving_authority: "interactive-oidc",
  methods: ["config.get"],
  objects: [object],
  limits: { calls: 5 },
  capabilities: [],
  token_lifetime_default_seconds: 300,
  token_lifetime_max_seconds: 300,
  inbound_execution: false,
  predecessor: null,
  state: "active",
  created_at: 0,
  expires_at: null,
  signer: "44".repeat(32),
  signature: "55".repeat(64),
};
let entitlement: ControlAuthorizationRecord;

function currentView(clock: { now: number }): CurrentAuthorizationView {
  return support.currentView(clock);
}

function issuanceInput(view: CurrentAuthorizationView) {
  return {
    entitlement,
    group_id: group,
    audience: "urn:heterodyne:control:node-a",
    node_key: node,
    issuance_nonce: "66".repeat(32),
    requested_lifetime_seconds: 300,
    node_policy_max_seconds: 3_600,
    authorization_view: view,
    methods: ["config.get"],
    objects: [object],
    limits: { calls: 5 },
  };
}

describe("Control opaque authorization view integration", () => {
  it("derives token time and checkpoint from effect-time revalidation", () => {
    const clock = { now: scenario.issuerKeyEpochOneState.checkpoint.observed_at + 10 };
    const view = currentView(clock);
    const issued = issueControlToken(issuanceInput(view));
    expect(issued).toMatchObject({
      verdict: "accept",
      token: {
        iat: clock.now,
        iss: `https://node.example/oidc/${nip19.npubEncode(scenario.persona)}`,
        registry_checkpoint: scenario.issuerKeyEpochOneState.checkpoint.commit_oid,
      },
    });
    const callerAuthoredAuthority = {
      ...issuanceInput(view),
      now: 1,
      issuer: "https://attacker.invalid/oidc/substituted",
      registry_checkpoint: "00".repeat(32),
      authorization_view_authenticated: false,
      authorization_view_conflicted: true,
      authorization_view_age_seconds: 999_999,
    };
    expect(issueControlToken(callerAuthoredAuthority)).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });

  it("binds Control authorization to the view's exact persona", () => {
    const checkpoint = scenario.issuerKeyEpochOneState.checkpoint;
    const clock = { now: checkpoint.observed_at };
    const view = currentView(clock);
    expect(issueControlToken({
      ...issuanceInput(view),
      entitlement: { ...entitlement, persona: "ff".repeat(32) },
    })).toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
  });

  it("revalidates immediately before token issuance and rejects stale or forged views", () => {
    const checkpoint = scenario.issuerKeyEpochOneState.checkpoint;
    const clock = { now: checkpoint.observed_at };
    const view = currentView(clock);
    clock.now = checkpoint.observed_at + 301;
    expect(issueControlToken(issuanceInput(view))).toEqual({
      verdict: "reject",
      reason_code: "control-authorization-view-stale",
    });
    expect(issueControlToken(issuanceInput({} as CurrentAuthorizationView))).toEqual({
      verdict: "reject",
      reason_code: "control-authorization-view-stale",
    });
  });

  it("revalidates the opaque view before accepting token use", () => {
    const checkpoint = scenario.issuerKeyEpochOneState.checkpoint;
    const clock = { now: checkpoint.observed_at + 10 };
    const view = currentView(clock);
    const issued = issueControlToken(issuanceInput(view));
    if (issued.verdict !== "accept") throw new Error("fixture rejected");
    expect(validateControlTokenUse({
      token: issued.token,
      signature_valid: true,
      expected_issuer: issued.token.iss,
      expected_audience: issued.token.aud,
      expected_node_key: node,
      authenticated_sender_jkt: issued.token.cnf.jkt,
      group_id: group,
      current_entitlement: entitlement,
      authorization_view: view,
      required_scope: "control",
      method: "config.get",
      object,
      usage: { calls: 1 },
      required_agent_role: null,
    }).verdict).toBe("accept");
  });

  it("commits enrollment only after effect-time view revalidation", () => {
    const checkpoint = scenario.issuerKeyEpochOneState.checkpoint;
    const clock = { now: checkpoint.observed_at };
    const view = currentView(clock);
    const input = {
      enrollment_id: "77".repeat(32),
      group_id: group,
      client_key: client,
      authorization_view: view,
    };
    expect(commitControlEnrollment(input)).toMatchObject({
      verdict: "accept",
      enrollment: {
        state: "enrollment-only",
        authority: false,
        committed_at: checkpoint.observed_at,
        registry_checkpoint: checkpoint.commit_oid,
        repository_rid: scenario.rid,
        persona_key: scenario.persona,
      },
    });

    clock.now += 301;
    expect(commitControlEnrollment(input)).toEqual({
      verdict: "reject",
      reason_code: "control-authorization-view-stale",
    });
    expect(commitControlEnrollment({ ...input, authorization_view: {} as CurrentAuthorizationView })).toEqual({
      verdict: "reject",
      reason_code: "control-authorization-view-stale",
    });
  });

  it("does not commit enrollment after manifest or checkpoint substitution", () => {
    const state = scenario.issuerKeyEpochOneState;
    const manifest = support.signedManifest(state);
    const substituted = support.signedManifest(state, { authorization_view_max_age: 301 });
    const clock = { now: state.checkpoint.observed_at };
    let loadedManifest = manifest;
    const view = support.currentView(
      clock,
      state,
      manifest,
      () => ({ manifest: loadedManifest, ledger_state: state }),
    );
    loadedManifest = substituted;
    expect(commitControlEnrollment({
      enrollment_id: "77".repeat(32),
      group_id: group,
      client_key: client,
      authorization_view: view,
    })).toEqual({
      verdict: "reject",
      reason_code: "oidc-issuer-authority-invalid",
    });

    let loadedState = state;
    loadedManifest = manifest;
    const checkpointView = support.currentView(
      clock,
      state,
      manifest,
      () => ({ manifest, ledger_state: loadedState }),
    );
    const records = [...state.records, scenario.grantOne, scenario.grantDivergent];
    const repository = buildLedgerRepositoryEvidence({
      repository_rid: scenario.rid,
      confirmed_records: records,
      observed_at: state.checkpoint.observed_at + 1,
      prior: scenario.issuerKeyEpochOneRepository.repository,
    });
    loadedState = mergeClaimLedger(
      records,
      [],
      repository.checkpoint,
      scenario.makeTask5Context(repository.repository),
    );
    expect(loadedState.conflicted_claim_ids).not.toEqual([]);
    expect(commitControlEnrollment({
      enrollment_id: "77".repeat(32),
      group_id: group,
      client_key: client,
      authorization_view: checkpointView,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-authorization-view-stale",
    });
  });
});
