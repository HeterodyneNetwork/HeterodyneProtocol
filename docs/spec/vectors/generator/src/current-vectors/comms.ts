import { buildAuthorizationFreshnessTestSupport } from "../authorization-freshness-test-support.js";
import { evaluateAuthorizationFreshness } from "../authorization-freshness.js";
import { resolveTier3Recipients } from "../follow-up-hardening.js";
import { validateOidcContinuityManifestSchemaOrThrow } from "../schema.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const decisionOutput = (
  decision: ReturnType<typeof evaluateAuthorizationFreshness>,
): Record<string, unknown> => decision.verdict === "accept"
  ? { verdict: "accept", current_authorization_view: "opaque" }
  : { verdict: "reject", reason_code: decision.reason };

export async function buildCommsCases(): Promise<CurrentVectorCase[]> {
  const support = await buildAuthorizationFreshnessTestSupport();
  const state = support.scenario.issuerKeyEpochOneState;
  const observedAt = state.checkpoint.observed_at;

  const checkpointBoundary = support.signedManifest(state, {
    checkpoint_age: 300,
    authorization_view_max_age: 300,
  });
  const checkpointBoundaryDecision = evaluateAuthorizationFreshness(
    support.authorityFor(checkpointBoundary, state, { now: observedAt + 300 }),
    checkpointBoundary,
  );
  const checkpointStale = support.signedManifest(state, {
    checkpoint_age: 301,
    authorization_view_max_age: 300,
  });
  const checkpointStaleDecision = evaluateAuthorizationFreshness(
    support.authorityFor(checkpointStale, state, { now: observedAt + 301 }),
    checkpointStale,
  );
  const view300 = support.signedManifest(state, { authorization_view_max_age: 300 });
  const view300Decision = evaluateAuthorizationFreshness(
    support.authorityFor(view300, state, { now: observedAt + 300 }),
    view300,
  );
  const view86400 = support.signedManifest(state, { authorization_view_max_age: 86_400 });
  const view86400Decision = evaluateAuthorizationFreshness(
    support.authorityFor(view86400, state, { now: observedAt + 86_400 }),
    view86400,
  );
  const malformed = support.signedManifest(state, { authorization_view_max_age: 86_401 });
  let malformedRejected = false;
  try {
    validateOidcContinuityManifestSchemaOrThrow(malformed);
  } catch {
    malformedRejected = true;
  }
  const persona = "11".repeat(32);
  const activeDevice = "22".repeat(32);
  const inactiveDevice = "33".repeat(32);
  const tier3Input = {
    memberPersonas: [persona],
    devices: [
      { persona, pubkey: activeDevice, active: true, role: "human-device" as const },
      { persona, pubkey: inactiveDevice, active: false, role: "human-device" as const },
    ],
    selected: [inactiveDevice],
  };
  const tier3Decision = resolveTier3Recipients(tier3Input);

  return [
    {
      relativePath: "comms/checkpoint-exact-boundary.json",
      vector_id: "comms/checkpoint-exact-boundary",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: [],
      description: "A signed ledger checkpoint exactly 300 seconds old remains eligible independently of authorization-view age.",
      direction: "consume",
      input: { trusted_now: observedAt + 300, manifest: checkpointBoundary, ledger_state: state },
      expected_output: decisionOutput(checkpointBoundaryDecision),
    },
    {
      relativePath: "comms/checkpoint-stale-independent.json",
      vector_id: "comms/checkpoint-stale-independent",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: ["oidc-checkpoint-stale"],
      description: "Checkpoint age above 300 seconds rejects even while the authorization view itself is fresh.",
      direction: "consume",
      input: { trusted_now: observedAt + 301, manifest: checkpointStale, ledger_state: state },
      expected_output: decisionOutput(checkpointStaleDecision),
    },
    {
      relativePath: "comms/authorization-view-300-boundary.json",
      vector_id: "comms/authorization-view-300-boundary",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: [],
      description: "A 300-second authorization view is accepted at its exact declared boundary.",
      direction: "consume",
      input: { trusted_now: observedAt + 300, manifest: view300, ledger_state: state },
      expected_output: decisionOutput(view300Decision),
    },
    {
      relativePath: "comms/authorization-view-86400-boundary.json",
      vector_id: "comms/authorization-view-86400-boundary",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: [],
      description: "The maximum 86400-second authorization-view bound is accepted exactly at its boundary.",
      direction: "consume",
      input: { trusted_now: observedAt + 86_400, manifest: view86400, ledger_state: state },
      expected_output: decisionOutput(view86400Decision),
    },
    {
      relativePath: "comms/authorization-view-maximum-malformed.json",
      vector_id: "comms/authorization-view-maximum-malformed",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-authorization-freshness")],
      invariants: ["COMMS-I-MINT-FRESHNESS"],
      reason_codes: ["claim-schema-invalid"],
      description: "An authorization-view maximum above 86400 seconds fails the registered manifest schema.",
      direction: "consume",
      input: { manifest: malformed },
      expected_output: malformedRejected
        ? { verdict: "reject", reason_code: "claim-schema-invalid" }
        : { verdict: "accept" },
    },
    {
      relativePath: "comms/tier3-recipient-confined.json",
      vector_id: "comms/tier3-recipient-confined",
      owner_document: "comms",
      spec_refs: [currentSpecRef("comms-tier3-confinement")],
      invariants: ["COMMS-I-TIER3-CONFINED"],
      reason_codes: ["tier3-recipient-not-active-device"],
      description: "Tier-3 delivery rejects a selected inactive device even when its persona remains a member.",
      direction: "produce",
      input: tier3Input,
      expected_output: tier3Decision,
    },
  ];
}
