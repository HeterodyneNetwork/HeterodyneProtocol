import { buildAuthorizationFreshnessTestSupport } from "../authorization-freshness-test-support.js";
import {
  evaluateAuthorizationFreshness,
  revalidateAuthorizationViewAtEffect,
  type AuthorizationFreshnessAuthority,
} from "../authorization-freshness.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const normalizeReason = <T extends Record<string, unknown>>(value: T): Record<string, unknown> =>
  "reason" in value ? (() => {
    const { reason, ...decision } = value;
    return { ...decision, reason_code: reason };
  })() : value;

export async function buildControlCases(): Promise<CurrentVectorCase[]> {
  const support = await buildAuthorizationFreshnessTestSupport();
  const state = support.scenario.issuerKeyEpochOneState;
  const manifest = support.signedManifest(state);
  const clock = { now: state.checkpoint.observed_at + 300 };
  const authority = support.authorityFor(manifest, state, clock);
  const prepared = evaluateAuthorizationFreshness(authority, manifest);
  if (prepared.verdict !== "accept") {
    throw new Error(`current authorization fixture rejected: ${prepared.reason}`);
  }
  const acceptedAtEffect = revalidateAuthorizationViewAtEffect(prepared.view);
  const callerDecision = evaluateAuthorizationFreshness(
    {
      now: clock.now,
      checkpoint_fresh: true,
      authorization_view_authenticated: true,
    } as unknown as AuthorizationFreshnessAuthority,
    manifest,
  );
  clock.now += 1;
  const staleAtEffect = revalidateAuthorizationViewAtEffect(prepared.view);

  return [
    {
      relativePath: "control/opaque-authorization-view-accepted.json",
      vector_id: "control/opaque-authorization-view-accepted",
      owner_document: "control",
      spec_refs: [currentSpecRef("control-token")],
      invariants: ["CONTROL-I-NIP46-OIDC-ACTIVATION"],
      reason_codes: [],
      description: "An opaque view issued by the trusted freshness authority is accepted at mutation effect.",
      direction: "consume",
      input: {
        manifest,
        ledger_state: state,
        trusted_now: state.checkpoint.observed_at + 300,
        current_authorization_view: "opaque",
      },
      expected_output: acceptedAtEffect,
    },
    {
      relativePath: "control/caller-freshness-booleans-rejected.json",
      vector_id: "control/caller-freshness-booleans-rejected",
      owner_document: "control",
      spec_refs: [currentSpecRef("control-token")],
      invariants: ["CONTROL-I-NIP46-OIDC-ACTIVATION"],
      reason_codes: ["control-authorization-view-stale"],
      description: "Caller-authored freshness booleans cannot substitute for an opaque authorization view.",
      direction: "consume",
      input: {
        manifest,
        now: state.checkpoint.observed_at + 300,
        checkpoint_fresh: true,
        authorization_view_authenticated: true,
      },
      expected_output: normalizeReason(callerDecision),
    },
    {
      relativePath: "control/authorization-view-stale-at-effect.json",
      vector_id: "control/authorization-view-stale-at-effect",
      owner_document: "control",
      spec_refs: [currentSpecRef("control-token")],
      invariants: ["CONTROL-I-NIP46-OIDC-ACTIVATION"],
      reason_codes: ["control-authorization-view-stale"],
      description: "A view prepared at its boundary is rejected when it becomes stale before mutation effect.",
      direction: "consume",
      input: {
        manifest,
        prepared_at: state.checkpoint.observed_at + 300,
        effected_at: state.checkpoint.observed_at + 301,
        current_authorization_view: "opaque",
      },
      expected_output: normalizeReason(staleAtEffect),
    },
  ];
}
