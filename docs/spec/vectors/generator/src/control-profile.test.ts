import { beforeAll, describe, expect, it } from "vitest";
import {
  createAuthorizationFreshnessAuthority,
  evaluateAuthorizationFreshness,
  type CurrentAuthorizationView,
} from "./authorization-freshness.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import { buildFixtures } from "./fixtures.js";
import { utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import { nip19 } from "nostr-tools";
import { createHash } from "node:crypto";
import {
  issueControlToken,
  validateControlTokenUse,
  type ControlAuthorizationRecord,
} from "./control-profile.js";
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
  entitlement = {
    ...authorizationRecord,
    persona: scenario.persona,
  };
});

const sha256 = (value: Uint8Array): string =>
  createHash("sha256").update(value).digest("hex");
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
  const state = scenario.issuerKeyEpochOneState;
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
    authorization_view_max_age: 300,
    current_jwks_sha256: sha256(utf8Bytes(jcsCanonicalize({ keys: [OIDC_RSA_ONE.public_jwk] }))),
    current_signing_key_id: OIDC_RSA_ONE.key_id,
    current_signing_jwk_sha256: sha256(utf8Bytes(jcsCanonicalize(OIDC_RSA_ONE.public_jwk))),
    retiring_signing_key_ids: [],
    retiring_jwks_sha256: [],
    status_lists: [],
    successor: null,
    authority: {
      writer_nid: scenario.writerOne.did_key,
      issued_at: state.checkpoint.observed_at,
      checkpoint: state.checkpoint,
    },
  };
  const manifest: ContinuityManifest = {
    ...body,
    authority_proof: createContinuityAuthorityProof(body, scenario.writerOne.private_key),
  };
  const authority = createAuthorizationFreshnessAuthority({
    repository_rid: manifest.repository_rid,
    persona_key: manifest.persona_key,
    manifest_digest: continuityManifestDigest(manifest),
  }, {
    trusted_now: () => clock.now,
    load_current_view: () => ({ manifest, ledger_state: state }),
  });
  const evaluated = evaluateAuthorizationFreshness(authority, manifest);
  if (evaluated.verdict !== "accept") throw new Error(`fixture rejected: ${evaluated.reason}`);
  return evaluated.view;
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
    const issued = issueControlToken({
      ...issuanceInput(view),
      now: 1,
      issuer: "https://attacker.invalid/oidc/substituted",
      registry_checkpoint: "00".repeat(32),
      authorization_view_authenticated: false,
      authorization_view_conflicted: true,
      authorization_view_age_seconds: 999_999,
    } as never);
    expect(issued).toMatchObject({
      verdict: "accept",
      token: {
        iat: clock.now,
        iss: `https://node.example/oidc/${nip19.npubEncode(scenario.persona)}`,
        registry_checkpoint: scenario.issuerKeyEpochOneState.checkpoint.commit_oid,
      },
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
    expect(issueControlToken({
      ...issuanceInput(view),
      now: checkpoint.observed_at,
      authorization_view_authenticated: true,
      authorization_view_conflicted: false,
      authorization_view_age_seconds: 0,
    } as never)).toEqual({
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
});
