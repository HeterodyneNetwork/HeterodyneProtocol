import { createHash } from "node:crypto";
import { nip19 } from "nostr-tools";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  createAuthorizationFreshnessAuthority,
  evaluateAuthorizationFreshness,
  type CurrentAuthorizationView,
} from "./authorization-freshness.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import {
  issueControlToken,
  validateControlTokenUse,
  type ControlAuthorizationRecord,
  type ControlToken,
  type TokenIssuanceInput,
  type TokenUseInput,
} from "./control-profile.js";
import { buildFixtures } from "./fixtures.js";
import { utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import {
  continuityManifestDigest,
  createContinuityAuthorityProof,
  type ContinuityManifest,
  type ContinuityManifestBody,
} from "./token-status.js";

const client = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const otherClient = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const node = "22".repeat(32);
const group = "33".repeat(32);
const expectedJkt = "2JF8vg9etJzjFwZwmkvhBLLZ0bfMVVOPivYR5lFtcec";
const otherJkt = "GKeBJdbiPSiSZ8qwiPH8NBmmtrLcKCZ7gYOzX0hwzlM";
const object = { class: "config_namespace" as const, id: "ui" };
const fixtures = buildFixtures();
let freshnessScenario: Awaited<ReturnType<typeof buildClaimLedgerScenario>>;
let freshnessClock: { now: number };
let checkpoint: string;

beforeAll(async () => {
  freshnessScenario = await buildClaimLedgerScenario(fixtures);
});

function currentAuthorizationView(): CurrentAuthorizationView {
  const state = freshnessScenario.issuerKeyEpochOneState;
  const personaKey = freshnessScenario.persona;
  const personaNpub = nip19.npubEncode(personaKey);
  const sha256 = (value: Uint8Array): string => createHash("sha256").update(value).digest("hex");
  const body: ContinuityManifestBody = {
    profile: "heterodyne-oidc-continuity-v1",
    repository_rid: freshnessScenario.rid,
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
      writer_nid: freshnessScenario.writerOne.did_key,
      issued_at: state.checkpoint.observed_at,
      checkpoint: state.checkpoint,
    },
  };
  const manifest: ContinuityManifest = {
    ...body,
    authority_proof: createContinuityAuthorityProof(body, freshnessScenario.writerOne.private_key),
  };
  const authority = createAuthorizationFreshnessAuthority({
    repository_rid: manifest.repository_rid,
    persona_key: manifest.persona_key,
    manifest_digest: continuityManifestDigest(manifest),
  }, {
    trusted_now: () => freshnessClock.now,
    load_current_view: () => ({ manifest, ledger_state: state }),
  });
  const result = evaluateAuthorizationFreshness(authority, manifest);
  if (result.verdict !== "accept") throw new Error(`freshness fixture rejected: ${result.reason}`);
  return result.view;
}

let authorization: ControlAuthorizationRecord;
let issuance: TokenIssuanceInput;

beforeEach(() => {
  const state = freshnessScenario.issuerKeyEpochOneState;
  freshnessClock = { now: state.checkpoint.observed_at };
  checkpoint = state.checkpoint.commit_oid;
  authorization = {
  record_id: "44".repeat(32),
  persona: freshnessScenario.persona,
  client_key: client,
  client_class: "automated" as const,
  approving_node: node,
  approving_authority: "fixture-local-approval",
  methods: ["config.get", "config.put"],
  objects: [object],
  limits: {
    max_content_bytes: 1_024,
    rate_window_seconds: 3_600,
    rate_count: 10,
    burst: 2,
    max_media_bytes: 2_048,
  },
  capabilities: ["control.token.extended"],
  token_lifetime_default_seconds: 300,
  token_lifetime_max_seconds: 3_600,
  inbound_execution: false,
  agent_role: "agent:newsletter",
  predecessor: null,
  state: "active" as const,
  created_at: 900,
  expires_at: null,
  signer: node,
  signature: "66".repeat(64),
  };
  issuance = {
    entitlement: authorization,
    group_id: group,
    audience: "urn:heterodyne:control:node-a",
    node_key: node,
    issuance_nonce: "77".repeat(32),
    requested_lifetime_seconds: 300,
    node_policy_max_seconds: 3_600,
    authorization_view: currentAuthorizationView(),
    methods: ["config.get"],
    objects: [object],
    limits: {
      max_content_bytes: 1_024,
      rate_count: 10,
    },
  };
});

function issue(overrides: Record<string, unknown> = {}) {
  return issueControlToken({
    ...issuance,
    ...overrides,
  } as TokenIssuanceInput);
}

function acceptedToken(overrides: Record<string, unknown> = {}) {
  const result = issue(overrides);
  if (result.verdict !== "accept") throw new Error("fixture token failed");
  return result.token;
}

function useInput(token = acceptedToken()): TokenUseInput {
  return {
    token,
    signature_valid: true,
    expected_issuer: token.iss,
    expected_audience: issuance.audience,
    expected_node_key: node,
    authenticated_sender_jkt: expectedJkt,
    group_id: group,
    current_entitlement: authorization,
    authorization_view: currentAuthorizationView(),
    required_scope: "control",
    method: "config.get",
    object,
    usage: { max_content_bytes: 512, rate_count: 1 },
    required_agent_role: "agent:newsletter",
  };
}

function withRecomputedJti(token: ControlToken): ControlToken {
  const { jti: _jti, ...claims } = token;
  return {
    ...claims,
    jti: createHash("sha256")
      .update(`heterodyne-control-token-jti-v1\0${jcsCanonicalize(claims)}`)
      .digest("hex"),
  };
}

describe("Control token authorization projection", () => {
  it("mints from the frozen compatibility authorization record", () => {
    expect(issue()).toMatchObject({
      verdict: "accept",
      token: {
        authorization_id: authorization.record_id,
        client_id: client,
        sub: client,
        client_class: "automated",
        scope: "control control.token.extended",
        methods: ["config.get"],
        objects: [object],
        registry_checkpoint: checkpoint,
        agent_role: "agent:newsletter",
      },
    });
  });

  it("derives the even-Y secp256k1 JWK thumbprint and rejects a non-point key", () => {
    expect(issue({ client_jkt: otherJkt })).toMatchObject({
      verdict: "accept",
      token: { cnf: { jkt: expectedJkt } },
    });
    expect(issue({
      entitlement: { ...authorization, client_key: "11".repeat(32) },
    })).toEqual({ verdict: "reject", reason_code: "control-token-invalid" });
  });

  it("derives extended lifetime authority at mint and revalidates its removal at use", () => {
    const withoutExtended = {
      ...authorization,
      capabilities: [] as ControlAuthorizationRecord["capabilities"],
    };
    expect(issue({
      entitlement: withoutExtended,
      requested_lifetime_seconds: 301,
      extended_capability: true,
    })).toEqual({ verdict: "reject", reason_code: "control-token-invalid" });

    const token = acceptedToken({ requested_lifetime_seconds: 3_600 });
    expect(validateControlTokenUse({
      ...useInput(token),
      current_entitlement: withoutExtended,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });
});

describe("Control token key and issuance-identifier binding", () => {
  it("rejects a sender JWK cross-bound to a different entitled client key", () => {
    const token = acceptedToken();
    const crossBound = withRecomputedJti({
      ...token,
      cnf: { jkt: otherJkt },
    });
    expect(validateControlTokenUse({
      ...useInput(crossBound),
      authenticated_sender_jkt: otherJkt,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });

  it("rejects a noncanonical base64url thumbprint even when its jti is recomputed", () => {
    const token = acceptedToken();
    const noncanonical = withRecomputedJti({
      ...token,
      cnf: { jkt: `${"A".repeat(42)}B` },
    });
    expect(validateControlTokenUse({
      ...useInput(noncanonical),
      authenticated_sender_jkt: noncanonical.cnf.jkt,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });

  it("gives same-second differing grants distinct identifiers", () => {
    const read = acceptedToken();
    const write = acceptedToken({ methods: ["config.put"] });
    const renewed = acceptedToken({ issuance_nonce: "88".repeat(32) });

    expect(read.iat).toBe(write.iat);
    expect(read.jti).not.toBe(write.jti);
    expect(read.jti).not.toBe(renewed.jti);
  });

  it("recomputes the issuance identifier before token use", () => {
    const token = acceptedToken();
    expect(validateControlTokenUse({
      ...useInput({ ...token, jti: "00".repeat(32) }),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-token-invalid",
    });
  });

  it("uses a second valid BIP-340 fixture for cross-binding coverage", () => {
    expect(otherClient).toMatch(/^[0-9a-f]{64}$/);
    expect(otherJkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});
