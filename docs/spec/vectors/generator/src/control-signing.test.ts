import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import { matchesAgentAttributionProfile } from "./agent-authorship.js";
import {
  authorizeNip46Signing,
  consumeNip46ConnectionSecret,
  prepareAutomatedSigning,
  type AutomatedPublication,
  type CompromiseResetCompletion,
  type CompromiseResetGrant,
  type SigningGrant,
  validateCompromiseReset,
} from "./control-signing.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { getEventId, getPublicKey, type NostrUnsignedEvent } from "./nostr.js";
import { proofBytes } from "./proof-bytes.js";

const hex = (byte: string) => byte.repeat(64);
const personaSecret = "01".repeat(32);
const otherPersonaSecret = "02".repeat(32);
const assuranceSecret = "03".repeat(32);
const agentSignerSecret = "04".repeat(32);
const persona = getPublicKey(personaSecret);
const otherPersona = getPublicKey(otherPersonaSecret);
const assuranceAuthority = getPublicKey(assuranceSecret);
const client = hex("3");
const agentSigner = getPublicKey(agentSignerSecret);
const otherSigner = hex("5");
const vaultId = hex("6");
const audience = "https://node.example/nip46/persona-1";
const connectionSecret = "09".repeat(32);
const connectionSecretSha256 = createHash("sha256")
  .update(hexToBytes(connectionSecret))
  .digest("hex");

function signGrant(
  value: Omit<SigningGrant, "signature">,
  secret = personaSecret,
): SigningGrant {
  return {
    ...value,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-control-signer-grant-v1", value),
      hexToBytes(secret),
      "00".repeat(32),
    )),
  };
}

function resignGrant(value: SigningGrant, secret = personaSecret): SigningGrant {
  const { signature: _signature, ...unsigned } = value;
  return signGrant(unsigned, secret);
}

const grant = signGrant({
  profile: "heterodyne.control.signer-grant.v1",
  spec_version: "heterodyne/0.5.0",
  grant_id: hex("7"),
  vault_id: vaultId,
  persona_active_key: persona,
  nip46_client_pubkey: client,
  signer_audience: audience,
  selected_signing_pubkey: agentSigner,
  key_class: "agent",
  persona_signing_authorized: false,
  allowed_methods: ["sign_event"],
  allowed_event_kinds: [1, 30023],
  limits: {
    request_window_seconds: 60,
    request_count: 20,
    max_event_bytes: 4096,
    max_value_msats: 0,
  },
  oidc_authorization_id: hex("8"),
  connection_secret_sha256: connectionSecretSha256,
  issued_at: 100,
  expires_at: 200,
  predecessor: null,
  state: "active",
  revoked_at: null,
  authorizing_pubkey: persona,
});

const automationPolicy = {
  workload_id: hex("a"),
  agent_class: "ai" as const,
  agent_association: { kind: "key" as const, value: agentSigner },
  tier: 1 as const,
  oidc_scopes: [] as string[],
};
const automationGrant = resignGrant({
  ...grant,
  automation_policy: automationPolicy,
});

const vaults = [
  {
    vault_id: hex("b"),
    persona_active_key: otherPersona,
    signers: [{
      public_key: otherSigner,
      key_class: "persona" as const,
      custody: "local" as const,
    }],
  },
  {
    vault_id: vaultId,
    persona_active_key: persona,
    signers: [{
      public_key: agentSigner,
      key_class: "agent" as const,
      custody: "local" as const,
    }],
  },
];

const request = {
  request_id: hex("d"),
  request_digest: hex("e"),
  grant_id: grant.grant_id,
  vault_id: vaultId,
  persona_active_key: persona,
  nip46_client_pubkey: client,
  signer_audience: audience,
  selected_signing_pubkey: agentSigner,
  key_class: "agent" as const,
  method: "sign_event",
  event_kind: 1,
  event_bytes: 512,
  value_msats: 0,
  now: 110,
};

const usageState = {
  grant_id: grant.grant_id,
  window_started_at: 100,
  consumed_request_count: 0,
  revision: 4,
  reservations: [],
};

const metadata = {
  requested_methods: ["sign_event"],
  requested_event_kinds: [1],
  requested_signer_audiences: [audience],
};

function automatedIntent(
  overrides: Partial<AutomatedPublication> = {},
): AutomatedPublication {
  return {
    profile: "heterodyne.control.agent-publish-intent.v1",
    spec_version: "heterodyne/0.5.0",
    grant_id: automationGrant.grant_id,
    vault_id: automationGrant.vault_id,
    persona_active_key: automationGrant.persona_active_key,
    nip46_client_pubkey: automationGrant.nip46_client_pubkey,
    signer_audience: automationGrant.signer_audience,
    selected_signing_pubkey: automationGrant.selected_signing_pubkey,
    key_class: automationGrant.key_class,
    created_at: 111,
    kind: 1,
    tags: [["t", "heterodyne"]],
    content: "bounded publication intent",
    value_msats: 0,
    agent_class: automationPolicy.agent_class,
    agent_association: automationPolicy.agent_association,
    tier: automationPolicy.tier,
    ...overrides,
  };
}

function intentDigest(publication: AutomatedPublication): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-agent-publish-intent-v1", publication))
    .digest("hex");
}

function persistedUsage(requestDigest: string) {
  return {
    ...usageState,
    consumed_request_count: 1,
    revision: usageState.revision + 1,
    reservations: [{
      request_id: request.request_id,
      request_digest: requestDigest,
      state: "reserved" as const,
      result_event_id: null,
    }],
  };
}

function signNostrEvent(event: NostrUnsignedEvent, secret = agentSignerSecret) {
  const id = getEventId(event);
  return {
    ...event,
    id,
    sig: bytesToHex(schnorr.sign(id, hexToBytes(secret), "00".repeat(32))),
  };
}

function authorize(overrides: Record<string, unknown> = {}) {
  return authorizeNip46Signing({
    grant_candidates: [grant],
    usage_state: usageState,
    presented_grant: structuredClone(grant),
    vaults,
    request,
    client_metadata: metadata,
    ...overrides,
  });
}

describe("Control NIP-46 signer grant authorization", () => {
  it("accepts the exact server-side grant in the exact persona vault", () => {
    expect(authorize()).toEqual({
      verdict: "accept",
      vault_id: vaultId,
      persona_active_key: persona,
      selected_signing_pubkey: agentSigner,
      key_class: "agent",
      custody: "local",
      authorization_mode: "reserved",
      usage_transition: {
        grant_id: grant.grant_id,
        request_id: request.request_id,
        request_digest: request.request_digest,
        expected_revision: 4,
        next_revision: 5,
        prior_window_started_at: 100,
        window_started_at: 100,
        prior_consumed_request_count: 0,
        consumed_request_count: 1,
        reservation_state: "reserved",
      },
    });
  });

  it("uses authoritative window consumption instead of a caller-selected count", () => {
    expect(authorize({
      usage_state: {
        ...usageState,
        consumed_request_count: grant.limits.request_count,
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signing-rate-limited",
    });
  });

  it("distinguishes a committed idempotent replay from a new reservation", () => {
    expect(authorize({
      usage_state: {
        ...usageState,
        consumed_request_count: 1,
        reservations: [{
          request_id: request.request_id,
          request_digest: request.request_digest,
          state: "committed",
          result_event_id: hex("f"),
        }],
      },
    })).toEqual({
      verdict: "replay",
      event_id: hex("f"),
    });
  });

  it("rejects forged grants and a stale predecessor instead of trusting caller-selected state", () => {
    const forged = { ...grant, signature: "00".repeat(64) };
    expect(authorize({
      grant_candidates: [forged],
      presented_grant: structuredClone(forged),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-unauthenticated",
    });

    const { signature: _signature, ...grantUnsigned } = grant;
    const successor = signGrant({
      ...grantUnsigned,
      grant_id: hex("c"),
      predecessor: grant.grant_id,
      issued_at: 105,
    });
    expect(authorize({
      grant_candidates: [grant, successor],
      presented_grant: structuredClone(grant),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-stale",
    });
  });

  it("rejects a self-signed attacker head grafted onto another persona grant", () => {
    const { signature: _signature, ...unsigned } = grant;
    const attackerHead = signGrant({
      ...unsigned,
      grant_id: hex("c"),
      persona_active_key: otherPersona,
      authorizing_pubkey: otherPersona,
      predecessor: grant.grant_id,
      issued_at: 105,
    }, otherPersonaSecret);
    expect(authorize({
      grant_candidates: [grant, attackerHead],
      presented_grant: structuredClone(attackerHead),
      usage_state: { ...usageState, grant_id: attackerHead.grant_id },
      vaults: [{
        vault_id: vaultId,
        persona_active_key: otherPersona,
        signers: [{
          public_key: agentSigner,
          key_class: "agent",
          custody: "local",
        }],
      }],
      request: {
        ...request,
        grant_id: attackerHead.grant_id,
        persona_active_key: otherPersona,
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-unauthenticated",
    });
  });

  it("rejects a change to every authority-bearing grant binding", () => {
    const mutations: Array<[string, (value: typeof grant) => void]> = [
      ["persona active key", (value) => { value.persona_active_key = otherPersona; }],
      ["NIP-46 client key", (value) => { value.nip46_client_pubkey = otherSigner; }],
      ["signer audience", (value) => { value.signer_audience = `${audience}/wider`; }],
      ["selected signer", (value) => { value.selected_signing_pubkey = otherSigner; }],
      ["key class", (value) => { value.key_class = "persona"; }],
      ["methods", (value) => { value.allowed_methods = ["sign_event", "nip44_decrypt"]; }],
      ["event kinds", (value) => { value.allowed_event_kinds = [1, 7, 30023]; }],
      ["limits", (value) => { value.limits.request_count += 1; }],
      ["issuance", (value) => { value.issued_at -= 1; }],
      ["expiry", (value) => { value.expires_at += 1; }],
      ["revocation state", (value) => { value.state = "revoked"; value.revoked_at = 105; }],
    ];

    for (const [name, mutate] of mutations) {
      const presented = structuredClone(grant);
      mutate(presented);
      expect(authorize({ presented_grant: presented }), name).toEqual({
        verdict: "reject",
        reason_code: "control-signer-binding-mismatch",
      });
    }
  });

  it("never falls through to another persona, key class, or local signer", () => {
    expect(authorize({
      request: { ...request, vault_id: vaults[0].vault_id },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-vault-isolation-failed",
    });

    expect(authorize({
      vaults: [{
        vault_id: vaultId,
        persona_active_key: persona,
        signers: [{
          public_key: otherSigner,
          key_class: "persona",
          custody: "local",
        }],
      }],
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signer-unavailable",
    });

    const mislabeledPersona = resignGrant({
      ...grant,
      selected_signing_pubkey: persona,
    });
    expect(authorizeNip46Signing({
      grant_candidates: [mislabeledPersona],
      usage_state: usageState,
      presented_grant: structuredClone(mislabeledPersona),
      vaults: [{
        vault_id: vaultId,
        persona_active_key: persona,
        signers: [{
          public_key: persona,
          key_class: "agent",
          custody: "local",
        }],
      }],
      request: { ...request, selected_signing_pubkey: persona },
      client_metadata: metadata,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signer-binding-mismatch",
    });
  });

  it("rejects client metadata that requests authority beyond the stored grant", () => {
    expect(authorize({
      client_metadata: {
        ...metadata,
        requested_methods: ["sign_event", "nip44_decrypt"],
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-client-metadata-widening",
    });
    expect(authorize({ request: { ...request, now: Number.NaN } })).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-invalid",
    });
    expect(authorize({
      client_metadata: {
        ...metadata,
        requested_event_kinds: [1, 7],
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-client-metadata-widening",
    });
  });

  it("requires explicit authority when the persona key signs", () => {
    const personaGrant = resignGrant({
      ...grant,
      selected_signing_pubkey: persona,
      key_class: "persona" as const,
      persona_signing_authorized: true,
    });
    const personaRequest = {
      ...request,
      selected_signing_pubkey: persona,
      key_class: "persona" as const,
    };
    const personaVaults = [{
      vault_id: vaultId,
      persona_active_key: persona,
      signers: [{
        public_key: persona,
        key_class: "persona" as const,
        custody: "nip46" as const,
      }],
    }];
    expect(authorizeNip46Signing({
      grant_candidates: [personaGrant],
      usage_state: usageState,
      presented_grant: structuredClone(personaGrant),
      vaults: personaVaults,
      request: personaRequest,
      client_metadata: metadata,
    })).toMatchObject({ verdict: "accept", key_class: "persona" });
    const unauthorizedPersonaGrant = resignGrant({
      ...personaGrant,
      persona_signing_authorized: false,
    });
    expect(authorizeNip46Signing({
      grant_candidates: [unauthorizedPersonaGrant],
      usage_state: usageState,
      presented_grant: structuredClone(unauthorizedPersonaGrant),
      vaults: personaVaults,
      request: personaRequest,
      client_metadata: metadata,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-invalid",
    });
  });
});

describe("OIDC activation and automated publication", () => {
  const pending = {
    profile: "heterodyne.control.device-authorization-state.v1" as const,
    spec_version: "heterodyne/0.5.0" as const,
    transaction_id: hex("c"),
    grant_id: grant.grant_id,
    oidc_authorization_id: grant.oidc_authorization_id,
    persona_active_key: persona,
    nip46_client_pubkey: client,
    signer_audience: audience,
    selected_signing_pubkey: agentSigner,
    key_class: "agent" as const,
    requested_methods: grant.allowed_methods,
    requested_event_kinds: grant.allowed_event_kinds,
    requested_limits: grant.limits,
    connection_secret_sha256: grant.connection_secret_sha256,
    connection_secret_state: "pending" as const,
    device_code_sha256: hex("1"),
    device_code_entropy_bits: 128,
    user_code_sha256: hex("2"),
    user_code_entropy_bits: 34.5,
    normalization: "uppercase-ascii-remove-hyphen" as const,
    client_fingerprint: "NIP-46 client 33333333",
    failed_guesses: 0,
    max_failed_guesses: 5 as const,
    interval_seconds: 5,
    issued_at: 100,
    expires_at: 150,
    state: "approved" as const,
    revision: 9,
  };
  const activation = {
    transaction_id: pending.transaction_id,
    grant_id: grant.grant_id,
    oidc_authorization_id: grant.oidc_authorization_id,
    persona_active_key: persona,
    nip46_client_pubkey: client,
    signer_audience: audience,
    selected_signing_pubkey: agentSigner,
    key_class: "agent" as const,
    presented_connection_secret: connectionSecret,
  };

  it("atomically consumes a complete approved OIDC/NIP-46 binding exactly once", () => {
    const first = consumeNip46ConnectionSecret({
      current_state: pending,
      grant_candidates: [grant],
      activation,
      now: 110,
    });
    expect(first).toEqual({
      verdict: "accept",
      state: {
        ...pending,
        connection_secret_state: "consumed",
        state: "consumed",
        revision: 10,
      },
      activation_transition: {
        transaction_id: pending.transaction_id,
        grant_id: grant.grant_id,
        oidc_authorization_id: grant.oidc_authorization_id,
        expected_revision: 9,
        next_revision: 10,
        prior_connection_secret_state: "pending",
        connection_secret_state: "consumed",
        prior_state: "approved",
        state: "consumed",
      },
    });
    if (first.verdict !== "accept") throw new Error("fixture activation failed");
    expect(consumeNip46ConnectionSecret({
      current_state: first.state,
      grant_candidates: [grant],
      activation,
      now: 110,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-connection-secret-reused",
    });
  });

  it("rejects altered activation bindings and activation after either lifetime", () => {
    expect(consumeNip46ConnectionSecret({
      current_state: pending,
      grant_candidates: [grant],
      activation: { ...activation, nip46_client_pubkey: otherSigner },
      now: 110,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-activation-binding-mismatch",
    });
    expect(consumeNip46ConnectionSecret({
      current_state: pending,
      grant_candidates: [grant],
      activation,
      now: pending.expires_at,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-connection-secret-invalid",
    });
  });

  it("injects valid Comms attribution before the signer sees an automated event", () => {
    let signerSawAttribution = false;
    const publication = automatedIntent();
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: persistedUsage(intentDigest(publication)),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: { ...request, request_digest: intentDigest(publication) },
        client_metadata: metadata,
      },
      publication,
      sign: (event: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }) => {
        signerSawAttribution = matchesAgentAttributionProfile(event.tags);
        return signNostrEvent(event);
      },
    });
    expect(signerSawAttribution).toBe(true);
    expect(result).toMatchObject({
      verdict: "accept",
      reservation_revision: 5,
      commit_transition: {
        grant_id: automationGrant.grant_id,
        request_id: request.request_id,
        request_digest: intentDigest(publication),
        expected_revision: 5,
        next_revision: 6,
        prior_reservation_state: "reserved",
        reservation_state: "committed",
      },
      event: {
        pubkey: agentSigner,
      },
    });
  });

  it("rejects a request digest copied from a different automated intent", () => {
    const original = automatedIntent();
    const altered = automatedIntent({ content: "different caller-selected content" });
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: persistedUsage(intentDigest(original)),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: { ...request, request_digest: intentDigest(original) },
        client_metadata: metadata,
      },
      publication: altered,
      sign: signNostrEvent,
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-operation-conflict",
    });
  });

  it("does not invoke the signer before the authoritative reservation is persisted", () => {
    let signerCalled = false;
    const publication = automatedIntent();
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: usageState,
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: { ...request, request_digest: intentDigest(publication) },
        client_metadata: metadata,
      },
      publication,
      sign: (event) => {
        signerCalled = true;
        return signNostrEvent(event);
      },
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-operation-reservation-required",
    });
    expect(signerCalled).toBe(false);
  });

  it("derives attribution policy from the authenticated grant and treats intent fields as hints", () => {
    const policyGrant = resignGrant({
      ...grant,
      automation_policy: {
        workload_id: hex("a"),
        agent_class: "ai",
        agent_association: { kind: "key", value: agentSigner },
        tier: 1,
        oidc_scopes: [],
      },
    } as SigningGrant & { automation_policy: Record<string, unknown> });
    const policyIntent = {
      profile: "heterodyne.control.agent-publish-intent.v1" as const,
      spec_version: "heterodyne/0.5.0" as const,
      grant_id: policyGrant.grant_id,
      vault_id: policyGrant.vault_id,
      persona_active_key: policyGrant.persona_active_key,
      nip46_client_pubkey: policyGrant.nip46_client_pubkey,
      signer_audience: policyGrant.signer_audience,
      selected_signing_pubkey: policyGrant.selected_signing_pubkey,
      key_class: policyGrant.key_class,
      created_at: 111,
      kind: 1,
      tags: [],
      content: "caller cannot select its attribution",
      value_msats: 0,
      agent_class: "programmatic" as const,
      agent_association: null,
      tier: 2 as const,
    };
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [policyGrant],
        usage_state: usageState,
        presented_grant: structuredClone(policyGrant),
        vaults,
        request: { ...request, request_digest: intentDigest(policyIntent) },
        client_metadata: metadata,
      },
      publication: policyIntent,
      sign: (event) => ({ ...event, id: hex("d"), sig: "e".repeat(128) }),
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-attribution-binding-mismatch",
    });
  });

  it("requires authenticated persona automation scope and exact closed intent bindings", () => {
    const personaPolicyGrant = resignGrant({
      ...grant,
      selected_signing_pubkey: persona,
      key_class: "persona",
      persona_signing_authorized: true,
      automation_policy: {
        workload_id: hex("a"),
        agent_class: "ai",
        agent_association: null,
        tier: 1,
        oidc_scopes: [],
      },
    } as SigningGrant & { automation_policy: Record<string, unknown> });
    const publication: AutomatedPublication = {
      profile: "heterodyne.control.agent-publish-intent.v1",
      spec_version: "heterodyne/0.5.0",
      grant_id: otherSigner,
      vault_id: vaultId,
      persona_active_key: persona,
      nip46_client_pubkey: client,
      signer_audience: audience,
      selected_signing_pubkey: persona,
      key_class: "persona",
      created_at: 111,
      kind: 1,
      tags: [],
      content: "missing authenticated scope",
      value_msats: 0,
      agent_class: "ai",
      agent_association: null,
      tier: 1,
    };
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [personaPolicyGrant],
        usage_state: usageState,
        presented_grant: structuredClone(personaPolicyGrant),
        vaults: [{
          vault_id: vaultId,
          persona_active_key: persona,
          signers: [{ public_key: persona, key_class: "persona", custody: "local" }],
        }],
        request: {
          ...request,
          selected_signing_pubkey: persona,
          key_class: "persona",
          request_digest: intentDigest(publication),
        },
        client_metadata: metadata,
      },
      publication,
      sign: (event) => ({ ...event, id: hex("d"), sig: "e".repeat(128) }),
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-persona-authority-required",
    });
  });

  it("rejects an unsupported attribution kind at the closed intent boundary", () => {
    let signerCalled = false;
    const unsupportedGrant = resignGrant({
      ...automationGrant,
      allowed_event_kinds: [2],
    });
    const publication = automatedIntent({
      kind: 2,
      tags: [],
      content: "unsupported attribution kind",
    });
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [unsupportedGrant],
        usage_state: usageState,
        presented_grant: structuredClone(unsupportedGrant),
        vaults,
        request: {
          ...request,
          event_kind: 2,
          request_digest: intentDigest(publication),
        },
        client_metadata: { ...metadata, requested_event_kinds: [2] },
      },
      publication,
      sign: (event: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }) => {
        signerCalled = true;
        return { ...event, id: hex("f"), sig: "0".repeat(128) };
      },
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-agent-intent-invalid",
    });
    expect(signerCalled).toBe(false);
  });

  it("rejects a shape-valid returned event ID and signature that do not verify", () => {
    const publication = automatedIntent();
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: persistedUsage(intentDigest(publication)),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: { ...request, request_digest: intentDigest(publication) },
        client_metadata: metadata,
      },
      publication,
      sign: (event) => ({ ...event, id: hex("d"), sig: "e".repeat(128) }),
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-signed-event-invalid",
    });
  });

  it("rejects extra non-NIP-01 fields on an otherwise valid signed event", () => {
    const publication = automatedIntent();
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: persistedUsage(intentDigest(publication)),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: { ...request, request_digest: intentDigest(publication) },
        client_metadata: metadata,
      },
      publication,
      sign: (event) => ({
        ...signNostrEvent(event),
        grant_id: automationGrant.grant_id,
      }),
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-signed-event-invalid",
    });
  });

  it("enforces the byte limit against the attributed event rather than caller metadata", () => {
    let signerCalled = false;
    const tinyGrant = resignGrant({
      ...automationGrant,
      limits: { ...grant.limits, max_event_bytes: 8 },
    });
    const publication = automatedIntent({
      tags: [],
      content: "larger than the grant after attribution",
    });
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [tinyGrant],
        usage_state: usageState,
        presented_grant: structuredClone(tinyGrant),
        vaults,
        request: {
          ...request,
          event_bytes: 1,
          request_digest: intentDigest(publication),
        },
        client_metadata: metadata,
      },
      publication,
      sign: (event: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }) => {
        signerCalled = true;
        return { ...event, id: hex("f"), sig: "0".repeat(128) };
      },
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-invalid",
    });
    expect(signerCalled).toBe(false);
  });
});

describe("Control compromise reset", () => {
  const signRecoveryGrant = (
    value: Omit<CompromiseResetGrant, "signature">,
    secret = personaSecret,
  ): CompromiseResetGrant => ({
    ...value,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-control-compromise-reset-grant-v1", value),
      hexToBytes(secret),
      "00".repeat(32),
    )),
  });
  const signRecoveryCompletion = (
    value: Omit<CompromiseResetCompletion, "signature">,
    secret = otherPersonaSecret,
  ): CompromiseResetCompletion => ({
    ...value,
    signature: bytesToHex(schnorr.sign(
      proofBytes("heterodyne-control-compromise-reset-completion-v1", value),
      hexToBytes(secret),
      "00".repeat(32),
    )),
  });
  const rid = (value: number) => value.toString(16).padStart(64, "0");
  const requiredReset = {
    nip46_oidc_grant_ids: [grant.grant_id],
    client_ids: [client],
    delegate_ids: [rid(2)],
    node_ids: [rid(3)],
    agent_ids: [agentSigner],
    trusted_seed_nids: ["did:key:z6MkwQp8f8Y11L3WJYJ4hXa1"],
    marmot_leaf_ids: [rid(4)],
    reachable_groups: [{ group_id: rid(5), epoch: 7 }],
    unreachable_group_ids: [rid(6)],
    subordinate_authority_ids: [rid(2), rid(3), agentSigner],
  };
  const authoritativeInventory = {
    inventory_id: rid(100),
    revision: 12,
    observed_at: 120,
    persona_active_key: persona,
    ...structuredClone(requiredReset),
    existing_transition_ids: [rid(7)],
    existing_keypackage_event_ids: [rid(8)],
  };
  const inventoryDigest = createHash("sha256")
    .update(proofBytes(
      "heterodyne-control-compromise-reset-inventory-v1",
      authoritativeInventory,
    ))
    .digest("hex");
  const recoveryGrant = signRecoveryGrant({
    profile: "heterodyne.control.compromise-reset-grant.v1",
    spec_version: "heterodyne/0.5.0",
    recovery_id: hex("1"),
    persona_active_key: persona,
    successor_active_key: otherPersona,
    authorization_class: "active-account",
    authorizing_pubkey: persona,
    assurance_head: null,
    inventory_id: authoritativeInventory.inventory_id,
    inventory_revision: authoritativeInventory.revision,
    inventory_digest: inventoryDigest,
    compromise_at: 120,
    required_reset: requiredReset,
    issued_at: 121,
    expires_at: 180,
    state: "active",
    revoked_at: null,
  });
  const transitionEvidence = {
    nip46_oidc_grants: [{ subject_id: grant.grant_id, evidence_id: rid(20) }],
    clients: [{ subject_id: client, evidence_id: rid(21) }],
    delegates: [{ subject_id: rid(2), evidence_id: rid(22) }],
    nodes: [{ subject_id: rid(3), evidence_id: rid(23) }],
    agents: [{ subject_id: agentSigner, evidence_id: rid(24) }],
    trusted_seeds: [{
      subject_nid: requiredReset.trusted_seed_nids[0],
      evidence_id: rid(25),
    }],
    marmot_leaves: [{ subject_id: rid(4), evidence_id: rid(26) }],
    groups: [{
      group_id: rid(5),
      prior_epoch: 7,
      next_epoch: 8,
      evidence_id: rid(27),
    }],
    stalled_groups: [{ subject_id: rid(6), evidence_id: rid(28) }],
  };
  const subordinateContract = (
    prior_authority_id: string,
    authorization_id: string,
    authority_class: "delegate" | "node" | "agent",
    permissions_digest: string,
  ) => {
    const unsigned = {
      prior_authority_id,
      authorization_id,
      authority_class,
      successor_active_key: otherPersona,
      issued_at: 122,
      expires_at: 170,
      permissions_digest,
    };
    return {
      ...unsigned,
      contract_digest: createHash("sha256")
        .update(proofBytes("heterodyne-control-subordinate-authorization-v1", unsigned))
        .digest("hex"),
    };
  };
  const subordinateReauthorizations = [
    subordinateContract(rid(2), rid(40), "delegate", rid(50)),
    subordinateContract(rid(3), rid(41), "node", rid(51)),
    subordinateContract(agentSigner, rid(42), "agent", rid(52)),
  ];
  const completion = signRecoveryCompletion({
    profile: "heterodyne.control.compromise-reset-completion.v1",
    spec_version: "heterodyne/0.5.0",
    recovery_id: recoveryGrant.recovery_id,
    persona_active_key: persona,
    successor_active_key: otherPersona,
    inventory_id: authoritativeInventory.inventory_id,
    inventory_revision: authoritativeInventory.revision,
    inventory_digest: inventoryDigest,
    evidence_revision: 13,
    revoked_nip46_oidc_grant_ids: [grant.grant_id],
    invalidated_client_ids: [client],
    invalidated_delegate_ids: [rid(2)],
    invalidated_node_ids: [rid(3)],
    invalidated_agent_ids: [agentSigner],
    invalidated_trusted_seed_nids: ["did:key:z6MkwQp8f8Y11L3WJYJ4hXa1"],
    removed_marmot_leaf_ids: [rid(4)],
    advanced_group_ids: [rid(5)],
    stalled_group_ids: [rid(6)],
    fresh_keypackages: [{
      keypackage_id: rid(30),
      account_key: otherPersona,
      event_id: rid(31),
    }],
    subordinate_reauthorizations: subordinateReauthorizations,
    transition_evidence: transitionEvidence,
    completed_at: 130,
    signer: otherPersona,
  });
  const authoritativeEvidence = {
    inventory_id: authoritativeInventory.inventory_id,
    inventory_revision: authoritativeInventory.revision,
    evidence_revision: completion.evidence_revision,
    observed_at: 130,
    transition_evidence: completion.transition_evidence,
    fresh_keypackages: completion.fresh_keypackages,
    subordinate_reauthorizations: completion.subordinate_reauthorizations,
  };

  function validateReset(overrides: Record<string, unknown> = {}) {
    const candidateCompletion = (overrides.completion ?? completion) as CompromiseResetCompletion;
    return validateCompromiseReset({
      grant: recoveryGrant,
      completion: candidateCompletion,
      authoritative_inventory: authoritativeInventory,
      authoritative_evidence: {
        ...authoritativeEvidence,
        evidence_revision: candidateCompletion.evidence_revision,
        transition_evidence: candidateCompletion.transition_evidence,
        fresh_keypackages: candidateCompletion.fresh_keypackages,
        subordinate_reauthorizations: candidateCompletion.subordinate_reauthorizations,
      },
      pinned_assurance_authority: null,
      now: 130,
      ...overrides,
    });
  }

  it("accepts an active-account reset without requiring Assurance", () => {
    expect(validateReset()).toMatchObject({
      verdict: "accept",
      reset_transition: {
        inventory_id: authoritativeInventory.inventory_id,
        recovery_id: recoveryGrant.recovery_id,
        expected_inventory_revision: 12,
        next_inventory_revision: 13,
        evidence_revision: 13,
      },
    });
  });

  it("keeps active-account reset valid when optional Assurance is configured", () => {
    expect(validateReset({
      pinned_assurance_authority: {
        head_id: rid(70),
        authority_pubkey: assuranceAuthority,
      },
    })).toMatchObject({ verdict: "accept" });
  });

  it("accepts only the exact pinned Assurance authority and head", () => {
    const { signature: _signature, ...unsigned } = recoveryGrant;
    const assuranceGrant = signRecoveryGrant({
      ...unsigned,
      authorization_class: "assurance-recovery",
      authorizing_pubkey: assuranceAuthority,
      assurance_head: rid(70),
    }, assuranceSecret);
    const pin = { head_id: rid(70), authority_pubkey: assuranceAuthority };
    expect(validateReset({
      grant: assuranceGrant,
      pinned_assurance_authority: pin,
    })).toMatchObject({ verdict: "accept" });
    expect(validateReset({
      grant: assuranceGrant,
      pinned_assurance_authority: { ...pin, head_id: rid(71) },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-unauthenticated",
    });
  });

  it("rejects every incomplete reset category and missing subordinate reauthorization", () => {
    const removals = [
      "revoked_nip46_oidc_grant_ids",
      "invalidated_client_ids",
      "invalidated_delegate_ids",
      "invalidated_node_ids",
      "invalidated_agent_ids",
      "invalidated_trusted_seed_nids",
      "removed_marmot_leaf_ids",
      "advanced_group_ids",
    ] as const;
    for (const member of removals) {
      const { signature: _signature, ...unsigned } = completion;
      expect(validateReset({
        completion: signRecoveryCompletion({ ...unsigned, [member]: [] }),
      }), member).toEqual({
        verdict: "reject",
        reason_code: "control-compromise-reset-incomplete",
      });
    }
    const { signature: _signature, ...completionUnsigned } = completion;
    expect(validateReset({
      completion: signRecoveryCompletion({
        ...completionUnsigned,
        subordinate_reauthorizations: completion.subordinate_reauthorizations.slice(1),
      }),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-subordinate-reauthorization-required",
    });
    expect(validateReset({
      completion: signRecoveryCompletion({ ...completionUnsigned, fresh_keypackages: [] }),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-incomplete",
    });

    const { signature: _grantSignature, ...grantUnsigned } = recoveryGrant;
    const sameKeyGrant = signRecoveryGrant({
      ...grantUnsigned,
      successor_active_key: persona,
    });
    expect(validateReset({
      grant: sameKeyGrant,
      completion: signRecoveryCompletion({
        ...completionUnsigned,
        successor_active_key: persona,
        signer: persona,
        fresh_keypackages: [{ keypackage_id: rid(30), account_key: persona, event_id: rid(31) }],
      }, personaSecret),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-incomplete",
    });
    expect(validateReset({
      now: Number.NaN,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-incomplete",
    });
    expect(validateReset({
      completion: signRecoveryCompletion({
        ...completionUnsigned,
        stalled_group_ids: completion.advanced_group_ids,
      }),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-incomplete",
    });
  });

  it("rejects unauthenticated reset records, caller-shrunk inventory, and reused evidence IDs", () => {
    expect(validateReset({
      grant: { ...recoveryGrant, signature: "00".repeat(64) },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-unauthenticated",
    });
    expect(validateReset({
      completion: { ...completion, signature: "00".repeat(64) },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-unauthenticated",
    });

    const { signature: _grantSignature, ...grantUnsigned } = recoveryGrant;
    const { signature: _completionSignature, ...completionUnsigned } = completion;
    const shrunkGrant = signRecoveryGrant({
      ...grantUnsigned,
      required_reset: { ...grantUnsigned.required_reset, marmot_leaf_ids: [] },
    });
    const shrunkCompletion = signRecoveryCompletion({
      ...completionUnsigned,
      removed_marmot_leaf_ids: [],
    });
    expect(validateReset({
      grant: shrunkGrant,
      completion: shrunkCompletion,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-inventory-mismatch",
    });

    expect(validateReset({
      completion: signRecoveryCompletion({
        ...completionUnsigned,
        fresh_keypackages: [{
          keypackage_id: rid(30),
          account_key: otherPersona,
          event_id: grant.grant_id,
        }],
      }),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("rejects a fresh KeyPackage that is not bound to the successor account", () => {
    const { signature: _signature, ...unsigned } = completion;
    const mixedAccountCompletion = signRecoveryCompletion({
      ...unsigned,
      fresh_keypackages: [
        ...completion.fresh_keypackages,
        { keypackage_id: rid(60), account_key: persona, event_id: rid(61) },
      ],
    });
    expect(validateReset({ completion: mixedAccountCompletion })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("requires the reset evidence transition to advance exactly one inventory revision", () => {
    const { signature: _signature, ...unsigned } = completion;
    const skippedRevision = signRecoveryCompletion({
      ...unsigned,
      evidence_revision: authoritativeInventory.revision + 2,
    });
    expect(validateReset({ completion: skippedRevision })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("rejects authoritative transition evidence observed after validation time", () => {
    expect(validateReset({
      authoritative_evidence: {
        ...authoritativeEvidence,
        observed_at: 131,
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("rejects a subordinate authorization that is not active at completion", () => {
    const { signature: _signature, ...completionUnsigned } = completion;
    const {
      contract_digest: _contractDigest,
      ...contractUnsigned
    } = completion.subordinate_reauthorizations[0];
    const futureUnsigned = { ...contractUnsigned, issued_at: 131 };
    const futureContract = {
      ...futureUnsigned,
      contract_digest: createHash("sha256")
        .update(proofBytes(
          "heterodyne-control-subordinate-authorization-v1",
          futureUnsigned,
        ))
        .digest("hex"),
    };
    expect(validateReset({
      completion: signRecoveryCompletion({
        ...completionUnsigned,
        subordinate_reauthorizations: [
          futureContract,
          ...completion.subordinate_reauthorizations.slice(1),
        ],
      }),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });
});
