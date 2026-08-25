import { describe, expect, it } from "vitest";
import { matchesAgentAttributionProfile } from "./agent-authorship.js";
import {
  authorizeNip46Signing,
  consumeNip46ConnectionSecret,
  prepareAutomatedSigning,
  type CompromiseResetCompletion,
  type CompromiseResetGrant,
  type SigningGrant,
  validateCompromiseReset,
} from "./control-signing.js";

const hex = (byte: string) => byte.repeat(64);
const persona = hex("1");
const otherPersona = hex("2");
const client = hex("3");
const agentSigner = hex("4");
const otherSigner = hex("5");
const vaultId = hex("6");
const audience = "https://node.example/nip46/persona-1";

const grant: SigningGrant = {
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
  connection_secret_sha256: hex("9"),
  issued_at: 100,
  expires_at: 200,
  predecessor: null,
  state: "active",
  revoked_at: null,
  authorizing_pubkey: persona,
  signature: "a".repeat(128),
};

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
  grant_id: grant.grant_id,
  vault_id: vaultId,
  persona_active_key: persona,
  nip46_client_pubkey: client,
  signer_audience: audience,
  selected_signing_pubkey: agentSigner,
  key_class: "agent" as const,
  method: "sign_event",
  event_kind: 1,
  request_count: 1,
  event_bytes: 512,
  value_msats: 0,
  now: 110,
};

const metadata = {
  requested_methods: ["sign_event"],
  requested_event_kinds: [1],
  requested_signer_audiences: [audience],
};

function authorize(overrides: Record<string, unknown> = {}) {
  return authorizeNip46Signing({
    stored_grant: grant,
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

    const mislabeledPersona = {
      ...grant,
      selected_signing_pubkey: persona,
    };
    expect(authorizeNip46Signing({
      stored_grant: mislabeledPersona,
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
    const personaGrant = {
      ...grant,
      selected_signing_pubkey: persona,
      key_class: "persona" as const,
      persona_signing_authorized: true,
    };
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
      stored_grant: personaGrant,
      presented_grant: structuredClone(personaGrant),
      vaults: personaVaults,
      request: personaRequest,
      client_metadata: metadata,
    })).toMatchObject({ verdict: "accept", key_class: "persona" });
    expect(authorizeNip46Signing({
      stored_grant: { ...personaGrant, persona_signing_authorized: false },
      presented_grant: { ...personaGrant, persona_signing_authorized: false },
      vaults: personaVaults,
      request: personaRequest,
      client_metadata: metadata,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-persona-authority-required",
    });
  });
});

describe("OIDC activation and automated publication", () => {
  const pending = {
    transaction_id: hex("c"),
    connection_secret_sha256: grant.connection_secret_sha256,
    connection_secret_state: "pending" as const,
    state: "approved" as const,
  };

  it("consumes an OIDC-issued NIP-46 connection secret exactly once", () => {
    const first = consumeNip46ConnectionSecret(pending, grant.connection_secret_sha256);
    expect(first).toEqual({
      verdict: "accept",
      state: { ...pending, connection_secret_state: "consumed" },
    });
    if (first.verdict !== "accept") throw new Error("fixture activation failed");
    expect(consumeNip46ConnectionSecret(
      first.state,
      grant.connection_secret_sha256,
    )).toEqual({
      verdict: "reject",
      reason_code: "control-connection-secret-reused",
    });
  });

  it("injects valid Comms attribution before the signer sees an automated event", () => {
    let signerSawAttribution = false;
    const result = prepareAutomatedSigning({
      authorization: {
        stored_grant: grant,
        presented_grant: structuredClone(grant),
        vaults,
        request,
        client_metadata: metadata,
      },
      publication: {
        created_at: 111,
        kind: 1,
        tags: [["t", "heterodyne"]],
        content: "bounded publication intent",
        value_msats: 0,
        agent_class: "ai",
        agent_association: { kind: "key" as const, value: agentSigner },
        tier: 1 as const,
      },
      sign: (event: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }) => {
        signerSawAttribution = matchesAgentAttributionProfile(event.tags);
        return { ...event, id: hex("d"), sig: "e".repeat(128) };
      },
    });
    expect(signerSawAttribution).toBe(true);
    expect(result).toMatchObject({
      verdict: "accept",
      event: {
        pubkey: agentSigner,
        id: hex("d"),
        sig: "e".repeat(128),
      },
    });
  });

  it("does not call the signer when attribution cannot be produced", () => {
    let signerCalled = false;
    const unsupportedGrant = {
      ...grant,
      allowed_event_kinds: [2],
    };
    const result = prepareAutomatedSigning({
      authorization: {
        stored_grant: unsupportedGrant,
        presented_grant: structuredClone(unsupportedGrant),
        vaults,
        request: { ...request, event_kind: 2 },
        client_metadata: { ...metadata, requested_event_kinds: [2] },
      },
      publication: {
        created_at: 111,
        kind: 2,
        tags: [],
        content: "unsupported attribution kind",
        value_msats: 0,
        agent_class: "ai",
        agent_association: { kind: "key" as const, value: agentSigner },
        tier: 1 as const,
      },
      sign: (event: { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }) => {
        signerCalled = true;
        return { ...event, id: hex("f"), sig: "0".repeat(128) };
      },
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-attribution-required",
    });
    expect(signerCalled).toBe(false);
  });

  it("enforces the byte limit against the attributed event rather than caller metadata", () => {
    let signerCalled = false;
    const tinyGrant = {
      ...grant,
      limits: { ...grant.limits, max_event_bytes: 8 },
    };
    const result = prepareAutomatedSigning({
      authorization: {
        stored_grant: tinyGrant,
        presented_grant: structuredClone(tinyGrant),
        vaults,
        request: { ...request, event_bytes: 1 },
        client_metadata: metadata,
      },
      publication: {
        created_at: 111,
        kind: 1,
        tags: [],
        content: "larger than the grant after attribution",
        value_msats: 0,
        agent_class: "ai",
        agent_association: { kind: "key" as const, value: agentSigner },
        tier: 1 as const,
      },
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
  const recoveryGrant: CompromiseResetGrant = {
    profile: "heterodyne.control.compromise-reset-grant.v1",
    spec_version: "heterodyne/0.5.0",
    recovery_id: hex("1"),
    persona_active_key: persona,
    successor_active_key: otherPersona,
    authorization_class: "active-account",
    authorizing_pubkey: persona,
    compromise_at: 120,
    required_reset: {
      nip46_oidc_grant_ids: [grant.grant_id],
      client_ids: [client],
      delegate_ids: [hex("2")],
      node_ids: [hex("3")],
      agent_ids: [agentSigner],
      trusted_seed_nids: ["did:key:z6MkwQp8f8Y11L3WJYJ4hXa1"],
      marmot_leaf_ids: [hex("4")],
      reachable_group_ids: [hex("5")],
      subordinate_authority_ids: [hex("2"), hex("3"), agentSigner],
    },
    issued_at: 121,
    expires_at: 180,
    state: "active",
    revoked_at: null,
    signature: "6".repeat(128),
  };
  const completion: CompromiseResetCompletion = {
    profile: "heterodyne.control.compromise-reset-completion.v1",
    spec_version: "heterodyne/0.5.0",
    recovery_id: recoveryGrant.recovery_id,
    persona_active_key: persona,
    successor_active_key: otherPersona,
    revoked_nip46_oidc_grant_ids: [grant.grant_id],
    invalidated_client_ids: [client],
    invalidated_delegate_ids: [hex("2")],
    invalidated_node_ids: [hex("3")],
    invalidated_agent_ids: [agentSigner],
    invalidated_trusted_seed_nids: ["did:key:z6MkwQp8f8Y11L3WJYJ4hXa1"],
    removed_marmot_leaf_ids: [hex("4")],
    advanced_group_ids: [hex("5")],
    stalled_group_ids: [],
    fresh_keypackages: [{ account_key: otherPersona, event_id: hex("7") }],
    subordinate_reauthorizations: [
      { prior_authority_id: hex("2"), authorization_id: hex("8") },
      { prior_authority_id: hex("3"), authorization_id: hex("9") },
      { prior_authority_id: agentSigner, authorization_id: hex("a") },
    ],
    completed_at: 130,
    signer: otherPersona,
    signature: "b".repeat(128),
  };

  it("accepts an active-account reset without requiring Assurance", () => {
    expect(validateCompromiseReset({ grant: recoveryGrant, completion, now: 130 }))
      .toEqual({ verdict: "accept" });
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
      expect(validateCompromiseReset({
        grant: recoveryGrant,
        completion: { ...completion, [member]: [] },
        now: 130,
      }), member).toEqual({
        verdict: "reject",
        reason_code: "control-compromise-reset-incomplete",
      });
    }
    expect(validateCompromiseReset({
      grant: recoveryGrant,
      completion: {
        ...completion,
        subordinate_reauthorizations: completion.subordinate_reauthorizations.slice(1),
      },
      now: 130,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-subordinate-reauthorization-required",
    });
    expect(validateCompromiseReset({
      grant: recoveryGrant,
      completion: { ...completion, fresh_keypackages: [] },
      now: 130,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-incomplete",
    });

    const sameKeyGrant = { ...recoveryGrant, successor_active_key: persona };
    expect(validateCompromiseReset({
      grant: sameKeyGrant,
      completion: {
        ...completion,
        successor_active_key: persona,
        signer: persona,
        fresh_keypackages: [{ account_key: persona, event_id: hex("7") }],
      },
      now: 130,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-incomplete",
    });
    expect(validateCompromiseReset({
      grant: recoveryGrant,
      completion,
      now: Number.NaN,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-incomplete",
    });
    expect(validateCompromiseReset({
      grant: recoveryGrant,
      completion: { ...completion, stalled_group_ids: completion.advanced_group_ids },
      now: 130,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-incomplete",
    });
  });
});
