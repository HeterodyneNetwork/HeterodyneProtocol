import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { describe, expect, it } from "vitest";
import {
  injectAgentAttribution,
  matchesAgentAttributionProfile,
} from "./agent-authorship.js";
import {
  authorizeNip46Signing,
  consumeNip46ConnectionSecret,
  compromiseResetEvidenceBundleDigest,
  executePersistedAutomatedSigning,
  keyPackageVerificationProofBytes,
  mlsCommitEvidenceProofBytes,
  nip46OperationId,
  prepareAutomatedExecution,
  prepareAutomatedSigning,
  ReferenceSignerExecutionFence,
  ReferenceSignerExecutionStore,
  resetStateEvidenceProofBytes,
  signingExecutionToken,
  type AutomatedPublication,
  type CompromiseResetCompletion,
  type CompromiseResetGrant,
  type SigningGrant,
  validateCompromiseReset,
} from "./control-signing.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
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

const rpcUnsignedEvent = {
  created_at: 111,
  kind: 1,
  tags: [] as string[][],
  content: "canonical NIP-46 payload",
};
const rpcRequest = {
  id: hex("d"),
  method: "sign_event",
  params: [jcsCanonicalize(rpcUnsignedEvent)],
};

const request = {
  grant_id: grant.grant_id,
  vault_id: vaultId,
  persona_active_key: persona,
  nip46_client_pubkey: client,
  signer_audience: audience,
  selected_signing_pubkey: agentSigner,
  key_class: "agent" as const,
  rpc_request: rpcRequest,
  value_msats: 0,
  now: 110,
};

function testGrantDigest(candidate: SigningGrant): string {
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-signer-grant-state-v1", candidate))
    .digest("hex");
}

function usageStateFor(candidate: SigningGrant) {
  return {
    grant_id: candidate.grant_id,
    grant_digest: testGrantDigest(candidate),
    authority: {
      vault_id: candidate.vault_id,
      persona_active_key: candidate.persona_active_key,
      nip46_client_pubkey: candidate.nip46_client_pubkey,
      signer_audience: candidate.signer_audience,
      selected_signing_pubkey: candidate.selected_signing_pubkey,
      key_class: candidate.key_class,
    },
    window_started_at: 100,
    consumed_request_count: 0,
    revision: 4,
    reservations: [],
  };
}

function testNip46RequestDigest(
  candidate: SigningGrant,
  rpc: typeof rpcRequest,
  valueMsats = 0,
): string {
  const parsed = rpc.method === "sign_event" && rpc.params.length === 1
    ? JSON.parse(rpc.params[0]) as Omit<NostrUnsignedEvent, "pubkey">
    : null;
  return createHash("sha256")
    .update(proofBytes("heterodyne-control-nip46-request-v1", {
      grant_digest: testGrantDigest(candidate),
      authority: usageStateFor(candidate).authority,
      rpc_request: rpc,
      normalized_event: parsed === null ? null : {
        pubkey: candidate.selected_signing_pubkey,
        ...parsed,
      },
      value_msats: valueMsats,
    }))
    .digest("hex");
}

const usageState = usageStateFor(grant);

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

function automatedRequest(
  publication: AutomatedPublication,
  candidate = automationGrant,
) {
  const policy = candidate.automation_policy;
  if (policy === undefined) throw new Error("automation fixture lacks policy");
  const attributed = injectAgentAttribution({
    kind: publication.kind,
    tags: publication.tags,
    agent_class: policy.agent_class,
    persona: candidate.persona_active_key,
    signer: candidate.selected_signing_pubkey,
    expected_signer: candidate.selected_signing_pubkey,
    signer_key_class: candidate.key_class,
    oidc_scopes: policy.oidc_scopes,
    agent_association: policy.agent_association ?? undefined,
    expected_agent_association: policy.agent_association ?? undefined,
    tier: policy.tier,
  });
  if (attributed.verdict !== "accept") throw new Error("automation fixture invalid");
  const template = {
    created_at: publication.created_at,
    kind: publication.kind,
    tags: attributed.tags,
    content: publication.content,
  };
  return {
    ...request,
    grant_id: candidate.grant_id,
    vault_id: candidate.vault_id,
    persona_active_key: candidate.persona_active_key,
    nip46_client_pubkey: candidate.nip46_client_pubkey,
    signer_audience: candidate.signer_audience,
    selected_signing_pubkey: candidate.selected_signing_pubkey,
    key_class: candidate.key_class,
    rpc_request: {
      id: request.rpc_request.id,
      method: "sign_event",
      params: [JSON.stringify(template)],
    },
    value_msats: publication.value_msats,
  };
}

function persistedUsage(
  automatedSigningRequest: ReturnType<typeof automatedRequest>,
  candidate = automationGrant,
) {
  const candidateUsage = usageStateFor(candidate);
  return {
    ...candidateUsage,
    consumed_request_count: 1,
    revision: candidateUsage.revision + 1,
    reservations: [{
      operation_id: nip46OperationId(candidate, automatedSigningRequest.rpc_request.id),
      request_id: automatedSigningRequest.rpc_request.id,
      request_digest: testNip46RequestDigest(
        candidate,
        automatedSigningRequest.rpc_request,
        automatedSigningRequest.value_msats,
      ),
      rpc_request: automatedSigningRequest.rpc_request,
      value_msats: automatedSigningRequest.value_msats,
      window_started_at: candidateUsage.window_started_at,
      reserved_at: automatedSigningRequest.now,
      claimed_at: null,
      executing_at: null,
      completed_at: null,
      state: "reserved" as const,
      execution_token: null,
      result_event_id: null,
      failure_digest: null,
    }],
  };
}

function claimedUsage(
  automatedSigningRequest: ReturnType<typeof automatedRequest>,
  candidate = automationGrant,
) {
  const persisted = persistedUsage(automatedSigningRequest, candidate);
  return {
    ...persisted,
    revision: persisted.revision + 1,
    reservations: persisted.reservations.map((reservation) => ({
      ...reservation,
      state: "claimed" as const,
      claimed_at: automatedSigningRequest.now,
    })),
  };
}

function executingUsage(
  automatedSigningRequest: ReturnType<typeof automatedRequest>,
  candidate = automationGrant,
) {
  const claimed = claimedUsage(automatedSigningRequest, candidate);
  const requestDigest = testNip46RequestDigest(
    candidate,
    automatedSigningRequest.rpc_request,
    automatedSigningRequest.value_msats,
  );
  return {
    ...claimed,
    revision: claimed.revision + 1,
    reservations: claimed.reservations.map((reservation) => ({
      ...reservation,
      state: "executing" as const,
      executing_at: automatedSigningRequest.now,
      execution_token: signingExecutionToken(candidate, requestDigest),
    })),
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

function referenceSignerExecution<
  T extends NostrUnsignedEvent & { id: string; sig: string },
>(keyOperation: (event: NostrUnsignedEvent) => T) {
  return new ReferenceSignerExecutionFence(
    new ReferenceSignerExecutionStore<T>(),
    keyOperation,
  );
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
        operation_id: nip46OperationId(grant, request.rpc_request.id),
        grant_id: grant.grant_id,
        grant_digest: usageState.grant_digest,
        authority: usageState.authority,
        request_id: request.rpc_request.id,
        request_digest: testNip46RequestDigest(grant, rpcRequest),
        rpc_request: rpcRequest,
        value_msats: 0,
        expected_revision: 4,
        next_revision: 5,
        prior_window_started_at: 100,
        window_started_at: 100,
        prior_consumed_request_count: 0,
        consumed_request_count: 1,
        reserved_at: request.now,
        reservation_state: "reserved",
      },
    });
  });

  it("derives the reservation digest from the canonical standard NIP-46 request", () => {
    const result = authorize({
      request: {
        ...request,
        rpc_request: rpcRequest,
      },
    });
    expect(result).toMatchObject({
      verdict: "accept",
      usage_transition: {
        request_digest: testNip46RequestDigest(grant, rpcRequest),
      },
    });
  });

  it("accepts the vanilla nostr-tools request id and EventTemplate wire shape", () => {
    const standardRpc = {
      id: "k3j9x7-1",
      method: "sign_event",
      params: [JSON.stringify({
        kind: rpcUnsignedEvent.kind,
        tags: rpcUnsignedEvent.tags,
        content: rpcUnsignedEvent.content,
        created_at: rpcUnsignedEvent.created_at,
      })],
    };
    expect(authorize({
      request: { ...request, rpc_request: standardRpc },
    })).toMatchObject({
      verdict: "accept",
      usage_transition: {
        operation_id: expect.stringMatching(/^[0-9a-f]{64}$/),
        request_id: standardRpc.id,
        request_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      },
    });
  });

  it("rejects a non-printable-ASCII NIP-46 wire request id", () => {
    expect(authorize({
      request: {
        ...request,
        rpc_request: { ...rpcRequest, id: "🔐-1" },
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-nip46-request-invalid",
    });
  });

  it("rejects duplicate or extra EventTemplate members unambiguously", () => {
    const duplicate = `{"kind":1,"kind":30023,"tags":[],"content":"x","created_at":111}`;
    const extra = JSON.stringify({
      kind: 1,
      tags: [],
      content: "x",
      created_at: 111,
      pubkey: agentSigner,
    });
    for (const param of [duplicate, extra]) {
      expect(authorize({
        request: {
          ...request,
          rpc_request: { id: "nostr-tools-1", method: "sign_event", params: [param] },
        },
      })).toEqual({
        verdict: "reject",
        reason_code: "control-nip46-request-invalid",
      });
    }
  });

  it("uses authoritative window consumption instead of a caller-selected count", () => {
    const reservations = Array.from({ length: grant.limits.request_count }, (_, index) => {
      const historicalRpc = {
        id: index.toString(16).padStart(64, "0"),
        method: "sign_event",
        params: [jcsCanonicalize(rpcUnsignedEvent)],
      };
      return {
        operation_id: nip46OperationId(grant, historicalRpc.id),
        request_id: historicalRpc.id,
        request_digest: testNip46RequestDigest(grant, historicalRpc),
        rpc_request: historicalRpc,
        value_msats: 0,
        window_started_at: usageState.window_started_at,
        reserved_at: 101,
        claimed_at: null,
        executing_at: null,
        completed_at: null,
        state: "reserved" as const,
        execution_token: null,
        result_event_id: null,
        failure_digest: null,
      };
    });
    expect(authorize({
      usage_state: {
        ...usageState,
        consumed_request_count: grant.limits.request_count,
        reservations,
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
          operation_id: nip46OperationId(grant, request.rpc_request.id),
          request_id: request.rpc_request.id,
          request_digest: testNip46RequestDigest(grant, rpcRequest),
          rpc_request: rpcRequest,
          value_msats: 0,
          window_started_at: usageState.window_started_at,
          reserved_at: 101,
          claimed_at: 102,
          executing_at: 102,
          completed_at: 103,
          state: "committed",
          execution_token: signingExecutionToken(
            grant,
            testNip46RequestDigest(grant, rpcRequest),
          ),
          result_event_id: hex("f"),
          failure_digest: null,
        }],
      },
    })).toEqual({
      verdict: "replay",
      event_id: hex("f"),
    });
  });

  it("rejects replay state copied from a different grant authority tuple", () => {
    expect(authorize({
      usage_state: {
        ...usageState,
        grant_digest: hex("0"),
        authority: {
          vault_id: vaults[0].vault_id,
          persona_active_key: otherPersona,
          nip46_client_pubkey: client,
          signer_audience: audience,
          selected_signing_pubkey: otherSigner,
          key_class: "agent",
        },
        consumed_request_count: 1,
        reservations: [{
          operation_id: nip46OperationId(grant, request.rpc_request.id),
          request_id: request.rpc_request.id,
          request_digest: testNip46RequestDigest(grant, rpcRequest),
          rpc_request: rpcRequest,
          value_msats: 0,
          window_started_at: usageState.window_started_at,
          reserved_at: 101,
          claimed_at: 102,
          executing_at: 102,
          completed_at: 103,
          state: "committed",
          execution_token: signingExecutionToken(
            grant,
            testNip46RequestDigest(grant, rpcRequest),
          ),
          result_event_id: hex("f"),
          failure_digest: null,
        }],
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-usage-binding-mismatch",
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

  it("does not permit an active child after an absorbing revoked grant", () => {
    const revoked = resignGrant({
      ...grant,
      state: "revoked",
      revoked_at: 105,
    });
    const { signature: _signature, ...unsigned } = grant;
    const resurrected = signGrant({
      ...unsigned,
      grant_id: hex("c"),
      predecessor: revoked.grant_id,
      issued_at: 106,
    });
    expect(authorize({
      grant_candidates: [revoked, resurrected],
      presented_grant: resurrected,
      usage_state: { ...usageState, grant_id: resurrected.grant_id },
      request: { ...request, grant_id: resurrected.grant_id },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-stale",
    });
  });

  it("rejects a predecessor chain with backdated child issuance", () => {
    const { signature: _signature, ...unsigned } = grant;
    const backdated = signGrant({
      ...unsigned,
      grant_id: hex("c"),
      predecessor: grant.grant_id,
      issued_at: grant.issued_at - 1,
    });
    expect(authorize({
      grant_candidates: [grant, backdated],
      presented_grant: backdated,
      usage_state: { ...usageState, grant_id: backdated.grant_id },
      request: { ...request, grant_id: backdated.grant_id },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-stale",
    });
  });

  it("rejects a revocation timestamp before grant issuance", () => {
    const impossible = resignGrant({
      ...grant,
      state: "revoked",
      revoked_at: grant.issued_at - 1,
    });
    expect(authorize({
      grant_candidates: [impossible],
      presented_grant: impossible,
    })).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-invalid",
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
      request: {
        ...request,
        selected_signing_pubkey: persona,
        rpc_request: {
          ...rpcRequest,
          params: [JSON.stringify(rpcUnsignedEvent)],
        },
      },
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
      rpc_request: {
        ...rpcRequest,
        params: [JSON.stringify(rpcUnsignedEvent)],
      },
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
      usage_state: usageStateFor(personaGrant),
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
    const signingRequest = automatedRequest(publication);
    const result = executePersistedAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: executingUsage(signingRequest),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication,
      signer_execution: referenceSignerExecution((event) => {
        signerSawAttribution = matchesAgentAttributionProfile(event.tags);
        return signNostrEvent(event);
      }),
    });
    expect(signerSawAttribution).toBe(true);
    expect(result).toMatchObject({
      verdict: "accept",
      completion_transition: {
        grant_id: automationGrant.grant_id,
        request_id: signingRequest.rpc_request.id,
        request_digest: testNip46RequestDigest(
          automationGrant,
          signingRequest.rpc_request,
        ),
        expected_revision: 7,
        next_revision: 8,
        prior_reservation_state: "executing",
        reservation_state: "committed",
      },
      event: {
        pubkey: agentSigner,
      },
    });
  });

  it("executes the underlying key operation once for duplicate persisted executing state", () => {
    let keyOperations = 0;
    const publication = automatedIntent();
    const signingRequest = automatedRequest(publication);
    const authorization = {
      grant_candidates: [automationGrant],
      usage_state: executingUsage(signingRequest),
      presented_grant: structuredClone(automationGrant),
      vaults,
      request: signingRequest,
      client_metadata: metadata,
    };
    const sharedStore = new ReferenceSignerExecutionStore<ReturnType<typeof signNostrEvent>>();
    const keyOperation = (event: NostrUnsignedEvent) => {
      keyOperations += 1;
      return signNostrEvent(event);
    };
    const firstProcessCapability = new ReferenceSignerExecutionFence(
      sharedStore,
      keyOperation,
    );
    const secondProcessCapability = new ReferenceSignerExecutionFence(
      sharedStore,
      keyOperation,
    );
    const first = executePersistedAutomatedSigning({
      authorization,
      publication,
      signer_execution: firstProcessCapability,
    });
    const second = executePersistedAutomatedSigning({
      authorization,
      publication,
      signer_execution: secondProcessCapability,
    });
    expect(first).toMatchObject({ verdict: "accept" });
    expect(second).toMatchObject({ verdict: "accept" });
    expect(keyOperations).toBe(1);
    expect(first).toMatchObject({ signer_execution_disposition: "executed" });
    expect(second).toMatchObject({ signer_execution_disposition: "cached" });
  });

  it("rejects an execution token replayed with different event or request digest", () => {
    let keyOperations = 0;
    const fence = referenceSignerExecution((event) => {
      keyOperations += 1;
      return signNostrEvent(event);
    });
    const unsigned = { pubkey: agentSigner, ...rpcUnsignedEvent };
    expect(fence.executeOnce(hex("a"), unsigned, hex("b")))
      .toMatchObject({ verdict: "accept", disposition: "executed" });
    expect(fence.executeOnce(hex("a"), { ...unsigned, content: "grafted" }, hex("b")))
      .toEqual({ verdict: "conflict" });
    expect(fence.executeOnce(hex("a"), unsigned, hex("c")))
      .toEqual({ verdict: "conflict" });
    expect(keyOperations).toBe(1);
  });

  it("rejects a raw signer callback at the execution API boundary", () => {
    let rawSignerCalls = 0;
    const publication = automatedIntent();
    const signingRequest = automatedRequest(publication);
    const result = executePersistedAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: executingUsage(signingRequest),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication,
      signer_execution: referenceSignerExecution(signNostrEvent),
      sign: (event: NostrUnsignedEvent) => {
        rawSignerCalls += 1;
        return signNostrEvent(event);
      },
    } as never);
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-operation-execution-fence-required",
    });
    expect(rawSignerCalls).toBe(0);
  });

  it("never invokes the signer from replayable claimed state", () => {
    let signerCalls = 0;
    const publication = automatedIntent();
    const signingRequest = automatedRequest(publication);
    const result = executePersistedAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: claimedUsage(signingRequest),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication,
      signer_execution: referenceSignerExecution((event) => {
        signerCalls += 1;
        return signNostrEvent(event);
      }),
    });
    expect(signerCalls).toBe(0);
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-operation-execution-fence-required",
    });
  });

  it("rejects a canonical NIP-46 request copied from a different automated intent", () => {
    const original = automatedIntent();
    const altered = automatedIntent({ content: "different caller-selected content" });
    const signingRequest = automatedRequest(original);
    const result = executePersistedAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: executingUsage(signingRequest),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication: altered,
      signer_execution: referenceSignerExecution(signNostrEvent),
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-operation-conflict",
    });
  });

  it("rejects automated execution before the authoritative reservation is persisted", () => {
    const publication = automatedIntent();
    const signingRequest = automatedRequest(publication);
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: usageStateFor(automationGrant),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication,
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-operation-reservation-required",
    });
  });

  it("requires an authoritative reserved-to-claimed CAS before execution", () => {
    const publication = automatedIntent();
    const signingRequest = automatedRequest(publication);
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: persistedUsage(signingRequest),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication,
    });
    expect(result).toMatchObject({
      verdict: "accept",
      authorization_mode: "claim-required",
      claim_transition: {
        grant_id: automationGrant.grant_id,
        request_id: signingRequest.rpc_request.id,
        expected_revision: 5,
        next_revision: 6,
        prior_reservation_state: "reserved",
        reservation_state: "claimed",
      },
    });
  });

  it("requires an authoritative claimed-to-executing CAS with a signer idempotency token", () => {
    const publication = automatedIntent();
    const signingRequest = automatedRequest(publication);
    const result = prepareAutomatedExecution({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: claimedUsage(signingRequest),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication,
    });
    expect(result).toMatchObject({
      verdict: "accept",
      authorization_mode: "execution-fence-required",
      execution_transition: {
        expected_revision: 6,
        next_revision: 7,
        prior_reservation_state: "claimed",
        reservation_state: "executing",
        execution_token: expect.stringMatching(/^[0-9a-f]{64}$/),
      },
    });
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
    const signingRequest = automatedRequest(policyIntent, policyGrant);
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [policyGrant],
        usage_state: usageState,
        presented_grant: structuredClone(policyGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication: policyIntent,
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
          rpc_request: {
            ...rpcRequest,
            params: [JSON.stringify(rpcUnsignedEvent)],
          },
        },
        client_metadata: metadata,
      },
      publication,
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-persona-authority-required",
    });
  });

  it("rejects an unsupported attribution kind at the closed intent boundary", () => {
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
          rpc_request: {
            ...rpcRequest,
            params: [jcsCanonicalize({ ...rpcUnsignedEvent, kind: 2 })],
          },
        },
        client_metadata: { ...metadata, requested_event_kinds: [2] },
      },
      publication,
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-agent-intent-invalid",
    });
  });

  it("rejects a shape-valid returned event ID and signature that do not verify", () => {
    const publication = automatedIntent();
    const signingRequest = automatedRequest(publication);
    const result = executePersistedAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: executingUsage(signingRequest),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication,
      signer_execution: referenceSignerExecution((event) => ({
        ...event,
        id: hex("d"),
        sig: "e".repeat(128),
      })),
    });
    expect(result).toMatchObject({
      verdict: "indeterminate",
      reason_code: "control-signer-effect-indeterminate",
      completion_transition: {
        prior_reservation_state: "executing",
        reservation_state: "indeterminate",
        expected_revision: 7,
        next_revision: 8,
      },
    });
  });

  it("rejects extra non-NIP-01 fields on an otherwise valid signed event", () => {
    const publication = automatedIntent();
    const signingRequest = automatedRequest(publication);
    const result = executePersistedAutomatedSigning({
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: executingUsage(signingRequest),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication,
      signer_execution: referenceSignerExecution((event) => ({
        ...signNostrEvent(event),
        grant_id: automationGrant.grant_id,
      })),
    });
    expect(result).toMatchObject({
      verdict: "indeterminate",
      reason_code: "control-signer-effect-indeterminate",
      completion_transition: {
        prior_reservation_state: "executing",
        reservation_state: "indeterminate",
      },
    });
  });

  it("makes a thrown executing signer effect durably indeterminate", () => {
    let keyOperations = 0;
    const publication = automatedIntent();
    const signingRequest = automatedRequest(publication);
    const signerExecution = referenceSignerExecution(() => {
      keyOperations += 1;
      throw new Error("remote signer outcome unknown");
    });
    const input = {
      authorization: {
        grant_candidates: [automationGrant],
        usage_state: executingUsage(signingRequest),
        presented_grant: structuredClone(automationGrant),
        vaults,
        request: signingRequest,
        client_metadata: metadata,
      },
      publication,
      signer_execution: signerExecution,
    };
    const first = executePersistedAutomatedSigning(input);
    const second = executePersistedAutomatedSigning(input);
    expect(first).toMatchObject({
      verdict: "indeterminate",
      reason_code: "control-signer-effect-indeterminate",
      signer_execution_disposition: "executed",
      completion_transition: {
        prior_reservation_state: "executing",
        reservation_state: "indeterminate",
        failure_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
      },
    });
    if (first.verdict !== "indeterminate") throw new Error("fixture must be indeterminate");
    expect(second).toMatchObject({
      verdict: "indeterminate",
      signer_execution_disposition: "cached",
      completion_transition: {
        failure_digest: first.completion_transition.failure_digest,
      },
    });
    expect(keyOperations).toBe(1);
  });

  it("enforces the byte limit against the attributed event rather than caller metadata", () => {
    const tinyGrant = resignGrant({
      ...automationGrant,
      limits: { ...grant.limits, max_event_bytes: 8 },
    });
    const publication = automatedIntent({
      tags: [],
      content: "larger than the grant after attribution",
    });
    const signingRequest = automatedRequest(publication, tinyGrant);
    const result = prepareAutomatedSigning({
      authorization: {
        grant_candidates: [tinyGrant],
        usage_state: usageState,
        presented_grant: structuredClone(tinyGrant),
        vaults,
        request: {
          ...signingRequest,
        },
        client_metadata: metadata,
      },
      publication,
    });
    expect(result).toEqual({
      verdict: "reject",
      reason_code: "control-signing-grant-invalid",
    });
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
    repository_ids: [rid(9)],
    delegate_ids: [rid(2)],
    node_ids: [rid(3)],
    agent_ids: [agentSigner],
    trusted_seed_nids: ["did:key:z6MkwQp8f8Y11L3WJYJ4hXa1"],
    marmot_leaf_ids: [rid(4)],
    reachable_groups: [{ group_id: rid(5), epoch: 7 }],
    unreachable_group_ids: [rid(6)],
    subordinate_authority_ids: [client, rid(9), rid(2), rid(3), agentSigner, rid(67)],
  };
  const authoritativeInventory = {
    inventory_id: rid(100),
    revision: 12,
    observed_at: 120,
    persona_active_key: persona,
    ...structuredClone(requiredReset),
    reachable_groups: [{
      group_id: rid(5),
      epoch: 7,
      state_digest: rid(10),
      mls_verifier_pubkey: assuranceAuthority,
      leaves: [{
        leaf_id: rid(4),
        leaf_index: 0,
        account_key: persona,
        keypackage_id: rid(11),
      }, {
        leaf_id: rid(34),
        leaf_index: 2,
        account_key: assuranceAuthority,
        keypackage_id: rid(35),
      }],
    }],
    existing_transition_ids: [rid(7)],
    existing_keypackage_event_ids: [rid(8)],
    authorization_records: [
      { authority_class: "nip46-oidc-grant" as const, subject_id: grant.grant_id, authorization_id: grant.grant_id, authorization_digest: rid(60) },
      { authority_class: "client" as const, subject_id: client, authorization_id: client, authorization_digest: rid(61) },
      { authority_class: "repository" as const, subject_id: rid(9), authorization_id: rid(9), authorization_digest: rid(62) },
      { authority_class: "delegate" as const, subject_id: rid(2), authorization_id: rid(2), authorization_digest: rid(63) },
      { authority_class: "node" as const, subject_id: rid(3), authorization_id: rid(3), authorization_digest: rid(64) },
      { authority_class: "agent" as const, subject_id: agentSigner, authorization_id: agentSigner, authorization_digest: rid(65) },
      { authority_class: "trusted-seed" as const, subject_id: requiredReset.trusted_seed_nids[0], authorization_id: rid(67), authorization_digest: rid(66) },
    ],
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
    repositories: [{ subject_id: rid(9), evidence_id: rid(29) }],
    delegates: [{ subject_id: rid(2), evidence_id: rid(22) }],
    nodes: [{ subject_id: rid(3), evidence_id: rid(23) }],
    agents: [{ subject_id: agentSigner, evidence_id: rid(24) }],
    trusted_seeds: [{
      subject_nid: requiredReset.trusted_seed_nids[0],
      evidence_id: rid(25),
    }],
    marmot_leaves: [{ subject_id: rid(4), evidence_id: rid(27) }],
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
    authority_class: "client" | "repository" | "delegate" | "node" | "agent" | "trusted-seed",
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
    subordinateContract(client, rid(43), "client", rid(53)),
    subordinateContract(rid(9), rid(44), "repository", rid(54)),
    subordinateContract(rid(2), rid(40), "delegate", rid(50)),
    subordinateContract(rid(3), rid(41), "node", rid(51)),
    subordinateContract(agentSigner, rid(42), "agent", rid(52)),
    subordinateContract(rid(67), rid(45), "trusted-seed", rid(55)),
  ];
  const signStateEvidence = (
    value: Omit<import("./control-signing.js").ResetStateEvidence, "signature">,
    secret = personaSecret,
  ) => ({
    ...value,
    signature: bytesToHex(schnorr.sign(
      resetStateEvidenceProofBytes(value),
      hexToBytes(secret),
      "00".repeat(32),
    )),
  });
  const stateEvidence = [
    ["nip46-oidc-grant", grant.grant_id, rid(20), rid(60), "revoked"],
    ["client", client, rid(21), rid(61), "invalidated"],
    ["repository", rid(9), rid(29), rid(62), "invalidated"],
    ["delegate", rid(2), rid(22), rid(63), "invalidated"],
    ["node", rid(3), rid(23), rid(64), "invalidated"],
    ["agent", agentSigner, rid(24), rid(65), "invalidated"],
    ["trusted-seed", requiredReset.trusted_seed_nids[0], rid(25), rid(66), "invalidated"],
    ["stalled-group", rid(6), rid(28), authoritativeInventory.inventory_id, "stalled"],
  ].map(([authority_class, subject_id, evidence_id, prior_authorization_digest, action]) =>
    signStateEvidence({
      evidence_id,
      authority_class: authority_class as import("./control-signing.js").ResetStateEvidence["authority_class"],
      subject_id,
      prior_authorization_digest,
      action: action as import("./control-signing.js").ResetStateEvidence["action"],
      effective_at: 124,
      recovery_id: recoveryGrant.recovery_id,
      signer: persona,
    })
  );
  const keyPackageContent = Buffer.from("standard-mls-keypackage-wire-v1", "utf8");
  const keyPackageEvent = signNostrEvent({
    pubkey: otherPersona,
    created_at: 125,
    kind: 30443,
    tags: [
      ["d", rid(33)],
      ["mls_protocol_version", "1.0"],
      ["i", rid(30)],
      ["mls_ciphersuite", "0x0001"],
      ["mls_extensions", "0x0002"],
      ["mls_proposals", "0x0001", "0x0002", "0x0003"],
      ["app_components", "0x8009"],
    ],
    content: keyPackageContent.toString("base64"),
  }, otherPersonaSecret) as CompromiseResetCompletion["fresh_keypackages"][number]["event"];
  const keyPackageUnsigned = {
    keypackage_id: rid(30),
    account_key: otherPersona,
    group_id: rid(5),
    event_id: keyPackageEvent.id,
    event: keyPackageEvent,
    content_sha256: createHash("sha256").update(keyPackageContent).digest("hex"),
    mls_verifier_pubkey: assuranceAuthority,
  };
  const freshKeyPackage = {
    ...keyPackageUnsigned,
    verification_signature: bytesToHex(schnorr.sign(
      keyPackageVerificationProofBytes({
        ...keyPackageUnsigned,
        verification_signature: "",
      }),
      hexToBytes(assuranceSecret),
      "00".repeat(32),
    )),
  };
  const signedFreshKeyPackage = (
    keypackageId: string,
    tags = keyPackageEvent.tags.map((tag) => [...tag]),
  ) => {
    const eventTags = tags.map((tag) =>
      tag[0] === "i" ? ["i", keypackageId] : tag
    );
    const event = signNostrEvent({
      pubkey: otherPersona,
      created_at: keyPackageEvent.created_at,
      kind: 30443,
      tags: eventTags,
      content: keyPackageEvent.content,
    }, otherPersonaSecret) as typeof keyPackageEvent;
    const unsigned = {
      ...freshKeyPackage,
      keypackage_id: keypackageId,
      event_id: event.id,
      event,
      verification_signature: "",
    };
    return {
      ...unsigned,
      verification_signature: bytesToHex(schnorr.sign(
        keyPackageVerificationProofBytes(unsigned),
        hexToBytes(assuranceSecret),
        "00".repeat(32),
      )),
    };
  };
  const commitBytes = Buffer.from("verified-mls-remove-commit-v1", "utf8");
  const commitUnsigned = {
    evidence_id: rid(27),
    recovery_id: recoveryGrant.recovery_id,
    group_id: rid(5),
    prior_epoch: 7,
    next_epoch: 8,
    prior_state_digest: rid(10),
    next_state_digest: rid(12),
    commit_bytes_base64: commitBytes.toString("base64"),
    commit_sha256: createHash("sha256").update(commitBytes).digest("hex"),
    removed_leaf_ids: [rid(4)],
    continuing_leaf_ids: [rid(34)],
    successor_leaves: [{
      leaf_id: rid(32),
      leaf_index: 1,
      account_key: otherPersona,
      keypackage_id: rid(30),
    }],
    verified_at: 126,
    mls_verifier_pubkey: assuranceAuthority,
  };
  const groupCommit = {
    ...commitUnsigned,
    verification_signature: bytesToHex(schnorr.sign(
      mlsCommitEvidenceProofBytes(commitUnsigned),
      hexToBytes(assuranceSecret),
      "00".repeat(32),
    )),
  };
  const evidenceBundle = {
    state_transitions: stateEvidence,
    group_commits: [groupCommit],
  };
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
    invalidated_repository_ids: [rid(9)],
    invalidated_delegate_ids: [rid(2)],
    invalidated_node_ids: [rid(3)],
    invalidated_agent_ids: [agentSigner],
    invalidated_trusted_seed_nids: ["did:key:z6MkwQp8f8Y11L3WJYJ4hXa1"],
    removed_marmot_leaf_ids: [rid(4)],
    advanced_group_ids: [rid(5)],
    stalled_group_ids: [rid(6)],
    fresh_keypackages: [freshKeyPackage],
    subordinate_reauthorizations: subordinateReauthorizations,
    transition_evidence: transitionEvidence,
    evidence_bundle_digest: compromiseResetEvidenceBundleDigest(evidenceBundle),
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
    evidence_bundle: evidenceBundle,
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
        evidence_bundle: authoritativeEvidence.evidence_bundle,
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

  it("rejects old-account-signed invalidation records during Assurance recovery", () => {
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
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
    expect(validateReset({
      grant: assuranceGrant,
      pinned_assurance_authority: { ...pin, head_id: rid(71) },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-unauthenticated",
    });
  });

  it("accepts Assurance recovery only with invalidations signed by the pinned authorizer", () => {
    const { signature: _grantSignature, ...grantUnsigned } = recoveryGrant;
    const assuranceGrant = signRecoveryGrant({
      ...grantUnsigned,
      authorization_class: "assurance-recovery",
      authorizing_pubkey: assuranceAuthority,
      assurance_head: rid(70),
    }, assuranceSecret);
    const assuranceStateEvidence = stateEvidence.map((record) => {
      const { signature: _signature, ...unsigned } = record;
      return signStateEvidence({
        ...unsigned,
        signer: assuranceAuthority,
      }, assuranceSecret);
    });
    const assuranceBundle = {
      ...evidenceBundle,
      state_transitions: assuranceStateEvidence,
    };
    const { signature: _completionSignature, ...completionUnsigned } = completion;
    const assuranceCompletion = signRecoveryCompletion({
      ...completionUnsigned,
      evidence_bundle_digest: compromiseResetEvidenceBundleDigest(assuranceBundle),
    });
    expect(validateReset({
      grant: assuranceGrant,
      completion: assuranceCompletion,
      pinned_assurance_authority: {
        head_id: rid(70),
        authority_pubkey: assuranceAuthority,
      },
      authoritative_evidence: {
        ...authoritativeEvidence,
        evidence_bundle: assuranceBundle,
      },
    })).toMatchObject({ verdict: "accept" });
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
        fresh_keypackages: [{ ...freshKeyPackage, account_key: persona }],
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
          ...freshKeyPackage,
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
        {
          ...freshKeyPackage,
          keypackage_id: rid(60),
          account_key: persona,
          event_id: rid(61),
        },
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

  it("rejects an opaque reset evidence identifier without an authenticated state transition", () => {
    const { signature: _signature, ...completionUnsigned } = completion;
    const opaqueEvidence = {
      ...completion.transition_evidence,
      nip46_oidc_grants: [{
        subject_id: grant.grant_id,
        evidence_id: rid(90),
      }],
    };
    expect(validateReset({
      completion: signRecoveryCompletion({
        ...completionUnsigned,
        transition_evidence: opaqueEvidence,
      }),
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("binds every Marmot leaf summary to its exact authenticated group Commit", () => {
    const { signature: _signature, ...completionUnsigned } = completion;
    const unboundTransitions = {
      ...completion.transition_evidence,
      marmot_leaves: [{ subject_id: rid(4), evidence_id: rid(90) }],
    };
    const unboundCompletion = signRecoveryCompletion({
      ...completionUnsigned,
      transition_evidence: unboundTransitions,
    });
    expect(validateReset({
      completion: unboundCompletion,
      authoritative_evidence: {
        ...authoritativeEvidence,
        transition_evidence: unboundTransitions,
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("rejects a grafted authoritative invalidation record with no valid state signature", () => {
    const { signature: _signature, ...completionUnsigned } = completion;
    const graftedBundle = {
      ...evidenceBundle,
      state_transitions: [
        { ...stateEvidence[0], effective_at: 125 },
        ...stateEvidence.slice(1),
      ],
    };
    const graftedCompletion = signRecoveryCompletion({
      ...completionUnsigned,
      evidence_bundle_digest: compromiseResetEvidenceBundleDigest(graftedBundle),
    });
    expect(validateReset({
      completion: graftedCompletion,
      authoritative_evidence: {
        ...authoritativeEvidence,
        evidence_bundle: graftedBundle,
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("rejects a grafted MLS Remove/Commit carrier not signed by the prior-group verifier", () => {
    const { signature: _signature, ...completionUnsigned } = completion;
    const graftedBundle = {
      ...evidenceBundle,
      group_commits: [{
        ...groupCommit,
        next_state_digest: rid(13),
      }],
    };
    const graftedCompletion = signRecoveryCompletion({
      ...completionUnsigned,
      evidence_bundle_digest: compromiseResetEvidenceBundleDigest(graftedBundle),
    });
    expect(validateReset({
      completion: graftedCompletion,
      authoritative_evidence: {
        ...authoritativeEvidence,
        evidence_bundle: graftedBundle,
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("verifies the canonical NIP-01 id and BIP-340 signature of successor KeyPackages", () => {
    const { signature: _signature, ...completionUnsigned } = completion;
    const invalidPackage = {
      ...freshKeyPackage,
      event: { ...freshKeyPackage.event, id: rid(99) },
      event_id: rid(99),
    };
    const invalidCompletion = signRecoveryCompletion({
      ...completionUnsigned,
      fresh_keypackages: [invalidPackage],
    });
    expect(validateReset({
      completion: invalidCompletion,
      authoritative_evidence: {
        ...authoritativeEvidence,
        fresh_keypackages: [invalidPackage],
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("rejects nonstandard or extra kind-30443 transport tags", () => {
    const nonstandardPackage = signedFreshKeyPackage(
      freshKeyPackage.keypackage_id,
      [...keyPackageEvent.tags, ["encoding", "base64"]],
    );
    const { signature: _signature, ...completionUnsigned } = completion;
    const nonstandardCompletion = signRecoveryCompletion({
      ...completionUnsigned,
      fresh_keypackages: [nonstandardPackage],
    });
    expect(validateReset({
      completion: nonstandardCompletion,
      authoritative_evidence: {
        ...authoritativeEvidence,
        fresh_keypackages: [nonstandardPackage],
      },
    })).toEqual({
      verdict: "reject",
      reason_code: "control-compromise-reset-evidence-invalid",
    });
  });

  it("derives prior KeyPackage ids from authoritative leaves and rejects reuse", () => {
    const reusedPackage = signedFreshKeyPackage(rid(35));
    const reusedCommitUnsigned = {
      ...commitUnsigned,
      successor_leaves: commitUnsigned.successor_leaves.map((leaf) => ({
        ...leaf,
        keypackage_id: rid(35),
      })),
    };
    const reusedCommit = {
      ...reusedCommitUnsigned,
      verification_signature: bytesToHex(schnorr.sign(
        mlsCommitEvidenceProofBytes(reusedCommitUnsigned),
        hexToBytes(assuranceSecret),
        "00".repeat(32),
      )),
    };
    const reusedBundle = {
      ...evidenceBundle,
      group_commits: [reusedCommit],
    };
    const { signature: _signature, ...completionUnsigned } = completion;
    const reusedCompletion = signRecoveryCompletion({
      ...completionUnsigned,
      fresh_keypackages: [reusedPackage],
      evidence_bundle_digest: compromiseResetEvidenceBundleDigest(reusedBundle),
    });
    expect(validateReset({
      completion: reusedCompletion,
      authoritative_evidence: {
        ...authoritativeEvidence,
        fresh_keypackages: [reusedPackage],
        evidence_bundle: reusedBundle,
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
