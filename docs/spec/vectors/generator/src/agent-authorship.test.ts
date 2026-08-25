import { describe, expect, it } from "vitest";
import { schnorr } from "@noble/curves/secp256k1";
import {
  deriveAgentIdentity,
  injectAgentAttribution,
  matchesAgentAttributionProfile,
  validateAgentAccessToken,
  validateWorkloadRegistration,
  type AgentTokenValidationInput,
} from "./agent-authorship.js";
import * as agentAuthorship from "./agent-authorship.js";
import {
  getEventId,
  getPublicKey,
  signEvent,
  type NostrSignedEvent,
  type NostrUnsignedEvent,
} from "./nostr.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { AUX_RAND } from "./vector-helpers.js";

const coldRoot = "11".repeat(32);
const roleId = "ab".repeat(32);
const publishingKey = "33".repeat(32);
const issuer = "https://issuer.example/oidc/npub1persona";
const audience = "https://node.example/control/agent-publication";
const subjectJkt = "A".repeat(43);
const malformedAssociations: unknown[] = [null, [], "key", { kind: "role" }];

describe("workload registration and stable identity", () => {
  const registration = {
    persona_key: coldRoot,
    client_id: "agent-client",
    subject_jkt: subjectJkt,
    subject_proof: { method: "dpop", jkt: subjectJkt },
    agent_class: "ai",
    selected_signer: publishingKey,
    signer_key_class: "agent",
    agent_association: { kind: "key", value: publishingKey },
    audience,
    scopes: ["heterodyne:agent:publish"],
    allowed_kinds: [1, 30023],
    allowed_feeds: ["main"],
    allowed_resources: ["feed:main"],
    max_content_bytes: 4096,
    rate_limit: { window_seconds: 60, count: 20, burst: 5 },
    not_before: 1_000,
    expires_at: 2_000,
  };

  it("accepts an agent-key signer bound to one persona, subject proof, and finite authority", () => {
    expect(validateWorkloadRegistration(registration)).toEqual(registration);
  });

  it("permits persona-key signing only under the explicit OIDC scope", () => {
    const personaSigner = {
      ...registration,
      selected_signer: coldRoot,
      signer_key_class: "persona",
      scopes: ["heterodyne:agent:publish", "heterodyne:agent:sign:persona"],
    };
    expect(validateWorkloadRegistration(personaSigner)).toEqual(personaSigner);
    expect(() => validateWorkloadRegistration({
      ...personaSigner,
      scopes: ["heterodyne:agent:publish"],
    })).toThrow(/agent-workload-registration-invalid/);
  });

  it("rejects signer, proof, authority, legacy delegation, or shape-invalid registrations", () => {
    for (const value of [
      { ...registration, scopes: [] },
      { ...registration, max_content_bytes: 0 },
      { ...registration, rate_limit: { ...registration.rate_limit, count: 0 } },
      { ...registration, selected_signer: "zz".repeat(32) },
      { ...registration, subject_proof: { method: "dpop", jkt: "B".repeat(43) } },
      { ...registration, proof_bytes: "legacy-delegation-proof" },
      { ...registration, expires_at: registration.not_before },
      { ...registration, unlimited: true },
      ...malformedAssociations.map((agent_association) => ({
        ...registration,
        agent_association,
      })),
    ]) {
      expect(() => validateWorkloadRegistration(value)).toThrow(
        /agent-workload-registration-invalid/,
      );
    }
  });

  it("keeps one persona's tuple stable across renewal and unlinkable across personas", () => {
    const first = deriveAgentIdentity(
      coldRoot,
      "https://sector.example",
      "55".repeat(32),
      issuer,
      "agent-client",
    );
    const renewed = deriveAgentIdentity(
      coldRoot,
      "https://sector.example",
      "55".repeat(32),
      issuer,
      "agent-client",
    );
    const otherPersona = deriveAgentIdentity(
      "66".repeat(32),
      "https://sector.example",
      "77".repeat(32),
      "https://other.example/oidc/npub1other",
      "agent-client",
    );
    expect(renewed).toEqual(first);
    expect(otherPersona.sub).not.toBe(first.sub);
  });
});

describe("agent workload access token", () => {
  const valid: AgentTokenValidationInput = {
    typ: "at+jwt",
    credential_ledger_persona: coldRoot,
    credential_ledger_generation: 0,
    expected_credential_ledger_persona: coldRoot,
    expected_credential_ledger_generation: 0,
    iss: issuer,
    sub: "stable-pairwise-sub",
    aud: [audience],
    exp: 1_250,
    iat: 1_000,
    jti: "token-1",
    client_id: "agent-client",
    scope: "heterodyne:agent:publish",
    cnf_jkt: subjectJkt,
    sender_proof_jkt: subjectJkt,
    sender_proof_valid: true,
    signer_key: publishingKey,
    signer_key_class: "agent",
    agent_association: { kind: "role", value: roleId },
    expected_issuer: issuer,
    expected_subject: "stable-pairwise-sub",
    expected_audience: audience,
    expected_client_id: "agent-client",
    expected_scope: "heterodyne:agent:publish",
    expected_signer_key: publishingKey,
    expected_signer_key_class: "agent",
    expected_agent_association: { kind: "role", value: roleId },
    now: 1_100,
    status: "VALID",
    ledger_active: true,
    ledger_binding_valid: true,
    status_binding_valid: true,
    session_expires_at: 1_300,
    delegation_expires_at: 1_300,
    registration_expires_at: 1_300,
    consent_expires_at: 1_300,
    source_authorization_expires_at: 1_300,
  };

  it("accepts one exact audience, normalized scope, cnf proof, active status, and five-minute cap", () => {
    expect(validateAgentAccessToken(valid)).toEqual({
      verdict: "accept",
      identity: {
        issuer,
        sub: "stable-pairwise-sub",
        client_id: "agent-client",
        signer: publishingKey,
        key_class: "agent",
        agent_association: { kind: "role", value: roleId },
      },
    });
  });

  it("accepts an explicitly scoped persona signer without inventing an agent role", () => {
    const scope = "heterodyne:agent:publish heterodyne:agent:sign:persona";
    expect(validateAgentAccessToken({
      ...valid,
      scope,
      expected_scope: scope,
      signer_key: coldRoot,
      expected_signer_key: coldRoot,
      signer_key_class: "persona",
      expected_signer_key_class: "persona",
      agent_association: undefined,
      expected_agent_association: undefined,
    })).toEqual({
      verdict: "accept",
      identity: {
        issuer,
        sub: "stable-pairwise-sub",
        client_id: "agent-client",
        signer: coldRoot,
        key_class: "persona",
      },
    });
  });

  it("rejects invalid token state, association mismatch, or legacy delegation proof", () => {
    const cases: Array<[Partial<AgentTokenValidationInput>, string]> = [
      [{ typ: "JWT" }, "agent-token-invalid"],
      [{ exp: 1_301 }, "agent-token-invalid"],
      [{ now: 1_251 }, "agent-token-invalid"],
      [{ status: "INVALID" }, "agent-token-invalid"],
      [{ aud: [audience, "https://other.example"] }, "agent-token-invalid"],
      [{ scope: "heterodyne:agent:publish extra" }, "agent-token-invalid"],
      [{ sender_proof_valid: false }, "agent-sender-proof-invalid"],
      [{ sender_proof_jkt: "B".repeat(43) }, "agent-sender-proof-invalid"],
      [{ signer_key: "44".repeat(32) }, "agent-signer-mismatch"],
      [{ signer_key_class: "persona" }, "agent-signer-mismatch"],
      [{
        scope: "heterodyne:agent:publish heterodyne:agent:sign:persona",
        expected_scope: "heterodyne:agent:publish heterodyne:agent:sign:persona",
        signer_key: coldRoot,
        expected_signer_key: coldRoot,
        signer_key_class: "persona",
        expected_signer_key_class: "persona",
        agent_association: { kind: "key", value: publishingKey },
        expected_agent_association: { kind: "key", value: "44".repeat(32) },
      }, "agent-signer-mismatch"],
      [{ proof_bytes: "legacy-delegation-proof" } as Partial<AgentTokenValidationInput>,
        "agent-token-invalid"],
      [{ ledger_active: false }, "agent-token-invalid"],
      [{ expected_credential_ledger_generation: 1 }, "credential_generation_stale"],
    ];
    for (const [patch, reason_code] of cases) {
      expect(validateAgentAccessToken({ ...valid, ...patch })).toEqual({
        verdict: "reject",
        reason_code,
      });
    }
  });

  it("fails malformed untrusted association claims closed without throwing", () => {
    for (const agent_association of malformedAssociations) {
      expect(validateAgentAccessToken({
        ...valid,
        agent_association,
      })).toEqual({
        verdict: "reject",
        reason_code: "agent-signer-mismatch",
      });
    }
  });
});

describe("canonical agent attribution", () => {
  const base = {
    kind: 1,
    tags: [
      ["client", "heterodyne"],
      ["heterodyne_agent", "v1", "forged", "forged", "forged", "44".repeat(32)],
      ["agent_action", "human"],
    ],
    agent_class: "ai" as const,
    persona: coldRoot,
    issuer,
    subject: "stable-pairwise-sub",
    client_id: "agent-client",
    signer: publishingKey,
    expected_signer: publishingKey,
    signer_key_class: "agent" as const,
    oidc_scopes: ["heterodyne:agent:publish"],
    agent_association: { kind: "key" as const, value: publishingKey },
    expected_agent_association: { kind: "key" as const, value: publishingKey },
    tier: 1 as const,
  };
  const canonicalTags = [
    ["L", "network.heterodyne.agent"],
    ["l", "ai", "network.heterodyne.agent"],
    ["heterodyne_agent", "v1", "key", publishingKey],
    ["agent_action", "publish"],
  ];

  it("removes caller forgery, inserts public-safe attribution, and keeps the signer authoritative", () => {
    expect(injectAgentAttribution(base)).toEqual({
      verdict: "accept",
      tags: [["client", "heterodyne"], ...canonicalTags],
      placement: "public",
      author: publishingKey,
    });
    const result = injectAgentAttribution(base);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(issuer);
    expect(serialized).not.toContain("stable-pairwise-sub");
    expect(serialized).not.toContain("agent-client");
  });

  it("keeps verified human review optional without changing agent classification", () => {
    const result = injectAgentAttribution({
      ...base,
      agent_review: "approved-by-human",
      agent_review_verified: true,
    });
    expect(result).toMatchObject({ verdict: "accept", placement: "public" });
    expect(result.verdict === "accept" && result.tags).toEqual([
      ["client", "heterodyne"],
      ...canonicalTags,
      ["agent_review", "approved-by-human"],
    ]);
  });

  it("puts Tier 3 attribution only in the encrypted logical event", () => {
    expect(injectAgentAttribution({ ...base, tier: 3 })).toMatchObject({
      verdict: "accept",
      placement: "encrypted-inner",
      clear_outer_tags: [],
    });
  });

  it("allows persona-key authorship only under explicit scope and keeps automation visible", () => {
    const personaSigned = injectAgentAttribution({
      ...base,
      signer: coldRoot,
      expected_signer: coldRoot,
      signer_key_class: "persona",
      oidc_scopes: ["heterodyne:agent:publish", "heterodyne:agent:sign:persona"],
    });
    expect(personaSigned).toMatchObject({ verdict: "accept", author: coldRoot });
    expect(personaSigned.verdict === "accept" && personaSigned.tags).toContainEqual(
      ["l", "ai", "network.heterodyne.agent"],
    );
    expect(injectAgentAttribution({
      ...base,
      signer: coldRoot,
      expected_signer: coldRoot,
      signer_key_class: "persona",
    })).toEqual({ verdict: "reject", reason_code: "agent-persona-scope-required" });
  });

  it("keeps the Heterodyne association optional without weakening the NIP-32 label", () => {
    const result = injectAgentAttribution({
      ...base,
      signer: coldRoot,
      expected_signer: coldRoot,
      signer_key_class: "persona",
      oidc_scopes: ["heterodyne:agent:publish", "heterodyne:agent:sign:persona"],
      agent_association: undefined,
      expected_agent_association: undefined,
    });
    expect(result).toMatchObject({
      verdict: "accept",
      tags: [
        ["client", "heterodyne"],
        ["L", "network.heterodyne.agent"],
        ["l", "ai", "network.heterodyne.agent"],
        ["agent_action", "publish"],
      ],
    });
  });

  it("requires the canonical attribution block to be contiguous in the original tag list", () => {
    const prefix = [["client", "heterodyne"]];
    const suffix = [["p", "55".repeat(32)]];
    expect(matchesAgentAttributionProfile([...prefix, ...canonicalTags, ...suffix])).toBe(true);
    expect(matchesAgentAttributionProfile([
      canonicalTags[0],
      ["client", "interleaved"],
      ...canonicalTags.slice(1),
    ])).toBe(false);
    expect(matchesAgentAttributionProfile([
      ...canonicalTags.slice(0, 2),
      ["p", "55".repeat(32)],
      ...canonicalTags.slice(2),
    ])).toBe(false);
    expect(matchesAgentAttributionProfile([
      ...canonicalTags.slice(0, 3),
      ["e", "66".repeat(32)],
      canonicalTags[3],
    ])).toBe(false);
  });

  it("fails malformed publication associations closed without throwing", () => {
    for (const agent_association of malformedAssociations) {
      expect(injectAgentAttribution({
        ...base,
        agent_association,
      })).toEqual({
        verdict: "reject",
        reason_code: "agent-signer-mismatch",
      });
    }
  });

  it("rejects unsupported kinds, mismatches, post-sign input, and legacy proof without fallback", () => {
    expect(injectAgentAttribution({ ...base, kind: 31007 })).toEqual({
      verdict: "reject",
      reason_code: "agent-attribution-profile-unavailable",
    });
    expect(injectAgentAttribution({ ...base, signer: "44".repeat(32) })).toEqual({
      verdict: "reject",
      reason_code: "agent-signer-mismatch",
    });
    expect(injectAgentAttribution({
      ...base,
      signer: coldRoot,
      expected_signer: coldRoot,
      signer_key_class: "persona",
      oidc_scopes: ["heterodyne:agent:publish", "heterodyne:agent:sign:persona"],
      agent_association: { kind: "role", value: roleId },
    })).toEqual({ verdict: "reject", reason_code: "agent-signer-mismatch" });
    expect(injectAgentAttribution({
      ...base,
      proof_bytes: "legacy-delegation-proof",
      key_proof_valid: true,
    } as typeof base)).toEqual({
      verdict: "reject",
      reason_code: "agent-attribution-invalid",
    });
    expect(injectAgentAttribution({ ...base, sig: "55".repeat(64) } as typeof base)).toEqual({
      verdict: "reject",
      reason_code: "agent-attribution-invalid",
    });
  });
});

describe("atomic Comms signed publication for Social", () => {
  const agentSecret = "17".repeat(32);
  const agentKey = getPublicKey(agentSecret);
  const association = { kind: "key" as const, value: agentKey };
  const registration = {
    persona_key: coldRoot,
    client_id: "social-agent-client",
    subject_jkt: subjectJkt,
    subject_proof: { method: "dpop", jkt: subjectJkt },
    agent_class: "ai" as const,
    selected_signer: agentKey,
    signer_key_class: "agent" as const,
    agent_association: association,
    audience,
    scopes: ["heterodyne:agent:publish"],
    allowed_kinds: [1],
    allowed_feeds: ["main"],
    allowed_resources: ["feed:main"],
    max_content_bytes: 4096,
    rate_limit: { window_seconds: 60, count: 20, burst: 5 },
    not_before: 900,
    expires_at: 1_300,
  };
  const token: AgentTokenValidationInput = {
    typ: "at+jwt",
    credential_ledger_persona: coldRoot,
    credential_ledger_generation: 0,
    expected_credential_ledger_persona: coldRoot,
    expected_credential_ledger_generation: 0,
    iss: issuer,
    sub: "social-pairwise-sub",
    aud: [audience],
    exp: 1_250,
    iat: 1_000,
    jti: "social-token-1",
    client_id: registration.client_id,
    scope: "heterodyne:agent:publish",
    cnf_jkt: subjectJkt,
    sender_proof_jkt: subjectJkt,
    sender_proof_valid: true,
    signer_key: agentKey,
    signer_key_class: "agent",
    agent_association: association,
    expected_issuer: issuer,
    expected_subject: "social-pairwise-sub",
    expected_audience: audience,
    expected_client_id: registration.client_id,
    expected_scope: "heterodyne:agent:publish",
    expected_signer_key: agentKey,
    expected_signer_key_class: "agent",
    expected_agent_association: association,
    now: 1_100,
    status: "VALID",
    ledger_active: true,
    ledger_binding_valid: true,
    status_binding_valid: true,
    session_expires_at: 1_300,
    delegation_expires_at: 1_300,
    registration_expires_at: 1_300,
    consent_expires_at: 1_300,
    source_authorization_expires_at: 1_300,
  };

  const intent: NostrUnsignedEvent = {
    pubkey: agentKey,
    created_at: 1_100,
    kind: 1,
    tags: [["t", "nostr"]],
    content: "authorized Social automation",
  };

  type AtomicApi = typeof agentAuthorship & {
    createCommsSocialPublicationAuthority?: (input: {
      trusted_now: () => number;
      signer_execution: {
        executeOnce: (
          executionToken: string,
          event: NostrUnsignedEvent,
          requestDigest: string,
        ) => { verdict: "accept"; disposition: "executed" | "cached"; event: NostrSignedEvent };
      };
    }) => object;
    signCommsSocialPublication?: (input: {
      authority: object;
      registration: unknown;
      token: AgentTokenValidationInput;
      represented_persona: string;
      event: NostrUnsignedEvent;
      requested_feed: string;
      requested_resource: string;
      execution_token: string;
      request_digest: string;
    }) => { verdict: "accept"; event: NostrSignedEvent; publication: object } | {
      verdict: "reject";
      reason_code: string;
    };
  };

  function signerExecution(
    signer: (event: NostrUnsignedEvent) => NostrSignedEvent = signNostrEvent,
  ) {
    return {
      executeOnce: (_token: string, event: NostrUnsignedEvent, _digest: string) => ({
        verdict: "accept" as const,
        disposition: "executed" as const,
        event: signer(event),
      }),
    };
  }

  function atomicInput(authority: object, overrides: Record<string, unknown> = {}) {
    return {
      authority,
      registration,
      token,
      represented_persona: coldRoot,
      event: intent,
      requested_feed: "main",
      requested_resource: "feed:main",
      execution_token: "aa".repeat(32),
      request_digest: "bb".repeat(32),
      ...overrides,
    };
  }

  it("fixes attribution before one execution and verifies the immutable signed result", () => {
    const api = agentAuthorship as AtomicApi;
    let signerCalls = 0;
    let received: NostrUnsignedEvent | undefined;
    const authority = api.createCommsSocialPublicationAuthority?.({
      trusted_now: () => 1_101,
      signer_execution: signerExecution((event) => {
        signerCalls += 1;
        received = event;
        expect(Object.isFrozen(event)).toBe(true);
        expect(Object.isFrozen(event.tags)).toBe(true);
        return signNostrEvent(event);
      }),
    });
    const result = authority === undefined
      ? undefined
      : api.signCommsSocialPublication?.(atomicInput(authority));
    expect(result).toMatchObject({
      verdict: "accept",
      event: { id: expect.stringMatching(/^[0-9a-f]{64}$/) },
      publication: expect.any(Object),
    });
    expect(signerCalls).toBe(1);
    expect(received).toEqual({
      ...intent,
      tags: [
        ["t", "nostr"],
        ["L", "network.heterodyne.agent"],
        ["l", "ai", "network.heterodyne.agent"],
        ["heterodyne_agent", "v1", "key", agentKey],
        ["agent_action", "publish"],
      ],
    });
  });

  it("captures the embedding execute-once method when the authority is created", () => {
    const api = agentAuthorship as AtomicApi;
    let originalCalls = 0;
    let replacementCalls = 0;
    const execution = signerExecution((event) => {
      originalCalls += 1;
      return signNostrEvent(event);
    });
    const authority = api.createCommsSocialPublicationAuthority?.({
      trusted_now: () => 1_101,
      signer_execution: execution,
    });
    execution.executeOnce = (_token, event, _digest) => {
      replacementCalls += 1;
      return {
        verdict: "accept",
        disposition: "executed",
        event: signNostrEvent({ ...event, content: "replacement method" }),
      };
    };
    const result = authority === undefined
      ? undefined
      : api.signCommsSocialPublication?.(atomicInput(authority));
    expect(result).toMatchObject({ verdict: "accept" });
    expect(originalCalls).toBe(1);
    expect(replacementCalls).toBe(0);
  });

  it("rejects stale current state before invoking the signer", () => {
    const api = agentAuthorship as AtomicApi;
    let signerCalls = 0;
    const execution = signerExecution((event) => {
      signerCalls += 1;
      return signNostrEvent(event);
    });
    const authority = api.createCommsSocialPublicationAuthority?.({
      trusted_now: () => 1_250,
      signer_execution: execution,
    });
    const result = authority === undefined
      ? undefined
      : api.signCommsSocialPublication?.(atomicInput(authority));
    expect(result).toEqual({ verdict: "reject", reason_code: "agent-signer-mismatch" });
    const currentAuthority = api.createCommsSocialPublicationAuthority?.({
      trusted_now: () => 1_101,
      signer_execution: execution,
    });
    if (currentAuthority === undefined) throw new Error("publication authority missing");
    for (const override of [
      { registration: { ...registration, audience: "https://other.example/" } },
      {
        registration: {
          ...registration,
          subject_jkt: "B".repeat(43),
          subject_proof: { method: "dpop" as const, jkt: "B".repeat(43) },
        },
      },
      { requested_feed: "other" },
      { token: { ...token, status: "SUSPENDED" as const } },
      { token: { ...token, expected_credential_ledger_generation: 1 } },
    ]) {
      expect(api.signCommsSocialPublication?.(atomicInput(currentAuthority, override)))
        .toEqual({ verdict: "reject", reason_code: "agent-signer-mismatch" });
    }
    expect(signerCalls).toBe(0);
  });

  it("cannot mint from a signed event by stripping after the fact", async () => {
    const api = agentAuthorship as AtomicApi;
    let signerCalls = 0;
    const authority = api.createCommsSocialPublicationAuthority?.({
      trusted_now: () => 1_101,
      signer_execution: signerExecution((event) => {
        signerCalls += 1;
        return signNostrEvent(event);
      }),
    });
    const alreadySigned = await signEvent({
      secretKey: agentSecret,
      created_at: intent.created_at,
      kind: intent.kind,
      tags: intent.tags,
      content: intent.content,
      auxRand: AUX_RAND,
    });
    const result = authority === undefined
      ? undefined
      : api.signCommsSocialPublication?.(atomicInput(authority, { event: alreadySigned }));
    expect(result).toEqual({ verdict: "reject", reason_code: "agent-signer-mismatch" });
    expect(signerCalls).toBe(0);
  });

  it("rejects a signer result that differs from the fixed attributed bytes", () => {
    const api = agentAuthorship as AtomicApi;
    const authority = api.createCommsSocialPublicationAuthority?.({
      trusted_now: () => 1_101,
      signer_execution: signerExecution((event) => signNostrEvent({
        ...event,
        content: "substituted after authorization",
      })),
    });
    const result = authority === undefined
      ? undefined
      : api.signCommsSocialPublication?.(atomicInput(authority));
    expect(result).toEqual({ verdict: "reject", reason_code: "agent-signer-mismatch" });
  });

  it("rejects an accessor that substitutes event B after validating event A", () => {
    const api = agentAuthorship as AtomicApi;
    let eventReads = 0;
    const authority = api.createCommsSocialPublicationAuthority?.({
      trusted_now: () => 1_101,
      signer_execution: {
        executeOnce: (_token, event, _digest) => {
          const valid = signNostrEvent(event);
          const substituted = signNostrEvent({
            ...event,
            content: "event B returned after event A validation",
          });
          return Object.defineProperty({
            verdict: "accept" as const,
            disposition: "executed" as const,
          }, "event", {
            enumerable: true,
            get() {
              eventReads += 1;
              return eventReads <= 7 ? valid : substituted;
            },
          }) as unknown as {
            verdict: "accept";
            disposition: "executed";
            event: NostrSignedEvent;
          };
        },
      },
    });
    const result = authority === undefined
      ? undefined
      : api.signCommsSocialPublication?.(atomicInput(authority));
    expect(result).toEqual({ verdict: "reject", reason_code: "agent-signer-mismatch" });
    expect(eventReads).toBe(0);
  });

  it("rejects open or non-data signer result trees", () => {
    const api = agentAuthorship as AtomicApi;
    let nestedGetterCalls = 0;
    const validOutcome = (event: NostrUnsignedEvent) => ({
      verdict: "accept" as const,
      disposition: "executed" as const,
      event: signNostrEvent(event),
    });
    const cases: Array<(event: NostrUnsignedEvent) => unknown> = [
      (event) => ({ ...validOutcome(event), extra: true }),
      (event) => Object.assign(validOutcome(event), { [Symbol("extra")]: true }),
      (event) => {
        const outcome = validOutcome(event);
        const tags = [...outcome.event.tags];
        delete tags[0];
        return { ...outcome, event: { ...outcome.event, tags } };
      },
      (event) => {
        const outcome = validOutcome(event);
        const accessorEvent = { ...outcome.event } as Record<string, unknown>;
        Object.defineProperty(accessorEvent, "content", {
          enumerable: true,
          get() {
            nestedGetterCalls += 1;
            return event.content;
          },
        });
        return { ...outcome, event: accessorEvent };
      },
    ];
    for (const createOutcome of cases) {
      const authority = api.createCommsSocialPublicationAuthority?.({
        trusted_now: () => 1_101,
        signer_execution: {
          executeOnce: (_token, event, _digest) => {
            return createOutcome(event) as {
              verdict: "accept";
              disposition: "executed";
              event: NostrSignedEvent;
            };
          },
        },
      });
      const result = authority === undefined
        ? undefined
        : api.signCommsSocialPublication?.(atomicInput(authority));
      expect(result).toEqual({ verdict: "reject", reason_code: "agent-signer-mismatch" });
    }
    expect(nestedGetterCalls).toBe(0);
  });
});

function signNostrEvent(event: NostrUnsignedEvent): NostrSignedEvent {
  const id = getEventId(event);
  return {
    ...event,
    id,
    sig: bytesToHex(schnorr.sign(id, hexToBytes("17".repeat(32)), AUX_RAND)),
  };
}
