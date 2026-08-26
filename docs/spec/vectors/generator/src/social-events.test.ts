import { beforeAll, describe, expect, it } from "vitest";
import {
  createCommsSocialPublicationAuthority,
  signCommsSocialPublication,
  type AgentTokenValidationInput,
  type CommsSocialPublicationAuthority,
  type CommsSocialSignedPublication,
} from "./agent-authorship.js";
import { schnorr } from "@noble/curves/secp256k1";
import {
  getPublicKey,
  getEventId,
  signEvent,
  type NostrSignedEvent,
  type NostrUnsignedEvent,
} from "./nostr.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import { AUX_RAND } from "./vector-helpers.js";

type AgentAssociation = { kind: "key" | "role"; value: string };
type SocialEventsModule = {
  createSocialAuthorshipValidator?: (input: {
    publication_authority: CommsSocialPublicationAuthority;
  }) => (input: {
    event: NostrSignedEvent;
    persona_active_key?: string;
    comms_authorization?: CommsSocialSignedPublication;
    requested_feed?: string;
    requested_resource?: string;
  }) => {
    verdict: "accept" | "reject";
    event_author?: string;
    represented_persona?: string;
    agent_association?: AgentAssociation;
    reason_code?: string;
  };
  validateSocialAuthorship?: (input: {
    event: NostrSignedEvent;
    persona_active_key?: string;
    comms_authorization?: CommsSocialSignedPublication;
    requested_feed?: string;
    requested_resource?: string;
    comms_authorized_signers?: Array<{
      pubkey: string;
      agent_association: AgentAssociation | null;
    }>;
  }) => {
    verdict: "accept" | "reject";
    event_author?: string;
    represented_persona?: string;
    agent_association?: AgentAssociation;
    reason_code?: string;
  };
  selectCurrentSocialEvent?: (input: {
    coordinate: { pubkey: string; kind: number; d?: string };
    candidates: Array<{
      carrier: "relay" | "repository";
      event: NostrSignedEvent;
    }>;
  }) => NostrSignedEvent | null;
  validateSocialReplaceableCandidate?: (input: {
    coordinate: { pubkey: string; kind: number; d?: string };
    event: NostrSignedEvent;
  }) => {
    verdict: "accept" | "reject";
    reason_code?: string;
  };
  assessSocialStateFreshness?: (
    event: NostrSignedEvent,
    now: number,
  ) => { valid: boolean; warning: "stale" | null };
};

async function loadSocialEvents(): Promise<SocialEventsModule> {
  return await import("./social-events.js").catch(() => ({}));
}

function unsigned(event: NostrSignedEvent): NostrUnsignedEvent {
  return {
    pubkey: event.pubkey,
    created_at: event.created_at,
    kind: event.kind,
    tags: event.tags,
    content: event.content,
  };
}

function publicationFor(
  event: NostrSignedEvent,
  agentAssociation: AgentAssociation | null,
  publicationAuthority?: CommsSocialPublicationAuthority,
): {
  event: NostrSignedEvent;
  comms_authorization: CommsSocialSignedPublication;
  publication_authority: CommsSocialPublicationAuthority;
  requested_feed: string;
  requested_resource: string;
} {
  const jkt = "A".repeat(43);
  const audience = "https://node.example/control/social-publication";
  const registration = {
    persona_key: personaKey,
    client_id: "social-agent-client",
    subject_jkt: jkt,
    subject_proof: { method: "dpop", jkt },
    agent_class: event.tags.some((tag) => tag[0] === "l" && tag[1] === "programmatic")
      ? "programmatic" as const
      : "ai" as const,
    selected_signer: event.pubkey,
    signer_key_class: "agent" as const,
    ...(agentAssociation === null ? {} : { agent_association: agentAssociation }),
    audience,
    scopes: ["heterodyne:agent:publish"],
    allowed_kinds: [event.kind],
    allowed_feeds: ["main"],
    allowed_resources: ["feed:main"],
    max_content_bytes: 4096,
    rate_limit: { window_seconds: 60, count: 20, burst: 5 },
    not_before: event.created_at - 10,
    expires_at: event.created_at + 200,
  };
  const token: AgentTokenValidationInput = {
    typ: "at+jwt",
    credential_ledger_persona: personaKey,
    credential_ledger_generation: 0,
    expected_credential_ledger_persona: personaKey,
    expected_credential_ledger_generation: 0,
    iss: "https://issuer.example/oidc/social",
    sub: "social-pairwise-sub",
    aud: [audience],
    exp: event.created_at + 100,
    iat: event.created_at - 1,
    jti: `social-${event.id}`,
    client_id: registration.client_id,
    scope: "heterodyne:agent:publish",
    cnf_jkt: jkt,
    sender_proof_jkt: jkt,
    sender_proof_valid: true,
    signer_key: event.pubkey,
    signer_key_class: "agent",
    ...(agentAssociation === null ? {} : { agent_association: agentAssociation }),
    expected_issuer: "https://issuer.example/oidc/social",
    expected_subject: "social-pairwise-sub",
    expected_audience: audience,
    expected_client_id: registration.client_id,
    expected_scope: "heterodyne:agent:publish",
    expected_signer_key: event.pubkey,
    expected_signer_key_class: "agent",
    ...(agentAssociation === null ? {} : { expected_agent_association: agentAssociation }),
    now: event.created_at,
    status: "VALID",
    ledger_active: true,
    ledger_binding_valid: true,
    status_binding_valid: true,
    session_expires_at: registration.expires_at,
    delegation_expires_at: registration.expires_at,
    registration_expires_at: registration.expires_at,
    consent_expires_at: registration.expires_at,
    source_authorization_expires_at: registration.expires_at,
  };
  const authority = publicationAuthority ?? createCommsSocialPublicationAuthority({
    trusted_now: () => event.created_at + 1,
    signer_execution: {
      executeOnce: (_executionToken, unsignedEvent, _requestDigest) => ({
        verdict: "accept",
        disposition: "executed",
        event: signAgentEvent(unsignedEvent),
      }),
    },
  });
  const result = signCommsSocialPublication({
    authority,
    registration,
    token,
    represented_persona: personaKey,
    event: {
      ...unsigned(event),
      tags: event.tags.filter((tag) =>
        !["L", "l", "heterodyne_agent", "agent_action", "agent_review"].includes(tag[0])),
    },
    requested_feed: "main",
    requested_resource: "feed:main",
    execution_token: event.id,
    request_digest: "bb".repeat(32),
  });
  if (result.verdict !== "accept") throw new Error(result.reason_code);
  // Later mutable-state revocation cannot retroactively change this signed result.
  token.status = "SUSPENDED";
  return {
    event: result.event,
    comms_authorization: result.publication,
    publication_authority: authority,
    requested_feed: "main",
    requested_resource: "feed:main",
  };
}

const personaSecret = "15".repeat(32);
const personaKey = getPublicKey(personaSecret);
const agentSecret = "16".repeat(32);
const agentKey = getPublicKey(agentSecret);
const association = { kind: "key", value: agentKey } as const;
let bareReply: NostrSignedEvent;
let profileState: NostrSignedEvent;
let directOrganizationPost: NostrSignedEvent;
let attributedAgentPost: NostrSignedEvent;

beforeAll(async () => {
  bareReply = await signEvent({
    secretKey: personaSecret,
    created_at: 1_000,
    kind: 1,
    tags: [
      ["e", "21".repeat(32), "wss://relay.example/", "root"],
      ["p", "22".repeat(32)],
    ],
    content: "ordinary NIP-10 reply",
    auxRand: AUX_RAND,
  });
  profileState = await signEvent({
    secretKey: personaSecret,
    created_at: 1_000,
    kind: 0,
    tags: [],
    content: JSON.stringify({ name: "example" }),
    auxRand: AUX_RAND,
  });
  directOrganizationPost = await signEvent({
    secretKey: personaSecret,
    created_at: 1_001,
    kind: 1,
    tags: [],
    content: "organization post",
    auxRand: AUX_RAND,
  });
  attributedAgentPost = await signEvent({
    secretKey: agentSecret,
    created_at: 1_002,
    kind: 1,
    tags: [
      ["L", "network.heterodyne.agent"],
      ["l", "ai", "network.heterodyne.agent"],
      ["heterodyne_agent", "v1", association.kind, association.value],
      ["agent_action", "publish"],
    ],
    content: "attributed organization automation",
    auxRand: AUX_RAND,
  });
});

describe("ordinary Social authorship", () => {
  it("rejects an automated proof minted by a different backdated authority", async () => {
    const social = await loadSocialEvents();
    const expectedAuthority = createCommsSocialPublicationAuthority({
      trusted_now: () => attributedAgentPost.created_at + 1,
      signer_execution: {
        executeOnce: (_token, event, _digest) => ({
          verdict: "accept",
          disposition: "executed",
          event: signAgentEvent(event),
        }),
      },
    });
    const attackerAuthority = createCommsSocialPublicationAuthority({
      trusted_now: () => attributedAgentPost.created_at,
      signer_execution: {
        executeOnce: (_token, event, _digest) => ({
          verdict: "accept",
          disposition: "executed",
          event: signAgentEvent(event),
        }),
      },
    });
    const validate = social.createSocialAuthorshipValidator?.({
      publication_authority: expectedAuthority,
    });
    expect(validate).toBeTypeOf("function");
    const attackerPublication = publicationFor(
      attributedAgentPost,
      association,
      attackerAuthority,
    );
    expect(validate?.({
      persona_active_key: personaKey,
      ...attackerPublication,
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });
    const expectedPublication = publicationFor(
      attributedAgentPost,
      association,
      expectedAuthority,
    );
    expect(validate?.({
      persona_active_key: personaKey,
      ...expectedPublication,
    })).toMatchObject({ verdict: "accept" });
  });

  it("accepts a valid bare-key NIP-10 event without Assurance or KEL context", async () => {
    const social = await loadSocialEvents();
    expect(social.validateSocialAuthorship?.({ event: bareReply })).toEqual({
      verdict: "accept",
      event_author: personaKey,
      represented_persona: personaKey,
    });
  });

  it("rejects a cryptographically signed event whose NIP-01 tag structure is invalid", async () => {
    const social = await loadSocialEvents();
    const malformed = await signEvent({
      secretKey: personaSecret,
      created_at: 1_000,
      kind: 1,
      tags: [[]],
      content: "empty tag name",
      auxRand: AUX_RAND,
    });
    expect(social.validateSocialAuthorship?.({ event: malformed })).toEqual({
      verdict: "reject",
      reason_code: "social-event-invalid",
    });
  });

  it("keeps the actual signer authoritative and honors a proof after later revocation", async () => {
    const social = await loadSocialEvents();
    expect(social.validateSocialAuthorship?.({
      event: directOrganizationPost,
      persona_active_key: personaKey,
    })).toEqual({
      verdict: "accept",
      event_author: personaKey,
      represented_persona: personaKey,
    });
    expect(social.validateSocialAuthorship?.({
      event: attributedAgentPost,
      persona_active_key: personaKey,
      comms_authorized_signers: [{
        pubkey: agentKey,
        agent_association: association,
      }],
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });
    const currentAuthorization = publicationFor(attributedAgentPost, association);
    const validateCurrent = social.createSocialAuthorshipValidator?.({
      publication_authority: currentAuthorization.publication_authority,
    });
    expect(validateCurrent?.({
      persona_active_key: personaKey,
      ...currentAuthorization,
    })).toEqual({
      verdict: "accept",
      event_author: agentKey,
      represented_persona: personaKey,
      agent_association: association,
    });
    expect(social.validateSocialAuthorship?.({
      event: attributedAgentPost,
      persona_active_key: personaKey,
      comms_authorization: {} as CommsSocialSignedPublication,
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });

    const oneUse = publicationFor(attributedAgentPost, association);
    const validateOneUse = social.createSocialAuthorshipValidator?.({
      publication_authority: oneUse.publication_authority,
    });
    expect(validateOneUse?.({
      persona_active_key: personaKey,
      ...oneUse,
    })).toMatchObject({ verdict: "accept" });
    expect(validateOneUse?.({
      persona_active_key: personaKey,
      ...oneUse,
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });

    const wrongDestination = publicationFor(attributedAgentPost, association);
    const validateWrongDestination = social.createSocialAuthorshipValidator?.({
      publication_authority: wrongDestination.publication_authority,
    });
    expect(validateWrongDestination?.({
      persona_active_key: personaKey,
      ...wrongDestination,
      requested_resource: "feed:other",
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });

    const differentEvent = await signEvent({
      secretKey: agentSecret,
      created_at: attributedAgentPost.created_at,
      kind: attributedAgentPost.kind,
      tags: attributedAgentPost.tags,
      content: "different event under a replayed capability",
      auxRand: AUX_RAND,
    });
    const authorization = publicationFor(attributedAgentPost, association);
    const validateDifferentEvent = social.createSocialAuthorshipValidator?.({
      publication_authority: authorization.publication_authority,
    });
    expect(validateDifferentEvent?.({
      ...authorization,
      event: differentEvent,
      persona_active_key: personaKey,
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });
  });

  it("rejects an agent association that is missing, unauthorized, or not signed into the event", async () => {
    const social = await loadSocialEvents();
    expect(social.validateSocialAuthorship?.({
      event: attributedAgentPost,
      persona_active_key: personaKey,
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });

    const unattributed = await signEvent({
      secretKey: agentSecret,
      created_at: 1_003,
      kind: 7,
      tags: [["e", bareReply.id], ["p", personaKey]],
      content: "+",
      auxRand: AUX_RAND,
    });
    expect(social.validateSocialAuthorship?.({
      event: unattributed,
      persona_active_key: personaKey,
      comms_authorized_signers: [{
        pubkey: agentKey,
        agent_association: association,
      }],
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });
  });

  it("rejects a role association that is authorized for a different signer", async () => {
    const social = await loadSocialEvents();
    const roleAssociation = { kind: "role", value: "publisher" } as const;
    const roleAttributed = await signEvent({
      secretKey: agentSecret,
      created_at: 1_004,
      kind: 1,
      tags: [
        ["L", "network.heterodyne.agent"],
        ["l", "ai", "network.heterodyne.agent"],
        ["heterodyne_agent", "v1", roleAssociation.kind, roleAssociation.value],
        ["agent_action", "publish"],
      ],
      content: "forged role association",
      auxRand: AUX_RAND,
    });
    expect(social.validateSocialAuthorship?.({
      event: roleAttributed,
      persona_active_key: personaKey,
      comms_authorized_signers: [{
        pubkey: personaKey,
        agent_association: roleAssociation,
      }],
    })).toEqual({ verdict: "reject", reason_code: "social-author-binding-invalid" });
  });

  it("accepts an exact authorized signer when the Comms association is explicitly absent", async () => {
    const social = await loadSocialEvents();
    const attributed = await signEvent({
      secretKey: agentSecret,
      created_at: 1_005,
      kind: 1,
      tags: [
        ["L", "network.heterodyne.agent"],
        ["l", "programmatic", "network.heterodyne.agent"],
        ["agent_action", "publish"],
      ],
      content: "association-free attributed automation",
      auxRand: AUX_RAND,
    });
    const publication = publicationFor(attributed, null);
    const validate = social.createSocialAuthorshipValidator?.({
      publication_authority: publication.publication_authority,
    });
    expect(validate?.({
      persona_active_key: personaKey,
      ...publication,
    })).toEqual({
      verdict: "accept",
      event_author: agentKey,
      represented_persona: personaKey,
    });
  });

  it("rejects a forged NIP-01 author instead of trusting persona metadata", async () => {
    const social = await loadSocialEvents();
    expect(social.validateSocialAuthorship?.({
      event: { ...bareReply, pubkey: agentKey },
      persona_active_key: personaKey,
      comms_authorized_signers: [{
        pubkey: agentKey,
        agent_association: association,
      }],
    })).toEqual({ verdict: "reject", reason_code: "social-event-invalid" });
  });
});

function signAgentEvent(event: NostrUnsignedEvent): NostrSignedEvent {
  const id = getEventId(event);
  return {
    ...event,
    id,
    sig: bytesToHex(schnorr.sign(id, hexToBytes(agentSecret), AUX_RAND)),
  };
}

describe("source-neutral Social state", () => {
  it("selects the newest valid replaceable event regardless of relay or repository carrier", async () => {
    const social = await loadSocialEvents();
    const oldRepository = await signEvent({
      secretKey: personaSecret,
      created_at: 2_000,
      kind: 10000,
      tags: [["p", agentKey]],
      content: "",
      auxRand: AUX_RAND,
    });
    const newRelay = await signEvent({
      secretKey: personaSecret,
      created_at: 2_001,
      kind: 10000,
      tags: [],
      content: "",
      auxRand: AUX_RAND,
    });
    expect(social.selectCurrentSocialEvent?.({
      coordinate: { pubkey: personaKey, kind: 10000 },
      candidates: [
        { carrier: "repository", event: oldRepository },
        { carrier: "relay", event: newRelay },
      ],
    })?.id).toBe(newRelay.id);
  });

  it("uses the lowest event id for a created_at tie and ignores invalid or wrong-coordinate candidates", async () => {
    const social = await loadSocialEvents();
    const left = await signEvent({
      secretKey: personaSecret,
      created_at: 2_100,
      kind: 30000,
      tags: [["d", "team"], ["p", agentKey]],
      content: "",
      auxRand: AUX_RAND,
    });
    const right = await signEvent({
      secretKey: personaSecret,
      created_at: 2_100,
      kind: 30000,
      tags: [["d", "team"], ["p", personaKey]],
      content: "",
      auxRand: AUX_RAND,
    });
    const wrongCoordinate = await signEvent({
      secretKey: personaSecret,
      created_at: 2_200,
      kind: 30000,
      tags: [["d", "other"]],
      content: "",
      auxRand: AUX_RAND,
    });
    const expected = [left, right].sort((a, b) => a.id.localeCompare(b.id))[0];
    expect(social.validateSocialReplaceableCandidate?.({
      coordinate: { pubkey: personaKey, kind: 30000, d: "team" },
      event: wrongCoordinate,
    })).toEqual({
      verdict: "reject",
      reason_code: "social-replaceable-coordinate-mismatch",
    });
    expect(social.validateSocialReplaceableCandidate?.({
      coordinate: { pubkey: personaKey, kind: 30000, d: "team" },
      event: { ...left, sig: "00".repeat(64) },
    })).toEqual({ verdict: "reject", reason_code: "social-event-invalid" });
    expect(social.selectCurrentSocialEvent?.({
      coordinate: { pubkey: personaKey, kind: 30000, d: "team" },
      candidates: [
        { carrier: "relay", event: right },
        { carrier: "repository", event: wrongCoordinate },
        { carrier: "repository", event: left },
        { carrier: "relay", event: { ...left, sig: "00".repeat(64) } },
      ],
    })?.id).toBe(expected.id);
  });

  it("uses the second d-tag member as the coordinate and permits trailing members", async () => {
    const social = await loadSocialEvents();
    const event = await signEvent({
      secretKey: personaSecret,
      created_at: 2_300,
      kind: 30000,
      tags: [["d", "team", "extension"]],
      content: "",
      auxRand: AUX_RAND,
    });
    expect(social.selectCurrentSocialEvent?.({
      coordinate: { pubkey: personaKey, kind: 30000, d: "team" },
      candidates: [{ carrier: "relay", event }],
    })?.id).toBe(event.id);
  });

  it("reports seven-day staleness as a warning without invalidating signed state", async () => {
    const social = await loadSocialEvents();
    expect(social.assessSocialStateFreshness?.(profileState, 1_000 + 7 * 86_400 + 1))
      .toEqual({ valid: true, warning: "stale" });
  });
});
