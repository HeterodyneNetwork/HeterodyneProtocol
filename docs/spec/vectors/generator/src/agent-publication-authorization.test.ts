import { createHash, createPrivateKey, createPublicKey, sign, verify, type JsonWebKey } from "node:crypto";
import { nip19 } from "nostr-tools";
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  authorizeAndSignAgentPublication,
  createAgentPublicationAuthorizationAuthority,
  type AgentPublicationAuthorizationAuthorityConfig,
  type AgentPublicationRequest,
} from "./agent-publication-authorization.js";
import { injectAgentAttribution } from "./agent-authorship.js";
import type { CurrentClaimAuthorizationView } from "./claim-authorization.js";
import { buildClaimLedgerScenario } from "./claim-ledger-test-support.js";
import {
  CLAIM_REVOCATION_PROFILE,
  inspectVerifiedClaim,
  verifyClaimRevocationEnvelope,
  type ClaimSemanticBody,
  type VerifiedClaimArtifact,
  type VerifiedClaimRevocationArtifact,
} from "./claims.js";
import { buildFixtures } from "./fixtures.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  getPublicKey,
  signEvent,
  verifyEventSignature,
  type NostrSignedEvent,
  type NostrUnsignedEvent,
} from "./nostr.js";
import { OIDC_RSA_ONE, OIDC_RSA_TWO } from "./oidc-rsa-fixtures.js";
import type {
  DurableAuthorityRecord,
  DurableAuthorityStore,
} from "./security-authority-support.js";

const fixtures = buildFixtures();
const persona = fixtures.personas.alice.epoch_keys.epoch_1.pubkey;
const agentSecret = "03".repeat(32);
const agentSigner = getPublicKey(agentSecret);
const otherSigner = getPublicKey("05".repeat(32));
const auxRand = "04".repeat(32);
const agentId = "synthetic-local-agent";
const scope = "heterodyne:agent:publish";
const audience = "https://control.example/agent-publication";
const method = "POST";
const target = "https://control.example/agent/publish";
const nonce = "synthetic-local-publication-nonce";
const dpopSender = OIDC_RSA_TWO.public_jwk.kid as string;
const mtlsPeer = createHash("sha256").update("synthetic-local-mtls-peer").digest("base64url");
const checkpointDigest = "c6".repeat(32);
const HETERODYNE_CLAIM_ORIGIN = "https://" + ["heterodyne", "network"].join(".");
const SELECTED_SIGNER_CLAIM = `${HETERODYNE_CLAIM_ORIGIN}/jwt/agent-selected-signer`;
const SIGNER_CLASS_CLAIM = `${HETERODYNE_CLAIM_ORIGIN}/jwt/agent-signer-key-class`;
const ASSOCIATION_CLAIM = `${HETERODYNE_CLAIM_ORIGIN}/jwt/agent-association`;
const CHECKPOINT_CLAIM = `${HETERODYNE_CLAIM_ORIGIN}/jwt/ledger-checkpoint`;
const STATUS_MIRROR_CLAIM = `${HETERODYNE_CLAIM_ORIGIN}/jwt/status-mirror`;

let ledger: Awaited<ReturnType<typeof buildClaimLedgerScenario>>;
let dpopWorkload: VerifiedClaimArtifact;
let unrelatedWorkload: VerifiedClaimArtifact;
let now: number;
let issuer: string;

beforeAll(async () => {
  ledger = await buildClaimLedgerScenario(fixtures);
  now = ledger.now + 100;
  issuer = `https://node.example/oidc/${nip19.npubEncode(persona)}`;
  dpopWorkload = (await workloadClaim(dpopSender)).verified_artifact;
  unrelatedWorkload = (await workloadClaim(dpopSender, { client_id: "unrelated-synthetic-agent" }))
    .verified_artifact;
});

async function workloadClaim(
  senderIdentity: string,
  registrationOverrides: Record<string, unknown> = {},
  claimOverrides: Partial<Omit<ClaimSemanticBody, "claim_id">> = {},
) {
  return ledger.makeClaim(ledger.writerOne, {
    subject: { type: "jwk-thumbprint", value: senderIdentity },
    namespace: "heterodyne.agent",
    name: "workload-registration",
    value: {
      persona_key: persona,
      client_id: agentId,
      subject_jkt: senderIdentity,
      subject_proof: { method: "dpop", jkt: senderIdentity },
      agent_class: "ai",
      selected_signer: agentSigner,
      signer_key_class: "agent",
      agent_association: { kind: "key", value: agentSigner },
      audience,
      scopes: [scope],
      allowed_kinds: [1],
      allowed_feeds: ["timeline"],
      allowed_resources: [target],
      max_content_bytes: 4_096,
      rate_limit: { window_seconds: 60, count: 10, burst: 2 },
      not_before: now - 60,
      expires_at: now + 600,
      ...registrationOverrides,
    },
    audience: [audience],
    resources: [target],
    not_before: now - 60,
    expires_at: now + 600,
    ...claimOverrides,
  });
}

async function delegatedWorkload(
  childOverrides: Partial<Omit<ClaimSemanticBody, "claim_id">> = {},
) {
  const leaf = inspectVerifiedClaim(dpopWorkload);
  const parent = await ledger.makeClaim(ledger.writerOne, {
    subject: { type: "nostr-secp256k1", value: persona },
    namespace: leaf.namespace,
    name: leaf.name,
    value: leaf.value,
    audience: [audience],
    resources: [target],
    constraints: {
      namespaces: ["heterodyne.agent"],
      audiences: [audience],
      resources: [target],
      remaining_depth: 1,
    },
    not_before: now - 60,
    expires_at: now + 600,
  });
  const child = await ledger.makeClaim(ledger.writerOne, {
    subject: { type: "jwk-thumbprint", value: dpopSender },
    namespace: leaf.namespace,
    name: leaf.name,
    value: leaf.value,
    audience: [audience],
    resources: [target],
    parent_claim_id: parent.artifact.semantic.claim_id,
    not_before: now - 60,
    expires_at: now + 600,
    ...childOverrides,
  });
  return { parent: parent.verified_artifact, child: child.verified_artifact };
}

async function revokeClaim(
  artifact: VerifiedClaimArtifact,
): Promise<VerifiedClaimRevocationArtifact> {
  const semantic = inspectVerifiedClaim(artifact);
  const revocation = {
    ...CLAIM_REVOCATION_PROFILE,
    claim_id: semantic.claim_id,
    revoked_at: now - 1,
    reason_code: "claim-revoked",
    revoker: semantic.issuer,
  } as const;
  return verifyClaimRevocationEnvelope(await signEvent({
    secretKey: ledger.issuer.private_key,
    auxRand,
    created_at: revocation.revoked_at,
    kind: 31014,
    tags: [["d", revocation.claim_id]],
    content: jcsCanonicalize(revocation),
  }));
}

function exactView(
  artifact: VerifiedClaimArtifact,
  overrides: Partial<CurrentClaimAuthorizationView> = {},
): CurrentClaimAuthorizationView {
  return {
    credential_ledger: {
      credential_ledger_persona: persona,
      credential_ledger_generation: 0,
    },
    checkpoint_digest: checkpointDigest,
    repository_revision: 7,
    claims: [artifact],
    revocations: [],
    conflicted_claim_ids: [],
    ledger_state: ledger.issuerKeyEpochOneState,
    ...overrides,
  };
}

function b64Json(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function rsaJwt(claimOverrides: Record<string, unknown> = {}): string {
  const root = nip19.npubEncode(persona);
  const statusPath = `.well-known/${root}/status-lists/1/${"ab".repeat(16)}/0.jwt`;
  const header = { alg: "RS256", kid: OIDC_RSA_ONE.public_jwk.kid, typ: "at+jwt" };
  const claims = {
    iss: issuer,
    sub: createHash("sha256").update("synthetic-local-agent-subject").digest("base64url"),
    aud: [audience],
    exp: now + 240,
    iat: now - 10,
    jti: "synthetic-local-jti-0001",
    client_id: agentId,
    scope,
    credential_ledger_persona: persona,
    credential_ledger_generation: 0,
    cnf: { jkt: dpopSender },
    [SELECTED_SIGNER_CLAIM]: agentSigner,
    [SIGNER_CLASS_CLAIM]: "agent",
    [ASSOCIATION_CLAIM]: { kind: "key", value: agentSigner },
    [CHECKPOINT_CLAIM]: {
      repository_rid: ledger.rid,
      branch: "main",
      commit_oid: "ac".repeat(20),
      observed_at: now - 20,
    },
    status: { status_list: { uri: `${issuer}/status-lists/1/${"ab".repeat(16)}/0.jwt`, idx: 0 } },
    [STATUS_MIRROR_CLAIM]: {
      repository_rid: ledger.rid,
      branch: "main",
      path: statusPath,
      sha256: "ad".repeat(32),
    },
    ...claimOverrides,
  };
  const signingInput = `${b64Json(header)}.${b64Json(claims)}`;
  const privateKey = createPrivateKey({ key: OIDC_RSA_ONE.private_jwk as JsonWebKey, format: "jwk" });
  return `${signingInput}.${sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url")}`;
}

function dpopCompact(overrides: Record<string, unknown> = {}): string {
  const header = { alg: "RS256", typ: "dpop+jwt", jwk: OIDC_RSA_TWO.public_jwk };
  const claims = {
    htm: method,
    htu: target,
    nonce,
    jti: "synthetic-local-dpop-jti",
    iat: now,
    ...overrides,
  };
  const signingInput = `${b64Json(header)}.${b64Json(claims)}`;
  const privateKey = createPrivateKey({ key: OIDC_RSA_TWO.private_jwk as JsonWebKey, format: "jwk" });
  return `${signingInput}.${sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url")}`;
}

class MemoryStore implements DurableAuthorityStore<NostrSignedEvent> {
  readonly records = new Map<string, DurableAuthorityRecord<NostrSignedEvent>>();
  readonly acquireInputs: Array<Parameters<DurableAuthorityStore<NostrSignedEvent>["acquire"]>[0]> = [];
  loadCalls = 0;
  commitCalls = 0;
  markCalls = 0;
  commitResult: "committed" | "conflict" | "unknown" = "committed";
  hideExecutingReadback = false;
  substituteIndeterminateDigest: string | null = null;

  async load(key: string): Promise<DurableAuthorityRecord<NostrSignedEvent> | null> {
    this.loadCalls += 1;
    const value = this.records.get(key) ?? null;
    if (this.hideExecutingReadback && value?.state === "executing") return null;
    return value;
  }

  async acquire(input: Parameters<DurableAuthorityStore<NostrSignedEvent>["acquire"]>[0]) {
    this.acquireInputs.push(input);
    const current = this.records.get(input.key);
    if (current !== undefined) {
      return current.binding_digest === input.binding_digest ? "replay" as const : "conflict" as const;
    }
    this.records.set(input.key, Object.freeze({
      state: "executing" as const,
      revision: 0,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
    }));
    return "acquired" as const;
  }

  async compareAndSwap(
    input: Parameters<DurableAuthorityStore<NostrSignedEvent>["compareAndSwap"]>[0],
  ) {
    const current = this.records.get(input.key);
    const revision = current?.revision ?? null;
    if (revision !== input.expected_revision) return "conflict" as const;
    this.records.set(input.key, input.next);
    return "committed" as const;
  }

  async commit(input: Parameters<DurableAuthorityStore<NostrSignedEvent>["commit"]>[0]) {
    this.commitCalls += 1;
    if (this.commitResult !== "committed") return this.commitResult;
    const current = this.records.get(input.key);
    if (current?.state !== "executing"
      || current.binding_digest !== input.binding_digest
      || current.execution_token !== input.execution_token) return "conflict" as const;
    this.records.set(input.key, Object.freeze({
      state: "committed" as const,
      revision: current.revision + 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      output_digest: input.output_digest,
      output: structuredClone(input.output),
    }));
    return "committed" as const;
  }

  async markIndeterminate(
    input: Parameters<DurableAuthorityStore<NostrSignedEvent>["markIndeterminate"]>[0],
  ) {
    this.markCalls += 1;
    const current = this.records.get(input.key);
    if (current?.state !== "executing"
      || current.binding_digest !== input.binding_digest
      || current.execution_token !== input.execution_token) return "conflict" as const;
    this.records.set(input.key, Object.freeze({
      state: "indeterminate" as const,
      revision: current.revision + 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      reconciliation_digest: this.substituteIndeterminateDigest ?? input.reconciliation_digest,
    }));
    return "indeterminate" as const;
  }
}

type Harness = Awaited<ReturnType<typeof harness>>;

async function harness(options: Readonly<{
  sender?: "dpop" | "mtls";
  authorityId?: string;
  claimViews?: CurrentClaimAuthorizationView[];
  statuses?: Array<Readonly<{ generation: number; state: "active" | "revoked"; checkpoint: string }>>;
  peerIdentity?: string | null;
  store?: MemoryStore;
  signerThrows?: boolean;
}> = {}) {
  const sender = options.sender ?? "dpop";
  const artifact = dpopWorkload;
  const views = options.claimViews ?? [exactView(artifact), exactView(artifact)];
  const statuses = options.statuses ?? [
    { generation: 0, state: "active", checkpoint: checkpointDigest },
    { generation: 0, state: "active", checkpoint: checkpointDigest },
  ];
  const store = options.store ?? new MemoryStore();
  const consumed = new Set<string>();
  let viewLoads = 0;
  let statusLoads = 0;
  let dpopCalls = 0;
  let signerCalls = 0;
  let mtlsCalls = 0;
  let peerIdentity = options.peerIdentity === undefined ? mtlsPeer : options.peerIdentity;
  const compactDpop = dpopCompact();

  const config: AgentPublicationAuthorizationAuthorityConfig = {
    authority_id: options.authorityId ?? "synthetic-local-agent-publication-authority",
    trusted_now: () => now,
    expected_issuer: issuer,
    expected_audience: audience,
    jwks: { keys: [OIDC_RSA_ONE.public_jwk] },
    load_claim_view: async () => views[Math.min(viewLoads++, views.length - 1)]!,
    load_status: async () => statuses[Math.min(statusLoads++, statuses.length - 1)]!,
    consume_dpop: async (proof) => {
      dpopCalls += 1;
      if (proof.method !== method || proof.target !== target || proof.nonce !== nonce) return null;
      const segments = proof.compact.split(".");
      if (segments.length !== 3 || consumed.has(proof.compact)) return null;
      try {
        const header = JSON.parse(Buffer.from(segments[0]!, "base64url").toString("utf8"));
        const claims = JSON.parse(Buffer.from(segments[1]!, "base64url").toString("utf8"));
        const expectedHeader = { alg: "RS256", typ: "dpop+jwt", jwk: OIDC_RSA_TWO.public_jwk };
        if (jcsCanonicalize(header) !== jcsCanonicalize(expectedHeader)
          || claims.htm !== proof.method
          || claims.htu !== proof.target
          || claims.nonce !== proof.nonce
          || claims.iat !== now
          || typeof claims.jti !== "string") return null;
        const key = createPublicKey({ key: OIDC_RSA_TWO.public_jwk as JsonWebKey, format: "jwk" });
        if (!verify(
          "RSA-SHA256",
          Buffer.from(`${segments[0]}.${segments[1]}`),
          key,
          Buffer.from(segments[2]!, "base64url"),
        )) return null;
      } catch {
        return null;
      }
      consumed.add(proof.compact);
      return {
        proof_digest: createHash("sha256").update(proof.compact).digest("hex"),
        sender_key: dpopSender,
      };
    },
    read_mtls_peer_identity: () => {
      mtlsCalls += 1;
      return peerIdentity;
    },
    store,
    sign_once: async (_executionToken, event) => {
      signerCalls += 1;
      if (options.signerThrows) throw new Error("synthetic local signer failure");
      return signEvent({
        secretKey: agentSecret,
        auxRand,
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags,
        content: event.content,
      });
    },
  };
  const authority = createAgentPublicationAuthorizationAuthority(config);
  const compactJwt = rsaJwt(sender === "dpop"
    ? {}
    : { cnf: { "x5t#S256": mtlsPeer } });
  const request: AgentPublicationRequest = {
    compact_jwt: compactJwt,
    represented_persona: persona,
    agent_id: agentId,
    signer: agentSigner,
    scope,
    ledger_generation: 0,
    publication: {
      pubkey: agentSigner,
      created_at: now,
      kind: 1,
      tags: [["t", "synthetic-local"], ["L", "network.heterodyne.agent"]],
      content: "synthetic local agent publication",
    },
    attribution_profile: "heterodyne-agent-v1",
    sender_proof: sender === "dpop"
      ? { kind: "dpop", compact: compactDpop, method, target, nonce }
      : { kind: "mtls" },
  };
  return {
    authority,
    config,
    request,
    store,
    compactDpop,
    setPeerIdentity: (identity: string | null) => { peerIdentity = identity; },
    counts: {
      dpop: () => dpopCalls,
      signer: () => signerCalls,
      mtls: () => mtlsCalls,
      views: () => viewLoads,
      statuses: () => statusLoads,
    },
  };
}

async function expectRejected(
  value: Harness,
  request: AgentPublicationRequest,
  reason: "agent-sender-proof-invalid" | "agent-signer-mismatch" = "agent-sender-proof-invalid",
) {
  await expect(authorizeAndSignAgentPublication(value.authority, request)).resolves.toEqual({
    verdict: "reject",
    reason_code: reason,
  });
  expect(value.counts.signer()).toBe(0);
}

describe("agent workload publication authorization", () => {
  it("BLUE TEAM VALIDATION: synthetic/local attribution snapshots are immutable before signing", () => {
    const result = injectAgentAttribution({
      kind: 1,
      tags: [["t", "synthetic-local"]],
      agent_class: "ai",
      persona,
      signer: agentSigner,
      expected_signer: agentSigner,
      signer_key_class: "agent",
      oidc_scopes: [scope],
      agent_association: { kind: "key", value: agentSigner },
      expected_agent_association: { kind: "key", value: agentSigner },
      tier: 1,
    });
    expect(result.verdict).toBe("accept");
    if (result.verdict !== "accept") throw new Error("synthetic attribution failed");
    expect(Object.isFrozen(result.tags)).toBe(true);
    expect(result.tags.every(Object.isFrozen)).toBe(true);
  });

  it("accepts one cryptographically verified DPoP publication atomically", async () => {
    const value = await harness();
    const result = await authorizeAndSignAgentPublication(value.authority, value.request);

    expect(result.verdict).toBe("accept");
    if (result.verdict !== "accept") throw new Error("synthetic publication was not accepted");
    expect(verifyEventSignature(result.output)).toBe(true);
    expect(result.output.pubkey).toBe(agentSigner);
    expect(result.output.tags).toEqual([
      ["t", "synthetic-local"],
      ["L", "network.heterodyne.agent"],
      ["l", "ai", "network.heterodyne.agent"],
      ["heterodyne_agent", "v1", "key", agentSigner],
      ["agent_action", "publish"],
    ]);
    expect(JSON.stringify(result.output)).not.toContain(value.request.compact_jwt);
    expect(value.counts.dpop()).toBe(1);
    expect(value.counts.signer()).toBe(1);
    expect(value.store.acquireInputs).toHaveLength(1);
    expect(value.store.acquireInputs[0]?.expected_revision).toBeNull();
    expect([...value.store.records.values()][0]).toMatchObject({ state: "committed" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local fails closed mTLS before state, peer, fence, or signer effects", async () => {
    const value = await harness({ sender: "mtls" });
    let substitutedSignerCalls = 0;
    (value.config as { read_mtls_peer_identity: () => string | null }).read_mtls_peer_identity = () => "wrong";
    (value.config as { sign_once: AgentPublicationAuthorizationAuthorityConfig["sign_once"] }).sign_once = async () => {
      substitutedSignerCalls += 1;
      throw new Error("substituted callback must not run");
    };

    const result = await authorizeAndSignAgentPublication(value.authority, value.request);

    expect(result).toEqual({ verdict: "reject", reason_code: "agent-sender-proof-invalid" });
    expect(value.counts.views()).toBe(0);
    expect(value.counts.statuses()).toBe(0);
    expect(value.counts.mtls()).toBe(0);
    expect(value.counts.dpop()).toBe(0);
    expect(value.counts.signer()).toBe(0);
    expect(value.store.loadCalls).toBe(0);
    expect(value.store.acquireInputs).toHaveLength(0);
    expect(substitutedSignerCalls).toBe(0);
  });

  it("accepts the exact agent registration when unrelated opaque workload claims are current", async () => {
    const value = await harness({
      claimViews: [
        exactView(dpopWorkload, { claims: [dpopWorkload, unrelatedWorkload] }),
        exactView(dpopWorkload, { claims: [dpopWorkload, unrelatedWorkload] }),
      ],
    });
    expect((await authorizeAndSignAgentPublication(value.authority, value.request)).verdict)
      .toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local requires the complete opaque workload claim chain", async () => {
    const active = await delegatedWorkload();
    const accepted = await harness({
      claimViews: [
        exactView(active.child, { claims: [active.parent, active.child] }),
        exactView(active.child, { claims: [active.parent, active.child] }),
      ],
    });
    expect((await authorizeAndSignAgentPublication(accepted.authority, accepted.request)).verdict)
      .toBe("accept");

    const parentId = inspectVerifiedClaim(active.parent).claim_id;
    const parentRevocation = await revokeClaim(active.parent);
    const hostileViews: CurrentClaimAuthorizationView[] = [
      exactView(active.child, {
        claims: [active.parent, active.child],
        revocations: [parentRevocation],
      }),
      exactView(active.child, {
        claims: [active.parent, active.child],
        conflicted_claim_ids: [parentId],
      }),
      exactView(active.child, {
        credential_ledger: {
          credential_ledger_persona: persona,
          credential_ledger_generation: 1,
        },
        claims: [active.parent, active.child],
      }),
    ];
    for (const view of hostileViews) {
      const value = await harness({ claimViews: [view] });
      await expectRejected(value, value.request);
      expect(value.store.acquireInputs).toHaveLength(0);
      expect(value.counts.dpop()).toBe(0);
    }

    const expired = await delegatedWorkload({ expires_at: now - 1 });
    const expiredValue = await harness({
      claimViews: [exactView(expired.child, { claims: [expired.parent, expired.child] })],
    });
    await expectRejected(expiredValue, expiredValue.request);
    expect(expiredValue.store.acquireInputs).toHaveLength(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects non-attenuated ancestors and exact outer audience/resource mismatches", async () => {
    const widened = await delegatedWorkload({ resources: [target, "https://wrong.example/resource"] });
    const wrongAudience = (await workloadClaim(dpopSender, {}, { audience: ["https://wrong.example/audience"] }))
      .verified_artifact;
    const wrongResource = (await workloadClaim(dpopSender, {}, { resources: ["https://wrong.example/resource"] }))
      .verified_artifact;
    const views = [
      exactView(widened.child, { claims: [widened.parent, widened.child] }),
      exactView(wrongAudience),
      exactView(wrongResource),
    ];
    for (const view of views) {
      const value = await harness({ claimViews: [view] });
      await expectRejected(value, value.request);
      expect(value.store.acquireInputs).toHaveLength(0);
      expect(value.counts.dpop()).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local revalidates the opaque chain immediately before signing", async () => {
    const active = await delegatedWorkload();
    const activeView = exactView(active.child, { claims: [active.parent, active.child] });
    const conflictedView = exactView(active.child, {
      claims: [active.parent, active.child],
      conflicted_claim_ids: [inspectVerifiedClaim(active.parent).claim_id],
    });
    const value = await harness({ claimViews: [activeView, activeView, conflictedView] });
    const result = await authorizeAndSignAgentPublication(value.authority, value.request);

    expect(result.verdict).toBe("indeterminate");
    expect(value.counts.views()).toBe(3);
    expect(value.counts.signer()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a wrong or substituted mTLS peer", async () => {
    const value = await harness({ sender: "mtls", peerIdentity: "x".repeat(43) });
    await expectRejected(value, value.request);
    expect(value.counts.mtls()).toBe(0);
    expect(value.store.acquireInputs).toHaveLength(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local never creates a retry terminal for unsupported mTLS", async () => {
    const value = await harness({ sender: "mtls" });
    await expectRejected(value, value.request);
    value.setPeerIdentity("x".repeat(43));
    await expectRejected(value, value.request);
    expect(value.counts.views()).toBe(0);
    expect(value.counts.mtls()).toBe(0);
    expect(value.store.records.size).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local never exposes authorize-then-sign and rejects proof replay", async () => {
    expect(Object.keys(await import("./agent-publication-authorization.js")))
      .not.toContain("VerifiedAgentPublicationAuthorization");
    const value = await harness();
    expect((await authorizeAndSignAgentPublication(value.authority, value.request)).verdict).toBe("accept");
    const changed = structuredClone(value.request);
    changed.publication.content = "different synthetic local publication";

    await expect(authorizeAndSignAgentPublication(value.authority, changed)).resolves.toEqual({
      verdict: "reject",
      reason_code: "agent-sender-proof-invalid",
    });
    expect(value.counts.signer()).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects wrong signer, audience, scope, nonce, method, and target", async () => {
    const cases: Array<readonly [string, (value: Harness) => AgentPublicationRequest, "agent-sender-proof-invalid" | "agent-signer-mismatch"]> = [
      ["signer", (value) => ({
        ...value.request,
        signer: otherSigner,
        publication: { ...value.request.publication, pubkey: otherSigner },
      }), "agent-signer-mismatch"],
      ["audience", (value) => ({
        ...value.request,
        compact_jwt: rsaJwt({ aud: ["https://wrong.example/agent-publication"] }),
      }), "agent-sender-proof-invalid"],
      ["scope", (value) => ({
        ...value.request,
        compact_jwt: rsaJwt({ scope: "heterodyne:agent:admin" }),
        scope: "heterodyne:agent:admin",
      }), "agent-sender-proof-invalid"],
      ["nonce", (value) => ({
        ...value.request,
        sender_proof: { ...value.request.sender_proof, kind: "dpop", nonce: "wrong" },
      } as AgentPublicationRequest), "agent-sender-proof-invalid"],
      ["method", (value) => ({
        ...value.request,
        sender_proof: { ...value.request.sender_proof, kind: "dpop", method: "DELETE" },
      } as AgentPublicationRequest), "agent-sender-proof-invalid"],
      ["target", (value) => ({
        ...value.request,
        sender_proof: { ...value.request.sender_proof, kind: "dpop", target: "https://wrong.example" },
      } as AgentPublicationRequest), "agent-sender-proof-invalid"],
    ];
    for (const [name, mutate, reason] of cases) {
      const value = await harness();
      await expectRejected(value, mutate(value), reason);
      expect(value.counts.signer(), name).toBe(0);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects stale status, generation, and changed claim view", async () => {
    const revoked = await harness({
      statuses: [
        { generation: 0, state: "active", checkpoint: checkpointDigest },
        { generation: 0, state: "revoked", checkpoint: checkpointDigest },
      ],
    });
    await expectRejected(revoked, revoked.request);

    const staleGeneration = await harness({
      statuses: [{ generation: 1, state: "active", checkpoint: checkpointDigest }],
    });
    await expectRejected(staleGeneration, staleGeneration.request);

    const changedView = await harness({
      claimViews: [exactView(dpopWorkload), exactView(dpopWorkload, { repository_revision: 8 })],
    });
    await expectRejected(changedView, changedView.request);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures the exact publication before asynchronous reads", async () => {
    const value = await harness();
    let release!: (view: CurrentClaimAuthorizationView) => void;
    let calls = 0;
    const firstView = new Promise<CurrentClaimAuthorizationView>((resolve) => { release = resolve; });
    (value.config as { load_claim_view: AgentPublicationAuthorizationAuthorityConfig["load_claim_view"] })
      .load_claim_view = async () => calls++ === 0 ? firstView : exactView(dpopWorkload);
    const authority = createAgentPublicationAuthorizationAuthority(value.config);
    const mutable = structuredClone(value.request) as AgentPublicationRequest & {
      publication: NostrUnsignedEvent;
    };
    const pending = authorizeAndSignAgentPublication(authority, mutable);
    mutable.publication.content = "post-capture attacker mutation";
    mutable.publication.tags[0]![1] = "mutated";
    release(exactView(dpopWorkload));

    const result = await pending;
    expect(result.verdict).toBe("accept");
    if (result.verdict !== "accept") throw new Error("captured publication was not accepted");
    expect(result.output.content).toBe("synthetic local agent publication");
    expect(result.output.tags[0]).toEqual(["t", "synthetic-local"]);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects plain cross-authority objects and callback-substituted issuers", async () => {
    const value = await harness();
    await expect(authorizeAndSignAgentPublication({} as never, value.request)).resolves.toEqual({
      verdict: "reject",
      reason_code: "agent-sender-proof-invalid",
    });
    const other = await harness({ authorityId: "synthetic-local-other-authority" });
    (other.config as { expected_issuer: string }).expected_issuer = "https://wrong.example/oidc/npub1wrong";
    expect((await authorizeAndSignAgentPublication(other.authority, other.request)).verdict).toBe("accept");
    expect(other.counts.signer()).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes signer throws indeterminate and never retries the effect", async () => {
    const value = await harness({ signerThrows: true });
    const first = await authorizeAndSignAgentPublication(value.authority, value.request);
    const retry = await authorizeAndSignAgentPublication(value.authority, value.request);

    expect(first).toMatchObject({ verdict: "indeterminate" });
    expect(retry).toEqual(first);
    expect(value.counts.signer()).toBe(1);
    expect(value.store.markCalls).toBeGreaterThan(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes terminal-write failure stable and non-reexecuting", async () => {
    const store = new MemoryStore();
    store.commitResult = "unknown";
    const value = await harness({ store });
    const first = await authorizeAndSignAgentPublication(value.authority, value.request);
    const retry = await authorizeAndSignAgentPublication(value.authority, value.request);

    expect(first).toMatchObject({ verdict: "indeterminate" });
    expect(retry).toEqual(first);
    expect(value.counts.signer()).toBe(1);
    expect(store.commitCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local never exposes a cached store-selected reconciliation digest", async () => {
    const value = await harness({ signerThrows: true });
    const first = await authorizeAndSignAgentPublication(value.authority, value.request);
    expect(first.verdict).toBe("indeterminate");
    const [key, record] = [...value.store.records.entries()][0]!;
    if (record.state !== "indeterminate") throw new Error("synthetic indeterminate record required");
    const substituted = "ef".repeat(32);
    value.store.records.set(key, { ...record, reconciliation_digest: substituted });

    const retry = await authorizeAndSignAgentPublication(value.authority, value.request);
    expect(retry).toEqual(first);
    expect(retry).not.toEqual({ verdict: "indeterminate", reconciliation_digest: substituted });
    expect(value.counts.signer()).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local authenticates post-write indeterminate readback locally", async () => {
    const store = new MemoryStore();
    store.substituteIndeterminateDigest = "ed".repeat(32);
    const value = await harness({ store, signerThrows: true });

    const first = await authorizeAndSignAgentPublication(value.authority, value.request);
    const retry = await authorizeAndSignAgentPublication(value.authority, value.request);
    expect(first.verdict).toBe("indeterminate");
    expect(first).toEqual(retry);
    expect(first).not.toEqual({
      verdict: "indeterminate",
      reconciliation_digest: store.substituteIndeterminateDigest,
    });
    expect(value.counts.signer()).toBe(1);
  });

  it("returns the immutable committed output on an exact retry without replaying DPoP or signing", async () => {
    const value = await harness();
    const first = await authorizeAndSignAgentPublication(value.authority, value.request);
    const retry = await authorizeAndSignAgentPublication(value.authority, value.request);

    expect(retry).toEqual(first);
    expect(value.counts.dpop()).toBe(1);
    expect(value.counts.signer()).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local refuses to sign without exact persisted executing readback", async () => {
    const store = new MemoryStore();
    store.hideExecutingReadback = true;
    const value = await harness({ store });
    const result = await authorizeAndSignAgentPublication(value.authority, value.request);

    expect(result).toMatchObject({ verdict: "indeterminate" });
    expect(value.counts.signer()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local enforces bounded closed capture before callbacks", async () => {
    const value = await harness();
    const accessor = structuredClone(value.request) as Record<string, unknown>;
    Object.defineProperty(accessor, "scope", { enumerable: true, get: () => scope });
    await expectRejected(value, accessor as AgentPublicationRequest);
    expect(value.counts.views()).toBe(0);

    const oversized = { ...value.request, compact_jwt: "a".repeat(70_000) };
    await expectRejected(value, oversized);
    expect(value.counts.views()).toBe(0);

    const proxied = new Proxy(structuredClone(value.request), {});
    await expectRejected(value, proxied);
    expect(value.counts.views()).toBe(0);

    const deepUnexpected: Record<string, unknown> = {};
    let cursor = deepUnexpected;
    for (let depth = 0; depth < 128; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }
    const deep = { ...value.request, unexpected: deepUnexpected } as unknown as AgentPublicationRequest;
    await expectRejected(value, deep);
    expect(value.counts.views()).toBe(0);

    let traps = 0;
    const trapped = new Proxy({}, {
      getPrototypeOf: () => { traps += 1; throw new Error("trap must remain cold"); },
      ownKeys: () => { traps += 1; throw new Error("trap must remain cold"); },
    });
    await expectRejected(value, {
      ...value.request,
      unexpected: trapped,
    } as unknown as AgentPublicationRequest);
    expect(traps).toBe(0);
    expect(value.counts.views()).toBe(0);

    const outerTags = structuredClone(value.request);
    outerTags.publication.tags = Array.from({ length: 1_025 }, () => ["t", "synthetic-local"]);
    await expectRejected(value, outerTags);
    expect(value.counts.views()).toBe(0);

    const tagMembers = structuredClone(value.request);
    tagMembers.publication.tags = [Array.from({ length: 65 }, () => "synthetic-local")];
    await expectRejected(value, tagMembers);
    expect(value.counts.views()).toBe(0);

    const aggregate = structuredClone(value.request);
    const largeMember = "x".repeat(4_096);
    aggregate.publication.tags = Array.from(
      { length: 81 },
      () => Array.from({ length: 64 }, () => largeMember),
    );
    await expectRejected(value, aggregate);
    expect(value.counts.views()).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects oversized malformed durable output before cryptographic work", async () => {
    const value = await harness();
    expect((await authorizeAndSignAgentPublication(value.authority, value.request)).verdict).toBe("accept");
    const [key, record] = [...value.store.records.entries()][0]!;
    if (record.state !== "committed") throw new Error("synthetic committed record required");
    value.store.records.set(key, {
      ...record,
      output: { ...record.output, content: "x".repeat(16_777_217) },
    });

    const result = await authorizeAndSignAgentPublication(value.authority, value.request);
    expect(result.verdict).toBe("indeterminate");
    expect(value.counts.signer()).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local length-caps opaque callback arrays before descriptor enumeration", async () => {
    const oversizedClaims = Array.from({ length: 257 }, () => dpopWorkload);
    let getterCalls = 0;
    let elementTraps = 0;
    const oversizedRevocations = new Array(1_000_000_000);
    Object.defineProperty(oversizedRevocations, "0", {
      enumerable: true,
      get: () => { getterCalls += 1; return undefined; },
    });
    oversizedRevocations[1] = new Proxy({}, {
      getPrototypeOf: () => { elementTraps += 1; throw new Error("element trap must remain cold"); },
      ownKeys: () => { elementTraps += 1; throw new Error("element trap must remain cold"); },
    });
    const originalDescriptors = Object.getOwnPropertyDescriptors;
    let oversizedEnumerations = 0;
    const descriptorSpy = vi.spyOn(Object, "getOwnPropertyDescriptors").mockImplementation(
      ((value: object) => {
        if (value === oversizedClaims || value === oversizedRevocations) {
          oversizedEnumerations += 1;
          throw new Error("oversized array descriptors must not be enumerated");
        }
        return originalDescriptors(value);
      }) as typeof Object.getOwnPropertyDescriptors,
    );
    try {
      const claimsValue = await harness({
        claimViews: [exactView(dpopWorkload, {
          claims: oversizedClaims as readonly VerifiedClaimArtifact[],
        })],
      });
      await expectRejected(claimsValue, claimsValue.request);
      expect(claimsValue.counts.dpop()).toBe(0);
      expect(claimsValue.store.acquireInputs).toHaveLength(0);

      const revocationsValue = await harness({
        claimViews: [exactView(dpopWorkload, {
          revocations: oversizedRevocations as readonly VerifiedClaimRevocationArtifact[],
        })],
      });
      await expectRejected(revocationsValue, revocationsValue.request);
      expect(revocationsValue.counts.dpop()).toBe(0);
      expect(revocationsValue.store.acquireInputs).toHaveLength(0);
    } finally {
      descriptorSpy.mockRestore();
    }
    expect(oversizedEnumerations).toBe(0);
    expect(getterCalls).toBe(0);
    expect(elementTraps).toBe(0);

    let arrayProxyTraps = 0;
    const proxiedClaims = new Proxy(oversizedClaims, {
      getPrototypeOf: () => { arrayProxyTraps += 1; throw new Error("array trap must remain cold"); },
      ownKeys: () => { arrayProxyTraps += 1; throw new Error("array trap must remain cold"); },
    });
    const proxiedValue = await harness({
      claimViews: [exactView(dpopWorkload, {
        claims: proxiedClaims as readonly VerifiedClaimArtifact[],
      })],
    });
    await expectRejected(proxiedValue, proxiedValue.request);
    expect(arrayProxyTraps).toBe(0);
    expect(proxiedValue.counts.dpop()).toBe(0);
    expect(proxiedValue.store.acquireInputs).toHaveLength(0);
  });
});
