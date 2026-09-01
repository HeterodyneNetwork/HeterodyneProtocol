import {
  createHash,
  createPrivateKey,
  sign,
  type JsonWebKey,
} from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  createAuthorizationFreshnessAuthority,
  evaluateAuthorizationFreshness,
  type CurrentAuthorizationView,
} from "./authorization-freshness.js";
import type { JsonValue } from "./claims.js";
import type { ControlAuthorizationObject } from "./control-profile.js";
import {
  consumeVerifiedControlToken,
  createControlTokenVerifier,
  verifyControlToken,
  type ControlTokenOperation,
  type ControlTokenUse,
} from "./control-token-verifier.js";
import { buildFixtures } from "./fixtures.js";
import { utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  CHECKPOINT_CLAIM,
  createValidatedProjectedJwtContext,
  projectAccessToken,
} from "./oidc.js";
import { OIDC_RSA_ONE } from "./oidc-rsa-fixtures.js";
import { buildLiveOidcScenario } from "./oidc-test-support.js";
import type {
  DurableAuthorityRecord,
  DurableAuthorityStore,
} from "./security-authority-support.js";
import {
  continuityManifestDigest,
  createContinuityAuthorityProof,
  createCurrentControlGrantView,
  generateStatusListToken,
  validateIssuerContinuityChain,
  type ContinuityManifest,
  type ContinuityManifestBody,
} from "./token-status.js";

const fixtures = buildFixtures();
const SENDER_KEY = "2JF8vg9etJzjFwZwmkvhBLLZ0bfMVVOPivYR5lFtcec";
const GROUP_ID = "33".repeat(32);
const AUTHORIZATION_ID = "44".repeat(32);
const AUTHORITY_ID = "synthetic-local-control-authority";
const OBJECT = Object.freeze({
  class: "config_namespace",
  id: "ui",
}) as ControlAuthorizationObject;
const REJECT = Object.freeze({ verdict: "reject", reason_code: "control-token-invalid" });

type LiveScenario = Awaited<ReturnType<typeof buildLiveOidcScenario>>;
type Output = Readonly<{ operation_id: string }>;

let live: LiveScenario;

beforeAll(async () => {
  live = await buildLiveOidcScenario(fixtures, {
    sender_constraint: "dpop",
    cnf: { jkt: SENDER_KEY },
  });
}, 30_000);

function sha256(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

function resignJwt(
  compact: string,
  mutateClaims: (claims: Record<string, any>) => void = () => undefined,
  mutateHeader: (header: Record<string, any>) => void = () => undefined,
): string {
  const [encodedHeader, encodedClaims] = compact.split(".");
  const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8"));
  const claims = JSON.parse(Buffer.from(encodedClaims, "base64url").toString("utf8"));
  mutateHeader(header);
  mutateClaims(claims);
  const nextHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const nextClaims = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${nextHeader}.${nextClaims}`;
  const key = createPrivateKey({
    key: OIDC_RSA_ONE.private_jwk as JsonWebKey,
    format: "jwk",
  });
  return `${input}.${sign("RSA-SHA256", Buffer.from(input), key).toString("base64url")}`;
}

function signedManifest(body: ContinuityManifestBody): ContinuityManifest {
  return {
    ...body,
    authority_proof: createContinuityAuthorityProof(body, live.s.writerOne.private_key),
  };
}

type TokenFixture = Awaited<ReturnType<typeof tokenFixture>>;

async function tokenFixture() {
  const state = live.issuedState;
  const now = state.checkpoint.observed_at;
  const statusUri = `${live.metadata.issuer}/${live.issuance.reservation.uri}`;
  const statusList = generateStatusListToken({
    state,
    uri: statusUri,
    private_jwk: OIDC_RSA_ONE.private_jwk,
    iat: now,
    exp: now + 600,
    ttl: 300,
  });
  const jwksBytes = utf8Bytes(jcsCanonicalize({ keys: [OIDC_RSA_ONE.public_jwk] }));
  const body: ContinuityManifestBody = {
    profile: "heterodyne-oidc-continuity-v1",
    repository_rid: live.s.rid,
    branch: "main",
    persona_npub: live.personaNpub,
    persona_key: live.personaKey,
    issuer: live.metadata.issuer,
    sequence: 0,
    predecessor_digest: null,
    max_checkpoint_age_seconds: 300,
    authorization_view_max_age: 300,
    current_jwks_sha256: sha256(jwksBytes),
    current_signing_key_id: OIDC_RSA_ONE.key_id,
    current_signing_jwk_sha256: sha256(utf8Bytes(jcsCanonicalize(OIDC_RSA_ONE.public_jwk))),
    retiring_signing_key_ids: [],
    retiring_jwks_sha256: [],
    status_lists: [{
      path: live.projectionContext.status_mirror.path,
      sha256: sha256(statusList.compact),
      issuer: live.metadata.issuer,
      uri: statusUri,
    }],
    successor: null,
    authority: {
      writer_nid: live.s.writerOne.did_key,
      issued_at: now,
      checkpoint: state.checkpoint,
    },
  };
  const manifest = signedManifest(body);
  const projected = projectAccessToken(await live.authorizeProjection("access_token", {
    ...live.projectionContext,
    status_mirror: {
      ...live.projectionContext.status_mirror,
      sha256: continuityManifestDigest(manifest),
    },
  }));
  const compact = resignJwt(projected.compact, (claims) => {
    claims.scope = "control";
    claims.group_id = GROUP_ID;
    claims.authorization_id = AUTHORIZATION_ID;
    claims.grant_generation = state.credential_ledger.credential_ledger_generation;
    claims.client_class = "automated";
    claims.methods = ["config.get"];
    claims.objects = [OBJECT];
    claims.registry_checkpoint = state.checkpoint.commit_oid;
    claims[CHECKPOINT_CLAIM] = state.checkpoint;
  });
  const validatedJwt = createValidatedProjectedJwtContext(
    compact,
    live.metadata.issuer,
    "https://api.example",
    { keys: [OIDC_RSA_ONE.public_jwk] },
    {
      now,
      token_use: "access_token",
      client_id: "registered-client",
      cnf: { jkt: SENDER_KEY },
      sender_constraint: "dpop",
      permitted_audiences: ["https://api.example"],
      credential_ledger: state.credential_ledger,
    },
  );
  const continuity = validateIssuerContinuityChain([{
    manifest,
    context: {
      identity: live.identity,
      repository_rid: live.s.rid,
      canonical_branch: "main",
      writer_nid: live.s.writerOne.did_key,
      now,
      ledger_state: state,
      succession_authority: null,
      active_persona_authority: null,
    },
  }]);
  const clock = { now };
  const authority = createAuthorizationFreshnessAuthority({
    repository_rid: live.s.rid,
    persona_key: live.personaKey,
    manifest_digest: continuityManifestDigest(manifest),
  }, {
    trusted_now: () => clock.now,
    load_current_view: () => ({ manifest, ledger_state: state }),
  });
  const prepared = evaluateAuthorizationFreshness(authority, manifest);
  if (prepared.verdict !== "accept") throw new Error(`fixture freshness rejected: ${prepared.reason}`);
  const plainPrepared = evaluateAuthorizationFreshness(authority, manifest);
  if (plainPrepared.verdict !== "accept") {
    throw new Error(`plain fixture freshness rejected: ${plainPrepared.reason}`);
  }
  const grant = {
    authority_id: AUTHORITY_ID,
    authorization_id: AUTHORIZATION_ID,
    credential_ledger_persona: state.credential_ledger.credential_ledger_persona,
    grant_generation: state.credential_ledger.credential_ledger_generation,
    subject: String(validatedJwt.claims.sub),
    sender_key: SENDER_KEY,
    client_id: "registered-client",
    client_class: "automated" as const,
    marmot_group_id: GROUP_ID,
    registry_checkpoint: state.checkpoint.commit_oid,
    scopes: ["control"],
    methods: ["config.get"],
    objects: [OBJECT],
    expires_at: Number(validatedJwt.claims.exp),
    status: "active" as const,
  };
  const view = createCurrentControlGrantView({
    authorization_view: prepared.view,
    grant,
    validated_jwt: validatedJwt,
    status_list: statusList,
    status_jwks_bytes: jwksBytes,
    status_resolved_at: now,
    continuity,
  });
  return {
    compact,
    clock,
    view,
    plain_view: plainPrepared.view,
    grant,
    validatedJwt,
    statusList,
    jwksBytes,
    continuity,
  };
}

class MemoryStore implements DurableAuthorityStore<Output> {
  readonly records = new Map<string, DurableAuthorityRecord<Output>>();
  acquireCalls = 0;
  commitCalls = 0;
  markCalls = 0;
  acquireMode: "normal" | "lie" = "normal";
  commitMode: "normal" | "unknown" | "mismatch" = "normal";

  async load(key: string): Promise<DurableAuthorityRecord<Output> | null> {
    return this.records.get(key) ?? null;
  }

  async acquire(input: Readonly<{
    key: string;
    expected_revision: number | null;
    binding_digest: string;
    execution_token: string;
  }>): Promise<"acquired" | "replay" | "conflict" | "unavailable"> {
    this.acquireCalls += 1;
    const existing = this.records.get(input.key);
    if (existing !== undefined) return "replay";
    if (this.acquireMode !== "lie") {
      this.records.set(input.key, {
        state: "executing",
        revision: 0,
        binding_digest: input.binding_digest,
        execution_token: input.execution_token,
      });
    }
    return "acquired";
  }

  async compareAndSwap(): Promise<"committed" | "conflict" | "unknown"> {
    return "conflict";
  }

  async commit(input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    output_digest: string;
    output: Output;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.commitCalls += 1;
    if (this.commitMode === "unknown") return "unknown";
    this.records.set(input.key, {
      state: "committed",
      revision: 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      output_digest: input.output_digest,
      output: this.commitMode === "mismatch"
        ? { operation_id: `${input.output.operation_id}-substituted` }
        : input.output,
    });
    return "committed";
  }

  async markIndeterminate(input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    reconciliation_digest: string;
  }>): Promise<"indeterminate" | "conflict" | "unknown"> {
    this.markCalls += 1;
    this.records.set(input.key, {
      state: "indeterminate",
      revision: 1,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
      reconciliation_digest: input.reconciliation_digest,
    });
    return "indeterminate";
  }
}

function use(overrides: Partial<ControlTokenUse> = {}): ControlTokenUse {
  return {
    sender_key: SENDER_KEY,
    marmot_group_id: GROUP_ID,
    authorization_id: AUTHORIZATION_ID,
    grant_generation: 0,
    required_scope: "control",
    method: "config.get",
    object: OBJECT,
    compact_proof: "synthetic-local-control-proof-0001",
    ...overrides,
  };
}

function operation(overrides: Partial<ControlTokenOperation> = {}): ControlTokenOperation {
  return {
    operation_id: "synthetic-local-operation-0001",
    request_digest: "55".repeat(32),
    payload: { namespace: "ui", value: "dark" },
    ...overrides,
  };
}

function changedOperation(): ControlTokenOperation {
  return operation({
    operation_id: "synthetic-local-operation-0002",
    request_digest: "66".repeat(32),
  });
}

function harness(fixture: TokenFixture, options: {
  store?: MemoryStore;
  view?: CurrentAuthorizationView;
  proof?: "accept" | "reject";
  onProof?: () => void;
  authority_id?: string;
  execute?: (executionToken: string, input: ControlTokenOperation) => Promise<Output>;
} = {}) {
  const store = options.store ?? new MemoryStore();
  const calls = { proof: 0, effect: 0, proofInputs: [] as unknown[], effectInputs: [] as unknown[] };
  const proofUses = new Set<string>();
  const execute = options.execute ?? (async (executionToken, input) => {
    calls.effect += 1;
    calls.effectInputs.push({ executionToken, input });
    return Object.freeze({ operation_id: input.operation_id });
  });
  const config = {
    authority_id: options.authority_id ?? AUTHORITY_ID,
    trusted_now: () => fixture.clock.now,
    expected_issuer: live.metadata.issuer,
    expected_audience: "https://api.example",
    jwks: { keys: [OIDC_RSA_ONE.public_jwk] } as JsonValue,
    load_grant_view: async (authorizationId: string) => {
      if (authorizationId !== AUTHORIZATION_ID) throw new Error("unknown synthetic grant");
      return options.view ?? fixture.view;
    },
    consume_proof: async (input: Readonly<{
      compact_proof: string;
      sender_key: string;
      operation_digest: string;
    }>) => {
      calls.proof += 1;
      calls.proofInputs.push(input);
      options.onProof?.();
      const binding = jcsCanonicalize(input);
      if (options.proof === "reject" || proofUses.has(input.compact_proof)) return null;
      proofUses.add(input.compact_proof);
      return sha256(`synthetic-local-proof-receipt\0${binding}`);
    },
    store,
    execute_operation: execute,
  };
  return { verifier: createControlTokenVerifier(config), config, store, calls };
}

async function verified(fixture: TokenFixture, testHarness = harness(fixture)) {
  const decision = await verifyControlToken(testHarness.verifier, fixture.compact, use());
  if (decision.verdict !== "accept") throw new Error("synthetic token rejected");
  return { token: decision.output, ...testHarness };
}

describe("current Control token verifier", () => {
  it("BLUE TEAM VALIDATION: synthetic/local consumes a verified token once", async () => {
    const fixture = await tokenFixture();
    const ready = await verified(fixture);
    const first = await consumeVerifiedControlToken(ready.verifier, ready.token, operation());
    const same = await consumeVerifiedControlToken(ready.verifier, ready.token, operation());
    const second = await consumeVerifiedControlToken(ready.verifier, ready.token, changedOperation());
    expect(first).toEqual({ verdict: "accept", output: { operation_id: operation().operation_id } });
    expect(same).toEqual(first);
    expect(second).toEqual(REJECT);
    expect(ready.calls.effect).toBe(1);
    expect(ready.calls.proof).toBe(1);
    expect(ready.calls.proofInputs).toEqual([{
      compact_proof: use().compact_proof,
      sender_key: SENDER_KEY,
      operation_digest: operation().request_digest,
    }]);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects one proof reused for another operation", async () => {
    const fixture = await tokenFixture();
    const testHarness = harness(fixture);
    const first = await verified(fixture, testHarness);
    const second = await verified(fixture, testHarness);
    expect((await consumeVerifiedControlToken(first.verifier, first.token, operation())).verdict)
      .toBe("accept");
    expect(await consumeVerifiedControlToken(second.verifier, second.token, changedOperation()))
      .toEqual(REJECT);
    expect(testHarness.calls.effect).toBe(1);
  });

  it.each([
    ["issuer", (claims: Record<string, any>) => { claims.iss = `${live.metadata.issuer}/other`; }],
    ["audience", (claims: Record<string, any>) => { claims.aud = "https://other.example"; }],
    ["subject", (claims: Record<string, any>) => { claims.sub = "A".repeat(43); }],
    ["sender", (claims: Record<string, any>) => { claims.cnf = { jkt: "A".repeat(43) }; }],
    ["expiry", (claims: Record<string, any>) => { claims.exp = claims.iat; }],
    ["group", (claims: Record<string, any>) => { claims.group_id = "99".repeat(32); }],
    ["grant", (claims: Record<string, any>) => { claims.authorization_id = "99".repeat(32); }],
    ["checkpoint", (claims: Record<string, any>) => {
      claims.registry_checkpoint = "99".repeat(32);
      claims[CHECKPOINT_CLAIM].commit_oid = "99".repeat(32);
    }],
    ["generation", (claims: Record<string, any>) => {
      claims.grant_generation += 1;
      claims.credential_ledger_generation += 1;
    }],
    ["status", (claims: Record<string, any>) => { claims.status.status_list.idx = 8; }],
    ["scope", (claims: Record<string, any>) => { claims.scope = "control.admin"; }],
    ["method", (claims: Record<string, any>) => { claims.methods = ["config.set"]; }],
    ["object", (claims: Record<string, any>) => {
      claims.objects = [{ class: "config_namespace", id: "security" }];
    }],
  ])("BLUE TEAM VALIDATION: synthetic/local rejects a signed token with wrong %s binding", async (_label, mutate) => {
    const fixture = await tokenFixture();
    const changed = resignJwt(fixture.compact, mutate);
    expect(await verifyControlToken(harness(fixture).verifier, changed, use())).toEqual(REJECT);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a bad signature and token type", async () => {
    const fixture = await tokenFixture();
    const parts = fixture.compact.split(".");
    const badSignature = `${parts[2][0] === "A" ? "B" : "A"}${parts[2].slice(1)}`;
    expect(await verifyControlToken(
      harness(fixture).verifier,
      `${parts[0]}.${parts[1]}.${badSignature}`,
      use(),
    )).toEqual(REJECT);
    const wrongType = resignJwt(fixture.compact, () => undefined, (header) => {
      header.typ = "JWT";
    });
    expect(await verifyControlToken(harness(fixture).verifier, wrongType, use())).toEqual(REJECT);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects stale, plain, and cloned grant views", async () => {
    const fixture = await tokenFixture();
    expect(await verifyControlToken(
      harness(fixture, { view: fixture.plain_view }).verifier,
      fixture.compact,
      use(),
    )).toEqual(REJECT);
    expect(await verifyControlToken(
      harness(fixture, { view: { ...fixture.view } as CurrentAuthorizationView }).verifier,
      fixture.compact,
      use(),
    )).toEqual(REJECT);
    fixture.clock.now += 301;
    expect(await verifyControlToken(harness(fixture).verifier, fixture.compact, use())).toEqual(REJECT);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a current grant view across authorities", async () => {
    const fixture = await tokenFixture();
    const other = harness(fixture, { authority_id: "synthetic-local-other-authority" });
    expect(await verifyControlToken(other.verifier, fixture.compact, use())).toEqual(REJECT);
    expect(other.calls.proof).toBe(0);
    expect(other.calls.effect).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local reloads current grant state before token use", async () => {
    const fixture = await tokenFixture();
    const ready = await verified(fixture);
    fixture.clock.now += 301;
    expect(await consumeVerifiedControlToken(ready.verifier, ready.token, operation())).toEqual(REJECT);
    expect(ready.calls.proof).toBe(0);
    expect(ready.calls.effect).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local reloads current grant state after proof consumption", async () => {
    const fixture = await tokenFixture();
    const ready = await verified(fixture, harness(fixture, {
      onProof: () => { fixture.clock.now += 301; },
    }));
    expect(await consumeVerifiedControlToken(ready.verifier, ready.token, operation())).toEqual(REJECT);
    expect(ready.calls.proof).toBe(1);
    expect(ready.store.acquireCalls).toBe(0);
    expect(ready.calls.effect).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects wrong use bindings and a consumed proof", async () => {
    const fixture = await tokenFixture();
    const verifier = harness(fixture).verifier;
    for (const changed of [
      use({ sender_key: "A".repeat(43) }),
      use({ marmot_group_id: "99".repeat(32) }),
      use({ authorization_id: "99".repeat(32) }),
      use({ grant_generation: 1 }),
      use({ required_scope: "control.admin" }),
      use({ method: "config.set" }),
      use({ object: { class: "config_namespace", id: "security" } }),
    ]) {
      expect(await verifyControlToken(verifier, fixture.compact, changed)).toEqual(REJECT);
    }
    const ready = await verified(fixture, harness(fixture, { proof: "reject" }));
    expect(await consumeVerifiedControlToken(ready.verifier, ready.token, operation())).toEqual(REJECT);
    expect(ready.calls.effect).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects lookalike, cloned, and cross-authority token handles", async () => {
    const fixture = await tokenFixture();
    const first = await verified(fixture);
    const second = harness(fixture, { authority_id: "synthetic-local-other-authority" });
    expect(await consumeVerifiedControlToken(
      first.verifier,
      Object.freeze({}) as typeof first.token,
      operation(),
    )).toEqual(REJECT);
    expect(await consumeVerifiedControlToken(
      first.verifier,
      { ...first.token },
      operation(),
    )).toEqual(REJECT);
    expect(await consumeVerifiedControlToken(second.verifier, first.token, operation())).toEqual(REJECT);
    expect(first.calls.effect).toBe(0);
    expect(second.calls.effect).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects accessors and proxies without invoking traps", async () => {
    const fixture = await tokenFixture();
    const testHarness = harness(fixture);
    let traps = 0;
    const accessor = { ...use() } as Record<string, unknown>;
    Object.defineProperty(accessor, "method", {
      enumerable: true,
      get: () => { traps += 1; return "config.get"; },
    });
    expect(await verifyControlToken(testHarness.verifier, fixture.compact, accessor as ControlTokenUse))
      .toEqual(REJECT);
    const proxy = new Proxy(use(), {
      ownKeys: () => { traps += 1; return []; },
      get: () => { traps += 1; return undefined; },
    });
    expect(await verifyControlToken(testHarness.verifier, fixture.compact, proxy)).toEqual(REJECT);
    const ready = await verified(fixture, testHarness);
    const operationProxy = new Proxy(operation(), {
      ownKeys: () => { traps += 1; return []; },
      get: () => { traps += 1; return undefined; },
    });
    expect(await consumeVerifiedControlToken(ready.verifier, ready.token, operationProxy)).toEqual(REJECT);
    expect(traps).toBe(0);
    expect(ready.calls.effect).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures grant, use, operation, and constructor callbacks", async () => {
    const fixture = await tokenFixture();
    const sourceGrant = fixture.grant as { methods: string[] };
    sourceGrant.methods[0] = "config.set";
    const inputUse = use();
    const inputOperation = operation();
    let releaseEffect!: () => void;
    const effectGate = new Promise<void>((resolve) => { releaseEffect = resolve; });
    const originalEffects: string[] = [];
    const testHarness = harness(fixture, {
      execute: async (_executionToken, input) => {
        await effectGate;
        originalEffects.push(String((input.payload as Record<string, JsonValue>).value));
        return { operation_id: input.operation_id };
      },
    });
    testHarness.config.execute_operation = async () => {
      throw new Error("mutated callback must not run");
    };
    const decision = await verifyControlToken(testHarness.verifier, fixture.compact, inputUse);
    if (decision.verdict !== "accept") throw new Error("synthetic token rejected");
    const pending = consumeVerifiedControlToken(testHarness.verifier, decision.output, inputOperation);
    (inputUse as { method: string }).method = "config.set";
    (inputOperation.payload as { value: string }).value = "mutated";
    releaseEffect();
    expect(await pending).toEqual({ verdict: "accept", output: { operation_id: operation().operation_id } });
    expect(originalEffects).toEqual(["dark"]);
  });

  it("BLUE TEAM VALIDATION: synthetic/local returns an exact committed retry after verifier restart", async () => {
    const fixture = await tokenFixture();
    const first = await verified(fixture);
    const accepted = await consumeVerifiedControlToken(first.verifier, first.token, operation());
    const restarted = harness(fixture, { store: first.store });
    const replay = await verified(fixture, restarted);
    expect(await consumeVerifiedControlToken(replay.verifier, replay.token, operation())).toEqual(accepted);
    expect(first.calls.effect).toBe(1);
    expect(restarted.calls.effect).toBe(0);
    expect(restarted.calls.proof).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local requires exact executing and terminal readback", async () => {
    const fixture = await tokenFixture();
    const missingExecutingStore = new MemoryStore();
    missingExecutingStore.acquireMode = "lie";
    const missing = await verified(fixture, harness(fixture, { store: missingExecutingStore }));
    expect((await consumeVerifiedControlToken(missing.verifier, missing.token, operation())).verdict)
      .toBe("indeterminate");
    expect(missing.calls.effect).toBe(0);

    const mismatchedTerminalStore = new MemoryStore();
    mismatchedTerminalStore.commitMode = "mismatch";
    const mismatched = await verified(fixture, harness(fixture, { store: mismatchedTerminalStore }));
    expect((await consumeVerifiedControlToken(mismatched.verifier, mismatched.token, operation())).verdict)
      .toBe("indeterminate");
    expect(mismatched.calls.effect).toBe(1);
    expect(mismatchedTerminalStore.markCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes an unknown effect terminal absorbing", async () => {
    const fixture = await tokenFixture();
    const store = new MemoryStore();
    store.commitMode = "unknown";
    const ready = await verified(fixture, harness(fixture, { store }));
    const first = await consumeVerifiedControlToken(ready.verifier, ready.token, operation());
    const second = await consumeVerifiedControlToken(ready.verifier, ready.token, operation());
    expect(first.verdict).toBe("indeterminate");
    expect(second).toEqual(first);
    expect(ready.calls.effect).toBe(1);
    expect(store.markCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects function-bearing operation input", async () => {
    const fixture = await tokenFixture();
    const ready = await verified(fixture);
    expect(await consumeVerifiedControlToken(ready.verifier, ready.token, {
      ...operation(),
      execute: async () => ({ operation_id: "caller-controlled" }),
    } as never)).toEqual(REJECT);
    expect(ready.calls.effect).toBe(0);
  });
});
