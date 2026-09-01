import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { beforeEach } from "vitest";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import {
  admitOrdinaryMarmotWelcome,
  createMarmotAdmissionAuthority,
  verifyMarmotWelcome,
  type MarmotAdmissionAuthorityConfig,
  type MarmotWelcomeInput,
  type VerifiedMarmotAdmission,
  type VerifiedMarmotWelcome,
} from "./marmot-admission-authority.js";
import type {
  DurableAuthorityRecord,
  DurableAuthorityStore,
} from "./security-authority-support.js";

const INVITER_SECRET = "11".repeat(32);
const RECIPIENT_SECRET = "22".repeat(32);
const INVITER = bytesToHex(schnorr.getPublicKey(hexToBytes(INVITER_SECRET)));
const RECIPIENT = bytesToHex(schnorr.getPublicKey(hexToBytes(RECIPIENT_SECRET)));
const INVITER_LEAF = "33".repeat(32);
const RECIPIENT_LEAF = "44".repeat(32);
const GROUP = "55".repeat(32);
const CHECKPOINT = "conversation:7";
const NOW = 1_800_000_000;
const CAPABILITIES = ["marmot.member.account-identity-proof.v2", "marmot.admin-policy.v1"];

type KeyPackageFixture = Readonly<{
  version: 1;
  account: string;
  leaf_key: string;
  capabilities: readonly string[];
  not_before: number;
  not_after: number;
  signature: string;
}>;

type WelcomeFixture = Readonly<{
  version: 1;
  group_id: string;
  inviter_account: string;
  recipient_account: string;
  inviter_leaf_key: string;
  recipient_leaf_key: string;
  member_accounts: readonly [string, string];
  required_capabilities: readonly string[];
  key_package_digest: string;
  checkpoint: string;
  not_before: number;
  not_after: number;
  signature: string;
}>;

const encode = (value: unknown): Uint8Array => utf8Bytes(JSON.stringify(value));
const digest = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const sign = (value: Readonly<Record<string, unknown>>, secret: string): string => bytesToHex(
  schnorr.sign(
    createHash("sha256").update(encode(value)).digest(),
    hexToBytes(secret),
    "00".repeat(32),
  ),
);

function keyPackageFixture(
  overrides: Partial<Omit<KeyPackageFixture, "signature">> = {},
): Uint8Array {
  const unsigned = {
    version: 1 as const,
    account: RECIPIENT,
    leaf_key: RECIPIENT_LEAF,
    capabilities: [...CAPABILITIES],
    not_before: NOW - 60,
    not_after: NOW + 60,
    ...overrides,
  };
  return encode({ ...unsigned, signature: sign(unsigned, RECIPIENT_SECRET) });
}

function welcomeFixture(
  keyPackage: Uint8Array,
  overrides: Partial<Omit<WelcomeFixture, "signature">> = {},
): Uint8Array {
  const unsigned = {
    version: 1 as const,
    group_id: GROUP,
    inviter_account: INVITER,
    recipient_account: RECIPIENT,
    inviter_leaf_key: INVITER_LEAF,
    recipient_leaf_key: RECIPIENT_LEAF,
    member_accounts: [INVITER, RECIPIENT] as const,
    required_capabilities: [...CAPABILITIES],
    key_package_digest: digest(keyPackage),
    checkpoint: CHECKPOINT,
    not_before: NOW - 60,
    not_after: NOW + 60,
    ...overrides,
  };
  return encode({ ...unsigned, signature: sign(unsigned, INVITER_SECRET) });
}

function verifyKeyPackage(bytes: Uint8Array): Readonly<{
  account: string;
  leaf_key: string;
  capabilities: readonly string[];
}> | null {
  try {
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as KeyPackageFixture;
    const { signature, ...unsigned } = parsed;
    if (
      Object.keys(parsed).length !== 7
      || parsed.version !== 1
      || !Number.isSafeInteger(parsed.not_before)
      || !Number.isSafeInteger(parsed.not_after)
      || NOW < parsed.not_before
      || NOW > parsed.not_after
      || !Array.isArray(parsed.capabilities)
      || !parsed.capabilities.every((value) => typeof value === "string")
      || !schnorr.verify(
        signature,
        createHash("sha256").update(encode(unsigned)).digest(),
        parsed.account,
      )
    ) return null;
    return Object.freeze({
      account: parsed.account,
      leaf_key: parsed.leaf_key,
      capabilities: Object.freeze([...parsed.capabilities]),
    });
  } catch {
    return null;
  }
}

class AdmissionStore implements DurableAuthorityStore<VerifiedMarmotAdmission> {
  readonly records = new Map<string, DurableAuthorityRecord<VerifiedMarmotAdmission>>();
  effectCalls = 0;
  commitCalls = 0;
  markCalls = 0;
  commitResult: "committed" | "conflict" | "unknown" = "committed";
  substituteCommittedExecutionToken = false;

  async load(key: string): Promise<DurableAuthorityRecord<VerifiedMarmotAdmission> | null> {
    return this.records.get(key) ?? null;
  }

  async acquire(input: Readonly<{
    key: string;
    expected_revision: number | null;
    binding_digest: string;
    execution_token: string;
  }>): Promise<"acquired" | "replay" | "conflict" | "unavailable"> {
    const current = this.records.get(input.key);
    if (current !== undefined) {
      return current.binding_digest === input.binding_digest ? "replay" : "conflict";
    }
    if (input.expected_revision !== null) return "conflict";
    this.records.set(input.key, Object.freeze({
      state: "executing",
      revision: 0,
      binding_digest: input.binding_digest,
      execution_token: input.execution_token,
    }));
    this.effectCalls += 1;
    return "acquired";
  }

  async compareAndSwap(input: Readonly<{
    key: string;
    expected_revision: number | null;
    next: DurableAuthorityRecord<VerifiedMarmotAdmission>;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    const current = this.records.get(input.key);
    if ((current?.revision ?? null) !== input.expected_revision) return "conflict";
    this.records.set(input.key, input.next);
    return "committed";
  }

  async commit(input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    output_digest: string;
    output: VerifiedMarmotAdmission;
  }>): Promise<"committed" | "conflict" | "unknown"> {
    this.commitCalls += 1;
    if (this.commitResult !== "committed") return this.commitResult;
    const current = this.records.get(input.key);
    if (
      current?.state !== "executing"
      || current.binding_digest !== input.binding_digest
      || current.execution_token !== input.execution_token
    ) return "conflict";
    this.records.set(input.key, Object.freeze({
      state: "committed",
      revision: current.revision + 1,
      ...input,
      execution_token: this.substituteCommittedExecutionToken
        ? "00".repeat(32)
        : input.execution_token,
    }));
    return "committed";
  }

  async markIndeterminate(input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    reconciliation_digest: string;
  }>): Promise<"indeterminate" | "conflict" | "unknown"> {
    this.markCalls += 1;
    const current = this.records.get(input.key);
    if (
      current?.binding_digest !== input.binding_digest
      || current.state === "committed"
    ) return "conflict";
    this.records.set(input.key, Object.freeze({
      state: "indeterminate",
      revision: current.revision + 1,
      ...input,
    }));
    return "indeterminate";
  }
}

let admissionStore: AdmissionStore;
let conversation: {
  checkpoint: string;
  state: "unseen" | "held" | "accepted" | "rejected";
};

function admissionConfig(
  overrides: Partial<MarmotAdmissionAuthorityConfig> = {},
): MarmotAdmissionAuthorityConfig {
  return {
    authority_id: "local-marmot-admission",
    trusted_now: () => NOW,
    store: admissionStore,
    load_conversation: async () => Object.freeze({ ...conversation }),
    verify_key_package: verifyKeyPackage,
    ...overrides,
  };
}

function admissionInput(
  overrides: Partial<MarmotWelcomeInput> = {},
  welcomeOverrides: Partial<Omit<WelcomeFixture, "signature">> = {},
  keyPackageOverrides: Partial<Omit<KeyPackageFixture, "signature">> = {},
): MarmotWelcomeInput {
  const keyPackage = keyPackageFixture(keyPackageOverrides);
  return {
    welcome_bytes: welcomeFixture(keyPackage, welcomeOverrides),
    key_package_bytes: keyPackage,
    inviter_account: INVITER,
    recipient_account: RECIPIENT,
    group_id: GROUP,
    member_accounts: [INVITER, RECIPIENT],
    required_capabilities: [...CAPABILITIES],
    ...overrides,
  };
}

function verifiedWelcome(
  authority: ReturnType<typeof createMarmotAdmissionAuthority>,
  input = admissionInput(),
): VerifiedMarmotWelcome {
  const decision = verifyMarmotWelcome(authority, input);
  expect(decision.verdict).toBe("accept");
  if (decision.verdict !== "accept") throw new Error("fixture Welcome was not verified");
  return decision.output;
}

describe("Marmot admission authority", () => {
  beforeEach(() => {
    admissionStore = new AdmissionStore();
    conversation = { checkpoint: CHECKPOINT, state: "unseen" };
  });

  it("verifies exact signed bytes and durably accepts the bound ordinary Welcome", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const verification = verifyMarmotWelcome(authority, admissionInput());

    expect(verification.verdict).toBe("accept");
    if (verification.verdict !== "accept") return;
    expect(verification.output).toEqual({});
    expect(Object.isFrozen(verification.output)).toBe(true);
    expect(Object.keys(verification.output)).toEqual([]);
    await expect(admitOrdinaryMarmotWelcome(authority, verification.output, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toEqual({
      verdict: "accept",
      output: { group_id: GROUP, checkpoint: CHECKPOINT, terminal: "accepted" },
    });
    expect(admissionStore.effectCalls).toBe(1);
    expect(admissionStore.commitCalls).toBe(1);
  });

  it("durably records the default no-signal hold terminal", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const welcome = verifiedWelcome(authority);

    await expect(admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "hold",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toEqual({
      verdict: "accept",
      output: { group_id: GROUP, checkpoint: CHECKPOINT, terminal: "held" },
    });
  });

  it.each([
    ["inviter account", { inviter_account: RECIPIENT }, {}],
    ["recipient account", { recipient_account: INVITER }, {}],
    ["group", { group_id: "66".repeat(32) }, {}],
    ["members", { member_accounts: [RECIPIENT, INVITER] as [string, string] }, {}],
    ["capabilities", { required_capabilities: [CAPABILITIES[0]] }, {}],
  ] as const)("BLUE TEAM VALIDATION: synthetic/local rejects a wrong %s binding", (
    _label,
    overrides,
    welcomeOverrides,
  ) => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    expect(verifyMarmotWelcome(authority, admissionInput(overrides, welcomeOverrides)))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects leaf-key reuse across accounts", () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const input = admissionInput(
      {},
      { recipient_leaf_key: INVITER_LEAF },
      { leaf_key: INVITER_LEAF },
    );
    expect(verifyMarmotWelcome(authority, input))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a stale conversation checkpoint", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const welcome = verifiedWelcome(authority);
    conversation = { checkpoint: "conversation:8", state: "unseen" };

    await expect(admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(admissionStore.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a caller-shaped Welcome", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const fake = Object.freeze({});
    await expect(admitOrdinaryMarmotWelcome(
      authority, fake as VerifiedMarmotWelcome,
      { decision: "accept", expected_checkpoint: CHECKPOINT },
    )).resolves.toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(admissionStore.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects clone and cross-authority handles", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const other = createMarmotAdmissionAuthority(admissionConfig({ authority_id: "other-authority" }));
    const welcome = verifiedWelcome(authority);

    for (const hostile of [Object.freeze({ ...welcome }), welcome]) {
      await expect(admitOrdinaryMarmotWelcome(
        hostile === welcome ? other : authority,
        hostile as VerifiedMarmotWelcome,
        { decision: "accept", expected_checkpoint: CHECKPOINT },
      )).resolves.toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    }
    expect(admissionStore.effectCalls).toBe(0);
  });

  it("isolates captured verification from later source mutation", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const input = admissionInput();
    const verification = verifyMarmotWelcome(authority, input);
    expect(verification.verdict).toBe("accept");
    if (verification.verdict !== "accept") return;

    input.welcome_bytes.fill(0);
    input.key_package_bytes.fill(0);
    (input.member_accounts as unknown as string[])[0] = RECIPIENT;
    (input.required_capabilities as string[]).splice(0);

    await expect(admitOrdinaryMarmotWelcome(authority, verification.output, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toMatchObject({ verdict: "accept" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects input accessors and proxies with zero traps", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const ordinary = admissionInput();
    let reads = 0;
    const accessor = Object.create(Object.prototype, {
      welcome_bytes: {
        enumerable: true,
        get() {
          reads += 1;
          return ordinary.welcome_bytes;
        },
      },
    });
    let traps = 0;
    const proxy = new Proxy(ordinary, {
      get() {
        traps += 1;
        return undefined;
      },
      getOwnPropertyDescriptor() {
        traps += 1;
        return undefined;
      },
      ownKeys() {
        traps += 1;
        return [];
      },
    });

    expect(verifyMarmotWelcome(authority, accessor as MarmotWelcomeInput))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(verifyMarmotWelcome(authority, proxy))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(reads).toBe(0);
    expect(traps).toBe(0);

    const welcome = verifiedWelcome(authority);
    const acceptanceProxy = new Proxy({
      decision: "accept" as const,
      expected_checkpoint: CHECKPOINT,
    }, {
      get() {
        traps += 1;
        return undefined;
      },
    });
    await expect(admitOrdinaryMarmotWelcome(authority, welcome, acceptanceProxy))
      .resolves.toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(traps).toBe(0);
    expect(admissionStore.effectCalls).toBe(0);
  });

  it("captures callback identity once at authority construction", async () => {
    let originalLoads = 0;
    const config = admissionConfig({
      load_conversation: async () => {
        originalLoads += 1;
        return Object.freeze({ ...conversation });
      },
    });
    const authority = createMarmotAdmissionAuthority(config);
    const welcome = verifiedWelcome(authority);
    (config as { load_conversation: MarmotAdmissionAuthorityConfig["load_conversation"] })
      .load_conversation = async () => ({ checkpoint: "attacker", state: "rejected" });

    await expect(admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "hold",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toMatchObject({ verdict: "accept" });
    expect(originalLoads).toBe(1);
  });

  it("returns an exact committed retry after authority restart without repeating admission", async () => {
    const firstAuthority = createMarmotAdmissionAuthority(admissionConfig());
    const first = await admitOrdinaryMarmotWelcome(
      firstAuthority,
      verifiedWelcome(firstAuthority),
      { decision: "accept", expected_checkpoint: CHECKPOINT },
    );
    conversation = { checkpoint: CHECKPOINT, state: "accepted" };
    const restartedAuthority = createMarmotAdmissionAuthority(admissionConfig());
    const retried = await admitOrdinaryMarmotWelcome(
      restartedAuthority,
      verifiedWelcome(restartedAuthority),
      { decision: "accept", expected_checkpoint: CHECKPOINT },
    );

    expect(retried).toEqual(first);
    expect(admissionStore.effectCalls).toBe(1);
    expect(admissionStore.commitCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes an unknown commit indeterminate and never repeats it", async () => {
    admissionStore.commitResult = "unknown";
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const welcome = verifiedWelcome(authority);

    await expect(admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toEqual({ verdict: "indeterminate" });
    await expect(admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toEqual({ verdict: "indeterminate" });
    expect(admissionStore.effectCalls).toBe(1);
    expect(admissionStore.commitCalls).toBe(1);
    expect(admissionStore.markCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a non-equal committed execution token", async () => {
    admissionStore.substituteCommittedExecutionToken = true;
    const authority = createMarmotAdmissionAuthority(admissionConfig());

    await expect(admitOrdinaryMarmotWelcome(
      authority,
      verifiedWelcome(authority),
      { decision: "accept", expected_checkpoint: CHECKPOINT },
    )).resolves.toEqual({ verdict: "indeterminate" });
    expect(admissionStore.effectCalls).toBe(1);
  });
});
