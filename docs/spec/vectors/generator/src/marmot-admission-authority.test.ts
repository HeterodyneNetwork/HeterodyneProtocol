import { describe, expect, it } from "vitest";
import { beforeEach } from "vitest";
import {
  admitOrdinaryMarmotWelcome,
  createMarmotAdmissionAuthority,
  verifyMarmotWelcome,
  type AuthenticatedMarmotWelcome,
  type MarmotAdmissionAuthorityConfig,
  type MarmotPrivateKeyPackageHandle,
  type MarmotWelcomeInput,
  type MarmotWelcomeTransition,
  type VerifiedMarmotAdmission,
  type VerifiedMarmotWelcome,
} from "./marmot-admission-authority.js";
import type {
  AuthorityDecision,
  DurableAuthorityRecord,
  DurableAuthorityStore,
} from "./security-authority-support.js";

const INVITER = "11".repeat(32);
const RECIPIENT = "22".repeat(32);
const INVITER_LEAF = "33".repeat(32);
const RECIPIENT_LEAF = "44".repeat(32);
const GROUP = "55".repeat(32);
const CHECKPOINT = "conversation:7";
const NOW = 1_800_000_000;
const CAPABILITIES = ["marmot.member.account-identity-proof.v2", "marmot.admin-policy.v1"];

// Deterministic, non-deployable adapter sentinels. They exercise exact-byte
// composition only and make no claim to encode or cryptographically verify MLS.
const SYNTHETIC_WELCOME_BYTES = new Uint8Array([0x00, 0x03, 0x00, 0x01, 0xa5, 0x5a]);
const SYNTHETIC_KEY_PACKAGE_BYTES = new Uint8Array([0x00, 0x01, 0x00, 0x02, 0xc3, 0x3c]);
const PRIVATE_KEY_PACKAGE = Object.freeze({}) as MarmotPrivateKeyPackageHandle;

function exactBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

class AdmissionStore implements DurableAuthorityStore<VerifiedMarmotAdmission> {
  readonly records = new Map<string, DurableAuthorityRecord<VerifiedMarmotAdmission>>();
  effectCalls = 0;
  commitCalls = 0;
  markCalls = 0;
  commitResult: "committed" | "conflict" | "unknown" = "committed";
  substituteCommittedExecutionToken = false;
  extendCommittedRecord = false;
  extendCommittedOutput = false;

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
    const output = this.extendCommittedOutput
      ? Object.freeze({ ...input.output, attacker_extension: true })
      : input.output;
    const committed = {
      state: "committed" as const,
      revision: current.revision + 1,
      binding_digest: input.binding_digest,
      output_digest: input.output_digest,
      output,
      execution_token: this.substituteCommittedExecutionToken
        ? "00".repeat(32)
        : input.execution_token,
    };
    this.records.set(input.key, Object.freeze(this.extendCommittedRecord
      ? { ...committed, attacker_extension: true }
      : committed) as DurableAuthorityRecord<VerifiedMarmotAdmission>);
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
    if (current?.binding_digest !== input.binding_digest || current.state === "committed") {
      return "conflict";
    }
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
let projection: AuthenticatedMarmotWelcome;
let loaderCalls: number;
let processorCalls: number;
let stagedTransitionCalls: number;
let transitionCommitCalls: number;
let transitionRollbackCalls: number;
let privateKeyPackageAvailable: boolean;
let escapedProcessorWelcome: Uint8Array | null;
let escapedProcessorKeyPackage: Uint8Array | null;
let processorTrapFactory: (() => unknown) | null;

function makeTransition(): MarmotWelcomeTransition {
  stagedTransitionCalls += 1;
  let terminal: "tentative" | "committed" | "rolled-back" = "tentative";
  return Object.freeze({
    async commit(executionToken: string): Promise<void> {
      expect(executionToken).toMatch(/^[0-9a-f]{64}$/);
      if (terminal !== "tentative") throw new Error("transition not tentative");
      transitionCommitCalls += 1;
      privateKeyPackageAvailable = false;
      terminal = "committed";
    },
    rollback(): void {
      if (terminal !== "tentative") return;
      transitionRollbackCalls += 1;
      terminal = "rolled-back";
    },
  });
}

function admissionConfig(
  overrides: Partial<MarmotAdmissionAuthorityConfig> = {},
): MarmotAdmissionAuthorityConfig {
  return {
    authority_id: "local-marmot-admission",
    trusted_now: () => NOW,
    store: admissionStore,
    load_conversation: async () => Object.freeze({ ...conversation }),
    load_private_key_package: (recipientAccount, keyPackageBytes) => {
      loaderCalls += 1;
      return privateKeyPackageAvailable
          && recipientAccount === RECIPIENT
          && exactBytes(keyPackageBytes, SYNTHETIC_KEY_PACKAGE_BYTES)
        ? PRIVATE_KEY_PACKAGE
        : null;
    },
    process_mls_welcome: (input) => {
      processorCalls += 1;
      escapedProcessorWelcome = input.welcome_bytes;
      escapedProcessorKeyPackage = input.key_package_bytes;
      if (processorTrapFactory !== null) return processorTrapFactory() as never;
      if (
        input.now !== NOW
        || input.private_key_package !== PRIVATE_KEY_PACKAGE
        || !exactBytes(input.welcome_bytes, SYNTHETIC_WELCOME_BYTES)
        || !exactBytes(input.key_package_bytes, SYNTHETIC_KEY_PACKAGE_BYTES)
      ) return null;
      return Object.freeze({
        authenticated: projection,
        transition: makeTransition(),
      });
    },
    ...overrides,
  };
}

function admissionInput(overrides: Partial<MarmotWelcomeInput> = {}): MarmotWelcomeInput {
  return {
    welcome_bytes: new Uint8Array(SYNTHETIC_WELCOME_BYTES),
    key_package_bytes: new Uint8Array(SYNTHETIC_KEY_PACKAGE_BYTES),
    inviter_account: INVITER,
    recipient_account: RECIPIENT,
    group_id: GROUP,
    member_accounts: [INVITER, RECIPIENT],
    required_capabilities: [...CAPABILITIES],
    ...overrides,
  };
}

async function verifiedWelcome(
  authority: ReturnType<typeof createMarmotAdmissionAuthority>,
  input = admissionInput(),
): Promise<VerifiedMarmotWelcome> {
  const decision = await verifyMarmotWelcome(authority, input);
  expect(decision.verdict).toBe("accept");
  if (decision.verdict !== "accept") throw new Error("fixture Welcome was not verified");
  return decision.output;
}

function expectReasonlessIndeterminate(
  decision: AuthorityDecision<"conversation-rejected", VerifiedMarmotAdmission>,
): string {
  expect(decision.verdict).toBe("indeterminate");
  if (decision.verdict !== "indeterminate") throw new Error("expected indeterminate decision");
  expect(Object.keys(decision).sort()).toEqual(["reconciliation_digest", "verdict"]);
  expect(decision.reconciliation_digest).toMatch(/^[0-9a-f]{64}$/);
  return decision.reconciliation_digest;
}

describe("Marmot admission authority", () => {
  beforeEach(() => {
    admissionStore = new AdmissionStore();
    conversation = { checkpoint: CHECKPOINT, state: "unseen" };
    projection = Object.freeze({
      wire_format: "mls_welcome",
      inviter_account: INVITER,
      recipient_account: RECIPIENT,
      inviter_leaf_key: INVITER_LEAF,
      recipient_leaf_key: RECIPIENT_LEAF,
      group_id: GROUP,
      member_accounts: Object.freeze([INVITER, RECIPIENT] as const),
      required_capabilities: Object.freeze([...CAPABILITIES]),
      checkpoint: CHECKPOINT,
    });
    loaderCalls = 0;
    processorCalls = 0;
    stagedTransitionCalls = 0;
    transitionCommitCalls = 0;
    transitionRollbackCalls = 0;
    privateKeyPackageAvailable = true;
    escapedProcessorWelcome = null;
    escapedProcessorKeyPackage = null;
    processorTrapFactory = null;
  });

  it("composes a captured standards adapter and commits its private transition after acquire", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const verification = await verifyMarmotWelcome(authority, admissionInput());

    expect(verification.verdict).toBe("accept");
    if (verification.verdict !== "accept") return;
    expect(verification.output).toEqual({});
    expect(Object.isFrozen(verification.output)).toBe(true);
    expect(Object.keys(verification.output)).toEqual([]);
    expect(transitionCommitCalls).toBe(0);
    await expect(admitOrdinaryMarmotWelcome(authority, verification.output, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toEqual({
      verdict: "accept",
      output: { group_id: GROUP, checkpoint: CHECKPOINT, terminal: "accepted" },
    });
    expect(loaderCalls).toBe(1);
    expect(processorCalls).toBe(1);
    expect(admissionStore.effectCalls).toBe(1);
    expect(transitionCommitCalls).toBe(1);
    expect(admissionStore.commitCalls).toBe(1);
    expect(transitionRollbackCalls).toBe(0);
  });

  it("durably records the default no-signal hold terminal", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const welcome = await verifiedWelcome(authority);
    await expect(admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "hold",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toEqual({
      verdict: "accept",
      output: { group_id: GROUP, checkpoint: CHECKPOINT, terminal: "held" },
    });
    expect(transitionCommitCalls).toBe(1);
  });

  it.each([
    ["inviter account", { inviter_account: RECIPIENT }],
    ["recipient account", { recipient_account: INVITER }],
    ["group", { group_id: "66".repeat(32) }],
    ["members", { member_accounts: [RECIPIENT, INVITER] as [string, string] }],
    ["capabilities", { required_capabilities: [CAPABILITIES[0]] }],
    ["Welcome bytes", { welcome_bytes: new Uint8Array([0, 3, 0, 1, 0xa5, 0]) }],
    ["KeyPackage bytes", { key_package_bytes: new Uint8Array([0, 1, 0, 2, 0xc3, 0]) }],
  ] as const)("BLUE TEAM VALIDATION: synthetic/local rejects a wrong %s binding", async (
    _label,
    overrides,
  ) => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    expect(await verifyMarmotWelcome(authority, admissionInput(overrides)))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects leaf-key reuse from the authenticated projection", async () => {
    projection = Object.freeze({ ...projection, recipient_leaf_key: INVITER_LEAF });
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    expect(await verifyMarmotWelcome(authority, admissionInput()))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(transitionRollbackCalls).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local binds the authority-owned private KeyPackage handle", async () => {
    const otherHandle = Object.freeze({}) as MarmotPrivateKeyPackageHandle;
    const authority = createMarmotAdmissionAuthority(admissionConfig({
      load_private_key_package: () => otherHandle,
    }));
    expect(await verifyMarmotWelcome(authority, admissionInput()))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rolls back tentative processing on stale current state", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const welcome = await verifiedWelcome(authority);
    conversation = { checkpoint: "conversation:8", state: "unseen" };

    await expect(admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(admissionStore.effectCalls).toBe(0);
    expect(transitionCommitCalls).toBe(0);
    expect(transitionRollbackCalls).toBe(1);
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
    const welcome = await verifiedWelcome(authority);
    for (const hostile of [Object.freeze({ ...welcome }), welcome]) {
      await expect(admitOrdinaryMarmotWelcome(
        hostile === welcome ? other : authority,
        hostile as VerifiedMarmotWelcome,
        { decision: "accept", expected_checkpoint: CHECKPOINT },
      )).resolves.toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    }
    expect(admissionStore.effectCalls).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local isolates source and adapter byte mutations", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const input = admissionInput();
    const verification = await verifyMarmotWelcome(authority, input);
    expect(verification.verdict).toBe("accept");
    if (verification.verdict !== "accept") return;

    input.welcome_bytes.fill(0);
    input.key_package_bytes.fill(0);
    escapedProcessorWelcome?.fill(1);
    escapedProcessorKeyPackage?.fill(1);
    (input.member_accounts as unknown as string[])[0] = RECIPIENT;
    (input.required_capabilities as string[]).splice(0);

    await expect(admitOrdinaryMarmotWelcome(authority, verification.output, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toMatchObject({ verdict: "accept" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects input and processor proxies/accessors with zero traps", async () => {
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const ordinary = admissionInput();
    let traps = 0;
    const proxy = new Proxy(ordinary, {
      get() { traps += 1; return undefined; },
      getOwnPropertyDescriptor() { traps += 1; return undefined; },
      ownKeys() { traps += 1; return []; },
    });
    expect(await verifyMarmotWelcome(authority, proxy))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(traps).toBe(0);

    processorTrapFactory = () => new Proxy({ authenticated: projection, transition: makeTransition() }, {
      get() { traps += 1; return undefined; },
      getOwnPropertyDescriptor() { traps += 1; return undefined; },
      ownKeys() { traps += 1; return []; },
    });
    expect(await verifyMarmotWelcome(authority, admissionInput()))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(traps).toBe(0);

    let reads = 0;
    processorTrapFactory = () => Object.create(Object.prototype, {
      authenticated: {
        enumerable: true,
        get() { reads += 1; return projection; },
      },
      transition: { enumerable: true, value: makeTransition() },
    });
    expect(await verifyMarmotWelcome(authority, admissionInput()))
      .toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
    expect(reads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures callback identity once", async () => {
    let originalLoads = 0;
    const config = admissionConfig({
      load_conversation: async () => {
        originalLoads += 1;
        return Object.freeze({ ...conversation });
      },
    });
    const authority = createMarmotAdmissionAuthority(config);
    const welcome = await verifiedWelcome(authority);
    (config as { load_conversation: MarmotAdmissionAuthorityConfig["load_conversation"] })
      .load_conversation = async () => ({ checkpoint: "attacker", state: "rejected" });
    await expect(admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "hold",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toMatchObject({ verdict: "accept" });
    expect(originalLoads).toBe(1);
  });

  it("BLUE TEAM VALIDATION: synthetic/local replays an exact committed join after restart without private MLS state", async () => {
    const firstAuthority = createMarmotAdmissionAuthority(admissionConfig());
    const first = await admitOrdinaryMarmotWelcome(
      firstAuthority,
      await verifiedWelcome(firstAuthority),
      { decision: "accept", expected_checkpoint: CHECKPOINT },
    );
    expect(first).toEqual({
      verdict: "accept",
      output: { group_id: GROUP, checkpoint: CHECKPOINT, terminal: "accepted" },
    });
    expect(privateKeyPackageAvailable).toBe(false);
    const callsAfterCommit = Object.freeze({
      loader: loaderCalls,
      processor: processorCalls,
      staged: stagedTransitionCalls,
      transitionCommit: transitionCommitCalls,
      effect: admissionStore.effectCalls,
      durableCommit: admissionStore.commitCalls,
    });

    conversation = { checkpoint: CHECKPOINT, state: "accepted" };
    const restartedAuthority = createMarmotAdmissionAuthority(admissionConfig());
    const replayVerification = await verifyMarmotWelcome(restartedAuthority, admissionInput());
    expect(replayVerification.verdict).toBe("accept");
    if (replayVerification.verdict !== "accept") return;
    const retried = await admitOrdinaryMarmotWelcome(
      restartedAuthority,
      replayVerification.output,
      { decision: "accept", expected_checkpoint: CHECKPOINT },
    );

    expect(retried).toEqual(first);
    expect({
      loader: loaderCalls,
      processor: processorCalls,
      staged: stagedTransitionCalls,
      transitionCommit: transitionCommitCalls,
      effect: admissionStore.effectCalls,
      durableCommit: admissionStore.commitCalls,
    }).toEqual(callsAfterCommit);
    expect(transitionRollbackCalls).toBe(0);
  });

  it.each([
    ["malformed committed terminal", "malformed"],
    ["mismatched committed binding", "mismatched"],
    ["executing terminal", "executing"],
    ["indeterminate terminal", "indeterminate"],
  ] as const)("BLUE TEAM VALIDATION: synthetic/local does not process a %s during restart lookup", async (
    _label,
    mode,
  ) => {
    const firstAuthority = createMarmotAdmissionAuthority(admissionConfig());
    const firstWelcome = await verifiedWelcome(firstAuthority);
    await expect(admitOrdinaryMarmotWelcome(firstAuthority, firstWelcome, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toMatchObject({ verdict: "accept" });
    const entry = [...admissionStore.records.entries()][0];
    if (entry === undefined || entry[1].state !== "committed") {
      throw new Error("fixture did not persist a committed terminal");
    }
    const [key, committed] = entry;
    const replacement: DurableAuthorityRecord<VerifiedMarmotAdmission> = mode === "malformed"
      ? Object.freeze({ ...committed, attacker_extension: true }) as
        DurableAuthorityRecord<VerifiedMarmotAdmission>
      : mode === "mismatched"
        ? Object.freeze({ ...committed, binding_digest: "00".repeat(32) })
        : mode === "executing"
          ? Object.freeze({
            state: "executing",
            revision: committed.revision,
            binding_digest: committed.binding_digest,
            execution_token: committed.execution_token,
          })
          : Object.freeze({
            state: "indeterminate",
            revision: committed.revision,
            binding_digest: committed.binding_digest,
            execution_token: committed.execution_token,
            reconciliation_digest: "aa".repeat(32),
          });
    admissionStore.records.set(key, replacement);
    const callsBeforeRestart = Object.freeze({
      loader: loaderCalls,
      processor: processorCalls,
      staged: stagedTransitionCalls,
    });

    const restartedAuthority = createMarmotAdmissionAuthority(admissionConfig());
    const decision = await verifyMarmotWelcome(restartedAuthority, admissionInput());

    expect(decision.verdict).not.toBe("accept");
    expect({
      loader: loaderCalls,
      processor: processorCalls,
      staged: stagedTransitionCalls,
    }).toEqual(callsBeforeRestart);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a committed replay when retained group state is absent", async () => {
    const firstAuthority = createMarmotAdmissionAuthority(admissionConfig());
    const firstWelcome = await verifiedWelcome(firstAuthority);
    await expect(admitOrdinaryMarmotWelcome(firstAuthority, firstWelcome, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    })).resolves.toMatchObject({ verdict: "accept" });
    conversation = { checkpoint: CHECKPOINT, state: "unseen" };
    const restartedAuthority = createMarmotAdmissionAuthority(admissionConfig());
    const replayVerification = await verifyMarmotWelcome(restartedAuthority, admissionInput());
    expect(replayVerification.verdict).toBe("accept");
    if (replayVerification.verdict !== "accept") return;

    await expect(admitOrdinaryMarmotWelcome(
      restartedAuthority,
      replayVerification.output,
      { decision: "accept", expected_checkpoint: CHECKPOINT },
    )).resolves.toEqual({ verdict: "reject", reason_code: "conversation-rejected" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local makes an unknown commit digest-bearing and never repeats the MLS effect", async () => {
    admissionStore.commitResult = "unknown";
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const welcome = await verifiedWelcome(authority);
    const first = await admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    });
    const second = await admitOrdinaryMarmotWelcome(authority, welcome, {
      decision: "accept",
      expected_checkpoint: CHECKPOINT,
    });
    expect(expectReasonlessIndeterminate(second)).toBe(expectReasonlessIndeterminate(first));
    expect(admissionStore.effectCalls).toBe(1);
    expect(transitionCommitCalls).toBe(1);
    expect(admissionStore.commitCalls).toBe(1);
    expect(admissionStore.markCalls).toBe(1);
  });

  it.each([
    ["non-equal committed execution token", "token"],
    ["extended committed record", "record"],
    ["extended committed output", "output"],
  ] as const)("BLUE TEAM VALIDATION: synthetic/local rejects a %s", async (_label, mode) => {
    admissionStore.substituteCommittedExecutionToken = mode === "token";
    admissionStore.extendCommittedRecord = mode === "record";
    admissionStore.extendCommittedOutput = mode === "output";
    const authority = createMarmotAdmissionAuthority(admissionConfig());
    const result = await admitOrdinaryMarmotWelcome(
      authority,
      await verifiedWelcome(authority),
      { decision: "accept", expected_checkpoint: CHECKPOINT },
    );
    expectReasonlessIndeterminate(result);
    expect(admissionStore.effectCalls).toBe(1);
    expect(transitionCommitCalls).toBe(1);
  });
});
