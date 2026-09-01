import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import { schnorr } from "@noble/curves/secp256k1";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type AuthorityDecision,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
} from "./security-authority-support.js";

const REJECT = Object.freeze({
  verdict: "reject" as const,
  reason_code: "conversation-rejected" as const,
});
const INDETERMINATE = Object.freeze({ verdict: "indeterminate" as const });
const HEX_32 = /^[0-9a-f]{64}$/;
const HEX_64 = /^[0-9a-f]{128}$/;

export type MarmotAdmissionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  store: DurableAuthorityStore<VerifiedMarmotAdmission>;
  load_conversation: (account: string, group_id: string) => Promise<Readonly<{
    checkpoint: string; state: "unseen" | "held" | "accepted" | "rejected";
  }>>;
  verify_key_package: (bytes: Uint8Array) => Readonly<{
    account: string; leaf_key: string; capabilities: readonly string[];
  }> | null;
}>;

export type MarmotWelcomeInput = Readonly<{
  welcome_bytes: Uint8Array; key_package_bytes: Uint8Array;
  inviter_account: string; recipient_account: string; group_id: string;
  member_accounts: readonly [string, string]; required_capabilities: readonly string[];
}>;

export type MarmotAdmissionAcceptance = Readonly<{
  decision: "accept" | "hold" | "reject"; expected_checkpoint: string;
}>;

export type VerifiedMarmotAdmission = Readonly<{
  group_id: string; checkpoint: string; terminal: "accepted" | "held";
}>;

export type MarmotAdmissionAuthority = Readonly<Record<never, never>>;
export type VerifiedMarmotWelcome = Readonly<Record<never, never>>;
export type MarmotAdmissionDecision = AuthorityDecision<
  "conversation-rejected", VerifiedMarmotAdmission
>;
export type MarmotWelcomeDecision = AuthorityDecision<
  "conversation-rejected", VerifiedMarmotWelcome
>;

type StoreCallbacks = Readonly<{
  load: DurableAuthorityStore<VerifiedMarmotAdmission>["load"];
  acquire: DurableAuthorityStore<VerifiedMarmotAdmission>["acquire"];
  compareAndSwap: DurableAuthorityStore<VerifiedMarmotAdmission>["compareAndSwap"];
  commit: DurableAuthorityStore<VerifiedMarmotAdmission>["commit"];
  markIndeterminate: DurableAuthorityStore<VerifiedMarmotAdmission>["markIndeterminate"];
}>;

type AuthorityRecord = Readonly<{
  authority_id: string;
  trusted_now: MarmotAdmissionAuthorityConfig["trusted_now"];
  load_conversation: MarmotAdmissionAuthorityConfig["load_conversation"];
  verify_key_package: MarmotAdmissionAuthorityConfig["verify_key_package"];
  store: StoreCallbacks;
}>;

type WelcomeRecord = Readonly<{
  authority: MarmotAdmissionAuthority;
  welcome_bytes: Uint8Array;
  key_package_bytes: Uint8Array;
  inviter_account: string;
  recipient_account: string;
  group_id: string;
  inviter_leaf_key: string;
  recipient_leaf_key: string;
  member_accounts: readonly [string, string];
  required_capabilities: readonly string[];
  checkpoint: string;
}>;

type SignedWelcome = Readonly<{
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

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const WELCOMES = new WeakMap<object, WelcomeRecord>();

function ownDataProperty(object: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`Marmot admission config requires data property ${name}`);
  }
  return descriptor.value;
}

function boundMethod<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  let owner: object | null = object;
  while (owner !== null) {
    if (utilTypes.isProxy(owner)) throw new TypeError("Marmot admission store cannot be a proxy");
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new TypeError(`Marmot admission store requires data method ${name}`);
      }
      return descriptor.value.bind(object) as T;
    }
    owner = Object.getPrototypeOf(owner) as object | null;
  }
  throw new TypeError(`Marmot admission store requires method ${name}`);
}

function snapshotConfig(config: MarmotAdmissionAuthorityConfig): AuthorityRecord {
  if (
    config === null
    || typeof config !== "object"
    || utilTypes.isProxy(config)
    || Object.getPrototypeOf(config) !== Object.prototype
  ) throw new TypeError("Marmot admission config must be an ordinary object");
  const descriptors = Object.getOwnPropertyDescriptors(config);
  const required = [
    "authority_id",
    "trusted_now",
    "store",
    "load_conversation",
    "verify_key_package",
  ];
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
    || Object.keys(descriptors).length !== required.length
    || !required.every((name) => Object.hasOwn(descriptors, name))
  ) throw new TypeError("Marmot admission config must be closed");
  const authorityId = ownDataProperty(config, "authority_id");
  const trustedNow = ownDataProperty(config, "trusted_now");
  const store = ownDataProperty(config, "store");
  const loadConversation = ownDataProperty(config, "load_conversation");
  const verifyKeyPackage = ownDataProperty(config, "verify_key_package");
  if (
    typeof authorityId !== "string"
    || authorityId.length === 0
    || typeof trustedNow !== "function"
    || typeof loadConversation !== "function"
    || typeof verifyKeyPackage !== "function"
    || store === null
    || typeof store !== "object"
    || utilTypes.isProxy(store)
  ) throw new TypeError("invalid Marmot admission config");
  return Object.freeze({
    authority_id: authorityId,
    trusted_now: trustedNow as MarmotAdmissionAuthorityConfig["trusted_now"],
    load_conversation: loadConversation as MarmotAdmissionAuthorityConfig["load_conversation"],
    verify_key_package: verifyKeyPackage as MarmotAdmissionAuthorityConfig["verify_key_package"],
    store: Object.freeze({
      load: boundMethod<StoreCallbacks["load"]>(store, "load"),
      acquire: boundMethod<StoreCallbacks["acquire"]>(store, "acquire"),
      compareAndSwap: boundMethod<StoreCallbacks["compareAndSwap"]>(store, "compareAndSwap"),
      commit: boundMethod<StoreCallbacks["commit"]>(store, "commit"),
      markIndeterminate: boundMethod<StoreCallbacks["markIndeterminate"]>(store, "markIndeterminate"),
    }),
  });
}

export function createMarmotAdmissionAuthority(
  config: MarmotAdmissionAuthorityConfig,
): MarmotAdmissionAuthority {
  const record = snapshotConfig(config);
  const authority = Object.freeze({});
  AUTHORITIES.set(authority, record);
  return authority;
}

function equalStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function exactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length
    && [...keys].sort().every((key, index) => actual[index] === key);
}

function decodeSignedWelcome(bytes: Uint8Array, now: number): SignedWelcome | null {
  try {
    const parsed = captureAuthorityInput(JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    ));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const value = parsed as Readonly<Record<string, unknown>>;
    if (!exactKeys(value, [
      "version", "group_id", "inviter_account", "recipient_account",
      "inviter_leaf_key", "recipient_leaf_key", "member_accounts",
      "required_capabilities", "key_package_digest", "checkpoint",
      "not_before", "not_after", "signature",
    ])) return null;
    const members = value.member_accounts;
    const capabilities = value.required_capabilities;
    if (
      value.version !== 1
      || typeof value.group_id !== "string" || !HEX_32.test(value.group_id)
      || typeof value.inviter_account !== "string" || !HEX_32.test(value.inviter_account)
      || typeof value.recipient_account !== "string" || !HEX_32.test(value.recipient_account)
      || typeof value.inviter_leaf_key !== "string" || !HEX_32.test(value.inviter_leaf_key)
      || typeof value.recipient_leaf_key !== "string" || !HEX_32.test(value.recipient_leaf_key)
      || !Array.isArray(members) || members.length !== 2
      || !members.every((member) => typeof member === "string" && HEX_32.test(member))
      || !Array.isArray(capabilities) || capabilities.length === 0
      || !capabilities.every((capability) => typeof capability === "string" && capability.length > 0)
      || new Set(capabilities).size !== capabilities.length
      || typeof value.key_package_digest !== "string" || !HEX_32.test(value.key_package_digest)
      || typeof value.checkpoint !== "string" || value.checkpoint.length === 0
      || !Number.isSafeInteger(value.not_before) || !Number.isSafeInteger(value.not_after)
      || (value.not_before as number) > now || now > (value.not_after as number)
      || typeof value.signature !== "string" || !HEX_64.test(value.signature)
    ) return null;
    const unsigned = {
      version: 1 as const,
      group_id: value.group_id,
      inviter_account: value.inviter_account,
      recipient_account: value.recipient_account,
      inviter_leaf_key: value.inviter_leaf_key,
      recipient_leaf_key: value.recipient_leaf_key,
      member_accounts: members as unknown as readonly [string, string],
      required_capabilities: capabilities as unknown as readonly string[],
      key_package_digest: value.key_package_digest,
      checkpoint: value.checkpoint,
      not_before: value.not_before as number,
      not_after: value.not_after as number,
    };
    const message = createHash("sha256").update(JSON.stringify(unsigned), "utf8").digest();
    if (!schnorr.verify(value.signature, message, value.inviter_account)) return null;
    return Object.freeze({ ...unsigned, signature: value.signature });
  } catch {
    return null;
  }
}

function capturedWelcomeInput(input: MarmotWelcomeInput): Readonly<MarmotWelcomeInput> | null {
  try {
    const captured = captureAuthorityInput(input);
    if (!exactKeys(captured as unknown as Readonly<Record<string, unknown>>, [
      "welcome_bytes", "key_package_bytes", "inviter_account", "recipient_account",
      "group_id", "member_accounts", "required_capabilities",
    ])) return null;
    if (
      !(captured.welcome_bytes instanceof Uint8Array)
      || !(captured.key_package_bytes instanceof Uint8Array)
      || typeof captured.inviter_account !== "string"
      || typeof captured.recipient_account !== "string"
      || typeof captured.group_id !== "string"
      || !Array.isArray(captured.member_accounts)
      || captured.member_accounts.length !== 2
      || !captured.member_accounts.every((member) => typeof member === "string")
      || !Array.isArray(captured.required_capabilities)
      || !captured.required_capabilities.every((capability) => typeof capability === "string")
    ) return null;
    return captured;
  } catch {
    return null;
  }
}

export function verifyMarmotWelcome(
  authority: MarmotAdmissionAuthority,
  input: MarmotWelcomeInput,
): MarmotWelcomeDecision {
  const authorityRecord = AUTHORITIES.get(authority);
  if (authorityRecord === undefined) return REJECT;
  const captured = capturedWelcomeInput(input);
  if (captured === null) return REJECT;
  try {
    const now = authorityRecord.trusted_now();
    if (!Number.isSafeInteger(now) || now < 0) return REJECT;
    const welcome = decodeSignedWelcome(captured.welcome_bytes, now);
    if (welcome === null) return REJECT;
    const keyPackageResult = authorityRecord.verify_key_package(
      new Uint8Array(captured.key_package_bytes),
    );
    if (keyPackageResult === null) return REJECT;
    const keyPackage = captureAuthorityInput(keyPackageResult);
    if (!exactKeys(keyPackage as unknown as Readonly<Record<string, unknown>>, [
      "account", "leaf_key", "capabilities",
    ])) return REJECT;
    if (
      typeof keyPackage.account !== "string"
      || !HEX_32.test(keyPackage.account)
      || typeof keyPackage.leaf_key !== "string"
      || !HEX_32.test(keyPackage.leaf_key)
      || !Array.isArray(keyPackage.capabilities)
      || !keyPackage.capabilities.every((capability) => typeof capability === "string")
      || welcome.inviter_account === welcome.recipient_account
      || welcome.inviter_leaf_key === welcome.recipient_leaf_key
      || welcome.inviter_account !== captured.inviter_account
      || welcome.recipient_account !== captured.recipient_account
      || welcome.group_id !== captured.group_id
      || !equalStrings(welcome.member_accounts, captured.member_accounts)
      || welcome.member_accounts[0] !== welcome.inviter_account
      || welcome.member_accounts[1] !== welcome.recipient_account
      || !equalStrings(welcome.required_capabilities, captured.required_capabilities)
      || welcome.key_package_digest !== createHash("sha256")
        .update(captured.key_package_bytes).digest("hex")
      || keyPackage.account !== welcome.recipient_account
      || keyPackage.leaf_key !== welcome.recipient_leaf_key
      || !welcome.required_capabilities.every((capability) =>
        keyPackage.capabilities.includes(capability)
      )
    ) return REJECT;
    const handle = Object.freeze({});
    WELCOMES.set(handle, Object.freeze({
      authority,
      welcome_bytes: new Uint8Array(captured.welcome_bytes),
      key_package_bytes: new Uint8Array(captured.key_package_bytes),
      inviter_account: welcome.inviter_account,
      recipient_account: welcome.recipient_account,
      group_id: welcome.group_id,
      inviter_leaf_key: welcome.inviter_leaf_key,
      recipient_leaf_key: welcome.recipient_leaf_key,
      member_accounts: Object.freeze([...welcome.member_accounts]) as readonly [string, string],
      required_capabilities: Object.freeze([...welcome.required_capabilities]),
      checkpoint: welcome.checkpoint,
    }));
    return Object.freeze({ verdict: "accept", output: handle });
  } catch {
    return REJECT;
  }
}

function captureConversation(value: unknown): Readonly<{
  checkpoint: string;
  state: "unseen" | "held" | "accepted" | "rejected";
}> | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const record = captured as Readonly<Record<string, unknown>>;
    if (
      !exactKeys(record, ["checkpoint", "state"])
      || typeof record.checkpoint !== "string"
      || !["unseen", "held", "accepted", "rejected"].includes(String(record.state))
    ) return null;
    return record as Readonly<{
      checkpoint: string;
      state: "unseen" | "held" | "accepted" | "rejected";
    }>;
  } catch {
    return null;
  }
}

function captureDurableRecord(
  value: DurableAuthorityRecord<VerifiedMarmotAdmission> | null,
): DurableAuthorityRecord<VerifiedMarmotAdmission> | null | undefined {
  if (value === null) return null;
  try {
    const captured = captureAuthorityInput(value);
    if (
      captured === null
      || typeof captured !== "object"
      || Array.isArray(captured)
      || !Number.isSafeInteger(captured.revision)
      || captured.revision < 0
      || typeof captured.binding_digest !== "string"
      || !HEX_32.test(captured.binding_digest)
      || !["available", "executing", "committed", "indeterminate"].includes(captured.state)
    ) return undefined;
    return captured;
  } catch {
    return undefined;
  }
}

function committedOutput(
  record: DurableAuthorityRecord<VerifiedMarmotAdmission>,
  bindingDigest: string,
  executionToken: string,
  outputDigest: string,
): VerifiedMarmotAdmission | null {
  if (
    record.state !== "committed"
    || record.binding_digest !== bindingDigest
    || record.execution_token !== executionToken
    || record.output_digest !== outputDigest
  ) return null;
  try {
    const output = captureAuthorityInput(record.output);
    if (
      output.group_id.length !== 64
      || typeof output.checkpoint !== "string"
      || !["accepted", "held"].includes(output.terminal)
      || authorityBindingDigest("heterodyne.marmot-admission.output/v1", {
        group_id: output.group_id,
        checkpoint: output.checkpoint,
        terminal: output.terminal,
      }) !== outputDigest
    ) return null;
    return output;
  } catch {
    return null;
  }
}

async function safeMarkIndeterminate(
  store: StoreCallbacks,
  input: Readonly<{
    key: string;
    binding_digest: string;
    execution_token: string;
    reconciliation_digest: string;
  }>,
): Promise<void> {
  try {
    await store.markIndeterminate(input);
  } catch {
    // The public state remains indeterminate even if the absorbing write is unavailable.
  }
}

export async function admitOrdinaryMarmotWelcome(
  authority: MarmotAdmissionAuthority,
  welcome: VerifiedMarmotWelcome,
  acceptance: MarmotAdmissionAcceptance,
): Promise<MarmotAdmissionDecision> {
  const authorityRecord = AUTHORITIES.get(authority);
  const welcomeRecord = WELCOMES.get(welcome);
  if (
    authorityRecord === undefined
    || welcomeRecord === undefined
    || welcomeRecord.authority !== authority
  ) return REJECT;
  let capturedAcceptance: Readonly<MarmotAdmissionAcceptance>;
  try {
    capturedAcceptance = captureAuthorityInput(acceptance);
    if (
      !exactKeys(capturedAcceptance as unknown as Readonly<Record<string, unknown>>, [
        "decision", "expected_checkpoint",
      ])
      || !["accept", "hold", "reject"].includes(capturedAcceptance.decision)
      || typeof capturedAcceptance.expected_checkpoint !== "string"
    ) return REJECT;
  } catch {
    return REJECT;
  }
  if (capturedAcceptance.decision === "reject") return REJECT;

  let conversation;
  try {
    conversation = captureConversation(await authorityRecord.load_conversation(
      welcomeRecord.recipient_account,
      welcomeRecord.group_id,
    ));
  } catch {
    return REJECT;
  }
  if (
    conversation === null
    || conversation.state === "rejected"
    || conversation.checkpoint !== welcomeRecord.checkpoint
    || conversation.checkpoint !== capturedAcceptance.expected_checkpoint
  ) return REJECT;

  const terminal = capturedAcceptance.decision === "accept" ? "accepted" : "held";
  const output = Object.freeze({
    group_id: welcomeRecord.group_id,
    checkpoint: conversation.checkpoint,
    terminal,
  }) as VerifiedMarmotAdmission;
  const welcomeDigest = authorityBindingDigest("heterodyne.marmot-welcome/v1", {
    welcome_bytes: welcomeRecord.welcome_bytes,
    key_package_bytes: welcomeRecord.key_package_bytes,
    inviter_account: welcomeRecord.inviter_account,
    recipient_account: welcomeRecord.recipient_account,
    group_id: welcomeRecord.group_id,
    inviter_leaf_key: welcomeRecord.inviter_leaf_key,
    recipient_leaf_key: welcomeRecord.recipient_leaf_key,
    member_accounts: welcomeRecord.member_accounts,
    required_capabilities: welcomeRecord.required_capabilities,
    checkpoint: welcomeRecord.checkpoint,
  });
  const key = authorityBindingDigest("heterodyne.marmot-admission.key/v1", {
    authority_id: authorityRecord.authority_id,
    recipient_account: welcomeRecord.recipient_account,
    group_id: welcomeRecord.group_id,
    welcome_digest: welcomeDigest,
  });
  const bindingDigest = authorityBindingDigest("heterodyne.marmot-admission.binding/v1", {
    authority_id: authorityRecord.authority_id,
    key,
    decision: capturedAcceptance.decision,
    expected_checkpoint: capturedAcceptance.expected_checkpoint,
  });
  const executionToken = authorityBindingDigest("heterodyne.marmot-admission.execution/v1", {
    key,
    binding_digest: bindingDigest,
  });
  const outputDigest = authorityBindingDigest("heterodyne.marmot-admission.output/v1", output);
  const reconciliationDigest = authorityBindingDigest(
    "heterodyne.marmot-admission.reconciliation/v1",
    { key, binding_digest: bindingDigest, execution_token: executionToken },
  );

  let loaded: DurableAuthorityRecord<VerifiedMarmotAdmission> | null | undefined;
  try {
    loaded = captureDurableRecord(await authorityRecord.store.load(key));
  } catch {
    return INDETERMINATE;
  }
  if (loaded === undefined) return INDETERMINATE;
  if (loaded?.binding_digest !== undefined && loaded.binding_digest !== bindingDigest) return REJECT;
  if (loaded?.state === "committed") {
    const cached = committedOutput(loaded, bindingDigest, executionToken, outputDigest);
    return cached === null
      ? INDETERMINATE
      : Object.freeze({ verdict: "accept", output: cached });
  }
  if (loaded?.state === "indeterminate" || loaded?.state === "executing") {
    return INDETERMINATE;
  }
  if (conversation.state === "accepted") return REJECT;

  let acquired;
  try {
    acquired = await authorityRecord.store.acquire(Object.freeze({
      key,
      expected_revision: loaded?.revision ?? null,
      binding_digest: bindingDigest,
      execution_token: executionToken,
    }));
  } catch {
    return INDETERMINATE;
  }
  if (acquired !== "acquired") {
    if (acquired === "unavailable") return INDETERMINATE;
    try {
      const replay = captureDurableRecord(await authorityRecord.store.load(key));
      if (replay === undefined || replay === null) return INDETERMINATE;
      if (replay.binding_digest !== bindingDigest) return REJECT;
      if (replay.state === "committed") {
        const cached = committedOutput(replay, bindingDigest, executionToken, outputDigest);
        return cached === null
          ? INDETERMINATE
          : Object.freeze({ verdict: "accept", output: cached });
      }
      return INDETERMINATE;
    } catch {
      return INDETERMINATE;
    }
  }

  let commitResult: "committed" | "conflict" | "unknown";
  try {
    commitResult = await authorityRecord.store.commit(Object.freeze({
      key,
      binding_digest: bindingDigest,
      execution_token: executionToken,
      output_digest: outputDigest,
      output,
    }));
  } catch {
    await safeMarkIndeterminate(authorityRecord.store, Object.freeze({
      key,
      binding_digest: bindingDigest,
      execution_token: executionToken,
      reconciliation_digest: reconciliationDigest,
    }));
    return INDETERMINATE;
  }
  if (commitResult !== "committed") {
    if (commitResult === "conflict") {
      try {
        const raced = captureDurableRecord(await authorityRecord.store.load(key));
        if (raced !== undefined && raced !== null && raced.state === "committed") {
          const cached = committedOutput(raced, bindingDigest, executionToken, outputDigest);
          if (cached !== null) return Object.freeze({ verdict: "accept", output: cached });
        }
      } catch {
        // Fall through to absorbing indeterminate state.
      }
    }
    await safeMarkIndeterminate(authorityRecord.store, Object.freeze({
      key,
      binding_digest: bindingDigest,
      execution_token: executionToken,
      reconciliation_digest: reconciliationDigest,
    }));
    return INDETERMINATE;
  }

  try {
    const committed = captureDurableRecord(await authorityRecord.store.load(key));
    if (committed !== undefined && committed !== null && committed.state === "committed") {
      const cached = committedOutput(committed, bindingDigest, executionToken, outputDigest);
      if (cached !== null) return Object.freeze({ verdict: "accept", output: cached });
    }
  } catch {
    // A committed result that cannot be read back is not safe to expose.
  }
  await safeMarkIndeterminate(authorityRecord.store, Object.freeze({
    key,
    binding_digest: bindingDigest,
    execution_token: executionToken,
    reconciliation_digest: reconciliationDigest,
  }));
  return INDETERMINATE;
}
