import { types as utilTypes } from "node:util";
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
const HEX_32 = /^[0-9a-f]{64}$/;
const ACCOUNT_IDENTITY_PROOF = "marmot.member.account-identity-proof.v2";

export type MarmotPrivateKeyPackageHandle = Readonly<Record<never, never>>;

export type AuthenticatedMarmotWelcome = Readonly<{
  wire_format: "mls_welcome";
  inviter_account: string;
  recipient_account: string;
  inviter_leaf_key: string;
  recipient_leaf_key: string;
  group_id: string;
  member_accounts: readonly [string, string];
  required_capabilities: readonly string[];
  checkpoint: string;
}>;

export type MarmotWelcomeTransition = Readonly<{
  commit(execution_token: string): Promise<void>;
  rollback(): void;
}>;

export type MarmotAdmissionAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  store: DurableAuthorityStore<VerifiedMarmotAdmission>;
  load_conversation: (account: string, group_id: string) => Promise<Readonly<{
    checkpoint: string; state: "unseen" | "held" | "accepted" | "rejected";
  }>>;
  load_private_key_package: (
    recipient_account: string,
    key_package_bytes: Uint8Array,
  ) => MarmotPrivateKeyPackageHandle | null;
  /**
   * Captured adapter to a standards-conforming Marmot/MLS implementation.
   * It performs RFC 9420 Welcome processing with authority-owned private
   * KeyPackage state and returns authenticated state plus a tentative join.
   * A null return or throw restores exact pre-processing state; the returned
   * transition remains non-durable until this authority calls commit.
   */
  process_mls_welcome: (input: Readonly<{
    welcome_bytes: Uint8Array;
    key_package_bytes: Uint8Array;
    private_key_package: MarmotPrivateKeyPackageHandle;
    now: number;
  }>) => Readonly<{
    authenticated: AuthenticatedMarmotWelcome;
    transition: MarmotWelcomeTransition;
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
  load_private_key_package: MarmotAdmissionAuthorityConfig["load_private_key_package"];
  process_mls_welcome: MarmotAdmissionAuthorityConfig["process_mls_welcome"];
  store: StoreCallbacks;
}>;

type PrivateTransition = {
  state: "tentative" | "committed" | "rolled-back" | "indeterminate";
  commit: MarmotWelcomeTransition["commit"];
  rollback: MarmotWelcomeTransition["rollback"];
};

type WelcomeRecord = Readonly<{
  authority: MarmotAdmissionAuthority;
  welcome_bytes: Uint8Array;
  key_package_bytes: Uint8Array;
  authenticated: AuthenticatedMarmotWelcome;
  transition: PrivateTransition;
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const WELCOMES = new WeakMap<object, WelcomeRecord>();

function exactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && expected.every((key, index) => actual[index] === key);
}

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
    if (utilTypes.isProxy(owner)) throw new TypeError("Marmot callback owner cannot be a proxy");
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new TypeError(`Marmot callback owner requires data method ${name}`);
      }
      return descriptor.value.bind(object) as T;
    }
    owner = Object.getPrototypeOf(owner) as object | null;
  }
  throw new TypeError(`Marmot callback owner requires method ${name}`);
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
    "load_private_key_package",
    "process_mls_welcome",
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
  const loadPrivateKeyPackage = ownDataProperty(config, "load_private_key_package");
  const processMlsWelcome = ownDataProperty(config, "process_mls_welcome");
  if (
    typeof authorityId !== "string"
    || authorityId.length === 0
    || typeof trustedNow !== "function"
    || typeof loadConversation !== "function"
    || typeof loadPrivateKeyPackage !== "function"
    || typeof processMlsWelcome !== "function"
    || store === null
    || typeof store !== "object"
    || utilTypes.isProxy(store)
  ) throw new TypeError("invalid Marmot admission config");
  return Object.freeze({
    authority_id: authorityId,
    trusted_now: trustedNow as MarmotAdmissionAuthorityConfig["trusted_now"],
    load_conversation: loadConversation as MarmotAdmissionAuthorityConfig["load_conversation"],
    load_private_key_package: loadPrivateKeyPackage as
      MarmotAdmissionAuthorityConfig["load_private_key_package"],
    process_mls_welcome: processMlsWelcome as MarmotAdmissionAuthorityConfig["process_mls_welcome"],
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

function snapshotProcessorResult(value: unknown): Readonly<{
  authenticated: unknown;
  transition: unknown;
}> | null {
  if (
    value === null
    || typeof value !== "object"
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
    || !exactKeys(descriptors as unknown as Readonly<Record<string, unknown>>, [
      "authenticated", "transition",
    ])
  ) return null;
  const authenticated = descriptors.authenticated;
  const transition = descriptors.transition;
  if (
    authenticated === undefined
    || !("value" in authenticated)
    || authenticated.enumerable !== true
    || transition === undefined
    || !("value" in transition)
    || transition.enumerable !== true
  ) return null;
  return Object.freeze({
    authenticated: authenticated.value,
    transition: transition.value,
  });
}

function captureTransition(value: unknown): PrivateTransition | null {
  if (
    value === null
    || typeof value !== "object"
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
    || !exactKeys(descriptors as unknown as Readonly<Record<string, unknown>>, ["commit", "rollback"])
  ) return null;
  const commit = descriptors.commit;
  const rollback = descriptors.rollback;
  if (
    commit === undefined || !("value" in commit) || typeof commit.value !== "function"
    || rollback === undefined || !("value" in rollback) || typeof rollback.value !== "function"
  ) return null;
  return {
    state: "tentative",
    commit: commit.value.bind(value) as MarmotWelcomeTransition["commit"],
    rollback: rollback.value.bind(value) as MarmotWelcomeTransition["rollback"],
  };
}

function captureAuthenticated(value: unknown): AuthenticatedMarmotWelcome | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const record = captured as Readonly<Record<string, unknown>>;
    if (!exactKeys(record, [
      "wire_format", "inviter_account", "recipient_account", "inviter_leaf_key",
      "recipient_leaf_key", "group_id", "member_accounts", "required_capabilities",
      "checkpoint",
    ])) return null;
    const members = record.member_accounts;
    const capabilities = record.required_capabilities;
    if (
      record.wire_format !== "mls_welcome"
      || typeof record.inviter_account !== "string" || !HEX_32.test(record.inviter_account)
      || typeof record.recipient_account !== "string" || !HEX_32.test(record.recipient_account)
      || typeof record.inviter_leaf_key !== "string" || !HEX_32.test(record.inviter_leaf_key)
      || typeof record.recipient_leaf_key !== "string" || !HEX_32.test(record.recipient_leaf_key)
      || typeof record.group_id !== "string" || !HEX_32.test(record.group_id)
      || !Array.isArray(members) || members.length !== 2
      || !members.every((member) => typeof member === "string" && HEX_32.test(member))
      || !Array.isArray(capabilities) || capabilities.length === 0
      || !capabilities.every((capability) => typeof capability === "string" && capability.length > 0)
      || new Set(capabilities).size !== capabilities.length
      || !capabilities.includes(ACCOUNT_IDENTITY_PROOF)
      || typeof record.checkpoint !== "string" || record.checkpoint.length === 0
    ) return null;
    return record as AuthenticatedMarmotWelcome;
  } catch {
    return null;
  }
}

function rollbackTransition(transition: PrivateTransition): void {
  if (transition.state !== "tentative") return;
  transition.state = "rolled-back";
  try {
    transition.rollback();
  } catch {
    // The standards adapter must preserve pre-state until commit; rollback is
    // cleanup only and a failure never creates admission authority.
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
  const welcomeBytes = new Uint8Array(captured.welcome_bytes);
  const keyPackageBytes = new Uint8Array(captured.key_package_bytes);
  try {
    const now = authorityRecord.trusted_now();
    if (!Number.isSafeInteger(now) || now < 0) return REJECT;
    const privateKeyPackage = authorityRecord.load_private_key_package(
      captured.recipient_account,
      new Uint8Array(keyPackageBytes),
    );
    if (
      privateKeyPackage === null
      || typeof privateKeyPackage !== "object"
      || utilTypes.isProxy(privateKeyPackage)
    ) return REJECT;
    const rawResult = authorityRecord.process_mls_welcome(Object.freeze({
      welcome_bytes: new Uint8Array(welcomeBytes),
      key_package_bytes: new Uint8Array(keyPackageBytes),
      private_key_package: privateKeyPackage,
      now,
    }));
    const result = snapshotProcessorResult(rawResult);
    if (result === null) return REJECT;
    const transition = captureTransition(result.transition);
    if (transition === null) return REJECT;
    const authenticated = captureAuthenticated(result.authenticated);
    if (
      authenticated === null
      || authenticated.inviter_account === authenticated.recipient_account
      || authenticated.inviter_leaf_key === authenticated.recipient_leaf_key
      || authenticated.inviter_account !== captured.inviter_account
      || authenticated.recipient_account !== captured.recipient_account
      || authenticated.group_id !== captured.group_id
      || !equalStrings(authenticated.member_accounts, captured.member_accounts)
      || authenticated.member_accounts[0] !== authenticated.inviter_account
      || authenticated.member_accounts[1] !== authenticated.recipient_account
      || !equalStrings(authenticated.required_capabilities, captured.required_capabilities)
    ) {
      rollbackTransition(transition);
      return REJECT;
    }
    const handle = Object.freeze({});
    WELCOMES.set(handle, Object.freeze({
      authority,
      welcome_bytes: new Uint8Array(welcomeBytes),
      key_package_bytes: new Uint8Array(keyPackageBytes),
      authenticated,
      transition,
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

function captureAdmissionOutput(value: unknown): VerifiedMarmotAdmission | null {
  try {
    const captured = captureAuthorityInput(value);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return null;
    const output = captured as Readonly<Record<string, unknown>>;
    if (
      !exactKeys(output, ["group_id", "checkpoint", "terminal"])
      || typeof output.group_id !== "string" || !HEX_32.test(output.group_id)
      || typeof output.checkpoint !== "string" || output.checkpoint.length === 0
      || (output.terminal !== "accepted" && output.terminal !== "held")
    ) return null;
    return output as VerifiedMarmotAdmission;
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
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) return undefined;
    const record = captured as unknown as Readonly<Record<string, unknown>>;
    if (
      !Number.isSafeInteger(record.revision)
      || (record.revision as number) < 0
      || typeof record.binding_digest !== "string"
      || !HEX_32.test(record.binding_digest)
    ) return undefined;
    if (record.state === "available") {
      if (!exactKeys(record, ["state", "revision", "binding_digest", "output"])) return undefined;
      if (captureAdmissionOutput(record.output) === null) return undefined;
    } else if (record.state === "executing") {
      if (!exactKeys(record, ["state", "revision", "binding_digest", "execution_token"])) {
        return undefined;
      }
      if (typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)) {
        return undefined;
      }
    } else if (record.state === "committed") {
      if (!exactKeys(record, [
        "state", "revision", "binding_digest", "execution_token", "output_digest", "output",
      ])) return undefined;
      if (
        typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)
        || typeof record.output_digest !== "string" || !HEX_32.test(record.output_digest)
        || captureAdmissionOutput(record.output) === null
      ) return undefined;
    } else if (record.state === "indeterminate") {
      if (!exactKeys(record, [
        "state", "revision", "binding_digest", "execution_token", "reconciliation_digest",
      ])) return undefined;
      if (
        typeof record.execution_token !== "string" || !HEX_32.test(record.execution_token)
        || typeof record.reconciliation_digest !== "string"
        || !HEX_32.test(record.reconciliation_digest)
      ) return undefined;
    } else {
      return undefined;
    }
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
  const output = captureAdmissionOutput(record.output);
  if (
    output === null
    || authorityBindingDigest("heterodyne.marmot-admission.output/v1", output) !== outputDigest
  ) return null;
  return output;
}

function indeterminateDecision(reconciliationDigest: string): MarmotAdmissionDecision {
  return Object.freeze({
    verdict: "indeterminate",
    reconciliation_digest: reconciliationDigest,
  });
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
    // The public result still carries the deterministic reconciliation digest.
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
    ) {
      rollbackTransition(welcomeRecord.transition);
      return REJECT;
    }
  } catch {
    rollbackTransition(welcomeRecord.transition);
    return REJECT;
  }
  if (capturedAcceptance.decision === "reject") {
    rollbackTransition(welcomeRecord.transition);
    return REJECT;
  }

  let conversation;
  try {
    conversation = captureConversation(await authorityRecord.load_conversation(
      welcomeRecord.authenticated.recipient_account,
      welcomeRecord.authenticated.group_id,
    ));
  } catch {
    rollbackTransition(welcomeRecord.transition);
    return REJECT;
  }
  if (
    conversation === null
    || conversation.state === "rejected"
    || conversation.checkpoint !== welcomeRecord.authenticated.checkpoint
    || conversation.checkpoint !== capturedAcceptance.expected_checkpoint
  ) {
    rollbackTransition(welcomeRecord.transition);
    return REJECT;
  }

  const terminal = capturedAcceptance.decision === "accept" ? "accepted" : "held";
  const output = Object.freeze({
    group_id: welcomeRecord.authenticated.group_id,
    checkpoint: conversation.checkpoint,
    terminal,
  }) as VerifiedMarmotAdmission;
  const welcomeDigest = authorityBindingDigest("heterodyne.marmot-welcome/v1", {
    welcome_bytes: welcomeRecord.welcome_bytes,
    key_package_bytes: welcomeRecord.key_package_bytes,
    wire_format: welcomeRecord.authenticated.wire_format,
    inviter_account: welcomeRecord.authenticated.inviter_account,
    recipient_account: welcomeRecord.authenticated.recipient_account,
    inviter_leaf_key: welcomeRecord.authenticated.inviter_leaf_key,
    recipient_leaf_key: welcomeRecord.authenticated.recipient_leaf_key,
    group_id: welcomeRecord.authenticated.group_id,
    member_accounts: welcomeRecord.authenticated.member_accounts,
    required_capabilities: welcomeRecord.authenticated.required_capabilities,
    checkpoint: welcomeRecord.authenticated.checkpoint,
  });
  const key = authorityBindingDigest("heterodyne.marmot-admission.key/v1", {
    authority_id: authorityRecord.authority_id,
    recipient_account: welcomeRecord.authenticated.recipient_account,
    group_id: welcomeRecord.authenticated.group_id,
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
  const indeterminate = () => indeterminateDecision(reconciliationDigest);

  let loaded: DurableAuthorityRecord<VerifiedMarmotAdmission> | null | undefined;
  try {
    loaded = captureDurableRecord(await authorityRecord.store.load(key));
  } catch {
    rollbackTransition(welcomeRecord.transition);
    return indeterminate();
  }
  if (loaded === undefined) {
    rollbackTransition(welcomeRecord.transition);
    return indeterminate();
  }
  if (loaded?.binding_digest !== undefined && loaded.binding_digest !== bindingDigest) {
    rollbackTransition(welcomeRecord.transition);
    return REJECT;
  }
  if (loaded?.state === "committed") {
    const cached = committedOutput(loaded, bindingDigest, executionToken, outputDigest);
    rollbackTransition(welcomeRecord.transition);
    return cached === null
      ? indeterminate()
      : Object.freeze({ verdict: "accept", output: cached });
  }
  if (loaded?.state === "indeterminate" || loaded?.state === "executing") {
    rollbackTransition(welcomeRecord.transition);
    return indeterminate();
  }
  if (conversation.state === "accepted") {
    rollbackTransition(welcomeRecord.transition);
    return REJECT;
  }

  let acquired;
  try {
    acquired = await authorityRecord.store.acquire(Object.freeze({
      key,
      expected_revision: loaded?.revision ?? null,
      binding_digest: bindingDigest,
      execution_token: executionToken,
    }));
  } catch {
    rollbackTransition(welcomeRecord.transition);
    return indeterminate();
  }
  if (acquired !== "acquired") {
    rollbackTransition(welcomeRecord.transition);
    if (acquired === "unavailable") return indeterminate();
    try {
      const replay = captureDurableRecord(await authorityRecord.store.load(key));
      if (replay === undefined || replay === null) return indeterminate();
      if (replay.binding_digest !== bindingDigest) return REJECT;
      if (replay.state === "committed") {
        const cached = committedOutput(replay, bindingDigest, executionToken, outputDigest);
        return cached === null
          ? indeterminate()
          : Object.freeze({ verdict: "accept", output: cached });
      }
      return indeterminate();
    } catch {
      return indeterminate();
    }
  }

  try {
    if (welcomeRecord.transition.state !== "tentative") throw new Error("Welcome transition unavailable");
    await welcomeRecord.transition.commit(executionToken);
    welcomeRecord.transition.state = "committed";
  } catch {
    welcomeRecord.transition.state = "indeterminate";
    await safeMarkIndeterminate(authorityRecord.store, Object.freeze({
      key,
      binding_digest: bindingDigest,
      execution_token: executionToken,
      reconciliation_digest: reconciliationDigest,
    }));
    return indeterminate();
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
    return indeterminate();
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
    return indeterminate();
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
  return indeterminate();
}
