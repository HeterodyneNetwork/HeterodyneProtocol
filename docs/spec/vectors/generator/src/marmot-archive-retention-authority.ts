import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import {
  isCanonicalCoreGitRef,
  isCanonicalCoreRepositoryRid,
} from "./core-policy.js";
import type { CurrentRepositoryWriterBinding } from "./core-writer-binding.js";
import {
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
} from "./nostr.js";
import {
  authorityBindingDigest,
  captureAuthorityInput,
  type AuthorityDecision,
  type DurableAuthorityRecord,
  type DurableAuthorityStore,
} from "./security-authority-support.js";

const REJECT = Object.freeze({
  verdict: "reject" as const,
  reason_code: "marmot-premature-ack" as const,
});
const HEX_32 = /^[0-9a-f]{64}$/u;
const COMMIT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;

export type MarmotArchiveRetentionAuthorityConfig = Readonly<{
  authority_id: string;
  store: DurableAuthorityStore<Readonly<{
    repository_rid: string;
    ref: string;
    object_digest: string;
    source_digest: string;
    commit: string;
  }>>;
  resolve_writer: (
    rid: string,
    ref: string,
  ) => Promise<CurrentRepositoryWriterBinding>;
  append_and_resolve: (input: Readonly<{
    repository_rid: string;
    ref: string;
    bytes: Uint8Array;
  }>) => Promise<Readonly<{
    object_digest: string;
    commit: string;
    reachable: boolean;
  }>>;
}>;

export type MarmotArchiveInput = Readonly<{
  repository_rid: string;
  ref: string;
  source: Readonly<
    | {
        kind: "signed-event";
        event: NostrSignedEvent;
        event_bytes: Uint8Array;
      }
    | {
        kind: "encrypted-media";
        ciphertext: Uint8Array;
        authorization_event: NostrSignedEvent;
      }
  >;
}>;

export type MarmotArchiveAppendReceipt = Readonly<Record<never, never>>;

export type MarmotArchiveReceiptData = Readonly<{
  repository_rid: string;
  ref: string;
  object_digest: string;
  source_digest: string;
  commit: string;
}>;

export type MarmotArchiveDecision = AuthorityDecision<
  "marmot-premature-ack",
  MarmotArchiveAppendReceipt
>;

export type MarmotArchiveRetentionAuthority = Readonly<Record<never, never>>;

type StoreCallbacks = Readonly<{
  load: DurableAuthorityStore<MarmotArchiveReceiptData>["load"];
  acquire: DurableAuthorityStore<MarmotArchiveReceiptData>["acquire"];
  compareAndSwap: DurableAuthorityStore<MarmotArchiveReceiptData>["compareAndSwap"];
  commit: DurableAuthorityStore<MarmotArchiveReceiptData>["commit"];
  markIndeterminate: DurableAuthorityStore<MarmotArchiveReceiptData>["markIndeterminate"];
}>;

type AuthorityRecord = Readonly<{
  authority_id: string;
  store: StoreCallbacks;
  resolve_writer: MarmotArchiveRetentionAuthorityConfig["resolve_writer"];
  append_and_resolve: MarmotArchiveRetentionAuthorityConfig["append_and_resolve"];
}>;

type CapturedArchiveInput = Readonly<{
  repository_rid: string;
  ref: string;
  bytes: Uint8Array;
  bytes_digest: string;
  source_digest: string;
  authorization_event_id: string;
}>;

type DurableRequest = Readonly<{
  key: string;
  binding_digest: string;
  execution_token: string;
  reconciliation_digest: string;
}>;

type ReceiptRecord = Readonly<{
  authority: MarmotArchiveRetentionAuthority;
  request: DurableRequest;
  output_digest: string;
  output: MarmotArchiveReceiptData;
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const RECEIPTS = new WeakMap<object, ReceiptRecord>();

function exactKeys(value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && expected.every((key, index) => actual[index] === key);
}

function ownDataProperty(object: object, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`Marmot archive config requires data property ${name}`);
  }
  return descriptor.value;
}

function boundMethod<T extends (...args: never[]) => unknown>(object: object, name: string): T {
  let owner: object | null = object;
  while (owner !== null) {
    if (utilTypes.isProxy(owner)) {
      throw new TypeError("Marmot archive callback owner cannot be a proxy");
    }
    const descriptor = Object.getOwnPropertyDescriptor(owner, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new TypeError(`Marmot archive callback owner requires data method ${name}`);
      }
      return descriptor.value.bind(object) as T;
    }
    owner = Object.getPrototypeOf(owner) as object | null;
  }
  throw new TypeError(`Marmot archive callback owner requires method ${name}`);
}

function snapshotConfig(config: MarmotArchiveRetentionAuthorityConfig): AuthorityRecord {
  if (
    config === null
    || typeof config !== "object"
    || utilTypes.isProxy(config)
    || Object.getPrototypeOf(config) !== Object.prototype
  ) throw new TypeError("Marmot archive config must be an ordinary object");
  const descriptors = Object.getOwnPropertyDescriptors(config);
  const required = ["authority_id", "store", "resolve_writer", "append_and_resolve"];
  if (
    Reflect.ownKeys(descriptors).some((key) => typeof key !== "string")
    || Object.keys(descriptors).length !== required.length
    || !required.every((name) => Object.hasOwn(descriptors, name))
  ) throw new TypeError("Marmot archive config must be closed");

  const authorityId = ownDataProperty(config, "authority_id");
  const store = ownDataProperty(config, "store");
  const resolveWriter = ownDataProperty(config, "resolve_writer");
  const appendAndResolve = ownDataProperty(config, "append_and_resolve");
  if (
    typeof authorityId !== "string"
    || authorityId.length === 0
    || authorityId.length > 256
    || store === null
    || typeof store !== "object"
    || utilTypes.isProxy(store)
    || typeof resolveWriter !== "function"
    || utilTypes.isProxy(resolveWriter)
    || typeof appendAndResolve !== "function"
    || utilTypes.isProxy(appendAndResolve)
  ) throw new TypeError("invalid Marmot archive config");

  return Object.freeze({
    authority_id: authorityId,
    store: Object.freeze({
      load: boundMethod<StoreCallbacks["load"]>(store, "load"),
      acquire: boundMethod<StoreCallbacks["acquire"]>(store, "acquire"),
      compareAndSwap: boundMethod<StoreCallbacks["compareAndSwap"]>(store, "compareAndSwap"),
      commit: boundMethod<StoreCallbacks["commit"]>(store, "commit"),
      markIndeterminate: boundMethod<StoreCallbacks["markIndeterminate"]>(store, "markIndeterminate"),
    }),
    resolve_writer: resolveWriter as MarmotArchiveRetentionAuthorityConfig["resolve_writer"],
    append_and_resolve: appendAndResolve as
      MarmotArchiveRetentionAuthorityConfig["append_and_resolve"],
  });
}

export function createMarmotArchiveRetentionAuthority(
  config: MarmotArchiveRetentionAuthorityConfig,
): MarmotArchiveRetentionAuthority {
  const record = snapshotConfig(config);
  const authority = Object.freeze({});
  AUTHORITIES.set(authority, record);
  return authority;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sameEvent(left: NostrSignedEvent, right: NostrSignedEvent): boolean {
  return left.pubkey === right.pubkey
    && left.created_at === right.created_at
    && left.kind === right.kind
    && left.content === right.content
    && left.id === right.id
    && left.sig === right.sig
    && left.tags.length === right.tags.length
    && left.tags.every((tag, index) => {
      const other = right.tags[index];
      return other !== undefined
        && tag.length === other.length
        && tag.every((value, member) => value === other[member]);
    });
}

function eventFromExactBytes(bytes: Uint8Array): NostrSignedEvent | null {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const parsed: unknown = JSON.parse(text);
    return snapshotAndVerifyNostrEvent(parsed);
  } catch {
    return null;
  }
}

function mediaEventBindsCiphertext(event: NostrSignedEvent, digest: string): boolean {
  if (event.kind !== 9) return false;
  const matches = event.tags.filter((tag) =>
    tag[0] === "imeta"
    && tag.includes("v encrypted-media-v2")
    && tag.includes(`ciphertext_sha256 ${digest}`)
  );
  return matches.length === 1;
}

function captureArchiveInput(value: MarmotArchiveInput): CapturedArchiveInput | null {
  try {
    const captured = captureAuthorityInput(value);
    if (
      captured === null
      || typeof captured !== "object"
      || Array.isArray(captured)
    ) return null;
    const input = captured as Readonly<Record<string, unknown>>;
    if (!exactKeys(input, ["repository_rid", "ref", "source"])) return null;
    if (
      !isCanonicalCoreRepositoryRid(input.repository_rid)
      || !isCanonicalCoreGitRef(input.ref)
      || typeof input.ref !== "string"
      || !/^refs\/xyz\.heterodyne\.marmot\/(?:writers|relays)\/[A-Za-z0-9._-]+$/u.test(input.ref)
      || input.source === null
      || typeof input.source !== "object"
      || Array.isArray(input.source)
    ) return null;
    const source = input.source as Readonly<Record<string, unknown>>;
    let bytes: Uint8Array;
    let sourceDigest: string;
    let authorizationEventId: string;
    if (source.kind === "signed-event") {
      if (
        !exactKeys(source, ["kind", "event", "event_bytes"])
        || !(source.event_bytes instanceof Uint8Array)
        || source.event_bytes.length === 0
      ) return null;
      const event = snapshotAndVerifyNostrEvent(source.event);
      const encoded = eventFromExactBytes(source.event_bytes);
      if (event === null || encoded === null || !sameEvent(event, encoded)) return null;
      bytes = new Uint8Array(source.event_bytes);
      sourceDigest = event.id;
      authorizationEventId = event.id;
    } else if (source.kind === "encrypted-media") {
      if (
        !exactKeys(source, ["kind", "ciphertext", "authorization_event"])
        || !(source.ciphertext instanceof Uint8Array)
        || source.ciphertext.length === 0
      ) return null;
      const event = snapshotAndVerifyNostrEvent(source.authorization_event);
      bytes = new Uint8Array(source.ciphertext);
      if (event === null || !mediaEventBindsCiphertext(event, sha256(bytes))) return null;
      sourceDigest = sha256(bytes);
      authorizationEventId = event.id;
    } else {
      return null;
    }
    return Object.freeze({
      repository_rid: input.repository_rid,
      ref: input.ref,
      bytes,
      bytes_digest: sha256(bytes),
      source_digest: sourceDigest,
      authorization_event_id: authorizationEventId,
    }) as CapturedArchiveInput;
  } catch {
    return null;
  }
}

function validOpaqueWriter(value: unknown): value is CurrentRepositoryWriterBinding {
  return value !== null
    && typeof value === "object"
    && !utilTypes.isProxy(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Reflect.ownKeys(value).length === 0
    && Object.isFrozen(value);
}

function durableRequest(authorityId: string, input: CapturedArchiveInput): DurableRequest {
  const key = authorityBindingDigest("heterodyne.marmot-archive.key/v1", {
    authority_id: authorityId,
    source_digest: input.source_digest,
  });
  const bindingDigest = authorityBindingDigest("heterodyne.marmot-archive.binding/v1", {
    authority_id: authorityId,
    key,
    repository_rid: input.repository_rid,
    ref: input.ref,
    bytes_digest: input.bytes_digest,
    source_digest: input.source_digest,
    authorization_event_id: input.authorization_event_id,
  });
  const executionToken = authorityBindingDigest("heterodyne.marmot-archive.execution/v1", {
    authority_id: authorityId,
    key,
    binding_digest: bindingDigest,
  });
  const reconciliationDigest = authorityBindingDigest(
    "heterodyne.marmot-archive.reconciliation/v1",
    {
      authority_id: authorityId,
      key,
      binding_digest: bindingDigest,
      execution_token: executionToken,
    },
  );
  return Object.freeze({
    key,
    binding_digest: bindingDigest,
    execution_token: executionToken,
    reconciliation_digest: reconciliationDigest,
  });
}

function captureArchiveOutput(value: unknown): MarmotArchiveReceiptData | null {
  try {
    const captured = captureAuthorityInput(value);
    if (
      captured === null
      || typeof captured !== "object"
      || Array.isArray(captured)
    ) return null;
    const output = captured as Readonly<Record<string, unknown>>;
    if (
      !exactKeys(output, [
        "repository_rid", "ref", "object_digest", "source_digest", "commit",
      ])
      || !isCanonicalCoreRepositoryRid(output.repository_rid)
      || typeof output.ref !== "string"
      || !isCanonicalCoreGitRef(output.ref)
      || typeof output.object_digest !== "string"
      || !HEX_32.test(output.object_digest)
      || typeof output.source_digest !== "string"
      || !HEX_32.test(output.source_digest)
      || typeof output.commit !== "string"
      || !COMMIT_ID.test(output.commit)
    ) return null;
    return output as MarmotArchiveReceiptData;
  } catch {
    return null;
  }
}

function sameOutput(left: MarmotArchiveReceiptData, right: MarmotArchiveReceiptData): boolean {
  return left.repository_rid === right.repository_rid
    && left.ref === right.ref
    && left.object_digest === right.object_digest
    && left.source_digest === right.source_digest
    && left.commit === right.commit;
}

function outputDigest(output: MarmotArchiveReceiptData): string {
  return authorityBindingDigest("heterodyne.marmot-archive.output/v1", output);
}

function captureDurableRecord(
  value: DurableAuthorityRecord<MarmotArchiveReceiptData> | null,
): DurableAuthorityRecord<MarmotArchiveReceiptData> | null | undefined {
  if (value === null) return null;
  try {
    const captured = captureAuthorityInput(value);
    if (
      captured === null
      || typeof captured !== "object"
      || Array.isArray(captured)
    ) return undefined;
    const record = captured as unknown as Readonly<Record<string, unknown>>;
    if (
      !Number.isSafeInteger(record.revision)
      || (record.revision as number) < 0
      || typeof record.binding_digest !== "string"
      || !HEX_32.test(record.binding_digest)
    ) return undefined;
    if (record.state === "available") {
      if (
        !exactKeys(record, ["state", "revision", "binding_digest", "output"])
        || captureArchiveOutput(record.output) === null
      ) return undefined;
    } else if (record.state === "executing") {
      if (
        !exactKeys(record, ["state", "revision", "binding_digest", "execution_token"])
        || typeof record.execution_token !== "string"
        || !HEX_32.test(record.execution_token)
      ) return undefined;
    } else if (record.state === "committed") {
      if (
        !exactKeys(record, [
          "state", "revision", "binding_digest", "execution_token", "output_digest", "output",
        ])
        || typeof record.execution_token !== "string"
        || !HEX_32.test(record.execution_token)
        || typeof record.output_digest !== "string"
        || !HEX_32.test(record.output_digest)
        || captureArchiveOutput(record.output) === null
      ) return undefined;
    } else if (record.state === "indeterminate") {
      if (
        !exactKeys(record, [
          "state", "revision", "binding_digest", "execution_token", "reconciliation_digest",
        ])
        || typeof record.execution_token !== "string"
        || !HEX_32.test(record.execution_token)
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

function terminalOutput(
  record: DurableAuthorityRecord<MarmotArchiveReceiptData>,
  request: DurableRequest,
): MarmotArchiveReceiptData | null {
  if (record.binding_digest !== request.binding_digest) return null;
  if (record.state === "committed") {
    if (record.execution_token !== request.execution_token) return null;
    const output = captureArchiveOutput(record.output);
    if (
      output === null
      || record.output_digest !== outputDigest(output)
    ) return null;
    return output;
  }
  if (record.state === "available") {
    return captureArchiveOutput(record.output);
  }
  return null;
}

function indeterminateDecision(
  reconciliationDigest: string,
): Readonly<{ verdict: "indeterminate"; reconciliation_digest: string }> {
  return Object.freeze({
    verdict: "indeterminate",
    reconciliation_digest: reconciliationDigest,
  });
}

async function safeMarkIndeterminate(
  store: StoreCallbacks,
  request: DurableRequest,
): Promise<void> {
  try {
    await store.markIndeterminate(Object.freeze({
      key: request.key,
      binding_digest: request.binding_digest,
      execution_token: request.execution_token,
      reconciliation_digest: request.reconciliation_digest,
    }));
  } catch {
    // The deterministic reconciliation digest remains the only public result.
  }
}

function mintReceipt(
  authority: MarmotArchiveRetentionAuthority,
  request: DurableRequest,
  output: MarmotArchiveReceiptData,
): MarmotArchiveDecision {
  const receipt = Object.freeze({});
  RECEIPTS.set(receipt, Object.freeze({
    authority,
    request,
    output_digest: outputDigest(output),
    output,
  }));
  return Object.freeze({ verdict: "accept", output: receipt });
}

function outputMatchesInput(
  output: MarmotArchiveReceiptData,
  input: CapturedArchiveInput,
): boolean {
  return output.repository_rid === input.repository_rid
    && output.ref === input.ref
    && output.source_digest === input.source_digest
    && output.object_digest === input.bytes_digest;
}

async function loadRecord(
  store: StoreCallbacks,
  key: string,
): Promise<DurableAuthorityRecord<MarmotArchiveReceiptData> | null | undefined> {
  try {
    return captureDurableRecord(await store.load(key));
  } catch {
    return undefined;
  }
}

export async function appendExactMarmotArchive(
  authority: MarmotArchiveRetentionAuthority,
  input: MarmotArchiveInput,
): Promise<MarmotArchiveDecision> {
  const authorityRecord = AUTHORITIES.get(authority);
  if (authorityRecord === undefined) return REJECT;
  const captured = captureArchiveInput(input);
  if (captured === null) return REJECT;

  try {
    const writer = await authorityRecord.resolve_writer(
      captured.repository_rid,
      captured.ref,
    );
    if (!validOpaqueWriter(writer)) return REJECT;
  } catch {
    return REJECT;
  }

  const request = durableRequest(authorityRecord.authority_id, captured);
  const indeterminate = () => indeterminateDecision(request.reconciliation_digest);
  let loaded = await loadRecord(authorityRecord.store, request.key);
  if (loaded === undefined) return indeterminate();
  if (loaded !== null && loaded.binding_digest !== request.binding_digest) return REJECT;
  if (loaded !== null) {
    const cached = terminalOutput(loaded, request);
    if (loaded.state === "committed" && cached !== null) {
      if (!outputMatchesInput(cached, captured)) return REJECT;
      return mintReceipt(authority, request, cached);
    }
    return indeterminate();
  }

  let acquired: "acquired" | "replay" | "conflict" | "unavailable";
  try {
    acquired = await authorityRecord.store.acquire(Object.freeze({
      key: request.key,
      expected_revision: null,
      binding_digest: request.binding_digest,
      execution_token: request.execution_token,
    }));
  } catch {
    return indeterminate();
  }
  if (acquired !== "acquired") {
    loaded = await loadRecord(authorityRecord.store, request.key);
    if (loaded?.binding_digest !== undefined && loaded.binding_digest !== request.binding_digest) {
      return REJECT;
    }
    if (loaded !== undefined && loaded !== null) {
      const cached = terminalOutput(loaded, request);
      if (cached !== null && outputMatchesInput(cached, captured)) {
        return mintReceipt(authority, request, cached);
      }
    }
    return indeterminate();
  }

  let appendResult: Readonly<{ object_digest: string; commit: string; reachable: boolean }> | null;
  try {
    const raw = await authorityRecord.append_and_resolve(Object.freeze({
      repository_rid: captured.repository_rid,
      ref: captured.ref,
      bytes: new Uint8Array(captured.bytes),
    }));
    const result = captureAuthorityInput(raw);
    if (
      result === null
      || typeof result !== "object"
      || Array.isArray(result)
      || !exactKeys(result as unknown as Readonly<Record<string, unknown>>, [
        "object_digest", "commit", "reachable",
      ])
      || typeof result.object_digest !== "string"
      || !HEX_32.test(result.object_digest)
      || typeof result.commit !== "string"
      || !COMMIT_ID.test(result.commit)
      || typeof result.reachable !== "boolean"
    ) appendResult = null;
    else appendResult = result;
  } catch {
    appendResult = null;
  }
  if (
    appendResult === null
    || appendResult.object_digest !== captured.bytes_digest
    || appendResult.reachable !== true
  ) {
    await safeMarkIndeterminate(authorityRecord.store, request);
    return indeterminate();
  }

  const output = Object.freeze({
    repository_rid: captured.repository_rid,
    ref: captured.ref,
    object_digest: appendResult.object_digest,
    source_digest: captured.source_digest,
    commit: appendResult.commit,
  });
  const digest = outputDigest(output);
  let committed: "committed" | "conflict" | "unknown";
  try {
    committed = await authorityRecord.store.commit(Object.freeze({
      key: request.key,
      binding_digest: request.binding_digest,
      execution_token: request.execution_token,
      output_digest: digest,
      output,
    }));
  } catch {
    committed = "unknown";
  }
  if (committed !== "committed") {
    if (committed === "conflict") {
      const raced = await loadRecord(authorityRecord.store, request.key);
      if (raced !== undefined && raced !== null && raced.state === "committed") {
        const cached = terminalOutput(raced, request);
        if (
          cached !== null
          && sameOutput(cached, output)
          && outputMatchesInput(cached, captured)
        ) return mintReceipt(authority, request, cached);
      }
    }
    await safeMarkIndeterminate(authorityRecord.store, request);
    return indeterminate();
  }

  const terminal = await loadRecord(authorityRecord.store, request.key);
  if (terminal === undefined || terminal === null) {
    await safeMarkIndeterminate(authorityRecord.store, request);
    return indeterminate();
  }
  const readback = terminalOutput(terminal, request);
  if (
    terminal.state !== "committed"
    || readback === null
    || !sameOutput(readback, output)
  ) {
    await safeMarkIndeterminate(authorityRecord.store, request);
    return indeterminate();
  }
  return mintReceipt(authority, request, readback);
}

function receiptState(
  authority: MarmotArchiveRetentionAuthority,
  receipt: MarmotArchiveAppendReceipt,
): Readonly<{ authority: AuthorityRecord; receipt: ReceiptRecord }> | null {
  const authorityRecord = AUTHORITIES.get(authority);
  const receiptRecord = RECEIPTS.get(receipt);
  if (
    authorityRecord === undefined
    || receiptRecord === undefined
    || receiptRecord.authority !== authority
  ) return null;
  return Object.freeze({ authority: authorityRecord, receipt: receiptRecord });
}

export async function acknowledgeMarmotArchive(
  authority: MarmotArchiveRetentionAuthority,
  receipt: MarmotArchiveAppendReceipt,
): Promise<AuthorityDecision<"marmot-premature-ack", MarmotArchiveReceiptData>> {
  const state = receiptState(authority, receipt);
  if (state === null) return REJECT;
  const terminal = await loadRecord(state.authority.store, state.receipt.request.key);
  if (terminal === undefined || terminal === null) {
    return indeterminateDecision(state.receipt.request.reconciliation_digest);
  }
  const output = terminalOutput(terminal, state.receipt.request);
  if (
    output === null
    || outputDigest(output) !== state.receipt.output_digest
    || !sameOutput(output, state.receipt.output)
  ) return indeterminateDecision(state.receipt.request.reconciliation_digest);
  return Object.freeze({ verdict: "accept", output });
}

export async function expireMarmotPresentation(
  authority: MarmotArchiveRetentionAuthority,
  receipt: MarmotArchiveAppendReceipt,
): Promise<AuthorityDecision<"marmot-premature-ack", MarmotArchiveReceiptData>> {
  const state = receiptState(authority, receipt);
  if (state === null) return REJECT;
  const indeterminate = () =>
    indeterminateDecision(state.receipt.request.reconciliation_digest);
  const loaded = await loadRecord(state.authority.store, state.receipt.request.key);
  if (loaded === undefined || loaded === null) return indeterminate();
  const output = terminalOutput(loaded, state.receipt.request);
  if (
    output === null
    || outputDigest(output) !== state.receipt.output_digest
    || !sameOutput(output, state.receipt.output)
  ) return indeterminate();
  if (loaded.state === "available") {
    return Object.freeze({ verdict: "accept", output });
  }
  if (loaded.state !== "committed") return indeterminate();

  let transitioned: "committed" | "conflict" | "unknown";
  try {
    transitioned = await state.authority.store.compareAndSwap(Object.freeze({
      key: state.receipt.request.key,
      expected_revision: loaded.revision,
      next: Object.freeze({
        state: "available" as const,
        revision: loaded.revision + 1,
        binding_digest: state.receipt.request.binding_digest,
        output,
      }),
    }));
  } catch {
    transitioned = "unknown";
  }
  if (transitioned !== "committed" && transitioned !== "conflict") return indeterminate();
  const readback = await loadRecord(state.authority.store, state.receipt.request.key);
  if (readback === undefined || readback === null || readback.state !== "available") {
    return indeterminate();
  }
  const retained = terminalOutput(readback, state.receipt.request);
  if (
    retained === null
    || outputDigest(retained) !== state.receipt.output_digest
    || !sameOutput(retained, state.receipt.output)
  ) return indeterminate();
  return Object.freeze({ verdict: "accept", output: retained });
}
