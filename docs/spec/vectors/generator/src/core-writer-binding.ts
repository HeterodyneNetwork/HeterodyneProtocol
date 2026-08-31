import { types as utilTypes } from "node:util";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import {
  captureExactDataObject,
  snapshotClosedDataTree,
} from "./closed-data.js";
import type {
  CurrentRepositoryPolicy,
  CurrentRepositoryWriterPolicy,
} from "./core-policy.js";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import { proofBytes } from "./proof-bytes.js";
import { validateRepositoryWriterBindingSchemaOrThrow } from "./schema.js";

const PROOF_DOMAIN = "heterodyne-core-repository-writer-binding-v1";
const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);
const HEX_KEY = /^[0-9a-f]{64}$/u;
const RID = /^rad:z[1-9A-HJ-NP-Za-km-z]+$/u;
const CHECKPOINT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const REF_NAMESPACE = /^refs\/(?!.*(?:\.\.|\/\/|@\{|\\))[A-Za-z0-9._/-]+\/$/u;
const WRITER_REF = /^refs\/(?!.*(?:\.\.|\/\/|@\{|\\))[A-Za-z0-9._/-]+$/u;

declare const CORE_REPOSITORY_WRITER_AUTHORITY: unique symbol;
declare const CURRENT_REPOSITORY_WRITER_BINDING: unique symbol;

export type RepositoryWriterBindingV1 = Readonly<{
  profile: "heterodyne.core.repository-writer-binding.v1";
  spec_version: "heterodyne/0.6.0";
  owner_active_key: string;
  repository_rid: string;
  writer_nid: string;
  ref_namespace: string;
  operations: readonly string[];
  issued_at: number;
  expires_at: number;
  owner_signature: string;
  nid_signature: string;
}>;

export type CoreRepositoryWriterAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  load_current_policy: (repositoryRid: string) => CurrentRepositoryPolicy;
}>;

export type RepositoryWriterRequest = Readonly<{
  owner_active_key: string;
  repository_rid: string;
  writer_nid: string;
  writer_ref: string;
  operation: "claim-ledger-write";
}>;

export type CoreRepositoryWriterAuthority = Readonly<{
  readonly [CORE_REPOSITORY_WRITER_AUTHORITY]: true;
}>;

export type CurrentRepositoryWriterBinding = Readonly<{
  readonly [CURRENT_REPOSITORY_WRITER_BINDING]: true;
}>;

type CapturedAuthority = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  load_current_policy: (repositoryRid: string) => CurrentRepositoryPolicy;
}>;

type CapturedPolicy = Readonly<{
  policy: CurrentRepositoryPolicy;
  fingerprint: string;
}>;

type BindingRecord = Readonly<{
  authority: CoreRepositoryWriterAuthority;
  authority_id: string;
  source: object;
  wire_digest: string;
  owner_active_key: string;
  repository_rid: string;
  writer_nid: string;
  writer_ref: string;
  operation: RepositoryWriterRequest["operation"];
  request: RepositoryWriterRequest;
  policy_fingerprint: string;
  policy_revision: number;
  policy_checkpoint: string;
  policy_predecessor: string | null;
}>;

const AUTHORITIES = new WeakMap<object, CapturedAuthority>();
const BINDINGS = new WeakMap<object, BindingRecord>();

export function createCoreRepositoryWriterAuthority(
  config: CoreRepositoryWriterAuthorityConfig,
): CoreRepositoryWriterAuthority {
  try {
    const captured = captureExactDataObject(config, [[
      "authority_id",
      "trusted_now",
      "load_current_policy",
    ]], "Core repository writer authority config");
    if (
      typeof captured.authority_id !== "string" ||
      captured.authority_id.length === 0 || captured.authority_id.length > 256 ||
      typeof captured.trusted_now !== "function" ||
      utilTypes.isProxy(captured.trusted_now) ||
      typeof captured.load_current_policy !== "function" ||
      utilTypes.isProxy(captured.load_current_policy)
    ) throw invalid("invalid authority config");

    const authority = Object.freeze({}) as CoreRepositoryWriterAuthority;
    AUTHORITIES.set(authority, Object.freeze({
      authority_id: captured.authority_id,
      trusted_now: captured.trusted_now as () => number,
      load_current_policy: captured.load_current_policy as CapturedAuthority["load_current_policy"],
    }));
    return authority;
  } catch (error) {
    throw normalizeInvalid(error);
  }
}

export function repositoryWriterBindingProofBytes(
  value: unknown,
): Uint8Array {
  try {
    return proofBytesFor(captureWireBinding(value));
  } catch (error) {
    throw normalizeInvalid(error);
  }
}

export function resolveCurrentRepositoryWriterBinding(
  authority: CoreRepositoryWriterAuthority,
  object: unknown,
  request: RepositoryWriterRequest,
): CurrentRepositoryWriterBinding {
  try {
    const authorityRecord = authorityState(authority);
    const source = ordinarySourceObject(object);
    const binding = captureWireBinding(object);
    const capturedRequest = captureRequest(request);
    const policy = evaluateCurrentBinding(
      authorityRecord,
      binding,
      capturedRequest,
    );
    const artifact = Object.freeze({}) as CurrentRepositoryWriterBinding;
    BINDINGS.set(artifact, Object.freeze({
      authority,
      authority_id: authorityRecord.authority_id,
      source,
      wire_digest: digest(binding),
      owner_active_key: binding.owner_active_key,
      repository_rid: binding.repository_rid,
      writer_nid: binding.writer_nid,
      writer_ref: capturedRequest.writer_ref,
      operation: capturedRequest.operation,
      request: capturedRequest,
      policy_fingerprint: policy.fingerprint,
      policy_revision: policy.policy.revision,
      policy_checkpoint: policy.policy.checkpoint,
      policy_predecessor: policy.policy.predecessor,
    }));
    return artifact;
  } catch (error) {
    throw normalizeInvalid(error);
  }
}

export function revalidateCurrentRepositoryWriterBinding(
  authority: CoreRepositoryWriterAuthority,
  binding: CurrentRepositoryWriterBinding,
): CurrentRepositoryWriterBinding {
  try {
    const authorityRecord = authorityState(authority);
    const record = opaqueBindingState(binding);
    if (
      record.authority !== authority ||
      record.authority_id !== authorityRecord.authority_id
    ) throw invalid("foreign authority binding");

    const currentWire = captureWireBinding(record.source);
    if (
      digest(currentWire) !== record.wire_digest ||
      currentWire.owner_active_key !== record.owner_active_key ||
      currentWire.repository_rid !== record.repository_rid ||
      currentWire.writer_nid !== record.writer_nid
    ) throw invalid("source binding changed");

    const currentPolicy = evaluateCurrentBinding(
      authorityRecord,
      currentWire,
      record.request,
    );
    if (
      currentPolicy.fingerprint !== record.policy_fingerprint ||
      currentPolicy.policy.revision !== record.policy_revision ||
      currentPolicy.policy.checkpoint !== record.policy_checkpoint ||
      currentPolicy.policy.predecessor !== record.policy_predecessor ||
      record.writer_ref !== record.request.writer_ref ||
      record.operation !== record.request.operation
    ) throw invalid("current policy changed");
    return binding;
  } catch (error) {
    throw normalizeInvalid(error);
  }
}

function evaluateCurrentBinding(
  authority: CapturedAuthority,
  binding: RepositoryWriterBindingV1,
  request: RepositoryWriterRequest,
): CapturedPolicy {
  const payload = proofBytesFor(binding);
  if (!validOwnerSignature(binding, payload) ||
      !validNidSignature(binding, payload)) {
    throw invalid("dual proof verification failed");
  }
  const now = authority.trusted_now();
  if (!Number.isSafeInteger(now) || now < 0 ||
      now < binding.issued_at || now >= binding.expires_at) {
    throw invalid("binding is outside trusted time bounds");
  }
  if (
    request.owner_active_key !== binding.owner_active_key ||
    request.repository_rid !== binding.repository_rid ||
    request.writer_nid !== binding.writer_nid ||
    request.operation !== "claim-ledger-write" ||
    !binding.operations.includes(request.operation) ||
    !isWriterRefInNamespace(request.writer_ref, binding.ref_namespace)
  ) throw invalid("request does not match binding");

  const current = captureCurrentPolicy(
    authority.load_current_policy(binding.repository_rid),
  );
  const policy = current.policy;
  if (
    policy.state !== "active" ||
    policy.repository_rid !== binding.repository_rid ||
    policy.owner_active_key !== binding.owner_active_key
  ) throw invalid("repository policy is not current and active");
  const matchingWriters = policy.writers.filter((writer) =>
    writer.state === "active" &&
    writer.writer_nid === binding.writer_nid &&
    writer.ref_namespace === binding.ref_namespace &&
    writer.operations.includes(request.operation)
  );
  if (matchingWriters.length !== 1) {
    throw invalid("writer is not uniquely active in current policy");
  }
  return current;
}

function captureWireBinding(value: unknown): RepositoryWriterBindingV1 {
  const captured = snapshotClosedDataTree(
    value,
    "Core repository writer binding",
  );
  validateRepositoryWriterBindingSchemaOrThrow(captured);
  return captured as RepositoryWriterBindingV1;
}

function captureRequest(value: unknown): RepositoryWriterRequest {
  const captured = captureExactDataObject(value, [[
    "owner_active_key",
    "repository_rid",
    "writer_nid",
    "writer_ref",
    "operation",
  ]], "Core repository writer request");
  if (
    typeof captured.owner_active_key !== "string" ||
    !HEX_KEY.test(captured.owner_active_key) ||
    typeof captured.repository_rid !== "string" ||
    !RID.test(captured.repository_rid) ||
    typeof captured.writer_nid !== "string" ||
    typeof captured.writer_ref !== "string" ||
    !WRITER_REF.test(captured.writer_ref) ||
    captured.operation !== "claim-ledger-write"
  ) throw invalid("invalid repository writer request");
  return Object.freeze({
    owner_active_key: captured.owner_active_key,
    repository_rid: captured.repository_rid,
    writer_nid: captured.writer_nid,
    writer_ref: captured.writer_ref,
    operation: captured.operation,
  });
}

function captureCurrentPolicy(value: unknown): CapturedPolicy {
  const snapshot = snapshotClosedDataTree(
    value,
    "current Core repository policy",
  );
  const captured = captureExactDataObject(snapshot, [[
    "repository_rid",
    "owner_active_key",
    "revision",
    "checkpoint",
    "predecessor",
    "state",
    "writers",
  ]], "current Core repository policy");
  if (
    typeof captured.repository_rid !== "string" ||
    !RID.test(captured.repository_rid) ||
    typeof captured.owner_active_key !== "string" ||
    !HEX_KEY.test(captured.owner_active_key) ||
    !Number.isSafeInteger(captured.revision) ||
    (captured.revision as number) < 0 ||
    typeof captured.checkpoint !== "string" ||
    !CHECKPOINT.test(captured.checkpoint) ||
    !(captured.predecessor === null ||
      typeof captured.predecessor === "string" &&
      CHECKPOINT.test(captured.predecessor)) ||
    !isPolicyState(captured.state) ||
    !Array.isArray(captured.writers)
  ) throw invalid("invalid current repository policy");

  const writers = (captured.writers as readonly unknown[]).map(
    captureCurrentWriter,
  );
  const keys = writers.map((writer) => [
    writer.writer_nid,
    writer.ref_namespace,
  ].join("\0"));
  if (new Set(keys).size !== keys.length) {
    throw invalid("duplicate current writer policy");
  }
  const policy = Object.freeze({
    repository_rid: captured.repository_rid,
    owner_active_key: captured.owner_active_key,
    revision: captured.revision as number,
    checkpoint: captured.checkpoint,
    predecessor: captured.predecessor as string | null,
    state: captured.state,
    writers: Object.freeze(writers),
  }) as CurrentRepositoryPolicy;
  return Object.freeze({ policy, fingerprint: digest(policy) });
}

function captureCurrentWriter(value: unknown): CurrentRepositoryWriterPolicy {
  const captured = captureExactDataObject(value, [[
    "writer_nid",
    "ref_namespace",
    "operations",
    "state",
  ]], "current Core repository writer policy");
  if (
    typeof captured.writer_nid !== "string" ||
    writerEd25519KeyFromNid(captured.writer_nid) === null ||
    typeof captured.ref_namespace !== "string" ||
    !REF_NAMESPACE.test(captured.ref_namespace) ||
    !Array.isArray(captured.operations) ||
    !captured.operations.every((operation) =>
      typeof operation === "string" &&
      /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u.test(operation)
    ) ||
    !isStrictlySorted(captured.operations as string[]) ||
    !isPolicyState(captured.state)
  ) throw invalid("invalid current writer policy");
  return Object.freeze({
    writer_nid: captured.writer_nid,
    ref_namespace: captured.ref_namespace,
    operations: Object.freeze([...(captured.operations as string[])]),
    state: captured.state,
  });
}

function proofBytesFor(binding: RepositoryWriterBindingV1): Uint8Array {
  return proofBytes(PROOF_DOMAIN, {
    profile: binding.profile,
    spec_version: binding.spec_version,
    owner_active_key: binding.owner_active_key,
    repository_rid: binding.repository_rid,
    writer_nid: binding.writer_nid,
    ref_namespace: binding.ref_namespace,
    operations: binding.operations,
    issued_at: binding.issued_at,
    expires_at: binding.expires_at,
  });
}

function validOwnerSignature(
  binding: RepositoryWriterBindingV1,
  payload: Uint8Array,
): boolean {
  try {
    return schnorr.verify(
      hexToBytes(binding.owner_signature),
      sha256(payload),
      hexToBytes(binding.owner_active_key),
    );
  } catch {
    return false;
  }
}

function validNidSignature(
  binding: RepositoryWriterBindingV1,
  payload: Uint8Array,
): boolean {
  try {
    const publicKey = writerEd25519KeyFromNid(binding.writer_nid);
    return publicKey !== null && ed25519.verify(
      hexToBytes(binding.nid_signature),
      payload,
      publicKey,
    );
  } catch {
    return false;
  }
}

function writerEd25519KeyFromNid(nid: string): Uint8Array | null {
  if (!nid.startsWith("did:key:z")) return null;
  try {
    const encoded = nid.slice("did:key:z".length);
    const decoded = base58.decode(encoded);
    if (
      decoded.length !== 34 ||
      decoded[0] !== ED25519_MULTICODEC[0] ||
      decoded[1] !== ED25519_MULTICODEC[1] ||
      base58.encode(decoded) !== encoded
    ) return null;
    return decoded.slice(2);
  } catch {
    return null;
  }
}

function authorityState(value: unknown): CapturedAuthority {
  if (value === null || typeof value !== "object") {
    throw invalid("unknown repository writer authority");
  }
  const state = AUTHORITIES.get(value);
  if (state === undefined) throw invalid("unknown repository writer authority");
  return state;
}

function opaqueBindingState(value: unknown): BindingRecord {
  if (value === null || typeof value !== "object") {
    throw invalid("unknown current repository writer binding");
  }
  const state = BINDINGS.get(value);
  if (state === undefined) {
    throw invalid("unknown current repository writer binding");
  }
  return state;
}

function ordinarySourceObject(value: unknown): object {
  if (value === null || typeof value !== "object" || utilTypes.isProxy(value)) {
    throw invalid("binding source must be an ordinary object");
  }
  return value;
}

function digest(value: unknown): string {
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize(value))));
}

function isWriterRefInNamespace(
  writerRef: string,
  namespace: string,
): boolean {
  return REF_NAMESPACE.test(namespace) && WRITER_REF.test(writerRef) &&
    writerRef.startsWith(namespace) && writerRef.length > namespace.length &&
    !writerRef.endsWith("/");
}

function isPolicyState(
  value: unknown,
): value is CurrentRepositoryPolicy["state"] {
  return value === "active" || value === "revoked" || value === "conflicted";
}

function isStrictlySorted(values: readonly string[]): boolean {
  return values.length > 0 && values.every(
    (value, index) => index === 0 || values[index - 1]! < value,
  );
}

function invalid(detail: string): Error {
  return new Error(`repository-writer-binding-invalid: ${detail}`);
}

function normalizeInvalid(error: unknown): Error {
  return error instanceof Error &&
      error.message.startsWith("repository-writer-binding-invalid:")
    ? error
    : invalid(error instanceof Error ? error.message : "validation failed");
}
