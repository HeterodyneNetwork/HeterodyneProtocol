import { randomBytes } from "node:crypto";
import { types as utilTypes } from "node:util";
import { sha256 } from "@noble/hashes/sha2";
import {
  authorizeWithClaim,
  claimArtifactBindingDigest,
  claimRevocationArtifactBindingDigest,
  inspectVerifiedClaim,
  validateKeyRef,
  type AuthorizationDecision,
  type KeyProof,
  type KeyRef,
  type SubjectProofChallenge,
  type VerifiedClaimArtifact,
  type VerifiedClaimRevocationArtifact,
} from "./claims.js";
import type { CredentialLedgerBinding } from "./credential-generation.js";
import { bytesToHex, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  revalidateLedgerWriterAuthorities,
  type LedgerMergeResult,
} from "./claim-ledger.js";

declare const claimAuthorizationAuthorityBrand: unique symbol;

export type ClaimAuthorizationAuthority = Readonly<{
  readonly [claimAuthorizationAuthorityBrand]: true;
}>;

export type ClaimEffectRecord = Readonly<{
  state: "executing" | "committed" | "indeterminate";
  binding_digest: string;
  execution_token: string;
  result_digest?: string;
  reconciliation_digest?: string;
  cached_result?: unknown;
}>;

export type CurrentClaimAuthorizationView = Readonly<{
  credential_ledger: CredentialLedgerBinding;
  checkpoint_digest: string;
  repository_revision: number;
  claims: readonly VerifiedClaimArtifact[];
  revocations: readonly VerifiedClaimRevocationArtifact[];
  conflicted_claim_ids: readonly string[];
  ledger_state: LedgerMergeResult;
}>;

export type ClaimEffectStore = Readonly<{
  load(singleUseKey: string): ClaimEffectRecord | null;
  acquire(
    singleUseKey: string,
    bindingDigest: string,
    executionToken: string,
  ): "acquired" | "replay" | "conflict";
  commit(
    executionToken: string,
    resultDigest: string,
    cachedResult: unknown,
  ): "committed" | "conflict";
  markIndeterminate(
    executionToken: string,
    reconciliationDigest: string,
  ): "indeterminate" | "conflict";
}>;

export type ClaimEffectDeadlineScheduler = Readonly<{
  schedule(duration_ms: number, fire: () => void): () => void;
}>;

export type ClaimAuthorizationAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  trusted_issuers: readonly KeyRef[];
  load_current_view: () => CurrentClaimAuthorizationView;
  store: ClaimEffectStore;
  effect_timeout_ms: number;
  schedule_effect_deadline: ClaimEffectDeadlineScheduler;
}>;

export type ClaimAuthorizationInspectionInput = Readonly<{
  leaf: VerifiedClaimArtifact;
  chain: readonly VerifiedClaimArtifact[];
  audience: string;
  resource: string;
  requested_namespace: string;
  operation: string;
  nonce: string;
  subject_proof: Readonly<{
    key: KeyRef;
    challenge: SubjectProofChallenge;
    proof: KeyProof;
  }> | null;
}>;

export type ClaimEffectOutcome<T> =
  | Readonly<{ status: "completed"; result: T }>
  | Readonly<{ status: "unknown" }>;

export type ClaimAuthorizationEffectInput<T> = ClaimAuthorizationInspectionInput & Readonly<{
  idempotency_key: string;
  effect_digest: string;
  effect(executionToken: string): ClaimEffectOutcome<T> | Promise<ClaimEffectOutcome<T>>;
}>;

export type ClaimEffectAuthorizationResult<T> =
  | Readonly<{
      verdict: "accept";
      allowed: true;
      state: "active";
      disposition: "executed" | "cached";
      result: T;
    }>
  | Readonly<{
      verdict: "reject";
      allowed: false;
      state: Exclude<AuthorizationDecision["state"], "active"> | "active";
      reason_code: string;
    }>
  | Readonly<{
      verdict: "indeterminate";
      allowed: false;
      state: "active";
      reason_code: "claim-authorization-effect-indeterminate";
      reconciliation_digest: string;
    }>;

type CapturedStore = Readonly<{
  load: ClaimEffectStore["load"];
  acquire: ClaimEffectStore["acquire"];
  commit: ClaimEffectStore["commit"];
  markIndeterminate: ClaimEffectStore["markIndeterminate"];
}>;

type AuthorityRecord = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  trusted_issuers: readonly KeyRef[];
  load_current_view: () => CurrentClaimAuthorizationView;
  store: CapturedStore;
  effect_timeout_ms: number;
  schedule_effect_deadline: ClaimEffectDeadlineScheduler["schedule"];
}>;

type ScheduledEffectDeadline = Readonly<{
  expired: () => boolean;
  wait: Promise<void>;
  cancel: () => void;
}>;

type CapturedInspection = Readonly<{
  leaf: VerifiedClaimArtifact;
  chain: readonly VerifiedClaimArtifact[];
  audience: string;
  resource: string;
  requested_namespace: string;
  operation: string;
  nonce: string;
  subject_proof: ClaimAuthorizationInspectionInput["subject_proof"];
}>;

type CapturedEffect<T> = CapturedInspection & Readonly<{
  idempotency_key: string;
  effect_digest: string;
  effect: ClaimAuthorizationEffectInput<T>["effect"];
}>;

type CapturedView = Readonly<{
  credential_ledger: CredentialLedgerBinding;
  checkpoint_digest: string;
  repository_revision: number;
  claims: readonly VerifiedClaimArtifact[];
  claim_bindings: ReadonlyMap<string, string>;
  revocations: readonly VerifiedClaimRevocationArtifact[];
  revocation_bindings: readonly string[];
  conflicted_claim_ids: readonly string[];
  ledger_state: LedgerMergeResult;
  writer_fingerprints: readonly string[];
}>;

const AUTHORITIES = new WeakMap<object, AuthorityRecord>();
const LOWER_HEX_32 = /^[0-9a-f]{64}$/u;
const MAX_COLLECTION = 256;
const MAX_CHAIN = 9;
const MAX_STRING = 4_096;
const MAX_RESULT_BYTES = 65_536;
const MAX_JSON_NODES = 4_096;
const MAX_JSON_DEPTH = 32;
const MAX_EFFECT_TIMEOUT_MS = 86_400_000;

export function createClaimAuthorizationAuthority(
  config: ClaimAuthorizationAuthorityConfig,
): ClaimAuthorizationAuthority {
  const captured = captureConfig(config);
  const authority = Object.freeze({}) as ClaimAuthorizationAuthority;
  AUTHORITIES.set(authority, captured);
  return authority;
}

export function inspectClaimState(
  authority: ClaimAuthorizationAuthority,
  input: ClaimAuthorizationInspectionInput,
): AuthorizationDecision {
  try {
    const retained = requireAuthority(authority);
    const captured = captureInspection(input, true);
    const view = loadView(retained);
    return evaluateCurrent(captured, retained, view, trustedNow(retained));
  } catch (error) {
    return rejected(error);
  }
}

export async function authorizeClaimEffect<T>(
  authority: ClaimAuthorizationAuthority,
  input: ClaimAuthorizationEffectInput<T>,
): Promise<ClaimEffectAuthorizationResult<T>> {
  let retained: AuthorityRecord;
  let captured: CapturedEffect<T>;
  try {
    retained = requireAuthority(authority);
    captured = captureEffect(input);
    const preparedView = loadView(retained);
    const preparedNow = trustedNow(retained);
    const prepared = evaluateCurrent(captured, retained, preparedView, preparedNow);
    if (prepared.state !== "active") return rejectedDecision(prepared);

    // The second load is intentionally adjacent to evaluation and acquire.
    const currentView = loadView(retained);
    const currentNow = trustedNow(retained);
    if (currentNow < preparedNow) {
      throw new Error("claim-issuer-authority-invalid: trusted clock regressed before acquire");
    }
    if (currentView.repository_revision < preparedView.repository_revision) {
      return rejectedDecision({
        allowed: false,
        state: "conflicted",
        reason_code: "claim-repository-conflict",
      });
    }
    const current = evaluateCurrent(captured, retained, currentView, currentNow);
    if (current.state !== "active") return rejectedDecision(current);

    const writerRevalidation = revalidateLedgerWriterAuthorities(
      currentView.ledger_state,
    );
    if (writerRevalidation.verdict !== "accept" ||
        jcsCanonicalize(writerRevalidation.writer_fingerprints) !==
          jcsCanonicalize(currentView.writer_fingerprints)) {
      throw new Error("claim-ledger-writer-unauthorized: current writer authority changed before acquire");
    }

    const binding = authorizationBinding(captured, retained, currentView);
    const executionToken = randomBytes(32).toString("hex");
    let acquisition: unknown;
    try {
      acquisition = retained.store.acquire(
        binding.single_use_key,
        binding.binding_digest,
        executionToken,
      );
    } catch {
      // The callback may have durably acquired before losing its return. Never
      // invoke the effect until the exact stored terminal/executing token is
      // reconciled; an absent record is a fail-closed replay rejection.
      return cachedTerminal<T>(
        retained,
        binding.single_use_key,
        binding.binding_digest,
      );
    }
    if (acquisition === "conflict") return replayRejected();
    if (acquisition === "replay") {
      return cachedTerminal<T>(retained, binding.single_use_key, binding.binding_digest);
    }
    if (acquisition !== "acquired") return replayRejected();
    if (!hasExactExecutingRecord(
      retained,
      binding.single_use_key,
      binding.binding_digest,
      executionToken,
    )) {
      return indeterminate(binding.binding_digest, executionToken, "acquire-confirmation-failed");
    }

    let outcome: ClaimEffectOutcome<T>;
    let deadline: ScheduledEffectDeadline | null = null;
    try {
      deadline = scheduleEffectDeadline(retained);
      if (deadline.expired()) {
        return persistIndeterminate(
          retained,
          binding.single_use_key,
          binding.binding_digest,
          executionToken,
          "effect-deadline-expired",
        );
      }
      const returned: unknown = captured.effect(executionToken);
      if (utilTypes.isProxy(returned)) {
        throw new Error("claim-authorization-effect-indeterminate: proxy effect outcome");
      }
      if (utilTypes.isPromise(returned)) {
        if (Object.getPrototypeOf(returned) !== Promise.prototype) {
          throw new Error("claim-authorization-effect-indeterminate: nonordinary effect promise");
        }
        const settled = await Promise.race([
          returned.then((value) => Object.freeze({ kind: "effect" as const, value })),
          deadline.wait.then(() => Object.freeze({ kind: "deadline" as const })),
        ]);
        if (settled.kind === "deadline") {
          return persistIndeterminate(
            retained,
            binding.single_use_key,
            binding.binding_digest,
            executionToken,
            "effect-deadline-expired",
          );
        }
        outcome = settled.value as ClaimEffectOutcome<T>;
      } else {
        if (deadline.expired()) {
          return persistIndeterminate(
            retained,
            binding.single_use_key,
            binding.binding_digest,
            executionToken,
            "effect-deadline-expired",
          );
        }
        outcome = returned as ClaimEffectOutcome<T>;
      }
    } catch {
      return persistIndeterminate(
        retained,
        binding.single_use_key,
        binding.binding_digest,
        executionToken,
        "effect-threw-or-rejected",
      );
    } finally {
      deadline?.cancel();
    }
    let result: T;
    try {
      const capturedOutcome = captureEffectOutcome(outcome);
      if (capturedOutcome.status === "unknown") {
        return persistIndeterminate(
          retained,
          binding.single_use_key,
          binding.binding_digest,
          executionToken,
          "effect-outcome-unknown",
        );
      }
      result = capturedOutcome.result as T;
    } catch {
      return persistIndeterminate(
        retained,
        binding.single_use_key,
        binding.binding_digest,
        executionToken,
        "effect-result-unsafe",
      );
    }
    const resultDigest = digest("heterodyne-claim-effect-result-v1", result);
    let terminal: "committed" | "conflict";
    try {
      terminal = retained.store.commit(executionToken, resultDigest, result);
    } catch {
      terminal = "conflict";
    }
    if (terminal === "committed") {
      const loaded = safeLoad(retained, binding.single_use_key);
      const record = loaded === null ? null : captureEffectRecord(loaded);
      if (
        record?.state === "committed" &&
        record.binding_digest === binding.binding_digest &&
        record.execution_token === executionToken &&
        record.result_digest === resultDigest &&
        record.cached_result !== undefined &&
        digest("heterodyne-claim-effect-result-v1", record.cached_result) === resultDigest
      ) {
        return Object.freeze({
          verdict: "accept",
          allowed: true,
          state: "active",
          disposition: "executed" as const,
          result: jsonSnapshot(record.cached_result, "cached_result") as T,
        });
      }
    }
    return persistIndeterminate(
      retained,
      binding.single_use_key,
      binding.binding_digest,
      executionToken,
      "terminal-write-failed",
    );
  } catch (error) {
    return rejectedResult(error);
  }
}

function captureConfig(value: unknown): AuthorityRecord {
  const members = captureClosedObject(value, [
    "authority_id",
    "trusted_now",
    "trusted_issuers",
    "load_current_view",
    "store",
    "effect_timeout_ms",
    "schedule_effect_deadline",
  ], "claim authorization configuration");
  const authorityId = boundedString(members.authority_id, "authority_id");
  const trustedNowCallback = safeCallback(members.trusted_now, "trusted_now");
  const loadCurrentView = safeCallback(members.load_current_view, "load_current_view");
  const trustedIssuers = captureArray(
    members.trusted_issuers,
    MAX_COLLECTION,
    "trusted_issuers",
  ).map((candidate) => {
    const key = jsonSnapshot(candidate, "trusted issuer") as KeyRef;
    validateKeyRef(key);
    return key;
  });
  const storeMembers = captureClosedObject(members.store, [
    "load",
    "acquire",
    "commit",
    "markIndeterminate",
  ], "claim effect store");
  if (
    !Number.isSafeInteger(members.effect_timeout_ms) ||
    (members.effect_timeout_ms as number) <= 0 ||
    (members.effect_timeout_ms as number) > MAX_EFFECT_TIMEOUT_MS
  ) throw new Error("claim-issuer-authority-invalid: invalid effect_timeout_ms");
  const schedulerMembers = captureClosedObject(
    members.schedule_effect_deadline,
    ["schedule"],
    "claim effect deadline scheduler",
  );
  return Object.freeze({
    authority_id: authorityId,
    trusted_now: trustedNowCallback as () => number,
    trusted_issuers: Object.freeze(trustedIssuers),
    load_current_view: loadCurrentView as () => CurrentClaimAuthorizationView,
    store: Object.freeze({
      load: safeCallback(storeMembers.load, "store.load") as ClaimEffectStore["load"],
      acquire: safeCallback(storeMembers.acquire, "store.acquire") as ClaimEffectStore["acquire"],
      commit: safeCallback(storeMembers.commit, "store.commit") as ClaimEffectStore["commit"],
      markIndeterminate: safeCallback(
        storeMembers.markIndeterminate,
        "store.markIndeterminate",
      ) as ClaimEffectStore["markIndeterminate"],
    }),
    effect_timeout_ms: members.effect_timeout_ms as number,
    schedule_effect_deadline: safeCallback(
      schedulerMembers.schedule,
      "schedule_effect_deadline.schedule",
    ) as ClaimEffectDeadlineScheduler["schedule"],
  });
}

function captureInspection(value: unknown, allowEffectMembers: boolean): CapturedInspection {
  const inspectionKeys = [
    "leaf",
    "chain",
    "audience",
    "resource",
    "requested_namespace",
    "operation",
    "nonce",
    "subject_proof",
  ];
  const effectKeys = [...inspectionKeys, "idempotency_key", "effect_digest", "effect"];
  const descriptors = exactDataDescriptors(
    value,
    allowEffectMembers ? [inspectionKeys, effectKeys] : [inspectionKeys],
    "claim authorization request",
  );
  const leaf = descriptors.leaf.value as VerifiedClaimArtifact;
  claimArtifactBindingDigest(leaf);
  const chain = captureArray(descriptors.chain.value, MAX_CHAIN, "claim chain")
    .map((artifact) => {
      claimArtifactBindingDigest(artifact as VerifiedClaimArtifact);
      return artifact as VerifiedClaimArtifact;
    });
  const subjectProof = descriptors.subject_proof.value === null
    ? null
    : jsonSnapshot(descriptors.subject_proof.value, "subject_proof") as NonNullable<
        ClaimAuthorizationInspectionInput["subject_proof"]
      >;
  return Object.freeze({
    leaf,
    chain: Object.freeze(chain),
    audience: boundedString(descriptors.audience.value, "audience"),
    resource: boundedString(descriptors.resource.value, "resource"),
    requested_namespace: boundedString(
      descriptors.requested_namespace.value,
      "requested_namespace",
    ),
    operation: boundedString(descriptors.operation.value, "operation"),
    nonce: boundedString(descriptors.nonce.value, "nonce"),
    subject_proof: subjectProof,
  });
}

function captureEffect<T>(value: unknown): CapturedEffect<T> {
  const common = captureInspection(value, true);
  const descriptors = exactDataDescriptors(value, [[
    "leaf",
    "chain",
    "audience",
    "resource",
    "requested_namespace",
    "operation",
    "nonce",
    "subject_proof",
    "idempotency_key",
    "effect_digest",
    "effect",
  ]], "claim effect request");
  const effectDigest = descriptors.effect_digest.value;
  if (typeof effectDigest !== "string" || !LOWER_HEX_32.test(effectDigest)) {
    throw new Error("claim-issuer-authority-invalid: effect_digest must be lowercase 32-byte hex");
  }
  return Object.freeze({
    ...common,
    idempotency_key: boundedString(descriptors.idempotency_key.value, "idempotency_key"),
    effect_digest: effectDigest,
    effect: safeCallback(descriptors.effect.value, "effect") as CapturedEffect<T>["effect"],
  });
}

function loadView(authority: AuthorityRecord): CapturedView {
  let loaded: unknown;
  try {
    loaded = authority.load_current_view();
  } catch {
    throw new Error("claim-issuer-authority-invalid: current claim view load failed");
  }
  const members = captureClosedObject(loaded, [
    "credential_ledger",
    "checkpoint_digest",
    "repository_revision",
    "claims",
    "revocations",
    "conflicted_claim_ids",
    "ledger_state",
  ], "current claim authorization view");
  const credential = captureCredentialLedger(members.credential_ledger);
  if (typeof members.checkpoint_digest !== "string" || !LOWER_HEX_32.test(members.checkpoint_digest)) {
    throw new Error("claim-issuer-authority-invalid: invalid checkpoint_digest");
  }
  if (!Number.isSafeInteger(members.repository_revision) || (members.repository_revision as number) < 0) {
    throw new Error("claim-issuer-authority-invalid: invalid repository_revision");
  }
  const claims = captureArray(members.claims, MAX_COLLECTION, "current claims")
    .map((artifact) => artifact as VerifiedClaimArtifact);
  const claimBindings = new Map<string, string>();
  for (const artifact of claims) {
    const semantic = inspectVerifiedClaim(artifact);
    if (claimBindings.has(semantic.claim_id)) {
      throw new Error("claim-repository-conflict: duplicate current claim ID");
    }
    claimBindings.set(semantic.claim_id, claimArtifactBindingDigest(artifact));
  }
  const revocations = captureArray(members.revocations, MAX_COLLECTION, "current revocations")
    .map((artifact) => artifact as VerifiedClaimRevocationArtifact);
  const revocationBindings = revocations.map(claimRevocationArtifactBindingDigest).sort();
  if (new Set(revocationBindings).size !== revocationBindings.length) {
    throw new Error("claim-repository-conflict: duplicate current revocation artifact");
  }
  const conflicts = captureArray(
    members.conflicted_claim_ids,
    MAX_COLLECTION,
    "conflicted_claim_ids",
  ).map((claimId) => {
    if (typeof claimId !== "string" || !LOWER_HEX_32.test(claimId)) {
      throw new Error("claim-issuer-authority-invalid: invalid conflicted claim ID");
    }
    return claimId;
  }).sort();
  if (new Set(conflicts).size !== conflicts.length) {
    throw new Error("claim-repository-conflict: duplicate conflicted claim ID");
  }
  const ledgerState = members.ledger_state as LedgerMergeResult;
  const writerAuthority = revalidateLedgerWriterAuthorities(ledgerState);
  if (writerAuthority.verdict !== "accept") {
    throw new Error("claim-ledger-writer-unauthorized: current claim view has no current writer authority");
  }
  return Object.freeze({
    credential_ledger: credential,
    checkpoint_digest: members.checkpoint_digest,
    repository_revision: members.repository_revision as number,
    claims: Object.freeze(claims),
    claim_bindings: claimBindings,
    revocations: Object.freeze(revocations),
    revocation_bindings: Object.freeze(revocationBindings),
    conflicted_claim_ids: Object.freeze(conflicts),
    ledger_state: ledgerState,
    writer_fingerprints: writerAuthority.writer_fingerprints,
  });
}

function evaluateCurrent(
  input: CapturedInspection,
  authority: AuthorityRecord,
  view: CapturedView,
  now: number,
): AuthorizationDecision {
  for (const artifact of input.chain) {
    const semantic = inspectVerifiedClaim(artifact);
    if (view.claim_bindings.get(semantic.claim_id) !== claimArtifactBindingDigest(artifact)) {
      return {
        allowed: false,
        state: view.conflicted_claim_ids.includes(semantic.claim_id) ? "conflicted" : "provisional",
        reason_code: view.conflicted_claim_ids.includes(semantic.claim_id)
          ? "claim-repository-conflict"
          : "claim-repository-unconfirmed",
      };
    }
  }
  return authorizeWithClaim(input.leaf, input.chain, {
    now,
    audience: input.audience,
    resource: input.resource,
    requested_namespace: input.requested_namespace,
    requested_operation: input.operation,
    expected_nonce: input.nonce,
    used_nonces: new Set<string>(),
    trusted_issuers: authority.trusted_issuers.map((key) =>
      jsonSnapshot(key, "trusted issuer") as KeyRef),
    credential_ledger: view.credential_ledger,
    repository_confirmed: new Set(view.claim_bindings.keys()),
    repository_conflicted: new Set(view.conflicted_claim_ids),
    revocations: view.revocations,
    subject_proof: input.subject_proof === null
      ? null
      : jsonSnapshot(input.subject_proof, "subject_proof") as NonNullable<
          ClaimAuthorizationInspectionInput["subject_proof"]
        >,
  });
}

function authorizationBinding(
  input: CapturedEffect<unknown>,
  authority: AuthorityRecord,
  view: CapturedView,
): Readonly<{ single_use_key: string; binding_digest: string }> {
  const leaf = inspectVerifiedClaim(input.leaf);
  const singleUseMembers = {
    issuer: leaf.issuer,
    subject: leaf.subject,
    claim_id: leaf.claim_id,
    audience: input.audience,
    resource: input.resource,
    operation: input.operation,
    nonce: input.nonce,
  };
  const singleUseKey = digest("heterodyne-claim-single-use-v1", singleUseMembers);
  const chainDigest = digest(
    "heterodyne-claim-artifact-chain-v1",
    input.chain.map(claimArtifactBindingDigest),
  );
  const currentViewDigest = digest("heterodyne-current-claim-authorization-view-v1", {
    credential_ledger: view.credential_ledger,
    checkpoint_digest: view.checkpoint_digest,
    repository_revision: view.repository_revision,
    claims: [...view.claim_bindings.entries()].sort(([left], [right]) => left.localeCompare(right)),
    revocations: view.revocation_bindings,
    conflicted_claim_ids: view.conflicted_claim_ids,
    writer_fingerprints: view.writer_fingerprints,
  });
  const bindingDigest = digest("heterodyne-claim-authorization-binding-v1", {
    single_use_key: singleUseKey,
    chain_digest: chainDigest,
    proof_digest: digest("heterodyne-claim-proof-binding-v1", input.subject_proof),
    current_view_digest: currentViewDigest,
    request: {
      ...singleUseMembers,
      requested_namespace: input.requested_namespace,
    },
    effect_digest: input.effect_digest,
    authority_id: authority.authority_id,
    idempotency_key: input.idempotency_key,
  });
  return Object.freeze({ single_use_key: singleUseKey, binding_digest: bindingDigest });
}

function cachedTerminal<T>(
  authority: AuthorityRecord,
  singleUseKey: string,
  bindingDigest: string,
): ClaimEffectAuthorizationResult<T> {
  let record: ClaimEffectRecord | null;
  try {
    const loaded = authority.store.load(singleUseKey);
    record = loaded === null ? null : captureEffectRecord(loaded);
  } catch {
    return indeterminate(bindingDigest, "00".repeat(32), "terminal-load-failed");
  }
  if (record === null || record.binding_digest !== bindingDigest) return replayRejected();
  if (record.state === "committed") {
    const result = record.cached_result;
    if (
      result === undefined ||
      record.result_digest === undefined ||
      digest("heterodyne-claim-effect-result-v1", result) !== record.result_digest
    ) return replayRejected();
    return Object.freeze({
      verdict: "accept",
      allowed: true,
      state: "active",
      disposition: "cached" as const,
      result: jsonSnapshot(result, "cached_result") as T,
    });
  }
  if (record.state === "indeterminate" && record.reconciliation_digest !== undefined) {
    return Object.freeze({
      verdict: "indeterminate",
      allowed: false,
      state: "active",
      reason_code: "claim-authorization-effect-indeterminate",
      reconciliation_digest: record.reconciliation_digest,
    });
  }
  return indeterminate(bindingDigest, record.execution_token, "execution-still-open");
}

function hasExactExecutingRecord(
  authority: AuthorityRecord,
  singleUseKey: string,
  bindingDigest: string,
  executionToken: string,
): boolean {
  const loaded = safeLoad(authority, singleUseKey);
  if (loaded === null) return false;
  try {
    const record = captureEffectRecord(loaded);
    return record.state === "executing" &&
      record.binding_digest === bindingDigest &&
      record.execution_token === executionToken;
  } catch {
    return false;
  }
}

function scheduleEffectDeadline(authority: AuthorityRecord): ScheduledEffectDeadline {
  let expired = false;
  let resolveDeadline!: () => void;
  const wait = new Promise<void>((resolve) => { resolveDeadline = resolve; });
  let cancel: unknown;
  try {
    cancel = authority.schedule_effect_deadline(authority.effect_timeout_ms, () => {
      expired = true;
      resolveDeadline();
    });
  } catch {
    throw new Error("claim-authorization-effect-indeterminate: effect deadline scheduling failed");
  }
  if (typeof cancel !== "function" || utilTypes.isProxy(cancel)) {
    throw new Error("claim-authorization-effect-indeterminate: effect deadline cancellation invalid");
  }
  return Object.freeze({
    expired: () => expired,
    wait,
    cancel: () => {
      try {
        (cancel as () => void)();
      } catch {
        // Cancellation cannot reopen an acquired execution token.
      }
    },
  });
}

function persistIndeterminate<T>(
  authority: AuthorityRecord,
  singleUseKey: string,
  bindingDigest: string,
  executionToken: string,
  failureClass: string,
): ClaimEffectAuthorizationResult<T> {
  const result = indeterminate(bindingDigest, executionToken, failureClass);
  try {
    authority.store.markIndeterminate(executionToken, result.reconciliation_digest);
  } catch {
    // The irreversible acquire still prevents reopening; retry reconciles it.
  }
  const loaded = safeLoad(authority, singleUseKey);
  if (loaded !== null) {
    try {
      const record = captureEffectRecord(loaded);
      if (
        record.state === "indeterminate" &&
        record.binding_digest === bindingDigest &&
        record.execution_token === executionToken &&
        record.reconciliation_digest !== undefined
      ) {
        return Object.freeze({
          ...result,
          reconciliation_digest: record.reconciliation_digest,
        });
      }
    } catch {
      // Never turn an unsafe terminal record into positive authority.
    }
  }
  return result;
}

function captureEffectRecord(value: unknown): ClaimEffectRecord {
  const descriptors = exactDataDescriptors(value, [
    ["state", "binding_digest", "execution_token"],
    ["state", "binding_digest", "execution_token", "result_digest", "cached_result"],
    ["state", "binding_digest", "execution_token", "reconciliation_digest"],
  ], "claim effect record");
  const state = descriptors.state.value;
  if (state !== "executing" && state !== "committed" && state !== "indeterminate") {
    throw new Error("claim-issuer-authority-invalid: invalid claim effect state");
  }
  const binding = exactDigest(descriptors.binding_digest.value, "binding_digest");
  const token = exactDigest(descriptors.execution_token.value, "execution_token");
  if (state === "executing" && Reflect.ownKeys(descriptors).length !== 3) {
    throw new Error("claim-issuer-authority-invalid: malformed executing effect record");
  }
  if (state === "committed") {
    if (Reflect.ownKeys(descriptors).length !== 5) {
      throw new Error("claim-issuer-authority-invalid: malformed committed effect record");
    }
    return Object.freeze({
      state,
      binding_digest: binding,
      execution_token: token,
      result_digest: exactDigest(descriptors.result_digest.value, "result_digest"),
      cached_result: jsonSnapshot(descriptors.cached_result.value, "cached_result"),
    });
  }
  if (state === "indeterminate") {
    if (Reflect.ownKeys(descriptors).length !== 4) {
      throw new Error("claim-issuer-authority-invalid: malformed indeterminate effect record");
    }
    return Object.freeze({
      state,
      binding_digest: binding,
      execution_token: token,
      reconciliation_digest: exactDigest(
        descriptors.reconciliation_digest.value,
        "reconciliation_digest",
      ),
    });
  }
  return Object.freeze({ state, binding_digest: binding, execution_token: token });
}

function captureEffectOutcome(value: unknown): ClaimEffectOutcome<unknown> {
  const descriptors = exactDataDescriptors(value, [
    ["status"],
    ["status", "result"],
  ], "claim effect outcome");
  if (descriptors.status.value === "unknown" && Reflect.ownKeys(descriptors).length === 1) {
    return Object.freeze({ status: "unknown" });
  }
  if (descriptors.status.value !== "completed" || Reflect.ownKeys(descriptors).length !== 2) {
    throw new Error("claim-authorization-effect-indeterminate: invalid effect outcome");
  }
  return Object.freeze({
    status: "completed",
    result: jsonSnapshot(descriptors.result.value, "effect result"),
  });
}

function captureCredentialLedger(value: unknown): CredentialLedgerBinding {
  const members = captureClosedObject(value, [
    "credential_ledger_persona",
    "credential_ledger_generation",
  ], "credential ledger binding");
  if (
    typeof members.credential_ledger_persona !== "string" ||
    !LOWER_HEX_32.test(members.credential_ledger_persona) ||
    !Number.isSafeInteger(members.credential_ledger_generation) ||
    (members.credential_ledger_generation as number) < 0
  ) throw new Error("credential_schema_invalid: invalid credential ledger binding");
  return Object.freeze({
    credential_ledger_persona: members.credential_ledger_persona,
    credential_ledger_generation: members.credential_ledger_generation as number,
  });
}

function trustedNow(authority: AuthorityRecord): number {
  let value: unknown;
  try {
    value = authority.trusted_now();
  } catch {
    throw new Error("claim-issuer-authority-invalid: trusted clock failed");
  }
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error("claim-issuer-authority-invalid: trusted clock returned an unsafe time");
  }
  return value as number;
}

function requireAuthority(value: unknown): AuthorityRecord {
  if (value === null || typeof value !== "object") {
    throw new Error("claim-issuer-authority-invalid: opaque claim authorization authority required");
  }
  const record = AUTHORITIES.get(value);
  if (record === undefined) {
    throw new Error("claim-issuer-authority-invalid: opaque claim authorization authority required");
  }
  return record;
}

function captureClosedObject(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  const descriptors = exactDataDescriptors(value, [keys], label);
  return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
}

function exactDataDescriptors(
  value: unknown,
  allowedShapes: readonly (readonly string[])[],
  label: string,
): Record<string, PropertyDescriptor & { value: unknown }> {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype
  ) throw new Error(`claim-issuer-authority-invalid: ${label} must be an ordinary object`);
  const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as PropertyDescriptorMap;
  const keys = Reflect.ownKeys(descriptors);
  const shape = allowedShapes.find((candidate) =>
    keys.length === candidate.length &&
    keys.every((key) => typeof key === "string" && candidate.includes(key))
  );
  if (shape === undefined) {
    throw new Error(`claim-issuer-authority-invalid: ${label} must have an exact shape`);
  }
  for (const key of shape) {
    const descriptor = descriptors[key];
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`claim-issuer-authority-invalid: ${label} must be data-only`);
    }
  }
  return descriptors as Record<string, PropertyDescriptor & { value: unknown }>;
}

function captureArray(value: unknown, maximum: number, label: string): unknown[] {
  if (
    value === null || typeof value !== "object" || utilTypes.isProxy(value) ||
    !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype
  ) throw new Error(`claim-issuer-authority-invalid: ${label} must be an ordinary array`);
  const descriptors = Object.getOwnPropertyDescriptors(value) as unknown as PropertyDescriptorMap;
  const lengthDescriptor = descriptors.length;
  const length = lengthDescriptor?.value as unknown;
  if (
    !Number.isSafeInteger(length) || (length as number) < 0 || (length as number) > maximum ||
    Reflect.ownKeys(descriptors).length !== (length as number) + 1
  ) throw new Error(`claim-issuer-authority-invalid: ${label} is sparse or oversized`);
  const result: unknown[] = [];
  for (let index = 0; index < (length as number); index += 1) {
    const descriptor = descriptors[String(index)];
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`claim-issuer-authority-invalid: ${label} must be data-only`);
    }
    result.push(descriptor.value);
  }
  return result;
}

function jsonSnapshot(value: unknown, label: string): unknown {
  let nodes = 0;
  const seen = new Set<object>();
  const visit = (node: unknown, depth: number): unknown => {
    nodes += 1;
    if (nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) {
      throw new Error(`claim-issuer-authority-invalid: ${label} is oversized`);
    }
    if (node === null || typeof node === "string" || typeof node === "boolean") return node;
    if (typeof node === "number") {
      if (!Number.isFinite(node)) throw new Error(`claim-issuer-authority-invalid: ${label} is not JSON`);
      return node;
    }
    if (typeof node !== "object" || utilTypes.isProxy(node) || seen.has(node)) {
      throw new Error(`claim-issuer-authority-invalid: ${label} is unsafe JSON`);
    }
    seen.add(node);
    try {
      if (Array.isArray(node)) {
        return captureArray(node, MAX_JSON_NODES, label).map((member) => visit(member, depth + 1));
      }
      const descriptors = Object.getOwnPropertyDescriptors(node);
      if (Object.getPrototypeOf(node) !== Object.prototype) {
        throw new Error(`claim-issuer-authority-invalid: ${label} is not an ordinary JSON object`);
      }
      const output: Record<string, unknown> = {};
      for (const key of Reflect.ownKeys(descriptors)) {
        const descriptor = descriptors[key as string];
        if (
          typeof key !== "string" || descriptor === undefined || !("value" in descriptor) ||
          !descriptor.enumerable || descriptor.value === undefined
        ) throw new Error(`claim-issuer-authority-invalid: ${label} is not data-only JSON`);
        output[key] = visit(descriptor.value, depth + 1);
      }
      return output;
    } finally {
      seen.delete(node);
    }
  };
  const snapshot = deepFreeze(visit(value, 0));
  if (Buffer.byteLength(jcsCanonicalize(snapshot), "utf8") > MAX_RESULT_BYTES) {
    throw new Error(`claim-issuer-authority-invalid: ${label} exceeds the serialized bound`);
  }
  return snapshot;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function safeCallback(value: unknown, label: string): (...args: any[]) => any {
  if (typeof value !== "function" || utilTypes.isProxy(value)) {
    throw new Error(`claim-issuer-authority-invalid: ${label} must be a non-proxy callback`);
  }
  return value as (...args: any[]) => any;
}

function boundedString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_STRING) {
    throw new Error(`claim-issuer-authority-invalid: invalid ${label}`);
  }
  return value;
}

function exactDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !LOWER_HEX_32.test(value)) {
    throw new Error(`claim-issuer-authority-invalid: invalid ${label}`);
  }
  return value;
}

function digest(domain: string, value: unknown): string {
  return bytesToHex(sha256(utf8Bytes(`${domain}\0${jcsCanonicalize(value)}`)));
}

function safeLoad(authority: AuthorityRecord, singleUseKey: string): ClaimEffectRecord | null {
  try {
    return authority.store.load(singleUseKey);
  } catch {
    return null;
  }
}

function replayRejected<T>(): ClaimEffectAuthorizationResult<T> {
  return Object.freeze({
    verdict: "reject",
    allowed: false,
    state: "invalid",
    reason_code: "claim-subject-proof-replayed",
  });
}

function indeterminate<T>(
  bindingDigest: string,
  executionToken: string,
  _failureClass: string,
): Extract<ClaimEffectAuthorizationResult<T>, { verdict: "indeterminate" }> {
  return Object.freeze({
    verdict: "indeterminate",
    allowed: false,
    state: "active",
    reason_code: "claim-authorization-effect-indeterminate",
    reconciliation_digest: digest("heterodyne-claim-effect-reconciliation-v1", {
      binding_digest: bindingDigest,
      execution_token: executionToken,
    }),
  });
}

function rejected(error: unknown): AuthorizationDecision {
  const reason = reasonFrom(error);
  return Object.freeze({ allowed: false, state: "invalid", reason_code: reason });
}

function rejectedResult<T>(error: unknown): ClaimEffectAuthorizationResult<T> {
  return Object.freeze({
    verdict: "reject",
    allowed: false,
    state: "invalid",
    reason_code: reasonFrom(error),
  });
}

function rejectedDecision<T>(decision: AuthorizationDecision): ClaimEffectAuthorizationResult<T> {
  return Object.freeze({
    verdict: "reject",
    allowed: false,
    state: decision.state,
    reason_code: decision.reason_code ?? "claim-issuer-authority-invalid",
  });
}

function reasonFrom(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  return message.match(/\b(claim-[a-z-]+|credential_[a-z_]+)\b/u)?.[1]
    ?? "claim-issuer-authority-invalid";
}
