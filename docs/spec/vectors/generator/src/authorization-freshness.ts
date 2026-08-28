import {
  currentAuthorizationLedgerView,
  evaluateLedgerCheckpointEligibility,
  type LedgerCheckpoint,
  type LedgerMergeResult,
} from "./claim-ledger.js";
import { jcsCanonicalize } from "./jcs.js";
import { captureExactDataObject, snapshotClosedDataTree } from "./closed-data.js";
import {
  continuityManifestDigest,
  resolveIssuerContinuity,
  type ContinuityManifest,
} from "./token-status.js";

declare const AUTHORIZATION_FRESHNESS_AUTHORITY: unique symbol;
declare const CURRENT_AUTHORIZATION_VIEW: unique symbol;

export type AuthorizationViewBinding = Readonly<{
  repository_rid: string;
  persona_key: string;
  manifest_digest: string;
}>;

export type AuthoritativeAuthorizationView = Readonly<{
  manifest: ContinuityManifest;
  ledger_state: LedgerMergeResult;
  previous_manifest?: ContinuityManifest | null;
}>;

export type AuthorizationFreshnessAuthority = Readonly<{
  [AUTHORIZATION_FRESHNESS_AUTHORITY]: true;
}>;

export type CurrentAuthorizationView = Readonly<{
  [CURRENT_AUTHORIZATION_VIEW]: true;
}>;

type FreshnessRejection = Readonly<{
  verdict: "reject";
  reason: "oidc-checkpoint-stale" | "oidc-issuer-authority-invalid" | "control-authorization-view-stale";
}>;

export type AuthorizationFreshnessDecision =
  | Readonly<{ verdict: "accept"; view: CurrentAuthorizationView }>
  | FreshnessRejection;

export type AuthorizationViewEffectDecision =
  | Readonly<{
    verdict: "accept";
    evaluated_at: number;
    checkpoint: LedgerCheckpoint;
    repository_rid: string;
    persona_key: string;
    manifest_digest: string;
    issuer: string;
  }>
  | FreshnessRejection;

export function createAuthorizationFreshnessAuthority(
  binding: AuthorizationViewBinding,
  source: {
    trusted_now: () => number;
    load_current_view: (binding: AuthorizationViewBinding) => AuthoritativeAuthorizationView;
  },
): AuthorizationFreshnessAuthority {
  const capturedBinding = captureExactDataObject(binding, [[
    "repository_rid", "persona_key", "manifest_digest",
  ]], "authorization freshness authority binding");
  const capturedSource = captureExactDataObject(source, [[
    "trusted_now", "load_current_view",
  ]], "authorization freshness authority source");
  if (typeof capturedSource.trusted_now !== "function" ||
      typeof capturedSource.load_current_view !== "function" ||
      typeof capturedBinding.repository_rid !== "string" ||
      typeof capturedBinding.persona_key !== "string" ||
      typeof capturedBinding.manifest_digest !== "string") {
    throw new Error("authorization freshness authority source must contain trusted functions");
  }
  const authority = Object.freeze({}) as AuthorizationFreshnessAuthority;
  AUTHORITY_RECORDS.set(authority, {
    binding: Object.freeze({
      repository_rid: capturedBinding.repository_rid,
      persona_key: capturedBinding.persona_key,
      manifest_digest: capturedBinding.manifest_digest,
    }),
    trusted_now: capturedSource.trusted_now as () => number,
    load_current_view: capturedSource.load_current_view as AuthorityRecord["load_current_view"],
  });
  return authority;
}

export function evaluateAuthorizationFreshness(
  authority: AuthorizationFreshnessAuthority,
  manifest: ContinuityManifest,
): AuthorizationFreshnessDecision {
  const evaluated = loadAndEvaluate(authority, manifest);
  if ("reason" in evaluated) return evaluated;
  const view = Object.freeze({}) as CurrentAuthorizationView;
  VIEW_RECORDS.set(view, {
    authority,
    manifest: structuredClone(evaluated.manifest),
    checkpoint: structuredClone(evaluated.checkpoint),
  });
  return { verdict: "accept", view };
}

export function revalidateAuthorizationViewAtEffect(
  view: CurrentAuthorizationView,
): AuthorizationViewEffectDecision {
  const prepared = isObject(view) ? VIEW_RECORDS.get(view) : undefined;
  if (prepared === undefined) return rejected("control-authorization-view-stale");
  const evaluated = loadAndEvaluate(prepared.authority, prepared.manifest);
  if ("reason" in evaluated) return evaluated;
  if (jcsCanonicalize(evaluated.manifest) !== jcsCanonicalize(prepared.manifest)) {
    return rejected("oidc-issuer-authority-invalid");
  }
  if (jcsCanonicalize(evaluated.checkpoint) !== jcsCanonicalize(prepared.checkpoint)) {
    return rejected("control-authorization-view-stale");
  }
  return {
    verdict: "accept",
    evaluated_at: evaluated.evaluated_at,
    checkpoint: structuredClone(evaluated.checkpoint),
    repository_rid: prepared.manifest.repository_rid,
    persona_key: prepared.manifest.persona_key,
    manifest_digest: continuityManifestDigest(prepared.manifest),
    issuer: prepared.manifest.issuer,
  };
}

type AuthorityRecord = Readonly<{
  binding: AuthorizationViewBinding;
  trusted_now: () => number;
  load_current_view: (binding: AuthorizationViewBinding) => AuthoritativeAuthorizationView;
}>;

type PreparedViewRecord = Readonly<{
  authority: AuthorizationFreshnessAuthority;
  manifest: ContinuityManifest;
  checkpoint: LedgerCheckpoint;
}>;

type EvaluatedView = Readonly<{
  manifest: ContinuityManifest;
  checkpoint: LedgerCheckpoint;
  evaluated_at: number;
}>;

const AUTHORITY_RECORDS = new WeakMap<object, AuthorityRecord>();
const VIEW_RECORDS = new WeakMap<object, PreparedViewRecord>();

function loadAndEvaluate(
  authority: AuthorizationFreshnessAuthority,
  presentedManifest: ContinuityManifest,
): EvaluatedView | FreshnessRejection {
  const record = isObject(authority) ? AUTHORITY_RECORDS.get(authority) : undefined;
  if (record === undefined) return rejected("control-authorization-view-stale");
  try {
    const presented = snapshotClosedDataTree(presentedManifest, "presented authorization manifest");
    if (presented.repository_rid !== record.binding.repository_rid
      || presented.persona_key !== record.binding.persona_key
      || continuityManifestDigest(presented) !== record.binding.manifest_digest) {
      return rejected("oidc-issuer-authority-invalid");
    }
    const evaluatedAt = record.trusted_now();
    if (!Number.isSafeInteger(evaluatedAt) || evaluatedAt < 0) {
      return rejected("control-authorization-view-stale");
    }
    const loadedValues = captureExactDataObject(
      record.load_current_view(record.binding),
      [["manifest", "ledger_state"], ["manifest", "ledger_state", "previous_manifest"]],
      "authoritative authorization loader result",
    );
    const loadedManifest = snapshotClosedDataTree(
      loadedValues.manifest as ContinuityManifest,
      "authoritative authorization manifest",
    );
    const previousManifest = loadedValues.previous_manifest === undefined || loadedValues.previous_manifest === null
      ? null
      : snapshotClosedDataTree(
        loadedValues.previous_manifest as ContinuityManifest,
        "previous authoritative authorization manifest",
      );
    const ledgerView = currentAuthorizationLedgerView(loadedValues.ledger_state as LedgerMergeResult);
    if (jcsCanonicalize(loadedManifest) !== jcsCanonicalize(presented)
      || continuityManifestDigest(loadedManifest) !== record.binding.manifest_digest) {
      return rejected("oidc-issuer-authority-invalid");
    }
    if (jcsCanonicalize(loadedManifest.authority.checkpoint) !== jcsCanonicalize(ledgerView.checkpoint)) {
      return rejected("control-authorization-view-stale");
    }
    const continuity = resolveIssuerContinuity(
      previousManifest,
      loadedManifest,
      {
        identity: {
          persona_npub: loadedManifest.persona_npub,
          persona_key: loadedManifest.persona_key,
        },
        repository_rid: record.binding.repository_rid,
        canonical_branch: "main",
        writer_nid: loadedManifest.authority.writer_nid,
        now: evaluatedAt,
        ledger_state: ledgerView.state,
        succession_authority: null,
        active_persona_authority: null,
      },
    );
    if (!continuity.allowed) return rejected("oidc-issuer-authority-invalid");

    const checkpointFreshness = evaluateLedgerCheckpointEligibility(
      loadedManifest.authority.issued_at,
      ledgerView.checkpoint,
      loadedManifest.max_checkpoint_age_seconds,
    );
    if (!checkpointFreshness.allowed) return rejected("oidc-checkpoint-stale");
    if (ledgerView.conflicted
      || !Number.isSafeInteger(loadedManifest.authorization_view_max_age)
      || loadedManifest.authorization_view_max_age < 1
      || loadedManifest.authorization_view_max_age > 86_400
      || evaluatedAt < ledgerView.checkpoint.observed_at
      || evaluatedAt - ledgerView.checkpoint.observed_at > loadedManifest.authorization_view_max_age) {
      return rejected("control-authorization-view-stale");
    }
    return {
      manifest: loadedManifest,
      checkpoint: structuredClone(ledgerView.checkpoint),
      evaluated_at: evaluatedAt,
    };
  } catch {
    return rejected("control-authorization-view-stale");
  }
}

function rejected(reason: FreshnessRejection["reason"]): FreshnessRejection {
  return { verdict: "reject", reason };
}

function isObject(value: unknown): value is object {
  return value !== null && typeof value === "object";
}
