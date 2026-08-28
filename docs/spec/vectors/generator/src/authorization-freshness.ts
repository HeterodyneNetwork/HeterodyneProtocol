import {
  currentAuthorizationLedgerView,
  evaluateLedgerCheckpointEligibility,
  type LedgerCheckpoint,
  type LedgerMergeResult,
} from "./claim-ledger.js";
import { jcsCanonicalize } from "./jcs.js";
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
  if (Object.keys(binding).sort().join("\0") !== "manifest_digest\0persona_key\0repository_rid") {
    throw new Error("authorization freshness authority binding must be exact");
  }
  if (Object.keys(source).sort().join("\0") !== "load_current_view\0trusted_now") {
    throw new Error("authorization freshness authority source must be exact");
  }
  if (typeof source.trusted_now !== "function" || typeof source.load_current_view !== "function") {
    throw new Error("authorization freshness authority source must contain trusted functions");
  }
  const authority = Object.freeze({}) as AuthorizationFreshnessAuthority;
  AUTHORITY_RECORDS.set(authority, {
    binding: Object.freeze({ ...binding }),
    trusted_now: source.trusted_now,
    load_current_view: source.load_current_view,
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
    if (presentedManifest.repository_rid !== record.binding.repository_rid
      || presentedManifest.persona_key !== record.binding.persona_key
      || continuityManifestDigest(presentedManifest) !== record.binding.manifest_digest) {
      return rejected("oidc-issuer-authority-invalid");
    }
    const evaluatedAt = record.trusted_now();
    if (!Number.isSafeInteger(evaluatedAt) || evaluatedAt < 0) {
      return rejected("control-authorization-view-stale");
    }
    const loaded = record.load_current_view(Object.freeze({ ...record.binding }));
    const allowedKeys = loaded.previous_manifest === undefined
      ? "ledger_state\0manifest"
      : "ledger_state\0manifest\0previous_manifest";
    if (!isObject(loaded) || Object.keys(loaded).sort().join("\0") !== allowedKeys) {
      return rejected("control-authorization-view-stale");
    }
    if (jcsCanonicalize(loaded.manifest) !== jcsCanonicalize(presentedManifest)
      || continuityManifestDigest(loaded.manifest) !== record.binding.manifest_digest) {
      return rejected("oidc-issuer-authority-invalid");
    }
    const ledgerView = currentAuthorizationLedgerView(loaded.ledger_state);
    if (jcsCanonicalize(loaded.manifest.authority.checkpoint) !== jcsCanonicalize(ledgerView.checkpoint)) {
      return rejected("control-authorization-view-stale");
    }
    const continuity = resolveIssuerContinuity(
      loaded.previous_manifest ?? null,
      loaded.manifest,
      {
        identity: {
          persona_npub: loaded.manifest.persona_npub,
          persona_key: loaded.manifest.persona_key,
        },
        repository_rid: record.binding.repository_rid,
        canonical_branch: "main",
        writer_nid: loaded.manifest.authority.writer_nid,
        now: evaluatedAt,
        ledger_state: loaded.ledger_state,
        succession_authority: null,
        active_persona_authority: null,
      },
    );
    if (!continuity.allowed) return rejected("oidc-issuer-authority-invalid");

    const checkpointFreshness = evaluateLedgerCheckpointEligibility(
      loaded.manifest.authority.issued_at,
      ledgerView.checkpoint,
      loaded.manifest.max_checkpoint_age_seconds,
    );
    if (!checkpointFreshness.allowed) return rejected("oidc-checkpoint-stale");
    if (ledgerView.conflicted
      || !Number.isSafeInteger(loaded.manifest.authorization_view_max_age)
      || loaded.manifest.authorization_view_max_age < 1
      || loaded.manifest.authorization_view_max_age > 86_400
      || evaluatedAt < ledgerView.checkpoint.observed_at
      || evaluatedAt - ledgerView.checkpoint.observed_at > loaded.manifest.authorization_view_max_age) {
      return rejected("control-authorization-view-stale");
    }
    return {
      manifest: structuredClone(loaded.manifest),
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
