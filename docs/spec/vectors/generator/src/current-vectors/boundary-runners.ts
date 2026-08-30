import * as agentAuthorship from "../agent-authorship.js";
import * as agentModeration from "../agent-moderation.js";
import * as assurance from "../assurance.js";
import * as assuranceObservation from "../assurance-observation.js";
import * as assurancePolicy from "../assurance-policy.js";
import * as authorizationFreshness from "../authorization-freshness.js";
import * as backupCrypto from "../backup-crypto.js";
import * as claimLedger from "../claim-ledger.js";
import * as claims from "../claims.js";
import * as commsPolicy from "../comms-policy.js";
import * as controlPolicy from "../control-policy.js";
import * as controlSigning from "../control-signing.js";
import * as corePolicy from "../core-policy.js";
import * as followUpHardening from "../follow-up-hardening.js";
import * as marmotAdmission from "../marmot-admission.js";
import * as marmotRoutingPolicy from "../marmot-routing-policy.js";
import * as oidc from "../oidc.js";
import * as profileNegotiation from "../profile-negotiation.js";
import * as privacyCrypto from "../privacy-crypto.js";
import * as publicReader from "../public-reader.js";
import * as radicle from "../radicle.js";
import * as registry from "../registry.js";
import * as replaceableSelection from "../replaceable-selection.js";
import * as schema from "../schema.js";
import * as socialEvents from "../social-events.js";
import * as socialPolicy from "../social-policy.js";
import * as tokenStatus from "../token-status.js";
import * as trustedSeed from "../trusted-seed.js";
import * as workspace from "../workspace.js";
import * as workspaceAssurance from "../workspace-assurance.js";
import * as workspacePolicy from "../workspace-policy.js";
import * as nip49 from "nostr-tools/nip49";
import { nip44 } from "nostr-tools";
import { bytesToHex, hexToBytes } from "../hex.js";
import type { CurrentCaseFixture } from "./types.js";
import { currentProfileOracleForVector } from "./profile-oracles.js";
import { evaluateCurrentTier3PrivateRoute } from "./private-route-authority.js";
import { evaluateCurrentRevocationProfile } from "./revocation-profile-boundary.js";
import type { CurrentRevocationExecutionFixture } from "./revocation-profile-fixtures.js";
import { resolve } from "node:path";

const REPOSITORY_ROOT = resolve(import.meta.dirname, "../../../../../..");

type BoundaryModule = Readonly<Record<string, unknown>>;
type BoundaryFunction = (...args: readonly unknown[]) => unknown;

const BOUNDARY_MODULES: Readonly<Record<string, BoundaryModule>> = Object.freeze({
  "agent-authorship": agentAuthorship,
  "agent-moderation": agentModeration,
  assurance,
  "assurance-observation": assuranceObservation,
  "assurance-policy": assurancePolicy,
  "authorization-freshness": authorizationFreshness,
  "backup-crypto": backupCrypto,
  "claim-ledger": claimLedger,
  claims,
  "comms-policy": commsPolicy,
  "control-policy": controlPolicy,
  "control-signing": controlSigning,
  "core-policy": corePolicy,
  "follow-up-hardening": followUpHardening,
  "marmot-admission": marmotAdmission,
  "marmot-routing-policy": marmotRoutingPolicy,
  oidc,
  "profile-negotiation": profileNegotiation,
  "privacy-crypto": privacyCrypto,
  "public-reader": publicReader,
  radicle,
  registry,
  "replaceable-selection": replaceableSelection,
  schema,
  "social-events": socialEvents,
  "social-policy": socialPolicy,
  "token-status": tokenStatus,
  "trusted-seed": trustedSeed,
  workspace,
  "workspace-assurance": workspaceAssurance,
  "workspace-policy": workspacePolicy,
});

function directBoundary(boundaryId: string): BoundaryFunction {
  const separator = boundaryId.indexOf(".");
  if (separator <= 0 || boundaryId.includes("+")) {
    throw new Error(`current boundary requires a closed composite runner: ${boundaryId}`);
  }
  const moduleId = boundaryId.slice(0, separator);
  const exportName = boundaryId.slice(separator + 1);
  const module = BOUNDARY_MODULES[moduleId];
  const candidate = module?.[exportName];
  if (typeof candidate !== "function") {
    throw new Error(`current boundary is not executable: ${boundaryId}`);
  }
  return candidate as BoundaryFunction;
}

function thrownProjection(error: unknown): Readonly<Record<string, unknown>> {
  const message = error instanceof Error ? error.message : String(error);
  const reason = message.match(/^([a-z][a-z0-9_-]*)(?::|$)/u)?.[1];
  if (reason === undefined) throw error;
  return { verdict: "reject", reason_code: reason };
}

/** Invokes only the evaluator identity selected by the closed case catalog. */
async function executeCurrentBoundary(
  boundaryId: string,
  fixture: CurrentCaseFixture,
): Promise<Readonly<{ raw_result: unknown; projected_output: unknown }>> {
  if (boundaryId === "profile-negotiation.validateCurrentKindProfileNegotiation") {
    const raw = profileNegotiation.validateCurrentKindProfileNegotiation(
      registry.loadRegistry(REPOSITORY_ROOT),
      fixture.input,
    );
    return { raw_result: raw, projected_output: raw };
  }
  if (boundaryId === "current-private-route.evaluateCurrentTier3PrivateRoute") {
    const route = evaluateCurrentTier3PrivateRoute(fixture.vector_id, fixture.input);
    return {
      raw_result: Object.freeze({
        ...route.decision,
        route_evidence: route.evidence,
      }),
      projected_output: route.decision,
    };
  }
  if (boundaryId === "current-revocation.evaluateCurrentRevocationProfile") {
    const [execution] = fixture.boundary_args ?? [];
    return evaluateCurrentRevocationProfile(
      fixture.vector_id,
      fixture.input,
      execution as CurrentRevocationExecutionFixture,
    );
  }
  if (
    boundaryId
    === "agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile"
  ) {
    const injection = agentAuthorship.injectAgentAttribution(
      fixture.input as Parameters<typeof agentAuthorship.injectAgentAttribution>[0],
    );
    const profileMatches = injection.verdict === "accept"
      && agentAuthorship.matchesAgentAttributionProfile(injection.tags);
    const raw = { injection, profile_matches: profileMatches };
    return {
      raw_result: raw,
      projected_output: injection.verdict === "accept" && profileMatches
        ? {
            verdict: "accept",
            author: injection.author,
            placement: injection.placement,
            profile_matches: true,
          }
        : injection.verdict === "reject"
          ? injection
          : { verdict: "reject", reason_code: "agent-attribution-invalid" },
    };
  }
  if (
    boundaryId
    === "agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy"
  ) {
    const input = fixture.input as Readonly<{
      publication: Parameters<typeof agentAuthorship.injectAgentAttribution>[0];
      policy: Parameters<typeof agentModeration.applySubscribedAgentPolicy>[0];
    }>;
    const injection = agentAuthorship.injectAgentAttribution(input.publication);
    const profileMatches = injection.verdict === "accept"
      && agentAuthorship.matchesAgentAttributionProfile(injection.tags);
    const policy = agentModeration.applySubscribedAgentPolicy(input.policy);
    const raw = { injection, profile_matches: profileMatches, policy };
    return {
      raw_result: raw,
      projected_output: injection.verdict === "accept"
        && profileMatches
        && policy.visible === false
        && policy.muted
        ? {
            verdict: "accept",
            author: injection.author,
            profile_matches: true,
            local_policy_applied: true,
          }
        : injection.verdict === "reject"
          ? injection
          : { verdict: "reject", reason_code: "agent-policy-binding-invalid" },
    };
  }
  if (boundaryId === "replaceable-selection.selectCurrentReplaceableEvent") {
    const input = fixture.input as {
      trusted_now: number;
      candidates: Parameters<typeof replaceableSelection.selectCurrentReplaceableEvent>[1];
    };
    const authority = replaceableSelection.createReplaceableSelectionAuthority({
      trusted_now: () => input.trusted_now,
    });
    const raw = replaceableSelection.selectCurrentReplaceableEvent(
      authority,
      input.candidates,
    );
    const quarantinedIds = raw.quarantined.map(({ event_id }) => event_id);
    const projected = fixture.vector_id === "core/replaceable-future-quarantined"
      ? {
          verdict: "reject",
          reason_code: raw.quarantined[0]?.reason_code,
          selected_event_id: raw.selected?.id ?? null,
          quarantined_event_ids: quarantinedIds,
        }
      : fixture.vector_id === "core/replaceable-at-premature-boundary"
        ? {
            verdict: "accept",
            selected_event_id: raw.selected?.id ?? null,
            quarantined_event_ids: quarantinedIds,
          }
        : {
            verdict: "accept",
            selected_event_id: raw.selected?.id ?? null,
          };
    return { raw_result: raw, projected_output: projected };
  }
  if (boundaryId === "radicle.validateNodeAdvertisement") {
    const input = fixture.input as {
      event: Parameters<typeof radicle.validateNodeAdvertisement>[0];
      trusted_now: number;
      reachable_oids: string[];
    };
    const raw = radicle.validateNodeAdvertisement(input.event, {
      now: input.trusted_now,
      graph_fetch: { status: "available", reachable_oids: input.reachable_oids },
    });
    return {
      raw_result: raw,
      projected_output: raw.status === "accepted"
        ? { verdict: "accept", normalized: raw }
        : { verdict: "reject", reason_code: raw.failure },
    };
  }
  if (boundaryId === "assurance-observation.evaluateEnrollmentEligibility") {
    const input = fixture.input as {
      inception: Parameters<typeof assurance.evaluateEnrollment>[0]["inception"];
      acceptance: Parameters<typeof assurance.evaluateEnrollment>[0]["acceptance"];
      authority_id: string;
      journal_integrity_key: string;
      witness_policy: {
        policy_digest: string;
        minimum_weight: number;
        witnesses: Array<[string, number]>;
      };
      steps: Array<{
        at: number;
        evidence: assuranceObservation.EnrollmentEvidenceInput;
      }>;
    };
    const entries = new Map<string, assuranceObservation.EnrollmentObservationJournalEntry>();
    let trustedNow = input.steps[0]?.at ?? 0;
    const authority = assuranceObservation.createAssuranceEnrollmentObservationAuthority({
      authority_id: input.authority_id,
      journal_integrity_key: input.journal_integrity_key,
      trusted_now: () => trustedNow,
      witness_policy: {
        policy_digest: input.witness_policy.policy_digest,
        minimum_weight: input.witness_policy.minimum_weight,
        witnesses: new Map(input.witness_policy.witnesses),
      },
      journal: {
        load: (key) => entries.get(key) ?? null,
        compareAndSwap(key, expectedRevision, next) {
          if ((entries.get(key)?.revision ?? null) !== expectedRevision) {
            return "conflict";
          }
          entries.set(key, next);
          return "committed";
        },
      },
    });
    let raw: Awaited<ReturnType<typeof assuranceObservation.evaluateEnrollmentEligibility>> = {
      verdict: "reject",
      reason_code: "assurance-enrollment-pending-window",
    };
    for (const step of input.steps) {
      trustedNow = step.at;
      raw = await assuranceObservation.evaluateEnrollmentEligibility(authority, {
        inception: input.inception,
        acceptance: input.acceptance,
        evidence: step.evidence,
      });
    }
    const projected = "verdict" in raw
      ? raw
      : raw.reason === null
        ? {
            verdict: "accept",
            state: raw.state,
            warnings: raw.warnings,
            assurance_head: raw.normalized.head,
          }
        : {
            verdict: "reject",
            reason_code: raw.reason,
            state: raw.state,
            warnings: raw.warnings,
            assurance_head: raw.normalized.head,
          };
    return { raw_result: raw, projected_output: projected };
  }
  if (boundaryId === "assurance.evaluateAssuranceAuthorityAt") {
    const input = fixture.input as { created_at: number; compromise_cutoff: number | null };
    const raw = assurance.evaluateAssuranceAuthorityAt(
      input.created_at,
      input.compromise_cutoff,
    );
    return { raw_result: raw, projected_output: raw };
  }
  if (
    boundaryId
    === "backup-crypto.nip49EncryptDeterministic+nostr-tools.nip49.decrypt"
  ) {
    const input = fixture.input as {
      secret_key: string;
      password: string;
      salt: string;
      nonce: string;
    };
    const ncryptsec = backupCrypto.nip49EncryptDeterministic(
      input.secret_key,
      input.password,
      input.salt,
      input.nonce,
    );
    const raw = {
      ncryptsec,
      recovered_secret: bytesToHex(nip49.decrypt(ncryptsec, input.password)),
    };
    return {
      raw_result: raw,
      projected_output: { verdict: "accept", ...raw },
    };
  }
  if (
    boundaryId === "privacy-crypto.deriveConfigPostKey+nostr-tools.nip44"
    || boundaryId === "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44"
  ) {
    const input = fixture.input as {
      config_audience_key?: string;
      audience_key?: string;
      key_id: string;
      plaintext: string;
    };
    const config = boundaryId.includes("deriveConfigPostKey");
    const key = config
      ? privacyCrypto.deriveConfigPostKey(input.config_audience_key!, input.key_id)
      : privacyCrypto.deriveTier3IndexKey(input.audience_key!, input.key_id);
    const nonce = config ? "60".repeat(32) : "61".repeat(32);
    const ciphertext = nip44.v2.encrypt(input.plaintext, key, hexToBytes(nonce));
    const recovered = nip44.v2.decrypt(ciphertext, key);
    const raw = { key, ciphertext, recovered };
    const authenticatedRoundTrip = recovered === input.plaintext
      && ciphertext !== input.plaintext;
    return {
      raw_result: raw,
      projected_output: {
        verdict: authenticatedRoundTrip ? "accept" : "mismatch",
        derived_key: bytesToHex(key),
        ciphertext,
        recovered_plaintext: recovered,
      },
    };
  }
  if (
    boundaryId
    === "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute"
  ) {
    const input = fixture.input as {
      audience_key: string;
      key_id: string;
      plaintext: string;
      memberPersonas: readonly string[];
      devices: readonly {
        persona: string;
        pubkey: string;
        active: boolean;
        role: "human-device" | "full-node" | "agent";
      }[];
      selected: readonly string[];
      requested_repository_rid: string;
      requested_interface_id: string;
      requested_route: string;
    };
    const key = privacyCrypto.deriveTier3IndexKey(input.audience_key, input.key_id);
    const ciphertext = nip44.v2.encrypt(
      input.plaintext,
      key,
      hexToBytes("61".repeat(32)),
    );
    const recovered = nip44.v2.decrypt(ciphertext, key);
    const crypto = {
      derived_key: bytesToHex(key),
      ciphertext,
      recovered_plaintext: recovered,
      authenticated_round_trip: recovered === input.plaintext
        && ciphertext !== input.plaintext,
    };
    const recipients = followUpHardening.resolveTier3Recipients({
      memberPersonas: input.memberPersonas,
      devices: input.devices,
      selected: input.selected,
    });
    const routeEvaluation = evaluateCurrentTier3PrivateRoute(
      fixture.vector_id,
      input,
    );
    const route = routeEvaluation.decision;
    const rejection = recipients.verdict === "reject"
      ? recipients
      : route.verdict === "reject"
        ? route
        : crypto.authenticated_round_trip
          ? null
          : { verdict: "reject" as const };
    const raw = rejection === null
      ? { verdict: "accept" as const, crypto, recipients, route }
      : { ...rejection, crypto, recipients, route };
    return {
      raw_result: { ...raw, route_evidence: routeEvaluation.evidence },
      projected_output: raw,
    };
  }
  if (boundaryId === "claims.validateClaimRevocationEnvelope+authorizeWithClaim") {
    const [event, leaf, chain, suppliedContext] = fixture.boundary_args ?? [];
    const revocation = claims.validateClaimRevocationEnvelope(
      event as Parameters<typeof claims.validateClaimRevocationEnvelope>[0],
    );
    const context = suppliedContext as Parameters<typeof claims.authorizeWithClaim>[2];
    const authorization = claims.authorizeWithClaim(
      leaf as Parameters<typeof claims.authorizeWithClaim>[0],
      chain as Parameters<typeof claims.authorizeWithClaim>[1],
      { ...context, now: revocation.revoked_at, revocations: [revocation] },
    );
    const raw = { revocation, authorization };
    return {
      raw_result: raw,
      projected_output: {
        verdict: authorization.allowed ? "accept" : "reject",
        ...(authorization.reason_code === null
          ? {}
          : { reason_code: authorization.reason_code }),
        evaluator_output: authorization,
      },
    };
  }
  if (boundaryId === "claim-ledger.mergeClaimLedger+evaluateReaderAccess") {
    const [records, tombstones, checkpoint, context, readerNid, request] =
      fixture.boundary_args ?? [];
    const state = claimLedger.mergeClaimLedger(
      records as Parameters<typeof claimLedger.mergeClaimLedger>[0],
      tombstones as Parameters<typeof claimLedger.mergeClaimLedger>[1],
      checkpoint as Parameters<typeof claimLedger.mergeClaimLedger>[2],
      context as Parameters<typeof claimLedger.mergeClaimLedger>[3],
    );
    const authorization = claimLedger.evaluateReaderAccess(
      readerNid as Parameters<typeof claimLedger.evaluateReaderAccess>[0],
      state,
      request as Parameters<typeof claimLedger.evaluateReaderAccess>[2],
    );
    return {
      raw_result: { state, authorization },
      projected_output: {
        verdict: authorization.allowed ? "accept" : "reject",
        authorization,
      },
    };
  }
  if (boundaryId === "oidc.projectAccessToken+validateProjectedJwt") {
    const [projection, expectedIssuer, expectedAudience, jwks, validationContext] =
      fixture.boundary_args ?? [];
    const token = oidc.projectAccessToken(
      projection as Parameters<typeof oidc.projectAccessToken>[0],
    );
    const authorization = oidc.validateProjectedJwt(
      token.compact,
      expectedIssuer as string,
      expectedAudience as string,
      jwks as Parameters<typeof oidc.validateProjectedJwt>[3],
      validationContext as Parameters<typeof oidc.validateProjectedJwt>[4],
    );
    return {
      raw_result: { token, authorization },
      projected_output: {
        verdict: authorization.allowed ? "accept" : "reject",
        authorization,
      },
    };
  }
  if (
    boundaryId
    === "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission"
  ) {
    const [authority, capability, mode] = fixture.boundary_args ?? [];
    const first = trustedSeed.evaluateTrustedSeedAdmission(
      authority as Parameters<typeof trustedSeed.evaluateTrustedSeedAdmission>[0],
      capability as Parameters<typeof trustedSeed.evaluateTrustedSeedAdmission>[1],
    );
    if (mode === "replay") {
      const second = trustedSeed.evaluateTrustedSeedAdmission(
        authority as Parameters<typeof trustedSeed.evaluateTrustedSeedAdmission>[0],
        capability as Parameters<typeof trustedSeed.evaluateTrustedSeedAdmission>[1],
      );
      return {
        raw_result: { first, second },
        projected_output: second,
      };
    }
    return { raw_result: first, projected_output: first };
  }
  if (
    boundaryId
    === "agent-authorship.validateWorkloadRegistration+validateAgentAccessToken"
  ) {
    const [registrationInput, tokenInput] = fixture.boundary_args ?? [];
    const registration = agentAuthorship.validateWorkloadRegistration(registrationInput);
    const token = agentAuthorship.validateAgentAccessToken(
      tokenInput as Parameters<typeof agentAuthorship.validateAgentAccessToken>[0],
    );
    return {
      raw_result: { registration, token },
      projected_output: {
        verdict: token.verdict,
        identity: token.verdict === "accept" ? token.identity : null,
      },
    };
  }
  const args = fixture.boundary_args ?? (
    boundaryId === "claims.validateClaimId"
      ? [fixture.input.claim]
      : boundaryId === "claims.validateKeyRef"
        ? [fixture.input.key_reference]
        : boundaryId === "schema.validateOidcContinuityManifestSchemaOrThrow"
          ? [fixture.input.manifest]
          : [fixture.input]
  );
  try {
    const raw = await directBoundary(boundaryId)(...args);
    if (boundaryId === "authorization-freshness.evaluateAuthorizationFreshness") {
      const decision = raw as ReturnType<typeof authorizationFreshness.evaluateAuthorizationFreshness>;
      return {
        raw_result: decision,
        projected_output: decision.verdict === "accept"
          ? { verdict: "accept", current_authorization_view: "opaque" }
          : { verdict: "reject", reason_code: decision.reason },
      };
    }
    if (boundaryId === "authorization-freshness.revalidateAuthorizationViewAtEffect") {
      const decision = raw as ReturnType<
        typeof authorizationFreshness.revalidateAuthorizationViewAtEffect
      >;
      if ("reason" in decision) {
        const { reason, ...wireDecision } = decision;
        return {
          raw_result: decision,
          projected_output: { ...wireDecision, reason_code: reason },
        };
      }
      return { raw_result: decision, projected_output: decision };
    }
    if (boundaryId === "claims.authorizeWithClaim") {
      const decision = raw as ReturnType<typeof claims.authorizeWithClaim>;
      if (!decision.allowed) {
        return {
          raw_result: decision,
          projected_output: fixture.vector_id === "comms/claim-repository-unconfirmed"
            ? {
                verdict: "reject",
                reason_code: decision.reason_code,
                state: decision.state,
              }
            : {
                verdict: "reject",
                reason_code: decision.reason_code,
                evaluator_output: decision,
              },
        };
      }
      return {
        raw_result: decision,
        projected_output: { verdict: "accept", authorization: decision },
      };
    }
    if (boundaryId === "claim-ledger.evaluateReaderAccess") {
      const decision = raw as ReturnType<typeof claimLedger.evaluateReaderAccess>;
      return {
        raw_result: decision,
        projected_output: {
          verdict: decision.allowed ? "accept" : "reject",
          reason_code: decision.reason_code,
          state: decision.state,
        },
      };
    }
    if (boundaryId === "public-reader.resolvePublicAsset") {
      return {
        raw_result: raw,
        projected_output: { verdict: "accept", resolution: raw },
      };
    }
    if (boundaryId === "social-events.selectCurrentSocialEvent") {
      const selected = raw as ReturnType<typeof socialEvents.selectCurrentSocialEvent>;
      return {
        raw_result: selected,
        projected_output: {
          verdict: "accept",
          selected_event_id: selected?.id ?? null,
        },
      };
    }
    if (
      boundaryId === "oidc.validateAuthorizationRequest"
      || boundaryId === "oidc.validateIssuerMetadata"
      || boundaryId === "oidc.validateProjectedJwt"
      || boundaryId === "claim-ledger.canMint"
    ) {
      const decision = raw as {
        allowed: boolean;
        reason_code?: string;
        released_claims?: unknown;
        source_claim_ids?: unknown;
      };
      if (!decision.allowed) {
        return {
          raw_result: decision,
          projected_output: {
            verdict: "reject",
            reason_code: decision.reason_code,
            evaluator_output: decision,
          },
        };
      }
      if (fixture.vector_id === "comms/oidc-claim-release") {
        return {
          raw_result: decision,
          projected_output: {
            verdict: "accept",
            released_claims: decision.released_claims,
            source_claim_ids: decision.source_claim_ids,
          },
        };
      }
      return {
        raw_result: decision,
        projected_output: { verdict: "accept", authorization: decision },
      };
    }
    if (boundaryId === "marmot-admission.ordinaryConversationAdmission") {
      const decision = raw as { outcome: string; reason_code?: string };
      return decision.outcome === "reject"
        ? {
            raw_result: decision,
            projected_output: {
              verdict: "reject",
              reason_code: decision.reason_code,
              evaluator_output: decision,
            },
          }
        : {
            raw_result: decision,
            projected_output: { verdict: "accept", admission: decision },
          };
    }
    return { raw_result: raw, projected_output: raw };
  } catch (error) {
    return { raw_result: error, projected_output: thrownProjection(error) };
  }
}

type SemanticVerdict = "accept" | "reject" | "indeterminate";

function recordSemanticVerdict(value: unknown): SemanticVerdict | undefined {
  if (value instanceof Error) return "reject";
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Readonly<Record<string, unknown>>;
  if (
    record.verdict === "accept"
    || record.verdict === "reject"
    || record.verdict === "indeterminate"
  ) return record.verdict;
  if (typeof record.allowed === "boolean") return record.allowed ? "accept" : "reject";
  if (typeof record.ok === "boolean") return record.ok ? "accept" : "reject";
  if (record.status === "accepted") return "accept";
  if (record.status === "rejected" || record.status === "quarantined") return "reject";
  if (record.outcome === "reject") return "reject";
  if (typeof record.outcome === "string") return "accept";
  if (Object.hasOwn(record, "reason")) return record.reason === null ? "accept" : "reject";
  for (const key of ["authorization", "token", "second"] as const) {
    const nested = recordSemanticVerdict(record[key]);
    if (nested !== undefined) return nested;
  }
  return undefined;
}

function recordSemanticReason(value: unknown): string | undefined {
  if (value instanceof Error) {
    return value.message.match(/^([a-z][a-z0-9_-]*)(?::|$)/u)?.[1];
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Readonly<Record<string, unknown>>;
  for (const key of ["reason_code", "reason", "failure"] as const) {
    if (typeof record[key] === "string") return record[key];
  }
  for (const key of ["authorization", "token", "second"] as const) {
    const nested = recordSemanticReason(record[key]);
    if (nested !== undefined) return nested;
  }
  return undefined;
}

function rawSemanticVerdict(
  boundaryId: string,
  fixture: CurrentCaseFixture,
  raw: unknown,
): SemanticVerdict {
  if (boundaryId === "replaceable-selection.selectCurrentReplaceableEvent") {
    if (fixture.vector_id !== "core/replaceable-future-quarantined") return "accept";
    const result = raw as ReturnType<
      typeof replaceableSelection.selectCurrentReplaceableEvent
    >;
    return result.selected === null && result.quarantined.length > 0 ? "reject" : "accept";
  }
  if (boundaryId === "backup-crypto.nip49EncryptDeterministic+nostr-tools.nip49.decrypt") {
    const result = raw as { recovered_secret?: unknown };
    return result.recovered_secret === fixture.input.secret_key ? "accept" : "reject";
  }
  if (
    boundaryId === "privacy-crypto.deriveConfigPostKey+nostr-tools.nip44"
    || boundaryId === "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44"
  ) {
    const result = raw as { recovered?: unknown };
    const ciphertext = (raw as { ciphertext?: unknown }).ciphertext;
    return result.recovered === fixture.input.plaintext
      && typeof ciphertext === "string"
      && ciphertext !== fixture.input.plaintext
      ? "accept"
      : "reject";
  }
  if (
    boundaryId
    === "agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile"
  ) {
    const result = raw as Readonly<{
      injection?: { verdict?: unknown };
      profile_matches?: unknown;
    }>;
    return result.injection?.verdict === "accept" && result.profile_matches === true
      ? "accept"
      : "reject";
  }
  if (
    boundaryId
    === "agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy"
  ) {
    const result = raw as Readonly<{
      injection?: { verdict?: unknown };
      profile_matches?: unknown;
      policy?: { visible?: unknown; muted?: unknown };
    }>;
    return result.injection?.verdict === "accept"
      && result.profile_matches === true
      && result.policy?.visible === false
      && result.policy.muted === true
      ? "accept"
      : "reject";
  }
  if (boundaryId === "public-reader.resolvePublicAsset") {
    return typeof raw === "string" ? "accept" : "reject";
  }
  if (boundaryId === "social-events.selectCurrentSocialEvent") {
    return raw === null || raw === undefined ? "reject" : "accept";
  }
  const verdict = recordSemanticVerdict(raw);
  if (verdict === undefined) {
    throw new Error(`current boundary raw result has no semantic verdict: ${fixture.vector_id}`);
  }
  return verdict;
}

function rawSemanticReason(
  boundaryId: string,
  fixture: CurrentCaseFixture,
  raw: unknown,
): string | undefined {
  if (
    boundaryId === "replaceable-selection.selectCurrentReplaceableEvent"
    && fixture.vector_id === "core/replaceable-future-quarantined"
  ) {
    const result = raw as ReturnType<
      typeof replaceableSelection.selectCurrentReplaceableEvent
    >;
    return result.quarantined[0]?.reason_code;
  }
  return recordSemanticReason(raw);
}

export function assertProjectionPreservesVerdict(
  rawVerdict: SemanticVerdict,
  projected: unknown,
  rawReason?: string,
): void {
  if (
    projected === null
    || typeof projected !== "object"
    || Array.isArray(projected)
    || (projected as Readonly<Record<string, unknown>>).verdict !== rawVerdict
  ) {
    throw new Error(`current projector changed semantic verdict: ${rawVerdict}`);
  }
  if (
    rawReason !== undefined
    && (projected as Readonly<Record<string, unknown>>).reason_code !== rawReason
  ) {
    throw new Error(`current projector changed semantic reason: ${rawReason}`);
  }
}

export async function invokeCurrentBoundary(
  boundaryId: string,
  fixture: CurrentCaseFixture,
): Promise<Readonly<{ raw_result: unknown; projected_output: unknown }>> {
  const profileOracle = currentProfileOracleForVector(fixture.vector_id);
  let registryComparison: ReturnType<
    typeof profileNegotiation.validateCurrentKindProfileNegotiation
  > | undefined;
  if (profileOracle !== undefined) {
    if (boundaryId !== profileOracle.semantic_boundary) {
      throw new Error(`current profile boundary/oracle mismatch: ${fixture.vector_id}`);
    }
    registryComparison = profileNegotiation.validateCurrentKindProfileNegotiation(
      registry.loadRegistry(REPOSITORY_ROOT),
      fixture.input,
    );
    if (registryComparison.verdict !== "accept") {
      throw new Error(
        `current profile registry prerequisite failed: ${fixture.vector_id} -> ${registryComparison.reason}`,
      );
    }
  }
  const execution = await executeCurrentBoundary(boundaryId, fixture);
  const rawVerdict = rawSemanticVerdict(boundaryId, fixture, execution.raw_result);
  assertProjectionPreservesVerdict(
    rawVerdict,
    execution.projected_output,
    rawVerdict === "accept"
      ? undefined
      : rawSemanticReason(boundaryId, fixture, execution.raw_result),
  );
  return registryComparison === undefined
    ? execution
    : {
        raw_result: Object.freeze({
          registry_comparison: registryComparison,
          semantic_boundary: profileOracle!.semantic_boundary,
          semantic_result: execution.raw_result,
        }),
        projected_output: execution.projected_output,
      };
}
