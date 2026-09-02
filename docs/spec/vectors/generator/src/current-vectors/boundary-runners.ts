import * as agentAuthorship from "../agent-authorship.js";
import * as agentModeration from "../agent-moderation.js";
import * as assurance from "../assurance.js";
import * as assuranceDowngrade from "../assurance-downgrade.js";
import * as assuranceObservation from "../assurance-observation.js";
import * as assurancePolicy from "../assurance-policy.js";
import * as authorizationFreshness from "../authorization-freshness.js";
import * as backupCrypto from "../backup-crypto.js";
import * as claimAuthorization from "../claim-authorization.js";
import * as claimLedger from "../claim-ledger.js";
import * as claims from "../claims.js";
import * as commsPolicy from "../comms-policy.js";
import * as controlPolicy from "../control-policy.js";
import * as controlSigning from "../control-signing.js";
import * as corePolicy from "../core-policy.js";
import * as coreWriterBinding from "../core-writer-binding.js";
import * as coreOperationalAssuranceAuthority from "../core-operational-assurance-authority.js";
import * as canonicalProfileSelectionAuthority from "../canonical-profile-selection-authority.js";
import * as controlDeviceAuthorization from "../control-device-authorization.js";
import * as controlEnrollmentAdmission from "../control-enrollment-admission.js";
import * as controlInvitePreauthorization from "../control-invite-preauthorization.js";
import * as marmotAdmissionAuthority from "../marmot-admission-authority.js";
import * as personaInboxAdmissionAuthority from "../persona-inbox-admission-authority.js";
import * as marmotArchiveRetentionAuthority from "../marmot-archive-retention-authority.js";
import * as oneTimeInviteAuthority from "../one-time-invite-authority.js";
import * as agentPublicationAuthorization from "../agent-publication-authorization.js";
import * as controlTokenVerifier from "../control-token-verifier.js";
import * as socialSubscriptionAuthority from "../social-subscription-authority.js";
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
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8Bytes } from "../hex.js";
import type { CurrentCaseFixture } from "./types.js";
import { currentProfileOracleForVector } from "./profile-oracles.js";
import { buildAssuranceCases } from "./assurance.js";
import { buildCommsCases } from "./comms.js";
import { buildControlCases } from "./control.js";
import { buildCoreCases } from "./core.js";
import { buildSocialCases } from "./social.js";
import { buildWorkspaceCases } from "./workspace.js";
import { buildProfileCases } from "./profiles.js";
import { evaluateCurrentTier3PrivateRoute } from "./private-route-authority.js";
import { evaluateCurrentRevocationProfile } from "./revocation-profile-boundary.js";
import type { CurrentRevocationExecutionFixture } from "./revocation-profile-fixtures.js";
import {
  declaredPrivateCurrentFixtureIds,
  isDeclaredPrivateCurrentFixtureId,
  registerPrivateCurrentFixtureSpecificationId,
  type PrivateCurrentFixtureSpecification,
} from "./private-fixture-specification.js";
import { resolve } from "node:path";

const REPOSITORY_ROOT = resolve(import.meta.dirname, "../../../../../..");

type BoundaryModule = Readonly<Record<string, unknown>>;
type BoundaryFunction = (...args: readonly unknown[]) => unknown;
type EvaluatorFunction = (...args: never[]) => unknown;
type EvaluatorPlanStep = Readonly<{
  step_id: string;
  evaluator: EvaluatorFunction;
}>;
type EvaluatorInvocation = Readonly<{
  step_id: string;
  evaluator: EvaluatorFunction;
  args: readonly unknown[];
  args_digest: string;
  result: unknown;
  result_digest: string;
  threw: boolean;
}>;
type CurrentPrivateFixtureRecord = Readonly<{
  args: readonly unknown[];
  fixture_digest: string;
}>;
const PRIVATE_CURRENT_FIXTURES = new WeakMap<object, CurrentPrivateFixtureRecord>();
const PRIVATE_CURRENT_FIXTURE_IDS = new Set<string>();

declare const CURRENT_BOUNDARY_EXECUTION: unique symbol;
export type CurrentBoundaryExecution = Readonly<{
  readonly [CURRENT_BOUNDARY_EXECUTION]: true;
  raw_result: unknown;
  projected_output: unknown;
}>;

export type CurrentBoundaryExecutionRecord = Readonly<{
  boundary_id: string;
  fixture_digest: string;
  result_digest: string;
  raw_result: unknown;
  projected_output: unknown;
  evaluator_invocations: readonly Readonly<{
    step_id: string;
    evaluator: EvaluatorFunction;
    args: readonly unknown[];
    args_digest: string;
    result: unknown;
    result_digest: string;
    threw: boolean;
  }>[];
}>;

type PrivateCurrentBoundaryExecutionRecord = CurrentBoundaryExecutionRecord & Readonly<{
  fixture: CurrentCaseFixture;
  evaluator_runner: EvaluatorFunction;
  evaluator_plan: readonly EvaluatorPlanStep[];
  evaluator_invocations: readonly EvaluatorInvocation[];
}>;

const EXECUTION_RECORDS = new WeakMap<object, PrivateCurrentBoundaryExecutionRecord>();

type DescriptorState = { seen: WeakSet<object>; nodes: number };

function boundedDescriptor(
  value: unknown,
  state: DescriptorState = { seen: new WeakSet<object>(), nodes: 0 },
  depth = 0,
): unknown {
  if (depth > 64) throw new Error("semantic execution descriptor depth exceeded");
  state.nodes += 1;
  if (state.nodes > 16_384) throw new Error("semantic execution descriptor size exceeded");
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("semantic execution descriptor is non-finite");
    return value;
  }
  if (typeof value === "undefined") return { type: "undefined" };
  if (typeof value === "bigint") return { type: "bigint", value: value.toString(10) };
  if (typeof value === "symbol") return { type: "symbol", value: value.description ?? "" };
  if (typeof value === "function") return { type: "function", name: value.name };
  const object = value as object;
  if (state.seen.has(object)) throw new Error("semantic execution descriptor cycle");
  state.seen.add(object);
  try {
    if (value instanceof Error) {
      return { type: "error", name: value.name, message: value.message };
    }
    if (ArrayBuffer.isView(value)) {
      return {
        type: value.constructor.name,
        value: bytesToHex(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)),
      };
    }
    if (Array.isArray(value)) {
      if (value.length > 4_096) throw new Error("semantic execution descriptor collection exceeded");
      return value.map((entry) => boundedDescriptor(entry, state, depth + 1));
    }
    if (value instanceof Map) {
      if (value.size > 4_096) throw new Error("semantic execution descriptor collection exceeded");
      return {
        type: "map",
        entries: [...value.entries()].map(([key, entry]) => [
          boundedDescriptor(key, state, depth + 1),
          boundedDescriptor(entry, state, depth + 1),
        ]),
      };
    }
    if (value instanceof Set) {
      if (value.size > 4_096) throw new Error("semantic execution descriptor collection exceeded");
      return {
        type: "set",
        entries: [...value].map((entry) => boundedDescriptor(entry, state, depth + 1)),
      };
    }
    const descriptors = Object.getOwnPropertyDescriptors(object);
    const keys = Reflect.ownKeys(descriptors).sort((left, right) =>
      String(left).localeCompare(String(right), "en")
    );
    if (keys.length > 4_096) throw new Error("semantic execution descriptor collection exceeded");
    const entries: Array<[string, unknown]> = [];
    for (const key of keys) {
      const descriptor = Reflect.getOwnPropertyDescriptor(object, key)!;
      if (!("value" in descriptor)) {
        throw new Error("semantic execution descriptor accessor rejected");
      }
      entries.push([String(key), boundedDescriptor(descriptor.value, state, depth + 1)]);
    }
    return { type: object.constructor?.name ?? "object", entries };
  } finally {
    state.seen.delete(object);
  }
}

export function currentFixtureDigest(value: unknown): string {
  return bytesToHex(sha256(utf8Bytes(JSON.stringify(boundedDescriptor(value)))));
}

/** Internal family-builder bridge. It registers authority but never returns it. */
export function registerPrivateCurrentFixture(
  specification: PrivateCurrentFixtureSpecification,
  fixture: CurrentCaseFixture,
  args: readonly unknown[],
): void {
  if (fixture.boundary_args !== undefined || PRIVATE_CURRENT_FIXTURES.has(fixture)) {
    throw new Error(`current private boundary fixture registration conflict: ${fixture.vector_id}`);
  }
  registerPrivateCurrentFixtureSpecificationId(specification, fixture.vector_id);
  PRIVATE_CURRENT_FIXTURES.set(fixture, Object.freeze({
    args: Object.freeze([...args]),
    fixture_digest: currentFixtureDigest(fixture),
  }));
  PRIVATE_CURRENT_FIXTURE_IDS.add(fixture.vector_id);
}

/** Non-authoritative diagnostics: IDs reveal no fixture identity or evaluator argument. */
export function registeredPrivateCurrentFixtureIds(): readonly string[] {
  return Object.freeze([...PRIVATE_CURRENT_FIXTURE_IDS].sort((left, right) =>
    left.localeCompare(right, "en")
  ));
}

const executionDigest = currentFixtureDigest;

class InvocationContext {
  readonly #plan: readonly EvaluatorPlanStep[];
  readonly #invocations: EvaluatorInvocation[] = [];
  #cursor = 0;

  constructor(plan: readonly EvaluatorPlanStep[]) {
    this.#plan = plan;
  }

  async call(stepId: string, args: readonly unknown[]): Promise<unknown> {
    const planned = this.#plan[this.#cursor];
    if (planned === undefined) {
      throw new Error(`current evaluator invocation exceeded plan at ${stepId}`);
    }
    if (planned.step_id !== stepId) {
      throw new Error(
        `current evaluator invocation order mismatch: expected ${planned.step_id}, received ${stepId}`,
      );
    }
    this.#cursor += 1;
    try {
      const result = await (planned.evaluator as BoundaryFunction)(...args);
      this.#invocations.push(Object.freeze({
        step_id: stepId,
        evaluator: planned.evaluator,
        args: Object.freeze([...args]),
        args_digest: executionDigest(args),
        result,
        result_digest: executionDigest(result),
        threw: false,
      }));
      return result;
    } catch (error) {
      this.#invocations.push(Object.freeze({
        step_id: stepId,
        evaluator: planned.evaluator,
        args: Object.freeze([...args]),
        args_digest: executionDigest(args),
        result: error,
        result_digest: executionDigest(error),
        threw: true,
      }));
      throw error;
    }
  }

  finish(): readonly EvaluatorInvocation[] {
    if (this.#cursor !== this.#plan.length || this.#invocations.length !== this.#plan.length) {
      throw new Error(
        `current evaluator invocation plan incomplete: ${this.#cursor}/${this.#plan.length}`,
      );
    }
    return Object.freeze([...this.#invocations]);
  }
}

function mintBoundaryExecution(
  boundaryId: string,
  fixture: CurrentCaseFixture,
  result: Readonly<{ raw_result: unknown; projected_output: unknown }>,
  evaluatorPlan: readonly EvaluatorPlanStep[],
  evaluatorInvocations: readonly EvaluatorInvocation[],
  evaluatorRunner: EvaluatorFunction,
): CurrentBoundaryExecution {
  const execution = Object.freeze({
    raw_result: result.raw_result,
    projected_output: result.projected_output,
  }) as CurrentBoundaryExecution;
  EXECUTION_RECORDS.set(execution, Object.freeze({
    boundary_id: boundaryId,
    fixture,
    raw_result: result.raw_result,
    projected_output: result.projected_output,
    fixture_digest: executionDigest(fixture),
    result_digest: executionDigest(result),
    evaluator_runner: evaluatorRunner,
    evaluator_plan: evaluatorPlan,
    evaluator_invocations: evaluatorInvocations,
  }));
  return execution;
}

export function inspectCurrentBoundaryExecution(
  execution: CurrentBoundaryExecution,
  boundaryId: string,
  fixture: CurrentCaseFixture,
): CurrentBoundaryExecutionRecord {
  const record = execution !== null && typeof execution === "object"
    ? EXECUTION_RECORDS.get(execution)
    : undefined;
  if (
    record === undefined
    || record.boundary_id !== boundaryId
    || record.fixture !== fixture
    || execution.raw_result !== record.raw_result
    || execution.projected_output !== record.projected_output
  ) throw new Error("semantic certificate requires the exact boundary execution");
  if (executionDigest(fixture) !== record.fixture_digest) {
    throw new Error("semantic certificate fixture changed after execution");
  }
  if (executionDigest({
    raw_result: execution.raw_result,
    projected_output: execution.projected_output,
  }) !== record.result_digest) {
    throw new Error("semantic certificate result changed after execution");
  }
  return record;
}

export function assertCurrentBoundaryEvaluatorIdentity(
  execution: CurrentBoundaryExecution,
  boundaryId: string,
  fixture: CurrentCaseFixture,
): void {
  const record = execution !== null && typeof execution === "object"
    ? EXECUTION_RECORDS.get(execution)
    : undefined;
  const actualPlan = actualEvaluatorPlan(boundaryId, fixture);
  if (
    record === undefined
    || record.evaluator_runner !== invokeCurrentBoundary
    || record.evaluator_plan.length !== actualPlan.length
    || record.evaluator_plan.some((step, index) =>
      step.step_id !== actualPlan[index]?.step_id
      || step.evaluator !== actualPlan[index]?.evaluator
    )
    || record.evaluator_invocations.length !== actualPlan.length
    || record.evaluator_invocations.some((invocation, index) =>
      invocation.step_id !== actualPlan[index]?.step_id
      || invocation.evaluator !== actualPlan[index]?.evaluator
      || invocation.args_digest !== executionDigest(invocation.args)
      || invocation.result_digest !== executionDigest(invocation.result)
    )
  ) throw new Error("semantic certificate requires the exact evaluator implementation");
}

function resolvePrivateCurrentBoundaryArgs(
  fixture: CurrentCaseFixture,
): readonly unknown[] | undefined {
  const record = PRIVATE_CURRENT_FIXTURES.get(fixture);
  if (record !== undefined && fixture.boundary_args !== undefined) {
    throw new Error(`current private boundary fixture registration conflict: ${fixture.vector_id}`);
  }
  if (record === undefined) {
    if (isDeclaredPrivateCurrentFixtureId(fixture.vector_id)) {
      throw new Error(`current private boundary fixture is unavailable: ${fixture.vector_id}`);
    }
    return fixture.boundary_args;
  }
  if (executionDigest(fixture) !== record.fixture_digest) {
    throw new Error(`current private boundary fixture changed after registration: ${fixture.vector_id}`);
  }
  return record.args;
}

/** Builds the only fixtures carrying catalog-private evaluator artifacts. */
export async function buildRegisteredCurrentCaseFixtures(): Promise<CurrentCaseFixture[]> {
  const fixtures = [
    ...await buildCoreCases(),
    ...await buildAssuranceCases(),
    ...await buildCommsCases(),
    ...await buildControlCases(),
    ...await buildSocialCases(),
    ...buildWorkspaceCases(),
    ...await buildProfileCases(),
  ];
  const declaredIds = declaredPrivateCurrentFixtureIds();
  const registeredIds = registeredPrivateCurrentFixtureIds();
  if (declaredIds.length !== registeredIds.length
    || declaredIds.some((caseId, index) => caseId !== registeredIds[index])) {
    throw new Error("private current fixture declarations do not match registrations");
  }
  return fixtures;
}

const BOUNDARY_MODULES: Readonly<Record<string, BoundaryModule>> = Object.freeze({
  "agent-authorship": agentAuthorship,
  "agent-moderation": agentModeration,
  assurance,
  "assurance-downgrade": assuranceDowngrade,
  "assurance-observation": assuranceObservation,
  "assurance-policy": assurancePolicy,
  "authorization-freshness": authorizationFreshness,
  "backup-crypto": backupCrypto,
  "claim-authorization": claimAuthorization,
  "claim-ledger": claimLedger,
  claims,
  "comms-policy": commsPolicy,
  "control-policy": controlPolicy,
  "control-signing": controlSigning,
  "core-policy": corePolicy,
  "core-writer-binding": coreWriterBinding,
  "core-operational-assurance-authority": coreOperationalAssuranceAuthority,
  "canonical-profile-selection-authority": canonicalProfileSelectionAuthority,
  "control-device-authorization": controlDeviceAuthorization,
  "control-enrollment-admission": controlEnrollmentAdmission,
  "control-invite-preauthorization": controlInvitePreauthorization,
  "marmot-admission-authority": marmotAdmissionAuthority,
  "persona-inbox-admission-authority": personaInboxAdmissionAuthority,
  "marmot-archive-retention-authority": marmotArchiveRetentionAuthority,
  "one-time-invite-authority": oneTimeInviteAuthority,
  "agent-publication-authorization": agentPublicationAuthorization,
  "control-token-verifier": controlTokenVerifier,
  "social-subscription-authority": socialSubscriptionAuthority,
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

function repeatedStep(step: EvaluatorFunction, count: number): readonly EvaluatorFunction[] {
  return Array.from({ length: count }, () => step);
}

function actualEvaluatorFunctions(
  boundaryId: string,
  fixture: CurrentCaseFixture,
): readonly EvaluatorFunction[] {
  switch (boundaryId) {
    case "profile-negotiation.validateCurrentKindProfileNegotiation":
      return [registry.loadRegistry, profileNegotiation.validateCurrentKindProfileNegotiation];
    case "current-private-route.evaluateCurrentTier3PrivateRoute":
      return [evaluateCurrentTier3PrivateRoute];
    case "current-revocation.evaluateCurrentRevocationProfile":
      return [evaluateCurrentRevocationProfile];
    case "agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile":
      return [
        agentAuthorship.injectAgentAttribution,
        agentAuthorship.matchesAgentAttributionProfile,
      ];
    case "social-subscription-authority.resolveSubscribedAgentPolicy+applySubscribedAgentPolicy":
      return [
        socialSubscriptionAuthority.resolveSubscribedAgentPolicy,
        socialSubscriptionAuthority.applySubscribedAgentPolicy,
      ];
    case "replaceable-selection.selectCurrentReplaceableEvent":
      return [
        replaceableSelection.createReplaceableSelectionAuthority,
        replaceableSelection.selectCurrentReplaceableEvent,
      ];
    case "radicle.validateNodeAdvertisement":
      return [radicle.validateNodeAdvertisement];
    case "assurance-observation.evaluateEnrollmentEligibility":
      return [
        assuranceObservation.createAssuranceEnrollmentObservationAuthority,
        ...repeatedStep(
          assuranceObservation.evaluateEnrollmentEligibility,
          Array.isArray(fixture.input.steps) ? fixture.input.steps.length : 0,
        ),
      ];
    case "assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade":
      return [
        assuranceObservation.createAssuranceEnrollmentObservationAuthority,
        ...repeatedStep(
          assuranceObservation.evaluateEnrollmentEligibility,
          Array.isArray(fixture.input.steps) ? fixture.input.steps.length : 0,
        ),
        assuranceDowngrade.evaluateAssuranceDowngrade,
        ...(fixture.vector_id === "assurance/dual-consent-downgrade-accepted"
          ? [assuranceDowngrade.commitAssuranceDowngrade]
          : []),
      ];
    case "assurance.evaluateAssuranceAuthorityAt":
      return [assurance.evaluateAssuranceAuthorityAt];
    case "backup-crypto.nip49EncryptDeterministic+nostr-tools.nip49.decrypt":
      return [backupCrypto.nip49EncryptDeterministic, nip49.decrypt];
    case "privacy-crypto.deriveConfigPostKey+nostr-tools.nip44":
      return [privacyCrypto.deriveConfigPostKey, nip44.v2.encrypt, nip44.v2.decrypt];
    case "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44":
      return [privacyCrypto.deriveTier3IndexKey, nip44.v2.encrypt, nip44.v2.decrypt];
    case "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute":
      return [
        privacyCrypto.deriveTier3IndexKey,
        nip44.v2.encrypt,
        nip44.v2.decrypt,
        followUpHardening.resolveTier3Recipients,
        evaluateCurrentTier3PrivateRoute,
      ];
    case "claim-authorization.authorizeClaimEffect+authorizeClaimEffect":
      return [
        claimAuthorization.authorizeClaimEffect,
        claimAuthorization.authorizeClaimEffect,
      ];
    case "core-writer-binding.resolveCurrentRepositoryWriterBinding+revalidateCurrentRepositoryWriterBinding":
      return fixture.vector_id === "core/repository-writer-owner-proof-invalid"
        ? [coreWriterBinding.resolveCurrentRepositoryWriterBinding]
        : [
            coreWriterBinding.resolveCurrentRepositoryWriterBinding,
            coreWriterBinding.revalidateCurrentRepositoryWriterBinding,
          ];
    case "claims.verifyClaimRevocationEnvelope+claim-authorization.inspectClaimState":
      return [claims.verifyClaimRevocationEnvelope, claimAuthorization.inspectClaimState];
    case "claim-ledger.mergeClaimLedger+evaluateReaderAccess":
      return [claimLedger.mergeClaimLedger, claimAuthorization.authorizeReaderAccessEffect];
    case "oidc.projectAccessToken+validateProjectedJwt":
      return [oidc.projectAccessToken, oidc.validateProjectedJwt];
    case "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission":
      return fixture.boundary_args?.[2] === "replay"
        ? [trustedSeed.evaluateTrustedSeedAdmission, trustedSeed.evaluateTrustedSeedAdmission]
        : [trustedSeed.evaluateTrustedSeedAdmission];
    case "agent-authorship.validateWorkloadRegistration+validateAgentAccessToken":
      return [
        agentAuthorship.validateWorkloadRegistration,
        agentAuthorship.validateAgentAccessToken,
      ];
    case "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization":
      return [
        workspace.authenticateWorkspaceRepositoryView,
        workspace.resolveWorkspaceEffectiveAuthorization,
      ];
    case "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+evaluateGrantActivation":
      return [
        workspace.authenticateWorkspaceRepositoryView,
        workspace.resolveWorkspaceEffectiveAuthorization,
        workspace.evaluateGrantActivation,
      ];
    case "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+consumeWorkspaceInvitationAcceptance+evaluateGrantActivation":
      return [
        workspace.authenticateWorkspaceRepositoryView,
        workspace.resolveWorkspaceEffectiveAuthorization,
        workspace.consumeWorkspaceInvitationAcceptance,
        workspace.evaluateGrantActivation,
      ];
    case "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+consumeWorkspaceInvitationAcceptance+evaluateGrantActivation+consumeWorkspaceInvitationAcceptance":
      return [
        workspace.authenticateWorkspaceRepositoryView,
        workspace.resolveWorkspaceEffectiveAuthorization,
        workspace.consumeWorkspaceInvitationAcceptance,
        workspace.evaluateGrantActivation,
        workspace.consumeWorkspaceInvitationAcceptance,
      ];
    case "control-device-authorization.createControlDeviceTransaction+pollControlDeviceAuthorization":
      return [
        controlDeviceAuthorization.createControlDeviceTransaction,
        controlDeviceAuthorization.pollControlDeviceAuthorization,
      ];
    case "marmot-admission-authority.verifyMarmotWelcome+admitOrdinaryMarmotWelcome":
      return [marmotAdmissionAuthority.verifyMarmotWelcome, marmotAdmissionAuthority.admitOrdinaryMarmotWelcome];
    case "marmot-archive-retention-authority.appendExactMarmotArchive+expireMarmotPresentation+acknowledgeMarmotArchive":
      return [marmotArchiveRetentionAuthority.appendExactMarmotArchive, marmotArchiveRetentionAuthority.expireMarmotPresentation, marmotArchiveRetentionAuthority.acknowledgeMarmotArchive];
    case "control-token-verifier.verifyControlToken+consumeVerifiedControlToken":
      return [controlTokenVerifier.verifyControlToken, controlTokenVerifier.consumeVerifiedControlToken];
    case "agent-publication-authorization.authorizeAndSignAgentPublication":
      return repeatedStep(
        agentPublicationAuthorization.authorizeAndSignAgentPublication,
        fixture.vector_id === "comms/agent-workload-token-accepted" ? 2 : 1,
      );
    case "control-signing.executePersistedAutomatedSigning+executePersistedAutomatedSigning":
      return [
        controlSigning.executePersistedAutomatedSigning,
        controlSigning.executePersistedAutomatedSigning,
      ];
    default:
      return [directBoundary(boundaryId)];
  }
}

function semanticStepId(index: number): string {
  return `semantic:${index}`;
}

function actualEvaluatorPlan(
  boundaryId: string,
  fixture: CurrentCaseFixture,
  semanticSteps: readonly EvaluatorFunction[] = actualEvaluatorFunctions(boundaryId, fixture),
): readonly EvaluatorPlanStep[] {
  const profileSteps: readonly EvaluatorPlanStep[] =
    currentProfileOracleForVector(fixture.vector_id) === undefined
      ? []
      : [
          { step_id: "profile:registry", evaluator: registry.loadRegistry },
          {
            step_id: "profile:negotiation",
            evaluator: profileNegotiation.validateCurrentKindProfileNegotiation,
          },
        ];
  return Object.freeze([
    ...profileSteps,
    ...semanticSteps.map((evaluator, index) => Object.freeze({
      step_id: semanticStepId(index),
      evaluator,
    })),
  ]);
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
  context: InvocationContext,
): Promise<Readonly<{ raw_result: unknown; projected_output: unknown }>> {
  const privateArgs = resolvePrivateCurrentBoundaryArgs(fixture);
  if (privateArgs !== fixture.boundary_args) {
    if (privateArgs === undefined) {
      throw new Error("current private boundary fixture is unavailable");
    }
    fixture = { ...fixture, boundary_args: privateArgs };
  }
  const callStep = async <T>(index: number, args: readonly unknown[]): Promise<T> =>
    await context.call(semanticStepId(index), args) as T;
  if (boundaryId === "profile-negotiation.validateCurrentKindProfileNegotiation") {
    const currentRegistry = await callStep<ReturnType<typeof registry.loadRegistry>>(
      0,
      [REPOSITORY_ROOT],
    );
    const raw = await callStep<ReturnType<
      typeof profileNegotiation.validateCurrentKindProfileNegotiation
    >>(1, [currentRegistry, fixture.input]);
    return { raw_result: raw, projected_output: raw };
  }
  if (boundaryId === "current-private-route.evaluateCurrentTier3PrivateRoute") {
    const route = await callStep<ReturnType<typeof evaluateCurrentTier3PrivateRoute>>(
      0,
      [fixture.vector_id, fixture.input],
    );
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
    return await callStep<Awaited<ReturnType<typeof evaluateCurrentRevocationProfile>>>(
      0,
      [fixture.vector_id, fixture.input, execution as CurrentRevocationExecutionFixture],
    );
  }
  if (
    boundaryId
    === "agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile"
  ) {
    const injection = await callStep<ReturnType<typeof agentAuthorship.injectAgentAttribution>>(
      0,
      [fixture.input as Parameters<typeof agentAuthorship.injectAgentAttribution>[0]],
    );
    const profileMatches = injection.verdict === "accept"
      && await callStep<boolean>(1, [injection.tags]);
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
  if (boundaryId === "social-subscription-authority.resolveSubscribedAgentPolicy+applySubscribedAgentPolicy") {
    const [authority, input, target] = fixture.boundary_args ?? [];
    const view = await callStep<Awaited<ReturnType<
      typeof socialSubscriptionAuthority.resolveSubscribedAgentPolicy
    >>>(0, [authority, input]);
    const terminal = await callStep<ReturnType<
      typeof socialSubscriptionAuthority.applySubscribedAgentPolicy
    >>(1, [view, target]);
    return {
      raw_result: { view, terminal, exact_view_transfer: view },
      projected_output: terminal.muted && terminal.visible === false
        ? { verdict: "accept", local_policy_applied: true }
        : { verdict: "reject", reason_code: "agent-policy-binding-invalid" },
    };
  }
  if (boundaryId === "replaceable-selection.selectCurrentReplaceableEvent") {
    const input = fixture.input as {
      trusted_now: number;
      candidates: Parameters<typeof replaceableSelection.selectCurrentReplaceableEvent>[1];
    };
    const authority = await callStep<ReturnType<
      typeof replaceableSelection.createReplaceableSelectionAuthority
    >>(0, [{ trusted_now: () => input.trusted_now }]);
    const raw = await callStep<ReturnType<
      typeof replaceableSelection.selectCurrentReplaceableEvent
    >>(1, [authority, input.candidates]);
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
    const raw = await callStep<ReturnType<typeof radicle.validateNodeAdvertisement>>(0, [
      input.event,
      {
        now: input.trusted_now,
        graph_fetch: { status: "available", reachable_oids: input.reachable_oids },
      },
    ]);
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
    const authority = await callStep<ReturnType<
      typeof assuranceObservation.createAssuranceEnrollmentObservationAuthority
    >>(0, [{
      authority_id: input.authority_id,
      journal_integrity_key: input.journal_integrity_key,
      trusted_now: () => trustedNow,
      witness_policy: {
        policy_digest: input.witness_policy.policy_digest,
        minimum_weight: input.witness_policy.minimum_weight,
        witnesses: new Map(input.witness_policy.witnesses),
      },
      journal: {
        load: (key: string) => entries.get(key) ?? null,
        compareAndSwap(
          key: string,
          expectedRevision: number | null,
          next: assuranceObservation.EnrollmentObservationJournalEntry,
        ) {
          if ((entries.get(key)?.revision ?? null) !== expectedRevision) {
            return "conflict";
          }
          entries.set(key, next);
          return "committed";
        },
      },
    }]);
    let raw: Awaited<ReturnType<typeof assuranceObservation.evaluateEnrollmentEligibility>> = {
      verdict: "reject",
      reason_code: "assurance-enrollment-pending-window",
    };
    for (const [index, step] of input.steps.entries()) {
      trustedNow = step.at;
      raw = await callStep<Awaited<ReturnType<
        typeof assuranceObservation.evaluateEnrollmentEligibility
      >>>(index + 1, [authority, {
          inception: input.inception,
          acceptance: input.acceptance,
          evidence: step.evidence,
        }]);
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
  if (
    boundaryId ===
      "assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade"
  ) {
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
      downgrade_event: Parameters<typeof assuranceDowngrade.evaluateAssuranceDowngrade>[1];
    };
    const entries = new Map<string, assuranceObservation.EnrollmentObservationJournalEntry>();
    let trustedNow = input.steps[0]?.at ?? 0;
    const authority = await callStep<ReturnType<
      typeof assuranceObservation.createAssuranceEnrollmentObservationAuthority
    >>(0, [{
      authority_id: input.authority_id,
      journal_integrity_key: input.journal_integrity_key,
      trusted_now: () => trustedNow,
      witness_policy: {
        policy_digest: input.witness_policy.policy_digest,
        minimum_weight: input.witness_policy.minimum_weight,
        witnesses: new Map(input.witness_policy.witnesses),
      },
      journal: {
        load: (key: string) => entries.get(key) ?? null,
        compareAndSwap(
          key: string,
          expectedRevision: number | null,
          next: assuranceObservation.EnrollmentObservationJournalEntry,
        ) {
          if ((entries.get(key)?.revision ?? null) !== expectedRevision) {
            return "conflict";
          }
          entries.set(key, next);
          return "committed";
        },
      },
    }]);
    let retained: Awaited<ReturnType<
      typeof assuranceObservation.evaluateEnrollmentEligibility
    >> = { verdict: "reject", reason_code: "assurance-pin-conflict" };
    for (const [index, step] of input.steps.entries()) {
      trustedNow = step.at;
      retained = await callStep<Awaited<ReturnType<
        typeof assuranceObservation.evaluateEnrollmentEligibility
      >>>(index + 1, [authority, {
          inception: input.inception,
          acceptance: input.acceptance,
          evidence: step.evidence,
        }]);
    }
    if (
      "verdict" in retained || retained.state !== "verified" ||
      retained.retained_pin === null
    ) return { raw_result: retained, projected_output: retained };
    const downgradeIndex = input.steps.length + 1;
    const evaluated = await callStep<ReturnType<
      typeof assuranceDowngrade.evaluateAssuranceDowngrade
    >>(downgradeIndex, [retained.retained_pin, input.downgrade_event]);
    if (evaluated.verdict === "reject") {
      return { raw_result: evaluated, projected_output: evaluated };
    }
    const committed = await callStep<ReturnType<
      typeof assuranceDowngrade.commitAssuranceDowngrade
    >>(downgradeIndex + 1, [evaluated.normalized]);
    return {
      raw_result: committed,
      projected_output: committed,
    };
  }
  if (boundaryId === "assurance.evaluateAssuranceAuthorityAt") {
    const input = fixture.input as { created_at: number; compromise_cutoff: number | null };
    const raw = await callStep<ReturnType<typeof assurance.evaluateAssuranceAuthorityAt>>(
      0,
      [input.created_at, input.compromise_cutoff],
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
    const ncryptsec = await callStep<string>(0, [
      input.secret_key,
      input.password,
      input.salt,
      input.nonce,
    ]);
    const raw = {
      ncryptsec,
      recovered_secret: bytesToHex(await callStep<Uint8Array>(1, [ncryptsec, input.password])),
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
    const key = await callStep<Uint8Array>(0, config
      ? [input.config_audience_key!, input.key_id]
      : [input.audience_key!, input.key_id]);
    const nonce = config ? "60".repeat(32) : "61".repeat(32);
    const ciphertext = await callStep<string>(1, [input.plaintext, key, hexToBytes(nonce)]);
    const recovered = await callStep<string>(2, [ciphertext, key]);
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
    const key = await callStep<Uint8Array>(0, [input.audience_key, input.key_id]);
    const ciphertext = await callStep<string>(1, [
      input.plaintext,
      key,
      hexToBytes("61".repeat(32)),
    ]);
    const recovered = await callStep<string>(2, [ciphertext, key]);
    const crypto = {
      derived_key: bytesToHex(key),
      ciphertext,
      recovered_plaintext: recovered,
      authenticated_round_trip: recovered === input.plaintext
        && ciphertext !== input.plaintext,
    };
    const recipients = await callStep<ReturnType<typeof followUpHardening.resolveTier3Recipients>>(3, [{
      memberPersonas: input.memberPersonas,
      devices: input.devices,
      selected: input.selected,
    }]);
    const routeEvaluation = await callStep<ReturnType<typeof evaluateCurrentTier3PrivateRoute>>(
      4,
      [fixture.vector_id, input],
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
  if (
    boundaryId === "claim-authorization.authorizeClaimEffect+authorizeClaimEffect"
  ) {
    const [authority, input, replayInput] = fixture.boundary_args ?? [];
    const first = await callStep<Awaited<ReturnType<
      typeof claimAuthorization.authorizeClaimEffect
    >>>(0, [authority, input]);
    const second = await callStep<Awaited<ReturnType<
      typeof claimAuthorization.authorizeClaimEffect
    >>>(1, [authority, replayInput]);
    return { raw_result: { first, second }, projected_output: second };
  }
  if (
    boundaryId
    === "core-writer-binding.resolveCurrentRepositoryWriterBinding+revalidateCurrentRepositoryWriterBinding"
  ) {
    const [authority, source, request] = fixture.boundary_args ?? [];
    try {
      const binding = await callStep<ReturnType<
        typeof coreWriterBinding.resolveCurrentRepositoryWriterBinding
      >>(0, [authority, source, request]);
      const revalidated = await callStep<ReturnType<
        typeof coreWriterBinding.revalidateCurrentRepositoryWriterBinding
      >>(1, [authority, binding]);
      return {
        raw_result: { binding, revalidated },
        projected_output: { verdict: "accept", current_writer_binding: "opaque" },
      };
    } catch (error) {
      return { raw_result: error, projected_output: thrownProjection(error) };
    }
  }
  if (
    boundaryId
    === "claims.verifyClaimRevocationEnvelope+claim-authorization.inspectClaimState"
  ) {
    const [event, authority, input] = fixture.boundary_args ?? [];
    const revocation = await callStep<ReturnType<
      typeof claims.verifyClaimRevocationEnvelope
    >>(0, [event]);
    const authorization = await callStep<ReturnType<
      typeof claimAuthorization.inspectClaimState
    >>(1, [authority, input]);
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
    const [records, tombstones, checkpoint, context, readerNid, request, authority] =
      fixture.boundary_args ?? [];
    const state = await callStep<ReturnType<typeof claimLedger.mergeClaimLedger>>(
      0,
      [records, tombstones, checkpoint, context],
    );
    const authorization = authority === undefined
      ? await callStep<ReturnType<typeof claimLedger.evaluateReaderAccess>>(
        1,
        [readerNid, state, request],
      )
      : await callStep<Awaited<ReturnType<
        typeof claimAuthorization.authorizeReaderAccessEffect
      >>>(1, [authority, {
          reader_nid: readerNid as string,
          state,
          request: request as claimLedger.ReaderAccessRequest,
          idempotency_key: `current-vector-${fixture.vector_id}`,
          effect_digest: "91".repeat(32),
          effect: () => ({
            status: "completed" as const,
            result: { access: "granted" },
          }),
        }]);
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
    const token = await callStep<ReturnType<typeof oidc.projectAccessToken>>(0, [projection]);
    const authorization = await callStep<ReturnType<typeof oidc.validateProjectedJwt>>(1, [
      token.compact,
      expectedIssuer,
      expectedAudience,
      jwks,
      validationContext,
    ]);
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
    const first = await callStep<ReturnType<typeof trustedSeed.evaluateTrustedSeedAdmission>>(
      0,
      [authority, capability],
    );
    if (mode === "replay") {
      const second = await callStep<ReturnType<typeof trustedSeed.evaluateTrustedSeedAdmission>>(
        1,
        [authority, capability],
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
    const registration = await callStep<ReturnType<
      typeof agentAuthorship.validateWorkloadRegistration
    >>(0, [registrationInput]);
    const token = await callStep<ReturnType<typeof agentAuthorship.validateAgentAccessToken>>(
      1,
      [tokenInput],
    );
    return {
      raw_result: { registration, token },
      projected_output: {
        verdict: token.verdict,
        identity: token.verdict === "accept" ? token.identity : null,
      },
    };
  }
  if (boundaryId.startsWith(
    "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization",
  )) {
    const [securityFixture, operationDigest, approval, acceptance, mismatchAcceptance,
      device, leaf] = fixture.boundary_args ?? [];
    const security = securityFixture as Readonly<{
      authority: object;
      clock: { now: number };
      signed_repository_view: object;
      grant_id: string;
      subject: string;
      resource: string;
    }>;
    const authenticated = await callStep<ReturnType<
      typeof workspace.authenticateWorkspaceRepositoryView
    >>(0, [security.signed_repository_view]);
    if (authenticated.verdict !== "accept") {
      return { raw_result: authenticated, projected_output: authenticated };
    }
    const carrier = fixture.vector_id === "workspace/carrier-not-ambient-authority";
    const escalated = fixture.vector_id === "workspace/inheritance-escalation-rejected";
    const resolution = await callStep<ReturnType<
      typeof workspace.resolveWorkspaceEffectiveAuthorization
    >>(1, [{
      authority: security.authority,
      current_state: authenticated.state,
      actor_account: carrier ? "a2".repeat(32) : security.subject,
      actor_device: device,
      actor_leaf: leaf,
      operation_digest: operationDigest,
      requested_capabilities: escalated ? ["write"] : ["invite", "read"],
      requested_resources: [security.resource],
      requested_delegable: false,
    }]);
    if (resolution.verdict !== "accept") {
      return {
        raw_result: { authenticated, terminal: resolution },
        projected_output: resolution,
      };
    }
    if (fixture.vector_id === "workspace/revocation-blocks-future-effect") {
      const preparedAt = security.clock.now;
      security.clock.now += 1;
      const terminal = await callStep<ReturnType<typeof workspace.evaluateGrantActivation>>(2, [{
        authority: security.authority,
        current_state: authenticated.state,
        authorization: resolution.authorization,
        invitation_acceptance: null,
        successor_reauthorization: null,
        grant_id: security.grant_id,
        membership: {
          authenticated_account: security.subject,
          accepted_device: device,
          accepted_leaf: leaf,
        },
        approvals: [approval],
      }]);
      return {
        raw_result: {
          authenticated,
          resolution,
          revocation_timing: Object.freeze({
            prepared_at: preparedAt,
            activation_at: security.clock.now,
          }),
          terminal,
        },
        projected_output: terminal,
      };
    }
    const consumed = await callStep<ReturnType<
      typeof workspace.consumeWorkspaceInvitationAcceptance
    >>(2, [{
      authority: security.authority,
      current_state: authenticated.state,
      acceptance,
    }]);
    if (consumed.verdict !== "accept") {
      return { raw_result: { authenticated, resolution, terminal: consumed }, projected_output: consumed };
    }
    const activation = await callStep<ReturnType<typeof workspace.evaluateGrantActivation>>(3, [{
      authority: security.authority,
      current_state: authenticated.state,
      authorization: resolution.authorization,
      invitation_acceptance: consumed.acceptance,
      successor_reauthorization: null,
      grant_id: security.grant_id,
      membership: {
        authenticated_account: security.subject,
        accepted_device: device,
        accepted_leaf: leaf,
      },
      approvals: [approval],
    }]);
    if (!boundaryId.endsWith("+consumeWorkspaceInvitationAcceptance")) {
      return {
        raw_result: { authenticated, resolution, consumed, terminal: activation },
        projected_output: activation,
      };
    }
    const second = await callStep<ReturnType<
      typeof workspace.consumeWorkspaceInvitationAcceptance
    >>(4, [{
      authority: security.authority,
      current_state: authenticated.state,
      acceptance: mismatchAcceptance,
    }]);
    return {
      raw_result: { authenticated, resolution, consumed, activation, terminal: second },
      projected_output: second,
    };
  }
  if (boundaryId === "control-device-authorization.createControlDeviceTransaction+pollControlDeviceAuthorization") {
    const [authority, request, clockValue, mode, store] = fixture.boundary_args ?? [];
    const clock = clockValue as { now: number };
    const created = await callStep<Awaited<ReturnType<typeof controlDeviceAuthorization.createControlDeviceTransaction>>>(0, [authority, request]);
    if (created.verdict !== "accept") return { raw_result: { terminal: created }, projected_output: created };
    if (mode !== "control/device-code-rate-limited") clock.now += created.output.interval_seconds;
    const poll = {
      device_code: created.output.device_code,
      user_code: mode === "control/device-code-invalid" ? "ZZZZ-ZZZZ" : created.output.user_code,
      displayed_fingerprint: mode === "control/device-code-display-mismatch"
        ? "SYNTHETIC-WRONG-FINGERPRINT" : "SYNTHETIC-CURRENT-FINGERPRINT",
    };
    const terminal = await callStep<Awaited<ReturnType<typeof controlDeviceAuthorization.pollControlDeviceAuthorization>>>(1, [authority, poll]);
    return { raw_result: { created, poll, terminal, store }, projected_output: terminal };
  }
  if (boundaryId === "marmot-admission-authority.verifyMarmotWelcome+admitOrdinaryMarmotWelcome") {
    const [authority, input, checkpoint, mode, store, evidenceValue] = fixture.boundary_args ?? [];
    const evidence = evidenceValue as { counts?: () => unknown };
    const verified = await callStep<Awaited<ReturnType<typeof marmotAdmissionAuthority.verifyMarmotWelcome>>>(0, [authority, input]);
    if (verified.verdict !== "accept") return { raw_result: { terminal: verified }, projected_output: verified };
    const terminal = await callStep<Awaited<ReturnType<typeof marmotAdmissionAuthority.admitOrdinaryMarmotWelcome>>>(1, [authority, verified.output, { decision: mode === "comms/conversation-rejected" ? "reject" : "hold", expected_checkpoint: checkpoint }]);
    return { raw_result: { verified, terminal, store, evidence: evidenceValue, counts: evidence.counts?.() }, projected_output: terminal };
  }
  if (boundaryId === "agent-publication-authorization.authorizeAndSignAgentPublication") {
    const [authority, request, store, signerCalls] = fixture.boundary_args ?? [];
    const first = await callStep<Awaited<ReturnType<typeof agentPublicationAuthorization.authorizeAndSignAgentPublication>>>(0, [authority, request]);
    if (fixture.vector_id !== "comms/agent-workload-token-accepted") {
      return { raw_result: { terminal: first, store, signer_calls: (signerCalls as () => number)() }, projected_output: first };
    }
    const retry = await callStep<Awaited<ReturnType<typeof agentPublicationAuthorization.authorizeAndSignAgentPublication>>>(1, [authority, request]);
    return {
      raw_result: { first, retry, terminal: retry, store, signer_calls: (signerCalls as () => number)() },
      projected_output: retry,
    };
  }
  if (boundaryId === "control-token-verifier.verifyControlToken+consumeVerifiedControlToken") {
    const [verifier, compact, use, operation, store, effectCalls] = fixture.boundary_args ?? [];
    const verified = await callStep<Awaited<ReturnType<typeof controlTokenVerifier.verifyControlToken>>>(0, [verifier, compact, use]);
    if (verified.verdict !== "accept") return { raw_result: { terminal: verified }, projected_output: verified };
    const terminal = await callStep<Awaited<ReturnType<typeof controlTokenVerifier.consumeVerifiedControlToken>>>(1, [verifier, verified.output, operation]);
    return { raw_result: { verified, terminal, store, effect_calls: (effectCalls as () => number)() }, projected_output: terminal };
  }
  if (boundaryId === "marmot-archive-retention-authority.appendExactMarmotArchive") {
    const [authority, input, store, appended] = fixture.boundary_args ?? [];
    const terminal = await callStep<Awaited<ReturnType<typeof marmotArchiveRetentionAuthority.appendExactMarmotArchive>>>(0, [authority, input]);
    return { raw_result: { terminal, store, appended }, projected_output: terminal };
  }
  if (boundaryId === "marmot-archive-retention-authority.acknowledgeMarmotArchive") {
    const [authority, receipt, store] = fixture.boundary_args ?? [];
    const terminal = await callStep<Awaited<ReturnType<
      typeof marmotArchiveRetentionAuthority.acknowledgeMarmotArchive
    >>>(0, [authority, receipt]);
    return { raw_result: { terminal, store }, projected_output: terminal };
  }
  if (boundaryId === "one-time-invite-authority.redeemOneTimeInvite") {
    const [authority, redemption, store] = fixture.boundary_args ?? [];
    const terminal = await callStep<Awaited<ReturnType<
      typeof oneTimeInviteAuthority.redeemOneTimeInvite
    >>>(0, [authority, redemption]);
    return { raw_result: { terminal, store }, projected_output: terminal };
  }
  if (boundaryId === "persona-inbox-admission-authority.admitPersonaInboxBundle") {
    const [authority, bundle, store, evidenceValue] = fixture.boundary_args ?? [];
    const evidence = evidenceValue as { loadCalls?: () => number };
    const terminal = await callStep<Awaited<ReturnType<
      typeof personaInboxAdmissionAuthority.admitPersonaInboxBundle
    >>>(0, [authority, bundle]);
    return { raw_result: { terminal, store, evidence: evidenceValue, load_calls: evidence.loadCalls?.() }, projected_output: terminal };
  }
  if (boundaryId === "control-enrollment-admission.admitControlEnrollment") {
    const [authority, request, store, evidence] = fixture.boundary_args ?? [];
    const terminal = await callStep<Awaited<ReturnType<
      typeof controlEnrollmentAdmission.admitControlEnrollment
    >>>(0, [authority, request]);
    return { raw_result: { terminal, store, evidence }, projected_output: terminal };
  }
  if (boundaryId === "marmot-archive-retention-authority.appendExactMarmotArchive+expireMarmotPresentation+acknowledgeMarmotArchive") {
    const [authority, input, store, appended] = fixture.boundary_args ?? [];
    const append = await callStep<Awaited<ReturnType<typeof marmotArchiveRetentionAuthority.appendExactMarmotArchive>>>(0, [authority, input]);
    if (append.verdict !== "accept") return { raw_result: { terminal: append }, projected_output: append };
    const expired = await callStep<Awaited<ReturnType<typeof marmotArchiveRetentionAuthority.expireMarmotPresentation>>>(1, [authority, append.output]);
    const terminal = await callStep<Awaited<ReturnType<typeof marmotArchiveRetentionAuthority.acknowledgeMarmotArchive>>>(2, [authority, append.output]);
    return { raw_result: { append, expired, terminal, store, appended }, projected_output: terminal };
  }
  if (boundaryId === "control-signing.executePersistedAutomatedSigning+executePersistedAutomatedSigning") {
    const [firstInput, retryInput, invocationCount] = fixture.boundary_args ?? [];
    const first = await callStep<ReturnType<typeof controlSigning.executePersistedAutomatedSigning>>(
      0,
      [firstInput],
    );
    const retry = await callStep<ReturnType<typeof controlSigning.executePersistedAutomatedSigning>>(
      1,
      [retryInput],
    );
    const signerCalls = typeof invocationCount === "function"
      ? (invocationCount as () => number)()
      : -1;
    return {
      raw_result: { first, retry, terminal: retry, signer_calls: signerCalls },
      projected_output: retry,
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
    const raw = await callStep<unknown>(0, args);
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
    if (boundaryId === "claim-authorization.inspectClaimState") {
      const decision = raw as ReturnType<typeof claimAuthorization.inspectClaimState>;
      return {
        raw_result: decision,
        projected_output: {
          verdict: decision.allowed ? "accept" : "reject",
          ...(decision.reason_code === null ? {} : { reason_code: decision.reason_code }),
          evaluator_output: decision,
        },
      };
    }
    if (boundaryId === "claim-authorization.authorizeClaimEffect") {
      const decision = raw as Awaited<ReturnType<typeof claimAuthorization.authorizeClaimEffect>>;
      return {
        raw_result: decision,
        projected_output: decision.verdict === "accept"
          ? { verdict: "accept", authorization: decision }
          : decision.verdict === "indeterminate"
            ? {
                verdict: decision.verdict,
                allowed: decision.allowed,
                state: decision.state,
                reason_code: decision.reason_code,
              }
            : decision,
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

async function executeProfilePrerequisite(
  context: InvocationContext,
  boundaryId: string,
  fixture: CurrentCaseFixture,
): Promise<ReturnType<typeof profileNegotiation.validateCurrentKindProfileNegotiation> | undefined> {
  const profileOracle = currentProfileOracleForVector(fixture.vector_id);
  if (profileOracle === undefined) return undefined;
  if (boundaryId !== profileOracle.semantic_boundary) {
    throw new Error(`current profile boundary/oracle mismatch: ${fixture.vector_id}`);
  }
  const currentRegistry = await context.call("profile:registry", [REPOSITORY_ROOT]) as
    ReturnType<typeof registry.loadRegistry>;
  const registryComparison = await context.call(
    "profile:negotiation",
    [currentRegistry, fixture.input],
  ) as ReturnType<typeof profileNegotiation.validateCurrentKindProfileNegotiation>;
  if (registryComparison.verdict !== "accept") {
    throw new Error(
      `current profile registry prerequisite failed: ${fixture.vector_id} -> ${registryComparison.reason}`,
    );
  }
  return registryComparison;
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
  for (const key of ["authorization", "token", "second", "terminal", "activation"] as const) {
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
  for (const key of ["authorization", "token", "second", "terminal", "activation"] as const) {
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
  if (
    boundaryId
    === "core-writer-binding.resolveCurrentRepositoryWriterBinding+revalidateCurrentRepositoryWriterBinding"
  ) {
    if (raw instanceof Error) return "reject";
    const result = raw as Readonly<{ binding?: unknown; revalidated?: unknown }>;
    return result.binding !== undefined && result.revalidated === result.binding
      ? "accept"
      : "reject";
  }
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
  if (boundaryId === "social-subscription-authority.resolveSubscribedAgentPolicy+applySubscribedAgentPolicy") {
    const result = raw as Readonly<{ view?: unknown; terminal?: { visible?: unknown; muted?: unknown } }>;
    return result.view !== null && result.view !== undefined
      && result.terminal?.visible === false && result.terminal.muted === true
      ? "accept" : "reject";
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
): Promise<CurrentBoundaryExecution> {
  const evaluatorSteps = actualEvaluatorFunctions(boundaryId, fixture);
  const evaluatorPlan = actualEvaluatorPlan(boundaryId, fixture, evaluatorSteps);
  const context = new InvocationContext(evaluatorPlan);
  const profileOracle = currentProfileOracleForVector(fixture.vector_id);
  const registryComparison = await executeProfilePrerequisite(context, boundaryId, fixture);
  const execution = await executeCurrentBoundary(boundaryId, fixture, context);
  const rawVerdict = rawSemanticVerdict(boundaryId, fixture, execution.raw_result);
  assertProjectionPreservesVerdict(
    rawVerdict,
    execution.projected_output,
    rawVerdict === "accept"
      ? undefined
      : rawSemanticReason(boundaryId, fixture, execution.raw_result),
  );
  const boundResult = registryComparison === undefined
    ? execution
    : {
        raw_result: Object.freeze({
          registry_comparison: registryComparison,
          semantic_boundary: profileOracle!.semantic_boundary,
          semantic_result: execution.raw_result,
        }),
        projected_output: execution.projected_output,
      };
  const evaluatorInvocations = context.finish();
  return mintBoundaryExecution(
    boundaryId,
    fixture,
    boundResult,
    evaluatorPlan,
    evaluatorInvocations,
    invokeCurrentBoundary,
  );
}

/** BLUE TEAM VALIDATION: synthetic/local test seam; substituted executions cannot certify. */
export async function invokeCurrentBoundaryWithTestEvaluatorSubstitution(
  boundaryId: string,
  fixture: CurrentCaseFixture,
  substitution: Readonly<{
    direct?: BoundaryFunction;
    composite_step?: Readonly<{ index: number; evaluator: BoundaryFunction }>;
  }>,
): Promise<CurrentBoundaryExecution> {
  const evaluatorSteps = [...actualEvaluatorFunctions(boundaryId, fixture)];
  if (substitution.direct !== undefined) {
    if (evaluatorSteps.length !== 1 || substitution.composite_step !== undefined) {
      throw new Error("direct evaluator substitution requires one direct boundary step");
    }
    evaluatorSteps[0] = substitution.direct;
  } else if (substitution.composite_step !== undefined) {
    const { index, evaluator } = substitution.composite_step;
    if (!Number.isSafeInteger(index) || index < 0 || index >= evaluatorSteps.length) {
      throw new Error("composite evaluator substitution index is invalid");
    }
    evaluatorSteps[index] = evaluator;
  } else {
    throw new Error("test evaluator substitution is required");
  }
  const evaluatorPlan = actualEvaluatorPlan(boundaryId, fixture, evaluatorSteps);
  const context = new InvocationContext(evaluatorPlan);
  const registryComparison = await executeProfilePrerequisite(context, boundaryId, fixture);
  const execution = await executeCurrentBoundary(boundaryId, fixture, context);
  const rawVerdict = rawSemanticVerdict(boundaryId, fixture, execution.raw_result);
  assertProjectionPreservesVerdict(
    rawVerdict,
    execution.projected_output,
    rawVerdict === "accept"
      ? undefined
      : rawSemanticReason(boundaryId, fixture, execution.raw_result),
  );
  const boundResult = registryComparison === undefined
    ? execution
    : {
        raw_result: Object.freeze({
          registry_comparison: registryComparison,
          semantic_boundary: currentProfileOracleForVector(fixture.vector_id)!.semantic_boundary,
          semantic_result: execution.raw_result,
        }),
        projected_output: execution.projected_output,
      };
  const evaluatorInvocations = context.finish();
  return mintBoundaryExecution(
    boundaryId,
    fixture,
    boundResult,
    evaluatorPlan,
    evaluatorInvocations,
    // Deliberately retain the production runner token so hostile tests isolate
    // the independently captured evaluator-step identity check.
    invokeCurrentBoundary,
  );
}

/** BLUE TEAM VALIDATION: synthetic/local same-terminal non-revocation counterexample. */
export async function invokeCurrentBoundaryWithTestNonRevocationDenial(
  boundaryId: string,
  fixture: CurrentCaseFixture,
): Promise<CurrentBoundaryExecution> {
  if (boundaryId !== "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+evaluateGrantActivation"
    || fixture.vector_id !== "workspace/revocation-blocks-future-effect") {
    throw new Error("test non-revocation denial requires the Workspace revocation boundary");
  }
  const privateArgs = resolvePrivateCurrentBoundaryArgs(fixture);
  const security = privateArgs?.[0] as { clock?: { now: number } } | undefined;
  const activation = actualEvaluatorFunctions(boundaryId, fixture)[2];
  if (security?.clock === undefined || activation === undefined) {
    throw new Error("test non-revocation denial fixture is unavailable");
  }
  return await invokeCurrentBoundaryWithTestEvaluatorSubstitution(boundaryId, fixture, {
    composite_step: {
      index: 2,
      evaluator: (...args: readonly unknown[]) => {
        security.clock!.now -= 1;
        const input = args[0] as { approvals: unknown[] };
        input.approvals = [];
        return Reflect.apply(activation, undefined, [input]);
      },
    },
  });
}

/** BLUE TEAM VALIDATION: synthetic/local test seam; incomplete plans never mint executions. */
export async function invokeCurrentBoundaryWithTestPlanOmission(
  boundaryId: string,
  fixture: CurrentCaseFixture,
  omittedStepIndex: number,
): Promise<never> {
  const evaluatorSteps = [...actualEvaluatorFunctions(boundaryId, fixture)];
  if (
    !Number.isSafeInteger(omittedStepIndex)
    || omittedStepIndex < 0
    || omittedStepIndex >= evaluatorSteps.length
  ) throw new Error("test evaluator omission index is invalid");
  evaluatorSteps.splice(omittedStepIndex, 1);
  const evaluatorPlan = actualEvaluatorPlan(boundaryId, fixture, evaluatorSteps);
  const context = new InvocationContext(evaluatorPlan);
  await executeProfilePrerequisite(context, boundaryId, fixture);
  await executeCurrentBoundary(boundaryId, fixture, context);
  context.finish();
  throw new Error("incomplete current evaluator plan unexpectedly completed");
}
