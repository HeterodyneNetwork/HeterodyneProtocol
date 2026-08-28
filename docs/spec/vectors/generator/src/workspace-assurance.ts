import { types as utilTypes } from "node:util";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8Bytes } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";

export type WorkspaceAssuranceConfig = Readonly<{
  trusted_now: () => number;
  resolve_verified_enrollment: (input: Readonly<{
    workspace_key: string;
    inception_event_id: string;
    evaluated_at: number;
  }>) => unknown;
  authorize_removal: (input: Readonly<{
    workspace_key: string;
    inception_event_id: string;
    transition_digest: string;
    evaluated_at: number;
  }>) => unknown;
}>;

declare const workspaceAssuranceAuthorityBrand: unique symbol;
export type WorkspaceAssuranceAuthority = Readonly<{
  [workspaceAssuranceAuthorityBrand]: true;
}>;

export type WorkspaceAssuranceProfile = Readonly<{
  profile: "heterodyne.workspace.assurance.v1";
  inception_event_id: string;
  required_state: "verified";
}>;

type CapturedWorkspaceAssuranceConfig = WorkspaceAssuranceConfig;

type WorkspaceAssuranceTransition = Readonly<{
  workspace_key: string;
  previous_policy_head: string | null;
  next_policy_head: string;
  previous_assurance: WorkspaceAssuranceProfile | null;
  next_assurance: WorkspaceAssuranceProfile | null;
}>;

export type WorkspaceAssuranceVerdict =
  | Readonly<{ verdict: "accept" }>
  | Readonly<{
    verdict: "reject";
    reason_code: "workspace-assurance-state-required";
  }>;

const AUTHORITIES = new WeakMap<object, CapturedWorkspaceAssuranceConfig>();
const H64_PATTERN = /^[0-9a-f]{64}$/u;
const ASSURANCE_REASON = "workspace-assurance-state-required" as const;

const reject = (): WorkspaceAssuranceVerdict => ({
  verdict: "reject",
  reason_code: ASSURANCE_REASON,
});

export function createWorkspaceAssuranceAuthority(
  value: unknown,
): WorkspaceAssuranceAuthority {
  const descriptors = exactDataDescriptors(value, [
    "trusted_now",
    "resolve_verified_enrollment",
    "authorize_removal",
  ]);
  const trustedNow = descriptorValue(descriptors?.trusted_now);
  const resolveVerifiedEnrollment = descriptorValue(descriptors?.resolve_verified_enrollment);
  const authorizeRemoval = descriptorValue(descriptors?.authorize_removal);
  if (typeof trustedNow !== "function"
    || typeof resolveVerifiedEnrollment !== "function"
    || typeof authorizeRemoval !== "function") {
    throw new TypeError("invalid Workspace Assurance configuration");
  }
  const authority = Object.freeze({}) as WorkspaceAssuranceAuthority;
  AUTHORITIES.set(authority, Object.freeze({
    trusted_now: trustedNow as () => number,
    resolve_verified_enrollment: resolveVerifiedEnrollment as WorkspaceAssuranceConfig[
      "resolve_verified_enrollment"
    ],
    authorize_removal: authorizeRemoval as WorkspaceAssuranceConfig["authorize_removal"],
  }));
  return authority;
}

export function evaluateWorkspaceAssuranceTransition(
  authority: WorkspaceAssuranceAuthority | null,
  input: unknown,
): WorkspaceAssuranceVerdict {
  const transition = captureTransition(input);
  if (transition === null) return reject();
  if (transition.previous_assurance === null && transition.next_assurance === null) {
    return { verdict: "accept" };
  }
  if (authority === null || typeof authority !== "object") return reject();
  const config = AUTHORITIES.get(authority);
  if (config === undefined) return reject();
  let evaluatedAt: number;
  try {
    evaluatedAt = config.trusted_now();
  } catch {
    return reject();
  }
  if (!isSafeNonNegativeInteger(evaluatedAt)) return reject();

  const previous = transition.previous_assurance;
  const next = transition.next_assurance;
  if (previous !== null
    && !hasVerifiedEnrollment(config, transition.workspace_key, previous, evaluatedAt)) {
    return reject();
  }
  if (next !== null
    && !sameProfile(previous, next)
    && !hasVerifiedEnrollment(config, transition.workspace_key, next, evaluatedAt)) {
    return reject();
  }
  if (previous !== null && !sameProfile(previous, next)) {
    const transitionDigest = digestTransition(transition);
    let result: unknown;
    try {
      result = config.authorize_removal(Object.freeze({
        workspace_key: transition.workspace_key,
        inception_event_id: previous.inception_event_id,
        transition_digest: transitionDigest,
        evaluated_at: evaluatedAt,
      }));
    } catch {
      return reject();
    }
    if (!isAuthorizedRemoval(result, transitionDigest, evaluatedAt)) return reject();
  }
  return { verdict: "accept" };
}

function hasVerifiedEnrollment(
  config: CapturedWorkspaceAssuranceConfig,
  workspaceKey: string,
  profile: WorkspaceAssuranceProfile,
  evaluatedAt: number,
): boolean {
  let result: unknown;
  try {
    result = config.resolve_verified_enrollment(Object.freeze({
      workspace_key: workspaceKey,
      inception_event_id: profile.inception_event_id,
      evaluated_at: evaluatedAt,
    }));
  } catch {
    return false;
  }
  const descriptors = exactDataDescriptors(result, [
    "state",
    "active_key",
    "inception_event_id",
    "evaluated_at",
  ]);
  return descriptorValue(descriptors?.state) === "verified"
    && descriptorValue(descriptors?.active_key) === workspaceKey
    && descriptorValue(descriptors?.inception_event_id) === profile.inception_event_id
    && descriptorValue(descriptors?.evaluated_at) === evaluatedAt;
}

function isAuthorizedRemoval(
  result: unknown,
  transitionDigest: string,
  evaluatedAt: number,
): boolean {
  const descriptors = exactDataDescriptors(result, [
    "authorized",
    "transition_digest",
    "evaluated_at",
  ]);
  return descriptorValue(descriptors?.authorized) === true
    && descriptorValue(descriptors?.transition_digest) === transitionDigest
    && descriptorValue(descriptors?.evaluated_at) === evaluatedAt;
}

function digestTransition(transition: WorkspaceAssuranceTransition): string {
  return bytesToHex(sha256(utf8Bytes(jcsCanonicalize({
    profile: "heterodyne.workspace.assurance-transition.v1",
    workspace_key: transition.workspace_key,
    previous_policy_head: transition.previous_policy_head,
    next_policy_head: transition.next_policy_head,
    previous_assurance: transition.previous_assurance,
    next_assurance: transition.next_assurance,
  }))));
}

function captureTransition(value: unknown): WorkspaceAssuranceTransition | null {
  const descriptors = exactDataDescriptors(value, [
    "workspace_key",
    "previous_policy_head",
    "next_policy_head",
    "previous_assurance",
    "next_assurance",
  ]);
  if (descriptors === null) return null;
  const workspaceKey = descriptorValue(descriptors.workspace_key);
  const previousPolicyHead = descriptorValue(descriptors.previous_policy_head);
  const nextPolicyHead = descriptorValue(descriptors.next_policy_head);
  const previousAssurance = captureProfile(descriptorValue(descriptors.previous_assurance));
  const nextAssurance = captureProfile(descriptorValue(descriptors.next_assurance));
  if (!isH64(workspaceKey)
    || !(previousPolicyHead === null || isH64(previousPolicyHead))
    || !isH64(nextPolicyHead)
    || previousAssurance === undefined
    || nextAssurance === undefined) return null;
  return Object.freeze({
    workspace_key: workspaceKey,
    previous_policy_head: previousPolicyHead,
    next_policy_head: nextPolicyHead,
    previous_assurance: previousAssurance,
    next_assurance: nextAssurance,
  });
}

function captureProfile(value: unknown): WorkspaceAssuranceProfile | null | undefined {
  if (value === null) return null;
  const descriptors = exactDataDescriptors(value, [
    "profile",
    "inception_event_id",
    "required_state",
  ]);
  if (descriptors === null
    || descriptorValue(descriptors.profile) !== "heterodyne.workspace.assurance.v1"
    || !isH64(descriptorValue(descriptors.inception_event_id))
    || descriptorValue(descriptors.required_state) !== "verified") return undefined;
  return Object.freeze({
    profile: "heterodyne.workspace.assurance.v1",
    inception_event_id: descriptorValue(descriptors.inception_event_id) as string,
    required_state: "verified",
  });
}

function sameProfile(
  left: WorkspaceAssuranceProfile | null,
  right: WorkspaceAssuranceProfile | null,
): boolean {
  return left === null ? right === null : right !== null
    && left.profile === right.profile
    && left.inception_event_id === right.inception_event_id
    && left.required_state === right.required_state;
}

function exactDataDescriptors(
  value: unknown,
  members: readonly string[],
): PropertyDescriptorMap | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || utilTypes.isProxy(value)) return null;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== members.length
      || keys.some((key) => typeof key !== "string" || !members.includes(key))) return null;
    for (const member of members) {
      const descriptor = descriptors[member];
      if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) {
        return null;
      }
    }
    return descriptors;
  } catch {
    return null;
  }
}

function descriptorValue(descriptor: PropertyDescriptor | undefined): unknown {
  return descriptor !== undefined && "value" in descriptor ? descriptor.value : undefined;
}

function isH64(value: unknown): value is string {
  return typeof value === "string" && H64_PATTERN.test(value);
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}
