import { types as utilTypes } from "node:util";
import { Ajv, type AnySchema } from "ajv";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import acceptanceSchema from "../../../schemas/assurance/active-key-acceptance-v1.schema.json" with { type: "json" };
import type { AssuranceVerdict } from "./assurance.js";
import {
  commitAssuranceEnrollmentDowngrade,
  resolveAssuranceEnrollmentPinForDowngrade,
  type AssuranceEnrollmentAuthoritativePin,
  type AssuranceEnrollmentDowngradeBinding,
  type AssuranceEnrollmentDowngradeCapability,
  type AssuranceEnrollmentDowngradeTerminal,
} from "./assurance-observation.js";
import { domainSeparatedJcsDigest } from "./credential-continuity.js";
import { bytesToHex } from "./hex.js";
import { jcsCanonicalize } from "./jcs.js";
import {
  snapshotAndVerifyNostrEvent,
  type VerifiedNostrEvent,
} from "./nostr.js";

declare const verifiedAssuranceDowngradeBrand: unique symbol;
export type VerifiedAssuranceDowngrade = Readonly<{
  readonly [verifiedAssuranceDowngradeBrand]: true;
}>;

type DowngradeRecord = Readonly<{
  profile: "heterodyne.assurance.active-key-acceptance.v1";
  spec_version: "heterodyne/0.6.0";
  active_key: string;
  created_at: number;
  predecessor: string;
  inception_event_id: string;
  cold_root: string;
  cold_root_signature: string;
  assurance_head: string;
  state: "downgraded";
  downgrade_consent: Readonly<{
    recovery_authority: string;
    signature: string;
  }>;
}>;

type CapturedDowngrade = {
  capability: AssuranceEnrollmentDowngradeCapability;
  source: object;
  source_snapshot: VerifiedNostrEvent;
  binding: AssuranceEnrollmentDowngradeBinding;
  completed: AssuranceEnrollmentDowngradeTerminal | null;
  failed: boolean;
};

const ajv = new Ajv({ allErrors: true, strict: false });
const validateAcceptance = ajv.compile(acceptanceSchema as AnySchema);
const VERIFIED_DOWNGRADES = new WeakMap<object, CapturedDowngrade>();

export function evaluateAssuranceDowngrade(
  retainedPin: AssuranceEnrollmentAuthoritativePin,
  sourceEvent: unknown,
): AssuranceVerdict<VerifiedAssuranceDowngrade> {
  const context = resolveAssuranceEnrollmentPinForDowngrade(retainedPin);
  if (context === null) return reject("assurance-pin-conflict");
  if (sourceEvent === null || typeof sourceEvent !== "object") {
    return reject("assurance-schema-invalid");
  }
  const event = snapshotAndVerifyNostrEvent(sourceEvent);
  if (event === null) {
    return looksLikeDowngradeOuterEnvelope(sourceEvent)
      ? reject("assurance-downgrade-consent-required")
      : reject("assurance-schema-invalid");
  }
  if (event.pubkey !== context.active_key) {
    return reject("assurance-downgrade-consent-required");
  }

  const parsed = parseDowngrade(event);
  if (parsed === null) {
    return missingDowngradeConsent(event)
      ? reject("assurance-downgrade-consent-required")
      : reject("assurance-schema-invalid");
  }
  if (!hasExactTags(event, [
    ["d", "assurance-head"],
    ["profile", parsed.profile],
  ])) return reject("assurance-schema-invalid");
  if (
    parsed.active_key !== context.active_key ||
    parsed.inception_event_id !== context.inception_event_id ||
    parsed.cold_root !== context.cold_root ||
    parsed.cold_root_signature !== context.inception_signature ||
    parsed.assurance_head !== context.accepted_head ||
    parsed.predecessor !== context.accepted_head
  ) return reject("assurance-head-mismatch");
  if (parsed.downgrade_consent.recovery_authority !== context.cold_root) {
    return reject("assurance-downgrade-consent-required");
  }

  const proofBody = {
    active_key: parsed.active_key,
    assurance_head: parsed.assurance_head,
    created_at: parsed.created_at,
    inception_event_id: parsed.inception_event_id,
    predecessor: parsed.predecessor,
  };
  const transitionDigest = domainSeparatedJcsDigest(
    "heterodyne-assurance-downgrade-v1",
    proofBody,
  );
  if (!validRecoveryProof(
    parsed.downgrade_consent.signature,
    transitionDigest,
    context.cold_root,
  )) return reject("assurance-downgrade-consent-required");

  const bindingBody = {
    active_key: context.active_key,
    inception_event_id: context.inception_event_id,
    cold_root: context.cold_root,
    accepted_head: context.accepted_head,
    predecessor: parsed.predecessor,
    created_at: parsed.created_at,
    downgrade_event_id: event.id,
    downgrade_event_signature: event.sig,
    transition_digest: transitionDigest,
  };
  const binding: AssuranceEnrollmentDowngradeBinding = Object.freeze({
    ...bindingBody,
    binding_digest: bytesToHex(sha256(new TextEncoder().encode(
      jcsCanonicalize({ retained_pin: retainedPin, source_event: event, binding: bindingBody }),
    ))),
  });
  const artifact = Object.freeze({});
  VERIFIED_DOWNGRADES.set(artifact, {
    capability: context.capability,
    source: sourceEvent,
    source_snapshot: event,
    binding,
    completed: null,
    failed: false,
  });
  return {
    verdict: "accept",
    normalized: artifact as VerifiedAssuranceDowngrade,
  };
}

export function commitAssuranceDowngrade(
  artifact: VerifiedAssuranceDowngrade,
): AssuranceVerdict<AssuranceEnrollmentDowngradeTerminal> {
  if (artifact === null || typeof artifact !== "object") {
    return reject("assurance-downgrade-consent-required");
  }
  const captured = VERIFIED_DOWNGRADES.get(artifact);
  if (captured === undefined || captured.failed) {
    return reject("assurance-downgrade-consent-required");
  }
  const current = snapshotAndVerifyNostrEvent(captured.source);
  if (
    current === null ||
    jcsCanonicalize(current) !== jcsCanonicalize(captured.source_snapshot)
  ) {
    captured.failed = true;
    return reject("assurance-downgrade-consent-required");
  }
  if (captured.completed !== null) {
    return { verdict: "accept", normalized: captured.completed };
  }
  const committed = commitAssuranceEnrollmentDowngrade(
    captured.capability,
    artifact,
  );
  if (committed.verdict === "accept") {
    captured.completed = committed.normalized;
  } else {
    captured.failed = true;
  }
  return committed;
}

export function verifiedAssuranceDowngradeBindingForCommit(
  artifact: unknown,
  capability: AssuranceEnrollmentDowngradeCapability,
): AssuranceEnrollmentDowngradeBinding | null {
  if (artifact === null || typeof artifact !== "object") return null;
  const captured = VERIFIED_DOWNGRADES.get(artifact);
  if (
    captured === undefined || captured.failed ||
    captured.capability !== capability
  ) return null;
  const current = snapshotAndVerifyNostrEvent(captured.source);
  if (
    current === null ||
    jcsCanonicalize(current) !== jcsCanonicalize(captured.source_snapshot)
  ) {
    captured.failed = true;
    return null;
  }
  return captured.binding;
}

function parseDowngrade(event: VerifiedNostrEvent): DowngradeRecord | null {
  try {
    if (event.kind !== 31000) return null;
    const value = JSON.parse(event.content) as unknown;
    if (
      event.content !== jcsCanonicalize(value) || !validateAcceptance(value) ||
      value === null || typeof value !== "object" || Array.isArray(value)
    ) return null;
    const record = value as Record<string, unknown>;
    if (
      record.created_at !== event.created_at ||
      record.state !== "downgraded" ||
      record.downgrade_consent === null ||
      typeof record.downgrade_consent !== "object"
    ) return null;
    return deepFreeze(value) as DowngradeRecord;
  } catch {
    return null;
  }
}

function missingDowngradeConsent(event: VerifiedNostrEvent): boolean {
  try {
    if (event.kind !== 31000) return false;
    const value = JSON.parse(event.content) as Record<string, unknown>;
    return event.content === jcsCanonicalize(value) &&
      value.state === "downgraded" && !Object.hasOwn(value, "downgrade_consent");
  } catch {
    return false;
  }
}

function looksLikeDowngradeOuterEnvelope(value: object): boolean {
  try {
    if (utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
      return false;
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const required = ["content", "created_at", "id", "kind", "pubkey", "tags"];
    const keys = Reflect.ownKeys(descriptors);
    if (
      keys.some((key) => typeof key !== "string") ||
      (keys.length !== required.length && keys.length !== required.length + 1) ||
      !required.every((member) => Object.hasOwn(descriptors, member)) ||
      (keys.length === required.length + 1 && !Object.hasOwn(descriptors, "sig"))
    ) return false;
    const read = (member: string): unknown => {
      const descriptor = descriptors[member];
      return descriptor !== undefined && "value" in descriptor &&
          descriptor.enumerable === true
        ? descriptor.value
        : undefined;
    };
    if (read("kind") !== 31000 || typeof read("content") !== "string") {
      return false;
    }
    const body = JSON.parse(read("content") as string) as unknown;
    return body !== null && typeof body === "object" && !Array.isArray(body) &&
      (body as Readonly<Record<string, unknown>>).state === "downgraded";
  } catch {
    return false;
  }
}

function hasExactTags(event: VerifiedNostrEvent, expected: string[][]): boolean {
  const canonical = (tags: readonly string[][]) =>
    tags.map((tag) => JSON.stringify(tag)).sort();
  return JSON.stringify(canonical(event.tags)) === JSON.stringify(canonical(expected));
}

function validRecoveryProof(signature: string, digest: string, key: string): boolean {
  try {
    return schnorr.verify(signature, digest, key);
  } catch {
    return false;
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) deepFreeze(member);
    Object.freeze(value);
  }
  return value;
}

function reject(reason_code: string): AssuranceVerdict<never> {
  return { verdict: "reject", reason_code };
}
