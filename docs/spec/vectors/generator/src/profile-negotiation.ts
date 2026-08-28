import {
  validateRegisteredKindProfile,
  type Registry,
  type RegisteredKindProfile,
} from "./registry.js";
import { stampOwner } from "./stamping.js";

export type CurrentProfileWireProbe = Readonly<{
  content_is_heterodyne_json: boolean;
  is_dr_outer: boolean;
  content_profile?: string;
  tags?: readonly (readonly string[])[];
  production_rule?: string;
  transport?: "marmot-inner";
  content_profile_id?: string;
}>;

export type CurrentKindProfileNegotiationInput = RegisteredKindProfile & Readonly<{
  wire_probe: CurrentProfileWireProbe;
}>;

type ProfileNegotiationDecision =
  | Readonly<{
      verdict: "accept";
      normalized: RegisteredKindProfile;
      stamp_owner: ReturnType<typeof stampOwner>;
      wire_binding: string;
    }>
  | Readonly<{
      verdict: "reject";
      reason:
        | "profile-not-registered"
        | "profile-metadata-mismatch"
        | "profile-wire-discriminator-mismatch";
    }>;

function hasTag(
  probe: CurrentProfileWireProbe,
  name: string,
  value: (candidate: string) => boolean,
): boolean {
  return probe.tags?.some((tag) =>
    tag.length === 2
    && tag[0] === name
    && typeof tag[1] === "string"
    && value(tag[1])
  ) === true;
}

function wireBindingMatches(
  discriminator: string,
  probe: CurrentProfileWireProbe,
): boolean {
  if (discriminator.startsWith("content.profile=")) {
    return probe.content_profile === discriminator.slice("content.profile=".length);
  }
  if (discriminator.startsWith("tag:")) {
    const allocation = discriminator.slice("tag:".length);
    const separator = allocation.indexOf("=");
    if (separator <= 0) return false;
    const name = allocation.slice(0, separator);
    const expected = allocation.slice(separator + 1);
    return hasTag(probe, name, (value) => value === expected);
  }
  if (discriminator.startsWith("tags:L=")) {
    const match = /^tags:L=([^,]+),l=<reason>@(.+)$/u.exec(discriminator);
    if (match === null || match[1] !== match[2]) return false;
    const namespace = match[1];
    return hasTag(probe, "L", (value) => value === namespace)
      && hasTag(probe, "l", (value) =>
        value.length > namespace.length + 1 && value.endsWith(`@${namespace}`)
      );
  }
  if (discriminator.startsWith("production-rule:")) {
    return probe.production_rule === discriminator.slice("production-rule:".length);
  }
  if (discriminator === "marmot-inner-only;content=control-frame-v1") {
    return probe.transport === "marmot-inner"
      && probe.content_profile_id === "control-frame-v1";
  }
  return false;
}

function expectedStampOwner(
  registry: Registry,
  profile: RegisteredKindProfile,
  probe: CurrentProfileWireProbe,
): ReturnType<typeof stampOwner> {
  if (probe.is_dr_outer) return null;
  if (profile.stamping) return profile.owner === "control" ? null : profile.owner;
  const kind = registry.kinds.find((candidate) => candidate.kind === profile.kind);
  if (
    kind === undefined
    || kind.allocation_authority !== "heterodyne"
    || kind.base_schema_owner === "nostr"
    || kind.base_schema_owner === "control"
  ) return null;
  return kind.base_schema_owner;
}

/**
 * Resolves one exact registered kind/profile tuple and validates the tuple's
 * declared wire discriminator before applying live stamping negotiation.
 */
export function validateCurrentKindProfileNegotiation(
  registry: Registry,
  value: unknown,
): ProfileNegotiationDecision {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { verdict: "reject", reason: "profile-metadata-mismatch" };
  }
  const { wire_probe: probe, ...candidate } = value as CurrentKindProfileNegotiationInput;
  if (probe === null || typeof probe !== "object" || Array.isArray(probe)) {
    return { verdict: "reject", reason: "profile-wire-discriminator-mismatch" };
  }
  const registered = validateRegisteredKindProfile(
    registry,
    candidate as RegisteredKindProfile,
  );
  if (registered.verdict === "reject") return registered;
  if (!wireBindingMatches(registered.normalized.discriminator, probe)) {
    return { verdict: "reject", reason: "profile-wire-discriminator-mismatch" };
  }
  const stamp = stampOwner({
    kind: registered.normalized.kind,
    profile_id: registered.normalized.profile_id,
    content_is_heterodyne_json: probe.content_is_heterodyne_json,
    is_dr_outer: probe.is_dr_outer,
  }, registry);
  const expectedStamp = expectedStampOwner(registry, registered.normalized, probe);
  if (stamp !== expectedStamp) {
    return { verdict: "reject", reason: "profile-wire-discriminator-mismatch" };
  }
  return {
    verdict: "accept",
    normalized: registered.normalized,
    stamp_owner: stamp,
    wire_binding: registered.normalized.discriminator,
  };
}
