import { FAMILY_VERSION, QUALIFIED_VERSION, parseFamilyVersion } from "./family.js";
import {
  canonicalNip01,
  snapshotAndVerifyNostrEvent,
  type NostrSignedEvent,
} from "./nostr.js";

export type CurrentRepositoryWriterPolicy = Readonly<{
  writer_nid: string;
  ref_namespace: string;
  operations: readonly string[];
  state: "active" | "revoked" | "conflicted";
}>;

export type CurrentRepositoryPolicy = Readonly<{
  repository_rid: string;
  owner_active_key: string;
  revision: number;
  checkpoint: string;
  predecessor: string | null;
  state: "active" | "revoked" | "conflicted";
  writers: readonly CurrentRepositoryWriterPolicy[];
}>;

type CoreReason =
  | "bad_signature"
  | "nip01_raw_mismatch"
  | "unknown_major_version"
  | "version_stamp_invalid";

type CoreWireEnvelopeInput = {
  event: NostrSignedEvent;
  nip01_raw: string;
  stamp_policy: "required" | "optional" | "forbidden";
};

type VerifiedCoreWireEnvelope =
  | { verdict: "accept"; event: NostrSignedEvent }
  | { verdict: "reject"; reason_code: CoreReason };

function verifyCoreWireEnvelope(input: CoreWireEnvelopeInput): VerifiedCoreWireEnvelope {
  if (input.nip01_raw !== canonicalNip01(input.event)) {
    return { verdict: "reject", reason_code: "nip01_raw_mismatch" };
  }
  const event = snapshotAndVerifyNostrEvent(input.event);
  if (event === null) return { verdict: "reject", reason_code: "bad_signature" };
  const stamps = event.tags.filter((tag) => tag[0] === "spec_version");
  if (stamps.length === 1 && stamps[0]!.length === 2) {
    try {
      const remote = parseFamilyVersion(stamps[0]![1]!);
      const localMajor = Number.parseInt(FAMILY_VERSION.split(".")[0]!, 10);
      const remoteMajor = Number.parseInt(remote.split(".")[0]!, 10);
      if (remoteMajor > localMajor) {
        return { verdict: "reject", reason_code: "unknown_major_version" };
      }
    } catch {
      return { verdict: "reject", reason_code: "version_stamp_invalid" };
    }
  }
  if (
    input.stamp_policy === "forbidden"
      ? stamps.length !== 0
      : input.stamp_policy === "required"
        ? stamps.length !== 1 || stamps[0]!.length !== 2 || stamps[0]![1] !== QUALIFIED_VERSION
        : stamps.length > 1 || (stamps.length === 1 && (stamps[0]!.length !== 2 || stamps[0]![1] !== QUALIFIED_VERSION))
  ) return { verdict: "reject", reason_code: "version_stamp_invalid" };
  return { verdict: "accept", event };
}

/** Verify the exact stored signing bytes and the current family stamp policy. */
export function validateCoreWireEnvelope(input: CoreWireEnvelopeInput):
  | { verdict: "accept"; event_id: string }
  | { verdict: "reject"; reason_code: CoreReason } {
  const verified = verifyCoreWireEnvelope(input);
  return verified.verdict === "reject"
    ? verified
    : { verdict: "accept", event_id: verified.event.id };
}

/** Verify one persona-scoped Core event against the exact active key. */
export function validateCorePersonaSignedEvent(
  input: CoreWireEnvelopeInput & { active_persona_key: string },
):
  | { verdict: "accept"; event_id: string }
  | { verdict: "reject"; reason_code: CoreReason | "delegation_mismatch" } {
  const verified = verifyCoreWireEnvelope(input);
  if (verified.verdict === "reject") return verified;
  if (verified.event.pubkey !== input.active_persona_key) {
    return { verdict: "reject", reason_code: "delegation_mismatch" };
  }
  return { verdict: "accept", event_id: verified.event.id };
}

type OperationalInput =
  | { operation: "resolve-host"; host: string; resolver: "clearnet" | "tor" }
  | { operation: "start-strict-mode"; tor_egress: boolean; explicit_user_choice: boolean }
  | { operation: "read-friend-cache"; owner_signed: boolean; content_class: "nostr" | "keri" }
  | { operation: "relay-profile"; vanilla_nip01_unchanged: boolean }
  | { operation: "publish-surface"; config_rid: string; values: readonly string[] };

/** Evaluate Core's non-cryptographic transport and disclosure fail-closed boundaries. */
export function evaluateCoreOperationalBoundary(input: OperationalInput):
  | { verdict: "accept" }
  | { verdict: "reject"; reason_code: "onion_dns_leak" | "strict_mode_tor_disabled" | "unauthorized_cache_content" | "relay_profile_mutation" | "config_rid_advertised" } {
  if (input.operation === "resolve-host") {
    return input.host.toLowerCase().endsWith(".onion") && input.resolver !== "tor"
      ? { verdict: "reject", reason_code: "onion_dns_leak" }
      : { verdict: "accept" };
  }
  if (input.operation === "start-strict-mode") {
    return !input.tor_egress && !input.explicit_user_choice
      ? { verdict: "reject", reason_code: "strict_mode_tor_disabled" }
      : { verdict: "accept" };
  }
  if (input.operation === "read-friend-cache") {
    return !input.owner_signed || input.content_class !== "nostr"
      ? { verdict: "reject", reason_code: "unauthorized_cache_content" }
      : { verdict: "accept" };
  }
  if (input.operation === "relay-profile") {
    return input.vanilla_nip01_unchanged
      ? { verdict: "accept" }
      : { verdict: "reject", reason_code: "relay_profile_mutation" };
  }
  return input.values.includes(input.config_rid)
    ? { verdict: "reject", reason_code: "config_rid_advertised" }
    : { verdict: "accept" };
}

export function validateOrganizationMemberAddition(input: {
  member_kel_authorized: boolean;
  org_admin_threshold_authorized: boolean;
}): { verdict: "accept" } | { verdict: "reject"; reason_code: "org_member_add_unauthorized" } {
  return input.member_kel_authorized && input.org_admin_threshold_authorized
    ? { verdict: "accept" }
    : { verdict: "reject", reason_code: "org_member_add_unauthorized" };
}

export function validateRoleDelegation(input: {
  namespace: string;
  registered_namespace: string;
  role_id: string;
  key_proof_valid: boolean;
}):
  | { verdict: "accept"; role_id: string }
  | { verdict: "reject"; reason_code: "role-delegation-address-invalid" | "role-delegation-key-proof-invalid" } {
  if (
    input.namespace !== input.registered_namespace
    || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(input.role_id)
  ) return { verdict: "reject", reason_code: "role-delegation-address-invalid" };
  if (!input.key_proof_valid) {
    return { verdict: "reject", reason_code: "role-delegation-key-proof-invalid" };
  }
  return { verdict: "accept", role_id: input.role_id };
}
