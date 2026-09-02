/**
 * Legacy pure-policy projections used by authored vector topics. These
 * functions do not verify exact Marmot bytes, authenticate a current Core
 * writer binding, perform a repository append, or establish durable readback.
 * Runtime archival evidence uses marmot-archive-retention-authority.ts.
 */
export type MarmotRoutingBindingInput = Readonly<{
  active_administrator: string;
  commit_author: string;
  canonical_h: string;
  binding_h: string;
  canonical_rid: string;
  binding_rid: string;
  canonical_genesis_digest: string;
  binding_genesis_digest: string;
  binding_digests: readonly string[];
  requested_writer_ref: string;
  authorized_writer_refs: readonly string[];
}>;

export type MarmotRoutingBindingDecision =
  | {
      verdict: "accept";
      normalized: { h: string; private_rid: string; writer_ref: string };
    }
  | {
      verdict: "reject";
      reason_code:
        | "marmot-routing-binding-invalid"
        | "marmot-routing-equivocation"
        | "marmot-unauthorized-ref";
    };

const HEX_32 = /^[0-9a-f]{64}$/;
const PRIVATE_RID = /^rad:z[1-9A-HJ-NP-Za-km-z]+$/;
const WRITER_REF = /^refs\/xyz\.heterodyne\.marmot\/(?:writers|relays)\/[A-Za-z0-9._-]+$/;

/**
 * Validates the security-bearing tuple that joins canonical Marmot routing
 * state to one Radicle repository generation and its authorized writer union.
 */
export function evaluateMarmotRoutingBinding(
  input: MarmotRoutingBindingInput,
): MarmotRoutingBindingDecision {
  if (
    !HEX_32.test(input.active_administrator)
    || input.commit_author !== input.active_administrator
    || input.canonical_h.length === 0
    || input.binding_h !== input.canonical_h
    || !PRIVATE_RID.test(input.canonical_rid)
    || input.binding_rid !== input.canonical_rid
    || !HEX_32.test(input.canonical_genesis_digest)
    || input.binding_genesis_digest !== input.canonical_genesis_digest
    || input.binding_digests.length === 0
    || input.binding_digests.some((digest) => !HEX_32.test(digest))
    || !WRITER_REF.test(input.requested_writer_ref)
    || input.authorized_writer_refs.length === 0
    || input.authorized_writer_refs.some((ref) => !WRITER_REF.test(ref))
    || new Set(input.authorized_writer_refs).size !== input.authorized_writer_refs.length
  ) {
    return { verdict: "reject", reason_code: "marmot-routing-binding-invalid" };
  }
  if (new Set(input.binding_digests).size !== 1) {
    return { verdict: "reject", reason_code: "marmot-routing-equivocation" };
  }
  if (!input.authorized_writer_refs.includes(input.requested_writer_ref)) {
    return { verdict: "reject", reason_code: "marmot-unauthorized-ref" };
  }
  return {
    verdict: "accept",
    normalized: {
      h: input.canonical_h,
      private_rid: input.canonical_rid,
      writer_ref: input.requested_writer_ref,
    },
  };
}

export type MarmotDurabilityInput = Readonly<{
  signed_event_bytes_preserved: boolean;
  encrypted_media_bytes_preserved: boolean;
  durable_local: boolean;
  configured_host_acceptances: number;
  acknowledgement_requested: boolean;
}>;

/** Projects claimed durability; it cannot mint an archival acknowledgement. */
export function evaluateMarmotDurability(input: MarmotDurabilityInput):
  | { verdict: "accept"; durable_ack: boolean; exact_bytes: true }
  | { verdict: "reject"; reason_code: "marmot-premature-ack" } {
  const exactBytes = input.signed_event_bytes_preserved
    && input.encrypted_media_bytes_preserved;
  const durable = exactBytes
    && input.durable_local
    && Number.isSafeInteger(input.configured_host_acceptances)
    && input.configured_host_acceptances >= 1;
  if (input.acknowledgement_requested && !durable) {
    return { verdict: "reject", reason_code: "marmot-premature-ack" };
  }
  return { verdict: "accept", durable_ack: input.acknowledgement_requested, exact_bytes: true };
}

export type MarmotRetentionInput = Readonly<{
  retention_expired: boolean;
  independent_git_objects_possible: boolean;
}>;

/**
 * Projects retention policy without mutating presentation state or claiming
 * deletion of independently held Git objects, clones, exports, or backups.
 */
export function evaluateMarmotRetention(input: MarmotRetentionInput): Readonly<{
  verdict: "accept";
  stop_advertising: boolean;
  stop_replication: boolean;
  erasure_guarantee: false;
}> {
  return {
    verdict: "accept",
    stop_advertising: input.retention_expired,
    stop_replication: input.retention_expired,
    erasure_guarantee: false,
  };
}
