import { describe, expect, it } from "vitest";
import {
  evaluateMarmotDurability,
  evaluateMarmotRetention,
  evaluateMarmotRoutingBinding,
} from "./marmot-routing-policy.js";

describe("current Marmot Radicle policy boundaries", () => {
  it("binds one canonical administrator routing commit and authorized writer union", () => {
    const binding = {
      active_administrator: "11".repeat(32),
      commit_author: "11".repeat(32),
      canonical_h: "routing-generation-a",
      binding_h: "routing-generation-a",
      canonical_rid: "rad:zCurrentMarmotRoute",
      binding_rid: "rad:zCurrentMarmotRoute",
      canonical_genesis_digest: "22".repeat(32),
      binding_genesis_digest: "22".repeat(32),
      binding_digests: ["33".repeat(32)],
      requested_writer_ref: "refs/xyz.heterodyne.marmot/writers/a",
      authorized_writer_refs: ["refs/xyz.heterodyne.marmot/writers/a"],
    };
    expect(evaluateMarmotRoutingBinding(binding)).toEqual({
      verdict: "accept",
      normalized: {
        h: binding.canonical_h,
        private_rid: binding.canonical_rid,
        writer_ref: binding.requested_writer_ref,
      },
    });
    expect(evaluateMarmotRoutingBinding({
      ...binding,
      binding_genesis_digest: "44".repeat(32),
    })).toEqual({ verdict: "reject", reason_code: "marmot-routing-binding-invalid" });
    expect(evaluateMarmotRoutingBinding({
      ...binding,
      binding_digests: ["33".repeat(32), "44".repeat(32)],
    })).toEqual({ verdict: "reject", reason_code: "marmot-routing-equivocation" });
    expect(evaluateMarmotRoutingBinding({
      ...binding,
      requested_writer_ref: "refs/xyz.heterodyne.marmot/writers/other",
    })).toEqual({ verdict: "reject", reason_code: "marmot-unauthorized-ref" });
  });

  it("requires exact-byte durability before acknowledgement and disclaims erasure", () => {
    expect(evaluateMarmotDurability({
      signed_event_bytes_preserved: true,
      encrypted_media_bytes_preserved: true,
      durable_local: true,
      configured_host_acceptances: 1,
      acknowledgement_requested: true,
    })).toEqual({ verdict: "accept", durable_ack: true, exact_bytes: true });
    expect(evaluateMarmotDurability({
      signed_event_bytes_preserved: true,
      encrypted_media_bytes_preserved: true,
      durable_local: false,
      configured_host_acceptances: 0,
      acknowledgement_requested: true,
    })).toEqual({ verdict: "reject", reason_code: "marmot-premature-ack" });
    expect(evaluateMarmotRetention({
      retention_expired: true,
      independent_git_objects_possible: true,
    })).toEqual({
      verdict: "accept",
      stop_advertising: true,
      stop_replication: true,
      erasure_guarantee: false,
    });
  });
});
