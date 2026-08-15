import { getEventId } from "./nostr.js";
import type { NostrUnsignedEvent } from "./nostr.js";

// The kel_head tag names the latest accepted KEL event the signer had
// accepted at signing time: ["kel_head", "<64-hex event id>", "<decimal seq>"]
// (spec §3.0, handling in §4.5.1). It is carried exactly once on every
// epoch-key-signed Heterodyne event per the §3.0 applicability matrix.
export type KelHead = { id: string; seq: number };

export type RotationReceipt = {
  witness_id: string;
  scheme: "bip340" | "did:key" | "atproto";
  sig: string;
};

// A minimal Core KERI inception (kind:31002): cold-root-authored, s=0,
// committing the initial epoch key, with no witnesses and the required owner
// stamp. The authoritative ceremony timestamp is retained exactly.
export function inceptionTemplate(
  coldRootPubkey: string,
  epochPubkey: string,
  createdAt: number,
): NostrUnsignedEvent {
  return {
    pubkey: coldRootPubkey,
    created_at: createdAt,
    kind: 31002,
    tags: [
      ["d", ""],
      ["heterodyne", "keri_inception"],
      ["p", coldRootPubkey],
      ["s", "0"],
      ["epoch_key", epochPubkey],
      ["spec_version", "heterodyne/0.5.0"],
    ],
    content: "",
  };
}

// Exact Core 0.5.0 rotation content. Receipt order is semantically relevant:
// callers must supply the actual wire receipts in ascending witness_id order.
export function rotationContent(receipts: RotationReceipt[]): string {
  let previousWitnessId: string | undefined;
  for (const receipt of receipts) {
    if (
      typeof receipt.witness_id !== "string"
      || receipt.witness_id.length === 0
      || !["bip340", "did:key", "atproto"].includes(receipt.scheme)
      || !/^[0-9a-f]{128}$/u.test(receipt.sig)
    ) {
      throw new Error("invalid KEL rotation receipt");
    }
    if (
      previousWitnessId !== undefined
      && Buffer.compare(Buffer.from(previousWitnessId, "utf8"), Buffer.from(receipt.witness_id, "utf8")) > 0
    ) {
      throw new Error("KEL rotation receipts are not ordered by witness_id");
    }
    previousWitnessId = receipt.witness_id;
  }
  return JSON.stringify({ spec_version: "heterodyne/0.5.0", receipts });
}

export function inceptionHead(
  coldRootPubkey: string,
  epochPubkey: string,
  createdAt: number,
): KelHead {
  return { id: getEventId(inceptionTemplate(coldRootPubkey, epochPubkey, createdAt)), seq: 0 };
}

export function kelHeadTag(head: KelHead): string[] {
  return ["kel_head", head.id, String(head.seq)];
}

// Append the kel_head tag to an event's tags. Producers append it last; the
// §3.0.1 canonical serialization preserves producer tag order.
export function withKelHead(tags: string[][], head: KelHead): string[][] {
  return [...tags, kelHeadTag(head)];
}
