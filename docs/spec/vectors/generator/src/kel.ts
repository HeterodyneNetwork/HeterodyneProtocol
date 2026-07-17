import { getEventId } from "./nostr.js";
import type { NostrUnsignedEvent } from "./nostr.js";

// The ADR-032 kel_head tag names the latest accepted KEL event the signer had
// accepted at signing time: ["kel_head", "<64-hex event id>", "<decimal seq>"]
// (spec §3.0, handling in §4.5.1). It is carried exactly once on every
// epoch-key-signed Heterodyne event per the §3.0 applicability matrix.
export type KelHead = { id: string; seq: number };

// A minimal well-formed KERI inception (kind:31002) template per §3.5.1: cold-
// root-authored, s=0, committing the initial epoch key, with no witnesses (so
// no threshold tag). Its id is the KEL head every kel_head references for a
// persona whose KEL has only its inception. The id is over the unsigned NIP-01
// serialization (§3.0.1), so the signature is not needed to compute it.
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
    ],
    content: "",
  };
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
