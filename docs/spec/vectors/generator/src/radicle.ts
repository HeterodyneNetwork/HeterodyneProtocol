import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { verifyEventSignature, type NostrSignedEvent } from "./nostr.js";

// Multicodec prefix for an Ed25519 public key (varint 0xed 0x01), per the
// did:key method and the multicodec table.
const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);

export function ed25519PublicKey(secretHex: string): string {
  return bytesToHex(ed25519.getPublicKey(hexToBytes(secretHex)));
}

export function ed25519Sign(message: string, secretHex: string): string {
  return bytesToHex(ed25519.sign(utf8Bytes(message), hexToBytes(secretHex)));
}

export function ed25519Verify(sigHex: string, message: string, pubHex: string): boolean {
  return ed25519.verify(hexToBytes(sigHex), utf8Bytes(message), hexToBytes(pubHex));
}

// did:key for an Ed25519 public key: multibase base58btc ("z" prefix) of the
// multicodec-prefixed raw public key.
export function didKeyFromEd25519(pubHex: string): string {
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + 32);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(hexToBytes(pubHex), ED25519_MULTICODEC.length);
  return `did:key:z${base58.encode(prefixed)}`;
}

// A deterministic fixture RID. Real Radicle RIDs are derived from a live
// repository; these are stable base58btc fixture identifiers of the shape
// `rad:z...` so vectors can reference an npub->RID binding without a repo.
export function fixtureRid(seed: string): string {
  const digest = sha256(utf8Bytes(`heterodyne-fixture-rid|${seed}`)).slice(0, 20);
  return `rad:z${base58.encode(digest)}`;
}

// Binding payload signed by BOTH the epoch key (via the outer Nostr sig over
// the tags) AND the NID's Ed25519 nid_proof for a kind:31001 NID delegation.
// The serialization is pinned by spec section 3.3.1.
export function nidBindingPayload(npubHex: string, nidDidKey: string): string {
  return `heterodyne-nid-binding-v1|${npubHex}|${nidDidKey}|radicle-nid-delegation`;
}

// Payload signed by the advertised NID's Ed25519 nid_proof for a kind:31010
// node/repo advertisement (section 7.0). The spec fixes the bound fields (RID,
// NID, endpoint, expiry, current canonical repo head) and defers the exact
// serialization to this vector; the domain-separated form below is that
// serialization.
export function nodeAdvertPayload(
  rid: string,
  nidDidKey: string,
  endpoint: string,
  expiry: number,
  repoHead: string,
): string {
  return `heterodyne-node-advert-v1|${rid}|${nidDidKey}|${endpoint}|${expiry}|${repoHead}`;
}

export type RepositoryGraphFetch =
  | { status: "available"; reachable_oids: string[] }
  | { status: "transport_unavailable" };

export type NodeAdvertisementValidation =
  | {
      status: "accepted";
      rid: string;
      endpoint: string;
      repo_head: string;
      expiry: number;
    }
  | {
      status: "rejected";
      failure:
        | "bad_signature"
        | "node_advert_shape_invalid"
        | "repo_head_invalid"
        | "nid_proof_invalid"
        | "expired"
        | "clock_skew"
        | "clock_uncertain"
        | "expiry_invalid"
        | "lifetime_exceeded"
        | "repo_head_unserved";
    }
  | {
      status: "provisional";
      failure: "transport_unavailable";
      retryable: true;
    };

export function validateNodeAdvertisement(
  event: NostrSignedEvent,
  context: { now: number; clock_uncertainty_seconds?: number; graph_fetch: RepositoryGraphFetch },
): NodeAdvertisementValidation {
  if (!verifyEventSignature(event)) {
    return { status: "rejected", failure: "bad_signature" };
  }
  if (event.kind !== 31010 || event.content !== "") {
    return { status: "rejected", failure: "node_advert_shape_invalid" };
  }

  const single = (name: string): string[] | null => {
    const matches = event.tags.filter((tag) => tag[0] === name);
    return matches.length === 1 && matches[0].length === 2 ? matches[0] : null;
  };
  const d = single("d");
  const heterodyne = single("heterodyne");
  const rid = single("rid");
  const nid = single("nid");
  const endpoint = single("endpoint");
  const expiryTag = single("expiry");
  const proof = single("nid_proof");
  const repoHead = single("repo_head");
  if (
    d === null ||
    heterodyne?.[1] !== "node_advert" ||
    rid === null ||
    nid === null ||
    endpoint === null ||
    expiryTag === null ||
    proof === null
  ) {
    return { status: "rejected", failure: "node_advert_shape_invalid" };
  }
  if (repoHead === null || !/^[0-9a-f]{40}$/.test(repoHead[1])) {
    return { status: "rejected", failure: "repo_head_invalid" };
  }
  if (d[1] !== rid[1] || endpoint[1].length === 0) {
    return { status: "rejected", failure: "node_advert_shape_invalid" };
  }

  const expiry = Number(expiryTag[1]);
  if (
    !Number.isSafeInteger(expiry) ||
    expiry < 0 ||
    String(expiry) !== expiryTag[1]
  ) {
    return { status: "rejected", failure: "node_advert_shape_invalid" };
  }
  if (expiry <= event.created_at) {
    return { status: "rejected", failure: "expiry_invalid" };
  }
  if (expiry - event.created_at > 86_400) {
    return { status: "rejected", failure: "lifetime_exceeded" };
  }

  const nidPublicKey = ed25519KeyFromDidKey(nid[1]);
  if (
    nidPublicKey === null ||
    !/^[0-9a-f]{128}$/.test(proof[1]) ||
    !safeEd25519Verify(
      proof[1],
      nodeAdvertPayload(rid[1], nid[1], endpoint[1], expiry, repoHead[1]),
      nidPublicKey,
    )
  ) {
    return { status: "rejected", failure: "nid_proof_invalid" };
  }
  if (expiry <= context.now) {
    return { status: "rejected", failure: "expired" };
  }
  if ((context.clock_uncertainty_seconds ?? 0) > 300) {
    return { status: "rejected", failure: "clock_uncertain" };
  }
  if (Math.abs(event.created_at - context.now) > 300) {
    return { status: "rejected", failure: "clock_skew" };
  }
  if (context.graph_fetch.status === "transport_unavailable") {
    return {
      status: "provisional",
      failure: "transport_unavailable",
      retryable: true,
    };
  }
  if (!context.graph_fetch.reachable_oids.includes(repoHead[1])) {
    return { status: "rejected", failure: "repo_head_unserved" };
  }
  return {
    status: "accepted",
    rid: rid[1],
    endpoint: endpoint[1],
    repo_head: repoHead[1],
    expiry,
  };
}

function ed25519KeyFromDidKey(value: string): string | null {
  if (!value.startsWith("did:key:z")) return null;
  try {
    const decoded = base58.decode(value.slice("did:key:z".length));
    if (
      decoded.length !== ED25519_MULTICODEC.length + 32 ||
      decoded[0] !== ED25519_MULTICODEC[0] ||
      decoded[1] !== ED25519_MULTICODEC[1]
    ) {
      return null;
    }
    return bytesToHex(decoded.slice(ED25519_MULTICODEC.length));
  } catch {
    return null;
  }
}

function safeEd25519Verify(sigHex: string, message: string, pubHex: string): boolean {
  try {
    return ed25519Verify(sigHex, message, pubHex);
  } catch {
    return false;
  }
}
