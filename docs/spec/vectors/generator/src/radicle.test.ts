import { ed25519 } from "@noble/curves/ed25519";
import { base58 } from "@scure/base";
import { describe, expect, it } from "vitest";
import { hexToBytes, utf8Bytes } from "./hex.js";
import {
  didKeyFromEd25519,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  nidBindingPayload,
  nodeAdvertPayload,
  validateNodeAdvertisement,
} from "./radicle.js";
import { signEvent } from "./nostr.js";

const AUX_RAND = "00".repeat(32);
const NODE_SECRET = "21".padStart(64, "0");
const NID_SECRET = "22".padStart(64, "0");
const RID = "rad:zFixtureRid";
const ENDPOINT = "wss://node.example/relay";
const EXPIRY = 1_800_000_000;
const REPO_HEAD = "ab".repeat(20);

async function nodeAdvertisement(
  mutateTags: (tags: string[][]) => string[][] = (tags) => tags,
  createdAt = EXPIRY - 100,
) {
  const nid = didKeyFromEd25519(ed25519PublicKey(NID_SECRET));
  const proof = ed25519Sign(
    nodeAdvertPayload(RID, nid, ENDPOINT, EXPIRY, REPO_HEAD),
    NID_SECRET,
  );
  return signEvent({
    secretKey: NODE_SECRET,
    created_at: createdAt,
    kind: 31010,
    tags: mutateTags([
      ["d", RID],
      ["heterodyne", "node_advert"],
      ["rid", RID],
      ["nid", nid],
      ["endpoint", ENDPOINT],
      ["repo_head", REPO_HEAD],
      ["expiry", String(EXPIRY)],
      ["nid_proof", proof],
      ["spec_version", "heterodyne/0.5.0"],
    ]),
    content: "",
    auxRand: AUX_RAND,
  });
}

describe("Radicle / NID helpers", () => {
  it("encodes an Ed25519 did:key as multibase base58btc of the multicodec-prefixed key", () => {
    // RFC 8032 Ed25519 test-1 public key.
    const pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const didKey = didKeyFromEd25519(pub);

    expect(didKey.startsWith("did:key:z6Mk")).toBe(true);
    const decoded = base58.decode(didKey.slice("did:key:z".length));
    expect(decoded[0]).toBe(0xed);
    expect(decoded[1]).toBe(0x01);
    expect(Array.from(decoded.slice(2))).toEqual(Array.from(hexToBytes(pub)));
  });

  it("signs and verifies deterministically with Ed25519 (pure EdDSA)", () => {
    const secret = "01".padStart(64, "0");
    const pub = ed25519PublicKey(secret);
    const message = "heterodyne-nid-binding-v1|npub|nid|radicle-nid-delegation";

    const sig = ed25519Sign(message, secret);
    expect(sig).toHaveLength(128);
    expect(ed25519Sign(message, secret)).toBe(sig);
    expect(ed25519Verify(sig, message, pub)).toBe(true);
    expect(ed25519.verify(hexToBytes(sig), utf8Bytes(message), hexToBytes(pub))).toBe(true);
  });

  it("pins the domain-separated binding payloads", () => {
    expect(nidBindingPayload("aa".repeat(32), "did:key:z6MkExample")).toBe(
      "heterodyne-nid-binding-v1|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|did:key:z6MkExample|radicle-nid-delegation",
    );
    expect(nodeAdvertPayload("rad:zRID", "did:key:z6MkNid", "wss://n.example/relay", 1767312000, "abcd")).toBe(
      "heterodyne-node-advert-v1|rad:zRID|did:key:z6MkNid|wss://n.example/relay|1767312000|abcd",
    );
  });

  it("accepts a dual-signed advertisement only when a successful graph fetch contains its exact head", async () => {
    const event = await nodeAdvertisement();
    expect(validateNodeAdvertisement(event, {
      now: EXPIRY - 1,
      graph_fetch: { status: "available", reachable_oids: [REPO_HEAD, "cd".repeat(20)] },
    })).toEqual({
      status: "accepted",
      rid: RID,
      endpoint: ENDPOINT,
      repo_head: REPO_HEAD,
      expiry: EXPIRY,
    });
    expect(validateNodeAdvertisement(event, {
      now: EXPIRY - 1,
      graph_fetch: { status: "available", reachable_oids: ["cd".repeat(20)] },
    })).toEqual({ status: "rejected", failure: "repo_head_unserved" });
  });

  it("treats transport unavailability as provisional instead of proving exclusion", async () => {
    const event = await nodeAdvertisement();
    expect(validateNodeAdvertisement(event, {
      now: EXPIRY - 1,
      graph_fetch: { status: "transport_unavailable" },
    })).toEqual({
      status: "provisional",
      failure: "transport_unavailable",
      retryable: true,
    });
  });

  it("enforces initial skew, lifetime, expiry ordering, and known clock uncertainty", async () => {
    const event = await nodeAdvertisement();
    expect(validateNodeAdvertisement(event, {
      now: event.created_at - 301,
      clock_uncertainty_seconds: 0,
      graph_fetch: { status: "available", reachable_oids: [REPO_HEAD] },
    })).toEqual({ status: "rejected", failure: "clock_skew" });
    expect(validateNodeAdvertisement(event, {
      now: event.created_at,
      clock_uncertainty_seconds: 301,
      graph_fetch: { status: "available", reachable_oids: [REPO_HEAD] },
    })).toEqual({ status: "rejected", failure: "clock_uncertain" });
  });

  it("retains a previously accepted advertisement without reapplying issuance skew", async () => {
    const event = await nodeAdvertisement((tags) => tags, EXPIRY - 20_000);
    expect(validateNodeAdvertisement(event, {
      now: event.created_at + 10_000,
      previously_accepted_event_id: event.id,
      graph_fetch: { status: "available", reachable_oids: [REPO_HEAD] },
    })).toMatchObject({ status: "accepted", repo_head: REPO_HEAD });
  });

  it("does not let a provisional prior observation bypass first-acceptance skew", async () => {
    const event = await nodeAdvertisement((tags) => tags, EXPIRY - 20_000);
    expect(validateNodeAdvertisement(event, {
      now: event.created_at + 10_000,
      graph_fetch: { status: "available", reachable_oids: [REPO_HEAD] },
    })).toEqual({ status: "rejected", failure: "clock_skew" });
    expect(validateNodeAdvertisement(event, {
      now: event.created_at + 10_000,
      previously_accepted_event_id: "00".repeat(32),
      graph_fetch: { status: "available", reachable_oids: [REPO_HEAD] },
    })).toEqual({ status: "rejected", failure: "clock_skew" });
  });

  it.each([
    ["missing", (tags: string[][]) => tags.filter(([name]) => name !== "repo_head")],
    ["duplicate", (tags: string[][]) => [...tags, ["repo_head", REPO_HEAD]]],
    ["malformed", (tags: string[][]) => tags.map((tag) =>
      tag[0] === "repo_head" ? ["repo_head", REPO_HEAD.toUpperCase()] : tag)],
  ])("rejects a %s canonical repo_head tag before graph lookup", async (_name, mutateTags) => {
    const event = await nodeAdvertisement(mutateTags);
    expect(validateNodeAdvertisement(event, {
      now: EXPIRY - 1,
      graph_fetch: { status: "available", reachable_oids: [REPO_HEAD] },
    })).toEqual({ status: "rejected", failure: "repo_head_invalid" });
  });

  it("rejects a head-tag substitution because the NID proof binds the exact head", async () => {
    const event = await nodeAdvertisement((tags) => tags.map((tag) =>
      tag[0] === "repo_head" ? ["repo_head", "cd".repeat(20)] : tag));
    expect(validateNodeAdvertisement(event, {
      now: EXPIRY - 1,
      graph_fetch: { status: "available", reachable_oids: ["cd".repeat(20)] },
    })).toEqual({ status: "rejected", failure: "nid_proof_invalid" });
  });
});
