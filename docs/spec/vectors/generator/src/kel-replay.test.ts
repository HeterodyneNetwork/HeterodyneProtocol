import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes, utf8Bytes } from "./hex.js";
import { inceptionTemplate, rotationContent } from "./kel.js";
import {
  parseKelCandidate,
  replayKel,
  type KelWireCandidate,
} from "./kel-replay.js";
import {
  canonicalNip01,
  getPublicKey,
  signEvent,
  type NostrUnsignedEvent,
} from "./nostr.js";

const AUX_RAND = "00".repeat(32);
const T = 1767225600;
const secret = (n: number) => n.toString(16).padStart(64, "0");
const COLD_SECRET = secret(1);
const EPOCH_ONE_SECRET = secret(2);
const EPOCH_TWO_SECRET = secret(3);
const EPOCH_THREE_SECRET = secret(4);
const WITNESS_SECRET = secret(5);
const COLD = getPublicKey(COLD_SECRET);
const EPOCH_ONE = getPublicKey(EPOCH_ONE_SECRET);
const EPOCH_TWO = getPublicKey(EPOCH_TWO_SECRET);
const EPOCH_THREE = getPublicKey(EPOCH_THREE_SECRET);
const WITNESS = getPublicKey(WITNESS_SECRET);

async function candidate(
  unsigned: Omit<NostrUnsignedEvent, "pubkey">,
  controllerSecret: string,
  source: KelWireCandidate["source"] = "relay",
  observedOrder = 0,
): Promise<KelWireCandidate> {
  const signed = await signEvent({
    ...unsigned,
    secretKey: controllerSecret,
    auxRand: AUX_RAND,
  });
  return {
    nip01_raw: canonicalNip01(signed),
    id: signed.id,
    sig: signed.sig,
    source,
    observed_order: observedOrder,
  };
}

async function inception(options?: {
  witness?: string;
  threshold?: number;
}): Promise<KelWireCandidate> {
  const template = inceptionTemplate(COLD, EPOCH_ONE, T);
  const tags = [...template.tags.slice(0, -1)];
  if (options?.witness !== undefined) {
    tags.push(["witness", options.witness, "1"]);
    tags.push(["threshold", String(options.threshold ?? 1)]);
  }
  tags.push(["spec_version", "heterodyne/0.5.0"]);
  return candidate(
    { created_at: T, kind: 31002, tags, content: "" },
    COLD_SECRET,
    "repo",
  );
}

async function committedRotation(
  prior: KelWireCandidate,
  epochKey: string,
  observedOrder = 0,
): Promise<KelWireCandidate> {
  return candidate(
    {
      created_at: T + 60,
      kind: 31003,
      tags: [
        ["d", "1"],
        ["heterodyne", "keri_rotation"],
        ["p", COLD],
        ["s", "1"],
        ["prior_digest", prior.id],
        ["strategy", "committed"],
        ["epoch_key", epochKey],
      ],
      content: rotationContent([]),
    },
    COLD_SECRET,
    "relay",
    observedOrder,
  );
}

async function noneRotation(
  prior: KelWireCandidate,
  receipts: Array<{ witness_id: string; scheme: "bip340"; sig: string }>,
  options: {
    epochKey?: string;
    source?: KelWireCandidate["source"];
    observedOrder?: number;
  } = {},
): Promise<KelWireCandidate> {
  return candidate(
    {
      created_at: T + 60,
      kind: 31003,
      tags: [
        ["d", "1"],
        ["heterodyne", "keri_rotation"],
        ["p", COLD],
        ["s", "1"],
        ["prior_digest", prior.id],
        ["strategy", "none"],
        ["epoch_key", options.epochKey ?? EPOCH_TWO],
      ],
      content: rotationContent(receipts),
    },
    EPOCH_ONE_SECRET,
    options.source,
    options.observedOrder,
  );
}

async function witnessedNoneRotation(
  prior: KelWireCandidate,
  epochKey: string,
  source: KelWireCandidate["source"],
  observedOrder: number,
): Promise<KelWireCandidate> {
  const unsigned: NostrUnsignedEvent = {
    pubkey: EPOCH_ONE,
    created_at: T + 60,
    kind: 31003,
    tags: [
      ["d", "1"],
      ["heterodyne", "keri_rotation"],
      ["p", COLD],
      ["s", "1"],
      ["prior_digest", prior.id],
      ["strategy", "none"],
      ["epoch_key", epochKey],
    ],
    content: "",
  };
  const digest = sha256(utf8Bytes(canonicalNip01(unsigned)));
  const signature = bytesToHex(
    schnorr.sign(digest, hexToBytes(WITNESS_SECRET), AUX_RAND),
  );
  return noneRotation(
    prior,
    [{ witness_id: WITNESS, scheme: "bip340", sig: signature }],
    { epochKey, source, observedOrder },
  );
}

describe("independent exact-byte KEL parser and replayer", () => {
  it("requires the Core owner stamp on current inception bytes", async () => {
    const stamped = await inception();
    expect(parseKelCandidate(stamped).event.tags.at(-1)).toEqual([
      "spec_version",
      "heterodyne/0.5.0",
    ]);
    expect(replayKel([stamped])).toMatchObject({
      status: "accepted",
      head: { id: stamped.id, seq: 0 },
      state: {
        cold_root: COLD,
        s: 0,
        epoch_key: EPOCH_ONE,
        witnesses: [],
        threshold: 0,
        producing_event_id: stamped.id,
      },
      rejected: [],
    });

    const legacyTemplate = inceptionTemplate(COLD, EPOCH_ONE, T);
    const unstamped = await candidate(
      {
        created_at: T,
        kind: 31002,
        tags: legacyTemplate.tags.slice(0, -1),
        content: "",
      },
      COLD_SECRET,
    );
    const result = replayKel([unstamped]);
    expect(result.head).toBeNull();
    expect(result.rejected).toContainEqual(
      expect.objectContaining({
        id: unstamped.id,
        error: "missing_or_invalid_spec_version",
      }),
    );
  });

  it("accepts exact rotation content and a witness-free committed rotation", async () => {
    const inc = await inception();
    const rotation = await committedRotation(inc, EPOCH_TWO);
    const result = replayKel([rotation, inc]);

    expect(rotationContent([])).toBe(
      '{"spec_version":"heterodyne/0.5.0","receipts":[]}',
    );
    expect(result.status).toBe("accepted");
    expect(result.head).toEqual({ id: rotation.id, seq: 1 });
    expect(result.entries.map((entry) => entry.nip01_raw)).toEqual([
      inc.nip01_raw,
      rotation.nip01_raw,
    ]);
    expect(result.state).toMatchObject({
      cold_root: COLD,
      s: 1,
      epoch_key: EPOCH_TWO,
      witnesses: [],
      threshold: 0,
      producing_event_id: rotation.id,
    });
  });

  it("deduplicates the same accepted event fetched from both repo and relay", async () => {
    const inc = await inception();
    const rotation = await committedRotation(inc, EPOCH_TWO);
    const result = replayKel([
      { ...inc, source: "relay", observed_order: 9 },
      inc,
      rotation,
      { ...rotation, source: "repo", observed_order: 10 },
    ]);

    expect(result).toMatchObject({
      status: "accepted",
      duplicity: false,
      head: { id: rotation.id, seq: 1 },
    });
    expect(result.entries.map(({ event_id }) => event_id)).toEqual([
      inc.id,
      rotation.id,
    ]);
  });

  it("accepts a cold-root committed rotation without receipts for a witnessed persona", async () => {
    const inc = await inception({ witness: WITNESS, threshold: 1 });
    const rotation = await committedRotation(inc, EPOCH_TWO);
    expect(replayKel([inc, rotation])).toMatchObject({
      status: "accepted",
      head: { id: rotation.id, seq: 1 },
      rejected: [],
    });
  });

  it("rejects a rotation whose content is not the exact compact receipt object", async () => {
    const inc = await inception();
    const invalid = await candidate(
      {
        created_at: T + 60,
        kind: 31003,
        tags: [
          ["d", "1"],
          ["heterodyne", "keri_rotation"],
          ["p", COLD],
          ["s", "1"],
          ["prior_digest", inc.id],
          ["strategy", "committed"],
          ["epoch_key", EPOCH_TWO],
        ],
        content: "[]",
      },
      COLD_SECRET,
    );

    const result = replayKel([inc, invalid]);
    expect(result.head).toEqual({ id: inc.id, seq: 0 });
    expect(result.rejected).toContainEqual(
      expect.objectContaining({
        id: invalid.id,
        error: "invalid_rotation_content",
      }),
    );
  });

  it("rejects threshold-zero strategy:none before selecting a valid committed successor", async () => {
    const inc = await inception();
    const invalidNone = await noneRotation(inc, []);
    const committed = await committedRotation(inc, EPOCH_THREE, 1);

    const result = replayKel([inc, invalidNone, committed]);
    expect(result.status).toBe("accepted");
    expect(result.duplicity).toBe(false);
    expect(result.head).toEqual({ id: committed.id, seq: 1 });
    expect(result.rejected).toContainEqual(
      expect.objectContaining({
        id: invalidNone.id,
        error: "none_requires_positive_prior_threshold",
      }),
    );
  });

  it("accepts strategy:none only with enough distinct valid prior-witness weight", async () => {
    const inc = await inception({ witness: WITNESS, threshold: 1 });
    const emptyContentEvent: NostrUnsignedEvent = {
      pubkey: EPOCH_ONE,
      created_at: T + 60,
      kind: 31003,
      tags: [
        ["d", "1"],
        ["heterodyne", "keri_rotation"],
        ["p", COLD],
        ["s", "1"],
        ["prior_digest", inc.id],
        ["strategy", "none"],
        ["epoch_key", EPOCH_TWO],
      ],
      content: "",
    };
    const witnessDigest = sha256(utf8Bytes(canonicalNip01(emptyContentEvent)));
    const receiptSig = bytesToHex(
      schnorr.sign(witnessDigest, hexToBytes(WITNESS_SECRET), AUX_RAND),
    );
    const rotation = await noneRotation(inc, [
      { witness_id: WITNESS, scheme: "bip340", sig: receiptSig },
    ]);

    const result = replayKel([inc, rotation]);
    expect(result.status).toBe("accepted");
    expect(result.head).toEqual({ id: rotation.id, seq: 1 });
  });

  it("stalls and surfaces duplicity for competing valid committed successors", async () => {
    const inc = await inception();
    const first = await committedRotation(inc, EPOCH_TWO, 0);
    const second = await committedRotation(inc, EPOCH_THREE, 1);

    const result = replayKel([inc, first, second]);
    expect(result).toMatchObject({
      status: "stalled",
      duplicity: true,
      stalled_at: 1,
      head: { id: inc.id, seq: 0 },
    });
    expect(result.competing_ids).toEqual([first.id, second.id].sort());
  });

  it("selects a threshold-valid repo-carried none successor over a relay-only conflict", async () => {
    const inc = await inception({ witness: WITNESS, threshold: 1 });
    const relay = await witnessedNoneRotation(inc, EPOCH_TWO, "relay", 0);
    const repo = await witnessedNoneRotation(inc, EPOCH_THREE, "repo", 1);

    expect(replayKel([inc, relay, repo])).toMatchObject({
      status: "accepted",
      duplicity: true,
      head: { id: repo.id, seq: 1 },
    });
  });

  it("counts an equivocating witness only for its first-observed relay successor", async () => {
    const inc = await inception({ witness: WITNESS, threshold: 1 });
    const later = await witnessedNoneRotation(inc, EPOCH_THREE, "relay", 2);
    const first = await witnessedNoneRotation(inc, EPOCH_TWO, "relay", 1);

    expect(replayKel([inc, later, first])).toMatchObject({
      status: "accepted",
      duplicity: true,
      head: { id: first.id, seq: 1 },
    });
  });

  it("stalls a positive-threshold none rotation that lacks sufficient receipts", async () => {
    const inc = await inception({ witness: WITNESS, threshold: 1 });
    const unsupported = await noneRotation(inc, []);
    expect(replayKel([inc, unsupported])).toMatchObject({
      status: "stalled",
      duplicity: false,
      stalled_at: 1,
      head: { id: inc.id, seq: 0 },
      competing_ids: [unsupported.id],
    });
  });

  it("dispatches a non-Ed25519 did:key receipt to a local suite verifier", async () => {
    const nonEdDidKey = "did:key:z6LSuiteSpecificWitness";
    const inc = await inception({ witness: nonEdDidKey, threshold: 1 });
    const rotation = await noneRotation(inc, [{
      witness_id: nonEdDidKey,
      scheme: "bip340",
      sig: "11".repeat(64),
    }]);
    const parsed = parseKelCandidate(rotation);
    parsed.body.type === "rotation" && (parsed.body.receipts[0].scheme = "did:key");
    const content = rotationContent(parsed.body.type === "rotation" ? parsed.body.receipts : []);
    const resigned = await candidate(
      { ...parsed.event, content },
      EPOCH_ONE_SECRET,
    );
    let calls = 0;
    const result = replayKel([inc, resigned], {
      verifyDidKeyReceipt: (witnessId, _digest, signature) => {
        calls += 1;
        return witnessId === nonEdDidKey && signature.length === 64;
      },
    });
    expect(calls).toBe(1);
    expect(result.head).toEqual({ id: resigned.id, seq: 1 });
  });

  it("rejects noncanonical raw bytes, id mismatches, and bad outer signatures", async () => {
    const inc = await inception();
    expect(() =>
      parseKelCandidate({ ...inc, nip01_raw: `${inc.nip01_raw} ` }),
    ).toThrow("non_canonical_nip01");
    expect(() =>
      parseKelCandidate({ ...inc, id: "00".repeat(32) }),
    ).toThrow("event_id_mismatch");
    expect(() =>
      parseKelCandidate({ ...inc, sig: "00".repeat(64) }),
    ).toThrow("invalid_outer_signature");
  });

  it("rejects broken sequence, prior digest, and controller continuity", async () => {
    const inc = await inception();
    const broken = await candidate(
      {
        created_at: T + 60,
        kind: 31003,
        tags: [
          ["d", "2"],
          ["heterodyne", "keri_rotation"],
          ["p", COLD],
          ["s", "2"],
          ["prior_digest", "00".repeat(32)],
          ["strategy", "none"],
          ["epoch_key", EPOCH_TWO],
        ],
        content: rotationContent([]),
      },
      COLD_SECRET,
    );

    const result = replayKel([inc, broken]);
    expect(result.head).toEqual({ id: inc.id, seq: 0 });
    expect(result.rejected).toContainEqual(
      expect.objectContaining({
        id: broken.id,
        error: "broken_sequence",
      }),
    );
  });
});
