import { beforeAll, describe, expect, it } from "vitest";
import { jcsCanonicalize } from "./jcs.js";
import { deriveMaterializedRefs, gitBlobOid, gitTreeOidSingle, type KelEntry } from "./keri-materialized.js";
import { utf8Bytes } from "./hex.js";
import { inceptionTemplate, rotationContent } from "./kel.js";
import { replayKel, type KelReplayResult } from "./kel-replay.js";
import { canonicalNip01, signEvent } from "./nostr.js";

// Reference OIDs produced by real git (git hash-object / mktree / commit-tree)
// over the same two-event KEL, pinning the §10.1.2 byte-identical recipe:
// a committed inception (s=0, no witnesses) and a committed rotation (s=1).
const COLD = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const E1 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const E2 = "1be68a5a028f2601d0e80d468c344ba331d611b96c358b6032e8b4da0547fc11";
const INC_ID = "22d30c9e60374b4a4c9caeb8ca6993becce42318bb9c4c1fdd316ffeb4ae9ba0";
const ROT_ID = "a1cf4cc9a146b9c2f92defd8d5c9bc816bc321f9adde108d0e26fe0c825a1e52";
const T = 1767225600;
const AUX_RAND = "00".repeat(32);
const COLD_SECRET = "1".padStart(64, "0");

let KEL: KelEntry[];
let replay: KelReplayResult;

beforeAll(async () => {
  const inception = await signEvent({
    secretKey: COLD_SECRET,
    created_at: T,
    kind: 31002,
    tags: inceptionTemplate(COLD, E1, T).tags,
    content: "",
    auxRand: AUX_RAND,
  });
  const rotation = await signEvent({
    secretKey: COLD_SECRET,
    created_at: T + 3600,
    kind: 31003,
    tags: [
      ["d", "1"],
      ["heterodyne", "keri_rotation"],
      ["p", COLD],
      ["s", "1"],
      ["prior_digest", inception.id],
      ["strategy", "committed"],
      ["epoch_key", E2],
    ],
    content: rotationContent([]),
    auxRand: AUX_RAND,
  });
  replay = replayKel([
    { nip01_raw: canonicalNip01(inception), id: inception.id, sig: inception.sig, source: "repo" },
    { nip01_raw: canonicalNip01(rotation), id: rotation.id, sig: rotation.sig, source: "repo" },
  ]);
  KEL = replay.entries;
});

describe("materialized-KEL ref derivation (§10.1.2)", () => {
  it("computes a git blob OID", () => {
    expect(gitBlobOid(utf8Bytes(KEL[0].nip01_raw))).toBe("0ff0af49b1366f819d5ed37335f70fa9b792d95e");
  });

  it("computes a single-entry git tree OID", () => {
    expect(gitTreeOidSingle("100644", "event.nip01", "0ff0af49b1366f819d5ed37335f70fa9b792d95e")).toBe(
      "58a5d4bb126e5f6c4f3f493ab6fafed87878662f",
    );
  });

  it("canonicalizes state.json per JCS with sorted keys and integer numbers", () => {
    expect(jcsCanonicalize(KEL[0].state)).toBe(
      `{"cold_root":"${COLD}","epoch_key":"${E1}","producing_event_id":"${INC_ID}","s":0,"threshold":0,"witnesses":[]}`,
    );
  });

  it("derives byte-identical log and state chains matching real git", () => {
    const refs = deriveMaterializedRefs(KEL);

    expect(refs.log[0]).toMatchObject({
      blob: "0ff0af49b1366f819d5ed37335f70fa9b792d95e",
      tree: "58a5d4bb126e5f6c4f3f493ab6fafed87878662f",
      commit: "79263458c882b087d18454c78cb00c9784d887ce",
      parents: [],
    });
    expect(refs.log[1]).toMatchObject({
      blob: "a59a2b655f9381e62de8af171f6e4347e58df5cc",
      tree: "149146cb5fcaf7fa473fca8b1ca42187be90a404",
      commit: "f5560bc313a2aff1f54e6c4f2c06fc67963ece53",
      parents: ["79263458c882b087d18454c78cb00c9784d887ce"],
    });
    expect(refs.state[0]).toMatchObject({
      blob: "392627d9c791377e50f169c5a9e14ed6662f989e",
      tree: "5e54ca5321fbf3a032873480daca9a4efe57e45f",
      commit: "e277cbfbf6ae6e095a077be56363d8a3838436a0",
      parents: ["79263458c882b087d18454c78cb00c9784d887ce"],
    });
    expect(refs.state[1]).toMatchObject({
      blob: "d42c51057cb5bf879516ef4cabd1449c25f4398b",
      tree: "920001c3a494c320674123bc0c143ee4ba9ca50c",
      commit: "226b5ea88217b6bb9478c195f7e7c26e148b2ede",
      parents: ["e277cbfbf6ae6e095a077be56363d8a3838436a0", "f5560bc313a2aff1f54e6c4f2c06fc67963ece53"],
    });
    expect(refs.log_tip).toBe("f5560bc313a2aff1f54e6c4f2c06fc67963ece53");
    expect(refs.state_tip).toBe("226b5ea88217b6bb9478c195f7e7c26e148b2ede");
  });

  it("derives materialized state only from independently replayed current wire bytes", () => {
    expect(replay).toMatchObject({
      status: "accepted",
      rejected: [],
      head: { id: ROT_ID, seq: 1 },
    });
    expect(KEL[0].event_id).toBe(INC_ID);
    expect(KEL[0].nip01_raw).toContain('["spec_version","core/0.5.0"]');
    expect(KEL[1].event_id).toBe(ROT_ID);
    expect(KEL[1].nip01_raw).toContain(
      '\\"spec_version\\":\\"core/0.5.0\\",\\"receipts\\":[]',
    );
  });

  it("deletes both refs for an empty accepted KEL", () => {
    const refs = deriveMaterializedRefs([]);
    expect(refs.log_tip).toBeNull();
    expect(refs.state_tip).toBeNull();
  });
});
