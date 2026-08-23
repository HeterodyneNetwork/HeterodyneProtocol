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
const INC_ID = "7e81c45ab6de08b6a1795f60068944db1405fa19c742a6c7b86ee46f2f04f8bf";
const ROT_ID = "cee59f50dded06fbd6ca22ef4d582ab398d66fd8817068b32fdbb837c4fec45d";
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
    expect(gitBlobOid(utf8Bytes(KEL[0].nip01_raw))).toBe("223093c303164038db332d13c76ff1508a68c819");
  });

  it("computes a single-entry git tree OID", () => {
    expect(gitTreeOidSingle("100644", "event.nip01", "223093c303164038db332d13c76ff1508a68c819")).toBe(
      "0483d3f17f71923a7e4061328c8241a3d18a7a48",
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
      blob: "223093c303164038db332d13c76ff1508a68c819",
      tree: "0483d3f17f71923a7e4061328c8241a3d18a7a48",
      commit: "dc7abf23d06341585bb74dcd69195b760e311861",
      parents: [],
    });
    expect(refs.log[1]).toMatchObject({
      blob: "9311d4190f25663d18ed2b2c8bfb4a78daa8aee3",
      tree: "f08c4406040852fcb35de99630913c5c94b03e02",
      commit: "3983f67aa5634438b5179605b5f9e6a7081c61ab",
      parents: ["dc7abf23d06341585bb74dcd69195b760e311861"],
    });
    expect(refs.state[0]).toMatchObject({
      blob: "dab8cb496816dcf166cecf647b9779607a67aa5b",
      tree: "6ebaffd6d7cec02e7fa633df7e7fda647bfbeff6",
      commit: "33d2cda3a282822f60be424ea78947c92977bcae",
      parents: ["dc7abf23d06341585bb74dcd69195b760e311861"],
    });
    expect(refs.state[1]).toMatchObject({
      blob: "6a0762e8b33ab97b136b0b971d3094a3385e205d",
      tree: "641c86198aaa07bb952043ff6a87d41ffb0eb7a2",
      commit: "b6835258d88577407cf6539820ee52a8f83e1cf4",
      parents: ["33d2cda3a282822f60be424ea78947c92977bcae", "3983f67aa5634438b5179605b5f9e6a7081c61ab"],
    });
    expect(refs.log_tip).toBe("3983f67aa5634438b5179605b5f9e6a7081c61ab");
    expect(refs.state_tip).toBe("b6835258d88577407cf6539820ee52a8f83e1cf4");
  });

  it("derives materialized state only from independently replayed current wire bytes", () => {
    expect(replay).toMatchObject({
      status: "accepted",
      rejected: [],
      head: { id: ROT_ID, seq: 1 },
    });
    expect(KEL[0].event_id).toBe(INC_ID);
    expect(KEL[0].nip01_raw).toContain('["spec_version","heterodyne/0.5.0"]');
    expect(KEL[1].event_id).toBe(ROT_ID);
    expect(KEL[1].nip01_raw).toContain(
      '\\"spec_version\\":\\"heterodyne/0.5.0\\",\\"receipts\\":[]',
    );
  });

  it("deletes both refs for an empty accepted KEL", () => {
    const refs = deriveMaterializedRefs([]);
    expect(refs.log_tip).toBeNull();
    expect(refs.state_tip).toBeNull();
  });
});
