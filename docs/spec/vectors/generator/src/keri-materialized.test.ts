import { describe, expect, it } from "vitest";
import { deriveMaterializedRefs, gitBlobOid, gitTreeOidSingle, jcsCanonicalize, type KelEntry } from "./keri-materialized.js";
import { utf8Bytes } from "./hex.js";

// Reference OIDs produced by real git (git hash-object / mktree / commit-tree)
// over the same two-event KEL, pinning the §10.1.2 byte-identical recipe:
// a committed inception (s=0, no witnesses) and a committed rotation (s=1).
const COLD = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const E1 = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const E2 = "1be68a5a028f2601d0e80d468c344ba331d611b96c358b6032e8b4da0547fc11";
const INC_ID = "2a182dd311941fa1bc6a9847d700c261d4dc1ef31168b8635aaea8d3d0171def";
const ROT_ID = "5087532c7f6cb9e276b4499dd55f29a346f742785cd26abdd7db0fb60562fb52";
const T = 1767225600;

const KEL: KelEntry[] = [
  {
    event_id: INC_ID,
    created_at: T,
    nip01_raw: `[0,"${COLD}",${T},31002,[["d",""],["heterodyne","keri_inception"],["p","${COLD}"],["s","0"],["epoch_key","${E1}"]],""]`,
    state: { cold_root: COLD, s: 0, epoch_key: E1, witnesses: [], threshold: 0, producing_event_id: INC_ID },
  },
  {
    event_id: ROT_ID,
    created_at: T + 3600,
    nip01_raw: `[0,"${COLD}",${T + 3600},31003,[["d","1"],["heterodyne","keri_rotation"],["p","${COLD}"],["s","1"],["prior_digest","${INC_ID}"],["strategy","committed"],["epoch_key","${E2}"]],"[]"]`,
    state: { cold_root: COLD, s: 1, epoch_key: E2, witnesses: [], threshold: 0, producing_event_id: ROT_ID },
  },
];

describe("materialized-KEL ref derivation (§10.1.2)", () => {
  it("computes a git blob OID", () => {
    expect(gitBlobOid(utf8Bytes(KEL[0].nip01_raw))).toBe("a8c3c25c035c9a66bd9fa68afc4f24484833d2a4");
  });

  it("computes a single-entry git tree OID", () => {
    expect(gitTreeOidSingle("100644", "event.nip01", "a8c3c25c035c9a66bd9fa68afc4f24484833d2a4")).toBe(
      "9525da0a274c93f7c2efa05762963a725d1ddc23",
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
      blob: "a8c3c25c035c9a66bd9fa68afc4f24484833d2a4",
      tree: "9525da0a274c93f7c2efa05762963a725d1ddc23",
      commit: "d3c49e5bf945410bca205c7a7bc0f57fa67b57ac",
      parents: [],
    });
    expect(refs.log[1]).toMatchObject({
      blob: "3249634aead8822bf7fcb51532553f2c71c543e9",
      tree: "02a6ea4675da8dc1e992f8952d446f390aac58a5",
      commit: "c1b8b81cc4262bbac4282290292baee2bbb9c400",
      parents: ["d3c49e5bf945410bca205c7a7bc0f57fa67b57ac"],
    });
    expect(refs.state[0]).toMatchObject({
      blob: "76b5d478b704eca50833a0245ead25ec25c20faa",
      tree: "116c6e43d9aa60fbc8ecd60a4fb2b2f5e772240e",
      commit: "6bdff9460228cc32bf7818f8c6310b6812368ad6",
      parents: ["d3c49e5bf945410bca205c7a7bc0f57fa67b57ac"],
    });
    expect(refs.state[1]).toMatchObject({
      blob: "e23d150b1d0014dce7f21a62135f8deffbd7ca42",
      tree: "961b2ad81f1ab4fa8c7d0db97412d4318ae2f493",
      commit: "1456fe106098191c8ac06df3d92d985ea51b3cc8",
      parents: ["6bdff9460228cc32bf7818f8c6310b6812368ad6", "c1b8b81cc4262bbac4282290292baee2bbb9c400"],
    });
    expect(refs.log_tip).toBe("c1b8b81cc4262bbac4282290292baee2bbb9c400");
    expect(refs.state_tip).toBe("1456fe106098191c8ac06df3d92d985ea51b3cc8");
  });

  it("deletes both refs for an empty accepted KEL", () => {
    const refs = deriveMaterializedRefs([]);
    expect(refs.log_tip).toBeNull();
    expect(refs.state_tip).toBeNull();
  });
});
