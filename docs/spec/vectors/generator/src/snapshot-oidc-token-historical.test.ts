import { nip19 } from "nostr-tools";
import { beforeAll, describe, expect, it } from "vitest";
import { buildFixtures } from "./snapshot-fixtures-adapter.js";
import {
  discoveryPaths,
  issuerMetadata,
  issuerUrl,
  validateColdRootBinding,
} from "./snapshot-oidc-adapter.js";
import { buildAndReplaySnapshotOidcTokenVectors } from "./snapshot-topic-runtime.js";

const fixtures = buildFixtures();
let replayed: Awaited<ReturnType<typeof buildAndReplaySnapshotOidcTokenVectors>>;

beforeAll(async () => {
  replayed = await buildAndReplaySnapshotOidcTokenVectors(fixtures);
}, 30_000);

describe("snapshot-only historical OIDC and token-status semantics", () => {
  it("keeps cold-root issuer construction only on the pinned OIDC adapter", () => {
    const root = nip19.npubEncode(fixtures.personas.alice.cold_root.pubkey);
    const epoch = nip19.npubEncode(fixtures.personas.alice.epoch_keys.epoch_1.pubkey);
    const identity = { cold_root_npub: root, epoch_npubs: [epoch] };
    const issuer = issuerUrl("https://node.example", root, identity);
    expect(issuer).toBe(`https://node.example/oidc/${root}`);
    expect(discoveryPaths("https://node.example", root, identity).issuer).toBe(issuer);
    expect(issuerMetadata("https://node.example", root, identity).issuer).toBe(issuer);
    expect(validateColdRootBinding(epoch, identity)).toMatchObject({ allowed: false });
  });

  it("compiles and replays the frozen OIDC topic through exact adapter remaps", async () => {
    expect(replayed.oidc).toHaveLength(13);
    expect(replayed.oidc.every(({ expected, replayed: actual }) =>
      JSON.stringify(expected) === JSON.stringify(actual))).toBe(true);
    expect(replayed.oidc.map(({ vector_id }) => vector_id)).toContain("oidc/pairwise-subject");
  });

  it("keeps KEL/cold-root continuity mutations in the frozen token topic", async () => {
    const mutationNames = replayed.token.flatMap(({ mutations }) => Object.keys(mutations));
    expect(mutationNames).toEqual(expect.arrayContaining([
      "stale_kel_head",
      "missing_persona_proof",
      "shared_key_only_successor",
      "old_https_issuer",
    ]));
    expect(replayed.token.every(({ expected, replayed: actual }) =>
      JSON.stringify(expected) === JSON.stringify(actual))).toBe(true);
  });
});
