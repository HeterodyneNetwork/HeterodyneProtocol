import test from "node:test";
import assert from "node:assert/strict";
import { compilePacket } from "./packet.mjs";

const repo = new URL("../../", import.meta.url).pathname;
test("partial graph never claims complete and retains normative context", async () => {
  const graph = { items: [{ semantic_id: "heterodyne:core#identity", type: "spec_anchor", source_path: "docs/spec/heterodyne-core.md" }], edges: [], receipt: { lane: "draft", spec_ref: "WORKTREE", inputs: [], unresolved_references: [{ reason: "unknown_profile_override" }] } };
  const packet = await compilePacket({ repo, graph, task: { taskId: "task", semanticIds: ["heterodyne:core#identity"], ownedPaths: [], acceptanceChecks: [] }, deliveredChunkIds: [] });
  assert.equal(packet.complete, false);
  assert.ok(packet.unresolved.length > 0);
  assert.equal(packet.mustRead.some((chunk) => chunk.kind === "normative"), true);
});

test("delivered chunks are not resent", async () => {
  const graph = { items: [{ semantic_id: "heterodyne:core#identity", type: "spec_anchor", source_path: "docs/spec/heterodyne-core.md" }], edges: [], receipt: { lane: "draft", spec_ref: "WORKTREE", inputs: [], unresolved_references: [] } };
  const first = await compilePacket({ repo, graph, task: { taskId: "task", semanticIds: ["heterodyne:core#identity"] }, deliveredChunkIds: [] });
  const second = await compilePacket({ repo, graph, task: { taskId: "task", semanticIds: ["heterodyne:core#identity"] }, deliveredChunkIds: first.deliveredChunkIds });
  assert.equal(second.mustRead.length + second.mayNeed.length, 0);
});
