import { createHash } from "node:crypto";
import { readFile, lstat } from "node:fs/promises";
import { join, normalize, isAbsolute } from "node:path";
import { buildGraph } from "../vector-trace.mjs";
import { queryPacket, compareProjections, buildWorklist } from "../vector-trace/impact.mjs";
import { symbolSpans } from "./symbols.mjs";

const hash = (v) => createHash("sha256").update(v).digest("hex");
const canonical = (v) => JSON.stringify(v, (_, x) => x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x);
const tokenEstimate = (s) => Math.ceil(String(s).length / 4);
const safePath = (path) => typeof path === "string" && !isAbsolute(path) && normalize(path).replaceAll("\\", "/") === path && !path.startsWith("../") && !path.includes("/../");

async function contents(repo, ref, path) {
  if (!safePath(path)) throw new Error(`unsafe packet path: ${path}`);
  if (ref && ref !== "WORKTREE") {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const { stdout } = await promisify(execFile)("git", ["show", `${ref}:${path}`], { cwd: repo, maxBuffer: 32 * 1024 * 1024 });
    return Buffer.from(stdout);
  }
  const st = await lstat(join(repo, path)); if (!st.isFile() || st.isSymbolicLink()) throw new Error(`unsafe packet source: ${path}`);
  return readFile(join(repo, path));
}
function chunk({ lane, inputRef, sourceDigest, symbolOrAnchor, startByte = 0, endByte = 0, kind, path, content, required = false }) {
  const chunkId = createHash("sha256").update(JSON.stringify([lane, inputRef, sourceDigest, symbolOrAnchor, startByte, endByte])).digest("hex");
  return { chunkId, lane, inputRef, sourceDigest, symbolOrAnchor, startByte, endByte, kind, path, content, required };
}

/** Compile a bounded, freshness-aware static task packet. */
export async function compilePacket({ repo, graph, task, deliveredChunkIds = [] }) {
  if (!repo || !graph || !task?.taskId || !Array.isArray(task.semanticIds)) throw new TypeError("repo, graph and task {taskId, semanticIds} are required");
  const receipt = graph.receipt ?? {}, lane = task.lane ?? receipt.lane, inputRef = task.inputRef ?? receipt.spec_ref ?? "WORKTREE";
  if (!lane || !["draft", "snapshot", "reconciliation"].includes(lane)) throw new Error("task lane must match graph receipt");
  if (task.lane && receipt.lane && task.lane !== receipt.lane) throw new Error("task lane disagrees with graph receipt");
  if (task.inputRef && receipt.spec_ref && task.inputRef !== receipt.spec_ref) throw new Error("task inputRef disagrees with graph receipt");
  const missing = task.semanticIds.filter((id) => !graph.items.some((item) => item.semantic_id === id));
  const packets = [];
  let unresolved = [...(graph.receipt?.unresolved_references ?? [])];
  for (const id of task.semanticIds) {
    if (!graph.items.some((item) => item.semantic_id === id)) { unresolved.push({ reason: "missing_semantic_id", id }); continue; }
    const p = queryPacket(graph, id, { direction: "both" });
    unresolved.push(...(p.unresolved ?? []));
    for (const item of [graph.items.find((x) => x.semantic_id === id), ...p.related]) {
      if (!item?.source_path) continue;
      let bytes; try { bytes = await contents(repo, inputRef === "WORKTREE" ? "WORKTREE" : inputRef, item.source_path); } catch (error) { unresolved.push({ reason: "source_unavailable", path: item.source_path, detail: error.message }); continue; }
      const source = bytes.toString("utf8"), digest = hash(bytes), isNormative = item.type === "spec_anchor";
      let start = 0, end = bytes.length, symbol = item.semantic_id;
      if (!isNormative && item.type === "source_module") { const spans = symbolSpans({ source, filePath: item.source_path }); const selected = task.selectors?.find((s) => s.path === item.source_path)?.symbol; const span = spans.find((s) => s.symbol === selected); if (span) { ({ startByte: start, endByte: end } = span); symbol = selected; } }
      const c = chunk({ lane, inputRef, sourceDigest: digest, symbolOrAnchor: symbol, startByte: start, endByte: end, kind: isNormative ? "normative" : item.type === "source_module" ? "interface" : "context", path: item.source_path, content: source.slice(0, end).slice(start), required: isNormative || item.semantic_id === id });
      if (!packets.some((x) => x.chunkId === c.chunkId)) packets.push(c);
    }
  }
  const checks = [...new Set([...(task.acceptanceChecks ?? []), "scripts/conformance-ci.sh"])].sort();
  const ownedPaths = [...new Set(task.ownedPaths ?? [])].sort();
  const dedupUnresolved = [...new Map(unresolved.map((x) => [canonical(x), x])).values()];
  const estimatedTokens = packets.reduce((n, c) => n + tokenEstimate(c.content), 0) + tokenEstimate(JSON.stringify(checks));
  const delivered = new Set(deliveredChunkIds);
  const deliver = packets.filter((c) => !delivered.has(c.chunkId));
  const deferred = estimatedTokens > 8000 ? [{ reason: "budget_expansion_required", estimatedTokens, requestedAdditionalTokens: estimatedTokens - 8000 }] : [];
  const complete = missing.length === 0 && dedupUnresolved.length === 0 && deferred.length === 0 && deliver.some((c) => c.kind === "normative");
  const contractDigest = hash(canonical(task.contract ?? {}));
  return { taskId: task.taskId, contractDigest, inputDigest: receipt.input_inventory_sha256 ?? hash(canonical(receipt.inputs ?? [])), mustRead: deliver.filter((c) => c.required), mayNeed: deliver.filter((c) => !c.required), unresolved: dedupUnresolved, deferred, deliveredChunkIds: deliver.map((c) => c.chunkId), estimatedTokens, complete, ownedPaths, acceptanceChecks: checks, backend: "core", tokenEstimator: "chars-per-4-v1", lane, inputRef, worklist: buildWorklist({ changed: task.semanticIds.map((id) => graph.items.find((x) => x.semantic_id === id)).filter(Boolean), related: [], unresolved: dedupUnresolved }) };
}

export { buildGraph, compareProjections };
