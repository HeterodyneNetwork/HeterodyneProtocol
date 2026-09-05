import { createHash } from "node:crypto";
import { lstat, readFile, realpath, writeFile } from "node:fs/promises";
import { isAbsolute, join, normalize, relative, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { buildGraph } from "../vector-trace.mjs";
import { compareProjections, queryPacket } from "../vector-trace/impact.mjs";
import { readDeclaredContracts } from "./metadata.mjs";
import { symbolSpans } from "./symbols.mjs";

const MAX_TOKENS = 8000;
const TOKEN_ESTIMATOR = "utf8-json-bytes-per-4-v1";
const CATALOG_SUFFIX = "/current-vectors/case-contracts.ts";
const LEGACY_SUFFIX = "/vector-metadata.ts";
const VALID_LANES = new Set(["draft", "snapshot", "reconciliation"]);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonical(value));
}

function unique(values) {
  return [...new Set(values)];
}

function safeRelativePath(path) {
  if (typeof path !== "string" || path.length === 0 || isAbsolute(path)) return false;
  const cleaned = normalize(path).split(sep).join("/");
  return cleaned === path && cleaned !== ".." && !cleaned.startsWith("../") && !cleaned.includes("/../");
}

async function worktreeBytes(repo, path) {
  if (!safeRelativePath(path)) throw new Error(`unsafe packet path: ${path}`);
  const root = await realpath(repo);
  const absolute = join(root, ...path.split("/"));
  const status = await lstat(absolute);
  if (!status.isFile() || status.isSymbolicLink()) throw new Error(`packet input is not a regular file: ${path}`);
  const resolved = await realpath(absolute);
  const rel = relative(root, resolved);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error(`packet input escapes repository: ${path}`);
  return readFile(resolved);
}

async function sourceAt(repo, inputRef, path) {
  if (!safeRelativePath(path)) throw new Error(`unsafe packet path: ${path}`);
  if (!inputRef || inputRef === "WORKTREE") return worktreeBytes(repo, path);
  const tree = spawnSync("git", ["ls-tree", "-z", inputRef, "--", path], {
    cwd: repo,
    encoding: null,
    maxBuffer: 1024 * 1024,
  });
  const listing = Buffer.from(tree.stdout ?? []).toString("utf8").replace(/\0$/u, "");
  const match = /^(\d{6})\s+blob\s+[a-f0-9]+\t([\s\S]+)$/u.exec(listing);
  if (tree.status !== 0 || !match || match[2] !== path) throw new Error(`historical packet input is not a blob: ${inputRef}:${path}`);
  if (match[1] === "120000") throw new Error(`historical packet input is a symlink: ${inputRef}:${path}`);
  if (match[1] !== "100644" && match[1] !== "100755") throw new Error(`unsupported historical packet mode ${match[1]}: ${inputRef}:${path}`);
  const result = spawnSync("git", ["show", `${inputRef}:${path}`], {
    cwd: repo,
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const detail = Buffer.from(result.stderr ?? []).toString("utf8").trim();
    throw new Error(detail || `git show ${inputRef}:${path} failed`);
  }
  return Buffer.from(result.stdout);
}

function lineRecords(bytes) {
  const source = bytes.toString("utf8");
  const records = [];
  let charStart = 0;
  let byteStart = 0;
  while (charStart < source.length) {
    const newline = source.indexOf("\n", charStart);
    const charEnd = newline < 0 ? source.length : newline + 1;
    const raw = source.slice(charStart, charEnd);
    const text = raw.endsWith("\n") ? raw.slice(0, -1).replace(/\r$/u, "") : raw.replace(/\r$/u, "");
    const byteEnd = byteStart + Buffer.byteLength(raw, "utf8");
    records.push({ text, byteStart, byteEnd });
    charStart = charEnd;
    byteStart = byteEnd;
  }
  if (records.length === 0 || source.endsWith("\n")) records.push({ text: "", byteStart, byteEnd: byteStart });
  return records;
}

function boundedAnchor(bytes, semanticId, path) {
  const anchorId = semanticId.split("#", 2)[1];
  const lines = lineRecords(bytes);
  const anchorLine = lines.findIndex(({ text }) => text === `<a id="${anchorId}"></a>`);
  if (anchorLine < 0) throw new Error(`anchor ${anchorId} is absent from ${path}`);
  let start = anchorLine + 1;
  while (lines[start]?.text.trim() === "") start += 1;
  let heading = lines[start]?.text.match(/^(#{1,6})\s+(.+?)\s*$/u);
  const headingAfter = Boolean(heading);
  if (!heading) {
    for (let index = anchorLine - 1; index >= 0; index -= 1) {
      heading = lines[index].text.match(/^(#{1,6})\s+(.+?)\s*$/u);
      if (heading) break;
    }
  }
  if (!heading) throw new Error(`anchor ${anchorId} has no containing heading in ${path}`);
  const level = heading[1].length;
  let end = lines.length;
  for (let index = start + (headingAfter ? 1 : 0); index < lines.length; index += 1) {
    if (!headingAfter && /^<a id="[a-z0-9-]+"><\/a>\s*$/u.test(lines[index].text)) {
      end = index;
      break;
    }
    const candidate = lines[index].text.match(/^(#{1,6})\s+/u);
    if (candidate && candidate[1].length <= level) {
      end = index;
      let prior = index - 1;
      while (prior >= start && lines[prior].text.trim() === "") prior -= 1;
      if (/^<a id="[a-z0-9-]+"><\/a>\s*$/u.test(lines[prior]?.text ?? "")) end = prior;
      break;
    }
  }
  while (end > start && lines[end - 1].text.trim() === "") end -= 1;
  const startByte = lines[start]?.byteStart ?? bytes.length;
  const endByte = lines[end - 1]?.byteEnd ?? startByte;
  const rawBytes = bytes.subarray(startByte, endByte);
  const normalizedContent = `${lines.slice(start, end).map(({ text }) => text).join("\n").replace(/\n*$/u, "")}\n`;
  return {
    startByte,
    endByte,
    content: rawBytes.toString("utf8"),
    normalizedContent,
    sourceDigest: sha256(normalizedContent),
  };
}

function chunkId({ lane, inputRef, sourceDigest, symbolOrAnchor, startByte, endByte }) {
  return sha256(JSON.stringify([lane, inputRef, sourceDigest, symbolOrAnchor, startByte, endByte]));
}

function makeChunk(fields) {
  return { chunkId: chunkId(fields), ...fields };
}

function relationSummary(packet) {
  const related = packet.related ?? [];
  const edges = packet.edges ?? [];
  const typeCounts = Object.fromEntries(Object.entries(related.reduce((counts, item) => {
    const type = item.type ?? "unknown";
    counts[type] = (counts[type] ?? 0) + 1;
    return counts;
  }, {})).sort());
  const relationCounts = Object.fromEntries(Object.entries(edges.reduce((counts, edge) => {
    const relation = edge.relation ?? "unknown";
    counts[relation] = (counts[relation] ?? 0) + 1;
    return counts;
  }, {})).sort());
  return {
    related: { count: related.length, digest: sha256(canonicalJson(related)), typeCounts },
    edges: { count: edges.length, digest: sha256(canonicalJson(edges)), relationCounts },
    graphArtifact: null,
  };
}

function deduplicateRecords(records) {
  const map = new Map();
  for (const record of records) map.set(canonicalJson(record), record);
  return [...map.values()];
}

const UNRESOLVED_PACKET_KEYS = [
  "reason", "from", "to", "semanticId", "source_path", "path", "line", "column",
  "startByte", "endByte", "sourceDigest", "relation", "symbol", "boundaryId",
  "selector", "id", "fields", "inputRef", "expected", "actual", "value", "detail",
];

function compactUnresolved(records) {
  return records.map((record) => Object.fromEntries(UNRESOLVED_PACKET_KEYS
    .filter((key) => record[key] !== undefined)
    .map((key) => [key, record[key]])));
}

async function checkedArtifactDirectory(artifactDirectory, repo) {
  if (typeof artifactDirectory !== "string" || artifactDirectory.length === 0) {
    throw new TypeError("artifactDirectory must be an existing directory path");
  }
  const status = await lstat(artifactDirectory);
  if (!status.isDirectory() || status.isSymbolicLink()) throw new Error("artifactDirectory must be a real directory");
  const resolved = await realpath(artifactDirectory);
  if (repo !== undefined) {
    const repository = await realpath(repo);
    const rel = relative(repository, resolved);
    if (rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel))) {
      throw new Error("artifactDirectory must be outside the repository worktree");
    }
  }
  return resolved;
}

function artifactComponent(value) {
  return { count: value.length, digest: sha256(canonicalJson(value)) };
}

async function persistPacketContext({ artifactDirectory, repo, related, edges, unresolved, receipt }) {
  const directory = await checkedArtifactDirectory(artifactDirectory, repo);
  const payload = {
    schema: "heterodyne-maintenance-packet-context-v1",
    kind: "maintenance-packet-context",
    version: 1,
    related,
    edges,
    unresolved,
    receipt,
  };
  const bytes = Buffer.from(`${canonicalJson(payload)}\n`, "utf8");
  const digest = sha256(bytes);
  const path = join(directory, `${digest}.json`);
  try {
    await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const status = await lstat(path);
    if (!status.isFile() || status.isSymbolicLink()) throw new Error(`packet artifact conflicts with non-file bytes: ${digest}`);
    const existing = await readFile(path);
    if (!existing.equals(bytes)) throw new Error(`packet artifact digest conflict: ${digest}`);
  }
  return {
    kind: "maintenance-packet-context",
    version: 1,
    digest,
    artifactId: `sha256:${digest}`,
    related: artifactComponent(related),
    edges: artifactComponent(edges),
    unresolved: artifactComponent(unresolved),
    receiptDigest: sha256(canonicalJson(receipt)),
  };
}

/** Resolve and verify one compiler-owned content-addressed context sidecar. */
export async function resolvePacketHandle({ artifactDirectory, handle }) {
  if (
    !handle || handle.kind !== "maintenance-packet-context" || handle.version !== 1
    || typeof handle.digest !== "string" || !/^[a-f0-9]{64}$/u.test(handle.digest)
  ) throw new Error("unsupported packet handle");
  const directory = await checkedArtifactDirectory(artifactDirectory);
  const path = join(directory, `${handle.digest}.json`);
  let status;
  try {
    status = await lstat(path);
  } catch (error) {
    throw new Error(`packet artifact missing: ${handle.digest}`, { cause: error });
  }
  if (!status.isFile() || status.isSymbolicLink()) throw new Error(`packet artifact is not a regular file: ${handle.digest}`);
  const bytes = await readFile(path);
  if (sha256(bytes) !== handle.digest) throw new Error(`packet artifact digest mismatch (tampered): ${handle.digest}`);
  let payload;
  try {
    payload = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw new Error(`packet artifact is malformed: ${handle.digest}`, { cause: error });
  }
  if (
    payload?.schema !== "heterodyne-maintenance-packet-context-v1"
    || payload.kind !== handle.kind || payload.version !== handle.version
    || !Array.isArray(payload.related) || !Array.isArray(payload.edges)
    || !Array.isArray(payload.unresolved) || !payload.receipt
  ) throw new Error(`unsupported packet artifact format: ${handle.digest}`);
  for (const key of ["related", "edges", "unresolved"]) {
    const actual = artifactComponent(payload[key]);
    if (actual.count !== handle[key]?.count || actual.digest !== handle[key]?.digest) {
      throw new Error(`packet artifact ${key} mismatch: ${handle.digest}`);
    }
  }
  if (sha256(canonicalJson(payload.receipt)) !== handle.receiptDigest) {
    throw new Error(`packet artifact receipt mismatch: ${handle.digest}`);
  }
  return {
    related: payload.related,
    edges: payload.edges,
    unresolved: payload.unresolved,
    receipt: payload.receipt,
  };
}

function inputMap(receipt, unresolved) {
  const map = new Map();
  for (const input of receipt.inputs ?? []) {
    if (!input || typeof input.path !== "string") {
      unresolved.push({ reason: "invalid_receipt_input", input });
      continue;
    }
    if (map.has(input.path)) {
      unresolved.push({ reason: "duplicate_receipt_input", path: input.path });
      continue;
    }
    map.set(input.path, input);
  }
  return map;
}

function fallbackRef(receipt) {
  return receipt.spec_ref ?? "WORKTREE";
}

async function loadInput({ repo, path, inputs, receipt, cache, unresolved }) {
  const input = inputs.get(path);
  if (!input) {
    unresolved.push({ reason: "missing_receipt_input", path });
    const inputRef = fallbackRef(receipt);
    try {
      const bytes = await sourceAt(repo, inputRef, path);
      return { bytes, inputRef, fullSourceDigest: sha256(bytes), receiptInput: null };
    } catch (error) {
      unresolved.push({ reason: "source_unavailable", path, inputRef, detail: error.message });
      return null;
    }
  }
  const inputRef = input.ref;
  if (typeof inputRef !== "string" || typeof input.sha256 !== "string") {
    unresolved.push({ reason: "invalid_receipt_input", path, input });
    return null;
  }
  const key = `${inputRef}\0${path}`;
  if (!cache.has(key)) {
    cache.set(key, (async () => {
      try {
        const bytes = await sourceAt(repo, inputRef, path);
        const actual = sha256(bytes);
        if (actual !== input.sha256) {
          unresolved.push({ reason: "input_digest_mismatch", path, inputRef, expected: input.sha256, actual });
        }
        return { bytes, inputRef, fullSourceDigest: actual, receiptInput: input };
      } catch (error) {
        unresolved.push({ reason: "source_unavailable", path, inputRef, detail: error.message });
        return null;
      }
    })());
  }
  return cache.get(key);
}

function directCases(graph, selectedIds) {
  const selected = new Set(selectedIds);
  const itemById = new Map(graph.items.map((item) => [item.semantic_id, item]));
  const result = new Set(selectedIds.filter((id) => itemById.get(id)?.type === "draft_case"));
  for (const edge of graph.edges) {
    if (edge.relation === "declares" && selected.has(edge.to) && itemById.get(edge.from)?.type === "draft_case") result.add(edge.from);
  }
  return [...result];
}

function directVectors(graph, selectedIds) {
  const selected = new Set(selectedIds);
  const itemById = new Map(graph.items.map((item) => [item.semantic_id, item]));
  const result = new Set(selectedIds.filter((id) => itemById.get(id)?.type === "vector"));
  for (const edge of graph.edges) {
    if (edge.relation === "covers" && selected.has(edge.to) && itemById.get(edge.from)?.type === "vector") {
      result.add(edge.from);
    }
  }
  return [...result];
}

function governingAnchors(graph, selectedIds) {
  const selected = new Set(selectedIds);
  const itemById = new Map(graph.items.map((item) => [item.semantic_id, item]));
  const result = new Set(selectedIds.filter((id) => itemById.get(id)?.type === "spec_anchor"));
  for (const edge of graph.edges) {
    if (edge.relation === "covers" && selected.has(edge.from) && itemById.get(edge.to)?.type === "spec_anchor") {
      result.add(edge.to);
    }
    if (edge.relation === "declares" && selected.has(edge.from) && itemById.get(edge.to)?.type === "spec_anchor") {
      result.add(edge.to);
    }
  }
  return [...result];
}

function directBoundaries(graph, caseIds) {
  const cases = new Set(caseIds);
  const result = [];
  for (const edge of graph.edges) {
    if (cases.has(edge.from) && edge.relation === "defined_by") {
      result.push({ semanticId: edge.to, symbol: edge.exported_name, boundaryId: edge.boundary_id });
    }
  }
  return [...new Map(result.map((entry) => [`${entry.semanticId}\0${entry.symbol}`, entry])).values()];
}

function metadataRef(receipt) {
  const catalog = (receipt.inputs ?? []).find(({ path }) => path?.endsWith(CATALOG_SUFFIX));
  if (catalog?.ref) return catalog.ref;
  const legacy = (receipt.inputs ?? []).find(({ path }) => path?.endsWith(LEGACY_SUFFIX));
  if (legacy?.ref) return legacy.ref;
  return fallbackRef(receipt);
}

function relevantMetadata(metadata, caseIds) {
  const ids = new Set(caseIds.map((id) => id.replace(/^case:/u, "")));
  const records = metadata.records.filter(({ id }) => ids.has(id));
  const recordIds = new Set(records.map(({ id }) => id));
  const unresolved = metadata.unresolved.filter((entry) => entry.id === undefined || recordIds.has(entry.id));
  return {
    layout: metadata.layout,
    layoutSelection: metadata.layoutSelection,
    inputDigest: metadata.inputDigest,
    records,
    unresolved,
  };
}

function estimateTokens(value) {
  return Math.ceil(Buffer.byteLength(canonicalJson(value), "utf8") / 4);
}

/**
 * Compile a version-1, bounded task packet. The task shape is camelCase:
 * `{taskId, semanticIds, ownedPaths?, acceptanceChecks?, contract?, selectors?}`.
 */
export async function compilePacket({ repo, graph, task, deliveredChunkIds = [], artifactDirectory }) {
  if (typeof repo !== "string" || !graph || !task?.taskId || !Array.isArray(task.semanticIds)) {
    throw new TypeError("repo, graph, and task {taskId, semanticIds} are required");
  }
  if (!Array.isArray(deliveredChunkIds) || deliveredChunkIds.some((id) => typeof id !== "string")) {
    throw new TypeError("deliveredChunkIds must be an array of strings");
  }
  const receipt = graph.receipt ?? {};
  const lane = task.lane ?? receipt.lane;
  if (!VALID_LANES.has(lane)) throw new Error("graph receipt must select draft, snapshot, or reconciliation lane");
  if (task.lane && receipt.lane && task.lane !== receipt.lane) throw new Error("task lane disagrees with graph receipt");
  if (task.inputRef && receipt.spec_ref && task.inputRef !== receipt.spec_ref) throw new Error("task inputRef disagrees with graph receipt");

  const unresolved = [...(receipt.unresolved_references ?? [])];
  if (receipt.fresh !== true) unresolved.push({ reason: "receipt_not_fresh", value: receipt.fresh ?? null });
  const inputs = inputMap(receipt, unresolved);
  const cache = new Map();
  await Promise.all([...inputs.keys()].map((path) => loadInput({ repo, path, inputs, receipt, cache, unresolved })));

  const items = new Map(graph.items.map((item) => [item.semantic_id, item]));
  for (const semanticId of task.semanticIds) {
    const item = items.get(semanticId);
    if (!item) continue;
    const selectedBySymbol = item.type === "source_module"
      && (task.selectors ?? []).some((selector) => selector?.path === item.source_path && typeof selector.symbol === "string");
    if (!["spec_anchor", "draft_case", "vector"].includes(item.type) && !selectedBySymbol) {
      unresolved.push({
        reason: "unsupported_selection_type",
        semanticId,
        path: item.source_path,
        value: item.type ?? null,
      });
    }
  }
  const queryPackets = [];
  for (const id of task.semanticIds) {
    if (!items.has(id)) {
      unresolved.push({ reason: "missing_semantic_id", id });
      continue;
    }
    queryPackets.push(queryPacket(graph, id, { direction: "both" }));
  }
  const relatedById = new Map();
  const selectedEdgeKeys = new Set();
  for (const packet of queryPackets) {
    for (const item of packet.related ?? []) relatedById.set(item.semantic_id, item);
    for (const edge of packet.edges ?? []) selectedEdgeKeys.add(canonicalJson(edge));
    unresolved.push(...(packet.unresolved ?? []));
  }
  // Filter the authoritative graph instead of Map-deduplicating query output:
  // repeated declarations are distinct retained relationships even when their
  // serialized fields are identical.
  const queryView = {
    related: [...relatedById.values()],
    edges: graph.edges.filter((edge) => selectedEdgeKeys.has(canonicalJson(edge))),
  };
  const inputDigest = receipt.input_inventory_sha256 ?? sha256(canonicalJson(receipt.inputs ?? []));
  const relationships = relationSummary(queryView);

  const caseIds = directCases(graph, task.semanticIds);
  const vectorIds = directVectors(graph, task.semanticIds);
  const anchorIds = governingAnchors(graph, task.semanticIds);
  const boundaryRefs = directBoundaries(graph, caseIds);
  const requiredChunks = [];

  for (const semanticId of anchorIds) {
    const item = items.get(semanticId);
    if (item?.type !== "spec_anchor" || typeof item.source_path !== "string") continue;
    const loaded = await loadInput({ repo, path: item.source_path, inputs, receipt, cache, unresolved });
    if (!loaded) continue;
    try {
      const section = boundedAnchor(loaded.bytes, semanticId, item.source_path);
      if (typeof item.source_digest === "string" && item.source_digest !== section.sourceDigest) {
        unresolved.push({ reason: "anchor_digest_mismatch", semanticId, path: item.source_path, expected: item.source_digest, actual: section.sourceDigest });
      }
      requiredChunks.push(makeChunk({
        lane,
        inputRef: loaded.inputRef,
        sourceDigest: section.sourceDigest,
        fullSourceDigest: loaded.fullSourceDigest,
        semanticId,
        symbolOrAnchor: semanticId,
        startByte: section.startByte,
        endByte: section.endByte,
        kind: "normative",
        path: item.source_path,
        content: section.content,
        normalizedContent: section.normalizedContent,
        normalization: "crlf-to-lf-and-one-trailing-newline",
      }));
    } catch (error) {
      unresolved.push({ reason: "anchor_span_unavailable", semanticId, path: item.source_path, detail: error.message });
    }
  }

  for (const semanticId of vectorIds) {
    const item = items.get(semanticId);
    if (!item?.source_path) {
      unresolved.push({ reason: "vector_source_unavailable", semanticId });
      continue;
    }
    const loaded = await loadInput({ repo, path: item.source_path, inputs, receipt, cache, unresolved });
    if (!loaded) continue;
    if (typeof item.source_digest === "string" && item.source_digest !== loaded.fullSourceDigest) {
      unresolved.push({ reason: "item_digest_mismatch", semanticId, path: item.source_path, expected: item.source_digest, actual: loaded.fullSourceDigest });
    }
    try {
      const value = JSON.parse(loaded.bytes.toString("utf8"));
      if (value?.vector_id !== semanticId.replace(/^vector:/u, "")) {
        unresolved.push({ reason: "vector_identity_mismatch", semanticId, path: item.source_path, value: value?.vector_id ?? null });
      }
    } catch (error) {
      unresolved.push({ reason: "vector_json_invalid", semanticId, path: item.source_path, detail: error.message });
    }
    requiredChunks.push(makeChunk({
      lane,
      inputRef: loaded.inputRef,
      sourceDigest: loaded.fullSourceDigest,
      fullSourceDigest: loaded.fullSourceDigest,
      semanticId,
      symbolOrAnchor: semanticId,
      startByte: 0,
      endByte: loaded.bytes.length,
      kind: "historical-vector",
      path: item.source_path,
      content: loaded.bytes.toString("utf8"),
      evidenceKind: item.evidence_kind ?? "historical_vector",
    }));
  }

  for (const semanticId of caseIds) {
    const item = items.get(semanticId);
    if (!item?.source_path) {
      unresolved.push({ reason: "case_source_unavailable", semanticId });
      continue;
    }
    const loaded = await loadInput({ repo, path: item.source_path, inputs, receipt, cache, unresolved });
    if (!loaded) continue;
    if (typeof item.source_digest === "string" && item.source_digest !== loaded.fullSourceDigest) {
      unresolved.push({ reason: "item_digest_mismatch", semanticId, path: item.source_path, expected: item.source_digest, actual: loaded.fullSourceDigest });
    }
    const source = loaded.bytes.toString("utf8");
    const symbol = semanticId.replace(/^case:/u, "");
    const span = symbolSpans({ source, filePath: item.source_path }).find((candidate) => candidate.symbol === symbol);
    if (!span) {
      unresolved.push({ reason: "case_span_unavailable", semanticId, path: item.source_path });
      continue;
    }
    const content = loaded.bytes.subarray(span.startByte, span.endByte).toString("utf8");
    requiredChunks.push(makeChunk({
      lane,
      inputRef: loaded.inputRef,
      sourceDigest: span.sourceDigest,
      fullSourceDigest: loaded.fullSourceDigest,
      semanticId,
      symbolOrAnchor: symbol,
      startByte: span.startByte,
      endByte: span.endByte,
      kind: "case-declaration",
      path: item.source_path,
      content,
    }));
  }

  for (const boundary of boundaryRefs) {
    const item = items.get(boundary.semanticId);
    if (!item?.source_path || typeof boundary.symbol !== "string") {
      unresolved.push({ reason: "boundary_source_unavailable", ...boundary });
      continue;
    }
    const loaded = await loadInput({ repo, path: item.source_path, inputs, receipt, cache, unresolved });
    if (!loaded) continue;
    if (typeof item.source_digest === "string" && item.source_digest !== loaded.fullSourceDigest) {
      unresolved.push({ reason: "item_digest_mismatch", semanticId: boundary.semanticId, path: item.source_path, expected: item.source_digest, actual: loaded.fullSourceDigest });
    }
    const source = loaded.bytes.toString("utf8");
    const span = symbolSpans({ source, filePath: item.source_path }).find((candidate) => candidate.symbol === boundary.symbol);
    if (!span) {
      unresolved.push({ reason: "boundary_span_unavailable", ...boundary, path: item.source_path });
      continue;
    }
    requiredChunks.push(makeChunk({
      lane,
      inputRef: loaded.inputRef,
      sourceDigest: span.sourceDigest,
      fullSourceDigest: loaded.fullSourceDigest,
      semanticId: boundary.semanticId,
      symbolOrAnchor: boundary.symbol,
      startByte: span.startByte,
      endByte: span.endByte,
      kind: "interface",
      path: item.source_path,
      content: loaded.bytes.subarray(span.startByte, span.endByte).toString("utf8"),
      boundaryId: boundary.boundaryId,
    }));
  }

  for (const selector of task.selectors ?? []) {
    if (!selector || typeof selector.path !== "string" || typeof selector.symbol !== "string") {
      unresolved.push({ reason: "invalid_selector", selector });
      continue;
    }
    const loaded = await loadInput({ repo, path: selector.path, inputs, receipt, cache, unresolved });
    if (!loaded) continue;
    const source = loaded.bytes.toString("utf8");
    const span = symbolSpans({ source, filePath: selector.path }).find((candidate) => candidate.symbol === selector.symbol);
    if (!span) {
      unresolved.push({ reason: "selector_span_unavailable", ...selector });
      continue;
    }
    requiredChunks.push(makeChunk({
      lane,
      inputRef: loaded.inputRef,
      sourceDigest: span.sourceDigest,
      fullSourceDigest: loaded.fullSourceDigest,
      semanticId: `source:${selector.path}`,
      symbolOrAnchor: selector.symbol,
      startByte: span.startByte,
      endByte: span.endByte,
      kind: "interface",
      path: selector.path,
      content: loaded.bytes.subarray(span.startByte, span.endByte).toString("utf8"),
    }));
  }

  const metadataAll = await readDeclaredContracts({ repo, ref: metadataRef(receipt), layout: "auto" });
  const metadata = relevantMetadata(metadataAll, caseIds);
  unresolved.push(...metadata.unresolved);
  for (const record of metadata.records) {
    if (record.unknownFields.length > 0) {
      unresolved.push({ reason: "declared_metadata_unknown", id: record.id, fields: record.unknownFields });
    }
  }

  const allChunks = [...new Map(requiredChunks.map((entry) => [entry.chunkId, entry])).values()];
  const deliveredBefore = new Set(deliveredChunkIds);
  const alreadyDeliveredObligations = allChunks.filter(({ chunkId: id }) => deliveredBefore.has(id)).length;
  const mustRead = allChunks.filter(({ chunkId: id }) => !deliveredBefore.has(id));
  const cumulativeDelivered = unique([...deliveredChunkIds, ...mustRead.map(({ chunkId: id }) => id)]);

  const unresolvedFull = deduplicateRecords(unresolved);
  relationships.unresolved = {
    count: unresolvedFull.length,
    digest: sha256(canonicalJson(unresolvedFull)),
  };
  const expandedSemanticIds = unique([
    ...task.semanticIds,
    ...anchorIds,
    ...caseIds,
    ...vectorIds,
    ...boundaryRefs.map(({ semanticId }) => semanticId),
  ]);
  relationships.expandedSemanticIds = expandedSemanticIds;

  const discoveryHandles = [];
  for (const entry of unresolvedFull) {
    if (entry.reason !== "missing_anchor" || typeof entry.from !== "string") continue;
    const chunk = allChunks.find(({ semanticId }) => semanticId === entry.from);
    if (!chunk) continue;
    discoveryHandles.push({
      kind: "source-span",
      reason: "missing_anchor",
      semanticId: entry.from,
      missingSemanticId: entry.to ?? null,
      path: chunk.path,
      inputRef: chunk.inputRef,
      sourceDigest: chunk.sourceDigest,
      startByte: chunk.startByte,
      endByte: chunk.endByte,
    });
  }

  let unresolvedOutput;
  if (artifactDirectory !== undefined) {
    relationships.graphArtifact = await persistPacketContext({
      artifactDirectory,
      repo,
      related: queryView.related,
      edges: queryView.edges,
      unresolved: unresolvedFull,
      receipt,
    });
    unresolvedOutput = compactUnresolved(unresolvedFull);
  } else {
    relationships.related.records = queryView.related;
    relationships.edges.records = queryView.edges;
    unresolvedOutput = unresolvedFull;
  }

  const ownedPaths = unique(task.ownedPaths ?? []).sort((left, right) => left.localeCompare(right, "en"));
  const acceptanceChecks = unique(task.acceptanceChecks ?? []).sort((left, right) => left.localeCompare(right, "en"));
  const contractDigest = sha256(canonicalJson(task.contract ?? {}));
  const measuredFields = [
    "version", "taskId", "contractDigest", "inputDigest", "mustRead", "mayNeed",
    "unresolved", "deferred", "deliveredChunkIds", "alreadyDeliveredObligations",
    "complete", "relationships", "metadata", "discoveryHandles", "ownedPaths",
    "acceptanceChecks", "backend", "tokenEstimator", "budget", "lane", "inputRef",
  ];
  const baseComplete = task.semanticIds.every((id) => items.has(id))
    && unresolvedOutput.length === 0
    && alreadyDeliveredObligations + mustRead.length === allChunks.length;
  const result = {
    version: 1,
    taskId: task.taskId,
    contractDigest,
    inputDigest,
    mustRead,
    mayNeed: [],
    unresolved: unresolvedOutput,
    deferred: [],
    deliveredChunkIds: cumulativeDelivered,
    alreadyDeliveredObligations,
    estimatedTokens: 0,
    complete: baseComplete,
    relationships,
    metadata,
    discoveryHandles,
    ownedPaths,
    acceptanceChecks,
    backend: "vector-trace-core",
    tokenEstimator: TOKEN_ESTIMATOR,
    budget: { maxTokens: MAX_TOKENS, measuredFields },
    lane,
    inputRef: receipt.spec_ref ?? null,
  };

  let estimatedTokens = estimateTokens({ ...result, estimatedTokens: 0 });
  if (estimatedTokens > MAX_TOKENS) {
    result.deferred = [{
      reason: "budget_expansion_required",
      estimatedTokens,
      maxTokens: MAX_TOKENS,
      requestedAdditionalTokens: estimatedTokens - MAX_TOKENS,
      normativeObligationsTruncated: false,
    }];
    result.complete = false;
    estimatedTokens = estimateTokens({ ...result, estimatedTokens: 0 });
    result.deferred[0].estimatedTokens = estimatedTokens;
    result.deferred[0].requestedAdditionalTokens = estimatedTokens - MAX_TOKENS;
    estimatedTokens = estimateTokens({ ...result, estimatedTokens: 0 });
  }
  result.estimatedTokens = estimatedTokens;
  return result;
}

export { buildGraph, compareProjections };
