/* Pure, conservative operations over a vector-trace projection.
 *
 * This module deliberately does not read the repository or execute generator
 * code.  The projection builder owns provenance; these functions only select
 * records and preserve uncertainty for callers.
 */

const DIRECTIONS = new Set(["upstream", "downstream", "both"]);
const FULL_GATE = "scripts/conformance-ci.sh";
const IMPORT = "imports";

function compareStrings(a, b) {
  return String(a ?? "").localeCompare(String(b ?? ""), "en");
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function sameValue(left, right) {
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
}

function graphIndex(projection) {
  if (!projection || !Array.isArray(projection.items) || !Array.isArray(projection.edges)) {
    throw new TypeError("projection must contain items and edges arrays");
  }
  const items = new Map();
  for (const value of projection.items) {
    if (!value || typeof value.semantic_id !== "string") continue;
    if (items.has(value.semantic_id)) throw new Error(`duplicate semantic id: ${value.semantic_id}`);
    items.set(value.semantic_id, value);
  }
  const edges = projection.edges.filter((edge) => edge && typeof edge.from === "string" && typeof edge.to === "string");
  return { items, edges };
}

function sortItems(values) {
  return [...values].sort((a, b) => compareStrings(a.semantic_id, b.semantic_id));
}

function sortEdges(values) {
  return [...values].sort((a, b) => compareStrings(a.from, b.from)
    || compareStrings(a.relation, b.relation) || compareStrings(a.to, b.to)
    || compareStrings(a.source_path, b.source_path));
}

function edgeDirections(edge, id, direction) {
  const outgoing = edge.from === id;
  const incoming = edge.to === id;
  if (direction === "upstream") return outgoing ? "outgoing" : null;
  if (direction === "downstream") return incoming ? "incoming" : null;
  if (outgoing) return "outgoing";
  if (incoming) return "incoming";
  return null;
}

function missingReferences(projection, index) {
  const unresolved = [];
  const seen = new Set();
  const add = (value) => {
    const key = JSON.stringify(canonical(value));
    if (!seen.has(key)) { seen.add(key); unresolved.push(value); }
  };
  for (const value of projection.receipt?.unresolved_references ?? []) add(value);
  for (const edge of index.edges) {
    if (!index.items.has(edge.from) || !index.items.has(edge.to)) add(edge);
  }
  return unresolved.sort((a, b) => JSON.stringify(canonical(a)).localeCompare(JSON.stringify(canonical(b)), "en"));
}

function testPath(path) {
  return typeof path === "string" && (
    /(^|\/)test\.[cm]?[jt]sx?$/u.test(path)
    || /(?:^|\.)test\.[cm]?[jt]sx?$/u.test(path)
    || /(?:^|\/)vitest(?:\.[^/]+)?\.config\.[cm]?[jt]s$/u.test(path)
  );
}

function candidateChecks(items) {
  const paths = new Set([FULL_GATE]);
  for (const value of items) if (testPath(value.source_path)) paths.add(value.source_path);
  return [...paths].sort(compareStrings);
}

function packetFor(projection, changed, related, unresolved, extra = {}) {
  const all = [...changed, ...related];
  const uniqueUnresolved = [...new Map(unresolved.map((value) => [JSON.stringify(canonical(value)), value])).values()];
  return {
    changed: sortItems(changed.filter((value, index, values) => values.findIndex((candidate) => candidate.semantic_id === value.semantic_id) === index)),
    related: sortItems(related.filter((value, index, values) => values.findIndex((candidate) => candidate.semantic_id === value.semantic_id) === index)),
    unresolved: uniqueUnresolved.sort((a, b) => JSON.stringify(canonical(a)).localeCompare(JSON.stringify(canonical(b)), "en")),
    suggested_checks: candidateChecks(all),
    collision_risks: extra.collision_risks ?? [],
    receipt: extra.receipt ?? projection.receipt ?? null,
    ...extra,
  };
}

/**
 * Return a bounded provenance-bearing packet around one semantic item.
 * `upstream` follows edge.from -> edge.to as requested by the trace contract;
 * `downstream` follows the reverse direction.
 */
export function queryPacket(projection, id, { direction = "both" } = {}) {
  if (!DIRECTIONS.has(direction)) throw new Error(`invalid direction: ${direction}`);
  const index = graphIndex(projection);
  if (!index.items.has(id)) throw new Error(`unknown semantic id: ${id}`);

  const related = new Map();
  const queue = [{ id, depth: 0, mode: "root" }];
  const visited = new Set();
  while (queue.length) {
    const current = queue.shift();
    // Import closures can contain cycles.  Depth is intentionally excluded so
    // a cycle cannot create a fresh queue state at every turn.
    const visitKey = `${current.id}:${current.mode}`;
    if (visited.has(visitKey)) continue;
    visited.add(visitKey);
    for (const edge of index.edges) {
      const side = edgeDirections(edge, current.id, direction);
      if (!side) continue;
      const nextId = side === "outgoing" ? edge.to : edge.from;
      const next = index.items.get(nextId);
      if (!next || nextId === id) continue;
      const currentItem = index.items.get(current.id);
      if (edge.relation === IMPORT && currentItem?.type === "source_module") {
        // Follow the complete dependency closure in the forward direction.
        // Reverse imports are admitted only for a directly selected source or
        // a source reached through an explicit case boundary; this avoids
        // fanning out from a shared fixture into every unrelated test.
        const allow = (side === "outgoing" && current.mode !== "dependent")
          || (side === "incoming"
            && (current.mode === "root" || current.mode === "structural" || current.mode === "dependent")
            && testPath(next.source_path));
        if (!allow) continue;
        related.set(nextId, next);
        queue.push({ id: nextId, depth: current.depth + 1, mode: side === "outgoing" ? "dependency" : "dependent" });
      } else if (current.depth < 2 && current.mode !== "dependent") {
        const structural = currentItem?.type === "spec_anchor"
          || currentItem?.type === "draft_case"
          || currentItem?.type === "vector"
          || currentItem?.type === "schema_artifact"
          || currentItem?.type === "registry_artifact"
          || (currentItem?.type === "source_module" && (current.mode === "root" || current.mode === "structural"));
        if (structural && edge.relation !== IMPORT) {
          related.set(nextId, next);
          queue.push({ id: nextId, depth: current.depth + 1, mode: "structural" });
        }
      }
    }
  }

  // A source path changed outside an explicit anchor is still useful context;
  // query itself remains graph-bounded and does not infer semantic relations.
  const unresolved = missingReferences(projection, index);
  const target = index.items.get(id);
  const packet = packetFor(projection, [target], [...related.values()].filter((value) => value.semantic_id !== id), unresolved);
  packet.edges = sortEdges(index.edges.filter((edge) => related.has(edge.from) || related.has(edge.to) || edge.from === id || edge.to === id));
  return packet;
}

function inputInventory(projection) {
  const result = new Map();
  for (const input of projection?.receipt?.inputs ?? []) {
    if (typeof input?.path !== "string") continue;
    result.set(input.path, input);
  }
  return result;
}

function changeRecord(before, after, changeKind) {
  if (changeKind === "added") return { ...after, change_kind: changeKind, before: null, after };
  if (changeKind === "removed") return { ...before, change_kind: changeKind, before, after: null };
  return { ...after, change_kind: changeKind, before, after };
}

function edgeKey(edge) {
  return JSON.stringify(canonical({ from: edge.from, to: edge.to, relation: edge.relation, source_path: edge.source_path }));
}

function diffInputs(before, after) {
  const left = inputInventory(before);
  const right = inputInventory(after);
  const added = [], removed = [], modified = [];
  for (const path of [...right.keys()].sort(compareStrings)) {
    if (!left.has(path)) added.push(path);
    else if (left.get(path)?.sha256 !== right.get(path)?.sha256) modified.push(path);
  }
  for (const path of [...left.keys()].sort(compareStrings)) if (!right.has(path)) removed.push(path);
  return { added, removed, modified, changed_paths: [...new Set([...added, ...removed, ...modified])].sort(compareStrings) };
}

function itemDiff(before, after) {
  const left = graphIndex(before).items;
  const right = graphIndex(after).items;
  const added = [], removed = [], modified = [], changed = [];
  for (const [id, value] of right) {
    if (!left.has(id)) { const record = changeRecord(null, value, "added"); added.push(record); changed.push(record); }
    else if (!sameValue(left.get(id), value)) { const record = changeRecord(left.get(id), value, "modified"); modified.push(record); changed.push(record); }
  }
  for (const [id, value] of left) if (!right.has(id)) { const record = changeRecord(value, null, "removed"); removed.push(record); changed.push(record); }
  return { added: sortItems(added), removed: sortItems(removed), modified: sortItems(modified), changed: sortItems(changed) };
}

/** Compare two projections without dropping historical records or file-only changes. */
export function compareProjections(before, after) {
  const left = graphIndex(before);
  const right = graphIndex(after);
  const items = itemDiff(before, after);
  const beforeEdges = new Map(left.edges.map((edge) => [edgeKey(edge), edge]));
  const afterEdges = new Map(right.edges.map((edge) => [edgeKey(edge), edge]));
  const edgeAdded = [...afterEdges].filter(([key]) => !beforeEdges.has(key)).map(([, edge]) => edge);
  const edgeRemoved = [...beforeEdges].filter(([key]) => !afterEdges.has(key)).map(([, edge]) => edge);
  const input_changes = diffInputs(before, after);
  const unresolved = [...missingReferences(before, left), ...missingReferences(after, right)];
  const unresolvedKeys = new Set();
  const uniqueUnresolved = unresolved.filter((value) => {
    const key = JSON.stringify(canonical(value));
    if (unresolvedKeys.has(key)) return false;
    unresolvedKeys.add(key); return true;
  });
  const changed = [...items.changed];
  const seeds = new Set(items.changed.map((value) => value.semantic_id));
  const traversalSeeds = new Set(seeds);
  const graphPathToIds = (projection, path) => graphIndex(projection).items.values().filter((value) => value.source_path === path).map((value) => value.semantic_id);
  for (const path of input_changes.changed_paths) {
    const ids = [...new Set([...graphPathToIds(before, path), ...graphPathToIds(after, path)])];
    if (ids.length === 0 || (path.startsWith("docs/spec/") && path.endsWith(".md") && !items.changed.some((value) => value.source_path === path))) {
      const record = { semantic_id: `document:${path}`, type: "document", source_path: path, change_kind: "document_changed", source_digest: null, evidence_kind: "unresolved_document_impact" };
      changed.push(record); seeds.add(record.semantic_id); traversalSeeds.add(record.semantic_id);
      uniqueUnresolved.push({ kind: "document_level_impact", path, reason: "input changed without an anchor-bounded graph change" });
    }
    for (const id of ids) traversalSeeds.add(id);
  }

  const related = new Map();
  const collect = (projection, seed) => {
    if (!projection?.items?.some((value) => value.semantic_id === seed)) return;
    const packet = queryPacket(projection, seed, { direction: "both" });
    for (const value of packet.related) if (!seeds.has(value.semantic_id)) related.set(value.semantic_id, value);
  };
  for (const seed of traversalSeeds) { collect(before, seed); collect(after, seed); }

  const receipt = {
    before: before.receipt ?? null,
    after: after.receipt ?? null,
    input_changes,
    changed_paths: input_changes.changed_paths,
  };
  const packet = packetFor(after, changed, [...related.values()], uniqueUnresolved, { receipt });
  packet.added = items.added;
  packet.removed = items.removed;
  packet.modified = items.modified;
  packet.edge_changes = { added: sortEdges(edgeAdded), removed: sortEdges(edgeRemoved) };
  packet.edges = sortEdges([...new Map([...beforeEdges, ...afterEdges].map(([key, edge]) => [key, edge])).values()]);
  packet.collision_risks = collisionRisks([...packet.changed, ...packet.related]);
  return packet;
}

function anchorForEdge(edge, items) {
  const from = items.get(edge.from);
  const to = items.get(edge.to);
  return from?.type === "spec_anchor" ? from : to?.type === "spec_anchor" ? to : null;
}

/** Return declared (not executed) vector coverage grouped by normative anchor. */
export function coverageReport(projection) {
  const index = graphIndex(projection);
  const coveredIds = new Set();
  const vectorEdges = [];
  for (const edge of index.edges) {
    if (edge.relation !== "covers") continue;
    const anchor = anchorForEdge(edge, index.items);
    const vector = index.items.get(edge.from)?.type === "vector" ? index.items.get(edge.from) : index.items.get(edge.to)?.type === "vector" ? index.items.get(edge.to) : null;
    if (!anchor || !vector) continue;
    coveredIds.add(anchor.semantic_id);
    vectorEdges.push({ edge, anchor, vector });
  }
  const anchors = sortItems([...index.items.values()].filter((value) => value.type === "spec_anchor"));
  const covered = anchors.filter((value) => coveredIds.has(value.semantic_id));
  const uncovered = anchors.filter((value) => !coveredIds.has(value.semantic_id));
  const declared = anchors.map((anchor) => {
    const cases = index.edges
      .filter((edge) => edge.relation === "declares" && edge.to === anchor.semantic_id && index.items.get(edge.from)?.type === "draft_case")
      .map((edge) => edge.from).sort(compareStrings);
    const vectors = vectorEdges.filter(({ anchor: candidate }) => candidate.semantic_id === anchor.semantic_id)
      .map(({ vector }) => vector.semantic_id).sort(compareStrings);
    return { ...anchor, covered: coveredIds.has(anchor.semantic_id), declared_by: cases, vector_ids: vectors, evidence: cases.length || vectors.length ? "declared" : "unresolved" };
  });
  const byOwner = new Map();
  for (const anchor of anchors) {
    const owner = anchor.owner ?? anchor.semantic_id.match(/^heterodyne:([^#]+)#/)?.[1] ?? "unknown";
    if (!byOwner.has(owner)) byOwner.set(owner, []);
    byOwner.get(owner).push({ ...anchor, covered: coveredIds.has(anchor.semantic_id), declared_only: true });
  }
  return {
    declared_only: true,
    anchors,
    covered,
    uncovered,
    declared,
    documents: [...byOwner].sort(([a], [b]) => compareStrings(a, b)).map(([owner, values]) => ({ owner, anchors: sortItems(values), declared: declared.filter((entry) => (entry.owner ?? owner) === owner) })),
    relations: vectorEdges.sort((a, b) => compareStrings(a.anchor.semantic_id, b.anchor.semantic_id)).map(({ edge }) => edge),
    receipt: projection.receipt ?? null,
  };
}

/** Produce stable anchor/vector rows plus all other declared graph relations. */
export function traceabilityMatrix(projection) {
  const index = graphIndex(projection);
  const rows = [];
  const coveredAnchors = new Set();
  for (const edge of sortEdges(index.edges)) {
    const anchor = anchorForEdge(edge, index.items);
    const from = index.items.get(edge.from);
    const to = index.items.get(edge.to);
    const vector = from?.type === "vector" ? from : to?.type === "vector" ? to : null;
    if (anchor && vector && edge.relation === "covers") coveredAnchors.add(anchor.semantic_id);
    rows.push({
      anchor_id: anchor?.semantic_id ?? "",
      owner: anchor?.owner ?? "",
      heading: anchor?.heading ?? "",
      vector_id: vector?.semantic_id?.replace(/^vector:/u, "") ?? "",
      profile: vector?.profile ?? "",
      vector_path: vector?.source_path ?? "",
      lane: projection.receipt?.lane ?? "",
      from: edge.from,
      to: edge.to,
      relation: edge.relation,
      source_path: edge.source_path,
    });
  }
  for (const anchor of sortItems([...index.items.values()].filter((value) => value.type === "spec_anchor" && !coveredAnchors.has(value.semantic_id)))) {
    rows.push({ anchor_id: anchor.semantic_id, owner: anchor.owner ?? "", heading: anchor.heading ?? "", vector_id: "", profile: "", vector_path: "", lane: projection.receipt?.lane ?? "", from: "", to: "", relation: "uncovered", source_path: anchor.source_path });
  }
  return rows.sort((a, b) => compareStrings(a.anchor_id, b.anchor_id) || compareStrings(a.vector_id, b.vector_id) || compareStrings(a.relation, b.relation));
}

function ownerOf(value) {
  if (typeof value.owner === "string" && value.owner) return value.owner;
  const match = value.semantic_id?.match(/^heterodyne:([^#]+)#|^(?:vector|case):([^/]+)/u);
  return match?.[1] ?? match?.[2] ?? "unassigned";
}

function collisionRisks(values) {
  const files = new Map();
  for (const value of values) {
    if (typeof value.source_path !== "string" || !value.source_path) continue;
    if (!files.has(value.source_path)) files.set(value.source_path, []);
    files.get(value.source_path).push(value);
  }
  return [...files].filter(([, entries]) => new Set(entries.map((value) => value.semantic_id)).size > 1)
    .sort(([a], [b]) => compareStrings(a, b))
    .map(([path, entries]) => ({ path, items: sortItems(entries).map((value) => value.semantic_id), owners: [...new Set(entries.map(ownerOf))].sort(compareStrings), reason: "multiple impacted graph items share a file" }));
}

/** Group packet records by owner and conservatively report parallel safety. */
export function buildWorklist(packet) {
  if (!packet || !Array.isArray(packet.changed) || !Array.isArray(packet.related)) throw new TypeError("packet must contain changed and related arrays");
  const values = [...packet.changed, ...packet.related];
  const groups = new Map();
  for (const value of values) {
    const owner = ownerOf(value);
    if (!groups.has(owner)) groups.set(owner, { owner, items: [], files: [] });
    const group = groups.get(owner);
    if (!group.items.some((entry) => entry.semantic_id === value.semantic_id)) group.items.push(value);
    if (value.source_path && !group.files.includes(value.source_path)) group.files.push(value.source_path);
  }
  const collisions = [...(packet.collision_risks ?? []), ...collisionRisks(values)];
  const uniqueCollisions = [...new Map(collisions.map((value) => [value.path, value])).values()].sort((a, b) => compareStrings(a.path, b.path));
  for (const group of groups.values()) { group.items = sortItems(group.items); group.files.sort(compareStrings); }
  const unresolved = packet.unresolved ?? [];
  return {
    groups: [...groups.values()].sort((a, b) => compareStrings(a.owner, b.owner)),
    collision_risks: uniqueCollisions,
    unresolved,
    parallel_safe: uniqueCollisions.length === 0 && unresolved.length === 0,
    suggested_checks: packet.suggested_checks?.length ? [...packet.suggested_checks] : candidateChecks(values),
    receipt: packet.receipt ?? null,
  };
}

export function formatMatrixCsv(rows) {
  const columns = ["anchor_id", "owner", "heading", "vector_id", "profile", "vector_path", "lane"];
  const quote = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  return `${[columns.join(","), ...rows.map((row) => columns.map((column) => quote(row[column])).join(","))].join("\r\n")}\r\n`;
}
