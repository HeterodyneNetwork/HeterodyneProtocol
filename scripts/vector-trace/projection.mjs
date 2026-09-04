import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { extname, posix } from "node:path";

import { readInputs } from "./history.mjs";

const SPECS = new Map([
  ["docs/spec/heterodyne-core.md", "core"],
  ["docs/spec/heterodyne-assurance.md", "assurance"],
  ["docs/spec/heterodyne-comms.md", "comms"],
  ["docs/spec/heterodyne-control.md", "control"],
  ["docs/spec/heterodyne-social.md", "social"],
  ["docs/spec/heterodyne-workspace.md", "workspace"],
]);
const SNAPSHOT = "docs/spec/vectors/snapshot.json";
const COVERAGE = "docs/spec/vectors/coverage/manifest.json";
const VECTOR_SCHEMA = "docs/spec/vectors/schema/vector.schema.json";
const LANES = new Set(["draft", "snapshot", "reconciliation"]);
const VECTOR_SCHEMA_VERSIONS = new Set(["2.0.0", "3.0.0"]);
const FULL_COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ARTIFACT_PATH = /^docs\/spec\/vectors\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9._-]+(?:\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9._-]+)*$/;
const EXCLUDED_TOP_LEVEL_DIRECTORIES = new Set(["coverage", "generator", "schema"]);
const EXCLUDED_TOP_LEVEL_FILES = new Set([
  "fixtures.json", "snapshot.json", "snapshot.meta.schema.json", "snapshot.schema.json",
  "snapshot-unique-by-path.meta.schema.json",
]);
const SUPPORT_PATHS = new Set([
  "fixtures.json",
  "coverage/manifest.json", "coverage/core.md", "coverage/comms.md", "coverage/control.md",
  "coverage/social.md", "coverage/workspace.md", "coverage/family.md", "schema/vector.schema.json",
  "schema/reason-codes.json", "schema/reason-codes.md",
]);
const OPTIONAL_SUPPORT_PATHS = new Set(["coverage/assurance.md"]);
const require = createRequire(import.meta.url);
const { default: Ajv } = require("../../docs/spec/vectors/generator/node_modules/ajv");

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function graphDigest(value) {
  return sha256(`${JSON.stringify(canonicalize(value))}\n`);
}

function parseSnapshotManifest(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`snapshot manifest must be an object: ${label}`);
  const keys = Object.keys(value).sort();
  if (keys.join("\0") !== ["artifacts", "snapshot_schema", "source_commit", "vector_count", "vector_schema_version"].join("\0")) {
    throw new Error(`snapshot manifest has unexpected fields: ${label}`);
  }
  if (value.snapshot_schema !== "1") throw new Error("snapshot schema must be 1");
  if (!FULL_COMMIT.test(value.source_commit ?? "")) throw new Error("snapshot source commit must be 40-lowercase-hex");
  if (!VECTOR_SCHEMA_VERSIONS.has(value.vector_schema_version)) throw new Error(`unsupported snapshot vector schema: ${value.vector_schema_version}`);
  if (!Number.isSafeInteger(value.vector_count) || value.vector_count < 0) throw new Error("snapshot vector count must be a non-negative safe integer");
  if (!Array.isArray(value.artifacts)) throw new Error("snapshot artifacts must be an array");
  let previous;
  const seen = new Set();
  for (const [index, artifact] of value.artifacts.entries()) {
    if (artifact === null || typeof artifact !== "object" || Array.isArray(artifact)) throw new Error(`malformed snapshot artifact ${index}`);
    if (Object.keys(artifact).sort().join("\0") !== "path\0sha256") throw new Error(`malformed snapshot artifact ${index}`);
    if (!ARTIFACT_PATH.test(artifact.path ?? "")) throw new Error(`unsafe snapshot artifact path: ${String(artifact.path)}`);
    if (!SHA256.test(artifact.sha256 ?? "")) throw new Error(`invalid snapshot artifact digest: ${artifact.path}`);
    if (seen.has(artifact.path)) throw new Error(`duplicate snapshot artifact: ${artifact.path}`);
    if (previous !== undefined && previous >= artifact.path) throw new Error("snapshot artifact paths must be unique and strictly sorted");
    seen.add(artifact.path); previous = artifact.path;
  }
  return value;
}

function artifactRelativePath(path) {
  return path.slice("docs/spec/vectors/".length);
}

function isVectorArtifact(path) {
  const relative = artifactRelativePath(path);
  const [top, ...rest] = relative.split("/");
  if (EXCLUDED_TOP_LEVEL_DIRECTORIES.has(top)) return false;
  if (rest.length === 0) return path.endsWith(".json") && !EXCLUDED_TOP_LEVEL_FILES.has(top);
  return path.endsWith(".json");
}

function gitBytes(repo, args) {
  const result = spawnSync("git", args, { cwd: repo, maxBuffer: 512 * 1024 * 1024 + 8 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(result.stderr?.toString().trim() || `git ${args.join(" ")} failed`);
  return result.stdout;
}

function snapshotInventory(repo, ref) {
  const records = gitBytes(repo, ["ls-tree", "-r", "-z", `${ref}^{commit}`, "--", "docs/spec/vectors"])
    .toString("utf8").split("\0").filter(Boolean);
  const paths = [];
  for (const record of records) {
    const match = record.match(/^(\d+) (blob|commit|tree) [0-9a-f]+\t(.+)$/);
    if (!match) throw new Error(`malformed historical vector tree entry: ${record}`);
    if (match[1] === "120000") throw new Error(`snapshot path must not be a symbolic link: ${match[3]}`);
    if (match[2] !== "blob") continue;
    const path = match[3];
    const relative = artifactRelativePath(path);
    const [top] = relative.split("/");
    if (SUPPORT_PATHS.has(relative)) {
      paths.push(path);
    } else if (EXCLUDED_TOP_LEVEL_DIRECTORIES.has(top)) {
      if (SUPPORT_PATHS.has(relative) || OPTIONAL_SUPPORT_PATHS.has(relative)) paths.push(path);
    } else {
      const candidate = (relative.split("/").length === 1 && path.endsWith(".json") && !EXCLUDED_TOP_LEVEL_FILES.has(top))
        || (relative.split("/").length > 1 && path.endsWith(".json"));
      if (!candidate) continue;
      if (!ARTIFACT_PATH.test(path)) throw new Error(`unsafe snapshot tree path: ${path}`);
      paths.push(path);
    }
  }
  return paths.sort();
}

export function semanticUuid(type, semanticId) {
  const bytes = createHash("sha256").update(`heterodyne-vector-trace-v1\0${type}\0${semanticId}`).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function anchorSections({ owner, path, content }) {
  const lines = content.replaceAll("\r\n", "\n").split("\n");
  const sections = [];
  for (let anchorLine = 0; anchorLine < lines.length; anchorLine += 1) {
    const anchor = lines[anchorLine].match(/^<a id="([a-z0-9-]+)"><\/a>\s*$/);
    if (!anchor) continue;
    let start = anchorLine + 1;
    while (lines[start]?.trim() === "") start += 1;
    let heading = lines[start]?.match(/^(#{1,6})\s+(.+?)\s*$/);
    const headingAfter = Boolean(heading);
    if (!heading) {
      for (let index = anchorLine - 1; index >= 0; index -= 1) {
        heading = lines[index].match(/^(#{1,6})\s+(.+?)\s*$/);
        if (heading) break;
      }
    }
    if (!heading) throw new Error(`anchor ${anchor[1]} has no containing heading in ${path}`);
    const level = heading[1].length;
    let end = lines.length;
    for (let index = start + (headingAfter ? 1 : 0); index < lines.length; index += 1) {
      if (!headingAfter && /^<a id="[a-z0-9-]+"><\/a>\s*$/.test(lines[index])) { end = index; break; }
      const candidate = lines[index].match(/^(#{1,6})\s+/);
      if (candidate && candidate[1].length <= level) {
        end = index;
        let prior = index - 1;
        while (prior >= start && lines[prior].trim() === "") prior -= 1;
        if (/^<a id="[a-z0-9-]+"><\/a>\s*$/.test(lines[prior] ?? "")) end = prior;
        break;
      }
    }
    const bounded = `${lines.slice(start, end).join("\n").replace(/\n*$/, "")}\n`;
    const semanticId = `heterodyne:${owner}#${anchor[1]}`;
    sections.push({
      content: bounded,
      item: {
        semantic_id: semanticId, sara_id: semanticUuid("spec_anchor", semanticId), type: "spec_anchor",
        owner, heading: heading[2], source_path: path, source_line: anchorLine + 1,
        source_digest: sha256(bounded), evidence_kind: "normative_spec",
      },
    });
  }
  return sections;
}

export function extractSpecAnchors(options) {
  return anchorSections(options).map(({ item }) => item);
}

export function indexItems(items) {
  const bySemanticId = new Map();
  const bySaraId = new Map();
  for (const item of items) {
    if (bySemanticId.has(item.semantic_id)) throw new Error(`duplicate semantic id: ${item.semantic_id}`);
    if (bySaraId.has(item.sara_id)) throw new Error(`duplicate SARA id: ${item.sara_id}`);
    bySemanticId.set(item.semantic_id, item);
    bySaraId.set(item.sara_id, item);
  }
  return { bySemanticId, bySaraId };
}

function parseJson(content, label) {
  try { return JSON.parse(content); } catch (error) { throw new Error(`malformed JSON in ${label}: ${error.message}`); }
}

function gitText(repo, args) {
  const result = spawnSync("git", args, { cwd: repo, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(result.stderr.trim() || `git ${args.join(" ")} failed`);
  return result.stdout.trim();
}

function sourceFilter(path) {
  if (SPECS.has(path)) return true;
  if ((path.startsWith("docs/spec/registry/") || path.startsWith("docs/spec/schemas/")) && path.endsWith(".json")) return true;
  if (path.startsWith("docs/spec/vectors/generator/src/") && [".ts", ".mjs"].includes(extname(path))) return true;
  if (/^docs\/spec\/vectors\/generator\/(package(?:-lock)?\.json|tsconfig[^/]*\.json|[^/]*\.config\.ts)$/.test(path)) return true;
  return false;
}

function loadSources(repo, ref) {
  return readInputs(repo, ref, {
    paths: [...SPECS.keys(),
      "docs/spec/vectors/generator/package.json",
      "docs/spec/vectors/generator/package-lock.json",
      "docs/spec/vectors/generator/tsconfig.json",
      "docs/spec/vectors/generator/tsconfig.current.json",
      "docs/spec/vectors/generator/vitest.current.config.ts",
    ],
    roots: ["docs/spec/registry", "docs/spec/schemas", "docs/spec/vectors/generator/src"],
    filter: sourceFilter,
  });
}

function snapshotBinding(repo) {
  const commit = gitText(repo, ["log", "-1", "--format=%H", "--", SNAPSHOT]);
  if (!commit) throw new Error(`snapshot history binding is unavailable for ${SNAPSHOT}`);
  return commit;
}

function loadVectors(repo, ref) {
  const manifestRead = readInputs(repo, ref, { paths: [SNAPSHOT] });
  const resolved = manifestRead.resolved_ref;
  const snapshot = parseJson(manifestRead.contents.get(SNAPSHOT), `${resolved}:${SNAPSHOT}`);
  parseSnapshotManifest(snapshot, `${resolved}:${SNAPSHOT}`);
  const expectedPaths = snapshotInventory(repo, resolved);
  const declaredPaths = snapshot.artifacts.map(({ path }) => path);
  if (declaredPaths.length !== expectedPaths.length || declaredPaths.some((path, index) => path !== expectedPaths[index])) {
    throw new Error("snapshot artifact inventory mismatch");
  }
  if (!declaredPaths.includes(COVERAGE) || !declaredPaths.includes(VECTOR_SCHEMA)) throw new Error(`snapshot does not declare required support artifacts`);
  const artifactRead = readInputs(repo, resolved, { paths: declaredPaths });
  for (const artifact of snapshot.artifacts) {
    if (sha256(artifactRead.contents.get(artifact.path)) !== artifact.sha256) throw new Error(`snapshot digest mismatch: ${artifact.path}`);
  }
  return {
    snapshot, resolved_ref: resolved,
    contents: new Map([...manifestRead.contents, ...artifactRead.contents]),
    inputs: [...manifestRead.inputs, ...artifactRead.inputs],
  };
}

function item(type, semanticId, path, content, evidenceKind, extra = {}) {
  return { semantic_id: semanticId, sara_id: semanticUuid(type, semanticId), type, source_path: path, source_digest: sha256(content), evidence_kind: evidenceKind, ...extra };
}

function createGraph(sourceContents, vectorData) {
  const items = [];
  const edges = [];
  const unresolved = [];
  const sections = [];
  for (const [path, owner] of SPECS) {
    const content = sourceContents.get(path);
    if (content === undefined) continue;
    const parsed = anchorSections({ owner, path, content });
    sections.push(...parsed); items.push(...parsed.map((section) => section.item));
  }
  const referencedArtifacts = [];
  for (const [path, content] of sourceContents) {
    if (path.startsWith("docs/spec/registry/") && path.endsWith(".json")) {
      const value = item("registry_artifact", `registry:${path}`, path, content, "normative_registry"); items.push(value); referencedArtifacts.push({ value, keys: [path], relation: "uses_registry" });
    } else if (path.startsWith("docs/spec/schemas/") && path.endsWith(".json")) {
      const parsed = parseJson(content, path); const key = typeof parsed.$id === "string" ? parsed.$id : path;
      const value = item("schema_artifact", `schema:${key}`, path, content, "normative_schema"); items.push(value); referencedArtifacts.push({ value, keys: [...new Set([path, key])], relation: "uses_schema" });
    } else if (path.startsWith("docs/spec/vectors/generator/")) {
      items.push(item("source_module", `source:${path}`, path, content, "generator_input"));
    }
  }
  for (const section of sections) for (const artifact of referencedArtifacts) {
    const linkedPaths = [...section.content.matchAll(/\]\((?:<)?([^\s)>]+)(?:>)?\)/g)]
      .map((match) => match[1].split("#", 1)[0])
      .filter((target) => target && !target.startsWith("/"))
      .map((target) => posix.normalize(posix.join(posix.dirname(section.item.source_path), target)));
    if (artifact.keys.some((key) => section.content.includes(key) || linkedPaths.includes(key))) {
      edges.push({ from: section.item.semantic_id, to: artifact.value.semantic_id, relation: artifact.relation, source_path: section.item.source_path });
    }
  }
  if (vectorData) {
    const coverage = parseJson(vectorData.contents.get(COVERAGE), `${vectorData.resolved_ref}:${COVERAGE}`);
    if (!Array.isArray(coverage)) throw new Error(`malformed coverage manifest: ${COVERAGE}`);
    const schema = parseJson(vectorData.contents.get(VECTOR_SCHEMA), `${vectorData.resolved_ref}:${VECTOR_SCHEMA}`);
    if (schema?.properties?.vector_schema_version?.const !== vectorData.snapshot.vector_schema_version) throw new Error("snapshot schema version disagreement: packaged vector schema");
    const validateVector = new Ajv({ allErrors: true, strict: false }).compile(schema);
    const vectors = new Map();
    for (const path of vectorData.snapshot.artifacts.map(({ path }) => path).filter(isVectorArtifact)) {
      const content = vectorData.contents.get(path);
      const value = parseJson(content, `${vectorData.resolved_ref}:${path}`);
      if (!validateVector(value)) {
        const details = (validateVector.errors ?? []).map(({ instancePath, message }) => `${instancePath || "/"} ${message}`).join(", ");
        throw new Error(`vector schema validation failed for ${path}: ${details}`);
      }
      if (vectors.has(value.vector_id)) throw new Error(`conflicting vector id: ${value.vector_id}`);
      vectors.set(value.vector_id, { path, content, value });
    }
    if (vectors.size !== vectorData.snapshot.vector_count) throw new Error(`snapshot vector_count mismatch: expected ${vectorData.snapshot.vector_count}, found ${vectors.size}`);
    const coverageIds = new Set();
    for (const entry of coverage) {
      if (typeof entry?.vector_id !== "string" || typeof entry.owner_document !== "string" || !Array.isArray(entry.spec_refs)) throw new Error(`malformed coverage entry in ${COVERAGE}`);
      if (coverageIds.has(entry.vector_id)) throw new Error(`conflicting coverage vector id: ${entry.vector_id}`);
      coverageIds.add(entry.vector_id);
      const vector = vectors.get(entry.vector_id);
      if (!vector) throw new Error(`missing vector artifact: ${entry.vector_id}`);
      if (vector.value.owner_document !== entry.owner_document) throw new Error(`incorrect declared owner for ${entry.vector_id}: ${vector.value.owner_document} != ${entry.owner_document}`);
      if (entry.profile !== vector.value.profile) throw new Error(`coverage profile mismatch for ${entry.vector_id}`);
      if (!entry.spec_refs.every((ref) => typeof ref === "string" && /^heterodyne:(core|assurance|comms|control|social|workspace)#[a-z0-9][a-z0-9-]*$/.test(ref))) throw new Error(`malformed coverage reference for ${entry.vector_id}`);
      if (entry.spec_refs.some((ref) => ref.split(":", 2)[1].split("#", 1)[0] !== entry.owner_document)) throw new Error(`coverage reference owner mismatch for ${entry.vector_id}`);
      if (JSON.stringify(entry.spec_refs) !== JSON.stringify(vector.value.spec_refs)) throw new Error(`coverage references mismatch for ${entry.vector_id}`);
      const semanticId = `vector:${entry.vector_id}`;
      items.push(item("vector", semanticId, vector.path, vector.content, "historical_vector", { owner: entry.owner_document, ...(entry.profile === undefined ? {} : { profile: entry.profile }) }));
      for (const ref of entry.spec_refs) {
        const edge = { from: semanticId, to: ref, relation: "covers", source_path: COVERAGE };
        if (items.some((candidate) => candidate.semantic_id === ref)) edges.push(edge); else unresolved.push(edge);
      }
    }
    if (coverageIds.size !== vectors.size) throw new Error(`coverage inventory mismatch: ${coverageIds.size} entries for ${vectors.size} vectors`);
  }
  items.sort((a, b) => a.semantic_id.localeCompare(b.semantic_id));
  edges.sort((a, b) => a.from.localeCompare(b.from) || a.relation.localeCompare(b.relation) || a.to.localeCompare(b.to));
  unresolved.sort((a, b) => a.from.localeCompare(b.from) || a.to.localeCompare(b.to));
  indexItems(items);
  return { items, edges, unresolved };
}

export async function buildProjection({ repo, lane, vectorRef, ref } = {}) {
  if (lane === undefined) throw new Error("lane is required");
  if (!LANES.has(lane)) throw new Error(`invalid lane: ${lane}`);
  const root = realpathSync(repo);
  const repositoryHead = gitText(root, ["rev-parse", "HEAD"]);
  let vectors;
  let specRef;
  if (lane === "draft") {
    specRef = ref ?? "WORKTREE";
    if (vectorRef !== undefined) throw new Error("draft lane does not accept vectorRef");
  } else if (lane === "snapshot") {
    if (ref !== undefined) throw new Error("snapshot lane source ref is fixed by the snapshot");
    vectors = loadVectors(root, vectorRef ?? snapshotBinding(root));
    specRef = vectors.snapshot.source_commit;
  } else {
    if (vectorRef === undefined) throw new Error("reconciliation requires vectorRef");
    vectors = loadVectors(root, vectorRef);
    specRef = ref ?? "WORKTREE";
  }
  const sources = loadSources(root, specRef);
  const graph = createGraph(sources.contents, vectors);
  const inputs = [...sources.inputs, ...(vectors?.inputs ?? [])].sort((a, b) => a.ref.localeCompare(b.ref) || a.path.localeCompare(b.path));
  const receipt = {
    receipt_schema: "1", parser_version: "2", graph_version: "2", lane,
    repository_head: repositoryHead, spec_ref: specRef === "WORKTREE" ? "WORKTREE" : sources.resolved_ref,
    vector_ref: vectors?.resolved_ref ?? null, ...(lane === "reconciliation" ? { maintenance_only: true } : {}),
    inputs, input_inventory_sha256: graphDigest(inputs),
    unresolved_references: graph.unresolved, graph_sha256: graphDigest({ items: graph.items, edges: graph.edges }),
  };
  const projection = { repository_root: root, items: graph.items, edges: graph.edges, receipt };
  Object.defineProperty(projection, "sourceContents", { value: sources.contents, enumerable: false });
  finalizeProjection(projection);
  const checked = verifyReceipt(projection);
  if (!checked.fresh) throw new Error(checked.issues.join("; "));
  return projection;
}

export function finalizeProjection(projection) {
  projection.receipt.graph_sha256 = graphDigest({ items: projection.items, edges: projection.edges });
  return projection;
}

export function verifyReceipt(projection) {
  const issues = [];
  if (projection.receipt.graph_sha256 !== graphDigest({ items: projection.items, edges: projection.edges })) {
    issues.push("graph digest mismatch");
  }
  try {
    const currentSources = loadSources(projection.repository_root, projection.receipt.spec_ref);
    const currentVectors = projection.receipt.vector_ref === null ? undefined : loadVectors(projection.repository_root, projection.receipt.vector_ref);
    const currentInputs = [...currentSources.inputs, ...(currentVectors?.inputs ?? [])]
      .sort((a, b) => a.ref.localeCompare(b.ref) || a.path.localeCompare(b.path));
    const inventory = graphDigest(currentInputs);
    if (inventory !== projection.receipt.input_inventory_sha256) issues.push("stale input inventory");
  } catch (error) {
    issues.push(`unavailable input inventory: ${error.message}`);
  }
  const groups = new Map();
  for (const input of projection.receipt.inputs) {
    if (!groups.has(input.ref)) groups.set(input.ref, []);
    groups.get(input.ref).push(input);
  }
  for (const [ref, inputs] of groups) {
    let read;
    try { read = readInputs(projection.repository_root, ref, { paths: inputs.map(({ path }) => path) }); }
    catch { for (const input of inputs) issues.push(`unavailable input: ${input.path}`); continue; }
    for (const input of inputs) if (sha256(read.contents.get(input.path)) !== input.sha256) issues.push(`stale input: ${input.path}`);
  }
  return { fresh: issues.length === 0, issues: issues.sort() };
}
