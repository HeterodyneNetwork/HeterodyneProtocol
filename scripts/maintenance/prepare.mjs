import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { basename, dirname, isAbsolute, join, normalize, relative, sep } from "node:path";
import { buildGraph } from "../vector-trace.mjs";
import { compilePacket } from "./packet.mjs";

const MAX_TOKENS = 8000;
const TOKEN_ESTIMATOR = "utf8-bytes-per-4-v1";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function canonicalJson(value) { return JSON.stringify(canonical(value)); }
function digestJson(value) { return sha256(`${canonicalJson(value)}\n`); }

function safeRelativePath(path) {
  if (typeof path !== "string" || path.length === 0 || isAbsolute(path)) return false;
  const cleaned = normalize(path).split(sep).join("/");
  return cleaned === path && cleaned !== ".." && !cleaned.startsWith("../") && !cleaned.includes("/../");
}

function graphItems(graph, type) {
  return (Array.isArray(graph?.items) ? graph.items : []).filter((item) => item?.type === type);
}

function itemOwner(item) {
  if (typeof item?.owner === "string" && item.owner.length > 0) return item.owner;
  const match = typeof item?.semantic_id === "string" ? /^heterodyne:([^#]+)#/u.exec(item.semantic_id) : null;
  return match?.[1] ?? "unknown";
}

function itemLine(item) {
  if (Number.isInteger(item?.source_line) && item.source_line > 0) return item.source_line;
  if (Number.isInteger(item?.declaration_location?.line) && item.declaration_location.line > 0) return item.declaration_location.line;
  return "?";
}

function caseReferences(graph, item) {
  const refs = Array.isArray(item.spec_refs) ? item.spec_refs
    : Array.isArray(item.raw_refs) ? item.raw_refs
      : (Array.isArray(graph?.edges) ? graph.edges
        .filter((edge) => edge.from === item.semantic_id && edge.relation === "declares")
        .map((edge) => edge.raw_ref ?? edge.to)
        .filter((ref) => typeof ref === "string") : []);
  return [...new Set(refs)];
}

export function renderReferences(graph) {
  const anchors = new Set(graphItems(graph, "spec_anchor").map((item) => item.semantic_id));
  const groups = new Map();
  for (const item of graphItems(graph, "draft_case")) {
    const refs = caseReferences(graph, item);
    const keys = refs.length > 0 ? refs : ["unknown (no declared spec_refs)"];
    for (const ref of keys) {
      if (!groups.has(ref)) groups.set(ref, []);
      groups.get(ref).push({
        id: item.semantic_id,
        path: item.source_path ?? "?",
        line: itemLine(item),
        boundary: item.boundary_id ?? "?",
        status: ref.startsWith("unknown ") ? "unknown"
          : anchors.has(ref) ? "anchor present; governing status not established"
            : "unresolved: anchor missing from graph",
      });
    }
  }
  const lines = ["# Declared draft-case references", "", "Existing anchors are indexed only; presence does not establish governing semantics.", ""];
  for (const [ref, cases] of [...groups.entries()].sort(([left], [right]) => left.localeCompare(right, "en"))) {
    lines.push(`## ${ref}`, "");
    for (const entry of cases.sort((left, right) => left.id.localeCompare(right.id, "en"))) {
      lines.push(`- \`${entry.id}\` — ${entry.path}:${entry.line}; boundary: \`${entry.boundary}\`; ${entry.status}`);
    }
    lines.push("");
  }
  if (groups.size === 0) lines.push("## unknown (no draft cases)", "", "No draft cases were present in the graph.", "");
  return `${lines.join("\n").replace(/\n+$/u, "")}\n`;
}

export function renderAnchors(graph) {
  const groups = new Map();
  const fullDigests = new Map((graph?.receipt?.inputs ?? [])
    .filter((input) => typeof input?.path === "string")
    .map((input) => [input.path, input.sha256 ?? "?"]));
  for (const item of graphItems(graph, "spec_anchor")) {
    const owner = itemOwner(item);
    if (!groups.has(owner)) groups.set(owner, []);
    groups.get(owner).push(item);
  }
  const lines = ["# Specification anchor index", "", "Grouped by source document; this is not a case-to-anchor or governing-answer map.", ""];
  for (const [owner, items] of [...groups.entries()].sort(([left], [right]) => left.localeCompare(right, "en"))) {
    lines.push(`## ${owner}`, "");
    for (const item of items.sort((left, right) => left.semantic_id.localeCompare(right.semantic_id, "en"))) {
      lines.push(`- \`${item.semantic_id}\` — ${item.heading ?? "?"}; ${item.source_path ?? "?"}:${itemLine(item)}; section digest: \`${item.source_digest ?? "?"}\`; full source digest: \`${fullDigests.get(item.source_path) ?? "?"}\``);
    }
    lines.push("");
  }
  if (groups.size === 0) lines.push("## unknown", "", "No specification anchors were present in the graph.", "");
  return `${lines.join("\n").replace(/\n+$/u, "")}\n`;
}

function lineSpan(source, startLine, endLine) {
  const starts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") starts.push(index + 1);
  }
  const start = starts[startLine - 1] ?? source.length;
  const end = starts[endLine] ?? source.length;
  return { start, end };
}

function excerptRecord(excerpt, source) {
  if (!excerpt || typeof excerpt.path !== "string" || !safeRelativePath(excerpt.path)) throw new Error(`unsafe additional source excerpt path: ${excerpt?.path ?? ""}`);
  if (!Number.isInteger(excerpt.startLine) || excerpt.startLine < 1 || !Number.isInteger(excerpt.endLine) || excerpt.endLine < excerpt.startLine) throw new Error(`invalid additional source excerpt range: ${excerpt.path}`);
  const lines = source.split("\n").length - (source.endsWith("\n") ? 1 : 0);
  if (excerpt.endLine > lines) throw new Error(`additional source excerpt range outside file: ${excerpt.path}`);
  const span = lineSpan(source, excerpt.startLine, excerpt.endLine);
  return {
    path: excerpt.path,
    purpose: excerpt.purpose ?? "",
    startLine: excerpt.startLine,
    endLine: excerpt.endLine,
    sourceDigest: sha256(Buffer.from(source, "utf8")),
    bytes: Buffer.byteLength(source, "utf8"),
    content: source.slice(span.start, span.end),
  };
}

export function renderTests(records) {
  const lines = ["# Additional source excerpts", ""];
  if (records.length === 0) lines.push("No additional source excerpts were declared.", "");
  for (const record of records) {
    lines.push(`## ${record.path}:${record.startLine}-${record.endLine}`, "");
    if (record.purpose) lines.push(record.purpose, "");
    lines.push(`Source digest: \`${record.sourceDigest}\`; bytes: ${record.bytes}`, "", "```text", record.content.replace(/\n$/u, ""), "```", "");
  }
  return `${lines.join("\n").replace(/\n+$/u, "")}\n`;
}

function git(repo, args) {
  const result = spawnSync("git", args, { cwd: repo, encoding: "utf8" });
  if (result.status !== 0) throw new Error((result.stderr || "git command failed").trim());
  return result.stdout.trim();
}

async function canonicalRepo(repo) {
  if (typeof repo !== "string" || repo.length === 0) throw new TypeError("repo is required");
  const root = await realpath(repo);
  const top = await realpath(git(root, ["rev-parse", "--show-toplevel"]));
  if (top !== root) throw new Error("repo must be a Git repository root");
  return root;
}

async function validateOutputDirectory(outputDirectory, repo) {
  if (typeof outputDirectory !== "string" || outputDirectory.length === 0) throw new TypeError("outputDirectory is required");
  const requested = normalize(outputDirectory);
  const parent = await realpath(dirname(requested));
  const target = join(parent, basename(requested));
  const rel = relative(repo, target);
  if (rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel))) throw new Error("output directory must be outside the repository worktree");
  try {
    await lstat(target);
    throw new Error("output directory must not already exist");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  return { parent, target };
}

async function regularSource(repo, path) {
  if (!safeRelativePath(path)) throw new Error(`unsafe source path: ${path}`);
  const absolute = join(repo, ...path.split("/"));
  const status = await lstat(absolute);
  if (!status.isFile() || status.isSymbolicLink()) throw new Error(`source input is not a regular file: ${path}`);
  const resolved = await realpath(absolute);
  const rel = relative(repo, resolved);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error(`source input escapes repository: ${path}`);
  return readFile(resolved);
}

async function dirtyInputs(repo, paths) {
  if (paths.length === 0) return;
  const result = spawnSync("git", ["status", "--porcelain=v1", "--untracked-files=all", "--", ...paths], { cwd: repo, encoding: "utf8" });
  if (result.status !== 0) throw new Error((result.stderr || "git status failed").trim());
  if (result.stdout.trim()) throw new Error(`source inputs are dirty: ${result.stdout.trim().split(/\r?\n/u).join("; ")}`);
}

function recipeExcerpts(recipe) { return Array.isArray(recipe?.additionalSourceExcerpts) ? recipe.additionalSourceExcerpts : []; }

function inputPaths(graph, recipe) {
  const paths = new Set((graph?.receipt?.inputs ?? []).map((input) => input?.path).filter((path) => typeof path === "string"));
  for (const excerpt of recipeExcerpts(recipe)) if (typeof excerpt?.path === "string") paths.add(excerpt.path);
  for (const selector of recipe?.task?.selectors ?? []) if (typeof selector?.path === "string") paths.add(selector.path);
  return [...paths].sort((left, right) => left.localeCompare(right, "en"));
}

async function fileInventory(repo, paths) {
  const files = [];
  for (const path of paths) {
    const bytes = await regularSource(repo, path);
    files.push({ path, sha256: sha256(bytes), bytes: bytes.length });
  }
  return files;
}

async function generatedInventory(root) {
  const files = [];
  async function visit(directory, prefix) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name, "en"))) {
      const absolute = join(directory, entry.name);
      const path = `${prefix}/${entry.name}`;
      if (entry.isDirectory()) await visit(absolute, path);
      else if (entry.isSymbolicLink() || !entry.isFile()) throw new Error(`generated artifact is not a regular file: ${path}`);
      else {
        const bytes = await readFile(absolute);
        files.push({ path, sha256: sha256(bytes), bytes: bytes.length });
      }
    }
  }
  await visit(join(root, "artifacts"), "artifacts");
  return files;
}

function byteSummary(files) {
  const combinedUtf8Bytes = files.reduce((total, file) => total + file.bytes, 0);
  const estimatedTokens = Math.ceil(combinedUtf8Bytes / 4);
  return {
    files,
    combinedUtf8Bytes,
    estimatedTokens,
    tokenEstimator: TOKEN_ESTIMATOR,
    maxTokens: MAX_TOKENS,
    expansionBeyond8000: Math.max(0, estimatedTokens - MAX_TOKENS),
    exceeds8000: estimatedTokens > MAX_TOKENS,
  };
}

function startHere() {
  return [
    "# Prepared maintenance context", "", "Read [references.md](references.md),",
    "[anchors.md](anchors.md), [tests.md](tests.md), [packet.json](packet.json),",
    "and [manifest.json](manifest.json). Compiler-owned sidecars are under",
    "[artifacts/](artifacts/).", "", "This context records the pinned input commit",
    "and declared relationships. Existing anchors are not certified as governing;",
    "unresolved, unknown, and declared-but-not-executed information remains visible.",
    "After editing, perform independent semantic and scope review, then rerun the",
    "unchanged full verification gate.", "",
  ].join("\n");
}

export async function prepareContext({ repo, recipe, outputDirectory }) {
  if (!recipe || typeof recipe !== "object" || Array.isArray(recipe)) throw new TypeError("recipe is required");
  if (typeof recipe.inputCommit !== "string" || !/^[0-9a-f]{40}$/u.test(recipe.inputCommit)) throw new Error("recipe.inputCommit must be a full commit ID");
  const repository = await canonicalRepo(repo);
  const { parent, target } = await validateOutputDirectory(outputDirectory, repository);
  const head = git(repository, ["rev-parse", "HEAD"]);
  if (head !== recipe.inputCommit) throw new Error(`repository HEAD does not match recipe inputCommit: ${head} != ${recipe.inputCommit}`);
  const excerpts = recipeExcerpts(recipe);
  for (const excerpt of excerpts) {
    if (!excerpt || !safeRelativePath(excerpt.path)) throw new Error(`unsafe additional source excerpt path: ${excerpt?.path ?? ""}`);
    const bytes = await regularSource(repository, excerpt?.path);
    excerptRecord(excerpt, bytes.toString("utf8"));
  }
  const graph = await buildGraph({ repo: repository, lane: "draft" });
  const paths = inputPaths(graph, recipe);
  await dirtyInputs(repository, paths);
  const files = await fileInventory(repository, paths);
  const tests = [];
  for (const excerpt of excerpts) {
    const bytes = await regularSource(repository, excerpt.path);
    tests.push(excerptRecord(excerpt, bytes.toString("utf8")));
  }
  const staging = await mkdtemp(join(parent, `.${basename(target)}.prepare-`));
  try {
    const artifacts = join(staging, "artifacts");
    await mkdir(artifacts);
    const packet = await compilePacket({ repo: repository, graph, task: recipe.task, deliveredChunkIds: [], artifactDirectory: artifacts });
    const packetBytes = Buffer.from(`${JSON.stringify(packet, null, 2)}\n`, "utf8");
    const referencesBytes = Buffer.from(renderReferences(graph), "utf8");
    const anchorsBytes = Buffer.from(renderAnchors(graph), "utf8");
    const testsBytes = Buffer.from(renderTests(tests), "utf8");
    const startHereBytes = Buffer.from(startHere(), "utf8");
    const rootFiles = [
      ["packet.json", packetBytes],
      ["references.md", referencesBytes],
      ["anchors.md", anchorsBytes],
      ["tests.md", testsBytes],
      ["START-HERE.md", startHereBytes],
    ].map(([path, bytes]) => ({ path, sha256: sha256(bytes), bytes: bytes.length }));
    const sidecarFiles = await generatedInventory(staging);
    const sourceInputs = byteSummary(files);
    const optionalSidecars = byteSummary(sidecarFiles);
    const manifest = {
      version: 2,
      inputCommit: head,
      graphInputDigest: graph.receipt?.input_inventory_sha256 ?? null,
      recipeDigest: digestJson(recipe),
      input: {
        commit: head,
        graphInputDigest: graph.receipt?.input_inventory_sha256 ?? null,
      },
      recipe: {
        digest: digestJson(recipe),
        taskId: recipe.task?.taskId ?? null,
      },
      sourceInputs,
      rootReadingSet: byteSummary([...rootFiles, { path: "manifest.json", bytes: 0 }]),
      optionalSidecars,
      sidecars: sidecarFiles,
      compiler: { estimatedTokens: packet.estimatedTokens ?? null, tokenEstimator: packet.tokenEstimator ?? null, maxTokens: packet.budget?.maxTokens ?? packet.maxTokens ?? null },
    };
    let manifestBytes;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
      const manifestEntry = manifest.rootReadingSet.files.find((file) => file.path === "manifest.json");
      const previous = manifestEntry.bytes;
      manifestEntry.bytes = manifestBytes.length;
      const summary = byteSummary(manifest.rootReadingSet.files);
      Object.assign(manifest.rootReadingSet, summary);
      if (previous === manifestBytes.length) break;
    }
    manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    await writeFile(join(staging, "packet.json"), packetBytes, { flag: "wx", mode: 0o600 });
    await writeFile(join(staging, "references.md"), referencesBytes, { flag: "wx", mode: 0o600 });
    await writeFile(join(staging, "anchors.md"), anchorsBytes, { flag: "wx", mode: 0o600 });
    await writeFile(join(staging, "tests.md"), testsBytes, { flag: "wx", mode: 0o600 });
    await writeFile(join(staging, "manifest.json"), manifestBytes, { flag: "wx", mode: 0o600 });
    await writeFile(join(staging, "START-HERE.md"), startHereBytes, { flag: "wx", mode: 0o600 });
    try {
      await rename(staging, target);
    } catch (error) {
      throw new Error(`could not publish fresh output directory: ${error.message}`, { cause: error });
    }
    return { outputDirectory: target, packet, manifest };
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

export { canonicalJson, digestJson };
