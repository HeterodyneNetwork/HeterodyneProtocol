import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;

function git(repo, args, options = {}) {
  const result = spawnSync("git", args, { cwd: repo, maxBuffer: MAX_TOTAL_BYTES + 8 * 1024 * 1024, ...options });
  if (result.status !== 0) throw new Error((result.stderr?.toString().trim()) || `git ${args.join(" ")} failed`);
  return result.stdout;
}

function safePath(repo, path) {
  if (typeof path !== "string" || path === "" || path.startsWith("/") || path.split("/").includes("..")) {
    throw new Error(`unsafe repository path: ${path}`);
  }
  const root = realpathSync(repo);
  const candidate = resolve(root, path);
  if (!candidate.startsWith(`${root}${sep}`)) throw new Error(`path escapes repository: ${path}`);
  return candidate;
}

function walk(repo, path, output) {
  const absolute = safePath(repo, path);
  if (!existsSync(absolute)) return;
  const stat = lstatSync(absolute);
  if (stat.isSymbolicLink()) throw new Error(`symlink input is not allowed: ${path}`);
  if (stat.isFile()) {
    output.push(path);
    return;
  }
  if (!stat.isDirectory()) return;
  for (const name of readdirSync(absolute).sort()) walk(repo, `${path}/${name}`, output);
}

function digest(content) {
  return createHash("sha256").update(content).digest("hex");
}

function readHistorical(repo, ref, paths) {
  let resolved;
  try {
    resolved = git(repo, ["rev-parse", "--verify", `${ref}^{commit}`], { encoding: "utf8" }).trim();
  } catch {
    throw new Error(`missing Git object ${ref}; fetch full history and retry`);
  }
  if (paths.length === 0) return { resolved, contents: new Map() };
  const requests = paths.map((path) => `${resolved}:${path}`).join("\n") + "\n";
  const raw = git(repo, ["cat-file", "--batch"], { input: requests });
  const contents = new Map();
  let offset = 0;
  for (const path of paths) {
    const newline = raw.indexOf(10, offset);
    if (newline < 0) throw new Error(`could not read Git blob ${resolved}:${path}`);
    const header = raw.subarray(offset, newline).toString();
    offset = newline + 1;
    if (header.endsWith(" missing")) throw new Error(`missing Git object ${resolved}:${path}; fetch full history and retry`);
    const match = header.match(/^[0-9a-f]+ blob ([0-9]+)$/);
    if (!match) throw new Error(`unexpected Git object for ${resolved}:${path}`);
    const size = Number(match[1]);
    if (size > MAX_FILE_BYTES) throw new Error(`Git blob exceeds 64 MiB input limit: ${resolved}:${path}`);
    contents.set(path, raw.subarray(offset, offset + size).toString("utf8"));
    offset += size + 1;
  }
  return { resolved, contents };
}

/** Read a bounded source inventory without executing bytes from the selected ref. */
export function readInputs(repo, ref, { roots = [], paths = [], filter = () => true } = {}) {
  const root = realpathSync(repo);
  let selected = [...paths];
  let resolvedRef = ref;
  let contents;
  if (ref === "WORKTREE") {
    for (const inputRoot of roots) walk(root, inputRoot, selected);
    selected = [...new Set(selected)].filter(filter).sort();
    contents = new Map();
    let total = 0;
    for (const path of selected) {
      const absolute = safePath(root, path);
      if (!existsSync(absolute)) throw new Error(`missing repository input: ${path}`);
      const stat = lstatSync(absolute);
      if (stat.isSymbolicLink()) throw new Error(`symlink input is not allowed: ${path}`);
      if (!stat.isFile()) throw new Error(`repository input is not a file: ${path}`);
      if (stat.size > MAX_FILE_BYTES) throw new Error(`repository input exceeds 64 MiB limit: ${path}`);
      total += stat.size;
      if (total > MAX_TOTAL_BYTES) throw new Error("repository inputs exceed 512 MiB aggregate limit");
      contents.set(path, readFileSync(absolute, "utf8"));
    }
  } else {
    if (roots.length) {
      let listing;
      try {
        listing = git(root, ["ls-tree", "-r", "--name-only", "-z", `${ref}^{commit}`, "--", ...roots]);
      } catch {
        throw new Error(`missing Git object ${ref}; fetch full history and retry`);
      }
      selected.push(...listing.toString().split("\0").filter(Boolean));
    }
    selected = [...new Set(selected)].filter(filter).sort();
    const historical = readHistorical(root, ref, selected);
    resolvedRef = historical.resolved;
    contents = historical.contents;
  }
  const inputs = selected.map((path) => ({ path, ref, sha256: digest(contents.get(path)) }));
  return { contents, inputs, resolved_ref: resolvedRef };
}
