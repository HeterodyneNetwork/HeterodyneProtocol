import { createHash } from "node:crypto";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { execFileSync } from "node:child_process";

const source = process.argv[2];
const repositoryRoot = resolve(import.meta.dirname, "../../../../..");
const commit = "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1";
if (!source) throw new Error("usage: node scripts/archive-marmot.mjs <checked-out-marmot-repository>");
if (execFileSync("git", ["-C", source, "rev-parse", "HEAD"], { encoding: "utf8" }).trim() !== commit) {
  throw new Error("Marmot source is not at the approved commit");
}

const candidates = execFileSync("git", ["-C", source, "ls-tree", "-r", "--name-only", commit], { encoding: "utf8" })
  .trim().split("\n");
const roots = ["foundation/", "protocol-core/", "app-components/", "transports/", "features/"];
const paths = candidates.filter((path) => {
  if (["LICENSE", "README.md", "layout.md", "principles.md"].includes(path)) return true;
  if (!path.endsWith(".md") || !roots.some((root) => path.startsWith(root))) return false;
  const text = readFileSync(join(source, path), "utf8");
  return text.match(/^Status: .*$/m)?.[0] === "Status: adopted.";
}).sort();

const archiveRoot = join(repositoryRoot, "docs/spec/external/marmot");
const destination = join(archiveRoot, commit);
rmSync(destination, { recursive: true, force: true });
mkdirSync(destination, { recursive: true });
const digest = (algorithm, bytes) => createHash(algorithm).update(bytes).digest("hex");
const files = paths.map((path) => {
  const bytes = readFileSync(join(source, path));
  const target = join(destination, path);
  mkdirSync(dirname(target), { recursive: true });
  cpSync(join(source, path), target);
  return {
    path,
    byte_length: bytes.length,
    git_blob: createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"),
    sha256: digest("sha256", bytes),
  };
});
const aggregate = files.map((file) => `${file.path}\0${file.byte_length}\0${file.git_blob}\0${file.sha256}\n`).join("");
const manifest = {
  archive_version: "1",
  upstream_repository: "https://github.com/marmot-protocol/marmot.git",
  commit,
  tree: "10d941f358de5d9fe4ee1db75581f3e5363f5e92",
  commit_signature: { verified: true, reason: "valid", verified_at: "2026-07-30T08:17:00Z" },
  aggregate_sha256: digest("sha256", aggregate),
  files,
};
mkdirSync(archiveRoot, { recursive: true });
writeFileSync(join(archiveRoot, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
