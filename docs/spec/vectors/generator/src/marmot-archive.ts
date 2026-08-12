import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, posix, relative } from "node:path";

type FileRecord = {
  path: string;
  byte_length: number;
  git_blob: string;
  sha256: string;
};

type Manifest = {
  archive_version: "1";
  upstream_repository: string;
  commit: string;
  tree: string;
  commit_signature: { verified: true; reason: "valid"; verified_at: string };
  aggregate_sha256: string;
  files: FileRecord[];
};

const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
const gitBlob = (bytes: Buffer) => createHash("sha1")
  .update(`blob ${bytes.length}\0`)
  .update(bytes)
  .digest("hex");

function filesUnder(root: string, current = root): string[] {
  return readdirSync(current).flatMap((name) => {
    const path = join(current, name);
    return statSync(path).isDirectory() ? filesUnder(root, path) : [relative(root, path).replaceAll("\\", "/")];
  }).sort();
}

export function archiveAggregate(files: readonly FileRecord[]): string {
  return sha256(files.map((file) =>
    `${file.path}\0${file.byte_length}\0${file.git_blob}\0${file.sha256}\n`).join(""));
}

export function verifyMarmotArchive(root: string): string[] {
  const issues: string[] = [];
  let manifest: Manifest;
  try {
    manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")) as Manifest;
  } catch {
    return ["missing or invalid Marmot archive manifest"];
  }
  const archiveRoot = join(root, manifest.commit);
  const safe = (path: string) => path.length > 0
    && path === posix.normalize(path)
    && !path.startsWith("/")
    && !path.startsWith("../")
    && !path.includes("/../");
  const expected = new Set<string>();
  for (const file of manifest.files) {
    if (!safe(file.path)) {
      issues.push(`unsafe archive path: ${file.path}`);
      continue;
    }
    if (expected.has(file.path)) issues.push(`duplicate archive path: ${file.path}`);
    expected.add(file.path);
    let bytes: Buffer;
    try {
      bytes = readFileSync(join(archiveRoot, file.path));
    } catch {
      issues.push(`missing archive file: ${file.path}`);
      continue;
    }
    if (bytes.length !== file.byte_length) issues.push(`byte length mismatch: ${file.path}`);
    if (sha256(bytes) !== file.sha256) issues.push(`sha256 digest mismatch: ${file.path}`);
    if (gitBlob(bytes) !== file.git_blob) issues.push(`Git blob mismatch: ${file.path}`);
  }
  let actual: string[] = [];
  try { actual = filesUnder(archiveRoot); } catch { issues.push("missing archive root"); }
  for (const path of actual) if (!expected.has(path)) issues.push(`extra archive file: ${path}`);
  if (manifest.aggregate_sha256 !== archiveAggregate(manifest.files)) {
    issues.push("aggregate digest mismatch");
  }
  if (
    manifest.upstream_repository !== "https://github.com/marmot-protocol/marmot.git"
    || manifest.commit !== "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1"
    || manifest.tree !== "10d941f358de5d9fe4ee1db75581f3e5363f5e92"
    || manifest.commit_signature?.verified !== true
    || manifest.commit_signature?.reason !== "valid"
  ) issues.push("Marmot provenance mismatch");
  return issues.sort();
}
