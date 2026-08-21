import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { packageSnapshot } from "./author.js";
import {
  buildSnapshotManifest,
  serializeSnapshotManifest,
} from "./snapshot-manifest.js";
import {
  checkSnapshot,
  type CommandRunner,
  withMaterializedCommit,
} from "./snapshot-orchestrator.js";

const SNAPSHOT_PATH = "docs/spec/vectors/snapshot.json";
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

describe("rolling snapshot lifecycle", () => {
  it("keeps an ordinary specification-only commit independent of the snapshot", async () => {
    const { root, sourceCommit } = repository();
    writeSnapshot(root, sourceCommit);
    const snapshotCommit = commit(root, "first reconciliation");
    const firstCommands: string[] = [];

    const before = await checkSnapshot(root, { run: acceptingRunner(firstCommands) });
    expect(firstCommands).toHaveLength(5);
    expect(before).toMatchObject({ sourceCommit, snapshotCommit });

    write(root, "docs/spec/heterodyne-core.md", "# Draft-only specification edit\n");
    commit(root, "ordinary specification edit");
    const laterCommands: string[] = [];
    const after = await checkSnapshot(root, { run: acceptingRunner(laterCommands) });

    expect(laterCommands).toHaveLength(5);
    expect(after).toMatchObject({ sourceCommit, snapshotCommit });
    expect(git(root, [
      "diff", "--name-only", snapshotCommit, "HEAD", "--", "docs/spec/vectors",
    ])).toBe("");
  });

  it("checks first and replacement reconciliations only after each is committed", async () => {
    const { root, sourceCommit } = repository();
    const commands: string[] = [];
    const run = acceptingRunner(commands);

    writeSnapshot(root, sourceCommit, "first");
    await expect(checkSnapshot(root, { run })).rejects.toThrow(/no committed snapshot manifest/);
    expect(commands).toEqual([]);

    const firstSnapshotCommit = commit(root, "first reconciliation");
    expect(await checkSnapshot(root, { run })).toMatchObject({
      sourceCommit,
      snapshotCommit: firstSnapshotCommit,
    });
    expect(commands).toHaveLength(5);

    commands.length = 0;
    writeSnapshot(root, sourceCommit, "replacement");
    await expect(checkSnapshot(root, { run })).rejects.toThrow(/manifest bytes differ/);
    expect(commands).toEqual([]);

    const replacementSnapshotCommit = commit(root, "replacement reconciliation");
    expect(await checkSnapshot(root, { run })).toMatchObject({
      sourceCommit,
      snapshotCommit: replacementSnapshotCommit,
    });
    expect(commands).toHaveLength(5);
  });

  it("checks a squash-shaped final snapshot tree", async () => {
    const { root, sourceCommit } = repository();
    writeSnapshot(root, sourceCommit);
    write(root, "docs/spec/heterodyne-core.md", "# Squashed specification and snapshot\n");
    git(root, ["add", "--all", "--"]);
    const tree = git(root, ["write-tree"]);
    const squashCommit = git(root, ["commit-tree", tree, "-p", sourceCommit], {
      GIT_AUTHOR_NAME: "Snapshot Lifecycle Test",
      GIT_AUTHOR_EMAIL: "snapshot@example.invalid",
      GIT_COMMITTER_NAME: "Snapshot Lifecycle Test",
      GIT_COMMITTER_EMAIL: "snapshot@example.invalid",
    });
    git(root, ["reset", "--quiet", "--hard", squashCommit, "--"]);
    const commands: string[] = [];

    const history = await checkSnapshot(root, { run: acceptingRunner(commands) });

    expect(commands).toHaveLength(5);
    expect(history).toMatchObject({ sourceCommit, snapshotCommit: squashCommit });
  });

  it("packages byte-identical reconciliations from the same pinned source", async () => {
    const { root } = repository();
    writeRawPackageInput(root, "raw");
    const sourceCommit = commit(root, "reconciliation source");
    const first = temporaryDirectory("heterodyne-lifecycle-first-");
    const second = temporaryDirectory("heterodyne-lifecycle-second-");

    await withMaterializedCommit(root, sourceCommit, async (sourceRoot) => {
      await packageSnapshot(join(sourceRoot, "raw"), first, sourceCommit);
      await packageSnapshot(join(sourceRoot, "raw"), second, sourceCommit);
    });

    expect(fileBytes(first)).toEqual(fileBytes(second));
    expect(JSON.parse(readFileSync(join(first, SNAPSHOT_PATH), "utf8"))).toMatchObject({
      source_commit: sourceCommit,
      vector_count: 1,
    });
  });
});

function repository(): { root: string; sourceCommit: string } {
  const root = temporaryDirectory("heterodyne-snapshot-lifecycle-");
  git(root, ["init", "--quiet"]);
  git(root, ["config", "user.email", "snapshot@example.invalid"]);
  git(root, ["config", "user.name", "Snapshot Lifecycle Test"]);
  write(root, "source.txt", "source bytes\n");
  return { root, sourceCommit: commit(root, "source") };
}

function acceptingRunner(commands: string[]): CommandRunner {
  return async (command, args) => {
    commands.push([command, ...args].join(" "));
  };
}

function writeSnapshot(root: string, sourceCommit: string, marker = "one"): void {
  const vectorRoot = "docs/spec/vectors";
  write(root, `${vectorRoot}/fixtures.json`, `${marker} fixtures\n`);
  write(root, `${vectorRoot}/schema/vector.schema.json`, `${JSON.stringify({
    properties: { vector_schema_version: { const: "2.0.0" } },
  }, null, 2)}\n`);
  for (const path of [
    "schema/reason-codes.json",
    "schema/reason-codes.md",
    "coverage/manifest.json",
    "coverage/core.md",
    "coverage/comms.md",
    "coverage/control.md",
    "coverage/social.md",
    "coverage/workspace.md",
    "coverage/family.md",
  ]) {
    write(root, `${vectorRoot}/${path}`, `${marker} ${path}\n`);
  }
  write(root, `${vectorRoot}/core/001-vector.json`, `${JSON.stringify({
    vector_id: `${marker}-vector`,
    vector_schema_version: "2.0.0",
  }, null, 2)}\n`);
  const manifest = buildSnapshotManifest(root, sourceCommit);
  write(root, SNAPSHOT_PATH, serializeSnapshotManifest(manifest));
}

function writeRawPackageInput(root: string, prefix: string): void {
  write(root, `${prefix}/schema/vector.schema.json`, `${JSON.stringify({
    type: "object",
    additionalProperties: true,
    required: [
      "vector_id", "vector_schema_version", "owner_document", "spec_version",
      "spec_refs", "description", "direction", "input", "expected_output",
    ],
    properties: {
      vector_id: { type: "string" },
      vector_schema_version: { const: "1.0.0" },
      owner_document: { const: "core" },
      spec_version: { type: "string" },
      spec_refs: { type: "array", items: { type: "string" } },
      description: { type: "string" },
      direction: { enum: ["produce", "consume", "round-trip"] },
      input: { type: "object" },
      expected_output: { type: "object" },
    },
  }, null, 2)}\n`);
  write(root, `${prefix}/schema/reason-codes.json`, `${JSON.stringify({
    reason_codes: [{
      code: "example",
      owner: "core",
      status: "draft",
      first_version: "heterodyne/0.5.0",
      description: "example reason",
      spec_refs: ["heterodyne:0.5.0#core-conformance"],
    }],
  }, null, 2)}\n`);
  write(
    root,
    `${prefix}/schema/reason-codes.md`,
    "# Reason codes\n\nheterodyne:0.5.0#core-conformance\n",
  );
  write(root, `${prefix}/fixtures.json`, `${JSON.stringify({
    vector_schema_version: "1.0.0",
    spec_version: "heterodyne/0.5.0",
    nested: { spec_version: "behavioral-version" },
  }, null, 2)}\n`);
  write(root, `${prefix}/identity/001-example.json`, `${JSON.stringify({
    vector_id: "identity/example",
    vector_schema_version: "1.0.0",
    owner_document: "core",
    spec_version: "heterodyne/0.5.0",
    spec_refs: ["heterodyne:0.5.0#core-root-attestation"],
    description: "example",
    direction: "produce",
    input: { spec_version: "behavioral-input-version" },
    expected_output: { spec_version: "behavioral-output-version" },
  }, null, 2)}\n`);
}

function fileBytes(root: string): Array<{ path: string; bytes: Buffer }> {
  const files: Array<{ path: string; bytes: Buffer }> = [];
  const visit = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile()) files.push({ path: relative(root, path), bytes: readFileSync(path) });
    }
  };
  visit(root);
  return files;
}

function write(root: string, path: string, bytes: string): void {
  const absolute = join(root, ...path.split("/"));
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, bytes, "utf8");
}

function commit(root: string, message: string): string {
  git(root, ["add", "--all", "--"]);
  git(root, ["commit", "--quiet", "-m", message, "--"]);
  return git(root, ["rev-parse", "HEAD"]);
}

function git(root: string, args: string[], env: NodeJS.ProcessEnv = {}): string {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, ...env },
  }).trim();
}

function temporaryDirectory(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(root);
  return root;
}
