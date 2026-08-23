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
import { dirname, join, relative, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { authorSnapshot, checkSnapshot } from "./snapshot-orchestrator.js";

const SNAPSHOT_PATH = "docs/spec/vectors/snapshot.json";
const repositoryRoot = resolve(import.meta.dirname, "../../../../../");
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

describe("rolling snapshot lifecycle", () => {
  it("executes authoring and checking across ordinary, replacement, and squash commits", async () => {
    const root = sourceRepository();
    installConformanceDependencies(root);
    const sourceCommit = git(root, ["rev-parse", "HEAD"]);

    await authorSnapshot(root, sourceCommit);
    await expect(checkSnapshot(root)).rejects.toThrow(/no committed snapshot manifest/);
    const firstSnapshotCommit = commit(root, "first reconciliation");
    expect(await checkSnapshot(root)).toMatchObject({ sourceCommit, snapshotCommit: firstSnapshotCommit });

    write(
      root,
      "docs/spec/heterodyne-core.md",
      `${readFileSync(join(root, "docs/spec/heterodyne-core.md"), "utf8")}`
        + "\n<!-- lifecycle test: ordinary draft-only edit -->\n",
    );
    const replacementSourceCommit = commit(root, "ordinary specification edit");
    expect(git(root, [
      "diff", "--name-only", firstSnapshotCommit, replacementSourceCommit,
      "--", "docs/spec/vectors",
    ])).toBe("");
    expect(await checkSnapshot(root)).toMatchObject({
      sourceCommit,
      snapshotCommit: firstSnapshotCommit,
    });

    await authorSnapshot(root, replacementSourceCommit);
    const firstAuthoringBytes = snapshotOwnedBytes(root);
    expect(firstAuthoringBytes.map(({ path }) => path)).toEqual(expect.arrayContaining([
      SNAPSHOT_PATH,
      "docs/spec/conformance/DEBT.md",
      "docs/spec/conformance/report.json",
    ]));
    expect(firstAuthoringBytes.some(({ path }) =>
      path.startsWith("docs/spec/conformance/baselines/"))).toBe(true);
    await expect(checkSnapshot(root)).rejects.toThrow(/manifest bytes differ/);

    await authorSnapshot(root, replacementSourceCommit);
    expect(snapshotOwnedBytes(root)).toEqual(firstAuthoringBytes);
    const replacementSnapshotCommit = commit(root, "replacement reconciliation");
    expect(await checkSnapshot(root)).toMatchObject({
      sourceCommit: replacementSourceCommit,
      snapshotCommit: replacementSnapshotCommit,
    });

    const finalTree = git(root, ["rev-parse", `${replacementSnapshotCommit}^{tree}`]);
    const squashCommit = git(root, [
      "commit-tree", finalTree, "-p", replacementSourceCommit,
    ], {
      GIT_AUTHOR_NAME: "Snapshot Lifecycle Test",
      GIT_AUTHOR_EMAIL: "snapshot@example.invalid",
      GIT_COMMITTER_NAME: "Snapshot Lifecycle Test",
      GIT_COMMITTER_EMAIL: "snapshot@example.invalid",
    });
    git(root, ["reset", "--quiet", "--hard", squashCommit, "--"]);

    expect(await checkSnapshot(root)).toMatchObject({
      sourceCommit: replacementSourceCommit,
      snapshotCommit: squashCommit,
    });
    expect(git(root, ["status", "--porcelain=v1", "--untracked-files=no"])).toBe("");
  }, 300_000);
});

function sourceRepository(): string {
  const root = temporaryDirectory("heterodyne-snapshot-lifecycle-");
  const archiveRoot = temporaryDirectory("heterodyne-snapshot-archive-");
  const archivePath = join(archiveRoot, "source.tar");
  execFileSync("git", ["archive", "--format=tar", "--output", archivePath, "HEAD"], {
    cwd: repositoryRoot,
  });
  execFileSync("tar", ["-xf", archivePath, "-C", root]);
  rmSync(join(root, SNAPSHOT_PATH));
  installPinnedSourceFixture(root);
  git(root, ["init", "--quiet"]);
  git(root, ["config", "user.email", "snapshot@example.invalid"]);
  git(root, ["config", "user.name", "Snapshot Lifecycle Test"]);
  commit(root, "source without snapshot history");
  return root;
}

function installPinnedSourceFixture(root: string): void {
  const generatorRoot = join(root, "docs/spec/vectors/generator");
  const packagePath = join(generatorRoot, "package.json");
  const packageJson = JSON.parse(readFileSync(packagePath, "utf8")) as {
    scripts: Record<string, string>;
  };
  packageJson.scripts.author = "node lifecycle-author.mjs";
  writeFileSync(packagePath, `${JSON.stringify(packageJson, null, 2)}\n`, "utf8");

  const files = {
    "schema/vector.schema.json": `${JSON.stringify({
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
    }, null, 2)}\n`,
    "schema/reason-codes.json": `${JSON.stringify({
      reason_codes: [{
        code: "example",
        owner: "core",
        status: "draft",
        first_version: "heterodyne/0.5.0",
        description: "example reason",
        spec_refs: ["heterodyne:0.5.0#core-conformance"],
      }],
    }, null, 2)}\n`,
    "schema/reason-codes.md": "# Reason codes\n\nheterodyne:0.5.0#core-conformance\n",
    "fixtures.json": `${JSON.stringify({
      vector_schema_version: "1.0.0",
      spec_version: "heterodyne/0.5.0",
    }, null, 2)}\n`,
    "identity/001-example.json": `${JSON.stringify({
      vector_id: "identity/example",
      vector_schema_version: "1.0.0",
      owner_document: "core",
      spec_version: "heterodyne/0.5.0",
      spec_refs: ["heterodyne:0.5.0#core-root-attestation"],
      description: "lifecycle integration fixture",
      direction: "produce",
      input: { value: "input" },
      expected_output: { value: "output" },
    }, null, 2)}\n`,
  };
  writeFileSync(join(generatorRoot, "lifecycle-author.mjs"), [
    'import { mkdir, writeFile } from "node:fs/promises";',
    'import { dirname, join, resolve } from "node:path";',
    `const files = ${JSON.stringify(files)};`,
    "const outputRoot = resolve(process.argv[2]);",
    "for (const [path, bytes] of Object.entries(files)) {",
    "  const target = join(outputRoot, ...path.split('/'));",
    "  await mkdir(dirname(target), { recursive: true });",
    "  await writeFile(target, bytes, 'utf8');",
    "}",
    "console.log(`authored ${Object.keys(files).filter((path) => path.startsWith('identity/')).length} vectors under ${outputRoot}`);",
    "",
  ].join("\n"), "utf8");
}

function installConformanceDependencies(root: string): void {
  execFileSync("npm", ["ci", "--ignore-scripts", "--no-audit", "--no-fund"], {
    cwd: join(root, "docs/spec/conformance"),
    stdio: "pipe",
  });
}

function snapshotOwnedBytes(root: string): Array<{ path: string; bytes: Buffer }> {
  const files: Array<{ path: string; bytes: Buffer }> = [];
  const visit = (path: string): void => {
    for (const entry of readdirSync(path, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name))) {
      const absolute = join(path, entry.name);
      const repositoryPath = relative(root, absolute).split("\\").join("/");
      if (repositoryPath.startsWith("docs/spec/vectors/generator/")) continue;
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile()) files.push({ path: repositoryPath, bytes: readFileSync(absolute) });
    }
  };
  visit(join(root, "docs/spec/vectors"));
  visit(join(root, "docs/spec/conformance/baselines"));
  for (const path of ["docs/spec/conformance/DEBT.md", "docs/spec/conformance/report.json"]) {
    files.push({ path, bytes: readFileSync(join(root, path)) });
  }
  return files.sort((left, right) => left.path.localeCompare(right.path));
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
