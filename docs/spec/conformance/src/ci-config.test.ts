import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const path of temporaryDirectories.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

function readRepositoryFile(relativePath: string): string {
  const absolutePath = join(repositoryRoot, relativePath);
  expect(existsSync(absolutePath), `${relativePath} must exist`).toBe(true);
  return existsSync(absolutePath) ? readFileSync(absolutePath, "utf8") : "";
}

function listTestFiles(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = join(root, entry.name);
    if (entry.isDirectory()) return listTestFiles(path);
    return entry.isFile() && entry.name.endsWith(".test.ts") ? [path] : [];
  });
}

function hasOnlyReadContentsPermission(workflow: string): boolean {
  const lines = workflow.split("\n");
  const declarations = lines.flatMap((line, index) => {
    const match = line.match(/^(\s*)(?:permissions|"permissions"|'permissions')\s*:(.*)$/);
    return match === null ? [] : [{ index, indentation: match[1], value: match[2] }];
  });
  if (declarations.length !== 1) {
    return false;
  }

  const declaration = declarations[0];
  if (
    declaration === undefined
    || declaration.indentation !== ""
    || declaration.value?.trim() !== ""
  ) {
    return false;
  }

  const entries: string[] = [];
  for (const line of lines.slice(declaration.index + 1)) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) {
      continue;
    }
    if (!line.startsWith(" ")) {
      break;
    }
    entries.push(line);
  }
  return entries.length === 1 && entries[0] === "  contents: read";
}

describe("shared conformance CI configuration", () => {
  it("keeps gate and subject unit tests independent of live vector documents", () => {
    const unitRoots = [
      join(repositoryRoot, "docs/spec/conformance/src/gates"),
      join(repositoryRoot, "docs/spec/conformance/src/subjects"),
    ];
    const hardcodedVectorDocument =
      /["'`]docs\/spec\/vectors\/(?!generator\/)[^"'`\n]*\.json["'`]/u;
    const importsFileSystem = /from\s+["']node:fs(?:\/promises)?["']/u;
    const derivesRepositoryRoot = /import\.meta\.(?:dirname|url)/u;
    const offenders = unitRoots.flatMap(listTestFiles).flatMap((path) => {
      const source = readFileSync(path, "utf8");
      return importsFileSystem.test(source)
        && derivesRepositoryRoot.test(source)
        && hardcodedVectorDocument.test(source)
        ? [path.slice(repositoryRoot.length + 1)]
        : [];
    });

    expect(offenders).toEqual([]);
  });

  it("keeps the complete job body in one strict repository-rooted script", () => {
    const script = readRepositoryFile("scripts/conformance-ci.sh");
    const significantLines = script.split("\n").filter((line) => line.length > 0);

    expect(significantLines).toEqual([
      "#!/usr/bin/env bash",
      "set -euo pipefail",
      'repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"',
      'cd "$repository_root"',
      "npm --prefix docs/spec/vectors/generator ci",
      "npm --prefix docs/spec/conformance ci",
      "npm --prefix docs/spec/vectors/generator run family:check",
      "npm --prefix docs/spec/vectors/generator run check",
      'npm --prefix docs/spec/conformance run check -- "$repository_root"',
    ]);
  });

  it("stops with the second check failure and never invokes the third check", () => {
    const temporaryDirectory = mkdtempSync(join(tmpdir(), "heterodyne-ci-config-"));
    temporaryDirectories.push(temporaryDirectory);
    const fakeBin = join(temporaryDirectory, "bin");
    const callLog = join(temporaryDirectory, "npm-calls.log");
    const fakeNpm = join(fakeBin, "npm");
    mkdirSync(fakeBin);
    writeFileSync(
      fakeNpm,
      `#!/usr/bin/env bash
set -u
printf '%s\\t%s\\n' "$PWD" "$*" >> "$HETERODYNE_TEST_CALL_LOG"
if [[ "$*" == "--prefix docs/spec/vectors/generator run check" ]]; then
  exit 23
fi
`,
      { mode: 0o755 },
    );
    chmodSync(fakeNpm, 0o755);

    const result = spawnSync(join(repositoryRoot, "scripts/conformance-ci.sh"), [], {
      cwd: temporaryDirectory,
      encoding: "utf8",
      env: {
        ...process.env,
        HETERODYNE_TEST_CALL_LOG: callLog,
        PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
      },
    });

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(23);
    expect(readFileSync(callLog, "utf8").trimEnd().split("\n")).toEqual([
      `${repositoryRoot}\t--prefix docs/spec/vectors/generator ci`,
      `${repositoryRoot}\t--prefix docs/spec/conformance ci`,
      `${repositoryRoot}\t--prefix docs/spec/vectors/generator run family:check`,
      `${repositoryRoot}\t--prefix docs/spec/vectors/generator run check`,
    ]);
  });

  it("keeps the GitHub wrapper read-only and limited to the shared script", () => {
    const workflow = readRepositoryFile(".github/workflows/conformance.yml");

    expect(workflow).toMatch(/^on:\n {2}pull_request:\n {2}push:\n {4}branches: \[main\]$/m);
    expect(hasOnlyReadContentsPermission(workflow)).toBe(true);
    expect(workflow).toContain("group: ${{ github.workflow }}-${{ github.ref }}");
    expect(workflow).toContain("cancel-in-progress: true");
    expect(workflow).toMatch(/^ {2}conformance:\n {4}name: conformance$/m);
    expect(workflow).toContain("uses: actions/checkout@v4");
    expect(workflow).toContain("uses: actions/setup-node@v4");
    expect(workflow).toMatch(/^ {10}node-version: 22$/m);
    expect(workflow).toContain("docs/spec/vectors/generator/package-lock.json");
    expect(workflow).toContain("docs/spec/conformance/package-lock.json");
    expect(workflow.match(/^\s+run:.*$/gm)).toEqual([
      "        run: scripts/conformance-ci.sh",
    ]);
    expect(workflow).not.toContain("pull_request_target");
    expect(workflow).not.toContain("secrets");
    expect(workflow).not.toMatch(/^\s+ref:/m);
  });

  it.each([
    [
      "an added top-level write permission",
      (workflow: string) => workflow.replace(
        "  contents: read",
        "  contents: read\n  pull-requests: write",
      ),
    ],
    [
      "a job-level permissions override",
      (workflow: string) => workflow.replace(
        "    name: conformance",
        "    permissions:\n      pull-requests: write\n    name: conformance",
      ),
    ],
    [
      "write-all",
      (workflow: string) => workflow.replace(
        "    name: conformance",
        "    permissions: write-all\n    name: conformance",
      ),
    ],
    [
      "a double-quoted write-all permissions key",
      (workflow: string) => workflow.replace(
        "    name: conformance",
        '    "permissions": write-all\n    name: conformance',
      ),
    ],
    [
      "a double-quoted permissions mapping override",
      (workflow: string) => workflow.replace(
        "    name: conformance",
        '    "permissions":\n      contents: write\n    name: conformance',
      ),
    ],
    [
      "a single-quoted write-all permissions key",
      (workflow: string) => workflow.replace(
        "    name: conformance",
        "    'permissions': write-all\n    name: conformance",
      ),
    ],
    [
      "a single-quoted permissions mapping override",
      (workflow: string) => workflow.replace(
        "    name: conformance",
        "    'permissions':\n      contents: write\n    name: conformance",
      ),
    ],
  ])("rejects %s", (_label, mutate) => {
    const workflow = readRepositoryFile(".github/workflows/conformance.yml");
    const unsafeWorkflow = mutate(workflow);

    expect(unsafeWorkflow).not.toBe(workflow);
    expect(hasOnlyReadContentsPermission(unsafeWorkflow)).toBe(false);
  });

  it.each([
    ["double-quoted", '"permissions":'],
    ["single-quoted", "'permissions':"],
  ])("accepts a safe %s root permissions key", (_label, quotedKey) => {
    const workflow = readRepositoryFile(".github/workflows/conformance.yml");
    const equivalentWorkflow = workflow.replace(/^permissions:$/m, quotedKey);

    expect(equivalentWorkflow).not.toBe(workflow);
    expect(hasOnlyReadContentsPermission(equivalentWorkflow)).toBe(true);
  });

  it("keeps the Radicle wrapper byte-exact and free of duplicated job logic", () => {
    expect(readRepositoryFile(".radicle/native.yaml")).toBe(
      "shell: |\n  scripts/conformance-ci.sh\n",
    );
  });
});
