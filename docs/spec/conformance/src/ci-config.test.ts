import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
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

describe("shared conformance CI configuration", () => {
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
    expect(workflow).toMatch(/^permissions:\n {2}contents: read$/m);
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

  it("keeps the Radicle wrapper byte-exact and free of duplicated job logic", () => {
    expect(readRepositoryFile(".radicle/native.yaml")).toBe(
      "shell: |\n  scripts/conformance-ci.sh\n",
    );
  });
});
