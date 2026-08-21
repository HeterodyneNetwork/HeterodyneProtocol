import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";

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

function listTypeScriptFiles(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = join(root, entry.name);
    if (entry.isDirectory()) return listTypeScriptFiles(path);
    return entry.isFile() && entry.name.endsWith(".ts") ? [path] : [];
  });
}

function initializeTemporaryRepository(): string {
  const root = mkdtempSync(join(tmpdir(), "heterodyne-ci-config-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "scripts"));
  writeFileSync(join(root, "tracked.txt"), "before\n");
  writeFileSync(
    join(root, "scripts/conformance-ci.sh"),
    readRepositoryFile("scripts/conformance-ci.sh"),
    { mode: 0o755 },
  );
  for (const args of [["init"], ["add", "."], [
    "-c",
    "user.name=CI Test",
    "-c",
    "user.email=ci@example.invalid",
    "commit",
    "-m",
    "fixture",
  ]]) {
    const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
  }
  return realpathSync(root);
}

function installFakeNpm(root: string, body = ""): { callLog: string; path: string } {
  const fakeBin = join(root, "bin");
  const callLog = join(root, "npm-calls.log");
  const fakeNpm = join(fakeBin, "npm");
  mkdirSync(fakeBin);
  writeFileSync(
    fakeNpm,
    `#!/usr/bin/env bash
set -u
printf '%s\\t%s\\n' "$PWD" "$*" >> "$HETERODYNE_TEST_CALL_LOG"
${body}
`,
    { mode: 0o755 },
  );
  chmodSync(fakeNpm, 0o755);
  return { callLog, path: `${fakeBin}:${process.env.PATH ?? ""}` };
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

type WorkflowExecutables = {
  actions: string[];
  runs: string[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function collectWorkflowExecutables(workflow: string): WorkflowExecutables | undefined {
  let document: unknown;
  try {
    document = parse(workflow, { merge: true }) as unknown;
  } catch {
    return undefined;
  }
  if (!isRecord(document) || !isRecord(document.jobs)) return undefined;

  const actions: string[] = [];
  const runs: string[] = [];
  const collect = (value: Record<string, unknown>): boolean => {
    if (Object.hasOwn(value, "uses")) {
      if (typeof value.uses !== "string") return false;
      actions.push(value.uses);
    }
    if (Object.hasOwn(value, "run")) {
      if (typeof value.run !== "string") return false;
      runs.push(value.run);
    }
    return true;
  };

  for (const job of Object.values(document.jobs)) {
    if (!isRecord(job) || !collect(job)) return undefined;
    if (job.steps === undefined) continue;
    if (!Array.isArray(job.steps)) return undefined;
    for (const step of job.steps) {
      if (!isRecord(step) || !collect(step)) return undefined;
    }
  }
  return { actions, runs };
}

function hasOnlyAllowedWorkflowActions(workflow: string): boolean {
  const executables = collectWorkflowExecutables(workflow);
  return executables !== undefined
    && executables.actions.length === 2
    && executables.actions[0] === "actions/checkout@v4"
    && executables.actions[1] === "actions/setup-node@v4";
}

function hasOnlyAllowedWorkflowRuns(workflow: string): boolean {
  const executables = collectWorkflowExecutables(workflow);
  return executables !== undefined
    && executables.runs.length === 1
    && executables.runs[0] === "scripts/conformance-ci.sh";
}

const FORBIDDEN_EXECUTABLE_CONTENT =
  /(?:\b(?:rm|publish|deploy|snapshot-author)\b|npm\s+run\s+(?:author|release|tag)|git\s+(?:add|commit|tag|push|checkout|reset|clean)|(?:^|[\n;&|])\s*(?:tag|push)(?:\s|$))/im;

function hasForbiddenExecutableContent(content: string): boolean {
  return FORBIDDEN_EXECUTABLE_CONTENT.test(content);
}

function hasCrossPackageImport(
  source: string,
  forbiddenPackage: string,
  forbiddenPath: string,
): boolean {
  const moduleSpecifiers = source.matchAll(
    /\b(?:from\s+|import\s*(?:\(\s*)?)(["'])([^"'\n]+)\1/gu,
  );
  return [...moduleSpecifiers].some(([, , specifier]) =>
    specifier === forbiddenPackage
    || specifier?.startsWith(`${forbiddenPackage}/`) === true
    || specifier?.includes(forbiddenPath) === true
  );
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

  it("keeps generator and conformance imports independent", () => {
    const conformanceSources = listTypeScriptFiles(
      join(repositoryRoot, "docs/spec/conformance/src"),
    );
    const generatorSources = listTypeScriptFiles(
      join(repositoryRoot, "docs/spec/vectors/generator/src"),
    );
    expect(conformanceSources.filter((path) =>
      hasCrossPackageImport(
        readFileSync(path, "utf8"),
        "@heterodyne/vector-generator",
        "vectors/generator",
      )
    )).toEqual([]);
    expect(generatorSources.filter((path) =>
      hasCrossPackageImport(
        readFileSync(path, "utf8"),
        "@heterodyne/conformance",
        "conformance",
      )
    )).toEqual([]);
  });

  it.each([
    ["the generator package name", 'import value from "@heterodyne/vector-' + 'generator"'],
    [
      "whitespace before a dynamic import paren",
      'const value = await import ("../vectors/' + 'generator/src/author.js")',
    ],
    [
      "whitespace after a dynamic import paren",
      'const value = await import(  "../vectors/' + 'generator/src/author.js")',
    ],
  ])("detects cross-package imports through %s", (_label, source) => {
    expect(hasCrossPackageImport(
      source,
      "@heterodyne/vector-generator",
      "vectors/generator",
    )).toBe(true);
  });

  it("runs locked installs, draft validation, snapshot validation, build, and tests in order", () => {
    const root = initializeTemporaryRepository();
    const fake = installFakeNpm(root);
    const result = spawnSync(join(root, "scripts/conformance-ci.sh"), [], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        HETERODYNE_TEST_CALL_LOG: fake.callLog,
        PATH: fake.path,
      },
    });

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(fake.callLog, "utf8").trimEnd().split("\n")).toEqual([
      `${root}\t--prefix docs/spec/vectors/generator ci`,
      `${root}\t--prefix docs/spec/conformance ci`,
      `${root}\t--prefix docs/spec/vectors/generator run draft:check -- ${root}`,
      `${root}\t--prefix docs/spec/vectors/generator run snapshot-check -- ${root}`,
      `${root}\t--prefix docs/spec/conformance run build`,
      `${root}\t--prefix docs/spec/conformance test`,
    ]);
  });

  it("stops with a snapshot failure before independent conformance runs", () => {
    const root = initializeTemporaryRepository();
    const fake = installFakeNpm(root, `
if [[ "$*" == "--prefix docs/spec/vectors/generator run snapshot-check -- $PWD" ]]; then
  exit 23
fi`);
    const result = spawnSync(join(root, "scripts/conformance-ci.sh"), [], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        HETERODYNE_TEST_CALL_LOG: fake.callLog,
        PATH: fake.path,
      },
    });

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(23);
    expect(readFileSync(fake.callLog, "utf8")).not.toContain("conformance run build");
  });

  it("fails when a validation stage mutates tracked or staged state", () => {
    const root = initializeTemporaryRepository();
    const fake = installFakeNpm(root, `
if [[ "$*" == "--prefix docs/spec/conformance test" ]]; then
  printf 'after\\n' > tracked.txt
  printf 'staged\\n' > staged.txt
  git add staged.txt
fi`);
    const result = spawnSync(join(root, "scripts/conformance-ci.sh"), [], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        HETERODYNE_TEST_CALL_LOG: fake.callLog,
        PATH: fake.path,
      },
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/mutated tracked or index state/i);
  });

  it("allows an unchanged preexisting staged and unstaged dirty tree", () => {
    const root = initializeTemporaryRepository();
    writeFileSync(join(root, "tracked.txt"), "staged-before\n");
    const staged = spawnSync("git", ["add", "tracked.txt"], {
      cwd: root,
      encoding: "utf8",
    });
    expect(staged.status, staged.stderr).toBe(0);
    writeFileSync(join(root, "tracked.txt"), "unstaged-before\n");
    const fake = installFakeNpm(root);

    const result = spawnSync(join(root, "scripts/conformance-ci.sh"), [], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        HETERODYNE_TEST_CALL_LOG: fake.callLog,
        PATH: fake.path,
      },
    });

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(join(root, "tracked.txt"), "utf8")).toBe("unstaged-before\n");
  });

  it("fails when validation changes bytes of an already-dirty unstaged file", () => {
    const root = initializeTemporaryRepository();
    writeFileSync(join(root, "tracked.txt"), "dirty-before\n");
    const fake = installFakeNpm(root, `
if [[ "$*" == "--prefix docs/spec/conformance test" ]]; then
  printf 'dirty-after\\n' > tracked.txt
fi`);

    const result = spawnSync(join(root, "scripts/conformance-ci.sh"), [], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        HETERODYNE_TEST_CALL_LOG: fake.callLog,
        PATH: fake.path,
      },
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/mutated tracked or index state/i);
  });

  it("keeps the GitHub wrapper read-only and limited to the shared script", () => {
    const workflow = readRepositoryFile(".github/workflows/conformance.yml");

    expect(workflow).toMatch(/^on:\n {2}pull_request:\n {2}push:\n {4}branches: \[main\]$/m);
    expect(hasOnlyReadContentsPermission(workflow)).toBe(true);
    expect(workflow).toContain("group: ${{ github.workflow }}-${{ github.ref }}");
    expect(workflow).toContain("cancel-in-progress: true");
    expect(workflow).toMatch(/^ {2}conformance:\n {4}name: conformance$/m);
    expect(workflow).toContain("uses: actions/checkout@v4");
    expect(workflow).toMatch(/uses: actions\/checkout@v4\n {8}with:\n {10}fetch-depth: 0/);
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
    expect(hasOnlyAllowedWorkflowActions(workflow)).toBe(true);
    expect(hasOnlyAllowedWorkflowRuns(workflow)).toBe(true);

    const workflowExecutables = collectWorkflowExecutables(workflow);
    expect(workflowExecutables).toBeDefined();
    const executableJobBodies = [
      readRepositoryFile("scripts/conformance-ci.sh"),
      readRepositoryFile(".radicle/native.yaml"),
      ...(workflowExecutables?.runs ?? []),
    ].join("\n");
    expect(hasForbiddenExecutableContent(executableJobBodies)).toBe(false);
  });

  it("rejects a publishing or deployment workflow action", () => {
    const workflow = readRepositoryFile(".github/workflows/conformance.yml");
    const unsafeWorkflow = workflow.replace(
      "      - uses: actions/setup-node@v4",
      "      - uses: softprops/action-gh-release@v2\n      - uses: actions/setup-node@v4",
    );

    expect(unsafeWorkflow).not.toBe(workflow);
    expect(hasOnlyAllowedWorkflowActions(unsafeWorkflow)).toBe(false);
  });

  it("treats flow-style and ordinary executable steps identically", () => {
    const equivalentWorkflow = `jobs:
  conformance:
    steps:
      - { uses: actions/checkout@v4 }
      - uses: actions/setup-node@v4
      - { run: scripts/conformance-ci.sh }
`;

    expect(hasOnlyAllowedWorkflowActions(equivalentWorkflow)).toBe(true);
    expect(hasOnlyAllowedWorkflowRuns(equivalentWorkflow)).toBe(true);
  });

  it("rejects a flow-style publishing or deployment workflow action", () => {
    const workflow = readRepositoryFile(".github/workflows/conformance.yml");
    const unsafeWorkflow = workflow.replace(
      "      - uses: actions/setup-node@v4",
      "      - { uses: softprops/action-gh-release@v2 }\n      - uses: actions/setup-node@v4",
    );

    expect(unsafeWorkflow).not.toBe(workflow);
    expect(hasOnlyAllowedWorkflowActions(unsafeWorkflow)).toBe(false);
  });

  it.each([
    ["git rm", "git rm tracked.txt"],
    ["shell rm", "rm tracked.txt"],
  ])("rejects a flow-style %s workflow run", (_label, unsafeCommand) => {
    const workflow = readRepositoryFile(".github/workflows/conformance.yml");
    const unsafeWorkflow = workflow.replace(
      "      - name: Run conformance",
      `      - { run: "${unsafeCommand}" }\n      - name: Run conformance`,
    );

    expect(unsafeWorkflow).not.toBe(workflow);
    expect(hasOnlyAllowedWorkflowRuns(unsafeWorkflow)).toBe(false);
    const executables = collectWorkflowExecutables(unsafeWorkflow);
    expect(executables).toBeDefined();
    expect(hasForbiddenExecutableContent((executables?.runs ?? []).join("\n"))).toBe(true);
  });

  it.each([
    ["git rm", "git rm tracked.txt"],
    ["shell rm", "rm tracked.txt"],
  ])("rejects %s in executable content", (_label, unsafeCommand) => {
    const executableContent = [
      readRepositoryFile("scripts/conformance-ci.sh"),
      readRepositoryFile(".radicle/native.yaml"),
      unsafeCommand,
    ].join("\n");

    expect(hasForbiddenExecutableContent(executableContent)).toBe(true);
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
