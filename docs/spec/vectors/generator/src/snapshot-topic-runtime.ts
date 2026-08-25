import { cp, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector } from "./types.js";

const here = dirname(new URL(import.meta.url).pathname);
const generatorRoot = resolve(here, "..");
const repositoryRoot = resolve(here, "../../../../../");
const frozenModerationTopic = resolve(here, "topics-agent-moderation.ts");
const allTopics = resolve(here, "topics.ts");
const liveImport = 'from "./agent-moderation.js";';
const snapshotImport = 'from "./snapshot-agent-moderation-adapter.js";';

export async function buildSnapshotAgentModerationVectors(): Promise<AuthoredVector[]> {
  const runtimeRoot = await materializeSnapshotRuntime([frozenModerationTopic]);
  try {
    const emittedTopic = emittedPath(runtimeRoot, frozenModerationTopic);
    const module = await import(`${pathToFileURL(emittedTopic).href}?runtime=${Date.now()}`) as {
      buildAgentModerationVectors: () => Promise<AuthoredVector[]>;
    };
    return await module.buildAgentModerationVectors();
  } finally {
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

export async function buildSnapshotCompatibleVectors(
  fixtures: Fixtures,
): Promise<AuthoredVector[]> {
  const runtimeRoot = await materializeSnapshotRuntime([allTopics]);
  try {
    const emittedTopics = emittedPath(runtimeRoot, allTopics);
    const module = await import(`${pathToFileURL(emittedTopics).href}?runtime=${Date.now()}`) as {
      buildAllVectors: (value: Fixtures) => Promise<AuthoredVector[]>;
    };
    return await module.buildAllVectors(fixtures);
  } finally {
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

async function materializeSnapshotRuntime(rootNames: string[]): Promise<string> {
  const runtimeRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-topic-runtime-"));
  const configPath = ts.findConfigFile(generatorRoot, ts.sys.fileExists, "tsconfig.json");
  if (configPath === undefined) throw new Error("snapshot-runtime-tsconfig-missing");
  const configFile = ts.readConfigFile(configPath, ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(
    configFile.config,
    ts.sys,
    generatorRoot,
    {
      noEmit: false,
      noEmitOnError: true,
      outDir: runtimeRoot,
      rootDir: repositoryRoot,
      sourceMap: false,
    },
    configPath,
  );
  const host = ts.createCompilerHost(parsed.options);
  const readSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreateNewSourceFile) => {
    const source = readSourceFile(
      fileName,
      languageVersion,
      onError,
      shouldCreateNewSourceFile,
    );
    if (source === undefined || resolve(fileName) !== frozenModerationTopic) return source;
    const matches = source.text.split(liveImport).length - 1;
    if (matches !== 1) throw new Error("snapshot-runtime-moderation-import-ambiguous");
    return ts.createSourceFile(
      fileName,
      source.text.replace(liveImport, snapshotImport),
      languageVersion,
      true,
      ts.ScriptKind.TS,
    );
  };
  const program = ts.createProgram({
    rootNames,
    options: parsed.options,
    projectReferences: parsed.projectReferences,
    host,
  });
  const emit = program.emit();
  const diagnostics = [...parsed.errors, ...ts.getPreEmitDiagnostics(program), ...emit.diagnostics];
  if (diagnostics.length > 0 || emit.emitSkipped) {
    throw new Error(ts.formatDiagnostics(diagnostics, {
      getCanonicalFileName: (fileName) => fileName,
      getCurrentDirectory: ts.sys.getCurrentDirectory,
      getNewLine: () => ts.sys.newLine,
    }));
  }
  await writeFile(join(runtimeRoot, "package.json"), '{"type":"module"}\n', "utf8");
  await symlink(
    join(repositoryRoot, "docs/spec/registry"),
    join(runtimeRoot, "docs/spec/registry"),
  );
  await cp(
    join(repositoryRoot, "docs/spec/schemas"),
    join(runtimeRoot, "docs/spec/schemas"),
    { force: true, recursive: true },
  );
  const emittedGenerator = join(
    runtimeRoot,
    relative(repositoryRoot, generatorRoot),
  );
  await symlink(join(generatorRoot, "node_modules"), join(emittedGenerator, "node_modules"));
  return runtimeRoot;
}

function emittedPath(runtimeRoot: string, sourcePath: string): string {
  return join(runtimeRoot, relative(repositoryRoot, sourcePath)).replace(/\.ts$/u, ".js");
}
