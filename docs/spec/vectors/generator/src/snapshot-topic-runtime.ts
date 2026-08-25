import { cp, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";
import type { Fixtures } from "./fixtures.js";
import type { AuthoredVector } from "./types.js";

const here = dirname(fileURLToPath(import.meta.url));
const generatorRoot = resolve(here, "..");
const repositoryRoot = resolve(here, "../../../../../");
const frozenModerationTopic = resolve(here, "topics-agent-moderation.ts");
const frozenClaimsTopic = resolve(here, "topics-claims.ts");
const frozenClaimLedgerTopic = resolve(here, "topics-claim-ledger.ts");
const allTopics = resolve(here, "topics.ts");
const snapshotClaimsAdapter = resolve(here, "snapshot-claims-adapter.ts");
const liveImport = 'from "./agent-moderation.js";';
const snapshotImport = 'from "./snapshot-agent-moderation-adapter.js";';
const liveClaimsImport = 'from "./claims.js";';
const snapshotClaimsImport = 'from "./snapshot-claims-adapter.js";';

export async function buildSnapshotAgentModerationVectors(): Promise<AuthoredVector[]> {
  const runtimeRoot = await materializeSnapshotRuntime([frozenModerationTopic]);
  try {
    const emittedTopic = emittedPath(runtimeRoot, frozenModerationTopic);
    const module = await import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic)) as {
      buildAgentModerationVectors: () => Promise<AuthoredVector[]>;
    };
    return await module.buildAgentModerationVectors();
  } finally {
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

export async function buildSnapshotClaimVectors(fixtures: Fixtures): Promise<AuthoredVector[]> {
  const runtimeRoot = await materializeSnapshotRuntime([frozenClaimsTopic]);
  try {
    const emittedTopic = emittedPath(runtimeRoot, frozenClaimsTopic);
    const module = await import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic)) as {
      buildClaimVectors: (value: Fixtures) => Promise<AuthoredVector[]>;
    };
    return await module.buildClaimVectors(fixtures);
  } finally {
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

export async function buildSnapshotClaimLedgerVectors(
  fixtures: Fixtures,
): Promise<AuthoredVector[]> {
  const runtimeRoot = await materializeSnapshotRuntime([frozenClaimLedgerTopic]);
  try {
    const emittedTopic = emittedPath(runtimeRoot, frozenClaimLedgerTopic);
    const module = await import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic)) as {
      buildClaimLedgerVectors: (value: Fixtures) => Promise<AuthoredVector[]>;
    };
    return await module.buildClaimLedgerVectors(fixtures);
  } finally {
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

export async function replaySnapshotClaimLedgerVectors(inputs: unknown[]): Promise<unknown[]> {
  const runtimeRoot = await materializeSnapshotRuntime([frozenClaimLedgerTopic]);
  try {
    const emittedTopic = emittedPath(runtimeRoot, frozenClaimLedgerTopic);
    const module = await import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopic)) as {
      replayClaimLedgerVector: (value: unknown) => unknown;
    };
    return inputs.map((input) => module.replayClaimLedgerVector(input));
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
    const module = await import(snapshotRuntimeModuleUrl(runtimeRoot, emittedTopics)) as {
      buildAllVectors: (value: Fixtures) => Promise<AuthoredVector[]>;
    };
    return await module.buildAllVectors(fixtures);
  } finally {
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

async function materializeSnapshotRuntime(rootNames: string[]): Promise<string> {
  const runtimeRoot = await mkdtemp(join(tmpdir(), "heterodyne-snapshot-topic-runtime-"));
  try {
    await materializeSnapshotRuntimeAt(runtimeRoot, rootNames);
    return runtimeRoot;
  } catch (error) {
    await rm(runtimeRoot, { recursive: true, force: true });
    throw error;
  }
}

async function materializeSnapshotRuntimeAt(
  runtimeRoot: string,
  rootNames: string[],
): Promise<void> {
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
    if (source === undefined) return source;
    const canonicalFile = resolve(fileName);
    let transformed = source.text;
    if (canonicalFile === frozenModerationTopic) {
      const matches = transformed.split(liveImport).length - 1;
      if (matches !== 1) throw new Error("snapshot-runtime-moderation-import-ambiguous");
      transformed = transformed.replace(liveImport, snapshotImport);
    }
    if (canonicalFile !== snapshotClaimsAdapter && transformed.includes(liveClaimsImport)) {
      transformed = transformed.replaceAll(liveClaimsImport, snapshotClaimsImport);
    }
    if (transformed === source.text) return source;
    return ts.createSourceFile(
      fileName,
      transformed,
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
  await cp(
    join(repositoryRoot, "docs/spec/registry"),
    join(runtimeRoot, "docs/spec/registry"),
    { force: true, recursive: true },
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
}

export function snapshotRuntimeModuleUrl(runtimeRoot: string, modulePath: string): string {
  const canonicalRoot = realpathSync(runtimeRoot);
  const canonicalModule = realpathSync(modulePath);
  const relativeModule = relative(canonicalRoot, canonicalModule);
  if (
    relativeModule.startsWith("..") ||
    resolve(canonicalRoot, relativeModule) !== canonicalModule
  ) {
    throw new Error("snapshot-runtime-module-outside-disposable-root");
  }
  return `${pathToFileURL(canonicalModule).href}?runtime=${Date.now()}`;
}

function emittedPath(runtimeRoot: string, sourcePath: string): string {
  return join(runtimeRoot, relative(repositoryRoot, sourcePath)).replace(/\.ts$/u, ".js");
}
