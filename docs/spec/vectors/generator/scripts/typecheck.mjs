import ts from "typescript";

const requestedConfig = process.argv[2] ?? "tsconfig.json";
const configPath = resolveConfigPath(requestedConfig);

const configFile = ts.readConfigFile(configPath, ts.sys.readFile);
const parsed = ts.parseJsonConfigFileContent(
  configFile.config,
  ts.sys,
  process.cwd(),
  { noEmit: true },
  configPath,
);
const host = ts.createCompilerHost(parsed.options);

host.resolveModuleNameLiterals = (
  moduleLiterals,
  containingFile,
  _redirectedReference,
  options,
) => moduleLiterals.map((literal) => {
  const frozenTopic = containingFile.endsWith("/src/topics-agent-moderation.ts");
  const moduleName = frozenTopic && literal.text === "./agent-moderation.js"
    ? "./snapshot-agent-moderation-adapter.js"
    : literal.text;
  return ts.resolveModuleName(moduleName, containingFile, options, host);
});

const program = ts.createProgram({
  rootNames: parsed.fileNames,
  options: parsed.options,
  projectReferences: parsed.projectReferences,
  host,
});
const diagnostics = [
  ...parsed.errors,
  ...ts.getPreEmitDiagnostics(program),
];

if (diagnostics.length > 0) {
  process.stderr.write(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCanonicalFileName: (fileName) => fileName,
    getCurrentDirectory: ts.sys.getCurrentDirectory,
    getNewLine: () => ts.sys.newLine,
  }));
  process.exitCode = 1;
}

function resolveConfigPath(requested) {
  const candidate = ts.sys.resolvePath(requested);
  if (!ts.sys.fileExists(candidate)) {
    throw new Error(`${requested} not found`);
  }
  return candidate;
}
