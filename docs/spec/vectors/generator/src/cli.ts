import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { authorAllVectors } from "./author.js";
import { lintFamilyDocs } from "./docs-lint.js";
import { writeWorkspaceSchemas } from "./workspace-schemas.js";
import { verifyVectorTree } from "./verify.js";
import { writeCoverage } from "./coverage.js";
import { authorRegistryRevision } from "./registry.js";
import { authorSnapshot, checkSnapshot } from "./snapshot-orchestrator.js";
import { snapshotPackageCheck } from "./verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const defaultVectorRoot = resolve(here, "..", "..");
const defaultRepositoryRoot = resolve(here, "../../../../../");
const command = process.argv[2];
const root = resolve(process.argv[3] ?? defaultVectorRoot);

if (command === "author") {
  const written = await authorAllVectors(root);
  console.log(`authored ${written.length} vectors under ${root}`);
} else if (command === "verify") {
  const result = await verifyVectorTree(root);
  if (result.errors.length > 0) {
    console.error(result.errors.join("\n"));
    process.exitCode = 1;
  } else {
    console.log(`verified ${result.validFiles} vectors under ${root}`);
  }
} else if (command === "family-check") {
  const repositoryRoot = resolve(process.argv[3] ?? defaultRepositoryRoot);
  const issues = lintFamilyDocs(repositoryRoot);
  if (issues.length > 0) {
    for (const issue of issues) {
      console.error(
        `${issue.path}:${issue.line} [${issue.code}] ${issue.message}`,
      );
    }
    process.exitCode = 1;
  } else {
    console.log("validated protocol document family");
  }
} else if (command === "coverage") {
  await writeCoverage(root);
  console.log(`generated vector coverage under ${resolve(root, "coverage")}`);
} else if (command === "registry-author") {
  const repositoryRoot = resolve(process.argv[3] ?? defaultRepositoryRoot);
  const revision = Number.parseInt(process.argv[4] ?? "6", 10);
  const digest = authorRegistryRevision(repositoryRoot, revision);
  console.log(`authored registry revision ${revision} (${digest})`);
} else if (command === "workspace-schemas") {
  const repositoryRoot = resolve(process.argv[3] ?? defaultRepositoryRoot);
  const written = writeWorkspaceSchemas(repositoryRoot);
  console.log(`generated ${written.length} Workspace schemas`);
} else if (command === "snapshot-author") {
  const repositoryRoot = resolve(process.argv[3] ?? defaultRepositoryRoot);
  const sourceCommit = process.argv[4];
  if (sourceCommit === undefined) {
    console.error("usage: tsx src/cli.ts snapshot-author <repo-root> <source-commit>");
    process.exitCode = 2;
  } else {
    await authorSnapshot(repositoryRoot, sourceCommit);
    console.log(`authored vector snapshot from ${sourceCommit}`);
  }
} else if (command === "snapshot-check") {
  const repositoryRoot = resolve(process.argv[3] ?? defaultRepositoryRoot);
  const history = await checkSnapshot(repositoryRoot);
  console.log(`verified ${history.manifest.vector_count} vectors at ${history.snapshotCommit}`);
} else if (command === "snapshot-package-check") {
  const flags = parseFlags(process.argv.slice(3));
  const rawRoot = flags?.get("--raw-root");
  const snapshotRoot = flags?.get("--snapshot-root");
  if (rawRoot === undefined || snapshotRoot === undefined || flags?.size !== 2) {
    console.error(
      "usage: tsx src/cli.ts snapshot-package-check --raw-root <owned-temp> --snapshot-root <repo>",
    );
    process.exitCode = 2;
  } else {
    await snapshotPackageCheck(resolve(rawRoot), resolve(snapshotRoot));
    console.log(`verified packaged snapshot under ${resolve(snapshotRoot)}`);
  }
} else {
  console.error(
    "usage: tsx src/cli.ts <author|verify|family-check|coverage|registry-author|workspace-schemas|snapshot-author|snapshot-check|snapshot-package-check> [arguments]",
  );
  process.exitCode = 2;
}

function parseFlags(args: string[]): Map<string, string> | undefined {
  if (args.length % 2 !== 0) return undefined;
  const flags = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag === undefined || value === undefined || !flag.startsWith("--") || flags.has(flag)) {
      return undefined;
    }
    flags.set(flag, value);
  }
  return flags;
}
