import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { authorAllVectors } from "./author.js";
import { lintFamilyDocs } from "./docs-lint.js";
import { writeWorkspaceSchemas } from "./workspace-schemas.js";
import { verifyVectorTree } from "./verify.js";
import { writeCoverage } from "./coverage.js";
import { authorRegistryRevision } from "./registry.js";

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
} else {
  console.error(
    "usage: tsx src/cli.ts <author|verify|family-check|coverage|registry-author|workspace-schemas> [root] [revision]",
  );
  process.exitCode = 2;
}
