import { resolve } from "node:path";

const defaultRepositoryRoot = resolve(import.meta.dirname, "../../../../../");
const command = process.argv[2];
const repositoryRoot = resolve(process.argv[3] ?? defaultRepositoryRoot);

if (command === "family-check") {
  const { lintFamilyDocs } = await import("./docs-lint.js");
  const issues = lintFamilyDocs(repositoryRoot);
  if (issues.length > 0) {
    for (const issue of issues) {
      console.error(
        `${issue.path}:${issue.line} [${issue.code}] ${issue.message}`,
      );
    }
    process.exitCode = 1;
  } else {
    console.log("validated current protocol document family");
  }
} else if (command === "registry-author") {
  const { authorRegistryRevision } = await import("./registry.js");
  const revision = Number.parseInt(process.argv[4] ?? "14", 10);
  const digest = authorRegistryRevision(repositoryRoot, revision);
  console.log(`authored registry revision ${revision} (${digest})`);
} else {
  console.error(
    "usage: tsx src/current-cli.ts <family-check|registry-author> [repo-root] [revision]",
  );
  process.exitCode = 2;
}
