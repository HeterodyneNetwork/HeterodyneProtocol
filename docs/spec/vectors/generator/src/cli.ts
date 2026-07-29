import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { authorAllVectors } from "./author.js";
import {
  assertAllowedDependency,
  DOCUMENT_DEPENDENCIES,
  DOCUMENT_VERSIONS,
  parseQualifiedVersion,
} from "./family.js";
import type { DocumentId } from "./types.js";
import {
  lintFamilyCutover,
  lintFamilyDocs,
  writeReleaseManifests,
} from "./docs-lint.js";
import { verifyVectorTree } from "./verify.js";
import { writeCoverage } from "./coverage.js";

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
  for (const document of Object.keys(DOCUMENT_VERSIONS) as DocumentId[]) {
    parseQualifiedVersion(`${document}/${DOCUMENT_VERSIONS[document]}`);
    for (const dependency of DOCUMENT_DEPENDENCIES[document]) {
      assertAllowedDependency(document, dependency);
    }
  }
  const repositoryRoot = resolve(process.argv[3] ?? defaultRepositoryRoot);
  const issues = [
    ...lintFamilyDocs(repositoryRoot),
    ...lintFamilyCutover(repositoryRoot),
  ];
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
} else if (command === "release-manifests") {
  const repositoryRoot = resolve(process.argv[3] ?? defaultRepositoryRoot);
  const written = writeReleaseManifests(repositoryRoot);
  console.log(`generated ${written.length} release manifests`);
} else {
  console.error(
    "usage: tsx src/cli.ts <author|verify|family-check|coverage|release-manifests> [root]",
  );
  process.exitCode = 2;
}
