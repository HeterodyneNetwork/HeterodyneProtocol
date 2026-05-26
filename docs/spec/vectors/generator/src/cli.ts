import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { authorAllVectors } from "./author.js";
import { verifyVectorTree } from "./verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const defaultVectorRoot = resolve(here, "..", "..");
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
} else {
  console.error("usage: tsx src/cli.ts <author|verify> [vector-root]");
  process.exitCode = 2;
}
