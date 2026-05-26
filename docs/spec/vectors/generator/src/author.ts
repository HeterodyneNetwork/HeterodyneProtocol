import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { buildFixtures } from "./fixtures.js";
import { REASON_CODES } from "./reason-codes.js";
import { VECTOR_SCHEMA, validateVectorOrThrow } from "./schema.js";
import { buildAllVectors } from "./topics.js";

export async function authorAllVectors(outputDir: string): Promise<string[]> {
  const fixtures = buildFixtures();
  const vectors = await buildAllVectors(fixtures);
  const written: string[] = [];

  await writeJson(join(outputDir, "fixtures.json"), fixtures);
  await writeJson(join(outputDir, "schema", "vector.schema.json"), VECTOR_SCHEMA);
  await writeJson(join(outputDir, "schema", "reason-codes.json"), { reason_codes: REASON_CODES });
  await writeReasonCodesMarkdown(join(outputDir, "schema", "reason-codes.md"));

  for (const { relativePath, vector } of vectors) {
    validateVectorOrThrow(vector);
    await writeJson(join(outputDir, relativePath), vector);
    written.push(relativePath);
  }

  return written.sort();
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeReasonCodesMarkdown(path: string): Promise<void> {
  const rows = REASON_CODES.map(
    (reason) => `| \`${reason.code}\` | ${reason.spec_refs.join(", ")} | ${reason.description} |`,
  ).join("\n");
  await mkdir(dirname(path), { recursive: true });
  await writeFile(
    path,
    `# Reason codes\n\n` +
      "`reason_code` values are conformance-test vocabulary. Implementations do not need to emit these strings on the wire.\n\n" +
      "| Code | Spec refs | Meaning |\n" +
      "|---|---|---|\n" +
      `${rows}\n`,
    "utf8",
  );
}
