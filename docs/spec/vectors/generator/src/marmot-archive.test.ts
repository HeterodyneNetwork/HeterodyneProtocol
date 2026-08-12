import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyMarmotArchive } from "./marmot-archive.js";

const root = resolve(import.meta.dirname, "../../../../../");
const temps: string[] = [];
afterEach(() => temps.splice(0).forEach((path) => rmSync(path, { recursive: true, force: true })));

function copyArchive(): string {
  const temp = mkdtempSync(join(tmpdir(), "heterodyne-marmot-"));
  temps.push(temp);
  cpSync(join(root, "docs/spec/external/marmot"), join(temp, "marmot"), { recursive: true });
  return join(temp, "marmot");
}

describe("closed Marmot normative archive", () => {
  it("accepts the committed archive", () => {
    expect(verifyMarmotArchive(join(root, "docs/spec/external/marmot"))).toEqual([]);
  });

  it("rejects changed, missing, extra, and unsafe entries", () => {
    const changed = copyArchive();
    writeFileSync(join(changed, "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/README.md"), "changed\n");
    expect(verifyMarmotArchive(changed).join("\n")).toMatch(/digest|length|blob/i);

    const missing = copyArchive();
    rmSync(join(missing, "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/README.md"));
    expect(verifyMarmotArchive(missing).join("\n")).toMatch(/missing/i);

    const extra = copyArchive();
    writeFileSync(join(extra, "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/extra.md"), "extra\n");
    expect(verifyMarmotArchive(extra).join("\n")).toMatch(/extra/i);

    const unsafe = copyArchive();
    const manifestPath = join(unsafe, "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.files[0].path = "../escape.md";
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    expect(verifyMarmotArchive(unsafe).join("\n")).toMatch(/unsafe/i);
  });
});
