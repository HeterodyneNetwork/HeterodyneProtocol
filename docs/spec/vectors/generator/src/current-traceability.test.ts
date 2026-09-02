import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildCurrentVectors } from "./current-vectors/index.js";

const repositoryRoot = resolve(import.meta.dirname, "../../../../../");
const currentReference = /^heterodyne:0\.6\.0#([a-z0-9][a-z0-9-]*)$/u;

function explicitAnchors(owner: string): ReadonlySet<string> {
  const specification = readFileSync(
    resolve(repositoryRoot, "docs/spec", `heterodyne-${owner}.md`),
    "utf8",
  );
  return new Set(
    [...specification.matchAll(/<a\s+id="([a-z0-9-]+)"\s*><\/a>/gu)]
      .map((match) => match[1]!),
  );
}

describe("current vector specification traceability", () => {
  it("resolves every current case reference in its owner specification", async () => {
    const vectors = await buildCurrentVectors();
    const anchorsByOwner = new Map<string, ReadonlySet<string>>();
    const failures: string[] = [];

    for (const { vector } of vectors) {
      let anchors = anchorsByOwner.get(vector.owner_document);
      if (anchors === undefined) {
        anchors = explicitAnchors(vector.owner_document);
        anchorsByOwner.set(vector.owner_document, anchors);
      }
      for (const reference of vector.spec_refs) {
        const match = currentReference.exec(reference);
        if (match === null || !anchors.has(match[1]!)) {
          failures.push(`${vector.vector_id} :: ${reference}`);
        }
      }
    }

    expect(failures.sort()).toEqual([]);
  }, 60_000);

});
