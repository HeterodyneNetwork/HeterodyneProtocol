import { mkdtempSync, rmSync, symlinkSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { parseJsonPointer, resolveJsonPointer } from "./json-pointer.js";
import { safeRepositoryPath } from "./artifacts.js";

const temps: string[] = [];

afterEach(() => {
  for (const path of temps.splice(0)) {
    rmSync(path, { recursive: true, force: true });
  }
});

describe("JSON Pointer", () => {
  it("resolves escaped tokens", () => {
    expect(resolveJsonPointer({ "a/b": { "~key": 7 } }, "/a~1b/~0key"))
      .toEqual({ found: true, value: 7 });
  });

  it("rejects root, relative, and prototype-traversing pointers", () => {
    for (const pointer of ["", "input/event", "/__proto__/x", "/constructor/prototype"]) {
      expect(() => parseJsonPointer(pointer)).toThrow();
    }
  });

  it("rejects malformed escape sequences", () => {
    for (const pointer of ["/~", "/~2", "/valid/~01/~x"]) {
      expect(() => parseJsonPointer(pointer)).toThrow();
    }
  });

  it("does not resolve inherited properties", () => {
    expect(resolveJsonPointer({}, "/toString")).toEqual({ found: false });
  });
});

describe("safeRepositoryPath", () => {
  it("rejects absolute and non-normalized paths", () => {
    const repositoryRoot = mkdtempSync(join(tmpdir(), "heterodyne-paths-"));
    temps.push(repositoryRoot);
    mkdirSync(resolve(repositoryRoot, "docs/spec"), { recursive: true });

    for (const path of ["/tmp/x", "../x", "docs//spec", "docs/./spec"]) {
      expect(() => safeRepositoryPath(repositoryRoot, path)).toThrow();
    }
  });

  it("rejects a symlink that resolves outside the repository", () => {
    const repositoryRoot = mkdtempSync(join(tmpdir(), "heterodyne-repository-"));
    const outsideRoot = mkdtempSync(join(tmpdir(), "heterodyne-outside-"));
    temps.push(repositoryRoot, outsideRoot);
    writeFileSync(resolve(outsideRoot, "artifact.json"), "{}\n", "utf8");
    symlinkSync(resolve(outsideRoot, "artifact.json"), resolve(repositoryRoot, "escape.json"));

    expect(() => safeRepositoryPath(repositoryRoot, "escape.json")).toThrow();
  });
});
