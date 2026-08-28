import {
  closeSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildIsolatedCurrentCatalog,
  copyRegularCurrentRuntimeAsset,
  parseCurrentRuntimeEnvelope,
  runGuardedCurrentRuntimeEntry,
  withDisposableCurrentRuntime,
} from "./current-authoring-runtime.js";
import {
  findInvariantCoverageIssues,
  findProfileCoverageIssues,
  findReasonCoverageIssues,
} from "./coverage.js";
import { loadRegistry } from "./registry.js";

const roots: string[] = [];

function temporaryRoot(label: string): string {
  const root = mkdtempSync(join(tmpdir(), label));
  roots.push(root);
  return root;
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("current authoring child runtime", () => {
  it("cleans the exact guarded runtime directory when construction or parsing fails", async () => {
    const generatorRoot = resolve(import.meta.dirname, "..");
    const before = (await (await import("node:fs/promises")).readdir(generatorRoot))
      .filter((name) => name.startsWith(".heterodyne-current-runtime-"));
    await expect(withDisposableCurrentRuntime(async (runtimeRoot) => {
      writeFileSync(join(runtimeRoot, "partial.txt"), "partial", "utf8");
      throw new Error("injected construction failure");
    })).rejects.toThrow(/injected construction failure/u);
    const after = (await (await import("node:fs/promises")).readdir(generatorRoot))
      .filter((name) => name.startsWith(".heterodyne-current-runtime-"));
    expect(after).toEqual(before);
  });

  it("fails closed on timeout and bounded stdout or stderr", async () => {
    const outer = temporaryRoot("heterodyne-current-runtime-limits-");
    const runtimeRoot = join(outer, ".heterodyne-current-runtime-limits");
    mkdirSync(runtimeRoot);
    const timeoutEntry = join(runtimeRoot, "timeout.mjs");
    const stdoutEntry = join(runtimeRoot, "stdout.mjs");
    const stderrEntry = join(runtimeRoot, "stderr.mjs");
    writeFileSync(timeoutEntry, "setInterval(() => {}, 1000);\n", "utf8");
    writeFileSync(stdoutEntry, 'process.stdout.write("x".repeat(11));\n', "utf8");
    writeFileSync(stderrEntry, 'process.stderr.write("x".repeat(11));\n', "utf8");
    await expect(runGuardedCurrentRuntimeEntry({
      runtimeRoot,
      entryPath: timeoutEntry,
      timeoutMs: 25,
    })).rejects.toThrow(/timed out/u);
    await expect(runGuardedCurrentRuntimeEntry({
      runtimeRoot,
      entryPath: stdoutEntry,
      stdoutLimit: 10,
    })).rejects.toThrow(/stdout exceeded/u);
    await expect(runGuardedCurrentRuntimeEntry({
      runtimeRoot,
      entryPath: stderrEntry,
      stderrLimit: 10,
    })).rejects.toThrow(/stderr exceeded/u);
  });

  it("rejects malformed, open, count-mismatched, and schema-invalid child envelopes", () => {
    expect(() => parseCurrentRuntimeEnvelope("not-json")).toThrow(/malformed JSON/u);
    expect(() => parseCurrentRuntimeEnvelope(JSON.stringify({
      format: "heterodyne-current-authoring-1",
      vectors: [],
      semantic_coverage: [],
      evidence: {},
    }))).toThrow(/must contain exactly/u);
    expect(() => parseCurrentRuntimeEnvelope(JSON.stringify({
      format: "heterodyne-current-authoring-1",
      vectors: [],
      semantic_coverage: [{
        vector_id: "core/missing",
        owner_document: "core",
        spec_refs: ["heterodyne:0.6.0#core-conformance"],
        invariants: ["CORE-I-IDENTITY-INTEGRITY"],
        reason_codes: [],
        semantic_boundary: "test.boundary",
      }],
    }))).toThrow(/count mismatch/u);
    expect(() => parseCurrentRuntimeEnvelope(JSON.stringify({
      format: "heterodyne-current-authoring-1",
      vectors: [{ relativePath: "core/invalid.json", vector: {} }],
      semantic_coverage: [],
    }))).toThrow(/schema-invalid vector/u);
    expect(() => parseCurrentRuntimeEnvelope(JSON.stringify({
      format: "heterodyne-current-authoring-1",
      vectors: [{ relativePath: "../escape.json", vector: {} }],
      semantic_coverage: [],
    }))).toThrow(/unsafe vector path/u);
  });

  it("authors all current vectors and semantic closure inside an exact disposable tree", async () => {
    const generatorRoot = resolve(import.meta.dirname, "..");
    const before = new Set(
      await (await import("node:fs/promises")).readdir(generatorRoot).then((names) =>
        names.filter((name) => name.startsWith(".heterodyne-current-runtime-"))
      ),
    );
    const catalog = await buildIsolatedCurrentCatalog();
    expect(catalog.vectors).toHaveLength(275);
    expect(catalog.semantic_coverage).toHaveLength(275);
    expect(findInvariantCoverageIssues(loadRegistry(resolve(generatorRoot, "../../../..")), catalog.semantic_coverage))
      .toEqual([]);
    expect(findReasonCoverageIssues(loadRegistry(resolve(generatorRoot, "../../../..")), catalog.semantic_coverage))
      .toEqual([]);
    expect(findProfileCoverageIssues(loadRegistry(resolve(generatorRoot, "../../../..")), catalog.semantic_coverage))
      .toEqual([]);
    const serialized = JSON.stringify(catalog);
    expect(serialized).not.toMatch(/raw_result|boundary_args|semanticEvidenceForCase/u);
    const after = (await import("node:fs/promises")).readdir(generatorRoot).then((names) =>
      names.filter((name) => name.startsWith(".heterodyne-current-runtime-"))
    );
    expect(new Set(await after)).toEqual(before);
  }, 180_000);

  it("copies only explicit regular assets and rejects symlinks or special files", () => {
    const outer = temporaryRoot("heterodyne-current-runtime-assets-");
    const sourceRoot = join(outer, "source");
    const runtimeRoot = join(outer, ".heterodyne-current-runtime-assets");
    mkdirSync(sourceRoot);
    mkdirSync(runtimeRoot);
    writeFileSync(join(sourceRoot, "allowed.json"), "{\"ok\":true}\n", "utf8");
    symlinkSync(join(sourceRoot, "allowed.json"), join(sourceRoot, "linked.json"));
    execFileSync("mkfifo", [join(sourceRoot, "special.json")]);

    copyRegularCurrentRuntimeAsset(sourceRoot, runtimeRoot, "allowed.json");
    expect(existsSync(join(runtimeRoot, "allowed.json"))).toBe(true);
    expect(() => copyRegularCurrentRuntimeAsset(sourceRoot, runtimeRoot, "linked.json"))
      .toThrow(/regular file/u);
    expect(() => copyRegularCurrentRuntimeAsset(sourceRoot, runtimeRoot, "special.json"))
      .toThrow(/regular file/u);
    expect(() => copyRegularCurrentRuntimeAsset(sourceRoot, runtimeRoot, "../escape.json"))
      .toThrow(/escapes/u);
  });

  it("denies reflective repository access and ambient execution capabilities", async () => {
    const outer = temporaryRoot("heterodyne-current-runtime-policy-");
    const runtimeRoot = join(outer, ".heterodyne-current-runtime-fixture");
    const sentinel = resolve(import.meta.dirname, "../package.json");
    const omittedTopic = resolve(import.meta.dirname, "topics.ts");
    const writeTarget = join(outer, "forbidden-write.txt");
    await import("node:fs/promises").then(({ mkdir }) => mkdir(runtimeRoot));
    writeFileSync(join(runtimeRoot, "fake.node"), "not-an-addon", "utf8");
    writeFileSync(
      join(runtimeRoot, "entry.mjs"),
      `
const attempts = {};
const capture = async (name, operation) => {
  try { attempts[name] = { ok: true, value: await operation() }; }
  catch (error) { attempts[name] = { ok: false, code: error?.code, name: error?.name }; }
};
const getBuiltin = Reflect.get(process, "getBuiltinModule").bind(process);
await capture("reflect_fs", () => Reflect.get(getBuiltin("node:fs"), "readFileSync")(process.argv[2], "utf8"));
await capture("reflect_require", () => {
  const createRequire = Reflect.get(getBuiltin("node:module"), "createRequire");
  return createRequire(import.meta.url)(process.argv[3]);
});
await capture("reflect_async_import", () => {
  const AsyncFunction = Reflect.getPrototypeOf(async function () {}).constructor;
  return AsyncFunction("specifier", "return import(specifier)")(process.argv[3]);
});
await capture("write", () => getBuiltin("node:fs").writeFileSync(process.argv[4], "x"));
await capture("child", () => getBuiltin("node:child_process").spawnSync(process.execPath, ["-e", "0"]));
await capture("worker", async () => {
  const { Worker } = getBuiltin("node:worker_threads");
  const worker = new Worker("", { eval: true });
  await worker.terminate();
});
await capture("addon", () => {
  const createRequire = Reflect.get(getBuiltin("node:module"), "createRequire");
  return createRequire(import.meta.url)(new URL("./fake.node", import.meta.url).pathname);
});
await capture("wasi", () => {
  const { WASI } = getBuiltin("node:wasi");
  return new WASI({ version: "preview1" });
});
await capture("fd", () => getBuiltin("node:fs").readFileSync(Number(process.argv[5]), "utf8"));
attempts.webassembly = { ok: typeof WebAssembly !== "undefined" };
process.stdout.write(JSON.stringify(attempts));
`,
      "utf8",
    );
    const fd = openSync(sentinel, "r");
    try {
      const result = await runGuardedCurrentRuntimeEntry({
        runtimeRoot,
        entryPath: join(runtimeRoot, "entry.mjs"),
        arguments: [sentinel, omittedTopic, writeTarget, String(fd)],
      });
      const attempts = JSON.parse(result.stdout) as Record<
        string,
        { ok: boolean; code?: string }
      >;
      expect(attempts.reflect_fs.code).toBe("ERR_ACCESS_DENIED");
      expect(attempts.reflect_require.code).toBe("ERR_ACCESS_DENIED");
      expect(attempts.reflect_async_import.code).toBe("ERR_ACCESS_DENIED");
      expect(attempts.write.code).toBe("ERR_ACCESS_DENIED");
      expect(attempts.child.code).toBe("ERR_ACCESS_DENIED");
      expect(attempts.worker.code).toBe("ERR_ACCESS_DENIED");
      expect(attempts.addon.code).toBe("ERR_DLOPEN_DISABLED");
      expect(attempts.wasi.code).toBe("ERR_ACCESS_DENIED");
      expect(attempts.fd.code).toBe("EBADF");
      expect(attempts.webassembly.ok).toBe(false);
    } finally {
      closeSync(fd);
    }
  });
});
