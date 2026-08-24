import { spawnSync } from "node:child_process";
import {
  afterEach,
  describe,
  expect,
  it,
} from "vitest";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { computeRegistryDigest, loadRegistry } from "./registry.js";

const here = dirname(fileURLToPath(import.meta.url));
const generatorRoot = resolve(here, "..");
const registryRoot = resolve(here, "../../../registry");
const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("registry-author CLI", () => {
  it("authors a deliberately stale manifest before importing unrelated vector fixtures", () => {
    const repositoryRoot = mkdtempSync(join(tmpdir(), "heterodyne-registry-author-"));
    temporaryRoots.push(repositoryRoot);
    const copiedRegistryRoot = resolve(repositoryRoot, "docs/spec/registry");
    const copiedGeneratorRoot = resolve(repositoryRoot, "docs/spec/vectors/generator");

    mkdirSync(resolve(repositoryRoot, "docs/spec/vectors"), { recursive: true });
    cpSync(registryRoot, copiedRegistryRoot, { recursive: true });
    cpSync(resolve(generatorRoot, "src"), resolve(copiedGeneratorRoot, "src"), {
      recursive: true,
    });
    cpSync(resolve(generatorRoot, "package.json"), resolve(copiedGeneratorRoot, "package.json"));
    cpSync(
      resolve(generatorRoot, "..", "schema"),
      resolve(copiedGeneratorRoot, "..", "schema"),
      { recursive: true },
    );
    cpSync(
      resolve(generatorRoot, "..", "..", "schemas"),
      resolve(copiedGeneratorRoot, "..", "..", "schemas"),
      { recursive: true },
    );
    for (const schema of [
      "snapshot.schema.json",
      "snapshot.meta.schema.json",
      "snapshot-unique-by-path.meta.schema.json",
    ]) {
      cpSync(resolve(generatorRoot, "..", schema), resolve(copiedGeneratorRoot, "..", schema));
    }
    symlinkSync(
      resolve(generatorRoot, "node_modules"),
      resolve(copiedGeneratorRoot, "node_modules"),
      "dir",
    );

    const featuresPath = resolve(copiedRegistryRoot, "features.json");
    const features = JSON.parse(readFileSync(featuresPath, "utf8")) as {
      features: Array<{ description: string }>;
    };
    const firstFeature = features.features[0];
    if (firstFeature === undefined) throw new Error("copied registry has no features");
    firstFeature.description += " Deliberately stale CLI fixture.";
    writeFileSync(featuresPath, `${JSON.stringify(features, null, 2)}\n`, "utf8");
    expect(() => loadRegistry(repositoryRoot)).toThrow(
      "registry manifest digest does not match current entry set",
    );

    const result = spawnSync(
      resolve(generatorRoot, "node_modules/.bin/tsx"),
      [
        resolve(copiedGeneratorRoot, "src/cli.ts"),
        "registry-author",
        repositoryRoot,
        "14",
      ],
      { cwd: copiedGeneratorRoot, encoding: "utf8" },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toMatch(/authored registry revision 14 \([0-9a-f]{64}\)/);
    const authored = loadRegistry(repositoryRoot);
    expect(authored.manifest.revision).toBe(14);
    expect(authored.manifest.entry_set_sha256).toBe(computeRegistryDigest(authored));
  });
});
