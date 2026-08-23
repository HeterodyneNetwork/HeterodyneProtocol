import type { ArtifactCorpus } from "../types.js";

const fixtureKeys = new Set([
  "audience_keys",
  "category_keysets",
  "device_publishing_keys",
  "ed25519_nids",
  "kel",
  "personas",
  "pinned_randomness",
  "radicle_rids",
  "registry_sha256",
  "test_epoch",
  "vector_schema_version",
]);

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function fixturePointer(key: string): string {
  return `/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`;
}

export function findFixturesConsistencyFailures(corpus: ArtifactCorpus): string[] {
  const failures = new Set<string>();

  for (const key of fixtureKeys) {
    if (!Object.hasOwn(corpus.fixtures, key)) {
      failures.add(`/${key}`);
    }
  }
  for (const key of Object.keys(corpus.fixtures)) {
    if (!fixtureKeys.has(key)) {
      failures.add(fixturePointer(key));
    }
  }

  if (corpus.fixtures.vector_schema_version !== corpus.vectorSchemaVersion) {
    failures.add("/vector_schema_version");
  }
  if (corpus.fixtures.registry_sha256 !== corpus.registry.manifest.entry_set_sha256) {
    failures.add("/registry_sha256");
  }

  return [...failures].sort(compareText);
}
