import { resolve } from "node:path";
import { loadRegistry } from "../registry.js";
import type { AuthoredVector } from "../types.js";
import { buildAssuranceCases } from "./assurance.js";
import { buildCommsCases } from "./comms.js";
import { buildControlCases } from "./control.js";
import { buildCoreCases } from "./core.js";
import { buildSocialCases } from "./social.js";
import { buildProfileCases } from "./profiles.js";
import { authorCurrentCase, type CurrentVectorCase } from "./types.js";
import { buildWorkspaceCases } from "./workspace.js";

const REPOSITORY_ROOT = resolve(import.meta.dirname, "../../../../../..");

export async function buildCurrentCases(): Promise<CurrentVectorCase[]> {
  return [
    ...await buildCoreCases(),
    ...await buildAssuranceCases(),
    ...await buildCommsCases(),
    ...await buildControlCases(),
    ...await buildSocialCases(),
    ...buildWorkspaceCases(),
    ...buildProfileCases(loadRegistry(REPOSITORY_ROOT)),
  ];
}

export async function buildCurrentVectors(): Promise<AuthoredVector[]> {
  const cases = await buildCurrentCases();
  const authored = cases.map(authorCurrentCase).sort((left, right) =>
    left.relativePath.localeCompare(right.relativePath, "en")
  );
  const paths = new Set<string>();
  const ids = new Set<string>();
  for (const { relativePath, vector } of authored) {
    if (paths.has(relativePath)) throw new Error(`duplicate current vector path: ${relativePath}`);
    if (ids.has(vector.vector_id)) throw new Error(`duplicate current vector id: ${vector.vector_id}`);
    paths.add(relativePath);
    ids.add(vector.vector_id);
  }
  return authored;
}

export type { CurrentVectorCase } from "./types.js";
