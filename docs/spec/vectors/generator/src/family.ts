import type { DocumentId } from "./types.js";

export type { DocumentId } from "./types.js";

/**
 * The single family version. The six documents are sections of one
 * specification, not independent lineages: every document pins the same
 * version and the same registry revision, so one string is the only source
 * of truth for both.
 */
export const FAMILY_VERSION = "0.6.0";

export const QUALIFIED_VERSION = `heterodyne/${FAMILY_VERSION}`;

export const DOCUMENTS: readonly DocumentId[] = [
  "core",
  "assurance",
  "comms",
  "control",
  "social",
  "workspace",
];

/**
 * Which documents each document may normatively depend on. This is a layering
 * constraint, not a versioning one: the six documents ship as one version,
 * but Core still MUST NOT reference Social, and the graph MUST stay acyclic.
 */
export const DOCUMENT_LAYERING: Record<DocumentId, readonly DocumentId[]> = {
  core: [],
  assurance: ["core"],
  comms: ["core"],
  control: ["core", "comms"],
  social: ["core", "comms"],
  workspace: ["core", "comms", "control", "social"],
};

export function assertAllowedDependency(
  document: DocumentId,
  dependency: DocumentId,
): void {
  if (!DOCUMENT_LAYERING[document].includes(dependency)) {
    throw new Error(`forbidden dependency: ${document} -> ${dependency}`);
  }
}

const SEMVER =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** Parses `heterodyne/<semver>` and returns the semver suffix. */
export function parseFamilyVersion(value: string): string {
  const semver = value.startsWith("heterodyne/")
    ? value.slice("heterodyne/".length)
    : null;
  if (semver === null || !SEMVER.test(semver)) {
    throw new Error(`invalid family version: ${value}`);
  }
  return semver;
}

export function assertCurrentFamilyVersion(value: string): void {
  if (parseFamilyVersion(value) !== FAMILY_VERSION) {
    throw new Error(`expected ${QUALIFIED_VERSION}, got ${value}`);
  }
}

export function negotiateExactFamilyVersion(
  local: readonly string[],
  remote: readonly string[],
): string | null {
  return local.includes(QUALIFIED_VERSION) && remote.includes(QUALIFIED_VERSION)
    ? QUALIFIED_VERSION
    : null;
}
