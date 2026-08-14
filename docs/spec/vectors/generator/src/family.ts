import type { DocumentId, QualifiedVersion } from "./types.js";

export type { DocumentId, QualifiedVersion } from "./types.js";

export const DOCUMENT_VERSIONS: Record<DocumentId, string> = {
  core: "0.5.0",
  comms: "0.5.0",
  control: "0.5.0",
  social: "0.5.0",
  workspace: "0.1.0",
};

export const DOCUMENT_DEPENDENCIES: Record<
  DocumentId,
  readonly DocumentId[]
> = {
  core: [],
  comms: ["core"],
  control: ["core", "comms"],
  social: ["core", "comms"],
  workspace: ["core", "comms", "control", "social"],
};

const QUALIFIED_VERSION =
  /^(core|comms|control|social|workspace)\/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseQualifiedVersion(value: string): QualifiedVersion {
  const match = QUALIFIED_VERSION.exec(value);
  if (match === null) {
    throw new Error(`invalid qualified version: ${value}`);
  }

  const [, document] = match;
  return {
    document: document as DocumentId,
    semver: value.slice(document.length + 1),
  };
}

export function assertAllowedDependency(
  document: DocumentId,
  dependency: DocumentId,
): void {
  if (!DOCUMENT_DEPENDENCIES[document].includes(dependency)) {
    throw new Error(`forbidden dependency: ${document} -> ${dependency}`);
  }
}
