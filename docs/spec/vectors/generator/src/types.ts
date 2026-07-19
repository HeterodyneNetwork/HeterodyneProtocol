export type DocumentId = "core" | "comms" | "control" | "social";

export type QualifiedVersion = { document: DocumentId; semver: string };

export type VectorDirection = "produce" | "consume" | "round-trip";

export type Vector = {
  vector_id: string;
  vector_schema_version: string;
  owner_document: DocumentId;
  owner_version: string;
  dependency_versions: Partial<Record<DocumentId, string>>;
  registry_revision: number;
  profile?: string;
  spec_refs: string[];
  description: string;
  direction: VectorDirection;
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
};

export type AuthoredVector = {
  relativePath: string;
  vector: Vector;
};
