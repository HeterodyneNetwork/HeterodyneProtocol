export type DocumentId = "core" | "comms" | "control" | "social" | "workspace";

export type VectorDirection = "produce" | "consume" | "round-trip";

export type Vector = {
  vector_id: string;
  vector_schema_version: string;
  /** The document that owns the requirement, for coverage reporting only. */
  owner_document: DocumentId;
  spec_version: string;
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
