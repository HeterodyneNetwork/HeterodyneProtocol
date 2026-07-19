export type DocumentId = "core" | "comms" | "control" | "social";

export type QualifiedVersion = { document: DocumentId; semver: string };

export type VectorDirection = "produce" | "consume" | "round-trip";

export type Vector = {
  vector_id: string;
  vector_schema_version: string;
  spec_version: string;
  spec_refs: string[];
  description: string;
  direction: VectorDirection;
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
  fixtures?: Record<string, unknown>;
  simulated_clock?: number;
  decision_trace?: string[];
  transport_context?: Record<string, unknown>;
  notes?: string;
};

export type AuthoredVector = {
  relativePath: string;
  vector: Vector;
};
