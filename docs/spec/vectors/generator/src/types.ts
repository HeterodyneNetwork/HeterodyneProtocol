export type DocumentId =
  | "core" | "assurance" | "comms" | "control" | "social" | "workspace";

export type VectorDirection = "produce" | "consume" | "round-trip";

export type ExpectedTerminalStage =
  | "event_structure" | "nip01_raw" | "identifier" | "signature"
  | "persona_resolution" | "version_stamp" | "kel_head"
  | "epoch_authority" | "subtype_nid" | "accept";

export type ConformanceCheck = {
  profile: "core-signed-event-v1";
  event_pointer: string;
  nip01_raw_pointer: string;
  context_pointer?: string;
  expected_terminal_stage: ExpectedTerminalStage;
};

export type RawVector = {
  vector_id: string;
  vector_schema_version: string;
  /** The document that owns the requirement, for coverage reporting only. */
  owner_document: DocumentId;
  spec_version: string;
  profile?: string;
  conformance_checks?: ConformanceCheck[];
  spec_refs: string[];
  description: string;
  direction: VectorDirection;
  input: Record<string, unknown>;
  expected_output: Record<string, unknown>;
};

/** Current draft generator input, retained independently from snapshot output. */
export type Vector = RawVector;

export type SnapshotVector = Omit<
  RawVector,
  "vector_schema_version" | "spec_version" | "spec_refs"
> & {
  vector_schema_version: "2.0.0";
  spec_refs: string[];
};

export type AuthoredVector = {
  relativePath: string;
  vector: Vector;
};
