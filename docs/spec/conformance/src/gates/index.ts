import { findAnchorCoverageFailures } from "./anchor-coverage.js";
import { findAnchorResolutionFailures } from "./anchor-resolution.js";
import { findDeadVocabularyFailures } from "./dead-vocabulary.js";
import { findFixturesConsistencyFailures } from "./fixtures-consistency.js";
import { findInvariantCompletenessFailures } from "./invariant-completeness.js";
import { findIdentifierIntegrityFailures } from "./identifier-integrity.js";
import { findNegativeHygieneFailures } from "./negative-hygiene.js";
import { findNip01RawFailures } from "./nip01-raw.js";
import { findOrphanSchemaFailures } from "./orphan-schemas.js";
import { findReasonCodeClosureFailures } from "./reason-code-closure.js";
import { findSignatureIntegrityFailures } from "./signature-integrity.js";
import type { Gate } from "./types.js";

export const G1: Gate = {
  id: "G1",
  name: "anchor-resolution",
  evaluate: findAnchorResolutionFailures,
};

export const G2: Gate = {
  id: "G2",
  name: "reason-code-closure",
  evaluate: findReasonCodeClosureFailures,
};

export const G3: Gate = {
  id: "G3",
  name: "invariant-completeness",
  evaluate: findInvariantCompletenessFailures,
};

export const G4: Gate = {
  id: "G4",
  name: "anchor-coverage",
  evaluate: findAnchorCoverageFailures,
};

export const G5: Gate = {
  id: "G5",
  name: "fixtures-consistency",
  evaluate: findFixturesConsistencyFailures,
};

export const G6: Gate = {
  id: "G6",
  name: "dead-vocabulary",
  evaluate: findDeadVocabularyFailures,
};

export const G7: Gate = {
  id: "G7",
  name: "orphan-schemas",
  evaluate: findOrphanSchemaFailures,
};

export const G8: Gate = {
  id: "G8",
  name: "identifier-integrity",
  evaluate: findIdentifierIntegrityFailures,
};

export const G9: Gate = {
  id: "G9",
  name: "signature-integrity",
  evaluate: findSignatureIntegrityFailures,
};

export const G10: Gate = {
  id: "G10",
  name: "nip01-raw",
  evaluate: findNip01RawFailures,
};

export const G11: Gate = {
  id: "G11",
  name: "negative-hygiene",
  evaluate: findNegativeHygieneFailures,
};

export const STATIC_GATES: readonly Gate[] = [G1, G2, G3, G4, G5, G6, G7];

export const ALL_GATES: readonly Gate[] = [
  G1, G2, G3, G4, G5, G6, G7, G8, G9, G10, G11,
];

export type { Gate, GateId, GateResult } from "./types.js";
