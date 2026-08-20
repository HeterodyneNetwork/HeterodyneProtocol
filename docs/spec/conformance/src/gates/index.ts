import { findAnchorCoverageFailures } from "./anchor-coverage.js";
import { findAnchorResolutionFailures } from "./anchor-resolution.js";
import { findDeadVocabularyFailures } from "./dead-vocabulary.js";
import { findFixturesConsistencyFailures } from "./fixtures-consistency.js";
import { findInvariantCompletenessFailures } from "./invariant-completeness.js";
import { findOrphanSchemaFailures } from "./orphan-schemas.js";
import { findReasonCodeClosureFailures } from "./reason-code-closure.js";
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

export const STATIC_GATES: readonly Gate[] = [G1, G2, G3, G4, G5, G6, G7];

export type { Gate, GateId, GateResult } from "./types.js";
