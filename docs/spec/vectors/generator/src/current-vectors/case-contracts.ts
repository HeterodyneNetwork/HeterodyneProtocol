import type { DocumentId } from "../types.js";
import { currentProfileOracleForVector } from "./profile-oracles.js";

export type CurrentCaseContract = Readonly<{
  boundary_id: string;
  owner_document: DocumentId;
  profile?: string;
  spec_refs: readonly string[];
  invariants: readonly string[];
  reason_codes: readonly string[];
  /** Executed diagnostic reasons, including non-reject terminal results. */
  semantic_reason_codes?: readonly string[];
}>;

/**
 * Closed, reviewable traceability allocation for the current catalog.
 *
 * Family fixture builders cannot mint or alter these labels. Runtime evidence
 * is accepted only when the built case is bound to this exact allocation.
 */
const CURRENT_CASE_CONTRACTS = {
  "assurance/associated-key-expired": {
    "boundary_id": "assurance.evaluateAssociatedKey",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-associated-key-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-associated-keys"
    ],
    "invariants": [
      "ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"
    ],
    "reason_codes": [
      "assurance-associated-key-expired"
    ]
  },
  "assurance/associated-key-revoked": {
    "boundary_id": "assurance.evaluateAssociatedKey",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-associated-key-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-associated-keys"
    ],
    "invariants": [
      "ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"
    ],
    "reason_codes": [
      "assurance-associated-key-revoked"
    ]
  },
  "assurance/associated-key-subject-proof-invalid": {
    "boundary_id": "assurance.evaluateAssociatedKey",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-associated-key-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-associated-keys"
    ],
    "invariants": [
      "ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"
    ],
    "reason_codes": [
      "assurance-associated-key-subject-proof-invalid"
    ]
  },
  "assurance/associated-key-subject-proof-required": {
    "boundary_id": "assurance-policy.evaluateAssuranceAssociatedKeyConsent",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-associated-key-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-associated-keys"
    ],
    "invariants": [
      "ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"
    ],
    "reason_codes": [
      "assurance-associated-key-subject-proof-required"
    ]
  },
  "assurance/authority-at-compromise-cutoff": {
    "boundary_id": "assurance.evaluateAssuranceAuthorityAt",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-compromise"
    ],
    "invariants": [
      "ASSURANCE-I-COMPROMISE-CUTOFF"
    ],
    "reason_codes": [
      "assurance-compromise-cutoff"
    ]
  },
  "assurance/compromise-subordinate-continuation-forbidden": {
    "boundary_id": "assurance-policy.evaluateAssuranceCompromiseContinuation",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-compromise"
    ],
    "invariants": [
      "ASSURANCE-I-COMPROMISE-CUTOFF",
      "ASSURANCE-I-NO-IMPLICIT-CONTINUATION"
    ],
    "reason_codes": [
      "assurance-subordinate-continuation-forbidden"
    ]
  },
  "assurance/duplicity-rejected": {
    "boundary_id": "assurance-policy.evaluateAssurancePinPolicy",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-chain-validation"
    ],
    "invariants": [
      "ASSURANCE-I-SUCCESSION-NON-ALIASING"
    ],
    "reason_codes": [
      "assurance-duplicity"
    ]
  },
  "assurance/enrollment-competing-inception": {
    "boundary_id": "assurance-observation.evaluateEnrollmentEligibility",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-enrollment-window"
    ],
    "invariants": [
      "ASSURANCE-I-ENROLLMENT-WINDOWED"
    ],
    "reason_codes": [
      "assurance-enrollment-contested"
    ]
  },
  "assurance/enrollment-forged-contest-ignored": {
    "boundary_id": "assurance-observation.evaluateEnrollmentEligibility",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-enrollment-window"
    ],
    "invariants": [
      "ASSURANCE-I-ENROLLMENT-WINDOWED",
      "ASSURANCE-I-CORE-OPTIONALITY"
    ],
    "reason_codes": []
  },
  "assurance/enrollment-late-warning-no-unpin": {
    "boundary_id": "assurance-observation.evaluateEnrollmentEligibility",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-pinning"
    ],
    "invariants": [
      "ASSURANCE-I-ENROLLMENT-WINDOWED",
      "ASSURANCE-I-PIN-DOWNGRADE"
    ],
    "reason_codes": []
  },
  "assurance/enrollment-pending-w-minus-one": {
    "boundary_id": "assurance-observation.evaluateEnrollmentEligibility",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-enrollment-inception-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-enrollment-window"
    ],
    "invariants": [
      "ASSURANCE-I-ENROLLMENT-WINDOWED"
    ],
    "reason_codes": [
      "assurance-enrollment-pending-window"
    ]
  },
  "assurance/enrollment-timely-contest": {
    "boundary_id": "assurance-observation.evaluateEnrollmentEligibility",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-enrollment-contest-profile-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-enrollment-window"
    ],
    "invariants": [
      "ASSURANCE-I-ENROLLMENT-WINDOWED"
    ],
    "reason_codes": [
      "assurance-enrollment-contested"
    ]
  },
  "assurance/enrollment-verified-at-window": {
    "boundary_id": "assurance-observation.evaluateEnrollmentEligibility",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-enrollment-window"
    ],
    "invariants": [
      "ASSURANCE-I-ENROLLMENT-WINDOWED"
    ],
    "reason_codes": []
  },
  "assurance/export-aid-substitution": {
    "boundary_id": "assurance-policy.evaluateAssuranceExport",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-keri-export"
    ],
    "invariants": [
      "ASSURANCE-I-EXPORT-LOSSLESS"
    ],
    "reason_codes": [
      "export_aid_substituted_for_npub"
    ]
  },
  "assurance/export-incomplete": {
    "boundary_id": "assurance-policy.evaluateAssuranceExport",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-keri-export"
    ],
    "invariants": [
      "ASSURANCE-I-EXPORT-LOSSLESS"
    ],
    "reason_codes": [
      "export_incomplete"
    ]
  },
  "assurance/export-lossless": {
    "boundary_id": "assurance-policy.evaluateAssuranceExport",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-keri-export"
    ],
    "invariants": [
      "ASSURANCE-I-EXPORT-LOSSLESS"
    ],
    "reason_codes": []
  },
  "assurance/export-unmappable-feature": {
    "boundary_id": "assurance-policy.evaluateAssuranceExport",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-keri-export"
    ],
    "invariants": [
      "ASSURANCE-I-EXPORT-LOSSLESS"
    ],
    "reason_codes": [
      "export_unmappable_feature"
    ]
  },
  "assurance/export-unsupported-suite": {
    "boundary_id": "assurance-policy.evaluateAssuranceExport",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-keri-export"
    ],
    "invariants": [
      "ASSURANCE-I-EXPORT-LOSSLESS"
    ],
    "reason_codes": [
      "export_unsupported_crypto_suite"
    ]
  },
  "assurance/keri-wire-format-rejected": {
    "boundary_id": "assurance-policy.validateAssuranceWireFormat",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-keri-export"
    ],
    "invariants": [
      "ASSURANCE-I-EXPORT-LOSSLESS"
    ],
    "reason_codes": [
      "keri_wire_format_rejected"
    ]
  },
  "assurance/persona-author-mismatch": {
    "boundary_id": "core-policy.validateCorePersonaSignedEvent",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-scope"
    ],
    "invariants": [
      "ASSURANCE-I-CORE-OPTIONALITY"
    ],
    "reason_codes": [
      "delegation_mismatch"
    ]
  },
  "assurance/pin-conflict-rejected": {
    "boundary_id": "assurance-policy.evaluateAssurancePinPolicy",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-pinning"
    ],
    "invariants": [
      "ASSURANCE-I-PIN-DOWNGRADE"
    ],
    "reason_codes": [
      "assurance-pin-conflict"
    ]
  },
  "assurance/profile-heterodyne-assurance-active-key-acceptance-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-active-key-acceptance-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-security"
    ],
    "invariants": [
      "ASSURANCE-I-RECIPROCAL-ENROLLMENT"
    ],
    "reason_codes": []
  },
  "assurance/profile-heterodyne-assurance-associated-key-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-associated-key-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-security"
    ],
    "invariants": [
      "ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"
    ],
    "reason_codes": []
  },
  "assurance/profile-heterodyne-assurance-enrollment-contest-profile-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-enrollment-contest-profile-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-security"
    ],
    "invariants": [
      "ASSURANCE-I-ENROLLMENT-WINDOWED"
    ],
    "reason_codes": []
  },
  "assurance/profile-heterodyne-assurance-enrollment-inception-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-enrollment-inception-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-security"
    ],
    "invariants": [
      "ASSURANCE-I-RECIPROCAL-ENROLLMENT"
    ],
    "reason_codes": []
  },
  "assurance/profile-heterodyne-assurance-succession-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-succession-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-security"
    ],
    "invariants": [
      "ASSURANCE-I-TRANSITION-PROOF-BINDING"
    ],
    "reason_codes": []
  },
  "assurance/reciprocal-proof-invalid": {
    "boundary_id": "assurance.evaluateEnrollment",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-reciprocal-enrollment"
    ],
    "invariants": [
      "ASSURANCE-I-RECIPROCAL-ENROLLMENT"
    ],
    "reason_codes": [
      "assurance-reciprocal-proof-invalid"
    ]
  },
  "assurance/retired-key-post-compromise": {
    "boundary_id": "follow-up-hardening.classifyRetiredKeyObservation",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-retired-wire-profiles"
    ],
    "invariants": [
      "ASSURANCE-I-COMPROMISE-CUTOFF"
    ],
    "reason_codes": [
      "revoked_key_post_compromise"
    ]
  },
  "assurance/succession-authority-invalid": {
    "boundary_id": "assurance.evaluateSuccession",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-succession"
    ],
    "invariants": [
      "ASSURANCE-I-TRANSITION-PROOF-BINDING"
    ],
    "reason_codes": [
      "assurance-authority-invalid"
    ]
  },
  "assurance/succession-head-mismatch": {
    "boundary_id": "assurance.evaluateSuccession",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-chain-validation"
    ],
    "invariants": [
      "ASSURANCE-I-TRANSITION-PROOF-BINDING"
    ],
    "reason_codes": [
      "assurance-head-mismatch"
    ]
  },
  "assurance/succession-new-key-acceptance-invalid": {
    "boundary_id": "assurance.evaluateSuccession",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-succession"
    ],
    "invariants": [
      "ASSURANCE-I-TRANSITION-PROOF-BINDING"
    ],
    "reason_codes": [
      "assurance-new-key-acceptance-invalid"
    ]
  },
  "assurance/succession-predecessor-mismatch": {
    "boundary_id": "assurance.evaluateSuccession",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-chain-validation"
    ],
    "invariants": [
      "ASSURANCE-I-TRANSITION-PROOF-BINDING"
    ],
    "reason_codes": [
      "assurance-predecessor-mismatch"
    ]
  },
  "assurance/succession-schema-invalid": {
    "boundary_id": "assurance.evaluateSuccession",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-succession-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-record-envelope"
    ],
    "invariants": [
      "ASSURANCE-I-TRANSITION-PROOF-BINDING"
    ],
    "reason_codes": [
      "assurance-schema-invalid"
    ]
  },
  "assurance/succession-valid": {
    "boundary_id": "assurance.evaluateSuccession",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-succession-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-succession"
    ],
    "invariants": [
      "ASSURANCE-I-NO-IMPLICIT-CONTINUATION",
      "ASSURANCE-I-SUCCESSION-NON-ALIASING",
      "ASSURANCE-I-TRANSITION-PROOF-BINDING"
    ],
    "reason_codes": []
  },
  "assurance/succession-witness-threshold-unsatisfied": {
    "boundary_id": "assurance.evaluateSuccession",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-keri-policy"
    ],
    "invariants": [
      "ASSURANCE-I-TRANSITION-PROOF-BINDING"
    ],
    "reason_codes": [
      "assurance-witness-threshold-unsatisfied"
    ]
  },
  "assurance/dual-consent-downgrade-accepted": {
    "boundary_id": "assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade",
    "owner_document": "assurance",
    "profile": "heterodyne-assurance-active-key-acceptance-v1",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-downgrade-resistance"
    ],
    "invariants": [
      "ASSURANCE-I-PIN-DOWNGRADE"
    ],
    "reason_codes": []
  },
  "assurance/unilateral-downgrade-rejected": {
    "boundary_id": "assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-downgrade-resistance"
    ],
    "invariants": [
      "ASSURANCE-I-PIN-DOWNGRADE"
    ],
    "reason_codes": [
      "assurance-downgrade-consent-required"
    ]
  },
  "assurance/witness-threshold-fail": {
    "boundary_id": "assurance-observation.evaluateEnrollmentEligibility",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-enrollment-window"
    ],
    "invariants": [
      "ASSURANCE-I-ENROLLMENT-WINDOWED"
    ],
    "reason_codes": [
      "assurance-enrollment-pending-window"
    ]
  },
  "assurance/witness-threshold-pass": {
    "boundary_id": "assurance-observation.evaluateEnrollmentEligibility",
    "owner_document": "assurance",
    "spec_refs": [
      "heterodyne:0.6.0#assurance-enrollment-window"
    ],
    "invariants": [
      "ASSURANCE-I-ENROLLMENT-WINDOWED"
    ],
    "reason_codes": []
  },
  "comms/agent-attribution-encrypted-inner": {
    "boundary_id": "agent-authorship.injectAgentAttribution",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-attribution"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-AGENT-SIGNER-BINDING"
    ],
    "reason_codes": []
  },
  "comms/agent-attribution-invalid": {
    "boundary_id": "agent-authorship.injectAgentAttribution",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-authorship"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION"
    ],
    "reason_codes": [
      "agent-attribution-invalid"
    ]
  },
  "comms/agent-attribution-profile-unavailable": {
    "boundary_id": "agent-authorship.injectAgentAttribution",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-authorship"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION"
    ],
    "reason_codes": [
      "agent-attribution-profile-unavailable"
    ]
  },
  "comms/agent-persona-scope-required": {
    "boundary_id": "agent-authorship.injectAgentAttribution",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-authorship"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION"
    ],
    "reason_codes": [
      "agent-persona-scope-required"
    ]
  },
  "comms/agent-sender-proof-invalid": {
    "boundary_id": "agent-authorship.validateAgentAccessToken",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-authorship"
    ],
    "invariants": [
      "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"
    ],
    "reason_codes": [
      "agent-sender-proof-invalid"
    ]
  },
  "comms/agent-signer-mismatch": {
    "boundary_id": "agent-authorship.validateAgentAccessToken",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-authorship"
    ],
    "invariants": [
      "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"
    ],
    "reason_codes": [
      "agent-signer-mismatch"
    ]
  },
  "comms/agent-token-invalid": {
    "boundary_id": "agent-authorship.validateAgentAccessToken",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-authorship"
    ],
    "invariants": [
      "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"
    ],
    "reason_codes": [
      "agent-token-invalid"
    ]
  },
  "comms/agent-workload-registration-invalid": {
    "boundary_id": "agent-authorship.validateWorkloadRegistration",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-authorship"
    ],
    "invariants": [
      "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"
    ],
    "reason_codes": [
      "agent-workload-registration-invalid"
    ]
  },
  "comms/agent-workload-token-accepted": {
    "boundary_id": "agent-authorship.validateWorkloadRegistration+validateAgentAccessToken",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-fail-closed"
    ],
    "invariants": [
      "COMMS-I-AGENT-SIGNER-BINDING",
      "COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"
    ],
    "reason_codes": []
  },
  "comms/auth-rejected-permanent": {
    "boundary_id": "comms-policy.classifyRelayWriteFailure",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-publishing"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "auth_rejected_permanent"
    ]
  },
  "comms/authorization-view-300-boundary": {
    "boundary_id": "authorization-freshness.evaluateAuthorizationFreshness",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-authorization-freshness"
    ],
    "invariants": [
      "COMMS-I-MINT-FRESHNESS"
    ],
    "reason_codes": []
  },
  "comms/authorization-view-86400-boundary": {
    "boundary_id": "authorization-freshness.evaluateAuthorizationFreshness",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-authorization-freshness"
    ],
    "invariants": [
      "COMMS-I-MINT-FRESHNESS"
    ],
    "reason_codes": []
  },
  "comms/authorization-view-maximum-malformed": {
    "boundary_id": "schema.validateOidcContinuityManifestSchemaOrThrow",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-authorization-freshness"
    ],
    "invariants": [
      "COMMS-I-MINT-FRESHNESS"
    ],
    "reason_codes": [
      "claim-schema-invalid"
    ]
  },
  "comms/checkpoint-exact-boundary": {
    "boundary_id": "authorization-freshness.evaluateAuthorizationFreshness",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-authorization-freshness"
    ],
    "invariants": [
      "COMMS-I-MINT-FRESHNESS"
    ],
    "reason_codes": []
  },
  "comms/checkpoint-stale-independent": {
    "boundary_id": "authorization-freshness.evaluateAuthorizationFreshness",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-authorization-freshness"
    ],
    "invariants": [
      "COMMS-I-MINT-FRESHNESS"
    ],
    "reason_codes": [
      "oidc-checkpoint-stale"
    ]
  },
  "comms/claim-active-authenticated": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-claim-verification"
    ],
    "invariants": [
      "COMMS-I-CLAIM-ATTENUATION",
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": []
  },
  "comms/claim-attenuation-violation": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-ATTENUATION"
    ],
    "reason_codes": [
      "claim-attenuation-violation"
    ]
  },
  "comms/claim-chain-cycle": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-ATTENUATION"
    ],
    "reason_codes": [
      "claim-chain-cycle"
    ]
  },
  "comms/claim-chain-depth-exceeded": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-ATTENUATION"
    ],
    "reason_codes": [
      "claim-chain-depth-exceeded"
    ]
  },
  "comms/claim-delegation-not-authorized": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-ATTENUATION"
    ],
    "reason_codes": [
      "claim-delegation-not-authorized"
    ]
  },
  "comms/claim-event-signature-invalid": {
    "boundary_id": "claims.validateClaimEnvelope",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": [
      "claim-event-signature-invalid"
    ]
  },
  "comms/claim-expired": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": [
      "claim-expired"
    ]
  },
  "comms/claim-id-mismatch": {
    "boundary_id": "claims.validateClaimId",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": [
      "claim-id-mismatch"
    ]
  },
  "comms/claim-issuer-authority-invalid": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": [
      "claim-issuer-authority-invalid"
    ]
  },
  "comms/claim-issuer-untrusted": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": [
      "claim-issuer-untrusted"
    ]
  },
  "comms/claim-key-reference-invalid": {
    "boundary_id": "claims.validateKeyRef",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": [
      "claim-key-reference-invalid"
    ]
  },
  "comms/claim-ledger-rollback": {
    "boundary_id": "claim-ledger.mergeClaimLedger",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-REPOSITORY-AUTHORITY"
    ],
    "reason_codes": [
      "claim-ledger-rollback"
    ]
  },
  "comms/claim-repository-conflict": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-REPOSITORY-AUTHORITY"
    ],
    "reason_codes": [
      "claim-repository-conflict"
    ]
  },
  "comms/claim-repository-unconfirmed": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-claim-ledger"
    ],
    "invariants": [
      "COMMS-I-CLAIM-REPOSITORY-AUTHORITY"
    ],
    "reason_codes": [
      "claim-repository-unconfirmed"
    ]
  },
  "comms/claim-revoked": {
    "boundary_id": "claims.validateClaimRevocationEnvelope+authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-REVOCATION"
    ],
    "reason_codes": [
      "claim-revoked"
    ]
  },
  "comms/claim-revoker-unauthorized": {
    "boundary_id": "claim-ledger.validateLedgerRecordOrThrow",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-REVOCATION"
    ],
    "reason_codes": [
      "claim-revoker-unauthorized"
    ]
  },
  "comms/claim-subject-proof-invalid": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": [
      "claim-subject-proof-invalid"
    ]
  },
  "comms/claim-subject-proof-required": {
    "boundary_id": "claims.authorizeWithClaim",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": [
      "claim-subject-proof-required"
    ]
  },
  "comms/config-private-state-encrypted": {
    "boundary_id": "privacy-crypto.deriveConfigPostKey+nostr-tools.nip44",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-config-repository"
    ],
    "invariants": [
      "COMMS-I-CONFIG-AT-REST",
      "COMMS-I-TIER2-HONESTY"
    ],
    "reason_codes": []
  },
  "comms/conversation-rejected": {
    "boundary_id": "marmot-admission.ordinaryConversationAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-ordinary-conversation-admission"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "conversation-rejected"
    ]
  },
  "comms/dm-invite-revoked-device": {
    "boundary_id": "comms-policy.validateDmInviteDevice",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-direct-messages"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "dm_invite_revoked_device"
    ]
  },
  "comms/dm-invite-unbound-device": {
    "boundary_id": "comms-policy.validateDmInviteDevice",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-direct-messages"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "dm_invite_unbound_device"
    ]
  },
  "comms/invite-already-reserved": {
    "boundary_id": "comms-policy.evaluateOneTimeInvite",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-one-time-invites"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "invite-already-reserved"
    ]
  },
  "comms/invite-authentication-invalid": {
    "boundary_id": "comms-policy.evaluateOneTimeInvite",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-one-time-invites"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "invite-authentication-invalid"
    ]
  },
  "comms/invite-expired": {
    "boundary_id": "comms-policy.evaluateOneTimeInvite",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-one-time-invites"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "invite-expired"
    ]
  },
  "comms/invite-purpose-mismatch": {
    "boundary_id": "comms-policy.evaluateOneTimeInvite",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-one-time-invites"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "invite-purpose-mismatch"
    ]
  },
  "comms/ledger-reader-authorized": {
    "boundary_id": "claim-ledger.mergeClaimLedger+evaluateReaderAccess",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-claim-ledger"
    ],
    "invariants": [
      "COMMS-I-CLAIM-REVOCATION",
      "COMMS-I-LEDGER-CONFINEMENT"
    ],
    "reason_codes": []
  },
  "comms/ledger-reader-unauthorized": {
    "boundary_id": "claim-ledger.evaluateReaderAccess",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-claim-ledger"
    ],
    "invariants": [
      "COMMS-I-LEDGER-CONFINEMENT"
    ],
    "reason_codes": [
      "claim-ledger-reader-unauthorized"
    ]
  },
  "comms/marmot-agent-scope-denied": {
    "boundary_id": "comms-policy.evaluateMarmotInboxBootstrap",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-agent-authorship"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "marmot-agent-scope-denied"
    ]
  },
  "comms/marmot-exact-bytes-durable": {
    "boundary_id": "marmot-routing-policy.evaluateMarmotDurability",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-exact-bytes"
    ],
    "invariants": [
      "COMMS-I-MARMOT-EXACT-BYTES"
    ],
    "reason_codes": []
  },
  "comms/marmot-expiration-not-erasure": {
    "boundary_id": "marmot-routing-policy.evaluateMarmotRetention",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-retention"
    ],
    "invariants": [
      "COMMS-I-RADICLE-NON-ERASURE"
    ],
    "reason_codes": []
  },
  "comms/marmot-keypackage-replayed": {
    "boundary_id": "comms-policy.evaluateMarmotInboxBootstrap",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-persona-inbox"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "marmot-keypackage-replayed"
    ]
  },
  "comms/marmot-ordinary-welcome-held": {
    "boundary_id": "marmot-admission.ordinaryConversationAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-ordinary-conversation-admission"
    ],
    "invariants": [
      "COMMS-I-MARMOT-ACCOUNT-IDENTITY",
      "COMMS-I-MARMOT-SECRET-CONFINEMENT",
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": []
  },
  "comms/marmot-premature-ack": {
    "boundary_id": "marmot-routing-policy.evaluateMarmotDurability",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-rotation"
    ],
    "invariants": [
      "COMMS-I-MARMOT-EXACT-BYTES"
    ],
    "reason_codes": [
      "marmot-premature-ack"
    ]
  },
  "comms/marmot-private-inbox-nid-required": {
    "boundary_id": "comms-policy.evaluateMarmotInboxBootstrap",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-persona-inbox"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "marmot-private-inbox-nid-required"
    ]
  },
  "comms/marmot-private-route-required": {
    "boundary_id": "current-private-route.evaluateCurrentTier3PrivateRoute",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-groups"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "marmot-private-route-required"
    ]
  },
  "comms/marmot-routing-binding-valid": {
    "boundary_id": "marmot-routing-policy.evaluateMarmotRoutingBinding",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-routing-generation"
    ],
    "invariants": [
      "COMMS-I-RADICLE-ROUTING-AUTHORITY"
    ],
    "reason_codes": []
  },
  "comms/marmot-routing-equivocation": {
    "boundary_id": "marmot-routing-policy.evaluateMarmotRoutingBinding",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-host-authority"
    ],
    "invariants": [
      "COMMS-I-RADICLE-ROUTING-AUTHORITY"
    ],
    "reason_codes": [
      "marmot-routing-equivocation"
    ]
  },
  "comms/marmot-routing-genesis-mismatch": {
    "boundary_id": "marmot-routing-policy.evaluateMarmotRoutingBinding",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-routing-generation"
    ],
    "invariants": [
      "COMMS-I-RADICLE-ROUTING-AUTHORITY"
    ],
    "reason_codes": [
      "marmot-routing-binding-invalid"
    ]
  },
  "comms/marmot-unauthorized-ref": {
    "boundary_id": "marmot-routing-policy.evaluateMarmotRoutingBinding",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-marmot-event-repository"
    ],
    "invariants": [
      "COMMS-I-RADICLE-ROUTING-AUTHORITY"
    ],
    "reason_codes": [
      "marmot-unauthorized-ref"
    ]
  },
  "comms/nip59-broadcast-rejected": {
    "boundary_id": "comms-policy.validatePrivateBroadcast",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-tier-three-profile"
    ],
    "invariants": [
      "COMMS-I-MARMOT-UPSTREAM-AUTHORITY"
    ],
    "reason_codes": [
      "nip59_broadcast_rejected"
    ]
  },
  "comms/oidc-access-token-validated": {
    "boundary_id": "oidc.projectAccessToken+validateProjectedJwt",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-jwt-projection"
    ],
    "invariants": [
      "COMMS-I-JWT-TYPE-AUDIENCE",
      "COMMS-I-STATUS-INTEGRITY"
    ],
    "reason_codes": []
  },
  "comms/oidc-audience-invalid": {
    "boundary_id": "oidc.validateProjectedJwt",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-jwt-projection"
    ],
    "invariants": [
      "COMMS-I-JWT-TYPE-AUDIENCE"
    ],
    "reason_codes": [
      "oidc-audience-invalid"
    ]
  },
  "comms/oidc-claim-release": {
    "boundary_id": "oidc.validateAuthorizationRequest",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-oidc-authorization"
    ],
    "invariants": [
      "COMMS-I-CLAIM-RELEASE",
      "COMMS-I-ISSUER-KEY-CONFINEMENT"
    ],
    "reason_codes": []
  },
  "comms/oidc-claim-release-denied": {
    "boundary_id": "oidc.validateAuthorizationRequest",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-oidc-authorization"
    ],
    "invariants": [
      "COMMS-I-CLAIM-RELEASE"
    ],
    "reason_codes": [
      "oidc-claim-release-denied"
    ]
  },
  "comms/oidc-client-unregistered": {
    "boundary_id": "oidc.validateAuthorizationRequest",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-oidc-authorization"
    ],
    "invariants": [
      "COMMS-I-CLAIM-RELEASE"
    ],
    "reason_codes": [
      "oidc-client-unregistered"
    ]
  },
  "comms/oidc-consent-required": {
    "boundary_id": "oidc.validateAuthorizationRequest",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-oidc-authorization"
    ],
    "invariants": [
      "COMMS-I-CLAIM-RELEASE"
    ],
    "reason_codes": [
      "oidc-consent-required"
    ]
  },
  "comms/oidc-grant-prohibited": {
    "boundary_id": "oidc.validateAuthorizationRequest",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-oidc-authorization"
    ],
    "invariants": [
      "COMMS-I-CLAIM-RELEASE"
    ],
    "reason_codes": [
      "oidc-grant-prohibited"
    ]
  },
  "comms/oidc-issuer-authority-invalid": {
    "boundary_id": "claim-ledger.canMint",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-ISSUER-KEY-CONFINEMENT"
    ],
    "reason_codes": [
      "oidc-issuer-authority-invalid"
    ]
  },
  "comms/oidc-issuer-mismatch": {
    "boundary_id": "oidc.validateIssuerMetadata",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-issuer-continuity"
    ],
    "invariants": [
      "COMMS-I-ISSUER-CONTINUITY"
    ],
    "reason_codes": [
      "oidc-issuer-mismatch"
    ]
  },
  "comms/oidc-issuer-persona-continuity": {
    "boundary_id": "oidc.validateIssuerMetadata",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-issuer-continuity"
    ],
    "invariants": [
      "COMMS-I-ISSUER-CONTINUITY"
    ],
    "reason_codes": []
  },
  "comms/oidc-signing-key-unavailable": {
    "boundary_id": "claim-ledger.canMint",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-ISSUER-KEY-CONFINEMENT"
    ],
    "reason_codes": [
      "oidc-signing-key-unavailable"
    ]
  },
  "comms/oidc-status-invalid": {
    "boundary_id": "token-status.encodeStatusList",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-conformance"
    ],
    "invariants": [
      "COMMS-I-STATUS-INTEGRITY"
    ],
    "reason_codes": [
      "oidc-status-invalid"
    ]
  },
  "comms/oidc-token-type-invalid": {
    "boundary_id": "oidc.validateProjectedJwt",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-jwt-projection"
    ],
    "invariants": [
      "COMMS-I-JWT-TYPE-AUDIENCE"
    ],
    "reason_codes": [
      "oidc-token-type-invalid"
    ]
  },
  "comms/profile-heterodyne-comms-agent-attribution-kind-1-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-agent-attribution-kind-1-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-AGENT-SIGNER-BINDING"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-agent-attribution-kind-1063-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-agent-attribution-kind-1063-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-AGENT-SIGNER-BINDING"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-agent-attribution-kind-16-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-agent-attribution-kind-16-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-AGENT-SIGNER-BINDING"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-agent-attribution-kind-1985-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-agent-attribution-kind-1985-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-AGENT-SIGNER-BINDING"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-agent-attribution-kind-30023-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-agent-attribution-kind-30023-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-AGENT-SIGNER-BINDING"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-agent-attribution-kind-4550-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-agent-attribution-kind-4550-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-AGENT-SIGNER-BINDING"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-agent-attribution-kind-6-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-agent-attribution-kind-6-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-AGENT-SIGNER-BINDING"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-agent-attribution-kind-7-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-agent-attribution-kind-7-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-AGENT-ATTRIBUTION",
      "COMMS-I-AGENT-SIGNER-BINDING"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-claim-revocation-jwk-jws-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-claim-revocation-jwk-jws-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-CLAIM-REVOCATION"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-claim-revocation-nostr-bip340-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-claim-revocation-nostr-bip340-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-CLAIM-REVOCATION"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-claim-revocation-radicle-ed25519-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-claim-revocation-radicle-ed25519-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-CLAIM-REVOCATION"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-key-claim-jwk-jws-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-key-claim-jwk-jws-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-key-claim-nostr-bip340-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-key-claim-nostr-bip340-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-key-claim-radicle-ed25519-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-key-claim-radicle-ed25519-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-CLAIM-AUTHENTICITY"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-tier3-wrapped-content-kind-1-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-TIER3-BLIND-CARRIER",
      "COMMS-I-TIER3-CONFINED"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1063-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-tier3-wrapped-content-kind-1063-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-TIER3-BLIND-CARRIER",
      "COMMS-I-TIER3-CONFINED"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-16-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-tier3-wrapped-content-kind-16-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-TIER3-BLIND-CARRIER",
      "COMMS-I-TIER3-CONFINED"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-30023-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-tier3-wrapped-content-kind-30023-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-TIER3-BLIND-CARRIER",
      "COMMS-I-TIER3-CONFINED"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-30402-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-tier3-wrapped-content-kind-30402-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-TIER3-BLIND-CARRIER",
      "COMMS-I-TIER3-CONFINED"
    ],
    "reason_codes": []
  },
  "comms/profile-heterodyne-comms-tier3-wrapped-content-kind-6-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "comms",
    "profile": "heterodyne-comms-tier3-wrapped-content-kind-6-v1",
    "spec_refs": [
      "heterodyne:0.6.0#comms-security"
    ],
    "invariants": [
      "COMMS-I-TIER3-BLIND-CARRIER",
      "COMMS-I-TIER3-CONFINED"
    ],
    "reason_codes": []
  },
  "comms/public-reader-private-content": {
    "boundary_id": "comms-policy.validatePublicReaderRendering",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-public-reader"
    ],
    "invariants": [
      "COMMS-I-PUBLIC-READER-TIER1-ONLY"
    ],
    "reason_codes": [
      "public-reader-private-content"
    ]
  },
  "comms/public-reader-private-tier": {
    "boundary_id": "public-reader.resolvePublicAsset",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-public-reader"
    ],
    "invariants": [
      "COMMS-I-PUBLIC-READER-TIER1-ONLY"
    ],
    "reason_codes": []
  },
  "comms/public-reader-relay-hint-invalid": {
    "boundary_id": "public-reader.validateBootstrapRelay",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-public-reader-security"
    ],
    "invariants": [
      "COMMS-I-PUBLIC-READER-TIER1-ONLY"
    ],
    "reason_codes": [
      "public-reader-relay-hint-invalid"
    ]
  },
  "comms/public-reader-route-invalid": {
    "boundary_id": "public-reader.parseLauncherFragment",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-public-launcher"
    ],
    "invariants": [
      "COMMS-I-PUBLIC-READER-TIER1-ONLY"
    ],
    "reason_codes": [
      "public-reader-route-invalid"
    ]
  },
  "comms/tier3-client-side-encryption": {
    "boundary_id": "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-tier-three-profile"
    ],
    "invariants": [
      "COMMS-I-CLIENT-SIDE-DELIVERY",
      "COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY",
      "COMMS-I-TIER3-BLIND-CARRIER"
    ],
    "reason_codes": []
  },
  "comms/tier3-recipient-confined": {
    "boundary_id": "follow-up-hardening.resolveTier3Recipients",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-tier3-confinement"
    ],
    "invariants": [
      "COMMS-I-TIER3-CONFINED"
    ],
    "reason_codes": [
      "tier3-recipient-not-active-device"
    ]
  },
  "comms/trusted-seed-acl-ambiguous": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-acl-ambiguous"
    ]
  },
  "comms/trusted-seed-acl-conflict": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-acl-conflict"
    ]
  },
  "comms/trusted-seed-acl-expired": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-acl-expired"
    ]
  },
  "comms/trusted-seed-acl-invalid": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-acl-invalid"
    ]
  },
  "comms/trusted-seed-acl-missing": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-acl-missing"
    ]
  },
  "comms/trusted-seed-acl-stale": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-acl-stale"
    ]
  },
  "comms/trusted-seed-event-invalid": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-event-invalid"
    ]
  },
  "comms/trusted-seed-exact-write": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-MARMOT-EXACT-BYTES",
      "COMMS-I-PRIVATE-RELAY-ACL",
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": []
  },
  "comms/trusted-seed-nip42-required": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-nip42-required"
    ]
  },
  "comms/trusted-seed-request-invalid": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-request-invalid"
    ]
  },
  "comms/trusted-seed-request-replay": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-request-replay"
    ]
  },
  "comms/trusted-seed-revoked": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-revoked"
    ]
  },
  "comms/trusted-seed-route-mismatch": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-route-mismatch"
    ]
  },
  "comms/trusted-seed-unauthorized": {
    "boundary_id": "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission",
    "owner_document": "comms",
    "spec_refs": [
      "heterodyne:0.6.0#comms-trusted-seed-private-relay"
    ],
    "invariants": [
      "COMMS-I-TRUSTED-SEED-CONFINEMENT"
    ],
    "reason_codes": [
      "trusted-seed-unauthorized"
    ]
  },
  "control/activation-binding-mismatch": {
    "boundary_id": "control-signing.consumeNip46ConnectionSecret",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-oidc-activation"
    ],
    "invariants": [
      "CONTROL-I-NIP46-OIDC-ACTIVATION"
    ],
    "reason_codes": [
      "control-activation-binding-mismatch"
    ]
  },
  "control/agent-attribution-bypass-prohibited": {
    "boundary_id": "control-policy.evaluateAutomatedControlGrant",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"
    ],
    "reason_codes": [
      "agent-attribution-bypass-prohibited"
    ]
  },
  "control/agent-human-profile-prohibited": {
    "boundary_id": "control-policy.evaluateAutomatedControlGrant",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"
    ],
    "reason_codes": [
      "agent-human-profile-prohibited"
    ]
  },
  "control/agent-intent-invalid": {
    "boundary_id": "control-signing.prepareAutomatedSigning",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"
    ],
    "reason_codes": [
      "control-agent-intent-invalid"
    ]
  },
  "control/agent-key-access-prohibited": {
    "boundary_id": "control-policy.evaluateAutomatedControlGrant",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"
    ],
    "reason_codes": [
      "agent-key-access-prohibited"
    ]
  },
  "control/agent-method-prohibited": {
    "boundary_id": "control-policy.evaluateAutomatedControlGrant",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"
    ],
    "reason_codes": [
      "agent-method-prohibited"
    ]
  },
  "control/agent-rate-limited": {
    "boundary_id": "control-policy.evaluateAutomatedControlGrant",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "agent-rate-limited"
    ]
  },
  "control/agent-resource-denied": {
    "boundary_id": "control-policy.evaluateAutomatedControlGrant",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-EXACT-SIGNER-GRANT"
    ],
    "reason_codes": [
      "agent-resource-denied"
    ]
  },
  "control/agent-size-exceeded": {
    "boundary_id": "control-policy.evaluateAutomatedControlGrant",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-EXACT-SIGNER-GRANT"
    ],
    "reason_codes": [
      "agent-size-exceeded"
    ]
  },
  "control/attribution-binding-mismatch": {
    "boundary_id": "control-signing.prepareAutomatedSigning",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"
    ],
    "reason_codes": [
      "control-attribution-binding-mismatch"
    ]
  },
  "control/attribution-required": {
    "boundary_id": "control-signing.prepareAutomatedSigning",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"
    ],
    "reason_codes": [
      "control-attribution-required"
    ]
  },
  "control/authorization-view-stale-at-effect": {
    "boundary_id": "authorization-freshness.revalidateAuthorizationViewAtEffect",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-token"
    ],
    "invariants": [
      "CONTROL-I-NIP46-OIDC-ACTIVATION"
    ],
    "reason_codes": [
      "control-authorization-view-stale"
    ]
  },
  "control/automation-attributed-before-signing": {
    "boundary_id": "control-signing.prepareAutomatedSigning",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING",
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": []
  },
  "control/caller-freshness-booleans-rejected": {
    "boundary_id": "authorization-freshness.evaluateAuthorizationFreshness",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-token"
    ],
    "invariants": [
      "CONTROL-I-NIP46-OIDC-ACTIVATION"
    ],
    "reason_codes": [
      "control-authorization-view-stale"
    ]
  },
  "control/client-metadata-widening": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-nip46-signing"
    ],
    "invariants": [
      "CONTROL-I-CLIENT-KEY-CONFINEMENT"
    ],
    "reason_codes": [
      "control-client-metadata-widening"
    ]
  },
  "control/compromise-reset-closure-required": {
    "boundary_id": "control-signing.validateCompromiseReset",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-compromise-reset"
    ],
    "invariants": [
      "CONTROL-I-COMPROMISE-RESET",
      "CONTROL-I-MARMOT-LEAF-COMPROMISE"
    ],
    "reason_codes": [
      "control-compromise-reset-incomplete"
    ]
  },
  "control/compromise-reset-evidence-invalid": {
    "boundary_id": "control-policy.evaluateCompromiseResetBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-compromise-reset"
    ],
    "invariants": [
      "CONTROL-I-COMPROMISE-RESET"
    ],
    "reason_codes": [
      "control-compromise-reset-evidence-invalid"
    ]
  },
  "control/compromise-reset-inventory-mismatch": {
    "boundary_id": "control-policy.evaluateCompromiseResetBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-compromise-reset"
    ],
    "invariants": [
      "CONTROL-I-COMPROMISE-RESET"
    ],
    "reason_codes": [
      "control-compromise-reset-inventory-mismatch"
    ]
  },
  "control/compromise-reset-unauthenticated": {
    "boundary_id": "control-policy.evaluateCompromiseResetBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-compromise-reset"
    ],
    "invariants": [
      "CONTROL-I-COMPROMISE-RESET"
    ],
    "reason_codes": [
      "control-compromise-reset-unauthenticated"
    ]
  },
  "control/connection-secret-invalid": {
    "boundary_id": "control-signing.consumeNip46ConnectionSecret",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-oidc-activation"
    ],
    "invariants": [
      "CONTROL-I-NIP46-OIDC-ACTIVATION"
    ],
    "reason_codes": [
      "control-connection-secret-invalid"
    ]
  },
  "control/connection-secret-reused": {
    "boundary_id": "control-signing.consumeNip46ConnectionSecret",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-oidc-activation"
    ],
    "invariants": [
      "CONTROL-I-NIP46-OIDC-ACTIVATION"
    ],
    "reason_codes": [
      "control-connection-secret-reused"
    ]
  },
  "control/device-code-display-mismatch": {
    "boundary_id": "control-policy.evaluateDeviceCodeBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-device-authorization"
    ],
    "invariants": [
      "CONTROL-I-NIP46-OIDC-ACTIVATION"
    ],
    "reason_codes": [
      "control-device-code-display-mismatch"
    ]
  },
  "control/device-code-invalid": {
    "boundary_id": "control-policy.evaluateDeviceCodeBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-device-authorization"
    ],
    "invariants": [
      "CONTROL-I-NIP46-OIDC-ACTIVATION"
    ],
    "reason_codes": [
      "control-device-code-invalid"
    ]
  },
  "control/device-code-rate-limited": {
    "boundary_id": "control-policy.evaluateDeviceCodeBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-device-authorization"
    ],
    "invariants": [
      "CONTROL-I-NIP46-OIDC-ACTIVATION"
    ],
    "reason_codes": [
      "control-device-code-rate-limited"
    ]
  },
  "control/enrollment-rate-limited": {
    "boundary_id": "control-policy.evaluateControlEnrollmentBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-invitation-policy"
    ],
    "invariants": [
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT"
    ],
    "reason_codes": [
      "control-enrollment-rate-limited"
    ]
  },
  "control/enrollment-required": {
    "boundary_id": "control-policy.evaluateControlEnrollmentBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-enrollment"
    ],
    "invariants": [
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT"
    ],
    "reason_codes": [
      "control-enrollment-required"
    ]
  },
  "control/enrollment-unavailable": {
    "boundary_id": "control-policy.evaluateControlEnrollmentBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-invitation-policy"
    ],
    "invariants": [
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT"
    ],
    "reason_codes": [
      "control-enrollment-unavailable"
    ]
  },
  "control/entitlement-conflict": {
    "boundary_id": "control-policy.evaluateControlEnrollmentBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-entitlement"
    ],
    "invariants": [
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT"
    ],
    "reason_codes": [
      "control-entitlement-conflict"
    ]
  },
  "control/exact-signer-grant-reserved": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-signer-grants"
    ],
    "invariants": [
      "CONTROL-I-AUDIT-AT-REST",
      "CONTROL-I-BASELINE-ACTIVE-KEY",
      "CONTROL-I-CLIENT-KEY-CONFINEMENT",
      "CONTROL-I-EXACT-SIGNER-GRANT",
      "CONTROL-I-NO-SIGNER-FALLBACK",
      "CONTROL-I-OPERATION-AT-MOST-ONCE",
      "CONTROL-I-PERSONA-VAULT-ISOLATION"
    ],
    "reason_codes": []
  },
  "control/frame-invalid": {
    "boundary_id": "control-policy.validateControlFrameBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-frame"
    ],
    "invariants": [
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT"
    ],
    "reason_codes": [
      "control-frame-invalid"
    ]
  },
  "control/invite-preauthorization-invalid": {
    "boundary_id": "control-policy.validateInvitePreauthorizationBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-one-time-invites"
    ],
    "invariants": [
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT"
    ],
    "reason_codes": [
      "invite-preauthorization-invalid"
    ]
  },
  "control/keypackage-invalid": {
    "boundary_id": "control-policy.evaluateControlEnrollmentBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-invitation-policy"
    ],
    "invariants": [
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT"
    ],
    "reason_codes": [
      "control-keypackage-invalid"
    ]
  },
  "control/keypackage-replenishment-paused": {
    "boundary_id": "control-policy.evaluateControlEnrollmentBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-invitation-policy"
    ],
    "invariants": [
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT"
    ],
    "reason_codes": [
      "control-keypackage-replenishment-paused"
    ]
  },
  "control/nip46-request-invalid": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-request-processing"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "control-nip46-request-invalid"
    ]
  },
  "control/opaque-authorization-view-accepted": {
    "boundary_id": "authorization-freshness.revalidateAuthorizationViewAtEffect",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-token"
    ],
    "invariants": [
      "CONTROL-I-NIP46-OIDC-ACTIVATION"
    ],
    "reason_codes": []
  },
  "control/operation-conflict": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-request-processing"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "control-operation-conflict"
    ]
  },
  "control/operation-execution-fence-required": {
    "boundary_id": "control-signing.executePersistedAutomatedSigning",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-request-processing"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "control-operation-execution-fence-required"
    ]
  },
  "control/operation-indeterminate": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-failover"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "control-operation-indeterminate"
    ]
  },
  "control/operation-reservation-required": {
    "boundary_id": "control-signing.prepareAutomatedSigning",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-request-processing"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "control-operation-reservation-required"
    ]
  },
  "control/persona-authority-required": {
    "boundary_id": "control-signing.prepareAutomatedSigning",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-signer-selection"
    ],
    "invariants": [
      "CONTROL-I-BASELINE-ACTIVE-KEY"
    ],
    "reason_codes": [
      "control-persona-authority-required"
    ]
  },
  "control/profile-heterodyne-control-marmot-frame-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "control",
    "profile": "heterodyne-control-marmot-frame-v1",
    "spec_refs": [
      "heterodyne:0.6.0#control-security"
    ],
    "invariants": [
      "CONTROL-I-MARMOT-GRANT-CONFINEMENT"
    ],
    "reason_codes": []
  },
  "control/refresh-prohibited": {
    "boundary_id": "control-policy.validateControlFrameBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-token"
    ],
    "invariants": [
      "CONTROL-I-CLIENT-KEY-CONFINEMENT"
    ],
    "reason_codes": [
      "control-refresh-prohibited"
    ]
  },
  "control/request-expired": {
    "boundary_id": "control-policy.evaluateControlOperationRequest",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-request-processing"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "control-request-expired"
    ]
  },
  "control/request-id-conflict": {
    "boundary_id": "control-policy.evaluateControlOperationRequest",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-request-processing"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "control-request-id-conflict"
    ]
  },
  "control/signed-event-invalid": {
    "boundary_id": "control-policy.validateControlSignedEffect",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"
    ],
    "reason_codes": [
      "control-signed-event-invalid"
    ]
  },
  "control/signer-binding-mismatch": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-signer-grants"
    ],
    "invariants": [
      "CONTROL-I-EXACT-SIGNER-GRANT"
    ],
    "reason_codes": [
      "control-signer-binding-mismatch"
    ]
  },
  "control/signer-effect-indeterminate": {
    "boundary_id": "control-policy.validateControlSignedEffect",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-agent-requirements"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [],
    "semantic_reason_codes": [
      "control-signer-effect-indeterminate"
    ]
  },
  "control/signer-unavailable": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-signer-selection"
    ],
    "invariants": [
      "CONTROL-I-NO-SIGNER-FALLBACK"
    ],
    "reason_codes": [
      "control-signer-unavailable"
    ]
  },
  "control/signing-grant-inactive": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-signer-grants"
    ],
    "invariants": [
      "CONTROL-I-EXACT-SIGNER-GRANT"
    ],
    "reason_codes": [
      "control-signing-grant-inactive"
    ]
  },
  "control/signing-grant-invalid": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-signer-grants"
    ],
    "invariants": [
      "CONTROL-I-EXACT-SIGNER-GRANT"
    ],
    "reason_codes": [
      "control-signing-grant-invalid"
    ]
  },
  "control/signing-grant-stale": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-signer-grants"
    ],
    "invariants": [
      "CONTROL-I-EXACT-SIGNER-GRANT"
    ],
    "reason_codes": [
      "control-signing-grant-stale"
    ]
  },
  "control/signing-grant-unauthenticated": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-signer-grants"
    ],
    "invariants": [
      "CONTROL-I-EXACT-SIGNER-GRANT"
    ],
    "reason_codes": [
      "control-signing-grant-unauthenticated"
    ]
  },
  "control/signing-rate-limited": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-request-processing"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "control-signing-rate-limited"
    ]
  },
  "control/subordinate-reauthorization-required": {
    "boundary_id": "control-policy.evaluateCompromiseResetBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-compromise-reset"
    ],
    "invariants": [
      "CONTROL-I-COMPROMISE-RESET"
    ],
    "reason_codes": [
      "control-subordinate-reauthorization-required"
    ]
  },
  "control/token-invalid": {
    "boundary_id": "control-policy.validateControlFrameBoundary",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-token"
    ],
    "invariants": [
      "CONTROL-I-CLIENT-KEY-CONFINEMENT"
    ],
    "reason_codes": [
      "control-token-invalid"
    ]
  },
  "control/usage-binding-mismatch": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-request-processing"
    ],
    "invariants": [
      "CONTROL-I-OPERATION-AT-MOST-ONCE"
    ],
    "reason_codes": [
      "control-usage-binding-mismatch"
    ]
  },
  "control/vault-isolation-failed": {
    "boundary_id": "control-signing.authorizeNip46Signing",
    "owner_document": "control",
    "spec_refs": [
      "heterodyne:0.6.0#control-persona-vaults"
    ],
    "invariants": [
      "CONTROL-I-PERSONA-VAULT-ISOLATION"
    ],
    "reason_codes": [
      "control-vault-isolation-failed"
    ]
  },
  "core/config-rid-published": {
    "boundary_id": "core-policy.evaluateCoreOperationalBoundary",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-conformance"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": [
      "config_rid_advertised"
    ]
  },
  "core/friend-cache-unsigned": {
    "boundary_id": "core-policy.evaluateCoreOperationalBoundary",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-conformance"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": [
      "unauthorized_cache_content"
    ]
  },
  "core/nip01-raw-mismatch": {
    "boundary_id": "core-policy.validateCoreWireEnvelope",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-verification"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": [
      "nip01_raw_mismatch"
    ]
  },
  "core/nip49-key-material-round-trip": {
    "boundary_id": "backup-crypto.nip49EncryptDeterministic+nostr-tools.nip49.decrypt",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-keys-repository"
    ],
    "invariants": [
      "CORE-I-KEY-MATERIAL-AT-REST"
    ],
    "reason_codes": []
  },
  "core/node-advert-bad-signature": {
    "boundary_id": "radicle.validateNodeAdvertisement",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-node-advertisement"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": [
      "bad_signature"
    ]
  },
  "core/node-advert-clock-skew": {
    "boundary_id": "follow-up-hardening.validateNodeAdvertisementTime",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-node-advertisement"
    ],
    "invariants": [
      "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"
    ],
    "reason_codes": [
      "node-advert-clock-skew"
    ]
  },
  "core/node-advert-clock-uncertain": {
    "boundary_id": "follow-up-hardening.validateNodeAdvertisementTime",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-node-advertisement"
    ],
    "invariants": [
      "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"
    ],
    "reason_codes": [
      "node-advert-clock-uncertain"
    ]
  },
  "core/node-advert-dual-proof-valid": {
    "boundary_id": "radicle.validateNodeAdvertisement",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-node-advertisement"
    ],
    "invariants": [
      "CORE-I-NID-DELEGATION-DUAL-PROOF",
      "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"
    ],
    "reason_codes": []
  },
  "core/node-advert-expired": {
    "boundary_id": "follow-up-hardening.validateNodeAdvertisementTime",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-node-advertisement"
    ],
    "invariants": [
      "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"
    ],
    "reason_codes": [
      "node_advert_expired"
    ]
  },
  "core/node-advert-expiry-invalid": {
    "boundary_id": "follow-up-hardening.validateNodeAdvertisementTime",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-node-advertisement"
    ],
    "invariants": [
      "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"
    ],
    "reason_codes": [
      "node-advert-expiry-invalid"
    ]
  },
  "core/node-advert-lifetime-exceeded": {
    "boundary_id": "follow-up-hardening.validateNodeAdvertisementTime",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-node-advertisement"
    ],
    "invariants": [
      "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"
    ],
    "reason_codes": [
      "node-advert-lifetime-exceeded"
    ]
  },
  "core/node-advert-nid-proof-invalid": {
    "boundary_id": "radicle.validateNodeAdvertisement",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-node-advertisement"
    ],
    "invariants": [
      "CORE-I-NID-DELEGATION-DUAL-PROOF"
    ],
    "reason_codes": [
      "nid_proof_invalid"
    ]
  },
  "core/onion-clearnet-resolution": {
    "boundary_id": "core-policy.evaluateCoreOperationalBoundary",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-conformance"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": [
      "onion_dns_leak"
    ]
  },
  "core/org-member-add-unauthorized": {
    "boundary_id": "core-policy.validateOrganizationMemberAddition",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-conformance"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": [
      "org_member_add_unauthorized"
    ]
  },
  "core/profile-heterodyne-core-rotation-breadcrumb-note-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "core",
    "profile": "heterodyne-core-rotation-breadcrumb-note-v1",
    "spec_refs": [
      "heterodyne:0.6.0#core-security"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": []
  },
  "core/profile-heterodyne-core-rotation-breadcrumb-profile-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "core",
    "profile": "heterodyne-core-rotation-breadcrumb-profile-v1",
    "spec_refs": [
      "heterodyne:0.6.0#core-security"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": []
  },
  "core/profile-nip05-key-mismatch": {
    "boundary_id": "follow-up-hardening.validateCanonicalProfile",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-persona-profile"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": [
      "profile-nip05-key-mismatch"
    ]
  },
  "core/profile-publisher-delegation-invalid": {
    "boundary_id": "follow-up-hardening.validateCanonicalProfile",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-persona-profile"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": [
      "profile-publisher-delegation-invalid"
    ]
  },
  "core/profile-repository-selection-required": {
    "boundary_id": "follow-up-hardening.validateCanonicalProfile",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-persona-profile"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": [
      "profile-repository-selection-required"
    ]
  },
  "core/relay-profile-mutated": {
    "boundary_id": "core-policy.evaluateCoreOperationalBoundary",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-conformance"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": [
      "relay_profile_mutation"
    ]
  },
  "core/replaceable-advisory-nip03-ignored": {
    "boundary_id": "replaceable-selection.selectCurrentReplaceableEvent",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-nip03-advisory"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": []
  },
  "core/replaceable-at-premature-boundary": {
    "boundary_id": "replaceable-selection.selectCurrentReplaceableEvent",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-created-at-bound"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": []
  },
  "core/replaceable-equal-time-lowest-id": {
    "boundary_id": "replaceable-selection.selectCurrentReplaceableEvent",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-source-neutral-selection"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": []
  },
  "core/replaceable-future-quarantined": {
    "boundary_id": "replaceable-selection.selectCurrentReplaceableEvent",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-created-at-bound"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": [
      "core-created-at-premature"
    ]
  },
  "core/retired-key-authority-window-invalid": {
    "boundary_id": "follow-up-hardening.classifyRetiredKeyObservation",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-retired-key-observation"
    ],
    "invariants": [
      "CORE-I-IDENTITY-INTEGRITY"
    ],
    "reason_codes": [
      "retired-key-authority-window-invalid"
    ]
  },
  "core/role-delegation-address-invalid": {
    "boundary_id": "core-policy.validateRoleDelegation",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-nid-delegation"
    ],
    "invariants": [
      "CORE-I-NID-DELEGATION-DUAL-PROOF"
    ],
    "reason_codes": [
      "role-delegation-address-invalid"
    ]
  },
  "core/role-delegation-key-proof-invalid": {
    "boundary_id": "core-policy.validateRoleDelegation",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-nid-delegation"
    ],
    "invariants": [
      "CORE-I-NID-DELEGATION-DUAL-PROOF"
    ],
    "reason_codes": [
      "role-delegation-key-proof-invalid"
    ]
  },
  "core/strict-mode-without-tor": {
    "boundary_id": "core-policy.evaluateCoreOperationalBoundary",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-conformance"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": [
      "strict_mode_tor_disabled"
    ]
  },
  "core/version-future-major": {
    "boundary_id": "core-policy.validateCoreWireEnvelope",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-conformance"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": [
      "unknown_major_version"
    ]
  },
  "core/version-stamp-missing": {
    "boundary_id": "core-policy.validateCoreWireEnvelope",
    "owner_document": "core",
    "spec_refs": [
      "heterodyne:0.6.0#core-verification"
    ],
    "invariants": [
      "CORE-I-VERIFY-BEFORE-USE"
    ],
    "reason_codes": [
      "version_stamp_invalid"
    ]
  },
  "social/agent-attribution-falsified": {
    "boundary_id": "social-policy.evaluateAgentModerationEvidence",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-agent-policy-receipts"
    ],
    "invariants": [
      "SOCIAL-I-AGENT-AUTHORSHIP-EXACT"
    ],
    "reason_codes": [
      "agent-attribution-falsified"
    ]
  },
  "social/agent-attribution-missing": {
    "boundary_id": "social-policy.evaluateAgentModerationEvidence",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-agent-policy-receipts"
    ],
    "invariants": [
      "SOCIAL-I-AGENT-AUTHORSHIP-EXACT"
    ],
    "reason_codes": [
      "agent-attribution-missing"
    ]
  },
  "social/agent-policy-binding-invalid": {
    "boundary_id": "agent-moderation.validateAgentPolicyList",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-agent-policy-list"
    ],
    "invariants": [
      "SOCIAL-I-AGENT-POLICY-LOCAL"
    ],
    "reason_codes": [
      "agent-policy-binding-invalid"
    ]
  },
  "social/agent-policy-receipt-invalid": {
    "boundary_id": "agent-moderation.validateAgentPolicyReceipt",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-agent-policy-receipts"
    ],
    "invariants": [
      "SOCIAL-I-AGENT-POLICY-LOCAL"
    ],
    "reason_codes": [
      "agent-policy-receipt-invalid"
    ]
  },
  "social/agent-publication-bypass": {
    "boundary_id": "social-policy.evaluateAgentModerationEvidence",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-agent-policy-receipts"
    ],
    "invariants": [
      "SOCIAL-I-AGENT-AUTHORSHIP-EXACT"
    ],
    "reason_codes": [
      "agent-publication-bypass"
    ]
  },
  "social/author-binding-invalid": {
    "boundary_id": "social-events.validateSocialAuthorship",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-interactions"
    ],
    "invariants": [
      "SOCIAL-I-NIP01-AUTHORSHIP"
    ],
    "reason_codes": [
      "social-author-binding-invalid"
    ]
  },
  "social/event-invalid": {
    "boundary_id": "social-events.validateSocialAuthorship",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-interactions"
    ],
    "invariants": [
      "SOCIAL-I-NIP01-AUTHORSHIP"
    ],
    "reason_codes": [
      "social-event-invalid"
    ]
  },
  "social/moderator-not-in-asof-declaration": {
    "boundary_id": "social-policy.evaluateModeratorAsOfDeclaration",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-moderation"
    ],
    "invariants": [
      "SOCIAL-I-AGENT-POLICY-LOCAL"
    ],
    "reason_codes": [
      "moderator_not_in_asof_declaration"
    ]
  },
  "social/profile-heterodyne-social-agent-policy-list-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "social",
    "profile": "heterodyne-social-agent-policy-list-v1",
    "spec_refs": [
      "heterodyne:0.6.0#social-security"
    ],
    "invariants": [
      "SOCIAL-I-AGENT-AUTHORSHIP-EXACT",
      "SOCIAL-I-AGENT-POLICY-LOCAL"
    ],
    "reason_codes": []
  },
  "social/profile-heterodyne-social-agent-policy-receipt-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "social",
    "profile": "heterodyne-social-agent-policy-receipt-v1",
    "spec_refs": [
      "heterodyne:0.6.0#social-security"
    ],
    "invariants": [
      "SOCIAL-I-AGENT-AUTHORSHIP-EXACT",
      "SOCIAL-I-AGENT-POLICY-LOCAL"
    ],
    "reason_codes": []
  },
  "social/profile-heterodyne-social-mute-list-v1": {
    "boundary_id": "profile-negotiation.validateCurrentKindProfileNegotiation",
    "owner_document": "social",
    "profile": "heterodyne-social-mute-list-v1",
    "spec_refs": [
      "heterodyne:0.6.0#social-security"
    ],
    "invariants": [
      "SOCIAL-I-PRIVATE-STATE-AT-REST"
    ],
    "reason_codes": []
  },
  "social/replaceable-coordinate-mismatch": {
    "boundary_id": "social-events.validateSocialReplaceableCandidate",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-interactions"
    ],
    "invariants": [
      "SOCIAL-I-SOURCE-NEUTRAL-SELECTION"
    ],
    "reason_codes": [
      "social-replaceable-coordinate-mismatch"
    ]
  },
  "social/source-neutral-core-quarantine": {
    "boundary_id": "social-events.selectCurrentSocialEvent",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-scope"
    ],
    "invariants": [
      "SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH",
      "SOCIAL-I-SOURCE-NEUTRAL-SELECTION"
    ],
    "reason_codes": []
  },
  "social/source-neutral-vanilla-authorship": {
    "boundary_id": "social-events.validateSocialAuthorship",
    "owner_document": "social",
    "spec_refs": [
      "heterodyne:0.6.0#social-interactions"
    ],
    "invariants": [
      "SOCIAL-I-NIP01-AUTHORSHIP"
    ],
    "reason_codes": []
  },
  "workspace/affiliation-stale": {
    "boundary_id": "workspace-policy.evaluateWorkspaceAffiliationBoundary",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-relationships"
    ],
    "invariants": [
      "WORKSPACE-I-FRESHNESS-BOUNDED"
    ],
    "reason_codes": [
      "affiliation_stale"
    ]
  },
  "workspace/assurance-dual-removal": {
    "boundary_id": "workspace-assurance.evaluateWorkspaceAssuranceTransition",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-optional-assurance"
    ],
    "invariants": [
      "WORKSPACE-I-OPTIONAL-ASSURANCE"
    ],
    "reason_codes": []
  },
  "workspace/assurance-history-mutation-revalidated": {
    "boundary_id": "workspace-assurance.verifyWorkspaceAssuranceAuthorization",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-optional-assurance"
    ],
    "invariants": [
      "WORKSPACE-I-OPTIONAL-ASSURANCE"
    ],
    "reason_codes": [
      "workspace-assurance-state-required"
    ]
  },
  "workspace/assurance-pending-activation": {
    "boundary_id": "workspace-assurance.evaluateWorkspaceAssuranceTransition",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-optional-assurance"
    ],
    "invariants": [
      "WORKSPACE-I-OPTIONAL-ASSURANCE"
    ],
    "reason_codes": [
      "workspace-assurance-state-required"
    ]
  },
  "workspace/assurance-unilateral-removal": {
    "boundary_id": "workspace-assurance.evaluateWorkspaceAssuranceTransition",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-optional-assurance"
    ],
    "invariants": [
      "WORKSPACE-I-OPTIONAL-ASSURANCE"
    ],
    "reason_codes": [
      "workspace-assurance-state-required"
    ]
  },
  "workspace/assurance-verified-activation": {
    "boundary_id": "workspace-assurance.evaluateWorkspaceAssuranceTransition",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-optional-assurance"
    ],
    "invariants": [
      "WORKSPACE-I-OPTIONAL-ASSURANCE"
    ],
    "reason_codes": []
  },
  "workspace/authority-checkpoint-stale": {
    "boundary_id": "workspace.evaluateFreshness",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-freshness"
    ],
    "invariants": [
      "WORKSPACE-I-AUTHENTICATED-CURRENT-STATE",
      "WORKSPACE-I-FRESHNESS-BOUNDED"
    ],
    "reason_codes": [
      "checkpoint_stale"
    ]
  },
  "workspace/authority-conflict": {
    "boundary_id": "workspace.evaluateWorkspaceObject",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-role-repositories"
    ],
    "invariants": [
      "WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"
    ],
    "reason_codes": [
      "authority_conflict"
    ]
  },
  "workspace/authority-freshness-boundary": {
    "boundary_id": "workspace.evaluateFreshness",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-freshness"
    ],
    "invariants": [
      "WORKSPACE-I-FRESHNESS-BOUNDED"
    ],
    "reason_codes": []
  },
  "workspace/bare-key-baseline": {
    "boundary_id": "workspace-assurance.evaluateWorkspaceAssuranceTransition",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-optional-assurance"
    ],
    "invariants": [
      "WORKSPACE-I-OPTIONAL-ASSURANCE"
    ],
    "reason_codes": []
  },
  "workspace/carrier-not-ambient-authority": {
    "boundary_id": "workspace-policy.evaluateWorkspaceCapabilityBoundary",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-security"
    ],
    "invariants": [
      "WORKSPACE-I-CARRIER-NOT-AUTHORITY",
      "WORKSPACE-I-NO-AMBIENT-AUTHORITY"
    ],
    "reason_codes": [
      "policy_denied"
    ]
  },
  "workspace/current-capability-intersection": {
    "boundary_id": "workspace-policy.evaluateWorkspaceCapabilityBoundary",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-role-policy"
    ],
    "invariants": [
      "WORKSPACE-I-AUTHENTICATED-CURRENT-STATE",
      "WORKSPACE-I-INHERITANCE-NARROWS",
      "WORKSPACE-I-NO-AMBIENT-AUTHORITY"
    ],
    "reason_codes": []
  },
  "workspace/device-revoked": {
    "boundary_id": "workspace.evaluateRoleLeafChange",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-role-control"
    ],
    "invariants": [
      "WORKSPACE-I-DEVICE-LEAF-SEPARATION"
    ],
    "reason_codes": [
      "device_revoked"
    ]
  },
  "workspace/history-denied": {
    "boundary_id": "workspace-policy.evaluateWorkspaceResourceDeliveryBoundary",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-key-delivery"
    ],
    "invariants": [
      "WORKSPACE-I-REVOCATION-FUTURE-ONLY"
    ],
    "reason_codes": [
      "history_denied"
    ]
  },
  "workspace/host-unauthorized": {
    "boundary_id": "workspace-policy.evaluateWorkspaceResourceDeliveryBoundary",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-key-delivery"
    ],
    "invariants": [
      "WORKSPACE-I-HOST-AUTHORITY-SEPARATION"
    ],
    "reason_codes": [
      "host_unauthorized"
    ]
  },
  "workspace/independent-device-leaf-removal": {
    "boundary_id": "workspace.evaluateRoleLeafChange",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-role-control"
    ],
    "invariants": [
      "WORKSPACE-I-DEVICE-LEAF-SEPARATION",
      "WORKSPACE-I-REVOCATION-FUTURE-ONLY"
    ],
    "reason_codes": []
  },
  "workspace/independent-resource-content-keys": {
    "boundary_id": "workspace-policy.evaluateWorkspaceResourceKeySeparation",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-key-delivery"
    ],
    "invariants": [
      "WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS"
    ],
    "reason_codes": []
  },
  "workspace/inheritance-escalation-rejected": {
    "boundary_id": "workspace-policy.evaluateWorkspaceCapabilityBoundary",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-role-policy"
    ],
    "invariants": [
      "WORKSPACE-I-INHERITANCE-NARROWS"
    ],
    "reason_codes": [
      "capability_escalation"
    ]
  },
  "workspace/invitation-replay": {
    "boundary_id": "workspace-policy.evaluateWorkspaceStateTransitionBoundary",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-grants"
    ],
    "invariants": [
      "WORKSPACE-I-NO-AMBIENT-AUTHORITY"
    ],
    "reason_codes": [
      "workspace_replay"
    ]
  },
  "workspace/private-topology-clean": {
    "boundary_id": "workspace.evaluatePrivateProjection",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-privacy"
    ],
    "invariants": [
      "WORKSPACE-I-PRIVATE-TOPOLOGY"
    ],
    "reason_codes": []
  },
  "workspace/private-topology-disclosed": {
    "boundary_id": "workspace.evaluatePrivateProjection",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-privacy"
    ],
    "invariants": [
      "WORKSPACE-I-PRIVATE-TOPOLOGY"
    ],
    "reason_codes": [
      "private_topology_disclosed"
    ]
  },
  "workspace/radicle-backed-hosts": {
    "boundary_id": "workspace.resolveEffectiveHosts",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-advertisements"
    ],
    "invariants": [
      "WORKSPACE-I-HOST-AUTHORITY-SEPARATION",
      "WORKSPACE-I-RADICLE-BACKSTOP"
    ],
    "reason_codes": []
  },
  "workspace/repository-invalid": {
    "boundary_id": "workspace.authenticateWorkspaceRepositoryView",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-role-repositories"
    ],
    "invariants": [
      "WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"
    ],
    "reason_codes": [
      "workspace_repository_invalid"
    ]
  },
  "workspace/resource-unknown": {
    "boundary_id": "workspace-policy.evaluateWorkspaceResourceDeliveryBoundary",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-key-delivery"
    ],
    "invariants": [
      "WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS"
    ],
    "reason_codes": [
      "resource_unknown"
    ]
  },
  "workspace/revocation-blocks-future-effect": {
    "boundary_id": "workspace-policy.evaluateWorkspaceCapabilityBoundary",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-grants"
    ],
    "invariants": [
      "WORKSPACE-I-REVOCATION-FUTURE-ONLY"
    ],
    "reason_codes": [
      "policy_denied"
    ]
  },
  "workspace/schema-invalid": {
    "boundary_id": "workspace.evaluateFreshness",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-object-types"
    ],
    "invariants": [
      "WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"
    ],
    "reason_codes": [
      "workspace_schema_invalid"
    ]
  },
  "workspace/signature-invalid": {
    "boundary_id": "workspace.eventsAreByteIdentical",
    "owner_document": "workspace",
    "spec_refs": [
      "heterodyne:0.6.0#workspace-object-types"
    ],
    "invariants": [
      "WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"
    ],
    "reason_codes": [
      "workspace_signature_invalid"
    ]
  }
} as const satisfies Readonly<
  Record<string, CurrentCaseContract>
>;

for (const contract of Object.values(CURRENT_CASE_CONTRACTS)) {
  Object.freeze(contract.spec_refs);
  Object.freeze(contract.invariants);
  Object.freeze(contract.reason_codes);
  if ("semantic_reason_codes" in contract) {
    Object.freeze(contract.semantic_reason_codes);
  }
  Object.freeze(contract);
}
Object.freeze(CURRENT_CASE_CONTRACTS);

export function currentCaseContract(vectorId: string): CurrentCaseContract {
  const contract = CURRENT_CASE_CONTRACTS[vectorId as keyof typeof CURRENT_CASE_CONTRACTS];
  if (contract === undefined) {
    throw new Error(`unregistered current vector case: ${vectorId}`);
  }
  const profileOracle = currentProfileOracleForVector(vectorId);
  if (profileOracle !== undefined) {
    return Object.freeze({
      ...contract,
      boundary_id: profileOracle.semantic_boundary,
      owner_document: profileOracle.tuple.owner,
      profile: profileOracle.tuple.profile_id,
      invariants: profileOracle.exercised_invariants,
      reason_codes: Object.freeze([]),
    });
  }
  return contract;
}

export function currentCaseIds(): readonly string[] {
  return Object.keys(CURRENT_CASE_CONTRACTS);
}
