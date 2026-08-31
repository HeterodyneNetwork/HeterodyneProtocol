import {
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey,
} from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { base58 } from "@scure/base";
import { repositoryWriterBindingProofBytes } from "../core-writer-binding.js";
import { hexToBytes } from "../hex.js";
import type { CurrentCaseContract } from "./case-contracts.js";
import {
  inspectCurrentBoundaryExecution,
  type CurrentBoundaryExecution,
  type CurrentBoundaryExecutionRecord,
} from "./boundary-runners.js";
import type { CurrentCaseFixture } from "./types.js";
import {
  workspaceObjectId,
  workspaceSigningPayload,
} from "../workspace.js";

declare const SEMANTIC_BOUNDARY_CERTIFICATE: unique symbol;
export type SemanticBoundaryCertificate = Readonly<{
  readonly [SEMANTIC_BOUNDARY_CERTIFICATE]: true;
}>;

type SemanticCertificateRecord = Readonly<{
  vector_id: string;
  boundary_id: string;
  fixture_digest: string;
  result_digest: string;
  verdict: "accept" | "reject" | "indeterminate";
  invariants: readonly string[];
  reasons: readonly string[];
  postcondition: string;
}>;

type SemanticAllocation = Readonly<{
  boundary_id: string;
  invariants: readonly string[];
  reasons: readonly string[];
  postcondition: string;
}>;

const SEMANTIC_ALLOCATIONS = {"assurance/associated-key-expired":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-expired"],"postcondition":"exact-executed-boundary"},"assurance/associated-key-revoked":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-revoked"],"postcondition":"exact-executed-boundary"},"assurance/associated-key-subject-proof-invalid":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-subject-proof-invalid"],"postcondition":"exact-executed-boundary"},"assurance/associated-key-subject-proof-required":{"boundary_id":"assurance-policy.evaluateAssuranceAssociatedKeyConsent","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-subject-proof-required"],"postcondition":"exact-executed-boundary"},"assurance/authority-at-compromise-cutoff":{"boundary_id":"assurance.evaluateAssuranceAuthorityAt","invariants":["ASSURANCE-I-COMPROMISE-CUTOFF"],"reasons":["assurance-compromise-cutoff"],"postcondition":"exact-executed-boundary"},"assurance/compromise-subordinate-continuation-forbidden":{"boundary_id":"assurance-policy.evaluateAssuranceCompromiseContinuation","invariants":["ASSURANCE-I-COMPROMISE-CUTOFF","ASSURANCE-I-NO-IMPLICIT-CONTINUATION"],"reasons":["assurance-subordinate-continuation-forbidden"],"postcondition":"exact-executed-boundary"},"assurance/duplicity-rejected":{"boundary_id":"assurance-policy.evaluateAssurancePinPolicy","invariants":["ASSURANCE-I-SUCCESSION-NON-ALIASING"],"reasons":["assurance-duplicity"],"postcondition":"exact-executed-boundary"},"assurance/enrollment-competing-inception":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-contested"],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-forged-contest-ignored":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED","ASSURANCE-I-CORE-OPTIONALITY"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-late-warning-no-unpin":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED","ASSURANCE-I-PIN-DOWNGRADE"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-pending-w-minus-one":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-pending-window"],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-timely-contest":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-contested"],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-verified-at-window":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"assurance/export-aid-substitution":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_aid_substituted_for_npub"],"postcondition":"exact-executed-boundary"},"assurance/export-incomplete":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_incomplete"],"postcondition":"exact-executed-boundary"},"assurance/export-lossless":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":[],"postcondition":"exact-executed-boundary"},"assurance/export-unmappable-feature":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_unmappable_feature"],"postcondition":"exact-executed-boundary"},"assurance/export-unsupported-suite":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_unsupported_crypto_suite"],"postcondition":"exact-executed-boundary"},"assurance/keri-wire-format-rejected":{"boundary_id":"assurance-policy.validateAssuranceWireFormat","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["keri_wire_format_rejected"],"postcondition":"exact-executed-boundary"},"assurance/persona-author-mismatch":{"boundary_id":"core-policy.validateCorePersonaSignedEvent","invariants":["ASSURANCE-I-CORE-OPTIONALITY"],"reasons":["delegation_mismatch"],"postcondition":"exact-executed-boundary"},"assurance/pin-conflict-rejected":{"boundary_id":"assurance-policy.evaluateAssurancePinPolicy","invariants":["ASSURANCE-I-PIN-DOWNGRADE"],"reasons":["assurance-pin-conflict"],"postcondition":"exact-executed-boundary"},"assurance/profile-heterodyne-assurance-active-key-acceptance-v1":{"boundary_id":"assurance.evaluateEnrollment","invariants":["ASSURANCE-I-RECIPROCAL-ENROLLMENT"],"reasons":[],"postcondition":"exact-executed-boundary"},"assurance/profile-heterodyne-assurance-associated-key-v1":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":[],"postcondition":"exact-executed-boundary"},"assurance/profile-heterodyne-assurance-enrollment-contest-profile-v1":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":[],"postcondition":"exact-executed-boundary"},"assurance/profile-heterodyne-assurance-enrollment-inception-v1":{"boundary_id":"assurance.evaluateEnrollment","invariants":["ASSURANCE-I-RECIPROCAL-ENROLLMENT"],"reasons":[],"postcondition":"exact-executed-boundary"},"assurance/profile-heterodyne-assurance-succession-v1":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"assurance/reciprocal-proof-invalid":{"boundary_id":"assurance.evaluateEnrollment","invariants":["ASSURANCE-I-RECIPROCAL-ENROLLMENT"],"reasons":["assurance-reciprocal-proof-invalid"],"postcondition":"exact-executed-boundary"},"assurance/retired-key-post-compromise":{"boundary_id":"follow-up-hardening.classifyRetiredKeyObservation","invariants":["ASSURANCE-I-COMPROMISE-CUTOFF"],"reasons":["revoked_key_post_compromise"],"postcondition":"exact-executed-boundary"},"assurance/succession-authority-invalid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-authority-invalid"],"postcondition":"exact-executed-boundary"},"assurance/succession-head-mismatch":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-head-mismatch"],"postcondition":"exact-executed-boundary"},"assurance/succession-new-key-acceptance-invalid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-new-key-acceptance-invalid"],"postcondition":"exact-executed-boundary"},"assurance/succession-predecessor-mismatch":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-predecessor-mismatch"],"postcondition":"exact-executed-boundary"},"assurance/succession-schema-invalid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-schema-invalid"],"postcondition":"exact-executed-boundary"},"assurance/succession-valid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-NO-IMPLICIT-CONTINUATION","ASSURANCE-I-SUCCESSION-NON-ALIASING","ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"assurance/succession-witness-threshold-unsatisfied":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-witness-threshold-unsatisfied"],"postcondition":"exact-executed-boundary"},"assurance/dual-consent-downgrade-accepted":{"boundary_id":"assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade","invariants":["ASSURANCE-I-PIN-DOWNGRADE"],"reasons":[],"postcondition":"assurance-dual-proof-downgrade"},"assurance/unilateral-downgrade-rejected":{"boundary_id":"assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade","invariants":["ASSURANCE-I-PIN-DOWNGRADE"],"reasons":["assurance-downgrade-consent-required"],"postcondition":"assurance-dual-proof-downgrade"},"assurance/witness-threshold-fail":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-pending-window"],"postcondition":"assurance-authoritative-observation"},"assurance/witness-threshold-pass":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"comms/agent-attribution-encrypted-inner":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/agent-attribution-invalid":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION"],"reasons":["agent-attribution-invalid"],"postcondition":"exact-executed-boundary"},"comms/agent-attribution-profile-unavailable":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION"],"reasons":["agent-attribution-profile-unavailable"],"postcondition":"exact-executed-boundary"},"comms/agent-persona-scope-required":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION"],"reasons":["agent-persona-scope-required"],"postcondition":"exact-executed-boundary"},"comms/agent-sender-proof-invalid":{"boundary_id":"agent-authorship.validateAgentAccessToken","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-sender-proof-invalid"],"postcondition":"exact-executed-boundary"},"comms/agent-signer-mismatch":{"boundary_id":"agent-authorship.validateAgentAccessToken","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-signer-mismatch"],"postcondition":"exact-executed-boundary"},"comms/agent-token-invalid":{"boundary_id":"agent-authorship.validateAgentAccessToken","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-token-invalid"],"postcondition":"exact-executed-boundary"},"comms/agent-workload-registration-invalid":{"boundary_id":"agent-authorship.validateWorkloadRegistration","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-workload-registration-invalid"],"postcondition":"exact-executed-boundary"},"comms/agent-workload-token-accepted":{"boundary_id":"agent-authorship.validateWorkloadRegistration+validateAgentAccessToken","invariants":["COMMS-I-AGENT-SIGNER-BINDING","COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/auth-rejected-permanent":{"boundary_id":"comms-policy.classifyRelayWriteFailure","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["auth_rejected_permanent"],"postcondition":"exact-executed-boundary"},"comms/authorization-view-300-boundary":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/authorization-view-86400-boundary":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/authorization-view-maximum-malformed":{"boundary_id":"schema.validateOidcContinuityManifestSchemaOrThrow","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":["claim-schema-invalid"],"postcondition":"exact-executed-boundary"},"comms/checkpoint-exact-boundary":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/checkpoint-stale-independent":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":["oidc-checkpoint-stale"],"postcondition":"exact-executed-boundary"},"comms/claim-active-authenticated":{"boundary_id":"claim-authorization.authorizeClaimEffect","invariants":["COMMS-I-CLAIM-ATTENUATION","COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[],"postcondition":"claim-artifact-durable-effect"},"comms/claim-attenuation-violation":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-attenuation-violation"],"postcondition":"exact-executed-boundary"},"comms/claim-chain-cycle":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-chain-cycle"],"postcondition":"exact-executed-boundary"},"comms/claim-chain-depth-exceeded":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-chain-depth-exceeded"],"postcondition":"exact-executed-boundary"},"comms/claim-delegation-not-authorized":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-delegation-not-authorized"],"postcondition":"exact-executed-boundary"},"comms/claim-event-signature-invalid":{"boundary_id":"claims.verifyClaimEnvelope","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-event-signature-invalid"],"postcondition":"exact-executed-boundary"},"comms/claim-expired":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-expired"],"postcondition":"exact-executed-boundary"},"comms/claim-id-mismatch":{"boundary_id":"claims.validateClaimId","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-id-mismatch"],"postcondition":"exact-executed-boundary"},"comms/claim-issuer-authority-invalid":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-issuer-authority-invalid"],"postcondition":"exact-executed-boundary"},"comms/claim-issuer-untrusted":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-issuer-untrusted"],"postcondition":"exact-executed-boundary"},"comms/claim-key-reference-invalid":{"boundary_id":"claims.validateKeyRef","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-key-reference-invalid"],"postcondition":"exact-executed-boundary"},"comms/claim-ledger-rollback":{"boundary_id":"claim-ledger.mergeClaimLedger","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-ledger-rollback"],"postcondition":"exact-executed-boundary"},"comms/claim-ledger-writer-unauthorized":{"boundary_id":"claim-ledger.mergeClaimLedger","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-ledger-writer-unauthorized"],"postcondition":"ledger-current-writer-rejection"},"comms/claim-repository-conflict":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-repository-conflict"],"postcondition":"exact-executed-boundary"},"comms/claim-repository-unconfirmed":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-repository-unconfirmed"],"postcondition":"exact-executed-boundary"},"comms/claim-revoked":{"boundary_id":"claims.verifyClaimRevocationEnvelope+claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":["claim-revoked"],"postcondition":"exact-executed-boundary"},"comms/claim-revoker-unauthorized":{"boundary_id":"claim-ledger.validateLedgerRecordOrThrow","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":["claim-revoker-unauthorized"],"postcondition":"exact-executed-boundary"},"comms/claim-subject-proof-invalid":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-subject-proof-invalid"],"postcondition":"exact-executed-boundary"},"comms/claim-subject-proof-required":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-subject-proof-required"],"postcondition":"exact-executed-boundary"},"comms/config-private-state-encrypted":{"boundary_id":"privacy-crypto.deriveConfigPostKey+nostr-tools.nip44","invariants":["COMMS-I-CONFIG-AT-REST","COMMS-I-TIER2-HONESTY"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/conversation-rejected":{"boundary_id":"marmot-admission.ordinaryConversationAdmission","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["conversation-rejected"],"postcondition":"exact-executed-boundary"},"comms/dm-invite-revoked-device":{"boundary_id":"comms-policy.validateDmInviteDevice","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["dm_invite_revoked_device"],"postcondition":"exact-executed-boundary"},"comms/dm-invite-unbound-device":{"boundary_id":"comms-policy.validateDmInviteDevice","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["dm_invite_unbound_device"],"postcondition":"exact-executed-boundary"},"comms/invite-already-reserved":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-already-reserved"],"postcondition":"exact-executed-boundary"},"comms/invite-authentication-invalid":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-authentication-invalid"],"postcondition":"exact-executed-boundary"},"comms/invite-expired":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-expired"],"postcondition":"exact-executed-boundary"},"comms/invite-purpose-mismatch":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-purpose-mismatch"],"postcondition":"exact-executed-boundary"},"comms/ledger-reader-authorized":{"boundary_id":"claim-ledger.mergeClaimLedger+evaluateReaderAccess","invariants":["COMMS-I-CLAIM-REVOCATION","COMMS-I-LEDGER-CONFINEMENT"],"reasons":[],"postcondition":"ledger-current-writer-durable-effect"},"comms/ledger-reader-unauthorized":{"boundary_id":"claim-ledger.evaluateReaderAccess","invariants":["COMMS-I-LEDGER-CONFINEMENT"],"reasons":["claim-ledger-reader-unauthorized"],"postcondition":"exact-executed-boundary"},"comms/marmot-agent-scope-denied":{"boundary_id":"comms-policy.evaluateMarmotInboxBootstrap","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-agent-scope-denied"],"postcondition":"exact-executed-boundary"},"comms/marmot-exact-bytes-durable":{"boundary_id":"marmot-routing-policy.evaluateMarmotDurability","invariants":["COMMS-I-MARMOT-EXACT-BYTES"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/marmot-expiration-not-erasure":{"boundary_id":"marmot-routing-policy.evaluateMarmotRetention","invariants":["COMMS-I-RADICLE-NON-ERASURE"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/marmot-keypackage-replayed":{"boundary_id":"comms-policy.evaluateMarmotInboxBootstrap","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-keypackage-replayed"],"postcondition":"exact-executed-boundary"},"comms/marmot-ordinary-welcome-held":{"boundary_id":"marmot-admission.ordinaryConversationAdmission","invariants":["COMMS-I-MARMOT-ACCOUNT-IDENTITY","COMMS-I-MARMOT-SECRET-CONFINEMENT","COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/marmot-premature-ack":{"boundary_id":"marmot-routing-policy.evaluateMarmotDurability","invariants":["COMMS-I-MARMOT-EXACT-BYTES"],"reasons":["marmot-premature-ack"],"postcondition":"exact-executed-boundary"},"comms/marmot-private-inbox-nid-required":{"boundary_id":"comms-policy.evaluateMarmotInboxBootstrap","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-private-inbox-nid-required"],"postcondition":"exact-executed-boundary"},"comms/marmot-private-route-required":{"boundary_id":"current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-private-route-required"],"postcondition":"exact-executed-boundary"},"comms/marmot-routing-binding-valid":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/marmot-routing-equivocation":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":["marmot-routing-equivocation"],"postcondition":"exact-executed-boundary"},"comms/marmot-routing-genesis-mismatch":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":["marmot-routing-binding-invalid"],"postcondition":"exact-executed-boundary"},"comms/marmot-unauthorized-ref":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":["marmot-unauthorized-ref"],"postcondition":"exact-executed-boundary"},"comms/nip59-broadcast-rejected":{"boundary_id":"comms-policy.validatePrivateBroadcast","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["nip59_broadcast_rejected"],"postcondition":"exact-executed-boundary"},"comms/oidc-access-token-validated":{"boundary_id":"oidc.projectAccessToken+validateProjectedJwt","invariants":["COMMS-I-JWT-TYPE-AUDIENCE","COMMS-I-STATUS-INTEGRITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/oidc-audience-invalid":{"boundary_id":"oidc.validateProjectedJwt","invariants":["COMMS-I-JWT-TYPE-AUDIENCE"],"reasons":["oidc-audience-invalid"],"postcondition":"exact-executed-boundary"},"comms/oidc-claim-release":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE","COMMS-I-ISSUER-KEY-CONFINEMENT"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/oidc-claim-release-denied":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-claim-release-denied"],"postcondition":"exact-executed-boundary"},"comms/oidc-client-unregistered":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-client-unregistered"],"postcondition":"exact-executed-boundary"},"comms/oidc-consent-required":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-consent-required"],"postcondition":"exact-executed-boundary"},"comms/oidc-grant-prohibited":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-grant-prohibited"],"postcondition":"exact-executed-boundary"},"comms/oidc-issuer-authority-invalid":{"boundary_id":"claim-ledger.canMint","invariants":["COMMS-I-ISSUER-KEY-CONFINEMENT"],"reasons":["oidc-issuer-authority-invalid"],"postcondition":"exact-executed-boundary"},"comms/oidc-issuer-mismatch":{"boundary_id":"oidc.validateIssuerMetadata","invariants":["COMMS-I-ISSUER-CONTINUITY"],"reasons":["oidc-issuer-mismatch"],"postcondition":"exact-executed-boundary"},"comms/oidc-issuer-persona-continuity":{"boundary_id":"oidc.validateIssuerMetadata","invariants":["COMMS-I-ISSUER-CONTINUITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/oidc-signing-key-unavailable":{"boundary_id":"claim-ledger.canMint","invariants":["COMMS-I-ISSUER-KEY-CONFINEMENT"],"reasons":["oidc-signing-key-unavailable"],"postcondition":"exact-executed-boundary"},"comms/oidc-status-invalid":{"boundary_id":"token-status.encodeStatusList","invariants":["COMMS-I-STATUS-INTEGRITY"],"reasons":["oidc-status-invalid"],"postcondition":"exact-executed-boundary"},"comms/oidc-token-type-invalid":{"boundary_id":"oidc.validateProjectedJwt","invariants":["COMMS-I-JWT-TYPE-AUDIENCE"],"reasons":["oidc-token-type-invalid"],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-agent-attribution-kind-1-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-agent-attribution-kind-1063-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-agent-attribution-kind-16-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-agent-attribution-kind-1985-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-agent-attribution-kind-30023-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-agent-attribution-kind-4550-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-agent-attribution-kind-6-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-agent-attribution-kind-7-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-claim-revocation-jwk-jws-v1":{"boundary_id":"current-revocation.evaluateCurrentRevocationProfile","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-claim-revocation-nostr-bip340-v1":{"boundary_id":"current-revocation.evaluateCurrentRevocationProfile","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-claim-revocation-radicle-ed25519-v1":{"boundary_id":"current-revocation.evaluateCurrentRevocationProfile","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-key-claim-jwk-jws-v1":{"boundary_id":"profile-negotiation.verifyCurrentClaimProofProfile","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-key-claim-nostr-bip340-v1":{"boundary_id":"profile-negotiation.verifyCurrentClaimProofProfile","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-key-claim-radicle-ed25519-v1":{"boundary_id":"profile-negotiation.verifyCurrentClaimProofProfile","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1063-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-16-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-30023-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-30402-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-6-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/public-reader-private-content":{"boundary_id":"comms-policy.validatePublicReaderRendering","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":["public-reader-private-content"],"postcondition":"exact-executed-boundary"},"comms/public-reader-private-tier":{"boundary_id":"public-reader.resolvePublicAsset","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/public-reader-relay-hint-invalid":{"boundary_id":"public-reader.validateBootstrapRelay","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":["public-reader-relay-hint-invalid"],"postcondition":"exact-executed-boundary"},"comms/public-reader-route-invalid":{"boundary_id":"public-reader.parseLauncherFragment","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":["public-reader-route-invalid"],"postcondition":"exact-executed-boundary"},"comms/tier3-client-side-encryption":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44","invariants":["COMMS-I-CLIENT-SIDE-DELIVERY","COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY","COMMS-I-TIER3-BLIND-CARRIER"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/tier3-recipient-confined":{"boundary_id":"follow-up-hardening.resolveTier3Recipients","invariants":["COMMS-I-TIER3-CONFINED"],"reasons":["tier3-recipient-not-active-device"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-acl-ambiguous":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-ambiguous"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-acl-conflict":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-conflict"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-acl-expired":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-expired"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-acl-invalid":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-invalid"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-acl-missing":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-missing"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-acl-stale":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-stale"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-event-invalid":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-event-invalid"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-exact-write":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-MARMOT-EXACT-BYTES","COMMS-I-PRIVATE-RELAY-ACL","COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":[],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-nip42-required":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-nip42-required"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-request-invalid":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-request-invalid"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-request-replay":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-request-replay"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-revoked":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-revoked"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-route-mismatch":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-route-mismatch"],"postcondition":"exact-executed-boundary"},"comms/trusted-seed-unauthorized":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-unauthorized"],"postcondition":"exact-executed-boundary"},"control/activation-binding-mismatch":{"boundary_id":"control-signing.consumeNip46ConnectionSecret","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-activation-binding-mismatch"],"postcondition":"exact-executed-boundary"},"control/agent-attribution-bypass-prohibited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["agent-attribution-bypass-prohibited"],"postcondition":"exact-executed-boundary"},"control/agent-human-profile-prohibited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["agent-human-profile-prohibited"],"postcondition":"exact-executed-boundary"},"control/agent-intent-invalid":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-agent-intent-invalid"],"postcondition":"exact-executed-boundary"},"control/agent-key-access-prohibited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["agent-key-access-prohibited"],"postcondition":"exact-executed-boundary"},"control/agent-method-prohibited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["agent-method-prohibited"],"postcondition":"exact-executed-boundary"},"control/agent-rate-limited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["agent-rate-limited"],"postcondition":"exact-executed-boundary"},"control/agent-resource-denied":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["agent-resource-denied"],"postcondition":"exact-executed-boundary"},"control/agent-size-exceeded":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["agent-size-exceeded"],"postcondition":"exact-executed-boundary"},"control/attribution-binding-mismatch":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-attribution-binding-mismatch"],"postcondition":"exact-executed-boundary"},"control/attribution-required":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-attribution-required"],"postcondition":"exact-executed-boundary"},"control/authorization-view-stale-at-effect":{"boundary_id":"authorization-freshness.revalidateAuthorizationViewAtEffect","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-authorization-view-stale"],"postcondition":"exact-executed-boundary"},"control/automation-attributed-before-signing":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING","CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":[],"postcondition":"exact-executed-boundary"},"control/caller-freshness-booleans-rejected":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-authorization-view-stale"],"postcondition":"exact-executed-boundary"},"control/client-metadata-widening":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-CLIENT-KEY-CONFINEMENT"],"reasons":["control-client-metadata-widening"],"postcondition":"exact-executed-boundary"},"control/compromise-reset-closure-required":{"boundary_id":"control-signing.validateCompromiseReset","invariants":["CONTROL-I-COMPROMISE-RESET","CONTROL-I-MARMOT-LEAF-COMPROMISE"],"reasons":["control-compromise-reset-incomplete"],"postcondition":"exact-executed-boundary"},"control/compromise-reset-evidence-invalid":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-compromise-reset-evidence-invalid"],"postcondition":"exact-executed-boundary"},"control/compromise-reset-inventory-mismatch":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-compromise-reset-inventory-mismatch"],"postcondition":"exact-executed-boundary"},"control/compromise-reset-unauthenticated":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-compromise-reset-unauthenticated"],"postcondition":"exact-executed-boundary"},"control/connection-secret-invalid":{"boundary_id":"control-signing.consumeNip46ConnectionSecret","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-connection-secret-invalid"],"postcondition":"exact-executed-boundary"},"control/connection-secret-reused":{"boundary_id":"control-signing.consumeNip46ConnectionSecret","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-connection-secret-reused"],"postcondition":"exact-executed-boundary"},"control/device-code-display-mismatch":{"boundary_id":"control-policy.evaluateDeviceCodeBoundary","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-device-code-display-mismatch"],"postcondition":"exact-executed-boundary"},"control/device-code-invalid":{"boundary_id":"control-policy.evaluateDeviceCodeBoundary","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-device-code-invalid"],"postcondition":"exact-executed-boundary"},"control/device-code-rate-limited":{"boundary_id":"control-policy.evaluateDeviceCodeBoundary","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-device-code-rate-limited"],"postcondition":"exact-executed-boundary"},"control/enrollment-rate-limited":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-enrollment-rate-limited"],"postcondition":"exact-executed-boundary"},"control/enrollment-required":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-enrollment-required"],"postcondition":"exact-executed-boundary"},"control/enrollment-unavailable":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-enrollment-unavailable"],"postcondition":"exact-executed-boundary"},"control/entitlement-conflict":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-entitlement-conflict"],"postcondition":"exact-executed-boundary"},"control/exact-signer-grant-reserved":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-AUDIT-AT-REST","CONTROL-I-BASELINE-ACTIVE-KEY","CONTROL-I-CLIENT-KEY-CONFINEMENT","CONTROL-I-EXACT-SIGNER-GRANT","CONTROL-I-NO-SIGNER-FALLBACK","CONTROL-I-OPERATION-AT-MOST-ONCE","CONTROL-I-PERSONA-VAULT-ISOLATION"],"reasons":[],"postcondition":"exact-executed-boundary"},"control/frame-invalid":{"boundary_id":"control-policy.validateControlFrameBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-frame-invalid"],"postcondition":"exact-executed-boundary"},"control/invite-preauthorization-invalid":{"boundary_id":"control-policy.validateInvitePreauthorizationBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["invite-preauthorization-invalid"],"postcondition":"exact-executed-boundary"},"control/keypackage-invalid":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-keypackage-invalid"],"postcondition":"exact-executed-boundary"},"control/keypackage-replenishment-paused":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-keypackage-replenishment-paused"],"postcondition":"exact-executed-boundary"},"control/nip46-request-invalid":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-nip46-request-invalid"],"postcondition":"exact-executed-boundary"},"control/opaque-authorization-view-accepted":{"boundary_id":"authorization-freshness.revalidateAuthorizationViewAtEffect","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":[],"postcondition":"exact-executed-boundary"},"control/operation-conflict":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-conflict"],"postcondition":"exact-executed-boundary"},"control/operation-execution-fence-required":{"boundary_id":"control-signing.executePersistedAutomatedSigning","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-execution-fence-required"],"postcondition":"exact-executed-boundary"},"control/operation-indeterminate":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-indeterminate"],"postcondition":"exact-executed-boundary"},"control/operation-reservation-required":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-reservation-required"],"postcondition":"exact-executed-boundary"},"control/persona-authority-required":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-BASELINE-ACTIVE-KEY"],"reasons":["control-persona-authority-required"],"postcondition":"exact-executed-boundary"},"control/profile-heterodyne-control-marmot-frame-v1":{"boundary_id":"profile-negotiation.validateCurrentControlGrantProfile","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":[],"postcondition":"exact-executed-boundary"},"control/refresh-prohibited":{"boundary_id":"control-policy.validateControlFrameBoundary","invariants":["CONTROL-I-CLIENT-KEY-CONFINEMENT"],"reasons":["control-refresh-prohibited"],"postcondition":"exact-executed-boundary"},"control/request-expired":{"boundary_id":"control-policy.evaluateControlOperationRequest","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-request-expired"],"postcondition":"exact-executed-boundary"},"control/request-id-conflict":{"boundary_id":"control-policy.evaluateControlOperationRequest","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-request-id-conflict"],"postcondition":"exact-executed-boundary"},"control/signed-event-invalid":{"boundary_id":"control-policy.validateControlSignedEffect","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-signed-event-invalid"],"postcondition":"exact-executed-boundary"},"control/signer-binding-mismatch":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signer-binding-mismatch"],"postcondition":"exact-executed-boundary"},"control/signer-effect-indeterminate":{"boundary_id":"control-policy.validateControlSignedEffect","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-signer-effect-indeterminate"],"postcondition":"exact-executed-boundary"},"control/signer-unavailable":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-NO-SIGNER-FALLBACK"],"reasons":["control-signer-unavailable"],"postcondition":"exact-executed-boundary"},"control/signing-grant-inactive":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-inactive"],"postcondition":"exact-executed-boundary"},"control/signing-grant-invalid":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-invalid"],"postcondition":"exact-executed-boundary"},"control/signing-grant-stale":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-stale"],"postcondition":"exact-executed-boundary"},"control/signing-grant-unauthenticated":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-unauthenticated"],"postcondition":"exact-executed-boundary"},"control/signing-rate-limited":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-signing-rate-limited"],"postcondition":"exact-executed-boundary"},"control/subordinate-reauthorization-required":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-subordinate-reauthorization-required"],"postcondition":"exact-executed-boundary"},"control/token-invalid":{"boundary_id":"control-policy.validateControlFrameBoundary","invariants":["CONTROL-I-CLIENT-KEY-CONFINEMENT"],"reasons":["control-token-invalid"],"postcondition":"exact-executed-boundary"},"control/usage-binding-mismatch":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-usage-binding-mismatch"],"postcondition":"exact-executed-boundary"},"control/vault-isolation-failed":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-PERSONA-VAULT-ISOLATION"],"reasons":["control-vault-isolation-failed"],"postcondition":"exact-executed-boundary"},"core/config-rid-published":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["config_rid_advertised"],"postcondition":"exact-executed-boundary"},"core/friend-cache-unsigned":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["unauthorized_cache_content"],"postcondition":"exact-executed-boundary"},"core/nip01-raw-mismatch":{"boundary_id":"core-policy.validateCoreWireEnvelope","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["nip01_raw_mismatch"],"postcondition":"exact-executed-boundary"},"core/nip49-key-material-round-trip":{"boundary_id":"backup-crypto.nip49EncryptDeterministic+nostr-tools.nip49.decrypt","invariants":["CORE-I-KEY-MATERIAL-AT-REST"],"reasons":[],"postcondition":"exact-executed-boundary"},"core/node-advert-bad-signature":{"boundary_id":"radicle.validateNodeAdvertisement","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["bad_signature"],"postcondition":"exact-executed-boundary"},"core/node-advert-clock-skew":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-clock-skew"],"postcondition":"exact-executed-boundary"},"core/node-advert-clock-uncertain":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-clock-uncertain"],"postcondition":"exact-executed-boundary"},"core/node-advert-dual-proof-valid":{"boundary_id":"radicle.validateNodeAdvertisement","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":[],"postcondition":"exact-executed-boundary"},"core/node-advert-expired":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node_advert_expired"],"postcondition":"exact-executed-boundary"},"core/node-advert-expiry-invalid":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-expiry-invalid"],"postcondition":"exact-executed-boundary"},"core/node-advert-lifetime-exceeded":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-lifetime-exceeded"],"postcondition":"exact-executed-boundary"},"core/node-advert-nid-proof-invalid":{"boundary_id":"radicle.validateNodeAdvertisement","invariants":[],"reasons":["nid_proof_invalid"],"postcondition":"exact-executed-boundary"},"core/onion-clearnet-resolution":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["onion_dns_leak"],"postcondition":"exact-executed-boundary"},"core/profile-heterodyne-core-rotation-breadcrumb-note-v1":{"boundary_id":"core-policy.validateCorePersonaSignedEvent","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"core/profile-heterodyne-core-rotation-breadcrumb-profile-v1":{"boundary_id":"core-policy.validateCorePersonaSignedEvent","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"core/profile-nip05-key-mismatch":{"boundary_id":"follow-up-hardening.validateCanonicalProfile","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["profile-nip05-key-mismatch"],"postcondition":"exact-executed-boundary"},"core/profile-publisher-delegation-invalid":{"boundary_id":"follow-up-hardening.validateCanonicalProfile","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["profile-publisher-delegation-invalid"],"postcondition":"exact-executed-boundary"},"core/profile-repository-selection-required":{"boundary_id":"follow-up-hardening.validateCanonicalProfile","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["profile-repository-selection-required"],"postcondition":"exact-executed-boundary"},"core/relay-profile-mutated":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["relay_profile_mutation"],"postcondition":"exact-executed-boundary"},"core/replaceable-advisory-nip03-ignored":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":[],"postcondition":"exact-executed-boundary"},"core/replaceable-at-premature-boundary":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":[],"postcondition":"exact-executed-boundary"},"core/replaceable-equal-time-lowest-id":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":[],"postcondition":"exact-executed-boundary"},"core/replaceable-future-quarantined":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["core-created-at-premature"],"postcondition":"exact-executed-boundary"},"core/retired-key-authority-window-invalid":{"boundary_id":"follow-up-hardening.classifyRetiredKeyObservation","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["retired-key-authority-window-invalid"],"postcondition":"exact-executed-boundary"},"core/strict-mode-without-tor":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["strict_mode_tor_disabled"],"postcondition":"exact-executed-boundary"},"core/version-future-major":{"boundary_id":"core-policy.validateCoreWireEnvelope","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["unknown_major_version"],"postcondition":"exact-executed-boundary"},"core/version-stamp-missing":{"boundary_id":"core-policy.validateCoreWireEnvelope","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["version_stamp_invalid"],"postcondition":"exact-executed-boundary"},"social/agent-attribution-falsified":{"boundary_id":"social-policy.evaluateAgentModerationEvidence","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT"],"reasons":["agent-attribution-falsified"],"postcondition":"exact-executed-boundary"},"social/agent-attribution-missing":{"boundary_id":"social-policy.evaluateAgentModerationEvidence","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT"],"reasons":["agent-attribution-missing"],"postcondition":"exact-executed-boundary"},"social/agent-policy-binding-invalid":{"boundary_id":"agent-moderation.validateAgentPolicyList","invariants":["SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":["agent-policy-binding-invalid"],"postcondition":"exact-executed-boundary"},"social/agent-policy-receipt-invalid":{"boundary_id":"agent-moderation.validateAgentPolicyReceipt","invariants":["SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":["agent-policy-receipt-invalid"],"postcondition":"exact-executed-boundary"},"social/agent-publication-bypass":{"boundary_id":"social-policy.evaluateAgentModerationEvidence","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT"],"reasons":["agent-publication-bypass"],"postcondition":"exact-executed-boundary"},"social/author-binding-invalid":{"boundary_id":"social-events.validateSocialAuthorship","invariants":["SOCIAL-I-NIP01-AUTHORSHIP"],"reasons":["social-author-binding-invalid"],"postcondition":"exact-executed-boundary"},"social/event-invalid":{"boundary_id":"social-events.validateSocialAuthorship","invariants":["SOCIAL-I-NIP01-AUTHORSHIP"],"reasons":["social-event-invalid"],"postcondition":"exact-executed-boundary"},"social/moderator-not-in-asof-declaration":{"boundary_id":"social-policy.evaluateModeratorAsOfDeclaration","invariants":["SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":["moderator_not_in_asof_declaration"],"postcondition":"exact-executed-boundary"},"social/profile-heterodyne-social-agent-policy-list-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT","SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":[],"postcondition":"exact-executed-boundary"},"social/profile-heterodyne-social-agent-policy-receipt-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT","SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":[],"postcondition":"exact-executed-boundary"},"social/profile-heterodyne-social-mute-list-v1":{"boundary_id":"privacy-crypto.deriveConfigPostKey+nostr-tools.nip44","invariants":["SOCIAL-I-PRIVATE-STATE-AT-REST"],"reasons":[],"postcondition":"exact-executed-boundary"},"social/replaceable-coordinate-mismatch":{"boundary_id":"social-events.validateSocialReplaceableCandidate","invariants":["SOCIAL-I-SOURCE-NEUTRAL-SELECTION"],"reasons":["social-replaceable-coordinate-mismatch"],"postcondition":"exact-executed-boundary"},"social/source-neutral-core-quarantine":{"boundary_id":"social-events.selectCurrentSocialEvent","invariants":["SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH","SOCIAL-I-SOURCE-NEUTRAL-SELECTION"],"reasons":[],"postcondition":"exact-executed-boundary"},"social/source-neutral-vanilla-authorship":{"boundary_id":"social-events.validateSocialAuthorship","invariants":["SOCIAL-I-NIP01-AUTHORSHIP"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/affiliation-stale":{"boundary_id":"workspace-policy.evaluateWorkspaceAffiliationBoundary","invariants":["WORKSPACE-I-FRESHNESS-BOUNDED"],"reasons":["affiliation_stale"],"postcondition":"exact-executed-boundary"},"workspace/assurance-dual-removal":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/assurance-history-mutation-revalidated":{"boundary_id":"workspace-assurance.verifyWorkspaceAssuranceAuthorization","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":["workspace-assurance-state-required"],"postcondition":"exact-executed-boundary"},"workspace/assurance-pending-activation":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":["workspace-assurance-state-required"],"postcondition":"exact-executed-boundary"},"workspace/assurance-unilateral-removal":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":["workspace-assurance-state-required"],"postcondition":"exact-executed-boundary"},"workspace/assurance-verified-activation":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/authority-checkpoint-stale":{"boundary_id":"workspace.evaluateFreshness","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE","WORKSPACE-I-FRESHNESS-BOUNDED"],"reasons":["checkpoint_stale"],"postcondition":"exact-executed-boundary"},"workspace/authority-conflict":{"boundary_id":"workspace.evaluateWorkspaceObject","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["authority_conflict"],"postcondition":"exact-executed-boundary"},"workspace/authority-freshness-boundary":{"boundary_id":"workspace.evaluateFreshness","invariants":["WORKSPACE-I-FRESHNESS-BOUNDED"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/bare-key-baseline":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/carrier-not-ambient-authority":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-CARRIER-NOT-AUTHORITY","WORKSPACE-I-NO-AMBIENT-AUTHORITY"],"reasons":["policy_denied"],"postcondition":"exact-executed-boundary"},"workspace/current-capability-intersection":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE","WORKSPACE-I-INHERITANCE-NARROWS","WORKSPACE-I-NO-AMBIENT-AUTHORITY"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/device-revoked":{"boundary_id":"workspace.evaluateRoleLeafChange","invariants":["WORKSPACE-I-DEVICE-LEAF-SEPARATION"],"reasons":["device_revoked"],"postcondition":"exact-executed-boundary"},"workspace/history-denied":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceDeliveryBoundary","invariants":["WORKSPACE-I-REVOCATION-FUTURE-ONLY"],"reasons":["history_denied"],"postcondition":"exact-executed-boundary"},"workspace/host-unauthorized":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceDeliveryBoundary","invariants":["WORKSPACE-I-HOST-AUTHORITY-SEPARATION"],"reasons":["host_unauthorized"],"postcondition":"exact-executed-boundary"},"workspace/independent-device-leaf-removal":{"boundary_id":"workspace.evaluateRoleLeafChange","invariants":["WORKSPACE-I-DEVICE-LEAF-SEPARATION","WORKSPACE-I-REVOCATION-FUTURE-ONLY"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/independent-resource-content-keys":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceKeySeparation","invariants":["WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/inheritance-escalation-rejected":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-INHERITANCE-NARROWS"],"reasons":["capability_escalation"],"postcondition":"exact-executed-boundary"},"workspace/invitation-replay":{"boundary_id":"workspace-policy.evaluateWorkspaceStateTransitionBoundary","invariants":["WORKSPACE-I-NO-AMBIENT-AUTHORITY"],"reasons":["workspace_replay"],"postcondition":"exact-executed-boundary"},"workspace/private-topology-clean":{"boundary_id":"workspace.evaluatePrivateProjection","invariants":["WORKSPACE-I-PRIVATE-TOPOLOGY"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/private-topology-disclosed":{"boundary_id":"workspace.evaluatePrivateProjection","invariants":["WORKSPACE-I-PRIVATE-TOPOLOGY"],"reasons":["private_topology_disclosed"],"postcondition":"exact-executed-boundary"},"workspace/radicle-backed-hosts":{"boundary_id":"workspace.resolveEffectiveHosts","invariants":["WORKSPACE-I-HOST-AUTHORITY-SEPARATION","WORKSPACE-I-RADICLE-BACKSTOP"],"reasons":[],"postcondition":"exact-executed-boundary"},"workspace/repository-invalid":{"boundary_id":"workspace.authenticateWorkspaceRepositoryView","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["workspace_repository_invalid"],"postcondition":"exact-executed-boundary"},"workspace/resource-unknown":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceDeliveryBoundary","invariants":["WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS"],"reasons":["resource_unknown"],"postcondition":"exact-executed-boundary"},"workspace/revocation-blocks-future-effect":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-REVOCATION-FUTURE-ONLY"],"reasons":["policy_denied"],"postcondition":"exact-executed-boundary"},"workspace/schema-invalid":{"boundary_id":"workspace.evaluateFreshness","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["workspace_schema_invalid"],"postcondition":"exact-executed-boundary"},"workspace/signature-invalid":{"boundary_id":"workspace.evaluateWorkspaceObject","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["workspace_signature_invalid"],"postcondition":"workspace-signed-object-rejected"}} as const satisfies Readonly<Record<string, SemanticAllocation>>;

const TASK_TEN_SEMANTIC_ALLOCATIONS = {
  "comms/claim-authorization-effect-indeterminate": {
    boundary_id: "claim-authorization.authorizeClaimEffect",
    invariants: ["COMMS-I-CLAIM-AUTHENTICITY"],
    reasons: ["claim-authorization-effect-indeterminate"],
    postcondition: "claim-effect-durable-indeterminate",
  },
  "comms/oidc-access-token-validated": {
    boundary_id: "oidc.projectAccessToken+validateProjectedJwt",
    invariants: ["COMMS-I-JWT-TYPE-AUDIENCE", "COMMS-I-STATUS-INTEGRITY"],
    reasons: [],
    postcondition: "oidc-durable-projection-validation",
  },
  "core/node-advert-nid-proof-invalid": {
    boundary_id: "radicle.validateNodeAdvertisement",
    invariants: ["CORE-I-VERIFY-BEFORE-USE"],
    reasons: ["nid_proof_invalid"],
    postcondition: "exact-executed-boundary",
  },
  "comms/claim-subject-proof-replayed": {
    boundary_id: "claim-authorization.authorizeClaimEffect+authorizeClaimEffect",
    invariants: ["COMMS-I-CLAIM-AUTHENTICITY"],
    reasons: ["claim-subject-proof-replayed"],
    postcondition: "claim-subject-proof-durable-replay",
  },
  "core/repository-writer-dual-proof-valid": {
    boundary_id: "core-writer-binding.resolveCurrentRepositoryWriterBinding+revalidateCurrentRepositoryWriterBinding",
    invariants: ["CORE-I-NID-DELEGATION-DUAL-PROOF"],
    reasons: [],
    postcondition: "core-current-writer-dual-proof",
  },
  "core/repository-writer-owner-proof-invalid": {
    boundary_id: "core-writer-binding.resolveCurrentRepositoryWriterBinding+revalidateCurrentRepositoryWriterBinding",
    invariants: ["CORE-I-NID-DELEGATION-DUAL-PROOF"],
    reasons: ["repository-writer-binding-invalid"],
    postcondition: "core-current-writer-dual-proof",
  },
} as const satisfies Readonly<Record<string, SemanticAllocation>>;

const ALL_SEMANTIC_ALLOCATIONS: Readonly<Record<string, SemanticAllocation>> =
  Object.freeze({ ...SEMANTIC_ALLOCATIONS, ...TASK_TEN_SEMANTIC_ALLOCATIONS });

for (const allocation of Object.values(ALL_SEMANTIC_ALLOCATIONS)) {
  Object.freeze(allocation.invariants);
  Object.freeze(allocation.reasons);
  Object.freeze(allocation);
}
Object.freeze(SEMANTIC_ALLOCATIONS);
Object.freeze(TASK_TEN_SEMANTIC_ALLOCATIONS);

const CERTIFICATES = new WeakMap<object, SemanticCertificateRecord>();

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function record(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Readonly<Record<string, unknown>>
    : undefined;
}

function verdictOf(value: unknown): SemanticCertificateRecord["verdict"] | undefined {
  const output = record(value);
  return output?.verdict === "accept"
    || output?.verdict === "reject"
    || output?.verdict === "indeterminate"
    ? output.verdict
    : undefined;
}

function exactExecutedBoundaryPostcondition(
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  return execution.raw_result !== undefined
    && record(execution.projected_output) !== undefined;
}

function workspaceSignedObjectRejected(
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const input = fixture.input;
  const object = record(input.object);
  const current = record(input.current);
  const raw = record(execution.raw_result);
  if (
    object === undefined
    || current === undefined
    || typeof object.workspace_key !== "string"
    || typeof object.signature !== "string"
    || current.workspace_key !== object.workspace_key
    || input.expected_object_id !== workspaceObjectId(object as Record<string, unknown>)
    || raw !== execution.projected_output
  ) return false;
  try {
    return !schnorr.verify(
      object.signature,
      workspaceSigningPayload(object as Record<string, unknown>),
      object.workspace_key,
    );
  } catch {
    return true;
  }
}

function assuranceAuthoritativeObservation(
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const raw = record(execution.raw_result);
  const input = fixture.input;
  if (
    raw === undefined
    || !Array.isArray(input.steps)
    || input.steps.length === 0
    || !input.steps.every((step) => {
      const candidate = record(step);
      return Number.isSafeInteger(candidate?.at) && record(candidate?.evidence) !== undefined;
    })
  ) return false;
  if (fixture.vector_id === "assurance/enrollment-pending-w-minus-one"
    || fixture.vector_id === "assurance/witness-threshold-fail") {
    const first = record(input.steps[0]);
    const last = record(input.steps[input.steps.length - 1]);
    return raw.state === "pending"
      && raw.retained_pin === null
      && record(raw.normalized)?.head ===
        (input.acceptance as Record<string, unknown>).id
      && Number.isSafeInteger(first?.at)
      && Number.isSafeInteger(last?.at)
      && (last!.at as number) >= (first!.at as number);
  }
  if (fixture.vector_id === "assurance/enrollment-timely-contest"
    || fixture.vector_id === "assurance/enrollment-competing-inception") {
    return raw.state === "contested"
      && record(raw.normalized)?.head === (input.acceptance as Record<string, unknown>).id;
  }
  if (raw.state !== "verified" || record(raw.normalized)?.head !==
    (input.acceptance as Record<string, unknown>).id) return false;
  if (fixture.vector_id === "assurance/enrollment-late-warning-no-unpin") {
    return raw.retained_pin !== null
      && Array.isArray(raw.warnings)
      && raw.warnings.length > 0;
  }
  return raw.retained_pin !== null || fixture.vector_id.includes("forged-contest");
}

function assuranceDualProofDowngrade(
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const raw = record(execution.raw_result);
  const event = record(fixture.input.downgrade_event);
  if (raw === undefined || event === undefined) return false;
  if (fixture.vector_id === "assurance/dual-consent-downgrade-accepted") {
    const normalized = record(raw.normalized);
    const content = typeof event.content === "string"
      ? record(JSON.parse(event.content))
      : undefined;
    return normalized?.state === "downgraded"
      && normalized.downgrade_event_id === event.id
      && normalized.predecessor === content?.predecessor;
  }
  const content = typeof event.content === "string"
    ? record(JSON.parse(event.content))
    : undefined;
  return content !== undefined && !Object.hasOwn(content, "downgrade_consent");
}

function claimArtifactDurableEffect(
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const raw = record(execution.raw_result);
  return raw?.disposition === "executed"
    && raw.state === "active"
    && record(raw.result)?.operation === "claim-authorized";
}

function claimSubjectProofDurableReplay(
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const raw = record(execution.raw_result);
  const first = record(raw?.first);
  const second = record(raw?.second);
  return second === execution.projected_output
    && first?.disposition === "executed"
    && record(first.result)?.operation === "claim-authorized"
    && record(first.result)?.execution_index === 1
    && second !== undefined
    && !Object.hasOwn(second, "disposition")
    && !Object.hasOwn(second, "result");
}

function claimEffectDurableIndeterminate(
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const raw = record(execution.raw_result);
  const projected = record(execution.projected_output);
  return raw?.state === "active"
    && typeof raw.reconciliation_digest === "string"
    && /^[0-9a-f]{64}$/u.test(raw.reconciliation_digest)
    && !Object.hasOwn(raw, "disposition")
    && !Object.hasOwn(raw, "result")
    && projected !== undefined
    && !Object.hasOwn(projected, "reconciliation_digest")
    && !Object.hasOwn(projected, "result");
}

function ledgerCurrentWriterDurableEffect(
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const raw = record(execution.raw_result);
  const authorization = record(raw?.authorization);
  return record(raw?.state) !== undefined
    && authorization?.disposition === "executed"
    && record(authorization.result)?.access === "granted";
}

function oidcDurableProjectionValidation(
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const raw = record(execution.raw_result);
  const token = record(raw?.token);
  const header = record(token?.protected_header);
  const claims = record(token?.claims);
  const projection = fixture.boundary_args?.[0];
  const jwks = record(fixture.boundary_args?.[3]);
  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  const jwk = record(keys[0]);
  const compact = token?.compact;
  if (
    projection === null
    || typeof projection !== "object"
    || !sameStrings(
      Reflect.ownKeys(projection).map(String).sort(),
      ["authorization", "authorization_authority"],
    )
    || record(projection)?.authorization === undefined
    || record(projection)?.authorization_authority === undefined
    || typeof compact !== "string"
    || compact !== fixture.input.compact
    || header?.alg !== "RS256"
    || header.typ !== "at+jwt"
    || claims === undefined
    || claims?.iss !== fixture.input.expected_issuer
    || !Array.isArray(claims.aud)
    || !claims.aud.includes(fixture.input.expected_audience)
    || record(claims.status)?.status_list === undefined
    || record(claims["https://heterodyne.network/jwt/status-mirror"]) === undefined
    || jwk === undefined
    || record(execution.projected_output)?.authorization !== raw?.authorization
  ) return false;
  const segments = compact.split(".");
  if (segments.length !== 3) return false;
  try {
    return verifySignature(
      "RSA-SHA256",
      Buffer.from(`${segments[0]}.${segments[1]}`, "ascii"),
      createPublicKey({ key: jwk as JsonWebKey, format: "jwk" }),
      Buffer.from(segments[2]!, "base64url"),
    );
  } catch {
    return false;
  }
}

function coreCurrentWriterDualProof(
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const binding = record(fixture.input.binding);
  if (
    binding === undefined
    || fixture.boundary_args?.[1] !== fixture.input.binding
    || fixture.boundary_args?.[2] !== fixture.input.request
    || typeof binding.owner_active_key !== "string"
    || typeof binding.owner_signature !== "string"
    || typeof binding.writer_nid !== "string"
    || typeof binding.nid_signature !== "string"
    || !binding.writer_nid.startsWith("did:key:z")
  ) return false;
  try {
    const payload = repositoryWriterBindingProofBytes(binding);
    const ownerValid = schnorr.verify(
      binding.owner_signature,
      sha256(payload),
      binding.owner_active_key,
    );
    const encodedNid = base58.decode(binding.writer_nid.slice("did:key:z".length));
    if (encodedNid.length !== 34 || encodedNid[0] !== 0xed || encodedNid[1] !== 0x01) {
      return false;
    }
    const nidValid = ed25519.verify(
      hexToBytes(binding.nid_signature),
      payload,
      encodedNid.slice(2),
    );
    if (fixture.vector_id === "core/repository-writer-dual-proof-valid") {
      const raw = record(execution.raw_result);
      const opaque = record(raw?.binding);
      return ownerValid
        && nidValid
        && opaque !== undefined
        && Reflect.ownKeys(opaque).length === 0
        && Object.isFrozen(opaque)
        && raw !== undefined
        && raw.revalidated === raw.binding;
    }
    return !ownerValid && nidValid && execution.raw_result instanceof Error;
  } catch {
    return false;
  }
}

function verifyPostcondition(
  allocation: SemanticAllocation,
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  switch (allocation.postcondition) {
    case "workspace-signed-object-rejected":
      return workspaceSignedObjectRejected(fixture, execution);
    case "assurance-authoritative-observation":
      return assuranceAuthoritativeObservation(fixture, execution);
    case "assurance-dual-proof-downgrade":
      return assuranceDualProofDowngrade(fixture, execution);
    case "claim-artifact-durable-effect":
      return claimArtifactDurableEffect(execution);
    case "claim-subject-proof-durable-replay":
      return claimSubjectProofDurableReplay(execution);
    case "claim-effect-durable-indeterminate":
      return claimEffectDurableIndeterminate(execution);
    case "ledger-current-writer-rejection":
      return execution.raw_result instanceof Error;
    case "ledger-current-writer-durable-effect":
      return ledgerCurrentWriterDurableEffect(execution);
    case "oidc-durable-projection-validation":
      return oidcDurableProjectionValidation(fixture, execution);
    case "core-current-writer-dual-proof":
      return coreCurrentWriterDualProof(fixture, execution);
    case "exact-executed-boundary":
      return exactExecutedBoundaryPostcondition(execution);
    default:
      return false;
  }
}

export function certifyBoundaryExecution(
  contract: CurrentCaseContract,
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecution,
): SemanticBoundaryCertificate {
  const allocation = ALL_SEMANTIC_ALLOCATIONS[fixture.vector_id];
  if (
    allocation === undefined
    || contract.boundary_id !== allocation.boundary_id
    || !sameStrings(contract.invariants, allocation.invariants)
    || !sameStrings(
      contract.semantic_reason_codes ?? contract.reason_codes,
      allocation.reasons,
    )
  ) throw new Error(`semantic certificate allocation mismatch: ${fixture.vector_id}`);
  const captured = inspectCurrentBoundaryExecution(
    execution,
    allocation.boundary_id,
    fixture,
  );
  if (!verifyPostcondition(allocation, fixture, captured)) {
    throw new Error(`semantic certificate postcondition failed: ${fixture.vector_id}`);
  }
  const verdict = verdictOf(captured.projected_output);
  if (verdict === undefined) {
    throw new Error(`semantic certificate has no terminal result: ${fixture.vector_id}`);
  }
  const certificate = Object.freeze({}) as SemanticBoundaryCertificate;
  CERTIFICATES.set(certificate, Object.freeze({
    vector_id: fixture.vector_id,
    boundary_id: allocation.boundary_id,
    fixture_digest: captured.fixture_digest,
    result_digest: captured.result_digest,
    verdict,
    invariants: allocation.invariants,
    reasons: allocation.reasons,
    postcondition: allocation.postcondition,
  }));
  return certificate;
}

export function inspectSemanticBoundaryCertificate(
  certificate: SemanticBoundaryCertificate,
): SemanticCertificateRecord {
  const state = certificate !== null && typeof certificate === "object"
    ? CERTIFICATES.get(certificate)
    : undefined;
  if (state === undefined) {
    throw new Error("unrecognized semantic boundary certificate");
  }
  return state;
}

export function semanticPostconditionInventory(): readonly Readonly<{
  vector_id: string;
  boundary_id: string;
  postcondition: string;
}>[] {
  return Object.entries(ALL_SEMANTIC_ALLOCATIONS)
    .filter(([, allocation]) => allocation.invariants.length > 0)
    .map(([vector_id, allocation]) => Object.freeze({
      vector_id,
      boundary_id: allocation.boundary_id,
      postcondition: allocation.postcondition,
    }))
    .sort((left, right) => left.vector_id.localeCompare(right.vector_id, "en"));
}
