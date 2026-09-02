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
import { bytesToHex, hexToBytes, utf8Bytes } from "../hex.js";
import { proofBytes } from "../proof-bytes.js";
import { nodeAdvertPayload } from "../radicle.js";
import {
  assertCurrentCaseContractIdentity,
  type CurrentCaseContract,
} from "./case-contracts.js";
import {
  assertCurrentBoundaryEvaluatorIdentity,
  currentFixtureDigest,
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

type SemanticAllocationSource = Readonly<{
  boundary_id: string;
  invariants: readonly string[];
  reasons: readonly string[];
  postcondition?: string;
}>;

const SEMANTIC_ALLOCATIONS = {"assurance/associated-key-expired":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-expired"]},"assurance/associated-key-revoked":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-revoked"]},"assurance/associated-key-subject-proof-invalid":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-subject-proof-invalid"]},"assurance/associated-key-subject-proof-required":{"boundary_id":"assurance-policy.evaluateAssuranceAssociatedKeyConsent","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-subject-proof-required"]},"assurance/authority-at-compromise-cutoff":{"boundary_id":"assurance.evaluateAssuranceAuthorityAt","invariants":["ASSURANCE-I-COMPROMISE-CUTOFF"],"reasons":["assurance-compromise-cutoff"]},"assurance/compromise-subordinate-continuation-forbidden":{"boundary_id":"assurance-policy.evaluateAssuranceCompromiseContinuation","invariants":["ASSURANCE-I-COMPROMISE-CUTOFF","ASSURANCE-I-NO-IMPLICIT-CONTINUATION"],"reasons":["assurance-subordinate-continuation-forbidden"]},"assurance/duplicity-rejected":{"boundary_id":"assurance-policy.evaluateAssurancePinPolicy","invariants":["ASSURANCE-I-SUCCESSION-NON-ALIASING"],"reasons":["assurance-duplicity"]},"assurance/enrollment-competing-inception":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-contested"],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-forged-contest-ignored":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED","ASSURANCE-I-CORE-OPTIONALITY"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-late-warning-no-unpin":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED","ASSURANCE-I-PIN-DOWNGRADE"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-pending-w-minus-one":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-pending-window"],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-timely-contest":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-contested"],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-verified-at-window":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"assurance/export-aid-substitution":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_aid_substituted_for_npub"]},"assurance/export-incomplete":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_incomplete"]},"assurance/export-lossless":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":[]},"assurance/export-unmappable-feature":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_unmappable_feature"]},"assurance/export-unsupported-suite":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_unsupported_crypto_suite"]},"assurance/keri-wire-format-rejected":{"boundary_id":"assurance-policy.validateAssuranceWireFormat","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["keri_wire_format_rejected"]},"assurance/persona-author-mismatch":{"boundary_id":"core-policy.validateCorePersonaSignedEvent","invariants":["ASSURANCE-I-CORE-OPTIONALITY"],"reasons":["delegation_mismatch"]},"assurance/pin-conflict-rejected":{"boundary_id":"assurance-policy.evaluateAssurancePinPolicy","invariants":["ASSURANCE-I-PIN-DOWNGRADE"],"reasons":["assurance-pin-conflict"]},"assurance/profile-heterodyne-assurance-active-key-acceptance-v1":{"boundary_id":"assurance.evaluateEnrollment","invariants":["ASSURANCE-I-RECIPROCAL-ENROLLMENT"],"reasons":[]},"assurance/profile-heterodyne-assurance-associated-key-v1":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":[]},"assurance/profile-heterodyne-assurance-enrollment-contest-profile-v1":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":[]},"assurance/profile-heterodyne-assurance-enrollment-inception-v1":{"boundary_id":"assurance.evaluateEnrollment","invariants":["ASSURANCE-I-RECIPROCAL-ENROLLMENT"],"reasons":[]},"assurance/profile-heterodyne-assurance-succession-v1":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":[]},"assurance/reciprocal-proof-invalid":{"boundary_id":"assurance.evaluateEnrollment","invariants":["ASSURANCE-I-RECIPROCAL-ENROLLMENT"],"reasons":["assurance-reciprocal-proof-invalid"]},"assurance/succession-authority-invalid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-authority-invalid"]},"assurance/succession-head-mismatch":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-head-mismatch"]},"assurance/succession-new-key-acceptance-invalid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-new-key-acceptance-invalid"]},"assurance/succession-predecessor-mismatch":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-predecessor-mismatch"]},"assurance/succession-schema-invalid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-schema-invalid"]},"assurance/succession-valid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-NO-IMPLICIT-CONTINUATION","ASSURANCE-I-SUCCESSION-NON-ALIASING","ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":[]},"assurance/succession-witness-threshold-unsatisfied":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-witness-threshold-unsatisfied"]},"assurance/dual-consent-downgrade-accepted":{"boundary_id":"assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade","invariants":["ASSURANCE-I-PIN-DOWNGRADE"],"reasons":[],"postcondition":"assurance-dual-proof-downgrade"},"assurance/unilateral-downgrade-rejected":{"boundary_id":"assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade","invariants":["ASSURANCE-I-PIN-DOWNGRADE"],"reasons":["assurance-downgrade-consent-required"],"postcondition":"assurance-dual-proof-downgrade"},"assurance/witness-threshold-fail":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-pending-window"],"postcondition":"assurance-authoritative-observation"},"assurance/witness-threshold-pass":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"comms/agent-attribution-encrypted-inner":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/agent-attribution-invalid":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION"],"reasons":["agent-attribution-invalid"]},"comms/agent-attribution-profile-unavailable":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION"],"reasons":["agent-attribution-profile-unavailable"]},"comms/agent-persona-scope-required":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION"],"reasons":["agent-persona-scope-required"]},"comms/agent-sender-proof-invalid":{"boundary_id":"agent-authorship.validateAgentAccessToken","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-sender-proof-invalid"]},"comms/agent-signer-mismatch":{"boundary_id":"agent-authorship.validateAgentAccessToken","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-signer-mismatch"]},"comms/agent-token-invalid":{"boundary_id":"agent-authorship.validateAgentAccessToken","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-token-invalid"]},"comms/agent-workload-registration-invalid":{"boundary_id":"agent-authorship.validateWorkloadRegistration","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-workload-registration-invalid"]},"comms/agent-workload-token-accepted":{"boundary_id":"agent-authorship.validateWorkloadRegistration+validateAgentAccessToken","invariants":["COMMS-I-AGENT-SIGNER-BINDING","COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":[]},"comms/authorization-view-300-boundary":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":[]},"comms/authorization-view-86400-boundary":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":[]},"comms/authorization-view-maximum-malformed":{"boundary_id":"schema.validateOidcContinuityManifestSchemaOrThrow","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":["claim-schema-invalid"]},"comms/checkpoint-exact-boundary":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":[]},"comms/checkpoint-stale-independent":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":["oidc-checkpoint-stale"]},"comms/claim-active-authenticated":{"boundary_id":"claim-authorization.authorizeClaimEffect","invariants":["COMMS-I-CLAIM-ATTENUATION","COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[],"postcondition":"claim-artifact-durable-effect"},"comms/claim-attenuation-violation":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-attenuation-violation"]},"comms/claim-chain-cycle":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-chain-cycle"]},"comms/claim-chain-depth-exceeded":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-chain-depth-exceeded"]},"comms/claim-delegation-not-authorized":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-delegation-not-authorized"]},"comms/claim-event-signature-invalid":{"boundary_id":"claims.verifyClaimEnvelope","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-event-signature-invalid"]},"comms/claim-expired":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-expired"]},"comms/claim-id-mismatch":{"boundary_id":"claims.validateClaimId","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-id-mismatch"]},"comms/claim-issuer-authority-invalid":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-issuer-authority-invalid"]},"comms/claim-issuer-untrusted":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-issuer-untrusted"]},"comms/claim-key-reference-invalid":{"boundary_id":"claims.validateKeyRef","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-key-reference-invalid"]},"comms/claim-ledger-rollback":{"boundary_id":"claim-ledger.mergeClaimLedger","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-ledger-rollback"]},"comms/claim-ledger-writer-unauthorized":{"boundary_id":"claim-ledger.mergeClaimLedger","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-ledger-writer-unauthorized"],"postcondition":"ledger-current-writer-rejection"},"comms/claim-repository-conflict":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-repository-conflict"]},"comms/claim-repository-unconfirmed":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-repository-unconfirmed"]},"comms/claim-revoked":{"boundary_id":"claims.verifyClaimRevocationEnvelope+claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":["claim-revoked"]},"comms/claim-revoker-unauthorized":{"boundary_id":"claim-ledger.validateLedgerRecordOrThrow","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":["claim-revoker-unauthorized"]},"comms/claim-subject-proof-invalid":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-subject-proof-invalid"]},"comms/claim-subject-proof-required":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-subject-proof-required"]},"comms/config-private-state-encrypted":{"boundary_id":"privacy-crypto.deriveConfigPostKey+nostr-tools.nip44","invariants":["COMMS-I-CONFIG-AT-REST","COMMS-I-TIER2-HONESTY"],"reasons":[]},"comms/conversation-rejected":{"boundary_id":"marmot-admission.ordinaryConversationAdmission","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["conversation-rejected"]},"comms/invite-already-reserved":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-already-reserved"]},"comms/invite-authentication-invalid":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-authentication-invalid"]},"comms/invite-expired":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-expired"]},"comms/invite-purpose-mismatch":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-purpose-mismatch"]},"comms/ledger-reader-authorized":{"boundary_id":"claim-ledger.mergeClaimLedger+evaluateReaderAccess","invariants":["COMMS-I-CLAIM-REVOCATION","COMMS-I-LEDGER-CONFINEMENT"],"reasons":[],"postcondition":"ledger-current-writer-durable-effect"},"comms/ledger-reader-unauthorized":{"boundary_id":"claim-ledger.evaluateReaderAccess","invariants":["COMMS-I-LEDGER-CONFINEMENT"],"reasons":["claim-ledger-reader-unauthorized"]},"comms/marmot-agent-scope-denied":{"boundary_id":"comms-policy.evaluateMarmotInboxBootstrap","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-agent-scope-denied"]},"comms/marmot-exact-bytes-durable":{"boundary_id":"marmot-routing-policy.evaluateMarmotDurability","invariants":["COMMS-I-MARMOT-EXACT-BYTES"],"reasons":[]},"comms/marmot-expiration-not-erasure":{"boundary_id":"marmot-routing-policy.evaluateMarmotRetention","invariants":["COMMS-I-RADICLE-NON-ERASURE"],"reasons":[]},"comms/marmot-keypackage-replayed":{"boundary_id":"comms-policy.evaluateMarmotInboxBootstrap","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-keypackage-replayed"]},"comms/marmot-ordinary-welcome-held":{"boundary_id":"marmot-admission.ordinaryConversationAdmission","invariants":["COMMS-I-MARMOT-ACCOUNT-IDENTITY","COMMS-I-MARMOT-SECRET-CONFINEMENT","COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":[]},"comms/marmot-premature-ack":{"boundary_id":"marmot-routing-policy.evaluateMarmotDurability","invariants":["COMMS-I-MARMOT-EXACT-BYTES"],"reasons":["marmot-premature-ack"]},"comms/marmot-private-inbox-nid-required":{"boundary_id":"comms-policy.evaluateMarmotInboxBootstrap","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-private-inbox-nid-required"]},"comms/marmot-private-route-required":{"boundary_id":"current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-private-route-required"]},"comms/marmot-routing-binding-valid":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":[]},"comms/marmot-routing-equivocation":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":["marmot-routing-equivocation"]},"comms/marmot-routing-genesis-mismatch":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":["marmot-routing-binding-invalid"]},"comms/marmot-unauthorized-ref":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":["marmot-unauthorized-ref"]},"comms/nip59-broadcast-rejected":{"boundary_id":"comms-policy.validatePrivateBroadcast","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["nip59_broadcast_rejected"]},"comms/oidc-access-token-validated":{"boundary_id":"oidc.projectAccessToken+validateProjectedJwt","invariants":["COMMS-I-JWT-TYPE-AUDIENCE","COMMS-I-STATUS-INTEGRITY"],"reasons":[]},"comms/oidc-audience-invalid":{"boundary_id":"oidc.validateProjectedJwt","invariants":["COMMS-I-JWT-TYPE-AUDIENCE"],"reasons":["oidc-audience-invalid"]},"comms/oidc-claim-release":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE","COMMS-I-ISSUER-KEY-CONFINEMENT"],"reasons":[]},"comms/oidc-claim-release-denied":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-claim-release-denied"]},"comms/oidc-client-unregistered":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-client-unregistered"]},"comms/oidc-consent-required":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-consent-required"]},"comms/oidc-grant-prohibited":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-grant-prohibited"]},"comms/oidc-issuer-authority-invalid":{"boundary_id":"claim-ledger.canMint","invariants":["COMMS-I-ISSUER-KEY-CONFINEMENT"],"reasons":["oidc-issuer-authority-invalid"]},"comms/oidc-issuer-mismatch":{"boundary_id":"oidc.validateIssuerMetadata","invariants":["COMMS-I-ISSUER-CONTINUITY"],"reasons":["oidc-issuer-mismatch"]},"comms/oidc-issuer-persona-continuity":{"boundary_id":"oidc.validateIssuerMetadata","invariants":["COMMS-I-ISSUER-CONTINUITY"],"reasons":[]},"comms/oidc-signing-key-unavailable":{"boundary_id":"claim-ledger.canMint","invariants":["COMMS-I-ISSUER-KEY-CONFINEMENT"],"reasons":["oidc-signing-key-unavailable"]},"comms/oidc-status-invalid":{"boundary_id":"token-status.encodeStatusList","invariants":["COMMS-I-STATUS-INTEGRITY"],"reasons":["oidc-status-invalid"]},"comms/oidc-token-type-invalid":{"boundary_id":"oidc.validateProjectedJwt","invariants":["COMMS-I-JWT-TYPE-AUDIENCE"],"reasons":["oidc-token-type-invalid"]},"comms/profile-heterodyne-comms-agent-attribution-kind-1-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-1063-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-16-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-1985-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-30023-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-4550-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-6-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-7-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-claim-revocation-jwk-jws-v1":{"boundary_id":"current-revocation.evaluateCurrentRevocationProfile","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":[]},"comms/profile-heterodyne-comms-claim-revocation-nostr-bip340-v1":{"boundary_id":"current-revocation.evaluateCurrentRevocationProfile","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":[]},"comms/profile-heterodyne-comms-claim-revocation-radicle-ed25519-v1":{"boundary_id":"current-revocation.evaluateCurrentRevocationProfile","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":[]},"comms/profile-heterodyne-comms-key-claim-jwk-jws-v1":{"boundary_id":"profile-negotiation.verifyCurrentClaimProofProfile","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[]},"comms/profile-heterodyne-comms-key-claim-nostr-bip340-v1":{"boundary_id":"profile-negotiation.verifyCurrentClaimProofProfile","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[]},"comms/profile-heterodyne-comms-key-claim-radicle-ed25519-v1":{"boundary_id":"profile-negotiation.verifyCurrentClaimProofProfile","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1063-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-16-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-30023-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-30402-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-6-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/public-reader-private-content":{"boundary_id":"comms-policy.validatePublicReaderRendering","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":["public-reader-private-content"]},"comms/public-reader-private-tier":{"boundary_id":"public-reader.resolvePublicAsset","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":[]},"comms/public-reader-relay-hint-invalid":{"boundary_id":"public-reader.validateBootstrapRelay","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":["public-reader-relay-hint-invalid"]},"comms/public-reader-route-invalid":{"boundary_id":"public-reader.parseLauncherFragment","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":["public-reader-route-invalid"]},"comms/tier3-client-side-encryption":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44","invariants":["COMMS-I-CLIENT-SIDE-DELIVERY","COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY","COMMS-I-TIER3-BLIND-CARRIER"],"reasons":[]},"comms/tier3-recipient-confined":{"boundary_id":"follow-up-hardening.resolveTier3Recipients","invariants":["COMMS-I-TIER3-CONFINED"],"reasons":["tier3-recipient-not-active-device"]},"comms/trusted-seed-acl-ambiguous":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-ambiguous"]},"comms/trusted-seed-acl-conflict":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-conflict"]},"comms/trusted-seed-acl-expired":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-expired"]},"comms/trusted-seed-acl-invalid":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-invalid"]},"comms/trusted-seed-acl-missing":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-missing"]},"comms/trusted-seed-acl-stale":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-stale"]},"comms/trusted-seed-event-invalid":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-event-invalid"]},"comms/trusted-seed-exact-write":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-MARMOT-EXACT-BYTES","COMMS-I-PRIVATE-RELAY-ACL","COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":[]},"comms/trusted-seed-nip42-required":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-nip42-required"]},"comms/trusted-seed-request-invalid":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-request-invalid"]},"comms/trusted-seed-request-replay":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-request-replay"]},"comms/trusted-seed-revoked":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-revoked"]},"comms/trusted-seed-route-mismatch":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-route-mismatch"]},"comms/trusted-seed-unauthorized":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-unauthorized"]},"control/activation-binding-mismatch":{"boundary_id":"control-signing.consumeNip46ConnectionSecret","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-activation-binding-mismatch"]},"control/agent-intent-invalid":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-agent-intent-invalid"]},"control/agent-rate-limited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["agent-rate-limited"]},"control/agent-size-exceeded":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["agent-size-exceeded"]},"control/attribution-binding-mismatch":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-attribution-binding-mismatch"]},"control/attribution-required":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-attribution-required"]},"control/authorization-view-stale-at-effect":{"boundary_id":"authorization-freshness.revalidateAuthorizationViewAtEffect","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-authorization-view-stale"]},"control/automation-attributed-before-signing":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING","CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":[]},"control/caller-freshness-booleans-rejected":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-authorization-view-stale"]},"control/client-metadata-widening":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-CLIENT-KEY-CONFINEMENT"],"reasons":["control-client-metadata-widening"]},"control/compromise-reset-closure-required":{"boundary_id":"control-signing.validateCompromiseReset","invariants":["CONTROL-I-COMPROMISE-RESET","CONTROL-I-MARMOT-LEAF-COMPROMISE"],"reasons":["control-compromise-reset-incomplete"]},"control/compromise-reset-evidence-invalid":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-compromise-reset-evidence-invalid"]},"control/compromise-reset-inventory-mismatch":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-compromise-reset-inventory-mismatch"]},"control/compromise-reset-unauthenticated":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-compromise-reset-unauthenticated"]},"control/connection-secret-invalid":{"boundary_id":"control-signing.consumeNip46ConnectionSecret","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-connection-secret-invalid"]},"control/connection-secret-reused":{"boundary_id":"control-signing.consumeNip46ConnectionSecret","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-connection-secret-reused"]},"control/device-code-display-mismatch":{"boundary_id":"control-policy.evaluateDeviceCodeBoundary","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-device-code-display-mismatch"]},"control/device-code-invalid":{"boundary_id":"control-policy.evaluateDeviceCodeBoundary","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-device-code-invalid"]},"control/device-code-rate-limited":{"boundary_id":"control-policy.evaluateDeviceCodeBoundary","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-device-code-rate-limited"]},"control/enrollment-rate-limited":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-enrollment-rate-limited"]},"control/enrollment-required":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-enrollment-required"]},"control/enrollment-unavailable":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-enrollment-unavailable"]},"control/entitlement-conflict":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-entitlement-conflict"]},"control/exact-signer-grant-reserved":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-AUDIT-AT-REST","CONTROL-I-BASELINE-ACTIVE-KEY","CONTROL-I-CLIENT-KEY-CONFINEMENT","CONTROL-I-EXACT-SIGNER-GRANT","CONTROL-I-NO-SIGNER-FALLBACK","CONTROL-I-OPERATION-AT-MOST-ONCE","CONTROL-I-PERSONA-VAULT-ISOLATION"],"reasons":[]},"control/frame-invalid":{"boundary_id":"control-policy.validateControlFrameBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-frame-invalid"]},"control/invite-preauthorization-invalid":{"boundary_id":"control-policy.validateInvitePreauthorizationBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["invite-preauthorization-invalid"]},"control/keypackage-invalid":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-keypackage-invalid"]},"control/keypackage-replenishment-paused":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-keypackage-replenishment-paused"]},"control/nip46-request-invalid":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-nip46-request-invalid"]},"control/opaque-authorization-view-accepted":{"boundary_id":"authorization-freshness.revalidateAuthorizationViewAtEffect","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":[]},"control/operation-conflict":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-conflict"]},"control/operation-execution-fence-required":{"boundary_id":"control-signing.executePersistedAutomatedSigning","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-execution-fence-required"]},"control/operation-indeterminate":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-indeterminate"]},"control/operation-reservation-required":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-reservation-required"]},"control/persona-authority-required":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-BASELINE-ACTIVE-KEY"],"reasons":["control-persona-authority-required"]},"control/profile-heterodyne-control-marmot-frame-v1":{"boundary_id":"profile-negotiation.validateCurrentControlGrantProfile","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":[]},"control/refresh-prohibited":{"boundary_id":"control-policy.validateControlFrameBoundary","invariants":["CONTROL-I-CLIENT-KEY-CONFINEMENT"],"reasons":["control-refresh-prohibited"]},"control/request-expired":{"boundary_id":"control-policy.evaluateControlOperationRequest","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-request-expired"]},"control/signer-binding-mismatch":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signer-binding-mismatch"]},"control/signer-effect-indeterminate":{"boundary_id":"control-policy.validateControlSignedEffect","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-signer-effect-indeterminate"]},"control/signer-unavailable":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-NO-SIGNER-FALLBACK"],"reasons":["control-signer-unavailable"]},"control/signing-grant-inactive":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-inactive"]},"control/signing-grant-invalid":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-invalid"]},"control/signing-grant-stale":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-stale"]},"control/signing-grant-unauthenticated":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-unauthenticated"]},"control/signing-rate-limited":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-signing-rate-limited"]},"control/subordinate-reauthorization-required":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-subordinate-reauthorization-required"]},"control/token-invalid":{"boundary_id":"control-policy.validateControlFrameBoundary","invariants":["CONTROL-I-CLIENT-KEY-CONFINEMENT"],"reasons":["control-token-invalid"]},"control/usage-binding-mismatch":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-usage-binding-mismatch"]},"control/vault-isolation-failed":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-PERSONA-VAULT-ISOLATION"],"reasons":["control-vault-isolation-failed"]},"core/config-rid-published":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["config_rid_advertised"]},"core/friend-cache-unsigned":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["unauthorized_cache_content"]},"core/nip01-raw-mismatch":{"boundary_id":"core-policy.validateCoreWireEnvelope","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["nip01_raw_mismatch"]},"core/nip49-key-material-round-trip":{"boundary_id":"backup-crypto.nip49EncryptDeterministic+nostr-tools.nip49.decrypt","invariants":["CORE-I-KEY-MATERIAL-AT-REST"],"reasons":[]},"core/node-advert-bad-signature":{"boundary_id":"radicle.validateNodeAdvertisement","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["bad_signature"]},"core/node-advert-clock-skew":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-clock-skew"]},"core/node-advert-clock-uncertain":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-clock-uncertain"]},"core/node-advert-dual-proof-valid":{"boundary_id":"radicle.validateNodeAdvertisement","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":[]},"core/node-advert-expired":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node_advert_expired"]},"core/node-advert-expiry-invalid":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-expiry-invalid"]},"core/node-advert-lifetime-exceeded":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-lifetime-exceeded"]},"core/node-advert-nid-proof-invalid":{"boundary_id":"radicle.validateNodeAdvertisement","invariants":[],"reasons":["nid_proof_invalid"]},"core/onion-clearnet-resolution":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["onion_dns_leak"]},"core/profile-heterodyne-core-rotation-breadcrumb-note-v1":{"boundary_id":"core-policy.validateCorePersonaSignedEvent","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":[]},"core/profile-heterodyne-core-rotation-breadcrumb-profile-v1":{"boundary_id":"core-policy.validateCorePersonaSignedEvent","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":[]},"core/profile-nip05-key-mismatch":{"boundary_id":"follow-up-hardening.validateCanonicalProfile","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["profile-nip05-key-mismatch"]},"core/profile-publisher-delegation-invalid":{"boundary_id":"follow-up-hardening.validateCanonicalProfile","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["profile-publisher-delegation-invalid"]},"core/profile-repository-selection-required":{"boundary_id":"follow-up-hardening.validateCanonicalProfile","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["profile-repository-selection-required"]},"core/relay-profile-mutated":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["relay_profile_mutation"]},"core/replaceable-advisory-nip03-ignored":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":[]},"core/replaceable-at-premature-boundary":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":[]},"core/replaceable-equal-time-lowest-id":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":[]},"core/replaceable-future-quarantined":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["core-created-at-premature"]},"core/strict-mode-without-tor":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["strict_mode_tor_disabled"]},"core/version-future-major":{"boundary_id":"core-policy.validateCoreWireEnvelope","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["unknown_major_version"]},"core/version-stamp-missing":{"boundary_id":"core-policy.validateCoreWireEnvelope","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["version_stamp_invalid"]},"social/agent-attribution-falsified":{"boundary_id":"social-policy.evaluateAgentModerationEvidence","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT"],"reasons":["agent-attribution-falsified"]},"social/agent-attribution-missing":{"boundary_id":"social-policy.evaluateAgentModerationEvidence","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT"],"reasons":["agent-attribution-missing"]},"social/agent-policy-binding-invalid":{"boundary_id":"agent-moderation.validateAgentPolicyList","invariants":["SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":["agent-policy-binding-invalid"]},"social/agent-policy-receipt-invalid":{"boundary_id":"agent-moderation.validateAgentPolicyReceipt","invariants":["SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":["agent-policy-receipt-invalid"]},"social/agent-publication-bypass":{"boundary_id":"social-policy.evaluateAgentModerationEvidence","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT"],"reasons":["agent-publication-bypass"]},"social/author-binding-invalid":{"boundary_id":"social-events.validateSocialAuthorship","invariants":["SOCIAL-I-NIP01-AUTHORSHIP"],"reasons":["social-author-binding-invalid"]},"social/event-invalid":{"boundary_id":"social-events.validateSocialAuthorship","invariants":["SOCIAL-I-NIP01-AUTHORSHIP"],"reasons":["social-event-invalid"]},"social/moderator-not-in-asof-declaration":{"boundary_id":"social-policy.evaluateModeratorAsOfDeclaration","invariants":["SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":["moderator_not_in_asof_declaration"]},"social/profile-heterodyne-social-agent-policy-list-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT","SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":[]},"social/profile-heterodyne-social-agent-policy-receipt-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT","SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":[]},"social/profile-heterodyne-social-mute-list-v1":{"boundary_id":"privacy-crypto.deriveConfigPostKey+nostr-tools.nip44","invariants":["SOCIAL-I-PRIVATE-STATE-AT-REST"],"reasons":[]},"social/replaceable-coordinate-mismatch":{"boundary_id":"social-events.validateSocialReplaceableCandidate","invariants":["SOCIAL-I-SOURCE-NEUTRAL-SELECTION"],"reasons":["social-replaceable-coordinate-mismatch"]},"social/source-neutral-core-quarantine":{"boundary_id":"social-events.selectCurrentSocialEvent","invariants":["SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH","SOCIAL-I-SOURCE-NEUTRAL-SELECTION"],"reasons":[]},"social/source-neutral-vanilla-authorship":{"boundary_id":"social-events.validateSocialAuthorship","invariants":["SOCIAL-I-NIP01-AUTHORSHIP"],"reasons":[]},"workspace/affiliation-stale":{"boundary_id":"workspace-policy.evaluateWorkspaceAffiliationBoundary","invariants":["WORKSPACE-I-FRESHNESS-BOUNDED"],"reasons":["affiliation_stale"]},"workspace/assurance-dual-removal":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":[]},"workspace/assurance-history-mutation-revalidated":{"boundary_id":"workspace-assurance.verifyWorkspaceAssuranceAuthorization","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":["workspace-assurance-state-required"]},"workspace/assurance-pending-activation":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":["workspace-assurance-state-required"]},"workspace/assurance-unilateral-removal":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":["workspace-assurance-state-required"]},"workspace/assurance-verified-activation":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":[]},"workspace/authority-checkpoint-stale":{"boundary_id":"workspace.evaluateFreshness","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE","WORKSPACE-I-FRESHNESS-BOUNDED"],"reasons":["checkpoint_stale"]},"workspace/authority-conflict":{"boundary_id":"workspace.evaluateWorkspaceObject","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["authority_conflict"]},"workspace/authority-freshness-boundary":{"boundary_id":"workspace.evaluateFreshness","invariants":["WORKSPACE-I-FRESHNESS-BOUNDED"],"reasons":[]},"workspace/bare-key-baseline":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":[]},"workspace/carrier-not-ambient-authority":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-CARRIER-NOT-AUTHORITY","WORKSPACE-I-NO-AMBIENT-AUTHORITY"],"reasons":["policy_denied"]},"workspace/current-capability-intersection":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE","WORKSPACE-I-INHERITANCE-NARROWS","WORKSPACE-I-NO-AMBIENT-AUTHORITY"],"reasons":[]},"workspace/device-revoked":{"boundary_id":"workspace.evaluateRoleLeafChange","invariants":["WORKSPACE-I-DEVICE-LEAF-SEPARATION"],"reasons":["device_revoked"]},"workspace/history-denied":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceDeliveryBoundary","invariants":["WORKSPACE-I-REVOCATION-FUTURE-ONLY"],"reasons":["history_denied"]},"workspace/host-unauthorized":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceDeliveryBoundary","invariants":["WORKSPACE-I-HOST-AUTHORITY-SEPARATION"],"reasons":["host_unauthorized"]},"workspace/independent-device-leaf-removal":{"boundary_id":"workspace.evaluateRoleLeafChange","invariants":["WORKSPACE-I-DEVICE-LEAF-SEPARATION","WORKSPACE-I-REVOCATION-FUTURE-ONLY"],"reasons":[]},"workspace/independent-resource-content-keys":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceKeySeparation","invariants":["WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS"],"reasons":[]},"workspace/inheritance-escalation-rejected":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-INHERITANCE-NARROWS"],"reasons":["capability_escalation"]},"workspace/invitation-replay":{"boundary_id":"workspace-policy.evaluateWorkspaceStateTransitionBoundary","invariants":["WORKSPACE-I-NO-AMBIENT-AUTHORITY"],"reasons":["workspace_replay"]},"workspace/private-topology-clean":{"boundary_id":"workspace.evaluatePrivateProjection","invariants":["WORKSPACE-I-PRIVATE-TOPOLOGY"],"reasons":[]},"workspace/private-topology-disclosed":{"boundary_id":"workspace.evaluatePrivateProjection","invariants":["WORKSPACE-I-PRIVATE-TOPOLOGY"],"reasons":["private_topology_disclosed"]},"workspace/radicle-backed-hosts":{"boundary_id":"workspace.resolveEffectiveHosts","invariants":["WORKSPACE-I-HOST-AUTHORITY-SEPARATION","WORKSPACE-I-RADICLE-BACKSTOP"],"reasons":[]},"workspace/repository-invalid":{"boundary_id":"workspace.authenticateWorkspaceRepositoryView","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["workspace_repository_invalid"]},"workspace/resource-unknown":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceDeliveryBoundary","invariants":["WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS"],"reasons":["resource_unknown"]},"workspace/revocation-blocks-future-effect":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-REVOCATION-FUTURE-ONLY"],"reasons":["policy_denied"]},"workspace/schema-invalid":{"boundary_id":"workspace.evaluateFreshness","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["workspace_schema_invalid"]},"workspace/signature-invalid":{"boundary_id":"workspace.evaluateWorkspaceObject","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["workspace_signature_invalid"],"postcondition":"workspace-signed-object-rejected"}} as const satisfies Readonly<Record<string, SemanticAllocationSource>>;

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
} as const satisfies Readonly<Record<string, SemanticAllocationSource>>;

const TASK_FIFTEEN_SEMANTIC_BOUNDARIES: Readonly<Record<string, Readonly<{
  boundary_id: string;
  postcondition: string;
}>>> = Object.freeze({
  "comms/agent-sender-proof-invalid": { boundary_id: "agent-publication-authorization.authorizeAndSignAgentPublication", postcondition: "task15-agent-publication" },
  "comms/agent-workload-token-accepted": { boundary_id: "agent-publication-authorization.authorizeAndSignAgentPublication", postcondition: "task15-agent-publication" },
  "comms/conversation-rejected": { boundary_id: "marmot-admission-authority.verifyMarmotWelcome+admitOrdinaryMarmotWelcome", postcondition: "task15-marmot-admission" },
  "comms/invite-authentication-invalid": { boundary_id: "one-time-invite-authority.redeemOneTimeInvite", postcondition: "task15-one-time-invite" },
  "comms/marmot-agent-scope-denied": { boundary_id: "persona-inbox-admission-authority.admitPersonaInboxBundle", postcondition: "task15-persona-inbox" },
  "comms/marmot-exact-bytes-durable": { boundary_id: "marmot-archive-retention-authority.appendExactMarmotArchive", postcondition: "task15-marmot-archive" },
  "comms/marmot-expiration-not-erasure": { boundary_id: "marmot-archive-retention-authority.appendExactMarmotArchive+expireMarmotPresentation+acknowledgeMarmotArchive", postcondition: "task15-marmot-archive" },
  "comms/marmot-keypackage-replayed": { boundary_id: "persona-inbox-admission-authority.admitPersonaInboxBundle", postcondition: "task15-persona-inbox" },
  "comms/marmot-ordinary-welcome-held": { boundary_id: "marmot-admission-authority.verifyMarmotWelcome+admitOrdinaryMarmotWelcome", postcondition: "task15-marmot-admission" },
  "comms/marmot-premature-ack": { boundary_id: "marmot-archive-retention-authority.acknowledgeMarmotArchive", postcondition: "task15-marmot-archive" },
  "comms/marmot-private-inbox-nid-required": { boundary_id: "persona-inbox-admission-authority.admitPersonaInboxBundle", postcondition: "task15-persona-inbox" },
  "control/compromise-reset-evidence-invalid": { boundary_id: "control-signing.validateCompromiseReset", postcondition: "task15-control-reset" },
  "control/compromise-reset-inventory-mismatch": { boundary_id: "control-signing.validateCompromiseReset", postcondition: "task15-control-reset" },
  "control/compromise-reset-unauthenticated": { boundary_id: "control-signing.validateCompromiseReset", postcondition: "task15-control-reset" },
  "control/subordinate-reauthorization-required": { boundary_id: "control-signing.validateCompromiseReset", postcondition: "task15-control-reset" },
  "control/device-code-display-mismatch": { boundary_id: "control-device-authorization.createControlDeviceTransaction+pollControlDeviceAuthorization", postcondition: "task15-control-device" },
  "control/device-code-invalid": { boundary_id: "control-device-authorization.createControlDeviceTransaction+pollControlDeviceAuthorization", postcondition: "task15-control-device" },
  "control/device-code-rate-limited": { boundary_id: "control-device-authorization.createControlDeviceTransaction+pollControlDeviceAuthorization", postcondition: "task15-control-device" },
  "control/enrollment-unavailable": { boundary_id: "control-enrollment-admission.admitControlEnrollment", postcondition: "task15-control-enrollment" },
  "control/frame-invalid": { boundary_id: "profile-negotiation.validateCurrentControlFrameProfile", postcondition: "task15-control-frame" },
  "control/invite-preauthorization-invalid": { boundary_id: "control-invite-preauthorization.verifyControlInvitePreauthorization", postcondition: "task15-control-invite" },
  "control/keypackage-invalid": { boundary_id: "control-enrollment-admission.admitControlEnrollment", postcondition: "task15-control-enrollment" },
  "control/keypackage-replenishment-paused": { boundary_id: "control-enrollment-admission.admitControlEnrollment", postcondition: "task15-control-enrollment" },
  "control/signer-effect-indeterminate": { boundary_id: "control-signing.executePersistedAutomatedSigning+executePersistedAutomatedSigning", postcondition: "task15-control-signer" },
  "control/token-invalid": { boundary_id: "control-token-verifier.verifyControlToken+consumeVerifiedControlToken", postcondition: "task15-control-token" },
  "core/friend-cache-unsigned": { boundary_id: "core-operational-assurance-authority.verifyCacheCandidate", postcondition: "task15-core-operational" },
  "core/profile-repository-selection-required": { boundary_id: "canonical-profile-selection-authority.selectCanonicalProfile", postcondition: "task15-canonical-profile" },
  "core/relay-profile-mutated": { boundary_id: "core-operational-assurance-authority.verifyRelayProfileCarrier", postcondition: "task15-core-operational" },
  "core/strict-mode-without-tor": { boundary_id: "core-operational-assurance-authority.verifyStrictTransport", postcondition: "task15-core-operational" },
  "workspace/carrier-not-ambient-authority": { boundary_id: "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization", postcondition: "task15-workspace-authority" },
  "workspace/current-capability-intersection": { boundary_id: "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+consumeWorkspaceInvitationAcceptance+evaluateGrantActivation", postcondition: "task15-workspace-authority" },
  "workspace/inheritance-escalation-rejected": { boundary_id: "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization", postcondition: "task15-workspace-authority" },
  "workspace/invitation-replay": { boundary_id: "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+consumeWorkspaceInvitationAcceptance+evaluateGrantActivation+consumeWorkspaceInvitationAcceptance", postcondition: "task15-workspace-authority" },
  "workspace/revocation-blocks-future-effect": { boundary_id: "workspace.authenticateWorkspaceRepositoryView+resolveWorkspaceEffectiveAuthorization+evaluateGrantActivation", postcondition: "task15-workspace-authority" },
  "social/profile-heterodyne-social-agent-policy-list-v1": { boundary_id: "social-subscription-authority.resolveSubscribedAgentPolicy+applySubscribedAgentPolicy", postcondition: "task15-social-subscription" },
  "social/profile-heterodyne-social-agent-policy-receipt-v1": { boundary_id: "social-subscription-authority.resolveSubscribedAgentPolicy+applySubscribedAgentPolicy", postcondition: "task15-social-subscription" },
});

const ALL_SEMANTIC_ALLOCATIONS: Readonly<Record<string, SemanticAllocation>> =
  Object.freeze(Object.fromEntries(
    Object.entries({ ...SEMANTIC_ALLOCATIONS, ...TASK_TEN_SEMANTIC_ALLOCATIONS })
      .map(([vectorId, source]) => {
        const replacement = TASK_FIFTEEN_SEMANTIC_BOUNDARIES[vectorId];
        return [vectorId, Object.freeze({
          ...source,
          ...(replacement ?? {
            postcondition: "postcondition" in source
              ? source.postcondition
              : `semantic:${source.boundary_id}`,
          }),
        })];
      }),
  ));

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

function exactKeys(value: Readonly<Record<string, unknown>>, expected: readonly string[]): boolean {
  return sameStrings(Reflect.ownKeys(value).map(String).sort(), [...expected].sort());
}

function verifiesNip01Event(value: unknown): boolean {
  const event = record(value);
  if (
    event === undefined
    || typeof event.pubkey !== "string"
    || typeof event.created_at !== "number"
    || typeof event.kind !== "number"
    || !Array.isArray(event.tags)
    || typeof event.content !== "string"
    || typeof event.id !== "string"
    || typeof event.sig !== "string"
  ) return false;
  const digest = sha256(utf8Bytes(JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ])));
  try {
    return event.id === Buffer.from(digest).toString("hex")
      && schnorr.verify(event.sig, digest, event.pubkey);
  } catch {
    return false;
  }
}

function assuranceEnrollmentSemanticProof(
  fixture: CurrentCaseFixture,
  raw: Readonly<Record<string, unknown>> | undefined,
  projected: Readonly<Record<string, unknown>> | undefined,
): boolean {
  const inception = record(fixture.input.inception);
  const acceptance = record(fixture.input.acceptance);
  const normalized = record(raw?.normalized);
  if (inception === undefined || acceptance === undefined || raw === undefined || projected === undefined) {
    return false;
  }
  if (raw.verdict === "accept") {
    let inceptionBody: Readonly<Record<string, unknown>> | undefined;
    let acceptanceBody: Readonly<Record<string, unknown>> | undefined;
    try {
      inceptionBody = typeof inception.content === "string"
        ? record(JSON.parse(inception.content))
        : undefined;
      acceptanceBody = typeof acceptance.content === "string"
        ? record(JSON.parse(acceptance.content))
        : undefined;
    } catch {
      return false;
    }
    return verifiesNip01Event(inception)
      && verifiesNip01Event(acceptance)
      && normalized !== undefined
      && inceptionBody !== undefined
      && acceptanceBody !== undefined
      && normalized.active_key === inceptionBody.active_key
      && normalized.active_key === acceptance.pubkey
      && normalized.head === acceptance.id
      && normalized.inception_event_id === inception.id
      && acceptanceBody.inception_event_id === inception.id
      && acceptanceBody.assurance_head === inception.id
      && projected.normalized === raw.normalized;
  }
  return !verifiesNip01Event(inception)
    || !verifiesNip01Event(acceptance)
    || raw.reason_code === "assurance-reciprocal-proof-invalid";
}

function socialAuthorshipSemanticProof(
  fixture: CurrentCaseFixture,
  raw: Readonly<Record<string, unknown>> | undefined,
  projected: Readonly<Record<string, unknown>> | undefined,
): boolean {
  const event = record(fixture.input.event);
  if (event === undefined || raw === undefined || raw !== projected) return false;
  const eventValid = verifiesNip01Event(event);
  const represented = fixture.input.persona_active_key ?? event.pubkey;
  if (raw.verdict === "accept") {
    return eventValid
      && typeof event.pubkey === "string"
      && raw.event_author === event.pubkey
      && raw.represented_persona === represented
      && exactKeys(raw, ["event_author", "represented_persona", "verdict"]);
  }
  if (raw.reason_code === "social-event-invalid") return !eventValid;
  return raw.reason_code === "social-author-binding-invalid"
    && eventValid
    && typeof represented === "string"
    && /^[0-9a-f]{64}$/u.test(represented)
    && represented !== event.pubkey
    && !Object.hasOwn(fixture.input, "assurance_state")
    && !Object.hasOwn(fixture.input, "delegation");
}

function workspaceFreshnessSemanticProof(
  fixture: CurrentCaseFixture,
  raw: Readonly<Record<string, unknown>> | undefined,
  projected: Readonly<Record<string, unknown>> | undefined,
): boolean {
  if (raw === undefined || raw !== projected) return false;
  const input = fixture.input;
  const exactInput = exactKeys(input, ["checkpoint_age", "operation_class", "policy_max_age"]);
  const operation = input.operation_class;
  const age = input.checkpoint_age;
  const maximum = input.policy_max_age;
  const validNumbers = Number.isSafeInteger(age) && (age as number) >= 0
    && Number.isSafeInteger(maximum) && (maximum as number) >= 0;
  const protocolMaximum = operation === "ordinary" ? 86_400
    : operation === "authority" ? 300 : -1;
  if (!exactInput || !validNumbers || protocolMaximum < 0 || (maximum as number) > protocolMaximum) {
    return raw.reason_code === "workspace_schema_invalid"
      && exactKeys(raw, ["reason_code", "verdict"]);
  }
  if ((age as number) > (maximum as number)) {
    return raw.reason_code === "checkpoint_stale"
      && exactKeys(raw, ["reason_code", "verdict"]);
  }
  const normalized = record(raw.normalized);
  return raw.verdict === "accept"
    && normalized !== undefined
    && normalized.age === age
    && normalized.maximum_age === maximum
    && exactKeys(normalized, ["age", "maximum_age"]);
}

function boundaryContractPostcondition(
  boundaryId: string,
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const captured = record(execution.raw_result);
  // Profile-oracle executions preserve the real evaluator object under
  // `semantic_result`; ordinary fixtures expose that object directly.
  const raw = record(captured?.semantic_result) ?? captured;
  const projected = record(execution.projected_output);
  switch (boundaryId) {
    case "agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy": {
      const injection = record(raw?.injection);
      const policy = record(raw?.policy);
      return injection !== undefined && policy !== undefined
        && projected?.author === injection.author
        && projected?.local_policy_applied === true
        && raw?.profile_matches === true
        && policy.visible === false
        && policy.muted === true;
    }
    case "agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile": {
      const injection = record(raw?.injection);
      return injection !== undefined
        && raw?.profile_matches === true
        && projected?.author === injection.author
        && projected?.placement === injection.placement;
    }
    case "agent-authorship.injectAgentAttribution":
      return raw === projected && raw !== undefined
        && (Array.isArray(raw.tags) || typeof raw.reason_code === "string");
    case "agent-authorship.validateAgentAccessToken":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "agent-authorship.validateWorkloadRegistration+validateAgentAccessToken": {
      const registration = record(raw?.registration);
      const token = record(raw?.token);
      return registration !== undefined && token !== undefined
        && projected?.identity === token.identity;
    }
    case "agent-authorship.validateWorkloadRegistration":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "agent-moderation.validateAgentPolicyList":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "agent-moderation.validateAgentPolicyReceipt":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "assurance-observation.evaluateEnrollmentEligibility":
      return raw !== undefined && projected !== undefined
        && record(raw.normalized) !== undefined
        && projected.assurance_head === record(raw.normalized)?.head
        && projected.state === raw.state
        && projected.warnings === raw.warnings;
    case "assurance-policy.evaluateAssuranceAssociatedKeyConsent":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "assurance-policy.evaluateAssuranceCompromiseContinuation":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "assurance-policy.evaluateAssurancePinPolicy":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "assurance-policy.validateAssuranceWireFormat":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "assurance-policy.evaluateAssuranceExport":
      return raw === projected && raw !== undefined
        && (record(raw.projection) !== undefined || typeof raw.reason_code === "string");
    case "assurance.evaluateAssociatedKey":
      return raw !== undefined && projected !== undefined
        && (record(raw.normalized) !== undefined
          ? projected.normalized === raw.normalized
          : captured === projected && typeof raw.reason_code === "string");
    case "assurance.evaluateEnrollment":
      return assuranceEnrollmentSemanticProof(fixture, raw, projected);
    case "assurance.evaluateSuccession":
      return raw !== undefined && projected !== undefined
        && (record(raw.normalized) !== undefined
          ? projected.normalized === raw.normalized
          : captured === projected && typeof raw.reason_code === "string");
    case "assurance.evaluateAssuranceAuthorityAt":
      return raw === projected && raw !== undefined
        && fixture.input.compromise_cutoff !== null
        && typeof fixture.input.compromise_cutoff === "number"
        && typeof fixture.input.created_at === "number"
        && fixture.input.created_at >= fixture.input.compromise_cutoff
        && raw.reason_code === "assurance-compromise-cutoff"
        && exactKeys(raw, ["reason_code", "verdict"]);
    case "authorization-freshness.evaluateAuthorizationFreshness": {
      const view = record(raw?.view);
      return raw !== undefined && projected !== undefined
        && (view !== undefined
          ? raw.verdict === "accept"
            && exactKeys(raw, ["verdict", "view"])
            && Reflect.ownKeys(view).length === 0
            && Object.isFrozen(view)
            && projected.current_authorization_view === "opaque"
          : projected.reason_code === raw.reason);
    }
    case "authorization-freshness.revalidateAuthorizationViewAtEffect":
      return raw !== undefined && projected !== undefined
        && (raw === projected
          ? raw.checkpoint === projected.checkpoint
          : projected.reason_code === raw.reason);
    case "backup-crypto.nip49EncryptDeterministic+nostr-tools.nip49.decrypt":
      return raw !== undefined && projected !== undefined
        && typeof raw.ncryptsec === "string"
        && raw.recovered_secret === fixture.input.secret_key
        && projected.ncryptsec === raw.ncryptsec
        && projected.recovered_secret === raw.recovered_secret;
    case "claim-authorization.authorizeClaimEffect+authorizeClaimEffect": {
      const second = record(raw?.second);
      return record(raw?.first) !== undefined && second !== undefined
        && execution.projected_output === raw?.second;
    }
    case "claim-authorization.authorizeClaimEffect":
      return raw !== undefined && projected !== undefined
        && (projected.authorization === execution.raw_result
          || (raw.state === projected.state && raw.reason_code === projected.reason_code));
    case "claim-authorization.inspectClaimState":
      return raw !== undefined && projected !== undefined
        && projected.evaluator_output === execution.raw_result
        && projected.reason_code === raw.reason_code;
    case "claim-ledger.canMint":
      return raw !== undefined && projected !== undefined
        && (projected.authorization === execution.raw_result
          || projected.evaluator_output === execution.raw_result);
    case "oidc.validateProjectedJwt":
      return raw !== undefined && projected !== undefined
        && (projected.authorization === execution.raw_result
          || projected.evaluator_output === execution.raw_result);
    case "claim-ledger.evaluateReaderAccess":
      return raw !== undefined && projected !== undefined
        && projected.state === raw.state && projected.reason_code === raw.reason_code;
    case "claim-ledger.mergeClaimLedger+evaluateReaderAccess":
      return raw !== undefined && projected !== undefined
        && projected.authorization === raw.authorization
        && record(raw.state) !== undefined;
    case "claim-ledger.mergeClaimLedger":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "claim-ledger.validateLedgerRecordOrThrow":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "claims.validateClaimId":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "claims.validateKeyRef":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "claims.verifyClaimEnvelope":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "schema.validateOidcContinuityManifestSchemaOrThrow":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "token-status.encodeStatusList":
      return execution.raw_result instanceof Error
        && projected !== undefined && typeof projected.reason_code === "string";
    case "claims.verifyClaimRevocationEnvelope+claim-authorization.inspectClaimState":
      return raw !== undefined && projected !== undefined
        && record(raw.revocation) !== undefined
        && projected.evaluator_output === raw.authorization;
    case "comms-policy.classifyRelayWriteFailure":
      return raw === projected && raw !== undefined
        && typeof raw.permanence === "string" && typeof raw.reason_code === "string";
    case "comms-policy.evaluateMarmotInboxBootstrap":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "comms-policy.evaluateOneTimeInvite":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "comms-policy.validateDmInviteDevice":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "comms-policy.validatePrivateBroadcast":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "comms-policy.validatePublicReaderRendering":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-policy.evaluateAutomatedControlGrant":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-policy.evaluateCompromiseResetBoundary":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-policy.evaluateControlEnrollmentBoundary":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-policy.evaluateControlOperationRequest":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-policy.evaluateDeviceCodeBoundary":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-policy.validateControlFrameBoundary":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-policy.validateControlSignedEffect":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-policy.validateInvitePreauthorizationBoundary":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-signing.authorizeNip46Signing":
      return raw === projected && raw !== undefined
        && (typeof raw.selected_signing_pubkey === "string"
          || typeof raw.reason_code === "string");
    case "control-signing.consumeNip46ConnectionSecret":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-signing.executePersistedAutomatedSigning":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-signing.validateCompromiseReset":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "control-signing.prepareAutomatedSigning":
      return raw === projected && raw !== undefined
        && (record(raw.unsigned_event) !== undefined || typeof raw.reason_code === "string");
    case "core-policy.evaluateCoreOperationalBoundary":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "core-policy.validateCoreWireEnvelope":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "core-policy.validateCorePersonaSignedEvent":
      return raw !== undefined && projected !== undefined
        && (typeof raw.event_id === "string"
          ? projected.event_id === raw.event_id
          : captured === projected && typeof raw.reason_code === "string");
    case "current-private-route.evaluateCurrentTier3PrivateRoute":
      return raw !== undefined && projected !== undefined
        && record(raw.route_evidence) !== undefined
        && raw.reason_code === projected.reason_code;
    case "current-revocation.evaluateCurrentRevocationProfile":
      return raw !== undefined && projected !== undefined
        && record(raw.revocation_evidence) !== undefined
        && projected.effect_result === record(raw.effect)?.result
        && projected.revocation_event_id === record(raw.revocation_evidence)?.verified_event_id;
    case "follow-up-hardening.classifyRetiredKeyObservation":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "follow-up-hardening.resolveTier3Recipients":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "follow-up-hardening.validateCanonicalProfile":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "follow-up-hardening.validateNodeAdvertisementTime":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "marmot-admission.ordinaryConversationAdmission":
      return raw !== undefined && projected !== undefined
        && (projected.admission === execution.raw_result
          || projected.evaluator_output === execution.raw_result);
    case "marmot-routing-policy.evaluateMarmotDurability":
      return raw === projected && raw !== undefined
        && (typeof raw.exact_bytes === "boolean" || typeof raw.reason_code === "string");
    case "marmot-routing-policy.evaluateMarmotRetention":
      return raw === projected && raw !== undefined
        && typeof raw.stop_advertising === "boolean"
        && typeof raw.stop_replication === "boolean"
        && typeof raw.erasure_guarantee === "boolean";
    case "marmot-routing-policy.evaluateMarmotRoutingBinding":
      return raw === projected && raw !== undefined
        && (record(raw.normalized) !== undefined || typeof raw.reason_code === "string");
    case "oidc.validateAuthorizationRequest":
      return raw !== undefined && projected !== undefined
        && (projected.evaluator_output === execution.raw_result
          || (projected.released_claims === raw.released_claims
            && projected.source_claim_ids === raw.source_claim_ids));
    case "oidc.validateIssuerMetadata":
      return raw !== undefined && projected !== undefined
        && (projected.evaluator_output === execution.raw_result
          || projected.authorization === execution.raw_result);
    case "privacy-crypto.deriveConfigPostKey+nostr-tools.nip44":
      return raw !== undefined && projected !== undefined
        && raw.recovered === fixture.input.plaintext
        && raw.ciphertext !== fixture.input.plaintext
        && projected.ciphertext === raw.ciphertext
        && projected.recovered_plaintext === raw.recovered;
    case "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44":
      return raw !== undefined && projected !== undefined
        && raw.recovered === fixture.input.plaintext
        && raw.ciphertext !== fixture.input.plaintext
        && projected.ciphertext === raw.ciphertext
        && projected.recovered_plaintext === raw.recovered;
    case "privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute":
      return raw !== undefined && projected !== undefined
        && record(raw.route_evidence) !== undefined
        && projected.crypto === raw.crypto
        && projected.recipients === raw.recipients
        && projected.route === raw.route;
    case "profile-negotiation.validateCurrentControlGrantProfile":
      return raw !== undefined && projected !== undefined
        && projected.grant_id === raw.grant_id
        && projected.released_secrets === raw.released_secrets;
    case "profile-negotiation.verifyCurrentClaimProofProfile":
      return raw !== undefined && projected !== undefined
        && projected.authenticated_message === raw.authenticated_message
        && projected.proof_suite === raw.proof_suite;
    case "public-reader.parseLauncherFragment":
      return raw === projected && raw !== undefined
        && typeof raw.network_activity === "boolean" && typeof raw.reason_code === "string";
    case "public-reader.resolvePublicAsset":
      return typeof execution.raw_result === "string"
        && projected?.resolution === execution.raw_result;
    case "public-reader.validateBootstrapRelay":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "radicle.validateNodeAdvertisement":
      return nodeAdvertisementCryptographicPostcondition(fixture, execution);
    case "replaceable-selection.selectCurrentReplaceableEvent": {
      const selected = record(raw?.selected);
      const quarantined = Array.isArray(raw?.quarantined) ? raw.quarantined : undefined;
      return quarantined !== undefined && projected !== undefined
        && projected.selected_event_id === (selected?.id ?? null)
        && (!Object.hasOwn(projected, "quarantined_event_ids")
          || (Array.isArray(projected.quarantined_event_ids)
            && projected.quarantined_event_ids.length === quarantined.length));
    }
    case "social-events.selectCurrentSocialEvent":
      return raw !== undefined && projected !== undefined
        && projected.selected_event_id === raw.id;
    case "social-events.validateSocialAuthorship":
      return socialAuthorshipSemanticProof(fixture, raw, projected);
    case "social-events.validateSocialReplaceableCandidate":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "social-policy.evaluateAgentModerationEvidence":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "social-policy.evaluateModeratorAsOfDeclaration":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission":
      return projected !== undefined
        && (execution.projected_output === execution.raw_result
          || execution.projected_output === raw?.second)
        && (typeof projected.acl_digest === "string" || typeof projected.reason_code === "string");
    case "workspace-assurance.evaluateWorkspaceAssuranceTransition":
      return raw === projected && raw !== undefined
        && (Object.hasOwn(raw, "authorization") || typeof raw.reason_code === "string");
    case "workspace-assurance.verifyWorkspaceAssuranceAuthorization":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "workspace-policy.evaluateWorkspaceAffiliationBoundary":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "workspace-policy.evaluateWorkspaceResourceDeliveryBoundary":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "workspace-policy.evaluateWorkspaceStateTransitionBoundary":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "workspace.authenticateWorkspaceRepositoryView":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "workspace-policy.evaluateWorkspaceCapabilityBoundary":
      return raw === projected && raw !== undefined
        && (record(raw.normalized) !== undefined || typeof raw.reason_code === "string");
    case "workspace.evaluateFreshness":
      return workspaceFreshnessSemanticProof(fixture, raw, projected);
    case "workspace.evaluatePrivateProjection":
      return raw === projected && raw !== undefined
        && (record(raw.normalized) !== undefined || typeof raw.reason_code === "string");
    case "workspace.evaluateRoleLeafChange":
      return raw === projected && raw !== undefined
        && (record(raw.normalized) !== undefined || typeof raw.reason_code === "string");
    case "workspace-policy.evaluateWorkspaceResourceKeySeparation":
      return raw === projected && raw !== undefined && record(raw.normalized) !== undefined;
    case "workspace.resolveEffectiveHosts":
      return raw === projected && raw !== undefined && record(raw.normalized) !== undefined;
    case "workspace.evaluateWorkspaceObject":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    default:
      return false;
  }
}

function nodeAdvertisementCryptographicPostcondition(
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const event = record(fixture.input.event);
  const raw = record(execution.raw_result);
  const projected = record(execution.projected_output);
  if (
    event === undefined
    || raw === undefined
    || projected === undefined
    || typeof event.pubkey !== "string"
    || typeof event.created_at !== "number"
    || typeof event.kind !== "number"
    || !Array.isArray(event.tags)
    || typeof event.content !== "string"
    || typeof event.id !== "string"
    || typeof event.sig !== "string"
  ) return false;
  const nip01Digest = sha256(utf8Bytes(JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ])));
  let outerValid = false;
  try {
    outerValid = event.id === Buffer.from(nip01Digest).toString("hex")
      && schnorr.verify(event.sig, nip01Digest, event.pubkey);
  } catch {
    outerValid = false;
  }
  const tags = event.tags as readonly unknown[];
  const tagValue = (name: string): string | undefined => {
    const matches = tags.filter((entry) =>
      Array.isArray(entry) && entry.length === 2 && entry[0] === name
    ) as unknown[][];
    return matches.length === 1 && typeof matches[0]?.[1] === "string"
      ? matches[0][1] as string
      : undefined;
  };
  const rid = tagValue("rid");
  const nid = tagValue("nid");
  const endpoint = tagValue("endpoint");
  const expiry = tagValue("expiry");
  const proof = tagValue("nid_proof");
  const repoHead = tagValue("repo_head");
  let nidValid = false;
  if (
    rid !== undefined
    && nid?.startsWith("did:key:z")
    && endpoint !== undefined
    && expiry !== undefined
    && proof !== undefined
    && repoHead !== undefined
  ) {
    try {
      const decoded = base58.decode(nid.slice("did:key:z".length));
      nidValid = decoded.length === 34
        && decoded[0] === 0xed
        && decoded[1] === 0x01
        && ed25519.verify(
          hexToBytes(proof),
          nodeAdvertPayload(rid, nid, endpoint, Number(expiry), repoHead),
          decoded.slice(2),
        );
    } catch {
      nidValid = false;
    }
  }
  if (fixture.vector_id === "core/node-advert-bad-signature") {
    return !outerValid && projected.reason_code === raw.failure;
  }
  if (fixture.vector_id === "core/node-advert-nid-proof-invalid") {
    return outerValid && !nidValid && projected.reason_code === raw.failure;
  }
  return outerValid
    && nidValid
    && raw.status === "accepted"
    && raw.rid === rid
    && raw.endpoint === endpoint
    && raw.expiry === Number(expiry)
    && raw.repo_head === repoHead
    && projected.normalized === execution.raw_result;
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

function durableRecordStates(value: unknown): readonly string[] {
  const candidate = value as { records?: unknown };
  if (!(candidate?.records instanceof Map)) return [];
  return [...candidate.records.values()].flatMap((entry) => {
    const captured = record(entry);
    return typeof captured?.state === "string" ? [captured.state] : [];
  });
}

function durableRecords(value: unknown): readonly Readonly<Record<string, unknown>>[] {
  const candidate = value as { records?: unknown };
  if (!(candidate?.records instanceof Map)) return [];
  return [...candidate.records.values()].flatMap((entry) => {
    const captured = record(entry);
    return captured === undefined ? [] : [captured];
  });
}

function exactBytes(left: unknown, right: unknown): boolean {
  return left instanceof Uint8Array && right instanceof Uint8Array
    && left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function stringMembers(value: unknown): readonly string[] | undefined {
  return Array.isArray(value) && value.every((member) => typeof member === "string")
    ? value as readonly string[]
    : undefined;
}

function recordMembers(value: unknown): readonly Readonly<Record<string, unknown>>[] {
  return Array.isArray(value)
    ? value.map(record).filter((member): member is Readonly<Record<string, unknown>> =>
      member !== undefined
    )
    : [];
}

function independentlyDerivedWorkspaceCapabilities(
  repositoryView: unknown,
  normalizedValue: unknown,
): readonly string[] | undefined {
  const view = record(repositoryView);
  const normalized = record(normalizedValue);
  const objects = recordMembers(view?.objects);
  const grantId = normalized?.qualifying_grant_id;
  const roleIds = stringMembers(normalized?.qualifying_role_path_ids);
  if (typeof grantId !== "string" || roleIds === undefined || roleIds.length === 0) {
    return undefined;
  }
  const grant = objects.find((value) =>
    value.object_type === "role-grant-v1" && value.grant_id === grantId
  );
  const roles = roleIds.map((roleId) => objects.find((value) =>
    value.object_type === "role-manifest-v1" && value.role_id === roleId
  ));
  if (grant === undefined || roles.some((role) => role === undefined)) return undefined;
  const relationship = objects.find((value) =>
    value.object_type === "workspace-relationship-v1"
      && value.source_role_id === grant.role_id
  );
  const resourceScope = stringMembers(grant.resource_scope);
  const resources = resourceScope?.map((resourceId) => objects.find((value) =>
    value.object_type === "resource-advertisement-v1" && value.resource_id === resourceId
  ));
  const ceilings = [
    ...roles.map((role) => stringMembers(role?.allowed_capabilities)),
    stringMembers(grant.capabilities),
    stringMembers(relationship?.capability_ceiling),
  ];
  if (ceilings.some((ceiling) => ceiling === undefined)
    || resources === undefined || resources.some((resource) => resource === undefined)) {
    return undefined;
  }
  const resourceRequired = new Set(resources.flatMap((resource) =>
    stringMembers(resource?.required_capabilities) ?? []
  ));
  if (grant.activation === "subject-acceptance") resourceRequired.add("invite");
  ceilings.push([...resourceRequired]);
  const [first, ...rest] = ceilings as readonly (readonly string[])[];
  return [...new Set(first)].filter((capability) =>
    rest.every((ceiling) => ceiling.includes(capability))
  ).sort();
}

function independentlyValidWorkspaceRevocationEffect(
  repositoryView: unknown,
  resolveInputValue: unknown,
  activationInputValue: unknown,
  timingValue: unknown,
): boolean {
  const view = record(repositoryView);
  const evidence = record(view?.evidence);
  const objects = recordMembers(view?.objects);
  const resolveInput = record(resolveInputValue);
  const activationInput = record(activationInputValue);
  const timing = record(timingValue);
  const grantId = activationInput?.grant_id;
  const grant = objects.find((value) => value.object_type === "role-grant-v1"
    && value.grant_id === grantId);
  const revocation = objects.find((value) => value.object_type === "role-revocation-v1"
    && value.target_type === "grant" && value.target_id === grantId);
  const policy = objects.find((value) => value.object_type === "workspace-policy-v1"
    && value.policy_id === grant?.policy_head);
  const governance = record(policy?.governance);
  const approvals = recordMembers(activationInput?.approvals);
  const approval = approvals[0];
  const preparedAt = timing?.prepared_at;
  const activationAt = timing?.activation_at;
  if (grant === undefined || revocation === undefined || policy === undefined
    || approval === undefined || approvals.length !== 1
    || grant.activation !== "approval-threshold" || grant.invitation !== null
    || typeof grantId !== "string" || resolveInput?.operation_digest === undefined
    || typeof preparedAt !== "number" || typeof activationAt !== "number"
    || typeof revocation.effective_at !== "number"
    || !(preparedAt < revocation.effective_at && revocation.effective_at <= activationAt)
    || typeof evidence?.observed_at !== "number" || typeof evidence.expires_at !== "number"
    || typeof policy.authority_mutation_max_age !== "number"
    || preparedAt < evidence.observed_at || activationAt < preparedAt
    || activationAt - evidence.observed_at > policy.authority_mutation_max_age
    || activationAt >= evidence.expires_at
    || approval.profile !== "heterodyne.workspace-grant-approval.v1"
    || approval.workspace_key !== grant.workspace_key
    || approval.policy_head !== grant.policy_head
    || approval.predecessor !== grant.predecessor
    || approval.authority_checkpoint !== grant.authority_checkpoint
    || typeof approval.approver_key !== "string" || typeof approval.signature !== "string"
    || typeof approval.issued_at !== "number" || typeof approval.expires_at !== "number"
    || approval.issued_at > activationAt || activationAt >= approval.expires_at
    || !Array.isArray(governance?.controllers)
    || !governance.controllers.includes(approval.approver_key)
    || governance.threshold !== 1) return false;
  const operation = { ...grant };
  delete operation.signature;
  delete operation.approval_ids;
  const operationDigest = bytesToHex(sha256(proofBytes(
    "heterodyne-workspace-grant-operation-v1", operation,
  )));
  const unsignedApproval = { ...approval };
  delete unsignedApproval.signature;
  try {
    return resolveInput.operation_digest === operationDigest
      && approval.operation_digest === operationDigest
      && Array.isArray(grant.approval_ids)
      && grant.approval_ids.length === 1
      && grant.approval_ids[0] === workspaceObjectId(approval)
      && schnorr.verify(
        approval.signature,
        proofBytes("heterodyne-workspace-grant-approval-v1", unsignedApproval),
        approval.approver_key,
      )
      && typeof revocation.signature === "string"
      && typeof revocation.workspace_key === "string"
      && schnorr.verify(
        revocation.signature,
        workspaceSigningPayload(revocation as Record<string, unknown>),
        revocation.workspace_key,
      );
  } catch {
    return false;
  }
}

function taskFifteenPostcondition(
  allocation: SemanticAllocation,
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const outerRaw = record(execution.raw_result);
  const raw = record(outerRaw?.semantic_result) ?? outerRaw;
  const projected = record(execution.projected_output);
  const invocations = execution.evaluator_invocations.filter(({ step_id }) =>
    step_id.startsWith("semantic:")
  );
  if (raw === undefined || projected === undefined || invocations.length === 0) return false;
  const terminal = record(raw.terminal) ?? projected;
  switch (allocation.postcondition) {
    case "task15-agent-publication": {
      if (terminal.verdict !== projected.verdict || typeof raw.signer_calls !== "number") return false;
      const request = record(invocations[0]?.args[1]);
      const publication = record(request?.publication);
      const senderProof = record(request?.sender_proof);
      if (fixture.vector_id === "comms/agent-sender-proof-invalid") {
        return terminal.reason_code === "agent-sender-proof-invalid"
          && invocations.length === 1
          && senderProof?.kind === "dpop"
          && typeof senderProof.compact === "string"
          && senderProof.compact.length > 0
          && raw.signer_calls === 0
          && durableRecordStates(raw.store).length === 0;
      }
      const first = record(raw.first), retry = record(raw.retry);
      const firstOutput = record(first?.output), retryOutput = record(retry?.output);
      const records = durableRecords(raw.store);
      const committed = records[0];
      const tags = Array.isArray(firstOutput?.tags) ? firstOutput.tags : [];
      const hasAgentClass = tags.some((tag) =>
        Array.isArray(tag) && tag[0] === "l" && tag[1] === "ai"
      );
      const hasSignerAssociation = tags.some((tag) =>
        Array.isArray(tag) && tag[0] === "heterodyne_agent"
          && tag.includes(request?.signer)
      );
      return first?.verdict === "accept"
        && retry?.verdict === "accept"
        && raw.signer_calls === 1
        && invocations.length === 2
        && invocations[0]?.args[0] === invocations[1]?.args[0]
        && invocations[0]?.args[1] === invocations[1]?.args[1]
        && invocations[0]?.result === raw.first
        && invocations[1]?.result === raw.retry
        && senderProof?.kind === "dpop"
        && publication?.pubkey === request?.signer
        && firstOutput?.pubkey === request?.signer
        && firstOutput?.created_at === publication?.created_at
        && firstOutput?.kind === publication?.kind
        && firstOutput?.content === publication?.content
        && verifiesNip01Event(firstOutput)
        && hasAgentClass
        && hasSignerAssociation
        && records.length === 1
        && committed?.state === "committed"
        && committed.revision === 1
        && typeof committed.output_digest === "string"
        && committed.output_digest.length === 64
        && currentFixtureDigest(committed.output) === currentFixtureDigest(firstOutput)
        && currentFixtureDigest(retryOutput) === currentFixtureDigest(firstOutput)
        && raw.terminal === raw.retry
        && execution.projected_output === raw.retry;
    }
    case "task15-marmot-admission": {
      const verified = record(raw.verified);
      const evidence = record(raw.evidence);
      const authenticated = record(evidence?.authenticated);
      const counts = record(raw.counts);
      const input = record(invocations[0]?.args[1]);
      if (verified?.verdict !== "accept"
        || invocations.length !== 2
        || invocations[1]?.args[1] !== verified.output
        || authenticated === undefined
        || authenticated.inviter_account !== input?.inviter_account
        || authenticated.recipient_account !== input?.recipient_account
        || authenticated.group_id !== input?.group_id
        || currentFixtureDigest(authenticated.member_accounts)
          !== currentFixtureDigest(input?.member_accounts)
        || currentFixtureDigest(authenticated.required_capabilities)
          !== currentFixtureDigest(input?.required_capabilities)
        || authenticated.inviter_leaf_key === authenticated.recipient_leaf_key
        || typeof authenticated.inviter_leaf_key !== "string"
        || authenticated.inviter_leaf_key.length !== 64
        || typeof authenticated.recipient_leaf_key !== "string"
        || authenticated.recipient_leaf_key.length !== 64
        || counts?.keyPackageLoads !== 1
        || counts.processCalls !== 1) return false;
      if (fixture.vector_id === "comms/conversation-rejected") {
        return terminal.reason_code === "conversation-rejected"
          && counts.conversationLoads === 0
          && counts.transitionCommits === 0
          && counts.transitionRollbacks === 1
          && durableRecords(raw.store).length === 0;
      }
      const privateKeyPackage = record(evidence?.private_key_package);
      const records = durableRecords(raw.store);
      const committed = records[0];
      return terminal.verdict === "accept"
        && record(terminal.output)?.terminal === "held"
        && record(terminal.output)?.group_id === authenticated.group_id
        && record(terminal.output)?.checkpoint === authenticated.checkpoint
        && counts.conversationLoads === 1
        && counts.transitionCommits === 1
        && counts.transitionRollbacks === 0
        && privateKeyPackage !== undefined
        && Reflect.ownKeys(privateKeyPackage).length === 0
        && Object.isFrozen(privateKeyPackage)
        && records.length === 1
        && committed?.state === "committed"
        && currentFixtureDigest(committed.output) === currentFixtureDigest(terminal.output);
    }
    case "task15-one-time-invite": {
      const redemption = record(invocations[0]?.args[1]);
      const envelope = record(redemption?.envelope);
      const descriptor = record(envelope?.descriptor);
      return terminal.reason_code === "invite-authentication-invalid"
        && invocations.length === 1
        && typeof envelope?.signature === "string"
        && envelope.signature.length === 128
        && typeof descriptor?.secret_sha256 === "string"
        && descriptor.secret_sha256.length === 64
        && redemption?.response_bytes instanceof Uint8Array
        && redemption.response_bytes.length > 0
        && durableRecords(raw.store).length === 0
        && record(terminal.output) === undefined;
    }
    case "task15-persona-inbox": {
      const bundle = record(invocations[0]?.args[1]);
      const evidence = record(raw.evidence);
      const inbox = record(evidence?.inbox);
      const expectedReason = fixture.vector_id === "comms/marmot-private-inbox-nid-required"
        ? "marmot-private-inbox-nid-required"
        : fixture.vector_id === "comms/marmot-keypackage-replayed"
          ? "marmot-keypackage-replayed"
          : "marmot-agent-scope-denied";
      const caseState = fixture.vector_id === "comms/marmot-private-inbox-nid-required"
        ? inbox?.recipient_nid === null
        : fixture.vector_id === "comms/marmot-keypackage-replayed"
          ? Array.isArray(inbox?.consumed_key_packages)
            && inbox.consumed_key_packages.includes(bundle?.key_package_ref)
          : bundle?.sender_kind === "agent"
            && typeof bundle.required_agent_scope === "string"
            && Array.isArray(inbox?.allowed_agent_scopes)
            && !inbox.allowed_agent_scopes.includes(bundle.required_agent_scope);
      return terminal.reason_code === expectedReason
        && invocations.length === 1
        && raw.load_calls === 1
        && caseState
        && durableRecords(raw.store).length === 0
        && record(terminal.output) === undefined;
    }
    case "task15-marmot-archive": {
      if (fixture.vector_id === "comms/marmot-premature-ack") {
        const receipt = record(invocations[0]?.args[1]);
        return terminal.reason_code === "marmot-premature-ack"
          && receipt !== undefined && Reflect.ownKeys(receipt).length === 0
          && record(raw.store)?.loadCalls === 0;
      }
      if (fixture.vector_id === "comms/marmot-exact-bytes-durable") {
        const input = record(invocations[0]?.args[1]);
        const source = record(input?.source);
        const event = record(source?.event);
        const records = durableRecords(raw.store);
        const committed = records[0];
        const output = record(committed?.output);
        const receipt = record(terminal.output);
        const appended = Array.isArray(raw.appended) ? raw.appended : [];
        const bytesDigest = source?.event_bytes instanceof Uint8Array
          ? Buffer.from(sha256(source.event_bytes)).toString("hex")
          : undefined;
        return terminal.verdict === "accept"
          && invocations.length === 1
          && receipt !== undefined
          && Reflect.ownKeys(receipt).length === 0
          && Object.isFrozen(receipt)
          && records.length === 1
          && committed?.state === "committed"
          && output?.repository_rid === input?.repository_rid
          && output?.ref === input?.ref
          && output?.object_digest === bytesDigest
          && output?.source_digest === event?.id
          && typeof output?.commit === "string"
          && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(output.commit as string)
          && appended.length === 1
          && exactBytes(appended[0], source?.event_bytes);
      }
      const append = record(raw.append), expired = record(raw.expired);
      const appendReceipt = record(append?.output);
      const input = record(invocations[0]?.args[1]);
      const source = record(input?.source);
      const event = record(source?.event);
      const records = durableRecords(raw.store);
      const available = records[0];
      const retained = record(available?.output);
      const expiredOutput = record(expired?.output);
      const terminalOutput = record(terminal.output);
      const appended = Array.isArray(raw.appended) ? raw.appended : [];
      return append?.verdict === "accept" && expired?.verdict === "accept"
        && terminal.verdict === "accept" && invocations.length === 3
        && invocations[1]?.args[1] === append.output
        && invocations[2]?.args[1] === append.output
        && appendReceipt !== undefined
        && Reflect.ownKeys(appendReceipt).length === 0
        && records.length === 1
        && available?.state === "available"
        && retained?.repository_rid === input?.repository_rid
        && retained?.ref === input?.ref
        && retained?.object_digest === (source?.event_bytes instanceof Uint8Array
          ? Buffer.from(sha256(source.event_bytes)).toString("hex")
          : undefined)
        && retained?.source_digest === event?.id
        && currentFixtureDigest(expiredOutput) === currentFixtureDigest(retained)
        && currentFixtureDigest(terminalOutput) === currentFixtureDigest(retained)
        && expiredOutput?.object_digest === terminalOutput?.object_digest
        && expiredOutput?.commit === terminalOutput?.commit
        && appended.length === 1
        && exactBytes(appended[0], source?.event_bytes);
    }
    case "task15-control-reset": {
      const input = record(invocations[0]?.args[0]);
      const grant = record(input?.grant), completion = record(input?.completion);
      const inventory = record(input?.authoritative_inventory);
      const exactReason = fixture.vector_id === "control/compromise-reset-evidence-invalid"
        ? "control-compromise-reset-evidence-invalid"
        : fixture.vector_id === "control/compromise-reset-inventory-mismatch"
          ? "control-compromise-reset-inventory-mismatch"
          : fixture.vector_id === "control/compromise-reset-unauthenticated"
            ? "control-compromise-reset-unauthenticated"
            : "control-subordinate-reauthorization-required";
      const sharedSignedBinding = typeof grant?.signature === "string"
        && grant.signature.length === 128
        && typeof completion?.signature === "string"
        && completion.signature.length === 128
        && grant.recovery_id === completion.recovery_id
        && grant.successor_active_key === completion.successor_active_key
        && raw.reset_transition === undefined;
      if (!sharedSignedBinding || terminal.reason_code !== exactReason || invocations.length !== 1) {
        return false;
      }
      if (fixture.vector_id === "control/compromise-reset-evidence-invalid") {
        return typeof inventory?.revision === "number"
          && completion?.evidence_revision !== inventory.revision + 1;
      }
      if (fixture.vector_id === "control/compromise-reset-inventory-mismatch") {
        return grant?.inventory_id !== inventory?.inventory_id;
      }
      if (fixture.vector_id === "control/compromise-reset-unauthenticated") {
        return grant?.authorization_class === "assurance-recovery"
          && input?.pinned_assurance_authority === null;
      }
      const required = record(grant?.required_reset);
      return Array.isArray(required?.subordinate_authority_ids)
        && required.subordinate_authority_ids.length === 1
        && Array.isArray(completion?.subordinate_reauthorizations)
        && completion.subordinate_reauthorizations.length === 0;
    }
    case "task15-control-device": {
      const created = record(raw.created), poll = record(raw.poll);
      const transaction = record(created?.output);
      const states = durableRecords(raw.store);
      const stored = record(states[0]?.output);
      const expectedDurableState = fixture.vector_id === "control/device-code-display-mismatch"
        ? states[0]?.state === "committed"
          && stored?.state === "denied"
          && stored.terminal_reason === "control-device-code-display-mismatch"
        : states[0]?.state === "available"
          && stored?.state === "pending"
          && (fixture.vector_id === "control/device-code-invalid"
            ? stored.failed_guesses === 1
            : stored.slow_down_count === 1);
      return created?.verdict === "accept" && poll !== undefined && transaction !== undefined
        && invocations.length === 2 && invocations[1]?.args[1] === raw.poll
        && poll.device_code === transaction.device_code
        && terminal.reason_code === (fixture.vector_id === "control/device-code-invalid"
          ? "control-device-code-invalid"
          : fixture.vector_id === "control/device-code-rate-limited"
            ? "control-device-code-rate-limited"
            : "control-device-code-display-mismatch")
        && states.length === 1
        && expectedDurableState
        && record(terminal.output) === undefined;
    }
    case "task15-control-enrollment": {
      const evidence = record(raw.evidence);
      const inventory = record(evidence?.inventory);
      const invite = record(evidence?.invite);
      const request = record(invocations[0]?.args[1]);
      const exactState = fixture.vector_id === "control/keypackage-invalid"
        ? request?.key_package_bytes instanceof Uint8Array
          && request.key_package_bytes.length === 4
        : fixture.vector_id === "control/enrollment-unavailable"
          ? inventory?.global_pending === inventory?.global_pending_cap
          : inventory?.replenishment_state === "paused";
      return terminal.reason_code === (fixture.vector_id === "control/keypackage-invalid"
        ? "control-keypackage-invalid"
        : fixture.vector_id === "control/enrollment-unavailable"
          ? "control-enrollment-unavailable"
          : "control-keypackage-replenishment-paused")
        && invocations.length === 1
        && request?.account === invite?.account
        && request?.client_key === invite?.client_key
        && exactState
        && record(raw.store)?.reserveCalls === 0
        && record(terminal.output) === undefined;
    }
    case "task15-control-signer": {
      const first = record(raw.first), retry = record(raw.retry);
      const firstTransition = record(first?.completion_transition);
      const retryTransition = record(retry?.completion_transition);
      const firstInput = record(invocations[0]?.args[0]);
      const retryInput = record(invocations[1]?.args[0]);
      const authorization = record(firstInput?.authorization);
      const presentedGrant = record(authorization?.presented_grant);
      const request = record(authorization?.request);
      const rpcRequest = record(request?.rpc_request);
      return first?.verdict === "indeterminate"
        && retry?.verdict === "indeterminate"
        && first.reason_code === "control-signer-effect-indeterminate"
        && retry.reason_code === "control-signer-effect-indeterminate"
        && first.signer_execution_disposition === "executed"
        && retry.signer_execution_disposition === "cached"
        && firstTransition?.prior_reservation_state === "executing"
        && firstTransition.reservation_state === "indeterminate"
        && retryTransition?.prior_reservation_state === "executing"
        && retryTransition.reservation_state === "indeterminate"
        && firstTransition.expected_revision === retryTransition.expected_revision
        && firstTransition.next_revision === retryTransition.next_revision
        && firstTransition.operation_id === retryTransition.operation_id
        && firstTransition.grant_id === retryTransition.grant_id
        && firstTransition.grant_digest === retryTransition.grant_digest
        && firstTransition.request_id === retryTransition.request_id
        && firstTransition.request_digest === retryTransition.request_digest
        && firstTransition.failure_digest === retryTransition.failure_digest
        && currentFixtureDigest(firstTransition.authority)
          === currentFixtureDigest(retryTransition.authority)
        && firstTransition.grant_id === presentedGrant?.grant_id
        && firstTransition.request_id === rpcRequest?.id
        && firstTransition.expected_revision === 7
        && firstTransition.next_revision === 8
        && firstTransition.completed_at === request?.now
        && typeof firstTransition.failure_digest === "string"
        && firstTransition.failure_digest.length === 64
        && invocations.length === 2
        && invocations[0]?.result === raw.first
        && invocations[1]?.result === raw.retry
        && invocations[0]?.args[0] !== invocations[1]?.args[0]
        && firstInput?.signer_execution !== retryInput?.signer_execution
        && currentFixtureDigest(firstInput?.authorization)
          === currentFixtureDigest(retryInput?.authorization)
        && currentFixtureDigest(firstInput?.publication)
          === currentFixtureDigest(retryInput?.publication)
        && raw.signer_calls === 1
        && execution.projected_output === raw.retry;
    }
    case "task15-control-frame":
      return terminal.reason_code === "control-frame-invalid"
        && invocations.length === 1
        && invocations[0]?.args[0] instanceof Uint8Array
        && invocations[0].args[0].length > 0
        && record(invocations[0]?.args[1]) !== undefined
        && record(terminal.output) === undefined;
    case "task15-control-invite": {
      const envelope = record(invocations[0]?.args[1]);
      const descriptor = record(envelope?.descriptor);
      const template = record(invocations[0]?.args[2]);
      const request = record(invocations[0]?.args[3]);
      return terminal.reason_code === "invite-preauthorization-invalid"
        && invocations.length === 1
        && typeof envelope?.signature === "string"
        && envelope.signature.length === 128
        && typeof descriptor?.invite_id === "string"
        && request?.audience !== template?.audience
        && record(terminal.output) === undefined;
    }
    case "task15-core-operational": {
      if (invocations.length !== 1 || record(terminal.output) !== undefined) return false;
      if (fixture.vector_id === "core/friend-cache-unsigned") {
        const candidate = record(invocations[0]?.args[1]);
        const event = record(candidate?.event);
        return terminal.reason_code === "unauthorized_cache_content"
          && typeof event?.sig === "string"
          && event.sig.length === 128
          && event.pubkey !== candidate?.expected_persona;
      }
      if (fixture.vector_id === "core/relay-profile-mutated") {
        const carrier = record(invocations[0]?.args[1]);
        const event = record(carrier?.event);
        return terminal.reason_code === "relay_profile_mutation"
          && carrier?.retained_bytes instanceof Uint8Array
          && typeof event?.id === "string"
          && event.id.length === 64;
      }
      const authority = record(invocations[0]?.args[0]);
      return fixture.vector_id === "core/strict-mode-without-tor"
        && terminal.reason_code === "strict_mode_tor_disabled"
        && authority !== undefined
        && Reflect.ownKeys(authority).length === 0
        && Object.isFrozen(authority);
    }
    case "task15-canonical-profile": {
      const input = record(invocations[0]?.args[1]);
      return terminal.reason_code === "profile-repository-selection-required"
        && invocations.length === 1
        && Array.isArray(input?.relay_candidates)
        && input.relay_candidates.length === 1
        && Array.isArray(input.repository_candidates)
        && input.repository_candidates.length === 0
        && record(terminal.output) === undefined;
    }
    case "task15-control-token": {
      const verified = record(raw.verified);
      const handle = record(verified?.output);
      const compact = invocations[0]?.args[1];
      return verified?.verdict === "accept" && terminal.reason_code === "control-token-invalid"
        && raw.effect_calls === 0 && invocations.length === 2
        && typeof compact === "string"
        && compact.split(".").length === 3
        && handle !== undefined
        && Reflect.ownKeys(handle).length === 0
        && Object.isFrozen(handle)
        && invocations[1]?.args[0] === invocations[0]?.args[0]
        && invocations[1]?.args[1] === verified.output
        && record(invocations[1]?.args[2]) !== undefined
        && durableRecords(raw.store).length === 0
        && record(terminal.output) === undefined;
    }
    case "task15-workspace-authority": {
      const authenticated = record(raw.authenticated);
      if (authenticated?.verdict !== "accept" || invocations.length < 2) return false;
      const resolveInput = record(invocations[1]?.args[0]);
      if (resolveInput?.current_state !== authenticated.state) return false;
      if (fixture.vector_id === "workspace/current-capability-intersection") {
        const resolution = record(raw.resolution), consumed = record(raw.consumed);
        const normalized = record(resolution?.normalized);
        const derivedCapabilities = independentlyDerivedWorkspaceCapabilities(
          invocations[0]?.args[0],
          normalized,
        );
        const effectiveCapabilities = stringMembers(normalized?.effective_capabilities);
        const activationInput = record(invocations[3]?.args[0]);
        const membership = record(activationInput?.membership);
        const signedView = record(invocations[0]?.args[0]);
        const objects = recordMembers(signedView?.objects);
        const grant = objects.find((value) => value.object_type === "role-grant-v1"
          && value.grant_id === normalized?.qualifying_grant_id);
        const recipient = record(grant?.recipient);
        return terminal.verdict === "accept" && invocations.length === 4
          && record(invocations[2]?.args[0])?.current_state === authenticated.state
          && activationInput?.authorization === resolution?.authorization
          && activationInput?.invitation_acceptance === consumed?.acceptance
          && derivedCapabilities !== undefined
          && effectiveCapabilities !== undefined
          && currentFixtureDigest(effectiveCapabilities)
            === currentFixtureDigest(derivedCapabilities)
          && membership?.authenticated_account === grant?.subject_account
          && membership?.accepted_device === grant?.target_device
          && membership?.accepted_leaf === recipient?.value
          && record(terminal.normalized)?.active === true
          && record(terminal.normalized)?.grant_id === grant?.grant_id;
      }
      if (fixture.vector_id === "workspace/invitation-replay") {
        const resolution = record(raw.resolution), consumed = record(raw.consumed);
        const activation = record(raw.activation);
        const firstConsumeInput = record(invocations[2]?.args[0]);
        const activationInput = record(invocations[3]?.args[0]);
        const secondConsumeInput = record(invocations[4]?.args[0]);
        return terminal.reason_code === "workspace_replay" && invocations.length === 5
          && consumed?.verdict === "accept"
          && activation?.verdict === "accept"
          && record(activation.normalized)?.active === true
          && activationInput?.authorization === resolution?.authorization
          && activationInput?.invitation_acceptance === consumed?.acceptance
          && firstConsumeInput?.current_state === authenticated.state
          && secondConsumeInput?.current_state === authenticated.state
          && firstConsumeInput?.acceptance !== secondConsumeInput?.acceptance
          && invocations.filter(({ evaluator }) =>
            evaluator === invocations[3]?.evaluator
          ).length === 1;
      }
      if (fixture.vector_id === "workspace/inheritance-escalation-rejected") {
        return terminal.verdict === "reject"
          && terminal.reason_code === "capability_escalation"
          && sameStrings(Reflect.ownKeys(terminal).map(String).sort(), ["reason_code", "verdict"])
          && invocations.length === 2
          && sameStrings(stringMembers(resolveInput?.requested_capabilities) ?? [], ["write"])
          && raw.authorization === undefined
          && raw.activation === undefined
          && raw.resolution === undefined;
      }
      if (fixture.vector_id === "workspace/revocation-blocks-future-effect") {
        const resolution = record(raw.resolution);
        const authorization = record(resolution?.authorization);
        const normalized = record(resolution?.normalized);
        const activationInput = record(invocations[2]?.args[0]);
        return resolution?.verdict === "accept"
          && authorization !== undefined
          && Reflect.ownKeys(authorization).length === 0
          && Object.isFrozen(authorization)
          && terminal.verdict === "reject"
          && terminal.reason_code === "policy_denied"
          && sameStrings(Reflect.ownKeys(terminal).map(String).sort(), ["reason_code", "verdict"])
          && invocations.length === 3
          && activationInput?.authority === resolveInput?.authority
          && activationInput?.current_state === authenticated.state
          && activationInput?.authorization === resolution.authorization
          && activationInput?.invitation_acceptance === null
          && activationInput?.grant_id === normalized?.qualifying_grant_id
          && independentlyValidWorkspaceRevocationEffect(
            invocations[0]?.args[0],
            invocations[1]?.args[0],
            invocations[2]?.args[0],
            raw.revocation_timing,
          )
          && raw.activation === undefined
          && terminal.normalized === undefined
          && terminal.output === undefined;
      }
      return terminal.reason_code === "policy_denied"
        && invocations.length === 2
        && raw.authorization === undefined
        && raw.activation === undefined;
    }
    case "task15-social-subscription": {
      const view = raw.view;
      return view !== null && typeof view === "object" && Object.isFrozen(view)
        && !Object.hasOwn(fixture.input, "subscribed")
        && !Object.hasOwn(fixture.input, "policy_event_selected")
        && !Object.hasOwn(fixture.input, "local_policy_applied")
        && raw.exact_view_transfer === view && invocations.length === 2
        && invocations[1]?.args[0] === invocations[0]?.result
        && projected.verdict === "accept";
    }
    default:
      return false;
  }
}

function verifyPostcondition(
  allocation: SemanticAllocation,
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  if (allocation.postcondition === "terminal-output-only") return true;
  if (allocation.postcondition === `semantic:${allocation.boundary_id}`) {
    return boundaryContractPostcondition(allocation.boundary_id, fixture, execution);
  }
  if (allocation.postcondition.startsWith("task15-")) {
    return taskFifteenPostcondition(allocation, fixture, execution);
  }
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
    default:
      return false;
  }
}

function allocationMatchesExecutedTerminal(
  allocation: SemanticAllocation,
  execution: CurrentBoundaryExecutionRecord,
): boolean {
  const projected = record(execution.projected_output);
  if (projected === undefined) return false;
  if (allocation.invariants.length === 0 && allocation.reasons.length === 0) return true;
  if (allocation.reasons.length === 0) {
    return !Object.hasOwn(projected, "reason_code");
  }
  return allocation.reasons.length === 1
    && projected.reason_code === allocation.reasons[0];
}

export function certifyBoundaryExecution(
  contract: CurrentCaseContract,
  fixture: CurrentCaseFixture,
  execution: CurrentBoundaryExecution,
): SemanticBoundaryCertificate {
  assertCurrentCaseContractIdentity(fixture.vector_id, contract);
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
  if (
    !verifyPostcondition(allocation, fixture, captured)
    || !allocationMatchesExecutedTerminal(allocation, captured)
  ) {
    throw new Error(`semantic certificate postcondition failed: ${fixture.vector_id}`);
  }
  assertCurrentBoundaryEvaluatorIdentity(execution, allocation.boundary_id, fixture);
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
