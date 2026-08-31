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
import { hexToBytes, utf8Bytes } from "../hex.js";
import { nodeAdvertPayload } from "../radicle.js";
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

type SemanticAllocationSource = Readonly<{
  boundary_id: string;
  invariants: readonly string[];
  reasons: readonly string[];
  postcondition?: string;
}>;

const SEMANTIC_ALLOCATIONS = {"assurance/associated-key-expired":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-expired"]},"assurance/associated-key-revoked":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-revoked"]},"assurance/associated-key-subject-proof-invalid":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-subject-proof-invalid"]},"assurance/associated-key-subject-proof-required":{"boundary_id":"assurance-policy.evaluateAssuranceAssociatedKeyConsent","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":["assurance-associated-key-subject-proof-required"]},"assurance/authority-at-compromise-cutoff":{"boundary_id":"assurance.evaluateAssuranceAuthorityAt","invariants":["ASSURANCE-I-COMPROMISE-CUTOFF"],"reasons":["assurance-compromise-cutoff"]},"assurance/compromise-subordinate-continuation-forbidden":{"boundary_id":"assurance-policy.evaluateAssuranceCompromiseContinuation","invariants":["ASSURANCE-I-COMPROMISE-CUTOFF","ASSURANCE-I-NO-IMPLICIT-CONTINUATION"],"reasons":["assurance-subordinate-continuation-forbidden"]},"assurance/duplicity-rejected":{"boundary_id":"assurance-policy.evaluateAssurancePinPolicy","invariants":["ASSURANCE-I-SUCCESSION-NON-ALIASING"],"reasons":["assurance-duplicity"]},"assurance/enrollment-competing-inception":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-contested"],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-forged-contest-ignored":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED","ASSURANCE-I-CORE-OPTIONALITY"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-late-warning-no-unpin":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED","ASSURANCE-I-PIN-DOWNGRADE"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-pending-w-minus-one":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-pending-window"],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-timely-contest":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-contested"],"postcondition":"assurance-authoritative-observation"},"assurance/enrollment-verified-at-window":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"assurance/export-aid-substitution":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_aid_substituted_for_npub"]},"assurance/export-incomplete":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_incomplete"]},"assurance/export-lossless":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":[]},"assurance/export-unmappable-feature":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_unmappable_feature"]},"assurance/export-unsupported-suite":{"boundary_id":"assurance-policy.evaluateAssuranceExport","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["export_unsupported_crypto_suite"]},"assurance/keri-wire-format-rejected":{"boundary_id":"assurance-policy.validateAssuranceWireFormat","invariants":["ASSURANCE-I-EXPORT-LOSSLESS"],"reasons":["keri_wire_format_rejected"]},"assurance/persona-author-mismatch":{"boundary_id":"core-policy.validateCorePersonaSignedEvent","invariants":["ASSURANCE-I-CORE-OPTIONALITY"],"reasons":["delegation_mismatch"]},"assurance/pin-conflict-rejected":{"boundary_id":"assurance-policy.evaluateAssurancePinPolicy","invariants":["ASSURANCE-I-PIN-DOWNGRADE"],"reasons":["assurance-pin-conflict"]},"assurance/profile-heterodyne-assurance-active-key-acceptance-v1":{"boundary_id":"assurance.evaluateEnrollment","invariants":["ASSURANCE-I-RECIPROCAL-ENROLLMENT"],"reasons":[]},"assurance/profile-heterodyne-assurance-associated-key-v1":{"boundary_id":"assurance.evaluateAssociatedKey","invariants":["ASSURANCE-I-ASSOCIATED-KEY-BOUNDS"],"reasons":[]},"assurance/profile-heterodyne-assurance-enrollment-contest-profile-v1":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":[]},"assurance/profile-heterodyne-assurance-enrollment-inception-v1":{"boundary_id":"assurance.evaluateEnrollment","invariants":["ASSURANCE-I-RECIPROCAL-ENROLLMENT"],"reasons":[]},"assurance/profile-heterodyne-assurance-succession-v1":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":[]},"assurance/reciprocal-proof-invalid":{"boundary_id":"assurance.evaluateEnrollment","invariants":["ASSURANCE-I-RECIPROCAL-ENROLLMENT"],"reasons":["assurance-reciprocal-proof-invalid"]},"assurance/retired-key-post-compromise":{"boundary_id":"follow-up-hardening.classifyRetiredKeyObservation","invariants":["ASSURANCE-I-COMPROMISE-CUTOFF"],"reasons":["revoked_key_post_compromise"]},"assurance/succession-authority-invalid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-authority-invalid"]},"assurance/succession-head-mismatch":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-head-mismatch"]},"assurance/succession-new-key-acceptance-invalid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-new-key-acceptance-invalid"]},"assurance/succession-predecessor-mismatch":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-predecessor-mismatch"]},"assurance/succession-schema-invalid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-schema-invalid"]},"assurance/succession-valid":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-NO-IMPLICIT-CONTINUATION","ASSURANCE-I-SUCCESSION-NON-ALIASING","ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":[]},"assurance/succession-witness-threshold-unsatisfied":{"boundary_id":"assurance.evaluateSuccession","invariants":["ASSURANCE-I-TRANSITION-PROOF-BINDING"],"reasons":["assurance-witness-threshold-unsatisfied"]},"assurance/dual-consent-downgrade-accepted":{"boundary_id":"assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade","invariants":["ASSURANCE-I-PIN-DOWNGRADE"],"reasons":[],"postcondition":"assurance-dual-proof-downgrade"},"assurance/unilateral-downgrade-rejected":{"boundary_id":"assurance-downgrade.evaluateAssuranceDowngrade+commitAssuranceDowngrade","invariants":["ASSURANCE-I-PIN-DOWNGRADE"],"reasons":["assurance-downgrade-consent-required"],"postcondition":"assurance-dual-proof-downgrade"},"assurance/witness-threshold-fail":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":["assurance-enrollment-pending-window"],"postcondition":"assurance-authoritative-observation"},"assurance/witness-threshold-pass":{"boundary_id":"assurance-observation.evaluateEnrollmentEligibility","invariants":["ASSURANCE-I-ENROLLMENT-WINDOWED"],"reasons":[],"postcondition":"assurance-authoritative-observation"},"comms/agent-attribution-encrypted-inner":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/agent-attribution-invalid":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION"],"reasons":["agent-attribution-invalid"]},"comms/agent-attribution-profile-unavailable":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION"],"reasons":["agent-attribution-profile-unavailable"]},"comms/agent-persona-scope-required":{"boundary_id":"agent-authorship.injectAgentAttribution","invariants":["COMMS-I-AGENT-ATTRIBUTION"],"reasons":["agent-persona-scope-required"]},"comms/agent-sender-proof-invalid":{"boundary_id":"agent-authorship.validateAgentAccessToken","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-sender-proof-invalid"]},"comms/agent-signer-mismatch":{"boundary_id":"agent-authorship.validateAgentAccessToken","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-signer-mismatch"]},"comms/agent-token-invalid":{"boundary_id":"agent-authorship.validateAgentAccessToken","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-token-invalid"]},"comms/agent-workload-registration-invalid":{"boundary_id":"agent-authorship.validateWorkloadRegistration","invariants":["COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":["agent-workload-registration-invalid"]},"comms/agent-workload-token-accepted":{"boundary_id":"agent-authorship.validateWorkloadRegistration+validateAgentAccessToken","invariants":["COMMS-I-AGENT-SIGNER-BINDING","COMMS-I-WORKLOAD-TOKEN-CONFINEMENT"],"reasons":[]},"comms/auth-rejected-permanent":{"boundary_id":"comms-policy.classifyRelayWriteFailure","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["auth_rejected_permanent"]},"comms/authorization-view-300-boundary":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":[]},"comms/authorization-view-86400-boundary":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":[]},"comms/authorization-view-maximum-malformed":{"boundary_id":"schema.validateOidcContinuityManifestSchemaOrThrow","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":["claim-schema-invalid"]},"comms/checkpoint-exact-boundary":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":[]},"comms/checkpoint-stale-independent":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["COMMS-I-MINT-FRESHNESS"],"reasons":["oidc-checkpoint-stale"]},"comms/claim-active-authenticated":{"boundary_id":"claim-authorization.authorizeClaimEffect","invariants":["COMMS-I-CLAIM-ATTENUATION","COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[],"postcondition":"claim-artifact-durable-effect"},"comms/claim-attenuation-violation":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-attenuation-violation"]},"comms/claim-chain-cycle":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-chain-cycle"]},"comms/claim-chain-depth-exceeded":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-chain-depth-exceeded"]},"comms/claim-delegation-not-authorized":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-ATTENUATION"],"reasons":["claim-delegation-not-authorized"]},"comms/claim-event-signature-invalid":{"boundary_id":"claims.verifyClaimEnvelope","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-event-signature-invalid"]},"comms/claim-expired":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-expired"]},"comms/claim-id-mismatch":{"boundary_id":"claims.validateClaimId","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-id-mismatch"]},"comms/claim-issuer-authority-invalid":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-issuer-authority-invalid"]},"comms/claim-issuer-untrusted":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-issuer-untrusted"]},"comms/claim-key-reference-invalid":{"boundary_id":"claims.validateKeyRef","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-key-reference-invalid"]},"comms/claim-ledger-rollback":{"boundary_id":"claim-ledger.mergeClaimLedger","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-ledger-rollback"]},"comms/claim-ledger-writer-unauthorized":{"boundary_id":"claim-ledger.mergeClaimLedger","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-ledger-writer-unauthorized"],"postcondition":"ledger-current-writer-rejection"},"comms/claim-repository-conflict":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-repository-conflict"]},"comms/claim-repository-unconfirmed":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-REPOSITORY-AUTHORITY"],"reasons":["claim-repository-unconfirmed"]},"comms/claim-revoked":{"boundary_id":"claims.verifyClaimRevocationEnvelope+claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":["claim-revoked"]},"comms/claim-revoker-unauthorized":{"boundary_id":"claim-ledger.validateLedgerRecordOrThrow","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":["claim-revoker-unauthorized"]},"comms/claim-subject-proof-invalid":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-subject-proof-invalid"]},"comms/claim-subject-proof-required":{"boundary_id":"claim-authorization.inspectClaimState","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":["claim-subject-proof-required"]},"comms/config-private-state-encrypted":{"boundary_id":"privacy-crypto.deriveConfigPostKey+nostr-tools.nip44","invariants":["COMMS-I-CONFIG-AT-REST","COMMS-I-TIER2-HONESTY"],"reasons":[]},"comms/conversation-rejected":{"boundary_id":"marmot-admission.ordinaryConversationAdmission","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["conversation-rejected"]},"comms/dm-invite-revoked-device":{"boundary_id":"comms-policy.validateDmInviteDevice","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["dm_invite_revoked_device"]},"comms/dm-invite-unbound-device":{"boundary_id":"comms-policy.validateDmInviteDevice","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["dm_invite_unbound_device"]},"comms/invite-already-reserved":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-already-reserved"]},"comms/invite-authentication-invalid":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-authentication-invalid"]},"comms/invite-expired":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-expired"]},"comms/invite-purpose-mismatch":{"boundary_id":"comms-policy.evaluateOneTimeInvite","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["invite-purpose-mismatch"]},"comms/ledger-reader-authorized":{"boundary_id":"claim-ledger.mergeClaimLedger+evaluateReaderAccess","invariants":["COMMS-I-CLAIM-REVOCATION","COMMS-I-LEDGER-CONFINEMENT"],"reasons":[],"postcondition":"ledger-current-writer-durable-effect"},"comms/ledger-reader-unauthorized":{"boundary_id":"claim-ledger.evaluateReaderAccess","invariants":["COMMS-I-LEDGER-CONFINEMENT"],"reasons":["claim-ledger-reader-unauthorized"]},"comms/marmot-agent-scope-denied":{"boundary_id":"comms-policy.evaluateMarmotInboxBootstrap","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-agent-scope-denied"]},"comms/marmot-exact-bytes-durable":{"boundary_id":"marmot-routing-policy.evaluateMarmotDurability","invariants":["COMMS-I-MARMOT-EXACT-BYTES"],"reasons":[]},"comms/marmot-expiration-not-erasure":{"boundary_id":"marmot-routing-policy.evaluateMarmotRetention","invariants":["COMMS-I-RADICLE-NON-ERASURE"],"reasons":[]},"comms/marmot-keypackage-replayed":{"boundary_id":"comms-policy.evaluateMarmotInboxBootstrap","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-keypackage-replayed"]},"comms/marmot-ordinary-welcome-held":{"boundary_id":"marmot-admission.ordinaryConversationAdmission","invariants":["COMMS-I-MARMOT-ACCOUNT-IDENTITY","COMMS-I-MARMOT-SECRET-CONFINEMENT","COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":[]},"comms/marmot-premature-ack":{"boundary_id":"marmot-routing-policy.evaluateMarmotDurability","invariants":["COMMS-I-MARMOT-EXACT-BYTES"],"reasons":["marmot-premature-ack"]},"comms/marmot-private-inbox-nid-required":{"boundary_id":"comms-policy.evaluateMarmotInboxBootstrap","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-private-inbox-nid-required"]},"comms/marmot-private-route-required":{"boundary_id":"current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["marmot-private-route-required"]},"comms/marmot-routing-binding-valid":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":[]},"comms/marmot-routing-equivocation":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":["marmot-routing-equivocation"]},"comms/marmot-routing-genesis-mismatch":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":["marmot-routing-binding-invalid"]},"comms/marmot-unauthorized-ref":{"boundary_id":"marmot-routing-policy.evaluateMarmotRoutingBinding","invariants":["COMMS-I-RADICLE-ROUTING-AUTHORITY"],"reasons":["marmot-unauthorized-ref"]},"comms/nip59-broadcast-rejected":{"boundary_id":"comms-policy.validatePrivateBroadcast","invariants":["COMMS-I-MARMOT-UPSTREAM-AUTHORITY"],"reasons":["nip59_broadcast_rejected"]},"comms/oidc-access-token-validated":{"boundary_id":"oidc.projectAccessToken+validateProjectedJwt","invariants":["COMMS-I-JWT-TYPE-AUDIENCE","COMMS-I-STATUS-INTEGRITY"],"reasons":[]},"comms/oidc-audience-invalid":{"boundary_id":"oidc.validateProjectedJwt","invariants":["COMMS-I-JWT-TYPE-AUDIENCE"],"reasons":["oidc-audience-invalid"]},"comms/oidc-claim-release":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE","COMMS-I-ISSUER-KEY-CONFINEMENT"],"reasons":[]},"comms/oidc-claim-release-denied":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-claim-release-denied"]},"comms/oidc-client-unregistered":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-client-unregistered"]},"comms/oidc-consent-required":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-consent-required"]},"comms/oidc-grant-prohibited":{"boundary_id":"oidc.validateAuthorizationRequest","invariants":["COMMS-I-CLAIM-RELEASE"],"reasons":["oidc-grant-prohibited"]},"comms/oidc-issuer-authority-invalid":{"boundary_id":"claim-ledger.canMint","invariants":["COMMS-I-ISSUER-KEY-CONFINEMENT"],"reasons":["oidc-issuer-authority-invalid"]},"comms/oidc-issuer-mismatch":{"boundary_id":"oidc.validateIssuerMetadata","invariants":["COMMS-I-ISSUER-CONTINUITY"],"reasons":["oidc-issuer-mismatch"]},"comms/oidc-issuer-persona-continuity":{"boundary_id":"oidc.validateIssuerMetadata","invariants":["COMMS-I-ISSUER-CONTINUITY"],"reasons":[]},"comms/oidc-signing-key-unavailable":{"boundary_id":"claim-ledger.canMint","invariants":["COMMS-I-ISSUER-KEY-CONFINEMENT"],"reasons":["oidc-signing-key-unavailable"]},"comms/oidc-status-invalid":{"boundary_id":"token-status.encodeStatusList","invariants":["COMMS-I-STATUS-INTEGRITY"],"reasons":["oidc-status-invalid"]},"comms/oidc-token-type-invalid":{"boundary_id":"oidc.validateProjectedJwt","invariants":["COMMS-I-JWT-TYPE-AUDIENCE"],"reasons":["oidc-token-type-invalid"]},"comms/profile-heterodyne-comms-agent-attribution-kind-1-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-1063-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-16-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-1985-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-30023-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-4550-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-6-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-agent-attribution-kind-7-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+matchesAgentAttributionProfile","invariants":["COMMS-I-AGENT-ATTRIBUTION","COMMS-I-AGENT-SIGNER-BINDING"],"reasons":[]},"comms/profile-heterodyne-comms-claim-revocation-jwk-jws-v1":{"boundary_id":"current-revocation.evaluateCurrentRevocationProfile","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":[]},"comms/profile-heterodyne-comms-claim-revocation-nostr-bip340-v1":{"boundary_id":"current-revocation.evaluateCurrentRevocationProfile","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":[]},"comms/profile-heterodyne-comms-claim-revocation-radicle-ed25519-v1":{"boundary_id":"current-revocation.evaluateCurrentRevocationProfile","invariants":["COMMS-I-CLAIM-REVOCATION"],"reasons":[]},"comms/profile-heterodyne-comms-key-claim-jwk-jws-v1":{"boundary_id":"profile-negotiation.verifyCurrentClaimProofProfile","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[]},"comms/profile-heterodyne-comms-key-claim-nostr-bip340-v1":{"boundary_id":"profile-negotiation.verifyCurrentClaimProofProfile","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[]},"comms/profile-heterodyne-comms-key-claim-radicle-ed25519-v1":{"boundary_id":"profile-negotiation.verifyCurrentClaimProofProfile","invariants":["COMMS-I-CLAIM-AUTHENTICITY"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-1063-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-16-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-30023-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-30402-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/profile-heterodyne-comms-tier3-wrapped-content-kind-6-v1":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44+follow-up-hardening.resolveTier3Recipients+current-private-route.evaluateCurrentTier3PrivateRoute","invariants":["COMMS-I-TIER3-BLIND-CARRIER","COMMS-I-TIER3-CONFINED"],"reasons":[]},"comms/public-reader-private-content":{"boundary_id":"comms-policy.validatePublicReaderRendering","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":["public-reader-private-content"]},"comms/public-reader-private-tier":{"boundary_id":"public-reader.resolvePublicAsset","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":[]},"comms/public-reader-relay-hint-invalid":{"boundary_id":"public-reader.validateBootstrapRelay","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":["public-reader-relay-hint-invalid"]},"comms/public-reader-route-invalid":{"boundary_id":"public-reader.parseLauncherFragment","invariants":["COMMS-I-PUBLIC-READER-TIER1-ONLY"],"reasons":["public-reader-route-invalid"]},"comms/tier3-client-side-encryption":{"boundary_id":"privacy-crypto.deriveTier3IndexKey+nostr-tools.nip44","invariants":["COMMS-I-CLIENT-SIDE-DELIVERY","COMMS-I-NO-CENTRAL-DELIVERY-DIRECTORY","COMMS-I-TIER3-BLIND-CARRIER"],"reasons":[]},"comms/tier3-recipient-confined":{"boundary_id":"follow-up-hardening.resolveTier3Recipients","invariants":["COMMS-I-TIER3-CONFINED"],"reasons":["tier3-recipient-not-active-device"]},"comms/trusted-seed-acl-ambiguous":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-ambiguous"]},"comms/trusted-seed-acl-conflict":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-conflict"]},"comms/trusted-seed-acl-expired":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-expired"]},"comms/trusted-seed-acl-invalid":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-invalid"]},"comms/trusted-seed-acl-missing":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-missing"]},"comms/trusted-seed-acl-stale":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-acl-stale"]},"comms/trusted-seed-event-invalid":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-event-invalid"]},"comms/trusted-seed-exact-write":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-MARMOT-EXACT-BYTES","COMMS-I-PRIVATE-RELAY-ACL","COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":[]},"comms/trusted-seed-nip42-required":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-nip42-required"]},"comms/trusted-seed-request-invalid":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-request-invalid"]},"comms/trusted-seed-request-replay":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-request-replay"]},"comms/trusted-seed-revoked":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-revoked"]},"comms/trusted-seed-route-mismatch":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-route-mismatch"]},"comms/trusted-seed-unauthorized":{"boundary_id":"trusted-seed.createTrustedSeedAdmissionAuthority+evaluateTrustedSeedAdmission","invariants":["COMMS-I-TRUSTED-SEED-CONFINEMENT"],"reasons":["trusted-seed-unauthorized"]},"control/activation-binding-mismatch":{"boundary_id":"control-signing.consumeNip46ConnectionSecret","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-activation-binding-mismatch"]},"control/agent-attribution-bypass-prohibited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["agent-attribution-bypass-prohibited"]},"control/agent-human-profile-prohibited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["agent-human-profile-prohibited"]},"control/agent-intent-invalid":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-agent-intent-invalid"]},"control/agent-key-access-prohibited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["agent-key-access-prohibited"]},"control/agent-method-prohibited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["agent-method-prohibited"]},"control/agent-rate-limited":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["agent-rate-limited"]},"control/agent-resource-denied":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["agent-resource-denied"]},"control/agent-size-exceeded":{"boundary_id":"control-policy.evaluateAutomatedControlGrant","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["agent-size-exceeded"]},"control/attribution-binding-mismatch":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-attribution-binding-mismatch"]},"control/attribution-required":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-attribution-required"]},"control/authorization-view-stale-at-effect":{"boundary_id":"authorization-freshness.revalidateAuthorizationViewAtEffect","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-authorization-view-stale"]},"control/automation-attributed-before-signing":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING","CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":[]},"control/caller-freshness-booleans-rejected":{"boundary_id":"authorization-freshness.evaluateAuthorizationFreshness","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-authorization-view-stale"]},"control/client-metadata-widening":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-CLIENT-KEY-CONFINEMENT"],"reasons":["control-client-metadata-widening"]},"control/compromise-reset-closure-required":{"boundary_id":"control-signing.validateCompromiseReset","invariants":["CONTROL-I-COMPROMISE-RESET","CONTROL-I-MARMOT-LEAF-COMPROMISE"],"reasons":["control-compromise-reset-incomplete"]},"control/compromise-reset-evidence-invalid":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-compromise-reset-evidence-invalid"]},"control/compromise-reset-inventory-mismatch":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-compromise-reset-inventory-mismatch"]},"control/compromise-reset-unauthenticated":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-compromise-reset-unauthenticated"]},"control/connection-secret-invalid":{"boundary_id":"control-signing.consumeNip46ConnectionSecret","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-connection-secret-invalid"]},"control/connection-secret-reused":{"boundary_id":"control-signing.consumeNip46ConnectionSecret","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-connection-secret-reused"]},"control/device-code-display-mismatch":{"boundary_id":"control-policy.evaluateDeviceCodeBoundary","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-device-code-display-mismatch"]},"control/device-code-invalid":{"boundary_id":"control-policy.evaluateDeviceCodeBoundary","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-device-code-invalid"]},"control/device-code-rate-limited":{"boundary_id":"control-policy.evaluateDeviceCodeBoundary","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":["control-device-code-rate-limited"]},"control/enrollment-rate-limited":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-enrollment-rate-limited"]},"control/enrollment-required":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-enrollment-required"]},"control/enrollment-unavailable":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-enrollment-unavailable"]},"control/entitlement-conflict":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-entitlement-conflict"]},"control/exact-signer-grant-reserved":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-AUDIT-AT-REST","CONTROL-I-BASELINE-ACTIVE-KEY","CONTROL-I-CLIENT-KEY-CONFINEMENT","CONTROL-I-EXACT-SIGNER-GRANT","CONTROL-I-NO-SIGNER-FALLBACK","CONTROL-I-OPERATION-AT-MOST-ONCE","CONTROL-I-PERSONA-VAULT-ISOLATION"],"reasons":[]},"control/frame-invalid":{"boundary_id":"control-policy.validateControlFrameBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-frame-invalid"]},"control/invite-preauthorization-invalid":{"boundary_id":"control-policy.validateInvitePreauthorizationBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["invite-preauthorization-invalid"]},"control/keypackage-invalid":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-keypackage-invalid"]},"control/keypackage-replenishment-paused":{"boundary_id":"control-policy.evaluateControlEnrollmentBoundary","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":["control-keypackage-replenishment-paused"]},"control/nip46-request-invalid":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-nip46-request-invalid"]},"control/opaque-authorization-view-accepted":{"boundary_id":"authorization-freshness.revalidateAuthorizationViewAtEffect","invariants":["CONTROL-I-NIP46-OIDC-ACTIVATION"],"reasons":[]},"control/operation-conflict":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-conflict"]},"control/operation-execution-fence-required":{"boundary_id":"control-signing.executePersistedAutomatedSigning","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-execution-fence-required"]},"control/operation-indeterminate":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-indeterminate"]},"control/operation-reservation-required":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-operation-reservation-required"]},"control/persona-authority-required":{"boundary_id":"control-signing.prepareAutomatedSigning","invariants":["CONTROL-I-BASELINE-ACTIVE-KEY"],"reasons":["control-persona-authority-required"]},"control/profile-heterodyne-control-marmot-frame-v1":{"boundary_id":"profile-negotiation.validateCurrentControlGrantProfile","invariants":["CONTROL-I-MARMOT-GRANT-CONFINEMENT"],"reasons":[]},"control/refresh-prohibited":{"boundary_id":"control-policy.validateControlFrameBoundary","invariants":["CONTROL-I-CLIENT-KEY-CONFINEMENT"],"reasons":["control-refresh-prohibited"]},"control/request-expired":{"boundary_id":"control-policy.evaluateControlOperationRequest","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-request-expired"]},"control/request-id-conflict":{"boundary_id":"control-policy.evaluateControlOperationRequest","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-request-id-conflict"]},"control/signed-event-invalid":{"boundary_id":"control-policy.validateControlSignedEffect","invariants":["CONTROL-I-AUTOMATION-ATTRIBUTION-BEFORE-SIGNING"],"reasons":["control-signed-event-invalid"]},"control/signer-binding-mismatch":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signer-binding-mismatch"]},"control/signer-effect-indeterminate":{"boundary_id":"control-policy.validateControlSignedEffect","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-signer-effect-indeterminate"]},"control/signer-unavailable":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-NO-SIGNER-FALLBACK"],"reasons":["control-signer-unavailable"]},"control/signing-grant-inactive":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-inactive"]},"control/signing-grant-invalid":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-invalid"]},"control/signing-grant-stale":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-stale"]},"control/signing-grant-unauthenticated":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-EXACT-SIGNER-GRANT"],"reasons":["control-signing-grant-unauthenticated"]},"control/signing-rate-limited":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-signing-rate-limited"]},"control/subordinate-reauthorization-required":{"boundary_id":"control-policy.evaluateCompromiseResetBoundary","invariants":["CONTROL-I-COMPROMISE-RESET"],"reasons":["control-subordinate-reauthorization-required"]},"control/token-invalid":{"boundary_id":"control-policy.validateControlFrameBoundary","invariants":["CONTROL-I-CLIENT-KEY-CONFINEMENT"],"reasons":["control-token-invalid"]},"control/usage-binding-mismatch":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-OPERATION-AT-MOST-ONCE"],"reasons":["control-usage-binding-mismatch"]},"control/vault-isolation-failed":{"boundary_id":"control-signing.authorizeNip46Signing","invariants":["CONTROL-I-PERSONA-VAULT-ISOLATION"],"reasons":["control-vault-isolation-failed"]},"core/config-rid-published":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["config_rid_advertised"]},"core/friend-cache-unsigned":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["unauthorized_cache_content"]},"core/nip01-raw-mismatch":{"boundary_id":"core-policy.validateCoreWireEnvelope","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["nip01_raw_mismatch"]},"core/nip49-key-material-round-trip":{"boundary_id":"backup-crypto.nip49EncryptDeterministic+nostr-tools.nip49.decrypt","invariants":["CORE-I-KEY-MATERIAL-AT-REST"],"reasons":[]},"core/node-advert-bad-signature":{"boundary_id":"radicle.validateNodeAdvertisement","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["bad_signature"]},"core/node-advert-clock-skew":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-clock-skew"]},"core/node-advert-clock-uncertain":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-clock-uncertain"]},"core/node-advert-dual-proof-valid":{"boundary_id":"radicle.validateNodeAdvertisement","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":[]},"core/node-advert-expired":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node_advert_expired"]},"core/node-advert-expiry-invalid":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-expiry-invalid"]},"core/node-advert-lifetime-exceeded":{"boundary_id":"follow-up-hardening.validateNodeAdvertisementTime","invariants":["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],"reasons":["node-advert-lifetime-exceeded"]},"core/node-advert-nid-proof-invalid":{"boundary_id":"radicle.validateNodeAdvertisement","invariants":[],"reasons":["nid_proof_invalid"]},"core/onion-clearnet-resolution":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["onion_dns_leak"]},"core/profile-heterodyne-core-rotation-breadcrumb-note-v1":{"boundary_id":"core-policy.validateCorePersonaSignedEvent","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":[]},"core/profile-heterodyne-core-rotation-breadcrumb-profile-v1":{"boundary_id":"core-policy.validateCorePersonaSignedEvent","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":[]},"core/profile-nip05-key-mismatch":{"boundary_id":"follow-up-hardening.validateCanonicalProfile","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["profile-nip05-key-mismatch"]},"core/profile-publisher-delegation-invalid":{"boundary_id":"follow-up-hardening.validateCanonicalProfile","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["profile-publisher-delegation-invalid"]},"core/profile-repository-selection-required":{"boundary_id":"follow-up-hardening.validateCanonicalProfile","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["profile-repository-selection-required"]},"core/relay-profile-mutated":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["relay_profile_mutation"]},"core/replaceable-advisory-nip03-ignored":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":[]},"core/replaceable-at-premature-boundary":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":[]},"core/replaceable-equal-time-lowest-id":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":[]},"core/replaceable-future-quarantined":{"boundary_id":"replaceable-selection.selectCurrentReplaceableEvent","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["core-created-at-premature"]},"core/retired-key-authority-window-invalid":{"boundary_id":"follow-up-hardening.classifyRetiredKeyObservation","invariants":["CORE-I-IDENTITY-INTEGRITY"],"reasons":["retired-key-authority-window-invalid"]},"core/strict-mode-without-tor":{"boundary_id":"core-policy.evaluateCoreOperationalBoundary","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["strict_mode_tor_disabled"]},"core/version-future-major":{"boundary_id":"core-policy.validateCoreWireEnvelope","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["unknown_major_version"]},"core/version-stamp-missing":{"boundary_id":"core-policy.validateCoreWireEnvelope","invariants":["CORE-I-VERIFY-BEFORE-USE"],"reasons":["version_stamp_invalid"]},"social/agent-attribution-falsified":{"boundary_id":"social-policy.evaluateAgentModerationEvidence","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT"],"reasons":["agent-attribution-falsified"]},"social/agent-attribution-missing":{"boundary_id":"social-policy.evaluateAgentModerationEvidence","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT"],"reasons":["agent-attribution-missing"]},"social/agent-policy-binding-invalid":{"boundary_id":"agent-moderation.validateAgentPolicyList","invariants":["SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":["agent-policy-binding-invalid"]},"social/agent-policy-receipt-invalid":{"boundary_id":"agent-moderation.validateAgentPolicyReceipt","invariants":["SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":["agent-policy-receipt-invalid"]},"social/agent-publication-bypass":{"boundary_id":"social-policy.evaluateAgentModerationEvidence","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT"],"reasons":["agent-publication-bypass"]},"social/author-binding-invalid":{"boundary_id":"social-events.validateSocialAuthorship","invariants":["SOCIAL-I-NIP01-AUTHORSHIP"],"reasons":["social-author-binding-invalid"]},"social/event-invalid":{"boundary_id":"social-events.validateSocialAuthorship","invariants":["SOCIAL-I-NIP01-AUTHORSHIP"],"reasons":["social-event-invalid"]},"social/moderator-not-in-asof-declaration":{"boundary_id":"social-policy.evaluateModeratorAsOfDeclaration","invariants":["SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":["moderator_not_in_asof_declaration"]},"social/profile-heterodyne-social-agent-policy-list-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT","SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":[]},"social/profile-heterodyne-social-agent-policy-receipt-v1":{"boundary_id":"agent-authorship.injectAgentAttribution+agent-moderation.applySubscribedAgentPolicy","invariants":["SOCIAL-I-AGENT-AUTHORSHIP-EXACT","SOCIAL-I-AGENT-POLICY-LOCAL"],"reasons":[]},"social/profile-heterodyne-social-mute-list-v1":{"boundary_id":"privacy-crypto.deriveConfigPostKey+nostr-tools.nip44","invariants":["SOCIAL-I-PRIVATE-STATE-AT-REST"],"reasons":[]},"social/replaceable-coordinate-mismatch":{"boundary_id":"social-events.validateSocialReplaceableCandidate","invariants":["SOCIAL-I-SOURCE-NEUTRAL-SELECTION"],"reasons":["social-replaceable-coordinate-mismatch"]},"social/source-neutral-core-quarantine":{"boundary_id":"social-events.selectCurrentSocialEvent","invariants":["SOCIAL-I-NO-CENTRAL-SOCIAL-GRAPH","SOCIAL-I-SOURCE-NEUTRAL-SELECTION"],"reasons":[]},"social/source-neutral-vanilla-authorship":{"boundary_id":"social-events.validateSocialAuthorship","invariants":["SOCIAL-I-NIP01-AUTHORSHIP"],"reasons":[]},"workspace/affiliation-stale":{"boundary_id":"workspace-policy.evaluateWorkspaceAffiliationBoundary","invariants":["WORKSPACE-I-FRESHNESS-BOUNDED"],"reasons":["affiliation_stale"]},"workspace/assurance-dual-removal":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":[]},"workspace/assurance-history-mutation-revalidated":{"boundary_id":"workspace-assurance.verifyWorkspaceAssuranceAuthorization","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":["workspace-assurance-state-required"]},"workspace/assurance-pending-activation":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":["workspace-assurance-state-required"]},"workspace/assurance-unilateral-removal":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":["workspace-assurance-state-required"]},"workspace/assurance-verified-activation":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":[]},"workspace/authority-checkpoint-stale":{"boundary_id":"workspace.evaluateFreshness","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE","WORKSPACE-I-FRESHNESS-BOUNDED"],"reasons":["checkpoint_stale"]},"workspace/authority-conflict":{"boundary_id":"workspace.evaluateWorkspaceObject","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["authority_conflict"]},"workspace/authority-freshness-boundary":{"boundary_id":"workspace.evaluateFreshness","invariants":["WORKSPACE-I-FRESHNESS-BOUNDED"],"reasons":[]},"workspace/bare-key-baseline":{"boundary_id":"workspace-assurance.evaluateWorkspaceAssuranceTransition","invariants":["WORKSPACE-I-OPTIONAL-ASSURANCE"],"reasons":[]},"workspace/carrier-not-ambient-authority":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-CARRIER-NOT-AUTHORITY","WORKSPACE-I-NO-AMBIENT-AUTHORITY"],"reasons":["policy_denied"]},"workspace/current-capability-intersection":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE","WORKSPACE-I-INHERITANCE-NARROWS","WORKSPACE-I-NO-AMBIENT-AUTHORITY"],"reasons":[]},"workspace/device-revoked":{"boundary_id":"workspace.evaluateRoleLeafChange","invariants":["WORKSPACE-I-DEVICE-LEAF-SEPARATION"],"reasons":["device_revoked"]},"workspace/history-denied":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceDeliveryBoundary","invariants":["WORKSPACE-I-REVOCATION-FUTURE-ONLY"],"reasons":["history_denied"]},"workspace/host-unauthorized":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceDeliveryBoundary","invariants":["WORKSPACE-I-HOST-AUTHORITY-SEPARATION"],"reasons":["host_unauthorized"]},"workspace/independent-device-leaf-removal":{"boundary_id":"workspace.evaluateRoleLeafChange","invariants":["WORKSPACE-I-DEVICE-LEAF-SEPARATION","WORKSPACE-I-REVOCATION-FUTURE-ONLY"],"reasons":[]},"workspace/independent-resource-content-keys":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceKeySeparation","invariants":["WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS"],"reasons":[]},"workspace/inheritance-escalation-rejected":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-INHERITANCE-NARROWS"],"reasons":["capability_escalation"]},"workspace/invitation-replay":{"boundary_id":"workspace-policy.evaluateWorkspaceStateTransitionBoundary","invariants":["WORKSPACE-I-NO-AMBIENT-AUTHORITY"],"reasons":["workspace_replay"]},"workspace/private-topology-clean":{"boundary_id":"workspace.evaluatePrivateProjection","invariants":["WORKSPACE-I-PRIVATE-TOPOLOGY"],"reasons":[]},"workspace/private-topology-disclosed":{"boundary_id":"workspace.evaluatePrivateProjection","invariants":["WORKSPACE-I-PRIVATE-TOPOLOGY"],"reasons":["private_topology_disclosed"]},"workspace/radicle-backed-hosts":{"boundary_id":"workspace.resolveEffectiveHosts","invariants":["WORKSPACE-I-HOST-AUTHORITY-SEPARATION","WORKSPACE-I-RADICLE-BACKSTOP"],"reasons":[]},"workspace/repository-invalid":{"boundary_id":"workspace.authenticateWorkspaceRepositoryView","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["workspace_repository_invalid"]},"workspace/resource-unknown":{"boundary_id":"workspace-policy.evaluateWorkspaceResourceDeliveryBoundary","invariants":["WORKSPACE-I-INDEPENDENT-RESOURCE-KEYS"],"reasons":["resource_unknown"]},"workspace/revocation-blocks-future-effect":{"boundary_id":"workspace-policy.evaluateWorkspaceCapabilityBoundary","invariants":["WORKSPACE-I-REVOCATION-FUTURE-ONLY"],"reasons":["policy_denied"]},"workspace/schema-invalid":{"boundary_id":"workspace.evaluateFreshness","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["workspace_schema_invalid"]},"workspace/signature-invalid":{"boundary_id":"workspace.evaluateWorkspaceObject","invariants":["WORKSPACE-I-AUTHENTICATED-CURRENT-STATE"],"reasons":["workspace_signature_invalid"],"postcondition":"workspace-signed-object-rejected"}} as const satisfies Readonly<Record<string, SemanticAllocationSource>>;

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

const ALL_SEMANTIC_ALLOCATIONS: Readonly<Record<string, SemanticAllocation>> =
  Object.freeze(Object.fromEntries(
    Object.entries({ ...SEMANTIC_ALLOCATIONS, ...TASK_TEN_SEMANTIC_ALLOCATIONS })
      .map(([vectorId, source]) => [vectorId, Object.freeze({
        ...source,
        postcondition: "postcondition" in source
          ? source.postcondition
          : `boundary-contract:${source.boundary_id}`,
      })]),
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
      return raw !== undefined && projected !== undefined
        && (record(raw.normalized) !== undefined
          ? projected.normalized === raw.normalized
          : captured === projected && typeof raw.reason_code === "string");
    case "assurance.evaluateSuccession":
      return raw !== undefined && projected !== undefined
        && (record(raw.normalized) !== undefined
          ? projected.normalized === raw.normalized
          : captured === projected && typeof raw.reason_code === "string");
    case "assurance.evaluateAssuranceAuthorityAt":
      return raw === projected && raw !== undefined && typeof raw.reason_code === "string";
    case "authorization-freshness.evaluateAuthorizationFreshness": {
      const view = record(raw?.view);
      return raw !== undefined && projected !== undefined
        && (view !== undefined
          ? projected.current_authorization_view === "opaque"
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
      return raw === projected && raw !== undefined
        && (typeof raw.event_author === "string" || typeof raw.reason_code === "string");
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
      return raw === projected && raw !== undefined
        && (record(raw.normalized) !== undefined || typeof raw.reason_code === "string");
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
  return outerValid && nidValid && projected.normalized === execution.raw_result;
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
  if (allocation.postcondition === `boundary-contract:${allocation.boundary_id}`) {
    return boundaryContractPostcondition(allocation.boundary_id, fixture, execution);
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
