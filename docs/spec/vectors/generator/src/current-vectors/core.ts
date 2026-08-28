import * as nip49 from "nostr-tools/nip49";
import { nip49EncryptDeterministic } from "../backup-crypto.js";
import {
  evaluateCoreOperationalBoundary,
  validateCoreWireEnvelope,
  validateOrganizationMemberAddition,
  validateRoleDelegation,
} from "../core-policy.js";
import { QUALIFIED_VERSION } from "../family.js";
import { bytesToHex } from "../hex.js";
import {
  classifyRetiredKeyObservation,
  validateCanonicalProfile,
  validateNodeAdvertisementTime,
} from "../follow-up-hardening.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "../nostr.js";
import {
  didKeyFromEd25519,
  ed25519PublicKey,
  ed25519Sign,
  nodeAdvertPayload,
  validateNodeAdvertisement,
} from "../radicle.js";
import {
  createReplaceableSelectionAuthority,
  selectCurrentReplaceableEvent,
} from "../replaceable-selection.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const SECRET = "19".repeat(32);
const AUX_RAND = "00".repeat(32);
const NOW = 1_800_000_000;
const NODE_SECRET = "21".padStart(64, "0");
const NID_SECRET = "22".padStart(64, "0");
const RID = "rad:zCurrentCatalogFixture";
const ENDPOINT = "wss://node.example/relay";
const EXPIRY = NOW + 3_600;
const REPO_HEAD = "ab".repeat(20);

async function replaceable(created_at: number, content: string): Promise<NostrSignedEvent> {
  return signEvent({
    secretKey: SECRET,
    created_at,
    kind: 30_000,
    tags: [["d", "current-selection"]],
    content,
    auxRand: AUX_RAND,
  });
}

async function nodeAdvertisement(repoHead = REPO_HEAD): Promise<NostrSignedEvent> {
  const nid = didKeyFromEd25519(ed25519PublicKey(NID_SECRET));
  const nidProof = ed25519Sign(
    nodeAdvertPayload(RID, nid, ENDPOINT, EXPIRY, REPO_HEAD),
    NID_SECRET,
  );
  return signEvent({
    secretKey: NODE_SECRET,
    created_at: NOW,
    kind: 31_010,
    tags: [
      ["d", RID],
      ["heterodyne", "node_advert"],
      ["rid", RID],
      ["nid", nid],
      ["endpoint", ENDPOINT],
      ["repo_head", repoHead],
      ["expiry", String(EXPIRY)],
      ["nid_proof", nidProof],
      ["spec_version", QUALIFIED_VERSION],
    ],
    content: "",
    auxRand: AUX_RAND,
  });
}

export async function buildCoreCases(): Promise<CurrentVectorCase[]> {
  const authority = createReplaceableSelectionAuthority({ trusted_now: () => NOW });
  const premature = await replaceable(NOW + 901, "premature candidate");
  const prematureResult = selectCurrentReplaceableEvent(authority, [premature]);
  const boundary = await replaceable(NOW + 900, "boundary candidate");
  const boundaryResult = selectCurrentReplaceableEvent(authority, [boundary]);
  const equalLeft = await replaceable(NOW, "equal left");
  const equalRight = await replaceable(NOW, "equal right");
  const equalResult = selectCurrentReplaceableEvent(authority, [equalLeft, equalRight]);
  const older = await replaceable(NOW - 2, "older");
  const newer = await replaceable(NOW - 1, "newer");
  const advisory = await signEvent({
    secretKey: SECRET,
    created_at: NOW,
    kind: 1_040,
    tags: [["e", older.id]],
    content: "synthetic advisory timestamp evidence",
    auxRand: AUX_RAND,
  });
  const advisoryResult = selectCurrentReplaceableEvent(authority, [older, advisory, newer]);
  const advert = await nodeAdvertisement();
  const advertDecision = validateNodeAdvertisement(advert, {
    now: NOW,
    graph_fetch: { status: "available", reachable_oids: [REPO_HEAD] },
  });
  const badAdvert = { ...advert, sig: "00".repeat(64) };
  const badAdvertDecision = validateNodeAdvertisement(badAdvert, {
    now: NOW,
    graph_fetch: { status: "available", reachable_oids: [REPO_HEAD] },
  });
  const substitutedHead = "cd".repeat(20);
  const substitutedAdvert = await nodeAdvertisement(substitutedHead);
  const substitutedDecision = validateNodeAdvertisement(substitutedAdvert, {
    now: NOW,
    graph_fetch: { status: "available", reachable_oids: [substitutedHead] },
  });
  const nsec = "01".padStart(64, "0");
  const password = "current-vector-passphrase";
  const salt = "70".repeat(16);
  const nonce = "71".repeat(24);
  const ncryptsec = nip49EncryptDeterministic(nsec, password, salt, nonce);
  const recoveredSecret = bytesToHex(nip49.decrypt(ncryptsec, password));
  const profileRepositoryInput = {
    canonicalRepoSelected: false,
    publisher: getPublicKey(NODE_SECRET),
    delegatedPublisher: getPublicKey(NODE_SECRET),
    nip05Present: false,
  };
  const profileRepositoryDecision = validateCanonicalProfile(profileRepositoryInput);
  const profileDelegationInput = { ...profileRepositoryInput, canonicalRepoSelected: true, delegatedPublisher: "00".repeat(32) };
  const profileDelegationDecision = validateCanonicalProfile(profileDelegationInput);
  const profileNip05Input = {
    ...profileRepositoryInput,
    canonicalRepoSelected: true,
    nip05Present: true,
    nip05ResolvedKey: "00".repeat(32),
  };
  const profileNip05Decision = validateCanonicalProfile(profileNip05Input);
  const retiredWindowInput = {
    signatureValid: true,
    createdAtInAuthorityWindow: false,
    compromiseSince: null,
    repoCommitAncestorOfRetirementCheckpoint: false,
    trustedLocalReceiptBeforeRetirement: false,
  };
  const retiredWindowDecision = classifyRetiredKeyObservation(retiredWindowInput);
  const nodeTimeCases = [
    {
      suffix: "expiry-invalid",
      reason: "node-advert-expiry-invalid",
      input: { createdAt: NOW, expiry: NOW, now: NOW, clockUncertainty: 0 },
    },
    {
      suffix: "lifetime-exceeded",
      reason: "node-advert-lifetime-exceeded",
      input: { createdAt: NOW, expiry: NOW + 86_401, now: NOW, clockUncertainty: 0 },
    },
    {
      suffix: "expired",
      reason: "node_advert_expired",
      input: { createdAt: NOW - 10, expiry: NOW, now: NOW, clockUncertainty: 0 },
    },
    {
      suffix: "clock-uncertain",
      reason: "node-advert-clock-uncertain",
      input: { createdAt: NOW, expiry: NOW + 60, now: NOW, clockUncertainty: 301 },
    },
    {
      suffix: "clock-skew",
      reason: "node-advert-clock-skew",
      input: { createdAt: NOW + 301, expiry: NOW + 600, now: NOW, clockUncertainty: 0 },
    },
  ].map((entry) => ({ ...entry, decision: validateNodeAdvertisementTime(entry.input) }));
  const unstampedEvent = await signEvent({
    secretKey: SECRET,
    created_at: NOW,
    kind: 1,
    tags: [],
    content: "unstamped current Core fixture",
    auxRand: AUX_RAND,
  });
  const futureMajorEvent = await signEvent({
    secretKey: SECRET,
    created_at: NOW,
    kind: 1,
    tags: [["spec_version", "heterodyne/1.0.0"]],
    content: "future-major current Core fixture",
    auxRand: AUX_RAND,
  });
  const nip01RawInput = {
    event: advert,
    nip01_raw: "[]",
    stamp_policy: "required" as const,
  };
  const missingStampInput = {
    event: unstampedEvent,
    nip01_raw: JSON.stringify([0, unstampedEvent.pubkey, unstampedEvent.created_at, unstampedEvent.kind, unstampedEvent.tags, unstampedEvent.content]),
    stamp_policy: "required" as const,
  };
  const futureMajorInput = {
    event: futureMajorEvent,
    nip01_raw: JSON.stringify([0, futureMajorEvent.pubkey, futureMajorEvent.created_at, futureMajorEvent.kind, futureMajorEvent.tags, futureMajorEvent.content]),
    stamp_policy: "required" as const,
  };
  const onionInput = { operation: "resolve-host" as const, host: "catalogfixture.onion", resolver: "clearnet" as const };
  const strictModeInput = { operation: "start-strict-mode" as const, tor_egress: false, explicit_user_choice: false };
  const cacheInput = { operation: "read-friend-cache" as const, owner_signed: false, content_class: "nostr" as const };
  const relayInput = { operation: "relay-profile" as const, vanilla_nip01_unchanged: false };
  const configRidInput = { operation: "publish-surface" as const, config_rid: RID, values: [RID] };
  const organizationInput = { member_kel_authorized: true, org_admin_threshold_authorized: false };
  const roleAddressInput = { namespace: "other.role", registered_namespace: "workspace.role", role_id: "maintainer", key_proof_valid: true };
  const roleProofInput = { namespace: "workspace.role", registered_namespace: "workspace.role", role_id: "maintainer", key_proof_valid: false };
  const corePolicyCases: CurrentVectorCase[] = [
    {
      relativePath: "core/nip01-raw-mismatch.json",
      semantic_boundary: "core-policy.validateCoreWireEnvelope",
      vector_id: "core/nip01-raw-mismatch",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-verification")],
      invariants: ["CORE-I-VERIFY-BEFORE-USE"],
      reason_codes: ["nip01_raw_mismatch"],
      description: "A stored raw NIP-01 signing input must be byte-identical to the canonical event serialization.",
      direction: "consume",
      input: nip01RawInput,
      expected_output: validateCoreWireEnvelope(nip01RawInput),
    },
    {
      relativePath: "core/version-stamp-missing.json",
      semantic_boundary: "core-policy.validateCoreWireEnvelope",
      vector_id: "core/version-stamp-missing",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-verification")],
      invariants: ["CORE-I-VERIFY-BEFORE-USE"],
      reason_codes: ["version_stamp_invalid"],
      description: "A current event class requiring a family version stamp rejects an absent stamp.",
      direction: "consume",
      input: missingStampInput,
      expected_output: validateCoreWireEnvelope(missingStampInput),
    },
    {
      relativePath: "core/version-future-major.json",
      semantic_boundary: "core-policy.validateCoreWireEnvelope",
      vector_id: "core/version-future-major",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-conformance")],
      invariants: ["CORE-I-VERIFY-BEFORE-USE"],
      reason_codes: ["unknown_major_version"],
      description: "A valid event carrying a strictly newer unsupported family major is rejected as incompatible.",
      direction: "consume",
      input: futureMajorInput,
      expected_output: validateCoreWireEnvelope(futureMajorInput),
    },
    ...[
      ["onion-clearnet-resolution", "onion_dns_leak", onionInput, evaluateCoreOperationalBoundary(onionInput)],
      ["strict-mode-without-tor", "strict_mode_tor_disabled", strictModeInput, evaluateCoreOperationalBoundary(strictModeInput)],
      ["friend-cache-unsigned", "unauthorized_cache_content", cacheInput, evaluateCoreOperationalBoundary(cacheInput)],
      ["relay-profile-mutated", "relay_profile_mutation", relayInput, evaluateCoreOperationalBoundary(relayInput)],
      ["config-rid-published", "config_rid_advertised", configRidInput, evaluateCoreOperationalBoundary(configRidInput)],
    ].map(([id, reason, input, decision]) => ({
      relativePath: `core/${id}.json`,
      semantic_boundary: "core-policy.evaluateCoreOperationalBoundary",
      vector_id: `core/${id}`,
      owner_document: "core" as const,
      spec_refs: [currentSpecRef("core-conformance")],
      invariants: [reason === "onion_dns_leak" || reason === "strict_mode_tor_disabled"
        ? "CORE-I-VERIFY-BEFORE-USE"
        : "CORE-I-IDENTITY-INTEGRITY"],
      reason_codes: [reason as string],
      description: `The Core operational boundary rejects ${String(id).replaceAll("-", " ")}.`,
      direction: "consume" as const,
      input: input as Record<string, unknown>,
      expected_output: decision as Record<string, unknown>,
    })),
    {
      relativePath: "core/org-member-add-unauthorized.json",
      semantic_boundary: "core-policy.validateOrganizationMemberAddition",
      vector_id: "core/org-member-add-unauthorized",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-conformance")],
      invariants: ["CORE-I-IDENTITY-INTEGRITY"],
      reason_codes: ["org_member_add_unauthorized"],
      description: "One member-KEL approval cannot substitute for the independent organization-admin threshold.",
      direction: "consume",
      input: organizationInput,
      expected_output: validateOrganizationMemberAddition(organizationInput),
    },
    {
      relativePath: "core/role-delegation-address-invalid.json",
      semantic_boundary: "core-policy.validateRoleDelegation",
      vector_id: "core/role-delegation-address-invalid",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-nid-delegation")],
      invariants: ["CORE-I-NID-DELEGATION-DUAL-PROOF"],
      reason_codes: ["role-delegation-address-invalid"],
      description: "A role-addressed delegation must use the exact registered namespace and role syntax.",
      direction: "consume",
      input: roleAddressInput,
      expected_output: validateRoleDelegation(roleAddressInput),
    },
    {
      relativePath: "core/role-delegation-key-proof-invalid.json",
      semantic_boundary: "core-policy.validateRoleDelegation",
      vector_id: "core/role-delegation-key-proof-invalid",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-nid-delegation")],
      invariants: ["CORE-I-NID-DELEGATION-DUAL-PROOF"],
      reason_codes: ["role-delegation-key-proof-invalid"],
      description: "A correctly addressed role delegation remains unauthorized without its registered key proof.",
      direction: "consume",
      input: roleProofInput,
      expected_output: validateRoleDelegation(roleProofInput),
    },
  ];

  return [
    ...corePolicyCases,
    {
      relativePath: "core/replaceable-future-quarantined.json",
      semantic_boundary: "replaceable-selection.selectCurrentReplaceableEvent",
      vector_id: "core/replaceable-future-quarantined",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-created-at-bound")],
      invariants: ["CORE-I-VERIFY-BEFORE-USE"],
      reason_codes: ["core-created-at-premature"],
      description: "A replaceable event more than 900 seconds ahead is quarantined without being selected.",
      direction: "consume",
      input: { trusted_now: NOW, candidates: [premature] },
      expected_output: {
        verdict: "reject",
        reason_code: prematureResult.quarantined[0]?.reason_code,
        selected_event_id: prematureResult.selected?.id ?? null,
        quarantined_event_ids: prematureResult.quarantined.map(({ event_id }) => event_id),
      },
    },
    {
      relativePath: "core/replaceable-at-premature-boundary.json",
      semantic_boundary: "replaceable-selection.selectCurrentReplaceableEvent",
      vector_id: "core/replaceable-at-premature-boundary",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-created-at-bound")],
      invariants: ["CORE-I-VERIFY-BEFORE-USE"],
      reason_codes: [],
      description: "A replaceable event exactly 900 seconds ahead remains eligible.",
      direction: "consume",
      input: { trusted_now: NOW, candidates: [boundary] },
      expected_output: {
        verdict: "accept",
        selected_event_id: boundaryResult.selected?.id ?? null,
        quarantined_event_ids: boundaryResult.quarantined.map(({ event_id }) => event_id),
      },
    },
    {
      relativePath: "core/replaceable-equal-time-lowest-id.json",
      semantic_boundary: "replaceable-selection.selectCurrentReplaceableEvent",
      vector_id: "core/replaceable-equal-time-lowest-id",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-source-neutral-selection")],
      invariants: ["CORE-I-VERIFY-BEFORE-USE"],
      reason_codes: [],
      description: "Equal-time replaceable events select the lowest lexicographic event identifier.",
      direction: "consume",
      input: { trusted_now: NOW, candidates: [equalLeft, equalRight] },
      expected_output: {
        verdict: "accept",
        selected_event_id: equalResult.selected?.id ?? null,
      },
    },
    {
      relativePath: "core/replaceable-advisory-nip03-ignored.json",
      semantic_boundary: "replaceable-selection.selectCurrentReplaceableEvent",
      vector_id: "core/replaceable-advisory-nip03-ignored",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-nip03-advisory")],
      invariants: ["CORE-I-VERIFY-BEFORE-USE"],
      reason_codes: [],
      description: "Advisory kind-1040 evidence has no authority over NIP-01 replacement selection.",
      direction: "consume",
      input: { trusted_now: NOW, candidates: [older, advisory, newer] },
      expected_output: {
        verdict: "accept",
        selected_event_id: advisoryResult.selected?.id ?? null,
      },
    },
    {
      relativePath: "core/node-advert-dual-proof-valid.json",
      semantic_boundary: "radicle.validateNodeAdvertisement",
      vector_id: "core/node-advert-dual-proof-valid",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-node-advertisement")],
      invariants: [
        "CORE-I-NID-DELEGATION-DUAL-PROOF",
        "CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY",
      ],
      reason_codes: [],
      description: "A locally verified NIP-01 advertisement and exact Ed25519 NID proof authorize one repository head without a directory lookup.",
      direction: "consume",
      input: { event: advert, trusted_now: NOW, reachable_oids: [REPO_HEAD] },
      expected_output: { verdict: "accept", normalized: advertDecision },
    },
    {
      relativePath: "core/node-advert-bad-signature.json",
      semantic_boundary: "radicle.validateNodeAdvertisement",
      vector_id: "core/node-advert-bad-signature",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-node-advertisement")],
      invariants: ["CORE-I-VERIFY-BEFORE-USE"],
      reason_codes: ["bad_signature"],
      description: "A node advertisement with a substituted NIP-01 signature is rejected before its NID proof or repository graph is trusted.",
      direction: "consume",
      input: { event: badAdvert, trusted_now: NOW, reachable_oids: [REPO_HEAD] },
      expected_output: { verdict: "reject", reason_code: badAdvertDecision.status === "rejected" ? badAdvertDecision.failure : null },
    },
    {
      relativePath: "core/node-advert-nid-proof-invalid.json",
      semantic_boundary: "radicle.validateNodeAdvertisement",
      vector_id: "core/node-advert-nid-proof-invalid",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-node-advertisement")],
      invariants: ["CORE-I-NID-DELEGATION-DUAL-PROOF"],
      reason_codes: ["nid_proof_invalid"],
      description: "A valid outer event cannot authorize a substituted repository head when the NID proof binds different exact bytes.",
      direction: "consume",
      input: { event: substitutedAdvert, trusted_now: NOW, reachable_oids: [substitutedHead] },
      expected_output: { verdict: "reject", reason_code: substitutedDecision.status === "rejected" ? substitutedDecision.failure : null },
    },
    {
      relativePath: "core/nip49-key-material-round-trip.json",
      semantic_boundary: "backup-crypto.nip49EncryptDeterministic+nostr-tools.nip49.decrypt",
      vector_id: "core/nip49-key-material-round-trip",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-keys-repository")],
      invariants: ["CORE-I-KEY-MATERIAL-AT-REST"],
      reason_codes: [],
      description: "Deterministic synthetic NIP-49 wrapping decrypts to the exact original persona secret key.",
      direction: "round-trip",
      input: { secret_key: nsec, password, salt, nonce },
      expected_output: { verdict: "accept", ncryptsec, recovered_secret: recoveredSecret },
    },
    {
      relativePath: "core/profile-repository-selection-required.json",
      semantic_boundary: "follow-up-hardening.validateCanonicalProfile",
      vector_id: "core/profile-repository-selection-required",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-persona-profile")],
      invariants: ["CORE-I-IDENTITY-INTEGRITY"],
      reason_codes: ["profile-repository-selection-required"],
      description: "Relay profile state cannot become canonical without selecting the verified profile repository.",
      direction: "consume",
      input: profileRepositoryInput,
      expected_output: profileRepositoryDecision,
    },
    {
      relativePath: "core/profile-publisher-delegation-invalid.json",
      semantic_boundary: "follow-up-hardening.validateCanonicalProfile",
      vector_id: "core/profile-publisher-delegation-invalid",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-persona-profile")],
      invariants: ["CORE-I-IDENTITY-INTEGRITY"],
      reason_codes: ["profile-publisher-delegation-invalid"],
      description: "A profile event signed by a key other than the active delegated publisher is rejected.",
      direction: "consume",
      input: profileDelegationInput,
      expected_output: profileDelegationDecision,
    },
    {
      relativePath: "core/profile-nip05-key-mismatch.json",
      semantic_boundary: "follow-up-hardening.validateCanonicalProfile",
      vector_id: "core/profile-nip05-key-mismatch",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-persona-profile")],
      invariants: ["CORE-I-IDENTITY-INTEGRITY"],
      reason_codes: ["profile-nip05-key-mismatch"],
      description: "Optional NIP-05 profile resolution cannot substitute a key other than the designated publisher.",
      direction: "consume",
      input: profileNip05Input,
      expected_output: profileNip05Decision,
    },
    {
      relativePath: "core/retired-key-authority-window-invalid.json",
      semantic_boundary: "follow-up-hardening.classifyRetiredKeyObservation",
      vector_id: "core/retired-key-authority-window-invalid",
      owner_document: "core",
      spec_refs: [currentSpecRef("core-retired-key-observation")],
      invariants: ["CORE-I-IDENTITY-INTEGRITY"],
      reason_codes: ["retired-key-authority-window-invalid"],
      description: "Retired-key content outside the exact accepted authority window is rejected.",
      direction: "consume",
      input: retiredWindowInput,
      expected_output: retiredWindowDecision,
    },
    ...nodeTimeCases.map(({ suffix, reason, input, decision }) => ({
      relativePath: `core/node-advert-${suffix}.json`,
      semantic_boundary: "follow-up-hardening.validateNodeAdvertisementTime",
      vector_id: `core/node-advert-${suffix}`,
      owner_document: "core" as const,
      spec_refs: [currentSpecRef("core-node-advertisement")],
      invariants: ["CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY"],
      reason_codes: [reason],
      description: `The node-advertisement time boundary rejects the ${suffix.replaceAll("-", " ")} condition.`,
      direction: "consume" as const,
      input,
      expected_output: decision,
    })),
  ];
}
