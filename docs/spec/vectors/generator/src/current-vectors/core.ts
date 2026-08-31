import * as nip49 from "nostr-tools/nip49";
import { nip49EncryptDeterministic } from "../backup-crypto.js";
import { evaluateCoreOperationalBoundary, validateCoreWireEnvelope, } from "../core-policy.js";
import { QUALIFIED_VERSION } from "../family.js";
import { bytesToHex } from "../hex.js";
import { classifyRetiredKeyObservation, validateCanonicalProfile, validateNodeAdvertisementTime, } from "../follow-up-hardening.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "../nostr.js";
import { didKeyFromEd25519, ed25519PublicKey, ed25519Sign, nodeAdvertPayload, validateNodeAdvertisement, } from "../radicle.js";
import { createReplaceableSelectionAuthority, selectCurrentReplaceableEvent, } from "../replaceable-selection.js";
import { currentSpecRef, type CurrentCaseFixture } from "./types.js";
const SECRET = "19".repeat(32);
const AUX_RAND = "00".repeat(32);
const NOW = 1800000000;
const NODE_SECRET = "21".padStart(64, "0");
const NID_SECRET = "22".padStart(64, "0");
const RID = "rad:zCurrentCatalogFixture";
const ENDPOINT = "wss://node.example/relay";
const EXPIRY = NOW + 3600;
const REPO_HEAD = "ab".repeat(20);
async function replaceable(created_at: number, content: string): Promise<NostrSignedEvent> {
    return signEvent({
        secretKey: SECRET,
        created_at,
        kind: 30000,
        tags: [["d", "current-selection"]],
        content,
        auxRand: AUX_RAND,
    });
}
async function nodeAdvertisement(repoHead = REPO_HEAD): Promise<NostrSignedEvent> {
    const nid = didKeyFromEd25519(ed25519PublicKey(NID_SECRET));
    const nidProof = ed25519Sign(nodeAdvertPayload(RID, nid, ENDPOINT, EXPIRY, REPO_HEAD), NID_SECRET);
    return signEvent({
        secretKey: NODE_SECRET,
        created_at: NOW,
        kind: 31010,
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
export async function buildCoreCases(): Promise<CurrentCaseFixture[]> {
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
        kind: 1040,
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
            input: { createdAt: NOW, expiry: NOW, now: NOW, clockUncertainty: 0 },
        },
        {
            suffix: "lifetime-exceeded",
            input: { createdAt: NOW, expiry: NOW + 86401, now: NOW, clockUncertainty: 0 },
        },
        {
            suffix: "expired",
            input: { createdAt: NOW - 10, expiry: NOW, now: NOW, clockUncertainty: 0 },
        },
        {
            suffix: "clock-uncertain",
            input: { createdAt: NOW, expiry: NOW + 60, now: NOW, clockUncertainty: 301 },
        },
        {
            suffix: "clock-skew",
            input: { createdAt: NOW + 301, expiry: NOW + 600, now: NOW, clockUncertainty: 0 },
        },
    ];
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
    const corePolicyCases: CurrentCaseFixture[] = [
        {
            vector_id: "core/nip01-raw-mismatch",
            description: "A stored raw NIP-01 signing input must be byte-identical to the canonical event serialization.",
            direction: "consume",
            input: nip01RawInput
        },
        {
            vector_id: "core/version-stamp-missing",
            description: "A current event class requiring a family version stamp rejects an absent stamp.",
            direction: "consume",
            input: missingStampInput
        },
        {
            vector_id: "core/version-future-major",
            description: "A valid event carrying a strictly newer unsupported family major is rejected as incompatible.",
            direction: "consume",
            input: futureMajorInput
        },
        ...[
            ["onion-clearnet-resolution", onionInput],
            ["strict-mode-without-tor", strictModeInput],
            ["friend-cache-unsigned", cacheInput],
            ["relay-profile-mutated", relayInput],
            ["config-rid-published", configRidInput],
        ].map(([id, input]) => ({
            vector_id: `core/${id}`,
            description: `The Core operational boundary rejects ${String(id).replaceAll("-", " ")}.`,
            direction: "consume" as const,
            input: input as Record<string, unknown>
        })),
    ];
    return [
        ...corePolicyCases,
        {
            vector_id: "core/replaceable-future-quarantined",
            description: "A replaceable event more than 900 seconds ahead is quarantined without being selected.",
            direction: "consume",
            input: { trusted_now: NOW, candidates: [premature] }
        },
        {
            vector_id: "core/replaceable-at-premature-boundary",
            description: "A replaceable event exactly 900 seconds ahead remains eligible.",
            direction: "consume",
            input: { trusted_now: NOW, candidates: [boundary] }
        },
        {
            vector_id: "core/replaceable-equal-time-lowest-id",
            description: "Equal-time replaceable events select the lowest lexicographic event identifier.",
            direction: "consume",
            input: { trusted_now: NOW, candidates: [equalLeft, equalRight] }
        },
        {
            vector_id: "core/replaceable-advisory-nip03-ignored",
            description: "Advisory kind-1040 evidence has no authority over NIP-01 replacement selection.",
            direction: "consume",
            input: { trusted_now: NOW, candidates: [older, advisory, newer] }
        },
        {
            vector_id: "core/node-advert-dual-proof-valid",
            description: "A locally verified NIP-01 advertisement and exact Ed25519 NID proof authorize one repository head without a directory lookup.",
            direction: "consume",
            input: { event: advert, trusted_now: NOW, reachable_oids: [REPO_HEAD] }
        },
        {
            vector_id: "core/node-advert-bad-signature",
            description: "A node advertisement with a substituted NIP-01 signature is rejected before its NID proof or repository graph is trusted.",
            direction: "consume",
            input: { event: badAdvert, trusted_now: NOW, reachable_oids: [REPO_HEAD] }
        },
        {
            vector_id: "core/node-advert-nid-proof-invalid",
            description: "A valid outer event cannot authorize a substituted repository head when the NID proof binds different exact bytes.",
            direction: "consume",
            input: { event: substitutedAdvert, trusted_now: NOW, reachable_oids: [substitutedHead] }
        },
        {
            vector_id: "core/nip49-key-material-round-trip",
            description: "Deterministic synthetic NIP-49 wrapping decrypts to the exact original persona secret key.",
            direction: "round-trip",
            input: { secret_key: nsec, password, salt, nonce }
        },
        {
            vector_id: "core/profile-repository-selection-required",
            description: "Relay profile state cannot become canonical without selecting the verified profile repository.",
            direction: "consume",
            input: profileRepositoryInput
        },
        {
            vector_id: "core/profile-publisher-delegation-invalid",
            description: "A profile event signed by a key other than the active delegated publisher is rejected.",
            direction: "consume",
            input: profileDelegationInput
        },
        {
            vector_id: "core/profile-nip05-key-mismatch",
            description: "Optional NIP-05 profile resolution cannot substitute a key other than the designated publisher.",
            direction: "consume",
            input: profileNip05Input
        },
        {
            vector_id: "core/retired-key-authority-window-invalid",
            description: "Retired-key content outside the exact accepted authority window is rejected.",
            direction: "consume",
            input: retiredWindowInput
        },
        ...nodeTimeCases.map(({ suffix, input }) => ({
            vector_id: `core/node-advert-${suffix}`,
            description: `The node-advertisement time boundary rejects the ${suffix.replaceAll("-", " ")} condition.`,
            direction: "consume" as const,
            input
        })),
    ];
}
