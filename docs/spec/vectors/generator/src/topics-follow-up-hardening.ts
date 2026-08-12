import type { Fixtures } from "./fixtures.js";
import {
  classifyRetiredKeyObservation,
  resolveTier3Recipients,
  validateCanonicalProfile,
  validateNodeAdvertisementTime,
} from "./follow-up-hardening.js";
import { consumeVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

const vector = (
  path: string,
  vector_id: string,
  description: string,
  input: Record<string, unknown>,
  expected_output: Record<string, unknown>,
): AuthoredVector => consumeVector(path, {
  vector_id,
  spec_refs: ["canonical anchor supplied by vector metadata"],
  description,
  input,
  expected_output,
});

export function buildFollowUpHardeningVectors(fixtures: Fixtures): AuthoredVector[] {
  const alice = fixtures.personas.alice;
  const bob = fixtures.personas.bob;
  const device1 = fixtures.device_publishing_keys.alice_device_1.pubkey;
  const device2 = fixtures.device_publishing_keys.alice_device_2.pubkey;
  const revoked = fixtures.device_publishing_keys.bob_device_1.pubkey;
  const devices = [
    { persona: alice.cold_root.pubkey, pubkey: device1, active: true, role: "human-device" as const },
    { persona: alice.cold_root.pubkey, pubkey: device2, active: true, role: "human-device" as const },
    { persona: alice.cold_root.pubkey, pubkey: revoked, active: false, role: "human-device" as const },
  ];
  const tier = (id: string, selected?: string[]) => {
    const input = { memberPersonas: [alice.cold_root.pubkey], devices, ...(selected ? { selected } : {}) };
    return vector(`privacy-tiers/${id}.json`, `privacy-tiers/${id.replace(/^\d+-/, "")}`,
      `Tier 3 recipient resolution: ${id.replace(/^\d+-/, "").replaceAll("-", " ")}.`, input,
      resolveTier3Recipients(input));
  };

  const validProfile = {
    canonicalRepoSelected: true,
    publisher: device1,
    delegatedPublisher: device1,
    nip05Present: false,
  };
  const profile = (id: string, input: Parameters<typeof validateCanonicalProfile>[0]) =>
    vector(`persona-profile/${id}.json`, `persona-profile/${id.replace(/^\d+-/, "")}`,
      `Canonical persona profile: ${id.replace(/^\d+-/, "").replaceAll("-", " ")}.`, input,
      validateCanonicalProfile(input));

  const retirementBase = {
    signatureValid: true,
    createdAtInAuthorityWindow: true,
    compromiseSince: null,
    repoCommitAncestorOfRetirementCheckpoint: false,
    trustedLocalReceiptBeforeRetirement: false,
  };
  const retired = (id: string, input: Parameters<typeof classifyRetiredKeyObservation>[0]) =>
    vector(`key-retirement/${id}.json`, `key-retirement/${id.replace(/^\d+-/, "")}`,
      `Retired-key late discovery: ${id.replace(/^\d+-/, "").replaceAll("-", " ")}.`, input,
      classifyRetiredKeyObservation(input));

  const advert = (id: string, input: Parameters<typeof validateNodeAdvertisementTime>[0]) =>
    vector(`node-advert/${id}.json`, `node-advert/${id.replace(/^\d+-/, "")}`,
      `Node advertisement time: ${id.replace(/^\d+-/, "").replaceAll("-", " ")}.`, input,
      validateNodeAdvertisementTime(input));

  return [
    tier("006-all-active-devices"),
    tier("007-selected-device-narrowing", [device2]),
    tier("008-cold-root-recipient-rejected", [alice.cold_root.pubkey]),
    tier("009-epoch-recipient-rejected", [alice.epoch_keys.epoch_1.pubkey]),
    tier("010-revoked-device-rejected", [revoked]),
    vector("privacy-tiers/011-light-device-decryption.json", "privacy-tiers/light-device-decryption",
      "An authenticated light device decrypts its audience-key wrap with its delegated device publishing key.",
      { wrap_recipient: device1, decrypting_key: device1, private_key_location: "light-device" },
      { verdict: "accept", normalized: { directly_decryptable: true } }),
    vector("privacy-tiers/012-device-removal-rotates-generation.json", "privacy-tiers/device-removal-rotates-generation",
      "Removing a device from the effective persona audience rotates the complete audience generation.",
      { removed_device: device2, prior_key_id: "aud-a", next_key_id: "aud-b", remaining_wraps: [device1] },
      { verdict: "accept", normalized: { full_generation_rotation: true } }),
    profile("001-designated-publisher-valid", validProfile),
    profile("002-nip05-mismatch-rejected", { ...validProfile, nip05Present: true, nip05ResolvedKey: device2 }),
    vector("persona-profile/003-successor-address-republished.json", "persona-profile/successor-address-republished",
      "A live addressable object is republished under the successor publisher and the repository index selects the new coordinate.",
      { old_coordinate: [device1, 30023, "article"], successor_coordinate: [device2, 30023, "article"], repo_index_updated_atomically: true },
      { verdict: "accept", normalized: { live_coordinate: [device2, 30023, "article"], old_coordinate: "historical" } }),
    vector("persona-profile/004-exact-author-set-discovery.json", "persona-profile/exact-author-set-discovery",
      "Historical discovery uses ordinary exact-hex author filters derived from accepted delegation history.",
      { accepted_publishers: [device1, device2], relay_filter_authors: [device1, device2] },
      { verdict: "accept", normalized: { relay_semantics_redefined: false } }),
    profile("005-relay-only-replacement-rejected", { ...validProfile, canonicalRepoSelected: false, publisher: device2, delegatedPublisher: device2 }),
    retired("001-repo-anchored-pre-retirement", { ...retirementBase, repoCommitAncestorOfRetirementCheckpoint: true }),
    retired("002-local-receipt-pre-retirement", { ...retirementBase, trustedLocalReceiptBeforeRetirement: true }),
    retired("003-relay-only-provisional", retirementBase),
    retired("004-compromise-cutoff-rejected", { ...retirementBase, compromiseSince: 100, eventCreatedAt: 100, repoCommitAncestorOfRetirementCheckpoint: true }),
    advert("006-maximum-lifetime", { createdAt: 1_300, expiry: 87_700, now: 1_000, clockUncertainty: 0 }),
    advert("007-excessive-lifetime", { createdAt: 1_000, expiry: 87_401, now: 1_000, clockUncertainty: 0 }),
    advert("008-future-clock-skew", { createdAt: 1_301, expiry: 2_000, now: 1_000, clockUncertainty: 0 }),
    advert("009-past-clock-skew", { createdAt: 699, expiry: 2_000, now: 1_000, clockUncertainty: 0 }),
    advert("010-expiry-not-after-created", { createdAt: 1_000, expiry: 1_000, now: 1_000, clockUncertainty: 0 }),
    advert("011-refresh-by-twelve-hours", { createdAt: 1_000, expiry: 87_400, now: 1_000, clockUncertainty: 0 }),
    advert("012-uncertain-clock-rejected", { createdAt: 1_000, expiry: 2_000, now: 1_000, clockUncertainty: 301 }),
    advert("013-previously-accepted-within-expiry", {
      createdAt: 1_000,
      expiry: 87_400,
      now: 10_000,
      clockUncertainty: 0,
      priorAcceptanceEvidence: true,
    }),
    advert("014-provisional-observation-does-not-bypass-skew", {
      createdAt: 1_000,
      expiry: 87_400,
      now: 10_000,
      clockUncertainty: 0,
      priorAcceptanceEvidence: false,
    }),
  ];
}
