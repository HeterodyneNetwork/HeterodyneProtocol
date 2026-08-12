import { describe, expect, it } from "vitest";
import {
  classifyRetiredKeyObservation,
  resolveTier3Recipients,
  validateCanonicalProfile,
  validateNodeAdvertisementTime,
} from "./follow-up-hardening.js";

const hex = (digit: string) => digit.repeat(64);

describe("Tier 3 device recipients", () => {
  const devices = [
    { persona: hex("a"), pubkey: hex("1"), active: true, role: "human-device" as const },
    { persona: hex("a"), pubkey: hex("2"), active: true, role: "human-device" as const },
    { persona: hex("a"), pubkey: hex("3"), active: false, role: "human-device" as const },
  ];

  it("expands a persona to every active delegated human device", () => {
    expect(resolveTier3Recipients({ memberPersonas: [hex("a")], devices })).toEqual({
      verdict: "accept",
      recipients: [hex("1"), hex("2")],
    });
  });

  it("allows narrowing but rejects identity and inactive keys", () => {
    expect(resolveTier3Recipients({ memberPersonas: [hex("a")], devices, selected: [hex("2")] }))
      .toMatchObject({ verdict: "accept", recipients: [hex("2")] });
    for (const selected of [[hex("3")], [hex("a")], [hex("b")]]) {
      expect(resolveTier3Recipients({ memberPersonas: [hex("a")], devices, selected }))
        .toMatchObject({ verdict: "reject", reason_code: "tier3-recipient-not-active-device" });
    }
  });
});

describe("canonical persona profiles", () => {
  it("accepts only the repo-designated active publisher and valid optional NIP-05", () => {
    expect(validateCanonicalProfile({
      canonicalRepoSelected: true,
      publisher: hex("1"),
      delegatedPublisher: hex("1"),
      nip05Present: true,
      nip05ResolvedKey: hex("1"),
    })).toEqual({ verdict: "accept" });
    expect(validateCanonicalProfile({
      canonicalRepoSelected: true,
      publisher: hex("1"),
      delegatedPublisher: hex("1"),
      nip05Present: true,
      nip05ResolvedKey: hex("2"),
    })).toMatchObject({ verdict: "reject", reason_code: "profile-nip05-key-mismatch" });
  });

  it("requires repository selection instead of relay replacement order", () => {
    expect(validateCanonicalProfile({
      canonicalRepoSelected: false,
      publisher: hex("2"),
      delegatedPublisher: hex("2"),
      nip05Present: false,
    })).toMatchObject({ verdict: "reject", reason_code: "profile-repository-selection-required" });
  });
});

describe("retired-key late discovery", () => {
  it("accepts pre-retirement anchors and otherwise returns provisional", () => {
    expect(classifyRetiredKeyObservation({
      signatureValid: true, createdAtInAuthorityWindow: true, compromiseSince: null,
      repoCommitAncestorOfRetirementCheckpoint: true, trustedLocalReceiptBeforeRetirement: false,
    })).toEqual({ verdict: "accept", state: "repo-confirmed-pre-retirement" });
    expect(classifyRetiredKeyObservation({
      signatureValid: true, createdAtInAuthorityWindow: true, compromiseSince: null,
      repoCommitAncestorOfRetirementCheckpoint: false, trustedLocalReceiptBeforeRetirement: false,
    })).toEqual({ verdict: "provisional", state: "provisional-retired-key" });
  });

  it("keeps compromise cutoffs absorbing", () => {
    expect(classifyRetiredKeyObservation({
      signatureValid: true, createdAtInAuthorityWindow: true, compromiseSince: 100,
      eventCreatedAt: 100, repoCommitAncestorOfRetirementCheckpoint: true,
      trustedLocalReceiptBeforeRetirement: true,
    })).toMatchObject({ verdict: "reject", reason_code: "revoked_key_post_compromise" });
  });
});

describe("node advertisement time", () => {
  it("accepts the exact skew and lifetime boundaries", () => {
    expect(validateNodeAdvertisementTime({ createdAt: 1_300, expiry: 87_700, now: 1_000, clockUncertainty: 0 }))
      .toEqual({ verdict: "accept", refresh_by: 44_500 });
  });

  it("does not reapply issuance skew to a previously accepted advertisement", () => {
    expect(validateNodeAdvertisementTime({
      createdAt: 1_000,
      expiry: 87_400,
      now: 10_000,
      clockUncertainty: 0,
      priorAcceptanceEvidence: true,
    })).toEqual({ verdict: "accept", refresh_by: 44_200 });
  });

  it("does not treat a prior provisional observation as acceptance evidence", () => {
    expect(validateNodeAdvertisementTime({
      createdAt: 1_000,
      expiry: 87_400,
      now: 10_000,
      clockUncertainty: 0,
      priorAcceptanceEvidence: false,
    })).toEqual({ verdict: "reject", reason_code: "node-advert-clock-skew" });
  });

  it.each([
    [{ createdAt: 1_301, expiry: 2_000, now: 1_000, clockUncertainty: 0 }, "node-advert-clock-skew"],
    [{ createdAt: 1_000, expiry: 87_401, now: 1_000, clockUncertainty: 0 }, "node-advert-lifetime-exceeded"],
    [{ createdAt: 1_000, expiry: 1_000, now: 1_000, clockUncertainty: 0 }, "node-advert-expiry-invalid"],
    [{ createdAt: 1_000, expiry: 2_000, now: 2_000, clockUncertainty: 0 }, "node_advert_expired"],
    [{ createdAt: 1_000, expiry: 2_000, now: 1_000, clockUncertainty: 301 }, "node-advert-clock-uncertain"],
  ])("rejects invalid time input %#", (input, reason_code) => {
    expect(validateNodeAdvertisementTime(input)).toMatchObject({ verdict: "reject", reason_code });
  });
});
