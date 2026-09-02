import { describe, expect, it } from "vitest";
import {
  evaluateEnrollment,
  evaluateSuccession,
  type AssuranceHeadState,
} from "./assurance.js";
import { jcsCanonicalize } from "./jcs.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";

const AUX_RAND = "00".repeat(32);
const secret = (value: number): string => value.toString(16).padStart(64, "0");
const COLD_SECRET = secret(1);
const ACTIVE_SECRET = secret(2);
const SUCCESSION_SECRET = secret(3);
const EPOCH_SECRET = secret(4);
const WITNESS_SECRET = secret(5);
const NEXT_EPOCH_SECRET = secret(7);
const COLD_KEY = getPublicKey(COLD_SECRET);
const ACTIVE_KEY = getPublicKey(ACTIVE_SECRET);
const SUCCESSION_KEY = getPublicKey(SUCCESSION_SECRET);
const EPOCH_KEY = getPublicKey(EPOCH_SECRET);
const WITNESS_KEY = getPublicKey(WITNESS_SECRET);
const NEXT_EPOCH_KEY = getPublicKey(NEXT_EPOCH_SECRET);
const CREATED_AT = 1_785_000_000;

async function assuranceEvent(
  secretKey: string,
  kind: number,
  d: string,
  profile: string,
  body: Record<string, unknown>,
  publicKeys: string[] = [],
): Promise<NostrSignedEvent> {
  return signEvent({
    secretKey,
    created_at: body.created_at as number,
    kind,
    tags: [
      ["d", d],
      ["profile", profile],
      ...publicKeys.map((key) => ["p", key]),
    ],
    content: jcsCanonicalize(body),
    auxRand: AUX_RAND,
  });
}

async function currentAssuranceState(): Promise<AssuranceHeadState> {
  const inceptionBody = {
    profile: "heterodyne.assurance.enrollment-inception.v1" as const,
    spec_version: "heterodyne/0.6.0" as const,
    active_key: ACTIVE_KEY,
    created_at: CREATED_AT,
    predecessor: null,
    cold_root: COLD_KEY,
    succession_authority: SUCCESSION_KEY,
    epoch_policy: {
      mode: "pre-rotation" as const,
      current_keys: [EPOCH_KEY],
      next_key_commitments: ["11".repeat(32)],
    },
    witnesses: [{ key: WITNESS_KEY, weight: 1 }],
    thresholds: { epoch: 1, witness: 1 },
    associated_key_policy: { active_key: [], epoch_threshold: [] },
  };
  const inception = await assuranceEvent(
    COLD_SECRET,
    31002,
    `assurance-inception:${ACTIVE_KEY}`,
    inceptionBody.profile,
    inceptionBody,
    [ACTIVE_KEY],
  );
  const acceptanceBody = {
    profile: "heterodyne.assurance.active-key-acceptance.v1" as const,
    spec_version: "heterodyne/0.6.0" as const,
    active_key: ACTIVE_KEY,
    created_at: CREATED_AT + 1,
    predecessor: inception.id,
    inception_event_id: inception.id,
    cold_root: COLD_KEY,
    cold_root_signature: inception.sig,
    assurance_head: inception.id,
    state: "assured" as const,
  };
  const acceptance = await assuranceEvent(
    ACTIVE_SECRET,
    31000,
    "assurance-head",
    acceptanceBody.profile,
    acceptanceBody,
  );
  const result = evaluateEnrollment({ inception, acceptance });
  if (result.verdict !== "accept") throw new Error(result.reason_code);
  return result.normalized;
}

describe("current Assurance rejects retired Core KEL wire grammar", () => {
  it("rejects an empty tag-based kind 31002 inception", async () => {
    const inception = await signEvent({
      secretKey: COLD_SECRET,
      created_at: CREATED_AT,
      kind: 31002,
      tags: [
        ["d", ""],
        ["heterodyne", "keri_inception"],
        ["p", COLD_KEY],
        ["s", "0"],
        ["epoch_key", EPOCH_KEY],
        ["spec_version", "heterodyne/0.5.0"],
      ],
      content: "",
      auxRand: AUX_RAND,
    });
    const acceptanceBody = {
      profile: "heterodyne.assurance.active-key-acceptance.v1" as const,
      spec_version: "heterodyne/0.6.0" as const,
      active_key: ACTIVE_KEY,
      created_at: CREATED_AT + 1,
      predecessor: inception.id,
      inception_event_id: inception.id,
      cold_root: COLD_KEY,
      cold_root_signature: inception.sig,
      assurance_head: inception.id,
      state: "assured" as const,
    };
    const acceptance = await assuranceEvent(
      ACTIVE_SECRET,
      31000,
      "assurance-head",
      acceptanceBody.profile,
      acceptanceBody,
    );

    expect(evaluateEnrollment({ inception, acceptance })).toEqual({
      verdict: "reject",
      reason_code: "assurance-reciprocal-proof-invalid",
    });
  });

  it("rejects a tag-based kind 31003 rotation with the retired receipt body", async () => {
    const state = await currentAssuranceState();
    const rotation = await signEvent({
      secretKey: COLD_SECRET,
      created_at: state.head_created_at + 10,
      kind: 31003,
      tags: [
        ["d", "1"],
        ["heterodyne", "keri_rotation"],
        ["p", COLD_KEY],
        ["s", "1"],
        ["prior_digest", state.head],
        ["strategy", "committed"],
        ["epoch_key", NEXT_EPOCH_KEY],
      ],
      content: '{"spec_version":"heterodyne/0.5.0","receipts":[]}',
      auxRand: AUX_RAND,
    });

    expect(evaluateSuccession({ current: state, event: rotation })).toEqual({
      verdict: "reject",
      reason_code: "assurance-schema-invalid",
    });
  });
});
