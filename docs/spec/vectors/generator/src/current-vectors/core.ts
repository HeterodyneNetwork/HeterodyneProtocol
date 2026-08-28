import { signEvent, type NostrSignedEvent } from "../nostr.js";
import {
  createReplaceableSelectionAuthority,
  selectCurrentReplaceableEvent,
} from "../replaceable-selection.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const SECRET = "19".repeat(32);
const AUX_RAND = "00".repeat(32);
const NOW = 1_800_000_000;

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

  return [
    {
      relativePath: "core/replaceable-future-quarantined.json",
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
  ];
}
