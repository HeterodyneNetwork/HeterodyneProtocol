import { getPublicKey, signEvent } from "../nostr.js";
import { createReplaceableSelectionAuthority } from "../replaceable-selection.js";
import {
  selectCurrentSocialEvent,
  validateSocialAuthorship,
} from "../social-events.js";
import { currentSpecRef, type CurrentVectorCase } from "./types.js";

const SECRET = "29".repeat(32);
const AUX_RAND = "00".repeat(32);
const NOW = 1_800_100_000;

export async function buildSocialCases(): Promise<CurrentVectorCase[]> {
  const eligible = await signEvent({
    secretKey: SECRET,
    created_at: NOW,
    kind: 30_000,
    tags: [["d", "source-neutral"]],
    content: "eligible relay state",
    auxRand: AUX_RAND,
  });
  const premature = await signEvent({
    secretKey: SECRET,
    created_at: NOW + 901,
    kind: 30_000,
    tags: [["d", "source-neutral"]],
    content: "premature repository state",
    auxRand: AUX_RAND,
  });
  const coordinate = {
    pubkey: getPublicKey(SECRET),
    kind: 30_000,
    d: "source-neutral",
  };
  const candidates = [
    { carrier: "repository" as const, event: premature },
    { carrier: "relay" as const, event: eligible },
  ];
  const selected = selectCurrentSocialEvent({
    selection_authority: createReplaceableSelectionAuthority({ trusted_now: () => NOW }),
    coordinate,
    candidates,
  });

  const note = await signEvent({
    secretKey: SECRET,
    created_at: NOW,
    kind: 1,
    tags: [],
    content: "ordinary vanilla Nostr authorship",
    auxRand: AUX_RAND,
  });
  const authorship = validateSocialAuthorship({ event: note });

  return [
    {
      relativePath: "social/source-neutral-core-quarantine.json",
      vector_id: "social/source-neutral-core-quarantine",
      owner_document: "social",
      spec_refs: [currentSpecRef("social-scope")],
      invariants: ["SOCIAL-I-SOURCE-NEUTRAL-SELECTION"],
      reason_codes: [],
      description: "Source-neutral Social selection inherits Core quarantine without giving repository transport priority.",
      direction: "consume",
      input: { trusted_now: NOW, coordinate, candidates },
      expected_output: { verdict: "accept", selected_event_id: selected?.id ?? null },
    },
    {
      relativePath: "social/source-neutral-vanilla-authorship.json",
      vector_id: "social/source-neutral-vanilla-authorship",
      owner_document: "social",
      spec_refs: [currentSpecRef("social-interactions")],
      invariants: ["SOCIAL-I-NIP01-AUTHORSHIP"],
      reason_codes: [],
      description: "A directly signed vanilla Nostr event preserves its NIP-01 author without requiring a Heterodyne persona.",
      direction: "consume",
      input: { event: note },
      expected_output: authorship,
    },
  ];
}
