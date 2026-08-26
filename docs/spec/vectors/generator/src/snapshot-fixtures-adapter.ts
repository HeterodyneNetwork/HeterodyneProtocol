import {
  buildFixtures as buildCurrentFixtures,
  CURRENT_REGISTRY_SHA256,
} from "./fixtures.js";
import { inceptionTemplate } from "./kel.js";
import { getEventId } from "./nostr.js";

export { CURRENT_REGISTRY_SHA256 };

// Snapshot-only compatibility surface for the frozen pre-redesign topic
// graph. Current-draft code imports fixtures.ts and cannot receive a KEL.
export function buildFixtures() {
  const current = buildCurrentFixtures();
  const {
    vector_schema_version,
    spec_version,
    registry_sha256,
    test_epoch,
    pinned_randomness,
    personas,
    ...remaining
  } = current;
  const kelFor = (coldRootPubkey: string, epochPubkey: string) => {
    const inceptionEvent = inceptionTemplate(coldRootPubkey, epochPubkey, test_epoch);
    return {
      inception_event: inceptionEvent,
      head: { id: getEventId(inceptionEvent), seq: 0 },
    };
  };
  const kel = {
    alice: kelFor(
      personas.alice.cold_root.pubkey,
      personas.alice.epoch_keys.epoch_1.pubkey,
    ),
    bob: kelFor(
      personas.bob.cold_root.pubkey,
      personas.bob.epoch_keys.epoch_1.pubkey,
    ),
    carol: kelFor(
      personas.carol.cold_root.pubkey,
      personas.carol.epoch_keys.epoch_1.pubkey,
    ),
  };

  // Preserve the original fixture member insertion order and therefore the
  // historical authored bytes: personas, kel, then all remaining fixtures.
  return {
    vector_schema_version,
    spec_version,
    registry_sha256,
    test_epoch,
    pinned_randomness,
    personas,
    kel,
    ...remaining,
  };
}

export type Fixtures = ReturnType<typeof buildFixtures>;
