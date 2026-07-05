// nostr-double-ratchet@0.0.138 (exact-pinned) publishes .d.ts files whose
// extensionless relative re-exports do not resolve under NodeNext module
// resolution, so we type the narrow API surface this generator uses.
// @ts-expect-error see above
import { Session } from "nostr-double-ratchet";

export type NdrRumor = {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
};

export type NdrVerifiedEvent = NdrRumor & { sig: string };

export type NdrSession = {
  state: {
    ourNextNostrKey: { publicKey: string; privateKey: Uint8Array };
  };
  sendEvent(event: Partial<NdrRumor>): { event: NdrVerifiedEvent; innerEvent: NdrRumor };
  receiveEvent(event: NdrVerifiedEvent): NdrRumor | undefined;
};

export const DoubleRatchetSession = Session as {
  init(
    theirEphemeralPublicKey: string,
    ourEphemeralSecretKey: Uint8Array,
    isInitiator: boolean,
    sharedSecret: Uint8Array,
    name?: string,
  ): NdrSession;
};
