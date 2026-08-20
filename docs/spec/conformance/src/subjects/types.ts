export type CheckerStage =
  | "event_structure" | "nip01_raw" | "identifier" | "signature"
  | "persona_resolution" | "version_stamp" | "kel_head"
  | "epoch_authority" | "subtype_nid" | "accept";

export type SubjectResult = {
  terminalStage: CheckerStage;
  verdict: "accept" | "accept_provisional" | "equivocation_flagged" | "reject";
  reasonCode?: string;
  stages: {
    stage: CheckerStage;
    verdict: "pass" | "provisional" | "equivocation_flagged" | "reject";
    reasonCode?: string;
  }[];
};

export type NostrSignedEvent = {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
};

export type CoreKelEntryV1 = {
  event_id: string;
  sequence: number;
  prior_event_id: string | null;
  epoch_pubkey: string;
  effective_from: number;
  effective_until: number | null;
  compromise_since: number | null;
};

export type CoreVerificationContextV1 = {
  persona: string;
  evaluation_time: number;
  nid_clock_skew_allowance: number;
  clock_uncertainty: number;
  pointer: {
    persona: string;
    kel_head: { event_id: string; sequence: number };
  };
  kel: CoreKelEntryV1[];
  kel_refresh: {
    status: "not-needed" | "succeeded" | "pending" | "failed";
  };
  signer:
    | { type: "epoch"; pubkey: string; delegation: null }
    | {
      type: "delegated";
      pubkey: string;
      delegation: {
        persona: string;
        publisher_pubkey: string;
        valid_from: number;
        valid_until: number | null;
        revoked_at: number | null;
      };
    };
  version_policy: {
    mode: "required" | "optional" | "forbidden";
    value: "heterodyne/0.5.0";
  };
  kel_head_policy: { mode: "required" | "optional" | "forbidden" };
  subtype_policy:
    | { mode: "generic"; nid_pubkey: null }
    | { mode: "nid-delegation" | "node-advertisement"; nid_pubkey: string };
};
