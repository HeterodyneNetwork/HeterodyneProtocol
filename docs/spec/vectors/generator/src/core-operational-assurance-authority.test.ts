import { describe, expect, it } from "vitest";
import type { CoreOperationalAssuranceAuthority } from "./core-operational-assurance-authority.js";
import { getPublicKey, signEvent, type NostrSignedEvent } from "./nostr.js";
import { createReplaceableSelectionAuthority } from "./replaceable-selection.js";
import { AUX_RAND } from "./vector-helpers.js";

type VerifiedCoreOperationalView = Readonly<Record<never, never>>;
type AuthorityDecision<Reason extends string, View> = Readonly<
  | { verdict: "accept"; view: View }
  | { verdict: "reject"; reason_code: Reason }
>;
type TransportSnapshot = Readonly<{
  role: "public-reader" | "authenticated-light" | "full-node";
  strict_profile: boolean;
  route: "tor" | "clearnet";
}>;
type CoreOperationalAssuranceAuthorityConfig = Readonly<{
  authority_id: string;
  trusted_now: () => number;
  capture_transport: () => TransportSnapshot;
}>;
type OperationalModule = {
  createCoreOperationalAssuranceAuthority?: (
    config: CoreOperationalAssuranceAuthorityConfig,
  ) => CoreOperationalAssuranceAuthority;
  verifyCacheCandidate?: (
    authority: CoreOperationalAssuranceAuthority,
    input: Readonly<{ event: NostrSignedEvent; expected_persona: string }>,
  ) => AuthorityDecision<"unauthorized_cache_content", VerifiedCoreOperationalView>;
  verifyRelayProfileCarrier?: (
    authority: CoreOperationalAssuranceAuthority,
    input: Readonly<{ event: NostrSignedEvent; retained_bytes: Uint8Array }>,
  ) => AuthorityDecision<"relay_profile_mutation", VerifiedCoreOperationalView>;
  verifyStrictTransport?: (
    authority: CoreOperationalAssuranceAuthority,
  ) => AuthorityDecision<"strict_mode_tor_disabled", VerifiedCoreOperationalView>;
};

const SECRET = "51".repeat(32);
const OTHER_SECRET = "52".repeat(32);
const NOW = 1_800_000_000;
const MISSING_AUTHORITY = Object.freeze({}) as CoreOperationalAssuranceAuthority;

async function loadOperational(): Promise<OperationalModule> {
  return await import("./core-operational-assurance-authority.js").catch(() => ({}));
}

async function signedProfileEvent(
  content = JSON.stringify({ name: "synthetic local cache candidate" }),
  secretKey = SECRET,
): Promise<NostrSignedEvent> {
  return await signEvent({
    secretKey,
    created_at: NOW,
    kind: 0,
    tags: [],
    content,
    auxRand: AUX_RAND,
  });
}

function operationalConfig(
  transport: TransportSnapshot = {
    role: "authenticated-light",
    strict_profile: true,
    route: "tor",
  },
): CoreOperationalAssuranceAuthorityConfig {
  return {
    authority_id: "synthetic-local-core-operational",
    trusted_now: () => NOW,
    capture_transport: () => transport,
  };
}

describe("Core operational assurance authority", () => {
  it("accepts an exact persona-authored cache event and returns an opaque view", async () => {
    const operational = await loadOperational();
    const event = await signedProfileEvent();
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(),
    ) ?? MISSING_AUTHORITY;

    const decision = operational.verifyCacheCandidate?.(authority, {
      event,
      expected_persona: event.pubkey,
    });

    expect(decision?.verdict).toBe("accept");
    if (decision?.verdict === "accept") {
      expect(decision.view).toEqual({});
      expect(Object.isFrozen(decision.view)).toBe(true);
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects unsigned and wrong-author cache candidates", async () => {
    const operational = await loadOperational();
    const event = await signedProfileEvent();
    const wrongAuthor = await signedProfileEvent(undefined, OTHER_SECRET);
    const unsigned = { ...event, sig: "00".repeat(64) };
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(),
    ) ?? MISSING_AUTHORITY;

    for (const hostile of [unsigned, wrongAuthor]) {
      expect(operational.verifyCacheCandidate?.(authority, {
        event: hostile,
        expected_persona: event.pubkey,
      })).toEqual({
        verdict: "reject",
        reason_code: "unauthorized_cache_content",
      });
    }
  });

  it("accepts exact retained relay event bytes", async () => {
    const operational = await loadOperational();
    const event = await signedProfileEvent();
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(),
    ) ?? MISSING_AUTHORITY;
    const retained = new TextEncoder().encode(JSON.stringify(event));

    expect(operational.verifyRelayProfileCarrier?.(authority, {
      event,
      retained_bytes: retained,
    })?.verdict).toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects mutated retained relay bytes", async () => {
    const operational = await loadOperational();
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(),
    ) ?? MISSING_AUTHORITY;
    const original = await signedProfileEvent();
    const retained = new TextEncoder().encode(JSON.stringify({
      ...original,
      content: "mutated",
    }));

    expect(operational.verifyRelayProfileCarrier?.(authority, {
      event: original,
      retained_bytes: retained,
    })).toEqual({ verdict: "reject", reason_code: "relay_profile_mutation" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects a valid recomputed retained event that differs from the exposed event", async () => {
    const operational = await loadOperational();
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(),
    ) ?? MISSING_AUTHORITY;
    const original = await signedProfileEvent("original");
    const substituted = await signedProfileEvent("substituted");

    expect(operational.verifyRelayProfileCarrier?.(authority, {
      event: original,
      retained_bytes: new TextEncoder().encode(JSON.stringify(substituted)),
    })).toEqual({ verdict: "reject", reason_code: "relay_profile_mutation" });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects strict role transport without Tor", async () => {
    const operational = await loadOperational();
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig({
        role: "authenticated-light",
        strict_profile: true,
        route: "clearnet",
      }),
    ) ?? MISSING_AUTHORITY;

    expect(operational.verifyStrictTransport?.(authority)).toEqual({
      verdict: "reject",
      reason_code: "strict_mode_tor_disabled",
    });
  });

  it("accepts disclosed reduced-assurance clearnet transport outside strict mode", async () => {
    const operational = await loadOperational();
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig({
        role: "public-reader",
        strict_profile: false,
        route: "clearnet",
      }),
    ) ?? MISSING_AUTHORITY;

    expect(operational.verifyStrictTransport?.(authority)?.verdict).toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures the transport observation in the constructor", async () => {
    const operational = await loadOperational();
    const transport = {
      role: "authenticated-light" as const,
      strict_profile: true,
      route: "tor" as "tor" | "clearnet",
    };
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(transport),
    ) ?? MISSING_AUTHORITY;
    transport.route = "clearnet";

    expect(operational.verifyStrictTransport?.(authority)?.verdict).toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local captures callbacks against post-construction substitution", async () => {
    const operational = await loadOperational();
    const mutableConfig = operationalConfig() as {
      authority_id: string;
      trusted_now: () => number;
      capture_transport: () => TransportSnapshot;
    };
    const authority = operational.createCoreOperationalAssuranceAuthority?.(mutableConfig)
      ?? MISSING_AUTHORITY;
    mutableConfig.trusted_now = () => Number.NaN;
    mutableConfig.capture_transport = () => ({
      role: "authenticated-light",
      strict_profile: true,
      route: "clearnet",
    });

    expect(operational.verifyStrictTransport?.(authority)?.verdict).toBe("accept");
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects mutation of an exposed event after signing", async () => {
    const operational = await loadOperational();
    const event = await signedProfileEvent();
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(),
    ) ?? MISSING_AUTHORITY;
    event.content = "mutated after signing";

    expect(operational.verifyCacheCandidate?.(authority, {
      event,
      expected_persona: getPublicKey(SECRET),
    })).toEqual({
      verdict: "reject",
      reason_code: "unauthorized_cache_content",
    });
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects cloned and cross-authority handles", async () => {
    const operational = await loadOperational();
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(),
    ) ?? MISSING_AUTHORITY;
    const cloned = Object.freeze({ ...authority }) as CoreOperationalAssuranceAuthority;
    const crossAuthority = createReplaceableSelectionAuthority({ trusted_now: () => NOW }) as
      unknown as CoreOperationalAssuranceAuthority;

    for (const hostile of [cloned, crossAuthority]) {
      expect(operational.verifyStrictTransport?.(hostile)).toEqual({
        verdict: "reject",
        reason_code: "strict_mode_tor_disabled",
      });
    }
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects proxy and accessor-bearing operational input", async () => {
    const operational = await loadOperational();
    const event = await signedProfileEvent();
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(),
    ) ?? MISSING_AUTHORITY;
    let reads = 0;
    const accessor = { expected_persona: event.pubkey } as {
      event: NostrSignedEvent;
      expected_persona: string;
    };
    Object.defineProperty(accessor, "event", {
      enumerable: true,
      get: () => {
        reads += 1;
        return event;
      },
    });
    const proxy = new Proxy({ event, expected_persona: event.pubkey }, {});

    for (const hostile of [accessor, proxy]) {
      expect(operational.verifyCacheCandidate?.(authority, hostile)).toEqual({
        verdict: "reject",
        reason_code: "unauthorized_cache_content",
      });
    }
    expect(reads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects accessor-bearing constructor configuration", async () => {
    const operational = await loadOperational();
    let reads = 0;
    const hostile = {
      authority_id: "synthetic-local-accessor",
      trusted_now: () => NOW,
    } as CoreOperationalAssuranceAuthorityConfig;
    Object.defineProperty(hostile, "capture_transport", {
      enumerable: true,
      get: () => {
        reads += 1;
        return () => ({
          role: "public-reader" as const,
          strict_profile: false,
          route: "clearnet" as const,
        });
      },
    });

    expect(() => operational.createCoreOperationalAssuranceAuthority?.(hostile))
      .toThrow("core-operational-authority-invalid");
    expect(reads).toBe(0);
  });

  it("BLUE TEAM VALIDATION: synthetic/local rejects an aggregate oversized signed cache event", async () => {
    const operational = await loadOperational();
    const oversized = await signEvent({
      secretKey: SECRET,
      created_at: NOW,
      kind: 0,
      tags: Array.from({ length: 130 }, () => ["x", "a".repeat(1_024)]),
      content: JSON.stringify({ name: "synthetic local bounded-work fixture" }),
      auxRand: AUX_RAND,
    });
    const authority = operational.createCoreOperationalAssuranceAuthority?.(
      operationalConfig(),
    ) ?? MISSING_AUTHORITY;

    expect(operational.verifyCacheCandidate?.(authority, {
      event: oversized,
      expected_persona: oversized.pubkey,
    })).toEqual({
      verdict: "reject",
      reason_code: "unauthorized_cache_content",
    });
  });
});
