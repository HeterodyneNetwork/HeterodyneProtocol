import { describe, expect, it } from "vitest";
import { nip19 } from "nostr-tools";
import {
  evaluateAtprotoFetch,
  parseLauncherFragment,
  resolvePublicAsset,
  validateBootstrapRelay,
  type AtprotoFetchInput,
  type PublicResolutionInput,
} from "./public-reader.js";

const personaKey = "11".repeat(32);
const eventId = "22".repeat(32);
const nprofile = nip19.nprofileEncode({
  pubkey: personaKey,
  relays: [
    "wss://relay.example/",
    "wss://relay-two.example/",
  ],
});
const nevent = nip19.neventEncode({
  id: eventId,
  author: personaKey,
  relays: ["wss://relay.example/"],
});
const naddr = nip19.naddrEncode({
  identifier: "article",
  pubkey: personaKey,
  kind: 30023,
  relays: ["wss://relay-two.example/"],
});

describe("universal launcher fragment", () => {
  it("round-trips persona, immutable-event, and addressable-event routes", () => {
    expect(parseLauncherFragment(`#/v1/p/${nprofile}`)).toMatchObject({
      verdict: "accept",
      route: { type: "persona", nprofile },
      relay_hints: ["wss://relay.example/", "wss://relay-two.example/"],
      network_activity: false,
    });
    expect(parseLauncherFragment(`#/v1/p/${nprofile}/e/${nevent}`)).toMatchObject({
      verdict: "accept",
      route: { type: "event", nprofile, nevent },
      network_activity: false,
    });
    expect(parseLauncherFragment(`#/v1/p/${nprofile}/a/${naddr}`)).toMatchObject({
      verdict: "accept",
      route: { type: "address", nprofile, naddr },
      network_activity: false,
    });
  });

  it("rejects unknown, malformed, and oversized routes before network activity", () => {
    for (const fragment of [
      `#/v2/p/${nprofile}`,
      "#/v1/p/not-an-nprofile",
      `#/v1/p/${"x".repeat(5_001)}`,
      `#${"x".repeat(16_384)}`,
    ]) {
      expect(parseLauncherFragment(fragment)).toEqual({
        verdict: "reject",
        reason_code: "public-reader-route-invalid",
        network_activity: false,
      });
    }
  });

  it("limits normalized relay hints to the first eight distinct accepted values", () => {
    const relays = Array.from({ length: 10 }, (_, index) =>
      `wss://relay-${index}.example/`);
    const many = nip19.nprofileEncode({ pubkey: personaKey, relays });
    const result = parseLauncherFragment(`#/v1/p/${many}`);
    expect(result).toMatchObject({
      verdict: "accept",
      relay_hints: relays.slice(0, 8),
    });
  });

  it("keeps target identifiers out of the launcher HTTP request path", () => {
    const link = new URL(`/client/#/v1/p/${nprofile}/e/${nevent}`, "https://client.example");
    expect(link.pathname).toBe("/client/");
    expect(link.pathname).not.toContain(nprofile);
    expect(link.pathname).not.toContain(nevent);
    expect(parseLauncherFragment(link.hash)).toMatchObject({ verdict: "accept" });
  });
});

describe("bootstrap relay validation", () => {
  it("accepts normalized public wss and marks onion hints as Tor-only", () => {
    expect(validateBootstrapRelay("wss://relay.example/")).toEqual({
      verdict: "accept",
      normalized: "wss://relay.example/",
      requires_tor: false,
    });
    const onionRelay = "wss://" + "a".repeat(56) + ".onion/";
    expect(validateBootstrapRelay(onionRelay)).toEqual({
      verdict: "accept",
      normalized: onionRelay,
      requires_tor: true,
    });
  });

  it("rejects credentials, query, fragment, insecure schemes, and local names", () => {
    const fixtureUrl = (authority: string): string => "wss://" + authority;
    for (const url of [
      fixtureUrl("user:pass@relay.example/"),
      "wss://relay.example/?token=x",
      "wss://relay.example/#fragment",
      "ws://relay.example/",
      "wss://localhost/",
      fixtureUrl("a.local/"),
      fixtureUrl("a.internal/"),
      fixtureUrl("singlelabel/"),
    ]) {
      expect(validateBootstrapRelay(url)).toEqual({
        verdict: "reject",
        reason_code: "public-reader-relay-hint-invalid",
      });
    }
  });

  it("rejects special-use literal and resolved destinations", () => {
    for (const address of [
      "127.0.0.1",
      "10.0.0.1",
      "169.254.1.1",
      "192.0.2.1",
      "198.18.0.1",
      "224.0.0.1",
      "::1",
      "fe80::1",
      "2001:db8::1",
    ]) {
      const literal = address.includes(":")
        ? "wss://" + `[${address}]/`
        : "wss://" + `${address}/`;
      expect(validateBootstrapRelay(literal)).toMatchObject({ verdict: "reject" });
      expect(validateBootstrapRelay("wss://relay.example/", address))
        .toMatchObject({ verdict: "reject" });
    }
  });
});

describe("ATProto connection pinning", () => {
  const accepted: AtprotoFetchInput = {
    initial_url: "https://pds.example/xrpc/com.atproto.repo.getRecord",
    can_bind_selected_address: true,
    can_inspect_peer_address: true,
    hops: [
      {
        requested_url: "https://pds.example/xrpc/com.atproto.repo.getRecord",
        resolved_addresses: ["93.184.216.34"],
        selected_address: "93.184.216.34",
        connected_peer_address: "93.184.216.34",
        tls_server_name: "pds.example",
        certificate_hostname: "pds.example",
        certificate_valid: true,
        host_header: "pds.example",
        automatic_redirects: false,
        redirect_location: null,
        non_default_port_allowed: false,
      },
    ],
  };

  it("accepts a direct pinned public connection with original-host identity", () => {
    expect(evaluateAtprotoFetch(accepted)).toEqual({
      verdict: "accept",
      conformance_claimable: true,
      normalized: {
        fetched_urls: [accepted.initial_url],
        redirect_count: 0,
        connection_pinned: true,
      },
    });
  });

  it("rejects special DNS answers and selection outside the validated set", () => {
    expect(
      evaluateAtprotoFetch({
        ...accepted,
        hops: [{
          ...accepted.hops[0],
          resolved_addresses: ["93.184.216.34", "127.0.0.1"],
        }],
      }),
    ).toMatchObject({ verdict: "reject", failure_class: "destination-invalid" });
    expect(
      evaluateAtprotoFetch({
        ...accepted,
        hops: [{
          ...accepted.hops[0],
          selected_address: "93.184.216.35",
          connected_peer_address: "93.184.216.35",
        }],
      }),
    ).toMatchObject({ verdict: "reject", failure_class: "address-not-validated" });
  });

  it("rejects connection substitution and hostname identity substitution", () => {
    expect(
      evaluateAtprotoFetch({
        ...accepted,
        hops: [{
          ...accepted.hops[0],
          connected_peer_address: "93.184.216.35",
        }],
      }),
    ).toMatchObject({ verdict: "reject", failure_class: "peer-address-mismatch" });
    for (const field of [
      "tls_server_name",
      "certificate_hostname",
      "host_header",
    ] as const) {
      expect(
        evaluateAtprotoFetch({
          ...accepted,
          hops: [{
            ...accepted.hops[0],
            [field]: "93.184.216.34",
          }],
        }),
      ).toMatchObject({ verdict: "reject", failure_class: "authority-mismatch" });
    }
    expect(
      evaluateAtprotoFetch({
        ...accepted,
        hops: [{ ...accepted.hops[0], certificate_valid: false }],
      }),
    ).toMatchObject({ verdict: "reject", failure_class: "certificate-invalid" });
  });

  it("requires manual, independently pinned redirect hops", () => {
    expect(
      evaluateAtprotoFetch({
        ...accepted,
        hops: [{
          ...accepted.hops[0],
          automatic_redirects: true,
        }],
      }),
    ).toMatchObject({ verdict: "reject", failure_class: "automatic-redirect" });

    const redirected: AtprotoFetchInput = {
      ...accepted,
      hops: [
        {
          ...accepted.hops[0],
          redirect_location: "https://cdn.example/record",
        },
        {
          ...accepted.hops[0],
          requested_url: "https://cdn.example/record",
          resolved_addresses: ["1.1.1.1"],
          selected_address: "1.1.1.1",
          connected_peer_address: "1.1.1.1",
          tls_server_name: "cdn.example",
          certificate_hostname: "cdn.example",
          host_header: "cdn.example",
        },
      ],
    };
    expect(evaluateAtprotoFetch(redirected)).toMatchObject({
      verdict: "accept",
      normalized: { redirect_count: 1, connection_pinned: true },
    });
    expect(
      evaluateAtprotoFetch({
        ...redirected,
        hops: [
          redirected.hops[0],
          {
            ...redirected.hops[1],
            resolved_addresses: ["10.0.0.1"],
            selected_address: "10.0.0.1",
            connected_peer_address: "10.0.0.1",
          },
        ],
      }),
    ).toMatchObject({ verdict: "reject", failure_class: "destination-invalid" });
    expect(
      evaluateAtprotoFetch({
        ...accepted,
        hops: [{
          ...accepted.hops[0],
          requested_url: "https://pds.example:8443/record",
          tls_server_name: "pds.example",
          certificate_hostname: "pds.example",
          host_header: "pds.example:8443",
        }],
        initial_url: "https://pds.example:8443/record",
      }),
    ).toMatchObject({ verdict: "reject", failure_class: "port-not-allowed" });
  });

  it("makes the feature unavailable when the runtime cannot enforce pinning", () => {
    for (const missing of [
      { can_bind_selected_address: false },
      { can_inspect_peer_address: false },
    ]) {
      expect(evaluateAtprotoFetch({ ...accepted, ...missing })).toEqual({
        verdict: "feature-unavailable",
        failure_class: "connection-pinning-unavailable",
        conformance_claimable: false,
      });
    }
  });
});

describe("public asset resolution", () => {
  const canonical: PublicResolutionInput = {
    tier: 1,
    available: true,
    signature_valid: true,
    complete_fetch: true,
    nip65_refreshed: true,
    canonical_feed_reachable: true,
    indexed: true,
    repo_confirmed: true,
    conflict: false,
  };

  it("returns all six terminal outcomes with deterministic precedence", () => {
    expect(resolvePublicAsset(canonical)).toBe("canonical");
    expect(resolvePublicAsset({ ...canonical, repo_confirmed: false }))
      .toBe("provisional-canonical");
    expect(resolvePublicAsset({ ...canonical, indexed: false }))
      .toBe("unindexed-signed-event");
    expect(resolvePublicAsset({ ...canonical, conflict: true })).toBe("conflicted");
    expect(resolvePublicAsset({ ...canonical, available: false })).toBe("unavailable");
    expect(resolvePublicAsset({ ...canonical, tier: 2 })).toBe("private");
    expect(resolvePublicAsset({ ...canonical, tier: 3 })).toBe("private");
  });

  it("does not call an unreachable or incomplete canonical feed empty", () => {
    expect(resolvePublicAsset({ ...canonical, nip65_refreshed: false })).toBe("unavailable");
    expect(resolvePublicAsset({ ...canonical, complete_fetch: false })).toBe("unavailable");
    expect(resolvePublicAsset({ ...canonical, canonical_feed_reachable: false }))
      .toBe("unavailable");
  });
});
