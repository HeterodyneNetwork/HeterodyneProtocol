import { nip19 } from "nostr-tools";
import {
  evaluateAtprotoFetch,
  parseLauncherFragment,
  resolvePublicAsset,
  validateBootstrapRelay,
  type PublicResolutionInput,
} from "./public-reader.js";
import { baseVector } from "./vector-helpers.js";
import type { AuthoredVector } from "./types.js";

const persona = "11".repeat(32);
const eventId = "22".repeat(32);
const nprofile = nip19.nprofileEncode({
  pubkey: persona,
  relays: ["wss://bootstrap.example/"],
});
const nevent = nip19.neventEncode({
  id: eventId,
  author: persona,
  relays: ["wss://event-relay.example/"],
});
const naddr = nip19.naddrEncode({
  identifier: "article",
  pubkey: persona,
  kind: 30023,
  relays: ["wss://address-relay.example/"],
});

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

export function buildPublicReaderVectors(): AuthoredVector[] {
  const vectors: AuthoredVector[] = [];
  for (const [number, name, fragment] of [
    ["001", "launcher-persona-roundtrip", `#/v1/p/${nprofile}`],
    ["002", "launcher-event-roundtrip", `#/v1/p/${nprofile}/e/${nevent}`],
    ["003", "launcher-address-roundtrip", `#/v1/p/${nprofile}/a/${naddr}`],
  ] as const) {
    vectors.push(authored(
      `public-reader/${number}-${name}.json`,
      `public-reader/${name}`,
      "A versioned universal-launcher fragment is parsed completely and locally before any network activity.",
      { fragment },
      parseLauncherFragment(fragment),
    ));
  }

  const fullLink = `https://heterodyne.network/client/#/v1/p/${nprofile}/e/${nevent}`;
  vectors.push(authored(
    "public-reader/004-target-absent-from-http-path.json",
    "public-reader/target-absent-from-http-path",
    "The reference launcher HTTP request path contains no persona, event, or relay identifier from the fragment.",
    { full_link: fullLink },
    {
      verdict: "accept",
      normalized: {
        request_origin: "https://heterodyne.network",
        request_path: "/client/",
        fragment_parsed_locally: true,
        target_in_request_path: false,
      },
    },
  ));

  for (const [number, name, fragment] of [
    ["005", "unknown-version-no-network", `#/v2/p/${nprofile}`],
    ["006", "malformed-entity-no-network", "#/v1/p/not-an-nprofile"],
    ["007", "oversized-fragment-no-network", `#${"x".repeat(16_384)}`],
  ] as const) {
    vectors.push(authored(
      `public-reader/${number}-${name}.json`,
      `public-reader/${name}`,
      "An invalid launcher fragment fails before any relay or other network activity.",
      { fragment },
      parseLauncherFragment(fragment),
    ));
  }

  for (const [number, name, url, resolvedAddress] of [
    ["008", "credential-relay-hint-rejected", "wss://user:pass@relay.example/", undefined],
    ["009", "localhost-relay-hint-rejected", "wss://localhost/", undefined],
    ["010", "private-resolved-relay-hint-rejected", "wss://relay.example/", "10.0.0.1"],
  ] as const) {
    vectors.push(authored(
      `public-reader/${number}-${name}.json`,
      `public-reader/${name}`,
      "An untrusted bootstrap relay hint that could target credentials or a local network is rejected.",
      { url, ...(resolvedAddress === undefined ? {} : { resolved_address: resolvedAddress }) },
      validateBootstrapRelay(url, resolvedAddress),
    ));
  }

  const onion = `wss://${"a".repeat(56)}.onion/`;
  vectors.push(authored(
    "public-reader/011-onion-hint-tor-required.json",
    "public-reader/onion-hint-tor-required",
    "A valid v3 onion relay hint is accepted only as a Tor-required locator.",
    { url: onion },
    validateBootstrapRelay(onion),
  ));

  vectors.push(authored(
    "public-reader/012-nip65-refresh-replaces-stale-hint.json",
    "public-reader/nip65-refresh-replaces-stale-hint",
    "Bootstrap hints start discovery, but the verified current NIP-65 relay list governs the subsequent public fetch.",
    {
      embedded_hints: ["wss://stale.example/"],
      nip65_refresh: {
        verified: true,
        relays: ["wss://current.example/"],
      },
    },
    {
      verdict: "accept",
      normalized: {
        fetch_relays: ["wss://current.example/"],
        stale_hint_authoritative: false,
      },
    },
  ));

  for (const [number, outcome, input] of [
    ["013", "canonical", canonical],
    ["014", "provisional-canonical", { ...canonical, repo_confirmed: false }],
    ["015", "unindexed-signed-event", { ...canonical, indexed: false }],
    ["016", "conflicted", { ...canonical, conflict: true }],
    ["017", "unavailable", { ...canonical, complete_fetch: false }],
    ["018", "private", { ...canonical, tier: 2 as const }],
  ] as const) {
    vectors.push(authored(
      `public-reader/${number}-resolution-${outcome}.json`,
      `public-reader/resolution-${outcome}`,
      `Public resolution terminates visibly as ${outcome}.`,
      input,
      {
        verdict: "accept",
        normalized: { outcome: resolvePublicAsset(input) },
      },
    ));
  }

  vectors.push(authored(
    "public-reader/019-tier3-refused.json",
    "public-reader/tier3-refused",
    "Public-reader mode refuses to interpret Tier 3 ciphertext as public content.",
    { ...canonical, tier: 3 },
    {
      verdict: "accept",
      normalized: {
        outcome: resolvePublicAsset({ ...canonical, tier: 3 }),
        ciphertext_interpreted: false,
      },
    },
  ));
  vectors.push(authored(
    "public-reader/020-external-media-disclosure.json",
    "public-reader/external-media-disclosure",
    "A non-Tor public reader strips credentials and referrer data and warns before an external-media request.",
    { tor_available: false, external_media: "https://media.example/image.png" },
    {
      verdict: "accept",
      normalized: {
        credentials: "omit",
        referrer: "none",
        network_address_warning: true,
      },
    },
  ));
  vectors.push(authored(
    "public-reader/021-transition-without-reload.json",
    "public-reader/transition-without-reload",
    "An explicit user action upgrades one running static client from public reader to an authenticated session without a hosted server session.",
    { initial_role: "public-reader", user_requested_connection: true },
    {
      verdict: "accept",
      normalized: {
        final_role: "authenticated-light",
        application_reload: false,
        hosted_server_session: false,
        disposable_session_key_generated_locally: true,
      },
    },
  ));
  vectors.push(authored(
    "public-reader/022-logout-cleanup.json",
    "public-reader/logout-cleanup",
    "Logout deletes session and private local state before returning the running application to public-reader mode.",
    { authenticated: true, revocation_delivery: "accepted" },
    {
      verdict: "accept",
      normalized: {
        final_role: "public-reader",
        application_reload: false,
        session_key_deleted: true,
        ratchet_state_deleted: true,
        private_cache_cleared: true,
      },
    },
  ));
  vectors.push(authored(
    "public-reader/023-failed-revocation-expiry.json",
    "public-reader/failed-revocation-expiry",
    "Local logout completes even when self-revocation delivery fails, with bounded full-node inactivity expiry as the remote backstop.",
    { authenticated: true, revocation_delivery: "failed", inactivity_expiry_seconds: 300 },
    {
      verdict: "accept",
      normalized: {
        local_cleanup_completed: true,
        final_role: "public-reader",
        remote_authority_expires_by: 300,
      },
    },
  ));

  const pinnedAtprotoHop = {
    initial_url: "https://pds.example/xrpc/com.atproto.repo.getRecord",
    can_bind_selected_address: true,
    can_inspect_peer_address: true,
    hops: [{
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
    }],
  };
  vectors.push(authored(
    "atproto/001-pinned-public-hop.json",
    "atproto/pinned-public-hop",
    "An ATProto resolver dials one explicitly validated public address while preserving original-host TLS and HTTP authority.",
    pinnedAtprotoHop,
    evaluateAtprotoFetch(pinnedAtprotoHop),
  ));
  vectors.push(authored(
    "atproto/002-connection-pinning-unavailable.json",
    "atproto/connection-pinning-unavailable",
    "A runtime unable to bind the selected address and inspect the peer reports the optional feature unavailable without claiming conformance.",
    { ...pinnedAtprotoHop, can_inspect_peer_address: false },
    {
      verdict: "accept",
      normalized: evaluateAtprotoFetch({
        ...pinnedAtprotoHop,
        can_inspect_peer_address: false,
      }),
    },
  ));

  return vectors;
}

function authored(
  relativePath: string,
  vectorId: string,
  description: string,
  input: Record<string, unknown>,
  expectedOutput: Record<string, unknown>,
): AuthoredVector {
  return {
    relativePath,
    vector: baseVector({
      vector_id: vectorId,
      spec_refs: ["metadata-selects-public-reader-anchor"],
      description,
      direction: "consume",
      input,
      expected_output: expectedOutput,
    }),
  };
}
