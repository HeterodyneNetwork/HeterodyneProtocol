import { isIP } from "node:net";
import { nip19 } from "nostr-tools";

export type LauncherRoute =
  | { type: "persona"; nprofile: string }
  | { type: "event"; nprofile: string; nevent: string }
  | { type: "address"; nprofile: string; naddr: string };

export type LauncherParseResult =
  | {
      verdict: "accept";
      route: LauncherRoute;
      relay_hints: string[];
      network_activity: false;
    }
  | {
      verdict: "reject";
      reason_code: "public-reader-route-invalid";
      network_activity: false;
    };

export type RelayHintResult =
  | {
      verdict: "accept";
      normalized: string;
      requires_tor: boolean;
    }
  | {
      verdict: "reject";
      reason_code: "public-reader-relay-hint-invalid";
    };

export type PublicOutcome =
  | "canonical"
  | "provisional-canonical"
  | "unindexed-signed-event"
  | "conflicted"
  | "unavailable"
  | "private";

export type PublicResolutionInput = {
  tier: 1 | 2 | 3;
  available: boolean;
  signature_valid: boolean;
  complete_fetch: boolean;
  nip65_refreshed: boolean;
  canonical_feed_reachable: boolean;
  indexed: boolean;
  repo_confirmed: boolean;
  conflict: boolean;
};

export type AtprotoFetchHop = {
  requested_url: string;
  resolved_addresses: string[];
  selected_address: string;
  connected_peer_address: string;
  tls_server_name: string;
  certificate_hostname: string;
  certificate_valid: boolean;
  host_header: string;
  automatic_redirects: boolean;
  redirect_location: string | null;
  non_default_port_allowed: boolean;
};

export type AtprotoFetchInput = {
  initial_url: string;
  can_bind_selected_address: boolean;
  can_inspect_peer_address: boolean;
  hops: AtprotoFetchHop[];
};

export type AtprotoFetchResult =
  | {
      verdict: "accept";
      conformance_claimable: true;
      normalized: {
        fetched_urls: string[];
        redirect_count: number;
        connection_pinned: true;
      };
    }
  | {
      verdict: "reject";
      failure_class:
        | "request-invalid"
        | "destination-invalid"
        | "port-not-allowed"
        | "address-not-validated"
        | "peer-address-mismatch"
      | "authority-mismatch"
        | "certificate-invalid"
        | "automatic-redirect"
        | "redirect-chain-invalid";
      conformance_claimable: false;
    }
  | {
      verdict: "feature-unavailable";
      failure_class: "connection-pinning-unavailable";
      conformance_claimable: false;
    };

const rejectRoute = (): LauncherParseResult => ({
  verdict: "reject",
  reason_code: "public-reader-route-invalid",
  network_activity: false,
});

export function parseLauncherFragment(fragment: string): LauncherParseResult {
  if (fragment.length > 16_384 || !fragment.startsWith("#/")) return rejectRoute();
  const segments = fragment.slice(2).split("/");
  if (
    segments.length !== 3
    && segments.length !== 5
  ) {
    return rejectRoute();
  }
  if (segments[0] !== "v1" || segments[1] !== "p") return rejectRoute();

  const nprofile = segments[2];
  if (!validEntityLength(nprofile)) return rejectRoute();
  const profile = decodeEntity(nprofile, "nprofile");
  if (profile === undefined) return rejectRoute();
  const profileData = profile.data as {
    pubkey?: unknown;
    relays?: unknown;
  };
  if (!isHex32(profileData.pubkey)) return rejectRoute();

  let route: LauncherRoute = { type: "persona", nprofile };
  const relaySources: unknown[] = [profileData.relays];
  if (segments.length === 5) {
    const entity = segments[4];
    if (!validEntityLength(entity)) return rejectRoute();
    if (segments[3] === "e") {
      const decoded = decodeEntity(entity, "nevent");
      if (decoded === undefined) return rejectRoute();
      const data = decoded.data as {
        id?: unknown;
        author?: unknown;
        relays?: unknown;
      };
      if (
        !isHex32(data.id)
        || (data.author !== undefined && data.author !== profileData.pubkey)
      ) {
        return rejectRoute();
      }
      relaySources.push(data.relays);
      route = { type: "event", nprofile, nevent: entity };
    } else if (segments[3] === "a") {
      const decoded = decodeEntity(entity, "naddr");
      if (decoded === undefined) return rejectRoute();
      const data = decoded.data as {
        identifier?: unknown;
        pubkey?: unknown;
        kind?: unknown;
        relays?: unknown;
      };
      if (
        typeof data.identifier !== "string"
        || data.identifier.length === 0
        || data.pubkey !== profileData.pubkey
        || !Number.isSafeInteger(data.kind)
      ) {
        return rejectRoute();
      }
      relaySources.push(data.relays);
      route = { type: "address", nprofile, naddr: entity };
    } else {
      return rejectRoute();
    }
  }

  return {
    verdict: "accept",
    route,
    relay_hints: acceptedRelayHints(relaySources),
    network_activity: false,
  };
}

function validEntityLength(value: string): boolean {
  return value.length > 0 && value.length <= 5_000;
}

function decodeEntity(
  value: string,
  expectedType: "nprofile" | "nevent" | "naddr",
): ReturnType<typeof nip19.decode> | undefined {
  try {
    const decoded = nip19.decode(value);
    return decoded.type === expectedType ? decoded : undefined;
  } catch {
    return undefined;
  }
}

function isHex32(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function acceptedRelayHints(sources: unknown[]): string[] {
  const accepted: string[] = [];
  const seen = new Set<string>();
  for (const source of sources) {
    if (!Array.isArray(source)) continue;
    for (const candidate of source) {
      if (typeof candidate !== "string") continue;
      const result = validateBootstrapRelay(candidate);
      if (result.verdict === "reject" || seen.has(result.normalized)) continue;
      seen.add(result.normalized);
      accepted.push(result.normalized);
      if (accepted.length === 8) return accepted;
    }
  }
  return accepted;
}

export function validateBootstrapRelay(
  url: string,
  resolvedAddress?: string,
): RelayHintResult {
  try {
    const parsed = new URL(url);
    if (
      parsed.protocol !== "wss:"
      || parsed.username !== ""
      || parsed.password !== ""
      || parsed.search !== ""
      || parsed.hash !== ""
    ) {
      return rejectRelay();
    }
    const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (hostname.length === 0) return rejectRelay();

    const onion = hostname.endsWith(".onion");
    if (onion) {
      if (!/^[a-z2-7]{56}\.onion$/.test(hostname)) return rejectRelay();
    } else if (isSpecialDestination(hostname)) {
      return rejectRelay();
    }
    if (resolvedAddress !== undefined && isSpecialDestination(resolvedAddress)) {
      return rejectRelay();
    }

    return {
      verdict: "accept",
      normalized: parsed.toString(),
      requires_tor: onion,
    };
  } catch {
    return rejectRelay();
  }
}

function rejectRelay(): RelayHintResult {
  return {
    verdict: "reject",
    reason_code: "public-reader-relay-hint-invalid",
  };
}

function isSpecialDestination(hostOrAddress: string): boolean {
  const value = hostOrAddress.toLowerCase().replace(/^\[|\]$/g, "");
  const ipVersion = isIP(value);
  if (ipVersion === 4) return !isPublicIpv4(value);
  if (ipVersion === 6) return !isPublicIpv6(value);
  return !value.includes(".")
    || value === "localhost"
    || value.endsWith(".localhost")
    || value.endsWith(".local")
    || value.endsWith(".internal");
}

function normalizeIp(address: string): string | undefined {
  const value = address.toLowerCase().replace(/^\[|\]$/g, "");
  if (isIP(value) === 4) {
    return value.split(".").map((octet) => String(Number(octet))).join(".");
  }
  const parsed = ipv6ToBigInt(value);
  return parsed === undefined ? undefined : parsed.toString(16);
}

function rejectAtproto(
  failure_class: Extract<AtprotoFetchResult, { verdict: "reject" }>["failure_class"],
): AtprotoFetchResult {
  return { verdict: "reject", failure_class, conformance_claimable: false };
}

export function evaluateAtprotoFetch(input: AtprotoFetchInput): AtprotoFetchResult {
  if (!input.can_bind_selected_address || !input.can_inspect_peer_address) {
    return {
      verdict: "feature-unavailable",
      failure_class: "connection-pinning-unavailable",
      conformance_claimable: false,
    };
  }
  if (input.hops.length === 0 || input.hops.length > 4) {
    return rejectAtproto("redirect-chain-invalid");
  }

  let expectedUrl = input.initial_url;
  const fetchedUrls: string[] = [];
  for (let index = 0; index < input.hops.length; index += 1) {
    const hop = input.hops[index];
    if (hop.automatic_redirects) return rejectAtproto("automatic-redirect");

    let requested: URL;
    try {
      requested = new URL(hop.requested_url);
    } catch {
      return rejectAtproto("request-invalid");
    }
    if (
      hop.requested_url !== expectedUrl
      || requested.protocol !== "https:"
      || requested.username !== ""
      || requested.password !== ""
      || requested.hostname.length === 0
    ) {
      return rejectAtproto("request-invalid");
    }
    if (requested.port !== "" && requested.port !== "443" && !hop.non_default_port_allowed) {
      return rejectAtproto("port-not-allowed");
    }
    if (isSpecialDestination(requested.hostname)) {
      return rejectAtproto("destination-invalid");
    }
    if (
      hop.resolved_addresses.length === 0
      || hop.resolved_addresses.some((address) =>
        normalizeIp(address) === undefined || isSpecialDestination(address))
    ) {
      return rejectAtproto("destination-invalid");
    }

    const selected = normalizeIp(hop.selected_address);
    const validated = new Set(hop.resolved_addresses.map(normalizeIp));
    if (selected === undefined || !validated.has(selected)) {
      return rejectAtproto("address-not-validated");
    }
    if (normalizeIp(hop.connected_peer_address) !== selected) {
      return rejectAtproto("peer-address-mismatch");
    }

    const hostname = requested.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    const expectedHost = requested.port === "" || requested.port === "443"
      ? hostname
      : `${hostname}:${requested.port}`;
    if (
      hop.tls_server_name.toLowerCase() !== hostname
      || hop.certificate_hostname.toLowerCase() !== hostname
      || hop.host_header.toLowerCase() !== expectedHost
    ) {
      return rejectAtproto("authority-mismatch");
    }
    if (!hop.certificate_valid) return rejectAtproto("certificate-invalid");

    fetchedUrls.push(hop.requested_url);
    if (hop.redirect_location === null) {
      if (index !== input.hops.length - 1) {
        return rejectAtproto("redirect-chain-invalid");
      }
      continue;
    }
    if (index === input.hops.length - 1) {
      return rejectAtproto("redirect-chain-invalid");
    }
    try {
      expectedUrl = new URL(hop.redirect_location, requested).toString();
    } catch {
      return rejectAtproto("redirect-chain-invalid");
    }
  }

  return {
    verdict: "accept",
    conformance_claimable: true,
    normalized: {
      fetched_urls: fetchedUrls,
      redirect_count: fetchedUrls.length - 1,
      connection_pinned: true,
    },
  };
}

function isPublicIpv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  const value = (
    ((octets[0] << 24) >>> 0)
    + (octets[1] << 16)
    + (octets[2] << 8)
    + octets[3]
  ) >>> 0;
  const inRange = (base: number, prefix: number): boolean => {
    const mask = prefix === 0 ? 0 : (0xffff_ffff << (32 - prefix)) >>> 0;
    return (value & mask) === (base & mask);
  };
  return ![
    [0x0000_0000, 8],
    [0x0a00_0000, 8],
    [0x6440_0000, 10],
    [0x7f00_0000, 8],
    [0xa9fe_0000, 16],
    [0xac10_0000, 12],
    [0xc000_0000, 24],
    [0xc000_0200, 24],
    [0xc0a8_0000, 16],
    [0xc612_0000, 15],
    [0xc633_6400, 24],
    [0xcb00_7100, 24],
    [0xe000_0000, 4],
    [0xf000_0000, 4],
  ].some(([base, prefix]) => inRange(base, prefix));
}

function isPublicIpv6(address: string): boolean {
  const value = ipv6ToBigInt(address);
  if (value === undefined) return false;
  const globalUnicast = value >> 125n === 1n;
  const documentation = value >> 96n === 0x20010db8n;
  return globalUnicast && !documentation;
}

function ipv6ToBigInt(address: string): bigint | undefined {
  const halves = address.split("::");
  if (halves.length > 2) return undefined;
  const left = halves[0] === "" ? [] : halves[0].split(":");
  const right = halves.length === 1 || halves[1] === "" ? [] : halves[1].split(":");
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return undefined;
  const groups = [
    ...left,
    ...Array.from({ length: missing }, () => "0"),
    ...right,
  ];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    return undefined;
  }
  return groups.reduce(
    (result, group) => (result << 16n) | BigInt(Number.parseInt(group, 16)),
    0n,
  );
}

export function resolvePublicAsset(input: PublicResolutionInput): PublicOutcome {
  if (input.tier !== 1) return "private";
  if (input.conflict) return "conflicted";
  if (!input.available || !input.signature_valid) return "unavailable";
  if (
    !input.complete_fetch
    || !input.nip65_refreshed
    || !input.canonical_feed_reachable
  ) {
    return "unavailable";
  }
  if (!input.indexed) return "unindexed-signed-event";
  return input.repo_confirmed ? "canonical" : "provisional-canonical";
}
