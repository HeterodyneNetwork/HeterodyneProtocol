import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8Bytes } from "../hex.js";
import { jcsCanonicalize } from "../jcs.js";

export type CurrentTier3RouteRequest = Readonly<{
  requested_repository_rid: string;
  requested_interface_id: string;
  requested_route: string;
}>;

type FixedPrivateRepositoryRoute = Readonly<{
  authenticated: true;
  repository_rid: string;
  interface_id: string;
  interface_class: "private-repository";
  route: string;
}>;

type PrivateRouteAuthority = Readonly<Record<never, never>>;

export type CurrentTier3RouteEvidence = Readonly<{
  /** Opaque per-evaluation identity; retained only in nonserialized evidence. */
  authority_identity: object;
  vector_id: string;
  request_digest: string;
  repository_rid: string;
  interface_id: string;
  route: string;
}>;

const PRIVATE_REPOSITORY_RID = "rad:z3CurrentPrivateRepository";
const PRIVATE_INTERFACE_ID = "radicle-native-private";
const PRIVATE_ROUTE = PRIVATE_REPOSITORY_RID;
const TIER3_PROFILE_KINDS = [1, 6, 16, 1063, 30023, 30402] as const;

const fixedRoute = Object.freeze({
  authenticated: true as const,
  repository_rid: PRIVATE_REPOSITORY_RID,
  interface_id: PRIVATE_INTERFACE_ID,
  interface_class: "private-repository" as const,
  route: PRIVATE_ROUTE,
});

const FIXED_PRIVATE_REPOSITORY_ORACLES = new Map<string, FixedPrivateRepositoryRoute>([
  ["comms/marmot-private-route-required", fixedRoute],
  ...TIER3_PROFILE_KINDS.map((kind) => [
    `comms/profile-heterodyne-comms-tier3-wrapped-content-kind-${kind}-v1`,
    fixedRoute,
  ] as const),
]);

const authorityState = new WeakMap<object, Readonly<{
  vector_id: string;
  request_digest: string;
  route: FixedPrivateRepositoryRoute;
}>>();

function bindingDigest(vectorId: string, request: CurrentTier3RouteRequest): string {
  return bytesToHex(sha256(utf8Bytes(
    "heterodyne-current-tier3-route-binding-v1\0"
      + jcsCanonicalize({ vector_id: vectorId, request }),
  )));
}

function mintPrivateRouteAuthority(
  vectorId: string,
  request: CurrentTier3RouteRequest,
): PrivateRouteAuthority | null {
  const route = FIXED_PRIVATE_REPOSITORY_ORACLES.get(vectorId);
  if (route === undefined) return null;
  const authority = Object.freeze({});
  authorityState.set(authority, {
    vector_id: vectorId,
    request_digest: bindingDigest(vectorId, request),
    route,
  });
  return authority;
}

function consumePrivateRouteAuthority(
  authority: PrivateRouteAuthority,
  vectorId: string,
  request: CurrentTier3RouteRequest,
): Readonly<{
  route: FixedPrivateRepositoryRoute;
  evidence: CurrentTier3RouteEvidence;
}> | null {
  const binding = authorityState.get(authority);
  authorityState.delete(authority);
  const requestDigest = bindingDigest(vectorId, request);
  if (
    binding === undefined
    || binding.vector_id !== vectorId
    || binding.request_digest !== requestDigest
  ) return null;
  return {
    route: binding.route,
    evidence: Object.freeze({
      authority_identity: authority,
      vector_id: vectorId,
      request_digest: requestDigest,
      repository_rid: request.requested_repository_rid,
      interface_id: request.requested_interface_id,
      route: request.requested_route,
    }),
  };
}

function closedRouteRequest(value: unknown): CurrentTier3RouteRequest | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const input = value as Readonly<Record<string, unknown>>;
  if ([
    "authority",
    "authorized_routes",
    "interface_class",
    "private_group",
    "repository_visibility",
    "route_authority",
    "route_evidence",
  ].some((member) => Object.hasOwn(input, member))) return null;
  if (
    typeof input.requested_repository_rid !== "string"
    || typeof input.requested_interface_id !== "string"
    || typeof input.requested_route !== "string"
  ) return null;
  return Object.freeze({
    requested_repository_rid: input.requested_repository_rid,
    requested_interface_id: input.requested_interface_id,
    requested_route: input.requested_route,
  });
}

/**
 * Evaluates a Tier-3 route only against the authenticated fixed profile
 * oracle. Each invocation mints and consumes a fresh authority. Its opaque
 * identity survives only in private evidence, never in case input or output.
 */
export function evaluateCurrentTier3PrivateRoute(
  vectorId: string,
  value: unknown,
): Readonly<{
  decision: Readonly<
    | { verdict: "accept" }
    | { verdict: "reject"; reason_code: "marmot-private-route-required" }
  >;
  evidence: CurrentTier3RouteEvidence | null;
}> {
  const request = closedRouteRequest(value);
  if (request === null) {
    return {
      decision: { verdict: "reject", reason_code: "marmot-private-route-required" },
      evidence: null,
    };
  }
  const authority = mintPrivateRouteAuthority(vectorId, request);
  if (authority === null) {
    return {
      decision: { verdict: "reject", reason_code: "marmot-private-route-required" },
      evidence: null,
    };
  }
  const authorized = consumePrivateRouteAuthority(authority, vectorId, request);
  if (authorized === null) {
    return {
      decision: { verdict: "reject", reason_code: "marmot-private-route-required" },
      evidence: null,
    };
  }
  const route = authorized.route;
  const publicCarrier = /^(?:https?|wss?):\/\//iu.test(request.requested_route);
  const accepted = route.authenticated
    && route.interface_class === "private-repository"
    && !publicCarrier
    && request.requested_repository_rid === route.repository_rid
    && request.requested_interface_id === route.interface_id
    && request.requested_route === route.route;
  return {
    decision: accepted
      ? { verdict: "accept" }
      : { verdict: "reject", reason_code: "marmot-private-route-required" },
    evidence: authorized.evidence,
  };
}
