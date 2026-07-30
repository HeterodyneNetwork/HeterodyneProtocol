# ADR-035: Universal public client and onion-first light-client transport

**Date:** 2026-07-30
**Status:** Accepted
**Decision makers:** user and protocol maintainers
**Spec targets:** `heterodyne:core/0.5.0#core-key-authority`,
`heterodyne:core/0.5.0#core-node-roles`,
`heterodyne:core/0.5.0#core-tor-reachability`,
`heterodyne:core/0.5.0#core-capabilities`,
`heterodyne:core/0.5.0#core-conformance`,
`heterodyne:comms/0.5.0#comms-publishing`,
`heterodyne:comms/0.5.0#comms-feed-index`,
`heterodyne:comms/0.5.0#comms-retrieval`,
`heterodyne:comms/0.5.0#comms-direct-messages`,
`heterodyne:comms/0.5.0#comms-conformance`,
and the incomplete
`heterodyne:control/0.5.0#control-reserved-scope`

## Context

Core currently requires every conforming client to include self-contained onion
reachability and to read and write through a repo relay. That requirement makes
browser-tab clients depend on an experimental WebSocket bridge path even when
they need only public content or relay-mediated Control. At the same time,
ADR-030 proposes a session-device client that can ask a full node to perform
key- and repository-holding operations, but it leaves relay selection and
response routing unspecified.

The protocol also lacks a universal, clickable public-persona address. A user
can share an `npub`, an event id, and relay hints separately, but there is no
standard HTTPS launcher that downloads a client and resolves a persona or
public asset entirely in the browser. A central reference launcher is useful
for adoption, provided that its origin never becomes identity, content, or
delivery authority and does not learn the requested persona merely from the
HTTP request.

Three requirements must coexist:

1. any ordinary browser can read public Heterodyne content from known clearnet
   Nostr relays without first acquiring Tor;
2. Tor-capable clients and full nodes retain an onion-first path that does not
   expose either endpoint's network location; and
3. the same browser client can enroll with a full node and gain bounded
   capabilities without receiving persona, NID, audience, repository, or
   ratchet secrets.

This ADR uses **onion service** for a Tor-hosted application endpoint and
**Tor relay** for infrastructure that forwards Tor traffic. A Heterodyne full
node runs the former by default; it does not become the latter.

## Decision

### 1. Role-scoped client model

Heterodyne defines these implementation roles:

- **Public reader** — a read-only client that resolves a persona and consumes
  Tier 1 public content from ordinary Nostr relays. It holds no persona or
  session key and needs no Heterodyne service backend.
- **Authenticated light/session client** — the same client after it generates a
  disposable session-device key and completes Control enrollment with a full
  node. It uses the full node for authorized key- and repository-holding
  operations.
- **Full node** — the existing Radicle node plus NIP-01 repo-relay adapter,
  extended by this ADR with embedded Tor, a persistent v3 onion-service
  endpoint, and relay-mediated light-client reachability.

A public reader or authenticated light client without repo access is fully
conforming for its declared role while operating in reduced-assurance
`provisional-accept` mode. It MUST expose that state and MUST upgrade from a
repo relay when one becomes reachable. Reduced assurance is a declared
verification state, not partial or experimental conformance.

### 2. Tor requirements by role

A baseline public reader or light client SHOULD provide self-contained outbound
Tor. A client that omits Tor MUST still support ordinary NIP-01 over clearnet
`wss://`, MUST advertise that Tor is unavailable, MUST visibly distinguish
clearnet operation from Tor-routed operation, and MUST NOT claim onion
reachability.

The Core strict client profile MUST require self-contained outbound Tor and
MUST start supported network backends Tor-routed unless the user explicitly
disables that behavior with a visible downgrade.

A full node MUST include self-contained Tor capability, MUST persist and serve
its NIP-01 repo-relay endpoint as a v3 onion service by default, and MUST
default its supported outbound Heterodyne backends to Tor-routed operation.
The operator MAY explicitly disable Tor routing for a backend, but the node
MUST surface the resulting downgrade. Running a public Tor relay is neither
required nor implied.

A NIP-01 connection from a light client to a full node's `.onion` repo relay is
direct only at the application layer. The Tor onion-service rendezvous remains
on the network path and preserves client- and service-location hiding. A
clearnet peer-to-peer or WebRTC path does not have that property and is not part
of this baseline.

### 3. Clearnet shared-relay compatibility

A full node that claims browser-compatible light-client reachability MUST
publish its active DR invite to and continuously monitor at least one ordinary
Nostr relay with a clearnet `wss://` endpoint. It SHOULD monitor at least two
independently operated clearnet relays. The full node MAY connect to every such
relay through Tor; it never needs to expose a clearnet listener or its network
address.

An ordinary relay may also publish an onion endpoint. "Clearnet-addressable"
means only that a browser without Tor can reach at least one advertised
`wss://` endpoint. No Heterodyne-aware relay behavior is required.

An out-of-band invite MUST carry one or more relay hints, or the client MUST
use a relay from which it fetched the active invite. Relay hints are locators,
not authority.

### 4. Ingress-relay response affinity

For each cryptographically accepted Control request, the full node records:

```text
(DR session id, Control request id, canonical ingress relay URL)
```

The full node MUST publish the response first and only to that ingress relay.
It MUST NOT fan a response out to every configured relay merely because the
request was observed on more than one relay.

If the client does not receive a response, it MAY retry the byte-identical
logical request with the same request id and expiry through another advertised
shared relay. The full node MUST use its restart-safe replay cache to:

- execute an unseen request at most once;
- return the cached final response for an identical retry;
- reply through the retry's new ingress relay; and
- reject reuse of the request id with a different method or payload.

The replay cache MUST atomically reserve the request id and bind it to the
authenticated session, method, payload digest, and first ingress relay before
dispatching the operation. Concurrent identical arrivals join that reserved
execution rather than dispatching a second operation. After a restart, the
executor MUST resume or recover the reserved operation through the same
request-id idempotency boundary; it MUST NOT invoke a committed side effect a
second time. The final response is persisted before it is eligible for replay.
The first cryptographically valid arrival therefore controls execution, while
later identical arrivals retrieve only the same in-progress or final result.
This handles the case in which a side effect committed but its response was
lost. An unauthenticated `reply_relay` URL is neither needed nor permitted.

Relays may still observe timing, volume, and within-ratchet-epoch outer-event
linkage. Tor hides the peers' direct network locations from a clearnet relay but
does not eliminate those metadata or global timing risks.

### 5. Universal public launcher

The reference launcher is a static browser application. Its version-1
fragment grammar is:

```text
Persona:
https://heterodyne.network/client/#/v1/p/<nprofile>

Immutable public asset:
https://heterodyne.network/client/#/v1/p/<nprofile>/e/<nevent>

Addressable or replaceable public asset:
https://heterodyne.network/client/#/v1/p/<nprofile>/a/<naddr>
```

The `nprofile` public key MUST be the persona's canonical cold-root `npub`.
Heterodyne MUST NOT substitute a `did:key`, Radicle NID, derived export AID, or
OIDC subject for this identity. `nevent` identifies an immutable event; `naddr`
identifies an addressable or replaceable event.

NIP-19 relay entries are untrusted bootstrap hints. A universally accessible
link SHOULD include at least one clearnet `wss://` hint and MAY include onion
hints. A non-Tor client skips onion hints and reports that limitation. After
bootstrap, the client MUST refresh the persona's current NIP-65 relay list.

The fragment grammar is provider-independent. Any compatible static host may
replace the origin while preserving the fragment:

```text
https://other-client.example/#/v1/p/<nprofile>/e/<nevent>
```

`heterodyne.network` is the reference launcher, never identity, content,
repository, or delivery authority.

Because browsers do not transmit URL fragments in HTTP requests, the reference
host receives only the request for `/client/`; persona, asset, and relay
identifiers remain client-side. This prevents the launcher origin and its CDN
logs from learning the requested target from the application request. Other
software through which the complete link passes may still log the fragment.
Content-specific server-rendered social previews are not a requirement.

### 6. Local public resolution

The downloaded client performs resolution locally:

1. parse and validate the complete versioned fragment before network activity;
2. decode the cold-root `nprofile` plus any `nevent` or `naddr`;
3. contact accepted clearnet relay hints and usable onion hints;
4. resolve and verify the cold-root identity pointer and available KEL
   material;
5. refresh the NIP-65 relay list;
6. locate public `kind:31007` feed indexes;
7. fetch the requested event from entry hints and the refreshed relay set;
8. verify NIP-01 bytes and signature, KEL authority, and feed-index integrity;
   and
9. require reachability from the persona's canonical Tier 1 feed before
   presenting the asset as a canonical Heterodyne publication.

A valid event absent from the canonical public index MAY be displayed only as
an explicitly labeled **unindexed signed event**. Public-reader mode MUST NOT
render Tier 2 plaintext or attempt to interpret Tier 3 ciphertext as public
content.

Resolution has these user-visible terminal states:

- `canonical`;
- `provisional-canonical` when repository confirmation is unavailable;
- `unindexed-signed-event`;
- `conflicted`;
- `unavailable`; and
- `private`.

Failure to reach every required relay or predecessor MUST NOT be rendered as an
empty feed. Existing complete-fetch, missing-event, truncation, and conflict
rules continue to apply.

### 7. Anonymous-to-authenticated transition

The static client begins without an identity or device key. When a user chooses
to connect a full node, it:

1. generates a disposable session-device key locally;
2. locates the full node's active invite on a shared relay;
3. establishes the accepted DR session;
4. completes Control enrollment;
5. receives its filtered configuration and grant; and
6. sends Control requests under the ingress-relay affinity rule.

The transition requires no application reload or hosted server session.
Without Tor or repo-relay access, the client remains a conforming
reduced-assurance light client. The full node may execute authorized operations
from its own repository-confirmed state; delivery alone never grants authority.

The session device receives no persona epoch secret, NID secret, audience key,
repository-decryption key, credential-ledger key, or ratchet secret. Private
actions use the Control grant and the full node's existing sign-,
publish-, commit-, and decrypt-on-behalf operations.

Logout sends self-revocation when possible, deletes the local session-device
key and ratchet state, clears private configuration and decrypted caches, and
returns the application to public-reader mode. Local deletion proceeds even
when revocation delivery fails; the full node's bounded inactivity expiry
remains the remote backstop.

### 8. Launcher and content security

The launcher MUST validate the complete fragment before opening a connection.
It MUST:

- accept only known versioned routes and valid NIP-19 entities;
- reject a complete fragment longer than 16,384 characters and enforce
  NIP-19's 5,000-character recommended maximum on each entity;
- use no more than the first eight distinct, normalized bootstrap relay hints
  across all route entities and ignore the rest;
- accept public clearnet bootstrap relays only as `wss://`;
- reject relay URLs containing credentials, query strings, or fragments;
- reject IP literals in private, link-local, loopback, unspecified,
  documentation, benchmarking, multicast, or otherwise special-use ranges;
- reject single-label hosts and special-use local names, including
  `localhost`, `*.localhost`, `*.local`, and `*.internal`;
- reject a hostname when the platform exposes a resolved destination in one of
  those ranges, and rely on the browser's private-network protections when it
  does not expose DNS results; and
- use `.onion` hints only through Tor.

These checks block direct local-network hint injection. They do not make DNS
rebinding impossible in a browser that hides resolution results, so the
launcher MUST also minimize each relay connection to the NIP-01 WebSocket
exchange and MUST NOT treat successful connection as authority.

Fetched content is data, never application code. The launcher MUST sanitize
rendered markup and MUST NOT execute publication-provided scripts, event
handlers, frames, or active content. External media requests MUST omit
credentials and referrer information. A client without Tor MUST warn that
loading external media reveals its IP address to that media host.

The reference client MUST load no third-party executable scripts, MUST use a
restrictive Content Security Policy, and SHOULD publish reproducible signed
release artifacts plus a public release-transparency record. It SHOULD display
its exact release identifier during enrollment and SHOULD give centrally
hosted browser sessions short-lived, constrained grants by default.

Hosted JavaScript remains part of the authenticated browser's trusted
computing base. Reproducibility and transparency improve detection but cannot
make mutable web delivery equivalent to an independently installed client.
Durable credential synchronization and high-authority grants SHOULD remain
confined to separately trusted clients. The identical reference artifact MUST
remain self-hostable.

"Anonymous public reader" means the reader presents no Heterodyne account or
persona. Without Tor, the launcher host sees the initial application download,
ordinary relays see client IP and subscription filters, and external media
hosts may see client IP. The client MUST NOT describe that state as network
anonymous.

### 9. Conformance allocation

Core must replace universal embedded-Tor and repo-relay requirements with
role-scoped capability requirements:

- every implementation still claims Core;
- a public-reader role may advertise ordinary-relay read support and a reduced
  repo feature set with rationale;
- absence of Tor is conforming outside strict mode when disclosed as above;
- Tor-capable light clients advertise onion and repo-relay features; and
- full nodes advertise their Tor/onion-service and browser-compatible
  shared-relay capabilities.

The integration patch MUST allocate separate stable feature IDs for ordinary
relay reading, outbound Tor, repo-relay access, full-node onion-service
hosting, and browser-compatible shared-relay rendezvous. A capability
advertisement MUST list only the features actually implemented; a prose
rationale is not a substitute for a stable feature ID.

Comms must define the stable `comms.public-reader.v1` receive-only Tier 1
feature rather than forcing a read-only implementation to claim publishing,
private tiers, claims, or DM behavior it does not implement. The feature
includes feed-index, retrieval, canonical-envelope consumption, and the
applicable receive-side security invariants and vectors.

An authenticated session client additionally implements the Comms DR and
negotiation features plus the Control client role. The paired full node
implements the corresponding Control server behavior. Control remains
non-claimable until ADR-030 and this ADR's relay-affinity rules are integrated
with closed schemas, state machines, and vectors.

The Core and Comms strict profiles continue to compose, but Core strict now
owns the mandatory outbound-Tor delta that baseline browser clients may omit.

### 10. Required conformance vectors

Integration requires at least:

- persona, immutable-event, and addressable-event launcher round trips;
- proof that fragment identifiers do not enter the launcher HTTP request;
- invalid, unknown-version, and oversized links causing no network activity;
- rejection of localhost, private-network, credential-bearing, and invalid
  relay hints;
- stale embedded relay hints followed by successful NIP-65 refresh;
- exact `canonical`, `provisional-canonical`, `unindexed-signed-event`,
  `conflicted`, `unavailable`, and `private` outcomes;
- Tier 2 and Tier 3 refusal in public-reader mode;
- missing-Tor reduced-assurance and external-media disclosure behavior;
- anonymous-to-authenticated transition without application reload;
- session-key confinement, logout cleanup, and failed-revocation expiry;
- response publication to the authenticated request's ingress relay;
- cross-relay identical retry returning a cached result without re-execution;
- rejection of a reused request id with changed method or payload;
- full-node v3 onion-service advertisement and default Tor routing; and
- browser-compatible full-node advertisement of at least one clearnet shared
  relay.

Wire-affecting vectors belong to Core, Comms, or Control according to the
family ownership above. Presentation-only checks may remain implementation
evidence but MUST be named in conformance reports when required by a profile.

## Alternatives considered

### Universal Tor requirement for every browser

Rejected as the baseline. Browser-tab Tor still needs a browser-compatible
transport gateway, raising the adoption floor for public reading. Tor remains
recommended in baseline and mandatory in strict mode.

### TURN or clearnet WebRTC between light client and full node

Deferred to a future optional expansion. It is unnecessary for NAT traversal
when the full node uses an onion service, creates another credentialed
provider path, and may expose endpoint network metadata. It MUST NOT become an
automatic optimization or silent downgrade.

### Relay every repository read and write

Rejected. Relay-mediated Control remains the bootstrap and command path, while
Tor-capable clients retain direct NIP-01 access to a full node's onion repo
relay for repository-backed content and finality.

### Path-routed universal links

Rejected for the reference launcher. Path routing would expose persona and
asset targets to the centralized origin and CDN logs. Fragment routing gives
up content-specific server previews to keep resolution local and target-blind
at the launcher.

### `did:key` as the persona URL identifier

Rejected. The cold-root `npub` is already canonical, `did:key` names Radicle
NIDs elsewhere in Heterodyne, and derived DIDs must not become alternate
persona authority. NIP-19 already supplies human-shareable Nostr identifiers
and relay hints.

### Server-side public-content aggregation

Rejected. A hosted aggregator would learn target queries, become an attractive
browsing-history intermediary, and weaken the rule that clients resolve and
verify locally.

## Consequences

- Any ordinary browser can open a single public Heterodyne link and locally
  render public content from known clearnet relays.
- The reference launcher is operationally centralized but not authoritative;
  mirrors can serve the identical fragment grammar and artifact.
- Browser clients without Tor remain conforming while visibly reduced in
  assurance and network privacy.
- Full nodes gain a stronger implementation obligation: embedded Tor,
  persistent onion-service hosting, Tor-default outbound behavior, and at
  least one clearnet shared relay when browser compatibility is claimed.
- Ordinary Nostr relays remain unchanged and act as blind rendezvous carriers.
- Relay affinity reduces unnecessary response fan-out while restart-safe
  idempotency handles lost replies.
- The public-reader profile requires a role-aware revision of Core and Comms
  conformance rather than a synchronized family-version change.
- Centrally hosted authenticated use retains web-supply-chain risk, bounded by
  session-device confinement, short expiry, constrained grants, and
  self-hostability rather than hidden by an overclaim.

## External standards

- Nostr NIP-01: client-relay WebSocket wire and event verification.
- Nostr NIP-19: `npub`, `nprofile`, `nevent`, and `naddr` shareable
  identifiers.
- Nostr NIP-65: replaceable read/write relay metadata.
- Tor v3 onion-service rendezvous specification: outbound-only service
  reachability, location hiding, and end-to-end onion authentication.
