# ADR-019: Mandatory embedded Tor — onion reachability as a client conformance requirement

Date: 2026-05-24
Status: Accepted
Spec target: `docs/spec/heterodyne.md` (§7.7 discovery/transport, §10.2 client model, §11.7 strict-mode, §14 conformance), `docs/architecture.md`, `docs/security/threat-model.md`

## Context

The threat model currently treats network-level deanonymization as
largely out of scope: the passive network observer is assumed
TLS-bounded (sees peers, timing, volume), "onion-routed Matrix" is
listed as future work under cross-persona linking, and "traffic
analysis against Tor-routed Matrix federation" sits in the explicit
out-of-scope list. Meanwhile, privacy-focused Nostr relays and Matrix
homeservers increasingly publish `.onion` endpoints. If Heterodyne
clients cannot reach those endpoints, onion-hosted feeds and relays
are second-class — discoverable in a NIP-65 relay list but
unreachable in practice — which undercuts the project's
identity-portability and censorship-resistance goals.

Two distinct capabilities were conflated in the originating proposal
and must be separated:

1. **Onion reachability** — the client can *connect to* `.onion` relay
   and homeserver URLs when they appear in a user's configuration or a
   discovered relay list. This is an addressing/reachability property.
2. **Egress privacy** — the client routes *its own* outbound
   connections over Tor to anonymize the user's network location. This
   is a transport-policy property with latency, battery, and
   network-compatibility costs.

A real interaction with §1's non-goal ("Heterodyne does not define a
new transport, relay protocol, or homeserver; it composes existing
ones") must be addressed: mandating Tor reachability is a **client
conformance requirement about which destination address types a
conforming client can reach**, not the definition of a new transport
or relay protocol. Tor is an existing transport the client composes.
The spec needs one clarifying sentence to make that framing explicit
rather than silently straining the non-goal.

Platform feasibility was verified. Native desktop, Node.js, and mobile
**apps** can embed Tor today (Onion Browser and Orbot ship the Tor
daemon on iOS; arti and the C `tor` daemon cover desktop/Node). The one
genuine exception is **browser-tab clients**: WASM cannot open the raw
TCP sockets Tor's protocol requires (Arti issue #343, open since 2022),
so a browser client reaches the Tor network only by tunneling embedded
Tor through a WebSocket-based pluggable transport / bridge. The
requirement wording must name that path so it stays satisfiable and
honest rather than implying a browser tab runs direct Tor.

## Decision

Heterodyne makes **embedded Tor a universal client conformance
requirement**, with reachability and egress treated as two separate
normative requirements:

- **Embedded, not delegated.** Conforming clients ship Tor capability
  *as part of the application* (e.g. via a Node.js library, a native
  binding, or a WASM build). The spec does NOT require — and does NOT
  reduce the obligation to — honoring an externally configured SOCKS5
  proxy. Embedding is the baseline; respecting an external proxy is an
  additional `MAY`.

- **Onion reachability is a Universal MUST.** Every conforming client,
  on every platform, MUST be able to connect to `.onion` relay and
  homeserver endpoints when they are present in configuration or a
  discovered relay list. Browser/WASM clients, which cannot open raw
  TCP sockets, satisfy this MUST by providing embedded Tor capability
  through a WebSocket-based pluggable transport / bridge. No platform
  is exempted from the MUST; only the *mechanism* differs for browsers.

- **Egress privacy is opt-in but prominent.** Routing the user's own
  outbound traffic over Tor is OFF by default and exposed through a
  prominent, easily discoverable client control. This preserves the
  compatibility-first stance (no surprise latency/battery cost, no
  breakage on Tor-blocking networks) while making the protection a
  first-class, one-toggle feature. The §11.7 strict-mode client profile
  (ADR-007) elevates egress-over-Tor to default-on.

- **Implementation-agnostic wording preserved.** Requirements are
  written in terms of *capability and reachability* (the client can
  reach `.onion`; the client offers Tor egress), never a named library,
  daemon, or version. The §1 transport non-goal gains one clarifying
  sentence stating that requiring reachability of an existing transport
  is a conformance property, not the definition of a new transport.

## Requirements (RFC 2119)

- A conforming client MUST provide self-contained, application-embedded
  Tor capability (a bundled library, native binding, app-managed daemon,
  or WASM build); it MUST NOT depend on a separately installed Tor daemon
  or an externally configured SOCKS5 proxy to satisfy onion reachability.
  The requirement is the *capability* (built-in, no external dependency),
  not a specific packaging.
- A conforming client MUST be able to establish connections to `.onion`
  relay and homeserver endpoints that appear in user configuration or a
  discovered relay list (e.g. NIP-65 `kind:10002`), with no DNS or
  connection leak of the `.onion` host to a clearnet resolver.
- A client running in an environment that cannot open raw TCP sockets
  (browser/WASM runtime) MUST satisfy the onion-reachability MUST by
  *implementing* a path that tunnels its embedded Tor through a
  WebSocket-based pluggable transport / bridge; such a client MUST
  surface a clear indicator when no usable bridge is available so the
  unreachable state is not silent. Conformance is evaluated on the
  client's *capability*, not ambient network conditions: a temporary
  bridge outage is an operational condition, not a conformance failure.
- A conforming client MUST offer egress-over-Tor (routing the client's
  own outbound connections through Tor) as a user-controllable feature.
- A conforming client MUST default egress-over-Tor to OFF and MUST
  expose its toggle through a prominent, discoverable control rather
  than a buried setting.
- A conforming client MUST NOT silently route user egress over Tor
  without the user having enabled it — except under a profile (e.g.
  §11.7 strict-mode) whose selection IS the explicit enablement, in
  which case the client MUST disclose that egress is default-on. In all
  cases the client MUST surface an active indicator while
  egress-over-Tor is on.
- The §11.7 strict-mode client profile MUST default egress-over-Tor to
  on; selecting strict mode constitutes the user's explicit selection of
  that transport policy, and a strict-mode client MUST disclose that
  egress-over-Tor is active by default.
- A conforming client MAY additionally honor an externally configured
  SOCKS5/system proxy, but MUST NOT treat that as a substitute for the
  embedded-Tor MUST.
- The specification MUST state, in or adjacent to the §1 transport
  non-goal, that requiring reachability of an existing transport
  (`.onion`) is a client conformance property and does NOT constitute
  defining a new transport, relay protocol, or homeserver.
- The threat model MUST be updated to move onion reachability and
  opt-in Tor egress from "out of scope / future work" into the
  in-scope mitigations for the passive network observer and
  cross-persona-linking-via-metadata threats, and MUST retain
  Tor-traffic-analysis (timing/volume correlation against the Tor
  network itself) as a documented residual limitation.
- Conformance test vectors and the strict-mode profile SHOULD be
  extended to cover onion reachability and the browser bridge path so
  the MUST is verifiable rather than aspirational.

## Consequences

- Onion-hosted relays and homeservers become first-class: any
  conforming client can reach them, so privacy-focused operators can
  rely on a baseline of universal reachability.
- The passive-network-observer and metadata-linking threats gain a
  concrete, in-scope mitigation (opt-in egress over Tor) instead of a
  deferred "future work" note. Residual Tor-level traffic analysis
  remains a documented limitation, not a silent gap.
- The universal MUST raises the conformance bar for every client author,
  including a non-trivial obligation for browser clients (embedded Tor
  over a WebSocket bridge is experimental and bridge-availability
  dependent). This is an accepted cost of keeping onion reachability
  uniform across platforms; the bridge dependency and its experimental
  status are documented rather than hidden.
- Keeping egress opt-in avoids regressing the compatibility-first stance
  and the §13 usability/availability posture, at the cost of weaker
  privacy-by-default for users who never flip the toggle — mitigated by
  the prominence requirement and the strict-mode escalation path.
- The §1 non-goal text must be touched to add the clarifying sentence;
  this is editorial, not a reversal of the non-goal.
- Binary size, update responsibility, and export/cryptography-compliance
  considerations now apply to every client; these are implementation
  concerns the implementation-agnostic spec notes but does not resolve.
