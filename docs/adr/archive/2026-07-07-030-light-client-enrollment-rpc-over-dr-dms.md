# ADR-030: Light-client device enrollment and RPC over double-ratchet DMs

**Date:** 2026-07-07
**Status:** Accepted
**Decision makers:** user (design direction); codex review integrated

## Family-allocation amendment (2026-07-19)

ADR-033 split the former monolith while ADR-030 remained proposed. This
amendment allocated the proposal across the independently versioned family; at
that date it neither accepted ADR-030 nor completed the Control profile.

| Family document | Allocation |
|---|---|
| `Core` | Session-device base extensibility for `kind:31001`: Core retains the base schema, delegation verification, registry allocation, finality, and owner stamp. |
| `Comms` | Epoch-key invite, undelegated initiator carve-out, distinct DR contexts, authenticated `control-enrollment` acceptance, subprotocol negotiation, and encrypted carriers. |
| `Control` | Enrollment, RPC framing and methods, grants, tokens, replay and lifecycle rules, audit semantics, and the MCP/agentic profile. |

The qualified integration targets are
`heterodyne:core/0.5.0#core-nid-delegation`,
`heterodyne:comms/0.5.0#comms-direct-messages`,
`heterodyne:comms/0.5.0#comms-acceptance-hook`,
`heterodyne:comms/0.5.0#comms-subprotocol-negotiation`, and the incomplete
`heterodyne:control/0.5.0#control-reserved-scope`. These replace the candidate
monolith integration targets in the original proposal.

The no-key-export rule is scoped to session devices: session devices MUST NOT
receive persona epoch secrets, NID secrets, audience keys, repository-
decryption keys, or ratchet secrets. Authorized durable NID devices continue
to use Comms credential-plane synchronization when they hold its explicit,
KEL-validated, revocable authorization. That credential path does not grant
Control authority and does not weaken session-device confinement.

**Historical monolith reference label.** Every unqualified `§...` reference
below names a section of the frozen 0.4.0 monolith and is not a current
integration target. This label applies only to those reference destinations;
live proposal statements are corrected in place by this amendment.

## Later-decision reconciliation (2026-08-03)

ADRs 032 through 038 were accepted after the original draft. ADR-030 is
accepted with the following reconciliations, which are also applied directly
to the operative Decision, Requirements, diagram, rationale, consequences,
and vector list below:

- **Core event ownership and finality.** A session-device `kind:31001` uses
  the non-stamping `heterodyne-control-session-device-v1` profile and carries
  the sole base-owner stamp `["spec_version","core/0.5.0"]`. Relay-valid
  evidence is only provisional under Core's declared finality policy. The
  exact delegation becomes final only when reachable from the canonical
  event-storage repository; `deny-until-repo` grants no provisional
  enrollment authority.
- **Enrollment invite and acceptance.** The epoch invite has exactly
  `kind:30078` and `d = double-ratchet/invites/epoch`, carries the mandatory
  `kel_head`, and is signed by the current KERI-authoritative epoch key.
  Enrollment names the exact currently active invite event. An undelegated
  initiator is permitted only in the authenticated `control-enrollment`
  context; it remains forbidden in every ordinary DM, credential, and other
  Comms context. Comms authenticates the carrier first and otherwise holds
  the request without a sender-visible policy signal until Control's
  QR/challenge/enrollment-token decision accepts or rejects it.
- **Relay-affine replay.** Before execution, the executor atomically reserves
  the accepted DR session, request id, method, canonical payload digest,
  request expiry, and first server-observed authenticated ingress relay. The
  ingress relay is transport context, never a caller-supplied request member.
  A retry must preserve the complete logical request, including expiry; each
  response is persisted before publication and sent first and only through
  the actual authenticated ingress relay for that arrival.
- **Authorization authority.** Control owns grant and enrollment-token
  semantics, but the Comms private claim ledger is their sole authorization
  authority. Only repository-final `active` state grants positive authority.
  Delivery, a DR session, a delegation alone, a filtered session view, or an
  OIDC/JWT projection does not. Authenticated revocations and reductions take
  effect immediately and are then committed for repository finality.
- **Three non-substitutable token classes.** The one-use, expiring Control
  enrollment token moves the enrollment ceremony in time. The Comms/OIDC
  agent workload access token is short-lived, sender-constrained publication
  authority. ADR-038's recovery transfer/bootstrap grant is key-bound,
  non-bearer, and valid for at most eight hours. None authorizes a use assigned
  to either of the other two classes.
- **Human and agent signing.** A human Control profile may expose explicitly
  grant-scoped signing methods where separately specified. An agentic profile
  never exposes raw signing, private-key access, a human publication method,
  or a human-key fallback. Agent publication uses only the intent-level
  `heterodyne.agent.publish` path, a current workload token and fresh per-use
  proof, mandatory attribution constructed by the full node, and the current
  full-node-held `agent:<role-id>` key.
- **Workload generation binding.** Agent issuance and every publication side
  effect bind the exact issuer, pairwise subject, `client_id`, role id, Control
  session, request, canonical payload digest, and current credential-ledger
  persona, generation, checkpoint, and status. A credential-ledger reset
  invalidates and purges prior-generation pending issuance and authority;
  further work requires current-generation reissuance.
- **Transport assurance.** Control enrollment and RPC remain relay-mediated
  and require no direct light-to-full-node channel. Strict clients use
  outbound Tor. A browser without Tor may use an authenticated clearnet shared
  relay only in visibly declared reduced-assurance mode. This does not
  prohibit optional direct application-layer access through Tor to an
  advertised onion repo relay for repository finality or retrieval; that
  connection does not become a Control transport.
- **Ratchet durability and termination.** DR receive-state advancement,
  durable persistence, and consumed-message-key erasure are one atomic action
  completed before plaintext release. A revocation or credential transition
  invalidates affected sessions locally and uses ADR-037's separately
  authenticated persistent NIP-59 peer tombstone to warn the peer; the
  tombstone is not a Control response or transcript.
- **Recovery and retention boundary.** ADR-038 recovery approval,
  bootstrap/transfer grants, admission, and authority activation are separate
  Core/Comms compositions and never open Control. Recovery does not restore
  active DR state, message keys, temporary workload tokens, sender proofs, or
  a live Control session. Relay-carried Control request/response traffic is
  never repository-committed or backfilled. A bounded encrypted side-effect
  audit may be retained in protected recovery material, but it is not a
  replayable RPC transcript and contains neither message keys nor raw workload
  tokens except under a separately bounded protected diagnostic policy.

Acceptance records the design decision; it does not open the incomplete
Control conformance gate. General Control activation, advertisement, and
conformance claims remain forbidden until registry revision 4, its closed
schemas and state machines, and the minimum normative vectors named by this
ADR and ADRs 035-038 are integrated and the profile gate is explicitly opened.

## Context

Since ADR-027, §3.3 authorizes a browser-only / light device with a
secp256k1 publishing key and no NID, stating that "its repo writes are
performed by a persona-controlled full node (§10 write path)" - but no
section specifies the mechanism by which the light device asks the full
node to perform those writes. Browsers and PWAs cannot run Heartwood,
so platforms without a full-node client currently have no complete
participation path. Two further use cases share the same shape:
automated client provisioning (no human enrollment ceremony) and
agentic clients commanded two-way by a controlling full node.

The building blocks already exist: §5.7 self-DM sessions are a
forward-secret device-to-device transport over ordinary relays;
§3.3.1 delegations distinguish NID-bearing from NID-less devices and
carry a `valid_until`; the epoch key alone signs a `kind:31001`, so
"who can enroll me" is a key-possession question; and `kind:31005`/
`kind:31001` give a QR entry point and relay-watchable provisional signal.

Prior art: **NIP-46 (Nostr Connect / remote signing)** - request and
response payloads over NIP-44-encrypted relay events with QR
onboarding. NIP-46 is signing-only, has no forward secrecy, and leaks
conversation metadata to relays; this ADR generalizes the pattern
over the §5.7 ratchet.

**Scope.** This ADR covers single-user personas. Org personas
(ADR-027) are excluded: full nodes reject org session-device
enrollment and grant mutations until a later revision specifies the
governance flow (see Requirements).

Design goals set by the user: a relay-mediated Control path requiring no
direct light-to-full-node channel; onboarding by QR scan or provisioning
token; Control session devices receive no persona, NID, audience,
repository-decryption, or ratchet secrets; the light client receives its
complete grant-filtered configuration so its UI matches any other device;
light-device keys are session-scoped and disposable; oracle power is
configurable. Optional Tor application-layer access to an advertised onion
repo relay for retrieval and repository finality is a separate data path, not
Control RPC.

## Decision

**A light device generates its own keypair and is cross-signed into
the delegation set by whichever device holds the epoch key; it then
drives the persona through RPC carried as inner rumors in a §5.7
double-ratchet session, the full node executing all key-holding and
repo-holding operations on its behalf under an active
Comms-ledger-authorized per-device grant.
Delegations are session-scoped and disposable; one-time tokens
support automated and agentic enrollment.**

1. **Device-generated keys; session devices vs publishing devices.**
   The new device generates its own secp256k1 keypair locally; the
   private key never leaves the device. This ADR defines the
   **session device** class: an ephemeral, RPC-driven device whose key
   never signs world-visible content - the full node performs an authorized
   human-profile operation with an applicable human key, or an agent
   publication with only its dedicated full-node-held `agent:<role-id>` key.
   It coexists with §10.1.2's
   **delegated publishing device** class (durable delegation, authors
   its own events); §10.1.2's "light node MUST author with its own
   key" rule is scoped to that class at spec integration. The session device
   key signs the enrollment `key_proof` and participates in Comms DR wire
   authentication as defined by Comms. Control RPC inner rumors are unsigned;
   they are authenticated by the accepted DR session, transcript, and carrier
   validation.

2. **Session-device delegation schema.** Enrollment produces a
   NID-less `kind:31001` mirroring the §3.3.1 bidirectional pattern:
   - `d` tag: `pubkey:<64-hex publishing key>` (replaceable per key).
   - Profile: the non-stamping
     `heterodyne-control-session-device-v1`; Core retains the base event and
     sole stamp.
   - Tags: `["heterodyne", "delegation"]`,
     `["spec_version", "core/0.5.0"]`, `["publishing_key", <hex>]`,
     `["cold_root", <npub hex>]`, `["valid_until", <unix-seconds>]`,
     `["binding_nonce", <64-char lowercase hex>]`, `["kel_head",
     <64-hex latest-accepted-KEL-event id>, <decimal seq>]` (mandatory
     on epoch-key-signed events per ADR-032 / spec §3.0), and
     `["key_proof", <64-byte hex BIP-340 sig by the publishing key>]`.
   - `binding_nonce` carries the 32-byte enrollment nonce ON THE WIRE:
     the full-node-issued enrollment challenge (interactive flows) or
     the token id (token flow).
   - Binding payload (domain-separated, deterministic, mirroring
     §3.3.1): `heterodyne-light-binding-v1|<npub>|<pubkey>|`
     `session-device|<nonce>` - `<npub>`/`<pubkey>` as 64-char
     lowercase hex, `<nonce>` the `binding_nonce` tag value verbatim.
     The outer Nostr `sig` (epoch key) covers all tags including the
     nonce; `key_proof` is the device key's signature over the payload
     reconstructed from those tags, proving the enrollee consented to
     exactly this enrollment. Verification needs no private
     enrollment-context state.
   - A relay-valid event is only provisional under Core's
     `provisional-accept` policy. Only reachability from the canonical
     event-storage repository makes this delegation final;
     `deny-until-repo` treats it as absent until then.

3. **The epoch key is the enrollment endpoint.** The persona publishes
   a §5.7.1 DR invite under the epoch key itself: a `kind:30078`,
   exact reserved `d` tag `double-ratchet/invites/epoch`, mandatory
   point-in-time `kel_head`, and signature by the current
   KERI-authoritative epoch key (an explicit carve-out from
   §5.7.2's delegated-device-key invite rule, amended at spec
   integration). Every device holding the epoch key - exactly the
   devices able to sign a delegation - listens on it alongside its own
   device-key invite; possession of the epoch key IS the capability,
   so no executor advertisement exists. Requests arriving there are by
   nature key operations and, after enrollment, are restricted to
   grant-scoped key-operation methods (activation, revocation, unlock).
   On rotation the current invite is published before the prior invite is
   tombstoned. Verifiers require the signer and `kel_head` to match current
   KEL authority, and an enrollment request references the exact currently
   active invite event id it used, defeating stale-invite replay.
   Three bootstrap variants, all §5.7 sessions initiated before the
   new key is delegated:
   - *Co-located:* the full node displays a QR encoding a §5.7.1
     out-of-band invite link; possession of the invite secret proves
     the physical scan. Preferred interactive flow.
   - *Remote interactive:* the device resolves `kind:31005`, fetches
     the epoch-key DR invite, and sends an enrollment request, which
     MUST pass a challenge-response before any ceremony is offered.
   - *Token:* the request carries a one-time enrollment token minted
     via the ceremony (item 11); no further interaction.
   A pending enrollment request expires after a configurable window
   (RECOMMENDED default: 2 minutes); an expired request requires a
   fresh bootstrap.
   Comms authenticates the carrier and transcript before Control policy. The
   sole undelegated-initiator exception is this `control-enrollment` context,
   where the default result is `hold` without a sender-visible policy signal;
   only the Control QR-secret, challenge-response, or enrollment-token
   decision may change that result to accept or reject. An undelegated
   initiator remains invalid in every other Comms context and cannot invoke
   activation, revocation, unlock, ordinary DM, or credential methods.

4. **Authorization ceremony (epoch key, not cold root).** Issuing a
   delegation is an epoch-key operation, performed for interactive
   enrollment only after fresh user authorization: passphrase
   re-entry (or equivalent local unlock) with the requesting key's
   fingerprint displayed for confirmation, plus - in the remote
   variant - a camera/QR challenge-response proving the enrollee is
   the intended device. Token enrollment does not skip the ceremony;
   it moves it to token minting.

5. **Enrollment confirmation without a direct Control channel.** The light
   device watches the persona's write relays for its `kind:31001`, but a
   relay-valid candidate permits only a visibly labeled provisional state
   under Core's `provisional-accept` policy. It is finally enrolled only when
   that exact delegation is repository-final and every applicable
   Comms-ledger authorization decision is `active`; `deny-until-repo` grants
   no provisional authority. No direct Control connection to the full node is
   required. A Tor-capable client may separately reach an advertised onion
   repo relay to obtain repository confirmation.

6. **RPC protocol.** Requests and responses are NIP-46-shaped payloads
   (`{id, method, params}` / `{id, result, error}`) carried inside the
   Comms generic subprotocol-payload rumor after negotiation. Control allocates
   no inner rumor kind and adds no wire stamp.
   Key-operation methods live on the epoch-key endpoint; all others
   run on the device-key session with the enrolling full node. The human
   profile's method vocabulary is the NIP-46
   base (`sign_event`, `get_public_key`, `nip44_encrypt`,
   `nip44_decrypt`, `ping`, ...) plus Heterodyne extensions:
   publish/fan-out, repo write via the §10 write path, feed-index
   update, configuration get/put, media upload, decrypt-on-behalf
   (Tier 3 audience keys and DM sessions), cross-sign / device
   activation, self-revocation, and unlock (challenge-response). A
   full node MAY also serve vanilla NIP-46 clients - separately
   opted-in with its own grants, never an automatic fallback for
   enrolled devices (no forward secrecy, no expiry/grant machinery).
   The agentic profile MUST NOT advertise or accept `sign_event`, private-key
   access, human publication, or an unlabeled/human-key fallback; its only
   publication operation is the intent-level `heterodyne.agent.publish`
   method described in item 12.

   Before dispatch, the full node durably and atomically reserves `(accepted
   DR session id, request id, method, canonical payload digest, request expiry,
   first authenticated ingress relay)`. The normalized ingress relay is
   observed by the receiver and MUST NOT be supplied in the request.
   Concurrent identical arrivals join one execution; a retry with a changed
   session, method, payload, or expiry conflicts. The reservation is the
   restart-recovery boundary: execution progress and side-effect commit
   evidence are reconciled through it after a crash, and an implementation
   that cannot prove an effect was not committed fails closed rather than
   repeating it. The final response is durably persisted in the reservation
   before it is publishable, is sent first and only to the actual ingress
   relay for the triggering arrival, and may be replayed through a later
   retry's actual ingress relay without re-execution. Responses are never
   fanned out merely because multiple relays carried the request.

7. **Session-device secrets stay on the full node.** On the Control path,
   epoch keys, audience keys, NID secrets, repository-decryption keys, and
   ratchet secrets stay on the full node, which decrypts, commits, and
   publishes on the session device's behalf and signs only with the key
   permitted by the selected human or agent-authorship profile. This does not prohibit the
   separately authorized Comms credential-sync path for durable NID devices.

8. **Per-device permission grants (configurable oracle power).** These tiers
   describe human-profile RPC. The agentic profile exposes only its closed,
   attenuated MCP tool set and never inherits human raw-signing authority:
   - *Baseline (all grants include this):* DM read/write/sign,
     decrypt-on-behalf, and self-revocation.
   - *Regular (the default for a newly enrolled light device):*
     baseline + posting (publish, feed-index update) + configuration
     read/write via the config repository.
   - *Full:* regular + cross-signing / device activation. Never the
     default; granting it requires the same ceremony as enrollment.
   - *Media upload:* a separate grant, combinable with regular or full.
   A regular posting grant does not authorize agent publication; item 12's
   workload token, proof, role, and attribution path is independently
   mandatory.

   Control defines these grant meanings, while the authoritative grant table,
   token registry, device inventory, and revocation state are records in the
   Comms private claim ledger. A positive grant takes effect only as
   repository-final `active` state. Delivery, an accepted DR session, the
   session-device delegation alone, or a projected JWT does not authorize.
   Authenticated reductions take effect immediately and are committed for
   finality. NID-less session devices receive only filtered views and never
   ledger repository access or its decryption key.

   **Security-policy state is not configuration.** The grant table,
   token registry, device inventory, and revocation records are
   excluded from the configuration grant and mutable only through the
   enumerated privileged paths (see Requirements), so a device can
   never edit its own grant, resurrect a spent token, or clear
   revocation state.

9. **Configuration over the session.** The full node delivers the complete
   grant-filtered client configuration (and subsequent updates) to the light device
   over the DR session, extending the §3.8.7 device-to-device sync
   channel, so a light client renders the same authorized UI as any other
   device without receiving security-policy state, ledger keys, or excluded
   secrets.

10. **Session-scoped keys: logout and inactivity expiry.** A session
    device's key is a session credential, so revoking it is free.
    *Logout* issues a self-revocation, honored without ceremony
    (revocation only reduces authority), and the device discards its
    key. *Inactivity:* delegations carry a short `valid_until`
    refreshed while active; absent activity the delegation lapses
    after a configurable timeout (RECOMMENDED default: 15 minutes)
    and the grant is dropped.

11. **One-time enrollment tokens (automated provisioning).** A user
    MAY mint, via the item-4 ceremony, an enrollment token: an
    epoch-key-signed credential encoding a unique token id, an expiry,
    the conferred grant, and the minting device (its NID or publishing
    key). Presenting a valid token enrolls the presenting key with no
    further interaction. Tokens are ALWAYS both single-use and
    expiring; they MAY pin an expected enrollee key for
    pre-provisioned automation; they are revocable before redemption;
    and they can never confer the full (cross-signing) grant -
    activation authority cannot ride a bearer credential.
    **Redemption is atomic at the issuer:** only the minting device
    redeems, recording the token id as spent (bound to the enrolling
    key) before publishing the delegation, so a stolen copy cannot
    race the legitimate device through another full node.
    This Control enrollment token is neither the short-lived Comms/OIDC agent
    workload access token nor ADR-038's key-bound recovery transfer/bootstrap
    grant; the three classes are not interchangeable.

12. **Agentic pattern (two-way RPC).** An agentic light client and an
    agentic control node (a full node) are a special case of this
    pattern:
    - The handshake is identical, but enrollment uses the item-11 Control
      enrollment token so provisioning is automated; that token grants no
      publication authority. Agentic traffic uses a
      distinct negotiated protocol id/profile for clarity and separate policy
      handling over the same Comms carrier kinds.
    - Agentic payloads follow the **MCP data layer** (JSON-RPC 2.0
      framing, initialize/capability lifecycle, notifications; pinned
      in `AGENTS.md`) carried as DR inner rumors - a custom transport
      MCP permits; Streamable HTTP/SSE is not used. Invocable
      operations are MCP tools with JSON schemas: each side exposes
      only the tools within the peer's grant - the tool list is the
      enforcement surface, backed by per-call argument validation and
      object-level authorization. Nothing may be invoked before
      initialize completes.
    - After mutual initialization, publication requires the Control
      token-issuance tool to obtain a current, at-most-five-minute RFC 9068
      workload access token from the persona's built-in Comms/OIDC issuer.
      The sender-constrained token and fresh per-publication proof bind the
      exact issuer, persona-scoped pairwise `sub`, `client_id`, role id,
      session, request id, method, canonical payload digest, current
      credential-ledger persona/generation/checkpoint, and status. The agent
      invokes only `heterodyne.agent.publish`; the full node validates current
      `active` authority and limits, constructs mandatory attribution, and
      signs with its current full-node-held `agent:<role-id>` key. It never
      releases that key or falls back to a persona, epoch, NID, human-device,
      or unlabeled publication path. A credential-ledger reset invalidates
      prior-generation pending issuance and authority and requires
      current-generation reissuance.
    - The relationship is two-way: the light client may be offered
      e.g. Nostr command execution and configuration reads on the
      node; the control node may be offered execution on the light
      client - notably commands into an ongoing AI or terminal
      session. Inbound execution is default-deny: advertised at
      enrollment or absent, sandboxed/allowlisted, no ambient
      filesystem/network/secrets access unless separately granted,
      with any active inbound-control session visibly surfaced.

13. **Revocation and session termination.** Revoking the device's
    `kind:31001` - by the user, by logout, by inactivity lapse, or by an
    applicable credential transition - ends authority at once: full nodes
    drop its grant, refuse further RPC, and invalidate affected DR sessions
    locally. Before an ADR-037 transition is accepted, its persistent
    authenticated NIP-59 peer tombstone is fully constructed and bound to the
    old session and both delivery identities; it is broadcast immediately
    after acceptance. Peer acknowledgement cannot delay local invalidation,
    and a valid peer rejects later messages on the tombstoned session.

14. **Retention.** RPC traffic is ordinary §5.7 traffic:
    relay-carried only, never repo-committed, and never backfilled (§5.7.3).
    Active ratchet state, message keys, sender proofs, and temporary workload
    tokens are likewise excluded from recovery archives. Full nodes keep a
    bounded local `CONTROL-I-AUDIT-AT-REST`-compliant encrypted audit record
    of side-effecting RPC, which MAY be included in protected recovery
    material. That audit is not a replayable request/response transcript and
    does not retain raw workload tokens except under a separately bounded
    protected diagnostic policy.

## Requirements (RFC 2119)

Enrollment and delegation:

- A light device MUST generate its own publishing keypair; a full node
  MUST NOT generate or receive a light device's private key.
- A session-device `kind:31001` MUST use profile
  `heterodyne-control-session-device-v1`, MUST carry the sole base-owner
  stamp `["spec_version","core/0.5.0"]`, and MUST use the Decision-2 schema
  including the on-wire `binding_nonce` tag; a verifier MUST
  reconstruct the binding payload from the event's tags alone and
  MUST reject a delegation lacking either signature or whose
  `key_proof` fails over that reconstructed payload. The issuing full
  node MUST additionally verify the nonce matches the challenge or
  token id of the live enrollment exchange.
- The epoch-key DR invite MUST have `kind:30078`, exact
  `d = double-ratchet/invites/epoch`, a mandatory `kel_head` for the
  latest accepted KEL state, and a signature by that state's
  KERI-authoritative epoch key. On rotation the successor invite MUST
  be published before the prior invite is tombstoned. An enrollment
  request MUST reference the exact invite event id it used, and a
  full node MUST process it only if that id is its currently active
  epoch-key invite; a stale, tombstoned, superseded, wrong-`kel_head`,
  or wrong-signer invite MUST be rejected.
- For an organization persona (ADR-027), a full node MUST reject
  session-device enrollment, activation, and grant changes outright
  until a later revision specifies the delegate-threshold approval
  artifact and its verification rule; epoch-key possession alone MUST
  NOT suffice.
- A session initiated to the epoch-key endpoint MAY originate from a
  not-yet-delegated key only in the authenticated
  `control-enrollment` acceptance context. Comms MUST authenticate the
  carrier and transcript before Control policy runs; the default
  decision is `hold` without a sender-visible policy signal, and only
  the Control QR-secret, challenge-response, or enrollment-token
  decision may produce `accept` or `reject`. The undelegated
  initiator exception MUST NOT be accepted for ordinary DMs,
  credential operations, activation, revocation, unlock, or any other
  context.
- A pending enrollment request MUST expire after a configurable window
  (RECOMMENDED default: 2 minutes); a full node MUST NOT act on an
  expired request.
- A full node MUST NOT issue an interactive enrollment delegation
  without fresh user authorization (epoch-key passphrase re-entry or
  equivalent local unlock) in a ceremony displaying the requesting
  key's fingerprint; remote interactive enrollment MUST pass
  challenge-response first, and the ceremony prompt MUST NOT be
  raised before the challenge validates locally (co-located: the
  invite secret satisfies the challenge).
- A full node SHOULD rate-limit epoch-key-endpoint bootstrap attempts
  and defer durable ratchet-state allocation until the
  challenge-response (or token check) passes.
- Session-device delegations MUST be NID-less and epoch-key-signed;
  enrollment MUST NOT require any cold-root operation.

Session lifecycle:

- A session-device delegation SHOULD carry a short `valid_until`
  refreshed while the session is active; on lapse (RECOMMENDED
  default inactivity timeout: 15 minutes, configurable) the full node
  MUST treat the device as revoked and drop its grant.
- A full node MUST honor a device's self-revocation without ceremony,
  from any grant tier, and MUST revoke immediately on the light
  client's logout.
- A client acting as the light side MAY treat a relay-valid
  `kind:31001` containing its publishing key only as visibly labeled
  provisional evidence under Core's `provisional-accept` policy. It
  MUST NOT treat itself as finally enrolled until that exact
  delegation is canonical-repository-final and every applicable
  Comms authorization decision is `active`; `deny-until-repo` MUST
  grant no provisional authority.
- Enrollment state MUST bind the epoch invite id, enrollee device key,
  accepted DR transcript and session, session-device delegation
  address and event id, grant subject, enrolling full-node NID and
  device key, and negotiated protocol/version tuple. A substitution
  at any of those joins MUST fail closed.

Tokens:

- An enrollment token MUST be epoch-key-signed and MUST encode a
  unique token id, an expiry, the conferred grant, and the minting
  device; tokens MUST be both single-use and expiring. A full node
  MUST reject an expired or revoked token; only the minting device
  MAY redeem a token, and it MUST durably record the token id as
  spent - bound to the enrolling key - before publishing the
  delegation. A retry of a spent token presenting the SAME enrolling
  key MUST complete idempotently (re-publish the recorded delegation,
  covering a crash between spend and publish); a spent token
  presenting a different key MUST be rejected. Token-redeemed
  enrollments MUST be surfaced in the persona's device inventory. A
  token MUST NOT confer the full (cross-signing) grant.
- A Control enrollment token MUST NOT be accepted as a Comms/OIDC
  workload access token or as an ADR-038 recovery transfer/bootstrap
  grant. Those three token classes are distinct and non-substitutable.

Grants and RPC:

- A full node MUST enforce the per-device grant table on every RPC
  method, MUST default new enrollments to the regular grant, and MUST
  NOT include cross-signing / device activation in any default grant;
  out-of-grant methods MUST be refused with an error.
- Security-policy state (grant table, token registry, device
  inventory, revocation records) MUST be excluded from the
  configuration grant. Its ONLY mutation paths are: enrollment /
  activation / token minting via the item-4 ceremony;
  self-revocation (scoped to the caller's own record); automatic
  inactivity lapse; and local full-node administrative action under
  fresh authorization. No other RPC method may touch it regardless
  of grant; a configuration write that reaches security-policy state
  MUST be refused.
- Control grant, enrollment-token, inventory, and revocation semantics
  MUST derive authority solely from the Comms private claim ledger.
  Positive authority requires repository-final `active` state;
  delivery, delegation, a DR session, a filtered session view, or a
  projected JWT MUST NOT grant it. An authenticated reduction or
  revocation MUST take effect immediately and MUST subsequently be
  committed for repository finality.
- Cross-signing / device-activation requests arriving over RPC MUST
  themselves trigger the fresh-authorization ceremony; a full grant
  authorizes the device to *request* activation, never to bypass the
  ceremony.
- RPC requests MUST carry a request id unique within the accepted DR
  session and an expiry. Before execution, a full node MUST atomically
  and durably reserve the accepted DR session id, request id, method,
  canonical payload digest, expiry, and first server-observed normalized
  authenticated ingress relay. Ingress relay is transport context and
  MUST NOT be a caller-supplied request member. Concurrent
  byte-identical logical requests MUST join one execution; a retry with
  a changed session, method, payload, or expiry MUST conflict. The
  final response MUST be durably persisted before publication and
  MUST be sent first and only through the actual ingress relay for
  that arrival. A later identical retry MUST replay the persisted
  response only through that retry's actual ingress relay and MUST NOT
  re-execute or fan out.
- On restart, an incomplete reservation MUST be resumed or reconciled through
  the same idempotency boundary. Execution progress and side-effect commit
  evidence MUST be durable enough to prevent repeating an already committed
  effect; if commit status cannot be proven, the executor MUST fail closed
  and require explicit repair rather than dispatch the side effect again.
- A full node MUST validate RPC and tool-call arguments against their
  schemas, MUST apply object-level authorization (a grant names the
  repos, config namespaces, or sessions it covers), SHOULD confirm
  destructive or exfiltrating operations explicitly, and SHOULD
  rate-limit and surface anomalous bulk decrypt-on-behalf activity.
- The full node MUST keep a local `CONTROL-I-AUDIT-AT-REST`-compliant encrypted audit record of
  executed side-effecting requests.
- Vanilla NIP-46 service, if offered, MUST be separately opted into
  with its own grants and MUST NOT be an automatic fallback for an
  enrolled device; clients MUST surface its reduced guarantees.
- RPC request and response rumors MUST NOT be committed to any repo or
  accepted by a repo relay for storage (§5.7.3 applies).
- Before releasing received plaintext, an implementation MUST complete
  DR receive-state advancement, durable persistence, and consumed
  message-key erasure as one atomic action.

Agentic profile:

- Agentic RPC MUST use its own negotiated protocol id/profile, distinct from
  the human RPC profile, over the same Comms carrier kinds. Neither agentic peer may invoke a method before
  the bidirectional MCP initialize/capability exchange completes, and
  each side MUST refuse methods and tools it did not advertise.
- An agentic profile MUST NOT advertise or accept raw signing,
  private-key access, a human publication method, or fallback to a
  persona, epoch, NID, human-device, or unlabeled key. After mutual
  initialization, agent publication MUST use only
  `heterodyne.agent.publish` with a current at-most-five-minute
  sender-constrained Comms/OIDC workload access token and a fresh
  per-publication proof. The full node MUST construct mandatory
  attribution and sign only with the current full-node-held
  `agent:<role-id>` key; that key MUST NOT be released to the agent.
- Workload-token issuance and each publication side effect MUST bind
  exact issuer, pairwise subject, `client_id`, role id, accepted
  Control session, request id, method, canonical payload digest, and
  current credential-ledger persona, generation, checkpoint, and
  status. A credential-ledger reset MUST invalidate prior-generation
  pending issuance and authority; further publication requires
  current-generation reissuance.
- Inbound execution on the light client (incl. commands into an
  ongoing AI or terminal session) MUST be advertised in the
  enrollment request and capabilities message, MUST default to
  absent, and MUST run sandboxed/allowlisted with no ambient
  filesystem, network, or secrets access unless separately granted;
  the light client MUST visibly surface an active inbound-control
  session and SHOULD require local consent per newly exercised tool.
- Agentic tool calls MUST support cancellation and timeouts.

Transport, termination, recovery, and retention:

- A strict light client MUST use outbound Tor. A browser without Tor
  MAY use an authenticated clearnet shared relay only in visibly
  declared reduced-assurance mode. Optional direct application-layer
  access through Tor to an advertised onion repo relay MAY be used for
  retrieval or repository-finality evidence, but MUST NOT be treated
  as a Control transport.
- Revocation or an applicable credential transition MUST invalidate
  affected DR sessions locally and stop Control immediately. The
  authenticated persistent NIP-59 peer tombstone MUST bind the old
  session and both delivery identities and MUST be broadcast after
  transition acceptance; peer acknowledgement MUST NOT delay local
  invalidation, and the tombstone MUST NOT be treated as a Control
  response or replayable transcript.
- Recovery approval, transfer, admission, and authority activation
  MUST remain separate Core/Comms compositions and MUST NOT open
  Control. Recovery MUST NOT restore active DR state, message keys,
  temporary workload tokens, sender proofs, or a live Control
  session; restored peers establish fresh sessions.
- Relay-carried Control request/response traffic and active ratchet
  state MUST NOT be repository-committed or backfilled. A bounded,
  encrypted side-effect audit MAY be included in protected recovery
  material, but it MUST NOT be a replayable RPC transcript and MUST
  NOT include message keys or raw workload tokens except under a
  separately bounded protected diagnostic policy.

## Rationale

Every element composes from existing primitives: the transport is §5.7
unchanged, enrollment is an ordinary §3.3 delegation issuance with the
same bidirectional-binding shape as §3.3.1, and confirmation reuses
`kind:31001` replaceable-event semantics. Epoch-key addressing
collapses executor discovery into key possession - the set of devices
that can respond is exactly the set that can sign. Session-scoped keys
with expiry-backed timeouts make the browser the disposable component,
so the system can revoke eagerly. Tokens move the ceremony in time
rather than removing it, and issuer-bound redemption gives single-use
semantics one point of atomicity instead of a replication race.
Splitting security-policy state from configuration keeps the grant system
non-self-modifying, while the Comms private claim ledger supplies one
repository-final authorization authority across devices. Human and agentic
traffic share the single generic Comms carrier family: `kind:31015`
negotiation and `kind:31016` payload, inside DR `kind:1060` messages. They are
differentiated inside encrypted canonical content by the negotiated Control
protocol, method, direction, and capabilities, keeping remote execution in
both directions from being confusable with, or silently reachable from, the
human client path. Framing agentic payloads as MCP keeps the payloads
JSON-RPC-shaped, reuses a proven capability-negotiation lifecycle, and -
unlike a state-sync protocol - tolerates the no-backfill DR carrier. Relay
affinity and durable request reservations provide restart-safe exactly-once
side effects without letting a caller choose the response route. Atomic
ratchet persistence prevents plaintext release from outrunning the state that
makes a consumed message key unusable after a crash.

## Alternatives Considered

### NIP-46 as-is (kind:24133 over relays)
- Pros: existing implementations; no new wire.
- Cons: signing-only; no forward secrecy; static kind and static keys
  leak conversation metadata to relays; no §3.3 delegation binding.
- Why rejected: the DR carrier gives strictly stronger properties; the
  payload shape is retained for interop.

### Agent Host Protocol (AHP) for the agentic profile
- Pros: purpose-built synchronized multi-observer session state;
  active spec (<https://github.com/microsoft/agent-host-protocol>).
- Cons: a state-synchronization protocol (immutable state, reducers,
  write-ahead reconciliation) presuming reconnect/catch-up, which the
  no-backfill DR carrier (§5.7.3) cannot provide; the capabilities
  exchange would still be invented around it; a second payload family
  beside the JSON-RPC-shaped human path; narrower ecosystem than MCP.
- Why rejected: MCP's initialize handshake IS the required capability
  negotiation, degrades gracefully on a lossy transport, and its
  tools-with-schemas map onto the grant model. Revisit AHP if
  synchronized multi-device live viewing of one session becomes a
  goal - MCP would hand-model that as a subscribable resource.

### Executor-capability advertisement on DR invites
- Pros: explicit discovery. Cons: a stale-able, topology-leaking
  surface, redundant with epoch-key possession.
- Why rejected: superseded by epoch-key addressing (the first draft
  of this ADR).

### Direct device-to-device channel (WebRTC / websocket)
- Pros: lower latency. Cons: needs reachability/NAT traversal or a
  rendezvous server and can expose a Tor full node's network identity.
- Why rejected for Control: relay mediation preserves the intended topology
  and works for every light-client class. A separately authorized
  application-layer connection through Tor to an onion repo relay remains
  permitted for repository retrieval and finality.

### Ship the epoch key to the light device
- Pros: no RPC layer. Cons: key custody in the weakest environment;
  revoking a browser key would mean epoch rotation.
- Why rejected: unacceptable custody regression.

### Matrix-based remote control
- Pros: existing E2EE rooms. Cons: Matrix is OPTIONAL (ADR-029).
- Why rejected: core paths must be Matrix-free.

## Assumed Versions (SHOULD)

- nostr-double-ratchet wire as normatively referenced by §5.7 (0.x);
  NIP-46 payload shape and base method vocabulary (prior art; wire
  kind:24133 is not used on the DR path).
- NIP-44 v2; NIP-01 replaceable-event semantics for `kind:31001` /
  `kind:31005`; `kind:30078` DR invites per §5.7.1.
- Model Context Protocol (MCP), data layer only - revision 2025-11-25,
  <https://modelcontextprotocol.io/specification/2025-11-25> (pinned
  in `AGENTS.md` 2026-07-07): JSON-RPC 2.0 framing, initialize
  lifecycle, tools, notifications; MCP transports are not used - the
  DR session is the transport.

## Diagram

<!-- renderer unavailable: Mermaid source only -->

<details><summary>Mermaid source</summary>

```mermaid
sequenceDiagram
    participant L as Light device (browser / agent)
    participant R as Nostr relays
    participant F as Epoch-key holder (full node)

    L->>R: fetch kind:31005, then the epoch-key DR invite
    L->>R: DR enrollment request to the epoch-key endpoint<br/>(QR secret, challenge-response, or enrollment token)<br/>references invite event id; carries key_proof
    R->>F: deliver kind:1060
    Note over F: interactive: challenge, then ceremony<br/>(passphrase + fingerprint)<br/>token: verify sig, expiry, unspent id (issuer-only)
    F->>R: publish kind:31001 (Core stamp, pubkey d-tag, key_proof, short valid_until)
    R->>L: relay-valid kind:31001 -> provisional only
    Note over L,F: canonical repository reachability + active Comms authorization -> finally enrolled
    Note over L,F: agentic only: MCP initialize capability exchange
    L->>R: RPC request rumor on authenticated ingress relay
    R->>F: accepted DR session + observed ingress
    Note over F: reserve session/id/method/digest/expiry/ingress<br/>active ledger grant + object authz; keys never leave
    F->>R: persist response, then publish only to actual ingress
    R->>L: RPC response rumor
    Note over L,F: logout/revocation/credential transition -> local invalidation + peer tombstone
```

</details>

## Consequences

- The incomplete Control profile at
  `heterodyne:control/0.5.0#control-reserved-scope` receives enrollment,
  RPC payloads, grants, tokens, and MCP/agentic semantics.
- Core session-device extensibility and the immutable non-stamping profile
  bind at `heterodyne:core/0.5.0#core-nid-delegation`.
- Comms receives the invite and initiator carve-outs, the distinct
  `control-enrollment` context, and negotiation/carrier behavior at
  `heterodyne:comms/0.5.0#comms-direct-messages`,
  `heterodyne:comms/0.5.0#comms-acceptance-hook`, and
  `heterodyne:comms/0.5.0#comms-subprotocol-negotiation`.
- Control security work binds to `CONTROL-I-AUDIT-AT-REST` and
  `CONTROL-I-SESSION-KEY-CONFINEMENT` without a Social dependency.
- The minimum Control conformance-vector corpus must cover session-device delegation binding,
  Core stamp/profile ownership, exact epoch invite and KEL currency,
  stale/tombstoned invite rejection, authentication-before-policy and
  enrollment-only undelegated initiation, provisional versus
  repository-final/active state, complete peer/executor identity joins,
  pending expiry, changed-expiry and cross-session replay conflicts,
  actual-ingress-only responses and crash-safe persisted replay, each Comms
  claim-ledger decision class, grant enforcement including security-policy
  write refusal, enrollment-token single use/expiry/issuer binding/grant
  ceiling, token-class non-substitution, self-revocation and inactivity lapse,
  MCP initialization before invocation, integrated agent token issuance and
  per-use proof, generation reset, atomic DR receive persistence, transition
  tombstones, Tor/reduced-assurance behavior, and recovery/no-backfill
  boundaries.
- Acceptance does not make Control claimable. The registry-revision-4,
  closed-schema, feature-prerequisite, release-manifest, and minimum-vector
  gates remain closed until the complete ADR-037/ADR-038 atomic batch is
  issued.

## Council Input

Drafted from user design direction across three rounds (epoch-key
addressing; expiries; self-revocation and session-scoped keys;
enrollment tokens; agentic MCP profile, AHP retained as alternative).
Codex rounds 1-2 (2026-07-08, `codex:codex-rescue`): 5 blocking / 8
should-fix / 2 nits, then 2 blocking partials + 5 should-fix - all
integrated (delegation schema with `key_proof` and on-wire
`binding_nonce`, epoch-key invite rules with the active-invite check,
atomic and idempotently-retryable token redemption, closed
security-policy mutation paths, §10.1.2 scoping, replay-cache
scoping, S1-S6 hardening). Round 3 verdict: accept with fixes -
resolved by rejecting org session-device mutations outright pending
the deferred org governance flow, plus a line-count trim. The 2026-08-03
acceptance reconciliation incorporated ADRs 032-038, including repository
finality, relay-affine replay, Comms-ledger authority, agent authorship,
credential generations, ratchet durability/termination, and the recovery
boundary. Review complete; accepted with the Control gate retained.
