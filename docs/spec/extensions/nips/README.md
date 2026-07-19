# Future NIP extractions

This is an upstream-facing, non-normative extraction index. It is not a home
for sibling Heterodyne protocols. Current family documents are
[Core](../../heterodyne-core.md), [Comms](../../heterodyne-comms.md),
[Control](../../heterodyne-control.md), and [Social](../../heterodyne-social.md).

The qualified owner and permanent anchor in each row replace stale monolith
section references. A proposal must recheck the named document version before
extracting behavior.

## Candidate extractions

| Qualified family source | Working title | Generalized scope |
|---|---|---|
| `heterodyne:core/0.5.0#core-identity-model` | Persona-preserving KERI rotation for Nostr identities | Generic cold-root/epoch authority and KEL verification. Highest identity extraction priority. |
| `heterodyne:core/0.5.0#core-identity-discovery` | External repository and serving-node identity hints | Signed npub-to-RID and node bootstrap usable beyond Heterodyne. |
| `heterodyne:comms/0.5.0#comms-feed-index` | Durable multi-carrier Nostr feed index | Generic ordering and paging across ordinary and repository relays. |
| `heterodyne:comms/0.5.0#comms-direct-messages` | Double-ratchet profile over Nostr | Candidate only after the currently pinned upstream wire is locally frozen. |
| `heterodyne:social/0.5.0#social-moderation` | Anchored editorial approvals | Likely an amendment/profile around NIP-72 rather than a new NIP. |
| `heterodyne:social/0.5.0#social-lists` | Stamped Social list profile | General profile-marker approach while preserving plain NIP-51 interoperability. |

Control is a Comms-carried application profile, so this directory does not
host Control protocol drafts. A genuinely reusable Control behavior would need
its own upstream venue and accepted boundary decision.

## Coordination

- NIP numbering is assigned upstream; local drafts use descriptive slugs.
- Kind and profile allocation comes from the pinned Core registry, not a
  numeric-range assumption.
- Each extracted draft records its source document version, registry revision,
  and immutable profile discriminator where applicable.
- Track NIP-EE/Marmot, NIP-65, NIP-72, NIP-78, and NIP-85 for upstream changes
  that may replace family behavior.
- Historical 0.4.0 section numbers belong only to the frozen archive and must
  not appear as current extraction anchors.
