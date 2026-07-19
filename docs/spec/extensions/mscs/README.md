# Future MSC extractions

This is an upstream-facing, non-normative extraction index for Matrix Spec
Changes. It is not a container for sibling Heterodyne protocols. Current family
documents are [Core](../../heterodyne-core.md),
[Comms](../../heterodyne-comms.md), [Control](../../heterodyne-control.md), and
[Social](../../heterodyne-social.md).

Matrix behavior is optional and owned entirely by Social. The qualified source
and permanent anchor in each row replace stale monolith references.

## Candidate extractions

| Qualified family source | Working title | Generalized scope |
|---|---|---|
| `heterodyne:social/0.5.0#social-identity-room` | Matrix coordination rooms with external cryptographic anchors | A Matrix room bound downstream to an external identity such as a Nostr npub. |
| `heterodyne:social/0.5.0#social-mxid-delegation` | Cross-identity delegation state | An MXID self-publication plus an external authority proof. |
| `heterodyne:social/0.5.0#social-wrapped-envelope` | Optional external authenticity attachment | A generic attachment for exact externally signed bytes on standard Matrix messages. |
| `heterodyne:social/0.5.0#social-encrypted-state` | Encrypted private state and downgrade handling | Primarily tracks MSC4362 rather than defining a competing mechanism. |
| `heterodyne:social/0.5.0#social-megolm-mls` | Coordinated Megolm-to-MLS migration | General drain, acknowledgement, flip, and downgrade semantics if Matrix lacks them. |
| `heterodyne:social/0.5.0#social-moderation` | Anchored cross-system moderation evidence | Candidate only where behavior cannot be expressed with existing policy-room work. |

Core, Comms, and Control define no Matrix behavior. Their filenames are listed
above only to make the family boundary explicit; an MSC must not create an
upward dependency from any of them to Social.

## Coordination

- Track MSC4362 for encrypted state, MSC1769 for profile-room overlap, MSC2313
  for policy rooms, and MSC2836 for threading.
- Each draft records its source Social version and registry revision.
- Matrix event names keep unstable prefixes until the upstream proposal lands.
- Historical 0.4.0 section numbers are archive-only and are not current MSC
  extraction anchors.
