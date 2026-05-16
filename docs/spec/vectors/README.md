# Test vectors

This directory contains conformance test vectors for the Heterodyne
specification. Each vector is a JSON file demonstrating a specific
behavior the spec requires. Implementations MUST produce byte-identical
output for every `produce` vector and MUST accept (and correctly
validate) every `consume` vector.

Vectors are normative: failing a vector means a Heterodyne client is
non-conformant for the corresponding spec section.

## Format

```
vectors/
  <topic>/
    <NN>-<short-description>.json
```

Each JSON file has the following shape:

```json
{
  "vector_id": "<topic>/<NN>",
  "spec_section": "<section number, e.g. '4.2'>",
  "description": "<one-line plain-English summary>",
  "direction": "produce | consume | round-trip",
  "input": {
    "...": "what the implementation is fed"
  },
  "expected_output": {
    "...": "what the implementation must emit, OR the verdict for consume"
  },
  "notes": "<optional clarifications, deferred questions, edge cases>"
}
```

- `produce` vectors: given `input` (e.g. user content + identity
  material), the implementation MUST emit `expected_output` (the wire
  bytes). Compared after canonical JSON serialization.
- `consume` vectors: given `input` (the wire bytes), the implementation
  MUST emit `expected_output` (typically `{ "verdict": "accept" }` or
  `{ "verdict": "reject", "reason": "..." }` plus a normalized view of
  the event).
- `round-trip` vectors: an event survives a wrap → unwrap →
  re-publication cycle byte-identically.

## Planned vector topics

| Topic | Coverage | Status |
|---|---|---|
| `identity/` | root attestation; delegation; successor chain; revocation | not yet authored |
| `envelope/` | wrapped event; bare event; wrap-mode default per room kind | not yet authored |
| `verification/` | signature failures; delegation-mismatch rejection; revoked-key rejection; backdated-event handling | not yet authored |
| `outbox/` | outbox state event; multi-category fan-out; encrypted private outbox entries | not yet authored |
| `interop/` | wrapped event round-tripped through a vanilla Nostr relay; bare DM rendered by vanilla Matrix client | not yet authored |

Vectors will be added as each spec section graduates from stub to drafted
state. The CI suite will run every conformance test from this directory
against the reference `heterodyne-core` build.
