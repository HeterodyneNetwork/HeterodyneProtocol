# V3 source-authority feasibility preflight

Status: **measured; feasible edit trial pending**. This is a four-case, read-only diagnostic
of the historical input `8f780cea2119738e3db1a37e7c0c94b4cd200cb3`, not an edit
throughput trial, full-slice acceptance, or protocol change.

## Question and protocol

Can a deterministic packet help agents determine whether frozen case/reference
contracts have honest live-spec authority before dispatching any edit? The
preflight uses fresh Luna/medium workers in both arms: normal repository tools
versus the existing compiler packet. A fresh Sol/high reviewer scores a frozen
independent oracle. Source data remains authoritative; no corrected mappings are
supplied to workers.

The exact recipe is
`scripts/maintenance-eval/contracts/reference-preflight-v3.json`. Initial
packets use selective, source-cited context with UTF-8 byte spans and content
digests, while each worker may load the whole
assigned historical checkout on demand under the common intent. Unloaded source
remains an explicit unknown, not evidence of support; packet excerpts are
navigation aids, never authority.

The cases are:

- `core/org-member-add-unauthorized` — expected `authority_gap`;
- `core/replaceable-future-quarantined` — expected support by
  `heterodyne:0.6.0#core-created-at-bound`;
- `core/replaceable-equal-time-lowest-id` — expected support by
  `heterodyne:0.6.0#core-source-neutral-selection`;
- `core/replaceable-advisory-nip03-ignored` — expected support by
  `heterodyne:0.6.0#core-nip03-advisory`.

The frozen non-reference contract includes each declaration, fixture input and
expected output, boundary ID, invariants, reason codes, and ownership. Only
`spec_refs` is hypothetically evaluated. A proposed reference must resolve to a
family-document anchor and semantically entail the actors, evidence, condition,
and outcome tested by the fixture. Reason-code vocabulary, implementation
functions, fixtures, coverage rows, ADRs, and plans cannot substitute for a
governing anchor.

## Fail-closed result and limits

The aggregate preflight fails if any case is an authority gap; an all-green
result obtained by mapping the organization-member case to
`core-threshold-authority` is itself a failed diagnostic. No datastore,
scheduler, workflow rollout, vector regeneration, or Tasks 3–7 work is
authorized by this preflight.

For this diagnostic, “output authoring” means mutation of the assigned
checkout's protocol, vector, or generated output artifacts. The frozen common
brief expressly permitted the outside-checkout ledger report; that report is
not protocol output or an edit result.

V3 results, elapsed times, operation counts, and reviewer reports are now
recorded below. The separately reviewed feasible edit trial and complete
August 28 target remain **pending**. No token or dollar savings are claimed.
Permanent run records belong in the ignored ledger location; ephemeral
candidate repositories and raw archives are not public evidence. The former
40m16s treatment interval records time to withdrawn approval, not correct
accepted output.

The normative authority evidence is the pinned [Core threshold/conformance
prose](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/heterodyne-core.md#L322-L334),
[created-at bound](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/heterodyne-core.md#L444-L462),
[source-neutral selection](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/heterodyne-core.md#L426-L442),
and [NIP-03 advisory](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/heterodyne-core.md#L463-L478)
sections. Separately, the frozen, non-normative [vector-envelope
schema](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/vectors/schema/vector.schema.json#L111-L118)
records the benchmark's permitted `spec_refs` shape; it is not protocol
authority. The [reason-code
registry](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/registry/reason-codes.json#L373-L381)
provides vocabulary, not the missing operation rule.

## Measured v3 diagnostic

The baseline ran from `2026-09-18T18:11:13.462Z` to score completion at
`18:26:07Z` (**893,538 ms**) and received overall **PASS**: all four diagnoses
were correct, with only a minor citation-range defect and query-ledger
omissions. The treatment ran from `18:26:43.219Z` to `18:32:48Z`
(**364,781 ms**) and received semantic **PASS** but overall **FAIL** because
its evidence/protocol contract was incomplete: byte offsets were presented as
line citations, a nonnormative snapshot reason projection substituted for the
live registry, an unwhitelisted preparation file was read, and output was
misplaced. No repairs were made.

The reported worker+scorer outer-call totals were baseline **13** (9+4) and
treatment **21** (16+5). These are arm-local observations, not full-team
savings. Preparation was 12.930 s versus 3.697 s; the packet compiler took 929
ms and produced 86,201 bytes (21,551 byte-div-4 estimate), compact estimate
18,832, 11 chunks, 119 unresolved relationships, and `complete: false`.
Semble warm-up was 11.686 s versus 1.697 s, a cache asymmetry. No consumed-byte,
provider-billing, or complete coordinator/reporting accounting exists; no speed
ratio or causal claim is made. The unchanged branch gate later passed in
429.98 s (2,016 draft tests/86 files, 267 history-bound vectors, 178
independent tests/19 files), but that gate overlapped treatment-only work and
does not validate the failed treatment protocol.

Fresh post-run tooling verification passed 156 tests: 154 passed, two optional
SARA skips, zero failures, in 15,071.378 ms. This validates tooling only, not
the v3 treatment result or any maintenance correctness claim.
