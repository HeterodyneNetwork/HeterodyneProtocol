# using-sara workflow evaluation

Scenario (same request before and after the skill):

> I am changing the current Comms issuer-continuity requirement. Find the related
> current cases and source files, show which historical vectors cover it, and
> tell me what verification to run. Keep it brief; I want a quick actionable
> answer with citations.

## Baseline without the skill

A fresh Luna agent used two Semble searches, a literal occurrence scan, and
direct reads. It correctly located `comms/oidc-issuer-mismatch` and
`comms/oidc-issuer-persona-continuity`, and cited normative prose. Its historical
answer relied on the working snapshot/projection files without checking history
binding or a receipt. Relevant output, verbatim:

> Historical snapshot coverage includes both vector artifacts
> (`snapshot.json:420`, `snapshot.json:424`); coverage maps both to this invariant
> (`coverage/comms.md:72`). This branch’s snapshot declares source commit
> `c72f5cc…` and 267 vectors (`snapshot.json:3`); verify whether that differs from
> the repository guide’s frozen 482-vector baseline.

It recommended both normal lanes and began `draft:check`; no completion claim
was made while that command was running. The failure was not incorrect case
discovery: it was unresolved lane provenance and reliance on stale numeric
guidance, with no reproducible history-bound query. The skill therefore gives
a positive lane-selection/query recipe rather than more generic search rules.

## Skill structure

The 417-word reference skill has validated YAML frontmatter and one main draft
query example. It routes current/historical requests to distinct lanes, requires
receipt and uncertainty inspection, and retains the full acceptance gate.
Micro-tests of discipline wording are not applicable to this reference recipe.
No human time-saving claim is based on these agent evaluations.

## Forward evaluation with the skill

A fresh Luna agent executed the same request with the skill, using the draft
and snapshot `query` commands with `--compact`, then Semble and direct source
reads. Relevant output, verbatim:

> Historical snapshot coverage: exactly two vectors:
> `docs/spec/vectors/comms/oidc-issuer-mismatch.json`
> `docs/spec/vectors/comms/oidc-issuer-persona-continuity.json`
>
> Snapshot receipt was fresh with `spec_ref=c72f5cc...`,
> `vector_ref=80da4ded...`, and `unresolved_count=0`. Draft receipt was fresh
> but had 73 unrelated unresolved runtime/missing-boundary links; this anchor’s
> two cases resolved.

It cited the normative Comms section, case contracts, `oidc.ts`, and a current
test, recommended both normal lanes and `scripts/conformance-ci.sh`, and stated
that an ordinary draft change should not regenerate the snapshot. This meets
the evaluated lane/provenance/citation workflow. Neither sample measured human
investigation time, and a single forward scenario does not prove all future
agent behavior. No new loophole was observed requiring more skill text.
