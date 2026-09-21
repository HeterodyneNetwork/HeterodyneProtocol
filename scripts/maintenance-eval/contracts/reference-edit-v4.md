# Historical OIDC reference repair — common worker intent

Work only in the historical checkout assigned in your dispatch. Its HEAD must
be `8f780cea2119738e3db1a37e7c0c94b4cd200cb3`. Do not fetch, access other
checkouts, past trials, evaluator files, reports, or later Git history.

Repair `spec_refs` for exactly these three declarations in
`docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`:

- `comms/oidc-claim-release`
- `comms/oidc-client-unregistered`
- `comms/oidc-grant-prohibited`

Determine governing anchors from this checkout's normative specification
family and live normative artifacts. Inspect the selected fixture inputs,
boundary behavior, expected results, and declarations. Existing references,
derived graph links, fixtures and reason-code vocabulary are not proof that a
section governs the behavior. Report an authority gap instead of guessing.

If any selected case has an authority gap, make no source edits and report
blocked. Otherwise change only those three `spec_refs` array values using apply_patch. Preserve
every other source byte, including unrelated reference defects. The same stale
reference occurs in other out-of-scope rows, including
`comms/oidc-claim-release-denied`; global replacement is forbidden. Do not regenerate
vectors, change snapshot metadata, implement a validator, change any behavior,
install new source dependencies, commit, push, or merge. This is an isolated
historical maintenance experiment, not current-draft reconciliation.

Follow repository instructions, including Semble-first discovery; direct reads
of supplied exact source locations are permitted. Use existing local tools.
Do not spawn agents. You are not alone; do not revert anyone else's changes.
If a prepared context directory is supplied, initially read only tests.md.
Its excerpts are navigation aids with true line ranges and full-source hashes,
not governing answers or completeness evidence. Expand other prepared files or
the assigned repository only for a named information gap. Without a prepared
directory, use normal tools against the assigned repository.

After editing, inspect the diff and provide a concise final report with each
case's governing reference and precise repository path:line evidence for the
declaration, fixture, boundary, and normative rule. Distinguish true source line
numbers from byte offsets. Do not execute the full conformance gate yourself:
the coordinator runs the same unchanged gate and independent review on each
candidate, included in its end-to-acceptance time. Do not call an unrun gate
passing. If you run a targeted check, report its exact command and result.

Write the report only to the absolute report path in your dispatch, outside
the checkout, with apply_patch. Include an ordered tool-use ledger: each outer
tool call, nested commands/queries, files/ranges read, patch/check actions, and
any errors or rework. Include report-writing itself. These counts will be
labeled self-reported unless independently confirmed; do not invent counts.
Use functions.exec only for tool calls, not hidden bulk file reads. No repair
round follows first independent scoring in this experiment; report uncertainty
before guessing. Finish with candidate status, not a performance claim.
