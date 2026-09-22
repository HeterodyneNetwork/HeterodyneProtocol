# V4 bounded historical reference-edit trial

Status: **measured; no arm accepted**. A three-case actual edit trial ran
against historical input `8f780cea2119738e3db1a37e7c0c94b4cd200cb3` (September
21 UTC / September 20 Pacific). The baseline was semantically correct but
failed its first-pass evidence/protocol score; its diagnostic full gate passed.
The treatment failed all three exact-reference checks and its evidence/protocol
score; its diagnostic full gate also failed at the opening draft lane.

This is a narrow refs-only feasibility trial, not all-275 throughput, complete
workload acceptance, a speedup claim, or Task 3 authorization. Production code,
protocol specifications, registries, schemas, vectors, snapshots, and behavior
remain unchanged in the feature branch. Existing `renderTests`/`prepareContext`
tooling is reused; no new platform is introduced.

## Frozen scope and provenance

The exact recipe is
`scripts/maintenance-eval/contracts/reference-edit-v4.json` with SHA-256
`0f85c40a72622aee46b75d3bd57a126fc249cb8b0b530e1d25c12980965db2de`.
The frozen common intent SHA-256 is
`445a14abeb708e0cbd00492947db3f2a217e2324539250716c4635d760339e77`.
Both hashes were fixed before either arm. Workers receive no corrected mapping,
prior report, or evaluator answer.

The selected declarations were exactly:

- `comms/oidc-claim-release`
- `comms/oidc-client-unregistered`
- `comms/oidc-grant-prohibited`

For each, the only permitted change is the `spec_refs` value in
`docs/spec/vectors/generator/src/current-vectors/case-contracts.ts`, from the
stale `heterodyne:0.6.0#comms-authorization-clients-consent-and-release` to
`heterodyne:0.6.0#comms-oidc-authorization`. Every other byte and every
unrelated occurrence of the stale reference, including
`comms/oidc-claim-release-denied`, must remain unchanged.

The three cases are supported by the pinned Comms authorization/client/consent
rules: registered-client requirements and Client Credentials prohibition at
lines 1674–1679, registration/consent state at 1681–1703, and release
intersection requirements at 1716–1723. See the [immutable Comms source](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/heterodyne-comms.md#L1671-L1723).
The pinned declarations and fixture/boundary evidence are listed in the
frozen recipe's source excerpts; those excerpts are navigation context, not
authority.

## Excluded authority gap

The proposed fourth case, `comms/oidc-consent-required`, was removed before
dispatch. Its fixture contains explicit consent but changes requested scopes to
`["profile"]`; the implementation rejects because `openid` is absent. The
pinned live specification does not require `openid` for this operation, so the
case is an authority gap rather than a safe refs-only repair. It remains a
historical out-of-scope issue; no mapping or behavior change is proposed.

The excluded behavior is documented by the pinned [fixture declaration](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/vectors/generator/src/current-vectors/comms.ts#L876-L879),
[boundary](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/vectors/generator/src/oidc.ts#L532-L535),
and [reason-code entry](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/registry/reason-codes.json#L824-L830).
The pinned [Core reference grammar](https://github.com/HeterodyneNetwork/HeterodyneProtocol/blob/8f780cea2119738e3db1a37e7c0c94b4cd200cb3/docs/spec/heterodyne-core.md#L53-L57)
requires `heterodyne:<semver>#<anchor>`; `heterodyne:comms#...` is not a
qualified protocol reference.

## Loading and execution policy

The prepared arm initially reads only generated `tests.md`; packet/index/
manifest material and the whole assigned pinned checkout remain available on
demand for a named gap. The initial `tests.md` carries true line ranges,
source digests, source byte counts, and excerpts. Freshness/unknown receipts
remain in the on-demand bundle rather than in the initial excerpt file;
incompleteness remains explicit. Excerpts are
navigation aids and never governing answers. The baseline may use normal tools
against its assigned checkout under the same pinned, no-history/no-fetch
boundary.

The frozen policy specified fresh Luna/medium workers, no repair round,
sequential execution,
the same independent semantic/protocol review, exact expected-file-byte oracle,
and unchanged `scripts/conformance-ci.sh`. End-to-acceptance timing includes
preparation, worker, review, exact-byte checks, and the candidate's full gate;
shared selection/coordinator work is reported separately.

## Measured trial result

The original shared selection and coordinator costs were not fully instrumented.
Worker/reviewer call counts are self-reported observations, distinct from
measured process time, billing, or consumed bytes. Preparation, cache state,
sequential ordering, and any coordinator gaps remain confounds. No token,
dollar, causal, or general maintenance-productivity claim is made.

The baseline preparation ran `04:51:26Z–04:51:29Z`; its worker report had 14
self-reported ledger entries. Scoring completed at `04:56:35Z` with semantic
PASS (3/3) but evidence/protocol FAIL: one positive-fixture citation was
inaccurate/incomplete, and the ledger omitted exact queries and nested-operation
accounting. Corrected scoring retained the overall FAIL. Exact expected-file
hash/scope checks passed at `04:58:20.957Z`, and the unchanged diagnostic gate
passed from `04:58:59Z–05:00:44Z` in 104.79 s: 1,172 draft tests/63 files,
family check, 275 history-bound vectors, and 176 independent tests/19 files.
This gate does not cure the first-pass evidence failure.

The treatment prepared from `05:02:29Z–05:02:33.824Z`; its rendered initial
context was 19,327 bytes / 4,832 estimated tokens, with prepared-context hash
prefix `06c9d890`. Its worker report had 15 self-reported ledger entries, not
an independently measured call count. Scoring completed at `05:07:57Z`:
semantic FAIL (0/3 exact references) and evidence/protocol FAIL. All three
edited values used `heterodyne:comms#comms-oidc-authorization`, omitting the
required `0.6.0` family version; the exact value is
`heterodyne:0.6.0#comms-oidc-authorization`. The treatment source/scope check
had **changed-path scope PASS**: the candidate remained at pinned HEAD with
only the allowed `case-contracts.ts` path changed. Its exact expected-file-byte/
hash oracle **FAILED**: actual file hash
`a48ee648822ffddecc511c52847cca6a2b9b83b40a68c49b2134fd5143df7250` did not
match expected
`aa12ea2ea8ceffa66c07d562385a4698391da42710c298d016a3fd4d2e26d19e`
(100,693 bytes). The standalone exact oracle returned failure. No repairs were
performed.

The baseline scorer's correction ended at `05:02:56Z`, overlapping the start of
treatment preparation; an earlier wrong-directory feature-gate launch was
aborted. Therefore the arms do not provide a clean sequential speed comparison.
The treatment's observed prep-to-gate-failure interval was about 511 seconds:
its unchanged gate started at `05:09:25Z` and failed at `05:11:00Z` (observed),
with exit 1 and 83.06 s real. It stopped after 1,172 draft tests/63 files,
with 1,170 passed and two failures in existing reference-format checks; later
family, snapshot, and independent lanes did not run. This is failure evidence,
not acceptance or a speed result.

The latest independent tooling check was 156 tests: 154 passed, two optional
SARA skips, zero failures, in 15,165.408292 ms. This validates tooling only.
The separate, stable-tree feature-branch gate passed from `05:18:38Z` to
`05:25:44Z` in 425.66 s: 2,016 draft tests/86 files, document-family check,
267 history-bound vectors, and 178 independent tests/19 files. An earlier
post-trial gate attempt was stopped after the coordinator edited the tracked
plan during verification; that aborted attempt is not a passing result.
The completed run had no tracked/index mutations. Only this verification
summary was finalized afterward; executable code and frozen contracts were
unchanged. These checks and reporting costs are outside the measured arms.

The experiment is complete as a failed feasibility comparison: no arm was
accepted and no speedup is demonstrated. Green feature-branch verification
does not change either failed trial verdict.

## Next bounded step

Before another representative replay, define a deterministic source/version/
reference-grammar preflight, preserve exact citation and operation ledgers, and
add cwd/HEAD guards. Reuse the existing schema/reference-format checks cheaply
before launching a full gate; do not add a redundant production validator.
The observed prepared-context gap (it omitted the Core reference-envelope
grammar) is a context finding, not a proven sole cause: current-SARA skill use,
a failed historical query, orchestration errors, and other confounds remain.
Do not start another ad hoc tiny trial, Task 3, or a new platform from this
failed experiment. A bounded, unimplemented design hypothesis is to separate
semantic anchor choice from mechanical reference rewriting: choose the anchor
against pinned source, then preserve the pinned family qualifier
deterministically during the byte rewrite, with the existing schema/format
check before the full gate. This is a proposal only, not a demonstrated fix or
causal explanation.
