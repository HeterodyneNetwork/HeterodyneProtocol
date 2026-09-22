# Reference-guard go/no-go evaluation

Status: **goal not met; packet/reference optimization is abandoned as the
primary sub-hour acceleration route.** The experimental helper is not retained
or shipped: its three synthetic tests passed, but it missed the requested
broader negative coverage and the historical dry run failed in `parseCatalog`
(`catalog object is not static`) before any edits. This is a compatibility
bug, not proof that the approach is fundamentally impossible. No helper
timing or speedup claim is made.

The complete August 28 baseline is 7h50m28s across ten task intervals. Reaching
less than 60 minutes would require approximately an 87.2% reduction in that
measured interval total. The archive also records 1,882 observed outer calls,
approximately 600 read/search-bearing shell candidates, and 332 nested patch
operations; these are different counting levels and must not be summed or
converted into a helper ceiling. The public baseline and timing limitations are
recorded in the [evaluation contract](sixty-minute-maintenance.md#baseline-and-pending-readiness).

Round 10 is useful as a reference-boundary shape—reference resolution,
declaration repair, and rejection before mutation—but it is not a complete
workload proxy. The former 40m16s treatment used fewer reported worker/reviewer
counters, but its semantic approval was withdrawn and it did not reproduce the
complete workload ([pilot v2](sixty-minute-maintenance-pilot-v2.md#second-matched-trial-result-former-approval-now-withdrawn)).
The later three-case refs-only trial accepted neither arm and explicitly made
no speedup claim ([V4 evaluation](sixty-minute-maintenance-edit-v4.md#measured-trial-result)).
Those three substitutions are not representative evidence for all ten rounds.
The bounded experiment used historical input
`8f780cea2119738e3db1a37e7c0c94b4cd200cb3`; its experimental helper state is
preserved at experiment commit `b905e96810663967a5317798bbbf8c6234ae88bd` for
audit history only, not as a shippable implementation.

Decision:

- Stop Tasks 3–7 expansion based on these trials. Do not add the proposed
  datastore, scheduler, or agent replay infrastructure, and do not authorize a
  new packet/reference replay on this evidence.
- Do not retain or ship the experimental helper. The bounded experiment ended
  at the failed historical compatibility check; no further helper repair cycle
  is authorized in light of the prior end-to-end evidence and limited scope.
  This stop is an investment decision, not an impossibility finding.
- A distinct future idea—complete acceptance criteria up front with batch review
  to avoid rounds 2–6—is unvalidated and is not started or authorized by this
  decision.

No quantitative ceiling for the helper is available. A future primary
acceleration claim requires a fresh equal-correctness complete-workload
measurement with the full verification clock, not extrapolation from the
round-10-shaped or three-case trials.

## Final verification

After removing the experimental helper, the tooling suite completed with
154 passed, two optional SARA skips, and no failures (156 total). The full
`scripts/conformance-ci.sh` gate exited successfully: 2,016 current-draft tests,
document-family validation, 267 history-bound snapshot vectors, and 178
independent conformance tests. These are repository verification results, not
maintenance-throughput measurements. Only documentation corrections and this
verification record were added after that stable-tree gate; retained executable
code and protocol artifacts are unchanged from the preceding PR state.

The locked installs reported dependency-audit warnings: seven vulnerabilities
in the generator package (one low, two moderate, four high) and one high in the
independent conformance package. No dependency remediation was attempted here.
