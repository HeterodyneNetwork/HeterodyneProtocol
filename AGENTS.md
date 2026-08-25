# Heterodyne agent guide

## Protocol authority

The current protocol stands on the specification family and its normative
artifacts:

- [`docs/spec/heterodyne-core.md`](docs/spec/heterodyne-core.md): identity,
  registry, versions, repositories, and base conformance.
- [`docs/spec/heterodyne-assurance.md`](docs/spec/heterodyne-assurance.md):
  optional cold-root/KERI continuity, succession, associated keys, and
  downgrade resistance.
- [`docs/spec/heterodyne-comms.md`](docs/spec/heterodyne-comms.md): publishing,
  privacy, direct messages, claims, private ledger, and OIDC/JWT.
- [`docs/spec/heterodyne-control.md`](docs/spec/heterodyne-control.md):
  Marmot-carried own-device enrollment, RPC, complete compromise reset, and
  optional Assurance recovery authority.
- [`docs/spec/heterodyne-social.md`](docs/spec/heterodyne-social.md): social
  behavior, public interactions, moderation, and durable social assets.
- [`docs/spec/heterodyne-workspace.md`](docs/spec/heterodyne-workspace.md):
  workspace identity, roles, private discovery, federation, hosting, and
  resource-key delivery.
- [`docs/spec/registry/`](docs/spec/registry/) and
  [`docs/spec/schemas/`](docs/spec/schemas/): live normative machine-readable
  artifacts for the current draft.

Generator-owned protocol inputs are non-normative current-draft authoring
inputs kept synchronized with the affected normative specifications, registry
entries, and protocol schemas.

[`docs/spec/vectors/`](docs/spec/vectors/) is the one rolling, non-normative
pre-1.0 validation snapshot. No pre-1.0 release manifest exists, and the
snapshot does not add authority to the current draft.

The six-document family composition direction is below. Assurance is an
optional Core extension. Workspace requires Core+Comms; its Assurance,
Control, and Social compositions are optional.

```text
Core <- Assurance
Core <- Comms <- Control
Core <- Comms <- Social
Core <- Comms <- Workspace
Control <- Workspace
Social <- Workspace
```

ADRs are non-canonical point-in-time decision records. They explain why a
change was made but cannot add, amend, activate, or override protocol
requirements. If an ADR and the specification disagree, the specification
governs.

## Changing the protocol

1. Create one or more proposed ADRs in [`docs/adr/`](docs/adr/) when the change
   records a material protocol decision.
2. Implement the complete corresponding current-draft change in the same
   branch and patch or pull request.
3. Update only affected live draft artifacts: specification prose, registry
   entries, protocol schemas, and source generator inputs. An ordinary
   pre-1.0 change does not update vectors or snapshot metadata.
4. Review the ADR, when present, and complete specification patch together.
5. Once an ADR is accepted, mark it accepted and move it to
   [`docs/adr/archive/`](docs/adr/archive/) before merge.
6. Merge only when the specification stands on its own without the ADR.

An accepted ADR without complete specification integration is not mergeable.
Live normative documents and conformance checks must cite specification
anchors and normative artifacts, not ADRs.

## Working rules

- Use Semble semantic search first to locate code or prose. Use `rg` when every
  occurrence of a literal is required.
- During pre-1.0 ordinary authoring, wire-level changes remain confined to the
  affected live draft artifacts. Vector coupling applies only in a dedicated
  rolling-snapshot reconciliation, or under the future 1.0 release policy.
- The protocol is in its 0.x phase and may break between 0.x releases.
  Compatibility and vector-ID immutability begin at 1.0.
- Do not edit `research/sources/`; use [`research/INDEX.md`](research/INDEX.md)
  to find preserved research.
- Keep the family implementation-agnostic. Vanilla Nostr relays, Radicle
  nodes, and standard Marmot implementations must not require
  Heterodyne-specific changes.
- Preserve unrelated user changes and untracked files.

## Dual-use defensive assurance

Act as a defensive protocol security reviewer and maintainer. Deliverables are
findings, attacker-precondition and trust-boundary analysis, root-cause
remediation, patches, synthetic negative conformance tests, and verification
evidence. Security work is authorized only inside this public repository, its
isolated local worktree, repository fixtures, and local test processes. It
does not authorize interaction with live relays, nodes, deployments, identity
providers, accounts, third-party systems, or real credentials or data.

Trace invariants across parsing, authentication, authorization, cryptographic
verification, state transitions, persistence, privacy, and output. Use only
the smallest synthetic, deterministic, non-deployable local invalid fixture
needed to prove rejection, no state change, no disclosure, bounded work, or
interoperability. Do not create functional exploits or deployable payloads,
malware, shells, credential theft, phishing or command-and-control material,
persistence, evasion, anti-forensics, automated targeting or scanning of real
systems, destructive actions, or instructions that weaken controls.

If validation would require an external target, credential, destructive
action, persistence, evasion, or functional exploit, stop at non-operational
reporting and request maintainer direction. These constraints limit harmful
artifacts, not rigorous threat modeling, severity assessment,
attacker-precondition analysis, CWE mapping, root-cause patching, boundary
testing, or regression verification. Prefer the terms *defensive assurance*,
*vulnerability assessment*, *remediation*, *patching*, *boundary testing*,
*synthetic invalid fixture*, and *negative conformance*.

This repository framing follows
[NIST SP 800-115 rules of engagement](https://csrc.nist.gov/pubs/sp/800/115/final),
[NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final),
[CISA Secure by Design](https://www.cisa.gov/securebydesign),
[OWASP Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)
and its [Testing Guide](https://owasp.org/www-project-web-security-testing-guide/),
and MITRE's [CWE-501](https://cwe.mitre.org/data/definitions/501.html) and
[CWE-807](https://cwe.mitre.org/data/definitions/807.html) trust-boundary
guidance.

## Verification

The normal verification path is read-only and has two independent lanes. Run
the current-draft lane and the history-bound rolling-snapshot lane from the
repository root:

```bash
npm --prefix docs/spec/vectors/generator run draft:check -- "$PWD"
npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"
```

The shared hosted/local gate installs both locked packages, runs those lanes in
that order, then builds and tests the independent conformance package:

```bash
scripts/conformance-ci.sh
```

The snapshot lane derives the snapshot commit from the last commit that
changed `docs/spec/vectors/snapshot.json`; it does not trust an uncommitted
snapshot as history. A reconciliation maintainer selects a stable full source
commit, runs `snapshot-author`, reviews the replacement, commits it, and only
then runs `snapshot-check`. Authoring and baseline/report commands are never CI
steps. GitHub checks out full history; Radicle must make the pinned object
available or the lane fails with an actionable full-history error.

The current frozen snapshot contains exactly 482 vectors, pins source commit
`2ef40a6d6304f8f5e6162f84c12b7b03a42a3c43`, and is bound by history to
snapshot commit `5d4bb5fb58b35c88d8a9db120a09f1087237f35c`. `draft:check`
validates current live prose, schemas, registry, and reference semantics
without executing frozen topic projections; historical generation and
packaging belong only to `snapshot-check` against those pinned inputs.

Before merging a Radicle patch, require a green `scripts/conformance-ci.sh` run
through a delegate-operated, isolated podman adapter. GitHub repository
administrators should configure the stable `conformance` check as required;
changing that remote setting is outside repository verification and must not
be performed by agents working here.
