# Heterodyne 0.5.0 Security & Architecture Review
**Reviewer:** Antigravity AI
**Date:** July 30, 2026
**Scope:** `docs/spec/*`, `docs/security/*`, `docs/adr/*`, and test vectors.

## Executive Summary
The Heterodyne protocol family 0.5.0 presents a robust, decentralized architecture combining Nostr events, Radicle Git storage, and optional Matrix transport. The strict dependency DAG (`Core <- Comms <- {Control, Social}`) is well-designed. However, there are significant gaps between the normative prose specifications and the reference implementation/test vectors. Several security assumptions, particularly around the KERI cold root and the Double Ratchet key deletion lifecycle, have implementation weaknesses.

This review used `semble` semantic searches across the specification and research documentation to identify inconsistencies, metadata leakage, and missing test vectors.

---

## 1. High Priority Gaps & Inconsistencies

### 1.1 Normative Vector Drift from 0.5.0 Specifications
**Observation:** The specification mandates byte-exact canonicalization and strict schema enforcement. However, the normative test vectors (specifically `keri/*` and `fixtures.json`) do not reflect the Core 0.5.0 requirements. 
- The `inception` and `delegation` fixtures lack the mandatory `["spec_version", "core/0.5.0"]` tags required by Core §3.2.
- The rotation fixture carries `content: "[]"`, which violates Core §4.3's requirement of `{"spec_version":"core/0.5.0","receipts":[...]}`.
**Impact:** A strict conformant implementation will fail the normative test vectors, because the vectors test against legacy-inferable or invalid formats rather than pure 0.5.0 bytes.
**Suggestion:** Regenerate `fixtures.json` and all `keri-authority/*` vectors using strict 0.5.0 stamps and exact JSON-schema conformance.

### 1.2 Agent Authorship (ADR-036) Integration Incomplete
**Observation:** ADR-036 introduced OIDC workload tokens and agent authorship (`kind:31001` at `d=agent:<role-id>`). While the ADR is marked "Accepted," it is not integrated into Registry revision 2 (`manifest.json`), nor does `docs/spec/heterodyne-control.md` specify its normative constraints.
**Impact:** Implementers adopting ADR-036 produce `kind:31001` events that Core 0.5.0 and the current registry consider non-conformant. Currently, attribution is the only control for agent actions, creating a security gap for automated actors.
**Suggestion:** Explicitly mark ADR-036 as "Integration Pending," or bump the registry to revision 3 and introduce the necessary agent vectors and `heterodyne-control.md` specs.

### 1.3 `room_secret` and Broadcast Taxonomy Staleness
**Observation:** ADR-017 and ADR-023 are still marked "Accepted", carrying `room_secret` and broadcast room architectures that were silently dropped in 0.5.0 (which migrated to pure Tier-3 audience keys and retired `private_broadcast`). Yet, the generator and fixtures still encode these legacy structures.
**Impact:** Mixed signals for developers leading to implementation of deprecated Matrix/Nostr hybrid room architectures.
**Suggestion:** Add explicit supersession notes to ADR-017 and ADR-023. Strip `room_secrets` and `private_broadcast` from the test generator and `fixtures.json`.

---

## 2. Security & Threat Model Vulnerabilities

### 2.1 Double Ratchet Forward Secrecy Latency
**Observation:** In `docs/spec/heterodyne-comms.md`, consuming a message key after ratchet advancement mandates key deletion. However, it lacks a *promptness* constraint.
**Impact:** Forward secrecy and post-compromise security (PCS) rely on immediate deletion of message keys. If a client batches deletions or delays them, device capture can expose recently processed messages.
**Suggestion:** Introduce a `SHOULD` or `MUST` requirement binding the deletion of the consumed message key synchronously to the acceptance of the next message key in the Double Ratchet state machine.

### 2.2 Cold Root Continuity Without Witness Thresholds
**Observation:** The KERI cold root is an intentional single point of failure for the npub-to-RID binding. A compromised cold root yields catastrophic persona authority. Furthermore, threshold-0 (`none`) rotations allow a compromised epoch key to rotate continuity without cold-root involvement.
**Impact:** Blast radius for key compromise is maximum without mitigating threshold checkpoints.
**Suggestion:** Introduce an optional witness-threshold re-anchor to bound cold-root blast radius. Update `docs/security/threat-model.md` to explicitly advise operators against witness-free personas.

### 2.3 Metadata Leakage in `previous_index` Chaining
**Observation:** ADR-006 introduced `prev_page_hash` to solve relay-partitioning page integrity, preventing relays from silently swapping historical pages. However, the vector corpus lacks tests for `deny-until-repo` and `previous_index` chain validation.
**Impact:** Relying purely on client behavior without test vector enforcement leaves the network vulnerable to malicious relay withholding or rewriting.
**Suggestion:** Introduce explicit vectors validating `prev_page_hash` enforcement, and explicitly test the hard-reject paths (like `deny-until-repo`) rather than only testing `provisional-accept`.

---

## 3. Structural & Ecosystem Recommendations

1. **Matrix MLS Finalization:** As Nostr transitions from NIP-04 to NIP-44 and NIP-EE (MLS), the Matrix side of Heterodyne must fully formalize its MLS integration. The current threat model notes that Matrix MLS is "not finalized," creating a temporal gap in group-chat scalability and security guarantees.
2. **Control Conformance Corpus:** `heterodyne-control.md` accurately labels itself incomplete. Before 1.0, the minimum corpus for Control (MCP JSON-RPC, single-use enrollment tokens, encrypted audit semantics) must be implemented and verified.
3. **Reference Verifier Strictness:** The TypeScript generator (`verify.ts`) is frequently treated as the reference verifier, but it contains divergences from the specification (e.g., accepting empty nonces for ID-tokens and incorrectly prioritizing local trust policy before structural verification). These mismatches should be reconciled or explicitly lint-checked against the expected output verdicts.
