# Key Claims and OIDC Projection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Comms-owned typed key claims, an authoritative private multi-writer persona claim ledger, and an interoperable OIDC/OAuth JWT projection with Radicle-backed issuer continuity and draft-21 token status.

**Architecture:** Implement this only after the ADR-033 split has cut over. Core remains the source of persona/KEL, delegation, NID, and repository primitives; Comms owns claim semantics, ledger convergence, JWT projection, issuer continuity, and status; Control consumes the resulting authorization interface. Canonical authorization state is committed to the encrypted private claim repository, while HTTPS OIDC endpoints and the public Radicle tree expose only standards metadata, public keys, continuity, and token status.

**Tech Stack:** Markdown; JSON and JSON Schema; TypeScript 5.9; Node.js `crypto`/`zlib`; AJV 8; Vitest 4; Nostr events; Radicle/Git data model; RFC 8785 JCS; SHA-256; OpenID Connect Core; OAuth RFCs 7517, 7519, 7636, 7638, 8414, 8628, 8705, 9068, and 9449; `draft-ietf-oauth-status-list-21`.

## Global Constraints

- Complete `docs/superpowers/plans/2026-07-18-four-document-protocol-split.md` first; this plan assumes `core/0.5.0`, `comms/0.5.0`, `control/0.5.0`, and registry revision 1 exist.
- Begin before any `core/v0.5.0`, `comms/v0.5.0`, `control/v0.5.0`, or `social/v0.5.0` tag is created. If any tag already exists, stop and record an ADR amendment plus a later document version instead of mutating a tagged release.
- The approved design is `docs/superpowers/specs/2026-07-18-key-claims-oidc-design.md`; any material departure requires an ADR amendment before implementation.
- Claims, the ledger, OIDC projection, issuer continuity, and status lists belong to Comms. Core receives only generic typed-key/proof hooks needed to validate Comms inputs; Control only consumes Comms decisions.
- `kind:31013` is the atomic claim and `kind:31014` is irreversible revocation/status.
- The private Radicle claim repository is authoritative for persona-issued device authorization and revocation. A delivered grant is provisional until repository-confirmed; a valid reduction takes effect immediately.
- Private claim contents, consent, issuance mappings, decryption material, and reader membership never enter public discovery or the public persona repository.
- There is one exact HTTPS issuer per persona and one simultaneous Radicle continuity root under `.well-known/<cold-root-npub>/` on canonical `main`.
- Multiple repository writers may mint only when they possess the separately encrypted signing key, active `oidc-token-issuer` authority, and a checkpoint no older than the manifest bound, which cannot exceed 300 seconds.
- RS256 is required. Access tokens use `typ: at+jwt`. Client Credentials, implicit, and password grants are prohibited in this profile.
- The dedicated stable-key scope is `heterodyne:key-ref`; the projected key claim is `https://heterodyne.network/jwt/key-ref`; the private-ledger checkpoint claim is `https://heterodyne.network/jwt/ledger-checkpoint`; and the public status-mirror claim is `https://heterodyne.network/jwt/status-mirror`.
- Comms 0.5 pins the complete semantics used from `draft-ietf-oauth-status-list-21`; do not silently track newer draft revisions.
- Existing vector IDs and registry history are immutable; new semantics receive new vector IDs and registry revision 2.
- The specification stays implementation-agnostic: vectors model bytes, state transitions, and decisions, not a prescribed HTTP server or language runtime.
- Run every command from the repository root unless a step explicitly says otherwise.
- `research/sources/` is read-only. Do not stage user/tool-state directories.

---

## File Structure

### Decision, normative text, and standards map

- `docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md` — accepted design decision and allocation record.
- `docs/spec/heterodyne-comms.md` — normative claims, ledger, OIDC, JWT, continuity, and status profile.
- `docs/spec/heterodyne-core.md` — bounded typed-key and proof-verification extension points only.
- `docs/spec/heterodyne-control.md` — consumes active claims for enrollment/RPC/agent authorization and filtered session-device views.
- `AGENTS.md` — canonical OIDC/OAuth/JWT/status references.
- `docs/security/threat-model.md` — new Comms invariants and attack analysis.

### Registry and schemas

- `docs/spec/registry/kinds.json` — kinds 31013 and 31014 plus immutable profile metadata.
- `docs/spec/registry/reason-codes.json` — claim/ledger/OIDC/status rejection and revocation codes.
- `docs/spec/registry/security-invariants.json` — new `COMMS-I-*` allocations.
- `docs/spec/registry/manifest.json` — revision 2 and recomputed JCS digest.
- `docs/spec/registry/history/2.json` — immutable canonical snapshot of registry revision 2.
- `docs/spec/schemas/comms/key-claim-v1.schema.json` — semantic claim content.
- `docs/spec/schemas/comms/key-claim-revocation-v1.schema.json` — irreversible revocation content.
- `docs/spec/schemas/comms/claim-ledger-record-v1.schema.json` — append-only encrypted ledger plaintext.
- `docs/spec/schemas/comms/oidc-issuance-record-v1.schema.json` — private `jti`/status/source-claim mapping.
- `docs/spec/schemas/comms/oidc-continuity-manifest-v1.schema.json` — public continuity and digest manifest.
- `docs/spec/schemas/comms/oidc-issuer-metadata-v1.schema.json` — public `issuer.json` extension metadata.

### Generator modules and vectors

- `docs/spec/vectors/generator/src/jcs.ts` and `jcs.test.ts` — shared RFC 8785 canonicalization.
- `docs/spec/vectors/generator/src/claims.ts` and `claims.test.ts` — IDs, typed refs, chain verification, and state.
- `docs/spec/vectors/generator/src/claim-ledger.ts` and `claim-ledger.test.ts` — authoritative merge, checkpoint, reader, and encryption decisions.
- `docs/spec/vectors/generator/src/oidc.ts` and `oidc.test.ts` — discovery/JWT projection and continuity.
- `docs/spec/vectors/generator/src/token-status.ts` and `token-status.test.ts` — pinned draft-21 encoding, allocation, and verification.
- `docs/spec/vectors/generator/src/topics-claims.ts` — claim vectors.
- `docs/spec/vectors/generator/src/topics-claim-ledger.ts` — repository vectors.
- `docs/spec/vectors/generator/src/topics-oidc.ts` — discovery/JWT/status vectors.
- `docs/spec/vectors/claims/` — committed claim vectors.
- `docs/spec/vectors/claim-ledger/` — committed repository vectors.
- `docs/spec/vectors/oidc/` — committed discovery/JWT vectors.
- `docs/spec/vectors/token-status/` — committed status/continuity vectors.

---

### Task 1: Record ADR-034 and allocate registry revision 2

**Files:**
- Create: `docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md`
- Modify: `docs/spec/registry/kinds.json`
- Modify: `docs/spec/registry/reason-codes.json`
- Modify: `docs/spec/registry/security-invariants.json`
- Modify: `docs/spec/registry/manifest.json`
- Create: `docs/spec/registry/history/2.json`
- Modify: `docs/spec/vectors/generator/src/registry.test.ts`

**Interfaces:**
- Consumes: ADR-033 ownership/DAG and registry revision 1.
- Produces: authoritative allocations for every later task and registry revision 2.

- [ ] **Step 1: Write failing allocation tests**

Assert that kind 31013 and 31014 are Comms-owned, start in `comms/0.5.0`,
have distinct immutable profile discriminators for Nostr BIP-340, Radicle
Ed25519, and JWK/JWS proofs, and that revision 2 contains the
required reason-code and invariant namespaces. Load `history/1.json`, prove
all its entries are byte-identical subsequences of revision 2, and prove
`history/2.json` equals the current canonical entry set and digest.

```ts
const kind = (value: number) => {
  const entry = registry.kinds.find((candidate) => candidate.kind === value);
  if (!entry) throw new Error(`missing kind ${value}`);
  return entry;
};
const reasonCodes = () => registry.reason_codes.map((entry) => entry.code);
const invariantIds = () => registry.security_invariants.map((entry) => entry.id);

expect(registry.manifest.revision).toBe(2);
expect(kind(31013).base_schema_owner).toBe("comms");
expect(kind(31014).base_schema_owner).toBe("comms");
expect(kind(31013).first_version).toBe("comms/0.5.0");
expect(reasonCodes()).toContain("claim-id-mismatch");
expect(reasonCodes()).toContain("claim-repository-unconfirmed");
expect(reasonCodes()).toContain("oidc-checkpoint-stale");
expect(invariantIds()).toContain("COMMS-I-CLAIM-AUTHENTICITY");
expect(invariantIds()).toContain("COMMS-I-STATUS-INTEGRITY");
```

- [ ] **Step 2: Run the focused test and confirm the red state**

Run `npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts` from the repository root.

Expected: FAIL because revision 2 and the new allocations do not exist.

- [ ] **Step 3: Write ADR-034**

Record status `Accepted`; context; Comms/Core/Control ownership; kinds
31013/31014; atomic claims; typed subjects; BIP-340/Ed25519/JWK-JWS native proof
profiles; proof of possession; eight-edge strict attenuation; layered
irreversible revocation; private-ledger authority; immediate
reduction/repository-final rule; NID-bearing reader requirement; multi-writer
merge; one issuer URL plus Radicle continuity tree; shared signing key
confinement; required OAuth grants; RS256/RFC 9068 profile; exact draft-21 pin;
writer-namespaced status allocation; privacy consequences; rejected
alternatives; migration; security; and vector obligations.

- [ ] **Step 4: Add registry entries and recompute the manifest**

Add these exact reason codes: `claim-schema-invalid`, `claim-id-mismatch`,
`claim-key-reference-invalid`, `claim-event-signature-invalid`,
`claim-issuer-authority-invalid`, `claim-issuer-untrusted`,
`claim-chain-cycle`, `claim-chain-depth-exceeded`,
`claim-delegation-not-authorized`, `claim-attenuation-violation`,
`claim-subject-proof-required`, `claim-subject-proof-invalid`,
`claim-repository-unconfirmed`, `claim-repository-conflict`,
`claim-expired`, `claim-revoked`, `claim-revoker-unauthorized`,
`claim-ledger-reader-unauthorized`, `claim-ledger-rollback`,
`oidc-issuer-authority-invalid`, `oidc-signing-key-unavailable`,
`oidc-checkpoint-stale`, `oidc-client-unregistered`,
`oidc-grant-prohibited`, `oidc-consent-required`, `oidc-claim-release-denied`,
`oidc-issuer-mismatch`, `oidc-token-type-invalid`, `oidc-audience-invalid`,
`oidc-status-stale`, `oidc-status-digest-mismatch`,
`oidc-status-index-invalid`, and `oidc-status-invalid`.

Allocate `COMMS-I-CLAIM-AUTHENTICITY`, `COMMS-I-CLAIM-ATTENUATION`,
`COMMS-I-CLAIM-REPOSITORY-AUTHORITY`, `COMMS-I-CLAIM-REVOCATION`,
`COMMS-I-LEDGER-CONFINEMENT`, `COMMS-I-ISSUER-KEY-CONFINEMENT`,
`COMMS-I-MINT-FRESHNESS`, `COMMS-I-ISSUER-CONTINUITY`,
`COMMS-I-CLAIM-RELEASE`, `COMMS-I-JWT-TYPE-AUDIENCE`, and
`COMMS-I-STATUS-INTEGRITY`. Recompute `entry_set_sha256` with
`computeRegistryDigest()`; never hand-edit the digest. Commit the exact
canonical entry set and digest as `history/2.json`; never rewrite
`history/1.json`.

- [ ] **Step 5: Verify and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/registry.test.ts
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
```

Expected: all commands exit 0 and the committed digest equals recomputation.

```bash
git add docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md docs/spec/registry docs/spec/vectors/generator/src/registry.test.ts
git commit -m "adr: adopt key claims and OIDC projection"
```

---

### Task 2: Implement canonical claim and revocation objects

**Files:**
- Create: `docs/spec/schemas/comms/key-claim-v1.schema.json`
- Create: `docs/spec/schemas/comms/key-claim-revocation-v1.schema.json`
- Create: `docs/spec/vectors/generator/src/jcs.ts`
- Create: `docs/spec/vectors/generator/src/jcs.test.ts`
- Create: `docs/spec/vectors/generator/src/claims.ts`
- Create: `docs/spec/vectors/generator/src/claims.test.ts`
- Modify: `docs/spec/vectors/generator/src/keri-materialized.ts`
- Modify: `docs/spec/vectors/generator/src/keri-materialized.test.ts`
- Modify: `docs/spec/vectors/generator/src/schema.ts`

**Interfaces:**
- Consumes: Core key/KEL verification results and registry revision 2.
- Produces: `KeyRef`, `ClaimSemanticBody`, `ClaimRevocation`, `computeClaimId()`, `validateClaimId()`, `validateClaimEnvelope()`, and shared `jcsCanonicalize()`.

- [ ] **Step 1: Write failing JCS and claim-ID tests**

Cover UTF-16 property ordering, escaping, finite JSON numbers, arrays, `-0` normalization, unsupported values, member omission, and lowercase digest validation. Keep the existing materialized-KEL vectors byte-identical after moving JCS.

```ts
const semantic = {
  issuer: { type: "nostr-secp256k1", value: fixtures.personaEpochPubkey },
  subject: { type: "radicle-ed25519-nid", value: fixtures.deviceNid },
  claim_class: "authorization",
  namespace: "heterodyne.device",
  name: "claim-ledger-reader",
  value: true,
  issued_at: 1784390400,
  not_before: 1784390400,
  expires_at: 1784476800,
  audience: [fixtures.personaColdRootNpub],
  visibility: "repository-private",
  comms_version: "comms/0.5.0",
  registry_revision: 2,
};
expect(computeClaimId(semantic)).toMatch(/^[0-9a-f]{64}$/);
expect(() => validateClaimId({ ...semantic, claim_id: "A".repeat(64) })).toThrow("lowercase");
```

- [ ] **Step 2: Verify focused failures**

Run `npm --prefix docs/spec/vectors/generator test -- src/jcs.test.ts src/claims.test.ts src/keri-materialized.test.ts`.

Expected: new tests FAIL because modules are absent; the pre-existing KERI test remains green.

- [ ] **Step 3: Extract complete RFC 8785 JCS support**

Move `jcsCanonicalize()` out of `keri-materialized.ts`. Support only valid JSON values, reject non-finite numbers and `undefined`, and use ECMAScript JSON number serialization and UTF-16 code-unit key ordering required by RFC 8785. Import it back into KERI so all historical expected OIDs remain unchanged.

- [ ] **Step 4: Define the exact claim types and schemas**

Use discriminated key references:

```ts
export type KeyRef =
  | { type: "nostr-secp256k1"; value: string }
  | { type: "radicle-ed25519-nid"; value: string }
  | { type: "jwk-thumbprint"; value: string };

export type ClaimClass = "descriptive" | "authorization";
export type ClaimVisibility = "public" | "pairwise-private" | "repository-private" | "local-only";
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export type DelegationConstraints = {
  namespaces: string[];
  audiences: string[];
  resources: string[];
  remaining_depth: number;
};

export type ClaimSemanticBody = {
  claim_id: string;
  issuer: KeyRef;
  subject: KeyRef;
  claim_class: ClaimClass;
  namespace: string;
  name: string;
  value: JsonValue;
  issued_at: number;
  not_before: number;
  expires_at?: number;
  audience?: string[];
  resources?: string[];
  visibility: ClaimVisibility;
  parent_claim_id?: string;
  constraints?: DelegationConstraints;
  revokers?: KeyRef[];
  comms_version: "comms/0.5.0";
  registry_revision: 2;
};

export type ClaimRevocation = {
  claim_id: string;
  revoked_at: number;
  reason_code: string;
  revoker: KeyRef;
  proof?: KeyProof;
};
export type VerifiedRevocation = ClaimRevocation & { signer: KeyRef; event_id: string };

export type KeyProof =
  | { type: "nostr-bip340"; signature: string }
  | { type: "radicle-ed25519"; public_key: string; signature: string }
  | { type: "jwk-jws"; jwk: Record<string, JsonValue>; protected: string; signature: string };

export type SubjectProofChallenge = {
  domain: "heterodyne-claim-pop-v1";
  claim_id: string;
  nonce: string;
  audience: string;
  resource: string;
  operation: string;
  issued_at: number;
  expires_at: number;
};

export type ClaimEnvelopeContext = {
  issuer_authorized: boolean;
  registry_revision: 2;
  existing_semantic_body?: ClaimSemanticBody;
};
```

The semantic body permits exactly one namespace/name/atomic JSON value, time bounds, optional audience, visibility, optional parent and delegation constraints, qualified Comms version, and registry revision. Forbid additional properties. Authorization values must have a bounded `expires_at` and delegation depth no greater than 8.

- [ ] **Step 5: Implement claim IDs and Nostr envelope validation**

`computeClaimId(body: Omit<ClaimSemanticBody, "claim_id">): string`
canonicalizes the entire semantic content with only `claim_id` omitted and
hashes UTF-8 bytes with SHA-256.
`validateClaimId(body: ClaimSemanticBody): void` first enforces lowercase
64-hex syntax and then compares `body.claim_id` to `computeClaimId()`.
`validateClaimEnvelope(event: NostrSignedEvent, context: ClaimEnvelopeContext): ClaimSemanticBody`
validates `kind:31013`, the single `d=claim_id` address tag, exact content
schema, canonical NIP-01 event ID/signature, typed-key syntax, the supplied
Core issuer-authority result, and identical-body behavior at the same address.
Import `NostrSignedEvent` from the existing `src/nostr.ts` module.
The corresponding revocation validator accepts only `kind:31014`, one target
claim ID, `revoked_at`, a registry reason code, a typed revoker, and the signer
identity used by Task 3's authority check. A matching Nostr revoker uses the
outer event signature. A Radicle NID or JWK-thumbprint revoker embeds the
registered native proof over RFC 8785 bytes of `{domain:
"heterodyne-claim-revocation-v1", claim_id, revoked_at, reason_code}`; the
Ed25519 public key must derive the named NID, and the embedded JWK must produce
the named RFC 7638 thumbprint.

- [ ] **Step 6: Run tests and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/jcs.test.ts src/claims.test.ts src/keri-materialized.test.ts src/schema.test.ts
npm --prefix docs/spec/vectors/generator run check
```

Expected: all tests pass; historical KERI vectors are byte-identical.

```bash
git add docs/spec/schemas/comms docs/spec/vectors/generator/src/jcs.ts docs/spec/vectors/generator/src/jcs.test.ts docs/spec/vectors/generator/src/claims.ts docs/spec/vectors/generator/src/claims.test.ts docs/spec/vectors/generator/src/keri-materialized.ts docs/spec/vectors/generator/src/keri-materialized.test.ts docs/spec/vectors/generator/src/schema.ts
git commit -m "spec: define canonical key claims and revocations"
```

---

### Task 3: Implement trust, attenuation, revocation, and authorization state

**Files:**
- Modify: `docs/spec/vectors/generator/src/claims.ts`
- Modify: `docs/spec/vectors/generator/src/claims.test.ts`
- Create: `docs/spec/vectors/generator/src/topics-claims.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Modify: `docs/spec/vectors/generator/src/fixtures.ts`
- Create: `docs/spec/vectors/claims/001-canonical-nostr-subject.json`
- Create: `docs/spec/vectors/claims/002-canonical-radicle-nid-subject.json`
- Create: `docs/spec/vectors/claims/003-canonical-jwk-thumbprint-subject.json`
- Create: `docs/spec/vectors/claims/004-claim-id-mismatch.json`
- Create: `docs/spec/vectors/claims/005-persona-issuance-active.json`
- Create: `docs/spec/vectors/claims/006-delegated-issuance-active.json`
- Create: `docs/spec/vectors/claims/007-third-party-issuer-untrusted.json`
- Create: `docs/spec/vectors/claims/008-chain-attenuation-valid.json`
- Create: `docs/spec/vectors/claims/009-chain-widening-rejected.json`
- Create: `docs/spec/vectors/claims/010-chain-depth-exceeded.json`
- Create: `docs/spec/vectors/claims/011-subject-proof-valid.json`
- Create: `docs/spec/vectors/claims/012-copied-proof-rejected.json`
- Create: `docs/spec/vectors/claims/013-provisional-authorization-denied.json`
- Create: `docs/spec/vectors/claims/014-repository-confirmed-active.json`
- Create: `docs/spec/vectors/claims/015-authorization-self-revocation.json`
- Create: `docs/spec/vectors/claims/016-descriptive-subject-rejection.json`
- Create: `docs/spec/vectors/claims/017-public-claim-publication.json`
- Create: `docs/spec/vectors/claims/018-pairwise-private-dr-delivery.json`
- Create: `docs/spec/vectors/claims/019-repository-private-encryption.json`
- Create: `docs/spec/vectors/claims/020-local-only-no-publication.json`

**Interfaces:**
- Consumes: validated claim envelopes plus Core issuer/subject proof results.
- Produces: `ClaimState`, `ClaimVerificationContext`, `verifyClaimChain()`, `resolveClaimState()`, and `authorizeWithClaim()`.

Use these public decision shapes throughout Tasks 3-8:

```ts
export type ClaimState = "invalid" | "untrusted" | "provisional" | "active" | "expired" | "revoked" | "conflicted";
export type ClaimVerificationContext = {
  now: number;
  audience: string;
  resource: string;
  trusted_issuers: KeyRef[];
  repository_confirmed: Set<string>;
  repository_conflicted: Set<string>;
  revocations: VerifiedRevocation[];
  subject_proof: { key: KeyRef; challenge: SubjectProofChallenge; proof: KeyProof } | null;
};
export type AuthorizationDecision = { allowed: boolean; state: ClaimState; reason_code: string | null };
export declare function verifyClaimChain(leaf: ClaimSemanticBody, claimsById: Map<string, ClaimSemanticBody>): ClaimSemanticBody[];
export declare function resolveClaimState(leaf: ClaimSemanticBody, chain: ClaimSemanticBody[], context: ClaimVerificationContext): ClaimState;
export declare function authorizeWithClaim(leaf: ClaimSemanticBody, chain: ClaimSemanticBody[], context: ClaimVerificationContext): AuthorizationDecision;
```

- [ ] **Step 1: Write failing state-machine and chain tests**

Cover `invalid`, `untrusted`, `provisional`, `active`, `expired`, `revoked`, and `conflicted`; persona and delegated issuers; third-party descriptive claims; exact scope preservation/narrowing; time shortening; audience/resource narrowing; depth decrement; the eight-edge limit; every authorized revoker; descriptive subject rejection versus authorization self-revocation; copied subject proof; and authentication-before-policy ordering.

- [ ] **Step 2: Run the focused red tests**

Run `npm --prefix docs/spec/vectors/generator test -- src/claims.test.ts`.

Expected: FAIL on absent chain/state functions.

- [ ] **Step 3: Implement deterministic chain validation**

Resolve by `parent_claim_id`; reject cycles, missing ancestors, depth over 8, absent issuance capability, namespace/name/value-scope widening, audience/resource widening, validity extension, increased remaining depth, or stale Core/KEL authority. Cryptographic validity must remain separate from local issuer trust.

- [ ] **Step 4: Implement revocation and processing order**

Authorization claim revocation accepts claim issuer, active ancestor issuer, authoritative persona epoch/cold-root authority, or subject self-revocation. Descriptive revocation accepts issuer, named revoker, or superior issuer; a subject rejection is a separate claim. Apply irreversible revocation and reduction before repository finality, then use the exact eight-stage processing pipeline from the design.

- [ ] **Step 5: Implement proof-bound authorization**

Require `active` repository state, current time/audience/namespace/resource
match, verifier trust, and fresh proof by the exact subject key over UTF-8 RFC
8785 bytes of `SubjectProofChallenge`. Require the fixed domain, matching
claim/audience/resource/operation, a unique verifier nonce, and a challenge
window no longer than 60 seconds. Verify BIP-340 for Nostr, Ed25519 with an NID
derivation match for Radicle, or JWS with an RFC 7638 thumbprint match for JWK
subjects. The JWK proof profile permits only RS256, ES256, or EdDSA and rejects
`none`, symmetric JWKs, embedded remote-key URLs, or an algorithm/key-type
mismatch. A proof for one claim, audience, nonce, resource, operation, or time
window must not authorize another.

- [ ] **Step 6: Author and verify normative claim vectors**

Generate vectors for canonical IDs, all key types,
persona/delegated/third-party issuance, trust separation, chain attenuation
failures, depth/cycle failures, revocation authority,
repository-provisional state, proof binding, and copied-proof rejection. Add
one vector per visibility profile: public relay publication; pairwise DR
delivery with no outer claim metadata; repository-private encrypted storage;
and local-only state with no transport artifact. All use owner `comms`,
version `0.5.0`, registry revision 2, and qualified Comms refs.

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/claims.test.ts
npm --prefix docs/spec/vectors/generator run author
git add docs/spec/vectors/claims
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run check
git diff --exit-code -- docs/spec/vectors/claims
```

Expected: all commands exit 0 and regeneration is deterministic.

- [ ] **Step 7: Commit**

```bash
git add docs/spec/vectors/claims docs/spec/vectors/generator/src/claims.ts docs/spec/vectors/generator/src/claims.test.ts docs/spec/vectors/generator/src/topics-claims.ts docs/spec/vectors/generator/src/topics.ts docs/spec/vectors/generator/src/fixtures.ts
git commit -m "test: specify claim trust and attenuation"
```

---

### Task 4: Implement the private claim-ledger state machine

**Files:**
- Create: `docs/spec/schemas/comms/claim-ledger-record-v1.schema.json`
- Create: `docs/spec/vectors/generator/src/claim-ledger.ts`
- Create: `docs/spec/vectors/generator/src/claim-ledger.test.ts`
- Create: `docs/spec/vectors/generator/src/topics-claim-ledger.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Create: `docs/spec/vectors/claim-ledger/001-reader-nid-authorized.json`
- Create: `docs/spec/vectors/claim-ledger/002-nidless-reader-denied.json`
- Create: `docs/spec/vectors/claim-ledger/003-delivered-grant-provisional.json`
- Create: `docs/spec/vectors/claim-ledger/004-immediate-revocation.json`
- Create: `docs/spec/vectors/claim-ledger/005-multiwriter-revocation-wins.json`
- Create: `docs/spec/vectors/claim-ledger/006-authority-reduction-wins.json`
- Create: `docs/spec/vectors/claim-ledger/007-nonmonotonic-conflict-blocks.json`
- Create: `docs/spec/vectors/claim-ledger/008-checkpoint-rollback-rejected.json`
- Create: `docs/spec/vectors/claim-ledger/009-keyed-path-metadata-private.json`
- Create: `docs/spec/vectors/claim-ledger/010-reader-removal-key-rotation.json`
- Create: `docs/spec/vectors/claim-ledger/011-multiwriter-status-allocation.json`
- Create: `docs/spec/vectors/claim-ledger/012-stale-minter-denied.json`
- Create: `docs/spec/vectors/claim-ledger/013-source-claim-revokes-token.json`

**Interfaces:**
- Consumes: Core encrypted-repository/canonical-branch primitives and validated claims/revocations.
- Produces: `LedgerRecord`, `LedgerCheckpoint`, `mergeClaimLedger()`, `deriveLedgerPath()`, `evaluateReaderAccess()`, and `resolveAuthoritativeClaimState()`.

```ts
export type LedgerRecordType = "claim" | "revocation" | "authority-reduction" | "reader-change" | "audience-key-epoch" | "issuer-authority" | "issuance-reservation" | "status-invalidation";
export type LedgerRecord = {
  record_id: string;
  record_type: LedgerRecordType;
  persona: string;
  writer_nid: string;
  created_at: number;
  parents: string[];
  payload: JsonValue;
  payload_digest: string;
  signature: string;
};
export type LedgerCheckpoint = { repository_rid: string; branch: "main"; commit_oid: string; observed_at: number };
export type LedgerMergeResult = { records: LedgerRecord[]; conflicted_claim_ids: string[]; checkpoint: LedgerCheckpoint };
export declare function mergeClaimLedger(left: LedgerRecord[], right: LedgerRecord[], checkpoint: LedgerCheckpoint): LedgerMergeResult;
export declare function deriveLedgerPath(audienceKey: Uint8Array, recordId: string): string;
export declare function evaluateReaderAccess(readerNid: string | null, claims: ClaimSemanticBody[], state: LedgerMergeResult): AuthorizationDecision;
export declare function resolveAuthoritativeClaimState(claimId: string, state: LedgerMergeResult): ClaimState;
```

- [ ] **Step 1: Write failing repository-authority tests**

Cover one persona ledger, durable-NID reader authorization, NID-less denial, DR grant provisionality, reachable canonical confirmation, authenticated immediate reduction, append-only merge, revocation-wins, authority-reduction-wins, unresolved non-monotonic conflicts, rollback/stale checkpoint rejection, reader removal, and audience-key rotation.

- [ ] **Step 2: Write failing metadata-minimization tests**

Assert that derived Git paths and visible commit metadata reveal no claim type, subject key, namespace, revocation count, consent, or issuer-key membership. Use a dedicated ledger audience key and keyed path derivation, not raw `claim_id` paths.

- [ ] **Step 3: Run the focused red tests**

Run `npm --prefix docs/spec/vectors/generator test -- src/claim-ledger.test.ts`.

Expected: FAIL because the ledger module is absent.

- [ ] **Step 4: Define records and canonical merge**

Define append-only records for claim issuance, revocation, authorization reduction, reader change, audience-key epoch, OIDC issuer authority, issuance reservation, and status invalidation. Sort/merge by immutable record ID after signature, schema, parent, canonical-branch, and persona checks. Never resolve a widening conflict by last-writer-wins; mark it `conflicted` and fail authorization/minting.

- [ ] **Step 5: Implement reader lifecycle and onboarding bundle**

Require active `claim-ledger-reader` authorization bound to a durable NID before Radicle replication/decryption. Model the DR self-DM bundle containing authorization, repository location, canonical checkpoint, current audience key, compact state, and Radicle access. On removal: commit revocation, deny immediately, rotate the audience key, encrypt only to remaining readers, remove Radicle access, and retire old encrypted state under Comms scrub rules.

- [ ] **Step 6: Author ledger vectors and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/claim-ledger.test.ts
npm --prefix docs/spec/vectors/generator run author
git add docs/spec/vectors/claim-ledger
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run check
git diff --exit-code -- docs/spec/vectors/claim-ledger
```

Expected: all commands exit 0; vectors prove deterministic convergence and absence of sensitive cleartext metadata.

```bash
git add docs/spec/schemas/comms/claim-ledger-record-v1.schema.json docs/spec/vectors/claim-ledger docs/spec/vectors/generator/src/claim-ledger.ts docs/spec/vectors/generator/src/claim-ledger.test.ts docs/spec/vectors/generator/src/topics-claim-ledger.ts docs/spec/vectors/generator/src/topics.ts
git commit -m "spec: define authoritative private claim ledger"
```

---

### Task 5: Implement multi-writer issuer authority and collision-free reservations

**Files:**
- Create: `docs/spec/schemas/comms/oidc-issuance-record-v1.schema.json`
- Modify: `docs/spec/vectors/generator/src/claim-ledger.ts`
- Modify: `docs/spec/vectors/generator/src/claim-ledger.test.ts`
- Modify: `docs/spec/vectors/generator/src/topics-claim-ledger.ts`
- Modify: `docs/spec/vectors/claim-ledger/011-multiwriter-status-allocation.json`
- Modify: `docs/spec/vectors/claim-ledger/012-stale-minter-denied.json`
- Modify: `docs/spec/vectors/claim-ledger/013-source-claim-revokes-token.json`

**Interfaces:**
- Consumes: canonical ledger state and active `oidc-token-issuer` claims.
- Produces: `MintingEligibility`, `IssuanceRecord`, `StatusReservation`, `canMint()`, and `reserveStatusIndex()`.

```ts
export type MintingEligibility = { allowed: boolean; reason_code: string | null; checkpoint: LedgerCheckpoint };
export type StatusReservation = { uri: string; idx: number; expiry_bucket: string; writer_nid_fingerprint: string; list_sequence: number };
export type IssuanceRecord = {
  jti: string;
  reservation: StatusReservation;
  checkpoint: LedgerCheckpoint;
  signing_key_id: string;
  source_claim_ids: string[];
  issued_at: number;
  expires_at: number;
};
export declare function canMint(now: number, checkpoint: LedgerCheckpoint, manifestMaxAgeSeconds: number, issuerClaimState: ClaimState, hasSigningKey: boolean): MintingEligibility;
export declare function reserveStatusIndex(writerNid: string, expiresAt: number, listSequence: number, existing: IssuanceRecord[]): StatusReservation;
```

- [ ] **Step 1: Write failing shared-issuer tests**

Test two authorized writers holding the same signing key, an ordinary reader without key access, stale checkpoint at 301 seconds, the exact 300-second boundary, issuer-authority removal, source-claim revocation, signing-key compromise, and concurrent status reservations from different NIDs.

- [ ] **Step 2: Verify failures**

Run `npm --prefix docs/spec/vectors/generator test -- src/claim-ledger.test.ts`.

Expected: FAIL on absent mint eligibility and reservation logic.

- [ ] **Step 3: Implement signing-key confinement and freshness**

Model the signing JWK as a separately encrypted ledger object using the Comms
audience-key encryption profile and per-recipient key wrapping already defined
for private repositories. Use a dedicated issuer-key audience key whose wraps
name only devices with an active `oidc-token-issuer` claim; the claim-ledger
audience key must not decrypt it. `canMint()` requires possession, active
claim, conflict-free canonical state, manifest freshness bound at most 300
seconds, and a synchronization attempt immediately before evaluation.
Authority removal stops new minting immediately, removes the recipient wrap,
and rotates the issuer-key audience key before another token is minted.

- [ ] **Step 4: Implement durable pre-return reservations**

Use the path tuple:

```text
status-lists/<expiry-bucket>/<writer-nid-fingerprint>/<list-sequence>.jwt
```

Derive `expiry-bucket` as the unsigned decimal value
`Math.floor(expires_at / 86400)`. Derive `writer-nid-fingerprint` as the first
32 lowercase hex characters of SHA-256 over the UTF-8 canonical Radicle NID.
Encode `list-sequence` as an unsigned decimal without leading zeroes. Within a
writer/list namespace, allocate monotonic indexes and durably commit `jti`,
URI, index, repository checkpoint, signing-key ID, and every source `claim_id`
before returning a JWT. Reject duplicate tuple/index reservations. Revoking
any source claim produces invalidation records for all mapped JWTs.

- [ ] **Step 5: Regenerate ledger vectors and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/claim-ledger.test.ts
npm --prefix docs/spec/vectors/generator run author
git add docs/spec/vectors/claim-ledger/011-multiwriter-status-allocation.json docs/spec/vectors/claim-ledger/012-stale-minter-denied.json docs/spec/vectors/claim-ledger/013-source-claim-revokes-token.json
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run check
git diff --exit-code -- docs/spec/vectors/claim-ledger
```

Expected: all commands exit 0; independent writer namespaces never collide and converged invalidations are identical.

```bash
git add docs/spec/schemas/comms/oidc-issuance-record-v1.schema.json docs/spec/vectors/claim-ledger docs/spec/vectors/generator/src/claim-ledger.ts docs/spec/vectors/generator/src/claim-ledger.test.ts docs/spec/vectors/generator/src/topics-claim-ledger.ts
git commit -m "spec: constrain multi-writer token minting"
```

---

### Task 6: Implement OIDC discovery, client flows, and JWT projection

**Files:**
- Create: `docs/spec/schemas/comms/oidc-issuer-metadata-v1.schema.json`
- Create: `docs/spec/vectors/generator/src/oidc.ts`
- Create: `docs/spec/vectors/generator/src/oidc.test.ts`
- Create: `docs/spec/vectors/generator/src/topics-oidc.ts`
- Modify: `docs/spec/vectors/generator/src/topics.ts`
- Create: `docs/spec/vectors/oidc/001-discovery-exact-issuer.json`
- Create: `docs/spec/vectors/oidc/002-issuer-mismatch-rejected.json`
- Create: `docs/spec/vectors/oidc/003-authorization-code-pkce.json`
- Create: `docs/spec/vectors/oidc/004-device-authorization.json`
- Create: `docs/spec/vectors/oidc/005-prohibited-grants.json`
- Create: `docs/spec/vectors/oidc/006-pairwise-subject.json`
- Create: `docs/spec/vectors/oidc/007-stable-key-consent-gated.json`
- Create: `docs/spec/vectors/oidc/008-id-token-valid.json`
- Create: `docs/spec/vectors/oidc/009-rfc9068-access-token-valid.json`
- Create: `docs/spec/vectors/oidc/010-token-type-confusion-rejected.json`
- Create: `docs/spec/vectors/oidc/011-dpop-confirmation-bound.json`
- Create: `docs/spec/vectors/oidc/012-registered-jwt-assertion.json`
- Create: `docs/spec/vectors/oidc/013-mtls-confirmation-bound.json`

**Interfaces:**
- Consumes: active ledger claims, consent/release decision, mint eligibility, and signing key.
- Produces: `issuerUrl()`, `discoveryPaths()`, `validateAuthorizationRequest()`, `projectIdToken()`, `projectAccessToken()`, and `validateProjectedJwt()`.

```ts
export type DiscoveryPaths = { issuer: string; oidc_discovery: string; rfc8414_alias: string };
export type JwtProjectionInput = {
  client_id: string;
  audience: string[];
  pairwise_sub: string;
  scopes: string[];
  now: number;
  expires_at: number;
  nonce?: string;
  cnf?: Record<string, JsonValue>;
  issuance: IssuanceRecord;
  released_claims: Record<string, JsonValue>;
};
export type ProjectedJwt = { protected_header: Record<string, JsonValue>; claims: Record<string, JsonValue>; compact: string };
export declare function issuerUrl(origin: string, coldRootNpub: string): string;
export declare function discoveryPaths(origin: string, coldRootNpub: string): DiscoveryPaths;
export declare function validateAuthorizationRequest(input: Record<string, JsonValue>): AuthorizationDecision;
export declare function projectIdToken(input: JwtProjectionInput, privateJwk: JsonValue): ProjectedJwt;
export declare function projectAccessToken(input: JwtProjectionInput, privateJwk: JsonValue): ProjectedJwt;
export declare function validateProjectedJwt(jwt: string, expectedIssuer: string, expectedAudience: string, jwks: JsonValue): AuthorizationDecision;
```

- [ ] **Step 1: Write failing issuer/discovery tests**

Assert one lowercase cold-root NIP-19 npub path and exact equality among
metadata `issuer`, ID/access token `iss`, and validation expectation:

```ts
const root = fixtures.personaColdRootNpub;
expect(discoveryPaths("https://node.example", root)).toEqual({
  issuer: `https://node.example/oidc/${root}`,
  oidc_discovery: `https://node.example/oidc/${root}/.well-known/openid-configuration`,
  rfc8414_alias: `https://node.example/.well-known/oauth-authorization-server/oidc/${root}`,
});
```

Reject mutable epoch keys, uppercase/bech32-invalid roots, path normalization changes, issuer aliases in `iss`, and discovery/JWKS issuer mismatch.

- [ ] **Step 2: Write failing OAuth flow and release tests**

Require Authorization Code with S256 PKCE and RFC 8628 Device Authorization.
Reject implicit, password, and Client Credentials grants. Require explicit
client registration. Verify release is the intersection of requested
scopes/audience, client policy, user consent, active repository state, trusted
namespaces, and subject-proof requirements. Assert pairwise `sub` by default;
release `https://heterodyne.network/jwt/key-ref` only when
`heterodyne:key-ref` was requested, registered for the client, and explicitly
consented.

- [ ] **Step 3: Write failing JWT profile tests**

Cover OIDC ID Tokens, RFC 9068 access JWTs, and separately registered assertions; required RS256 support; optional ES256/EdDSA advertisement; access `typ: at+jwt`; required `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, and `scope`; nonce for ID Tokens; `cnf` binding when DPoP or mTLS is negotiated; and ID/access-token confusion rejection.

- [ ] **Step 4: Run focused tests and observe failure**

Run `npm --prefix docs/spec/vectors/generator test -- src/oidc.test.ts`.

Expected: FAIL because the OIDC module is absent.

- [ ] **Step 5: Implement pure protocol projections**

Implement deterministic builders and validators over JSON/JWS inputs and
ledger decisions; do not implement an HTTP framework. Preserve claim
provenance privately, project only consented fields, put the exact checkpoint
object in `https://heterodyne.network/jwt/ledger-checkpoint`, and use exact
audience/token-type rules. Standard validators must need only HTTPS discovery
and JWKS.

- [ ] **Step 6: Author OIDC vectors and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/oidc.test.ts
npm --prefix docs/spec/vectors/generator run author
git add docs/spec/vectors/oidc
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run check
git diff --exit-code -- docs/spec/vectors/oidc
```

Expected: all commands exit 0 and the vectors cover discovery, PKCE, Device Authorization, consent, pairwise subject, standard JWT validation, sender constraints, and token confusion.

```bash
git add docs/spec/schemas/comms/oidc-issuer-metadata-v1.schema.json docs/spec/vectors/oidc docs/spec/vectors/generator/src/oidc.ts docs/spec/vectors/generator/src/oidc.test.ts docs/spec/vectors/generator/src/topics-oidc.ts docs/spec/vectors/generator/src/topics.ts
git commit -m "spec: add interoperable OIDC JWT projection"
```

---

### Task 7: Implement pinned token-status semantics and Radicle continuity

**Files:**
- Create: `docs/spec/schemas/comms/oidc-continuity-manifest-v1.schema.json`
- Create: `docs/spec/vectors/generator/src/token-status.ts`
- Create: `docs/spec/vectors/generator/src/token-status.test.ts`
- Modify: `docs/spec/vectors/generator/src/oidc.ts`
- Modify: `docs/spec/vectors/generator/src/oidc.test.ts`
- Modify: `docs/spec/vectors/generator/src/topics-oidc.ts`
- Modify: `docs/spec/vectors/oidc/008-id-token-valid.json`
- Modify: `docs/spec/vectors/oidc/009-rfc9068-access-token-valid.json`
- Create: `docs/spec/vectors/token-status/001-valid-status-list.json`
- Create: `docs/spec/vectors/token-status/002-invalidated-token.json`
- Create: `docs/spec/vectors/token-status/003-stale-status-list-rejected.json`
- Create: `docs/spec/vectors/token-status/004-writer-index-collision-rejected.json`
- Create: `docs/spec/vectors/token-status/005-https-radicle-byte-identity.json`
- Create: `docs/spec/vectors/token-status/006-radicle-digest-mismatch.json`
- Create: `docs/spec/vectors/token-status/007-https-outage-radicle-fallback.json`
- Create: `docs/spec/vectors/token-status/008-issuer-successor.json`
- Create: `docs/spec/vectors/token-status/009-signing-key-compromise.json`

**Interfaces:**
- Consumes: committed status reservations, invalidations, public signing keys, and persona repository state.
- Produces: `StatusListToken`, `ContinuityManifest`, `encodeStatusList()`, `validateTokenStatus()`, `buildContinuityTree()`, and `resolveIssuerContinuity()`.

```ts
export type TokenStatus = 0 | 1; // draft-21 VALID=0x00, INVALID=0x01
export type StatusListToken = {
  protected_header: { alg: string; kid: string; typ: "statuslist+jwt" };
  claims: { sub: string; iat: number; exp: number; ttl: number; status_list: { bits: 1; lst: string } };
  compact: string;
};
export type ContinuityManifest = {
  cold_root_npub: string;
  cold_root_hex: string;
  persona_kel_head: string;
  issuer: string;
  sequence: number;
  predecessor_digest: string | null;
  max_checkpoint_age_seconds: number;
  current_jwks_sha256: string;
  retiring_jwks_sha256: string[];
  status_lists: Array<{ path: string; sha256: string }>;
  successor: { issuer: string; manifest_sha256: string } | null;
  authority_proof: KeyProof;
};
export declare function encodeStatusList(statuses: TokenStatus[]): { bits: 1; lst: string };
export declare function validateTokenStatus(referencedJwt: ProjectedJwt, statusListJwt: StatusListToken, now: number): AuthorizationDecision;
export declare function buildContinuityTree(manifest: ContinuityManifest, discovery: JsonValue, jwksBytes: Uint8Array, statusTokens: Map<string, Uint8Array>): Map<string, Uint8Array>;
export declare function resolveIssuerContinuity(previous: ContinuityManifest | null, candidate: ContinuityManifest): AuthorizationDecision;
```

- [ ] **Step 1: Write failing draft-21 encoding tests**

Freeze all draft-21 fields and algorithms in vectors: one bit per token;
`VALID=0x00`; `INVALID=0x01`; indexes packed from least-significant to
most-significant bit within each byte; RFC 1951 DEFLATE in the RFC 1950 ZLIB
format at level 9; unpadded base64url in `status_list.lst`; protected-header
`typ: statuslist+jwt`; response media type `application/statuslist+jwt`;
referenced-token `status.status_list.uri`/`idx`; Status List Token `sub` equal
to that URI; and `iat`, `exp`, and positive `ttl`. A valid bit never overrides
an expired, signature-invalid, wrong-audience, or wrong-type JWT;
stale/unverifiable status fails closed for authorization.

- [ ] **Step 2: Write failing mirror and continuity tests**

Require the public canonical-main tree:

```text
.well-known/<cold-root-npub>/issuer.json
.well-known/<cold-root-npub>/openid-configuration
.well-known/<cold-root-npub>/jwks.json
.well-known/<cold-root-npub>/manifest.json
.well-known/<cold-root-npub>/status-lists/<list-id>.jwt
```

Test byte-identical HTTPS/Radicle JWKS and status tokens, manifest SHA-256 digests, raw lowercase cold-root hex, sequence/predecessor, current/retiring key digests, current issuer, successor declaration, mismatch rejection, HTTPS outage fallback for Heterodyne validators, and exact-issuer behavior for ordinary OIDC validators.

- [ ] **Step 3: Run the focused red tests**

Run `npm --prefix docs/spec/vectors/generator test -- src/token-status.test.ts src/oidc.test.ts`.

Expected: FAIL because token-status and continuity functions are absent.

- [ ] **Step 4: Implement status and mirror validation**

Put the draft-standard `status.status_list` reference in each projected JWT.
Put the Radicle RID/branch/path/digest object in the top-level
`https://heterodyne.network/jwt/status-mirror` claim, never inside the draft
`status` object. Keep status tokens separate from `jwks.json`; a private-use
JWKS pointer may reference the public manifest. Regeneration from converged
issuance/invalidation records must be byte-deterministic.

- [ ] **Step 5: Implement issuer succession**

Treat a canonical-main repository manifest as authoritative only for
Heterodyne continuity after validating its Core persona binding, KEL head,
writer NID authorization, predecessor digest, and native authority proof over
the JCS manifest body with `authority_proof` omitted. Routine JWKS/status
updates require an active `oidc-token-issuer` writer. A successor record also
requires current persona epoch authority or a valid Core cold-root/recovery
re-anchor; possession of the shared OIDC signing key alone cannot move the
issuer. A valid successor advances sequence, binds predecessor, changes the
one active HTTPS issuer, and stops old issuance. Keep old JWKS/status available
through the maximum old-token expiry. Standard clients must register/trust the
new exact issuer; they do not follow Radicle automatically.

- [ ] **Step 6: Author status and continuity vectors**

Cover encoding boundaries, expiry/TTL, invalidation, duplicate allocation, multiple writers, byte identity, digest mismatch, shared-key minting, stale/revoked issuer authority, signing-key rotation, public/private separation, HTTPS fallback, and issuer succession.

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/token-status.test.ts src/oidc.test.ts
npm --prefix docs/spec/vectors/generator run author
git add docs/spec/vectors/token-status docs/spec/vectors/oidc
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run check
git diff --exit-code -- docs/spec/vectors/token-status docs/spec/vectors/oidc
```

Expected: all commands exit 0 and regeneration is deterministic.

- [ ] **Step 7: Commit**

```bash
git add docs/spec/schemas/comms/oidc-continuity-manifest-v1.schema.json docs/spec/vectors/token-status docs/spec/vectors/oidc docs/spec/vectors/generator/src/token-status.ts docs/spec/vectors/generator/src/token-status.test.ts docs/spec/vectors/generator/src/oidc.ts docs/spec/vectors/generator/src/oidc.test.ts docs/spec/vectors/generator/src/topics-oidc.ts
git commit -m "spec: add token status and issuer continuity"
```

---

### Task 8: Integrate normative Comms, bounded Core, and Control consumption

**Files:**
- Modify: `docs/spec/heterodyne-comms.md`
- Modify: `docs/spec/heterodyne-core.md`
- Modify: `docs/spec/heterodyne-control.md`
- Modify: `docs/spec/heterodyne-social.md`
- Modify: `docs/spec/vectors/generator/src/docs-lint.test.ts`
- Modify: `docs/spec/vectors/coverage/manifest.json`
- Modify: `docs/spec/vectors/coverage/core.md`
- Modify: `docs/spec/vectors/coverage/comms.md`
- Modify: `docs/spec/vectors/coverage/control.md`
- Modify: `docs/spec/vectors/coverage/social.md`
- Modify: `docs/spec/vectors/coverage/family.md`

**Interfaces:**
- Consumes: executable semantics and registry revision 2 from Tasks 1-7.
- Produces: permanent normative anchors and qualified references for every new vector.

- [ ] **Step 1: Write failing ownership and normative-coverage tests**

Require Comms anchors for claim objects, trust, chain validation, repository, OIDC endpoints, JWTs, status lists, multi-writer minting, and continuity. Reject OIDC/claim authority definitions in Core and duplicate wire definitions in Control. Require every new registry entry and vector to resolve to a qualified permanent anchor.

- [ ] **Step 2: Run focused tests and confirm failure**

Run `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts src/coverage.test.ts`.

Expected: FAIL because normative sections and anchors are absent.

- [ ] **Step 3: Add bounded Core interfaces**

Document typed-key syntax/registration, Core/KEL issuer-authority result, NID proof verification, generic encrypted-repository/canonical-main primitives, and registry hooks. Do not define claims, trust, authorization state, OIDC, JWT, or status in Core.

- [ ] **Step 4: Add the complete Comms profile**

Integrate exact schemas, Nostr address/discriminator behavior, claim pipeline, states, delegation and revocation, private ledger authority/merge/onboarding/scrub, public continuity tree, endpoint paths, OAuth grants, client/consent/release rules, shared issuer keys, minting freshness, JWT profiles, sender constraints, pinned draft-21 behavior, operational flows, and downgrade/unknown-profile behavior.

State that selective release selects whole atomic signed claims. Comms 0.5.0
defines neither SD-JWT disclosure nor automatic bundling of multiple claim
names into one signed claim.

- [ ] **Step 5: Add bounded Control consumption**

Define Control enrollment/RPC/agent authorization as a consumer of `active` Comms claims. NID-less session devices receive filtered decisions/views and never ledger keys or direct repository access. Control cannot turn provisional/untrusted/conflicted claims into authority.

Update all four document headers to registry revision 2. Social receives no
claim/OIDC semantics or dependency change; its only edit is the registry pin
and any regenerated registry-reference table.

- [ ] **Step 6: Regenerate coverage and commit**

Run:

```bash
npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts src/coverage.test.ts
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run check
git diff --exit-code -- docs/spec/vectors
```

Expected: every new vector has one owner, qualified refs, registry revision 2, and resolvable anchors; all commands exit 0.

```bash
git add docs/spec/heterodyne-core.md docs/spec/heterodyne-comms.md docs/spec/heterodyne-control.md docs/spec/heterodyne-social.md docs/spec/vectors/coverage docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "spec: integrate claims and OIDC into protocol family"
```

---

### Task 9: Complete threat analysis, standards references, and release verification

**Files:**
- Modify: `docs/security/threat-model.md`
- Modify: `AGENTS.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/architecture.md`
- Modify: `docs/glossary.md`
- Modify: `docs/spec/vectors/README.md`
- Modify: `docs/spec/releases/core/0.5.0.json`
- Modify: `docs/spec/releases/comms/0.5.0.json`
- Modify: `docs/spec/releases/control/0.5.0.json`
- Modify: `docs/spec/releases/social/0.5.0.json`
- Modify: `docs/spec/releases/release-manifest.schema.json`

**Interfaces:**
- Consumes: final normative anchors, registry revision 2, coverage manifest, and ADR-034.
- Produces: auditable security/standards map and release-manifest feature declaration.

- [ ] **Step 1: Write failing companion/security lint tests**

Require canonical external references for every standard in the design, the exact draft-21 pin, all new `COMMS-I-*` invariants, public/private data-flow separation, and release features `key-claims`, `private-claim-ledger`, `oidc-jwt-projection`, and `token-status-list-draft-21`.

- [ ] **Step 2: Run focused tests and confirm failure**

Run `npm --prefix docs/spec/vectors/generator test -- src/docs-lint.test.ts src/registry.test.ts`.

Expected: FAIL until companions and release manifests are updated.

- [ ] **Step 3: Extend the threat model**

Cover forged/malleated claims, compromised or stale issuers, chain amplification, proof replay, provisional-grant use, repository rollback, metadata leakage, reader removal, multi-writer conflicts, signing-key overdistribution, stale minting nodes, confused-deputy/token confusion, issuer mix-up, consent overrelease, status index collision, stale/downgraded lists, Radicle/HTTPS equivocation, successor hijack, and privacy leakage through status correlation. Map each threat to a namespaced invariant, normative mitigation, and vectors.

- [ ] **Step 4: Update external references and navigation**

Add canonical sources to `AGENTS.md` for OpenID Connect Core/Discovery, RFCs 7517/7519/7636/7638/8414/8628/8705/9068/9449, and the exact draft-21 URL. Describe when each source must be fetched. Update the README, repo map, architecture, glossary, vector README, and changelog without claiming that OIDC is canonical authorization.

- [ ] **Step 5: Update release manifests**

Pin all four untagged 0.5.0 manifests to registry revision 2 so the family
combination is reproducible. Advertise `key-claims`, `private-claim-ledger`,
`oidc-jwt-projection`, and `token-status-list-draft-21` only from Comms. Keep
Control dependent on the exact Comms release and describe claim consumption
without asserting an independent claim wire profile. Core and Social acquire
no claim/OIDC feature. Recompute release digests using the existing release
tooling.

- [ ] **Step 6: Run complete verification**

From the repository root run:

```bash
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run author
npm --prefix docs/spec/vectors/generator run coverage
npm --prefix docs/spec/vectors/generator run check
git diff --exit-code -- docs/spec/vectors
git diff --check
```

Then audit the approved design:

```bash
rg -n 'kind:31013|kind:31014|claim-ledger-reader|oidc-token-issuer|300 seconds|RS256|at\+jwt|draft-ietf-oauth-status-list-21|status-lists/<expiry-bucket>' docs/spec/heterodyne-comms.md docs/security/threat-model.md docs/adr/2026-07-18-034-key-claims-private-ledger-oidc-projection.md
rg -n 'private claim|consent record|issuance mapping|audience key' docs/spec/heterodyne-comms.md docs/security/threat-model.md
```

Expected: all commands exit 0; the first audit finds every required rule in ADR/spec/security text; the second confirms each private item is explicitly prohibited from public discovery.

- [ ] **Step 7: Review acceptance criteria and commit**

Map each of the eight approved-design acceptance criteria to an ADR section, permanent Comms anchor, registry entry, vector group, and threat-model invariant. Any missing mapping blocks completion.

```bash
git add AGENTS.md README.md CLAUDE.md CHANGELOG.md docs/architecture.md docs/glossary.md docs/security/threat-model.md docs/spec/vectors/README.md docs/spec/releases docs/spec/vectors/generator/src/docs-lint.test.ts
git commit -m "docs: complete claims and OIDC conformance profile"
```

- [ ] **Step 8: Do not release or push without explicit authorization**

Implementation completion permits local commits only. Creating or pushing tags, pushing the branch, opening a PR, publishing issuer metadata, or rotating any real signing key requires a separate user request.
