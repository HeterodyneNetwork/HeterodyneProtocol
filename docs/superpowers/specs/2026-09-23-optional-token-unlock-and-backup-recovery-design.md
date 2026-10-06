# Optional token unlock and backup recovery design

**Date:** 2026-09-23

**Status:** Proposed for maintainer review

**Scope:** Local key custody and portable-backup recovery direction; no current-draft protocol change

## Intent and authority boundary

Make a PRF-capable FIDO2 security key the recommended *convenience* unlock for
an average user's encrypted local cold-root and epoch-key storage, without
requiring a token. A user may instead use a memorized passphrase or another
supported recovery method. When the token path is chosen, two independently
enrolled tokens are recommended for recoverability: either token can unlock,
so this is not a two-token threshold or a claim of stronger theft resistance.

Backups should be creatable unattended, use a fresh random data-encryption key
for each artifact, and remain restorable after loss of the original computer.
A token may unlock the private recovery material needed to restore a backup;
it is not the backup cipher, the Nostr signer, or a protocol identity.

This document is design guidance, not a live protocol profile. The current
[Core keys-repository rule](../../spec/heterodyne-core.md#core-keys-repository)
requires encryption at rest and preservation of that boundary in backups, but
does not define a portable backup container or recipient slots. The older
[portable recovery design](2026-07-31-portable-recovery-and-large-object-design.md)
proposed per-archive bulk and authority keys and multiple recipient slots;
its [ADR-038](../../adr/archive/2026-07-31-038-portable-recovery-nodes-and-large-object-sync.md)
is a point-in-time design record, not current normative authority. Any future
standardized backup format needs its own complete current-draft integration.
Other backup storage and unlock strategies remain allowed; this document
describes a recommended path, not a conformance prerequisite.

## Selected approach and alternatives

Use a dedicated backup recipient keypair. The public key is available to the
backup producer; its private key is encrypted in a portable recovery envelope.
The envelope has independently authenticated unlock slots for a passphrase,
each enrolled PRF-capable token, or another supported method. A selected slot
opens the same recovery key; no token is mandatory. Keep backup decryption
authority distinct from the Assurance cold root and epoch signing keys.

Directly wrapping every backup data key under a token-derived key is simpler,
but generally requires the token during backup creation. Reusing the cold-root
signing key as the everyday backup recipient avoids a separate keypair, but
brings the deliberately offline root into ordinary restore operations. Neither
is the recommended average-user path. Direct, non-exportable BIP-340 hardware
signing remains an optional higher-assurance custody path where compatible
hardware and integration exist; a FIDO2 token used for PRF unlock does not
provide it.

## Boundaries and components

1. **Local signing vault.** Encrypt the cold-root and epoch secrets at rest in
   separate compartments with independent data keys and unlock contexts.
   An honest epoch signing session does not open the cold-root compartment.
   The cold root remains offline except for the explicit Assurance ceremonies
   named in [Assurance §3.1](../../spec/heterodyne-assurance.md#assurance-reciprocal-enrollment).
   Epoch signing may use a bounded unlock session. The token gates a software
   signer; plaintext signing material necessarily exists briefly on the host
   during software signing. An always-on unlocked cold-root signer is not the
   recommended posture. Preserve Core's existing NIP-49-or-equivalent boundary
   for the active persona nsec; if a token helps unlock that record, it opens
   the user-controlled secret behind the existing boundary rather than
   silently replacing the boundary.
2. **Unlock providers.** A passphrase path uses a memory-hard authenticated
   wrapping scheme. A FIDO2 path requires an actually PRF-enabled credential,
   not merely a device that advertises `hmac-secret`. Derive a purpose-bound
   wrapping key from the credential's PRF output; use separate context for
   signing-vault and backup-recovery envelopes. Each token receives its own
   slot. Expose the token's touch/PIN requirements rather than promising
   silent unlock. A U2F-only authenticator cannot serve as a PRF provider.
3. **Backup producer.** Generate a fresh random authenticated-encryption data
   key for each backup. Encrypt the backup with that key and wrap it to the
   dedicated backup public key. An authority-bearing format should keep
   recoverable signing authority under a separate authority data key and
   recipient policy, as in the earlier recovery design. A bulk-only recipient
   must not be able to open that key; a full-recovery recipient may open both
   keys but still cannot bypass the restore authorization ceremony. The
   producer needs the public key but neither the backup private key nor an
   unlock token.
4. **Recovery envelope.** Include a copy of the encrypted backup private key
   and its authenticated slot metadata with each self-contained backup. A user
   may additionally keep independently protected recovery material elsewhere.
   Never place a plaintext private key or PRF output in the archive. Bind the
   reusable envelope's slots to its own key ID, algorithms, and version; bind
   each backup to the exact envelope digest and recipient public key it used.
   This permits copying a prevalidated envelope into an unattended backup
   without re-enrolling a token while detecting envelope substitution.
5. **Restore.** Select one configured unlock method, open the encrypted backup
   private key, unwrap the artifact's data key, and authenticate all archive
   content before installing anything. Restore into an isolated staging area.
   Data restore does not automatically activate persona or device signing
   authority; existing Core, Control, and optional Assurance authorization
   still governs that transition.

The exact archive bytes, algorithms, KDF parameters, registry entries, and
schemas belong in a separately reviewed portable-backup profile. The local
custody recommendation must remain implementation-agnostic and optional even
if such a profile is later standardized.

## Lifecycle and failure behavior

- Enrollment verifies that a new token credential actually returns a PRF
  result and that its newly wrapped slot can open the intended envelope.
  Advertising `hmac-secret` alone is insufficient. No real token is enrolled
  or modified as part of this design review.
- Enrollment tests a recovery route end-to-end while its unlock input is
  present. Unattended backup creation copies the prevalidated encrypted
  recovery envelope without opening it, checks its identity and integrity,
  and self-tests the archive encryption it can verify locally. It must not
  claim an untested new route is recoverable. The UI recommends two separately
  stored PRF-capable tokens or another recoverable combination, but does not
  require a token or a particular number of methods.
- A wrong password, missing token, unsupported PRF, corrupted ciphertext,
  mismatched metadata, or failed authentication yields no plaintext release,
  no restored state, and no signer grant. Loss of *all* configured unlock
  methods makes the protected material unrecoverable; setup must say so.
- Adding a token creates a new wrapped slot; removing one updates current
  envelopes and future backups. Removing a slot cannot revoke access to a
  historical backup that still contains it. Suspected compromise calls for
  rotating the backup recipient key and re-encrypting retained archives if
  historical access must be revoked.
- A fresh data key limits the impact of disclosure of that one artifact's
  data key. Compromise of a long-lived backup private key can open every
  backup addressed to its public key. Multiple either/or token slots improve
  availability, not resistance to compromise of any one usable path.
- Token-derived wrapping material and plaintext software-signing keys appear
  transiently in host memory. Short-lived sessions, minimal privileged code,
  memory hygiene, and offline cold-root ceremonies reduce exposure but do not
  turn the design into hardware-isolated Nostr key custody. Separate contexts
  prevent accidental key reuse, not a compromised host from asking an inserted
  token for another authorized output. Keeping cold-root ciphertext and its
  signer off the routine online machine is the stronger recommended posture.

## Verification and implementation boundary

The implementation plan should separate (a) optional local-custody guidance
and capability checks from (b) any new portable-backup wire profile. It should
not activate ADR-038 by implication, restructure the generator, or regenerate
the rolling vector snapshot during ordinary draft authoring.

Use synthetic, deterministic local fixtures to test password-only restore,
either-token restore, lost-host restore from an included encrypted recovery
envelope, distinct per-artifact data keys, recipient-key rotation, and negative
cases for wrong unlock input, substituted slots, corrupted metadata, truncated
archives, and attempted premature authority activation. A device capability
scan is read-only; a real-token end-to-end trial requires a disposable
credential and separate authorization because enrollment changes token state.
Normal repository verification remains the current-draft and history-bound
snapshot checks plus the shared conformance gate.

## References

- [Yubico: CTAP2 `hmac-secret` deep dive](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html)
- [Yubico: multi-device unlock with envelope encryption](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html)
- [Yubico: enabling `hmac-secret` for a credential](https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html)
