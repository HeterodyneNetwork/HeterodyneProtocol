# Local key custody choices

This guide is non-normative. A PRF-capable FIDO2 token is optional and
recommended as a replacement for a memorized vault-unlock passphrase. It is
not a BIP-340 signer or a mandatory Heterodyne protocol component. Token
unlock is a convenience boundary around encrypted software-held keys, not
hardware-isolated Nostr signing.

| Path | What the hardware does | What must be tested |
| --- | --- | --- |
| Passphrase | No token required; a memory-hard key derivation opens an authenticated encrypted slot | Unwrap and restore rehearsal |
| PRF-token unlock | Gates an encrypted software signer or backup-recovery key | Credential PRF output and envelope-open round trip |
| Direct hardware signing | Keeps a signing key non-exportable in a compatible signer | Exact BIP-340 digest signature, identity binding, and recovery plan |

The first two paths can expose plaintext signing material briefly in host RAM.
Direct hardware signing is a separate, potentially more expensive assurance
path; a favorable FIDO PRF result does not establish that capability.

## Local vault boundary

Keep encrypted cold-root and epoch-key material in distinct compartments, with
independent data keys and purpose-bound unlock contexts. An ordinary epoch
signing session must not open the cold-root compartment. Keep the cold root
offline except for explicit [Assurance ceremonies](../spec/heterodyne-assurance.md#assurance-reciprocal-enrollment).
Software signing necessarily brings a plaintext key into host memory for the
bounded operation. A token does not protect that key from a compromised host
after unlock. Keep sessions short and avoid an always-on cold-root signer.
The active persona nsec retains [Core's NIP-49-or-equivalent keys-repository
protection](../spec/heterodyne-core.md#core-keys-repository); a token may open
that protected record but must not silently replace its at-rest boundary.

## Screening hardware without changing it

From the repository root, `node scripts/hardware-key-check.mjs --help` shows
the local commands. `node scripts/hardware-key-check.mjs scan` reads only
`fido2-token -L` and `fido2-token -I <device>` metadata. It neither enrolls a
credential nor asks the authenticator to sign. A U2F-only `nocbor` interface
is incompatible with PRF unlock. A CTAP2 `hmac-secret` advertisement is only
a `candidate`; missing or failed metadata is `undetermined`. The FIDO scan
reports direct BIP-340 signing separately as `incompatible` for that
interface, not as a verdict on other hardware interfaces.

For a documented capability claim, put a local JSON profile in a file and run
`node scripts/hardware-key-check.mjs assess profile.json` (add
`--existing-identity` when preserving an existing Nostr public key is
required). For example:

```json
{
  "name": "Example device or integration",
  "capabilities": {
    "fido2_prf_credential": true,
    "slot_open_round_trip": null,
    "recovery_plan": true,
    "secp256k1_bip340": false
  },
  "evidence": {"note": "Replace with locally reviewed evidence"}
}
```

Each capability must be `true`, `false`, or `null`; an omitted field is also
unknown. An explicit `false` blocks its role, unknown required fields yield
`undetermined`, and all-true required fields yield only `candidate`, never a
certification. The profile's evidence is user-supplied and is not verified by
the checker. `scan` results never fill a profile's credential-trial fields.
A real PRF credential and slot-open round trip require a separately authorized
trial with a disposable credential, because enrollment changes token state.
Repository tests and CI use synthetic data and do not try real tokens.
Token PIN and touch requirements may prevent silent unlock.

## Recovery and backup direction

Two independently enrolled tokens are either/or recovery options, not a
two-token threshold. A passphrase or another supported recovery method can
replace or complement tokens. Rehearse each configured route while its unlock
input is available. Losing all configured methods makes the protected material
unrecoverable; token redundancy improves availability, not theft resistance
against any one usable method.

The recommended backup direction uses a dedicated public/private recovery
keypair, distinct from cold-root and epoch signing keys. An unattended backup
producer needs only the recovery public key. For each artifact it generates a
fresh random authenticated-encryption data key, encrypts the content, and
wraps that key to the recovery public key. Keep any signing-authority payload
under a separate authority data key and recipient policy, so a bulk-data
recipient does not silently gain signing authority.

Each self-contained archive includes an encrypted copy of the recovery
private key and independently authenticated unlock slots for its configured
passphrase, token credentials, or other methods. Never include a plaintext
private key or PRF output. Bind slots to the recovery key and envelope
version; bind the archive to the exact envelope digest and recipient public
key used for encryption. A restore opens one authorized slot, authenticates
the complete archive in isolated staging before installing any state, and
grants no automatic signing authority activation. Existing Core, Control,
and optional Assurance authorization still governs any later activation.

Removing a token slot from current envelopes affects future backups, but
cannot revoke access to historical archives that still carry the old slot.
If historical access must be revoked after suspected compromise, rotate the
backup recipient key and re-encrypt retained archives. Compromise of the
long-lived recovery private key can expose every artifact addressed to it;
per-artifact data keys do not remove that shared-recipient risk.

This document is not a portable-backup profile. It does not authorize an
archive format, algorithm suite, KDF parameters, recipient-slot schema,
registry entries, schemas, or a restore implementation. Those details need a
separate design review and complete current-draft integration before code or
conformance vectors are written.
