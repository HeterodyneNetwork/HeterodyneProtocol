# Screening hardware for Assurance cold-root and epoch keys

This is an informational device-selection aid, not a change to the protocol.
The current [Assurance specification](../spec/heterodyne-assurance.md#assurance-reciprocal-enrollment)
keeps the cold-root secret offline except for enrollment, recovery, or
downgrade. Its [epoch policy](../spec/heterodyne-assurance.md#assurance-keri-policy)
is optional; when enabled, current epoch keys sign threshold proofs over an
exact 32-byte transition digest. The [Core specification](../spec/heterodyne-core.md#core-verification)
requires ordinary NIP-01 BIP-340 signatures. The older
[cold-root design](../superpowers/specs/2026-05-21-cold-root-epoch-keys-design.md)
describes a password-encrypted file on USB as a backup default, but it is not
the current normative storage requirement.

## Quick check

With `fido2-token` installed, inspect connected FIDO devices without creating
credentials or changing device state:

```bash
node scripts/hardware-key-check.mjs scan
```

The inserted `Google Inc. tk-x001` reported USB ID `18d1:5026` and
`caps: wink, nocbor, msg` on this host. That is a FIDO U2F interface.
Its assertions cannot stand in for a Nostr BIP-340 signature over an event ID
or an Assurance proof digest: [FIDO's assertion contract](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
binds an assertion to authenticator data and a relying-party challenge. The
device's exact retail model and any other private signing interface remain
unconfirmed. A FIDO-only interface is therefore unsuitable for these keys.

For a device with a documented signing API, create a JSON capability profile
and run `assess`. Use `true`, `false`, or `null` for yes, no, or unknown:

```json
{
  "name": "Candidate signer and firmware version",
  "capabilities": {
    "hardware_backed": null,
    "offline_signing": null,
    "non_exportable_private_key": null,
    "secp256k1_bip340": null,
    "arbitrary_32_byte_digest": null,
    "public_key_available": null,
    "on_device_key_generation": null,
    "recovery_plan": null,
    "existing_key_provisioning": null
  },
  "evidence": {
    "vendor_spec": "https://example.org/device-capabilities",
    "integration_test": null
  }
}
```

```bash
node scripts/hardware-key-check.mjs assess candidate.json
node scripts/hardware-key-check.mjs assess candidate.json --existing-identity
```

`offline_signing` means the device can stay disconnected except during a
local signing ceremony; it does not imply an air gap while connected.
`arbitrary_32_byte_digest` excludes APIs restricted to Bitcoin transactions,
WebAuthn assertions, or proprietary message formats. `public_key_available`
allows the host to derive the Nostr x-only public key. If preserving an
existing npub, `existing_key_provisioning` must establish that the exact
existing private key can be imported or derived. Importing an existing key
may expose it during provisioning and needs its own handling review.

The script reports `incompatible` for a stated hard failure,
`undetermined` for missing facts, and `candidate` when all hard facts are
affirmed. These are screening results from supplied claims. Before adoption,
an implementation must generate a disposable key on the device, verify its
public key, and verify a synthetic NIP-01 event signature and Assurance proof
signature through the intended host integration. A separate recovery plan is
needed for loss or failure of a non-exportable key.

## Options worth checking further

| Option | Current finding |
| --- | --- |
| Google `tk-x001` through its detected FIDO interface | Incompatible for direct cold-root or epoch signing; no arbitrary BIP-340 signing path observed. |
| YubiKey 5 PIV/OpenPGP | [PIV lists P-256/P-384](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/webdocs.pdf); [OpenPGP lists secp256k1](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html), but a curve listing is not evidence of BIP-340 signing. Require an exact signature test before considering it. |
| [Passport Prime Nostr signer project](https://github.com/BitcoinQnA/passport-nostr-signer) | Promising BIP-340/NIP-01 software and a device demo. Its own README says browser integration currently uses a simulator and hardware transport awaits a public API. Treat as experimental. |
| [Heartwood ESP32 signer](https://github.com/forgesworn/heartwood-esp32) | Reports on-device Nostr signing and a USB mode with radios disabled. Evaluate physical key isolation, firmware trust, disconnected-at-rest operation, and recovery before cold-root use. |

A password-encrypted USB file can be a recovery backup, but the private key
must be decrypted on a general-purpose host to sign. It does not meet the
hardware-isolated signing preference by itself.
