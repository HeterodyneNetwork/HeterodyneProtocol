# Core vector coverage

Generated from [manifest.json](manifest.json); do not edit by hand.

| Vector | Owner | Profile | Invariants | Reason codes | Spec references |
|---|---|---|---|---|---|
| `core/config-rid-published` | core | — | `CORE-I-IDENTITY-INTEGRITY` | `config_rid_advertised` | `heterodyne:core#core-conformance` |
| `core/friend-cache-unsigned` | core | — | `CORE-I-IDENTITY-INTEGRITY` | `unauthorized_cache_content` | `heterodyne:core#core-conformance` |
| `core/nip01-raw-mismatch` | core | — | `CORE-I-VERIFY-BEFORE-USE` | `nip01_raw_mismatch` | `heterodyne:core#core-verification` |
| `core/nip49-key-material-round-trip` | core | — | `CORE-I-KEY-MATERIAL-AT-REST` | — | `heterodyne:core#core-keys-repository` |
| `core/node-advert-bad-signature` | core | — | `CORE-I-VERIFY-BEFORE-USE` | `bad_signature` | `heterodyne:core#core-node-advertisement` |
| `core/node-advert-clock-skew` | core | — | `CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY` | `node-advert-clock-skew` | `heterodyne:core#core-node-advertisement` |
| `core/node-advert-clock-uncertain` | core | — | `CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY` | `node-advert-clock-uncertain` | `heterodyne:core#core-node-advertisement` |
| `core/node-advert-dual-proof-valid` | core | — | `CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY` | — | `heterodyne:core#core-node-advertisement` |
| `core/node-advert-expired` | core | — | `CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY` | `node_advert_expired` | `heterodyne:core#core-node-advertisement` |
| `core/node-advert-expiry-invalid` | core | — | `CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY` | `node-advert-expiry-invalid` | `heterodyne:core#core-node-advertisement` |
| `core/node-advert-lifetime-exceeded` | core | — | `CORE-I-NO-CENTRAL-IDENTITY-DIRECTORY` | `node-advert-lifetime-exceeded` | `heterodyne:core#core-node-advertisement` |
| `core/node-advert-nid-proof-invalid` | core | — | `CORE-I-VERIFY-BEFORE-USE` | `nid_proof_invalid` | `heterodyne:core#core-node-advertisement` |
| `core/onion-clearnet-resolution` | core | — | `CORE-I-VERIFY-BEFORE-USE` | `onion_dns_leak` | `heterodyne:core#core-conformance` |
| `core/profile-heterodyne-core-rotation-breadcrumb-note-v1` | core | `heterodyne-core-rotation-breadcrumb-note-v1` | `CORE-I-IDENTITY-INTEGRITY` | — | `heterodyne:core#core-security` |
| `core/profile-heterodyne-core-rotation-breadcrumb-profile-v1` | core | `heterodyne-core-rotation-breadcrumb-profile-v1` | `CORE-I-IDENTITY-INTEGRITY` | — | `heterodyne:core#core-security` |
| `core/profile-nip05-key-mismatch` | core | — | `CORE-I-IDENTITY-INTEGRITY` | `profile-nip05-key-mismatch` | `heterodyne:core#core-persona-profile` |
| `core/profile-publisher-delegation-invalid` | core | — | `CORE-I-IDENTITY-INTEGRITY` | `profile-publisher-delegation-invalid` | `heterodyne:core#core-persona-profile` |
| `core/profile-repository-selection-required` | core | — | `CORE-I-IDENTITY-INTEGRITY` | `profile-repository-selection-required` | `heterodyne:core#core-persona-profile` |
| `core/relay-profile-mutated` | core | — | `CORE-I-IDENTITY-INTEGRITY` | `relay_profile_mutation` | `heterodyne:core#core-conformance` |
| `core/replaceable-advisory-nip03-ignored` | core | — | `CORE-I-VERIFY-BEFORE-USE` | — | `heterodyne:core#core-nip03-advisory` |
| `core/replaceable-at-premature-boundary` | core | — | `CORE-I-VERIFY-BEFORE-USE` | — | `heterodyne:core#core-created-at-bound` |
| `core/replaceable-equal-time-lowest-id` | core | — | `CORE-I-VERIFY-BEFORE-USE` | — | `heterodyne:core#core-source-neutral-selection` |
| `core/replaceable-future-quarantined` | core | — | `CORE-I-VERIFY-BEFORE-USE` | `core-created-at-premature` | `heterodyne:core#core-created-at-bound` |
| `core/repository-writer-dual-proof-valid` | core | — | `CORE-I-NID-DELEGATION-DUAL-PROOF` | — | `heterodyne:core#core-nid-delegation` |
| `core/repository-writer-owner-proof-invalid` | core | — | `CORE-I-NID-DELEGATION-DUAL-PROOF` | `repository-writer-binding-invalid` | `heterodyne:core#core-nid-delegation` |
| `core/strict-mode-without-tor` | core | — | `CORE-I-VERIFY-BEFORE-USE` | `strict_mode_tor_disabled` | `heterodyne:core#core-conformance` |
| `core/version-future-major` | core | — | `CORE-I-VERIFY-BEFORE-USE` | `unknown_major_version` | `heterodyne:core#core-conformance` |
| `core/version-stamp-missing` | core | — | `CORE-I-VERIFY-BEFORE-USE` | `version_stamp_invalid` | `heterodyne:core#core-verification` |
