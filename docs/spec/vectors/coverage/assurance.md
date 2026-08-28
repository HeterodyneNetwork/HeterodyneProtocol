# Assurance vector coverage

Generated from [manifest.json](manifest.json); do not edit by hand.

| Vector | Owner | Profile | Invariants | Reason codes | Spec references |
|---|---|---|---|---|---|
| `assurance/associated-key-expired` | assurance | `heterodyne-assurance-associated-key-v1` | `ASSURANCE-I-ASSOCIATED-KEY-BOUNDS` | `assurance-associated-key-expired` | `heterodyne:assurance#assurance-associated-keys` |
| `assurance/associated-key-revoked` | assurance | `heterodyne-assurance-associated-key-v1` | `ASSURANCE-I-ASSOCIATED-KEY-BOUNDS` | `assurance-associated-key-revoked` | `heterodyne:assurance#assurance-associated-keys` |
| `assurance/associated-key-subject-proof-invalid` | assurance | `heterodyne-assurance-associated-key-v1` | `ASSURANCE-I-ASSOCIATED-KEY-BOUNDS` | `assurance-associated-key-subject-proof-invalid` | `heterodyne:assurance#assurance-associated-keys` |
| `assurance/associated-key-subject-proof-required` | assurance | `heterodyne-assurance-associated-key-v1` | `ASSURANCE-I-ASSOCIATED-KEY-BOUNDS` | `assurance-associated-key-subject-proof-required` | `heterodyne:assurance#assurance-associated-keys` |
| `assurance/authority-at-compromise-cutoff` | assurance | — | `ASSURANCE-I-COMPROMISE-CUTOFF` | `assurance-compromise-cutoff` | `heterodyne:assurance#assurance-compromise` |
| `assurance/compromise-subordinate-continuation-forbidden` | assurance | — | `ASSURANCE-I-COMPROMISE-CUTOFF`<br>`ASSURANCE-I-NO-IMPLICIT-CONTINUATION` | `assurance-subordinate-continuation-forbidden` | `heterodyne:assurance#assurance-compromise` |
| `assurance/duplicity-rejected` | assurance | — | `ASSURANCE-I-SUCCESSION-NON-ALIASING` | `assurance-duplicity` | `heterodyne:assurance#assurance-chain-validation` |
| `assurance/enrollment-competing-inception` | assurance | — | `ASSURANCE-I-ENROLLMENT-WINDOWED` | `assurance-enrollment-contested` | `heterodyne:assurance#assurance-enrollment-window` |
| `assurance/enrollment-forged-contest-ignored` | assurance | — | `ASSURANCE-I-CORE-OPTIONALITY`<br>`ASSURANCE-I-ENROLLMENT-WINDOWED` | — | `heterodyne:assurance#assurance-enrollment-window` |
| `assurance/enrollment-late-warning-no-unpin` | assurance | — | `ASSURANCE-I-ENROLLMENT-WINDOWED`<br>`ASSURANCE-I-PIN-DOWNGRADE` | — | `heterodyne:assurance#assurance-pinning` |
| `assurance/enrollment-pending-w-minus-one` | assurance | `heterodyne-assurance-enrollment-inception-v1` | `ASSURANCE-I-ENROLLMENT-WINDOWED` | `assurance-enrollment-pending-window` | `heterodyne:assurance#assurance-enrollment-window` |
| `assurance/enrollment-timely-contest` | assurance | `heterodyne-assurance-enrollment-contest-profile-v1` | `ASSURANCE-I-ENROLLMENT-WINDOWED` | `assurance-enrollment-contested` | `heterodyne:assurance#assurance-enrollment-window` |
| `assurance/enrollment-verified-at-window` | assurance | — | `ASSURANCE-I-ENROLLMENT-WINDOWED` | — | `heterodyne:assurance#assurance-enrollment-window` |
| `assurance/export-aid-substitution` | assurance | — | `ASSURANCE-I-EXPORT-LOSSLESS` | `export_aid_substituted_for_npub` | `heterodyne:assurance#assurance-keri-export` |
| `assurance/export-incomplete` | assurance | — | `ASSURANCE-I-EXPORT-LOSSLESS` | `export_incomplete` | `heterodyne:assurance#assurance-keri-export` |
| `assurance/export-lossless` | assurance | — | `ASSURANCE-I-EXPORT-LOSSLESS` | — | `heterodyne:assurance#assurance-keri-export` |
| `assurance/export-unmappable-feature` | assurance | — | `ASSURANCE-I-EXPORT-LOSSLESS` | `export_unmappable_feature` | `heterodyne:assurance#assurance-keri-export` |
| `assurance/export-unsupported-suite` | assurance | — | `ASSURANCE-I-EXPORT-LOSSLESS` | `export_unsupported_crypto_suite` | `heterodyne:assurance#assurance-keri-export` |
| `assurance/keri-wire-format-rejected` | assurance | — | `ASSURANCE-I-EXPORT-LOSSLESS` | `keri_wire_format_rejected` | `heterodyne:assurance#assurance-keri-export` |
| `assurance/persona-author-mismatch` | assurance | — | `ASSURANCE-I-CORE-OPTIONALITY` | `delegation_mismatch` | `heterodyne:assurance#assurance-scope` |
| `assurance/pin-conflict-rejected` | assurance | — | `ASSURANCE-I-PIN-DOWNGRADE` | `assurance-pin-conflict` | `heterodyne:assurance#assurance-pinning` |
| `assurance/profile-heterodyne-assurance-active-key-acceptance-v1` | assurance | `heterodyne-assurance-active-key-acceptance-v1` | `ASSURANCE-I-RECIPROCAL-ENROLLMENT` | — | `heterodyne:assurance#assurance-security` |
| `assurance/profile-heterodyne-assurance-associated-key-v1` | assurance | `heterodyne-assurance-associated-key-v1` | `ASSURANCE-I-ASSOCIATED-KEY-BOUNDS` | — | `heterodyne:assurance#assurance-security` |
| `assurance/profile-heterodyne-assurance-enrollment-contest-profile-v1` | assurance | `heterodyne-assurance-enrollment-contest-profile-v1` | `ASSURANCE-I-ENROLLMENT-WINDOWED` | — | `heterodyne:assurance#assurance-security` |
| `assurance/profile-heterodyne-assurance-enrollment-inception-v1` | assurance | `heterodyne-assurance-enrollment-inception-v1` | `ASSURANCE-I-RECIPROCAL-ENROLLMENT` | — | `heterodyne:assurance#assurance-security` |
| `assurance/profile-heterodyne-assurance-succession-v1` | assurance | `heterodyne-assurance-succession-v1` | `ASSURANCE-I-TRANSITION-PROOF-BINDING` | — | `heterodyne:assurance#assurance-security` |
| `assurance/reciprocal-proof-invalid` | assurance | — | `ASSURANCE-I-RECIPROCAL-ENROLLMENT` | `assurance-reciprocal-proof-invalid` | `heterodyne:assurance#assurance-reciprocal-enrollment` |
| `assurance/retired-key-post-compromise` | assurance | — | `ASSURANCE-I-COMPROMISE-CUTOFF` | `revoked_key_post_compromise` | `heterodyne:assurance#assurance-retired-wire-profiles` |
| `assurance/succession-authority-invalid` | assurance | — | `ASSURANCE-I-TRANSITION-PROOF-BINDING` | `assurance-authority-invalid` | `heterodyne:assurance#assurance-succession` |
| `assurance/succession-head-mismatch` | assurance | — | `ASSURANCE-I-TRANSITION-PROOF-BINDING` | `assurance-head-mismatch` | `heterodyne:assurance#assurance-chain-validation` |
| `assurance/succession-new-key-acceptance-invalid` | assurance | — | `ASSURANCE-I-TRANSITION-PROOF-BINDING` | `assurance-new-key-acceptance-invalid` | `heterodyne:assurance#assurance-succession` |
| `assurance/succession-predecessor-mismatch` | assurance | — | `ASSURANCE-I-TRANSITION-PROOF-BINDING` | `assurance-predecessor-mismatch` | `heterodyne:assurance#assurance-chain-validation` |
| `assurance/succession-schema-invalid` | assurance | `heterodyne-assurance-succession-v1` | `ASSURANCE-I-TRANSITION-PROOF-BINDING` | `assurance-schema-invalid` | `heterodyne:assurance#assurance-record-envelope` |
| `assurance/succession-valid` | assurance | `heterodyne-assurance-succession-v1` | `ASSURANCE-I-NO-IMPLICIT-CONTINUATION`<br>`ASSURANCE-I-SUCCESSION-NON-ALIASING`<br>`ASSURANCE-I-TRANSITION-PROOF-BINDING` | — | `heterodyne:assurance#assurance-succession` |
| `assurance/succession-witness-threshold-unsatisfied` | assurance | — | `ASSURANCE-I-TRANSITION-PROOF-BINDING` | `assurance-witness-threshold-unsatisfied` | `heterodyne:assurance#assurance-keri-policy` |
| `assurance/unilateral-downgrade-rejected` | assurance | — | `ASSURANCE-I-PIN-DOWNGRADE` | `assurance-downgrade-consent-required` | `heterodyne:assurance#assurance-downgrade-resistance` |
| `assurance/witness-threshold-fail` | assurance | — | `ASSURANCE-I-ENROLLMENT-WINDOWED` | `assurance-enrollment-pending-window` | `heterodyne:assurance#assurance-enrollment-window` |
| `assurance/witness-threshold-pass` | assurance | — | `ASSURANCE-I-ENROLLMENT-WINDOWED` | — | `heterodyne:assurance#assurance-enrollment-window` |
