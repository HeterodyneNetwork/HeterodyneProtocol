# Optional Token Custody and Capability Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide a read-only hardware compatibility screen and non-normative custody guidance for optional FIDO2 PRF unlock of encrypted local cold-root, epoch, and backup-recovery material.

**Architecture:** A dependency-free Node CLI separates observed FIDO interface metadata from user-supplied, evidence-backed capability claims. It reports PRF vault unlock and direct BIP-340 signing as distinct roles and never treats metadata as proof of a working credential. A security guide explains the approved local-vault and backup direction without defining a protocol archive format.

**Tech Stack:** Node 22 built-ins (`node:child_process`, `node:fs`, `node:test`); optional `fido2-token` for a read-only scan; Markdown.

**Spec:** [Optional token unlock and backup recovery design](../specs/2026-09-23-optional-token-unlock-and-backup-recovery-design.md)

## Global Constraints

- This is a non-normative local-custody aid, not a current-draft protocol or portable-backup profile; do not edit live spec, registry, schemas, generator inputs, or vectors.
- A token is recommended, never required. Two independently enrolled PRF credentials are an either/or recovery recommendation, never a 2-of-2 requirement.
- `hmac-secret` device metadata is only a candidate signal. A usable PRF credential and an envelope-open round trip require a separately authorized disposable-credential trial.
- `scan` may invoke only `fido2-token -L` and `fido2-token -I <device>`; it must not create credentials, prompt for a PIN, sign, write a file, or change device state.
- A FIDO PRF provider is not a Nostr BIP-340 signer. Direct non-exportable signing is a separate, higher-assurance role requiring a synthetic signing integration test.
- Offline cold-root ceremonies, separate root/epoch compartments, Core's NIP-49-or-equivalent active-nsec boundary, authenticated staging before restore, and no automatic authority activation remain explicit.
- No real token is enrolled or modified by the repository tests. Use synthetic output and capability profiles only.

## Review Focus

- A U2F-only interface must be `incompatible` for PRF unlock, even if marketed as a security key; Task 1 tests this.
- A CTAP2 `hmac-secret` advertisement must remain `candidate`, not `verified`; Task 1 tests this.
- Missing, malformed, or truncated device metadata must not become a positive result; Task 1 tests this.
- Positive FIDO metadata must never confer direct BIP-340 signing; Tasks 1 and 2 test this.
- False or unknown recovery and round-trip evidence must not be hidden behind a favorable hardware claim; Task 2 tests this.

---

## Scope and file map

The approved design deliberately does not choose portable archive bytes, algorithms, KDF parameters, recipient-slot schema, or registry entries. Those decisions require a separately reviewed portable-backup profile before any backup producer, restore implementation, or normative conformance vectors are written. This plan implements the independently useful capability-and-guidance subsystem only; it does not claim to deliver password-only restore, either-token restore, recipient rotation, or archive tamper tests. Those tests belong to the later profile's implementation plan.

- `scripts/hardware-key-check.mjs`: pure FIDO-output parsing and role assessment plus read-only CLI orchestration.
- `scripts/hardware-key-check.test.mjs`: synthetic metadata, profile, and injected-runner tests; no physical device access.
- `docs/security/local-key-custody.md`: user/implementer-facing non-normative decision and failure guidance.
- `docs/security/threat-model.md`: one link and trust-boundary summary pointing to the guide.

The earlier reverted implementation at commit `6ab32e6` is a reference for CLI conventions, not an acceptable finished implementation: it assessed direct signing alone and treated every FIDO interface as incompatible for that role. Retain that distinction while adding PRF unlock as a separate role.

### Task 1: Read-only FIDO metadata screen

**Files:**
- Create: `scripts/hardware-key-check.mjs`
- Create: `scripts/hardware-key-check.test.mjs`

**Interfaces:**
- Produces: `parseFidoListing(output: string): Device[]`, where `Device` has `path`, `vendor`, `product`, and `label` strings.
- Produces: `parseFidoInfo(output: string): {versions: string[], extensions: string[], capabilities: string[]}`.
- Produces: `assessFidoInterface(info): {prf_vault_unlock: Verdict, direct_bip340_signing: Verdict}`, where `Verdict` is `{verdict: 'incompatible'|'undetermined'|'candidate', reason: string}`.
- Produces: `scanDevices(run: (command: string, args: string[], options: object) => string): DeviceAssessment[]` and `main(args: string[], io, run): number` for Task 2 and the CLI.

- [ ] **Step 1: Write failing metadata and non-mutation tests.** Add these exact tests (with the Node imports) to `scripts/hardware-key-check.test.mjs`:

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import {parseFidoInfo, assessFidoInterface, scanDevices} from './hardware-key-check.mjs';

test('U2F-only cannot unlock a PRF vault', () => {
  const info = parseFidoInfo('caps: 0x03 (wink, nocbor, msg)\n');
  assert.equal(assessFidoInterface(info).prf_vault_unlock.verdict, 'incompatible');
});

test('hmac-secret metadata is a candidate, not an enrolled credential', () => {
  const info = parseFidoInfo('versions: FIDO_2_1\nextensions: hmac-secret, credProtect\n');
  const roles = assessFidoInterface(info);
  assert.equal(roles.prf_vault_unlock.verdict, 'candidate');
  assert.match(roles.prf_vault_unlock.reason, /credential.*round.trip/i);
  assert.equal(roles.direct_bip340_signing.verdict, 'incompatible');
});

test('missing or truncated metadata is undetermined', () => {
  assert.equal(assessFidoInterface(parseFidoInfo('')).prf_vault_unlock.verdict, 'undetermined');
  assert.equal(assessFidoInterface(parseFidoInfo('versions: FIDO_2_1\n')).prf_vault_unlock.verdict, 'undetermined');
});

test('scanner invokes only read-only listing and information commands', () => {
  const calls = [];
  const run = (command, args) => {
    calls.push([command, args]);
    return args[0] === '-L'
      ? 'test://token: vendor=0x1050, product=0x0407 (Synthetic token)\n'
      : 'versions: FIDO_2_1\nextensions: hmac-secret\n';
  };
  const devices = scanDevices(run);
  assert.equal(devices.length, 1);
  assert.deepEqual(calls, [
    ['fido2-token', ['-L']],
    ['fido2-token', ['-I', 'test://token']],
  ]);
});
```

- [ ] **Step 2: Run the red test.** Run `node --test scripts/hardware-key-check.test.mjs`; expected failure is missing `hardware-key-check.mjs`.
- [ ] **Step 3: Implement the parser, assessment, and scan.** Use anchored line parsing; split only the named `versions`, `extensions`, and `caps` fields. `nocbor` means U2F-only; an explicit CTAP2 version plus `hmac-secret` means `candidate`; other incomplete output is `undetermined`. Preserve a per-device `undetermined` result when `-I` fails. Use `execFileSync` with `{encoding:'utf8',timeout:5000,maxBuffer:262144}` and an injected runner; never use a shell. `main(['scan'], io, run)` prints JSON including both role verdicts and the metadata-only caveat. Export the interfaces above.

```js
import {execFileSync} from 'node:child_process';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export function parseFidoListing(output) {
  return output.split(/\r?\n/).flatMap(line => {
    const match = /^(\S+): vendor=(0x[\da-f]+), product=(0x[\da-f]+) \((.*)\)$/.exec(line.trim());
    return match ? [{path: match[1], vendor: match[2], product: match[3], label: match[4]}] : [];
  });
}
export function parseFidoInfo(output) {
  const fields = Object.fromEntries(output.split(/\r?\n/).flatMap(line => {
    const match = /^(versions|extensions|caps):\s*(.*)$/.exec(line.trim());
    return match ? [[match[1], match[2]]] : [];
  }));
  const split = value => (value ?? '').split(',').map(item => item.trim()).filter(Boolean);
  const caps = /\(([^)]*)\)/.exec(fields.caps ?? '');
  return {
    versions: split(fields.versions),
    extensions: split(fields.extensions),
    capabilities: split(caps?.[1]),
  };
}
export function assessFidoInterface(info) {
  const u2f = info.capabilities.includes('nocbor');
  const ctap2 = info.versions.some(version => /^FIDO_2_/.test(version));
  const prf = u2f
    ? {verdict: 'incompatible', reason: 'U2F-only interface has no PRF extension.'}
    : ctap2 && info.extensions.includes('hmac-secret')
      ? {verdict: 'candidate', reason: 'Metadata only; credential PRF and slot-open round-trip remain untested.'}
      : {verdict: 'undetermined', reason: 'PRF support not established by available metadata.'};
  return {
    prf_vault_unlock: prf,
    direct_bip340_signing: {verdict: 'incompatible', reason: 'FIDO assertions are not arbitrary Nostr BIP-340 signatures; assess other interfaces separately.'},
  };
}
export function scanDevices(run = execFileSync) {
  const options = {encoding: 'utf8', timeout: 5000, maxBuffer: 262144};
  return parseFidoListing(run('fido2-token', ['-L'], options)).map(device => {
    try {
      const info = parseFidoInfo(run('fido2-token', ['-I', device.path], options));
      return {...device, info, roles: assessFidoInterface(info)};
    } catch {
      return {...device, roles: {
        prf_vault_unlock: {verdict: 'undetermined', reason: 'FIDO information probe failed.'},
        direct_bip340_signing: {verdict: 'incompatible', reason: 'FIDO interface is not a Nostr BIP-340 signer.'},
      }};
    }
  });
}
export function main(args, io = {stdout: process.stdout, stderr: process.stderr}, run = execFileSync) {
  if (args.length === 1 && args[0] === '--help') {
    io.stdout.write('Usage: node scripts/hardware-key-check.mjs scan\nRead-only metadata screen; no credential is created or verified.\n');
    return 0;
  }
  if (args.length === 1 && args[0] === 'scan') {
    try {
      io.stdout.write(`${JSON.stringify({devices: scanDevices(run), note: 'Metadata is not an end-to-end credential trial.'}, null, 2)}\n`);
      return 0;
    } catch (error) {
      io.stderr.write(`${error.message}\n`);
      return 2;
    }
  }
  io.stderr.write('Usage: node scripts/hardware-key-check.mjs scan\n');
  return 2;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
```
- [ ] **Step 4: Run the green test.** Run `node --test scripts/hardware-key-check.test.mjs`; expect all four tests to pass. Run `node scripts/hardware-key-check.mjs --help`; expect the read-only warning and no device probe.
- [ ] **Step 5: Commit.** Run `git add scripts/hardware-key-check.mjs scripts/hardware-key-check.test.mjs` and `git commit -m "Add read-only PRF hardware capability screen"`.

### Task 2: Evidence-backed capability profile for both custody roles

**Files:**
- Modify: `scripts/hardware-key-check.mjs`
- Modify: `scripts/hardware-key-check.test.mjs`

**Interfaces:**
- Consumes: Task 1 `main` and role verdict structure.
- Produces: `assessProfile(profile: object, options?: {existingIdentity?: boolean}): {name: string, roles: {prf_vault_unlock: VerdictWithEvidence, direct_bip340_signing: VerdictWithEvidence}, evidence: object|null}`. `VerdictWithEvidence` has `verdict`, `blockers: string[]`, `unknown: string[]`, and `reason`.
- Profile `capabilities` values are strictly `true`, `false`, or `null`. PRF keys are `fido2_prf_credential`, `slot_open_round_trip`, `recovery_plan`. Direct-signing keys are `hardware_backed`, `offline_signing`, `non_exportable_private_key`, `secp256k1_bip340`, `arbitrary_32_byte_digest`, `public_key_available`, `on_device_key_generation`, `bip340_integration_trial`, `recovery_plan`, plus `existing_key_provisioning` only with `--existing-identity`.

- [ ] **Step 1: Add failing profile tests.** Import `assessProfile` and add:

```js
test('a documented PRF route still needs a slot-open trial', () => {
  const roles = assessProfile({name: 'Synthetic', capabilities: {
    fido2_prf_credential: true, slot_open_round_trip: null, recovery_plan: true,
    secp256k1_bip340: false,
  }}).roles;
  assert.equal(roles.prf_vault_unlock.verdict, 'undetermined');
  assert.deepEqual(roles.prf_vault_unlock.unknown, ['slot_open_round_trip']);
  assert.equal(roles.direct_bip340_signing.verdict, 'incompatible');
});

test('missing recovery evidence cannot yield a candidate', () => {
  const roles = assessProfile({capabilities: {
    fido2_prf_credential: true, slot_open_round_trip: true, recovery_plan: false,
  }}).roles;
  assert.equal(roles.prf_vault_unlock.verdict, 'incompatible');
  assert.deepEqual(roles.prf_vault_unlock.blockers, ['recovery_plan']);
});

test('existing direct signer must preserve the exact existing identity', () => {
  const result = assessProfile({capabilities: {
    hardware_backed: true, offline_signing: true,
    non_exportable_private_key: true, secp256k1_bip340: true,
    arbitrary_32_byte_digest: true, public_key_available: true,
    on_device_key_generation: true, bip340_integration_trial: true,
    recovery_plan: true,
  }}, {existingIdentity: true});
  assert.deepEqual(result.roles.direct_bip340_signing.unknown, ['existing_key_provisioning']);
});

test('malformed capability values are rejected', () => {
  assert.throws(() => assessProfile({capabilities: {recovery_plan: 'yes'}}), /recovery_plan/);
  assert.throws(() => assessProfile({capabilities: []}), /capabilities/);
});
```

- [ ] **Step 2: Run the red test.** Run `node --test scripts/hardware-key-check.test.mjs`; expect the new profile tests to fail because `assessProfile` is absent.
- [ ] **Step 3: Implement the profile and `assess` command.** Compute each role separately: any `false` in its required list means `incompatible`; otherwise any `null` or absent key means `undetermined`; only all `true` means `candidate`. Validate all supplied capability values before assessment. `assess <profile.json> [--existing-identity]` reads one local JSON file and prints both roles, unknowns, blockers, supplied evidence, and a statement that user claims are not certification. Reject extra CLI arguments. Keep `scan` independent of `assess` so scanner metadata cannot silently fill credential-trial fields.

```js
const prfKeys = ['fido2_prf_credential', 'slot_open_round_trip', 'recovery_plan'];
const signingKeys = [
  'hardware_backed', 'offline_signing', 'non_exportable_private_key',
  'secp256k1_bip340', 'arbitrary_32_byte_digest', 'public_key_available',
  'on_device_key_generation', 'bip340_integration_trial', 'recovery_plan',
];
function role(capabilities, keys) {
  const blockers = keys.filter(key => capabilities[key] === false);
  const unknown = keys.filter(key => capabilities[key] == null);
  const verdict = blockers.length ? 'incompatible' : unknown.length ? 'undetermined' : 'candidate';
  return {verdict, blockers, unknown,
    reason: verdict === 'candidate' ? 'Claimed capability candidate, not certification.' :
      blockers.length ? 'Required capability explicitly absent.' : 'Required evidence missing.'};
}
export function assessProfile(profile, {existingIdentity = false} = {}) {
  if (!profile || typeof profile !== 'object' || Array.isArray(profile) ||
      !profile.capabilities || typeof profile.capabilities !== 'object' ||
      Array.isArray(profile.capabilities)) throw new Error('Profile needs a capabilities object');
  const capabilities = profile.capabilities;
  for (const [key, value] of Object.entries(capabilities)) {
    if (value !== true && value !== false && value !== null) {
      throw new Error(`${key} must be true, false, or null`);
    }
  }
  return {
    name: profile.name ?? 'Unnamed device',
    roles: {
      prf_vault_unlock: role(capabilities, prfKeys),
      direct_bip340_signing: role(capabilities, existingIdentity
        ? [...signingKeys, 'existing_key_provisioning'] : signingKeys),
    },
    evidence: profile.evidence ?? null,
  };
}
```

Add `import {readFileSync} from 'node:fs'` at the top of the module and replace Task 1's `main` with:

```js
export function main(args, io = {stdout: process.stdout, stderr: process.stderr}, run = execFileSync) {
  const usage = 'Usage: node scripts/hardware-key-check.mjs scan | assess <profile.json> [--existing-identity]\nRead-only metadata screen; no credential is created or verified.\n';
  if (args.length === 1 && args[0] === '--help') {
    io.stdout.write(usage);
    return 0;
  }
  if (args.length === 1 && args[0] === 'scan') {
    try {
      io.stdout.write(`${JSON.stringify({devices: scanDevices(run), note: 'Metadata is not an end-to-end credential trial.'}, null, 2)}\n`);
      return 0;
    } catch (error) {
      io.stderr.write(`${error.message}\n`);
      return 2;
    }
  }
  if (args[0] === 'assess' && args[1] &&
      (args.length === 2 || (args.length === 3 && args[2] === '--existing-identity'))) {
    try {
      const profile = JSON.parse(readFileSync(resolve(args[1]), 'utf8'));
      io.stdout.write(`${JSON.stringify(assessProfile(profile, {
        existingIdentity: args[2] === '--existing-identity',
      }), null, 2)}\n`);
      return 0;
    } catch (error) {
      io.stderr.write(`${error.message}\n`);
      return 2;
    }
  }
  io.stderr.write(usage);
  return 2;
}
```
- [ ] **Step 4: Run green tests and smoke check.** Run `node --test scripts/hardware-key-check.test.mjs` and `node scripts/hardware-key-check.mjs --help`; expect all tests to pass and both CLI modes to be documented.
- [ ] **Step 5: Commit.** Run `git add scripts/hardware-key-check.mjs scripts/hardware-key-check.test.mjs` and `git commit -m "Assess PRF unlock and direct signing separately"`.

### Task 3: Custody guidance and audit boundary

**Files:**
- Create: `docs/security/local-key-custody.md`
- Modify: `docs/security/threat-model.md`
- Modify: `scripts/hardware-key-check.test.mjs`

**Interfaces:**
- Consumes: Task 2 CLI field names and verdict definitions.
- Produces: a non-normative guide linked from the threat model; no current-draft requirement or archive serialization.

- [ ] **Step 1: Add a failing documentation-contract test.** Import `readFileSync` and add:

```js
test('custody guide states optionality and archive boundary', () => {
  const guide = readFileSync(new URL('../docs/security/local-key-custody.md', import.meta.url), 'utf8');
  assert.match(guide, /token.*optional/i);
  assert.match(guide, /two.*either\/or/i);
  assert.match(guide, /not.*BIP-340 signer/i);
  assert.match(guide, /portable-backup profile/i);
  assert.match(guide, /no automatic.*authority activation/i);
});
```

- [ ] **Step 2: Run the red test.** Run `node --test scripts/hardware-key-check.test.mjs`; expect the guide file read to fail.
- [ ] **Step 3: Write the guide and threat-model link.** The guide must contain: (1) a decision table with optional passphrase, PRF-token software unlock, and direct non-exportable BIP-340 signing, explicitly separating convenience from hardware-isolated signing; (2) distinct encrypted cold-root and epoch compartments, root offline except Assurance ceremonies, host-RAM exposure during software signing, and preserved Core active-nsec NIP-49-or-equivalent protection; (3) instructions for `scan` and `assess`, tri-state evidence, disposable-credential round trip only after separate authorization, no real-token trial in CI; (4) either/or independent tokens or alternative recovery method, PIN/touch caveat, lost-all-methods warning; (5) backup direction with a dedicated public/private recovery keypair, unattended creation from only its public key, fresh per-artifact data key, encrypted private key and authenticated slots included in each archive, envelope digest and recipient-public-key binding, separate authority key/recipient policy, authenticated staging, and no automatic signing-authority activation; (6) historical-backup slot-removal limits and recipient-key rotation; (7) an explicit statement that this document is not a portable-backup profile and does not authorize an archive format or restore implementation. Add one paragraph and link under `docs/security/threat-model.md`'s `### Compromise` section.

```markdown
# Local key custody choices

This guide is non-normative. A PRF-capable FIDO2 token is optional and
recommended as a replacement for a memorized vault-unlock passphrase. It is not a BIP-340 signer or a mandatory Heterodyne protocol component.

| Path | What the hardware does | What must be tested |
| --- | --- | --- |
| Passphrase | No token required | Memory-hard authenticated unwrap and a restore rehearsal |
| PRF-token unlock | Gates an encrypted software signer | Credential PRF output and envelope-open round trip |
| Direct hardware signing | Keeps the signing key non-exportable | Exact BIP-340 digest signature and recovery plan |

Two independently enrolled tokens are either/or recovery options, not a
two-token threshold. No automatic signing authority activation follows data restore.
The portable-backup profile is a separate design and review; this guide does
not define its bytes, algorithms, registry entries, or schemas.
```
- [ ] **Step 4: Verify documentation and repo gates.** Run `node --test scripts/hardware-key-check.test.mjs`, `git diff --check`, `npm --prefix docs/spec/vectors/generator run draft:check -- "$PWD"`, `npm --prefix docs/spec/vectors/generator run snapshot-check -- "$PWD"`, and `scripts/conformance-ci.sh`. Expect zero failures. Review the guide against the seven required content groups, not just the regex test.
- [ ] **Step 5: Commit.** Run `git add docs/security/local-key-custody.md docs/security/threat-model.md scripts/hardware-key-check.test.mjs` and `git commit -m "Document optional token custody and backup boundary"`.

## Branch handoff

After all three tasks, inspect `git diff origin/main...HEAD`, confirm no live protocol or vector artifact changed, run the verification gate again after the last edit, and push with the explicit refspec `git push origin HEAD:refs/heads/docs/optional-token-backup-recovery`. Update PR #33; do not merge it. The portable-backup wire profile requires its own reviewed design and implementation plan before code, schemas, or vectors are attempted.
