import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {parseFidoInfo, assessFidoInterface, scanDevices, assessProfile, main} from './hardware-key-check.mjs';

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

test('incomplete CTAP2 version cannot be a PRF candidate', () => {
  const info = parseFidoInfo('versions: FIDO_2_\nextensions: hmac-secret\n');
  assert.equal(assessFidoInterface(info).prf_vault_unlock.verdict, 'undetermined');
});

test('malformed CTAP2 version cannot be a PRF candidate', () => {
  const info = parseFidoInfo('versions: FIDO_2_bogus\nextensions: hmac-secret\n');
  assert.equal(assessFidoInterface(info).prf_vault_unlock.verdict, 'undetermined');
});

test('truncated capability metadata cannot be a PRF candidate', () => {
  const info = parseFidoInfo('versions: FIDO_2_1\nextensions: hmac-secret\ncaps: 0x03 (wink, nocbor\n');
  assert.equal(assessFidoInterface(info).prf_vault_unlock.verdict, 'undetermined');
});

test('contradictory duplicate capability fields cannot be a PRF candidate', () => {
  const info = parseFidoInfo('versions: FIDO_2_1\nextensions: hmac-secret\ncaps: 0x03 (wink, nocbor, msg)\ncaps: 0x00 ()\n');
  assert.equal(assessFidoInterface(info).prf_vault_unlock.verdict, 'undetermined');
});

test('trailing empty version or extension list item cannot be a PRF candidate', () => {
  for (const output of [
    'versions: FIDO_2_1,\nextensions: hmac-secret\n',
    'versions: FIDO_2_1\nextensions: hmac-secret,\n',
  ]) {
    assert.equal(assessFidoInterface(parseFidoInfo(output)).prf_vault_unlock.verdict, 'undetermined');
  }
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

test('assess CLI labels supplied evidence as unverified claims', () => {
  const directory = mkdtempSync(join(tmpdir(), 'hardware-key-check-'));
  try {
    const profilePath = join(directory, 'profile.json');
    writeFileSync(profilePath, JSON.stringify({capabilities: {fido2_prf_credential: true}}));
    let output = '';
    const io = {stdout: {write: value => { output += value; }}, stderr: {write: () => {}}};
    assert.equal(main(['assess', profilePath], io), 0);
    const result = JSON.parse(output);
    assert.match(result.note, /claims.*not certification/i);
    assert.deepEqual(result.roles.prf_vault_unlock.unknown, ['slot_open_round_trip', 'recovery_plan']);
  } finally {
    rmSync(directory, {recursive: true});
  }
});

test('custody guide states optionality and archive boundary', () => {
  const guide = readFileSync(new URL('../docs/security/local-key-custody.md', import.meta.url), 'utf8');
  assert.match(guide, /token.*optional/i);
  assert.match(guide, /two.*either\/or/i);
  assert.match(guide, /not.*BIP-340 signer/i);
  assert.match(guide, /portable-backup profile/i);
  assert.match(guide, /no automatic.*authority activation/i);
});
