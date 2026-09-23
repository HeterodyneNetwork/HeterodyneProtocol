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
