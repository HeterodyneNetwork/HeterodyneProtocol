import test from 'node:test';
import assert from 'node:assert/strict';
import {assessProfile, parseFidoListing, parseFidoInfo, assessFidoInterface} from './hardware-key-check.mjs';

const capable = {
  name: 'Example signer',
  capabilities: {
    hardware_backed: true,
    offline_signing: true,
    non_exportable_private_key: true,
    secp256k1_bip340: true,
    arbitrary_32_byte_digest: true,
    public_key_available: true,
    on_device_key_generation: true,
    recovery_plan: true,
  },
};

test('FIDO U2F interface cannot satisfy Nostr BIP-340 signing', () => {
  const devices = parseFidoListing('ioreg://4302182104: vendor=0x18d1, product=0x5026 (Google Inc. tk-x001)\n');
  assert.equal(devices.length, 1);
  assert.equal(devices[0].path, 'ioreg://4302182104');
  assert.equal(devices[0].product, '0x5026');
  const info = parseFidoInfo('proto: 0x02\nmajor: 0x00\nminor: 0x00\nbuild: 0x00\ncaps: 0x03 (wink, nocbor, msg)\n');
  assert.equal(assessFidoInterface(info).verdict, 'incompatible');
});

test('FIDO2 metadata alone leaves other device interfaces unassessed', () => {
  const info = parseFidoInfo('versions: FIDO_2_1\noptions: rk, clientPin\n');
  const result = assessFidoInterface(info);
  assert.equal(result.verdict, 'incompatible');
  assert.match(result.reason, /FIDO/);
});

test('secp256k1 ECDSA is not BIP-340, even with secure hardware storage', () => {
  const result = assessProfile({
    ...capable,
    capabilities: {...capable.capabilities, secp256k1_bip340: false},
  });
  assert.equal(result.verdict, 'incompatible');
  assert.deepEqual(result.blockers, ['secp256k1_bip340']);
});

test('positive documentation is a candidate, never a verified signer', () => {
  const result = assessProfile(capable);
  assert.equal(result.verdict, 'candidate');
  assert.deepEqual(result.blockers, []);
  assert.deepEqual(result.unknown, []);
});

test('missing signing evidence and recovery remain visible', () => {
  const result = assessProfile({
    ...capable,
    capabilities: {...capable.capabilities, arbitrary_32_byte_digest: null, recovery_plan: false},
  });
  assert.equal(result.verdict, 'incompatible');
  assert.deepEqual(result.blockers, ['recovery_plan']);
  assert.deepEqual(result.unknown, ['arbitrary_32_byte_digest']);
  assert.deepEqual(result.cautions, ['No recovery plan for a lost or failed device.']);
});

test('unknown recovery cannot produce a cold-root candidate', () => {
  const result = assessProfile({
    ...capable,
    capabilities: {...capable.capabilities, recovery_plan: null},
  });
  assert.equal(result.verdict, 'undetermined');
  assert.equal(result.roles.cold_root, 'undetermined');
  assert.deepEqual(result.unknown, ['recovery_plan']);
});

test('existing identity requires a way to load or derive its exact key', () => {
  const result = assessProfile(capable, {existingIdentity: true});
  assert.equal(result.verdict, 'undetermined');
  assert.deepEqual(result.unknown, ['existing_key_provisioning']);
});
