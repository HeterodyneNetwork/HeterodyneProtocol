#!/usr/bin/env node
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const required = [
  'hardware_backed',
  'offline_signing',
  'non_exportable_private_key',
  'secp256k1_bip340',
  'arbitrary_32_byte_digest',
  'public_key_available',
  'on_device_key_generation',
  'recovery_plan',
];

export function assessProfile(profile, {existingIdentity = false} = {}) {
  if (!profile || typeof profile !== 'object' || !profile.capabilities || typeof profile.capabilities !== 'object') {
    throw new Error('Profile needs a capabilities object');
  }
  const capabilities = profile.capabilities;
  const fields = existingIdentity ? [...required, 'existing_key_provisioning'] : required;
  for (const [key, value] of Object.entries(capabilities)) {
    if (value !== true && value !== false && value !== null) throw new Error(`${key} must be true, false, or null`);
  }
  const blockers = fields.filter(key => capabilities[key] === false);
  const unknown = fields.filter(key => capabilities[key] == null);
  const cautions = [];
  if (capabilities.recovery_plan === false) cautions.push('No recovery plan for a lost or failed device.');
  else if (capabilities.recovery_plan == null) cautions.push('Recovery after device loss is unconfirmed.');
  const verdict = blockers.length ? 'incompatible' : unknown.length ? 'undetermined' : 'candidate';
  return {
    name: profile.name ?? 'Unnamed device',
    verdict,
    roles: {cold_root: verdict, epoch_key: verdict},
    blockers,
    unknown,
    cautions,
    evidence: profile.evidence ?? null,
    note: 'A candidate still needs a synthetic BIP-340 signing and public-key verification test with the exact integration path.',
  };
}

export function parseFidoListing(output) {
  return output.split(/\r?\n/).flatMap(line => {
    const match = /^(\S+): vendor=(0x[0-9a-f]+), product=(0x[0-9a-f]+) \((.*)\)$/.exec(line.trim());
    return match ? [{path: match[1], vendor: match[2], product: match[3], label: match[4]}] : [];
  });
}

export function parseFidoInfo(output) {
  const caps = /^caps:.*\(([^)]*)\)/m.exec(output);
  const versions = /^versions:\s*(.*)$/m.exec(output);
  return {
    capabilities: caps ? caps[1].split(',').map(item => item.trim()) : [],
    versions: versions ? versions[1].split(',').map(item => item.trim()) : [],
  };
}

export function assessFidoInterface(info) {
  if (!info.capabilities?.length && !info.versions?.length) {
    return {verdict: 'undetermined', reason: 'FIDO interface information unavailable.'};
  }
  const protocol = info.capabilities.includes('nocbor') ? 'FIDO U2F' : 'FIDO';
  return {
    verdict: 'incompatible',
    reason: `${protocol} assertions do not expose arbitrary 32-byte BIP-340 Nostr signing. Other device interfaces require separate assessment.`,
  };
}

const help = `Usage:
  node scripts/hardware-key-check.mjs scan
  node scripts/hardware-key-check.mjs assess <profile.json> [--existing-identity]

scan reads connected FIDO token metadata with fido2-token -L/-I. It does not
create credentials, sign, change PINs, or modify the device. A FIDO interface
result does not assess other interfaces on the same hardware.

assess screens documented capabilities. true/false/null mean yes/no/unknown.
The verdict is a screening result, never a security certification.
`;

export function main(args, io = {stdout: process.stdout, stderr: process.stderr}) {
  try {
    if (args.length === 1 && args[0] === '--help') {
      io.stdout.write(help);
      return 0;
    }
    if (args.length === 1 && args[0] === 'scan') {
      const readOptions = {encoding: 'utf8', timeout: 5000, maxBuffer: 256 * 1024};
      const listing = execFileSync('fido2-token', ['-L'], readOptions);
      const devices = parseFidoListing(listing).map(device => {
        try {
          const info = parseFidoInfo(execFileSync('fido2-token', ['-I', device.path], readOptions));
          return {...device, fido_interface: assessFidoInterface(info), info};
        } catch (error) {
          return {...device, fido_interface: {verdict: 'undetermined', reason: `FIDO probe failed: ${error.message}`}};
        }
      });
      io.stdout.write(`${JSON.stringify({devices, note: 'FIDO metadata cannot establish support for Nostr BIP-340 signing through another interface.'}, null, 2)}\n`);
      return 0;
    }
    if (args[0] === 'assess' && args[1] && args.length <= 3 && (args.length === 2 || args[2] === '--existing-identity')) {
      const profile = JSON.parse(readFileSync(resolve(args[1]), 'utf8'));
      io.stdout.write(`${JSON.stringify(assessProfile(profile, {existingIdentity: args[2] === '--existing-identity'}), null, 2)}\n`);
      return 0;
    }
    io.stderr.write(help);
    return 2;
  } catch (error) {
    io.stderr.write(`${error.message}\n`);
    return 2;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
