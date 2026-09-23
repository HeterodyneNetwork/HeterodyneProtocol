import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export function parseFidoListing(output) {
  return output.split(/\r?\n/).flatMap(line => {
    const match = /^(\S+): vendor=(0x[\da-f]+), product=(0x[\da-f]+) \((.*)\)$/.exec(line.trim());
    return match ? [{path: match[1], vendor: match[2], product: match[3], label: match[4]}] : [];
  });
}

export function parseFidoInfo(output) {
  const fields = new Map();
  const parseErrors = [];
  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = /^(versions|extensions|caps):\s*(.*)$/.exec(line);
    if (!match) {
      if (/^(versions|extensions|caps)\b/i.test(line)) parseErrors.push('Malformed FIDO information field.');
      continue;
    }
    if (fields.has(match[1])) parseErrors.push(`Duplicate ${match[1]} field.`);
    else fields.set(match[1], match[2]);
  }
  const split = (field, value = fields.get(field)) => {
    if (value === undefined) return [];
    const items = value.split(',').map(item => item.trim());
    if (items.some(item => !item)) parseErrors.push(`Malformed ${field} list.`);
    return items.filter(Boolean);
  };
  const versions = split('versions');
  const extensions = split('extensions');
  if (versions.some(version => !/^(?:FIDO_2_\d+|U2F_V2)$/.test(version))) {
    parseErrors.push('Malformed FIDO version.');
  }
  if (extensions.some(extension => !/^[A-Za-z][A-Za-z0-9_-]*$/.test(extension))) {
    parseErrors.push('Malformed FIDO extension.');
  }
  const capsValue = fields.get('caps');
  const caps = capsValue === undefined ? null : /^0x[\da-fA-F]+ \(([^)]*)\)$/.exec(capsValue);
  if (capsValue !== undefined && !caps) parseErrors.push('Malformed FIDO capabilities.');
  const capabilities = caps ? (caps[1] ? split('caps', caps[1]) : []) : [];
  if (capabilities.some(capability => !/^[A-Za-z][A-Za-z0-9_-]*$/.test(capability))) {
    parseErrors.push('Malformed FIDO capability.');
  }
  return {
    versions,
    extensions,
    capabilities,
    parseErrors,
  };
}

export function assessFidoInterface(info) {
  const u2f = info.capabilities.includes('nocbor');
  const ctap2 = info.versions.some(version => /^FIDO_2_\d+$/.test(version));
  const prf = info.parseErrors?.length
    ? {verdict: 'undetermined', reason: 'Malformed or contradictory FIDO metadata cannot establish PRF support.'}
    : u2f
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
    note: 'Supplied capability claims are not certification or an end-to-end hardware trial.',
  };
}

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

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
