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
