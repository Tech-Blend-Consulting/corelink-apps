'use strict';

// Runtime fingerprint computation for NHI identity verification.
//
// Same construction as the Python and Go SDKs: the digest is
// sha256(binaryHashBytes || machineId || hostname || nhiId).
//
// The binary hash covers the running interpreter, so the value differs per
// language runtime on the same host -- a Node process and a Ruby process
// produce different fingerprints. That is intended: each workload enrols its
// own NHI, and the fingerprint is what binds a session to that specific
// running artifact.

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

/**
 * Compute a runtime fingerprint for this process.
 *
 * @param {string} nhiId
 * @returns {{fingerprint: string, metadata: object}}
 */
function computeFingerprint(nhiId) {
  const metadata = {};

  // Binary hash: SHA-256 of the running executable. process.execPath is the
  // node binary itself, matching the Python SDK's use of sys.executable.
  let binaryHash;
  try {
    binaryHash = crypto.createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex');
  } catch {
    binaryHash = crypto.createHash('sha256').update(process.version).digest('hex');
  }
  metadata.binary_hash = binaryHash;

  const machineId = readMachineId();
  metadata.machine_id = machineId;

  const hostname = os.hostname();
  metadata.hostname = hostname;
  metadata.os = process.platform === 'win32' ? 'windows' : process.platform;
  metadata.arch = process.arch;

  const h = crypto.createHash('sha256');
  h.update(Buffer.from(binaryHash, 'hex'));
  h.update(machineId);
  h.update(hostname);
  h.update(nhiId || '');

  return { fingerprint: h.digest('hex'), metadata };
}

/** Read the platform-specific machine ID, falling back to the hostname. */
function readMachineId() {
  const platform = process.platform;

  if (platform === 'linux') {
    try {
      const id = fs.readFileSync('/etc/machine-id', 'utf8').trim();
      if (id) return id;
    } catch {
      // fall through to the container fallback
    }
    // Container fallback: the cgroup path ends in the container ID.
    try {
      const cgroup = fs.readFileSync('/proc/self/cgroup', 'utf8');
      for (const line of cgroup.split('\n')) {
        const parts = line.trim().split('/');
        const last = parts[parts.length - 1];
        if (last && last.length >= 12) return last.slice(0, 12);
      }
    } catch {
      // fall through
    }
  } else if (platform === 'darwin') {
    try {
      const out = execFileSync('ioreg', ['-rd1', '-c', 'IOPlatformExpertDevice'], {
        encoding: 'utf8',
        timeout: 5000,
      });
      for (const line of out.split('\n')) {
        if (line.includes('IOPlatformUUID')) {
          const value = line.split('=')[1];
          if (value) return value.trim().replace(/"/g, '');
        }
      }
    } catch {
      // fall through
    }
  } else if (platform === 'win32') {
    try {
      const out = execFileSync(
        'reg',
        ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'],
        { encoding: 'utf8', timeout: 5000 },
      );
      for (const line of out.split('\n')) {
        if (line.includes('MachineGuid')) {
          const parts = line.trim().split(/\s+/);
          return parts[parts.length - 1];
        }
      }
    } catch {
      // fall through
    }
  }

  return os.hostname();
}

module.exports = { computeFingerprint };
