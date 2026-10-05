'use strict';

/**
 * Opening a sealed envelope.
 *
 * The application takes ciphertext from a connector and the key from CoreLink,
 * and opens the secret itself. Nothing between the two holds both halves: the
 * connector is granted secrets:cache and keeps envelopes it has no authority to
 * open, and the application is granted secrets:unwrap and may open one it
 * already has.
 *
 * The additional authenticated data is rebuilt here from the secret id and
 * version and required to equal the value stored on the envelope. Decrypting
 * with whatever the envelope carries would detect an altered envelope, because
 * the tag breaks, but would bind nothing -- an envelope claiming to be some
 * other secret would open happily.
 *
 * See docs/secret-delivery.md.
 */

const crypto = require('node:crypto');

// Prefix of the additional authenticated data. Must match crypto.SecretAAD on
// the platform byte for byte: the two are one wire format, and changing either
// alone stops every envelope opening. Pinned by
// sdk/testdata/sealed_envelope.json, which the platform produces.
const AAD_PREFIX = 'cl.secret.v1';

// AES-GCM's tag, which Go appends to the ciphertext and Node wants separately.
const TAG_BYTES = 16;

/**
 * A cached envelope the current key will not open.
 *
 * Separate from CorruptEnvelope because the recoveries differ: ask the connector
 * for a fresh envelope. A rollback attempt and a damaged envelope look identical
 * at the AEAD and should not look identical in a log.
 */
class StaleEnvelope extends Error {
  constructor(message) {
    super(message);
    this.name = 'StaleEnvelope';
  }
}

/**
 * An envelope that did not open and was not stale.
 *
 * The key belonged to the version the envelope claims and it still failed, so
 * the ciphertext or the tag has been altered. Refetching will not help.
 */
class CorruptEnvelope extends Error {
  constructor(message) {
    super(message);
    this.name = 'CorruptEnvelope';
  }
}

/**
 * A connector answered with a different secret than the one asked for.
 *
 * The case the AAD does not cover. An envelope is bound to its own id and
 * version, so another secret's id and envelope together are internally
 * consistent and open cleanly -- under the wrong name. A compromised connector
 * can therefore answer a request for one secret with another the application
 * also holds unwrap on, and every cryptographic check passes.
 *
 * CoreLink returns the name the id really belongs to, and the application knows
 * the name it asked for; neither alone can see the substitution, so the
 * comparison happens in the client.
 */
class WrongSecret extends Error {
  constructor(message) {
    super(message);
    this.name = 'WrongSecret';
  }
}

/** The additional authenticated data for a secret and version. */
function secretAad(secretId, version) {
  return Buffer.from(`${AAD_PREFIX}|${secretId}|${version}`, 'utf8');
}

/**
 * Open a sealed envelope and return the plaintext as a Buffer.
 *
 * dek is the key CoreLink returned for this secret. secretId and version are the
 * authorized context the AAD is rebuilt from, not values read out of the
 * envelope.
 */
function openEnvelope(envelopeB64, dek, secretId, version) {
  let body;
  try {
    body = JSON.parse(Buffer.from(envelopeB64, 'base64').toString('utf8'));
  } catch (err) {
    throw new CorruptEnvelope(`the envelope is not an envelope: ${err.message}`);
  }

  const expected = secretAad(secretId, version);
  // An envelope carrying no AAD was written before binding existed, and opens
  // with none. That is not a rollback -- the thing this must never be confused
  // with -- and the platform skips its own compare for these too. Setting the
  // expected value here instead would break every secret written before the
  // binding did, which is all of them at a given installation until the first
  // rotation.
  const unbound = !body.aad;
  if (body.aad) {
    const stored = Buffer.from(body.aad, 'base64');
    if (!stored.equals(expected)) {
      // Sealed for a different secret or version. Named as stale rather than
      // corrupt: the likely cause is a connector holding an old envelope, and
      // the recovery is to ask it again.
      throw new StaleEnvelope(
        `the envelope is bound to something other than ${secretId} version ${version}`
      );
    }
  }

  if (!body.encrypted_data || !body.nonce) {
    throw new CorruptEnvelope('the envelope is missing its ciphertext');
  }
  const sealed = Buffer.from(body.encrypted_data, 'base64');
  const nonce = Buffer.from(body.nonce, 'base64');
  if (sealed.length <= TAG_BYTES) {
    throw new CorruptEnvelope('the envelope carries no ciphertext');
  }

  // Go appends the tag; Node takes it separately.
  const ciphertext = sealed.subarray(0, sealed.length - TAG_BYTES);
  const tag = sealed.subarray(sealed.length - TAG_BYTES);

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', dek, nonce);
    if (!unbound) decipher.setAAD(expected);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    // The key was for the version the envelope claims and the binding matched,
    // so this is not a rollback: something has been altered.
    throw new CorruptEnvelope('the envelope did not open with the key for its own version');
  }
}

/**
 * The secret's value from a stored record.
 *
 * What is sealed is the record, which wraps the value. Older records may be the
 * bare value, so that is the fallback rather than an error.
 */
function valueFrom(plaintext) {
  const text = plaintext.toString('utf8');
  try {
    const record = JSON.parse(text);
    if (record && typeof record === 'object' && record.value) return record.value;
  } catch {
    // Not a record; the bare value.
  }
  return text;
}

/**
 * Escape a secret name for a URL, keeping the slashes that are part of it.
 *
 * A "." or ".." segment is refused rather than escaped. Clients and servers
 * normalise dot segments in a path, so such a name would be asked for as a
 * different one, and no secret can be named that way: the platform's own path
 * validation rejects "..".
 */
function envelopePath(name) {
  const trimmed = String(name).replace(/^\/+|\/+$/g, '');
  if (!trimmed) throw new Error('a secret name is required');
  const parts = trimmed.split('/');
  for (const part of parts) {
    if (!part) throw new Error(`${name} has an empty path segment`);
    if (part === '.' || part === '..') throw new Error(`${name} is not a secret name`);
  }
  return parts.map((p) => encodeURIComponent(p)).join('/');
}

/**
 * Parse a TLS bundle out of a secret's value.
 *
 * The value is one level deeper than it looks: the stored record wraps it, and
 * for a certificate the value is itself JSON. valueFrom unwraps the record, and
 * this parses what came out.
 *
 * Both halves are required. A secret that merely happens to be JSON would
 * otherwise come back as a certificate with empty fields, which is worse than an
 * error because it fails later and somewhere else.
 */
function certificateFrom(value) {
  let bundle;
  try {
    bundle = JSON.parse(value);
  } catch (err) {
    throw new Error(`not a TLS certificate bundle: ${err.message}`);
  }
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    throw new Error('not a TLS certificate bundle');
  }
  const certificate = bundle.certificate || '';
  const privateKey = bundle.private_key || '';
  if (!certificate || !privateKey) {
    throw new Error('carries no certificate and key');
  }
  return { certificate, privateKey, caChain: bundle.ca_chain || '' };
}

module.exports = {
  StaleEnvelope,
  CorruptEnvelope,
  WrongSecret,
  secretAad,
  openEnvelope,
  valueFrom,
  certificateFrom,
  envelopePath,
};
