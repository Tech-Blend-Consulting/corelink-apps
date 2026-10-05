'use strict';

/**
 * Leased credentials: request, keep alive while in use, hand back.
 *
 * The other half of what a short-lived credential needs. A secret that rotates is
 * followed by re-reading it; a leased credential expires, and the holder is the
 * only party that knows it is still needed.
 *
 * Renewal bounds itself: CoreLink refuses past the credential's maximum lifetime,
 * so keeping one alive for as long as it is used is not the same as keeping it
 * forever -- which is why keepAlive is safe to run in the background, and why it
 * stops rather than retrying when it is refused.
 *
 * The wire shapes here were verified against a running CoreLink rather than read
 * off the handler: the lease listing is wrapped in `data` (not `leases`) and the
 * credential is a string (not an object). Both were guessed wrong first.
 *
 * See docs/secret-delivery.md.
 */

/** Resource types a credential can be leased against. */
const RESOURCE_SECRET = 'secret';
const RESOURCE_DATABASE = 'database';
const RESOURCE_CLOUD = 'cloud';

const RESOURCE_TYPES = [RESOURCE_SECRET, RESOURCE_DATABASE, RESOURCE_CLOUD];

/**
 * This credential will not extend again.
 *
 * It has reached its maximum lifetime, so retrying is pointless: request a new
 * credential. Distinct from an ordinary failure because the recovery differs, and
 * CoreLink does not say which limit was reached because the action is the same.
 */
class LeaseExhausted extends Error {
  constructor(message) {
    super(message);
    this.name = 'LeaseExhausted';
  }
}

/**
 * The lease is unknown, already revoked, or belongs to another identity --
 * deliberately indistinguishable, so a caller learns nothing about leases that
 * are not its own.
 */
class LeaseNotFound extends Error {
  constructor(message) {
    super(message);
    this.name = 'LeaseNotFound';
  }
}

/** A credential and the terms it was issued under. */
class Lease {
  constructor({ id, credential = '', expiresAt = null, issuedAt = null }) {
    this.id = id;
    this.credential = credential;
    this.expiresAt = expiresAt;
    this.issuedAt = issuedAt;
  }

  /** How long this lease has left, in milliseconds, as last known. */
  remainingMs() {
    if (!this.expiresAt) return 0;
    const ms = new Date(this.expiresAt).getTime() - Date.now();
    return Number.isFinite(ms) && ms > 0 ? ms : 0;
  }

  /**
   * Redacts the credential.
   *
   * A lease is logged while tracing its lifecycle far more often than a secret
   * is, so its default rendering must not be where the credential escapes.
   */
  toJSON() {
    return { id: this.id, expiresAt: this.expiresAt, credential: '<redacted>' };
  }

  toString() {
    return `Lease { id: ${this.id}, expiresAt: ${this.expiresAt}, credential: <redacted> }`;
  }
}

/** Build a Lease from either the issue response or a listing row. */
function leaseFrom(payload) {
  return new Lease({
    id: payload.lease_id || payload.id || '',
    credential: payload.credential || '',
    expiresAt: payload.expires_at || null,
    issuedAt: payload.issued_at || null,
  });
}

/**
 * How long the lease was issued for, in milliseconds.
 *
 * CoreLink reports an expiry on issue and not on renewal, so after the first
 * renewal there is nothing to measure against and the original term is what the
 * next wait is based on.
 */
function termMs(lease, fallback = 60000) {
  if (!lease.issuedAt || !lease.expiresAt) return fallback;
  const term = new Date(lease.expiresAt).getTime() - new Date(lease.issuedAt).getTime();
  return Number.isFinite(term) && term > 0 ? term : fallback;
}

module.exports = {
  RESOURCE_SECRET,
  RESOURCE_DATABASE,
  RESOURCE_CLOUD,
  RESOURCE_TYPES,
  LeaseExhausted,
  LeaseNotFound,
  Lease,
  leaseFrom,
  termMs,
};
