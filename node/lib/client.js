'use strict';

const fs = require('node:fs');
const { request } = require('./http');
const { computeFingerprint } = require('./fingerprint');
const sealed = require('./sealed');
const leases = require('./leases');

const K8S_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token';
const HEARTBEAT_MS = 50 * 60 * 1000; // platform sessions last an hour
const APPROVAL_POLL_MS = 5000;
const APPROVAL_ATTEMPTS = 60; // 5 minutes

/**
 * Client for the Tech Blend Transit API.
 *
 * Authentication is NHI (Non-Human Identity) passwordless attestation. Call
 * bootstrap() before any other call; the client then renews its session in the
 * background every 50 minutes.
 */
class TransitClient {
  /**
   * @param {object} options
   * @param {string} options.transitUrl   base URL of the transit agent
   * @param {string} [options.platformUrl] base URL of the platform (NHI connect/heartbeat)
   * @param {string} [options.nhiId]       NHI identity for attestation
   * @param {string} [options.caCertFile]  path to a CA bundle for TLS pinning
   */
  constructor(options = {}) {
    const { transitUrl, platformUrl = '', nhiId = '', caCertFile = '', attest } = options;
    if (!transitUrl) throw new Error('transitUrl is required');

    this._url = transitUrl.replace(/\/+$/, '');
    this._platformUrl = platformUrl ? platformUrl.replace(/\/+$/, '') : '';
    this._nhiId = nhiId;
    // attest supplies the attestation to present, instead of the SDK detecting
    // one: a function returning {type, evidence}.
    //
    // For a workload that runs nowhere the SDK can recognise -- a product with
    // no connector, no pod and no instance identity document -- and federates to
    // its own OIDC issuer instead. Return {type: 'oidc', evidence: <token>}.
    //
    // A function rather than a string, because these tokens are short lived by
    // design: it is called on every connect and reconnect, so a session that
    // drops at three in the morning re-mints rather than replaying something
    // that expired hours ago.
    //
    // Nothing it returns authorises anything: CoreLink verifies the token
    // against the issuer pinned to this identity, and the grant decides what the
    // identity may do.
    this._attest = attest;
    this._sessionId = null;
    this._heartbeatTimer = null;
    this._closed = false;
    this._ca = caCertFile ? fs.readFileSync(caCertFile) : undefined;
  }

  /** Connect via NHI attestation and start the background heartbeat. */
  async bootstrap() {
    await this._nhiConnect();
  }

  /**
   * The secrets available to this client.
   *
   * A connector serves envelopes by name and offers no way to enumerate them:
   * an application asks for what it was configured to ask for. There is nothing
   * to list, so this rejects rather than returning an empty array that would
   * read as "no secrets".
   *
   * @returns {Promise<Array<{name: string, value: string}>>}
   */
  async listSecrets() {
    throw new Error(
      'a connector serves envelopes by name and offers no listing; ' +
        'name the secrets this application needs'
    );
  }

  /**
   * The value of a single secret by name.
   *
   * Takes the sealed envelope from the connector, asks CoreLink for the key to
   * that secret, and opens it here. The connector cannot read what it served and
   * CoreLink never sees the plaintext, so the value exists in this process and
   * nowhere else.
   *
   * It used to ask the connector for plaintext. That endpoint answers 410 now,
   * and this goes the sealed way instead, so an application already calling
   * getSecret needs no change.
   *
   * @returns {Promise<string>}
   */
  async getSecret(name) {
    return this.getSecretSealed(name);
  }

  /**
   * Open a secret from a sealed envelope. See getSecret.
   *
   * Requires secrets:unwrap on the secret, and a connector granted
   * secrets:cache on it.
   *
   * A stale envelope is retried once with the connector told to refetch, which
   * is the case this exists for: the connector holding a version CoreLink has
   * since rotated past. A second failure of the same kind is reported as stale
   * rather than retried forever.
   *
   * @returns {Promise<string>}
   */
  async getSecretSealed(name) {
    if (!this._url) throw new Error('getSecretSealed needs a connector; set transitUrl');
    if (!this._platformUrl || !this._nhiId) {
      throw new Error('getSecretSealed needs an identity; set platformUrl and nhiId');
    }
    try {
      return await this._openSealed(name, false);
    } catch (err) {
      if (err instanceof sealed.StaleEnvelope) return this._openSealed(name, true);
      throw err;
    }
  }

  /**
   * A TLS bundle, fetched through the sealed path and parsed here.
   *
   * A certificate is a secret whose value is a bundle, so it needs no delivery
   * mechanism of its own: the same envelope, the same key, the same binding. The
   * connector used to serve a bundle's parts from plaintext it held in memory,
   * which was the last readable thing in that process.
   *
   * The private key exists in this process and nowhere else.
   *
   * @returns {Promise<{certificate: string, privateKey: string, caChain: string}>}
   */
  async getCertificate(name) {
    return sealed.certificateFrom(await this.getSecretSealed(name));
  }

  /**
   * Ask CoreLink for a credential leased for a while.
   *
   * resourceType is one of leases.RESOURCE_SECRET, RESOURCE_DATABASE or
   * RESOURCE_CLOUD. A zero ttlSeconds takes CoreLink's default; asking for longer
   * than policy allows is CoreLink's decision, and the lease says what was
   * actually granted.
   *
   * @returns {Promise<import('./leases').Lease>}
   */
  async requestCredential(resourceType, resourceId, ttlSeconds = 0) {
    if (!this._platformUrl || !this._nhiId) {
      throw new Error('requestCredential needs an identity; set platformUrl and nhiId');
    }
    if (!leases.RESOURCE_TYPES.includes(resourceType)) {
      throw new Error(
        `resource type ${resourceType} is not one of ${leases.RESOURCE_TYPES.join(', ')}`
      );
    }
    if (!resourceId) throw new Error('a resource id is required');

    const body = { resource_type: resourceType, resource_id: resourceId };
    if (ttlSeconds > 0) body.ttl_seconds = Math.floor(ttlSeconds);

    const res = await this._platformRequest('POST', '/api/v1/nhi-agent/credentials', body);
    if (res.status !== 200) {
      throw new Error(`CoreLink refused to issue a credential (status ${res.status})`);
    }
    const lease = leases.leaseFrom(res.json());
    if (!lease.id) throw new Error('CoreLink issued a credential with no lease id');
    return lease;
  }

  /**
   * Extend a lease, or say why it will not extend.
   *
   * Throws LeaseExhausted at the credential's maximum lifetime. That is not a
   * failure to retry: request a new credential.
   */
  async renewLease(leaseId) {
    if (!leaseId) throw new Error('a lease id is required');
    const res = await this._platformRequest(
      'POST',
      `/api/v1/nhi-agent/leases/${encodeURIComponent(leaseId)}/renew`
    );
    if (res.status === 200) return;
    if (res.status === 422) throw new leases.LeaseExhausted('this credential cannot be extended further');
    if (res.status === 404) throw new leases.LeaseNotFound('lease not found');
    throw new Error(`renewing the lease failed (status ${res.status})`);
  }

  /**
   * Hand a credential back before it expires.
   *
   * Worth doing rather than letting it lapse: it stops working at once, which
   * closes the window between finishing with it and its expiry. A lease already
   * gone is not an error, because the caller's intent is satisfied either way.
   */
  async releaseCredential(leaseId) {
    if (!leaseId) throw new Error('a lease id is required');
    const res = await this._platformRequest(
      'DELETE',
      `/api/v1/nhi-agent/credentials/${encodeURIComponent(leaseId)}`
    );
    if ([200, 204, 404].includes(res.status)) return;
    throw new Error(`releasing the credential failed (status ${res.status})`);
  }

  /**
   * The identity's active leases, without their credentials.
   *
   * The material is handed over once, at issue. Useful after a restart: a process
   * that lost track of what it holds can find out rather than requesting more and
   * leaving the old ones to expire.
   *
   * @returns {Promise<Array<import('./leases').Lease>>}
   */
  async listLeases() {
    const res = await this._platformRequest('GET', '/api/v1/nhi-agent/credentials');
    if (res.status !== 200) throw new Error(`listing leases failed (status ${res.status})`);
    // "data" is the key CoreLink sends.
    return (res.json().data || []).map(leases.leaseFrom);
  }

  /**
   * Renew a lease in the background for as long as it is in use.
   *
   * Renews at half the remaining life, so a missed attempt has another before the
   * credential lapses, and stops when CoreLink refuses. onExpiry is called once
   * with the reason, which is how an application learns it must request a new
   * credential.
   *
   * Returns a function that stops the renewals. It does not release the lease;
   * releaseCredential does that.
   */
  keepAlive(lease, onExpiry) {
    let stopped = false;
    let timer = null;
    const term = leases.termMs(lease);

    const floor = this._keepAliveFloorMs || 1000;
    const schedule = (remaining) => {
      if (stopped) return;
      const wait = Math.max(remaining / 2, floor);
      timer = setTimeout(async () => {
        if (stopped) return;
        try {
          await this.renewLease(lease.id);
        } catch (err) {
          if (onExpiry) onExpiry(err);
          return;
        }
        schedule(term);
      }, wait);
      if (timer.unref) timer.unref();
    };
    schedule(lease.remainingMs() || term);

    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }

  /** Send an authenticated request to CoreLink. */
  async _platformRequest(method, path, body) {
    if (!this._sessionId) throw new Error('no CoreLink session; call bootstrap() first');
    return request(`${this._platformUrl}${path}`, {
      method,
      headers: { 'X-NHI-Session': this._sessionId },
      body,
      ca: this._ca,
    });
  }

  /** One attempt at fetching, unwrapping and opening. */
  async _openSealed(name, refresh) {
    const envelope = await this._fetchEnvelope(name, refresh);
    const { dek, version, name: authoritativeName } = await this._unwrapDek(envelope.secret_id);

    // The name CoreLink says this id belongs to must be the name that was asked
    // for. See sealed.WrongSecret: the AAD binds an envelope to its own id and
    // version, so a substituted secret opens cleanly and only this catches it.
    const asked = String(name).replace(/^\/+|\/+$/g, '');
    if (authoritativeName && authoritativeName !== asked) {
      throw new sealed.WrongSecret(
        `asked for ${asked} and the connector answered with ${authoritativeName}`
      );
    }

    // The key belongs to whatever version CoreLink currently holds. A different
    // one means this envelope is behind, and saying so is clearer than letting
    // the AEAD fail for an unexplained reason.
    if (version !== envelope.version) {
      throw new sealed.StaleEnvelope(
        `the connector served version ${envelope.version}, CoreLink is on ${version}`
      );
    }

    const plaintext = sealed.openEnvelope(envelope.envelope, dek, envelope.secret_id, version);
    try {
      return sealed.valueFrom(plaintext);
    } finally {
      dek.fill(0);
      plaintext.fill(0);
    }
  }

  /**
   * Take the sealed envelope from the connector.
   *
   * Unauthenticated, because the connector has nothing to decide: what it serves
   * cannot be opened without a grant CoreLink checks.
   */
  async _fetchEnvelope(name, refresh) {
    let url = `${this._url}/v1/envelopes/${sealed.envelopePath(name)}`;
    if (refresh) url += '?refresh=1';
    const res = await request(url, { ca: this._ca });
    if (res.status !== 200) {
      throw new Error(
        `the connector has no envelope for ${name} (status ${res.status}: ${String(res.body).slice(0, 200).trim()})`
      );
    }
    const envelope = res.json();
    if (!envelope.envelope || !envelope.secret_id) {
      throw new Error(`the connector served an incomplete envelope for ${name}`);
    }
    return envelope;
  }

  /**
   * Ask CoreLink for the key to one secret.
   *
   * CoreLink unwraps its own copy, so nothing this process holds takes part: an
   * application handed somebody else's ciphertext cannot have it opened by
   * naming a secret it is entitled to.
   */
  async _unwrapDek(secretId) {
    if (!this._sessionId) throw new Error('no CoreLink session; call bootstrap() first');
    const res = await request(
      `${this._platformUrl}/api/v1/nhi-agent/secrets/${encodeURIComponent(secretId)}/unwrap`,
      { method: 'POST', headers: { 'X-NHI-Session': this._sessionId }, ca: this._ca }
    );
    if (res.status !== 200) {
      throw new Error(
        `CoreLink refused to unwrap (status ${res.status}: ${String(res.body).slice(0, 200).trim()})`
      );
    }
    const body = res.json();
    const dek = Buffer.from(body.dek || '', 'base64');
    if (dek.length === 0) throw new Error('CoreLink returned no key');
    // The name is CoreLink's answer to "which secret is this id?", which only it
    // can give. The caller compares it against what it asked for.
    return { dek, version: body.version, name: body.name || '' };
  }

  /** @returns {Promise<Array<{name: string, file_name: string, content: string}>>} */
  async listConfigs() {
    const res = await this._authedGet(`${this._url}/v1/configs`);
    this._ensureOk(res, 'list configs');
    return res.json().configs || [];
  }

  /** @returns {Promise<string>} */
  async getConfig(name) {
    const res = await this._authedGet(`${this._url}/v1/configs/${encodeURIComponent(name)}`);
    this._ensureOk(res, `get config ${name}`);
    return res.json().content || '';
  }

  /** Stop the heartbeat and release the NHI session. Safe to call twice. */
  async close() {
    this._closed = true;
    if (this._heartbeatTimer) {
      clearTimeout(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
    await this._nhiDisconnect();
  }

  // ---------------------------------------------------------------------------
  // NHI session management
  // ---------------------------------------------------------------------------

  /**
   * Detect the runtime and return attestation evidence.
   *
   * Kubernetes first (the kubelet projects a service account token), then a
   * host fingerprint. The returned evidence MUST NOT be logged -- under
   * Kubernetes it is a service account JWT.
   *
   * @returns {{type: string, evidence: string}}
   */
  _collectAttestation() {
    // The caller first: a workload federating to its own issuer knows how to
    // get its token and the SDK does not; a pod or a host is the other way
    // round.
    if (this._attest) return this._attest();
    return this._detectAttestation();
  }

  /** @returns {{type: string, evidence: string}} */
  _detectAttestation() {
    try {
      const token = fs.readFileSync(K8S_TOKEN_PATH, 'utf8').trim();
      if (token) return { type: 'kubernetes', evidence: token };
    } catch {
      // not running under Kubernetes
    }
    const { fingerprint } = computeFingerprint(this._nhiId);
    return { type: 'host', evidence: fingerprint };
  }

  async _nhiConnect() {
    const { type, evidence } = this._collectAttestation();
    const res = await request(`${this._platformUrl}/api/v1/nhi-agent/connect`, {
      method: 'POST',
      body: { nhi_id: this._nhiId, attestation: { type, evidence } },
      ca: this._ca,
    });

    if (res.status === 403) throw new Error('NHI identity verification failed');
    this._ensureOk(res, 'NHI connect');

    const data = res.json();
    const sessionId = data.session_id;
    if (!sessionId) throw new Error('NHI connect returned no session_id');

    // A missing status means "active" -- older platforms omit the field.
    const status = data.status || 'active';
    if (status === 'pending_approval') {
      await this._pollApproval(sessionId);
    } else if (status !== 'active') {
      throw new Error(`NHI connect returned unexpected status: ${status}`);
    }

    this._sessionId = sessionId;
    this._scheduleHeartbeat();
  }

  /** Poll until an admin approves or rejects, or five minutes elapse. */
  async _pollApproval(sessionId) {
    const url = `${this._platformUrl}/api/v1/nhi-agent/connect/${sessionId}/status`;
    for (let i = 0; i < APPROVAL_ATTEMPTS; i++) {
      await sleep(APPROVAL_POLL_MS);
      let res;
      try {
        res = await request(url, { ca: this._ca });
      } catch {
        continue; // transient; keep polling
      }
      if (!res.ok) continue;
      let status;
      try {
        status = res.json().status;
      } catch {
        continue;
      }
      if (status === 'active') return;
      if (status === 'rejected') throw new Error('Connect request rejected by admin');
    }
    throw new Error('Approval timeout (5 minutes)');
  }

  async _nhiHeartbeat() {
    if (this._closed) return;
    const { type, evidence } = this._collectAttestation();
    try {
      const res = await request(`${this._platformUrl}/api/v1/nhi-agent/heartbeat`, {
        method: 'POST',
        headers: this._authHeader(),
        body: { attestation: { type, evidence } },
        ca: this._ca,
      });
      // The platform rejects a heartbeat whose evidence no longer matches the
      // session, which is expected after a host change -- reconnect rather than
      // fail the process.
      if (res.status === 401 || res.status === 403) {
        await this._nhiConnect();
        return;
      }
      this._ensureOk(res, 'NHI heartbeat');
    } catch {
      try {
        await this._nhiConnect();
        return;
      } catch {
        // Leave the session as-is; the next heartbeat retries.
      }
    }
    this._scheduleHeartbeat();
  }

  _scheduleHeartbeat() {
    if (this._heartbeatTimer) clearTimeout(this._heartbeatTimer);
    if (this._closed) return;
    this._heartbeatTimer = setTimeout(() => {
      this._nhiHeartbeat().catch(() => {});
    }, HEARTBEAT_MS);
    // Do not hold the event loop open on the heartbeat alone.
    if (typeof this._heartbeatTimer.unref === 'function') this._heartbeatTimer.unref();
  }

  async _nhiDisconnect() {
    if (!this._sessionId) return;
    try {
      await request(`${this._platformUrl}/api/v1/nhi-agent/disconnect`, {
        method: 'POST',
        headers: this._authHeader(),
        timeout: 5000,
        ca: this._ca,
      });
    } catch {
      // best effort -- the session expires on its own
    }
    this._sessionId = null;
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  _authHeader() {
    return this._sessionId ? { 'X-NHI-Session': this._sessionId } : {};
  }

  /** GET with session auth; on 401 reconnect and retry exactly once. */
  async _authedGet(url) {
    const res = await request(url, { headers: this._authHeader(), ca: this._ca });
    if (res.status !== 401) return res;
    try {
      await this._nhiConnect();
    } catch {
      return res; // surface the original 401
    }
    return request(url, { headers: this._authHeader(), ca: this._ca });
  }

  /** Throw with status and a short body excerpt, never the request payload. */
  _ensureOk(res, what) {
    if (res.ok) return;
    const excerpt = (res.text || '').slice(0, 200);
    throw new Error(`${what} failed: HTTP ${res.status}${excerpt ? ` -- ${excerpt}` : ''}`);
  }
}

function sleep(ms) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === 'function') t.unref();
  });
}

module.exports = { TransitClient };
