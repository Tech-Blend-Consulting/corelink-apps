'use strict';

// The leased-credential lifecycle against a fake CoreLink.
//
// The wire shapes are the ones a live CoreLink was observed to send -- the listing
// wrapped in "data", the credential as a string -- because the Go SDK guessed both
// wrong from reading the handler and only a real call disagreed.
//
// Run: node --test sdk/node/test/leases.test.js

const assert = require('node:assert');
const http = require('node:http');
const { test } = require('node:test');

const { TransitClient } = require('../lib/client');
const leases = require('../lib/leases');

// A fake broker, started per test so counters never leak between them.
function startBroker({ renewLimit = 0 } = {}) {
  const state = { renewals: 0, released: [], requested: [] };
  const server = http.createServer((req, res) => {
    const send = (status, payload) => {
      const body = payload === undefined ? '' : JSON.stringify(payload);
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(body);
    };

    if (req.method === 'POST' && req.url === '/api/v1/nhi-agent/credentials') {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        state.requested.push(JSON.parse(raw || '{}'));
        const now = new Date();
        send(200, {
          lease_id: 'lease-1',
          credential: '{"username":"dyn_abc"}',
          issued_at: now.toISOString(),
          expires_at: new Date(now.getTime() + 900000).toISOString(),
        });
      });
      return;
    }
    if (req.method === 'POST' && req.url.endsWith('/renew')) {
      if (req.url.includes('unknown-lease')) return send(404, { error: {} });
      if (renewLimit && state.renewals >= renewLimit) return send(422, { error: {} });
      state.renewals++;
      return send(200, { renewed: true });
    }
    if (req.method === 'DELETE' && req.url.startsWith('/api/v1/nhi-agent/credentials/')) {
      state.released.push(req.url.split('/').pop());
      return send(204);
    }
    if (req.method === 'GET' && req.url === '/api/v1/nhi-agent/credentials') {
      // "data", not "leases".
      return send(200, { data: [{ id: 'lease-1', expires_at: new Date().toISOString() }] });
    }
    send(404, {});
  });
  server.listen(0);
  server.unref();
  return { server, state, url: () => `http://127.0.0.1:${server.address().port}` };
}

function clientFor(broker) {
  const c = new TransitClient({ transitUrl: 'http://127.0.0.1:1', platformUrl: broker.url(), nhiId: 'nhi-1' });
  c._sessionId = 'session-in-place';
  return c;
}

test('a credential is leased with its terms, and the credential is redacted', async () => {
  const broker = startBroker();
  const c = clientFor(broker);
  try {
    const lease = await c.requestCredential(leases.RESOURCE_SECRET, 'secret-1', 300);
    assert.strictEqual(lease.id, 'lease-1');
    assert.match(lease.credential, /dyn_abc/);
    assert.ok(lease.expiresAt, 'no expiry means nothing can tell when to renew');
    assert.ok(lease.remainingMs() > 0);
    assert.strictEqual(broker.state.requested[0].ttl_seconds, 300);

    // A lease is logged while tracing its lifecycle; its rendering must not leak.
    assert.doesNotMatch(JSON.stringify(lease), /dyn_abc/);
    assert.doesNotMatch(String(lease), /dyn_abc/);
  } finally {
    broker.server.close();
  }
});

test('an unknown resource type is refused locally', async () => {
  const broker = startBroker();
  const c = clientFor(broker);
  try {
    await assert.rejects(() => c.requestCredential('kubernetes', 'x'));
    await assert.rejects(() => c.requestCredential(leases.RESOURCE_SECRET, ''));
    assert.strictEqual(broker.state.requested.length, 0, 'nothing should have reached CoreLink');
  } finally {
    broker.server.close();
  }
});

test('renewal tells exhausted apart from not found', async () => {
  const broker = startBroker({ renewLimit: 1 });
  const c = clientFor(broker);
  try {
    await c.renewLease('lease-1');
    assert.strictEqual(broker.state.renewals, 1);
    await assert.rejects(() => c.renewLease('lease-1'), leases.LeaseExhausted);
    await assert.rejects(() => c.renewLease('unknown-lease'), leases.LeaseNotFound);
  } finally {
    broker.server.close();
  }
});

test('release is idempotent and the listing omits the credential', async () => {
  const broker = startBroker();
  const c = clientFor(broker);
  try {
    await c.releaseCredential('lease-1');
    assert.deepStrictEqual(broker.state.released, ['lease-1']);

    const found = await c.listLeases();
    assert.strictEqual(found.length, 1);
    assert.strictEqual(found[0].id, 'lease-1');
    assert.strictEqual(found[0].credential, '',
      'a listing that returned the credential would make it re-readable for the lease life');
  } finally {
    broker.server.close();
  }
});

test('a session is required', async () => {
  const broker = startBroker();
  const c = clientFor(broker);
  c._sessionId = null;
  try {
    await assert.rejects(() => c.renewLease('lease-1'), /session/);
  } finally {
    broker.server.close();
  }
});

test('keepAlive renews then stops when refused', async () => {
  // One renewal allowed, the next refused: proves it renews, and proves it stops
  // rather than retrying something that cannot succeed.
  const broker = startBroker({ renewLimit: 1 });
  const c = clientFor(broker);
  c._keepAliveFloorMs = 20;
  try {
    const now = new Date();
    const lease = new leases.Lease({
      id: 'lease-1',
      issuedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 60).toISOString(),
    });

    const reported = [];
    const stop = c.keepAlive(lease, (err) => reported.push(err));
    try {
      const deadline = Date.now() + 3000;
      while (reported.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 20));
      }
    } finally {
      stop();
    }

    assert.strictEqual(reported.length, 1, 'onExpiry should be called exactly once');
    assert.ok(reported[0] instanceof leases.LeaseExhausted,
      `reported ${reported[0]}, want LeaseExhausted so the application re-requests`);
    assert.ok(broker.state.renewals >= 1, 'it should have renewed before being refused');
  } finally {
    broker.server.close();
  }
});
