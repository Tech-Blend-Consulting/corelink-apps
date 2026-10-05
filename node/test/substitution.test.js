'use strict';

// A connector that answers with a different secret than the one asked for.
//
// The attack the AAD does not cover. An envelope is bound to its own id and
// version, so a substituted secret is internally consistent: the key CoreLink
// returns for that id opens it, the version matches, the tag verifies. Every
// cryptographic check passes and the application gets a value it did not ask for.
//
// The fixture is a real one, produced by the platform's own crypto, served under
// the wrong name. Nothing is forged -- that is the point. The only thing that can
// catch it is comparing the name CoreLink says the id belongs to against the name
// the application asked for.
//
// Run: node --test sdk/node/test/substitution.test.js

const assert = require('node:assert');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { test } = require('node:test');

const { TransitClient } = require('../lib/client');
const sealed = require('../lib/sealed');

const FX = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'testdata', 'sealed_envelope.json'), 'utf8')
);

// The name the fixture's secret really has, and the name the application asks
// for. The connector answers the second with the first.
const REAL_NAME = 'production/other-secret';
const ASKED_NAME = 'production/dbone';

// One server standing in for both the connector and CoreLink.
function startFake(authoritativeName) {
  const server = http.createServer((req, res) => {
    const send = (status, payload) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    };

    // The connector: asked for one name, answers with the other secret's id and
    // envelope. A real envelope, just not the requested one.
    if (req.method === 'GET' && req.url.startsWith('/v1/envelopes/')) {
      return send(200, {
        secret_id: FX.secret_id,
        name: ASKED_NAME,
        version: FX.version,
        envelope: FX.envelope,
      });
    }

    // CoreLink: unwraps its own copy and says which name the id belongs to.
    if (req.method === 'POST' && req.url.endsWith('/unwrap')) {
      return send(200, { dek: FX.dek, version: FX.version, name: authoritativeName });
    }

    return send(404, { error: 'not found' });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const base = `http://127.0.0.1:${server.address().port}`;
      const client = new TransitClient({
        transitUrl: base,
        platformUrl: base,
        nhiId: '11111111-1111-1111-1111-111111111111',
      });
      // The session the sealed path requires; this test is about the name
      // comparison, not about how the session was obtained.
      client._sessionId = 'test-session';
      resolve({ server, client });
    });
  });
}

test('a substituted secret is refused', async () => {
  const { server, client } = await startFake(REAL_NAME);
  try {
    await assert.rejects(
      () => client.getSecretSealed(ASKED_NAME),
      (err) => {
        assert.ok(err instanceof sealed.WrongSecret, `got ${err.name}: ${err.message}`);
        // The message has to name both, or an operator cannot tell which
        // connector lied about what.
        assert.match(err.message, new RegExp(ASKED_NAME));
        assert.match(err.message, new RegExp(REAL_NAME));
        return true;
      }
    );
  } finally {
    server.close();
  }
});

test('the right secret still opens', async () => {
  // The same path with the names agreeing: proves the check refuses
  // substitution rather than refusing everything.
  const { server, client } = await startFake(ASKED_NAME);
  try {
    assert.strictEqual(await client.getSecretSealed(ASKED_NAME), FX.expected_value);
  } finally {
    server.close();
  }
});

test('no name from the platform does not refuse', async () => {
  // An older CoreLink that does not send the name yet. Refusing here would break
  // every application against it; the AAD still binds id and version.
  const { server, client } = await startFake('');
  try {
    assert.strictEqual(await client.getSecretSealed(ASKED_NAME), FX.expected_value);
  } finally {
    server.close();
  }
});
