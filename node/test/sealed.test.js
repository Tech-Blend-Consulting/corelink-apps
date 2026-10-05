'use strict';

// The sealed envelope, opened against a fixture the platform produced.
//
// The fixture comes from internal/crypto, which is what CoreLink stores and what
// the unwrap endpoint returns, so this checks agreement with the platform rather
// than agreement with itself.
//
// Regenerate: go test ./internal/crypto/ -run TestSDKFixture -update
// Run:        node --test sdk/node/test/

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const sealed = require('../lib/sealed');

const fx = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'testdata', 'sealed_envelope.json'), 'utf8')
);
const dek = Buffer.from(fx.dek, 'base64');

test("the AAD matches the platform's", () => {
  // One wire format shared with crypto.SecretAAD. If this drifts, nothing
  // opens, so it is checked against bytes the platform wrote.
  assert.deepStrictEqual(
    sealed.secretAad(fx.secret_id, fx.version),
    Buffer.from(fx.aad, 'base64')
  );
});

test('it opens what the platform sealed', () => {
  const plaintext = sealed.openEnvelope(fx.envelope, dek, fx.secret_id, fx.version);
  assert.strictEqual(plaintext.toString('utf8'), fx.expected_plaintext);
  assert.strictEqual(sealed.valueFrom(plaintext), fx.expected_value);
});

test('the wrong version does not open it', () => {
  // What makes a stale cached envelope fail closed rather than being served as
  // though it were current.
  assert.throws(
    () => sealed.openEnvelope(fx.envelope, dek, fx.secret_id, fx.version + 1),
    sealed.StaleEnvelope
  );
});

test('a false secret id does not open it', () => {
  // The case authorization cannot catch: the caller may hold unwrap on both
  // secrets, so only the binding can stop this.
  assert.throws(
    () => sealed.openEnvelope(fx.envelope, dek, '00000000-0000-0000-0000-000000000000', fx.version),
    sealed.StaleEnvelope
  );
});

test('another key does not open it', () => {
  assert.throws(
    () => sealed.openEnvelope(fx.envelope, Buffer.alloc(32), fx.secret_id, fx.version),
    sealed.CorruptEnvelope
  );
});

test('altered ciphertext is corrupt, not stale', () => {
  // Refetching cannot repair this, so it must not be reported as something a
  // refetch would fix.
  const body = JSON.parse(Buffer.from(fx.envelope, 'base64').toString('utf8'));
  const data = Buffer.from(body.encrypted_data, 'base64');
  data[0] ^= 0xff;
  body.encrypted_data = data.toString('base64');
  const altered = Buffer.from(JSON.stringify(body), 'utf8').toString('base64');

  assert.throws(
    () => sealed.openEnvelope(altered, dek, fx.secret_id, fx.version),
    sealed.CorruptEnvelope
  );
});

test('envelopePath keeps slashes and refuses dot segments', () => {
  assert.strictEqual(sealed.envelopePath('production/dbone'), 'production/dbone');
  assert.strictEqual(sealed.envelopePath('/production/dbone/'), 'production/dbone');
  assert.strictEqual(sealed.envelopePath('prod/db one'), 'prod/db%20one');
  for (const bad of ['prod/../etc/passwd', 'prod/.', '..', 'prod//dbone', '', '/']) {
    assert.throws(() => sealed.envelopePath(bad), undefined, `${bad} should be refused`);
  }
});

// A certificate comes back one level deeper than a password.
//
// The stored record wraps the value, and for a certificate the value is itself
// JSON. An SDK that returned the record rather than its value would look correct
// on a password and produce an empty certificate here, so this runs the whole
// local chain against a bundle the platform sealed.
const certFx = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'testdata', 'sealed_certificate.json'), 'utf8')
);

test('the chain produces the bundle the platform sealed', () => {
  const certDek = Buffer.from(certFx.dek, 'base64');
  const plaintext = sealed.openEnvelope(certFx.envelope, certDek, certFx.secret_id, certFx.version);
  const value = sealed.valueFrom(plaintext);
  assert.strictEqual(value, certFx.expected_value);

  const cert = sealed.certificateFrom(value);
  assert.ok(cert.certificate.includes('BEGIN CERTIFICATE'), cert.certificate);
  assert.ok(cert.privateKey.includes('BEGIN PRIVATE KEY'), cert.privateKey);
  assert.ok(cert.caChain.includes('BEGIN CERTIFICATE'), cert.caChain);
});

test('a secret that is not a bundle is refused', () => {
  // An empty certificate returned as success would fail later and somewhere
  // else.
  for (const bad of ['{"value":"a-password"}', 'a-bare-password', '{}',
                     '{"certificate":"c"}', '{"private_key":"k"}', '[]']) {
    assert.throws(() => sealed.certificateFrom(bad), undefined, `${bad} should be refused`);
  }
});

// An envelope written before binding existed carries no AAD, and opens.
//
// Not a rollback -- the thing this must never be confused with. The platform skips
// its own compare for these, so an SDK that insisted on the expected AAD would
// call every pre-binding secret corrupt. All twenty of production's versions were
// unbound when this was measured, so that SDK could not read a single real secret.
const legacy = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'testdata', 'sealed_legacy_no_aad.json'), 'utf8')
);

test('a pre-binding envelope opens and is not called corrupt', () => {
  const plaintext = sealed.openEnvelope(
    legacy.envelope, Buffer.from(legacy.dek, 'base64'), legacy.secret_id, legacy.version);
  assert.strictEqual(sealed.valueFrom(plaintext), legacy.expected_value);
});

test('a pre-binding envelope still needs the right key', () => {
  // Unbound does not mean unchecked.
  assert.throws(
    () => sealed.openEnvelope(
      legacy.envelope, Buffer.alloc(32), legacy.secret_id, legacy.version),
    (err) => err instanceof sealed.CorruptEnvelope
  );
});
