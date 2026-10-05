'use strict';

// The deployment file reader, against the cases every SDK shares.
//
// Six hand-written readers drift unless one thing pins them.
// sdk/testdata/deployment_cases.json is that thing: the accepted files with
// their expected result, and the rejected files that must be refused rather than
// read as something their author did not write.
//
// Run: node --test sdk/node/test/deployment.test.js

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const deployment = require('../lib/deployment');

const CASES = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'testdata', 'deployment_cases.json'), 'utf8')
);

// Run the whole load, so the shared cases exercise what an application calls.
function parseText(text) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deployment-'));
  try {
    const p = path.join(dir, 'secrets.yaml');
    fs.writeFileSync(p, text);
    return deployment.loadDeployment(p);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('the shared cases: accepted', () => {
  assert.ok(CASES.accepted.length > 0);
  for (const c of CASES.accepted) {
    const d = parseText(c.text);
    assert.strictEqual(d.nhiId, c.nhiId, `${c.name}: nhiId`);
    assert.strictEqual(d.serviceAccount, c.serviceAccount, `${c.name}: serviceAccount`);
    assert.deepStrictEqual(d.secrets, c.secrets, `${c.name}: secrets`);
  }
});

test('the shared cases: rejected', () => {
  assert.ok(CASES.rejected.length > 0);
  for (const c of CASES.rejected) {
    assert.throws(
      () => parseText(c.text),
      (err) => err instanceof deployment.DeploymentError,
      `${c.name} was accepted; it should be refused rather than read as something ` +
        'its author did not write'
    );
  }
});

test('a missing file is not an error for the optional loader', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deployment-'));
  try {
    assert.strictEqual(deployment.loadDeploymentIfPresent(path.join(dir, 'absent.yaml')), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('but a file that does not parse still is', () => {
  // "No file" and "a file I could not read" are different, and running the
  // application on a configuration nobody wrote is the wrong recovery.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deployment-'));
  try {
    const p = path.join(dir, 'broken.yaml');
    fs.writeFileSync(p, 'nhiId: a\nsecrets: [one]\n');
    assert.throws(() => deployment.loadDeploymentIfPresent(p));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the environment overrides the path', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deployment-'));
  try {
    const p = path.join(dir, 'elsewhere.yaml');
    fs.writeFileSync(p, 'nhiId: abc\nsecrets: production/one\n');
    process.env[deployment.DEPLOYMENT_PATH_ENV] = p;
    assert.strictEqual(deployment.loadDeployment().path, p);
  } finally {
    delete process.env[deployment.DEPLOYMENT_PATH_ENV];
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The ServiceAccount check only speaks when it can see a disagreement.
test('no serviceAccount named: no opinion', () => {
  new deployment.Deployment({ nhiId: 'a', secrets: ['one'] }).verifyServiceAccount();
});

test('no projected token: no opinion', () => {
  // Not running under Kubernetes, which is the ordinary case for a host.
  new deployment.Deployment({
    nhiId: 'a',
    serviceAccount: 'orders',
    secrets: ['one'],
  }).verifyServiceAccount();
});

test('it reads the name out of a projected token', () => {
  const payload = Buffer.from(
    JSON.stringify({
      'kubernetes.io': { serviceaccount: { name: 'orders' } },
      sub: 'system:serviceaccount:prod:orders',
    })
  ).toString('base64url');
  assert.strictEqual(deployment.serviceAccountFromToken(`x.${payload}.y`), 'orders');
});

test('it falls back to the subject', () => {
  const payload = Buffer.from(
    JSON.stringify({ sub: 'system:serviceaccount:prod:billing' })
  ).toString('base64url');
  assert.strictEqual(deployment.serviceAccountFromToken(`x.${payload}.y`), 'billing');
});

test('junk is no opinion', () => {
  assert.strictEqual(deployment.serviceAccountFromToken('not-a-token'), null);
});
