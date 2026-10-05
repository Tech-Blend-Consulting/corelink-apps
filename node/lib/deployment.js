'use strict';

/**
 * The deployment file: what an application was configured to ask for.
 *
 *   nhiId:          11111111-2222-3333-4444-555555555555
 *   serviceAccount: orders
 *   secrets:
 *     - production/dbone
 *     - production/apikey
 *
 * It tells the SDK which identity to attest as and which secrets to ask for.
 * That is all it is.
 *
 * **Nothing in it grants anything**, and that must stay true even when somebody
 * proposes provisioning grants from it as a convenience. Anyone who can edit a
 * Deployment can add a path to this file; if that provisioned access, "edit
 * deployments" would quietly become "read any secret". The file is a request.
 * The grant on the NHI is the only answer, and CoreLink checks it on every call
 * regardless of what is written here.
 *
 * Neither value is sensitive. The NHI id is a pointer, not a credential: Connect
 * looks the identity up by the id presented and then verifies the evidence
 * against *that identity's* binding, so naming someone else's id and attesting
 * with your own ServiceAccount fails the claim match.
 *
 * **Deliberately not a YAML parser.** YAML is a large language -- anchors, flow
 * collections, multi-line scalars, implicit typing -- and most of it is ways for
 * a file to mean something other than it appears to. Three keys are needed, so
 * everything else is refused rather than guessed at. A file using a feature this
 * does not implement fails loudly instead of being read as something its author
 * did not write, which is the safe direction: this file decides which secrets an
 * application asks for.
 *
 * Pinned against the other five SDKs by sdk/testdata/deployment_cases.json.
 */

const fs = require('node:fs');

/** Where the file is looked for when no path is given. */
const DEFAULT_DEPLOYMENT_PATH = '/etc/corelink/secrets.yaml';

/** Environment variable that overrides the default path. */
const DEPLOYMENT_PATH_ENV = 'CORELINK_DEPLOYMENT_FILE';

const SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token';

/** A deployment file that could not be read as written. */
class DeploymentError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DeploymentError';
  }
}

/** A parsed deployment file. */
class Deployment {
  constructor({ nhiId = '', serviceAccount = '', secrets = [], path: p = '' } = {}) {
    this.nhiId = nhiId;
    this.serviceAccount = serviceAccount;
    this.secrets = secrets;
    this.path = p;
  }

  /**
   * Throw if the pod is not running as the ServiceAccount the file names.
   *
   * **A misconfiguration check, not a security control.** The projected token's
   * claims are read without verifying its signature, because nothing this
   * concludes is trusted: CoreLink verifies that token properly, against the
   * identity's own binding, and that is what decides whether the workload is who
   * it says. Re-deciding it here would be a second authorization path for one
   * question.
   *
   * What it is for: a Deployment whose secrets.yaml names one ServiceAccount
   * while the pod spec says another will fail at CoreLink with a claim mismatch,
   * later and somewhere less obvious.
   *
   * No name, no token, or an unreadable one: no opinion, no error.
   */
  verifyServiceAccount() {
    if (!this.serviceAccount) return;
    let token;
    try {
      token = fs.readFileSync(SA_TOKEN_PATH, 'utf8');
    } catch {
      return;
    }
    const actual = serviceAccountFromToken(token);
    if (actual === null) return;
    if (actual !== this.serviceAccount) {
      throw new DeploymentError(
        `${this.path} names serviceAccount ${this.serviceAccount} but this pod is ` +
          `running as ${actual}; the deployment file and the pod spec disagree`
      );
    }
  }
}

function resolvePath(p) {
  return p || process.env[DEPLOYMENT_PATH_ENV] || DEFAULT_DEPLOYMENT_PATH;
}

/** Read the deployment file, throwing if it is missing or unreadable. */
function loadDeployment(p) {
  const file = resolvePath(p);
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new DeploymentError(`reading the deployment file ${file}: ${err.message}`);
  }

  let d;
  try {
    d = parseDeployment(text);
  } catch (err) {
    throw new DeploymentError(`${file}: ${err.message}`);
  }
  d.path = file;

  if (!d.nhiId) {
    throw new DeploymentError(`${file}: nhiId is required; it names the identity to attest as`);
  }
  if (d.secrets.length === 0) {
    throw new DeploymentError(
      `${file}: secrets is required; an application asks for what it was configured ` +
        'to ask for rather than discovering what exists'
    );
  }
  return d;
}

/**
 * loadDeployment, except that a missing file returns null.
 *
 * A file that exists and does not parse is still an error: the difference that
 * matters is "no file" against "a file I could not read", and silently ignoring
 * the second would run the application on a configuration nobody wrote.
 */
function loadDeploymentIfPresent(p) {
  const file = resolvePath(p);
  if (!fs.existsSync(file)) return null;
  return loadDeployment(file);
}

/** Read the one shape this file has, and refuse the rest. */
function parseDeployment(text) {
  const d = new Deployment();
  const seen = new Set();
  let listKey = null;

  const lines = String(text).split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const n = i + 1;

    if (raw.includes('\t')) {
      throw new DeploymentError(`line ${n}: tabs are not allowed in indentation`);
    }

    // A comment is only a comment at the start of a line here. Stripping a
    // trailing "#" would corrupt any value that legitimately contains one.
    const trimmed = raw.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    if (trimmed.startsWith('---') || trimmed.startsWith('...')) {
      throw new DeploymentError(`line ${n}: multiple documents are not supported`);
    }
    if (trimmed.includes('&') || trimmed.includes('*')) {
      throw new DeploymentError(`line ${n}: anchors and aliases are not supported`);
    }

    // A list entry, which belongs to the key above it.
    if (trimmed.startsWith('- ') || trimmed === '-') {
      if (listKey === null) {
        throw new DeploymentError(`line ${n}: a list entry with no key above it`);
      }
      const item = scalar(trimmed.slice(1).trim(), n);
      if (item === '') throw new DeploymentError(`line ${n}: an empty list entry`);
      if (listKey !== 'secrets') {
        throw new DeploymentError(`line ${n}: ${listKey} does not take a list`);
      }
      d.secrets.push(item);
      continue;
    }

    // Anything else must be a key at the left margin. Leading whitespace is what
    // makes it indented; trailing whitespace is invisible and harmless.
    if (raw.replace(/^ +/, '') !== raw) {
      throw new DeploymentError(
        `line ${n}: unexpected indentation; this file is a flat set of keys`
      );
    }
    const colon = trimmed.indexOf(':');
    if (colon < 0) throw new DeploymentError(`line ${n}: expected "key: value"`);
    let key = trimmed.slice(0, colon);
    let value = trimmed.slice(colon + 1);
    // YAML needs a space after the colon to make this a mapping at all --
    // "nhiId:abc" is a plain scalar, not a key.
    if (value !== '' && !value.startsWith(' ')) {
      throw new DeploymentError(`line ${n}: a key needs a space after its colon`);
    }
    key = key.trim();
    value = value.trim();

    if (seen.has(key)) {
      // Two values for one key: a reader has to pick, and either choice is
      // somebody's surprise.
      throw new DeploymentError(`line ${n}: ${key} appears more than once`);
    }
    seen.add(key);
    listKey = null;

    if (key === 'nhiId' || key === 'nhiID' || key === 'nhi_id') {
      d.nhiId = scalar(value, n);
    } else if (key === 'serviceAccount' || key === 'service_account') {
      d.serviceAccount = scalar(value, n);
    } else if (key === 'secrets') {
      if (value === '') {
        // The list form; entries follow on their own lines.
        listKey = 'secrets';
        continue;
      }
      d.secrets.push(scalar(value, n));
    } else {
      // Refused rather than ignored. A typo in a key an application relies on
      // would otherwise be silence, and the application would run asking for
      // nothing.
      throw new DeploymentError(`line ${n}: unknown key ${key}`);
    }
  }

  return d;
}

/** Read one plain value, refusing the YAML forms this does not implement. */
function scalar(v, n) {
  if (v === '') return '';
  if (v.startsWith('[') || v.startsWith('{')) {
    throw new DeploymentError(
      `line ${n}: flow collections are not supported; use a "- item" list`
    );
  }
  if (v.startsWith('|') || v.startsWith('>')) {
    throw new DeploymentError(`line ${n}: multi-line scalars are not supported`);
  }
  if (v.length >= 2) {
    const first = v[0];
    const last = v[v.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      const inner = v.slice(1, -1);
      if (inner.includes(first)) {
        throw new DeploymentError(`line ${n}: escapes inside a quoted value are not supported`);
      }
      return inner;
    }
    if (first === '"' || first === "'") {
      throw new DeploymentError(`line ${n}: a quoted value is not closed`);
    }
  } else if (v === '"' || v === "'") {
    throw new DeploymentError(`line ${n}: a quoted value is not closed`);
  }
  if (v.includes(': ') || v.endsWith(':')) {
    // YAML refuses ": " inside a plain scalar because it cannot tell the value
    // from a nested mapping.
    throw new DeploymentError(`line ${n}: a value containing a colon must be quoted`);
  }
  if (v.includes('#')) {
    // Ambiguous: YAML would read " #" as a trailing comment, and a reader that
    // guesses either way is wrong for somebody.
    throw new DeploymentError(`line ${n}: a value containing # must be quoted`);
  }
  return v;
}

/**
 * The ServiceAccount name from a projected token, or null.
 *
 * The signature is not checked; see Deployment#verifyServiceAccount.
 */
function serviceAccountFromToken(token) {
  const parts = String(token).trim().split('.');
  if (parts.length !== 3) return null;
  let claims;
  try {
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!claims || typeof claims !== 'object') return null;
  // The subject, which is the canonical and flat form:
  //   system:serviceaccount:<namespace>:<name>
  // Every projected token carries it, so there is no need to reach into the
  // nested kubernetes.io claim for the same name.
  const bits = String(claims.sub || '').split(':');
  if (bits.length === 4 && bits[0] === 'system') return bits[3];
  return null;
}

module.exports = {
  DEFAULT_DEPLOYMENT_PATH,
  DEPLOYMENT_PATH_ENV,
  Deployment,
  DeploymentError,
  loadDeployment,
  loadDeploymentIfPresent,
  parseDeployment,
  serviceAccountFromToken,
};
