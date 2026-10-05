'use strict';

// Minimal JSON-over-HTTP helper built on node:http/node:https.
//
// Deliberately not fetch(): pinning a CA through fetch means constructing an
// undici Agent, which only exists on Node 18+ and is awkward to configure. The
// core modules give the same control on every supported Node and keep this
// package dependency-free, which matters for a client that sits in the
// credential path.

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');

/**
 * Perform a JSON request.
 *
 * @param {string} url
 * @param {object} [options]
 * @param {string} [options.method='GET']
 * @param {object} [options.headers]
 * @param {any}    [options.body]        serialised as JSON when present
 * @param {number} [options.timeout=10000]
 * @param {Buffer|string} [options.ca]   PEM bundle for TLS pinning
 * @returns {Promise<{status:number, ok:boolean, json:function():any, text:string}>}
 */
function request(url, options = {}) {
  const {
    method = 'GET',
    headers = {},
    body,
    timeout = 10000,
    ca,
  } = options;

  const parsed = new URL(url);
  const isTLS = parsed.protocol === 'https:';
  const transport = isTLS ? https : http;

  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
  const reqHeaders = Object.assign({ Accept: 'application/json' }, headers);
  if (payload) {
    reqHeaders['Content-Type'] = 'application/json';
    reqHeaders['Content-Length'] = payload.length;
  }

  const reqOptions = {
    method,
    hostname: parsed.hostname,
    port: parsed.port || (isTLS ? 443 : 80),
    path: parsed.pathname + parsed.search,
    headers: reqHeaders,
  };
  // Pinning replaces the default trust store rather than adding to it, which is
  // the point: a pinned deployment should not accept a public CA.
  if (isTLS && ca) reqOptions.ca = ca;

  return new Promise((resolve, reject) => {
    const req = transport.request(reqOptions, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: res.statusCode,
          ok: res.statusCode >= 200 && res.statusCode < 300,
          text,
          json() {
            return text ? JSON.parse(text) : {};
          },
        });
      });
    });

    req.setTimeout(timeout, () => {
      req.destroy(new Error(`request timed out after ${timeout}ms`));
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

module.exports = { request };
