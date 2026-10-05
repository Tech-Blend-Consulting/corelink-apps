'use strict';

/**
 * Polls the transit API and fires callbacks when values change.
 *
 * Register callbacks with watchSecret / watchConfig before calling start().
 * Name '*' watches everything. Named and wildcard callbacks are independent:
 * both fire when a named value changes and a wildcard watch is registered.
 *
 * Transient fetch errors are skipped; polling resumes on the next tick.
 */
class Watcher {
  /**
   * @param {import('./client').TransitClient} client
   * @param {number} [intervalMs=15000]
   */
  constructor(client, intervalMs = 15000) {
    this._client = client;
    this._interval = intervalMs;
    this._secretVals = new Map();
    this._configVals = new Map();
    this._secretSeen = new Set();
    this._configSeen = new Set();
    this._secretFns = new Map();
    this._configFns = new Map();
    this._timer = null;
    this._stopped = false;
  }

  /** Register fn(value) for a secret. Use '*' for all secrets. */
  watchSecret(name, fn) {
    push(this._secretFns, name, fn);
  }

  /** Register fn(content) for a config file. Use '*' for all configs. */
  watchConfig(name, fn) {
    push(this._configFns, name, fn);
  }

  /** Begin polling. Non-blocking; the first poll runs immediately. */
  start() {
    this._stopped = false;
    const tick = async () => {
      if (this._stopped) return;
      await this._poll();
      if (this._stopped) return;
      this._timer = setTimeout(tick, this._interval);
      if (typeof this._timer.unref === 'function') this._timer.unref();
    };
    tick().catch(() => {});
  }

  /** Stop polling. In-flight requests are allowed to settle. */
  stop() {
    this._stopped = true;
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
  }

  // ---------------------------------------------------------------------------

  async _poll() {
    await this._pollSecrets();
    await this._pollConfigs();
  }

  async _pollSecrets() {
    const hasWild = this._secretFns.has('*');
    const names = [...this._secretFns.keys()].filter((n) => n !== '*');
    const processed = new Set();

    if (hasWild) {
      let secrets;
      try {
        secrets = await this._client.listSecrets();
      } catch {
        return; // whole listing failed; try again next tick
      }
      for (const s of secrets) {
        const value = s.value || '';
        if (this._update(this._secretVals, this._secretSeen, s.name, value)) {
          dispatch(this._secretFns, '*', value);
          dispatch(this._secretFns, s.name, value);
        }
        processed.add(s.name);
      }
    }

    for (const name of names) {
      if (processed.has(name)) continue;
      let value;
      try {
        value = await this._client.getSecret(name);
      } catch {
        continue;
      }
      if (this._update(this._secretVals, this._secretSeen, name, value)) {
        dispatch(this._secretFns, name, value);
      }
    }
  }

  async _pollConfigs() {
    const hasWild = this._configFns.has('*');
    const names = [...this._configFns.keys()].filter((n) => n !== '*');
    const processed = new Set();

    if (hasWild) {
      let configs;
      try {
        configs = await this._client.listConfigs();
      } catch {
        return;
      }
      for (const c of configs) {
        const content = c.content || '';
        if (this._update(this._configVals, this._configSeen, c.name, content)) {
          dispatch(this._configFns, '*', content);
          dispatch(this._configFns, c.name, content);
        }
        processed.add(c.name);
      }
    }

    for (const name of names) {
      if (processed.has(name)) continue;
      let content;
      try {
        content = await this._client.getConfig(name);
      } catch {
        continue;
      }
      if (this._update(this._configVals, this._configSeen, name, content)) {
        dispatch(this._configFns, name, content);
      }
    }
  }

  /** Store and report whether this is the first sighting or a change. */
  _update(vals, seen, name, value) {
    if (!seen.has(name) || vals.get(name) !== value) {
      vals.set(name, value);
      seen.add(name);
      return true;
    }
    return false;
  }
}

function push(map, key, fn) {
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(fn);
}

/** A throwing callback must not stop the others or kill the poll loop. */
function dispatch(map, key, value) {
  for (const fn of map.get(key) || []) {
    try {
      fn(value);
    } catch {
      // callback errors are the caller's problem, not the watcher's
    }
  }
}

module.exports = { Watcher };
