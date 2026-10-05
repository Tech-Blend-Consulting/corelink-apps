"""Background polling watcher for the Tech Blend Transit API client."""

import threading


class Watcher:
    """Polls the transit API and fires callbacks when values change.

    Use watch_secret / watch_config to register callbacks before calling start.
    Pass name '*' to receive a callback for every secret or config that changes.
    Named and wildcard callbacks are independent: both fire when a named value
    changes and a wildcard watch is also registered.

    Transient fetch errors are logged and silently skipped; polling resumes on
    the next tick.
    """

    def __init__(self, client, interval=15.0):
        self._client = client
        self._interval = interval
        self._lock = threading.Lock()
        self._secret_vals = {}    # name -> last seen value
        self._config_vals = {}    # name -> last seen content
        self._secret_seen = {}    # name -> bool (fetched at least once)
        self._config_seen = {}
        self._secret_fns = {}     # name -> [fn, ...]; '*' = wildcard
        self._config_fns = {}
        self._stop_event = threading.Event()
        self._thread = None

    def watch_secret(self, name, fn):
        """Register fn(value) to be called when the named secret changes.

        Use name '*' to watch all secrets.
        """
        with self._lock:
            self._secret_fns.setdefault(name, []).append(fn)

    def watch_config(self, name, fn):
        """Register fn(content) to be called when the named config changes.

        Use name '*' to watch all config files.
        """
        with self._lock:
            self._config_fns.setdefault(name, []).append(fn)

    def start(self):
        """Start background polling. Non-blocking."""
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the polling thread to stop."""
        self._stop_event.set()

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _loop(self):
        # Poll immediately so callbacks fire on the first fetch.
        self._poll()
        while not self._stop_event.wait(timeout=self._interval):
            self._poll()

    def _poll(self):
        self._poll_secrets()
        self._poll_configs()

    def _poll_secrets(self):
        with self._lock:
            has_wild = "*" in self._secret_fns
            names = [n for n in self._secret_fns if n != "*"]

        # Wildcard pass: fetch all secrets, fire wildcard AND named callbacks.
        processed = set()
        if has_wild:
            try:
                secrets = self._client.list_secrets()
            except Exception:
                return
            for s in secrets:
                name, val = s["name"], s.get("value", "")
                if self._update_secret(name, val):
                    self._dispatch(self._secret_fns, "*", val)
                    self._dispatch(self._secret_fns, name, val)
                processed.add(name)

        # Named pass: individually fetch names not already updated above.
        for name in names:
            if name in processed:
                continue
            try:
                val = self._client.get_secret(name)
            except Exception:
                continue
            if self._update_secret(name, val):
                self._dispatch(self._secret_fns, name, val)

    def _poll_configs(self):
        with self._lock:
            has_wild = "*" in self._config_fns
            names = [n for n in self._config_fns if n != "*"]

        processed = set()
        if has_wild:
            try:
                configs = self._client.list_configs()
            except Exception:
                return
            for c in configs:
                name, content = c["name"], c.get("content", "")
                if self._update_config(name, content):
                    self._dispatch(self._config_fns, "*", content)
                    self._dispatch(self._config_fns, name, content)
                processed.add(name)

        for name in names:
            if name in processed:
                continue
            try:
                content = self._client.get_config(name)
            except Exception:
                continue
            if self._update_config(name, content):
                self._dispatch(self._config_fns, name, content)

    def _update_secret(self, name, val):
        """Store val and return True if this is the first fetch or value changed."""
        with self._lock:
            if not self._secret_seen.get(name) or self._secret_vals.get(name) != val:
                self._secret_vals[name] = val
                self._secret_seen[name] = True
                return True
        return False

    def _update_config(self, name, content):
        """Store content and return True if this is the first fetch or content changed."""
        with self._lock:
            if not self._config_seen.get(name) or self._config_vals.get(name) != content:
                self._config_vals[name] = content
                self._config_seen[name] = True
                return True
        return False

    def _dispatch(self, fns_map, key, val):
        """Invoke all callbacks registered under key without holding the lock."""
        with self._lock:
            fns = list(fns_map.get(key, []))
        for fn in fns:
            try:
                fn(val)
            except Exception:
                pass
