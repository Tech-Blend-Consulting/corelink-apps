package transit

import (
	"sync"
	"time"
)

// Watcher polls the transit API on a fixed interval and fires registered
// callbacks whenever a secret value or config file content changes.
//
// Use WatchSecret / WatchConfig to register callbacks before calling Start.
// Pass name "*" to receive a callback for every secret or config that changes.
// Named and wildcard callbacks are independent: both fire when the named value
// changes and a wildcard watch is also registered.
type Watcher struct {
	client   *Client
	interval time.Duration

	mu         sync.Mutex
	secretVals map[string]string // last seen value by name
	configVals map[string]string // last seen content by name
	secretSeen map[string]bool   // whether this name has been fetched at least once
	configSeen map[string]bool
	secretFns  map[string][]func(string) // name -> callbacks; "*" = wildcard
	configFns  map[string][]func(string)

	stopCh chan struct{}
}

// NewWatcher creates a Watcher that uses client and fires callbacks every interval.
func NewWatcher(client *Client, interval time.Duration) *Watcher {
	return &Watcher{
		client:     client,
		interval:   interval,
		secretVals: make(map[string]string),
		configVals: make(map[string]string),
		secretSeen: make(map[string]bool),
		configSeen: make(map[string]bool),
		secretFns:  make(map[string][]func(string)),
		configFns:  make(map[string][]func(string)),
		stopCh:     make(chan struct{}),
	}
}

// WatchSecret registers fn to be called whenever the named secret's value
// changes. Use name "*" to receive callbacks for all secrets on every change.
// Safe to call after Start.
func (w *Watcher) WatchSecret(name string, fn func(value string)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.secretFns[name] = append(w.secretFns[name], fn)
}

// WatchConfig registers fn to be called whenever the named config file's
// content changes. Use name "*" to receive callbacks for all config files.
// Safe to call after Start.
func (w *Watcher) WatchConfig(name string, fn func(content string)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.configFns[name] = append(w.configFns[name], fn)
}

// Start begins background polling. It is non-blocking.
func (w *Watcher) Start() {
	go w.loop()
}

// Close stops background polling.
func (w *Watcher) Close() {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
}

func (w *Watcher) loop() {
	// Poll once immediately so callbacks fire on the first fetch.
	w.poll()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.poll()
		}
	}
}

func (w *Watcher) poll() {
	w.pollSecrets()
	w.pollConfigs()
}

func (w *Watcher) pollSecrets() {
	w.mu.Lock()
	_, hasWild := w.secretFns["*"]
	names := make([]string, 0, len(w.secretFns))
	for name := range w.secretFns {
		if name != "*" {
			names = append(names, name)
		}
	}
	w.mu.Unlock()

	// Wildcard pass: fetch all secrets, fire wildcard AND named callbacks.
	processed := make(map[string]bool)
	if hasWild {
		secrets, err := w.client.ListSecrets()
		if err != nil {
			// Transient error — skip this tick.
			return
		}
		for _, s := range secrets {
			if w.updateSecret(s.Name, s.Value) {
				w.dispatchSecrets("*", s.Value)
				w.dispatchSecrets(s.Name, s.Value)
			}
			processed[s.Name] = true
		}
	}

	// Named pass: individually fetch any names not already updated above.
	for _, name := range names {
		if processed[name] {
			continue
		}
		val, err := w.client.GetSecret(name)
		if err != nil {
			continue
		}
		if w.updateSecret(name, val) {
			w.dispatchSecrets(name, val)
		}
	}
}

func (w *Watcher) pollConfigs() {
	w.mu.Lock()
	_, hasWild := w.configFns["*"]
	names := make([]string, 0, len(w.configFns))
	for name := range w.configFns {
		if name != "*" {
			names = append(names, name)
		}
	}
	w.mu.Unlock()

	processed := make(map[string]bool)
	if hasWild {
		configs, err := w.client.ListConfigs()
		if err != nil {
			return
		}
		for _, cfg := range configs {
			if w.updateConfig(cfg.Name, cfg.Content) {
				w.dispatchConfigs("*", cfg.Content)
				w.dispatchConfigs(cfg.Name, cfg.Content)
			}
			processed[cfg.Name] = true
		}
	}

	for _, name := range names {
		if processed[name] {
			continue
		}
		content, err := w.client.GetConfig(name)
		if err != nil {
			continue
		}
		if w.updateConfig(name, content) {
			w.dispatchConfigs(name, content)
		}
	}
}

// updateSecret records val and returns true if this is the first fetch or the
// value has changed since the last fetch.
func (w *Watcher) updateSecret(name, val string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.secretSeen[name] || w.secretVals[name] != val {
		w.secretVals[name] = val
		w.secretSeen[name] = true
		return true
	}
	return false
}

// updateConfig is the config-file equivalent of updateSecret.
func (w *Watcher) updateConfig(name, content string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.configSeen[name] || w.configVals[name] != content {
		w.configVals[name] = content
		w.configSeen[name] = true
		return true
	}
	return false
}

// dispatchSecrets invokes all callbacks registered under key without holding
// the lock, copying the slice first to avoid holding the lock during user code.
func (w *Watcher) dispatchSecrets(key, val string) {
	w.mu.Lock()
	fns := append([]func(string){}, w.secretFns[key]...)
	w.mu.Unlock()
	for _, fn := range fns {
		fn(val)
	}
}

// dispatchConfigs is the config-file equivalent of dispatchSecrets.
func (w *Watcher) dispatchConfigs(key, content string) {
	w.mu.Lock()
	fns := append([]func(string){}, w.configFns[key]...)
	w.mu.Unlock()
	for _, fn := range fns {
		fn(content)
	}
}
