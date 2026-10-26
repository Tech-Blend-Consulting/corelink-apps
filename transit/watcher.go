package transit

import (
	"errors"
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
	// unavailableFns hear that a secret already delivered was withdrawn.
	unavailableFns []func(name string, err error)
	// errorFns hear every failed fetch, for an application showing its status.
	errorFns []func(name string, err error)

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

// OnUnavailable registers fn to be called once when a secret this Watcher has
// already delivered is withdrawn: it was disabled in CoreLink, its database
// connection was locked, or this application's identity was suspended
// (ErrSecretWithheld; ErrIdentityRefused withdraws every secret at once). The
// application should stop using the value it holds -- close connections opened
// with it, forget it -- because nothing delivers it again until that is undone.
// Then the secret's WatchSecret callbacks fire again with its value, as on the
// first fetch. Safe to call after Start.
func (w *Watcher) OnUnavailable(fn func(name string, err error)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.unavailableFns = append(w.unavailableFns, fn)
}

// OnError registers fn to be called with every failed fetch of a watched secret,
// delivered or not: withheld (see WithheldReason), CoreLink or the connector
// unreachable, and so on. It is for showing status; OnUnavailable is what says
// to stop using a value. Safe to call after Start.
func (w *Watcher) OnError(fn func(name string, err error)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.errorFns = append(w.errorFns, fn)
}

// reportError tells OnError about a failed fetch.
func (w *Watcher) reportError(name string, err error) {
	w.mu.Lock()
	fns := append([]func(string, error){}, w.errorFns...)
	w.mu.Unlock()
	for _, fn := range fns {
		fn(name, err)
	}
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
			w.reportError(name, err)
			switch {
			case errors.Is(err, ErrIdentityRefused):
				// The identity itself is refused: nothing it holds may be used,
				// and asking again by name this tick changes nothing.
				w.withdrawAll(err)
				return
			case errors.Is(err, ErrSecretWithheld):
				w.withdraw(name, err)
			}
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

// withdraw forgets a secret's value and tells OnUnavailable, once, if it had
// been delivered. Forgetting it is what makes its callbacks fire again when it
// is enabled.
func (w *Watcher) withdraw(name string, err error) {
	w.mu.Lock()
	had := w.secretSeen[name]
	delete(w.secretSeen, name)
	delete(w.secretVals, name)
	fns := append([]func(string, error){}, w.unavailableFns...)
	w.mu.Unlock()
	if !had {
		return
	}
	for _, fn := range fns {
		fn(name, err)
	}
}

// withdrawAll withdraws every secret delivered so far.
func (w *Watcher) withdrawAll(err error) {
	w.mu.Lock()
	names := make([]string, 0, len(w.secretSeen))
	for name := range w.secretSeen {
		names = append(names, name)
	}
	w.mu.Unlock()
	for _, name := range names {
		w.withdraw(name, err)
	}
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
