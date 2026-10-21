package httpapi

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// readyWindow is how recent the last successful API server probe must be
// for /readyz to pass.
const readyWindow = 10 * time.Second

// Readiness caches the result of an API server probe, so /readyz answers
// without calling the API server on every kubelet probe.
type Readiness struct {
	probe func(context.Context) error
	now   func() time.Time

	mu           sync.Mutex
	lastOK       time.Time
	shuttingDown bool
}

// NewReadiness returns a Readiness that is not ready until probe succeeds.
func NewReadiness(probe func(context.Context) error, now func() time.Time) *Readiness {
	return &Readiness{probe: probe, now: now}
}

// Probe runs the probe once and records a success.
func (r *Readiness) Probe(ctx context.Context) error {
	if err := r.probe(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastOK = r.now()
	return nil
}

// Run probes every interval until ctx is done.
func (r *Readiness) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, interval)
			_ = r.Probe(pctx) // a failure simply leaves lastOK to age out
			cancel()
		}
	}
}

// ShutDown makes the tool unready for good: the first shutdown step.
func (r *Readiness) ShutDown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.shuttingDown = true
}

// Ready reports whether the API server answered within readyWindow.
func (r *Readiness) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.shuttingDown && !r.lastOK.IsZero() && r.now().Sub(r.lastOK) <= readyWindow
}

// NewOpsHandler serves /healthz, /readyz and /metrics.
func NewOpsHandler(ready *Readiness, metrics http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Ready() {
			http.Error(w, "not ready: no successful API server probe in the last 10s", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /metrics", metrics)
	return mux
}
