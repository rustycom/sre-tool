package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rustycom/sre-tool/internal/isolation"
)

type requestIDKey struct{}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// statusRecorder remembers the status a handler wrote, for the access log
// and for panic recovery.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// routeOf turns a ServeMux pattern ("GET /v1/isolations/{id}") into the route
// label ("/v1/isolations/{id}"). Using the pattern, never the raw path, keeps
// log fields and metric labels bounded (SPEC §5.3, §9).
func routeOf(pattern string) string {
	if _, path, ok := strings.Cut(pattern, " "); ok {
		return path
	}
	return pattern
}

// withMiddleware adds, outermost first: request ID, access log, and panic
// recovery. It reads the route after the mux has run, because ServeMux sets
// r.Pattern on the request it is given.
func withMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 128 {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
		rec := &statusRecorder{ResponseWriter: w}

		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p) // the server's own signal to abort the response
				}
				logger.ErrorContext(r.Context(), "panic", "request_id", id, "panic", p, "stack", string(debug.Stack()))
				if rec.status == 0 {
					writeError(logger, rec, r, &isolation.Error{Status: http.StatusInternalServerError,
						Code: "internal", Message: "the request failed; see the tool's log for request " + id})
				}
			}
			logger.InfoContext(r.Context(), "request", "request_id", id, "method", r.Method, "route", routeOf(r.Pattern),
				"status", rec.status, "duration_ms", time.Since(start).Milliseconds())
		}()
		next.ServeHTTP(rec, r)
	})
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	return hex.EncodeToString(b)
}
