// Package httpapi serves the tool's HTTP API (SPEC §8) and its ops endpoints.
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/rustycom/sre-tool/internal/config"
	"github.com/rustycom/sre-tool/internal/isolation"
)

// maxBodyBytes caps request bodies (SPEC §8).
const maxBodyBytes = 1 << 20

// NewServer returns a server with the SPEC §8 timeouts. Handlers' contexts
// derive from base, so cancelling base cancels in-flight work at shutdown.
func NewServer(base context.Context, addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      config.WriteTimeout,
		BaseContext:       func(net.Listener) context.Context { return base },
	}
}

// Isolations is what the handlers need from the isolation service.
type Isolations interface {
	Create(ctx context.Context, req isolation.Request) (isolation.CreateResult, error)
	Delete(ctx context.Context, id string) (isolation.DeleteResult, error)
	List(ctx context.Context) ([]isolation.Status, error)
	Get(ctx context.Context, id string) (isolation.Status, error)
}

type api struct {
	iso    Isolations
	logger *slog.Logger
}

// NewAPIHandler returns the API routes wrapped in the middleware.
func NewAPIHandler(iso Isolations, logger *slog.Logger) http.Handler {
	a := &api{iso: iso, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/isolations", a.createIsolation)
	mux.HandleFunc("GET /v1/isolations", a.listIsolations)
	mux.HandleFunc("GET /v1/isolations/{id}", a.getIsolation)
	mux.HandleFunc("DELETE /v1/isolations/{id}", a.deleteIsolation)
	// Everything else gets the JSON error shape rather than the mux's text.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(a.logger, w, r, &isolation.Error{Status: http.StatusNotFound, Code: "not_found", Message: "no such route"})
	})
	return withMiddleware(mux, logger)
}

func (a *api) createIsolation(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	req, err := isolation.Decode(body)
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	res, err := a.iso.Create(r.Context(), req)
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	a.logger.InfoContext(r.Context(), "isolation applied", "request_id", requestID(r.Context()), "isolation_id", res.ID,
		"created", len(res.Created), "repaired", len(res.Repaired), "action", "create")
	status := http.StatusOK
	if len(res.Created) > 0 {
		status = http.StatusCreated
	}
	writeJSON(w, status, res)
}

func (a *api) listIsolations(w http.ResponseWriter, r *http.Request) {
	list, err := a.iso.List(r.Context())
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"isolations": list})
}

func (a *api) getIsolation(w http.ResponseWriter, r *http.Request) {
	st, err := a.iso.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *api) deleteIsolation(w http.ResponseWriter, r *http.Request) {
	res, err := a.iso.Delete(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	a.logger.InfoContext(r.Context(), "isolation removed", "request_id", requestID(r.Context()), "isolation_id", res.ID,
		"deleted", len(res.Deleted), "action", "delete")
	writeJSON(w, http.StatusOK, res)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status is already sent; a failed write means the client went away.
	_ = json.NewEncoder(w).Encode(v)
}
