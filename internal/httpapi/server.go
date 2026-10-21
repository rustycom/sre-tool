// Package httpapi serves the tool's HTTP API and its ops endpoints.
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
	"github.com/rustycom/sre-tool/internal/hardening"
	"github.com/rustycom/sre-tool/internal/isolation"
)

// maxBodyBytes caps request bodies.
const maxBodyBytes = 1 << 20

// NewServer returns a server with the API timeouts. Handlers' contexts
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

// Hardening is what the handlers need from the hardening service.
type Hardening interface {
	Plan(ctx context.Context, namespaces []string) (hardening.Plan, error)
	Apply(ctx context.Context, namespaces []string, planHash string) (hardening.ApplyResult, error)
	Undo(ctx context.Context, namespaces []string, dryRun bool) (hardening.ApplyResult, error)
}

type api struct {
	iso    Isolations
	hrd    Hardening
	logger *slog.Logger
}

// NewAPIHandler returns the API routes wrapped in the middleware.
func NewAPIHandler(iso Isolations, hrd Hardening, logger *slog.Logger, obs RequestObserver) http.Handler {
	a := &api{iso: iso, hrd: hrd, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/isolations", a.createIsolation)
	mux.HandleFunc("GET /v1/isolations", a.listIsolations)
	mux.HandleFunc("GET /v1/isolations/{id}", a.getIsolation)
	mux.HandleFunc("DELETE /v1/isolations/{id}", a.deleteIsolation)
	mux.HandleFunc("POST /v1/hardening/plan", a.planHardening)
	mux.HandleFunc("POST /v1/hardening/apply", a.applyHardening)
	mux.HandleFunc("POST /v1/hardening/undo", a.undoHardening)
	// Everything else gets the JSON error shape rather than the mux's text.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(a.logger, w, r, &isolation.Error{Status: http.StatusNotFound, Code: "not_found", Message: "no such route"})
	})
	return withMiddleware(mux, logger, obs)
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

// readHardening reads and decodes a plan or apply body.
func readHardening(w http.ResponseWriter, r *http.Request) (hardening.Request, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return hardening.Request{}, err
	}
	return hardening.Decode(body)
}

func (a *api) planHardening(w http.ResponseWriter, r *http.Request) {
	req, err := readHardening(w, r)
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	plan, err := a.hrd.Plan(r.Context(), req.Namespaces)
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (a *api) applyHardening(w http.ResponseWriter, r *http.Request) {
	req, err := readHardening(w, r)
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	res, err := a.hrd.Apply(r.Context(), req.Namespaces, req.PlanHash)
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	a.logResults(r, "apply", res)
	writeJSON(w, http.StatusOK, res)
}

func (a *api) undoHardening(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	req, err := hardening.DecodeUndo(body)
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	res, err := a.hrd.Undo(r.Context(), req.Namespaces, req.DryRun)
	if err != nil {
		writeError(a.logger, w, r, err)
		return
	}
	if !req.DryRun {
		a.logResults(r, "undo", res)
	}
	writeJSON(w, http.StatusOK, res)
}

// logResults logs each workload apply or undo changed or failed on, then the outcome.
func (a *api) logResults(r *http.Request, action string, res hardening.ApplyResult) {
	for _, wr := range res.Results {
		if wr.Status == hardening.StatusApplied || wr.Status == hardening.StatusFailed {
			a.logger.InfoContext(r.Context(), "hardening "+wr.Status, "request_id", requestID(r.Context()),
				"namespace", wr.Namespace, "kind", wr.Kind, "name", wr.Name, "action", action, "message", wr.Message)
		}
	}
	a.logger.InfoContext(r.Context(), "hardening "+action+" finished", "request_id", requestID(r.Context()),
		"outcome", res.Outcome, "reason", res.Reason, "action", action)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status is already sent; a failed write means the client went away.
	_ = json.NewEncoder(w).Encode(v)
}
