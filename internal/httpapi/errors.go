package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/rustycom/sre-tool/internal/hardening"
	"github.com/rustycom/sre-tool/internal/isolation"
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details"`
}

// writeError maps err to the SPEC §5.2 error shape. Typed request errors keep
// their status and code; anything else is an unexpected failure, usually a
// Kubernetes API error, and becomes 500 internal. Its text goes to the log,
// not to the client.
func writeError(logger *slog.Logger, w http.ResponseWriter, r *http.Request, err error) {
	var e *isolation.Error
	var he *hardening.Error
	var tooLarge *http.MaxBytesError
	d := errorDetail{Details: map[string]any{}}
	status := http.StatusInternalServerError
	switch {
	case errors.As(err, &e):
		status, d.Code, d.Message = e.Status, e.Code, e.Message
		if e.Details != nil {
			d.Details = e.Details
		}
	case errors.As(err, &he):
		status, d.Code, d.Message = he.Status, he.Code, he.Message
		if he.Details != nil {
			d.Details = he.Details
		}
	case errors.As(err, &tooLarge):
		status, d.Code = http.StatusRequestEntityTooLarge, "body_too_large"
		d.Message = fmt.Sprintf("the request body is larger than %d bytes", tooLarge.Limit)
	default:
		id := requestID(r.Context())
		logger.ErrorContext(r.Context(), "request failed", "request_id", id, "error", err)
		d.Code = "internal"
		d.Message = "the request failed; see the tool's log for request " + id
		d.Details["retryable"] = retryable(err)
	}
	writeJSON(w, status, errorBody{Error: d})
}

// retryable reports timeouts and 5xx responses from the API server (SPEC §8):
// failures that a retry of the same idempotent request may get past.
func retryable(err error) bool {
	var st apierrors.APIStatus
	if errors.As(err, &st) && st.Status().Code >= http.StatusInternalServerError {
		return true
	}
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}
