package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/rustycom/sre-tool/internal/config"
	"github.com/rustycom/sre-tool/internal/hardening"
	"github.com/rustycom/sre-tool/internal/isolation"
	"github.com/rustycom/sre-tool/internal/metrics"
)

// fakeIsolations returns err from every call, or canned results.
type fakeIsolations struct {
	err     error
	created isolation.CreateResult
	got     []isolation.Request
}

func (f *fakeIsolations) Create(_ context.Context, req isolation.Request) (isolation.CreateResult, error) {
	f.got = append(f.got, req)
	return f.created, f.err
}
func (f *fakeIsolations) Delete(context.Context, string) (isolation.DeleteResult, error) {
	return isolation.DeleteResult{}, f.err
}
func (f *fakeIsolations) List(context.Context) ([]isolation.Status, error) { return nil, f.err }
func (f *fakeIsolations) Get(context.Context, string) (isolation.Status, error) {
	return isolation.Status{}, f.err
}

// fakeHardening returns err from every call, or canned results.
type fakeHardening struct {
	err     error
	applied hardening.ApplyResult
	gotHash string
	gotNS   []string
}

func (f *fakeHardening) Plan(_ context.Context, ns []string) (hardening.Plan, error) {
	f.gotNS = ns
	return hardening.Plan{PlanHash: "sha256:p", Namespaces: ns}, f.err
}
func (f *fakeHardening) Apply(_ context.Context, ns []string, hash string) (hardening.ApplyResult, error) {
	f.gotNS, f.gotHash = ns, hash
	return f.applied, f.err
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const briefYAML = `isolate:
  a:
    namespace: tenant-a
    selector:
      app: gateway
  b:
    namespace: tenant-b
    selector:
      app: dashboard
`

func do(h http.Handler, method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServer_APIDefaultsToLoopback(t *testing.T) {
	cfg, err := config.Load(nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(context.Background(), cfg.APIAddr, http.NotFoundHandler())
	host, _, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Errorf("API listens on %q, want a loopback address", srv.Addr)
	}
	if srv.WriteTimeout != 15*time.Minute || srv.ReadHeaderTimeout != 5*time.Second || srv.ReadTimeout != 30*time.Second {
		t.Errorf("timeouts = %v/%v/%v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout)
	}
}

func TestHandlers_ErrorShapeAndCodes(t *testing.T) {
	typed := func(status int, code string) error {
		return &isolation.Error{Status: status, Code: code, Message: "m", Details: map[string]any{"k": "v"}}
	}
	htyped := func(status int, code string) error {
		return &hardening.Error{Status: status, Code: code, Message: "m", Details: map[string]any{"k": "v"}}
	}
	plan, apply := `{"namespaces":["demo"]}`, `{"namespaces":["demo"],"planHash":"sha256:x"}`
	gr := schema.GroupResource{Group: "networking.k8s.io", Resource: "networkpolicies"}
	tests := []struct {
		name          string
		err           error
		method, path  string
		body          string
		wantStatus    int
		wantCode      string
		wantRetryable any // nil: no retryable detail expected
	}{
		{"malformed body", nil, "POST", "/v1/isolations", "isolate: [", 400, "invalid_request", nil},
		{"unknown field", nil, "POST", "/v1/isolations", "selecter: {}\n" + briefYAML, 400, "invalid_request", nil},
		{"forbidden namespace", typed(403, "forbidden_namespace"), "POST", "/v1/isolations", briefYAML, 403, "forbidden_namespace", nil},
		{"conflicting policies", typed(409, "conflicting_policies"), "POST", "/v1/isolations", briefYAML, 409, "conflicting_policies", nil},
		{"name conflict", typed(409, "name_conflict"), "POST", "/v1/isolations", briefYAML, 409, "name_conflict", nil},
		{"body too large", nil, "POST", "/v1/isolations", strings.Repeat("#", maxBodyBytes+1), 413, "body_too_large", nil},
		{"namespace not found", typed(422, "namespace_not_found"), "POST", "/v1/isolations", briefYAML, 422, "namespace_not_found", nil},
		{"empty selector", typed(422, "empty_selector"), "POST", "/v1/isolations", briefYAML, 422, "empty_selector", nil},
		{"overlapping sides", typed(422, "overlapping_sides"), "POST", "/v1/isolations", briefYAML, 422, "overlapping_sides", nil},
		{"partial apply", typed(500, "partial_apply"), "POST", "/v1/isolations", briefYAML, 500, "partial_apply", nil},
		{"not found", typed(404, "not_found"), "GET", "/v1/isolations/abc", "", 404, "not_found", nil},
		{"unknown route", nil, "GET", "/v2/nope", "", 404, "not_found", nil},
		{"hardening malformed body", nil, "POST", "/v1/hardening/plan", `{"namespaces":`, 400, "invalid_request", nil},
		{"hardening unknown field", nil, "POST", "/v1/hardening/apply", `{"namespaces":["demo"],"hash":"x"}`, 400, "invalid_request", nil},
		{"hardening forbidden namespace", htyped(403, "forbidden_namespace"), "POST", "/v1/hardening/plan", plan, 403, "forbidden_namespace", nil},
		{"hardening body too large", nil, "POST", "/v1/hardening/plan", strings.Repeat(" ", maxBodyBytes+1), 413, "body_too_large", nil},
		{"hardening namespace not found", htyped(422, "namespace_not_found"), "POST", "/v1/hardening/plan", plan, 422, "namespace_not_found", nil},
		{"stale plan", htyped(409, "stale_plan"), "POST", "/v1/hardening/apply", apply, 409, "stale_plan", nil},
		{"apply in progress", htyped(409, "apply_in_progress"), "POST", "/v1/hardening/apply", apply, 409, "apply_in_progress", nil},
		{"hardening API failure", apierrors.NewServiceUnavailable("down"), "POST", "/v1/hardening/plan", plan, 500, "internal", true},
		{"API 503 is retryable", apierrors.NewServiceUnavailable("down"), "GET", "/v1/isolations", "", 500, "internal", true},
		{"API timeout is retryable", apierrors.NewTimeoutError("slow", 1), "DELETE", "/v1/isolations/abc", "", 500, "internal", true},
		{"deadline is retryable", context.DeadlineExceeded, "GET", "/v1/isolations/abc", "", 500, "internal", true},
		{"API 403 is not retryable", apierrors.NewForbidden(gr, "x", errors.New("rbac")), "GET", "/v1/isolations", "", 500, "internal", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAPIHandler(&fakeIsolations{err: tt.err}, &fakeHardening{err: tt.err}, discardLogger(), metrics.New())
			rec := do(h, tt.method, tt.path, tt.body)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q", ct)
			}
			var body struct {
				Error *struct {
					Code    string         `json:"code"`
					Message string         `json:"message"`
					Details map[string]any `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == nil {
				t.Fatalf("body %q is not the error shape: %v", rec.Body, err)
			}
			if body.Error.Code != tt.wantCode || body.Error.Message == "" || body.Error.Details == nil {
				t.Errorf("error = %+v, want code %s, a message and details", body.Error, tt.wantCode)
			}
			if got := body.Error.Details["retryable"]; got != tt.wantRetryable {
				t.Errorf("details.retryable = %v, want %v", got, tt.wantRetryable)
			}
		})
	}
}

func TestHandlers_YAMLAndJSONBodies(t *testing.T) {
	jsonBody := `{"isolate":{"a":{"namespace":"tenant-a","selector":{"app":"gateway"}},"b":{"namespace":"tenant-b","selector":{"app":"dashboard"}}}}`
	f := &fakeIsolations{created: isolation.CreateResult{ID: "x", Created: []string{"tenant-a/p"}}}
	h := NewAPIHandler(f, &fakeHardening{}, discardLogger(), metrics.New())
	for _, tc := range []struct{ ct, body string }{{"application/yaml", briefYAML}, {"application/json", jsonBody}} {
		if rec := do(h, "POST", "/v1/isolations", tc.body, "Content-Type", tc.ct); rec.Code != http.StatusCreated {
			t.Errorf("%s: status = %d, body %s", tc.ct, rec.Code, rec.Body)
		}
	}
	if len(f.got) != 2 || !reflect.DeepEqual(f.got[0], f.got[1]) {
		t.Errorf("YAML and JSON decoded differently: %+v", f.got)
	}

	// Nothing created (all unchanged or repaired) is 200, not 201.
	f.created = isolation.CreateResult{ID: "x", Repaired: []string{"tenant-a/p"}}
	if rec := do(h, "POST", "/v1/isolations", briefYAML); rec.Code != http.StatusOK {
		t.Errorf("repeat: status = %d, want 200", rec.Code)
	}
}

func TestHandlers_HardeningRoutes(t *testing.T) {
	f := &fakeHardening{applied: hardening.ApplyResult{Outcome: "halted", Reason: "rollout_failed", Results: []hardening.Result{}}}
	h := NewAPIHandler(&fakeIsolations{}, f, discardLogger(), metrics.New())

	rec := do(h, "POST", "/v1/hardening/plan", "namespaces: [b, a]\n", "Content-Type", "application/yaml")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"planHash":"sha256:p"`) || !reflect.DeepEqual(f.gotNS, []string{"a", "b"}) {
		t.Errorf("plan: status %d, body %s, namespaces %v", rec.Code, rec.Body, f.gotNS)
	}
	// A halted apply is still a 200: the outcome is data (SPEC §7.7).
	rec = do(h, "POST", "/v1/hardening/apply", `{"namespaces":["a"],"planHash":"sha256:abc"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"outcome":"halted"`) || f.gotHash != "sha256:abc" {
		t.Errorf("apply: status %d, body %s, hash %q", rec.Code, rec.Body, f.gotHash)
	}
}

func TestHandlers_BodyTooLarge(t *testing.T) {
	f := &fakeIsolations{}
	h := NewAPIHandler(f, &fakeHardening{}, discardLogger(), metrics.New())
	// A valid request padded with a YAML comment past the limit.
	rec := do(h, "POST", "/v1/isolations", briefYAML+"#"+strings.Repeat("x", maxBodyBytes))
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "body_too_large") {
		t.Errorf("status = %d, body %s", rec.Code, rec.Body)
	}
	if len(f.got) != 0 {
		t.Error("the service was called with an oversized body")
	}
	// Exactly at the limit is fine.
	atLimit := briefYAML + "#" + strings.Repeat("x", maxBodyBytes-len(briefYAML)-1)
	if rec := do(h, "POST", "/v1/isolations", atLimit); rec.Code == http.StatusRequestEntityTooLarge {
		t.Errorf("a body of exactly %d bytes was refused", maxBodyBytes)
	}
}

func TestMiddleware_RequestIDEchoed(t *testing.T) {
	h := NewAPIHandler(&fakeIsolations{}, &fakeHardening{}, discardLogger(), metrics.New())
	if got := do(h, "GET", "/v1/isolations", "", "X-Request-ID", "abc-123").Header().Get("X-Request-ID"); got != "abc-123" {
		t.Errorf("echoed %q, want abc-123", got)
	}
	a := do(h, "GET", "/v1/isolations", "").Header().Get("X-Request-ID")
	b := do(h, "GET", "/v1/isolations", "").Header().Get("X-Request-ID")
	if len(a) != 16 || a == b {
		t.Errorf("generated IDs %q and %q, want two different 16-hex IDs", a, b)
	}
}

func TestMiddleware_RecoversPanics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	rec := do(withMiddleware(mux, discardLogger(), metrics.New()), "GET", "/boom", "")
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"internal"`) {
		t.Errorf("status = %d, body %s", rec.Code, rec.Body)
	}
}

func TestReadyz_ReflectsAPIServerReachability(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	var probeErr error
	ready := NewReadiness(func(context.Context) error { return probeErr }, func() time.Time { return now })
	h := NewOpsHandler(ready, http.NotFoundHandler())
	readyz := func() int { return do(h, "GET", "/readyz", "").Code }

	steps := []struct {
		name    string
		advance time.Duration
		probe   error // nil: probe succeeds; errSkipProbe: no probe this step
		want    int
	}{
		{"no probe yet", 0, errSkipProbe, 503},
		{"probe fails", 0, errors.New("refused"), 503},
		{"probe succeeds", 0, nil, 200},
		{"10s later, still cached", readyWindow, errSkipProbe, 200},
		{"failed probe keeps the last success", 0, errors.New("refused"), 200},
		{"just past the window", time.Nanosecond, errSkipProbe, 503},
		{"recovers", 0, nil, 200},
	}
	for _, s := range steps {
		now = now.Add(s.advance)
		if s.probe != errSkipProbe {
			probeErr = s.probe
			_ = ready.Probe(context.Background())
		}
		if got := readyz(); got != s.want {
			t.Errorf("%s: /readyz = %d, want %d", s.name, got, s.want)
		}
	}
	ready.ShutDown()
	if got := readyz(); got != 503 {
		t.Errorf("after ShutDown: /readyz = %d, want 503", got)
	}
	if got := do(h, "GET", "/healthz", "").Code; got != 200 {
		t.Errorf("/healthz = %d, want 200 even while not ready", got)
	}
}

var errSkipProbe = errors.New("skip")

func TestMetrics_RouteLabelIsPatternNotPath(t *testing.T) {
	m := metrics.New()
	h := NewAPIHandler(&fakeIsolations{}, &fakeHardening{}, discardLogger(), m)
	for _, id := range []string{"abc", "def", "ghi"} {
		do(h, "GET", "/v1/isolations/"+id, "")
	}
	do(h, "GET", "/no/such/path", "")
	do(h, "FOO", "/x", "")

	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, f := range families {
		if f.GetName() != "sre_tool_http_requests_total" {
			continue
		}
		for _, metric := range f.GetMetric() {
			var route, method, code string
			for _, l := range metric.GetLabel() {
				switch l.GetName() {
				case "route":
					route = l.GetValue()
				case "method":
					method = l.GetValue()
				case "code":
					code = l.GetValue()
				}
			}
			got[method+" "+route+" "+code] = metric.GetCounter().GetValue()
		}
	}
	want := map[string]float64{"GET /v1/isolations/{id} 200": 3, "GET / 404": 1, "other / 404": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("requests by route = %v, want %v", got, want)
	}
}
