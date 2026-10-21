package isolation

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// briefYAML is the brief's example, verbatim.
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

func briefRequest() Request {
	return Request{Isolate: Pair{
		A: &Side{Namespace: "tenant-a", Selector: map[string]string{"app": "gateway"}},
		B: &Side{Namespace: "tenant-b", Selector: map[string]string{"app": "dashboard"}},
	}}
}

func TestDecode_BriefExampleVerbatim(t *testing.T) {
	fromYAML, err := Decode([]byte(briefYAML))
	if err != nil {
		t.Fatalf("decode YAML: %v", err)
	}
	fromJSON, err := Decode([]byte(`{"isolate":{"a":{"namespace":"tenant-a","selector":{"app":"gateway"}},` +
		`"b":{"namespace":"tenant-b","selector":{"app":"dashboard"}}}}`))
	if err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if !reflect.DeepEqual(fromYAML, briefRequest()) {
		t.Errorf("YAML decoded to %+v, want the brief request", fromYAML)
	}
	if !reflect.DeepEqual(fromJSON, fromYAML) {
		t.Errorf("JSON decoded to %+v, YAML to %+v", fromJSON, fromYAML)
	}
}

func TestDecode_RejectsUnknownFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"typo in side", strings.Replace(briefYAML, "selector:\n      app: gateway", "selecter:\n      app: gateway", 1)},
		{"unknown top-level field", "isolat: {}\n" + briefYAML},
		{"duplicate field", briefYAML + "isolate: {}\n"},
		{"not YAML", "isolate: [unclosed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode([]byte(tt.body))
			assertCode(t, err, http.StatusBadRequest, "invalid_request")
		})
	}
}

func TestValidate_Table(t *testing.T) {
	side := func(mutate func(*Side)) *Side {
		s := &Side{Namespace: "tenant-a", Selector: map[string]string{"app": "gateway"}}
		mutate(s)
		return s
	}
	ok := side(func(*Side) {})
	tests := []struct {
		name    string
		req     Request
		wantErr string // substring of the message; empty means valid
	}{
		{"brief example", briefRequest(), ""},
		{"namespaces list", Request{Isolate: Pair{A: side(func(s *Side) { s.Namespace, s.Namespaces = "", []string{"x", "y"} }), B: ok}}, ""},
		{"valid name", Request{Name: "incident-42", Isolate: Pair{A: ok, B: ok}}, ""},
		{"expressions only", Request{Isolate: Pair{A: side(func(s *Side) {
			s.Selector = nil
			s.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpExists}}
		}), B: ok}}, ""},
		{"missing side a", Request{Isolate: Pair{B: ok}}, "isolate.a is missing"},
		{"missing side b", Request{Isolate: Pair{A: ok}}, "isolate.b is missing"},
		{"both namespace and namespaces", Request{Isolate: Pair{A: side(func(s *Side) { s.Namespaces = []string{"x"} }), B: ok}}, "not both"},
		{"neither namespace nor namespaces", Request{Isolate: Pair{A: side(func(s *Side) { s.Namespace = "" }), B: ok}}, "set one of"},
		{"too many namespaces", Request{Isolate: Pair{A: side(func(s *Side) {
			s.Namespace, s.Namespaces = "", strings.Split("a,b,c,d,e,f,g,h,i,j,k", ",")
		}), B: ok}}, "at most 10"},
		{"empty namespace in list", Request{Isolate: Pair{A: side(func(s *Side) { s.Namespace, s.Namespaces = "", []string{"x", ""} }), B: ok}}, `namespace ""`},
		{"invalid namespace", Request{Isolate: Pair{A: ok, B: side(func(s *Side) { s.Namespace = "Tenant_B" })}}, "isolate.b"},
		{"invalid label key", Request{Isolate: Pair{A: side(func(s *Side) { s.Selector = map[string]string{"bad key": "x"} }), B: ok}}, "selector"},
		{"invalid label value", Request{Isolate: Pair{A: side(func(s *Side) { s.Selector = map[string]string{"app": "-x"} }), B: ok}}, "selector"},
		{"unknown operator", Request{Isolate: Pair{A: side(func(s *Side) {
			s.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Gt", Values: []string{"1"}}}
		}), B: ok}}, "selector"},
		{"In without values", Request{Isolate: Pair{A: side(func(s *Side) {
			s.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpIn}}
		}), B: ok}}, "selector"},
		{"Exists with values", Request{Isolate: Pair{A: side(func(s *Side) {
			s.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpExists, Values: []string{"x"}}}
		}), B: ok}}, "selector"},
		{"name too long", Request{Name: strings.Repeat("a", 41), Isolate: Pair{A: ok, B: ok}}, "longer than 40"},
		{"name not DNS-1123", Request{Name: "Incident_42", Isolate: Pair{A: ok, B: ok}}, "name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.req)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			assertCode(t, err, http.StatusBadRequest, "invalid_request")
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func assertCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error = %v, want *Error with code %s", err, code)
	}
	if e.Status != status || e.Code != code {
		t.Errorf("error = %d %s (%s), want %d %s", e.Status, e.Code, e.Message, status, code)
	}
}
