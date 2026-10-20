// Package isolation turns an isolation request into the NetworkPolicies that
// cut network traffic between two sets of pods (SPEC §6).
package isolation

import (
	"fmt"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const (
	maxNameLen       = 40
	maxNamespacesLen = 10
)

// Request is the body of POST /v1/isolations (SPEC §6.1).
type Request struct {
	Name               string `json:"name,omitempty"`
	Force              bool   `json:"force,omitempty"`
	AllowEmptySelector bool   `json:"allowEmptySelector,omitempty"`
	Isolate            Pair   `json:"isolate"`
}

// Pair holds the two sides. Pointers tell a missing side apart from an empty one.
type Pair struct {
	A *Side `json:"a"`
	B *Side `json:"b"`
}

// Side is one set of pods: a label selector applied in one or more namespaces.
type Side struct {
	Namespace        string                            `json:"namespace,omitempty"`
	Namespaces       []string                          `json:"namespaces,omitempty"`
	Selector         map[string]string                 `json:"selector,omitempty"`
	MatchExpressions []metav1.LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// Error is a request failure carrying the HTTP status and error code from
// SPEC §6.3 and §8, so the HTTP layer can map it without string matching.
type Error struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func invalid(format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: fmt.Sprintf(format, args...)}
}

// Decode parses a JSON or YAML body strictly and validates it. sigs.k8s.io/yaml
// converts YAML to JSON first, and JSON is valid YAML, so one path serves both
// content types. Strict mode rejects unknown and duplicate fields (FR-ISO-01).
func Decode(body []byte) (Request, error) {
	var req Request
	if err := yaml.UnmarshalStrict(body, &req); err != nil {
		return Request{}, invalid("decode request: %v", err)
	}
	if err := Validate(req); err != nil {
		return Request{}, err
	}
	return req, nil
}

// Validate applies the static 400 rules of FR-ISO-03. It needs no cluster access.
func Validate(req Request) error {
	if req.Name != "" {
		if len(req.Name) > maxNameLen {
			return invalid("name %q is longer than %d characters", req.Name, maxNameLen)
		}
		if errs := validation.IsDNS1123Label(req.Name); len(errs) > 0 {
			return invalid("name %q: %s", req.Name, errs[0])
		}
	}
	for _, s := range []struct {
		label string
		side  *Side
	}{{"a", req.Isolate.A}, {"b", req.Isolate.B}} {
		if s.side == nil {
			return invalid("isolate.%s is missing", s.label)
		}
		if err := validateSide(*s.side); err != nil {
			return invalid("isolate.%s: %v", s.label, err)
		}
	}
	return nil
}

func validateSide(s Side) error {
	switch {
	case s.Namespace != "" && len(s.Namespaces) > 0:
		return fmt.Errorf("set namespace or namespaces, not both")
	case s.Namespace == "" && len(s.Namespaces) == 0:
		return fmt.Errorf("set one of namespace or namespaces")
	case len(s.Namespaces) > maxNamespacesLen:
		return fmt.Errorf("namespaces has %d entries, at most %d are allowed", len(s.Namespaces), maxNamespacesLen)
	}
	namespaces := s.Namespaces
	if s.Namespace != "" {
		namespaces = []string{s.Namespace}
	}
	for _, ns := range namespaces {
		if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
			return fmt.Errorf("namespace %q: %s", ns, errs[0])
		}
	}
	// The apimachinery conversion validates label keys, values, operators and
	// the operator/values combination exactly as the API server would.
	if _, err := metav1.LabelSelectorAsSelector(labelSelector(s)); err != nil {
		return fmt.Errorf("selector: %w", err)
	}
	return nil
}

// labelSelector returns the side's selector in its Kubernetes form.
func labelSelector(s Side) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: s.Selector, MatchExpressions: s.MatchExpressions}
}
