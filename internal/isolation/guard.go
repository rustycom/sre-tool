package isolation

import (
	"fmt"
	"net/http"
	"reflect"
	"slices"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Cluster is the snapshot the guards check a request against. The service
// fills it from the API, which keeps the rules here pure and table-testable.
type Cluster struct {
	Protected  map[string]bool // namespaces the tool must never touch
	Namespaces map[string]bool // namespaces that exist
	Pods       []corev1.Pod    // pods in the request's namespaces
}

// CheckGuards applies the cluster-dependent rules of FR-ISO-03 in SPEC order;
// the first failure wins. name_conflict needs the existing isolations and is
// checked by the service.
func CheckGuards(normalized Request, c Cluster) error {
	a, b := *normalized.Isolate.A, *normalized.Isolate.B
	all := append(slices.Clone(a.Namespaces), b.Namespaces...)

	for _, ns := range all {
		if c.Protected[ns] {
			return &Error{Status: http.StatusForbidden, Code: "forbidden_namespace",
				Message: fmt.Sprintf("namespace %s is protected and cannot be isolated", ns), Details: map[string]any{"namespace": ns}}
		}
	}
	for _, ns := range all {
		if !c.Namespaces[ns] {
			return &Error{Status: http.StatusUnprocessableEntity, Code: "namespace_not_found",
				Message: fmt.Sprintf("namespace %s does not exist", ns), Details: map[string]any{"namespace": ns}}
		}
	}
	if !normalized.AllowEmptySelector {
		for _, s := range []struct {
			name string
			side Side
		}{{"a", a}, {"b", b}} {
			if len(s.side.Selector) == 0 && len(s.side.MatchExpressions) == 0 {
				return &Error{Status: http.StatusUnprocessableEntity, Code: "empty_selector",
					Message: fmt.Sprintf("side %s has an empty selector, which selects every pod in its namespaces; set allowEmptySelector to confirm", s.name),
					Details: map[string]any{"side": s.name}}
			}
		}
	}
	return checkOverlap(a, b, c.Pods)
}

// checkOverlap refuses sides that select the same pod: its policies would
// block the pod from itself and its peers on both sides, which is never what
// an operator means. Selectors that only overlap for pods created later are
// not detected (SPEC §14).
func checkOverlap(a, b Side, pods []corev1.Pod) error {
	overlap := func(details map[string]any) error {
		return &Error{Status: http.StatusUnprocessableEntity, Code: "overlapping_sides",
			Message: "sides a and b select the same pods", Details: details}
	}
	// Compare flattened requirements, so {app: x} and "app In [x]" count as
	// identical.
	for _, ns := range a.Namespaces {
		if slices.Contains(b.Namespaces, ns) && reflect.DeepEqual(requirements(a), requirements(b)) {
			return overlap(map[string]any{"namespace": ns})
		}
	}
	// Both selectors were validated by Validate, so conversion cannot fail.
	selA, errA := metav1.LabelSelectorAsSelector(labelSelector(a))
	selB, errB := metav1.LabelSelectorAsSelector(labelSelector(b))
	if errA != nil || errB != nil {
		return invalid("selector: %v %v", errA, errB)
	}
	for _, p := range pods {
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		set := labels.Set(p.Labels)
		if slices.Contains(a.Namespaces, p.Namespace) && selA.Matches(set) &&
			slices.Contains(b.Namespaces, p.Namespace) && selB.Matches(set) {
			return overlap(map[string]any{"pod": p.Namespace + "/" + p.Name})
		}
	}
	return nil
}
