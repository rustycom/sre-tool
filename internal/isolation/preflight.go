package isolation

import (
	"fmt"
	"net/http"
	"slices"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Conflict is an existing policy that already selects a side's pods for
// ingress, so the isolation could not mean what it says (FR-ISO-04).
type Conflict struct {
	Policy      string `json:"policy"` // namespace/name
	Side        string `json:"side"`
	IsolationID string `json:"isolationId,omitempty"` // set when another isolation owns it
}

// Preflight returns the policies that conflict with the isolation id.
// policies and pods cover the namespaces of both sides. Policies are additive
// allow-lists (I-1): an existing ingress policy on a side either already
// admits the other side, which the new policy cannot take away, or restricts
// the side, which the new "everything except the other side" policy would
// widen. Only pods that exist now are considered (SPEC §6.4).
func Preflight(normalized Request, id string, policies []networkingv1.NetworkPolicy, pods []corev1.Pod) []Conflict {
	var conflicts []Conflict
	for _, s := range []struct {
		name string
		side Side
	}{{"a", *normalized.Isolate.A}, {"b", *normalized.Isolate.B}} {
		sideSel, err := metav1.LabelSelectorAsSelector(labelSelector(s.side))
		if err != nil {
			continue // unreachable: Validate checked the selector
		}
		for _, p := range policies {
			if !slices.Contains(s.side.Namespaces, p.Namespace) || isOwnPolicy(p, id) ||
				!slices.Contains(p.Spec.PolicyTypes, networkingv1.PolicyTypeIngress) {
				continue
			}
			if selectsAnySidePod(p, sideSel, pods) {
				c := Conflict{Policy: p.Namespace + "/" + p.Name, Side: s.name}
				if p.Labels[LabelManagedBy] == ManagedByValue {
					c.IsolationID = p.Labels[LabelIsolationID]
				}
				conflicts = append(conflicts, c)
			}
		}
	}
	return conflicts
}

func isOwnPolicy(p networkingv1.NetworkPolicy, id string) bool {
	return p.Labels[LabelManagedBy] == ManagedByValue && p.Labels[LabelIsolationID] == id
}

// selectsAnySidePod reports whether p selects a live pod of the side in p's
// namespace. An empty podSelector selects every pod, including future ones,
// so it conflicts even when the side has no pods yet. A selector the API
// server accepted but we cannot parse counts as a conflict (fail closed).
func selectsAnySidePod(p networkingv1.NetworkPolicy, sideSel labels.Selector, pods []corev1.Pod) bool {
	if len(p.Spec.PodSelector.MatchLabels) == 0 && len(p.Spec.PodSelector.MatchExpressions) == 0 {
		return true
	}
	polSel, err := metav1.LabelSelectorAsSelector(&p.Spec.PodSelector)
	if err != nil {
		return true
	}
	for _, pod := range pods {
		if pod.Namespace != p.Namespace || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		set := labels.Set(pod.Labels)
		if sideSel.Matches(set) && polSel.Matches(set) {
			return true
		}
	}
	return false
}

// conflictError is the 409 returned when conflicts exist and force is false.
func conflictError(conflicts []Conflict) *Error {
	return &Error{
		Status: http.StatusConflict,
		Code:   "conflicting_policies",
		Message: fmt.Sprintf("%d existing NetworkPolicies already select these pods for ingress; policies are additive, "+
			"so isolation could not block traffic they allow and would widen traffic they restrict (set force to proceed anyway)", len(conflicts)),
		Details: map[string]any{"policies": conflicts},
	}
}
