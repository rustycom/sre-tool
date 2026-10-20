package isolation

import (
	"reflect"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func TestNegate_Table(t *testing.T) {
	tests := []struct {
		in, want metav1.LabelSelectorOperator
		values   []string
	}{
		{metav1.LabelSelectorOpIn, metav1.LabelSelectorOpNotIn, []string{"x", "y"}},
		{metav1.LabelSelectorOpNotIn, metav1.LabelSelectorOpIn, []string{"x"}},
		{metav1.LabelSelectorOpExists, metav1.LabelSelectorOpDoesNotExist, nil},
		{metav1.LabelSelectorOpDoesNotExist, metav1.LabelSelectorOpExists, nil},
	}
	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			got := Negate(metav1.LabelSelectorRequirement{Key: "app", Operator: tt.in, Values: tt.values})
			want := metav1.LabelSelectorRequirement{Key: "app", Operator: tt.want, Values: tt.values}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Negate = %+v, want %+v", got, want)
			}
		})
	}
}

// TestComplement_MatchesExactlyNonMembers is tricky test #1 (TESTING §4). For
// every label set over a small universe, including sets that lack a key, a pod
// must match some complement peer if and only if it does not match the side's
// selector. The oracle is apimachinery's own selector matching, the code the
// API server and CNIs use, so the test does not trust our reading of the
// operators. It fails if NotIn were replaced by "Exists and !=", which would
// miss pods without the key, or if the namespace and pod selectors were split
// into separate (OR'd) peers.
func TestComplement_MatchesExactlyNonMembers(t *testing.T) {
	const ns = "tenant-b"
	in := func(k string, v ...string) metav1.LabelSelectorRequirement {
		return metav1.LabelSelectorRequirement{Key: k, Operator: metav1.LabelSelectorOpIn, Values: v}
	}
	notIn := func(k string, v ...string) metav1.LabelSelectorRequirement {
		return metav1.LabelSelectorRequirement{Key: k, Operator: metav1.LabelSelectorOpNotIn, Values: v}
	}
	exists := func(k string) metav1.LabelSelectorRequirement {
		return metav1.LabelSelectorRequirement{Key: k, Operator: metav1.LabelSelectorOpExists}
	}
	doesNotExist := func(k string) metav1.LabelSelectorRequirement {
		return metav1.LabelSelectorRequirement{Key: k, Operator: metav1.LabelSelectorOpDoesNotExist}
	}
	tests := []struct {
		name string
		side Side
	}{
		{"matchLabels one key", Side{Selector: map[string]string{"app": "x"}}},
		{"matchLabels two keys", Side{Selector: map[string]string{"app": "x", "tier": "y"}}},
		{"In", Side{MatchExpressions: []metav1.LabelSelectorRequirement{in("app", "x", "y")}}},
		{"NotIn", Side{MatchExpressions: []metav1.LabelSelectorRequirement{notIn("app", "x")}}},
		{"Exists", Side{MatchExpressions: []metav1.LabelSelectorRequirement{exists("tier")}}},
		{"DoesNotExist", Side{MatchExpressions: []metav1.LabelSelectorRequirement{doesNotExist("tier")}}},
		{"matchLabels and expressions", Side{Selector: map[string]string{"app": "x"},
			MatchExpressions: []metav1.LabelSelectorRequirement{notIn("tier", "z"), exists("tier")}}},
		{"three requirements on two keys", Side{MatchExpressions: []metav1.LabelSelectorRequirement{
			in("app", "x", "z"), doesNotExist("tier"), notIn("app", "y")}}},
		{"empty selector (all pods)", Side{}},
	}

	// Every label set over keys {app, tier} with values {x, y, z}, each key
	// possibly absent: 4 × 4 = 16 sets, including the empty set.
	var universe []labels.Set
	for _, app := range []string{"", "x", "y", "z"} {
		for _, tier := range []string{"", "x", "y", "z"} {
			set := labels.Set{}
			if app != "" {
				set["app"] = app
			}
			if tier != "" {
				set["tier"] = tier
			}
			universe = append(universe, set)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector, err := metav1.LabelSelectorAsSelector(labelSelector(tt.side))
			if err != nil {
				t.Fatalf("selector: %v", err)
			}
			peers := ComplementPeers(ns, tt.side)
			for _, podLabels := range universe {
				member := selector.Matches(podLabels)
				if got := admitted(t, peers, ns, podLabels); got == member {
					t.Errorf("pod %v: side selects it = %v, complement admits it = %v; want exactly one", podLabels, member, got)
				}
				if admitted(t, peers, "other-ns", podLabels) {
					t.Errorf("pod %v in another namespace is admitted by a peer for %s", podLabels, ns)
				}
			}
		})
	}
}

// admitted reports whether any peer selects a pod with podLabels in namespace
// ns, evaluating peers as Kubernetes does: OR across peers, AND within one.
func admitted(t *testing.T, peers []networkingv1.NetworkPolicyPeer, ns string, podLabels labels.Set) bool {
	t.Helper()
	nsLabels := labels.Set{namespaceNameLabel: ns}
	for _, p := range peers {
		nsSel, err := metav1.LabelSelectorAsSelector(p.NamespaceSelector)
		if err != nil {
			t.Fatalf("namespace selector: %v", err)
		}
		podSel, err := metav1.LabelSelectorAsSelector(p.PodSelector)
		if err != nil {
			t.Fatalf("pod selector: %v", err)
		}
		if nsSel.Matches(nsLabels) && podSel.Matches(podLabels) {
			return true
		}
	}
	return false
}
