package isolation

import (
	"slices"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// namespaceNameLabel is set by the API server on every namespace and cannot
// be changed, so it safely targets a namespace by name.
const namespaceNameLabel = "kubernetes.io/metadata.name"

// Negate returns the requirement that matches exactly the pods r does not:
// In ↔ NotIn and Exists ↔ DoesNotExist, values unchanged. NotIn and
// DoesNotExist also match pods without the key, which is what negating In and
// Exists needs.
func Negate(r metav1.LabelSelectorRequirement) metav1.LabelSelectorRequirement {
	negated := map[metav1.LabelSelectorOperator]metav1.LabelSelectorOperator{
		metav1.LabelSelectorOpIn:           metav1.LabelSelectorOpNotIn,
		metav1.LabelSelectorOpNotIn:        metav1.LabelSelectorOpIn,
		metav1.LabelSelectorOpExists:       metav1.LabelSelectorOpDoesNotExist,
		metav1.LabelSelectorOpDoesNotExist: metav1.LabelSelectorOpExists,
	}
	return metav1.LabelSelectorRequirement{Key: r.Key, Operator: negated[r.Operator], Values: slices.Clone(r.Values)}
}

// ComplementPeers returns peers that together admit every pod in namespace
// that side's selector does not select. By De Morgan, ¬(r1 ∧ r2) = ¬r1 ∨ ¬r2:
// one peer per negated requirement, and peers are OR'd. Each peer pairs the
// namespace and pod selectors in one entry, so they are AND'd.
// An empty selector selects every pod, so its complement is no peers at all.
func ComplementPeers(namespace string, side Side) []networkingv1.NetworkPolicyPeer {
	var peers []networkingv1.NetworkPolicyPeer
	for _, r := range requirements(side) {
		peers = append(peers, networkingv1.NetworkPolicyPeer{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{namespaceNameLabel: namespace}},
			PodSelector:       &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{Negate(r)}},
		})
	}
	return peers
}

// requirements flattens a side's selector into one list, with matchLabels
// k: v as k In [v], sorted by (key, operator) so peers come out in a
// deterministic order.
func requirements(side Side) []metav1.LabelSelectorRequirement {
	var reqs []metav1.LabelSelectorRequirement
	for k, v := range side.Selector {
		reqs = append(reqs, metav1.LabelSelectorRequirement{Key: k, Operator: metav1.LabelSelectorOpIn, Values: []string{v}})
	}
	reqs = append(reqs, side.MatchExpressions...)
	slices.SortStableFunc(reqs, func(x, y metav1.LabelSelectorRequirement) int {
		if c := strings.Compare(x.Key, y.Key); c != 0 {
			return c
		}
		if c := strings.Compare(string(x.Operator), string(y.Operator)); c != 0 {
			return c
		}
		return slices.Compare(x.Values, y.Values)
	})
	return reqs
}
