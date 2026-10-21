package isolation

import (
	"slices"
	"strconv"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Labels and annotations on every policy the tool creates.
const (
	LabelManagedBy           = "app.kubernetes.io/managed-by"
	ManagedByValue           = "sre-tool"
	LabelIsolationID         = "sre-tool.io/isolation-id"
	LabelSide                = "sre-tool.io/side"
	AnnotationRequest        = "sre-tool.io/request"
	AnnotationExpectedPolicy = "sre-tool.io/expected-policies"
	AnnotationForced         = "sre-tool.io/forced"
)

// BuildPolicies returns one ingress-only NetworkPolicy per (side, namespace)
// for a normalised request. Each policy selects its side's pods
// and admits everything except the other side. Ingress on both sides is
// enough to stop new connections in both directions, and leaving egress alone
// keeps DNS working. The output order is deterministic: side a's
// namespaces, then side b's, each sorted.
func BuildPolicies(normalized Request, id string, podCIDRs []string) []networkingv1.NetworkPolicy {
	a, b := *normalized.Isolate.A, *normalized.Isolate.B
	expected := strconv.Itoa(len(a.Namespaces) + len(b.Namespaces))
	identity := Identity(normalized)

	var policies []networkingv1.NetworkPolicy
	for _, s := range []struct {
		name        string
		self, other Side
	}{{"a", a, b}, {"b", b, a}} {
		for _, ns := range s.self.Namespaces {
			policies = append(policies, networkingv1.NetworkPolicy{
				TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
				ObjectMeta: metav1.ObjectMeta{
					Name:      PolicyName(id, s.name),
					Namespace: ns,
					Labels: map[string]string{
						LabelManagedBy:   ManagedByValue,
						LabelIsolationID: id,
						LabelSide:        s.name,
					},
					Annotations: map[string]string{
						AnnotationRequest:        identity,
						AnnotationExpectedPolicy: expected,
					},
				},
				Spec: networkingv1.NetworkPolicySpec{
					PodSelector: *labelSelector(s.self).DeepCopy(),
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					Ingress:     []networkingv1.NetworkPolicyIngressRule{{From: peersExcluding(s.other, podCIDRs)}},
				},
			})
		}
	}
	return policies
}

// peersExcluding admits every source except the pods of side y, in a fixed
// order: pods outside y's namespaces, then the complement of y's
// selector inside each of them, then non-pod traffic. An empty y selector
// yields no complement peers, so y's namespaces are blocked entirely.
func peersExcluding(y Side, podCIDRs []string) []networkingv1.NetworkPolicyPeer {
	peers := []networkingv1.NetworkPolicyPeer{{
		NamespaceSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: namespaceNameLabel, Operator: metav1.LabelSelectorOpNotIn, Values: slices.Clone(y.Namespaces),
		}}},
	}}
	for _, ns := range y.Namespaces {
		peers = append(peers, ComplementPeers(ns, y)...)
	}
	// The except keeps a CNI that matches ipBlocks against pod IPs from
	// re-admitting y through this peer.
	return append(peers, networkingv1.NetworkPolicyPeer{
		IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0", Except: slices.Clone(podCIDRs)},
	})
}
