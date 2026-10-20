package isolation

import (
	"net/http"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testPod(ns, name string, lbls map[string]string) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbls},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
}

// testPolicy returns a policy in ns selecting podLabels (nil = every pod).
func testPolicy(ns, name string, podLabels, objLabels map[string]string, types ...networkingv1.PolicyType) networkingv1.NetworkPolicy {
	return networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: objLabels},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: podLabels},
			PolicyTypes: types,
		},
	}
}

var (
	ingress    = networkingv1.PolicyTypeIngress
	egress     = networkingv1.PolicyTypeEgress
	gwLabels   = map[string]string{"app": "gateway"}
	dashLabels = map[string]string{"app": "dashboard"}
	briefPods  = []corev1.Pod{
		testPod("tenant-a", "gw-1", gwLabels),
		testPod("tenant-a", "other-1", map[string]string{"app": "other"}),
		testPod("tenant-b", "dash-1", dashLabels),
	}
)

// preflightBrief runs Preflight for the brief's request against policies.
func preflightBrief(policies ...networkingv1.NetworkPolicy) (string, []Conflict) {
	n := Normalize(briefRequest())
	id := ID(n)
	return id, Preflight(n, id, policies, briefPods)
}

func TestPreflight_ConflictWhenExistingPolicySelectsSide(t *testing.T) {
	_, got := preflightBrief(
		testPolicy("tenant-a", "allow-gw", gwLabels, nil, ingress),
		testPolicy("tenant-a", "other-only", map[string]string{"app": "other"}, nil, ingress), // selects no side pod
		testPolicy("tenant-c", "elsewhere", nil, nil, ingress),                                // not a side namespace
	)
	want := []Conflict{{Policy: "tenant-a/allow-gw", Side: "a"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("conflicts = %+v, want %+v", got, want)
	}
	err := conflictError(got)
	if err.Status != http.StatusConflict || err.Code != "conflicting_policies" {
		t.Errorf("error = %d %s, want 409 conflicting_policies", err.Status, err.Code)
	}
	if !reflect.DeepEqual(err.Details["policies"], want) {
		t.Errorf("details.policies = %+v, want %+v", err.Details["policies"], want)
	}
}

func TestPreflight_EmptyPodSelectorConflicts(t *testing.T) {
	// The deny-all shape: selects every pod in tenant-b, so side b.
	_, got := preflightBrief(testPolicy("tenant-b", "default-deny", nil, nil, ingress))
	want := []Conflict{{Policy: "tenant-b/default-deny", Side: "b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("conflicts = %+v, want %+v", got, want)
	}
}

func TestPreflight_EgressOnlyPolicyIsNotAConflict(t *testing.T) {
	_, got := preflightBrief(
		testPolicy("tenant-a", "egress-only", gwLabels, nil, egress),
		testPolicy("tenant-b", "egress-all", nil, nil, egress),
	)
	if len(got) != 0 {
		t.Fatalf("conflicts = %+v, want none", got)
	}
}

func TestPreflight_OtherIsolationOnSameSideConflicts(t *testing.T) {
	n := Normalize(briefRequest())
	id := ID(n)
	own := BuildPolicies(n, id, testCIDRs) // this isolation's policies: never a conflict
	managed := func(isoID string) map[string]string {
		return map[string]string{LabelManagedBy: ManagedByValue, LabelIsolationID: isoID}
	}
	policies := append(own, testPolicy("tenant-a", "sre-iso-other-a", gwLabels, managed("other"), ingress))

	got := Preflight(n, id, policies, briefPods)
	want := []Conflict{{Policy: "tenant-a/sre-iso-other-a", Side: "a", IsolationID: "other"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("conflicts = %+v, want %+v", got, want)
	}
}
