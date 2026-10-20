package isolation

import (
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGuards_Table(t *testing.T) {
	pod := func(ns, name string, phase corev1.PodPhase, lbls map[string]string) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: lbls}, Status: corev1.PodStatus{Phase: phase}}
	}
	cluster := func(pods ...corev1.Pod) Cluster {
		return Cluster{
			Protected:  map[string]bool{"kube-system": true, "sre-tool": true},
			Namespaces: map[string]bool{"tenant-a": true, "tenant-b": true, "kube-system": true, "sre-tool": true},
			Pods:       pods,
		}
	}
	side := func(ns string, lbls map[string]string) *Side { return &Side{Namespace: ns, Selector: lbls} }
	gw, dash := map[string]string{"app": "gateway"}, map[string]string{"app": "dashboard"}

	tests := []struct {
		name       string
		req        Request
		cluster    Cluster
		wantStatus int // 0 means no error
		wantCode   string
	}{
		{"brief example passes", briefRequest(), cluster(), 0, ""},
		{"protected namespace", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("kube-system", dash)}},
			cluster(), http.StatusForbidden, "forbidden_namespace"},
		{"own namespace is protected", Request{Isolate: Pair{A: side("sre-tool", gw), B: side("tenant-b", dash)}},
			cluster(), http.StatusForbidden, "forbidden_namespace"},
		{"protected wins over missing", Request{Isolate: Pair{A: side("nope", gw), B: side("kube-system", dash)}},
			cluster(), http.StatusForbidden, "forbidden_namespace"},
		{"missing namespace", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-x", dash)}},
			cluster(), http.StatusUnprocessableEntity, "namespace_not_found"},
		{"empty selector", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-b", nil)}},
			cluster(), http.StatusUnprocessableEntity, "empty_selector"},
		{"empty selector allowed", Request{AllowEmptySelector: true, Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-b", nil)}},
			cluster(), 0, ""},
		{"overlap by live pod", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-a", map[string]string{"tier": "web"})}},
			cluster(pod("tenant-a", "both", corev1.PodRunning, map[string]string{"app": "gateway", "tier": "web"})),
			http.StatusUnprocessableEntity, "overlapping_sides"},
		{"overlap by pending pod", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-a", map[string]string{"tier": "web"})}},
			cluster(pod("tenant-a", "both", corev1.PodPending, map[string]string{"app": "gateway", "tier": "web"})),
			http.StatusUnprocessableEntity, "overlapping_sides"},
		{"terminated pod does not overlap", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-a", map[string]string{"tier": "web"})}},
			cluster(pod("tenant-a", "done", corev1.PodSucceeded, map[string]string{"app": "gateway", "tier": "web"}),
				pod("tenant-a", "crashed", corev1.PodFailed, map[string]string{"app": "gateway", "tier": "web"})), 0, ""},
		{"matching labels in a namespace only one side covers", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-b", map[string]string{"tier": "web"})}},
			cluster(pod("tenant-a", "both", corev1.PodRunning, map[string]string{"app": "gateway", "tier": "web"})), 0, ""},
		{"identical selectors in the same namespace", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-a", gw)}},
			cluster(), http.StatusUnprocessableEntity, "overlapping_sides"},
		{"identical empty selectors in the same namespace", Request{AllowEmptySelector: true, Isolate: Pair{A: side("tenant-a", nil), B: side("tenant-a", nil)}},
			cluster(), http.StatusUnprocessableEntity, "overlapping_sides"},
		{"identical selectors in different namespaces", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-b", gw)}},
			cluster(), 0, ""},
		{"same namespace, disjoint selectors", Request{Isolate: Pair{A: side("tenant-a", gw), B: side("tenant-a", dash)}},
			cluster(pod("tenant-a", "gw", corev1.PodRunning, gw), pod("tenant-a", "dash", corev1.PodRunning, dash)), 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Validate(tt.req); err != nil {
				t.Fatalf("test request is invalid: %v", err)
			}
			err := CheckGuards(Normalize(tt.req), tt.cluster)
			if tt.wantStatus == 0 {
				if err != nil {
					t.Fatalf("CheckGuards() = %v, want nil", err)
				}
				return
			}
			assertCode(t, err, tt.wantStatus, tt.wantCode)
		})
	}
}
