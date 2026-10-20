package hardening

import (
	"context"
	"errors"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDecode_ValidatesNamespacesAndHash(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		needHash bool
		want     []string // nil: want a 400
	}{
		{"sorted and de-duplicated", `{"namespaces":["b","a","b"]}`, false, []string{"a", "b"}},
		{"YAML body", "namespaces: [a]\n", false, []string{"a"}},
		{"empty list", `{"namespaces":[]}`, false, nil},
		{"over the maximum", `{"namespaces":["a","b","c"]}`, false, nil},
		{"invalid name", `{"namespaces":["Not_A_Name"]}`, false, nil},
		{"unknown field", `{"namespace":["a"]}`, false, nil},
		{"apply without hash", `{"namespaces":["a"]}`, true, nil},
		{"apply with hash", `{"namespaces":["a"],"planHash":"sha256:ab"}`, true, []string{"a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Decode([]byte(tt.body), 2, tt.needHash)
			var e *Error
			switch {
			case tt.want == nil && (!errors.As(err, &e) || e.Status != 400):
				t.Errorf("err = %v, want a 400", err)
			case tt.want != nil && err != nil:
				t.Errorf("err = %v", err)
			case tt.want != nil && !slices.Equal(r.Namespaces, tt.want):
				t.Errorf("namespaces = %v, want %v", r.Namespaces, tt.want)
			}
		})
	}
}

func TestCollect_GuardsAndListsOnlyRequestedNamespaces(t *testing.T) {
	ns := func(n string) *corev1.Namespace { return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}} }
	dep := func(ns, n string) *appsv1.Deployment {
		return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: n}}
	}
	client := fake.NewClientset(ns("demo"), ns("other"), ns("kube-system"), dep("demo", "a"), dep("other", "b"))
	protected := map[string]bool{"kube-system": true}

	in, err := Collect(context.Background(), client, []string{"demo"}, protected)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Namespaces) != 1 || len(in.Deployments) != 1 || in.Deployments[0].Name != "a" {
		t.Errorf("collected %d namespaces and deployments %+v, want demo/a only", len(in.Namespaces), in.Deployments)
	}

	for _, tt := range []struct {
		name       string
		namespaces []string
		status     int
		code       string
	}{
		{"protected", []string{"demo", "kube-system"}, 403, "forbidden_namespace"},
		{"missing", []string{"demo", "nope"}, 422, "namespace_not_found"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client.ClearActions()
			_, err := Collect(context.Background(), client, tt.namespaces, protected)
			var e *Error
			if !errors.As(err, &e) || e.Status != tt.status || e.Code != tt.code {
				t.Fatalf("err = %v, want %d %s", err, tt.status, tt.code)
			}
			if tt.code == "forbidden_namespace" && len(client.Actions()) != 0 {
				t.Errorf("a protected namespace was refused only after %d API calls", len(client.Actions()))
			}
		})
	}
}
