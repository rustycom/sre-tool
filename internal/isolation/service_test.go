package isolation

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/events"
)

type fakeGauge struct{ v float64 }

func (g *fakeGauge) Set(v float64) { g.v = v }

// fixture is a fake cluster with the tenant namespaces and the brief's pods,
// plus extra objects.
func fixture(extra ...runtime.Object) *fake.Clientset {
	objs := []runtime.Object{}
	for _, ns := range []string{"tenant-a", "tenant-b", "tenant-c", "kube-system"} {
		objs = append(objs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	}
	for i := range briefPods {
		objs = append(objs, &briefPods[i])
	}
	return fake.NewClientset(append(objs, extra...)...)
}

func newService(client *fake.Clientset) (*Service, *events.FakeRecorder, *fakeGauge) {
	rec, g := events.NewFakeRecorder(100), &fakeGauge{}
	return NewService(client, rec, testCIDRs, map[string]bool{"kube-system": true}, g), rec, g
}

// wantError fails unless err is an *Error with the given status and code,
// and returns its details.
func wantError(t *testing.T, err error, status int, code string) map[string]any {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Status != status || e.Code != code {
		t.Fatalf("err = %v, want %d %s", err, status, code)
	}
	return e.Details
}

func getPolicy(t *testing.T, c *fake.Clientset, ns, name string) *networkingv1.NetworkPolicy {
	t.Helper()
	p, err := c.NetworkingV1().NetworkPolicies(ns).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s/%s: %v", ns, name, err)
	}
	return p
}

// writes returns the create, update, patch and delete actions recorded.
func writes(c *fake.Clientset) []k8stesting.Action {
	var out []k8stesting.Action
	for _, a := range c.Actions() {
		if slices.Contains([]string{"create", "update", "patch", "delete"}, a.GetVerb()) {
			out = append(out, a)
		}
	}
	return out
}

func drain(rec *events.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func TestCreate_CreatesBothPoliciesWithEvents(t *testing.T) {
	ctx := context.Background()
	client := fixture()
	svc, rec, gauge := newService(client)

	res, err := svc.Create(ctx, briefRequest())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := []string{"tenant-a/sre-iso-" + res.ID + "-a", "tenant-b/sre-iso-" + res.ID + "-b"}
	if !reflect.DeepEqual(res.Created, want) {
		t.Errorf("Created = %v, want %v", res.Created, want)
	}
	if gauge.v != 1 {
		t.Errorf("active gauge = %v, want 1", gauge.v)
	}
	evs := drain(rec)
	if len(evs) != 2 || !strings.Contains(evs[0], "Normal IsolationApplied") {
		t.Errorf("events = %v, want two IsolationApplied", evs)
	}
}

func TestCreate_Idempotent(t *testing.T) {
	ctx := context.Background()
	client := fixture()
	svc, _, _ := newService(client)
	if _, err := svc.Create(ctx, briefRequest()); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	client.ClearActions()

	res, err := svc.Create(ctx, briefRequest())
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if len(res.Created) != 0 || len(res.Repaired) != 0 || len(res.Unchanged) != 2 {
		t.Errorf("result = %+v, want 2 unchanged only", res)
	}
	// The fake never sets resourceVersion (FINDINGS A7), so only the action
	// log can prove that the second call wrote nothing.
	if w := writes(client); len(w) != 0 {
		t.Errorf("second call recorded writes: %v", w)
	}
}

func TestCreate_RepairsMissingAndDriftedPolicies(t *testing.T) {
	ctx := context.Background()
	client := fixture()
	svc, _, _ := newService(client)
	res, err := svc.Create(ctx, briefRequest())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	nameA, nameB := "sre-iso-"+res.ID+"-a", "sre-iso-"+res.ID+"-b"
	want := getPolicy(t, client, "tenant-b", nameB).Spec

	// Someone deletes side a's policy and widens side b's.
	if err := client.NetworkingV1().NetworkPolicies("tenant-a").Delete(ctx, nameA, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	edited := getPolicy(t, client, "tenant-b", nameB)
	edited.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{}} // allow all
	edited.Labels["team"] = "web"                                     // a label someone else added
	if _, err := client.NetworkingV1().NetworkPolicies("tenant-b").Update(ctx, edited, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}

	res, err = svc.Create(ctx, briefRequest())
	if err != nil {
		t.Fatalf("repair Create: %v", err)
	}
	if !reflect.DeepEqual(res.Created, []string{"tenant-a/" + nameA}) || !reflect.DeepEqual(res.Repaired, []string{"tenant-b/" + nameB}) {
		t.Errorf("result = %+v, want a created and b repaired", res)
	}
	got := getPolicy(t, client, "tenant-b", nameB)
	if !reflect.DeepEqual(got.Spec, want) {
		t.Errorf("repaired spec = %+v, want %+v", got.Spec, want)
	}
	if got.Labels["team"] != "web" {
		t.Errorf("repair dropped a label it does not own: %v", got.Labels)
	}
}

func TestCreate_RefusesToOverwriteUnmanagedPolicy(t *testing.T) {
	ctx := context.Background()
	n := Normalize(briefRequest())
	squatter := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-b", Name: PolicyName(ID(n), "b")},
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"x": "y"}}},
	}
	client := fixture(squatter.DeepCopy())
	svc, _, _ := newService(client)

	_, err := svc.Create(ctx, briefRequest())
	wantError(t, err, http.StatusConflict, "name_conflict")
	if got := getPolicy(t, client, "tenant-b", squatter.Name); !reflect.DeepEqual(got, squatter) {
		t.Errorf("unmanaged policy changed: %+v", got)
	}
	// Ownership is checked for every name before any write, so side a's
	// policy was not created either.
	if w := writes(client); len(w) != 0 {
		t.Errorf("recorded writes: %v", w)
	}
}

func TestCreate_NamedRequestWithDifferentIdentityConflicts(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newService(fixture())
	req := briefRequest()
	req.Name = "gw-dash"
	if _, err := svc.Create(ctx, req); err != nil {
		t.Fatalf("Create: %v", err)
	}
	other := briefRequest()
	other.Name = "gw-dash"
	other.Isolate.B.Namespace = "tenant-c"
	_, err := svc.Create(ctx, other)
	wantError(t, err, http.StatusConflict, "name_conflict")

	// Same identity with force added is not a name conflict (SPEC §6.2).
	req.Force = true
	if _, err := svc.Create(ctx, req); err != nil {
		t.Errorf("same identity with force: %v", err)
	}
}

func TestCreate_PartialFailureKeepsCreatedPolicies(t *testing.T) {
	ctx := context.Background()
	client := fixture()
	creates := 0
	client.PrependReactor("create", "networkpolicies", func(k8stesting.Action) (bool, runtime.Object, error) {
		creates++
		if creates == 2 {
			return true, nil, errors.New("injected API failure")
		}
		return false, nil, nil
	})
	svc, _, _ := newService(client)

	_, err := svc.Create(ctx, briefRequest())
	details := wantError(t, err, http.StatusInternalServerError, "partial_apply")
	id := ID(Normalize(briefRequest()))
	if got := details["created"]; !reflect.DeepEqual(got, []string{"tenant-a/sre-iso-" + id + "-a"}) {
		t.Errorf("details.created = %v", got)
	}
	if got, _ := details["failed"].([]string); len(got) != 1 || !strings.Contains(got[0], "tenant-b/") {
		t.Errorf("details.failed = %v", details["failed"])
	}
	// No rollback: the first policy is still there.
	getPolicy(t, client, "tenant-a", "sre-iso-"+id+"-a")
}

func TestPreflight_ForceProceedsWithWarnings(t *testing.T) {
	ctx := context.Background()
	deny := testPolicy("tenant-b", "default-deny", nil, nil, ingress)
	client := fixture(&deny)
	svc, rec, _ := newService(client)

	_, err := svc.Create(ctx, briefRequest())
	details := wantError(t, err, http.StatusConflict, "conflicting_policies")
	if !reflect.DeepEqual(details["policies"], []Conflict{{Policy: "tenant-b/default-deny", Side: "b"}}) {
		t.Errorf("details.policies = %+v", details["policies"])
	}

	req := briefRequest()
	req.Force = true
	res, err := svc.Create(ctx, req)
	if err != nil {
		t.Fatalf("forced Create: %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "tenant-b/default-deny") {
		t.Errorf("warnings = %v", res.Warnings)
	}
	for _, name := range res.Created {
		ns, n, _ := strings.Cut(name, "/")
		if got := getPolicy(t, client, ns, n).Annotations[AnnotationForced]; got != "true" {
			t.Errorf("%s forced annotation = %q, want true", name, got)
		}
	}
	var warnings int
	for _, ev := range drain(rec) {
		if strings.HasPrefix(ev, "Warning IsolationForced") {
			warnings++
		}
	}
	if warnings != 2 {
		t.Errorf("IsolationForced events = %d, want 2", warnings)
	}
}
