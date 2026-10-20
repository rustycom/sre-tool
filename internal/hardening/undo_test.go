package hardening

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// appliedFixture is newFixture after a complete apply: a, b and c are
// hardened and sre-tool owns the fields it set. The fake clientset runs real
// server-side apply field ownership (FINDINGS A7), which is what undo uses.
func appliedFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	res, err := f.svc.Apply(context.Background(), []string{"demo"}, f.plan(t).PlanHash)
	if err != nil || res.Outcome != "complete" {
		t.Fatalf("apply: %v %+v", err, res)
	}
	f.client.ClearActions()
	f.waiter.got = nil
	return f
}

func (f *fixture) deployment(t *testing.T, name string) *appsv1.Deployment {
	t.Helper()
	d, err := f.client.AppsV1().Deployments("demo").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestUndo_RemovesOnlyOwnedFields(t *testing.T) {
	f := appliedFixture(t)
	// A human changes one tool-set field after apply, as `kubectl set
	// resources` does. An update takes ownership of a changed field (I-16), so
	// sre-tool no longer owns requests.cpu on a.
	a := f.deployment(t, "a")
	a.Spec.Template.Spec.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("200m")
	if _, err := f.client.AppsV1().Deployments("demo").Update(context.Background(), a, metav1.UpdateOptions{FieldManager: "kubectl-set"}); err != nil {
		t.Fatal(err)
	}

	res, err := f.svc.Undo(context.Background(), []string{"demo"}, false)
	if err != nil || res.Outcome != "complete" {
		t.Fatalf("undo: %v %+v", err, res)
	}
	if got, want := statuses(res), []string{"a=applied", "b=applied", "c=applied"}; !slices.Equal(got, want) {
		t.Errorf("statuses = %v, want %v", got, want)
	}
	if !slices.Equal(f.waiter.got, []string{"a", "b", "c"}) {
		t.Errorf("waited for %v, want every changed workload", f.waiter.got)
	}

	want := map[string]corev1.PodSpec{
		"a": {Containers: []corev1.Container{{Name: "app", Image: "img", Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m")}}}}},
		"b": {Containers: []corev1.Container{{Name: "app", Image: "img"}}},
	}
	for name, spec := range want {
		got := f.deployment(t, name).Spec.Template.Spec
		if got := emptyAsUnset(got); !equality.Semantic.DeepEqual(got, spec) {
			t.Errorf("%s after undo:\n got %+v\nwant %+v", name, got, spec)
		}
	}
	for _, ch := range res.Results[0].Changes {
		if ch.Field == FieldCPURequest {
			t.Errorf("undo reports the human's cpu request as released: %+v", ch)
		}
	}
	if len(res.Results[1].Changes) != 5 {
		t.Errorf("b released %+v, want the 5 planned fields", res.Results[1].Changes)
	}
}

// emptyAsUnset clears the empty securityContexts and resource lists that a
// removal can leave behind; the API server treats them as unset.
func emptyAsUnset(spec corev1.PodSpec) corev1.PodSpec {
	if sc := spec.SecurityContext; sc != nil && equality.Semantic.DeepEqual(*sc, corev1.PodSecurityContext{}) {
		spec.SecurityContext = nil
	}
	cs := slices.Clone(spec.Containers)
	for i := range cs {
		if sc := cs[i].SecurityContext; sc != nil && equality.Semantic.DeepEqual(*sc, corev1.SecurityContext{}) {
			cs[i].SecurityContext = nil
		}
		if len(cs[i].Resources.Requests) == 0 {
			cs[i].Resources.Requests = nil
		}
		if len(cs[i].Resources.Limits) == 0 {
			cs[i].Resources.Limits = nil
		}
	}
	spec.Containers = cs
	return spec
}

func TestUndo_SecondUndoChangesNothing(t *testing.T) {
	f := appliedFixture(t)
	if _, err := f.svc.Undo(context.Background(), []string{"demo"}, false); err != nil {
		t.Fatal(err)
	}
	before := f.deployment(t, "a").Spec.Template
	f.waiter.got = nil
	res, err := f.svc.Undo(context.Background(), []string{"demo"}, false)
	if err != nil || res.Outcome != "complete" {
		t.Fatalf("second undo: %v %+v", err, res)
	}
	for _, r := range res.Results {
		if len(r.Changes) != 0 {
			t.Errorf("second undo changed %s: %+v", r.Name, r.Changes)
		}
	}
	if len(f.waiter.got) != 0 {
		t.Errorf("second undo waited for rollouts of %v, want none", f.waiter.got)
	}
	if after := f.deployment(t, "a").Spec.Template; !equality.Semantic.DeepEqual(before, after) {
		t.Errorf("second undo changed the template:\nbefore %+v\n after %+v", before, after)
	}
}

func TestUndo_DryRunWritesNothing(t *testing.T) {
	f := appliedFixture(t)
	// The fake clientset would persist a dry-run (FINDINGS A7), so it goes
	// through the faked validator. b's result stands in for the API server's
	// answer: everything sre-tool set is gone.
	f.validator.got = nil
	f.validator.result = map[string]runtime.Object{"b": &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "img"}}}}}}}
	f.validator.fail = map[string]string{"c": "boom"}

	res, err := f.svc.Undo(context.Background(), []string{"demo"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.applied(); len(got) != 0 {
		t.Errorf("dry-run sent real applies to %v", got)
	}
	if !slices.Equal(f.validator.got, []string{"a", "b", "c"}) {
		t.Errorf("dry-ran %v, want a, b and c", f.validator.got)
	}
	if got, want := statuses(res), []string{"a=dry_run", "b=dry_run", "c=failed"}; !slices.Equal(got, want) || res.Outcome != "complete" {
		t.Errorf("outcome %s, statuses %v; want complete, %v", res.Outcome, got, want)
	}
	if len(res.Results[1].Changes) != 5 {
		t.Errorf("b would release %+v, want the 5 applied fields", res.Results[1].Changes)
	}
	for _, ch := range res.Results[1].Changes {
		if ch.To != nil {
			t.Errorf("b: %s would become %v, want unset", ch.Field, ch.To)
		}
	}
}

func TestUndo_HaltsOnRolloutFailure(t *testing.T) {
	f := appliedFixture(t)
	f.waiter.hook = func(_ context.Context, name string) error {
		if name == "b" {
			return errors.New("CreateContainerConfigError")
		}
		return nil
	}
	res, err := f.svc.Undo(context.Background(), []string{"demo"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := statuses(res), []string{"a=applied", "b=failed", "c=not_attempted"}; !slices.Equal(got, want) || res.Reason != "rollout_failed" {
		t.Errorf("reason %s, statuses %v; want rollout_failed, %v", res.Reason, got, want)
	}
	if got := f.applied(); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("applied %v, want a and b only", got)
	}
}

func TestUndo_SkipsWorkloadsSREToolNeverApplied(t *testing.T) {
	f := newFixture(t) // nothing applied yet
	res, err := f.svc.Undo(context.Background(), []string{"demo"}, false)
	if err != nil || len(res.Results) != 0 || len(f.applied()) != 0 {
		t.Errorf("undo before any apply: err %v, results %+v, applied %v; want nothing", err, res.Results, f.applied())
	}
}

func TestEmptyPatch_IdentityOnly(t *testing.T) {
	tests := []struct{ kind, want string }{
		{"Deployment", `{"kind":"Deployment","apiVersion":"apps/v1","metadata":{"name":"n","namespace":"ns"}}`},
		{"StatefulSet", `{"kind":"StatefulSet","apiVersion":"apps/v1","metadata":{"name":"n","namespace":"ns"}}`},
		{"DaemonSet", `{"kind":"DaemonSet","apiVersion":"apps/v1","metadata":{"name":"n","namespace":"ns"}}`},
		{"CronJob", `{"kind":"CronJob","apiVersion":"batch/v1","metadata":{"name":"n","namespace":"ns"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			b, err := json.Marshal(emptyPatch(Workload{Kind: tt.kind, Namespace: "ns", Name: "n"}).config)
			if err != nil || string(b) != tt.want {
				t.Errorf("config = %s (err %v), want %s", b, err, tt.want)
			}
		})
	}
	if p := emptyPatch(Workload{Kind: "Job"}); p.config != nil {
		t.Errorf("Job got config %v, want none", p.config)
	}
}

func TestFieldDiff(t *testing.T) {
	no := false
	hardened := corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		SecurityContext: &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		InitContainers: []corev1.Container{{Name: "init", SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: &no, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}},
		Containers: []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")}}}},
	}}
	tests := []struct {
		name          string
		before, after *corev1.PodTemplateSpec
		want          []Change
	}{
		{"identical", &hardened, &hardened, nil},
		{"everything released", &hardened, &corev1.PodTemplateSpec{}, []Change{
			{Container: "", Field: FieldSeccomp, From: "RuntimeDefault"},
			{Container: "app", Field: FieldCPURequest, From: "100m"},
			{Container: "init", Init: true, Field: FieldAllowPrivEsc, From: false},
			{Container: "init", Init: true, Field: FieldCapabilitiesDrop, From: []string{"ALL"}},
		}},
		{"a value changed", &hardened, &corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			SecurityContext: hardened.Spec.SecurityContext, InitContainers: hardened.Spec.InitContainers,
			Containers: []corev1.Container{{Name: "app", Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("200m")}}}}}},
			[]Change{{Container: "app", Field: FieldCPURequest, From: "100m", To: "200m"}}},
		{"nil templates", nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fieldDiff(tt.before, tt.after); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fieldDiff =\n %+v\nwant\n %+v", got, tt.want)
			}
		})
	}
}
