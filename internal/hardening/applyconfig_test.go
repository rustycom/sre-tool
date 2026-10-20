package hardening

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestApplyConfig_OnlyPlannedFieldsAndKeys(t *testing.T) {
	tpl := func(spec string) string { return `{"template":{"spec":` + spec + `}}` }
	podSpec := `{
		"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
		"initContainers": [{"name": "init", "securityContext": {"allowPrivilegeEscalation": false}}],
		"containers": [{"name": "app",
			"resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "512Mi"}},
			"securityContext": {"runAsNonRoot": true, "readOnlyRootFilesystem": true, "capabilities": {"drop": ["ALL"]}}}]
	}`
	changes := []Change{
		{Field: FieldSeccomp, To: "RuntimeDefault"},
		{Container: "init", Init: true, Field: FieldAllowPrivEsc, To: false},
		{Container: "app", Field: FieldCPURequest, To: "100m"},
		{Container: "app", Field: FieldMemoryRequest, To: "128Mi"},
		{Container: "app", Field: FieldMemoryLimit, To: "512Mi"},
		{Container: "app", Field: FieldRunAsNonRoot, To: true},
		{Container: "app", Field: FieldCapabilitiesDrop, To: []string{"ALL"}},
		{Container: "app", Field: FieldReadOnlyRootFS, To: true},
	}
	// Live objects with images and other fields that sre-tool does not own,
	// which must not appear in the patch.
	om := metav1.ObjectMeta{Namespace: "ns", Name: "w", Labels: map[string]string{"app": "w"}}
	live := corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init", Image: "img"}},
		Containers:     []corev1.Container{{Name: "app", Image: "img", Args: []string{"serve"}}},
	}}
	tests := []struct {
		kind, apiVersion, spec string
		live                   runtime.Object
	}{
		{"Deployment", "apps/v1", tpl(podSpec), &appsv1.Deployment{ObjectMeta: om, Spec: appsv1.DeploymentSpec{Replicas: new(int32(2)), Template: live}}},
		{"StatefulSet", "apps/v1", tpl(podSpec), &appsv1.StatefulSet{ObjectMeta: om, Spec: appsv1.StatefulSetSpec{Template: live}}},
		{"DaemonSet", "apps/v1", tpl(podSpec), &appsv1.DaemonSet{ObjectMeta: om, Spec: appsv1.DaemonSetSpec{Template: live}}},
		{"CronJob", "batch/v1", `{"jobTemplate":{"spec":` + tpl(podSpec) + `}}`, &batchv1.CronJob{ObjectMeta: om,
			Spec: batchv1.CronJobSpec{Schedule: "@daily", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: live}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			p, err := BuildPatch(Workload{Kind: tt.kind, Namespace: "ns", Name: "w", Changes: changes}, tt.live)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(p.config)
			if err != nil {
				t.Fatal(err)
			}
			want := `{"kind":"` + tt.kind + `","apiVersion":"` + tt.apiVersion + `","metadata":{"name":"w","namespace":"ns"},"spec":` + tt.spec + `}`
			var g, w any
			if err := json.Unmarshal(got, &g); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(want), &w); err != nil {
				t.Fatal(err)
			}
			// Anything beyond the planned fields and the container names would
			// make sre-tool own it, or overwrite it (I-15).
			if !reflect.DeepEqual(g, w) {
				t.Errorf("apply config =\n%s\nwant\n%s", got, want)
			}
		})
	}

	dep := &appsv1.Deployment{ObjectMeta: om, Spec: appsv1.DeploymentSpec{Template: live}}
	if _, err := BuildPatch(Workload{Kind: "Job", Changes: changes}, &batchv1.Job{ObjectMeta: om}); err == nil {
		t.Error("BuildPatch of a Job succeeded; Jobs are report-only")
	}
	for _, bad := range []Workload{
		{Kind: "Deployment", Changes: []Change{{Container: "app", Field: FieldCPURequest, To: "lots"}}},
		{Kind: "Deployment", Changes: []Change{{Container: "app", Field: "container.image", To: "x"}}},
		{Kind: "Deployment", Changes: []Change{{Field: FieldAllowPrivEsc, To: false}}},
	} {
		if _, err := BuildPatch(bad, dep); err == nil {
			t.Errorf("BuildPatch(%+v) succeeded, want an error", bad)
		}
	}
}

// The fake clientset merges an apply like the API server does (FINDINGS A7),
// so this shows a partial config keeps every field it does not name.
func TestPatch_SendMergesByContainerName(t *testing.T) {
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "w"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "img"}, {Name: "side", Image: "img2"}}}}}}
	client := fake.NewClientset(d)
	p, err := BuildPatch(Workload{Kind: "Deployment", Namespace: "ns", Name: "w",
		Changes: []Change{{Container: "side", Field: FieldAllowPrivEsc, To: false}}}, d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.send(context.Background(), client, false); err != nil {
		t.Fatal(err)
	}
	got, err := client.AppsV1().Deployments("ns").Get(context.Background(), "w", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cs := got.Spec.Template.Spec.Containers
	if len(cs) != 2 || cs[0].Image != "img" || cs[1].Image != "img2" ||
		cs[1].SecurityContext == nil || cs[1].SecurityContext.AllowPrivilegeEscalation == nil || cs[0].SecurityContext != nil {
		t.Errorf("containers after apply = %+v", cs)
	}
	var patch *k8stesting.PatchActionImpl
	for _, a := range client.Actions() {
		if pa, ok := a.(k8stesting.PatchActionImpl); ok {
			patch = &pa
		}
	}
	if patch == nil || patch.GetPatchType() != types.ApplyPatchType {
		t.Fatalf("actions = %v, want one apply patch", client.Actions())
	}
}

// A later apply must keep what earlier applies set. SSA removes fields the
// manager owned and no longer sends (I-17), so a patch that held only the
// new changes would strip earlier hardening, e.g. moving to strict would
// drop seccomp and the resource defaults.
func TestPatch_KeepsFieldsAppliedBefore(t *testing.T) {
	ctx := context.Background()
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "w"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "img"}}}}}}
	client := fake.NewClientset(d)
	apply := func(changes ...Change) {
		t.Helper()
		live, err := client.AppsV1().Deployments("ns").Get(ctx, "w", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		p, err := BuildPatch(Workload{Kind: "Deployment", Namespace: "ns", Name: "w", Changes: changes}, live)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.send(ctx, client, false); err != nil {
			t.Fatal(err)
		}
	}
	apply(Change{Field: FieldSeccomp, To: "RuntimeDefault"},
		Change{Container: "app", Field: FieldCPURequest, To: "100m"},
		Change{Container: "app", Field: FieldAllowPrivEsc, To: false})
	apply(Change{Container: "app", Field: FieldRunAsNonRoot, To: true},
		Change{Container: "app", Field: FieldMemoryRequest, To: "128Mi"})

	got, err := client.AppsV1().Deployments("ns").Get(ctx, "w", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	spec := got.Spec.Template.Spec
	c := spec.Containers[0]
	switch {
	case spec.SecurityContext == nil || spec.SecurityContext.SeccompProfile == nil:
		t.Errorf("seccomp from the first apply was removed: %+v", spec.SecurityContext)
	case c.Resources.Requests.Cpu().String() != "100m" || c.Resources.Requests.Memory().String() != "128Mi":
		t.Errorf("requests = %v, want cpu from the first apply and memory from the second", c.Resources.Requests)
	case c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || c.SecurityContext.RunAsNonRoot == nil:
		t.Errorf("container securityContext = %+v, want fields from both applies", c.SecurityContext)
	case c.Image != "img":
		t.Errorf("image = %q", c.Image)
	}
}
