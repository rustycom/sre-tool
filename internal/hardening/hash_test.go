package hardening

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestHash_StableAcrossStatusAndResourceVersion(t *testing.T) {
	base := func() Input {
		return Input{
			Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}},
			Deployments: []appsv1.Deployment{{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: "u1", ResourceVersion: "100", Generation: 1},
				Spec:       appsv1.DeploymentSpec{Replicas: new(int32(2)), Template: template()},
			}},
		}
	}
	want := BuildPlan(base(), testDefaults).PlanHash

	tests := []struct {
		name     string
		mutate   func(*appsv1.Deployment)
		wantSame bool
	}{
		{"resourceVersion bumped", func(d *appsv1.Deployment) { d.ResourceVersion = "101" }, true},
		{"status written", func(d *appsv1.Deployment) {
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 2}
		}, true},
		{"generation bumped", func(d *appsv1.Deployment) { d.Generation = 7 }, true},
		{"scaled by an HPA", func(d *appsv1.Deployment) { d.Spec.Replicas = new(int32(5)) }, true},
		{"label on the Deployment", func(d *appsv1.Deployment) { d.Labels = map[string]string{"team": "x"} }, true},
		{"image changed", func(d *appsv1.Deployment) { d.Spec.Template.Spec.Containers[0].Image = "img:v2" }, false},
		{"template label changed", func(d *appsv1.Deployment) { d.Spec.Template.Labels = map[string]string{"v": "2"} }, false},
		{"recreated with a new UID", func(d *appsv1.Deployment) { d.UID = "u2" }, false},
		{"skip annotation added", func(d *appsv1.Deployment) { d.Annotations = map[string]string{SkipAnnotation: "true"} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := base()
			tt.mutate(&in.Deployments[0])
			got := BuildPlan(in, testDefaults).PlanHash
			if (got == want) != tt.wantSame {
				t.Errorf("hash same = %v, want %v (%s vs %s)", got == want, tt.wantSame, got, want)
			}
		})
	}
}
