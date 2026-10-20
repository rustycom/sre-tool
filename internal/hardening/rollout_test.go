package hardening

import (
	"context"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// outcome is what an evaluator returned, as one comparable string.
func outcome(done bool, err error) string {
	switch {
	case err != nil:
		return "failed"
	case done:
		return "done"
	}
	return "waiting"
}

func TestRollout_DeploymentEvaluator(t *testing.T) {
	// A finished rollout of 2 replicas at generation 2.
	base := func(mut func(*appsv1.Deployment)) *appsv1.Deployment {
		d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Generation: 2}, Spec: appsv1.DeploymentSpec{Replicas: new(int32(2))},
			Status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 2, UpdatedReplicas: 2, AvailableReplicas: 2}}
		mut(d)
		return d
	}
	tests := []struct {
		name string
		d    *appsv1.Deployment
		want string
	}{
		{"complete", base(func(*appsv1.Deployment) {}), "done"},
		{"controller has not seen the patch", base(func(d *appsv1.Deployment) { d.Generation = 3 }), "waiting"},
		{"not all replicas updated", base(func(d *appsv1.Deployment) { d.Status.UpdatedReplicas = 1 }), "waiting"},
		{"old replicas still running", base(func(d *appsv1.Deployment) { d.Status.Replicas = 3 }), "waiting"},
		{"updated but unavailable", base(func(d *appsv1.Deployment) { d.Status.AvailableReplicas = 1 }), "waiting"},
		{"progress deadline exceeded", base(func(d *appsv1.Deployment) {
			d.Status.UpdatedReplicas = 1
			d.Status.Conditions = []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Reason: "ProgressDeadlineExceeded"}}
		}), "failed"},
		{"paused does not wait", base(func(d *appsv1.Deployment) { d.Spec.Paused, d.Generation = true, 3 }), "done"},
		{"progressing normally", base(func(d *appsv1.Deployment) {
			d.Status.Conditions = []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Reason: "NewReplicaSetAvailable"}}
		}), "done"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outcome(deploymentDone(tt.d)); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRollout_StatefulSetEvaluator(t *testing.T) {
	base := func(mut func(*appsv1.StatefulSet)) *appsv1.StatefulSet {
		s := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Generation: 2},
			Spec: appsv1.StatefulSetSpec{Replicas: new(int32(3)), UpdateStrategy: appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType}},
			Status: appsv1.StatefulSetStatus{ObservedGeneration: 2, ReadyReplicas: 3, UpdatedReplicas: 3,
				CurrentRevision: "r2", UpdateRevision: "r2"}}
		mut(s)
		return s
	}
	partition := func(p int32) func(*appsv1.StatefulSet) {
		return func(s *appsv1.StatefulSet) {
			s.Spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{Partition: new(p)}
			s.Status.CurrentRevision = "r1" // ordinals below the partition keep the old revision
		}
	}
	tests := []struct {
		name string
		s    *appsv1.StatefulSet
		want string
	}{
		{"complete", base(func(*appsv1.StatefulSet) {}), "done"},
		{"never observed", base(func(s *appsv1.StatefulSet) { s.Status.ObservedGeneration = 0 }), "waiting"},
		{"generation lag", base(func(s *appsv1.StatefulSet) { s.Generation = 3 }), "waiting"},
		{"not all ready", base(func(s *appsv1.StatefulSet) { s.Status.ReadyReplicas = 2 }), "waiting"},
		{"revisions differ", base(func(s *appsv1.StatefulSet) { s.Status.CurrentRevision = "r1" }), "waiting"},
		{"partition 2: one updated is enough", base(func(s *appsv1.StatefulSet) { partition(2)(s); s.Status.UpdatedReplicas = 1 }), "done"},
		{"partition 1: one updated of two", base(func(s *appsv1.StatefulSet) { partition(1)(s); s.Status.UpdatedReplicas = 1 }), "waiting"},
		{"OnDelete does not wait", base(func(s *appsv1.StatefulSet) {
			s.Spec.UpdateStrategy.Type = appsv1.OnDeleteStatefulSetStrategyType
			s.Generation, s.Status.CurrentRevision = 3, "r1"
		}), "done"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outcome(statefulSetDone(tt.s)); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRollout_DaemonSetEvaluator(t *testing.T) {
	base := func(mut func(*appsv1.DaemonSet)) *appsv1.DaemonSet {
		d := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Generation: 2},
			Status: appsv1.DaemonSetStatus{ObservedGeneration: 2, DesiredNumberScheduled: 3, UpdatedNumberScheduled: 3, NumberAvailable: 3}}
		mut(d)
		return d
	}
	tests := []struct {
		name string
		d    *appsv1.DaemonSet
		want string
	}{
		{"complete", base(func(*appsv1.DaemonSet) {}), "done"},
		{"generation lag", base(func(d *appsv1.DaemonSet) { d.Generation = 3 }), "waiting"},
		{"not all nodes updated", base(func(d *appsv1.DaemonSet) { d.Status.UpdatedNumberScheduled = 2 }), "waiting"},
		{"updated but unavailable", base(func(d *appsv1.DaemonSet) { d.Status.NumberAvailable = 2 }), "waiting"},
		{"OnDelete does not wait", base(func(d *appsv1.DaemonSet) {
			d.Spec.UpdateStrategy.Type = appsv1.OnDeleteDaemonSetStrategyType
			d.Generation = 3
		}), "done"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outcome(daemonSetDone(tt.d)); got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRollout_FailFastOnPodError(t *testing.T) {
	since := time.Date(2026, 10, 20, 12, 0, 0, 500_000_000, time.UTC)
	// A rollout that never finishes: the controller has not seen generation 2.
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web", Generation: 2},
		Spec:   appsv1.DeploymentSpec{Replicas: new(int32(2)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 1}}
	pod := func(name string, created time.Time, reason string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, Labels: map[string]string{"app": "web"}, CreationTimestamp: metav1.NewTime(created)},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: "container has runAsNonRoot and image will run as root"}}}}},
		}
	}
	tests := []struct {
		name    string
		pods    []*corev1.Pod
		timeout time.Duration
		want    string
	}{
		// The timeout is an hour, so only fail-fast can return.
		{"new pod with CreateContainerConfigError", []*corev1.Pod{pod("new", since, "CreateContainerConfigError")}, time.Hour,
			"pod new container app: CreateContainerConfigError"},
		// Created in the same second as the patch: creationTimestamp has
		// second precision, so it must still count as new.
		{"same second as the patch", []*corev1.Pod{pod("new", since.Truncate(time.Second), "CrashLoopBackOff")}, time.Hour,
			"CrashLoopBackOff"},
		{"old crashing pod is ignored", []*corev1.Pod{pod("old", since.Add(-time.Minute), "CrashLoopBackOff")}, 20 * time.Millisecond,
			"did not finish within"},
		{"a starting pod is not an error", []*corev1.Pod{pod("new", since, "ContainerCreating")}, 20 * time.Millisecond,
			"did not finish within"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientset(dep)
			for _, p := range tt.pods {
				if _, err := client.CoreV1().Pods("ns").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			w := RolloutWaiter{Client: client, Interval: time.Millisecond, Timeout: tt.timeout}
			err := w.Wait(context.Background(), "Deployment", "ns", "web", since)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Wait = %v, want an error containing %q", err, tt.want)
			}
		})
	}

	t.Run("cancelled context says so", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		w := RolloutWaiter{Client: fake.NewClientset(dep), Interval: time.Millisecond, Timeout: time.Hour}
		if err := w.Wait(ctx, "Deployment", "ns", "web", since); err == nil || !strings.Contains(err.Error(), "stopped waiting") {
			t.Errorf("Wait = %v, want a cancellation error", err)
		}
	})
	t.Run("CronJob does not wait", func(t *testing.T) {
		w := RolloutWaiter{Client: fake.NewClientset(), Interval: time.Millisecond, Timeout: time.Hour}
		if err := w.Wait(context.Background(), "CronJob", "ns", "nightly", since); err != nil {
			t.Errorf("Wait = %v", err)
		}
	})
}
