package hardening

import (
	"context"
	"errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The evaluators mirror `kubectl rollout status`: done only
// when the controller has seen the new generation and the updated, ready and
// total counts line up. An error means the rollout has failed for good.

func deploymentDone(d *appsv1.Deployment) (bool, error) {
	// A paused Deployment does not roll out until resumed, and kubectl
	// refuses to undo it, so waiting would only end in a misleading halt.
	// Like OnDelete, the plan says "pending resume" and the gate does not wait.
	if d.Spec.Paused {
		return true, nil
	}
	if d.Generation > d.Status.ObservedGeneration {
		return false, nil
	}
	for _, c := range d.Status.Conditions {
		if c.Type == appsv1.DeploymentProgressing && c.Reason == "ProgressDeadlineExceeded" {
			return false, fmt.Errorf("deployment exceeded its progress deadline: %s", c.Message)
		}
	}
	if d.Spec.Replicas != nil && d.Status.UpdatedReplicas < *d.Spec.Replicas {
		return false, nil
	}
	if d.Status.Replicas > d.Status.UpdatedReplicas { // old pods still running
		return false, nil
	}
	return d.Status.AvailableReplicas >= d.Status.UpdatedReplicas, nil
}

func statefulSetDone(s *appsv1.StatefulSet) (bool, error) {
	if s.Spec.UpdateStrategy.Type == appsv1.OnDeleteStatefulSetStrategyType {
		return true, nil // pods change only when deleted: "pending restart"
	}
	if s.Status.ObservedGeneration == 0 || s.Generation > s.Status.ObservedGeneration {
		return false, nil
	}
	if s.Spec.Replicas != nil && s.Status.ReadyReplicas < *s.Spec.Replicas {
		return false, nil
	}
	// With a partition, only ordinals at or above it update, so the revisions
	// never converge; kubectl counts the updated replicas instead.
	if ru := s.Spec.UpdateStrategy.RollingUpdate; ru != nil && ru.Partition != nil && *ru.Partition > 0 && s.Spec.Replicas != nil {
		return s.Status.UpdatedReplicas >= *s.Spec.Replicas-*ru.Partition, nil
	}
	return s.Status.UpdateRevision == s.Status.CurrentRevision, nil
}

func daemonSetDone(d *appsv1.DaemonSet) (bool, error) {
	if d.Spec.UpdateStrategy.Type == appsv1.OnDeleteDaemonSetStrategyType {
		return true, nil
	}
	if d.Generation > d.Status.ObservedGeneration {
		return false, nil
	}
	if d.Status.UpdatedNumberScheduled < d.Status.DesiredNumberScheduled {
		return false, nil
	}
	return d.Status.NumberAvailable >= d.Status.DesiredNumberScheduled, nil
}

// failFastReasons are container waiting reasons that will not fix themselves
// within a rollout timeout, so waiting for the timeout only delays the halt.
var failFastReasons = map[string]bool{
	"CreateContainerConfigError": true, // e.g. runAsNonRoot on a root image
	"CrashLoopBackOff":           true,
	"ImagePullBackOff":           true,
	"ErrImagePull":               true,
}

// RolloutWaiter waits for a workload's rollout after a patch.
type RolloutWaiter struct {
	Client   kubernetes.Interface
	Interval time.Duration // --rollout-poll-interval
	Timeout  time.Duration // --rollout-timeout
}

// Wait returns nil once the rollout is done, or an error when it fails,
// times out or ctx is cancelled. since is when the patch was sent: only pods
// created from then on are inspected for fail-fast reasons, so an old pod
// that was already crashing does not fail the new rollout.
func (w RolloutWaiter) Wait(ctx context.Context, kind, ns, name string, since time.Time) error {
	if kind == "CronJob" {
		return nil // affects future Jobs only
	}
	wctx, cancel := context.WithTimeout(ctx, w.Timeout)
	defer cancel()
	for {
		done, selector, err := w.check(wctx, kind, ns, name)
		if err == nil && done {
			return nil
		}
		if err == nil {
			err = w.failFast(wctx, ns, selector, since)
		}
		if err == nil {
			select {
			case <-wctx.Done():
				err = wctx.Err()
			case <-time.After(w.Interval):
				continue
			}
		}
		// Say why we stopped: the caller went away, the timeout, or the error.
		switch {
		case ctx.Err() != nil:
			return fmt.Errorf("stopped waiting for the rollout: %w", ctx.Err())
		case errors.Is(wctx.Err(), context.DeadlineExceeded):
			return fmt.Errorf("rollout did not finish within %s", w.Timeout)
		}
		return err
	}
}

// check reads the workload and evaluates it; it also returns the pod selector.
func (w RolloutWaiter) check(ctx context.Context, kind, ns, name string) (bool, *metav1.LabelSelector, error) {
	get := metav1.GetOptions{}
	switch kind {
	case "Deployment":
		d, err := w.Client.AppsV1().Deployments(ns).Get(ctx, name, get)
		if err != nil {
			return false, nil, fmt.Errorf("get deployment: %w", err)
		}
		done, err := deploymentDone(d)
		return done, d.Spec.Selector, err
	case "StatefulSet":
		s, err := w.Client.AppsV1().StatefulSets(ns).Get(ctx, name, get)
		if err != nil {
			return false, nil, fmt.Errorf("get statefulset: %w", err)
		}
		done, err := statefulSetDone(s)
		return done, s.Spec.Selector, err
	case "DaemonSet":
		d, err := w.Client.AppsV1().DaemonSets(ns).Get(ctx, name, get)
		if err != nil {
			return false, nil, fmt.Errorf("get daemonset: %w", err)
		}
		done, err := daemonSetDone(d)
		return done, d.Spec.Selector, err
	}
	return false, nil, fmt.Errorf("no rollout check for kind %s", kind)
}

// failFast looks at the workload's pods created since the patch.
// Limitation: "new" is judged by creationTimestamp against our clock, so clock
// skew larger than a rollout makes fail-fast miss; the timeout still halts.
// Matching the newest ReplicaSet or revision hash per kind would remove that.
func (w RolloutWaiter) failFast(ctx context.Context, ns string, sel *metav1.LabelSelector, since time.Time) error {
	selector, err := metav1.LabelSelectorAsSelector(sel)
	if sel == nil || err != nil || selector.Empty() {
		return nil // nothing safe to match; the evaluator and the timeout still apply
	}
	pods, err := w.Client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	// creationTimestamp has second precision.
	cut := since.Truncate(time.Second)
	for _, p := range pods.Items {
		if p.CreationTimestamp.Time.Before(cut) {
			continue
		}
		for _, st := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
			if st.State.Waiting != nil && failFastReasons[st.State.Waiting.Reason] {
				return fmt.Errorf("pod %s container %s: %s: %s", p.Name, st.Name, st.State.Waiting.Reason, st.State.Waiting.Message)
			}
		}
	}
	return nil
}
