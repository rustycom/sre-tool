package hardening

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/client-go/kubernetes"
)

// Validator runs the server-side dry-run of the exact apply that apply would
// send (SPEC §7.6). It is an interface because the fake clientset ignores
// DryRun and persists the change (FINDINGS A7): unit tests fake it, and the
// real one runs only against a real API server.
type Validator interface {
	DryRun(ctx context.Context, p Patch) error
}

// ClientValidator dry-runs patches against the API server, which runs
// validation and admission without persisting. Pod Security Admission only
// warns on workload objects; it enforces on Pods, so a PSA rejection shows up
// later, as pods that are never created (the rollout gate's timeout).
type ClientValidator struct{ Client kubernetes.Interface }

// DryRun sends p with DryRun: [All].
func (v ClientValidator) DryRun(ctx context.Context, p Patch) error {
	_, err := p.send(ctx, v.Client, true)
	return err
}

// validatePlan dry-runs every patch workload and records the outcome in
// dryRun. A failure keeps the action patch, so the operator sees what was
// intended, but apply refuses that workload (SPEC §7.6).
func validatePlan(ctx context.Context, v Validator, plan *Plan, in Input) {
	for i := range plan.Workloads {
		w := &plan.Workloads[i]
		if w.Action != ActionPatch {
			continue
		}
		p, err := BuildPatch(*w, liveObject(in, w.Kind, w.Namespace, w.Name))
		if err == nil {
			err = v.DryRun(ctx, p)
		}
		w.DryRun = "ok"
		if err != nil {
			w.DryRun = "failed: " + err.Error()
		}
	}
}

// liveObject finds a patchable workload in the collected input; nil if absent.
func liveObject(in Input, kind, ns, name string) runtime.Object {
	match := func(m metav1.ObjectMeta) bool { return m.Namespace == ns && m.Name == name }
	switch kind {
	case "Deployment":
		for i := range in.Deployments {
			if match(in.Deployments[i].ObjectMeta) {
				return &in.Deployments[i]
			}
		}
	case "StatefulSet":
		for i := range in.StatefulSets {
			if match(in.StatefulSets[i].ObjectMeta) {
				return &in.StatefulSets[i]
			}
		}
	case "DaemonSet":
		for i := range in.DaemonSets {
			if match(in.DaemonSets[i].ObjectMeta) {
				return &in.DaemonSets[i]
			}
		}
	case "CronJob":
		for i := range in.CronJobs {
			if match(in.CronJobs[i].ObjectMeta) {
				return &in.CronJobs[i]
			}
		}
	}
	return nil
}
