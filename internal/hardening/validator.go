package hardening

import (
	"context"

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
// validation, admission and Pod Security Admission without persisting.
type ClientValidator struct{ Client kubernetes.Interface }

// DryRun sends p with DryRun: [All].
func (v ClientValidator) DryRun(ctx context.Context, p Patch) error {
	_, err := p.send(ctx, v.Client, true)
	return err
}

// validatePlan dry-runs every patch workload and records the outcome in
// dryRun. A failure keeps the action patch, so the operator sees what was
// intended, but apply refuses that workload (SPEC §7.6).
func validatePlan(ctx context.Context, v Validator, plan *Plan) {
	for i := range plan.Workloads {
		w := &plan.Workloads[i]
		if w.Action != ActionPatch {
			continue
		}
		p, err := BuildPatch(*w)
		if err == nil {
			err = v.DryRun(ctx, p)
		}
		w.DryRun = "ok"
		if err != nil {
			w.DryRun = "failed: " + err.Error()
		}
	}
}
