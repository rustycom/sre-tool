package hardening

import (
	"context"
	"errors"
	"testing"
)

// fakeValidator fails the dry-run of the workloads named in fail.
type fakeValidator struct {
	fail map[string]string // name → error message
	got  []string
}

func (f *fakeValidator) DryRun(_ context.Context, p Patch) error {
	f.got = append(f.got, p.Name)
	if msg, ok := f.fail[p.Name]; ok {
		return errors.New(msg)
	}
	return nil
}

func TestValidatePlan_DryRunsPatchWorkloadsOnly(t *testing.T) {
	ch := []Change{{Container: "app", Field: FieldAllowPrivEsc, To: false}}
	plan := Plan{Workloads: []Workload{
		{Kind: "Deployment", Name: "good", Action: ActionPatch, Changes: ch},
		{Kind: "Deployment", Name: "bad", Action: ActionPatch, Changes: ch},
		{Kind: "Deployment", Name: "done", Action: ActionNone},
		{Kind: "Pod", Name: "bare", Action: ActionReport},
	}}
	v := &fakeValidator{fail: map[string]string{"bad": "cannot set allowPrivilegeEscalation to false and privileged to true"}}
	validatePlan(context.Background(), v, &plan)

	want := map[string]string{"good": "ok", "bad": "failed: cannot set allowPrivilegeEscalation to false and privileged to true", "done": "", "bare": ""}
	for _, w := range plan.Workloads {
		if w.DryRun != want[w.Name] {
			t.Errorf("%s: dryRun = %q, want %q", w.Name, w.DryRun, want[w.Name])
		}
		if w.Name == "bad" && w.Action != ActionPatch {
			t.Errorf("a failed dry-run changed the action to %s; it must stay patch", w.Action)
		}
	}
	if len(v.got) != 2 {
		t.Errorf("dry-ran %v, want only the two patch workloads", v.got)
	}
}
