package hardening

import (
	"cmp"
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	batchv1ac "k8s.io/client-go/applyconfigurations/batch/v1"
)

// Undo releases every field sre-tool owns on the workloads it hardened in
// namespaces. It needs no stored snapshot: server-side apply
// already records what sre-tool owns. Applying an empty configuration as
// sre-tool removes the fields only sre-tool owns and keeps those a human or
// another manager has since changed or co-owns.
//
// It runs one workload at a time with the same rollout gate, halt and budget
// rules as apply. With dryRun, every apply is a server-side dry-run and the
// result lists what would change.
func (s *Service) Undo(ctx context.Context, namespaces []string, dryRun bool) (ApplyResult, error) {
	if len(namespaces) > s.set.MaxNamespaces {
		return ApplyResult{}, invalid("at most %d namespaces per request", s.set.MaxNamespaces)
	}
	if !dryRun { // a dry-run writes nothing, so like plan it takes no lock
		if !s.applying.TryLock() {
			return ApplyResult{}, inProgress()
		}
		defer s.applying.Unlock()
	}

	start := s.set.Now()
	in, err := Collect(ctx, s.client, namespaces, s.set.Protected)
	if err != nil {
		return ApplyResult{}, err
	}
	res := ApplyResult{Outcome: "complete", Results: []Result{}}
	var stop *halt
	for _, c := range candidates(in) {
		live := liveObject(in, c.kind, c.meta.Namespace, c.meta.Name) // nil for Jobs and Pods
		if live == nil || !appliedBySRETool(c.meta) {
			continue
		}
		w := Workload{Kind: c.kind, Namespace: c.meta.Namespace, Name: c.meta.Name}
		r := Result{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
		switch {
		case stop != nil:
			r.Status = StatusNotAttempted
		case dryRun:
			s.undoDryRun(ctx, w, live, &r)
		default:
			stop = s.undoOne(ctx, w, in, start, &r)
		}
		s.obs.ObserveWorkload("undo", r.Status)
		res.Results = append(res.Results, r)
		if stop != nil && res.Outcome != "halted" {
			res.Outcome, res.Reason, res.Remedy = "halted", stop.reason, stop.remedy
		}
	}
	return res, nil
}

// appliedBySRETool reports whether sre-tool's apply owns fields on the object.
func appliedBySRETool(m metav1.ObjectMeta) bool {
	return slices.ContainsFunc(m.ManagedFields, func(e metav1.ManagedFieldsEntry) bool {
		return e.Manager == FieldManager && e.Operation == metav1.ManagedFieldsOperationApply
	})
}

func (s *Service) undoOne(ctx context.Context, w Workload, in Input, start time.Time, r *Result) *halt {
	if h := s.beforeNext(ctx, start, r); h != nil {
		return h
	}
	// Re-read: earlier workloads' rollouts took time, and the diff and the
	// gate decision below must compare against what the apply changes.
	live, _, err := s.recheck(ctx, w, in)
	if err != nil {
		r.Status, r.Message = StatusFailed, err.Error()
		return &halt{reason: "apply_failed", remedy: "run undo again"}
	}
	since := s.set.Now()
	after, err := emptyPatch(w).send(ctx, s.client, false)
	if err != nil {
		r.Status, r.Message = StatusFailed, "undo: "+err.Error()
		s.event(live, corev1.EventTypeWarning, "HardeningFailed", r.Message)
		return &halt{reason: "apply_failed", remedy: "nothing was changed on this workload; run undo again once the error is fixed"}
	}
	r.Changes = fieldDiff(templateOf(live), templateOf(after))
	// Only a template change rolls pods out. When every released field
	// is still owned by someone else, there is nothing to wait for.
	if reflect.DeepEqual(templateOf(live), templateOf(after)) {
		r.Status, r.Message = StatusApplied, "ownership released; the pod template did not change, so nothing rolls out"
		return nil
	}
	h := s.gate(ctx, w, after, since, r, "HardeningUndone", fmt.Sprintf("%d fields released", len(r.Changes)))
	if h != nil && h.reason == "rollout_failed" {
		// sre-tool owns nothing here any more, so another undo skips this
		// workload. Rolling back restores the hardened template, which ran.
		h.remedy = fmt.Sprintf("the unhardened template does not roll out; kubectl -n %s rollout undo %s/%s restores the hardened one (no longer owned by sre-tool)",
			w.Namespace, strings.ToLower(w.Kind), w.Name)
	}
	return h
}

// undoDryRun fills r with what undo would change. A failure is recorded on
// the workload and does not stop the others, as in plan.
func (s *Service) undoDryRun(ctx context.Context, w Workload, live runtime.Object, r *Result) {
	after, err := s.validator.DryRun(ctx, emptyPatch(w))
	if err != nil {
		r.Status, r.Message = StatusFailed, "server-side dry-run failed: "+err.Error()
		return
	}
	r.Changes = fieldDiff(templateOf(live), templateOf(after))
	r.Status, r.Message = StatusDryRun, fmt.Sprintf("%d fields would be released", len(r.Changes))
}

// emptyPatch is an apply configuration with identity only. Sent by sre-tool,
// it tells the API server that sre-tool no longer wants any field.
func emptyPatch(w Workload) Patch {
	p := Patch{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
	switch w.Kind {
	case "Deployment":
		p.config = appsv1ac.Deployment(w.Name, w.Namespace)
	case "StatefulSet":
		p.config = appsv1ac.StatefulSet(w.Name, w.Namespace)
	case "DaemonSet":
		p.config = appsv1ac.DaemonSet(w.Name, w.Namespace)
	case "CronJob":
		p.config = batchv1ac.CronJob(w.Name, w.Namespace)
	}
	return p // an unknown kind leaves config nil, which send refuses
}

// templateOf returns a patchable workload's pod template; nil otherwise.
func templateOf(obj runtime.Object) *corev1.PodTemplateSpec {
	switch o := obj.(type) {
	case *appsv1.Deployment:
		return &o.Spec.Template
	case *appsv1.StatefulSet:
		return &o.Spec.Template
	case *appsv1.DaemonSet:
		return &o.Spec.Template
	case *batchv1.CronJob:
		return &o.Spec.JobTemplate.Spec.Template
	}
	return nil
}

// fieldKey names one field a Change can set, in one container.
type fieldKey struct {
	container, field string
	init             bool
}

// fieldDiff lists the fields a Change can set whose value differs between
// two templates, as Changes from before to after; nil means unset. These are
// the only fields sre-tool ever sets, so they are the only ones undo moves.
func fieldDiff(before, after *corev1.PodTemplateSpec) []Change {
	b, a := fieldValues(before), fieldValues(after)
	var keys []fieldKey
	for k := range b {
		keys = append(keys, k)
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(x, y fieldKey) int {
		return cmp.Or(cmp.Compare(x.container, y.container), cmp.Compare(x.field, y.field))
	})
	var out []Change
	for _, k := range keys {
		if !reflect.DeepEqual(b[k], a[k]) {
			out = append(out, Change{Container: k.container, Init: k.init, Field: k.field, From: b[k], To: a[k]})
		}
	}
	return out
}

// fieldValues reads every set field a Change can set, in the types the
// planner uses for Change.To: strings for quantities and the seccomp type,
// bools, and a string list for dropped capabilities.
func fieldValues(t *corev1.PodTemplateSpec) map[fieldKey]any {
	out := map[fieldKey]any{}
	if t == nil {
		return out
	}
	if sc := t.Spec.SecurityContext; sc != nil && sc.SeccompProfile != nil {
		out[fieldKey{field: FieldSeccomp}] = string(sc.SeccompProfile.Type)
	}
	for list, cs := range [][]corev1.Container{t.Spec.InitContainers, t.Spec.Containers} {
		for _, c := range cs {
			set := func(field string, v any) { out[fieldKey{container: c.Name, field: field, init: list == 0}] = v }
			if q, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
				set(FieldCPURequest, q.String())
			}
			if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
				set(FieldMemoryRequest, q.String())
			}
			if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
				set(FieldMemoryLimit, q.String())
			}
			sc := c.SecurityContext
			if sc == nil {
				continue
			}
			if sc.AllowPrivilegeEscalation != nil {
				set(FieldAllowPrivEsc, *sc.AllowPrivilegeEscalation)
			}
			if sc.RunAsNonRoot != nil {
				set(FieldRunAsNonRoot, *sc.RunAsNonRoot)
			}
			if sc.ReadOnlyRootFilesystem != nil {
				set(FieldReadOnlyRootFS, *sc.ReadOnlyRootFilesystem)
			}
			if sc.Capabilities != nil && len(sc.Capabilities.Drop) > 0 {
				drop := make([]string, 0, len(sc.Capabilities.Drop))
				for _, d := range sc.Capabilities.Drop {
					drop = append(drop, string(d))
				}
				set(FieldCapabilitiesDrop, drop)
			}
		}
	}
	return out
}
