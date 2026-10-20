package hardening

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/events"
)

// Waiter waits for a workload's rollout after a patch (SPEC §7.8).
type Waiter interface {
	Wait(ctx context.Context, kind, ns, name string, since time.Time) error
}

// Observer records hardening metrics (SPEC §9).
type Observer interface {
	ObserveWorkload(action, result string)
	ObserveRollout(kind, result string, d time.Duration)
}

// Settings are the service's configuration.
type Settings struct {
	Defaults       Defaults
	Protected      map[string]bool
	MaxNamespaces  int
	RolloutTimeout time.Duration
	ApplyBudget    time.Duration
	Now            func() time.Time // injected so tests control the budget
}

// Result statuses of one workload in an apply.
const (
	StatusApplied      = "applied"
	StatusFailed       = "failed"
	StatusSkipped      = "skipped"
	StatusNotAttempted = "not_attempted"
)

// ApplyResult is the response of POST /v1/hardening/apply (SPEC §7.7). A
// halted apply is still a 200: the outcome is data, not an error.
type ApplyResult struct {
	Outcome string   `json:"outcome"`          // complete | halted
	Reason  string   `json:"reason,omitempty"` // why it halted, a snake_case code
	Remedy  string   `json:"remedy,omitempty"`
	Results []Result `json:"results"`
}

// Result is what apply did with one workload, in plan order.
type Result struct {
	Kind           string  `json:"kind"`
	Namespace      string  `json:"namespace"`
	Name           string  `json:"name"`
	Status         string  `json:"status"`
	Message        string  `json:"message,omitempty"`
	RolloutSeconds float64 `json:"rolloutSeconds"`
}

// Service plans and applies hardening. It keeps no state between requests
// apart from the apply lock: every apply re-reads the cluster.
type Service struct {
	client    kubernetes.Interface
	validator Validator
	waiter    Waiter
	recorder  events.EventRecorder
	obs       Observer
	set       Settings

	// applying makes apply single-flight (SPEC §7.7). A second caller gets a
	// 409 rather than waiting, because an apply can take minutes. It is per
	// process, which is why the tool runs one replica (ADR-012).
	applying sync.Mutex
}

// NewService returns a hardening Service.
func NewService(client kubernetes.Interface, v Validator, w Waiter, recorder events.EventRecorder, obs Observer, set Settings) *Service {
	return &Service{client: client, validator: v, waiter: w, recorder: recorder, obs: obs, set: set}
}

// Plan returns what apply would do, without changing anything (SPEC §7.4):
// the only writes are server-side dry-runs.
func (s *Service) Plan(ctx context.Context, namespaces []string) (Plan, error) {
	plan, _, err := s.plan(ctx, namespaces)
	return plan, err
}

func (s *Service) plan(ctx context.Context, namespaces []string) (Plan, Input, error) {
	if len(namespaces) > s.set.MaxNamespaces {
		return Plan{}, Input{}, invalid("at most %d namespaces per request", s.set.MaxNamespaces)
	}
	in, err := Collect(ctx, s.client, namespaces, s.set.Protected)
	if err != nil {
		return Plan{}, Input{}, err
	}
	plan := BuildPlan(in, s.set.Defaults)
	validatePlan(ctx, s.validator, &plan, in)
	return plan, in, nil
}

// halt is why apply stopped at a workload.
type halt struct {
	reason, remedy string
}

// replan is the halt for reasons where re-planning is the whole remedy.
func replan(reason string) *halt {
	return &halt{reason: reason, remedy: "plan again and apply the new planHash; workloads already hardened show as none"}
}

// Apply applies a reviewed plan one workload at a time (SPEC §7.7). It never
// reverts: on a failure it stops, so at most one workload is in a bad state,
// and the remedy says how to roll that one back.
func (s *Service) Apply(ctx context.Context, namespaces []string, planHash string) (ApplyResult, error) {
	if !strings.HasPrefix(planHash, "sha256:") {
		return ApplyResult{}, invalid("planHash is required: send the planHash of the plan you reviewed")
	}
	if !s.applying.TryLock() {
		return ApplyResult{}, &Error{Status: http.StatusConflict, Code: "apply_in_progress",
			Message: "another apply is running; wait for it to finish, then plan again"}
	}
	defer s.applying.Unlock()

	start := s.set.Now()
	plan, in, err := s.plan(ctx, namespaces)
	if err != nil {
		return ApplyResult{}, err
	}
	if plan.PlanHash != planHash {
		return ApplyResult{}, &Error{Status: http.StatusConflict, Code: "stale_plan",
			Message: "the cluster changed since that plan was made; review the current plan and apply its hash",
			Details: map[string]any{"currentPlanHash": plan.PlanHash}}
	}

	res := ApplyResult{Outcome: "complete", Results: []Result{}}
	var stop *halt
	for _, w := range plan.Workloads {
		r := Result{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
		switch {
		case stop != nil:
			r.Status = StatusNotAttempted
		case w.Action != ActionPatch:
			r.Status, r.Message = StatusSkipped, "action "+string(w.Action)
		default:
			stop = s.applyOne(ctx, w, in, start, &r)
		}
		s.obs.ObserveWorkload(string(w.Action), r.Status)
		res.Results = append(res.Results, r)
		if stop != nil && res.Outcome != "halted" {
			res.Outcome, res.Reason, res.Remedy = "halted", stop.reason, stop.remedy
		}
	}
	return res, nil
}

// applyOne runs the per-workload steps of SPEC §7.7 and fills r. It returns
// non-nil when apply must stop.
func (s *Service) applyOne(ctx context.Context, w Workload, in Input, start time.Time, r *Result) *halt {
	// Checked before anything is touched, so a workload is never cut off
	// mid-rollout and the response beats the HTTP write timeout.
	if ctx.Err() != nil {
		r.Status, r.Message = StatusNotAttempted, "cancelled before this workload: "+ctx.Err().Error()
		return replan("cancelled")
	}
	if left := s.set.ApplyBudget - s.set.Now().Sub(start); left < s.set.RolloutTimeout {
		r.Status, r.Message = StatusNotAttempted, fmt.Sprintf("%s of the apply budget left, less than one rollout timeout (%s)", left.Round(time.Second), s.set.RolloutTimeout)
		return replan("apply_budget_exhausted")
	}

	obj, changes, err := s.recheck(ctx, w, in)
	if err != nil {
		r.Status, r.Message = StatusFailed, err.Error()
		return replan("changed_since_plan")
	}
	if !reflect.DeepEqual(changes, w.Changes) {
		r.Status, r.Message = StatusFailed, "the workload changed since the plan; its changes are no longer the planned ones"
		s.event(obj, corev1.EventTypeWarning, "HardeningFailed", r.Message)
		return replan("changed_since_plan")
	}
	if w.DryRun != "ok" {
		r.Status, r.Message = StatusFailed, "server-side dry-run "+w.DryRun
		s.event(obj, corev1.EventTypeWarning, "HardeningFailed", r.Message)
		return &halt{reason: "dry_run_failed", remedy: "fix or annotate " + SkipAnnotation + `: "true" on this workload, then plan again`}
	}

	// Built from the object just re-read, so it carries what sre-tool owns now.
	p, err := BuildPatch(w, obj)
	if err == nil {
		since := s.set.Now()
		var applied runtime.Object
		if applied, err = p.send(ctx, s.client, false); err == nil {
			obj = applied
			return s.gate(ctx, w, obj, since, r)
		}
	}
	r.Status, r.Message = StatusFailed, "apply: "+err.Error()
	s.event(obj, corev1.EventTypeWarning, "HardeningFailed", r.Message)
	if apierrors.IsConflict(err) {
		// Another manager owns a field with a different value (I-16): we do
		// not take it over.
		return &halt{reason: "field_conflict", remedy: "another field manager owns one of these fields; resolve it with that owner, then plan again"}
	}
	return &halt{reason: "apply_failed", remedy: "nothing was changed on this workload; plan again once the error is fixed"}
}

// gate waits for the rollout of a workload that was just patched.
func (s *Service) gate(ctx context.Context, w Workload, obj runtime.Object, since time.Time, r *Result) *halt {
	err := s.waiter.Wait(ctx, w.Kind, w.Namespace, w.Name, since)
	took := s.set.Now().Sub(since)
	r.RolloutSeconds = took.Seconds()
	if w.Kind != "CronJob" { // nothing rolls out
		result := "ok"
		if err != nil {
			result = "failed"
		}
		s.obs.ObserveRollout(w.Kind, result, took)
	}
	if err != nil && ctx.Err() != nil {
		// The caller went away or the tool is shutting down: the patch is in,
		// and the rollout may well finish healthy, so do not suggest undo.
		r.Status, r.Message = StatusFailed, "rollout not verified: "+err.Error()
		return &halt{reason: "cancelled",
			remedy: fmt.Sprintf("kubectl -n %s rollout status %s/%s, then plan again", w.Namespace, strings.ToLower(w.Kind), w.Name)}
	}
	if err != nil {
		r.Status, r.Message = StatusFailed, "rollout: "+err.Error()
		s.event(obj, corev1.EventTypeWarning, "HardeningFailed", r.Message)
		// No automatic revert (ADR-008): the old pods keep serving under the
		// rolling update, and the operator decides.
		return &halt{reason: "rollout_failed",
			remedy: fmt.Sprintf("kubectl -n %s rollout undo %s/%s", w.Namespace, strings.ToLower(w.Kind), w.Name)}
	}
	r.Status, r.Message = StatusApplied, fmt.Sprintf("%d changes; %s", len(w.Changes), w.RolloutImpact)
	s.event(obj, corev1.EventTypeNormal, "HardeningApplied", r.Message)
	return nil
}

// recheck re-reads one workload and recomputes its changes with the rest of
// the plan's input (namespace, LimitRanges, HPAs), so a skip annotation or a
// template edit made since the plan shows up here.
func (s *Service) recheck(ctx context.Context, w Workload, in Input) (runtime.Object, []Change, error) {
	one := Input{Namespaces: in.Namespaces, LimitRanges: in.LimitRanges, HPAs: in.HPAs}
	var obj runtime.Object
	var err error
	get := metav1.GetOptions{}
	switch w.Kind {
	case "Deployment":
		var o *appsv1.Deployment
		if o, err = s.client.AppsV1().Deployments(w.Namespace).Get(ctx, w.Name, get); err == nil {
			one.Deployments, obj = append(one.Deployments, *o), o
		}
	case "StatefulSet":
		var o *appsv1.StatefulSet
		if o, err = s.client.AppsV1().StatefulSets(w.Namespace).Get(ctx, w.Name, get); err == nil {
			one.StatefulSets, obj = append(one.StatefulSets, *o), o
		}
	case "DaemonSet":
		var o *appsv1.DaemonSet
		if o, err = s.client.AppsV1().DaemonSets(w.Namespace).Get(ctx, w.Name, get); err == nil {
			one.DaemonSets, obj = append(one.DaemonSets, *o), o
		}
	case "CronJob":
		var o *batchv1.CronJob
		if o, err = s.client.BatchV1().CronJobs(w.Namespace).Get(ctx, w.Name, get); err == nil {
			one.CronJobs, obj = append(one.CronJobs, *o), o
		}
	default:
		return nil, nil, fmt.Errorf("kind %s cannot be patched", w.Kind)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("re-read %s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	for _, cur := range BuildPlan(one, s.set.Defaults).Workloads {
		if cur.Kind == w.Kind && cur.Namespace == w.Namespace && cur.Name == w.Name && cur.Action == ActionPatch {
			return obj, cur.Changes, nil
		}
	}
	return obj, nil, nil // no longer a patch: nil never equals planned changes
}

// event records on the workload, so it shows in `kubectl get events -n <ns>`.
func (s *Service) event(obj runtime.Object, eventType, reason, note string) {
	if obj == nil {
		return
	}
	s.recorder.Eventf(obj, nil, eventType, reason, "Apply", "%s", note)
}
