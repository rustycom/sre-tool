package hardening

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/events"
)

// fakeWaiter calls hook (if set) for each rollout and returns its error.
type fakeWaiter struct {
	hook func(ctx context.Context, name string) error
	got  []string
}

func (f *fakeWaiter) Wait(ctx context.Context, _, _, name string, _ time.Time) error {
	f.got = append(f.got, name)
	if f.hook != nil {
		return f.hook(ctx, name)
	}
	return nil
}

type fakeObserver struct{ workloads, rollouts []string }

func (f *fakeObserver) ObserveWorkload(action, result string) {
	f.workloads = append(f.workloads, action+"/"+result)
}
func (f *fakeObserver) ObserveRollout(kind, result string, _ time.Duration) {
	f.rollouts = append(f.rollouts, kind+"/"+result)
}

// fakeClock is advanced by hand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fixture struct {
	svc       *Service
	client    *fake.Clientset
	validator *fakeValidator
	waiter    *fakeWaiter
	clock     *fakeClock
	recorder  *events.FakeRecorder
	obs       *fakeObserver
}

// newFixture has namespace demo with Deployments a, b and c, each with one
// container and nothing hardened, so all three are patch.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	objs := []runtime.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo"}}}
	for _, n := range []string{"a", "b", "c"} {
		objs = append(objs, &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: n, UID: types.UID("uid-" + n)},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app", Image: "img"}}}}},
		})
	}
	f := &fixture{client: fake.NewClientset(objs...), validator: &fakeValidator{}, waiter: &fakeWaiter{},
		clock: &fakeClock{now: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}, recorder: events.NewFakeRecorder(100), obs: &fakeObserver{}}
	f.svc = NewService(f.client, f.validator, f.waiter, f.recorder, f.obs, Settings{
		Defaults:       Defaults{CPURequest: resource.MustParse("100m"), MemoryRequest: resource.MustParse("128Mi"), MemoryLimit: resource.MustParse("512Mi")},
		Protected:      map[string]bool{"kube-system": true},
		MaxNamespaces:  2,
		RolloutTimeout: 3 * time.Minute,
		ApplyBudget:    12 * time.Minute,
		Now:            f.clock.Now,
	})
	return f
}

// plan returns a fresh plan for demo, failing the test on error.
func (f *fixture) plan(t *testing.T) Plan {
	t.Helper()
	p, err := f.svc.Plan(context.Background(), []string{"demo"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// applied lists the workloads that received a real apply patch.
func (f *fixture) applied() []string {
	var out []string
	for _, a := range f.client.Actions() {
		if p, ok := a.(k8stesting.PatchActionImpl); ok && p.GetPatchType() == types.ApplyPatchType {
			out = append(out, p.GetName())
		}
	}
	return out
}

func statuses(res ApplyResult) []string {
	var out []string
	for _, r := range res.Results {
		out = append(out, r.Name+"="+r.Status)
	}
	return out
}

func TestApply_StalePlanReturns409(t *testing.T) {
	f := newFixture(t)
	old := f.plan(t)
	// Someone edits a pod template after the plan was reviewed.
	d, _ := f.client.AppsV1().Deployments("demo").Get(context.Background(), "b", metav1.GetOptions{})
	d.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "X", Value: "1"}}
	if _, err := f.client.AppsV1().Deployments("demo").Update(context.Background(), d, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	f.client.ClearActions()

	_, err := f.svc.Apply(context.Background(), []string{"demo"}, old.PlanHash)
	var e *Error
	if !errors.As(err, &e) || e.Status != 409 || e.Code != "stale_plan" {
		t.Fatalf("err = %v, want 409 stale_plan", err)
	}
	if cur := f.plan(t).PlanHash; e.Details["currentPlanHash"] != cur || cur == old.PlanHash {
		t.Errorf("details.currentPlanHash = %v, want the new hash %s", e.Details["currentPlanHash"], cur)
	}
	if got := f.applied(); len(got) != 0 {
		t.Errorf("a stale apply patched %v", got)
	}
}

func TestApply_SingleFlight(t *testing.T) {
	f := newFixture(t)
	hash := f.plan(t).PlanHash
	entered, release := make(chan struct{}), make(chan struct{})
	f.waiter.hook = func(context.Context, string) error {
		if len(f.waiter.got) == 1 {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan error)
	go func() {
		_, err := f.svc.Apply(context.Background(), []string{"demo"}, hash)
		done <- err
	}()
	<-entered // the first apply is now waiting on a rollout and holds the lock

	_, err := f.svc.Apply(context.Background(), []string{"demo"}, hash)
	var e *Error
	if !errors.As(err, &e) || e.Status != 409 || e.Code != "apply_in_progress" {
		t.Errorf("concurrent apply: err = %v, want 409 apply_in_progress", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Errorf("first apply: %v", err)
	}
	// The lock is released afterwards.
	if _, err := f.svc.Apply(context.Background(), []string{"demo"}, f.plan(t).PlanHash); err != nil {
		t.Errorf("apply after the first finished: %v", err)
	}
}

func TestApply_HaltsAndLeavesRemainingUntouched(t *testing.T) {
	f := newFixture(t)
	hash := f.plan(t).PlanHash
	f.waiter.hook = func(_ context.Context, name string) error {
		if name == "b" {
			return errors.New("pod b-1 container app: CreateContainerConfigError")
		}
		return nil
	}
	res, err := f.svc.Apply(context.Background(), []string{"demo"}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a=applied", "b=failed", "c=not_attempted"}; !slices.Equal(statuses(res), want) {
		t.Errorf("statuses = %v, want %v", statuses(res), want)
	}
	if res.Outcome != "halted" || res.Reason != "rollout_failed" || !strings.Contains(res.Remedy, "kubectl -n demo rollout undo deployment/b") {
		t.Errorf("outcome %s, reason %s, remedy %q", res.Outcome, res.Reason, res.Remedy)
	}
	// c was never patched: halting means the remaining workloads stay as they were.
	if got := f.applied(); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("apply patches sent to %v, want [a b]", got)
	}
	if !slices.Equal(f.waiter.got, []string{"a", "b"}) {
		t.Errorf("waited for %v", f.waiter.got)
	}
	ev := strings.Join(drain(f.recorder), "\n")
	if !strings.Contains(ev, "Normal HardeningApplied") || !strings.Contains(ev, "Warning HardeningFailed") {
		t.Errorf("events = %s", ev)
	}
	if want := []string{"patch/applied", "patch/failed", "patch/not_attempted"}; !slices.Equal(f.obs.workloads, want) {
		t.Errorf("workload metrics = %v, want %v", f.obs.workloads, want)
	}
	if want := []string{"Deployment/ok", "Deployment/failed"}; !slices.Equal(f.obs.rollouts, want) {
		t.Errorf("rollout metrics = %v, want %v", f.obs.rollouts, want)
	}
}

func drain(rec *events.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func TestPlan_DryRunFailureMarksWorkload(t *testing.T) {
	f := newFixture(t)
	f.validator.fail = map[string]string{"b": "admission webhook denied the request"}
	plan := f.plan(t)
	for _, w := range plan.Workloads {
		want := "ok"
		if w.Name == "b" {
			want = "failed: admission webhook denied the request"
		}
		if w.DryRun != want || w.Action != ActionPatch {
			t.Errorf("%s: dryRun %q action %s, want %q patch", w.Name, w.DryRun, w.Action, want)
		}
	}
	res, err := f.svc.Apply(context.Background(), []string{"demo"}, plan.PlanHash)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a=applied", "b=failed", "c=not_attempted"}; !slices.Equal(statuses(res), want) || res.Reason != "dry_run_failed" {
		t.Errorf("statuses = %v reason %s, want %v dry_run_failed", statuses(res), res.Reason, want)
	}
	if got := f.applied(); !slices.Equal(got, []string{"a"}) {
		t.Errorf("apply patches sent to %v, want only a", got)
	}
}

func TestApply_ChangedSincePlanHalts(t *testing.T) {
	f := newFixture(t)
	hash := f.plan(t).PlanHash
	// While a rolls out, someone sets one of b's fields by hand: b's
	// changes are no longer the planned ones.
	f.waiter.hook = func(ctx context.Context, name string) error {
		if name != "a" {
			return nil
		}
		d, err := f.client.AppsV1().Deployments("demo").Get(ctx, "b", metav1.GetOptions{})
		if err != nil {
			return err
		}
		d.Spec.Template.Spec.Containers[0].Resources.Requests = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m")}
		_, err = f.client.AppsV1().Deployments("demo").Update(ctx, d, metav1.UpdateOptions{})
		return err
	}
	res, err := f.svc.Apply(context.Background(), []string{"demo"}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a=applied", "b=failed", "c=not_attempted"}; !slices.Equal(statuses(res), want) || res.Reason != "changed_since_plan" {
		t.Errorf("statuses = %v reason %s, want %v changed_since_plan", statuses(res), res.Reason, want)
	}
	if got := f.applied(); !slices.Equal(got, []string{"a"}) {
		t.Errorf("apply patches sent to %v, want only a", got)
	}
}

func TestApply_ContextCancelStopsBeforeNext(t *testing.T) {
	f := newFixture(t)
	hash := f.plan(t).PlanHash
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The client goes away while a's rollout finishes.
	f.waiter.hook = func(context.Context, string) error { cancel(); return nil }
	res, err := f.svc.Apply(ctx, []string{"demo"}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a=applied", "b=not_attempted", "c=not_attempted"}; !slices.Equal(statuses(res), want) || res.Reason != "cancelled" {
		t.Errorf("statuses = %v reason %s, want %v cancelled", statuses(res), res.Reason, want)
	}
	if got := f.applied(); !slices.Equal(got, []string{"a"}) {
		t.Errorf("apply patches sent to %v, want only a", got)
	}
}

func TestApply_BudgetExhaustedHaltsBeforeNext(t *testing.T) {
	f := newFixture(t)
	hash := f.plan(t).PlanHash
	// a's rollout takes 9m01s of the 12m budget: 2m59s is left, less than
	// the 3m rollout timeout, so b must not start.
	f.waiter.hook = func(context.Context, string) error { f.clock.Advance(9*time.Minute + time.Second); return nil }
	res, err := f.svc.Apply(context.Background(), []string{"demo"}, hash)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a=applied", "b=not_attempted", "c=not_attempted"}; !slices.Equal(statuses(res), want) {
		t.Errorf("statuses = %v, want %v", statuses(res), want)
	}
	if res.Outcome != "halted" || res.Reason != "apply_budget_exhausted" {
		t.Errorf("outcome %s reason %s, want halted apply_budget_exhausted", res.Outcome, res.Reason)
	}
	if got := f.applied(); !slices.Equal(got, []string{"a"}) {
		t.Errorf("apply patches sent to %v, want only a", got)
	}

	// Exactly one rollout timeout left is still enough.
	f = newFixture(t)
	f.waiter.hook = func(context.Context, string) error { f.clock.Advance(9 * time.Minute); return nil }
	if res, err := f.svc.Apply(context.Background(), []string{"demo"}, f.plan(t).PlanHash); err != nil || res.Results[1].Status != StatusApplied {
		t.Errorf("with 3m left: err %v, statuses %v; want b applied", err, statuses(res))
	}
}

func TestApply_SecondApplyPatchesNothing(t *testing.T) {
	f := newFixture(t)
	res, err := f.svc.Apply(context.Background(), []string{"demo"}, f.plan(t).PlanHash)
	if err != nil || res.Outcome != "complete" {
		t.Fatalf("first apply: %v %+v", err, res)
	}
	second := f.plan(t)
	if second.Summary.Patch != 0 {
		t.Fatalf("after apply the plan still patches %d workloads: %+v", second.Summary.Patch, second.Workloads)
	}
	f.client.ClearActions()
	f.waiter.got = nil
	res, err = f.svc.Apply(context.Background(), []string{"demo"}, second.PlanHash)
	if err != nil || res.Outcome != "complete" {
		t.Fatalf("second apply: %v %+v", err, res)
	}
	if got := f.applied(); len(got) != 0 || len(f.waiter.got) != 0 {
		t.Errorf("second apply patched %v and waited for %v, want nothing", got, f.waiter.got)
	}
}

func TestService_RejectsBadRequests(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name   string
		call   func() error
		status int
		code   string
	}{
		{"too many namespaces", func() error { _, err := f.svc.Plan(context.Background(), []string{"a", "b", "c"}); return err }, 400, "invalid_request"},
		{"apply without hash", func() error { _, err := f.svc.Apply(context.Background(), []string{"demo"}, ""); return err }, 400, "invalid_request"},
		{"protected", func() error { _, err := f.svc.Plan(context.Background(), []string{"kube-system"}); return err }, 403, "forbidden_namespace"},
		{"missing", func() error { _, err := f.svc.Apply(context.Background(), []string{"nope"}, "sha256:x"); return err }, 422, "namespace_not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e *Error
			if err := tt.call(); !errors.As(err, &e) || e.Status != tt.status || e.Code != tt.code {
				t.Errorf("err = %v, want %d %s", err, tt.status, tt.code)
			}
		})
	}
}
