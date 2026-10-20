package hardening

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

// loadInput decodes multi-document manifests into typed planner input, the
// same types the collector will list from the API.
func loadInput(t *testing.T, paths ...string) Input {
	t.Helper()
	var in Input
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		r := utilyaml.NewYAMLReader(bufio.NewReader(f))
		for {
			doc, err := r.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			if len(bytes.TrimSpace(doc)) == 0 {
				continue
			}
			obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(doc, nil, nil)
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			switch o := obj.(type) {
			case *corev1.Namespace:
				in.Namespaces = append(in.Namespaces, *o)
			case *appsv1.Deployment:
				in.Deployments = append(in.Deployments, *o)
			case *appsv1.StatefulSet:
				in.StatefulSets = append(in.StatefulSets, *o)
			case *appsv1.DaemonSet:
				in.DaemonSets = append(in.DaemonSets, *o)
			case *batchv1.CronJob:
				in.CronJobs = append(in.CronJobs, *o)
			case *batchv1.Job:
				in.Jobs = append(in.Jobs, *o)
			case *corev1.Pod:
				in.Pods = append(in.Pods, *o)
			case *corev1.LimitRange:
				in.LimitRanges = append(in.LimitRanges, *o)
			case *autoscalingv2.HorizontalPodAutoscaler:
				in.HPAs = append(in.HPAs, *o)
			}
		}
		_ = f.Close()
	}
	return in
}

func demoInput(t *testing.T) Input {
	return loadInput(t, "../../examples/workloads/hardening-demo.yaml", "../../examples/workloads/hardening-lr.yaml")
}

// find returns the planned workload, failing the test if it is not listed.
func find(t *testing.T, p Plan, kind, ns, name string) Workload {
	t.Helper()
	for _, w := range p.Workloads {
		if w.Kind == kind && w.Namespace == ns && w.Name == name {
			return w
		}
	}
	t.Fatalf("%s %s/%s not in plan", kind, ns, name)
	return Workload{}
}

func meta(name string, owner *metav1.OwnerReference) metav1.ObjectMeta {
	m := metav1.ObjectMeta{Namespace: "ns", Name: name}
	if owner != nil {
		m.OwnerReferences = []metav1.OwnerReference{*owner}
	}
	return m
}

func controller(apiVersion, kind, name string) *metav1.OwnerReference {
	return &metav1.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, Controller: new(true)}
}

func template() corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{Spec: *specWith()}
}

func TestPlanner_KindDispatch(t *testing.T) {
	in := Input{
		Namespaces:   []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}},
		Deployments:  []appsv1.Deployment{{ObjectMeta: meta("deploy", nil), Spec: appsv1.DeploymentSpec{Template: template()}}},
		StatefulSets: []appsv1.StatefulSet{{ObjectMeta: meta("sts", nil), Spec: appsv1.StatefulSetSpec{Template: template()}}},
		DaemonSets:   []appsv1.DaemonSet{{ObjectMeta: meta("ds", nil), Spec: appsv1.DaemonSetSpec{Template: template()}}},
		CronJobs: []batchv1.CronJob{{ObjectMeta: meta("cron", nil), Spec: batchv1.CronJobSpec{
			JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: template()}}}}},
		Jobs: []batchv1.Job{
			{ObjectMeta: meta("job", nil), Spec: batchv1.JobSpec{Template: template()}},
			{ObjectMeta: meta("cron-123", controller("batch/v1", "CronJob", "cron")), Spec: batchv1.JobSpec{Template: template()}},
			// A custom resource that happens to be called CronJob is not batch's.
			{ObjectMeta: meta("custom-1", controller("acme.io/v1", "CronJob", "c")), Spec: batchv1.JobSpec{Template: template()}},
		},
		Pods: []corev1.Pod{
			{ObjectMeta: meta("bare", nil), Spec: *specWith()},
			{ObjectMeta: meta("deploy-abc-xyz", controller("apps/v1", "ReplicaSet", "deploy-abc")), Spec: *specWith()},
		},
	}
	// A Deployment owned by an operator: that operator would revert a patch.
	owned := in.Deployments[0]
	owned.ObjectMeta = meta("operated", controller("db.example.com/v1", "Database", "pg"))
	in.Deployments = append(in.Deployments, owned)
	// An ownerReference that is not the controller does not count.
	shared := in.Deployments[0]
	shared.ObjectMeta = meta("shared", &metav1.OwnerReference{Kind: "ConfigMap", Name: "cfg"})
	in.Deployments = append(in.Deployments, shared)

	p := BuildPlan(in, testDefaults)

	want := []struct {
		kind, name string
		action     Action
		reason     string // substring
	}{
		{"CronJob", "cron", ActionPatch, ""},
		{"Deployment", "deploy", ActionPatch, ""},
		{"Deployment", "operated", ActionReport, "managed by Database/pg"},
		{"Deployment", "shared", ActionPatch, ""},
		{"StatefulSet", "sts", ActionPatch, ""},
		{"DaemonSet", "ds", ActionPatch, ""},
		{"Job", "custom-1", ActionReport, "managed by CronJob/c"},
		{"Job", "job", ActionReport, "immutable"},
		{"Pod", "bare", ActionReport, "bare Pod"},
	}
	if len(p.Workloads) != len(want) {
		t.Fatalf("got %d workloads, want %d (CronJob Jobs and owned Pods must not be listed): %+v", len(p.Workloads), len(want), p.Workloads)
	}
	for i, w := range want {
		got := p.Workloads[i]
		if got.Kind != w.kind || got.Name != w.name || got.Action != w.action || !strings.Contains(got.Reason, w.reason) {
			t.Errorf("workload %d = %s/%s %s %q, want %s/%s %s containing %q", i, got.Kind, got.Name, got.Action, got.Reason, w.kind, w.name, w.action, w.reason)
		}
		if got.Action == ActionReport && len(got.Changes) > 0 {
			t.Errorf("%s/%s: report-only workload has changes", got.Kind, got.Name)
		}
	}
	if s := p.Summary; s != (Summary{Patch: 5, Report: 4}) {
		t.Errorf("summary = %+v", s)
	}
}

func TestPlanner_Exclusions(t *testing.T) {
	skip := map[string]string{SkipAnnotation: "true"}
	deploy := func(ns, name string, ann map[string]string) appsv1.Deployment {
		return appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: ann}, Spec: appsv1.DeploymentSpec{Template: template()}}
	}
	in := Input{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "open"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "closed", Annotations: skip}},
		},
		Deployments: []appsv1.Deployment{
			deploy("open", "normal", nil),
			deploy("open", "opted-out", skip),
			deploy("open", "not-really", map[string]string{SkipAnnotation: "false"}),
			deploy("closed", "normal", nil),
		},
		Pods: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "closed", Name: "bare"}, Spec: *specWith()}},
	}
	p := BuildPlan(in, testDefaults)
	tests := []struct {
		kind, ns, name string
		want           Action
	}{
		{"Deployment", "open", "normal", ActionPatch},
		{"Deployment", "open", "opted-out", ActionSkip},
		{"Deployment", "open", "not-really", ActionPatch},
		{"Deployment", "closed", "normal", ActionSkip},
		{"Pod", "closed", "bare", ActionSkip}, // skip wins over report
	}
	for _, tt := range tests {
		t.Run(tt.ns+"/"+tt.name, func(t *testing.T) {
			w := find(t, p, tt.kind, tt.ns, tt.name)
			if w.Action != tt.want {
				t.Errorf("action = %s (%s), want %s", w.Action, w.Reason, tt.want)
			}
			if w.Action == ActionSkip && (len(w.Changes) > 0 || w.Reason == "") {
				t.Errorf("skip must have a reason and no changes: %+v", w)
			}
		})
	}
}

func TestPlanner_LimitRangeCovers(t *testing.T) {
	p := BuildPlan(demoInput(t), testDefaults)
	w := find(t, p, "Deployment", "hardening-lr", "lr-app")
	for _, c := range w.Changes {
		if c.Field == FieldMemoryRequest || c.Field == FieldMemoryLimit {
			t.Errorf("memory change despite LimitRange: %+v", c)
		}
	}
	var covered int
	for _, f := range w.Findings {
		if strings.Contains(f.Message, "LimitRange memory-defaults") {
			covered++
		}
	}
	if covered != 2 {
		t.Errorf("want R2 and R3 covered findings, got %d in %+v", covered, w.Findings)
	}
	// The LimitRange is namespaced: the same app in hardening-demo gets memory defaults.
	if !slices.ContainsFunc(find(t, p, "Deployment", "hardening-demo", "safe-app").Changes,
		func(c Change) bool { return c.Field == FieldMemoryLimit }) {
		t.Error("LimitRange in hardening-lr leaked into hardening-demo")
	}
}

func TestPlanner_HPAWarning(t *testing.T) {
	hpa := func(kind, name string, res corev1.ResourceName) autoscalingv2.HorizontalPodAutoscaler {
		return autoscalingv2.HorizontalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "h-" + name},
			Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
				ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{Kind: kind, Name: name},
				Metrics: []autoscalingv2.MetricSpec{{Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{Name: res}}},
			},
		}
	}
	withCPU := template()
	resources("requests.cpu=200m")(&withCPU.Spec)
	in := Input{
		Namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}},
		Deployments: []appsv1.Deployment{
			{ObjectMeta: meta("cpu-added", nil), Spec: appsv1.DeploymentSpec{Template: template()}},
			{ObjectMeta: meta("cpu-already", nil), Spec: appsv1.DeploymentSpec{Template: withCPU}},
			{ObjectMeta: meta("no-hpa", nil), Spec: appsv1.DeploymentSpec{Template: template()}},
		},
		StatefulSets: []appsv1.StatefulSet{{ObjectMeta: meta("cpu-added", nil), Spec: appsv1.StatefulSetSpec{Template: template()}}},
		HPAs: []autoscalingv2.HorizontalPodAutoscaler{
			hpa("Deployment", "cpu-added", corev1.ResourceCPU),
			hpa("Deployment", "cpu-already", corev1.ResourceCPU),
		},
	}
	p := BuildPlan(in, testDefaults)
	tests := []struct {
		kind, name string
		want       bool
	}{
		{"Deployment", "cpu-added", true},
		{"Deployment", "cpu-already", false}, // the request exists; nothing changes for the HPA
		{"Deployment", "no-hpa", false},
		{"StatefulSet", "cpu-added", false}, // same name, different kind
	}
	for _, tt := range tests {
		t.Run(tt.kind+"/"+tt.name, func(t *testing.T) {
			w := find(t, p, tt.kind, "ns", tt.name)
			got := slices.ContainsFunc(w.Findings, func(f Finding) bool {
				return f.Rule == "HPA" && f.Severity == "warning" && strings.Contains(f.Message, "begins scaling on cpu")
			})
			if got != tt.want {
				t.Errorf("HPA warning = %v, want %v; findings %+v", got, tt.want, w.Findings)
			}
		})
	}
}

// TestPlanner_DemoGolden pins the whole plan for the SPEC §12 workloads.
// The golden file was reviewed by hand against the SPEC §12 table.
// Regenerate with -update and review the diff.
func TestPlanner_DemoGolden(t *testing.T) {
	got, err := json.MarshalIndent(BuildPlan(demoInput(t), testDefaults), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "hardening-demo.plan.golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("plan differs from %s; run with -update and review the diff.\ngot:\n%s", path, got)
	}
}

// SPEC §10.3: the tool must pass its own hardening.
func TestPlanner_ToolOwnDeploymentIsCompliant(t *testing.T) {
	in := loadInput(t, "../../deploy/deployment.yaml")
	if len(in.Deployments) != 1 {
		t.Fatalf("want 1 Deployment in deploy/deployment.yaml, got %d", len(in.Deployments))
	}
	in.Namespaces = []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "sre-tool"}}}
	w := find(t, BuildPlan(in, testDefaults), "Deployment", "sre-tool", "sre-tool")
	if w.Action != ActionNone {
		t.Errorf("action = %s, changes %+v; the tool's own Deployment must need no hardening", w.Action, w.Changes)
	}
	// Strict findings would mean it passes only because they are report-only.
	for _, f := range w.Findings {
		if f.Severity != "info" {
			t.Errorf("non-info finding on the tool's own Deployment: %+v", f)
		}
	}
}

// applyChanges is what a successful apply does to a pod spec, as a pure
// function: it sets each planned field on a copy.
func applyChanges(t *testing.T, spec corev1.PodSpec, changes []Change) corev1.PodSpec {
	t.Helper()
	spec = *spec.DeepCopy()
	for _, ch := range changes {
		if ch.Field == FieldSeccomp {
			if spec.SecurityContext == nil {
				spec.SecurityContext = &corev1.PodSecurityContext{}
			}
			spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileType(ch.To.(string))}
			continue
		}
		c := containerByName(&spec, ch.Container)
		if c == nil {
			t.Fatalf("change for unknown container %q", ch.Container)
		}
		if c.SecurityContext == nil {
			c.SecurityContext = &corev1.SecurityContext{}
		}
		setQuantity := func(list *corev1.ResourceList, res corev1.ResourceName) {
			if *list == nil {
				*list = corev1.ResourceList{}
			}
			(*list)[res] = resource.MustParse(ch.To.(string))
		}
		switch ch.Field {
		case FieldAllowPrivEsc:
			c.SecurityContext.AllowPrivilegeEscalation = new(ch.To.(bool))
		case FieldRunAsNonRoot:
			c.SecurityContext.RunAsNonRoot = new(ch.To.(bool))
		case FieldReadOnlyRootFS:
			c.SecurityContext.ReadOnlyRootFilesystem = new(ch.To.(bool))
		case FieldCapabilitiesDrop:
			if c.SecurityContext.Capabilities == nil {
				c.SecurityContext.Capabilities = &corev1.Capabilities{}
			}
			for _, d := range ch.To.([]string) {
				c.SecurityContext.Capabilities.Drop = append(c.SecurityContext.Capabilities.Drop, corev1.Capability(d))
			}
		case FieldCPURequest:
			setQuantity(&c.Resources.Requests, corev1.ResourceCPU)
		case FieldMemoryRequest:
			setQuantity(&c.Resources.Requests, corev1.ResourceMemory)
		case FieldMemoryLimit:
			setQuantity(&c.Resources.Limits, corev1.ResourceMemory)
		default:
			t.Fatalf("applyChanges does not know field %s", ch.Field)
		}
	}
	return spec
}

func containerByName(spec *corev1.PodSpec, name string) *corev1.Container {
	for _, cs := range [][]corev1.Container{spec.InitContainers, spec.Containers} {
		for i := range cs {
			if cs[i].Name == name {
				return &cs[i]
			}
		}
	}
	return nil
}

// TestPlan_SecondPassIsEmpty is tricky test #3. Apply every planned change to
// a copy of each demo workload, plan again, and require zero patch actions.
// If a rule's condition does not see its own output as "set" (or wrote a
// nondeterministic value), every apply would restart everything (I-9).
func TestPlan_SecondPassIsEmpty(t *testing.T) {
	in := demoInput(t)
	// A strict copy of root-nginx, so X1-X3 changes converge too.
	i := slices.IndexFunc(in.Deployments, func(d appsv1.Deployment) bool { return d.Name == "root-nginx" })
	strict := *in.Deployments[i].DeepCopy()
	strict.Name, strict.Annotations = "root-nginx-strict", map[string]string{ProfileAnnotation: StrictProfile}
	in.Deployments = append(in.Deployments, strict)

	first := BuildPlan(in, testDefaults)
	if first.Summary.Patch == 0 {
		t.Fatal("first plan has nothing to patch; the test would prove nothing")
	}
	changes := map[string][]Change{}
	for _, w := range first.Workloads {
		changes[w.Kind+"/"+w.Namespace+"/"+w.Name] = w.Changes
	}
	key := func(kind string, m metav1.ObjectMeta) string { return kind + "/" + m.Namespace + "/" + m.Name }
	for i := range in.Deployments {
		d := &in.Deployments[i]
		d.Spec.Template.Spec = applyChanges(t, d.Spec.Template.Spec, changes[key("Deployment", d.ObjectMeta)])
	}
	for i := range in.StatefulSets {
		s := &in.StatefulSets[i]
		s.Spec.Template.Spec = applyChanges(t, s.Spec.Template.Spec, changes[key("StatefulSet", s.ObjectMeta)])
	}
	for i := range in.DaemonSets {
		d := &in.DaemonSets[i]
		d.Spec.Template.Spec = applyChanges(t, d.Spec.Template.Spec, changes[key("DaemonSet", d.ObjectMeta)])
	}
	for i := range in.CronJobs {
		c := &in.CronJobs[i]
		c.Spec.JobTemplate.Spec.Template.Spec = applyChanges(t, c.Spec.JobTemplate.Spec.Template.Spec, changes[key("CronJob", c.ObjectMeta)])
	}

	second := BuildPlan(in, testDefaults)
	if second.Summary.Patch != 0 {
		for _, w := range second.Workloads {
			if w.Action == ActionPatch {
				t.Errorf("second pass still patches %s %s/%s: %+v", w.Kind, w.Namespace, w.Name, w.Changes)
			}
		}
	}
	// Zero patches means apply sends nothing, so no template changes and no
	// rollout. Template hashes of untouched workloads must not move either.
	for i, w := range first.Workloads {
		if w.Action != ActionPatch && second.Workloads[i].TemplateHash != w.TemplateHash {
			t.Errorf("%s %s/%s: template hash changed although nothing was applied", w.Kind, w.Namespace, w.Name)
		}
	}
	// Every workload the first plan patched now reports none, nothing else moved.
	for i, w := range first.Workloads {
		want := w.Action
		if want == ActionPatch {
			want = ActionNone
		}
		if got := second.Workloads[i].Action; got != want {
			t.Errorf("%s %s/%s: action %s after apply, want %s", w.Kind, w.Namespace, w.Name, got, want)
		}
	}
}
