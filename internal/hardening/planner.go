package hardening

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Input is everything the planner looks at, for the requested namespaces
// only. Checking that those namespaces exist and are not protected (403/422)
// happens before planning, because it needs the live namespace list.
type Input struct {
	Namespaces   []corev1.Namespace
	Deployments  []appsv1.Deployment
	StatefulSets []appsv1.StatefulSet
	DaemonSets   []appsv1.DaemonSet
	CronJobs     []batchv1.CronJob
	Jobs         []batchv1.Job
	Pods         []corev1.Pod
	LimitRanges  []corev1.LimitRange
	HPAs         []autoscalingv2.HorizontalPodAutoscaler
}

// candidate is a listed workload before the rules run.
type candidate struct {
	kind   string
	meta   metav1.ObjectMeta
	spec   corev1.PodSpec // what the rules look at
	hashed any            // what the template hash covers (SPEC §7.5)
	report string         // non-empty: report only, for this reason
	impact string         // rollout impact if patched
}

// kindRank is the kind sort order of SPEC §7.4.
func kindRank(kind string) int {
	return slices.Index([]string{"CronJob", "Deployment", "StatefulSet", "DaemonSet", "Job", "Pod"}, kind)
}

// BuildPlan is the pure planner (SPEC §7.4): same input, same plan.
func BuildPlan(in Input, d Defaults) Plan {
	skippedNS := map[string]bool{}
	var namespaces []string
	for _, ns := range in.Namespaces {
		namespaces = append(namespaces, ns.Name)
		if ns.Annotations[SkipAnnotation] == "true" {
			skippedNS[ns.Name] = true
		}
	}
	slices.Sort(namespaces)

	plan := Plan{Namespaces: namespaces, Workloads: []Workload{}}
	for _, c := range candidates(in) {
		w := Workload{Kind: c.kind, Namespace: c.meta.Namespace, Name: c.meta.Name, UID: c.meta.UID,
			TemplateHash: templateHash(c.hashed), Findings: []Finding{}}
		owner := metav1.GetControllerOfNoCopy(&c.meta)
		switch {
		case skippedNS[w.Namespace]:
			w.Action, w.Reason = ActionSkip, "namespace annotated "+SkipAnnotation
		case c.meta.Annotations[SkipAnnotation] == "true":
			w.Action, w.Reason = ActionSkip, "annotated "+SkipAnnotation
		case owner != nil:
			// The owning controller would revert a patch (ADR-009).
			w.Action, w.Reason = ActionReport, fmt.Sprintf("managed by %s/%s", owner.Kind, owner.Name)
		case c.report != "":
			w.Action, w.Reason = ActionReport, c.report
		default:
			r := templateRules(&c.spec, ruleContext{
				strict:    c.meta.Annotations[ProfileAnnotation] == StrictProfile,
				defaults:  d,
				coveredBy: coveredBy(in.LimitRanges, w.Namespace),
			})
			w.Changes = r.changes
			w.Findings = append(w.Findings, r.findings...)
			w.Findings = append(w.Findings, hpaWarnings(in.HPAs, c, r.changes)...)
			w.Action = ActionNone
			if len(w.Changes) > 0 {
				w.Action, w.RolloutImpact = ActionPatch, c.impact
			}
		}
		plan.Workloads = append(plan.Workloads, w)
	}

	slices.SortFunc(plan.Workloads, func(a, b Workload) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(kindRank(a.Kind), kindRank(b.Kind)), cmp.Compare(a.Name, b.Name))
	})
	plan.PlanHash = planHash(plan.Workloads)
	for _, w := range plan.Workloads {
		switch w.Action {
		case ActionPatch:
			plan.Summary.Patch++
		case ActionNone:
			plan.Summary.None++
		case ActionReport:
			plan.Summary.Report++
		case ActionSkip:
			plan.Summary.Skip++
		}
	}
	return plan
}

// candidates applies the kind dispatch of SPEC §7.1. ReplicaSets are never
// in the input; Jobs created by a CronJob and Pods created by any controller
// are not listed, because their owner is the unit (and CronJob Jobs come and
// go, which would change the plan hash on every run).
func candidates(in Input) []candidate {
	var out []candidate
	for _, o := range in.Deployments {
		impact := "rolling restart"
		switch {
		case o.Spec.Paused:
			impact = "pending resume: paused, pods change when the Deployment is resumed"
		case o.Spec.Strategy.Type == appsv1.RecreateDeploymentStrategyType:
			impact = "recreate: all pods restart at once"
		}
		out = append(out, candidate{kind: "Deployment", meta: o.ObjectMeta, spec: o.Spec.Template.Spec, hashed: o.Spec.Template, impact: impact})
	}
	for _, o := range in.StatefulSets {
		impact := "rolling restart"
		switch ru := o.Spec.UpdateStrategy.RollingUpdate; {
		case o.Spec.UpdateStrategy.Type == appsv1.OnDeleteStatefulSetStrategyType:
			impact = "pending restart: OnDelete, pods change only when deleted"
		case ru != nil && ru.Partition != nil && *ru.Partition > 0:
			impact = fmt.Sprintf("partial: only ordinals >= %d update; the rest when the partition changes", *ru.Partition)
		}
		out = append(out, candidate{kind: "StatefulSet", meta: o.ObjectMeta, spec: o.Spec.Template.Spec, hashed: o.Spec.Template, impact: impact})
	}
	for _, o := range in.DaemonSets {
		impact := "rolling restart"
		if o.Spec.UpdateStrategy.Type == appsv1.OnDeleteDaemonSetStrategyType {
			impact = "pending restart: OnDelete, pods change only when deleted"
		}
		out = append(out, candidate{kind: "DaemonSet", meta: o.ObjectMeta, spec: o.Spec.Template.Spec, hashed: o.Spec.Template, impact: impact})
	}
	for _, o := range in.CronJobs {
		out = append(out, candidate{kind: "CronJob", meta: o.ObjectMeta, spec: o.Spec.JobTemplate.Spec.Template.Spec, hashed: o.Spec.JobTemplate.Spec.Template, impact: "future Jobs only; nothing restarts"})
	}
	for _, o := range in.Jobs {
		if owner := metav1.GetControllerOfNoCopy(&o.ObjectMeta); owner != nil && owner.Kind == "CronJob" && strings.HasPrefix(owner.APIVersion, "batch/") {
			continue
		}
		out = append(out, candidate{kind: "Job", meta: o.ObjectMeta, spec: o.Spec.Template.Spec, hashed: o.Spec.Template,
			report: "Job: pod template is immutable; change whatever creates it"})
	}
	for _, o := range in.Pods {
		if metav1.GetControllerOfNoCopy(&o.ObjectMeta) != nil {
			continue
		}
		out = append(out, candidate{kind: "Pod", meta: o.ObjectMeta, spec: o.Spec, hashed: o.Spec,
			report: "bare Pod: spec is immutable; recreate it from a controller"})
	}
	return out
}

// coveredBy maps each resource that a Container LimitRange in ns defaults
// (default or defaultRequest) to that LimitRange. With several, the first by
// name wins, so the finding text is stable.
func coveredBy(lrs []corev1.LimitRange, ns string) map[corev1.ResourceName]string {
	out := map[corev1.ResourceName]string{}
	sorted := slices.Clone(lrs)
	slices.SortFunc(sorted, func(a, b corev1.LimitRange) int { return cmp.Compare(a.Name, b.Name) })
	for _, lr := range sorted {
		if lr.Namespace != ns {
			continue
		}
		for _, item := range lr.Spec.Limits {
			if item.Type != corev1.LimitTypeContainer {
				continue
			}
			for _, list := range []corev1.ResourceList{item.Default, item.DefaultRequest} {
				for res := range list {
					if _, seen := out[res]; !seen {
						out[res] = lr.Name
					}
				}
			}
		}
	}
	return out
}

// hpaWarnings warns when an HPA scales the workload on utilisation of a
// resource whose request the plan adds: utilisation is measured against the
// request, so the HPA starts acting (ADR-007).
func hpaWarnings(hpas []autoscalingv2.HorizontalPodAutoscaler, c candidate, changes []Change) []Finding {
	added := map[corev1.ResourceName]bool{}
	for _, ch := range changes {
		switch ch.Field {
		case FieldCPURequest:
			added[corev1.ResourceCPU] = true
		case FieldMemoryRequest:
			added[corev1.ResourceMemory] = true
		}
	}
	var out []Finding
	for _, h := range hpas {
		if h.Namespace != c.meta.Namespace || h.Spec.ScaleTargetRef.Kind != c.kind || h.Spec.ScaleTargetRef.Name != c.meta.Name {
			continue
		}
		for _, m := range h.Spec.Metrics {
			if m.Type == autoscalingv2.ResourceMetricSourceType && m.Resource != nil && added[m.Resource.Name] {
				out = append(out, Finding{Rule: "HPA", Severity: "warning",
					Message: fmt.Sprintf("HPA %s begins scaling on %s utilisation relative to the new request", h.Name, m.Resource.Name)})
			}
		}
	}
	return out
}
