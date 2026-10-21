package hardening

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	batchv1ac "k8s.io/client-go/applyconfigurations/batch/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
)

// FieldManager owns every field the tool sets (server-side apply).
const FieldManager = "sre-tool"

// Patch is one workload's server-side apply configuration.
type Patch struct {
	Kind, Namespace, Name string
	config                any // a *<Kind>ApplyConfiguration
}

// BuildPatch builds the apply configuration for a patch workload from its
// live object: the fields sre-tool already owns there, plus the planned
// changes, plus the container names that key them.
//
// Starting from what sre-tool owns is required, not cosmetic: an apply
// removes every field its manager owned and no longer sends, so a
// configuration with only the new changes would strip earlier hardening
// (moving a workload to strict would drop its seccomp profile and resource
// defaults). Nothing owned by another manager is included.
func BuildPatch(w Workload, live runtime.Object) (Patch, error) {
	p := Patch{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
	tpl, err := p.extract(live)
	if err != nil {
		return Patch{}, fmt.Errorf("%s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	if tpl.Spec == nil {
		tpl.WithSpec(corev1ac.PodSpec())
	}
	for _, ch := range w.Changes {
		if err := addChange(tpl.Spec, ch); err != nil {
			return Patch{}, fmt.Errorf("%s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
		}
	}
	return p, nil
}

// extract sets p.config to what sre-tool owns on live and returns its pod
// template, created empty when sre-tool owns nothing there yet.
func (p *Patch) extract(live runtime.Object) (*corev1ac.PodTemplateSpecApplyConfiguration, error) {
	tpl := corev1ac.PodTemplateSpec()
	switch o := live.(type) {
	case *appsv1.Deployment:
		ac, err := appsv1ac.ExtractDeployment(o, FieldManager)
		if err != nil {
			return nil, fmt.Errorf("extract owned fields: %w", err)
		}
		if ac.Spec == nil {
			ac.WithSpec(appsv1ac.DeploymentSpec())
		}
		if ac.Spec.Template == nil {
			ac.Spec.WithTemplate(tpl)
		}
		p.config, tpl = ac, ac.Spec.Template
	case *appsv1.StatefulSet:
		ac, err := appsv1ac.ExtractStatefulSet(o, FieldManager)
		if err != nil {
			return nil, fmt.Errorf("extract owned fields: %w", err)
		}
		if ac.Spec == nil {
			ac.WithSpec(appsv1ac.StatefulSetSpec())
		}
		if ac.Spec.Template == nil {
			ac.Spec.WithTemplate(tpl)
		}
		p.config, tpl = ac, ac.Spec.Template
	case *appsv1.DaemonSet:
		ac, err := appsv1ac.ExtractDaemonSet(o, FieldManager)
		if err != nil {
			return nil, fmt.Errorf("extract owned fields: %w", err)
		}
		if ac.Spec == nil {
			ac.WithSpec(appsv1ac.DaemonSetSpec())
		}
		if ac.Spec.Template == nil {
			ac.Spec.WithTemplate(tpl)
		}
		p.config, tpl = ac, ac.Spec.Template
	case *batchv1.CronJob:
		ac, err := batchv1ac.ExtractCronJob(o, FieldManager)
		if err != nil {
			return nil, fmt.Errorf("extract owned fields: %w", err)
		}
		if ac.Spec == nil {
			ac.WithSpec(batchv1ac.CronJobSpec())
		}
		if ac.Spec.JobTemplate == nil {
			ac.Spec.WithJobTemplate(batchv1ac.JobTemplateSpec())
		}
		if ac.Spec.JobTemplate.Spec == nil {
			ac.Spec.JobTemplate.WithSpec(batchv1ac.JobSpec())
		}
		if ac.Spec.JobTemplate.Spec.Template == nil {
			ac.Spec.JobTemplate.Spec.WithTemplate(tpl)
		}
		p.config, tpl = ac, ac.Spec.JobTemplate.Spec.Template
	default:
		return nil, fmt.Errorf("kind %T cannot be patched", live)
	}
	return tpl, nil
}

// send applies the patch with force: false, so a field another manager owns
// with a different value is a Conflict rather than a silent takeover.
// dryRun asks the API server to run validation and admission without
// persisting anything.
func (p Patch) send(ctx context.Context, c kubernetes.Interface, dryRun bool) (runtime.Object, error) {
	opts := metav1.ApplyOptions{FieldManager: FieldManager, Force: false}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	switch ac := p.config.(type) {
	case *appsv1ac.DeploymentApplyConfiguration:
		return c.AppsV1().Deployments(p.Namespace).Apply(ctx, ac, opts)
	case *appsv1ac.StatefulSetApplyConfiguration:
		return c.AppsV1().StatefulSets(p.Namespace).Apply(ctx, ac, opts)
	case *appsv1ac.DaemonSetApplyConfiguration:
		return c.AppsV1().DaemonSets(p.Namespace).Apply(ctx, ac, opts)
	case *batchv1ac.CronJobApplyConfiguration:
		return c.BatchV1().CronJobs(p.Namespace).Apply(ctx, ac, opts)
	}
	return nil, fmt.Errorf("%s %s/%s: no apply configuration", p.Kind, p.Namespace, p.Name)
}

// container returns the named container in spec's configuration, adding it
// with only its name (the list key) when sre-tool owns nothing in it yet.
// The pointer is into the slice, so it is used before the next append.
func container(spec *corev1ac.PodSpecApplyConfiguration, name string, init bool) *corev1ac.ContainerApplyConfiguration {
	list := &spec.Containers
	if init {
		list = &spec.InitContainers
	}
	for i := range *list {
		if c := &(*list)[i]; c.Name != nil && *c.Name == name {
			return c
		}
	}
	*list = append(*list, *corev1ac.Container().WithName(name))
	return &(*list)[len(*list)-1]
}

// addChange sets one planned field in the pod spec configuration.
func addChange(spec *corev1ac.PodSpecApplyConfiguration, ch Change) error {
	if ch.Container == "" {
		t, ok := ch.To.(string)
		if ch.Field != FieldSeccomp || !ok {
			return fmt.Errorf("unsupported pod-level change %s=%v", ch.Field, ch.To)
		}
		if spec.SecurityContext == nil {
			spec.WithSecurityContext(corev1ac.PodSecurityContext())
		}
		spec.SecurityContext.WithSeccompProfile(corev1ac.SeccompProfile().WithType(corev1.SeccompProfileType(t)))
		return nil
	}
	c := container(spec, ch.Container, ch.Init)
	if err := setContainerField(c, ch); err != nil {
		return fmt.Errorf("container %s: %w", ch.Container, err)
	}
	return nil
}

func setContainerField(c *corev1ac.ContainerApplyConfiguration, ch Change) error {
	switch ch.Field {
	case FieldCPURequest, FieldMemoryRequest, FieldMemoryLimit:
		s, ok := ch.To.(string)
		if !ok {
			return fmt.Errorf("%s: want a quantity string, got %T", ch.Field, ch.To)
		}
		q, err := resource.ParseQuantity(s)
		if err != nil {
			return fmt.Errorf("%s: %w", ch.Field, err)
		}
		if c.Resources == nil {
			c.WithResources(corev1ac.ResourceRequirements())
		}
		r := c.Resources
		switch ch.Field {
		case FieldCPURequest, FieldMemoryRequest:
			if r.Requests == nil {
				r.WithRequests(corev1.ResourceList{})
			}
			name := corev1.ResourceCPU
			if ch.Field == FieldMemoryRequest {
				name = corev1.ResourceMemory
			}
			(*r.Requests)[name] = q
		default:
			if r.Limits == nil {
				r.WithLimits(corev1.ResourceList{})
			}
			(*r.Limits)[corev1.ResourceMemory] = q
		}
	case FieldAllowPrivEsc, FieldRunAsNonRoot, FieldReadOnlyRootFS:
		b, ok := ch.To.(bool)
		if !ok {
			return fmt.Errorf("%s: want a bool, got %T", ch.Field, ch.To)
		}
		if c.SecurityContext == nil {
			c.WithSecurityContext(corev1ac.SecurityContext())
		}
		switch ch.Field {
		case FieldAllowPrivEsc:
			c.SecurityContext.WithAllowPrivilegeEscalation(b)
		case FieldRunAsNonRoot:
			c.SecurityContext.WithRunAsNonRoot(b)
		default:
			c.SecurityContext.WithReadOnlyRootFilesystem(b)
		}
	case FieldCapabilitiesDrop:
		drop, ok := ch.To.([]string)
		if !ok {
			return fmt.Errorf("%s: want a string list, got %T", ch.Field, ch.To)
		}
		caps := make([]corev1.Capability, 0, len(drop))
		for _, d := range drop {
			caps = append(caps, corev1.Capability(d))
		}
		if c.SecurityContext == nil {
			c.WithSecurityContext(corev1ac.SecurityContext())
		}
		c.SecurityContext.WithCapabilities(corev1ac.Capabilities().WithDrop(caps...))
	default:
		return fmt.Errorf("unsupported change %s", ch.Field)
	}
	return nil
}
