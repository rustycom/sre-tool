package hardening

import (
	"context"
	"fmt"

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

// Patch is one workload's server-side apply: a typed apply configuration
// that holds only the planned fields plus the keys that locate them (I-15).
type Patch struct {
	Kind, Namespace, Name string
	config                any // a *<Kind>ApplyConfiguration
}

// BuildPatch turns a patch workload's changes into its apply configuration.
func BuildPatch(w Workload) (Patch, error) {
	tpl, err := podTemplate(w.Changes)
	if err != nil {
		return Patch{}, fmt.Errorf("%s %s/%s: %w", w.Kind, w.Namespace, w.Name, err)
	}
	p := Patch{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
	switch w.Kind {
	case "Deployment":
		p.config = appsv1ac.Deployment(w.Name, w.Namespace).WithSpec(appsv1ac.DeploymentSpec().WithTemplate(tpl))
	case "StatefulSet":
		p.config = appsv1ac.StatefulSet(w.Name, w.Namespace).WithSpec(appsv1ac.StatefulSetSpec().WithTemplate(tpl))
	case "DaemonSet":
		p.config = appsv1ac.DaemonSet(w.Name, w.Namespace).WithSpec(appsv1ac.DaemonSetSpec().WithTemplate(tpl))
	case "CronJob":
		p.config = batchv1ac.CronJob(w.Name, w.Namespace).WithSpec(batchv1ac.CronJobSpec().WithJobTemplate(
			batchv1ac.JobTemplateSpec().WithSpec(batchv1ac.JobSpec().WithTemplate(tpl))))
	default:
		return Patch{}, fmt.Errorf("%s %s/%s: kind cannot be patched", w.Kind, w.Namespace, w.Name)
	}
	return p, nil
}

// send applies the patch with force: false, so a field another manager owns
// with a different value is a Conflict rather than a silent takeover (I-16).
// dryRun asks the API server to run validation and admission without
// persisting anything (SPEC §7.6).
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

// containerPatch collects one container's changes. Resources are gathered
// first because WithRequests and WithLimits replace the whole list.
type containerPatch struct {
	ac               *corev1ac.ContainerApplyConfiguration
	init             bool
	requests, limits corev1.ResourceList
}

func (c *containerPatch) securityContext() *corev1ac.SecurityContextApplyConfiguration {
	if c.ac.SecurityContext == nil {
		c.ac.WithSecurityContext(corev1ac.SecurityContext())
	}
	return c.ac.SecurityContext
}

// podTemplate builds the pod template part of the apply configuration.
// Containers keep the order of their first change, which follows template
// order, so the output is deterministic.
func podTemplate(changes []Change) (*corev1ac.PodTemplateSpecApplyConfiguration, error) {
	spec := corev1ac.PodSpec()
	var order []*containerPatch
	byName := map[string]*containerPatch{}
	for _, ch := range changes {
		if ch.Container == "" {
			t, ok := ch.To.(string)
			if ch.Field != FieldSeccomp || !ok {
				return nil, fmt.Errorf("unsupported pod-level change %s=%v", ch.Field, ch.To)
			}
			spec.WithSecurityContext(corev1ac.PodSecurityContext().WithSeccompProfile(
				corev1ac.SeccompProfile().WithType(corev1.SeccompProfileType(t))))
			continue
		}
		c := byName[ch.Container]
		if c == nil {
			c = &containerPatch{ac: corev1ac.Container().WithName(ch.Container), init: ch.Init,
				requests: corev1.ResourceList{}, limits: corev1.ResourceList{}}
			byName[ch.Container] = c
			order = append(order, c)
		}
		if err := c.add(ch); err != nil {
			return nil, fmt.Errorf("container %s: %w", ch.Container, err)
		}
	}
	for _, c := range order {
		if len(c.requests) > 0 || len(c.limits) > 0 {
			r := corev1ac.ResourceRequirements()
			if len(c.requests) > 0 {
				r.WithRequests(c.requests)
			}
			if len(c.limits) > 0 {
				r.WithLimits(c.limits)
			}
			c.ac.WithResources(r)
		}
		// WithContainers copies the value, so it runs after the container is complete.
		if c.init {
			spec.WithInitContainers(c.ac)
		} else {
			spec.WithContainers(c.ac)
		}
	}
	return corev1ac.PodTemplateSpec().WithSpec(spec), nil
}

func (c *containerPatch) add(ch Change) error {
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
		switch ch.Field {
		case FieldCPURequest:
			c.requests[corev1.ResourceCPU] = q
		case FieldMemoryRequest:
			c.requests[corev1.ResourceMemory] = q
		default:
			c.limits[corev1.ResourceMemory] = q
		}
	case FieldAllowPrivEsc, FieldRunAsNonRoot, FieldReadOnlyRootFS:
		b, ok := ch.To.(bool)
		if !ok {
			return fmt.Errorf("%s: want a bool, got %T", ch.Field, ch.To)
		}
		sc := c.securityContext()
		switch ch.Field {
		case FieldAllowPrivEsc:
			sc.WithAllowPrivilegeEscalation(b)
		case FieldRunAsNonRoot:
			sc.WithRunAsNonRoot(b)
		default:
			sc.WithReadOnlyRootFilesystem(b)
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
		c.securityContext().WithCapabilities(corev1ac.Capabilities().WithDrop(caps...))
	default:
		return fmt.Errorf("unsupported change %s", ch.Field)
	}
	return nil
}
