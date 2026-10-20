package hardening

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// ruleContext is what the rules need beyond the pod spec itself.
type ruleContext struct {
	strict   bool // workload annotated sre-tool.io/harden-profile: strict
	defaults Defaults
	// coveredBy maps a resource to the LimitRange that defaults it at
	// admission in this namespace; R1–R3 leave such resources alone.
	coveredBy map[corev1.ResourceName]string
}

// result collects the changes and findings of the rules for one template.
type result struct {
	changes  []Change
	findings []Finding
}

func (r *result) change(container, field string, to any) {
	r.changes = append(r.changes, Change{Container: container, Field: field, To: to})
}

func (r *result) finding(container, rule, severity, message string) {
	r.findings = append(r.findings, Finding{Container: container, Rule: rule, Severity: severity, Message: message})
}

// templateRules runs every rule on one pod spec (SPEC §7.3): pod-level rules
// first, then each init container and container in template order, so the
// output is deterministic. Ephemeral containers are never touched: they are
// added through their own subresource and cannot be set in a template.
func templateRules(spec *corev1.PodSpec, ctx ruleContext) result {
	var r result
	// API validation rejects seccomp, allowPrivilegeEscalation, capabilities
	// and readOnlyRootFilesystem on Windows pods, so setting them would only
	// make apply fail (ADR-018). Resources and runAsNonRoot are allowed.
	windows := spec.OS != nil && spec.OS.Name == corev1.Windows
	if windows {
		r.finding("", "WIN", "info", "Windows pod: seccomp, allowPrivilegeEscalation, capabilities and readOnlyRootFilesystem are not allowed, so S1, S2, X2 and X3 are skipped")
	} else {
		ruleS1(&r, spec)
	}
	ruleHostNamespaces(&r, spec)
	for list, cs := range [][]corev1.Container{spec.InitContainers, spec.Containers} {
		for i := range cs {
			c := &cs[i]
			first := len(r.changes)
			rulePrivileged(&r, c)
			if !windows {
				ruleS2(&r, c)
			}
			ruleRequest(&r, c, corev1.ResourceCPU, "R1", ctx.defaults.CPURequest, FieldCPURequest, ctx)
			ruleRequest(&r, c, corev1.ResourceMemory, "R2", ctx.defaults.MemoryRequest, FieldMemoryRequest, ctx)
			ruleR3(&r, c, ctx)
			ruleR4(&r, c)
			ruleX1(&r, c, spec, ctx)
			if !windows {
				ruleX2(&r, c, ctx)
				ruleX3(&r, c, ctx)
			}
			for j := first; j < len(r.changes); j++ {
				r.changes[j].Init = list == 0
			}
		}
	}
	return r
}

// ruleS1 sets the pod-level seccomp profile when it is unset. A container-level
// profile overrides the pod one (I-13), so it is left alone either way.
func ruleS1(r *result, spec *corev1.PodSpec) {
	if spec.SecurityContext == nil || spec.SecurityContext.SeccompProfile == nil {
		r.change("", FieldSeccomp, string(corev1.SeccompProfileTypeRuntimeDefault))
	}
}

func ruleHostNamespaces(r *result, spec *corev1.PodSpec) {
	for _, h := range []struct {
		on   bool
		name string
	}{{spec.HostNetwork, "hostNetwork"}, {spec.HostPID, "hostPID"}, {spec.HostIPC, "hostIPC"}} {
		if h.on {
			r.finding("", "HOST", "warning", h.name+" is enabled; reported, never changed")
		}
	}
}

func rulePrivileged(r *result, c *corev1.Container) {
	if isPrivileged(c) {
		r.finding(c.Name, "PRIV", "warning", "privileged container; reported, never changed")
	}
}

// ruleS2 sets allowPrivilegeEscalation=false when it is unset, except where
// API validation rejects that value: with privileged or CAP_SYS_ADMIN (I-12).
func ruleS2(r *result, c *corev1.Container) {
	if c.SecurityContext != nil && c.SecurityContext.AllowPrivilegeEscalation != nil {
		return
	}
	if isPrivileged(c) || addsSysAdmin(c) {
		r.finding(c.Name, "S2", "warning",
			"allowPrivilegeEscalation unset; not set because the API server rejects false with privileged or SYS_ADMIN")
		return
	}
	r.change(c.Name, FieldAllowPrivEsc, false)
}

// ruleRequest is R1 (cpu) and R2 (memory): set a default request only when
// neither a request nor a limit exists. With a limit, admission already sets
// the request to the limit (I-11); adding the default would lower it.
func ruleRequest(r *result, c *corev1.Container, res corev1.ResourceName, rule string, def resource.Quantity, field string, ctx ruleContext) {
	if _, ok := c.Resources.Requests[res]; ok {
		return
	}
	if lim, ok := c.Resources.Limits[res]; ok {
		r.finding(c.Name, rule, "info", fmt.Sprintf("%s request unset; it defaults to the %s limit at admission, so no lower request is added", res, lim.String()))
		return
	}
	if lr, ok := ctx.coveredBy[res]; ok {
		r.finding(c.Name, rule, "info", fmt.Sprintf("%s request covered at admission by LimitRange %s", res, lr))
		return
	}
	r.change(c.Name, field, def.String())
}

// ruleR3 sets a memory limit no lower than the request. When there is no
// request, R2 adds the default one (the limit is unset here too), so that
// default is the request to compare against.
func ruleR3(r *result, c *corev1.Container, ctx ruleContext) {
	if _, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
		return
	}
	if lr, ok := ctx.coveredBy[corev1.ResourceMemory]; ok {
		// SPEC §7.3 skips R1–R3 for a resource the LimitRange defaults at all.
		// It may set only defaultRequest, so this does not claim a limit is set.
		r.finding(c.Name, "R3", "info", "memory limit left to LimitRange "+lr+", which defaults memory at admission")
		return
	}
	req, ok := c.Resources.Requests[corev1.ResourceMemory]
	if !ok {
		req = ctx.defaults.MemoryRequest
	}
	limit := ctx.defaults.MemoryLimit
	if req.Cmp(limit) > 0 {
		limit = req
	}
	r.change(c.Name, FieldMemoryLimit, limit.String())
}

// ruleR4 never sets a CPU limit (ADR-007: throttling hurts more than it
// protects); it only says so.
func ruleR4(r *result, c *corev1.Container) {
	if _, ok := c.Resources.Limits[corev1.ResourceCPU]; !ok {
		r.finding(c.Name, "R4", "info", "no CPU limit; not set on purpose, CPU limits throttle even on idle nodes")
	}
}

// ruleX1 covers runAsNonRoot, which the kubelet checks only at container start
// (I-14): an image that runs as root then fails, and no dry-run can tell.
// Hence report by default and set only on the strict opt-in (ADR-006).
func ruleX1(r *result, c *corev1.Container, spec *corev1.PodSpec, ctx ruleContext) {
	if spec.SecurityContext != nil && spec.SecurityContext.RunAsNonRoot != nil {
		return
	}
	if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
		return
	}
	if ctx.strict {
		r.change(c.Name, FieldRunAsNonRoot, true)
		return
	}
	r.finding(c.Name, "X1", "warning",
		"runAsNonRoot unset; applied only with harden-profile=strict (fails at start if the image runs as root)")
}

// ruleX2 drops all capabilities on the strict opt-in. Existing add entries are
// kept: the patch only sets drop, and add is a separate field.
func ruleX2(r *result, c *corev1.Container, ctx ruleContext) {
	if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil && len(c.SecurityContext.Capabilities.Drop) > 0 {
		return
	}
	if ctx.strict {
		r.change(c.Name, FieldCapabilitiesDrop, []string{"ALL"})
		return
	}
	r.finding(c.Name, "X2", "warning",
		"capabilities.drop empty; [ALL] applied only with harden-profile=strict (some images need capabilities such as SETUID)")
}

func ruleX3(r *result, c *corev1.Container, ctx ruleContext) {
	if c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil {
		return
	}
	if ctx.strict {
		r.change(c.Name, FieldReadOnlyRootFS, true)
		return
	}
	r.finding(c.Name, "X3", "warning",
		"readOnlyRootFilesystem unset; applied only with harden-profile=strict (fails if the app writes to its filesystem)")
}

func isPrivileged(c *corev1.Container) bool {
	return c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged
}

func addsSysAdmin(c *corev1.Container) bool {
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		return false
	}
	for _, cap := range c.SecurityContext.Capabilities.Add {
		if cap == "SYS_ADMIN" || cap == "CAP_SYS_ADMIN" {
			return true
		}
	}
	return false
}
