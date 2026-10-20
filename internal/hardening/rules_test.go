package hardening

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// specWith returns a pod spec with one container "app" that has nothing set,
// after applying the mutators.
func specWith(mutate ...func(*corev1.PodSpec)) *corev1.PodSpec {
	s := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "img"}}}
	for _, m := range mutate {
		m(s)
	}
	return s
}

// sc returns the first container's securityContext, creating it if needed.
func sc(s *corev1.PodSpec) *corev1.SecurityContext {
	if s.Containers[0].SecurityContext == nil {
		s.Containers[0].SecurityContext = &corev1.SecurityContext{}
	}
	return s.Containers[0].SecurityContext
}

// changed lists "container/field" for every change, in output order.
func changed(r result) []string {
	var out []string
	for _, c := range r.changes {
		out = append(out, c.Container+"/"+c.Field)
	}
	return out
}

func findingRules(r result) []string {
	var out []string
	for _, f := range r.findings {
		out = append(out, f.Container+"/"+f.Rule)
	}
	return out
}

func TestRules_FillUnsetOnly(t *testing.T) {
	strict := ruleContext{strict: true}
	// Control: with nothing set and the strict profile, every field is filled.
	// Without it, the cases below would pass even if the rules did nothing.
	all := changed(templateRules(specWith(), strict))
	for _, f := range []string{"/" + FieldSeccomp, "app/" + FieldAllowPrivEsc, "app/" + FieldRunAsNonRoot,
		"app/" + FieldCapabilitiesDrop, "app/" + FieldReadOnlyRootFS} {
		if !slices.Contains(all, f) {
			t.Fatalf("control: %s not filled on an empty spec; got %v", f, all)
		}
	}

	tests := []struct {
		name   string
		mutate func(*corev1.PodSpec)
		field  string // must not be changed
	}{
		{"pod seccomp Unconfined", func(s *corev1.PodSpec) {
			s.SecurityContext = &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}}
		}, "/" + FieldSeccomp},
		{"allowPrivilegeEscalation true", func(s *corev1.PodSpec) { sc(s).AllowPrivilegeEscalation = new(true) },
			"app/" + FieldAllowPrivEsc},
		{"container runAsNonRoot false", func(s *corev1.PodSpec) { sc(s).RunAsNonRoot = new(false) },
			"app/" + FieldRunAsNonRoot},
		{"pod runAsNonRoot false", func(s *corev1.PodSpec) {
			s.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: new(false)}
		}, "app/" + FieldRunAsNonRoot},
		{"capabilities drop NET_RAW only", func(s *corev1.PodSpec) {
			sc(s).Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}}
		}, "app/" + FieldCapabilitiesDrop},
		{"readOnlyRootFilesystem false", func(s *corev1.PodSpec) { sc(s).ReadOnlyRootFilesystem = new(false) },
			"app/" + FieldReadOnlyRootFS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := changed(templateRules(specWith(tt.mutate), strict))
			if slices.Contains(got, tt.field) {
				t.Errorf("explicit value overwritten: %s in %v", tt.field, got)
			}
		})
	}
}

func TestRules_PrivilegedSkipsAllowPrivilegeEscalation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*corev1.PodSpec)
	}{
		{"privileged", func(s *corev1.PodSpec) { sc(s).Privileged = new(true) }},
		{"adds SYS_ADMIN", func(s *corev1.PodSpec) {
			sc(s).Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}}
		}},
		{"adds CAP_SYS_ADMIN", func(s *corev1.PodSpec) {
			sc(s).Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"CAP_SYS_ADMIN"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := templateRules(specWith(tt.mutate), ruleContext{})
			if got := changed(r); slices.Contains(got, "app/"+FieldAllowPrivEsc) {
				t.Errorf("allowPrivilegeEscalation set although the API rejects it here: %v", got)
			}
			if got := findingRules(r); !slices.Contains(got, "app/S2") {
				t.Errorf("no S2 finding; findings %v", got)
			}
		})
	}
	// privileged: false is an explicit value, but not a reason to skip S2.
	r := templateRules(specWith(func(s *corev1.PodSpec) { sc(s).Privileged = new(false) }), ruleContext{})
	if !slices.Contains(changed(r), "app/"+FieldAllowPrivEsc) {
		t.Errorf("privileged=false should still get allowPrivilegeEscalation=false; got %v", changed(r))
	}
}

func TestRules_StrictOnlyFields(t *testing.T) {
	strictFields := []string{"app/" + FieldRunAsNonRoot, "app/" + FieldCapabilitiesDrop, "app/" + FieldReadOnlyRootFS}

	t.Run("default reports", func(t *testing.T) {
		r := templateRules(specWith(), ruleContext{})
		for _, f := range strictFields {
			if slices.Contains(changed(r), f) {
				t.Errorf("%s changed without the strict profile", f)
			}
		}
		if got, want := findingRules(r), []string{"app/X1", "app/X2", "app/X3"}; !containsAll(got, want) {
			t.Errorf("findings %v, want them to include %v", got, want)
		}
	})
	t.Run("strict sets", func(t *testing.T) {
		r := templateRules(specWith(), ruleContext{strict: true})
		if got := changed(r); !containsAll(got, strictFields) {
			t.Errorf("changes %v, want them to include %v", got, strictFields)
		}
		if got := findingRules(r); slices.Contains(got, "app/X1") || slices.Contains(got, "app/X2") || slices.Contains(got, "app/X3") {
			t.Errorf("strict still reports X findings: %v", got)
		}
	})
	t.Run("strict keeps capabilities add", func(t *testing.T) {
		r := templateRules(specWith(func(s *corev1.PodSpec) {
			sc(s).Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"NET_BIND_SERVICE"}}
		}), ruleContext{strict: true})
		for _, c := range r.changes {
			if c.Field == FieldCapabilitiesDrop && !slices.Equal(c.To.([]string), []string{"ALL"}) {
				t.Errorf("drop = %v, want [ALL]", c.To)
			}
			if c.Field == "container.securityContext.capabilities.add" {
				t.Errorf("capabilities.add touched: %+v", c)
			}
		}
		if !slices.Contains(changed(r), "app/"+FieldCapabilitiesDrop) {
			t.Errorf("drop not set: %v", changed(r))
		}
	})
}

func TestRules_InitContainersCoveredEphemeralIgnored(t *testing.T) {
	s := specWith(func(s *corev1.PodSpec) {
		s.InitContainers = []corev1.Container{{Name: "init", Image: "img"}}
		s.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "img"}}}
	})
	got := changed(templateRules(s, ruleContext{}))
	if !slices.Contains(got, "init/"+FieldAllowPrivEsc) {
		t.Errorf("init container not covered: %v", got)
	}
	for _, c := range got {
		if strings.HasPrefix(c, "debug/") {
			t.Errorf("ephemeral container touched: %v", got)
		}
	}
	// Init containers come before containers, so the order is stable.
	if i, j := slices.Index(got, "init/"+FieldAllowPrivEsc), slices.Index(got, "app/"+FieldAllowPrivEsc); i > j {
		t.Errorf("init container after app container: %v", got)
	}
}

func containsAll(got, want []string) bool {
	for _, w := range want {
		if !slices.Contains(got, w) {
			return false
		}
	}
	return true
}
