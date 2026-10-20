package isolation

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/")

var testCIDRs = []string{"10.244.0.0/16"}

func build(t *testing.T, req Request) []networkingv1.NetworkPolicy {
	t.Helper()
	if err := Validate(req); err != nil {
		t.Fatalf("test request is invalid: %v", err)
	}
	n := Normalize(req)
	return BuildPolicies(n, ID(n), testCIDRs)
}

// toYAML renders policies as a multi-document YAML stream, the form a human
// would kubectl apply.
func toYAML(t *testing.T, policies []networkingv1.NetworkPolicy) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, p := range policies {
		b, err := yaml.Marshal(p)
		if err != nil {
			t.Fatalf("marshal %s: %v", p.Name, err)
		}
		buf.WriteString("---\n")
		buf.Write(b)
	}
	return buf.Bytes()
}

// TestBuild_BriefExampleGolden compares against testdata, which was checked by
// hand against SPEC §6.5. Regenerate with -update and review the diff.
func TestBuild_BriefExampleGolden(t *testing.T) {
	got := toYAML(t, build(t, briefRequest()))
	path := filepath.Join("testdata", "brief-example.golden.yaml")
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
		t.Errorf("policies differ from %s:\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}

func TestBuild_IngressOnly(t *testing.T) {
	for _, p := range build(t, briefRequest()) {
		if !reflect.DeepEqual(p.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}) {
			t.Errorf("%s: policyTypes = %v, want [Ingress]", p.Name, p.Spec.PolicyTypes)
		}
		if len(p.Spec.Egress) != 0 {
			t.Errorf("%s: has %d egress rules, want none", p.Name, len(p.Spec.Egress))
		}
		if len(p.Spec.Ingress) != 1 {
			t.Fatalf("%s: has %d ingress rules, want 1", p.Name, len(p.Spec.Ingress))
		}
		if len(p.Spec.Ingress[0].Ports) != 0 {
			t.Errorf("%s: ingress rule has ports %v, want none (all ports)", p.Name, p.Spec.Ingress[0].Ports)
		}
	}
}

func TestBuild_LabelsAndAnnotations(t *testing.T) {
	req := Normalize(briefRequest())
	id := ID(req)
	policies := BuildPolicies(req, id, testCIDRs)
	if len(policies) != 2 {
		t.Fatalf("got %d policies, want 2", len(policies))
	}
	for i, side := range []string{"a", "b"} {
		p := policies[i]
		if p.Name != PolicyName(id, side) {
			t.Errorf("policy %d name = %s, want %s", i, p.Name, PolicyName(id, side))
		}
		wantLabels := map[string]string{LabelManagedBy: "sre-tool", LabelIsolationID: id, LabelSide: side}
		if !reflect.DeepEqual(p.Labels, wantLabels) {
			t.Errorf("%s labels = %v, want %v", p.Name, p.Labels, wantLabels)
		}
		wantAnnotations := map[string]string{
			AnnotationRequest:        `{"isolate":{"a":{"namespaces":["tenant-a"],"selector":{"app":"gateway"}},"b":{"namespaces":["tenant-b"],"selector":{"app":"dashboard"}}}}`,
			AnnotationExpectedPolicy: "2",
		}
		if !reflect.DeepEqual(p.Annotations, wantAnnotations) {
			t.Errorf("%s annotations = %v, want %v", p.Name, p.Annotations, wantAnnotations)
		}
	}
}

func TestBuild_SameNamespace(t *testing.T) {
	policies := build(t, Request{Isolate: Pair{
		A: &Side{Namespace: "shared", Selector: map[string]string{"app": "gateway"}},
		B: &Side{Namespace: "shared", Selector: map[string]string{"app": "dashboard"}},
	}})
	if len(policies) != 2 {
		t.Fatalf("got %d policies, want 2", len(policies))
	}
	// Side a is dashboard (its JSON sorts first); its policy blocks gateway.
	if got := policies[0].Spec.PodSelector.MatchLabels["app"]; got != "dashboard" {
		t.Fatalf("policy 0 protects app=%s, want dashboard", got)
	}
	from := policies[0].Spec.Ingress[0].From
	if got := from[0].NamespaceSelector.MatchExpressions[0].Values; !reflect.DeepEqual(got, []string{"shared"}) {
		t.Errorf("peer 1 excludes %v, want [shared]", got)
	}
	// Pods of the shared namespace that are not side b (gateway) are still
	// admitted, including side a's own pods and unlabelled pods.
	for _, tc := range []struct {
		labels map[string]string
		want   bool
	}{
		{map[string]string{"app": "dashboard"}, true},
		{map[string]string{"app": "other"}, true},
		{map[string]string{}, true},
		{map[string]string{"app": "gateway"}, false},
	} {
		if got := admitted(t, from[1:2], "shared", tc.labels); got != tc.want {
			t.Errorf("pod %v in shared namespace admitted = %v, want %v", tc.labels, got, tc.want)
		}
	}
}

func TestBuild_MultiNamespaceSides(t *testing.T) {
	policies := build(t, Request{Isolate: Pair{
		A: &Side{Namespaces: []string{"a2", "a1"}, Selector: map[string]string{"app": "gw"}},
		B: &Side{Namespaces: []string{"b1", "b2", "b3"}, Selector: map[string]string{"app": "db"}},
	}})
	var got []string
	for _, p := range policies {
		got = append(got, p.Namespace+"/"+p.Labels[LabelSide])
		if p.Annotations[AnnotationExpectedPolicy] != "5" {
			t.Errorf("%s/%s expected-policies = %s, want 5", p.Namespace, p.Name, p.Annotations[AnnotationExpectedPolicy])
		}
	}
	// The side whose JSON sorts first is a: {"namespaces":["a1",...]}.
	if want := []string{"a1/a", "a2/a", "b1/b", "b2/b", "b3/b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("policies = %v, want %v", got, want)
	}
	for _, p := range policies {
		wantOther := []string{"b1", "b2", "b3"}
		if p.Labels[LabelSide] == "b" {
			wantOther = []string{"a1", "a2"}
		}
		from := p.Spec.Ingress[0].From
		if got := from[0].NamespaceSelector.MatchExpressions[0].Values; !reflect.DeepEqual(got, wantOther) {
			t.Errorf("%s/%s peer 1 NotIn %v, want %v", p.Namespace, p.Name, got, wantOther)
		}
		// One complement peer per other-side namespace (one requirement each),
		// plus peer 1 and the ipBlock.
		if len(from) != len(wantOther)+2 {
			t.Errorf("%s/%s has %d peers, want %d", p.Namespace, p.Name, len(from), len(wantOther)+2)
		}
	}
}

func TestBuild_EmptyOtherSelector(t *testing.T) {
	policies := build(t, Request{AllowEmptySelector: true, Isolate: Pair{
		A: &Side{Namespace: "tenant-a", Selector: map[string]string{"app": "gateway"}},
		B: &Side{Namespace: "tenant-b"},
	}})
	for _, p := range policies {
		from := p.Spec.Ingress[0].From
		if p.Namespace == "tenant-a" {
			// Only peer 1 and the ipBlock: all of tenant-b is blocked.
			if len(from) != 2 || from[0].NamespaceSelector == nil || from[1].IPBlock == nil {
				t.Errorf("tenant-a policy peers = %+v, want [namespace NotIn, ipBlock]", from)
			}
		}
		if p.Namespace == "tenant-b" && !reflect.DeepEqual(p.Spec.PodSelector, metav1.LabelSelector{}) {
			t.Errorf("tenant-b podSelector = %+v, want empty (every pod)", p.Spec.PodSelector)
		}
	}
}

func TestBuild_DeterministicOrder(t *testing.T) {
	expr := func(key, value string) metav1.LabelSelectorRequirement {
		return metav1.LabelSelectorRequirement{Key: key, Operator: metav1.LabelSelectorOpNotIn, Values: []string{value, "z"}}
	}
	ordered := Request{Isolate: Pair{
		A: &Side{Namespaces: []string{"a1", "a2"}, Selector: map[string]string{"app": "gw", "tier": "web", "zone": "1"},
			MatchExpressions: []metav1.LabelSelectorRequirement{expr("env", "x"), expr("team", "y")}},
		B: &Side{Namespaces: []string{"b1", "b2"}, Selector: map[string]string{"app": "db", "role": "primary"}},
	}}
	shuffled := Request{Isolate: Pair{
		A: &Side{Namespaces: []string{"b2", "b1"}, Selector: map[string]string{"role": "primary", "app": "db"}},
		B: &Side{Namespaces: []string{"a2", "a1", "a2"}, Selector: map[string]string{"zone": "1", "tier": "web", "app": "gw"},
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "team", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"z", "y"}},
				{Key: "env", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"z", "x"}},
			}},
	}}
	want := toYAML(t, build(t, ordered))
	// Map iteration order is random, so build repeatedly to catch an order
	// that depends on it.
	for i := 0; i < 20; i++ {
		if got := toYAML(t, build(t, shuffled)); !bytes.Equal(got, want) {
			t.Fatalf("run %d: output differs:\n--- got\n%s\n--- want\n%s", i, got, want)
		}
	}
	if !strings.Contains(string(want), "role") {
		t.Error("sanity: expected a complement peer for the role label")
	}
}
