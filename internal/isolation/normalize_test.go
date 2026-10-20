package isolation

import (
	"reflect"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestNormalize_SidesAreCanonical(t *testing.T) {
	ab := briefRequest()
	ba := Request{Isolate: Pair{A: ab.Isolate.B, B: ab.Isolate.A}}

	nab, nba := Normalize(ab), Normalize(ba)
	if ID(nab) != ID(nba) {
		t.Errorf("ID(a,b) = %s, ID(b,a) = %s, want equal", ID(nab), ID(nba))
	}
	if !reflect.DeepEqual(nab, nba) {
		t.Errorf("normalised requests differ:\n a,b: %s\n b,a: %s", canonicalJSON(nab), canonicalJSON(nba))
	}
	if got := nab.Isolate.A.Namespaces; !reflect.DeepEqual(got, []string{"tenant-a"}) {
		t.Errorf("side a namespaces = %v, want [tenant-a] (its JSON sorts first)", got)
	}
}

func TestNormalize_IDStableAcrossOrdering(t *testing.T) {
	expr := func(key string, op metav1.LabelSelectorOperator, values ...string) metav1.LabelSelectorRequirement {
		return metav1.LabelSelectorRequirement{Key: key, Operator: op, Values: values}
	}
	base := Request{Isolate: Pair{
		A: &Side{Namespaces: []string{"x", "y"}, Selector: map[string]string{"app": "gw", "tier": "web"},
			MatchExpressions: []metav1.LabelSelectorRequirement{expr("env", metav1.LabelSelectorOpIn, "dev", "prod"), expr("zone", metav1.LabelSelectorOpExists)}},
		B: &Side{Namespace: "z", Selector: map[string]string{"app": "db"}},
	}}
	want := ID(Normalize(base))

	tests := []struct {
		name string
		req  Request
	}{
		{"namespaces reordered", Request{Isolate: Pair{
			A: &Side{Namespaces: []string{"y", "x"}, Selector: base.Isolate.A.Selector, MatchExpressions: base.Isolate.A.MatchExpressions},
			B: base.Isolate.B}}},
		{"namespaces duplicated", Request{Isolate: Pair{
			A: &Side{Namespaces: []string{"x", "y", "x"}, Selector: base.Isolate.A.Selector, MatchExpressions: base.Isolate.A.MatchExpressions},
			B: base.Isolate.B}}},
		{"expressions and values reordered", Request{Isolate: Pair{
			A: &Side{Namespaces: base.Isolate.A.Namespaces, Selector: base.Isolate.A.Selector,
				MatchExpressions: []metav1.LabelSelectorRequirement{expr("zone", metav1.LabelSelectorOpExists), expr("env", metav1.LabelSelectorOpIn, "prod", "dev")}},
			B: base.Isolate.B}}},
		{"namespace folded into namespaces", Request{Isolate: Pair{
			A: base.Isolate.A,
			B: &Side{Namespaces: []string{"z"}, Selector: map[string]string{"app": "db"}}}}},
		{"sides swapped", Request{Isolate: Pair{A: base.Isolate.B, B: base.Isolate.A}}},
		{"force does not change the ID", Request{Force: true, Isolate: base.Isolate}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ID(Normalize(tt.req)); got != want {
				t.Errorf("ID = %s, want %s", got, want)
			}
		})
	}

	t.Run("a different selector changes the ID", func(t *testing.T) {
		other := Request{Isolate: Pair{A: base.Isolate.A, B: &Side{Namespace: "z", Selector: map[string]string{"app": "cache"}}}}
		if ID(Normalize(other)) == want {
			t.Error("different requests got the same ID")
		}
	})
	t.Run("input is not modified", func(t *testing.T) {
		req := Request{Isolate: Pair{A: &Side{Namespaces: []string{"y", "x"}}, B: base.Isolate.B}}
		Normalize(req)
		if got := req.Isolate.A.Namespaces; !reflect.DeepEqual(got, []string{"y", "x"}) {
			t.Errorf("caller's namespaces = %v, want [y x]", got)
		}
	})
}

func TestNormalize_IdentityIgnoresNameAndForce(t *testing.T) {
	plain := Normalize(briefRequest())
	named := plain
	named.Name, named.Force = "incident-42", true
	if Identity(plain) != Identity(named) {
		t.Errorf("Identity differs: %s vs %s", Identity(plain), Identity(named))
	}
	empty := plain
	empty.AllowEmptySelector = true
	if Identity(plain) == Identity(empty) {
		t.Error("allowEmptySelector is part of the identity but did not change it")
	}
	if ID(named) != "incident-42" {
		t.Errorf("ID = %s, want the name", ID(named))
	}
}

func TestPolicyName_LengthAndDNS(t *testing.T) {
	for _, id := range []string{"0123456789", strings.Repeat("a", maxNameLen), "x"} {
		for _, side := range []string{"a", "b"} {
			name := PolicyName(id, side)
			if len(name) > 63 {
				t.Errorf("PolicyName(%q) = %d chars, want ≤ 63", id, len(name))
			}
			if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
				t.Errorf("PolicyName(%q) = %q is not a DNS-1123 subdomain: %v", id, name, errs)
			}
			if errs := validation.IsValidLabelValue(id); len(errs) > 0 {
				t.Errorf("ID %q is not a valid label value: %v", id, errs)
			}
		}
	}
}
