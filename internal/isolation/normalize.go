package isolation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const idHexLen = 10

// Normalize returns the canonical form of a validated request:
// namespace folded into namespaces, namespaces de-duplicated and sorted,
// expressions sorted by (key, operator, values) with sorted, de-duplicated values, and the side whose
// canonical JSON sorts first as side a. Equivalent requests therefore get the
// same ID and byte-identical policies. The input is not modified.
func Normalize(req Request) Request {
	a, b := normalizeSide(*req.Isolate.A), normalizeSide(*req.Isolate.B)
	if canonicalJSON(b) < canonicalJSON(a) {
		a, b = b, a
	}
	req.Isolate = Pair{A: &a, B: &b}
	return req
}

func normalizeSide(s Side) Side {
	namespaces := slices.Clone(s.Namespaces)
	if s.Namespace != "" {
		namespaces = append(namespaces, s.Namespace)
	}
	slices.Sort(namespaces)

	var exprs []metav1.LabelSelectorRequirement
	for _, e := range s.MatchExpressions {
		e.Values = slices.Clone(e.Values)
		slices.Sort(e.Values)
		e.Values = slices.Compact(e.Values)
		exprs = append(exprs, e)
	}
	slices.SortStableFunc(exprs, func(x, y metav1.LabelSelectorRequirement) int {
		if c := strings.Compare(x.Key, y.Key); c != 0 {
			return c
		}
		if c := strings.Compare(string(x.Operator), string(y.Operator)); c != 0 {
			return c
		}
		// Values break ties, so two requirements on the same key and
		// operator cannot keep their input order and change the ID.
		return slices.Compare(x.Values, y.Values)
	})

	var selector map[string]string
	if len(s.Selector) > 0 {
		selector = make(map[string]string, len(s.Selector))
		for k, v := range s.Selector {
			selector[k] = v
		}
	}
	return Side{Namespaces: slices.Compact(namespaces), Selector: selector, MatchExpressions: exprs}
}

// canonicalJSON is deterministic because encoding/json writes struct fields in
// declaration order and map keys sorted. The error is dropped on purpose: the
// only values passed in are built from strings, bools, string maps and string
// slices, which json.Marshal cannot fail on.
func canonicalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Identity is the canonical JSON of what the isolation does: the normalised
// isolate block plus allowEmptySelector, without name and force.
// It is stored in the sre-tool.io/request annotation, so name_conflict and
// drift checks compare two strings.
func Identity(normalized Request) string {
	return canonicalJSON(Request{AllowEmptySelector: normalized.AllowEmptySelector, Isolate: normalized.Isolate})
}

// ID is the request's name when given, otherwise the first 10 hex characters
// of the SHA-256 of the canonical JSON of the normalised isolate block.
func ID(normalized Request) string {
	if normalized.Name != "" {
		return normalized.Name
	}
	sum := sha256.Sum256([]byte(canonicalJSON(normalized.Isolate)))
	return hex.EncodeToString(sum[:])[:idHexLen]
}

// PolicyName is the name of the policy protecting side ("a" or "b"). With a
// name of at most 40 characters it stays well inside 63.
func PolicyName(id, side string) string {
	return "sre-iso-" + id + "-" + side
}
