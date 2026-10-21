package hardening

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"k8s.io/apimachinery/pkg/types"
)

// templateHash is the SHA-256 of the canonical JSON of what apply would patch.
// encoding/json writes struct fields in declaration order and map
// keys sorted, so equal templates give equal bytes.
func templateHash(template any) string {
	return sha256Hex(canonicalJSON(template))
}

// planHash covers every listed workload, in plan order. It leaves out
// resourceVersion and generation on purpose: status writes, HPAs and
// `kubectl scale` bump those without changing what apply would patch,
// and the hash would flap. Finding text is left out too.
func planHash(ws []Workload) string {
	type entry struct {
		UID          types.UID `json:"uid"`
		Kind         string    `json:"kind"`
		Namespace    string    `json:"namespace"`
		Name         string    `json:"name"`
		TemplateHash string    `json:"templateHash"`
		Action       Action    `json:"action"`
		Changes      []Change  `json:"changes"`
	}
	entries := make([]entry, 0, len(ws))
	for _, w := range ws {
		entries = append(entries, entry{w.UID, w.Kind, w.Namespace, w.Name, w.TemplateHash, w.Action, w.Changes})
	}
	return "sha256:" + sha256Hex(canonicalJSON(entries))
}

// canonicalJSON drops json.Marshal's error on purpose: the values are typed
// API structs and plain strings, bools and string slices, none of which can
// fail to marshal, and panic is not allowed outside main.
func canonicalJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
