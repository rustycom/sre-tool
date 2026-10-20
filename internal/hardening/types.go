// Package hardening plans and applies securityContext and resource defaults
// to workloads (SPEC §7). The planner is pure: it works on typed objects that
// a collector fetched, and makes no API calls.
package hardening

import "k8s.io/apimachinery/pkg/types"

// Annotations read by the planner (SPEC §5.1).
const (
	SkipAnnotation    = "sre-tool.io/skip"
	ProfileAnnotation = "sre-tool.io/harden-profile"
	StrictProfile     = "strict"
)

// Action is what apply would do with a workload.
type Action string

const (
	ActionPatch  Action = "patch"
	ActionNone   Action = "none" // already compliant
	ActionReport Action = "report"
	ActionSkip   Action = "skip"
)

// Plan is the response of POST /v1/hardening/plan (SPEC §7.4).
type Plan struct {
	PlanHash   string     `json:"planHash"`
	Namespaces []string   `json:"namespaces"`
	Summary    Summary    `json:"summary"`
	Workloads  []Workload `json:"workloads"`
}

// Summary counts workloads per action. A struct rather than a map, so every
// action is always present, zero included.
type Summary struct {
	Patch  int `json:"patch"`
	None   int `json:"none"`
	Report int `json:"report"`
	Skip   int `json:"skip"`
}

// Workload is one listed workload and what apply would do to it.
type Workload struct {
	Kind          string    `json:"kind"`
	Namespace     string    `json:"namespace"`
	Name          string    `json:"name"`
	Action        Action    `json:"action"`
	Reason        string    `json:"reason,omitempty"`        // why report or skip
	RolloutImpact string    `json:"rolloutImpact,omitempty"` // patch only
	Changes       []Change  `json:"changes,omitempty"`
	Findings      []Finding `json:"findings"`

	// Inputs to the plan hash (SPEC §7.5), not part of the response.
	UID          types.UID `json:"-"`
	TemplateHash string    `json:"-"`
}

// Change sets one unset field. Container is empty for pod-level fields;
// container names are unique across containers and initContainers, so the
// name alone locates the container.
type Change struct {
	Container string `json:"container"`
	Field     string `json:"field"`
	// From is always null: rules fill unset fields only (SPEC §7.3). It is
	// kept so the response shows the before and after side by side.
	From any `json:"from"`
	To   any `json:"to"`
}

// Finding is something the operator should know that the plan does not change.
type Finding struct {
	Container string `json:"container"`
	Rule      string `json:"rule"`
	Severity  string `json:"severity"` // info | warning
	Message   string `json:"message"`
}

// Fields a Change can set. Phase 5 builds apply configurations from these.
const (
	FieldSeccomp          = "pod.securityContext.seccompProfile.type"
	FieldAllowPrivEsc     = "container.securityContext.allowPrivilegeEscalation"
	FieldCPURequest       = "container.resources.requests.cpu"
	FieldMemoryRequest    = "container.resources.requests.memory"
	FieldMemoryLimit      = "container.resources.limits.memory"
	FieldRunAsNonRoot     = "container.securityContext.runAsNonRoot"
	FieldCapabilitiesDrop = "container.securityContext.capabilities.drop"
	FieldReadOnlyRootFS   = "container.securityContext.readOnlyRootFilesystem"
)
