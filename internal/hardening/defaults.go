package hardening

import (
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/rustycom/sre-tool/internal/config"
)

// Defaults are the values rules R1–R3 fill in (ADR-007). There is no CPU
// limit on purpose.
type Defaults struct {
	CPURequest    resource.Quantity
	MemoryRequest resource.Quantity
	MemoryLimit   resource.Quantity
}

// DefaultsFrom takes the defaults from validated configuration, which already
// guarantees the memory request is not above the memory limit.
func DefaultsFrom(c config.Config) Defaults {
	return Defaults{CPURequest: c.DefaultCPURequest, MemoryRequest: c.DefaultMemRequest, MemoryLimit: c.DefaultMemLimit}
}
