// Package config parses and validates the tool's flags and environment
// variables. Invalid configuration fails startup.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

// WriteTimeout is the API server's write timeout. It is long
// because apply is synchronous; an apply budget at or above it would let the
// HTTP response time out while apply carries on.
const WriteTimeout = 15 * time.Minute

// defaultOwnNamespace is protected when POD_NAMESPACE is unset (run-local).
const defaultOwnNamespace = "sre-tool"

// Config is the validated configuration.
type Config struct {
	ShowVersion         bool
	APIAddr             string
	OpsAddr             string
	Kubeconfig          string
	KubeContext         string
	PodCIDRs            []string        // canonical, sorted, de-duplicated
	ProtectedNamespaces map[string]bool // always includes the tool's own namespace
	RolloutTimeout      time.Duration
	ApplyBudget         time.Duration
	RolloutPollInterval time.Duration
	DefaultCPURequest   resource.Quantity
	DefaultMemRequest   resource.Quantity
	DefaultMemLimit     resource.Quantity
	MaxNamespaces       int
	LogLevel            slog.Level
}

// Load parses args (without the program name) and SRE_TOOL_* environment
// variables read through getenv. A flag given on the command line wins over
// its environment variable.
func Load(args []string, getenv func(string) string) (Config, error) {
	fs := flag.NewFlagSet("sre-tool", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var c Config
	var podCIDRs, protected, cpuReq, memReq, memLim, logLevel string
	fs.BoolVar(&c.ShowVersion, "version", false, "print the version and exit")
	fs.StringVar(&c.APIAddr, "api-addr", "127.0.0.1:8080", "API listener; loopback by default, reached through kubectl port-forward")
	fs.StringVar(&c.OpsAddr, "ops-addr", ":8081", "listener for /healthz, /readyz and /metrics")
	fs.StringVar(&c.Kubeconfig, "kubeconfig", "", "kubeconfig file for out-of-cluster use; empty means in-cluster")
	fs.StringVar(&c.KubeContext, "kube-context", "", "kubeconfig context; required with --kubeconfig")
	fs.StringVar(&podCIDRs, "pod-cidrs", "10.244.0.0/16", "comma-separated pod CIDRs excluded from the external ipBlock")
	fs.StringVar(&protected, "protected-namespaces", "kube-system,kube-public,kube-node-lease,local-path-storage", "comma-separated namespaces the tool never touches")
	fs.DurationVar(&c.RolloutTimeout, "rollout-timeout", 3*time.Minute, "per-workload rollout wait during apply")
	fs.DurationVar(&c.ApplyBudget, "apply-budget", 12*time.Minute, "total time one apply may spend")
	fs.DurationVar(&c.RolloutPollInterval, "rollout-poll-interval", 2*time.Second, "rollout status poll interval")
	fs.StringVar(&cpuReq, "default-cpu-request", "100m", "hardening default CPU request")
	fs.StringVar(&memReq, "default-memory-request", "128Mi", "hardening default memory request")
	fs.StringVar(&memLim, "default-memory-limit", "512Mi", "hardening default memory limit")
	fs.IntVar(&c.MaxNamespaces, "max-namespaces", 20, "maximum namespaces per hardening request")
	fs.StringVar(&logLevel, "log-level", "info", "debug, info, warn or error")

	// Environment first, then Parse, so the command line overrides it.
	var envErr error
	fs.VisitAll(func(f *flag.Flag) {
		env := "SRE_TOOL_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v := getenv(env); v != "" {
			if err := fs.Set(f.Name, v); err != nil {
				envErr = errors.Join(envErr, fmt.Errorf("%s: %w", env, err))
			}
		}
	})
	if envErr != nil {
		return Config{}, envErr
	}
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if c.ShowVersion {
		return c, nil
	}

	var err error
	if c.Kubeconfig != "" && c.KubeContext == "" {
		return Config{}, errors.New("--kube-context is required with --kubeconfig, so the tool never acts on whatever context happens to be current")
	}
	if c.PodCIDRs, err = parseCIDRs(podCIDRs); err != nil {
		return Config{}, err
	}
	if c.DefaultCPURequest, err = resource.ParseQuantity(cpuReq); err != nil {
		return Config{}, fmt.Errorf("--default-cpu-request: %w", err)
	}
	if c.DefaultMemRequest, err = resource.ParseQuantity(memReq); err != nil {
		return Config{}, fmt.Errorf("--default-memory-request: %w", err)
	}
	if c.DefaultMemLimit, err = resource.ParseQuantity(memLim); err != nil {
		return Config{}, fmt.Errorf("--default-memory-limit: %w", err)
	}
	if c.DefaultMemRequest.Cmp(c.DefaultMemLimit) > 0 {
		return Config{}, fmt.Errorf("--default-memory-request %s is larger than --default-memory-limit %s", memReq, memLim)
	}
	if c.RolloutTimeout <= 0 || c.RolloutPollInterval <= 0 {
		return Config{}, errors.New("--rollout-timeout and --rollout-poll-interval must be positive")
	}
	if c.ApplyBudget < c.RolloutTimeout || c.ApplyBudget >= WriteTimeout {
		return Config{}, fmt.Errorf("--apply-budget %s must be at least --rollout-timeout %s and less than %s (the API write timeout)", c.ApplyBudget, c.RolloutTimeout, WriteTimeout)
	}
	if c.MaxNamespaces < 1 {
		return Config{}, errors.New("--max-namespaces must be at least 1")
	}
	if err := c.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return Config{}, fmt.Errorf("--log-level: %w", err)
	}

	c.ProtectedNamespaces = map[string]bool{}
	for _, ns := range splitList(protected) {
		c.ProtectedNamespaces[ns] = true
	}
	own := getenv("POD_NAMESPACE")
	if own == "" {
		own = defaultOwnNamespace
	}
	c.ProtectedNamespaces[own] = true
	return c, nil
}

// parseCIDRs accepts only canonical IPv4 prefixes with a non-zero length.
// They end up in an ipBlock except list, which the API server rejects when an
// entry is not inside 0.0.0.0/0 or equals it. Sorting keeps the generated
// policy byte-stable, so a reordered flag does not show up as drift.
func parseCIDRs(s string) ([]string, error) {
	var out []string
	for _, c := range splitList(s) {
		p, err := netip.ParsePrefix(c)
		switch {
		case err != nil:
			return nil, fmt.Errorf("--pod-cidrs: %w", err)
		case !p.Addr().Is4():
			return nil, fmt.Errorf("--pod-cidrs: %s is not IPv4", c)
		case p.Masked() != p:
			return nil, fmt.Errorf("--pod-cidrs: %s is not canonical, use %s", c, p.Masked())
		case p.Bits() == 0:
			return nil, fmt.Errorf("--pod-cidrs: %s would exclude every address", c)
		}
		out = append(out, p.String())
	}
	if len(out) == 0 {
		return nil, errors.New("--pod-cidrs: at least one CIDR is required")
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
