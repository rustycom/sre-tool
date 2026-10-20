package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestConfig_Defaults(t *testing.T) {
	c, err := Load(nil, env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.APIAddr != "127.0.0.1:8080" || c.OpsAddr != ":8081" {
		t.Errorf("addrs = %q, %q", c.APIAddr, c.OpsAddr)
	}
	if !reflect.DeepEqual(c.PodCIDRs, []string{"10.244.0.0/16"}) {
		t.Errorf("PodCIDRs = %v", c.PodCIDRs)
	}
	if c.RolloutTimeout != 3*time.Minute || c.ApplyBudget != 12*time.Minute || c.MaxNamespaces != 20 {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

func TestConfig_RejectsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		wantErr string
	}{
		{"bad CIDR", []string{"--pod-cidrs=10.244.0.0/33"}, nil, "--pod-cidrs"},
		{"non-canonical CIDR", []string{"--pod-cidrs=10.244.1.0/16"}, nil, "not canonical"},
		{"IPv6 CIDR", []string{"--pod-cidrs=fd00::/64"}, nil, "not IPv4"},
		{"zero-length CIDR", []string{"--pod-cidrs=0.0.0.0/0"}, nil, "every address"},
		{"empty CIDR list", []string{"--pod-cidrs=,"}, nil, "at least one"},
		{"bad quantity", []string{"--default-cpu-request=lots"}, nil, "--default-cpu-request"},
		{"bad quantity from env", nil, map[string]string{"SRE_TOOL_DEFAULT_MEMORY_LIMIT": "x"}, "--default-memory-limit"},
		{"request larger than limit", []string{"--default-memory-request=1Gi", "--default-memory-limit=512Mi"}, nil, "larger than"},
		{"kubeconfig without context", []string{"--kubeconfig=/tmp/kc"}, nil, "--kube-context is required"},
		{"budget below rollout timeout", []string{"--apply-budget=1m", "--rollout-timeout=3m"}, nil, "--apply-budget"},
		{"budget at write timeout", []string{"--apply-budget=15m"}, nil, "--apply-budget"},
		{"zero poll interval", []string{"--rollout-poll-interval=0s"}, nil, "positive"},
		{"bad log level", []string{"--log-level=loud"}, nil, "--log-level"},
		{"unknown flag", []string{"--nope"}, nil, "nope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(tt.args, env(tt.env))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_EnvAndFlagPrecedence(t *testing.T) {
	e := env(map[string]string{"SRE_TOOL_POD_CIDRS": "10.0.0.0/8", "SRE_TOOL_LOG_LEVEL": "debug"})
	c, err := Load([]string{"--pod-cidrs=10.96.0.0/12,10.244.0.0/16,10.96.0.0/12"}, e)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The flag wins over the env var; the list is sorted and de-duplicated.
	if want := []string{"10.244.0.0/16", "10.96.0.0/12"}; !reflect.DeepEqual(c.PodCIDRs, want) {
		t.Errorf("PodCIDRs = %v, want %v", c.PodCIDRs, want)
	}
	if c.LogLevel.String() != "DEBUG" {
		t.Errorf("LogLevel = %v, want DEBUG from env", c.LogLevel)
	}
}

func TestConfig_ProtectsOwnNamespace(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantOwn  string
		wantMiss string
	}{
		{"POD_NAMESPACE is added", map[string]string{"POD_NAMESPACE": "ops"}, "ops", "sre-tool"},
		{"sre-tool when unset", nil, "sre-tool", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Load([]string{"--protected-namespaces=kube-system"}, env(tt.env))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !c.ProtectedNamespaces[tt.wantOwn] || !c.ProtectedNamespaces["kube-system"] {
				t.Errorf("protected = %v, want %s and kube-system", c.ProtectedNamespaces, tt.wantOwn)
			}
			if tt.wantMiss != "" && c.ProtectedNamespaces[tt.wantMiss] {
				t.Errorf("protected = %v, did not want %s", c.ProtectedNamespaces, tt.wantMiss)
			}
		})
	}
}
