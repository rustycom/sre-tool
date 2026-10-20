package kube

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: kind
  cluster: {server: "https://127.0.0.1:6443"}
- name: prod
  cluster: {server: "https://prod.example.com"}
users:
- name: u
  user: {token: t}
contexts:
- name: kind-sre-tool
  context: {cluster: kind, user: u}
- name: prod
  context: {cluster: prod, user: u}
current-context: prod
`

func TestRESTConfig_ExplicitContextGuard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(testKubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		context  string
		wantHost string
		wantErr  string
	}{
		// current-context is prod; the named context must win over it.
		{"named context is used, not current", "kind-sre-tool", "https://127.0.0.1:6443", ""},
		{"missing context is refused", "kind-other", "", "not found"},
		{"empty context is refused", "", "", "required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := RESTConfig(path, tt.context)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Host != tt.wantHost {
				t.Errorf("Host = %s, want %s", cfg.Host, tt.wantHost)
			}
		})
	}
}
