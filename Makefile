# Every kubectl/helm call goes through KUBECTL/HELM, which pin the kind context.
# Never call kubectl without --context: the author's machine has real clusters.
# The kubeconfig is the repo's own file (gitignored), so kind never touches ~/.kube/config.
CLUSTER ?= sre-tool
KCTX    := kind-$(CLUSTER)
KUBECONFIG_FILE ?= $(CURDIR)/.kube/kind-sre-tool.kubeconfig
KUBECTL := kubectl --kubeconfig $(KUBECONFIG_FILE) --context $(KCTX)
HELM    := helm --kubeconfig $(KUBECONFIG_FILE) --kube-context $(KCTX)
export CLUSTER KCTX KUBECONFIG_FILE

VERSION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
# Pinned tools live in ./bin (gitignored), so local runs and CI use the same binaries.
GOLANGCI_LINT_VERSION := 2.14.0
GOVULNCHECK_VERSION   := 1.8.0
GOLANGCI_LINT := $(CURDIR)/bin/golangci-lint
GOVULNCHECK   := $(CURDIR)/bin/govulncheck

WORKLOAD_NAMESPACES := tenant-a tenant-b tenant-c hardening-demo hardening-lr

.DEFAULT_GOAL := help
.PHONY: help build test tools lint verify cluster-up cluster-down workloads \
	image kind-load deploy undeploy port-forward run-local \
	e2e e2e-isolation e2e-hardening e2e-rbac ci demo

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

build: ## Build bin/sre-tool
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/sre-tool ./cmd/sre-tool

test: ## Unit tests
	go test ./...

tools: $(GOLANGCI_LINT) $(GOVULNCHECK) ## Install the pinned golangci-lint and govulncheck into ./bin

$(GOLANGCI_LINT):
	GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_LINT_VERSION)
$(GOVULNCHECK):
	GOBIN=$(CURDIR)/bin go install golang.org/x/vuln/cmd/govulncheck@v$(GOVULNCHECK_VERSION)

lint: $(GOLANGCI_LINT) ## golangci-lint, the pinned ./bin copy (same binary as CI)
	@$(GOLANGCI_LINT) --version | grep -q "version $(GOLANGCI_LINT_VERSION) " || \
		{ echo "$(GOLANGCI_LINT) is not $(GOLANGCI_LINT_VERSION); rm it and run make tools"; exit 1; }
	$(GOLANGCI_LINT) run ./...

verify: ## gofmt check, go vet, golangci-lint, go test -race
	@test -z "$$(gofmt -l $$(git ls-files --cached --others --exclude-standard '*.go'))" || \
		{ echo "gofmt needed on:"; gofmt -l $$(git ls-files --cached --others --exclude-standard '*.go'); exit 1; }
	go vet ./...
	$(MAKE) --no-print-directory lint
	go test -race ./...

cluster-up: ## Create the kind cluster with Cilium
	hack/up.sh

cluster-down: ## Delete the kind cluster
	hack/down.sh

workloads: ## Apply the sample workloads and wait until they are ready
	$(KUBECTL) apply -f examples/workloads/
	@for ns in $(WORKLOAD_NAMESPACES); do \
		ws=$$($(KUBECTL) -n $$ns get deploy,statefulset,daemonset -o name) || exit 1; \
		for w in $$ws; do \
			$(KUBECTL) -n $$ns rollout status $$w --timeout=180s || exit 1; \
		done; \
	done
	$(KUBECTL) -n hardening-demo wait --for=condition=Complete job/once --timeout=120s
	$(KUBECTL) -n hardening-demo wait --for=condition=Ready pod/bare-pod --timeout=120s

# Implemented in later phases; failing loudly beats silently doing nothing.
image kind-load deploy undeploy port-forward e2e-isolation e2e-rbac: ## (Phase 3)
	@echo "$@: not implemented yet (Phase 3)"; exit 1
run-local: ## Run the tool on this machine against the kind cluster (API on 127.0.0.1:8080)
	go run ./cmd/sre-tool --kubeconfig $(KUBECONFIG_FILE) --kube-context $(KCTX)
e2e-hardening: ## (Phase 5)
	@echo "$@: not implemented yet (Phase 5)"; exit 1
e2e: e2e-isolation e2e-hardening e2e-rbac ## All e2e scripts
ci: ## (Phase 6)
	@echo "$@: not implemented yet (Phase 6)"; exit 1
demo: ## (Phase 8)
	@echo "$@: not implemented yet (Phase 8)"; exit 1
