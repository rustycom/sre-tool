# Every kubectl/helm call goes through KUBECTL/HELM, which pin the kind context.
# Never call kubectl without --context: the author's machine has real clusters.
# The kubeconfig is the repo's own file (gitignored), so kind never touches ~/.kube/config.
CLUSTER ?= sre-tool
KCTX    := kind-$(CLUSTER)
KUBECONFIG_FILE ?= $(CURDIR)/.kube/kind-sre-tool.kubeconfig
KUBECTL := kubectl --kubeconfig $(KUBECONFIG_FILE) --context $(KCTX)
HELM    := helm --kubeconfig $(KUBECONFIG_FILE) --kube-context $(KCTX)
export CLUSTER KCTX KUBECONFIG_FILE

# --dirty: a rebuild after an uncommitted edit gets a new tag, so deploy rolls it out.
VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
IMAGE   ?= sre-tool:$(VERSION)
# Pinned tools live in ./bin (gitignored), so local runs and CI use the same binaries.
GOLANGCI_LINT_VERSION := 2.14.0
GOVULNCHECK_VERSION   := 1.8.0
ACTIONLINT_VERSION    := 1.7.12
GOLANGCI_LINT := $(CURDIR)/bin/golangci-lint
GOVULNCHECK   := $(CURDIR)/bin/govulncheck
ACTIONLINT    := $(CURDIR)/bin/actionlint

WORKLOAD_NAMESPACES := tenant-a tenant-b tenant-c hardening-demo hardening-lr

.DEFAULT_GOAL := help
.PHONY: help build test tools lint verify vuln cluster-up cluster-down workloads \
	image kind-load deploy undeploy port-forward port-forward-ops run-local \
	e2e e2e-isolation e2e-hardening e2e-rbac ci demo

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

build: ## Build bin/sre-tool
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/sre-tool ./cmd/sre-tool

test: ## Unit tests
	go test ./...

tools: $(GOLANGCI_LINT) $(GOVULNCHECK) $(ACTIONLINT) ## Install the pinned golangci-lint, govulncheck and actionlint into ./bin

$(GOLANGCI_LINT):
	GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_LINT_VERSION)
$(GOVULNCHECK):
	GOBIN=$(CURDIR)/bin go install golang.org/x/vuln/cmd/govulncheck@v$(GOVULNCHECK_VERSION)
$(ACTIONLINT):
	GOBIN=$(CURDIR)/bin go install github.com/rhysd/actionlint/cmd/actionlint@v$(ACTIONLINT_VERSION)

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

vuln: $(GOVULNCHECK) ## govulncheck: known vulnerabilities in code paths we actually call
	$(GOVULNCHECK) ./...

# The CI verify job runs exactly this target, so a green `make ci` here is a green job there.
ci: verify vuln $(ACTIONLINT) ## Everything the CI verify job runs, plus actionlint on the workflow
	$(ACTIONLINT)

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

image: ## Build the container image sre-tool:<git sha>
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

kind-load: ## Load the image into the kind cluster
	kind load docker-image $(IMAGE) --name $(CLUSTER)

# The manifests name sre-tool:dev; one apply with the real tag avoids a second rollout.
deploy: ## Deploy the tool (image sre-tool:<git sha>) and wait until it is Available
	$(KUBECTL) kustomize deploy/ | sed 's|image: sre-tool:dev|image: $(IMAGE)|' | $(KUBECTL) apply -f -
	$(KUBECTL) -n sre-tool rollout status deploy/sre-tool --timeout=120s

undeploy: ## Remove the tool (isolation policies stay in their namespaces)
	$(KUBECTL) delete -k deploy/ --ignore-not-found

port-forward: ## Expose the tool's API on localhost:8080
	$(KUBECTL) -n sre-tool port-forward deploy/sre-tool 8080:8080

port-forward-ops: ## Expose the tool's health and metrics port on localhost:8081
	$(KUBECTL) -n sre-tool port-forward deploy/sre-tool 8081:8081

e2e-isolation: ## Isolation connectivity matrix against kind (needs deploy)
	hack/verify-isolation.sh

e2e-hardening: ## Hardening plan/apply, idempotency, stale plan, strict-failure demo and undo (needs deploy)
	hack/verify-hardening.sh

e2e-rbac: ## Check what the tool's ServiceAccount may and may not do
	hack/verify-rbac.sh

run-local: ## Run the tool on this machine against the kind cluster (API on 127.0.0.1:8080)
	go run ./cmd/sre-tool --kubeconfig $(KUBECONFIG_FILE) --kube-context $(KCTX)
e2e: e2e-isolation e2e-hardening e2e-rbac ## All e2e scripts
demo: cluster-up workloads image kind-load deploy e2e ## From nothing to a verified demo: cluster, workloads, tool, every e2e
