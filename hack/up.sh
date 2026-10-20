#!/usr/bin/env bash
# Create the kind cluster and install Cilium. Idempotent: an existing cluster is reused.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER="${CLUSTER:-sre-tool}"
KCTX="kind-${CLUSTER}"
KIND_VERSION="v0.32.0" # docs/VERSIONS.md; the node image digest in kind-config.yaml is built for it

kind version | grep -q "kind ${KIND_VERSION} " ||
  echo "warning: kind ${KIND_VERSION} is pinned; local is: $(kind version)" >&2

if kind get clusters | grep -qx "${CLUSTER}"; then
  echo "kind cluster ${CLUSTER} already exists; reusing it"
else
  # Note: kind makes its new context current. Nothing here relies on that; every
  # kubectl/helm call passes --context explicitly.
  kind create cluster --name "${CLUSTER}" --config hack/kind-config.yaml
fi

CLUSTER="${CLUSTER}" hack/install-cilium.sh
kubectl --context "${KCTX}" get nodes -o wide
