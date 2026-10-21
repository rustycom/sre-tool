#!/usr/bin/env bash
# Create the kind cluster and install Cilium. Idempotent: an existing cluster is reused.
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

KIND_VERSION="v0.32.0" # the node image digest in kind-config.yaml is built for it

kind version | grep -q "kind ${KIND_VERSION} " ||
  echo "warning: kind ${KIND_VERSION} is pinned; local is: $(kind version)" >&2

mkdir -p "$(dirname "${KUBECONFIG_FILE}")"
# --kubeconfig: kind writes its credentials and its current-context only to our own file,
# never to the user's kubeconfig.
if kind get clusters | grep -qx "${CLUSTER}"; then
  echo "kind cluster ${CLUSTER} already exists; reusing it"
  kind export kubeconfig --name "${CLUSTER}" --kubeconfig "${KUBECONFIG_FILE}"
else
  kind create cluster --name "${CLUSTER}" --config hack/kind-config.yaml --kubeconfig "${KUBECONFIG_FILE}"
fi

hack/install-cilium.sh
"${KUBECTL[@]}" get nodes -o wide
