#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh
kind delete cluster --name "${CLUSTER}" --kubeconfig "${KUBECONFIG_FILE}"
