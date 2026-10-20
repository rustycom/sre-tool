# Sourced by every script in hack/. The one place that says which cluster, context and
# kubeconfig file the scripts may touch, so kind never writes to the user's ~/.kube/config.
# shellcheck shell=bash
HACK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="${CLUSTER:-sre-tool}"
KCTX="kind-${CLUSTER}"
KUBECONFIG_FILE="${KUBECONFIG_FILE:-${HACK_ROOT}/.kube/kind-sre-tool.kubeconfig}"
KUBECTL=(kubectl --kubeconfig "${KUBECONFIG_FILE}" --context "${KCTX}")
HELM=(helm --kubeconfig "${KUBECONFIG_FILE}" --kube-context "${KCTX}")
