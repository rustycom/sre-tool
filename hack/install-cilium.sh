#!/usr/bin/env bash
# Install Cilium from the pinned Helm chart and wait for it and the nodes to be ready.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

CILIUM_VERSION="1.20.2" # docs/VERSIONS.md

"${KUBECTL[@]}" cluster-info >/dev/null || { echo "context ${KCTX} is not reachable" >&2; exit 1; }

"${HELM[@]}" repo add cilium https://helm.cilium.io/ --force-update >/dev/null
# ipam.mode=kubernetes: pod IPs come from each node's podCIDR inside 10.244.0.0/16,
# which is what the isolation ipBlock except list assumes (SPEC §6.5, §11).
"${HELM[@]}" upgrade --install cilium cilium/cilium \
  --version "${CILIUM_VERSION}" \
  --namespace kube-system \
  --set ipam.mode=kubernetes \
  --set operator.replicas=1 \
  --wait --timeout 10m

"${KUBECTL[@]}" -n kube-system rollout status daemonset/cilium --timeout=5m
"${KUBECTL[@]}" -n kube-system rollout status deployment/cilium-operator --timeout=5m
"${KUBECTL[@]}" wait --for=condition=Ready nodes --all --timeout=5m
