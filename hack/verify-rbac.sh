#!/usr/bin/env bash
# RBAC e2e (TESTING §3.3): the tool's ServiceAccount can do exactly what SPEC §10.2 grants,
# and the dangerous neighbours are denied. --all-namespaces asks about every namespace at
# once, which is what a ClusterRoleBinding grants.
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

SA=system:serviceaccount:sre-tool:sre-tool
MISMATCHES=0

# check <yes|no> <verb> <resource[.group]>
check() {
  local got
  got=$("${KUBECTL[@]}" auth can-i "$2" "$3" --all-namespaces --as="$SA" 2>/dev/null || true)
  if [[ $got == "$1" ]]; then
    printf '  %-4s %-8s %s\n' "$got" "$2" "$3"
  else
    printf '  %-4s %-8s %-45s <- want %s\n' "$got" "$2" "$3" "$1"
    MISMATCHES=$((MISMATCHES + 1))
  fi
}
# allow <resource> <verbs…>
allow() { local r=$1 v; shift; for v in "$@"; do check yes "$v" "$r"; done; }

require_context
echo "Allowed (SPEC §10.2):"
allow networkpolicies.networking.k8s.io get list watch create update delete
for r in deployments statefulsets daemonsets; do allow "$r.apps" get list watch patch; done
allow replicasets.apps get list
allow cronjobs.batch get list watch patch
allow jobs.batch get list
for r in pods namespaces limitranges; do allow "$r" get list watch; done
allow horizontalpodautoscalers.autoscaling get list
allow events.events.k8s.io create patch

echo "Denied:"
check no get secrets
check no create pods
check no delete deployments.apps
check no patch clusterroles.rbac.authorization.k8s.io
check no create pods/exec

((MISMATCHES == 0)) || die "$MISMATCHES RBAC check(s) did not match"
echo "PASS: RBAC e2e"
