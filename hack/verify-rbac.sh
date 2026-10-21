#!/usr/bin/env bash
# RBAC e2e: the tool's ServiceAccount can do exactly what deploy/clusterrole.yaml grants,
# and the dangerous neighbours are denied. --all-namespaces asks about every namespace at
# once, which is what a ClusterRoleBinding grants.
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

SA=system:serviceaccount:sre-tool:sre-tool
MISMATCHES=0

# check <yes|no> <verb> <resource[.group][/subresource]> [who…]: who defaults to the tool's
# ServiceAccount in every namespace. A subresource must go through --subresource: can-i
# reads "pods/exec" as the pod named "exec". stderr is kept, so a warning such as an
# unknown resource type makes the answer differ from a bare yes/no and fails the check.
check() {
  local want=$1 verb=$2 res=${3%%/*} got
  local args=("$verb" "$res")
  [[ $3 != */* ]] || args+=(--subresource="${3#*/}")
  shift 3
  if (($#)); then args+=("$@"); else args+=(--all-namespaces --as="$SA"); fi
  got=$("${KUBECTL[@]}" auth can-i "${args[@]}" 2>&1 || true)
  if [[ $got == "$want" ]]; then
    printf '  %-4s %s\n' "$got" "${args[*]}"
  else
    printf '  %-4s %s <- want %s\n' "$got" "${args[*]}" "$want"
    MISMATCHES=$((MISMATCHES + 1))
  fi
}
# allow <resource> <verbs…>
allow() { local r=$1 v; shift; for v in "$@"; do check yes "$v" "$r"; done; }

require_context
echo "Allowed:"
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
# Neighbours of what is granted, so a widened rule shows up here.
check no get configmaps
check no update pods
check no patch replicasets.apps
check no patch jobs.batch
check no create rolebindings.rbac.authorization.k8s.io

# The operator Role is the API's access boundary.
OPERATOR=(-n sre-tool --as=e2e-operator --as-group=sre-operators)
echo "Operator group sre-operators (namespace sre-tool):"
check yes create pods/portforward "${OPERATOR[@]}"
check yes get deployments.apps "${OPERATOR[@]}"
check no create pods/exec "${OPERATOR[@]}"
check no get secrets "${OPERATOR[@]}"

((MISMATCHES == 0)) || die "$MISMATCHES RBAC check(s) did not match"
echo "PASS: RBAC e2e"
