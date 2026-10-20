#!/usr/bin/env bash
# Isolation e2e (TESTING §3.1): proves on a real CNI that isolation blocks exactly A<->B,
# survives pod churn and a tool restart, and that DELETE restores the baseline.
# Needs: make cluster-up workloads image kind-load deploy.
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

PF_PORT="${PF_PORT:-18080}"
POLL_TIMEOUT=30 # FINDINGS A6: worst case 1.99s, so 30s is >15x headroom
REQUEST=examples/requests/isolate-gateway-dashboard.yaml
MANAGED=app.kubernetes.io/managed-by=sre-tool
SANITY_NS=np-sanity # the namespace in hack/experiments/a1-np-sanity.yaml
TMP=$(mktemp -d)
PF_PID=""
ID=""
MISMATCHES=0
MATRIX_PRINTED=0

# The matrix: from-namespace, from-selector, target, and the expected During result.
# Before and After are always ok.
FROM_NS=(tenant-a tenant-b tenant-b tenant-c tenant-c tenant-a tenant-b tenant-a tenant-a tenant-a)
FROM_SEL=(app=gateway app=dashboard app=dashboard app=client app=client app=other app=other app=gateway app=gateway app=other)
TO=(dashboard.tenant-b:8080 gateway.tenant-a:8080 GATEWAY_POD_IP gateway.tenant-a:8080
  dashboard.tenant-b:8080 dashboard.tenant-b:8080 gateway.tenant-a:8080 client.tenant-c:8080
  dns:kubernetes.default.svc.cluster.local gateway.tenant-a:8080)
DURING=(blocked blocked blocked ok ok ok ok ok ok ok)
declare -A RESULT

start_pf() {
  "${KUBECTL[@]}" -n sre-tool port-forward deploy/sre-tool "${PF_PORT}:8080" >"$TMP/pf.log" 2>&1 &
  PF_PID=$!
  poll_until 20 curl -sf -o /dev/null "http://127.0.0.1:${PF_PORT}/v1/isolations" ||
    die "port-forward to the tool did not come up: $(cat "$TMP/pf.log")"
}
stop_pf() { [[ -z $PF_PID ]] || kill "$PF_PID" 2>/dev/null || true; wait "$PF_PID" 2>/dev/null || true; PF_PID=""; }

# api <method> <path> [yaml file]: prints the HTTP status; the body lands in $TMP/body.
api() {
  local args=(-s -o "$TMP/body" -w '%{http_code}' -X "$1" "http://127.0.0.1:${PF_PORT}$2")
  [[ $# -lt 3 ]] || args+=(-H 'Content-Type: application/yaml' --data-binary "@$3")
  curl "${args[@]}"
}
expect_status() { # <want> <got> <what>
  [[ $2 == "$1" ]] || die "$3: want HTTP $1, got $2: $(cat "$TMP/body")"
  echo "  $3 -> $2"
}

# check_matrix <Before|During|After>: probes every row and records the result.
check_matrix() {
  local i want got
  for i in "${!TO[@]}"; do
    want=ok; [[ $1 != During ]] || want=${DURING[$i]}
    got=$(probe_result "${FROM_NS[$i]}" "${FROM_SEL[$i]}" "${TO[$i]}")
    if [[ $got != "$want" ]]; then got="$got (want $want)"; MISMATCHES=$((MISMATCHES + 1)); fi
    RESULT[$1,$i]=$got
  done
  echo "  $1 matrix probed"
}

print_matrix() {
  local i
  echo
  row "#" "From" "To" "Before" "During" "After"
  for i in "${!TO[@]}"; do
    row $((i + 1)) "${FROM_NS[$i]}/${FROM_SEL[$i]#app=}" "${TO[$i]}" \
      "${RESULT[Before,$i]:--}" "${RESULT[During,$i]:--}" "${RESULT[After,$i]:--}"
  done
  echo
}

cleanup() {
  local rc=$?
  set +e
  # On an early failure, show what was probed so far.
  ((MATRIX_PRINTED || ${#RESULT[@]} == 0)) || print_matrix
  stop_pf
  "${KUBECTL[@]}" -n tenant-b scale deploy/dashboard --replicas=2 >/dev/null
  # A failed run must not leave A and B isolated for the next one.
  [[ -z $ID ]] || "${KUBECTL[@]}" delete netpol -A -l "${MANAGED},sre-tool.io/isolation-id=${ID}" --ignore-not-found >/dev/null
  "${KUBECTL[@]}" delete namespace "$SANITY_NS" --ignore-not-found --wait=false >/dev/null
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT

echo "Stage 0: guards"
require_context
"${KUBECTL[@]}" -n sre-tool wait --for=condition=Available deploy/sre-tool --timeout=60s >/dev/null ||
  die "deploy/sre-tool is not Available (make image kind-load deploy?)"
[[ -z $("${KUBECTL[@]}" get netpol -A -l "$MANAGED" -o name) ]] ||
  die "sre-tool policies already exist; delete them first so the baseline means something"
! "${KUBECTL[@]}" get namespace "$SANITY_NS" >/dev/null 2>&1 ||
  die "namespace $SANITY_NS already exists; this script owns it"
# CNI sanity: an allowed probe that a deny-all then blocks. Without this, a CNI that ignores
# NetworkPolicy would make every "ok" row pass and every "blocked" row look like a tool bug.
"${KUBECTL[@]}" apply -f hack/experiments/a1-np-sanity.yaml >/dev/null
"${KUBECTL[@]}" -n "$SANITY_NS" wait --for=condition=Ready pod --all --timeout=120s >/dev/null
poll_until "$POLL_TIMEOUT" probe "$SANITY_NS" pod/client server."$SANITY_NS":8080 ok ||
  die "CNI sanity: client cannot reach server even without a policy"
"${KUBECTL[@]}" apply -f hack/experiments/a1-deny-all.yaml >/dev/null
poll_until "$POLL_TIMEOUT" probe "$SANITY_NS" pod/client server."$SANITY_NS":8080 blocked ||
  die "CNI is not enforcing NetworkPolicy"
echo "  CNI enforces a deny-all"
"${KUBECTL[@]}" delete namespace "$SANITY_NS" --wait=false >/dev/null
preexisting_rv=$("${KUBECTL[@]}" -n tenant-c get netpol preexisting-allow-all-ingress -o jsonpath='{.metadata.resourceVersion}')
gw_ip=$("${KUBECTL[@]}" -n tenant-a get pod -l app=gateway -o jsonpath='{.items[0].status.podIP}')
TO[2]="${gw_ip}:8080"
start_pf

echo "Stage 1: baseline"
check_matrix Before

echo "Stage 2: isolate"
expect_status 201 "$(api POST /v1/isolations "$REQUEST")" "POST $REQUEST"
ID=$(jq -r .id "$TMP/body")
poll_until "$POLL_TIMEOUT" probe tenant-a app=gateway dashboard.tenant-b:8080 blocked ||
  die "row 1 not blocked within ${POLL_TIMEOUT}s"
check_matrix During

echo "Stage 3: pod churn"
old_pods=$("${KUBECTL[@]}" -n tenant-b get pod -l app=dashboard -o name)
"${KUBECTL[@]}" -n tenant-b scale deploy/dashboard --replicas=3 >/dev/null
"${KUBECTL[@]}" -n tenant-b rollout status deploy/dashboard --timeout=120s >/dev/null
new_pod=$("${KUBECTL[@]}" -n tenant-b get pod -l app=dashboard -o name | grep -vxF "$old_pods" | head -1 || true)
[[ -n $new_pod ]] || die "no new dashboard pod after scaling to 3"
# One probe, not a poll: a new B pod must never get a window to reach A.
got=$(probe_result tenant-b "$new_pod" gateway.tenant-a:8080)
[[ $got == blocked ]] || die "new pod $new_pod -> gateway.tenant-a: want blocked, got $got"
echo "  new pod $new_pod -> gateway.tenant-a: blocked"

echo "Stage 4: idempotency"
rvs() { "${KUBECTL[@]}" get netpol -A -l "$MANAGED" -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}={.metadata.resourceVersion}{"\n"}{end}' | sort; }
rv_before=$(rvs)
expect_status 200 "$(api POST /v1/isolations "$REQUEST")" "POST again"
[[ $(rvs) == "$rv_before" ]] || die "policy resourceVersions changed on the second POST"
echo "  resourceVersions unchanged: $(tr '\n' ' ' <<<"$rv_before")"

echo "Stage 5: restart"
stop_pf
"${KUBECTL[@]}" -n sre-tool rollout restart deploy/sre-tool >/dev/null
"${KUBECTL[@]}" -n sre-tool rollout status deploy/sre-tool --timeout=120s >/dev/null
start_pf
expect_status 200 "$(api GET "/v1/isolations/$ID")" "GET /v1/isolations/$ID after restart"
[[ $(jq -r .complete "$TMP/body") == true ]] || die "isolation not complete after restart: $(cat "$TMP/body")"
echo "  complete: true"

echo "Stage 6: restore"
expect_status 200 "$(api DELETE "/v1/isolations/$ID")" "DELETE /v1/isolations/$ID"
deleted=$(jq -r '.deleted | length' "$TMP/body")
[[ $deleted == 2 ]] || die "want exactly 2 deletions, got $deleted: $(cat "$TMP/body")"
echo "  deleted: $(jq -c .deleted "$TMP/body")"
ID=""
poll_until "$POLL_TIMEOUT" probe tenant-a app=gateway dashboard.tenant-b:8080 ok ||
  die "row 1 not allowed again within ${POLL_TIMEOUT}s"
check_matrix After
rv=$("${KUBECTL[@]}" -n tenant-c get netpol preexisting-allow-all-ingress -o jsonpath='{.metadata.resourceVersion}')
[[ $rv == "$preexisting_rv" ]] || die "tenant-c/preexisting-allow-all-ingress changed: rv $preexisting_rv -> $rv"
echo "  tenant-c/preexisting-allow-all-ingress untouched (rv $rv)"

print_matrix
MATRIX_PRINTED=1
((MISMATCHES == 0)) || die "$MISMATCHES matrix cell(s) did not match"
echo "PASS: isolation e2e"
