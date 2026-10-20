#!/usr/bin/env bash
# Hardening e2e (TESTING §3.2): plan, apply, idempotency, stale plan and the strict-failure
# demo against the real API server, where dry-run, SSA and rollouts actually happen.
# Needs: make cluster-up image kind-load deploy. It recreates the two demo namespaces
# first, because a previous run leaves them hardened and plan would then find nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/lib.sh

PF_PORT="${PF_PORT:-18081}"
DEMO=hardening-demo
LR=hardening-lr
BODY='{"namespaces":["hardening-demo","hardening-lr"]}'
TMP=$(mktemp -d)
PF_PID=""

cleanup() {
  local rc=$?
  set +e
  [[ -z $PF_PID ]] || kill "$PF_PID" 2>/dev/null
  wait "$PF_PID" 2>/dev/null
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT

# post <path> <json>: prints the HTTP status; the body lands in $TMP/body. Apply is
# synchronous and may take minutes (--apply-budget 12m), hence the long max-time.
post() {
  curl -s --max-time 900 -o "$TMP/body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    --data-binary "$2" "http://127.0.0.1:${PF_PORT}$1"
}
expect_status() { # <want> <got> <what>
  [[ $2 == "$1" ]] || die "$3: want HTTP $1, got $2: $(head -c 2000 "$TMP/body")"
  echo "  $3 -> $2"
}
# check <description> <jq expression that must be true on $TMP/body>. The jq helpers:
# w(name) is that workload in a plan; r(name) its result in an apply.
check() {
  # shellcheck disable=SC2016 # jq variables, not shell ones
  local defs='def w($n): first(.workloads[] | select(.name == $n));
              def r($n): first(.results[] | select(.name == $n));
              def fields($n): [w($n).changes[] | .field];
              def rules($n): [w($n).findings[] | .rule];'
  jq -e "$defs $2" "$TMP/body" >/dev/null || die "$1 (jq: $2) on: $(head -c 3000 "$TMP/body")"
  echo "  ok: $1"
}
# jp <kind/name> <jsonpath> [namespace]: one field of a live object.
jp() { "${KUBECTL[@]}" -n "${3:-$DEMO}" get "$1" -o jsonpath="$2"; }
expect_field() { # <kind/name> <jsonpath> <want> [namespace]
  local got
  got=$(jp "$1" "$2" "${4:-$DEMO}")
  [[ $got == "$3" ]] || die "$1 $2: want '$3', got '$got'"
  echo "  ok: $1 $2 = '${3}'"
}
rollouts() { # every Deployment, StatefulSet and DaemonSet in the demo namespaces is healthy
  local ns w
  for ns in $DEMO $LR; do
    for w in $("${KUBECTL[@]}" -n "$ns" get deploy,statefulset,daemonset -o name); do
      "${KUBECTL[@]}" -n "$ns" rollout status "$w" --timeout=180s >/dev/null || die "$ns/$w is not healthy"
    done
  done
}
# state: generation of every workload plus the ReplicaSet count of every Deployment. A
# rollout bumps the first and adds to the second, so equal state means no rollout.
state() {
  local ns
  for ns in $DEMO $LR; do
    "${KUBECTL[@]}" -n "$ns" get deploy,statefulset,daemonset,cronjob -o json |
      jq -r --arg ns "$ns" '.items[] | "\($ns)/\(.kind)/\(.metadata.name) generation=\(.metadata.generation)"'
    "${KUBECTL[@]}" -n "$ns" get rs -o json |
      jq -r --arg ns "$ns" '[.items[] | .metadata.ownerReferences[0].name] | group_by(.) | .[] | "\($ns)/ReplicaSets/\(.[0]) count=\(length)"'
  done | sort
}

echo "Stage 0: guards and fresh demo workloads"
require_context
"${KUBECTL[@]}" -n sre-tool wait --for=condition=Available deploy/sre-tool --timeout=60s >/dev/null ||
  die "deploy/sre-tool is not Available (make image kind-load deploy?)"
"${KUBECTL[@]}" delete namespace $DEMO $LR --ignore-not-found --timeout=180s >/dev/null
"${KUBECTL[@]}" apply -f examples/workloads/hardening-demo.yaml -f examples/workloads/hardening-lr.yaml >/dev/null
rollouts
"${KUBECTL[@]}" -n $DEMO wait --for=condition=Complete job/once --timeout=120s >/dev/null
"${KUBECTL[@]}" -n $DEMO wait --for=condition=Ready pod/bare-pod --timeout=120s >/dev/null
echo "  $DEMO and $LR recreated and ready"
"${KUBECTL[@]}" -n sre-tool port-forward deploy/sre-tool "${PF_PORT}:8080" >"$TMP/pf.log" 2>&1 &
PF_PID=$!
poll_until 20 curl -sf -o /dev/null "http://127.0.0.1:${PF_PORT}/v1/isolations" ||
  die "port-forward to the tool did not come up: $(cat "$TMP/pf.log")"

echo "Stage 1: plan"
expect_status 200 "$(post /v1/hardening/plan "$BODY")" "plan $DEMO $LR"
check "summary is SPEC §7.4 plus lr-app" '.summary == {"patch": 9, "none": 1, "report": 2, "skip": 1}'
check "actions per workload" '[.workloads[] | "\(.name)=\(.action)"] | sort == ([
  "safe-app=patch", "root-nginx=patch", "privileged-app=patch", "limits-only=patch", "already-hardened=none",
  "skipped-app=skip", "hpa-app=patch", "stateful-app=patch", "node-agent=patch", "nightly=patch",
  "once=report", "bare-pod=report", "lr-app=patch"] | sort)'
check "every patch passed the server-side dry-run" '[.workloads[] | select(.action == "patch") | .dryRun] | all(. == "ok")'
check "safe-app gets S1, S2, R1-R3" 'fields("safe-app") | sort == ([
  "pod.securityContext.seccompProfile.type", "container.securityContext.allowPrivilegeEscalation",
  "container.resources.requests.cpu", "container.resources.requests.memory", "container.resources.limits.memory"] | sort)'
check "root-nginx: strict fields reported, not set" '(rules("root-nginx") | contains(["X1", "X2", "X3"]))
  and (fields("root-nginx") | index("container.securityContext.runAsNonRoot") == null)'
check "privileged-app: S2 skipped with a finding" '(fields("privileged-app") | index("container.securityContext.allowPrivilegeEscalation") == null)
  and (rules("privileged-app") | contains(["S2", "PRIV"]))'
check "limits-only: R1 only, memory left to the 64Mi limit" '(fields("limits-only") | index("container.resources.requests.cpu") != null)
  and (fields("limits-only") | map(select(test("memory"))) == []) and (rules("limits-only") | index("R2") != null)'
check "hpa-app: HPA warning" 'rules("hpa-app") | index("HPA") != null'
check "nightly: future Jobs only" 'w("nightly").rolloutImpact | test("future Jobs")'
check "lr-app: memory covered by the LimitRange" '(fields("lr-app") | map(select(test("memory"))) == [])
  and ([w("lr-app").findings[] | select(.rule == "R2") | .message] | any(test("LimitRange")))'
check "bare-pod reported as immutable" 'w("bare-pod").reason | test("immutable")'
PLAN_HASH=$(jq -r .planHash "$TMP/body")

echo "Stage 2: apply"
start=$SECONDS
expect_status 200 "$(post /v1/hardening/apply "{\"namespaces\":[\"$DEMO\",\"$LR\"],\"planHash\":\"$PLAN_HASH\"}")" "apply $PLAN_HASH"
check "outcome complete" '.outcome == "complete"'
check "9 applied, the rest skipped" '([.results[] | select(.status == "applied")] | length) == 9
  and ([.results[] | select(.status != "applied")] | all(.status == "skipped"))'
jq -r '.results[] | "    \(.namespace)/\(.kind)/\(.name): \(.status) \(.rolloutSeconds | floor)s"' "$TMP/body"
echo "  apply took $((SECONDS - start))s"
rollouts
echo "  every rollout healthy"
expect_field deploy/safe-app '{.spec.template.spec.securityContext.seccompProfile.type}' RuntimeDefault
expect_field deploy/safe-app '{.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation}' false
expect_field deploy/safe-app '{.spec.template.spec.containers[0].resources.requests.cpu}' 100m
expect_field deploy/safe-app '{.spec.template.spec.containers[0].resources.requests.memory}' 128Mi
expect_field deploy/safe-app '{.spec.template.spec.containers[0].resources.limits.memory}' 512Mi
expect_field deploy/safe-app '{.metadata.managedFields[?(@.manager=="sre-tool")].operation}' Apply
expect_field deploy/privileged-app '{.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation}' ""
expect_field deploy/privileged-app '{.spec.template.spec.securityContext.seccompProfile.type}' RuntimeDefault
expect_field deploy/limits-only '{.spec.template.spec.containers[0].resources.requests.memory}' ""
expect_field deploy/limits-only '{.spec.template.spec.containers[0].resources.limits.memory}' 64Mi
expect_field deploy/limits-only '{.spec.template.spec.containers[0].resources.requests.cpu}' 100m
expect_field statefulset/stateful-app '{.spec.template.spec.securityContext.seccompProfile.type}' RuntimeDefault
expect_field daemonset/node-agent '{.spec.template.spec.securityContext.seccompProfile.type}' RuntimeDefault
expect_field cronjob/nightly '{.spec.jobTemplate.spec.template.spec.securityContext.seccompProfile.type}' RuntimeDefault
expect_field deploy/lr-app '{.spec.template.spec.containers[0].resources.requests.cpu}' 100m $LR
expect_field deploy/lr-app '{.spec.template.spec.containers[0].resources.requests.memory}' "" $LR
expect_field deploy/skipped-app '{.spec.template.spec.securityContext.seccompProfile}' ""
applied_event() {
  "${KUBECTL[@]}" -n $DEMO get events.events.k8s.io -o json |
    jq -e '.items[] | select(.reason == "HardeningApplied" and .regarding.name == "safe-app" and .reportingController == "sre-tool")' >/dev/null
}
poll_until 30 applied_event || die "no HardeningApplied event on $DEMO/safe-app"
echo "  ok: Event HardeningApplied on deploy/safe-app"

echo "Stage 3: idempotency"
before=$(state)
expect_status 200 "$(post /v1/hardening/plan "$BODY")" "re-plan"
check "zero patch actions" '.summary.patch == 0'
SECOND_HASH=$(jq -r .planHash "$TMP/body")
expect_status 200 "$(post /v1/hardening/apply "{\"namespaces\":[\"$DEMO\",\"$LR\"],\"planHash\":\"$SECOND_HASH\"}")" "apply again"
check "second apply complete and applied nothing" '.outcome == "complete" and ([.results[] | select(.status == "applied")] | length) == 0'
after=$(state)
[[ $after == "$before" ]] || die "second apply changed generations or ReplicaSets: $(diff <(echo "$before") <(echo "$after"))"
echo "  generations and ReplicaSet counts unchanged ($(wc -l <<<"$after" | tr -d ' ') values)"

echo "Stage 4: stale plan"
expect_status 200 "$(post /v1/hardening/plan "$BODY")" "plan"
OLD_HASH=$(jq -r .planHash "$TMP/body")
"${KUBECTL[@]}" -n $DEMO set env deploy/safe-app E2E_STALE=1 >/dev/null
expect_status 409 "$(post /v1/hardening/apply "{\"namespaces\":[\"$DEMO\",\"$LR\"],\"planHash\":\"$OLD_HASH\"}")" "apply the old hash after kubectl set env"
check "stale_plan with the current hash" '.error.code == "stale_plan" and (.error.details.currentPlanHash | startswith("sha256:"))'
"${KUBECTL[@]}" -n $DEMO rollout status deploy/safe-app --timeout=180s >/dev/null

echo "Stage 5: strict failure demo"
"${KUBECTL[@]}" -n $DEMO annotate deploy/root-nginx sre-tool.io/harden-profile=strict --overwrite >/dev/null
expect_status 200 "$(post /v1/hardening/plan "$BODY")" "plan with root-nginx strict"
check "only root-nginx patches, with runAsNonRoot" '.summary.patch == 1
  and (fields("root-nginx") | index("container.securityContext.runAsNonRoot") != null)'
STRICT_HASH=$(jq -r .planHash "$TMP/body")
start=$SECONDS
expect_status 200 "$(post /v1/hardening/apply "{\"namespaces\":[\"$DEMO\",\"$LR\"],\"planHash\":\"$STRICT_HASH\"}")" "apply strict"
check "outcome halted at root-nginx" '.outcome == "halted" and .reason == "rollout_failed" and r("root-nginx").status == "failed"'
check "the reason names non-root or CreateContainerConfigError" 'r("root-nginx").message | test("non-root|runAsNonRoot|CreateContainerConfigError")'
echo "  gate failed after $((SECONDS - start))s: $(jq -r '.results[] | select(.name == "root-nginx") | .message' "$TMP/body")"
echo "  remedy: $(jq -r .remedy "$TMP/body")"
# The old ReplicaSet's pods keep serving: with 2 replicas, maxUnavailable rounds down to 0 (I-20).
expect_field deploy/root-nginx '{.status.availableReplicas}' 2
got=$(probe_result $DEMO app=safe-app root-nginx.$DEMO:80)
[[ $got == ok ]] || die "root-nginx Service does not answer during the failed rollout: $got"
echo "  ok: Service root-nginx answers from the old pods"
"${KUBECTL[@]}" -n $DEMO rollout undo deploy/root-nginx >/dev/null
"${KUBECTL[@]}" -n $DEMO rollout status deploy/root-nginx --timeout=180s >/dev/null
"${KUBECTL[@]}" -n $DEMO annotate deploy/root-nginx sre-tool.io/harden-profile- >/dev/null
expect_status 200 "$(post /v1/hardening/plan "$BODY")" "plan after rollout undo"
check "back to zero patch actions" '.summary.patch == 0'

echo "PASS: hardening e2e"
