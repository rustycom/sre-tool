# Sourced by every script in hack/. The one place that says which cluster, context and
# kubeconfig file the scripts may touch, so kind never writes to the user's ~/.kube/config.
# shellcheck shell=bash
HACK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="${CLUSTER:-sre-tool}"
KCTX="kind-${CLUSTER}"
KUBECONFIG_FILE="${KUBECONFIG_FILE:-${HACK_ROOT}/.kube/kind-sre-tool.kubeconfig}"
KUBECTL=(kubectl --kubeconfig "${KUBECONFIG_FILE}" --context "${KCTX}")
HELM=(helm --kubeconfig "${KUBECONFIG_FILE}" --kube-context "${KCTX}")

# --- Helpers for the e2e scripts (SPEC §13.2). ---

die() { echo "FAIL: $*" >&2; exit 1; }

# require_context: refuse to run unless the kind context in our kubeconfig answers.
require_context() {
  "${KUBECTL[@]}" get --raw /readyz >/dev/null 2>&1 ||
    die "context ${KCTX} in ${KUBECONFIG_FILE} is not reachable (make cluster-up?)"
}

# probe_result <ns> <selector|pod/NAME> <host:port|dns:NAME>: prints ok, blocked or
# "error: …". blocked means a timeout, which is what a dropping NetworkPolicy looks like;
# refused, DNS and exec failures are errors, never mistaken for enforcement (FINDINGS notes).
probe_result() {
  local pod=$2 out
  if [[ $pod != pod/* ]]; then
    pod=pod/$("${KUBECTL[@]}" -n "$1" get pod -l "$2" --field-selector status.phase=Running \
      -o jsonpath='{.items[0].metadata.name}') || { echo "error: no pod for $2"; return; }
  fi
  if [[ $3 == dns:* ]]; then
    out=$("${KUBECTL[@]}" -n "$1" exec "$pod" -- dig +short +time=3 +tries=1 "${3#dns:}" 2>&1) || true
    if grep -qE '^[0-9.]+$' <<<"$out"; then echo ok
    elif grep -q 'timed out' <<<"$out"; then echo blocked
    else echo "error: $(head -1 <<<"$out")"; fi
    return
  fi
  if out=$("${KUBECTL[@]}" -n "$1" exec "$pod" -- /agnhost connect "$3" --timeout=3s 2>&1); then
    echo ok
  elif grep -q '^TIMEOUT' <<<"$out"; then
    echo blocked
  else
    echo "error: $(head -1 <<<"$out")"
  fi
}

# probe <ns> <selector|pod/NAME> <target> <ok|blocked>: succeeds when the result matches.
probe() { [[ $(probe_result "$1" "$2" "$3") == "$4" ]]; }

# poll_until <timeout-seconds> <command…>: reruns the command every second until it succeeds.
poll_until() {
  local deadline=$((SECONDS + $1)); shift
  until "$@"; do
    ((SECONDS < deadline)) || return 1
    sleep 1
  done
}

# row <cells…>: one line of a fixed-width result table.
row() { printf '%-3s %-20s %-42s %-9s %-9s %s\n' "$@"; }
