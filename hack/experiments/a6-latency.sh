#!/usr/bin/env bash
# A6: time from `kubectl apply` of the golden policies until gateway -> dashboard pod IP is
# blocked, over 5 runs. Measured from the host, so each sample is an upper bound with
# roughly one probe interval (kubectl exec + 1s connect timeout) of resolution.
set -euo pipefail
cd "$(dirname "$0")"
K=(kubectl --context kind-sre-tool)
DEADLINE=60 # seconds; a run that exceeds it fails instead of hanging

gw=$("${K[@]}" -n tenant-a get pod -l app=gateway -o jsonpath='{.items[0].metadata.name}')
db_ip=$("${K[@]}" -n tenant-b get pod -l app=dashboard -o jsonpath='{.items[0].status.podIP}')
now() { python3 -c 'import time; print(f"{time.time():.2f}")'; }
reachable() { "${K[@]}" -n tenant-a exec "$gw" -- /agnhost connect "$db_ip:8080" --timeout=1s >/dev/null 2>&1; }
# wait_until <want: 0=reachable 1=blocked>
wait_until() {
  local end=$((SECONDS + DEADLINE))
  while :; do
    if reachable; then [ "$1" = 0 ] && return 0; else [ "$1" = 1 ] && return 0; fi
    [ "$SECONDS" -lt "$end" ] || { echo "deadline of ${DEADLINE}s exceeded" >&2; exit 1; }
  done
}
trap '"${K[@]}" delete -f a2-golden-policies.yaml --ignore-not-found >/dev/null' EXIT

for run in 1 2 3 4 5; do
  wait_until 0 # start each run from an open path
  t0=$(now)
  "${K[@]}" apply -f a2-golden-policies.yaml >/dev/null
  wait_until 1
  t1=$(now)
  echo "run $run: blocked after $(python3 -c "print(f'{$t1 - $t0:.2f}')")s"
  "${K[@]}" delete -f a2-golden-policies.yaml >/dev/null
done
