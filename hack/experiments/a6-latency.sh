#!/usr/bin/env bash
# A6: time from `kubectl apply` of the golden policies until gateway -> dashboard pod IP is
# blocked, over 5 runs. Measured from the host, so each sample is an upper bound with
# roughly one probe interval (kubectl exec + 1s connect timeout) of resolution.
set -euo pipefail
cd "$(dirname "$0")"
K=(kubectl --context kind-sre-tool)

gw=$("${K[@]}" -n tenant-a get pod -l app=gateway -o jsonpath='{.items[0].metadata.name}')
db_ip=$("${K[@]}" -n tenant-b get pod -l app=dashboard -o jsonpath='{.items[0].status.podIP}')
now() { python3 -c 'import time; print(f"{time.time():.2f}")'; }
reachable() { "${K[@]}" -n tenant-a exec "$gw" -- /agnhost connect "$db_ip:8080" --timeout=1s >/dev/null 2>&1; }

for run in 1 2 3 4 5; do
  until reachable; do sleep 1; done # baseline: start each run from an open path
  t0=$(now)
  "${K[@]}" apply -f a2-golden-policies.yaml >/dev/null
  while reachable; do :; done
  t1=$(now)
  echo "run $run: blocked after $(python3 -c "print(f'{$t1 - $t0:.2f}')")s"
  "${K[@]}" delete -f a2-golden-policies.yaml >/dev/null
done
