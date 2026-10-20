#!/usr/bin/env bash
# Probe matrix for A2 (pod traffic from B), A3 (host network -> A) and A4 (external NodePort -> A).
# Run once as a baseline, once with a2-golden-policies.yaml applied, and once with
# a2-no-except-variant.yaml applied. Needs a3-a4-host-and-nodeport.yaml and the sample workloads.
set -euo pipefail
cd "$(dirname "$0")"
K=(kubectl --context kind-sre-tool)
NGINX=nginx:1.30.6@sha256:eb1c896deef834f4e056829fd6dadac8305501f16cc71ba65fb252c8d0aa168e

# pod <namespace> <label selector> <node>: first pod matching on that node.
pod() { "${K[@]}" -n "$1" get pod -l "$2" --field-selector "spec.nodeName=$3" -o jsonpath='{.items[0].metadata.name}'; }
ip() { "${K[@]}" -n "$1" get pod "$2" -o jsonpath='{.status.podIP}'; }
row() { printf '%-4s %-58s %s\n' "$1" "$2" "$3"; }

gw=$(pod tenant-a app=gateway sre-tool-worker2); gw_ip=$(ip tenant-a "$gw")
db_same=$(pod tenant-b app=dashboard sre-tool-worker2)
db_cross=$(pod tenant-b app=dashboard sre-tool-worker)
c=$("${K[@]}" -n tenant-c get pod -l app=client -o jsonpath='{.items[0].metadata.name}')
a_other=$("${K[@]}" -n tenant-a get pod -l app=other -o jsonpath='{.items[0].metadata.name}')
b_other=$("${K[@]}" -n tenant-b get pod -l app=other -o jsonpath='{.items[0].metadata.name}')
worker2_ip=$("${K[@]}" get node sre-tool-worker2 -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')

echo "target gateway pod $gw ($gw_ip) on sre-tool-worker2"
row A2 "tenant-a/gateway -> dashboard.tenant-b svc" "$(./probe.sh tenant-a "$gw" dashboard.tenant-b:8080)"
row A2 "tenant-b/dashboard -> gateway.tenant-a svc" "$(./probe.sh tenant-b "$db_same" gateway.tenant-a:8080)"
row A2 "tenant-b/dashboard (same node) -> gateway pod IP" "$(./probe.sh tenant-b "$db_same" "$gw_ip:8080")"
row A2 "tenant-b/dashboard (other node) -> gateway pod IP" "$(./probe.sh tenant-b "$db_cross" "$gw_ip:8080")"
row ctl "tenant-c/client -> gateway pod IP" "$(./probe.sh tenant-c "$c" "$gw_ip:8080")"
row ctl "tenant-b/other -> gateway pod IP" "$(./probe.sh tenant-b "$b_other" "$gw_ip:8080")"
row ctl "tenant-a/other -> gateway pod IP (same namespace)" "$(./probe.sh tenant-a "$a_other" "$gw_ip:8080")"
for node in sre-tool-worker2 sre-tool-worker sre-tool-control-plane; do
  h=$(pod np-experiments app=hostnet "$node")
  row A3 "hostNetwork pod on $node -> gateway pod IP" "$(./probe.sh np-experiments "$h" "$gw_ip:8080")"
done
ready=$("${K[@]}" -n tenant-a get pod "$gw" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
restarts=$("${K[@]}" -n tenant-a get pod "$gw" -o jsonpath='{.status.containerStatuses[0].restartCount}')
row A3 "kubelet readiness probe on gateway (Ready, restarts)" "$ready, $restarts"
# A4: a container on the kind docker network but outside the cluster, i.e. a truly external client.
ext() { docker run --rm --network kind "$NGINX" curl -s -o /dev/null -m 3 -w '%{http_code}' "$1" 2>/dev/null || true; }
nodeport() { [ "$1" = 200 ] && echo "ok (HTTP 200)" || echo "blocked (curl: ${1:-none})"; }
row A4 "external -> NodePort on worker2 (gateway pod local)" "$(nodeport "$(ext "$worker2_ip:30080/healthz")")"
for node in sre-tool-worker sre-tool-control-plane; do
  nip=$("${K[@]}" get node "$node" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
  row A4 "external -> NodePort on $node (5 tries, either gateway)" "$(for _ in 1 2 3 4 5; do nodeport "$(ext "$nip:30080/healthz")"; done | sort | uniq -c | xargs)"
done
