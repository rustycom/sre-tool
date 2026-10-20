# Phase 0 CNI experiments

Hand-run checks for the design assumptions A1–A9 (SPEC §13.1), against the kind cluster from
`make cluster-up workloads`. They are not part of the e2e suite; they record *how* each
assumption was tested so the result can be reproduced. Every command uses `--context kind-sre-tool`.

| Assumption | Files | How |
|---|---|---|
| A1 deny-all is enforced | `a1-np-sanity.yaml`, `a1-deny-all.yaml` | apply the first, probe `client → server.np-sanity:8080`, apply the second, probe again |
| A2 B stays blocked; A3 host traffic; A4 NodePort | `a2-golden-policies.yaml`, `a2-no-except-variant.yaml`, `a3-a4-host-and-nodeport.yaml`, `a2-a4-matrix.sh` | run the matrix as a baseline, with the golden policies, and with side a swapped for the no-`except` variant |
| A3 follow-up (CR-15) | `a3-node-cidr-peer.yaml` | additive node-CIDR peer, tried with and without Cilium `policyCIDRMatchMode=nodes` |
| A5 established connection | `a5-established.yaml`, `a5-client.yaml` | start the stream, apply the golden policies, watch `kubectl logs -f a5-client`, then delete the policies |
| A6 enforcement latency | `a6-latency.sh` | 5 apply → blocked timings |
| A8 server-side dry-run Apply | `a8-dry-run/*.yaml` | `kubectl apply --server-side --dry-run=server --field-manager=sre-tool -f <file>`; `privileged-negative.yaml` must be rejected |
| A9 port-forward to 127.0.0.1 | `a9-loopback.yaml` | `kubectl port-forward pod/loopback 18080:8080` under a deny-all policy |

A7 (fake clientset fidelity) was a throwaway Go test and is intentionally not kept.
`probe.sh <ns> <pod> <host:port>` prints `ok` or `blocked` (agnhost `connect`, 3s timeout).
Clean up with `kubectl --context kind-sre-tool delete ns np-sanity np-experiments a9-portforward`
and `kubectl --context kind-sre-tool -n tenant-a delete svc gateway-nodeport`.
