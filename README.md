# sre-tool

A single Go service that runs in a Kubernetes cluster and does two things on demand:

1. **Isolation.** Stop two workloads (namespace(s) + label selector) from exchanging any traffic, leave everything else working, and restore the previous connectivity when isolation is turned off.
2. **Hardening.** Fill in missing resource requests/limits and a hardened `securityContext` on workloads in one or more namespaces, with a **plan → apply** flow so the operator sees every change first. A bonus **undo** removes exactly what the tool set.

## 1. Overview and motivation

The scenario is an unauthenticated RCE in a tenant's web frontend, such as React2Shell (CVE-2025-55182, Next.js CVE-2025-66478). The on-call SRE wants to cut the compromised frontend off from the tenant it could pivot to in seconds, without taking either tenant offline. They also want to tighten workloads so injected code can do less, without restarting anything into a broken state. Both actions have to be safe to run in a hurry, explain themselves before they act, and be reversible.

What I used and why: plain `client-go` (typed clients, typed server-side apply configurations, the events recorder and the fake clientset), `sigs.k8s.io/yaml` so the brief's YAML request is accepted verbatim, and `prometheus/client_golang` for `/metrics`. There is no framework: the tool is a request/response API, not a controller, so controller-runtime would add a cache and a manager it never uses.

## 2. Prerequisites

| Tool | Version used | Notes |
|---|---|---|
| Go | 1.27.3 (`go.mod` minimum 1.27.0) | builder image `golang:1.27.3`, pinned by digest |
| Docker | 20.10+ | builds the image and runs kind |
| kind | v0.32.0 | node image `kindest/node:v1.36.1`, pinned by digest |
| kubectl | v1.36.1 or newer (within skew) | |
| helm | v4.2.4 | installs the Cilium chart 1.20.2 |
| jq, curl | any recent | used by the e2e scripts and the examples below |

`make tools` installs the pinned linters (golangci-lint v2.14.0, govulncheck v1.8.0, actionlint v1.7.12) into `./bin`. Every image, module and GitHub Action is pinned exactly; the images by digest.

**Your kubeconfig is never touched.** kind writes the cluster's credentials only to `.kube/kind-sre-tool.kubeconfig` in this repository (gitignored), and every `kubectl`/`helm` call in the Makefile and scripts passes both that file and `--context kind-sre-tool`.

## 3. Quick start

Create a 3-node kind cluster with Cilium, deploy the sample workloads, build and deploy the tool (about 8 minutes on a laptop):

```sh
make cluster-up workloads image kind-load deploy
```

In a **second terminal**, expose the API on `localhost:8080` and leave it running:

```sh
make port-forward
```

For the hand-run `kubectl` commands below, point this terminal at the repository's kubeconfig and always name the context (the `make` targets do this for you):

```sh
export KUBECONFIG=$PWD/.kube/kind-sre-tool.kubeconfig
kubectl --context kind-sre-tool -n sre-tool get pods
```

`make demo` runs everything from nothing to a verified result (cluster, workloads, tool, all e2e scripts). `make help` lists every target.

## 4. Using the tool

The API listens on `127.0.0.1:8080` *inside* the pod, so the only way in is `kubectl port-forward`; Kubernetes RBAC on `pods/portforward` in namespace `sre-tool` is the authorisation boundary. Errors always have the shape `{"error": {"code": "...", "message": "...", "details": {...}}}`. The sample outputs below come from the cold-start run, compacted and abbreviated with `…`.

### Isolation

Turn isolation on with the brief's example request, verbatim (YAML or JSON both work):

```sh
curl -s -X POST -H 'Content-Type: application/yaml' \
  --data-binary @examples/requests/isolate-gateway-dashboard.yaml \
  localhost:8080/v1/isolations | jq
```

```json
{
  "id": "59957de534",
  "created": ["tenant-a/sre-iso-59957de534-a", "tenant-b/sre-iso-59957de534-b"],
  "repaired": [],
  "unchanged": []
}
```

The ID is derived from the request, so posting it again is idempotent (200, nothing changes) and swapping `a` and `b` gives the same isolation. Give `name: <id>` in the request to choose the ID yourself.

List isolations, and inspect one (`complete` and `drifted` tell you whether anyone deleted or edited a policy; re-POSTing the same request repairs it):

```sh
curl -s localhost:8080/v1/isolations | jq '.isolations[] | {id, policies, complete, drifted}'
curl -s localhost:8080/v1/isolations/59957de534 | jq '{id, complete, drifted, forced, matchedPods}'
```

```json
{"id": "59957de534", "policies": ["tenant-a/sre-iso-59957de534-a", "tenant-b/sre-iso-59957de534-b"], "complete": true, "drifted": false}
{"id": "59957de534", "complete": true, "drifted": false, "forced": false, "matchedPods": {"a": 2, "b": 2}}
```

What it created, and the audit trail:

```sh
kubectl --context kind-sre-tool get netpol -A -l app.kubernetes.io/managed-by=sre-tool
kubectl --context kind-sre-tool -n tenant-a get events --field-selector reason=IsolationApplied
```

Turn it off. Only the policies carrying this isolation's ID and `managed-by=sre-tool` are deleted, each with a UID precondition:

```sh
curl -s -X DELETE localhost:8080/v1/isolations/59957de534 | jq
```

```json
{"id": "59957de534", "deleted": ["tenant-a/sre-iso-59957de534-a", "tenant-b/sre-iso-59957de534-b"]}
```

A request whose sides already have an unrelated ingress policy is refused with 409 `conflicting_policies`, because NetworkPolicies are additive and that policy would either let the other side in or be widened by ours. Adding `force: true` proceeds, records `forced`, and emits a Warning event. Try it with tenant-c, which has such a policy:

```sh
curl -s -X POST -H 'Content-Type: application/yaml' localhost:8080/v1/isolations --data-binary '
isolate:
  a: {namespace: tenant-c, selector: {app: client}}
  b: {namespace: tenant-b, selector: {app: dashboard}}' | jq '.error | {code, details}'
```

```json
{"code": "conflicting_policies", "details": {"policies": [{"policy": "tenant-c/preexisting-allow-all-ingress", "side": "b"}]}}
```

**Break-glass** (the tool is down and you need traffic back now): `kubectl --context kind-sre-tool delete netpol -A -l sre-tool.io/isolation-id=<id>`.

### Hardening

Plan (changes nothing; every `patch` is checked with a server-side dry-run of the exact apply):

```sh
curl -s -X POST -d @examples/requests/harden-plan.json localhost:8080/v1/hardening/plan > plan.json
jq '{planHash, summary}' plan.json
jq -r '.workloads[] | [.action, .kind, .namespace + "/" + .name, (.rolloutImpact // .reason // "")] | @tsv' plan.json
jq '.workloads[] | select(.name == "safe-app") | {changes, findings}' plan.json
```

```text
{"planHash": "sha256:6f98073941d8…", "summary": {"patch": 9, "none": 1, "report": 2, "skip": 1}}
patch   CronJob      hardening-demo/nightly           future Jobs only; nothing restarts
none    Deployment   hardening-demo/already-hardened
patch   Deployment   hardening-demo/root-nginx        rolling restart
patch   Deployment   hardening-demo/safe-app          rolling restart
skip    Deployment   hardening-demo/skipped-app       annotated sre-tool.io/skip
report  Job          hardening-demo/once              Job: pod template is immutable; change whatever creates it
report  Pod          hardening-demo/bare-pod          bare Pod: spec is immutable; recreate it from a controller
…
"changes":  seccompProfile.type → RuntimeDefault, allowPrivilegeEscalation → false,
            requests.cpu → 100m, requests.memory → 128Mi, limits.memory → 512Mi
"findings": R4 info "no CPU limit; not set on purpose, CPU limits throttle even on idle nodes",
            X1/X2/X3 warning: runAsNonRoot, capabilities.drop, readOnlyRootFilesystem
            "applied only with harden-profile=strict"
```

Apply exactly that plan. The `planHash` ties apply to what you reviewed: if anything changed since, you get 409 `stale_plan` instead of a surprise. Workloads are patched one at a time, and each rollout must become healthy before the next starts:

```sh
jq '{namespaces, planHash}' plan.json | curl -s -X POST -d @- localhost:8080/v1/hardening/apply \
  | jq '{outcome, results: [.results[] | select(.status != "skipped") | "\(.status) \(.kind)/\(.name) \(.rolloutSeconds | round)s"]}'
```

```json
{
  "outcome": "complete",
  "results": [
    "applied CronJob/nightly 0s",
    "applied Deployment/hpa-app 2s",
    "applied Deployment/root-nginx 4s",
    "applied StatefulSet/stateful-app 6s",
    "applied DaemonSet/node-agent 4s",
    "…9 applied in total"
  ]
}
```

A second plan now has nothing to patch, and applying it causes no rollout:

```sh
curl -s -X POST -d @examples/requests/harden-plan.json localhost:8080/v1/hardening/plan | jq .summary
```

```json
{"patch": 0, "none": 10, "report": 2, "skip": 1}
```

Undo (bonus) removes only the fields the tool still owns. Preview it with `dryRun`, then run it:

```sh
curl -s -X POST -d '{"namespaces": ["hardening-demo", "hardening-lr"], "dryRun": true}' \
  localhost:8080/v1/hardening/undo | jq '[.results[] | select(.status != "skipped")] | length'
curl -s -X POST -d '{"namespaces": ["hardening-demo", "hardening-lr"]}' \
  localhost:8080/v1/hardening/undo | jq '{outcome, undone: [.results[] | select(.status == "applied") | .name]}'
```

```json
9
{"outcome": "complete", "undone": ["hpa-app", "limits-only", "privileged-app", "root-nginx", "safe-app", "lr-app", "stateful-app", "node-agent", "nightly"]}
```

Opt-outs and opt-ins are annotations on a workload or namespace: `sre-tool.io/skip: "true"` (never touched) and `sre-tool.io/harden-profile: strict` (also set `runAsNonRoot`, `capabilities.drop: [ALL]` and `readOnlyRootFilesystem`). `make e2e-hardening` shows the strict profile on nginx, which runs as root: the new pod fails with `CreateContainerConfigError`, apply halts within seconds with a `kubectl rollout undo` remedy, and the two old pods keep serving the whole time.

## 5. How isolation is verified

```sh
make e2e-isolation
```

The script (`hack/verify-isolation.sh`) first proves the CNI enforces NetworkPolicy at all (a deny-all must turn `ok` into `blocked`), then probes a 10-row matrix before, during and after isolation. `blocked` means the connection timed out; a refused connection, a DNS failure or a failed `kubectl exec` is reported as an error, so a dead pod can never pass as "isolated". During isolation it also starts a new `app=dashboard` pod and checks that it is isolated on its first probe, restarts the tool and checks status survives, re-POSTs and checks nothing was rewritten, and after DELETE checks that exactly two policies went and that tenant-c's own policy is unchanged. Output from the cold-start run:

```text
Stage 0: guards
  CNI enforces a deny-all
Stage 1: baseline
  Before matrix probed
Stage 2: isolate
  POST examples/requests/isolate-gateway-dashboard.yaml -> 201
  During matrix probed
Stage 3: pod churn
  new pod pod/dashboard-cfc95457f-g2gnx -> gateway.tenant-a: blocked; -> client.tenant-c: ok
Stage 4: idempotency
  POST again -> 200
  resourceVersions unchanged: tenant-a/sre-iso-59957de534-a=3547 tenant-b/sre-iso-59957de534-b=3548 
Stage 5: restart
  GET /v1/isolations/59957de534 after restart -> 200
  complete: true
Stage 6: restore
  DELETE /v1/isolations/59957de534 -> 200
  deleted: ["tenant-a/sre-iso-59957de534-a","tenant-b/sre-iso-59957de534-b"]
  After matrix probed
  tenant-c/preexisting-allow-all-ingress untouched (rv 1637)

#   From                 To                                         Before    During    After
1   tenant-a/gateway     dashboard.tenant-b:8080                    ok        blocked   ok
2   tenant-b/dashboard   gateway.tenant-a:8080                      ok        blocked   ok
3   tenant-b/dashboard   10.244.2.209:8080                          ok        blocked   ok
4   tenant-c/client      gateway.tenant-a:8080                      ok        ok        ok
5   tenant-c/client      dashboard.tenant-b:8080                    ok        ok        ok
6   tenant-a/other       dashboard.tenant-b:8080                    ok        ok        ok
7   tenant-b/other       gateway.tenant-a:8080                      ok        ok        ok
8   tenant-a/gateway     client.tenant-c:8080                       ok        ok        ok
9   tenant-a/gateway     dns:kubernetes.default.svc.cluster.local   ok        ok        ok
10  tenant-a/other       gateway.tenant-a:8080                      ok        ok        ok

PASS: isolation e2e
```

`make e2e-hardening` covers plan, apply, field-level checks, idempotency (generation and ReplicaSet counts unchanged), a stale plan, the strict-profile failure and undo. `make e2e-rbac` checks what the tool's ServiceAccount can and cannot do.

## 6. Decisions

The brief left these open. Each answer below is the short version of a decision record.

**How isolation behaves as pods come and go.** Isolation is two ingress NetworkPolicies, one per side, each admitting "everything except the other side". The CNI evaluates label selectors live, so a new pod matching a side is isolated the moment it exists, and a pod relabelled out of a side leaves it, with no action from the tool. New namespaces are covered by a `NotIn` namespace peer. The tool keeps no state of its own: the ID, request and expected policy count live in labels and annotations on the policies. If the tool crashes, isolation stays on (fail-closed), and DELETE works after a restart because it lists by label.
- *Why ingress-only on both sides:* a new connection in either direction needs the receiver's ingress to admit it, and replies on allowed connections are stateful. Leaving egress alone keeps DNS and everything else working.
- *Why "everything except B" instead of "deny B":* standard NetworkPolicy has no deny. The complement of B's selector is built with De Morgan (`{app: x, tier: y}` becomes `app NotIn [x]` OR `tier NotIn [y]`), and an `ipBlock 0.0.0.0/0 except <pod CIDR>` peer keeps node and external traffic working.
- *Why refuse on conflict:* policies are OR'd. An existing ingress policy on either side would either admit the other side or be widened by ours, and a second isolation on the same pods would cancel the first. So the tool returns 409 and lists them; `force: true` overrides it and is recorded.
- *Why no rollback on partial failure:* half an isolation is better containment than none, and a retried POST completes the set.

**What counts as a hardened `securityContext`.** By default the tool sets only what cannot break a correctly written workload: pod `seccompProfile: RuntimeDefault` and container `allowPrivilegeEscalation: false`. `runAsNonRoot: true`, `capabilities.drop: [ALL]` and `readOnlyRootFilesystem: true` break many real images (root nginx, apps that write to `/tmp`), and the API can't tell in advance, so they are reported as findings and applied only with the `strict` annotation, behind the rollout gate. Values that are set are never changed, including `false`, `Unconfined` and `privileged: true`. `allowPrivilegeEscalation` is skipped for privileged or `SYS_ADMIN` containers, because API validation rejects that combination.

**Set default requests and limits, or only report.** Set, because a pod without requests is invisible to the scheduler and first to be evicted. Defaults: CPU request 100m, memory request 128Mi, memory limit max(512Mi, request), all configurable by flag. **No CPU limit, ever:** CPU throttling hurts latency even on an idle node, while memory without a limit can take the node down. When a container already has a limit but no request, admission already sets request = limit, so the tool adds nothing and reports it. When a namespace LimitRange supplies defaults, those win. An HPA on CPU utilisation gets a warning, because adding a request changes what "80%" means.

**Which workload types.** Deployments, StatefulSets, DaemonSets and CronJobs are patched, because each has a mutable pod template (CronJobs affect future Jobs only). Jobs and bare Pods are reported only, because their specs are immutable. Anything owned by another controller is reported as "managed by …", because that controller would revert the patch.

**How an operator triggers actions and sees results.** A small HTTP API behind `kubectl port-forward`, rather than a CRD and controller: an incident action should happen when asked and return its outcome in the same response, and port-forward makes Kubernetes RBAC and the audit log the access control without the tool handling credentials. The operator sees results in four places: the JSON response, Kubernetes Events on each policy or workload (`IsolationApplied`, `IsolationForced`, `IsolationRemoved`, `HardeningApplied`, `HardeningFailed`, `HardeningUndone`), Prometheus metrics, and structured JSON logs. Hardening is plan first, then apply of that exact plan hash.

**Which namespaces and workloads are never touched.** `kube-system`, `kube-public`, `kube-node-lease`, `local-path-storage` and the tool's own namespace are refused with 403 by both features (configurable with `--protected-namespaces`; the own namespace is always added). Anything annotated `sre-tool.io/skip: "true"`, on the workload or its namespace, is reported as `skip`.

**How apply avoids breaking workloads.**
- Patches use server-side apply with `fieldManager: sre-tool` and `force: false`. A field that someone else (a human, GitOps) owns with a different value is a conflict, and apply halts rather than fighting them.
- Each patch carries every field sre-tool already owns plus the new ones, because an apply drops the manager's owned fields it leaves out.
- One workload at a time, and each rollout is gated on the same conditions `kubectl rollout status` uses, with fail-fast on `CreateContainerConfigError`, `CrashLoopBackOff` and image pull errors.
- On the first failure it halts, does not auto-revert (a revert is another rollout, made under pressure), and returns the exact remedy.
- One apply runs at a time. One apply has a 12m budget and halts before a workload that might not finish in the time left, so the response always arrives before the server's 15m write timeout.
- The plan hash covers each pod template, not `resourceVersion` or `generation`, so an HPA scaling a workload doesn't make every plan stale.

**Undo.** Undo needs no snapshot. It sends an apply as `sre-tool` that contains only the object's identity. Server-side apply then removes every field only `sre-tool` owned. A field a human has since changed (say `kubectl set resources --requests=cpu=200m`) is owned by that human, so it is kept. Undo uses the same lock, budget, rollout gate and halt rules as apply.

**Deployment shape.** One replica with `strategy: Recreate`, because the apply lock and isolation mutex are in-process; there is no leader election to explain. The tool's own pod is non-root, read-only root filesystem, all capabilities dropped, seccomp `RuntimeDefault`, in a namespace that enforces Pod Security `restricted`, and the pure planner returns `none` on its own Deployment (a unit test). Its ClusterRole grants exactly what the features need: no Secrets, no ConfigMaps, no Pod writes, no RBAC.

**Decisions I made where the spec was silent**, during the build:
- The `sre-tool.io/request` annotation stores the request's identity (without `name` and `force`), so a re-POST with `force: true` is a repair, not a name conflict.
- `forced` is recorded only when `force` actually overrode a conflict.
- Every target policy name is checked for ownership before anything is written, so a 409 never leaves half an isolation.
- Windows pods skip the Linux-only securityContext fields (validation rejects them there).
- On Cilium, traffic from other nodes' host network to an isolated pod is blocked during isolation. I documented this rather than working around it (see Limitations).

## 7. Testing

Run `make tools` once first: `verify` and `ci` use the pinned linters in `./bin`.

```sh
make verify   # gofmt, go vet, golangci-lint, go test -race ./...
make e2e      # isolation, hardening and RBAC scripts against kind (needs the quick start)
make ci       # verify + govulncheck + actionlint, exactly what the CI verify job runs
```

| Layer | What it covers | How |
|---|---|---|
| Pure unit tests | request decoding and validation, normalisation and IDs, the selector complement, the policy builder, guards, preflight, the hardening rules, planner, plan hash and rollout evaluators | table-driven; golden files for the generated policies and the demo plan |
| Fake-clientset tests | isolation create/repair/delete/status, hardening collect/apply/undo, halts, budget, single-flight | `k8s.io/client-go/kubernetes/fake`, asserting on recorded actions; injected clocks, no `time.Sleep` |
| HTTP tests | routes, status codes, error mapping, body limit, request IDs, readiness | `httptest` |
| e2e against kind | real packets, real admission, real rollouts, real RBAC | `hack/verify-*.sh` |

The fake clientset never sets `resourceVersion`, ignores UID preconditions and ignores dry-run. So the unit tests assert on recorded actions, the dry-run validator is always faked behind an interface, and the e2e scripts prove what only a real API server can.

**The three tricky tests, and why I chose them:**

1. **`TestComplement_MatchesExactlyNonMembers`** (`internal/isolation`). "Everyone except B" must be expressed in an allow-only API. That is the core correctness risk of the whole isolation feature, and it is easy to get subtly wrong in two ways: forgetting De Morgan for multi-label selectors, or forgetting that `NotIn` matches pods with no such label. If it is wrong, the tool either fails to block B or blocks innocent traffic. The test checks every label combination against apimachinery's own selector implementation, so it doesn't rely on my understanding being right.
2. **`TestDelete_OnlyRemovesOwnPolicies`** (`internal/isolation`). The brief stresses turning isolation off safely. The dangerous bug is not failing to delete; it is deleting too much (someone else's policy, another incident's isolation) during an incident. The fixtures are adversarial: same name prefix, same managed-by label with a different ID.
3. **`TestPlan_SecondPassIsEmpty`** (`internal/hardening`). "Without breaking them": a non-idempotent patcher restarts every workload on every run, for example by stamping a timestamp or flapping a defaulted field. The test proves convergence, and the e2e confirms no new ReplicaSet appears on a real cluster.

Each of the three was checked by breaking the code on purpose and watching it fail.

## 8. Observability and operations

- **Ops port 8081** (cluster-internal, the only port the tool's NetworkPolicy admits): `/healthz` (alive), `/readyz` (the API server answered within the last 10s), `/metrics`.
- **Metrics:** `sre_tool_http_requests_total{route,method,code}`, `sre_tool_http_request_duration_seconds`, `sre_tool_isolations_active`, `sre_tool_hardening_workloads_total{action,result}`, `sre_tool_rollout_duration_seconds{kind,result}`. Labels are bounded: route patterns, never raw paths or IDs. In another terminal, forward the ops port and leave it running:
  ```sh
  make port-forward-ops
  ```
  Then:
  ```sh
  curl -s localhost:8081/metrics | grep ^sre_tool_
  ```
- **Events** land in the namespace of the policy or workload they are about: `kubectl --context kind-sre-tool -n <ns> get events --field-selector reportingComponent=sre-tool`.
- **Logs** are JSON with `request_id`, `route`, `status`, `duration_ms`, and `isolation_id` or `namespace`/`kind`/`name` where they apply. Request bodies are never logged.
- **Break-glass:** isolation is just labelled NetworkPolicies, so `kubectl --context kind-sre-tool delete netpol -A -l sre-tool.io/isolation-id=<id>` turns it off without the tool. A halted hardening apply returns the `kubectl rollout undo` command for the failed workload.
- **Day to day:** run plan in report mode on a schedule to see drift from the baseline; apply in small namespace batches during working hours; alert on `sre_tool_isolations_active > 0` for longer than an incident should last, and on `sre_tool_hardening_workloads_total{result="failed"}`. Shutdown on SIGTERM drains in-flight requests for up to 25s; an apply interrupted by shutdown stops before its next workload.

## 9. Known limitations and what I'd do with more time

**Isolation**
- Standard NetworkPolicy has no deny, so existing ingress policies on either side force a refusal (or `force`). The right production backend is AdminNetworkPolicy or Cilium's native `ingressDeny`, behind the same interface.
- Isolation does not block internet egress from a compromised pod.
- On Cilium 1.20.2 (kind, default datapath), an established TCP connection from B to A stops passing packets within the enforcement latency (under 2 s measured). Packets are dropped, not reset, so applications see a stall or timeout rather than an error. After the policies were removed, the stalled connection resumed after about 12 s (TCP retransmission backoff). This behaviour is CNI-specific: on CNIs that only evaluate policy at connection setup, established connections may survive isolation.
- On Cilium (tunnel mode), traffic from the host network of *other* nodes to an isolated pod is blocked while isolation is on, for example node agents with `hostNetwork`. Kubelet probes and external/NodePort traffic are unaffected. Cilium gives that traffic the `remote-node` identity, which no standard NetworkPolicy peer selects; installing Cilium with `policyCIDRMatchMode: nodes` did not change it. The production fix is a Cilium `fromEntities: [remote-node]` rule or AdminNetworkPolicy.
- Preflight only sees pods that exist at the time, and the overlap guard can't catch selectors that would overlap only for pods created later (A=`{app: x, tier: web}`, B=`{app: x}` with no pods yet).
- There is no background reconciler: drift is reported on GET and repaired by re-POSTing.

**Hardening**
- One-shot hardening is reverted by the next deploy or by GitOps (Argo CD, Flux). The production answer is admission control (Pod Security Admission, ValidatingAdmissionPolicy, or a mutating policy engine), with this tool as the migration aid that shows what would break first.
- `runAsNonRoot` can't be judged from the API without inspecting the image, hence the strict opt-in plus the rollout gate.
- Server-side dry-run catches validation and admission rejections, but Pod Security Admission only *warns* on workload objects; its enforcement shows up as pods that are never created, which the gate reports only at its 3-minute timeout. Quota and LimitRange min/max rejections behave the same way.
- Transient API errors while waiting for a rollout halt the apply rather than retrying, which is safe but noisy.
- Apply is synchronous and single-flight with no job queue. A large estate halts with `apply_budget_exhausted` and needs repeated plan/apply passes.

**General**
- The tool doesn't know who the caller is: access is via port-forward, so identity lives only in the Kubernetes audit log.
- Its ServiceAccount can patch workload templates in every unprotected namespace, which is effectively code execution if the token is stolen, and creating NetworkPolicies is a denial-of-service capability. The `sre-tool` namespace must stay locked down.
- IPv4 only. Single replica.

**What I'd do next**, in order:
1. An AdminNetworkPolicy (or Cilium-native deny) backend for isolation, which removes the conflict refusal and the remote-node gap.
2. A CRD (`Isolation`, `HardeningPlan`) with a controller, for continuous reconciliation, GitOps-friendly history and real caller identity through RBAC on the CRD.
3. Treat `ReplicaFailure` and `FailedCreate` as fail-fast in the rollout gate, and retry transient API errors while waiting.
4. Ship the hardening baseline as an admission policy, so new workloads are born compliant.
5. A Helm chart, and leader election if more than one replica is ever needed.

## 10. Time taken and feedback on the brief

<!-- AUTHOR: time taken, from docs/TIMELOG.md (honest total, and how it split across phases) -->

<!-- AUTHOR: feedback on the brief: anything unclear or inconsistent, in your own words -->

## 11. AI assistance

<!-- AUTHOR: AI-assistance statement: which tools you used, for what, and how you checked the output -->
