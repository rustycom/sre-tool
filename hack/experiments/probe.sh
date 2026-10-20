#!/usr/bin/env bash
# Usage: probe.sh <namespace> <pod> <host:port>
# Prints "ok" if a TCP connection from the pod succeeds within 3s, otherwise "blocked".
set -uo pipefail
if kubectl --context kind-sre-tool -n "$1" exec "$2" -- /agnhost connect "$3" --timeout=3s >/dev/null 2>&1; then
  echo ok
else
  echo blocked
fi
