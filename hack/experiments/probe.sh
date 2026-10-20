#!/usr/bin/env bash
# Usage: probe.sh <namespace> <pod> <host:port>
# Prints "ok" if a TCP connection from the pod succeeds within 3s and "blocked" if it times
# out (what a dropping NetworkPolicy looks like). Anything else (refused, DNS failure, exec
# error) prints "error: <reason>" so it can't be mistaken for enforcement.
set -uo pipefail
source "$(dirname "$0")/../lib.sh"
if out=$("${KUBECTL[@]}" -n "$1" exec "$2" -- /agnhost connect "$3" --timeout=3s 2>&1); then
  echo ok
elif grep -q '^TIMEOUT' <<<"$out"; then
  echo blocked
else
  echo "error: $(head -1 <<<"$out")"
fi
