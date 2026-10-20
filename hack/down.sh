#!/usr/bin/env bash
set -euo pipefail
CLUSTER="${CLUSTER:-sre-tool}"
kind delete cluster --name "${CLUSTER}"
