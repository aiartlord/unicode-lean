#!/usr/bin/env bash
# Static import-boundary guard for the default `Unicode` root.
#
# This wrapper intentionally delegates to `audit-lean-root-boundaries.py` so
# CI, local runtime builds, and the staged-cache runbook share one definition
# of the consumer boundary.

set -euo pipefail

cd "$(dirname "$0")/.."

scripts/audit-lean-root-boundaries.py \
  --root Unicode \
  --consumer-root Unicode \
  --fail-consumer-boundary \
  --fail-direct-root-imports
