#!/usr/bin/env bash
# Fail if any `.lean` file under `Unicode/` contains unfinished-proof tactic
# invocations. Match only at tactic boundaries so prose and identifiers do not
# false-positive.

set -euo pipefail

cd "$(dirname "$0")/.."

sorry_hits="$(grep -rnE '\bsorry([[:space:]]*$|[;,)}])' \
    --include='*.lean' Unicode/ \
    | grep -v '^[^:]*:[0-9]*:[[:space:]]*--' \
    || true)"
if [ -n "$sorry_hits" ]; then
  echo "FATAL: sorry tactic found in proof files:"
  echo "$sorry_hits"
  exit 1
fi

admit_hits="$(grep -rnE '\badmit([[:space:]]*$|[;,)}])' \
    --include='*.lean' Unicode/ \
    | grep -v '^[^:]*:[0-9]*:[[:space:]]*--' \
    || true)"
if [ -n "$admit_hits" ]; then
  echo "FATAL: admit tactic found in proof files:"
  echo "$admit_hits"
  exit 1
fi

echo "clean: zero sorry, zero admit"
