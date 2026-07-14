#!/usr/bin/env bash
# Build the full official-fixture conformance root. This is intentionally opt-in
# because it imports assurance proofs and large fixture-backed evidence suites.

set -euo pipefail

cd "$(dirname "$0")/.."

if [ "${UNICODE_BUILD_HEAVY:-}" != "1" ]; then
  cat >&2 <<'EOF'
Refusing to build UnicodeFullConformance without explicit opt-in.

This target imports proof-heavy theorem modules and official fixture-backed
evidence suites. It is intended for release, audit, and scheduled verification,
not routine local iteration.

Run intentionally with:

  UNICODE_BUILD_HEAVY=1 scripts/build-full-conformance.sh
EOF
  exit 2
fi

lake build UnicodeFullConformance
