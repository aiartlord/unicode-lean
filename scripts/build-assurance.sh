#!/usr/bin/env bash
# Build the proof-heavy assurance root. This is intentionally opt-in because it
# may require substantially more memory and time than the runtime root.

set -euo pipefail

cd "$(dirname "$0")/.."

if [ "${UNICODE_BUILD_HEAVY:-}" != "1" ]; then
  cat >&2 <<'EOF'
Refusing to build UnicodeAssurance without explicit opt-in.

This target imports proof-heavy theorem modules and may require substantially
more memory than the runtime build.

Run intentionally with:

  UNICODE_BUILD_HEAVY=1 scripts/build-assurance.sh
EOF
  exit 2
fi

lake build UnicodeAssurance
