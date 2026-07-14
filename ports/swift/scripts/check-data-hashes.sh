#!/usr/bin/env bash
# Verify Swift-port vendored homoglyph data against its pinned manifest and the
# canonical repository data.

set -euo pipefail

cd "$(dirname "$0")/.."

for file in confusables.txt KnownAttackTargets.txt; do
  if ! cmp -s "Sources/UnicodeSecurity/Resources/Data/$file" "../../data/$file"; then
    echo "FATAL: Swift vendored data drift: Sources/UnicodeSecurity/Resources/Data/$file differs from data/$file" >&2
    exit 1
  fi
done

(cd Sources/UnicodeSecurity/Resources/Data && sha256sum -c --strict --quiet SHA256SUMS)

echo "clean: Swift runtime data hashes match canonical data"
