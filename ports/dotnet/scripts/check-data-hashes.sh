#!/usr/bin/env bash
# Verify .NET-port vendored homoglyph data against its pinned manifest and the
# canonical repository data inputs.

set -euo pipefail

cd "$(dirname "$0")/.."

(cd Data && sha256sum -c --strict --quiet SHA256SUMS)

for file in confusables.txt KnownAttackTargets.txt; do
  if ! cmp -s "../../data/$file" "Data/$file"; then
    echo "FATAL: .NET vendored data drift: Data/$file differs from data/$file" >&2
    echo "run: scripts/sync-runtime-data.sh --apply" >&2
    exit 1
  fi
done

echo "clean: .NET runtime data hashes match canonical data"
