#!/usr/bin/env bash
# Verify JVM-port vendored homoglyph data against its pinned manifest and the
# canonical repository data inputs.

set -euo pipefail

cd "$(dirname "$0")/.."

(cd src/main/resources/com/unicodesecurity/data && sha256sum -c --strict --quiet SHA256SUMS)

for file in confusables.txt KnownAttackTargets.txt; do
  if ! cmp -s "../../data/$file" "src/main/resources/com/unicodesecurity/data/$file"; then
    echo "FATAL: JVM vendored data drift: src/main/resources/com/unicodesecurity/data/$file differs from data/$file" >&2
    echo "run: scripts/sync-runtime-data.sh --apply" >&2
    exit 1
  fi
done

echo "clean: JVM runtime data hashes match canonical data"
