#!/usr/bin/env bash
# Verify TypeScript-port vendored runtime data against its pinned manifest
# and the canonical repository data inputs.

set -euo pipefail

cd "$(dirname "$0")/.."

(cd src/data && sha256sum -c --strict --quiet SHA256SUMS)

for file in CaseFolding.txt confusables.txt KnownAttackTargets.txt StandardizedVariants.txt emoji-variation-sequences.txt; do
  if ! cmp -s "../../data/$file" "src/data/$file"; then
    echo "FATAL: TypeScript vendored data drift: src/data/$file differs from data/$file" >&2
    echo "run: scripts/sync-runtime-data.sh --apply" >&2
    exit 1
  fi
done

echo "clean: TypeScript runtime data hashes match canonical data"
