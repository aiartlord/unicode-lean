#!/usr/bin/env bash
# Verify that the table-integrity digests embedded as code constants in each
# runtime-loading port stay in sync with the canonical data/SHA256SUMS.
#
# The runtime-loading ports (TypeScript, .NET, JVM, Swift) hash their vendored
# UCD tables at load and compare against digests hard-coded in their source, so
# the code is the trust anchor rather than a swappable manifest. That only holds
# if those embedded constants track the canonical bytes: a UCD refresh that
# updates the vendored tables but not a port's embedded digest would make the
# port fail closed on correct data, or keep pinning a stale table. This gate
# catches that drift. It is source-only and does not build any port.
#
# Portable to bash 3.x — no associative arrays.

set -euo pipefail

cd "$(dirname "$0")/.."

manifest="data/SHA256SUMS"
[ -f "$manifest" ] || { echo "FATAL: $manifest missing" >&2; exit 1; }

# Tables that the runtime-loading ports pin at load.
tables="CaseFolding.txt confusables.txt KnownAttackTargets.txt StandardizedVariants.txt emoji-variation-sequences.txt DerivedBidiClass.txt"

# port:source-file carrying the embedded digest constants.
ports="typescript:ports/typescript/src/security.js
dotnet:ports/dotnet/src/UnicodeSecurity/Security.cs
jvm:ports/jvm/src/main/java/com/unicodesecurity/Security.java
swift:ports/swift/Sources/UnicodeSecurity/UnicodeSecurity.swift"

fail=0

for table in $tables; do
  canon="$(awk -v n="$table" '$2 == n { print $1 }' "$manifest")"
  if [ -z "$canon" ]; then
    echo "FATAL: no canonical digest for $table in $manifest" >&2
    fail=1
    continue
  fi
  for entry in $ports; do
    port="${entry%%:*}"
    src="${entry#*:}"
    if [ ! -f "$src" ]; then
      echo "FATAL: $port source missing: $src" >&2
      fail=1
      continue
    fi
    # The embedded digest sits on the same line as the quoted table-name key.
    embedded="$(grep -F "\"$table\"" "$src" | grep -oE '[0-9a-f]{64}' | LC_ALL=C sort -u)"
    if [ -z "$embedded" ]; then
      echo "FATAL: $port ($src) has no embedded digest for $table" >&2
      fail=1
    elif [ "$embedded" != "$canon" ]; then
      echo "FATAL: $port digest for $table does not match canonical:" >&2
      echo "  embedded : $embedded" >&2
      echo "  canonical: $canon" >&2
      fail=1
    fi
  done
done

if [ "$fail" -eq 0 ]; then
  echo "clean: all runtime-loading ports pin the canonical data/SHA256SUMS digests"
fi
exit "$fail"
