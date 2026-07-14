#!/usr/bin/env bash
# Verify the Go runtime port's vendored security data matches its
# SHA-256 manifest. These bytes feed the data-backed homoglyph detector.

set -euo pipefail

cd "$(dirname "$0")/../security/data"

if [ ! -f SHA256SUMS ]; then
  echo "FATAL: ports/go/security/data/SHA256SUMS missing"
  exit 1
fi

sha256sum -c --strict --quiet SHA256SUMS

count="$(wc -l < SHA256SUMS | tr -d ' ')"
echo "clean: Go runtime data matches SHA-256 manifest ($count file(s))"
