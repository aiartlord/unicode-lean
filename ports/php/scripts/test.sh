#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for test_file in test/*_test.php; do
  php "$test_file"
done
