#!/usr/bin/env bash
# Verify the checked-in Zig confusables lookup table is reproducible
# from the vendored UTS #39 source data.

set -euo pipefail

cd "$(dirname "$0")/.."

python3 tools/generate_confusables_data.py --check
