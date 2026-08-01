#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p bin
cobc -x -free -Wall -o bin/usec src/usec.cob
python3 testdata/run_fixtures.py
