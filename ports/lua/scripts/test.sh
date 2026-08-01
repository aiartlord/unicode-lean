#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

export LUA_PATH="test/?.lua;src/?.lua;src/?/init.lua;;"

for test_file in test/*_test.lua; do
  lua "$test_file"
done
