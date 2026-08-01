#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
rm -rf ebin
mkdir -p ebin
erlc -o ebin src/*.erl test/*.erl
erl -pa ebin -noshell -s usec_test run -s init stop
