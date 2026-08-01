#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

ruby -Ilib -Itest -e 'Dir["test/**/*_test.rb"].sort.each { |path| require File.expand_path(path) }'
