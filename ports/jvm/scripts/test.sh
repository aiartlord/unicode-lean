#!/usr/bin/env bash
# Compile and run the dependency-free JVM contract tests.

set -euo pipefail

cd "$(dirname "$0")/.."

build_dir="${JVM_BUILD_DIR:-build}"
classes="$build_dir/classes"
test_classes="$build_dir/test-classes"
javac_bin="${JAVAC:-javac}"
java_bin="${JAVA:-java}"

rm -rf "$build_dir"
mkdir -p "$classes" "$test_classes"

mapfile -t main_sources < <(find src/main/java -name '*.java' | sort)
"$javac_bin" -encoding UTF-8 -d "$classes" "${main_sources[@]}"
cp -R src/main/resources/. "$classes/"
mapfile -t test_sources < <(find src/test/java -name '*.java' | sort)
"$javac_bin" -encoding UTF-8 -cp "$classes" -d "$test_classes" "${test_sources[@]}"
"$java_bin" -ea -cp "$classes:$test_classes" com.unicodesecurity.SecurityContractTest

echo "clean: JVM contract tests pass"
