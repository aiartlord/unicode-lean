#!/usr/bin/env bash
# Build and run the C++ runtime tests under ASAN + UBSAN.
#
# This is an optional hardening gate for the C++ port. It does not invoke Lean.
# Pass --corpus PATH to also run tools/diff_runner.cpp over a generated
# cross-port differential corpus.

set -euo pipefail

cd "$(dirname "$0")/.."

build_dir="build-sanitize"
corpus_path=""
jobs="${JOBS:-1}"

usage() {
  cat <<'USAGE'
Usage: scripts/check-cpp-sanitizers.sh [options]

Options:
  --build-dir DIR  CMake build directory. Defaults to build-sanitize.
  --corpus PATH    Optional differential corpus JSONL for tools/diff_runner.cpp.
  -h, --help       Show this help.

Environment:
  JOBS=N           Parallel build jobs. Defaults to 1.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-dir)
      if [[ $# -lt 2 ]]; then
        echo "--build-dir requires a directory" >&2
        exit 2
      fi
      build_dir="$2"
      shift 2
      ;;
    --corpus)
      if [[ $# -lt 2 ]]; then
        echo "--corpus requires a JSONL path" >&2
        exit 2
      fi
      corpus_path="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "$corpus_path" && ! -f "$corpus_path" ]]; then
  echo "missing differential corpus: $corpus_path" >&2
  echo "generate one with: cargo test --manifest-path ports/rust/Cargo.toml --test diff_runner --release diff_gen_corpus -- --nocapture" >&2
  exit 1
fi

sanitize_cxx_flags=("-fsanitize=address,undefined" "-fno-sanitize-recover=all" "-g" "-O1")
sanitize_link_flags=("-fsanitize=address,undefined")

echo "== configure C++ sanitizer build =="
cmake -Wno-deprecated -S ports/cpp -B "$build_dir" -G Ninja \
  -DCMAKE_CXX_FLAGS="${sanitize_cxx_flags[*]}" \
  -DCMAKE_EXE_LINKER_FLAGS="${sanitize_link_flags[*]}" \
  -DUNICODE_CPP_BUILD_TESTS=ON

echo "== build C++ sanitizer tests =="
cmake --build "$build_dir" --target unicode_cpp_tests --parallel "$jobs"

echo "== run C++ sanitizer tests =="
ctest --test-dir "$build_dir" --output-on-failure

if [[ -n "$corpus_path" ]]; then
  echo "== build C++ sanitizer differential runner =="
  c++ -std=c++20 -Wall -Wextra -Wpedantic -Werror \
    "${sanitize_cxx_flags[@]}" "${sanitize_link_flags[@]}" \
    -Iinclude -o "$build_dir/diff_runner" tools/diff_runner.cpp

  echo "== run C++ sanitizer differential runner =="
  corpus_tmp="$build_dir/diff_corpus.jsonl"
  output_tmp="$build_dir/cpp_diff_sanitize.jsonl"
  stderr_tmp="$build_dir/cpp_sanitize.stderr"
  cp "$corpus_path" "$corpus_tmp"
  UNICODE_CPP_DIFF_CORPUS="$corpus_tmp" \
    "$build_dir/diff_runner" > "$output_tmp" 2> "$stderr_tmp"
  if [[ -s "$stderr_tmp" ]]; then
    echo "sanitizer/differential stderr was not empty:" >&2
    sed -n '1,40p' "$stderr_tmp" >&2
    exit 1
  fi
  lines="$(wc -l < "$output_tmp" | tr -d ' ')"
  echo "clean: C++ sanitizer differential runner produced $lines row(s)"
else
  echo "clean: C++ sanitizer tests passed; no differential corpus supplied"
fi
