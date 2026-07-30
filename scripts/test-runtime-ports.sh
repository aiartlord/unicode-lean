#!/usr/bin/env bash
# Run native runtime-port tests. This intentionally does not build Lean.
# shellcheck disable=SC2030,SC2031

set -euo pipefail

cd "$(dirname "$0")/.."

mode="smoke"
run_rust=1
run_python=1
run_cpp=1
run_haskell=1
run_jvm=1
run_go=1
run_typescript=1
run_dotnet=1
run_swift=1
run_zig=1
jobs="${JOBS:-2}"
rust_dir="${UNICODE_RUST_DIR:-ports/rust}"
cpp_dir="${UNICODE_CPP_DIR:-ports/cpp}"
python_dir="${UNICODE_PYTHON_DIR:-ports/python}"
haskell_dir="${UNICODE_HASKELL_DIR:-ports/haskell}"
jvm_dir="${UNICODE_JVM_DIR:-ports/jvm}"
go_dir="${UNICODE_GO_DIR:-ports/go}"
typescript_dir="${UNICODE_TYPESCRIPT_DIR:-ports/typescript}"
dotnet_dir="${UNICODE_DOTNET_DIR:-ports/dotnet}"
swift_dir="${UNICODE_SWIFT_DIR:-ports/swift}"
zig_dir="${UNICODE_ZIG_DIR:-ports/zig}"

usage() {
  cat <<'USAGE'
Usage: scripts/test-runtime-ports.sh [options]

Default mode is a bounded runtime-port smoke gate:
  - shared policy contract
  - Rust library + CLI + normal integration tests + doctests
  - Python tests
  - C++ tests
  - Haskell tests
  - JVM tests
  - Go tests
  - TypeScript tests
  - .NET tests
  - Swift tests
  - Zig tests

Options:
  --smoke        Run the bounded default gate.
  --all          Run all Rust tests, including noisy/deep red-team and diff tests.
  --rust-only    Run only the Rust tier plus the shared contract.
  --python-only  Run only the Python tier plus the shared contract.
  --cpp-only     Run only the C++ tier plus the shared contract.
  --haskell-only Run only the Haskell tier plus the shared contract.
  --jvm-only     Run only the JVM tier plus the shared contract.
  --go-only      Run only the Go tier plus the shared contract.
  --typescript-only
                 Run only the TypeScript tier plus the shared contract.
  --dotnet-only  Run only the .NET tier plus the shared contract.
  --swift-only   Run only the Swift tier plus the shared contract.
  --zig-only     Run only the Zig tier plus the shared contract.
  --with-haskell Include the Haskell tier. This is already on by default.
  --no-rust      Skip Rust.
  --no-python    Skip Python.
  --no-cpp       Skip C++.
  --no-haskell   Skip Haskell.
  --no-jvm       Skip JVM.
  --no-go        Skip Go.
  --no-typescript
                 Skip TypeScript.
  --no-dotnet    Skip .NET.
  --no-swift     Skip Swift.
  --no-zig       Skip Zig.
  -h, --help     Show this help.

Environment:
  JOBS=N         Parallel build jobs for Rust/C++ tiers (default: 2).
  UNICODE_HASKELL_DIR=PATH
                 Haskell port directory (default: ports/haskell).
  UNICODE_PYTHON_DATA_DIR=PATH
                 Python vendored data directory
                 (default: ports/python/src/unicode_python/data).
  UNICODE_JVM_DIR=PATH
                 JVM port directory (default: ports/jvm).
  UNICODE_GO_DIR=PATH
                 Go port directory (default: ports/go).
  UNICODE_TYPESCRIPT_DIR=PATH
                 TypeScript port directory (default: ports/typescript).
  UNICODE_DOTNET_DIR=PATH
                 .NET port directory (default: ports/dotnet).
  UNICODE_SWIFT_DIR=PATH
                 Swift port directory (default: ports/swift).
  UNICODE_ZIG_DIR=PATH
                 Zig port directory (default: ports/zig).
  RUST_WARNINGS=1
                 Show Rust warnings during the runtime smoke gate.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --smoke)
      mode="smoke"
      ;;
    --all)
      mode="all"
      ;;
    --rust-only)
      run_rust=1
      run_python=0
      run_cpp=0
      run_haskell=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --python-only)
      run_rust=0
      run_python=1
      run_cpp=0
      run_haskell=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --cpp-only)
      run_rust=0
      run_python=0
      run_cpp=1
      run_haskell=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --haskell-only)
      run_rust=0
      run_python=0
      run_cpp=0
      run_haskell=1
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --jvm-only)
      run_rust=0
      run_python=0
      run_cpp=0
      run_haskell=0
      run_jvm=1
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --go-only)
      run_rust=0
      run_python=0
      run_cpp=0
      run_haskell=0
      run_jvm=0
      run_go=1
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --typescript-only)
      run_rust=0
      run_python=0
      run_cpp=0
      run_haskell=0
      run_jvm=0
      run_go=0
      run_typescript=1
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --dotnet-only)
      run_rust=0
      run_python=0
      run_cpp=0
      run_haskell=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=1
      run_swift=0
      run_zig=0
      ;;
    --swift-only)
      run_rust=0
      run_python=0
      run_cpp=0
      run_haskell=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=1
      run_zig=0
      ;;
    --zig-only)
      run_rust=0
      run_python=0
      run_cpp=0
      run_haskell=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=1
      ;;
    --with-haskell)
      run_haskell=1
      ;;
    --no-rust)
      run_rust=0
      ;;
    --no-python)
      run_python=0
      ;;
    --no-cpp)
      run_cpp=0
      ;;
    --no-haskell)
      run_haskell=0
      ;;
    --no-jvm)
      run_jvm=0
      ;;
    --no-go)
      run_go=0
      ;;
    --no-typescript)
      run_typescript=0
      ;;
    --no-dotnet)
      run_dotnet=0
      ;;
    --no-swift)
      run_swift=0
      ;;
    --no-zig)
      run_zig=0
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
  shift
done

echo "== policy contract =="
scripts/check-policy-contract.sh

data_args=()
if [[ "$run_haskell" -eq 0 ]]; then
  data_args+=(--no-haskell)
fi
if [[ "$run_python" -eq 0 ]]; then
  data_args+=(--no-python)
fi
if [[ "$run_go" -eq 0 ]]; then
  data_args+=(--no-go)
fi
if [[ "$run_jvm" -eq 0 ]]; then
  data_args+=(--no-jvm)
fi
if [[ "$run_typescript" -eq 0 ]]; then
  data_args+=(--no-typescript)
fi
if [[ "$run_dotnet" -eq 0 ]]; then
  data_args+=(--no-dotnet)
fi
if [[ "$run_swift" -eq 0 ]]; then
  data_args+=(--no-swift)
fi
if [[ "$run_zig" -eq 0 ]]; then
  data_args+=(--no-zig)
fi

echo "== runtime data =="
scripts/check-runtime-data.sh "${data_args[@]}"

if [[ "$run_rust" -eq 1 ]]; then
  echo "== rust runtime (${mode}) =="
  export CARGO_BUILD_JOBS="$jobs"
  if [[ "${RUST_WARNINGS:-0}" != "1" ]]; then
    if [[ -n "${RUSTFLAGS:-}" ]]; then
      export RUSTFLAGS="$RUSTFLAGS -Awarnings"
    else
      export RUSTFLAGS="-Awarnings"
    fi
    if [[ -n "${RUSTDOCFLAGS:-}" ]]; then
      export RUSTDOCFLAGS="$RUSTDOCFLAGS -Awarnings"
    else
      export RUSTDOCFLAGS="-Awarnings"
    fi
  fi
  if [[ "$mode" == "all" ]]; then
    cargo test --quiet --manifest-path "$rust_dir/Cargo.toml"
  else
    cargo test --quiet --manifest-path "$rust_dir/Cargo.toml" \
      --lib \
      --test bom \
      --test identifier \
      --test noncharacters \
      --test opaque_blob \
      --test security \
      --test security_policy \
      --test cli \
      --test decode_policy \
      --test utf16 \
      --test utf32 \
      --test utf8 \
      --test validated_utf8
    cargo test --quiet --manifest-path "$rust_dir/Cargo.toml" --doc
  fi
fi

if [[ "$run_python" -eq 1 ]]; then
  echo "== python runtime =="
  (
    cd "$python_dir"
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q
  )
fi

if [[ "$run_cpp" -eq 1 ]]; then
  echo "== cpp runtime =="
  cmake -Wno-deprecated -S "$cpp_dir" -B "$cpp_dir/build" -G Ninja -DUNICODE_CPP_BUILD_TESTS=ON
  cmake --build "$cpp_dir/build" --parallel "$jobs"
  ctest --test-dir "$cpp_dir/build" --output-on-failure --quiet
fi

if [[ "$run_haskell" -eq 1 ]]; then
  echo "== haskell runtime =="
  if [[ ! -f "$haskell_dir/cabal.project" && ! -f "$haskell_dir/unicode-haskell.cabal" ]]; then
    echo "missing Haskell port at $haskell_dir" >&2
    echo "set UNICODE_HASKELL_DIR=/path/to/haskell-port or use --no-haskell" >&2
    exit 1
  fi
  (
    cd "$haskell_dir"
    export HOME="$PWD/.home"
    mkdir -p "$HOME"
    cabal test all --offline
  )
fi

if [[ "$run_jvm" -eq 1 ]]; then
  echo "== jvm runtime =="
  if [[ ! -x "$jvm_dir/scripts/test.sh" ]]; then
    echo "missing JVM port test script at $jvm_dir/scripts/test.sh" >&2
    echo "set UNICODE_JVM_DIR=/path/to/jvm-port or use --no-jvm" >&2
    exit 1
  fi
  (
    cd "$jvm_dir"
    scripts/test.sh
  )
fi

if [[ "$run_go" -eq 1 ]]; then
  echo "== go runtime =="
  if [[ ! -f "$go_dir/go.mod" ]]; then
    echo "missing Go port at $go_dir" >&2
    echo "set UNICODE_GO_DIR=/path/to/go-port or use --no-go" >&2
    exit 1
  fi
  (
    cd "$go_dir"
    export HOME="$PWD/.home"
    export GOCACHE="$PWD/.cache/go-build"
    export GOMODCACHE="$PWD/.cache/go-mod"
    mkdir -p "$HOME" "$GOCACHE" "$GOMODCACHE"
    go test ./...
  )
fi

if [[ "$run_typescript" -eq 1 ]]; then
  echo "== typescript runtime =="
  if [[ ! -f "$typescript_dir/package.json" ]]; then
    echo "missing TypeScript port at $typescript_dir" >&2
    echo "set UNICODE_TYPESCRIPT_DIR=/path/to/typescript-port or use --no-typescript" >&2
    exit 1
  fi
  (
    cd "$typescript_dir"
    node --test test/*.test.js
  )
fi

if [[ "$run_dotnet" -eq 1 ]]; then
  echo "== dotnet runtime =="
  if [[ ! -f "$dotnet_dir/test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj" ]]; then
    echo "missing .NET port at $dotnet_dir" >&2
    echo "set UNICODE_DOTNET_DIR=/path/to/dotnet-port or use --no-dotnet" >&2
    exit 1
  fi
  (
    cd "$dotnet_dir"
    export DOTNET_CLI_HOME="$PWD/.dotnet-home"
    export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
    export DOTNET_NOLOGO=1
    mkdir -p "$DOTNET_CLI_HOME"
    dotnet run --project test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
  )
fi

if [[ "$run_swift" -eq 1 ]]; then
  echo "== swift runtime =="
  if [[ ! -x "$swift_dir/scripts/test.sh" ]]; then
    echo "missing Swift port test script at $swift_dir/scripts/test.sh" >&2
    echo "set UNICODE_SWIFT_DIR=/path/to/swift-port or use --no-swift" >&2
    exit 1
  fi
  (
    cd "$swift_dir"
    scripts/test.sh
  )
fi

if [[ "$run_zig" -eq 1 ]]; then
  echo "== zig runtime =="
  if [[ ! -f "$zig_dir/build.zig" ]]; then
    echo "missing Zig port at $zig_dir" >&2
    echo "set UNICODE_ZIG_DIR=/path/to/zig-port or use --no-zig" >&2
    exit 1
  fi
  (
    cd "$zig_dir"
    export ZIG_GLOBAL_CACHE_DIR="$PWD/.cache/zig-global"
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR"
    zig build test
  )
fi

echo "clean: runtime-port gate passes"
