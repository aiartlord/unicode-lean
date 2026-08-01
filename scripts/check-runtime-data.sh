#!/usr/bin/env bash
# Verify runtime-port vendored data and generated lookup tables. This is
# intentionally bounded and does not build Lean.

set -euo pipefail

cd "$(dirname "$0")/.."

run_haskell=1
run_python=1
run_jvm=1
run_go=1
run_typescript=1
run_dotnet=1
run_swift=1
run_zig=1
haskell_dir="${UNICODE_HASKELL_DIR:-ports/haskell}"
python_data_dir="${UNICODE_PYTHON_DATA_DIR:-ports/python/src/unicode_python/data}"
jvm_dir="${UNICODE_JVM_DIR:-ports/jvm}"
go_dir="${UNICODE_GO_DIR:-ports/go}"
typescript_dir="${UNICODE_TYPESCRIPT_DIR:-ports/typescript}"
dotnet_dir="${UNICODE_DOTNET_DIR:-ports/dotnet}"
swift_dir="${UNICODE_SWIFT_DIR:-ports/swift}"
zig_dir="${UNICODE_ZIG_DIR:-ports/zig}"
ruby_data_dir="${UNICODE_RUBY_DATA_DIR:-ports/ruby/data}"
lua_data_dir="${UNICODE_LUA_DATA_DIR:-ports/lua/data}"
php_data_dir="${UNICODE_PHP_DATA_DIR:-ports/php/data}"

usage() {
  cat <<'USAGE'
Usage: scripts/check-runtime-data.sh [options]

Default checks all runtime ports with vendored data.

Options:
  --haskell-only Run only the Haskell data guard.
  --python-only  Run only the Python data parity guard.
  --jvm-only     Run only the JVM data guard.
  --go-only      Run only the Go data guard.
  --typescript-only
                 Run only the TypeScript data guard.
  --dotnet-only  Run only the .NET data guard.
  --swift-only   Run only the Swift data guard.
  --zig-only     Run only the Zig data and generated-table guards.
  --no-haskell   Skip Haskell.
  --no-python    Skip Python.
  --no-jvm       Skip JVM.
  --no-go        Skip Go.
  --no-typescript
                 Skip TypeScript.
  --no-dotnet    Skip .NET.
  --no-swift     Skip Swift.
  --no-zig       Skip Zig.
  -h, --help     Show this help.

Environment:
  UNICODE_HASKELL_DIR=PATH
  UNICODE_PYTHON_DATA_DIR=PATH
  UNICODE_JVM_DIR=PATH
  UNICODE_GO_DIR=PATH
  UNICODE_TYPESCRIPT_DIR=PATH
  UNICODE_DOTNET_DIR=PATH
  UNICODE_SWIFT_DIR=PATH
  UNICODE_ZIG_DIR=PATH
  UNICODE_RUBY_DATA_DIR=PATH
  UNICODE_LUA_DATA_DIR=PATH
  UNICODE_PHP_DATA_DIR=PATH
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --haskell-only)
      run_haskell=1
      run_python=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --python-only)
      run_haskell=0
      run_python=1
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --jvm-only)
      run_haskell=0
      run_python=0
      run_jvm=1
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --go-only)
      run_haskell=0
      run_python=0
      run_jvm=0
      run_go=1
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --typescript-only)
      run_haskell=0
      run_python=0
      run_jvm=0
      run_go=0
      run_typescript=1
      run_dotnet=0
      run_swift=0
      run_zig=0
      ;;
    --dotnet-only)
      run_haskell=0
      run_python=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=1
      run_swift=0
      run_zig=0
      ;;
    --swift-only)
      run_haskell=0
      run_python=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=1
      run_zig=0
      ;;
    --zig-only)
      run_haskell=0
      run_python=0
      run_jvm=0
      run_go=0
      run_typescript=0
      run_dotnet=0
      run_swift=0
      run_zig=1
      ;;
    --no-haskell)
      run_haskell=0
      ;;
    --no-python)
      run_python=0
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

check_vendored_data_dir() {
  local label="$1"
  local dir="$2"
  if [[ ! -d "$dir" ]]; then
    echo "missing $label data directory at $dir" >&2
    exit 1
  fi
  if [[ ! -f "$dir/SHA256SUMS" ]]; then
    echo "missing $label SHA256SUMS at $dir/SHA256SUMS" >&2
    exit 1
  fi
  (
    cd "$dir"
    sha256sum -c --strict --quiet SHA256SUMS
  )
  local count=0
  while IFS= read -r vendored_file; do
    local rel="${vendored_file#"$dir"/}"
    local canonical_file="data/$rel"
    if [[ ! -e "$canonical_file" ]]; then
      echo "missing canonical runtime data file for $label vendored data: $canonical_file" >&2
      exit 1
    fi
    if ! cmp -s "$canonical_file" "$vendored_file"; then
      echo "$label vendored data drift: $vendored_file differs from $canonical_file" >&2
      echo "refresh with: scripts/sync-runtime-data.sh --apply" >&2
      exit 1
    fi
    count=$((count + 1))
  done < <(find "$dir" -type f ! -name SHA256SUMS | sort)

  if [[ "$count" -eq 0 ]]; then
    echo "FATAL: no $label vendored data files found under $dir" >&2
    exit 1
  fi
  echo "clean: $label runtime data matches canonical data/ inputs ($count file(s))"
}

if [[ "$run_haskell" -eq 1 ]]; then
  echo "== haskell runtime data =="
  if [[ ! -x "$haskell_dir/scripts/check-ucd-hashes.sh" ]]; then
    echo "missing Haskell data guard at $haskell_dir/scripts/check-ucd-hashes.sh" >&2
    exit 1
  fi
  "$haskell_dir/scripts/check-ucd-hashes.sh"
fi

if [[ "$run_python" -eq 1 ]]; then
  echo "== python runtime data =="
  if [[ ! -d "$python_data_dir" ]]; then
    echo "missing Python data directory at $python_data_dir" >&2
    exit 1
  fi
  if [[ ! -f data/SHA256SUMS ]]; then
    echo "FATAL: data/SHA256SUMS missing" >&2
    exit 1
  fi
  (cd data && sha256sum -c --strict --quiet SHA256SUMS)

  count=0
  while IFS= read -r python_file; do
    base="${python_file##*/}"
    canonical_file="data/$base"
    if [[ ! -e "$canonical_file" ]]; then
      echo "missing canonical runtime data file for Python vendored data: $canonical_file" >&2
      exit 1
    fi
    if ! cmp -s "$canonical_file" "$python_file"; then
      echo "Python vendored data drift: $python_file differs from $canonical_file" >&2
      echo "refresh with: cp $canonical_file $python_file" >&2
      exit 1
    fi
    count=$((count + 1))
  done < <(find "$python_data_dir" -maxdepth 1 -type f -name '*.txt' | sort)

  if [[ "$count" -eq 0 ]]; then
    echo "FATAL: no Python vendored data files found under $python_data_dir" >&2
    exit 1
  fi
  echo "clean: Python runtime data matches canonical data/ inputs ($count file(s))"
fi

if [[ "$run_go" -eq 1 ]]; then
  echo "== go runtime data =="
  if [[ ! -x "$go_dir/scripts/check-data-hashes.sh" ]]; then
    echo "missing Go data guard at $go_dir/scripts/check-data-hashes.sh" >&2
    exit 1
  fi
  "$go_dir/scripts/check-data-hashes.sh"
fi

if [[ "$run_jvm" -eq 1 ]]; then
  echo "== jvm runtime data =="
  if [[ ! -x "$jvm_dir/scripts/check-data-hashes.sh" ]]; then
    echo "missing JVM data guard at $jvm_dir/scripts/check-data-hashes.sh" >&2
    exit 1
  fi
  "$jvm_dir/scripts/check-data-hashes.sh"
fi

if [[ "$run_typescript" -eq 1 ]]; then
  echo "== typescript runtime data =="
  if [[ ! -x "$typescript_dir/scripts/check-data-hashes.sh" ]]; then
    echo "missing TypeScript data guard at $typescript_dir/scripts/check-data-hashes.sh" >&2
    exit 1
  fi
  "$typescript_dir/scripts/check-data-hashes.sh"
fi

if [[ "$run_dotnet" -eq 1 ]]; then
  echo "== dotnet runtime data =="
  if [[ ! -x "$dotnet_dir/scripts/check-data-hashes.sh" ]]; then
    echo "missing .NET data guard at $dotnet_dir/scripts/check-data-hashes.sh" >&2
    exit 1
  fi
  "$dotnet_dir/scripts/check-data-hashes.sh"
fi

if [[ "$run_swift" -eq 1 ]]; then
  echo "== swift runtime data =="
  if [[ ! -x "$swift_dir/scripts/check-data-hashes.sh" ]]; then
    echo "missing Swift data guard at $swift_dir/scripts/check-data-hashes.sh" >&2
    exit 1
  fi
  "$swift_dir/scripts/check-data-hashes.sh"
fi

if [[ "$run_zig" -eq 1 ]]; then
  echo "== zig runtime data =="
  if [[ ! -x "$zig_dir/scripts/check-data-hashes.sh" ]]; then
    echo "missing Zig data guard at $zig_dir/scripts/check-data-hashes.sh" >&2
    exit 1
  fi
  if [[ ! -x "$zig_dir/scripts/check-generated-confusables.sh" ]]; then
    echo "missing Zig generated-data guard at $zig_dir/scripts/check-generated-confusables.sh" >&2
    exit 1
  fi
  "$zig_dir/scripts/check-data-hashes.sh"
  "$zig_dir/scripts/check-generated-confusables.sh"
fi

echo "== ruby runtime data =="
check_vendored_data_dir Ruby "$ruby_data_dir"

echo "== lua runtime data =="
check_vendored_data_dir Lua "$lua_data_dir"

echo "== php runtime data =="
check_vendored_data_dir PHP "$php_data_dir"

echo "== embedded port digest sync =="
scripts/check-port-pinned-digests.sh

echo "clean: runtime-port data guards pass"
