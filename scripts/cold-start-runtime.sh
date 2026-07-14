#!/usr/bin/env bash
# Serial runtime cold-start gate. This does not invoke Lean builds.

set -euo pipefail

cd "$(dirname "$0")/.."

dist_dir="${UNICODE_RUNTIME_DIST:-dist/runtime-cold-start}"
timeout_sec="${UNICODE_COLD_START_TIMEOUT_SEC:-5400}"
min_available_gb="${UNICODE_COLD_START_MIN_AVAILABLE_GB:-8}"
run_package=1
run_deployment=1

usage() {
  cat <<'USAGE'
Usage: scripts/cold-start-runtime.sh [options]

Run the runtime/product cold-start gate serially with conservative defaults.

Options:
  --dist-dir DIR          Runtime package output tree.
                          Defaults to UNICODE_RUNTIME_DIST or
                          dist/runtime-cold-start.
  --timeout-sec N         Per-phase timeout in seconds. Default: 5400.
  --min-available-gb N    Minimum MemAvailable before starting a phase.
                          Default: 8.
  --skip-package          Skip runtime packaging and package verification.
  --skip-deployment       Skip packaged deployment smoke consumers.
  -h, --help              Show this help.

Environment:
  JOBS=N                  Build jobs. Defaults to 1.
  UNICODE_COLD_START_TIMEOUT_SEC=N
  UNICODE_COLD_START_MIN_AVAILABLE_GB=N
  UNICODE_RUNTIME_DIST=DIR
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist-dir)
      [[ $# -ge 2 ]] || { echo "FATAL: --dist-dir needs a value" >&2; exit 1; }
      dist_dir="$2"
      shift 2
      ;;
    --timeout-sec)
      [[ $# -ge 2 ]] || { echo "FATAL: --timeout-sec needs a value" >&2; exit 1; }
      timeout_sec="$2"
      shift 2
      ;;
    --min-available-gb)
      [[ $# -ge 2 ]] || { echo "FATAL: --min-available-gb needs a value" >&2; exit 1; }
      min_available_gb="$2"
      shift 2
      ;;
    --skip-package)
      run_package=0
      shift
      ;;
    --skip-deployment)
      run_deployment=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "FATAL: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "$dist_dir" in
  /*) dist_abs="$dist_dir" ;;
  *) dist_abs="$PWD/$dist_dir" ;;
esac

export JOBS="${JOBS:-1}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-1}"
export MAKEFLAGS="${MAKEFLAGS:--j1}"

available_gb() {
  awk '/^MemAvailable:/ { printf "%.0f\n", $2 / 1024 / 1024 }' /proc/meminfo 2>/dev/null || printf '999\n'
}

check_memory() {
  local available
  available="$(available_gb)"
  if [[ "$available" =~ ^[0-9]+$ ]] && (( available < min_available_gb )); then
    echo "FATAL: MemAvailable ${available}G is below ${min_available_gb}G" >&2
    exit 1
  fi
  echo "MemAvailable: ${available}G"
}

run_phase() {
  local name="$1"
  shift
  echo "== $(date -u +%Y-%m-%dT%H:%M:%SZ) :: $name =="
  check_memory
  timeout "$timeout_sec" "$@"
}

echo "Runtime cold-start gate"
echo "dist: $dist_abs"
echo "jobs: $JOBS"
echo "timeout_sec: $timeout_sec"
echo "min_available_gb: $min_available_gb"

run_phase "shared policy contract" scripts/check-policy-contract.sh
run_phase "runtime data parity" scripts/check-runtime-data.sh
run_phase "self-contained ports" scripts/check-port-self-contained.sh
run_phase "runtime port smoke tests" scripts/test-runtime-ports.sh --smoke

if [[ "$run_package" -eq 1 ]]; then
  run_phase "runtime package build" env UNICODE_RUNTIME_DIST="$dist_abs" JOBS="$JOBS" scripts/package-runtime.sh
  run_phase "runtime package verification" scripts/check-runtime-package.sh "$dist_abs"
  if [[ "$run_deployment" -eq 1 ]]; then
    run_phase "deployment consumer smokes" scripts/check-deployment-smokes.sh --dist-dir "$dist_abs"
  fi
fi

echo "clean: runtime cold-start gate passed"
