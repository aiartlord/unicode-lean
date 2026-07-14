#!/usr/bin/env bash
# Record wall/RSS evidence for bounded runtime tiers.

set -euo pipefail

cd "$(dirname "$0")/.."

only="all"
out_dir="${UNICODE_MEASURE_OUT:-dist/measurements/runtime}"
dist_dir="${UNICODE_RUNTIME_DIST:-/tmp/unicode-runtime-budget-package}"
dry_run=0

usage() {
  cat <<'USAGE'
Usage: scripts/measure-runtime-budgets.sh [options]

Options:
  --only NAME     Measure one tier: runtime-build, runtime-ports, runtime-package, all.
  --out-dir DIR   Measurement output directory. Defaults to dist/measurements/runtime.
  --dist-dir DIR  Runtime package output directory for runtime-package measurement.
  --dry-run       Print the commands without running them.
  -h, --help      Show this help.

Run through the runtime shell for stable tool availability:

  nix develop .#runtime -c scripts/measure-runtime-budgets.sh --only runtime-package
USAGE
}

fail() {
  echo "FATAL: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)
      [[ $# -ge 2 ]] || fail "--only requires a value"
      only="$2"
      shift
      ;;
    --out-dir)
      [[ $# -ge 2 ]] || fail "--out-dir requires a value"
      out_dir="$2"
      shift
      ;;
    --dist-dir)
      [[ $# -ge 2 ]] || fail "--dist-dir requires a value"
      dist_dir="$2"
      shift
      ;;
    --dry-run)
      dry_run=1
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

case "$only" in
  all|runtime-build|runtime-ports|runtime-package) ;;
  *) fail "unknown tier for --only: $only" ;;
esac

run_measure() {
  local label="$1"
  shift
  if [[ "$dry_run" -eq 1 ]]; then
    printf 'scripts/measure-build-tier.sh --label %q --out-dir %q --' "$label" "$out_dir"
    printf ' %q' "$@"
    printf '\n'
    return
  fi
  scripts/measure-build-tier.sh --label "$label" --out-dir "$out_dir" -- "$@"
}

if [[ "$only" == "all" || "$only" == "runtime-build" ]]; then
  run_measure runtime-build env JOBS="${JOBS:-1}" scripts/build-runtime.sh
fi

if [[ "$only" == "all" || "$only" == "runtime-ports" ]]; then
  run_measure runtime-ports env JOBS="${JOBS:-1}" scripts/test-runtime-ports.sh --smoke
fi

if [[ "$only" == "all" || "$only" == "runtime-package" ]]; then
  run_measure runtime-package env JOBS="${JOBS:-1}" UNICODE_RUNTIME_DIST="$dist_dir" scripts/package-runtime.sh
fi
