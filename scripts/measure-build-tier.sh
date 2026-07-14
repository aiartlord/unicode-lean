#!/usr/bin/env bash
# Measure wall time and maximum RSS for a build-tier command.

set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  cat <<'USAGE'
Usage: scripts/measure-build-tier.sh [options] -- COMMAND [ARG...]

Options:
  --label NAME     Stable measurement label. Defaults to the command basename.
  --out-dir DIR    Output directory. Defaults to dist/measurements.
  -h, --help       Show this help.

Examples:
  scripts/measure-build-tier.sh --label runtime-build -- \
    nix develop .#runtime -c scripts/build-runtime.sh

  scripts/measure-build-tier.sh --label runtime-package -- \
    nix develop .#runtime -c env JOBS=1 scripts/package-runtime.sh
USAGE
}

label=""
out_dir="${UNICODE_MEASURE_OUT:-dist/measurements}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      [[ $# -ge 2 ]] || {
        echo "FATAL: --label requires a value" >&2
        exit 2
      }
      label="$2"
      shift 2
      ;;
    --out-dir)
      [[ $# -ge 2 ]] || {
        echo "FATAL: --out-dir requires a value" >&2
        exit 2
      }
      out_dir="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

[[ $# -gt 0 ]] || {
  usage >&2
  exit 2
}

if [[ -z "$label" ]]; then
  label="$(basename "$1")"
fi

case "$out_dir" in
  /*) out_abs="$out_dir" ;;
  *) out_abs="$PWD/$out_dir" ;;
esac

safe_label="$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '_')"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log="$out_abs/${safe_label}-${stamp}.txt"

mkdir -p "$out_abs"

time_bin="${TIME_BIN:-}"
if [[ -z "$time_bin" ]]; then
  if [[ -x /usr/bin/time ]]; then
    time_bin="/usr/bin/time"
  else
    time_bin="$(type -P time || true)"
  fi
fi

if [[ -z "$time_bin" || ! -x "$time_bin" ]]; then
  echo "FATAL: GNU time is required for maximum RSS evidence" >&2
  exit 1
fi

if ! "$time_bin" -v true >/dev/null 2>&1; then
  echo "FATAL: $time_bin does not support GNU time -v output" >&2
  exit 1
fi

command_line="$(printf '%q ' "$@")"
commit="$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
tree_state="clean"
if [[ -n "$(git status --porcelain --untracked-files=normal 2>/dev/null)" ]]; then
  tree_state="dirty"
fi

set +e
{
  echo "label: $label"
  echo "timestamp_utc: $stamp"
  echo "git_commit: $commit"
  echo "git_tree_state: $tree_state"
  echo "host: $(hostname 2>/dev/null || printf 'unknown')"
  echo "kernel: $(uname -a)"
  echo "cwd: $PWD"
  echo "command: $command_line"
  echo
  "$time_bin" -v "$@"
} 2>&1 | tee "$log"
status="${PIPESTATUS[0]}"
set -e

{
  echo
  echo "exit_status: $status"
  echo "measurement_log: $log"
} | tee -a "$log"

exit "$status"
