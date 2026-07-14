#!/usr/bin/env bash
# Inventory launch-cleanup candidates without deleting or moving files.

set -euo pipefail

cd "$(dirname "$0")/.."

out="${UNICODE_LAUNCH_CLEANUP_REPORT:-dist/audits/launch-cleanup.txt}"
fail_on_findings=0

usage() {
  cat <<'USAGE'
Usage: scripts/audit-launch-cleanup.sh [options]

Options:
  --out FILE          Report path. Defaults to dist/audits/launch-cleanup.txt.
  --fail-on-findings  Exit nonzero if cleanup candidates are found.
  -h, --help          Show this help.

The report is inventory only. It never deletes, moves, or rewrites files.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      [[ $# -ge 2 ]] || {
        echo "FATAL: --out requires a value" >&2
        exit 2
      }
      out="$2"
      shift
      ;;
    --fail-on-findings)
      fail_on_findings=1
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

case "$out" in
  /*) out_abs="$out" ;;
  *) out_abs="$PWD/$out" ;;
esac

mkdir -p "$(dirname "$out_abs")"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

untracked="$tmpdir/untracked"
candidates="$tmpdir/candidates"
ignored="$tmpdir/ignored"

git ls-files --others --exclude-standard > "$untracked"

find . \
  \( -path ./.git -o -path ./.lake -o -path ./.elan -o -path ./target \
     -o -path ./build -o -path ./build-sanitize -o -path ./dist \
     -o -path './ports/go/.cache' -o -path './ports/haskell/dist-newstyle' \
     -o -path './ports/zig/.zig-cache' \) -prune \
  -o -type f \
  \( -iname '*probe*.lean' -o -iname '*scratch*' -o -iname '*prototype*' \
     -o -iname '*experiment*' -o -iname '*-old*' -o -iname '*_old*' \
     -o -iname 'old-*' -o -iname 'old_*' -o -iname '*backup*' \) \
  -print | sed 's|^\./||' | sort > "$candidates"

find . \
  \( -path ./.git -o -path ./.lake -o -path ./.elan \) -prune \
  -o -type d \
  \( -name __pycache__ -o -name .cache -o -name .home -o -name dist-newstyle \
     -o -name .zig-cache \) \
  -print | sed 's|^\./||' | sort > "$ignored"

{
  echo "launch cleanup audit"
  echo
  echo "timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_commit: $(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')"
  echo "git_tree_state: $(if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then printf dirty; else printf clean; fi)"
  echo
  echo "untracked files"
  if [[ -s "$untracked" ]]; then
    sed 's/^/  /' "$untracked"
  else
    echo "  none"
  fi
  echo
  echo "prototype/probe/scratch path candidates"
  if [[ -s "$candidates" ]]; then
    sed 's/^/  /' "$candidates"
  else
    echo "  none"
  fi
  echo
  echo "cache/build directories present"
  if [[ -s "$ignored" ]]; then
    sed 's/^/  /' "$ignored"
  else
    echo "  none"
  fi
  echo
  echo "next action"
  echo "  decide for each untracked source path: commit, document as local-only, or remove before launch"
} > "$out_abs"

cat "$out_abs"

if [[ "$fail_on_findings" -eq 1 ]] && { [[ -s "$untracked" ]] || [[ -s "$candidates" ]]; }; then
  exit 1
fi
